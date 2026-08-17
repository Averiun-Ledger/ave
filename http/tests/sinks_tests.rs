use reqwest::Client;
use serde_json::{Value, json};
use test_log::test;

use crate::common::{
    TestPersistencePaths, TestServer, TestServerOptions, create_governance,
    login, make_request,
    test_sink::{ResponseMode, TestSink},
    wait_request_finish,
};

pub mod common;

/// Return a valid but non-existent subject identifier.
///
/// The sink endpoints parse `subject_id` as a `DigestIdentifier`, so a dummy
/// string of `X`s yields `400 Bad Request`. A real digest string is needed to
/// exercise the `404 Not Found` path.
fn unknown_subject_id() -> String {
    use ave_bridge::ave_common::identity::{DigestIdentifier, HashAlgorithm};
    DigestIdentifier::new(HashAlgorithm::Blake3, vec![0u8; 32])
        .unwrap()
        .to_string()
}

/// Build a JSON sink configuration with one governance sink and one schema sink.
/// `governance_id` is the subject id of the governance that owns the `Example1`
/// schema; it is required for the schema sink target.
fn sinks_config(
    gov_sink_url: &str,
    schema_sink_url: &str,
    governance_id: &str,
) -> String {
    format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "gov-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{gov_sink_url}" }} }}]
        }},
        {{
            "target": {{ "type": "schema", "schema_id": "Example1", "governance_id": "{governance_id}" }},
            "servers": [{{ "server": "schema-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{schema_sink_url}" }} }}]
        }}
        "#
    )
}

/// Start a server with two configured sinks: `gov-sink` and `schema-sink`.
/// The server is started without sinks, a governance is created, the server is
/// shut down and reopened with the sink configuration pinned to that governance.
async fn start_server_with_sinks(
    enable_auth: bool,
    always_accept: bool,
    safe_mode: bool,
) -> Option<(
    TestServer,
    TestSink,
    TestSink,
    String,
    Vec<tempfile::TempDir>,
)> {
    let gov_sink = TestSink::start().await;
    let schema_sink = TestSink::start().await;

    let (server, dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth,
        always_accept,
        safe_mode,
        sinks_config: None,
        ..Default::default()
    })
    .await?;

    let client = Client::new();

    let gov_body = create_governance(&client, &server, None).await;
    let governance_id = gov_body["subject_id"].as_str()?.to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        gov_body["request_id"].as_str()?,
    )
    .await;

    let schema_body =
        add_example_schema(&client, &server, None, &governance_id).await;
    wait_request_finish(
        &client,
        &server,
        None,
        schema_body["request_id"].as_str()?,
    )
    .await;

    server.shutdown().await;

    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    let (server, _new_dirs) =
        TestServer::build_with_options(TestServerOptions {
            enable_auth,
            always_accept,
            safe_mode,
            persistence: Some(persistence),
            sinks_config: Some(sinks_config(
                &gov_sink.url(),
                &schema_sink.url(),
                &governance_id,
            )),
            ..Default::default()
        })
        .await?;

    Some((server, gov_sink, schema_sink, governance_id, dirs))
}

/// HTTP Test 1: `GET /sinks` with real configured sinks and query filters.
///
/// **Objective:** verify that `GET /sinks` serialises and deserialises
/// `SinksQuery`, returns the configured sinks and honours every filter.
///
/// **Setup:** start a server with `gov-sink` (target governance) and
/// `schema-sink` (target schema Example1).
///
/// **Sequence:**
/// 1. `GET /sinks` without filters -> 200, both sinks, sorted by manager/name.
/// 2. Verify `SinkInfo` shape for each sink.
/// 3. `GET /sinks/schema-sink` -> 200, single `SinkInfo` object.
/// 4. `GET /sinks?target=governance` -> only `gov-sink`.
/// 5. `GET /sinks?target=schema` -> only `schema-sink`.
/// 6. `GET /sinks?schema_id=Example1` -> only `schema-sink`.
/// 7. `GET /sinks?governance_id=<id>` -> only `schema-sink`.
/// 8. `GET /sinks?in_config=true` -> both sinks.
/// 9. `GET /sinks?running=true` -> both sinks (they should be running).
/// 10. `GET /sinks?target=schema&in_config=true&running=true` -> `schema-sink`.
/// 11. `GET /sinks/nonexistent` -> 404.
/// 12. `GET /sinks?target=unknown` -> 400 (target only admits `governance`
///     or `schema`).
///
/// **Verifications:**
/// - All responses return 200.
/// - Responses are JSON arrays.
/// - Each filter returns exactly the expected sink names.
#[test(tokio::test)]
async fn test_http_get_sinks_with_filters() {
    let Some((server, _gov_sink, _schema_sink, governance_id, _dirs)) =
        start_server_with_sinks(false, true, false).await
    else {
        return;
    };

    let client = Client::new();
    let base = server.url("/sinks");

    let (status, body) = make_request(&client, &base, "GET", None, None).await;
    assert_eq!(status, 200);
    let sinks: Vec<Value> =
        serde_json::from_value(body).expect("sinks should be an array");
    assert_eq!(sinks.len(), 2);
    let names: Vec<&str> =
        sinks.iter().map(|s| s["name"].as_str().unwrap()).collect();
    assert!(names.contains(&"gov-sink"));
    assert!(names.contains(&"schema-sink"));

    for sink in &sinks {
        assert!(sink["name"].is_string());
        assert!(sink.get("target").is_some());
        assert!(sink["manager"].is_object());
        assert!(sink["manager"]["type"].is_string());
        assert!(sink["in_config"].is_boolean());
        assert!(sink["running"].is_boolean());
        assert!(sink["blocked"].is_null() || sink["blocked"].is_string());
        assert!(
            sink["lagging_subjects"].is_u64()
                || sink["lagging_subjects"].is_i64()
        );
        assert!(sink["server"].is_object());
        assert_eq!(sink["transport"], "http");
        // Sanitized view: delivery contract present, internals absent.
        let server_view = &sink["server"];
        assert!(server_view["events"].is_array());
        assert_eq!(server_view["transport"]["type"], "http");
        assert!(server_view.get("catch_up_batch_size").is_none());
        assert!(server_view.get("server").is_none());
        assert!(server_view["transport"].get("max_retries").is_none());
    }

    let (status, body) = make_request(
        &client,
        &server.url("/sinks/schema-sink"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "schema-sink");
    assert!(body["target"].is_object());
    assert!(body["manager"].is_object());
    assert_eq!(body["in_config"], true);
    assert_eq!(body["running"], true);
    assert_eq!(body["transport"], "http");

    assert_filter(&client, &base, "target=governance", &["gov-sink"]).await;
    assert_filter(&client, &base, "target=schema", &["schema-sink"]).await;
    assert_filter(&client, &base, "schema_id=Example1", &["schema-sink"]).await;
    assert_filter(
        &client,
        &base,
        &format!("governance_id={}", governance_id),
        &["schema-sink"],
    )
    .await;
    assert_filter(
        &client,
        &base,
        "in_config=true",
        &["gov-sink", "schema-sink"],
    )
    .await;
    assert_filter(&client, &base, "running=true", &["gov-sink", "schema-sink"])
        .await;
    assert_filter(
        &client,
        &base,
        "target=schema&in_config=true&running=true",
        &["schema-sink"],
    )
    .await;
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/nonexistent"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);

    let (status, body) = make_request(
        &client,
        &server.url("/sinks?target=unknown"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 400, "invalid target must be rejected: {body}");
}

/// HTTP Test 2: `GET /sinks/status`.
///
/// **Objective:** verify the status endpoint shape and that it only returns
/// configured sinks.
///
/// **Setup:** same as HTTP Test 1.
///
/// **Sequence:**
/// 1. `GET /sinks/status` -> 200, two sinks.
/// 2. Verify `SinkStatusInfo` fields: `name`, `in_config`, `running`,
///    `blocked`, `lagging_subjects`.
///
/// **Verifications:**
/// - Status is 200.
/// - Both sinks have `in_config: true` and `running: true`.
/// - Neither sink is blocked.
#[test(tokio::test)]
async fn test_http_get_sinks_status() {
    let Some((server, _gov_sink, _schema_sink, _governance_id, _dirs)) =
        start_server_with_sinks(false, true, false).await
    else {
        return;
    };

    let client = Client::new();
    let (status, body) =
        make_request(&client, &server.url("/sinks/status"), "GET", None, None)
            .await;
    assert_eq!(status, 200);
    let statuses: Vec<Value> =
        serde_json::from_value(body).expect("statuses should be an array");
    assert_eq!(statuses.len(), 2);

    for status in &statuses {
        assert!(status["name"].is_string());
        assert_eq!(status["in_config"].as_bool(), Some(true));
        assert_eq!(status["running"].as_bool(), Some(true));
        assert!(status["blocked"].is_null());
        assert!(
            status["lagging_subjects"].is_u64()
                || status["lagging_subjects"].is_i64()
        );
    }
}

/// HTTP Test 3: `POST /sinks/{sink_name}/unblock` happy path.
///
/// **Objective:** verify that the unblock endpoint returns 200 for a blocked
/// sink and for a healthy sink (no-op).
///
/// **Setup:** start a server with `example-sink` configured in `ClientError`
/// mode (`422`) so that the governance create event blocks it.
///
/// **Sequence:**
/// 1. Create a governance -> sink becomes blocked.
/// 2. `POST /sinks/example-sink/unblock` -> 200.
/// 3. `POST /sinks/example-sink/unblock` again -> 200 (no-op).
/// 4. `POST /sinks/missing-sink/unblock` -> 404.
///
/// **Verifications:**
/// - Real unblock returns 200.
/// - No-op returns 200.
/// - Missing sink returns 404.
#[test(tokio::test)]
async fn test_http_unblock_sink() {
    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::ClientError).await;
    let sinks_json = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "example-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        sink.url()
    );

    let (server, dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        sinks_config: Some(sinks_json),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let gov_body = create_governance(&client, &server, None).await;
    wait_request_finish(
        &client,
        &server,
        None,
        gov_body["request_id"].as_str().unwrap(),
    )
    .await;

    wait_for_sink_blocked(&client, &server, "example-sink").await;

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/unblock"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/unblock"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/missing-sink/unblock"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);

    server.shutdown().await;
    drop(dirs);
}

/// HTTP Test 4: `POST /sinks/{sink_name}/unblock` permissions and safe mode.
///
/// **Objective:** verify RBAC (`node_sink:post`) and safe-mode behaviour.
///
/// **Setup:**
/// - Server with `enable_auth: true` and a sink configured.
/// - Users with roles `sink` (`node_sink:all`), `data` (no `node_sink`) and
///   `superadmin` (all).
/// - Variant of the server in safe mode.
///
/// **Sequence:**
/// 1. User with role `sink` -> 200.
/// 2. User with role `data` -> 403.
/// 3. Superadmin outside safe mode -> 200.
/// 4. Superadmin in safe mode -> 503.
///
/// **Verifications:**
/// - Missing permission returns 403.
/// - Safe mode returns 503.
#[test(tokio::test)]
async fn test_http_unblock_sink_permissions_and_safe_mode() {
    let sink = TestSink::start().await;
    let sinks_json = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "example-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        sink.url()
    );

    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        sinks_config: Some(sinks_json),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");

    // The `sink` role has full control of its domain (node_sink:all).
    let sink_key =
        create_sink_user_and_login(&server, &client, &admin_key).await;

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/unblock"),
        "POST",
        Some(&sink_key),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // A role without node_sink permissions is still rejected.
    let data_key = create_role_user_and_login(
        &server,
        &client,
        &admin_key,
        "data",
        "data_user",
    )
    .await;

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/unblock"),
        "POST",
        Some(&data_key),
        None,
    )
    .await;
    assert_eq!(status, 403);

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/unblock"),
        "POST",
        Some(&admin_key),
        None,
    )
    .await;
    assert_eq!(status, 200);

    // Safe mode variant.
    server.shutdown().await;
    let persistence = TestPersistencePaths::from_tempdirs(&_dirs);
    let (server, _dirs2) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        safe_mode: true,
        persistence: Some(persistence),
        sinks_config: Some(format!(
            r#"
            {{
                "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
                "servers": [{{ "server": "example-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
            }}
            "#,
            sink.url()
        )),
        ..Default::default()
    })
    .await
    .expect("safe mode server should build");

    let admin_key2 = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login in safe mode");
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/unblock"),
        "POST",
        Some(&admin_key2),
        None,
    )
    .await;
    assert_eq!(status, 503);
}

/// HTTP Test 4b: `POST /sinks/{sink_name}/test` status codes.
///
/// **Objective:** the endpoint distinguishes a failed delivery (502), a
/// registered-but-unconfigured sink (409) and an unknown sink (404).
///
/// **Setup:** two governance sinks: `failing-sink`, whose receiver rejects
/// deliveries with 422, and `residual-sink`, removed from the configuration
/// on a restart so it stays registered but unconfigured.
///
/// **Sequence:**
/// 1. `POST /sinks/failing-sink/test` -> 502 (test delivery failed).
/// 2. Restart without `residual-sink` in config;
///    `POST /sinks/residual-sink/test` -> 409.
/// 3. `POST /sinks/missing-sink/test` -> 404.
#[test(tokio::test)]
async fn test_http_test_sink_status_codes() {
    let failing_sink = TestSink::start().await;
    failing_sink.set_mode(ResponseMode::ClientError).await;
    let residual_sink = TestSink::start().await;

    let initial_config = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "failing-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }},
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "residual-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        failing_sink.url(),
        residual_sink.url()
    );

    let (server, dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        sinks_config: Some(initial_config),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();

    // Wait until the sink is registered before testing it: the registry is
    // populated asynchronously after the server starts.
    wait_for_sink_visible(&client, &server, "failing-sink").await;

    // 1. The receiver rejects the test delivery -> 502 Bad Gateway.
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/failing-sink/test"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 502);

    server.shutdown().await;

    // Restart without residual-sink in config so it becomes residual.
    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    let second_config = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "failing-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        failing_sink.url()
    );
    let (server, _dirs2) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        persistence: Some(persistence),
        sinks_config: Some(second_config),
        ..Default::default()
    })
    .await
    .expect("server should build");

    // Wait until the residual sink is visible again after the restart.
    wait_for_sink_visible(&client, &server, "residual-sink").await;

    // 2. Registered but not configured -> 409 Conflict.
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/residual-sink/test"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 409);

    // 3. Unknown sink -> 404 Not Found.
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/missing-sink/test"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

/// HTTP Test 5: `POST /sinks/{sink_name}/reset-cursors` happy path.
///
/// **Objective:** verify cursor reset in safe mode.
///
/// **Setup:** server in safe mode with one in-config sink and one residual
/// sink (`in_config: false`).
///
/// **Sequence:**
/// 1. `GET /sinks/status` -> 200; includes the residual sink with
///    `in_config: false` alongside the in-config one.
/// 2. `POST /sinks/in-config-sink/reset-cursors` -> 200; sink still appears in lists.
/// 3. `POST /sinks/residual-sink/reset-cursors` -> 200; sink disappears from
///    `GET /sinks?in_config=false`.
/// 4. `POST /sinks/missing-sink/reset-cursors` -> 404.
///
/// **Verifications:**
/// - `/sinks/status` exposes residual sinks.
/// - In-config sink survives the reset.
/// - Residual sink is removed from registry.
/// - Missing sink returns 404.
#[test(tokio::test)]
async fn test_http_reset_sink_cursors() {
    let in_config_sink = TestSink::start().await;
    let residual_sink = TestSink::start().await;

    // First start: configure both sinks.
    let initial_config = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "in-config-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }},
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "residual-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        in_config_sink.url(),
        residual_sink.url()
    );

    let (server, dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        sinks_config: Some(initial_config),
        ..Default::default()
    })
    .await
    .expect("server should build");

    server.shutdown().await;

    // Restart without residual-sink in config so it becomes residual.
    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    let second_config = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "in-config-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        in_config_sink.url()
    );
    let (server, _dirs2) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        safe_mode: true,
        persistence: Some(persistence),
        sinks_config: Some(second_config),
        ..Default::default()
    })
    .await
    .expect("server should reopen");

    let client = Client::new();

    // `/sinks/status` must include the residual sink (in_config: false), not
    // only the ones present in the current config. Poll until the registry
    // reflects the persisted state instead of assuming startup timing.
    let mut statuses: Vec<Value> = Vec::new();
    for _ in 0..100 {
        let (status, body) = make_request(
            &client,
            &server.url("/sinks/status"),
            "GET",
            None,
            None,
        )
        .await;
        assert_eq!(status, 200);
        statuses = serde_json::from_value(body).unwrap();
        if statuses.iter().any(|s| s["name"] == "residual-sink") {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }
    let residual = statuses
        .iter()
        .find(|s| s["name"] == "residual-sink")
        .expect("residual sink must appear in /sinks/status");
    assert_eq!(residual["in_config"], false);
    let in_config = statuses
        .iter()
        .find(|s| s["name"] == "in-config-sink")
        .expect("in-config sink must appear in /sinks/status");
    assert_eq!(in_config["in_config"], true);

    // The singular endpoint also resolves residual sinks.
    let (status, body) = make_request(
        &client,
        &server.url("/sinks/residual-sink"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "residual-sink");
    assert_eq!(body["in_config"], false);
    assert!(body["server"].is_null());
    assert!(body["transport"].is_null());

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/in-config-sink/reset-cursors"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = make_request(
        &client,
        &server.url("/sinks/in-config-sink"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["name"], "in-config-sink");

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/residual-sink/reset-cursors"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);

    let (status, body) = make_request(
        &client,
        &server.url("/sinks?in_config=false"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let residuals: Vec<Value> = serde_json::from_value(body).unwrap();
    assert!(residuals.is_empty());

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/missing-sink/reset-cursors"),
        "POST",
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

/// HTTP Test 6: `POST /sinks/{sink_name}/reset-cursors` permissions and safe mode.
///
/// **Objective:** verify `node_sink:post` and the safe-mode requirement.
///
/// **Setup:**
/// - Server with auth and a sink.
/// - User with role `sink`.
/// - Variant outside safe mode.
///
/// **Sequence:**
/// 1. `sink` user -> 503 (passes permissions, hits the safe-mode gate).
/// 2. Superadmin outside safe mode -> 503.
/// 3. Superadmin in safe mode -> 200.
#[test(tokio::test)]
async fn test_http_reset_sink_cursors_permissions_and_safe_mode() {
    let sink = TestSink::start().await;
    let sinks_json = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "example-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        sink.url()
    );

    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        sinks_config: Some(sinks_json.clone()),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");
    let sink_key =
        create_sink_user_and_login(&server, &client, &admin_key).await;

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/reset-cursors"),
        "POST",
        Some(&sink_key),
        None,
    )
    .await;
    assert_eq!(status, 503);

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/reset-cursors"),
        "POST",
        Some(&admin_key),
        None,
    )
    .await;
    assert_eq!(status, 503);

    server.shutdown().await;
    let persistence = TestPersistencePaths::from_tempdirs(&_dirs);
    let (server, _dirs2) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        safe_mode: true,
        persistence: Some(persistence),
        sinks_config: Some(sinks_json),
        ..Default::default()
    })
    .await
    .expect("safe mode server should build");

    let admin_key2 = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login in safe mode");
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/example-sink/reset-cursors"),
        "POST",
        Some(&admin_key2),
        None,
    )
    .await;
    assert_eq!(status, 200);
}

/// HTTP Test 6a: the legacy `DELETE /sinks/{sink_name}` route is not mounted.
///
/// **Objective:** the cursor reset operation moved to
/// `POST /sinks/{sink_name}/reset-cursors`; the old route must be gone.
/// The path exists for `GET /sinks/{sink_name}`, so a `DELETE` hits the
/// method router and must be rejected with 405 Method Not Allowed.
#[test(tokio::test)]
async fn test_http_legacy_delete_sink_route_is_not_mounted() {
    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let (status, body) = make_request(
        &client,
        &server.url("/sinks/example-sink"),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(
        status, 405,
        "legacy DELETE /sinks/{{sink_name}} must not be mounted"
    );
    assert!(
        body["error"].is_string(),
        "405 must return the canonical error body: {body}"
    );
}

/// HTTP Test 6b: `POST /sinks/{sink_name}/reset-cursors` requires `node_sink:post`.
///
/// **Objective:** the permission action moved from `delete` to `post` together
/// with the route. A role holding `node_sink:post` must pass the permission
/// layer (failing later with 503 outside safe mode), while a role holding
/// only `node_sink:delete` must be rejected with 403.
#[test(tokio::test)]
async fn test_http_reset_sink_cursors_requires_post_permission() {
    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");

    // A role holding node_sink:post passes the permission layer and reaches
    // the safe-mode gate (503 outside safe mode)
    let post_key = create_user_with_sink_action(
        &server,
        &client,
        &admin_key,
        "sink_poster",
        "post",
    )
    .await;
    let (status, body) = make_request(
        &client,
        &server.url("/sinks/example-sink/reset-cursors"),
        "POST",
        Some(&post_key),
        None,
    )
    .await;
    assert_eq!(
        status, 503,
        "node_sink:post must pass permissions and hit the safe-mode gate: {body}"
    );

    // A role holding only node_sink:delete must not gain access
    let delete_key = create_user_with_sink_action(
        &server,
        &client,
        &admin_key,
        "sink_deleter",
        "delete",
    )
    .await;
    let (status, body) = make_request(
        &client,
        &server.url("/sinks/example-sink/reset-cursors"),
        "POST",
        Some(&delete_key),
        None,
    )
    .await;
    assert_eq!(
        status, 403,
        "node_sink:delete alone must not grant access to reset-cursors: {body}"
    );
}

/// HTTP Test 7: `POST /sinks/replay` happy path and functional errors.
///
/// **Objective:** verify request body parsing and response shape.
///
/// **Setup:** server with a governance sink and a governance with a schema.
///
/// **Sequence:**
/// 1. Valid replay -> 200, `processed` with one item, empty `errors`.
/// 2. Missing sink -> 200, item in `errors` (`SinkNotFound`).
/// 3. Unknown subject -> 200, item in `errors`.
/// 4. `from_sn` out of range -> 200, item in `errors`.
/// 5. Blocked sink -> 200, item in `errors` ("sink is blocked").
///
/// **Verifications:**
/// - All responses are 200.
/// - Response shape is `SinkReplayResponse` (`processed` and `errors` arrays).
#[test(tokio::test)]
async fn test_http_replay_sink_events() {
    let good_sink = TestSink::start().await;
    let bad_sink = TestSink::start().await;
    bad_sink.set_mode(ResponseMode::ClientError).await;
    let sinks_json = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "good-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }},
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "bad-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        good_sink.url(),
        bad_sink.url()
    );

    let (server, dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        sinks_config: Some(sinks_json),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();

    let gov_body = create_governance(&client, &server, None).await;
    let governance_id = gov_body["subject_id"].as_str().unwrap().to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        gov_body["request_id"].as_str().unwrap(),
    )
    .await;

    let replay_body = |sink: &str, subject_id: &str, from_sn: u64| {
        Some(json!({
            "requests": [{ "sink": sink, "subject_id": subject_id, "from_sn": from_sn }]
        }))
    };

    // Wait for the governance create event to be delivered so the sink manager
    // knows the subject and can replay it. The bad sink is in client-error mode,
    // so it will become blocked on the same create event.
    good_sink.wait_for_count(1, true).await;
    wait_for_sink_blocked(&client, &server, "bad-sink").await;

    let (status, body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        None,
        replay_body("good-sink", &governance_id, 0),
    )
    .await;
    assert_eq!(status, 200);
    assert!(body["processed"].is_array());
    assert!(body["errors"].is_array());
    assert_eq!(body["processed"].as_array().unwrap().len(), 1);
    assert!(body["errors"].as_array().unwrap().is_empty());

    let (status, body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        None,
        replay_body("missing-sink", &governance_id, 0),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["processed"].as_array().unwrap().len(), 0);
    assert_eq!(body["errors"].as_array().unwrap().len(), 1);

    let (status, body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        None,
        replay_body("good-sink", &unknown_subject_id(), 0),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["errors"].as_array().unwrap().len(), 1);

    let (status, body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        None,
        replay_body("good-sink", &governance_id, 9999),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["errors"].as_array().unwrap().len(), 1);

    // Replay against a blocked sink must report an error.
    let (status, body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        None,
        replay_body("bad-sink", &governance_id, 0),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["errors"].as_array().unwrap().len(), 1);

    server.shutdown().await;
    drop(dirs);
}

/// HTTP Test 8: `POST /sinks/replay` permissions and safe mode.
///
/// **Objective:** verify `node_sink:post` and safe-mode rejection.
///
/// **Setup:**
/// - Server with auth and a governance sink.
/// - User with role `sink`.
/// - Variant in safe mode.
///
/// **Sequence:**
/// 1. `sink` user -> 200 (`node_sink:all`); role without `node_sink` -> 403.
/// 2. Malformed `subject_id` -> 400 (rejected before execution).
/// 3. Superadmin in safe mode -> 400/503.
/// 4. Superadmin outside safe mode -> 200.
#[test(tokio::test)]
async fn test_http_replay_sink_events_permissions_and_safe_mode() {
    let sink = TestSink::start().await;
    let sinks_json = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "gov-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        sink.url()
    );

    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        sinks_config: Some(sinks_json.clone()),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");
    let sink_key =
        create_sink_user_and_login(&server, &client, &admin_key).await;

    let body = Some(json!({
        "requests": [{ "sink": "gov-sink", "subject_id": unknown_subject_id(), "from_sn": 0 }]
    }));

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        Some(&sink_key),
        body.clone(),
    )
    .await;
    assert_eq!(status, 200);

    // A role without node_sink permissions is still rejected.
    let data_key = create_role_user_and_login(
        &server,
        &client,
        &admin_key,
        "data",
        "data_user",
    )
    .await;
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        Some(&data_key),
        body.clone(),
    )
    .await;
    assert_eq!(status, 403);

    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        Some(&admin_key),
        body.clone(),
    )
    .await;
    assert_eq!(status, 200);

    // A malformed subject_id is rejected up front (400), not reported as a
    // per-item error inside a 200 response.
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        Some(&admin_key),
        Some(json!({
            "requests": [{ "sink": "gov-sink", "subject_id": "not-a-valid-digest", "from_sn": 0 }]
        })),
    )
    .await;
    assert_eq!(status, 400);

    server.shutdown().await;
    let persistence = TestPersistencePaths::from_tempdirs(&_dirs);
    let (server, _dirs2) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        safe_mode: true,
        persistence: Some(persistence),
        sinks_config: Some(sinks_json),
        ..Default::default()
    })
    .await
    .expect("safe mode server should build");

    let admin_key2 = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login in safe mode");
    let (status, _body) = make_request(
        &client,
        &server.url("/sinks/replay"),
        "POST",
        Some(&admin_key2),
        body,
    )
    .await;
    assert!(
        status == 400 || status == 503,
        "safe mode should reject replay, got {}",
        status
    );
}

/// HTTP Test 9: `GET /subjects/{subject_id}/sink-events` query params.
///
/// **Objective:** verify query param parsing and response shape.
///
/// **Setup:** server with a governance subject (SN 0 is enough to exercise
/// pagination and validation).
///
/// **Sequence:**
/// 1. `GET /subjects/<governance>/sink-events?from_sn=0&limit=100` -> 200.
/// 2. `GET /subjects/<governance>/sink-events?from_sn=0&limit=1` -> 200.
/// 3. `GET /subjects/<governance>/sink-events?from_sn=0&to_sn=0` -> 200.
/// 4. `GET /subjects/<governance>/sink-events?limit=0` -> 400.
/// 5. `GET /subjects/<governance>/sink-events?limit=1000` -> 200; `limit=1001` -> 400 (cap).
/// 6. `GET /subjects/<governance>/sink-events?from_sn=5&to_sn=3` -> 400.
/// 7. `GET /subjects/<missing>/sink-events` -> 404.
///
/// **Verifications:**
/// - Responses are `SinkEventsPage` with `from_sn`, `to_sn`, `limit`,
///   `next_sn`, `has_more`, `events`.
#[test(tokio::test)]
async fn test_http_get_sink_events_queries() {
    let (server, dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: false,
        always_accept: true,
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();

    let gov_body = create_governance(&client, &server, None).await;
    let governance_id = gov_body["subject_id"].as_str().unwrap().to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        gov_body["request_id"].as_str().unwrap(),
    )
    .await;

    assert_query(
        &client,
        &server,
        &governance_id,
        "?from_sn=0&limit=100",
        200,
    )
    .await;
    assert_query(&client, &server, &governance_id, "?from_sn=0&limit=1", 200)
        .await;
    assert_query(&client, &server, &governance_id, "?from_sn=0&to_sn=0", 200)
        .await;
    assert_query(&client, &server, &governance_id, "?limit=0", 400).await;
    assert_query(&client, &server, &governance_id, "?limit=1000", 200).await;
    assert_query(&client, &server, &governance_id, "?limit=1001", 400).await;
    assert_query(&client, &server, &governance_id, "?from_sn=5&to_sn=3", 400)
        .await;

    let (status, _body) = make_request(
        &client,
        &format!(
            "{}/subjects/{}/sink-events",
            server.url(""),
            unknown_subject_id()
        ),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, 404);

    server.shutdown().await;
    drop(dirs);
}

/// HTTP Test 10: `GET /subjects/{subject_id}/sink-events` permissions.
///
/// **Objective:** verify `node_sink:get`.
///
/// **Setup:** server with auth.
///
/// **Sequence:**
/// 1. User with role `sink` -> allowed (200/404).
/// 2. Users with roles `admin`, `sender`, `manager`, `data` -> 403.
#[test(tokio::test)]
async fn test_http_get_sink_events_permissions() {
    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");

    let unknown_subject = unknown_subject_id();

    // sink role should be allowed (will get 404 for the unknown subject).
    let sink_key =
        create_sink_user_and_login(&server, &client, &admin_key).await;
    let (status, _body) = make_request(
        &client,
        &format!(
            "{}/subjects/{}/sink-events",
            server.url(""),
            unknown_subject
        ),
        "GET",
        Some(&sink_key),
        None,
    )
    .await;
    assert!(
        status == 200 || status == 404,
        "sink role should be allowed to read sink events, got {}",
        status
    );

    for role in ["admin", "sender", "manager", "data"] {
        let role_id = get_role_id(&server, &client, &admin_key, role).await;
        let username = format!("{}_user", role);
        make_request(
            &client,
            &server.url("/admin/users"),
            "POST",
            Some(&admin_key),
            Some(json!({
                "username": username,
                "password": "TestPass123!",
                "is_superadmin": false,
                "role_ids": [role_id],
                "must_change_password": false
            })),
        )
        .await;
        let key = login(&server, &client, &username, "TestPass123!")
            .await
            .unwrap_or_else(|_| panic!("{} login", role));
        let (status, _body) = make_request(
            &client,
            &format!(
                "{}/subjects/{}/sink-events",
                server.url(""),
                unknown_subject
            ),
            "GET",
            Some(&key),
            None,
        )
        .await;
        assert_eq!(status, 403, "role {} should not access sink events", role);
    }
}

/// HTTP Test 11: role `sink` endpoints.
///
/// **Objective:** verify that the `sink` role can read and operate sink
/// endpoints (`node_sink:all`) while unmatched paths stay forbidden.
///
/// **Setup:** server with auth, sinks configured, user with role `sink`.
///
/// **Sequence:**
/// 1. `GET /sinks` -> 200.
/// 2. `GET /sinks/status` -> 200.
/// 3. `GET /subjects/<subject>/sink-events` -> 200/404.
/// 4. `POST /sinks/example-sink/unblock` -> 200.
/// 5. `POST /sinks/example-sink` -> 403 (unmatched route).
/// 6. `POST /sinks/replay` -> 200.
#[test(tokio::test)]
async fn test_http_sink_role_endpoints() {
    let sink = TestSink::start().await;
    let sinks_json = format!(
        r#"
        {{
            "target": {{ "type": "schema", "schema_id": "governance", "governance_id": null }},
            "servers": [{{ "server": "example-sink", "events": ["all"], "transport": {{ "type": "http", "url": "{}" }} }}]
        }}
        "#,
        sink.url()
    );

    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        sinks_config: Some(sinks_json),
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");
    let sink_key =
        create_sink_user_and_login(&server, &client, &admin_key).await;

    let unknown_subject = unknown_subject_id();

    for (method, path, expected) in [
        ("GET", "/sinks", 200u16),
        ("GET", "/sinks/status", 200),
        (
            "GET",
            &format!("/subjects/{}/sink-events", unknown_subject),
            404,
        ),
        ("POST", "/sinks/example-sink/unblock", 200),
        ("POST", "/sinks/example-sink", 403),
        ("POST", "/sinks/replay", 200),
    ] {
        let body = if path == "/sinks/replay" {
            Some(json!({
                "requests": [{ "sink": "example-sink", "subject_id": unknown_subject.clone(), "from_sn": 0 }]
            }))
        } else {
            None
        };
        let (status, _body) = make_request(
            &client,
            &server.url(path),
            method,
            Some(&sink_key),
            body,
        )
        .await;
        assert_eq!(
            status.as_u16(),
            expected,
            "{} {} returned unexpected status",
            method,
            path
        );
    }
}

/// HTTP Test 11b: the `sink` role includes the common self-management base.
///
/// **Objective:** verify that the `sink` role, like every other functional
/// role, can call `/me` and manage its own API keys (`user` / `user_api_key`
/// grants from migration 004).
///
/// **Sequence:**
/// 1. `GET /me` -> 200 with the expected username.
/// 2. `POST /me/api-keys` -> 201.
#[test(tokio::test)]
async fn test_http_sink_role_has_common_base() {
    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let admin_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .expect("admin login");
    let sink_key =
        create_sink_user_and_login(&server, &client, &admin_key).await;

    let (status, body) =
        make_request(&client, &server.url("/me"), "GET", Some(&sink_key), None)
            .await;
    assert_eq!(status, 200, "sink role must reach /me: {body}");
    assert_eq!(body["username"], "sink_user");

    let (status, body) = make_request(
        &client,
        &server.url("/me/api-keys"),
        "POST",
        Some(&sink_key),
        Some(json!({ "name": "sink_service", "is_management": false })),
    )
    .await;
    assert_eq!(
        status, 201,
        "sink role must manage its own API keys: {body}"
    );
}

/// HTTP Test 12: authentication is required for all sink endpoints.
///
/// **Objective:** verify that requests without `X-API-Key` return 401.
///
/// **Setup:** server with `enable_auth: true`.
///
/// **Sequence:** call every sink endpoint without a key.
///
/// **Verifications:** all return 401.
#[test(tokio::test)]
async fn test_http_sinks_require_auth() {
    let (server, _dirs) = TestServer::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        ..Default::default()
    })
    .await
    .expect("server should build");

    let client = Client::new();
    let dummy_subject = "JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI";

    for (method, path, body) in [
        ("GET", "/sinks", None),
        ("GET", "/sinks/status", None),
        (
            "GET",
            &format!("/subjects/{}/sink-events", dummy_subject),
            None,
        ),
        ("POST", "/sinks/example-sink/unblock", None),
        ("POST", "/sinks/example-sink", None),
        (
            "POST",
            "/sinks/replay",
            Some(json!({
                "requests": [{ "sink": "example-sink", "subject_id": dummy_subject, "from_sn": 0 }]
            })),
        ),
    ] {
        let (status, _body) =
            make_request(&client, &server.url(path), method, None, body).await;
        assert_eq!(
            status.as_u16(),
            401,
            "{} {} without auth should return 401",
            method,
            path
        );
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Add the `Example1` schema to an existing governance without adding a new
/// member. The node that created the governance is already a member named
/// `Owner`, so roles are assigned to it.
async fn add_example_schema(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    governance_id: &str,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/requests"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "fact",
                "data": {
                    "subject_id": governance_id,
                    "payload": {
                        "schemas": {
                            "add": [
                                {
                                    "id": "Example1",
                                    "contract": common::EXAMPLE_CONTRACT,
                                    "initial_value": {
                                        "one": 0,
                                        "two": 0,
                                        "three": 0
                                    }
                                }
                            ]
                        },
                        "policies": {
                            "governance": {
                                "change": {
                                    "evaluate": {
                                        "fixed": 1
                                    },
                                    "validate": {
                                        "fixed": 1
                                    },
                                    "approve": {
                                        "fixed": 1
                                    }
                                }
                            }
                        },
                        "roles": {
                            "schema": [
                                {
                                    "schema_id": "Example1",
                                    "add": {
                                        "evaluator": [{"name": "Owner", "namespace": []}],
                                        "validator": [{"name": "Owner", "namespace": []}],
                                        "witness": [{"name": "Owner", "namespace": []}],
                                        "creator": [{"name": "Owner", "namespace": [], "quantity": "infinity"}],
                                        "issuer": [{"name": "Owner", "namespace": []}]
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "schema fact failed: {body}");
    body
}

async fn assert_query(
    client: &Client,
    server: &TestServer,
    tracker_id: &str,
    query: &str,
    expected_status: u16,
) {
    let (status, body) = make_request(
        client,
        &format!(
            "{}/subjects/{}/sink-events{}",
            server.url(""),
            tracker_id,
            query
        ),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(
        status.as_u16(),
        expected_status,
        "query {} returned unexpected status: {:?}",
        query,
        body
    );
    if status.is_success() {
        assert!(body["from_sn"].is_u64() || body["from_sn"].is_null());
        assert!(body["to_sn"].is_u64() || body["to_sn"].is_null());
        assert!(body["limit"].is_u64() || body["limit"].is_null());
        assert!(body["next_sn"].is_u64() || body["next_sn"].is_null());
        assert!(body["has_more"].is_boolean());
        assert!(body["events"].is_array());
    }
}

/// Poll `GET /sinks/{name}` until the sink reports a non-null `blocked`
/// reason or the timeout expires.
async fn wait_for_sink_blocked(
    client: &Client,
    server: &TestServer,
    name: &str,
) {
    for _ in 0..40 {
        let (status, body) = make_request(
            client,
            &server.url(&format!("/sinks/{}", name)),
            "GET",
            None,
            None,
        )
        .await;
        if status == 200 {
            let sink: Value = serde_json::from_value(body).unwrap();
            if !sink["blocked"].is_null() {
                return;
            }
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
    panic!("sink {} did not become blocked in time", name);
}

/// Poll `GET /sinks/{name}` until the sink is registered (200) or the
/// timeout expires.
async fn wait_for_sink_visible(
    client: &Client,
    server: &TestServer,
    name: &str,
) {
    for _ in 0..40 {
        let (status, _body) = make_request(
            client,
            &server.url(&format!("/sinks/{}", name)),
            "GET",
            None,
            None,
        )
        .await;
        if status == 200 {
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(250)).await;
    }
    panic!("sink {} did not become visible in time", name);
}

async fn assert_filter(
    client: &Client,
    base: &str,
    query: &str,
    expected: &[&str],
) {
    let (status, body) =
        make_request(client, &format!("{}?{}", base, query), "GET", None, None)
            .await;
    assert_eq!(status, 200, "query {} failed", query);
    let filtered: Vec<Value> = serde_json::from_value(body)
        .expect("filtered sinks should be an array");
    let mut got: Vec<&str> = filtered
        .iter()
        .map(|s| s["name"].as_str().unwrap())
        .collect();
    let mut expected: Vec<&str> = expected.to_vec();
    got.sort();
    expected.sort();
    assert_eq!(got, expected, "query {} returned unexpected sinks", query);
}

async fn create_sink_user_and_login(
    server: &TestServer,
    client: &Client,
    admin_key: &str,
) -> String {
    create_role_user_and_login(server, client, admin_key, "sink", "sink_user")
        .await
}

async fn create_role_user_and_login(
    server: &TestServer,
    client: &Client,
    admin_key: &str,
    role: &str,
    username: &str,
) -> String {
    let role_id = get_role_id(server, client, admin_key, role).await;
    let (status, _body) = make_request(
        client,
        &server.url("/admin/users"),
        "POST",
        Some(admin_key),
        Some(json!({
            "username": username,
            "password": "TestPass123!",
            "is_superadmin": false,
            "role_ids": [role_id],
            "must_change_password": false
        })),
    )
    .await;
    assert_eq!(status, 201);
    login(server, client, username, "TestPass123!")
        .await
        .expect("role user login")
}

async fn get_role_id(
    server: &TestServer,
    client: &Client,
    admin_key: &str,
    name: &str,
) -> i64 {
    let (status, roles) = make_request(
        client,
        &server.url("/admin/roles"),
        "GET",
        Some(admin_key),
        None,
    )
    .await;
    assert_eq!(status, 200);
    roles
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == name)
        .map(|r| r["id"].as_i64().unwrap())
        .unwrap_or_else(|| panic!("role {} not found", name))
}

/// Create a role holding `node_sink:{action}`, a user with that role, and
/// return the user's management API key
async fn create_user_with_sink_action(
    server: &TestServer,
    client: &Client,
    admin_key: &str,
    username: &str,
    action: &str,
) -> String {
    let (status, body) = make_request(
        client,
        &server.url("/admin/roles"),
        "POST",
        Some(admin_key),
        Some(json!({
            "name": format!("{username}_role"),
            "description": "test role"
        })),
    )
    .await;
    assert_eq!(status, 201, "create role: {body}");
    let role_id = body["id"].as_i64().unwrap();

    let (status, body) = make_request(
        client,
        &server.url(&format!("/admin/roles/{role_id}/permissions")),
        "POST",
        Some(admin_key),
        Some(json!({
            "resource": "node_sink",
            "action": action,
            "allowed": true
        })),
    )
    .await;
    assert_eq!(status, 200, "set role permission: {body}");

    let (status, body) = make_request(
        client,
        &server.url("/admin/users"),
        "POST",
        Some(admin_key),
        Some(json!({
            "username": username,
            "password": "SinkPass123!",
            "role_ids": [role_id],
            "must_change_password": false
        })),
    )
    .await;
    assert_eq!(status, 201, "create user: {body}");

    login(server, client, username, "SinkPass123!")
        .await
        .expect("user login")
}
