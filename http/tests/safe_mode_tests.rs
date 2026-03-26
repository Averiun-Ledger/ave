use std::{collections::HashSet, time::Duration};

use ave_bridge::ave_common::identity::{KeyPair, keys::Ed25519Signer};
use futures::future::join_all;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use test_log::test;

use crate::common::{
    TestPersistencePaths, TestServer, TestServerOptions,
    add_example_schema_to_governance, add_governance_member_as_witness,
    add_tracker_fact_mod_one, create_governance, create_subject, login,
    make_request, server_auth_route_catalog, server_main_route_catalog,
    server_public_auth_route_catalog, transfer_subject, wait_request_finish,
};

pub mod common;

const MEMBER_PUBLIC_KEY: &str = "EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk";

fn safe_mode_main_route_classified(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("get", "/request")
            | ("get", "/request/{request_id}")
            | ("get", _)
            | ("post", "/request")
            | ("post", "/request-abort/{subject_id}")
            | ("post", "/update/{subject_id}")
            | ("post", "/manual-distribution/{subject_id}")
            | ("put", "/auth/{subject_id}")
            | ("delete", "/auth/{subject_id}")
            | ("delete", "/maintenance/subjects/{subject_id}")
            | ("patch", "/approval/{subject_id}")
    )
}

fn safe_mode_auth_route_classified(method: &str, path: &str) -> bool {
    matches!(
        (method, path),
        ("post", "/login")
            | ("get", _)
            | ("post", _)
            | ("put", _)
            | ("patch", _)
            | ("delete", _)
    )
}

#[derive(Debug)]
struct NodeFixture {
    governance_id: String,
    tracker_id: String,
    request_id: String,
}

#[derive(Debug)]
struct AuthFixture {
    user_id: i64,
    role_id: i64,
    api_key_id: String,
    api_key_name: String,
    usage_plan_id: String,
}

struct NodeEnv {
    server: TestServer,
    _dirs: Vec<tempfile::TempDir>,
    fixture: NodeFixture,
}

struct AuthEnv {
    server: TestServer,
    _dirs: Vec<tempfile::TempDir>,
    admin_api_key: String,
    fixture: AuthFixture,
}

#[derive(Debug)]
struct TrackerDeleteFixture {
    governance_id: String,
    tracker_id: String,
    second_tracker_id: Option<String>,
    auth_witness: String,
    transfer_owner: String,
}

struct TrackerDeleteEnv {
    server: TestServer,
    _dirs: Vec<tempfile::TempDir>,
    fixture: TrackerDeleteFixture,
}

#[derive(Debug)]
struct GovernanceDeleteFixture {
    governance_id: String,
    tracker_ids: Vec<String>,
    auth_witness: String,
}

struct GovernanceDeleteEnv {
    server: TestServer,
    _dirs: Vec<tempfile::TempDir>,
    fixture: GovernanceDeleteFixture,
}

async fn assert_safe_mode_blocked(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    method: &str,
    path: &str,
    body: Option<Value>,
) {
    let (status, body) =
        make_request(client, &server.url(path), method, api_key, body).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
    let error = body["error"]
        .as_str()
        .unwrap_or("missing error message")
        .to_ascii_lowercase();
    assert!(
        error.contains("safe mode"),
        "{path}: unexpected error body {body}"
    );
}

async fn wait_network_running(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
) {
    let mut last_status = StatusCode::INTERNAL_SERVER_ERROR;
    let mut last_body = Value::Null;
    for _ in 0..30 {
        let (status, body) = make_request(
            client,
            &server.url("/network-state"),
            "GET",
            api_key,
            None,
        )
        .await;
        let is_running = body
            .as_str()
            .is_some_and(|state| state.eq_ignore_ascii_case("running"));
        if status == StatusCode::OK && is_running {
            return;
        }
        last_status = status;
        last_body = body;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    panic!(
        "network did not reach running state in safe mode; last_status={last_status}, last_body={last_body}"
    );
}

async fn assert_events_endpoint_missing_or_empty(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) {
    let (status, body) = make_request(
        client,
        &server.url(&format!("/events/{subject_id}")),
        "GET",
        None,
        None,
    )
    .await;

    if status == StatusCode::OK {
        let events = body["events"].as_array().cloned().unwrap_or_default();
        assert!(events.is_empty(), "{body}");
    } else {
        assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    }
}

async fn assert_auth_endpoint_missing(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) {
    let (status, body) = make_request(
        client,
        &server.url(&format!("/auth/{subject_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

async fn assert_sink_events_endpoint_missing(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) {
    let (status, body) = make_request(
        client,
        &server.url(&format!("/sink-events/{subject_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");
}

async fn reopen_persisted_server_without_auth(
    persistence: TestPersistencePaths,
    safe_mode: bool,
    node_type: &str,
    node: Option<(String, u16)>,
) -> Option<TestServer> {
    TestServer::reopen_with_persistence(
        persistence,
        false,
        true,
        safe_mode,
        node_type,
        node,
    )
    .await
}

async fn assert_tracker_deleted_views(
    client: &Client,
    server: &TestServer,
    governance_id: &str,
    tracker_id: &str,
) {
    let (status, body) = make_request(
        client,
        &server.url(&format!("/state/{tracker_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = make_request(
        client,
        &server.url(&format!("/subjects/{governance_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let subjects = body.as_array().cloned().unwrap_or_default();
    assert!(subjects.iter().all(|item| item["subject_id"] != tracker_id));

    let (status, body) = make_request(
        client,
        &server.url("/pending-transfers"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let transfers = body.as_array().cloned().unwrap_or_default();
    assert!(
        transfers
            .iter()
            .all(|item| item["subject_id"] != tracker_id)
    );

    assert_sink_events_endpoint_missing(client, server, tracker_id).await;
    assert_events_endpoint_missing_or_empty(client, server, tracker_id).await;
    assert_auth_endpoint_missing(client, server, tracker_id).await;
}

async fn assert_governance_deleted_views(
    client: &Client,
    server: &TestServer,
    governance_id: &str,
) {
    let (status, body) = make_request(
        client,
        &server.url(&format!("/state/{governance_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = make_request(
        client,
        &server.url(&format!("/subjects/{governance_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) =
        make_request(client, &server.url("/subjects"), "GET", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let governances = body.as_array().cloned().unwrap_or_default();
    assert!(
        governances
            .iter()
            .all(|item| item["governance_id"] != governance_id)
    );

    assert_sink_events_endpoint_missing(client, server, governance_id).await;
    assert_events_endpoint_missing_or_empty(client, server, governance_id)
        .await;
    assert_auth_endpoint_missing(client, server, governance_id).await;
}

async fn accept_approval(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) {
    for _ in 0..120 {
        let (status, body) = make_request(
            client,
            &server.url(&format!("/approval/{subject_id}")),
            "GET",
            None,
            None,
        )
        .await;

        if status == StatusCode::OK && !body.is_null() {
            let (status, body) = make_request(
                client,
                &server.url(&format!("/approval/{subject_id}")),
                "PATCH",
                None,
                Some(json!("accepted")),
            )
            .await;
            assert_eq!(status, StatusCode::OK, "{body}");
            return;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }

    panic!(
        "approval for subject {subject_id} did not become available in time"
    );
}

async fn setup_node_env_without_auth() -> Option<NodeEnv> {
    let normal_options = TestServerOptions {
        enable_auth: false,
        always_accept: false,
        node: None,
        safe_mode: false,
        node_type: "Bootstrap".to_string(),
        persistence: None,
    };
    let (server, dirs) = TestServer::build_with_options(normal_options).await?;

    let client = Client::new();
    let pending_member_public_key =
        KeyPair::Ed25519(Ed25519Signer::generate().ok()?)
            .public_key()
            .to_string();

    let governance_body = create_governance(&client, &server, None).await;
    let governance_id = governance_body["subject_id"].as_str()?.to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        governance_body["request_id"].as_str()?,
    )
    .await;

    let schema_body = add_example_schema_to_governance(
        &client,
        &server,
        None,
        &governance_id,
        MEMBER_PUBLIC_KEY,
    )
    .await;
    accept_approval(&client, &server, &governance_id).await;
    wait_request_finish(
        &client,
        &server,
        None,
        schema_body["request_id"].as_str()?,
    )
    .await;

    let tracker_body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example1",
        "Traceability Subject",
    )
    .await;
    let tracker_id = tracker_body["subject_id"].as_str()?.to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        tracker_body["request_id"].as_str()?,
    )
    .await;

    let fact_body = add_governance_member_as_witness(
        &client,
        &server,
        None,
        &governance_id,
        &pending_member_public_key,
    )
    .await;
    let request_id = fact_body["request_id"].as_str()?.to_string();

    let (status, _) = make_request(
        &client,
        &server.url(&format!("/auth/{governance_id}")),
        "PUT",
        None,
        Some(json!([MEMBER_PUBLIC_KEY])),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    server.shutdown().await;

    let safe_options = TestServerOptions {
        enable_auth: false,
        always_accept: false,
        node: Some(("12D3KooWNode1".to_string(), 65535)),
        safe_mode: true,
        node_type: "Addressable".to_string(),
        persistence: Some(persistence),
    };
    let (safe_server, _) = TestServer::build_with_options(safe_options).await?;

    wait_network_running(&client, &safe_server, None).await;

    Some(NodeEnv {
        server: safe_server,
        _dirs: dirs,
        fixture: NodeFixture {
            governance_id,
            tracker_id,
            request_id,
        },
    })
}

async fn setup_auth_env_with_auth() -> Option<AuthEnv> {
    let normal_options = TestServerOptions {
        enable_auth: true,
        always_accept: true,
        node: None,
        safe_mode: false,
        node_type: "Bootstrap".to_string(),
        persistence: None,
    };
    let (server, dirs) = TestServer::build_with_options(normal_options).await?;

    let client = Client::new();
    let admin_api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .ok()?;

    let (status, body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "username": "safe_mode_user",
            "password": "SafeUser123!",
            "must_change_password": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let user_id = body["id"].as_i64()?;

    let (status, body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "name": "safe_mode_role",
            "description": "safe mode role"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let role_id = body["id"].as_i64()?;

    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/users/{user_id}/roles/{role_id}")),
        "POST",
        Some(&admin_api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/roles/{role_id}/permissions")),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "resource": "node_request",
            "action": "get",
            "allowed": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/users/{user_id}/permissions")),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "resource": "node_subject",
            "action": "get",
            "allowed": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let usage_plan_id = "safe-mode-plan";
    let (status, _) = make_request(
        &client,
        &server.url("/admin/usage-plans"),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "id": usage_plan_id,
            "name": "Safe Mode Plan",
            "description": "plan for safe mode tests",
            "monthly_events": 1000
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, body) = make_request(
        &client,
        &server.url("/me/api-keys"),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "name": "safe-mode-service-key",
            "description": "service key",
            "expires_in_seconds": 3600
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let api_key_id = body["key_info"]["id"].as_str()?.to_string();
    let api_key_name = body["key_info"]["name"].as_str()?.to_string();

    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/user/{user_id}")),
        "POST",
        Some(&admin_api_key),
        Some(json!({
            "name": "safe-mode-user-key",
            "description": "user key",
            "expires_in_seconds": 3600
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{api_key_id}/plan")),
        "PUT",
        Some(&admin_api_key),
        Some(json!({
            "plan_id": usage_plan_id
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    server.shutdown().await;

    let safe_options = TestServerOptions {
        enable_auth: true,
        always_accept: true,
        node: Some(("12D3KooWNode1".to_string(), 65535)),
        safe_mode: true,
        node_type: "Addressable".to_string(),
        persistence: Some(persistence),
    };
    let (safe_server, _) = TestServer::build_with_options(safe_options).await?;

    let safe_admin_api_key =
        login(&safe_server, &client, "admin", "AdminPass123!")
            .await
            .ok()?;

    wait_network_running(&client, &safe_server, Some(&safe_admin_api_key))
        .await;

    Some(AuthEnv {
        server: safe_server,
        _dirs: dirs,
        admin_api_key: safe_admin_api_key,
        fixture: AuthFixture {
            user_id,
            role_id,
            api_key_id,
            api_key_name,
            usage_plan_id: usage_plan_id.to_string(),
        },
    })
}

async fn setup_tracker_delete_env_without_auth(
    with_second_tracker: bool,
    tracker_fact_count: u32,
) -> Option<TrackerDeleteEnv> {
    let normal_options = TestServerOptions {
        enable_auth: false,
        always_accept: true,
        node: None,
        safe_mode: false,
        node_type: "Bootstrap".to_string(),
        persistence: None,
    };
    let (server, dirs) = TestServer::build_with_options(normal_options).await?;

    let client = Client::new();
    let auth_witness = KeyPair::Ed25519(Ed25519Signer::generate().ok()?)
        .public_key()
        .to_string();
    let transfer_owner = MEMBER_PUBLIC_KEY.to_string();

    let governance_body = create_governance(&client, &server, None).await;
    let governance_id = governance_body["subject_id"].as_str()?.to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        governance_body["request_id"].as_str()?,
    )
    .await;

    let schema_body = add_example_schema_to_governance(
        &client,
        &server,
        None,
        &governance_id,
        MEMBER_PUBLIC_KEY,
    )
    .await;
    wait_request_finish(
        &client,
        &server,
        None,
        schema_body["request_id"].as_str()?,
    )
    .await;

    let tracker_body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example1",
        "Deleteable Tracker",
    )
    .await;
    let tracker_id = tracker_body["subject_id"].as_str()?.to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        tracker_body["request_id"].as_str()?,
    )
    .await;

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/auth/{tracker_id}")),
        "PUT",
        None,
        Some(json!([auth_witness])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    for index in 0..tracker_fact_count.max(1) {
        let fact_body = add_tracker_fact_mod_one(
            &client,
            &server,
            None,
            &tracker_id,
            index + 1,
        )
        .await;
        wait_request_finish(
            &client,
            &server,
            None,
            fact_body["request_id"].as_str()?,
        )
        .await;
    }

    let transfer_body =
        transfer_subject(&client, &server, None, &tracker_id, &transfer_owner)
            .await;
    wait_request_finish(
        &client,
        &server,
        None,
        transfer_body["request_id"].as_str()?,
    )
    .await;

    let second_tracker_id = if with_second_tracker {
        let body = create_subject(
            &client,
            &server,
            None,
            &governance_id,
            "Example1",
            "Deleteable Tracker 2",
        )
        .await;
        let second_tracker_id = body["subject_id"].as_str()?.to_string();
        wait_request_finish(
            &client,
            &server,
            None,
            body["request_id"].as_str()?,
        )
        .await;

        let fact_body = add_tracker_fact_mod_one(
            &client,
            &server,
            None,
            &second_tracker_id,
            99,
        )
        .await;
        wait_request_finish(
            &client,
            &server,
            None,
            fact_body["request_id"].as_str()?,
        )
        .await;

        Some(second_tracker_id)
    } else {
        None
    };

    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    server.shutdown().await;

    let safe_options = TestServerOptions {
        enable_auth: false,
        always_accept: true,
        node: Some(("12D3KooWNode1".to_string(), 65535)),
        safe_mode: true,
        node_type: "Addressable".to_string(),
        persistence: Some(persistence),
    };
    let (safe_server, _) = TestServer::build_with_options(safe_options).await?;

    wait_network_running(&client, &safe_server, None).await;

    Some(TrackerDeleteEnv {
        server: safe_server,
        _dirs: dirs,
        fixture: TrackerDeleteFixture {
            governance_id,
            tracker_id,
            second_tracker_id,
            auth_witness,
            transfer_owner,
        },
    })
}

async fn setup_governance_delete_env_without_auth(
    tracker_count: usize,
) -> Option<GovernanceDeleteEnv> {
    let normal_options = TestServerOptions {
        enable_auth: false,
        always_accept: true,
        node: None,
        safe_mode: false,
        node_type: "Bootstrap".to_string(),
        persistence: None,
    };
    let (server, dirs) = TestServer::build_with_options(normal_options).await?;

    let client = Client::new();
    let auth_witness = KeyPair::Ed25519(Ed25519Signer::generate().ok()?)
        .public_key()
        .to_string();

    let governance_body = create_governance(&client, &server, None).await;
    let governance_id = governance_body["subject_id"].as_str()?.to_string();
    wait_request_finish(
        &client,
        &server,
        None,
        governance_body["request_id"].as_str()?,
    )
    .await;

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/auth/{governance_id}")),
        "PUT",
        None,
        Some(json!([auth_witness])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let schema_body = add_example_schema_to_governance(
        &client,
        &server,
        None,
        &governance_id,
        MEMBER_PUBLIC_KEY,
    )
    .await;
    wait_request_finish(
        &client,
        &server,
        None,
        schema_body["request_id"].as_str()?,
    )
    .await;

    let mut tracker_ids = Vec::new();
    for index in 0..tracker_count {
        let tracker_body = create_subject(
            &client,
            &server,
            None,
            &governance_id,
            "Example1",
            &format!("Governance Delete Tracker {}", index + 1),
        )
        .await;
        let tracker_id = tracker_body["subject_id"].as_str()?.to_string();
        wait_request_finish(
            &client,
            &server,
            None,
            tracker_body["request_id"].as_str()?,
        )
        .await;

        let fact_body = add_tracker_fact_mod_one(
            &client,
            &server,
            None,
            &tracker_id,
            (index as u32) + 1,
        )
        .await;
        wait_request_finish(
            &client,
            &server,
            None,
            fact_body["request_id"].as_str()?,
        )
        .await;

        tracker_ids.push(tracker_id);
    }

    let persistence = TestPersistencePaths::from_tempdirs(&dirs);
    server.shutdown().await;

    let safe_options = TestServerOptions {
        enable_auth: false,
        always_accept: true,
        node: Some(("12D3KooWNode1".to_string(), 65535)),
        safe_mode: true,
        node_type: "Addressable".to_string(),
        persistence: Some(persistence),
    };
    let (safe_server, _) = TestServer::build_with_options(safe_options).await?;

    wait_network_running(&client, &safe_server, None).await;

    Some(GovernanceDeleteEnv {
        server: safe_server,
        _dirs: dirs,
        fixture: GovernanceDeleteFixture {
            governance_id,
            tracker_ids,
            auth_witness,
        },
    })
}

#[test(tokio::test)]
async fn safe_mode_node_api_without_auth_keeps_reads_and_blocks_mutations() {
    let Some(env) = setup_node_env_without_auth().await else {
        return;
    };
    let client = Client::new();
    let fixture = &env.fixture;

    let query_paths = [
        "/config".to_string(),
        format!("/events/{}", fixture.governance_id),
        format!("/events/{}", fixture.tracker_id),
        format!("/events/{}/0", fixture.governance_id),
        format!("/events/{}/0", fixture.tracker_id),
        format!("/aborts/{}", fixture.governance_id),
        format!("/events-first-last/{}?quantity=1", fixture.governance_id),
    ];

    for path in query_paths {
        let (status, body) =
            make_request(&client, &env.server.url(&path), "GET", None, None)
                .await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }

    let (status, body) = make_request(
        &client,
        &env.server.url("/public-key"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let public_key = body.as_str().unwrap_or_default();
    assert!(!public_key.is_empty());

    let (status, body) =
        make_request(&client, &env.server.url("/peer-id"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK);
    let peer_id = body.as_str().unwrap_or_default();
    assert!(!peer_id.is_empty());

    let (status, body) = make_request(
        &client,
        &env.server.url("/network-state"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!("Running"));

    let (status, body) = make_request(
        &client,
        &env.server.url("/requests-in-manager"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body["handling"][fixture.governance_id.as_str()],
        json!(fixture.request_id)
    );
    assert_eq!(body["in_queue"], json!({}));

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/requests-in-manager/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["handling"], json!(fixture.request_id));
    assert!(body["in_queue"].is_null(), "{body}");

    let (status, body) = make_request(
        &client,
        &env.server.url("/pending-transfers"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!([]));

    let (status, body) =
        make_request(&client, &env.server.url("/auth"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK);
    let auth_subjects = body.as_array().cloned().unwrap_or_default();
    assert_eq!(auth_subjects, vec![json!(fixture.governance_id)]);

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/auth/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let witnesses = body.as_array().cloned().unwrap_or_default();
    assert_eq!(witnesses, vec![json!(MEMBER_PUBLIC_KEY)]);

    let (status, body) =
        make_request(&client, &env.server.url("/subjects"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK);
    let govs = body.as_array().cloned().unwrap_or_default();
    assert_eq!(govs.len(), 1, "{body}");
    assert_eq!(govs[0]["governance_id"], json!(fixture.governance_id));
    assert_eq!(govs[0]["name"], json!("Governance"));
    assert_eq!(govs[0]["active"], json!(true));

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/subjects/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let subjects = body.as_array().cloned().unwrap_or_default();
    assert_eq!(subjects.len(), 1, "{body}");
    assert_eq!(subjects[0]["subject_id"], json!(fixture.tracker_id));
    assert_eq!(subjects[0]["schema_id"], json!("Example1"));

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!(
            "/subjects/{}?schema_id=Example1",
            fixture.governance_id
        )),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let subjects = body.as_array().cloned().unwrap_or_default();
    assert_eq!(subjects.len(), 1, "{body}");
    assert_eq!(subjects[0]["subject_id"], json!(fixture.tracker_id));

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/approval/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["state"], json!("pending"));
    assert_eq!(body["request"]["subject_id"], json!(fixture.governance_id));

    let (status, body) =
        make_request(&client, &env.server.url("/approval"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK);
    let approvals = body.as_array().cloned().unwrap_or_default();
    assert_eq!(approvals.len(), 1, "{body}");
    assert_eq!(approvals[0]["state"], json!("pending"));

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/state/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["subject_id"], json!(fixture.governance_id));
    assert_eq!(body["schema_id"], json!("governance"));

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/state/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["subject_id"], json!(fixture.tracker_id));
    assert_eq!(body["governance_id"], json!(fixture.governance_id));

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/sink-events/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["events"].is_array(), "{body}");

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/sink-events/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["events"].is_array(), "{body}");

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.tracker_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let message = body.as_str().unwrap_or_default().to_ascii_lowercase();
    assert!(message.contains("tracker deleted successfully"), "{body}");

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/state/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/subjects/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let subjects = body.as_array().cloned().unwrap_or_default();
    assert!(subjects.is_empty(), "{body}");

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.tracker_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.governance_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        body.as_str()
            .unwrap_or_default()
            .contains("Governance deleted successfully")
    );

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.governance_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("not found")
    );

    let (status, body) =
        make_request(&client, &env.server.url("/config"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["node"]["safe_mode"], json!(true));
    assert_eq!(body["node"]["network"]["node_type"], json!("Addressable"));

    let (status, body) =
        make_request(&client, &env.server.url("/request"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("request tracking is unavailable")
    );

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/request/{}", fixture.request_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("request tracking is unavailable")
    );

    let metrics_response = client
        .get(env.server.url("/metrics"))
        .send()
        .await
        .expect("metrics request");
    assert_eq!(metrics_response.status(), StatusCode::OK);

    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "POST",
        "/request",
        Some(json!({
            "request": {
                "event": "create",
                "data": {
                    "name": "Blocked Governance",
                    "description": "Should fail in safe mode",
                    "schema_id": "governance"
                }
            }
        })),
    )
    .await;
    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "PATCH",
        &format!("/approval/{}", fixture.governance_id),
        Some(json!("accepted")),
    )
    .await;
    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "POST",
        &format!("/request-abort/{}", fixture.governance_id),
        None,
    )
    .await;
    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "PUT",
        &format!("/auth/{}", fixture.governance_id),
        Some(json!(["EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk"])),
    )
    .await;
    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "DELETE",
        &format!("/auth/{}", fixture.governance_id),
        None,
    )
    .await;
    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "POST",
        &format!("/update/{}", fixture.governance_id),
        None,
    )
    .await;
    assert_safe_mode_blocked(
        &client,
        &env.server,
        None,
        "POST",
        &format!("/manual-distribution/{}", fixture.governance_id),
        None,
    )
    .await;
}

#[test(tokio::test)]
async fn safe_mode_tracker_delete_removes_tracker_from_views_and_query_data() {
    let Some(env) = setup_tracker_delete_env_without_auth(false, 1).await
    else {
        return;
    };
    let client = Client::new();
    let fixture = &env.fixture;

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/state/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["subject_id"], json!(fixture.tracker_id));

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/subjects/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let subjects = body.as_array().cloned().unwrap_or_default();
    assert!(
        subjects
            .iter()
            .any(|item| item["subject_id"] == fixture.tracker_id)
    );

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/events/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let events = body["events"].as_array().cloned().unwrap_or_default();
    assert!(!events.is_empty(), "{body}");

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/sink-events/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "{body}"
    );

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/auth/{}", fixture.tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let witnesses = body.as_array().cloned().unwrap_or_default();
    assert!(
        witnesses
            .iter()
            .any(|value| value == &json!(fixture.auth_witness))
    );

    let (status, body) = make_request(
        &client,
        &env.server.url("/pending-transfers"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let transfers = body.as_array().cloned().unwrap_or_default();
    assert!(
        transfers
            .iter()
            .any(|item| item["subject_id"] == fixture.tracker_id)
    );
    assert!(
        transfers
            .iter()
            .any(|item| item["new_owner"] == fixture.transfer_owner)
    );

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.tracker_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_tracker_deleted_views(
        &client,
        &env.server,
        &fixture.governance_id,
        &fixture.tracker_id,
    )
    .await;

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/state/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["subject_id"], json!(fixture.governance_id));

    let persistence = TestPersistencePaths::from_tempdirs(&env._dirs);
    let governance_id = fixture.governance_id.clone();
    let tracker_id = fixture.tracker_id.clone();
    env.server.shutdown().await;

    let Some(server) = reopen_persisted_server_without_auth(
        persistence,
        false,
        "Bootstrap",
        None,
    )
    .await
    else {
        return;
    };
    let client = Client::new();

    assert_tracker_deleted_views(&client, &server, &governance_id, &tracker_id)
        .await;

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/state/{governance_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["subject_id"], json!(governance_id));

    server.shutdown().await;
}

#[test(tokio::test)]
async fn safe_mode_tracker_delete_clears_pending_transfer_and_serializes_global_delete()
 {
    let Some(env) = setup_tracker_delete_env_without_auth(true, 6).await else {
        return;
    };
    let client = Client::new();
    let fixture = &env.fixture;
    let second_tracker_id =
        fixture.second_tracker_id.clone().expect("second tracker");

    let (status, body) = make_request(
        &client,
        &env.server.url("/pending-transfers"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let transfers = body.as_array().cloned().unwrap_or_default();
    assert!(
        transfers
            .iter()
            .any(|item| item["subject_id"] == fixture.tracker_id)
    );
    assert!(
        transfers
            .iter()
            .any(|item| item["new_owner"] == fixture.transfer_owner)
    );

    let delete_urls: Vec<_> = (0..12)
        .map(|index| {
            let subject_id = if index % 2 == 0 {
                fixture.tracker_id.clone()
            } else {
                second_tracker_id.clone()
            };
            env.server
                .url(&format!("/maintenance/subjects/{subject_id}"))
        })
        .collect();

    let responses =
        join_all(
            delete_urls.into_iter().map(|url| {
                let client = client.clone();
                async move {
                    client.delete(url).send().await.expect("delete request")
                }
            }),
        )
        .await;

    let statuses: Vec<_> =
        responses.iter().map(|response| response.status()).collect();
    assert!(
        statuses.contains(&StatusCode::OK),
        "expected at least one delete to succeed, got {statuses:?}"
    );
    assert!(
        statuses.contains(&StatusCode::CONFLICT),
        "expected at least one delete to be rejected while another is in progress, got {statuses:?}"
    );

    let conflict_body = responses
        .into_iter()
        .find(|response| response.status() == StatusCode::CONFLICT)
        .expect("conflict response")
        .json::<Value>()
        .await
        .expect("conflict body");
    assert!(
        conflict_body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("deletion already in progress"),
        "{conflict_body}"
    );

    let (status, body) = make_request(
        &client,
        &env.server.url("/pending-transfers"),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let transfers = body.as_array().cloned().unwrap_or_default();
    assert!(
        transfers
            .iter()
            .all(|item| item["subject_id"] != fixture.tracker_id)
    );
}

#[test(tokio::test)]
async fn safe_mode_governance_delete_lists_pending_trackers() {
    let Some(env) = setup_governance_delete_env_without_auth(3).await else {
        return;
    };
    let client = Client::new();
    let fixture = &env.fixture;

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/state/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["subject_id"], json!(fixture.governance_id));

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/subjects/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let subjects = body.as_array().cloned().unwrap_or_default();
    assert_eq!(subjects.len(), fixture.tracker_ids.len(), "{body}");
    for tracker_id in &fixture.tracker_ids {
        assert!(
            subjects
                .iter()
                .any(|item| item["subject_id"] == *tracker_id)
        );
    }

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/events/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "{body}"
    );

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/sink-events/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body["events"]
            .as_array()
            .cloned()
            .unwrap_or_default()
            .is_empty(),
        "{body}"
    );

    let (status, body) = make_request(
        &client,
        &env.server.url(&format!("/auth/{}", fixture.governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let witnesses = body.as_array().cloned().unwrap_or_default();
    assert!(
        witnesses
            .iter()
            .any(|value| value == &json!(fixture.auth_witness))
    );

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.governance_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("still has trackers associated"),
        "{body}"
    );

    let returned_trackers = body["trackers"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .into_iter()
        .filter_map(|value| value.as_str().map(str::to_owned))
        .collect::<HashSet<_>>();
    let expected_trackers =
        fixture.tracker_ids.iter().cloned().collect::<HashSet<_>>();
    assert_eq!(returned_trackers, expected_trackers, "{body}");
}

#[test(tokio::test)]
async fn safe_mode_governance_delete_removes_views_after_trackers_are_deleted()
{
    let Some(env) = setup_governance_delete_env_without_auth(3).await else {
        return;
    };
    let client = Client::new();
    let fixture = &env.fixture;

    let (status, body) =
        make_request(&client, &env.server.url("/subjects"), "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let governances = body.as_array().cloned().unwrap_or_default();
    assert!(
        governances
            .iter()
            .any(|item| item["governance_id"] == fixture.governance_id)
    );

    for tracker_id in &fixture.tracker_ids {
        let (status, body) = make_request(
            &client,
            &env.server
                .url(&format!("/maintenance/subjects/{tracker_id}")),
            "DELETE",
            None,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{tracker_id}: {body}");
    }

    let (status, body) = make_request(
        &client,
        &env.server
            .url(&format!("/maintenance/subjects/{}", fixture.governance_id)),
        "DELETE",
        None,
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let message = body.as_str().unwrap_or_default().to_ascii_lowercase();
    assert!(
        message.contains("governance deleted successfully"),
        "{body}"
    );

    assert_governance_deleted_views(
        &client,
        &env.server,
        &fixture.governance_id,
    )
    .await;

    let persistence = TestPersistencePaths::from_tempdirs(&env._dirs);
    let governance_id = fixture.governance_id.clone();
    env.server.shutdown().await;

    let Some(server) = reopen_persisted_server_without_auth(
        persistence,
        false,
        "Bootstrap",
        None,
    )
    .await
    else {
        return;
    };
    let client = Client::new();

    assert_governance_deleted_views(&client, &server, &governance_id).await;

    server.shutdown().await;
}

#[test(tokio::test)]
async fn safe_mode_auth_api_with_auth_keeps_reads_and_blocks_mutations() {
    let Some(env) = setup_auth_env_with_auth().await else {
        return;
    };
    let client = Client::new();
    let api_key = env.admin_api_key.as_str();
    let fixture = &env.fixture;

    let read_paths = [
        "/admin/users".to_string(),
        format!("/admin/users/{}", fixture.user_id),
        format!("/admin/users/{}/permissions", fixture.user_id),
        "/admin/roles".to_string(),
        format!("/admin/roles/{}", fixture.role_id),
        format!("/admin/roles/{}/permissions", fixture.role_id),
        format!("/admin/api-keys/user/{}", fixture.user_id),
        "/admin/api-keys".to_string(),
        format!("/admin/api-keys/{}", fixture.api_key_id),
        format!("/admin/api-keys/{}/quota", fixture.api_key_id),
        "/admin/usage-plans".to_string(),
        format!("/admin/usage-plans/{}", fixture.usage_plan_id),
        "/admin/resources".to_string(),
        "/admin/actions".to_string(),
        "/admin/audit-logs".to_string(),
        "/admin/audit-logs/stats".to_string(),
        "/admin/rate-limits/stats".to_string(),
        "/admin/config".to_string(),
        "/me".to_string(),
        "/me/permissions".to_string(),
        "/me/permissions/detailed".to_string(),
        "/me/api-keys".to_string(),
    ];

    for path in read_paths {
        let (status, body) = make_request(
            &client,
            &env.server.url(&path),
            "GET",
            Some(api_key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{path}: {body}");
    }

    let (status, body) = make_request(
        &client,
        &env.server.url("/login"),
        "POST",
        None,
        Some(json!({
            "username": "admin",
            "password": "AdminPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert!(body["api_key"].as_str().is_some());

    let blocked = [
        (
            None,
            "POST",
            "/change-password".to_string(),
            Some(json!({
                "username": "admin",
                "current_password": "AdminPass123!",
                "new_password": "AnotherPass123!"
            })),
        ),
        (
            Some(api_key),
            "POST",
            "/admin/users".to_string(),
            Some(json!({
                "username": "blocked_user",
                "password": "Blocked123!",
                "must_change_password": false
            })),
        ),
        (
            Some(api_key),
            "PUT",
            format!("/admin/users/{}", fixture.user_id),
            Some(json!({"is_active": false})),
        ),
        (
            Some(api_key),
            "DELETE",
            format!("/admin/users/{}", fixture.user_id),
            None,
        ),
        (
            Some(api_key),
            "POST",
            format!("/admin/users/{}/password", fixture.user_id),
            Some(json!({"password": "BlockedReset123!"})),
        ),
        (
            Some(api_key),
            "POST",
            format!(
                "/admin/users/{}/roles/{}",
                fixture.user_id, fixture.role_id
            ),
            None,
        ),
        (
            Some(api_key),
            "DELETE",
            format!(
                "/admin/users/{}/roles/{}",
                fixture.user_id, fixture.role_id
            ),
            None,
        ),
        (
            Some(api_key),
            "POST",
            format!("/admin/users/{}/permissions", fixture.user_id),
            Some(json!({
                "resource": "node_subject",
                "action": "delete",
                "allowed": false
            })),
        ),
        (
            Some(api_key),
            "DELETE",
            format!(
                "/admin/users/{}/permissions?resource=node_subject&action=get",
                fixture.user_id
            ),
            None,
        ),
        (
            Some(api_key),
            "POST",
            "/admin/roles".to_string(),
            Some(json!({"name": "blocked_role", "description": "blocked"})),
        ),
        (
            Some(api_key),
            "PUT",
            format!("/admin/roles/{}", fixture.role_id),
            Some(json!({"description": "blocked update"})),
        ),
        (
            Some(api_key),
            "DELETE",
            format!("/admin/roles/{}", fixture.role_id),
            None,
        ),
        (
            Some(api_key),
            "POST",
            format!("/admin/roles/{}/permissions", fixture.role_id),
            Some(json!({
                "resource": "node_request",
                "action": "post",
                "allowed": true
            })),
        ),
        (
            Some(api_key),
            "DELETE",
            format!(
                "/admin/roles/{}/permissions?resource=node_request&action=get",
                fixture.role_id
            ),
            None,
        ),
        (
            Some(api_key),
            "POST",
            format!("/admin/api-keys/user/{}", fixture.user_id),
            Some(json!({
                "name": "blocked-key",
                "description": "blocked",
                "expires_in_seconds": 3600
            })),
        ),
        (
            Some(api_key),
            "DELETE",
            format!("/admin/api-keys/{}", fixture.api_key_id),
            Some(json!({"reason": "blocked"})),
        ),
        (
            Some(api_key),
            "POST",
            format!("/admin/api-keys/{}/rotate", fixture.api_key_id),
            Some(json!({
                "name": "rotated",
                "description": "blocked rotate",
                "expires_in_seconds": 3600,
                "reason": "blocked"
            })),
        ),
        (
            Some(api_key),
            "PUT",
            format!("/admin/api-keys/{}/plan", fixture.api_key_id),
            Some(json!({"plan_id": fixture.usage_plan_id})),
        ),
        (
            Some(api_key),
            "POST",
            format!("/admin/api-keys/{}/quota-extensions", fixture.api_key_id),
            Some(json!({"extra_events": 100, "reason": "blocked"})),
        ),
        (
            Some(api_key),
            "POST",
            "/admin/usage-plans".to_string(),
            Some(json!({
                "id": "blocked-plan",
                "name": "blocked plan",
                "description": "blocked",
                "monthly_events": 100
            })),
        ),
        (
            Some(api_key),
            "PUT",
            format!("/admin/usage-plans/{}", fixture.usage_plan_id),
            Some(json!({"description": "blocked update"})),
        ),
        (
            Some(api_key),
            "DELETE",
            format!("/admin/usage-plans/{}", fixture.usage_plan_id),
            None,
        ),
        (
            Some(api_key),
            "PUT",
            "/admin/config/auth.rate_limit.max_requests".to_string(),
            Some(json!({"value": 9999})),
        ),
        (
            Some(api_key),
            "POST",
            "/me/api-keys".to_string(),
            Some(json!({
                "name": "another-key",
                "description": "blocked",
                "expires_in_seconds": 3600
            })),
        ),
        (
            Some(api_key),
            "DELETE",
            format!("/me/api-keys/{}", fixture.api_key_name),
            None,
        ),
    ];

    for (key, method, path, body) in blocked {
        assert_safe_mode_blocked(
            &client,
            &env.server,
            key,
            method,
            &path,
            body,
        )
        .await;
    }
}

#[test]
fn safe_mode_tests_cover_all_http_route_catalogs() {
    let catalog_main = server_main_route_catalog();
    let unclassified_main: Vec<_> = catalog_main
        .into_iter()
        .filter(|(method, path)| !safe_mode_main_route_classified(method, path))
        .collect();
    assert!(
        unclassified_main.is_empty(),
        "Safe mode main routes without policy classification: {unclassified_main:?}"
    );

    let mut catalog_auth = server_auth_route_catalog();
    catalog_auth.extend(server_public_auth_route_catalog());
    let unclassified_auth: Vec<_> = catalog_auth
        .into_iter()
        .filter(|(method, path)| !safe_mode_auth_route_classified(method, path))
        .collect();
    assert!(
        unclassified_auth.is_empty(),
        "Safe mode auth routes without policy classification: {unclassified_auth:?}"
    );
}
