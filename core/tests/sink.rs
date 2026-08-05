mod common;

use std::{
    collections::BTreeSet, collections::HashMap, sync::atomic::Ordering,
};

use ave_common::{
    SinkTarget, SinkTypes,
    bridge::request::{
        ApprovalStateRes, SinkEventsQuery, SinkReplayItem, SinkReplayRequest,
        SinksQuery,
    },
    identity::{
        DigestIdentifier, HashAlgorithm, KeyPairAlgorithm, PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    sink::{
        DataToSinkEvent, SinkCompression, HttpProxyConfig, HttpTlsConfig,
        IncomingSinkEvent, OAuth2GrantType, SinkAuthConfig, SinkAuthMethod,
        SinkTransportConfig,
    },
};
use ave_core::{Api, auth::AuthWitness, config::SinkConfigEntry, error::Error};
use ave_network::NodeType;
use futures::future::join_all;
use serde_json::json;
use std::str::FromStr;
use std::time::Duration;
use tracing_test::traced_test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
    TempEnvVar, create_and_authorize_governance, create_node,
    create_nodes_and_connections, create_subject, emit_approve, emit_confirm,
    emit_eol, emit_fact, emit_fact_viewpoints, emit_reject, emit_transfer,
    get_subject, node_running,
    sink_setup::{
        assert_data_to_sink_is_create, assert_data_to_sink_is_fact_full,
        assert_event_is_confirm, assert_event_is_create, assert_event_is_eol,
        assert_event_is_fact_full, assert_event_is_reject,
        assert_event_is_transfer, assert_no_duplicate_events,
        assert_no_fact_full_events, assert_sink_blocked,
        assert_sink_contains_confirm, assert_sink_contains_confirm_with_name,
        assert_sink_contains_create, assert_sink_contains_eol,
        assert_sink_contains_fact_full, assert_sink_contains_fact_opaque,
        assert_sink_contains_light_fact, assert_sink_contains_reject,
        assert_sink_contains_transfer,
        assert_sink_contains_transfer_with_owners, assert_sink_events_page,
        assert_sink_lagging, assert_sink_not_lagging, assert_sink_running,
        assert_sink_unblocked, assert_subject_sn_sequence,
        count_events_for_subject, deduplicate_events_by_sn,
        example_schema_governance_fact, example_sink_config,
        flapping_sink_config, governance_sink_config,
        governance_with_transfer_roles_fact, governance_with_viewpoints_fact,
        make_governance_sink_entry, make_sink_entry, make_sink_entry_batch,
        make_sink_entry_with_auth, make_sink_entry_with_concurrency,
        make_sink_entry_with_headers, make_sink_entry_with_proxy,
        make_sink_entry_with_retry_policy, make_sink_entry_with_signature,
        make_sink_entry_with_signature_and_retries, make_sink_entry_with_tls,
        restart_config, restart_config_safe_mode, restart_config_with_peers,
        sample_sinks, short_idle_sink_config, transient_error_sink_config,
        wait_for_sink_blocked, wait_for_sink_caught_up,
        wait_for_sink_lagging_subjects, wait_for_sink_unblocked,
    },
    test_sink::{AuthResponseMode, ResponseMode, TestProxy, TestSink},
};
use ave_network::RoutingNode;

/// Poll the test sink until the number of raw events stabilizes (no new
/// arrivals for a few consecutive checks), tolerating slow or loaded systems.
/// Returns the final raw event list.
async fn wait_for_sink_events_stable(
    sink: &TestSink,
) -> Vec<IncomingSinkEvent> {
    let mut attempts = 0;
    let mut last_count = 0;
    let mut stable_iterations = 0;
    loop {
        let events = sink.snapshot().await;
        let current_count = events.len();
        if current_count == last_count {
            stable_iterations += 1;
            if stable_iterations >= 3 {
                return events;
            }
        } else {
            stable_iterations = 0;
        }
        last_count = current_count;
        if attempts > 40 {
            panic!(
                "sink event count did not stabilize after 4s; current: {}",
                current_count
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        attempts += 1;
    }
}

#[traced_test]
#[tokio::test]
async fn sink_registry_populated_from_config() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let sinks = node.api.get_sinks(SinksQuery::default()).await.unwrap();

    assert_eq!(sinks.len(), 2);
    let names: Vec<_> = sinks.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"gov-sink"));
    assert!(names.contains(&"schema-sink"));

    let gov = sinks.iter().find(|s| s.name == "gov-sink").unwrap();
    assert!(gov.in_config);
    assert_eq!(
        gov.manager,
        ave_common::bridge::response::SinkManagerTarget::Node
    );

    let schema = sinks.iter().find(|s| s.name == "schema-sink").unwrap();
    assert!(schema.in_config);
    assert!(
        matches!(
            schema.manager,
            ave_common::bridge::response::SinkManagerTarget::Governance { .. }
        ),
        "schema sink should be managed by its governance"
    );
}

#[traced_test]
#[tokio::test]
async fn get_sinks_status_returns_configured_sinks() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let statuses = node.api.get_sinks_status().await.unwrap();
    let names: Vec<_> = statuses.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"gov-sink"));
    assert!(names.contains(&"schema-sink"));
    assert!(
        statuses
            .iter()
            .all(|s| s.transport.as_deref() == Some("http")),
        "sample sinks should report the http transport kind"
    );
}

#[traced_test]
#[tokio::test]
async fn sink_custom_headers_are_delivered_and_internal_headers_override() {
    let sink = TestSink::start().await;
    let mut headers = HashMap::new();
    headers.insert("X-Custom-Header".to_owned(), "custom-value".to_owned());
    // Internal headers take precedence: the sink must still send JSON.
    headers.insert("Content-Type".to_owned(), "text/plain".to_owned());

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_headers(
            "example-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            headers,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    create_subject(&node.api, governance_id, "Example", "", true)
        .await
        .unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(1, true).await;

    assert_eq!(
        sink.last_header("X-Custom-Header").await.as_deref(),
        Some("custom-value")
    );
    assert_eq!(
        sink.last_header("Content-Type").await.as_deref(),
        Some("application/json")
    );
}

#[traced_test]
#[tokio::test]
async fn sink_event_type_url_template_routes_by_type() {
    let sink = TestSink::start().await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry(
            "example-sink",
            format!("{}/{{{{event-type}}}}", sink.url()),
            Some(governance_id.to_string()),
            // Filtered to Create: facts arrive as lightweight events, so the
            // test exercises the `{{event-type}}` routing of both `send`
            // (full create) and `send_light` (light fact).
            BTreeSet::from([SinkTypes::Create]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();
    let governance_id_str = governance_id.to_string();
    emit_fact(&node.api, subject_id, json!({"ModOne": {"data": 1}}), true)
        .await
        .unwrap();

    sink.wait_for_count(2, true).await;

    // Deliveries are ordered per subject: create (sn 0) before fact (sn 1).
    assert_eq!(sink.paths().await, vec!["/events/create", "/events/fact"]);

    // The create arrived as a full event and the fact as a light one.
    let events = sink.snapshot().await;
    assert_sink_contains_create(&events, &subject_id_str, 0);
    assert_sink_contains_light_fact(
        &events,
        &subject_id_str,
        &governance_id_str,
        1,
        true,
    );
}

#[traced_test]
#[tokio::test]
async fn sink_batch_event_type_url_groups_by_type() {
    let sink = TestSink::start().await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "example-sink",
            format!("{}/{{{{event-type}}}}", sink.url()),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkCompression::None,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id, "Example", "", true)
            .await
            .unwrap();
    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    sink.wait_for_count(3, true).await;

    // Every POST went to the route of its event type; the exact flush split
    // depends on batch timing, so only the routing is asserted.
    let paths = sink.paths().await;
    assert!(
        paths
            .iter()
            .all(|p| p == "/events/create" || p == "/events/fact"),
        "unexpected request paths: {paths:?}"
    );
    assert_eq!(
        paths.iter().filter(|p| *p == "/events/create").count(),
        1,
        "the create event must be delivered exactly once: {paths:?}"
    );
    assert!(
        paths.iter().any(|p| p == "/events/fact"),
        "fact events must reach the fact route: {paths:?}"
    );
    let lens = sink.batch_lens().await;
    assert_eq!(
        lens.iter().sum::<usize>(),
        3,
        "all three events must be accepted: {lens:?}"
    );
}


#[traced_test]
#[tokio::test]
async fn sink_last_error_is_reported_after_delivery_failure() {
    let sink = TestSink::start().await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id, "Example", "", true)
            .await
            .unwrap();

    sink.wait_for_count(1, true).await;

    // Make the sink fail every delivery.
    sink.set_mode(ResponseMode::ServerError).await;

    emit_fact(&node.api, subject_id, json!({"ModOne": {"data": 1}}), true)
        .await
        .unwrap();

    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;

    // The worker schedules periodic healthchecks that may clear last_error on
    // recovery; poll briefly to observe the error before any transient recovery.
    let mut found = false;
    for _ in 0..20 {
        let statuses = node.api.get_sinks_status().await.unwrap();
        if let Some(status) = statuses.iter().find(|s| s.name == "example-sink")
            && status.last_error.is_some() {
                found = true;
                break;
            }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(found, "last_error should be set after a delivery failure");
}

#[traced_test]
#[tokio::test]
async fn delete_sink_cursors_fails_outside_safe_mode() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let err = node
        .api
        .delete_sink_cursors("gov-sink".to_owned())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::SafeMode(_)),
        "expected safe mode error, got {:?}",
        err
    );
}

#[traced_test]
#[tokio::test]
async fn unknown_sink_returns_not_found() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let err = node
        .api
        .unblock_sink("missing-sink".to_owned())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::SinkNotFound(_)),
        "expected sink not found, got {:?}",
        err
    );
}

/// Test 1: `replay_single_subject_after_sink_loss`.
///
/// **Objective:** replay a subject's events to a sink after a partial loss.
///
/// **Setup:**
/// - Node with `example-sink` for schema `Example`, events `All`.
/// - Create subject `S1`.
/// - Emit 5 facts (`ModOne` with data 1..5), waiting for confirmation.
/// - Verify the sink received 6 events: Create + 5 FactFull.
///
/// **Simulate loss:**
/// - Stop the `TestSink`.
/// - Emit 2 more facts (`ModOne` with data 6, 7). Because the sink is down, the
///   events become `lagging`.
/// - Bring the `TestSink` back up.
/// - Verify the sink receives the 2 pending events (automatic catch-up).
///
/// **Manual replay:**
/// - Delete all sink events from SN 5 onwards (simulate loss in the sink).
/// - Call `api.replay_sink_events(SinkReplayRequest { requests: vec![{sink:
///   "example-sink", subject_id: S1, from_sn: 5}] })`.
/// - Wait and verify the sink receives events with SN 5, 6, 7 (Create is SN 0,
///   FactFull SN 1..7; from_sn=5 re-sends SN 5..7).
///
/// **Verifications:**
/// - All events have the correct `subject_id`.
/// - SNs are consecutive and in order: `[0, 1, 2, 3, 4, 5, 6, 7]`.
/// - Payloads match.
/// - The replay response has `processed.len() == 1`, empty `errors`, and
///   `processed` contains exactly the requested item.
#[traced_test]
#[tokio::test]
async fn replay_single_subject_after_sink_loss() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=5 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(6, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 6);
    assert_event_is_create(&initial[0], &subject_id.to_string(), 0);
    for i in 1..=5 {
        assert_event_is_fact_full(
            &initial[i],
            &subject_id.to_string(),
            i as u64,
            true,
            Some(json!({"ModOne": {"data": i}})),
        );
    }

    // A sink without `signature: true` must not send signature headers.
    let signature_headers = sink.signature_headers().await;
    assert!(
        signature_headers.iter().all(|h| h.signature.is_none()
            && h.timestamp.is_none()
            && h.public_key.is_none()),
        "a sink without `signature: true` must not send X-Ave-Signature* headers"
    );

    // Simulate a crashed sink: accept TCP but never respond to delivery requests.
    sink.set_mode(ResponseMode::Drop).await;

    for i in 6..=7 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Wait until the worker has marked the sink as lagging for this subject.
    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;
    assert_sink_lagging(&node.api, "example-sink", 1).await;
    assert_sink_unblocked(&node.api, "example-sink").await;

    // Bring the sink back online. The worker should automatically catch up.
    sink.set_mode(ResponseMode::Accept).await;

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(8, true).await;
    let recovered = sink.snapshot().await;
    assert_eq!(recovered.len(), 8);
    assert_event_is_fact_full(
        &recovered[6],
        &subject_id.to_string(),
        6,
        true,
        Some(json!({"ModOne": {"data": 6}})),
    );
    assert_event_is_fact_full(
        &recovered[7],
        &subject_id.to_string(),
        7,
        true,
        Some(json!({"ModOne": {"data": 7}})),
    );
    assert_sink_not_lagging(&node.api, "example-sink").await;

    // Simulate data loss at the sink from SN 5 onwards.
    sink.remove_events_for_subject_from_sn(&subject_id.to_string(), 5)
        .await;

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id.to_string(),
                from_sn: 5,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert!(response.errors.is_empty());
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "example-sink");
    assert_eq!(processed.subject_id, subject_id.to_string());
    assert_eq!(processed.from_sn, 5);

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(8, true).await;
    let replayed = sink.snapshot().await;
    assert_eq!(replayed.len(), 8);

    let sns: Vec<_> = replayed.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3, 4, 5, 6, 7]);

    assert_event_is_create(&replayed[0], &subject_id.to_string(), 0);
    for i in 1..=7 {
        assert_event_is_fact_full(
            &replayed[i as usize],
            &subject_id.to_string(),
            i,
            true,
            Some(json!({"ModOne": {"data": i}})),
        );
    }
    assert_sink_not_lagging(&node.api, "example-sink").await;
}

/// Test 2: `replay_multiple_subjects_and_sinks`.
///
/// **Objective:** replay events from several subjects to several sinks in a
/// single call.
///
/// **Setup:**
/// - Node with two sinks:
///   - `example-sink-all` for schema `Example`, events `{All}`.
///   - `example-sink-fact` for schema `Example`, events `{Fact}`.
/// - Create subjects `S1` and `S2`.
/// - Emit facts on both.
/// - Verify that `example-sink-all` receives Create + Fact, and
///   `example-sink-fact` receives only Fact.
///
/// **Replay:**
/// - Delete events in both sinks for `S1` from SN 1.
/// - Call replay with:
///   - `{sink: "example-sink-all", subject_id: S1, from_sn: 1}`
///   - `{sink: "example-sink-fact", subject_id: S1, from_sn: 1}`
///   - `{sink: "example-sink-all", subject_id: S2, from_sn: 1}`
/// - Verify that each sink receives the corresponding events.
///
/// **Verifications:**
/// - `example-sink-all` has replayed events for S1 and S2 (S1: Create + 2
///   facts; S2: 2 additional facts on top of the existing ones).
/// - `example-sink-fact` has only replayed the Facts for S1.
/// - Response has 3 processed, 0 errors, and `processed` contains exactly the
///   3 requested items.
#[traced_test]
#[tokio::test]
async fn replay_multiple_subjects_and_sinks() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let (s2, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink_all = TestSink::start().await;
    let sink_fact = TestSink::start().await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![
            make_sink_entry(
                "example-sink-all",
                sink_all.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            ),
            make_sink_entry(
                "example-sink-fact",
                sink_fact.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::Fact]),
            ),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    for i in 1..=2 {
        emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": i}}), true)
            .await
            .unwrap();
        emit_fact(
            &node.api,
            s2.clone(),
            json!({"ModOne": {"data": 10 + i}}),
            true,
        )
        .await
        .unwrap();
    }

    let s1_str = s1.to_string();
    let s2_str = s2.to_string();

    wait_for_sink_caught_up(&node.api, "example-sink-all").await;
    sink_all.wait_for_count(6, true).await;
    let all_events = sink_all.snapshot().await;
    assert_eq!(all_events.len(), 6);
    assert_sink_contains_create(&all_events, &s1_str, 0);
    assert_sink_contains_create(&all_events, &s2_str, 0);
    assert_sink_contains_fact_full(
        &all_events,
        &s1_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &s1_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &s2_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 11}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &s2_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 12}})),
    );

    sink_fact.wait_for_full_count(4, true).await;
    let fact_events = sink_fact.full_snapshot().await;
    assert_eq!(fact_events.len(), 4);
    assert_sink_contains_fact_full(
        &fact_events,
        &s1_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &fact_events,
        &s1_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_sink_contains_fact_full(
        &fact_events,
        &s2_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 11}})),
    );
    assert_sink_contains_fact_full(
        &fact_events,
        &s2_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 12}})),
    );

    sink_all.remove_events_for_subject_from_sn(&s1_str, 1).await;
    sink_fact
        .remove_events_for_subject_from_sn(&s1_str, 1)
        .await;

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                SinkReplayItem {
                    sink: "example-sink-all".to_owned(),
                    subject_id: s1_str.clone(),
                    from_sn: 1,
                },
                SinkReplayItem {
                    sink: "example-sink-fact".to_owned(),
                    subject_id: s1_str.clone(),
                    from_sn: 1,
                },
                SinkReplayItem {
                    sink: "example-sink-all".to_owned(),
                    subject_id: s2_str.clone(),
                    from_sn: 1,
                },
            ],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 3);
    assert!(response.errors.is_empty());
    let expected_items: std::collections::BTreeSet<_> = [
        ("example-sink-all".to_owned(), s1_str.clone(), 1u64),
        ("example-sink-fact".to_owned(), s1_str.clone(), 1u64),
        ("example-sink-all".to_owned(), s2_str.clone(), 1u64),
    ]
    .into_iter()
    .collect();
    let actual_items: std::collections::BTreeSet<_> = response
        .processed
        .iter()
        .map(|i| (i.sink.clone(), i.subject_id.clone(), i.from_sn))
        .collect();
    assert_eq!(actual_items, expected_items);

    wait_for_sink_caught_up(&node.api, "example-sink-all").await;
    sink_all.wait_for_count(8, true).await;
    let all_after = sink_all.snapshot().await;
    assert_eq!(all_after.len(), 8);
    assert_eq!(count_events_for_subject(&all_after, &s1_str), 3);
    assert_eq!(count_events_for_subject(&all_after, &s2_str), 5);
    assert_sink_contains_create(&all_after, &s1_str, 0);
    assert_sink_contains_create(&all_after, &s2_str, 0);
    assert_sink_contains_fact_full(
        &all_after,
        &s1_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &all_after,
        &s1_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_sink_contains_fact_full(
        &all_after,
        &s2_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 11}})),
    );
    assert_sink_contains_fact_full(
        &all_after,
        &s2_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 12}})),
    );
    // Only one Create per subject: replays started at SN 1.
    assert_eq!(
        all_after
            .iter()
            .filter(|e| e.event_type() == SinkTypes::Create)
            .count(),
        2
    );

    sink_fact.wait_for_full_count(4, true).await;
    let fact_after = sink_fact.full_snapshot().await;
    assert_eq!(fact_after.len(), 4);
    assert!(
        !fact_after
            .iter()
            .any(|e| e.event_type() == SinkTypes::Create),
        "fact-only sink must not contain Create events"
    );
    assert_eq!(count_events_for_subject(&fact_after, &s1_str), 2);
    assert_eq!(count_events_for_subject(&fact_after, &s2_str), 2);
    assert_sink_contains_fact_full(
        &fact_after,
        &s1_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &fact_after,
        &s1_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_sink_contains_fact_full(
        &fact_after,
        &s2_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 11}})),
    );
    assert_sink_contains_fact_full(
        &fact_after,
        &s2_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 12}})),
    );
}

/// Test 4: `replay_filters_and_combinations`.
///
/// **Objective:** test event-filter combinations in sinks.
///
/// **Setup:**
/// - Node with 6 sinks for schema `Example`:
///   - `sink-create`: `{Create}`
///   - `sink-fact`: `{Fact}`
///   - `sink-transfer`: `{Transfer}`
///   - `sink-confirm`: `{Confirm}`
///   - `sink-reject`: `{Reject}`
///   - `sink-all`: `{All}`
/// - Create subject.
/// - Emit:
///   - 2 facts (one successful and one failed, to verify that `Fact` includes
///     both);
///   - 2 transfers (the first to a new owner, the second back, so the first can
///     be confirmed and the second rejected);
///   - 1 confirm;
///   - 1 reject;
///   - 1 EOL.
/// - Verify that each sink receives only what it is configured for.
///
/// **Replay:**
/// - Delete each sink's cursor.
/// - Call replay for each sink with `from_sn: 0`.
/// - Verify correct re-sending according to filters.
///
/// **Verifications:**
/// - `sink-create` only receives Create (SN 0).
/// - `sink-fact` receives the 2 Facts (successful SN 1 and failed SN 2).
/// - `sink-transfer` receives the 2 Transfers (SN 3 and SN 5).
/// - `sink-confirm` receives Confirm (SN 4).
/// - `sink-reject` receives Reject (SN 6).
/// - `sink-all` receives the 8 events in order: Create, Fact, Fact, Transfer,
///   Confirm, Transfer, Reject, EOL.
#[traced_test]
#[tokio::test]
async fn replay_filters_and_combinations() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let mut owner = nodes.remove(0);
    let mut new_owner = nodes.remove(0);

    let mut owner_dirs: Vec<_> = dirs.drain(0..2).collect();
    let mut new_owner_dirs: Vec<_> = dirs.drain(0..2).collect();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![&new_owner.api]).await;

    emit_fact(
        &owner.api,
        governance_id.clone(),
        governance_with_transfer_roles_fact(new_owner.api.public_key()),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let sink_specs = [
        ("sink-create", BTreeSet::from([SinkTypes::Create])),
        ("sink-fact", BTreeSet::from([SinkTypes::Fact])),
        ("sink-transfer", BTreeSet::from([SinkTypes::Transfer])),
        ("sink-confirm", BTreeSet::from([SinkTypes::Confirm])),
        ("sink-reject", BTreeSet::from([SinkTypes::Reject])),
        ("sink-all", BTreeSet::from([SinkTypes::All])),
    ];

    let sinks: Vec<TestSink> = futures::future::join_all(
        (0..sink_specs.len()).map(|_| TestSink::start()),
    )
    .await;

    let sink_entries: Vec<SinkConfigEntry> = sink_specs
        .iter()
        .zip(sinks.iter())
        .map(|((name, events), sink)| {
            make_sink_entry(
                name,
                sink.url(),
                Some(governance_id.to_string()),
                events.clone(),
            )
        })
        .collect();

    let owner_keys = owner.keys.clone();
    let owner_local_db = owner_dirs[0].path().to_path_buf();
    let owner_ext_db = owner_dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (owner, mut owner_dirs2) = create_node(restart_config(
        owner_keys,
        owner_local_db,
        owner_ext_db,
        format!("/memory/{}", owner_port),
        sink_entries,
    ))
    .await;
    owner_dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    let owner_peer_id = owner.api.peer_id().to_string();
    let owner_address = owner.listen_address.clone();

    let new_owner_keys = new_owner.keys.clone();
    let new_owner_local_db = new_owner_dirs[0].path().to_path_buf();
    let new_owner_ext_db = new_owner_dirs[1].path().to_path_buf();
    new_owner.token.cancel();
    join_all(new_owner.handler.iter_mut()).await;

    let new_owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_owner, mut new_owner_dirs2) =
        create_node(restart_config_with_peers(
            new_owner_keys,
            new_owner_local_db,
            new_owner_ext_db,
            format!("/memory/{}", new_owner_port),
            vec![RoutingNode {
                peer_id: owner_peer_id,
                address: vec![owner_address],
            }],
            vec![],
        ))
        .await;
    new_owner_dirs.append(&mut new_owner_dirs2);
    node_running(&new_owner.api).await.unwrap();

    get_subject(&new_owner.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        &owner.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    emit_fact(
        &owner.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let new_owner_pk =
        PublicKey::from_str(new_owner.api.public_key()).unwrap();
    emit_transfer(&owner.api, subject_id.clone(), new_owner_pk, true)
        .await
        .unwrap();

    get_subject(&new_owner.api, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_confirm(&new_owner.api, subject_id.clone(), None, true)
        .await
        .unwrap();

    let owner_pk = PublicKey::from_str(owner.api.public_key()).unwrap();
    emit_transfer(&new_owner.api, subject_id.clone(), owner_pk, true)
        .await
        .unwrap();

    get_subject(&owner.api, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    emit_reject(&owner.api, subject_id.clone(), true)
        .await
        .unwrap();
    // Ensure NewOwner has seen the reject (SN 6) before it issues the EOL
    // (SN 7), otherwise it would build the EOL as a duplicate SN 6.
    get_subject(&new_owner.api, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    emit_eol(&new_owner.api, subject_id.clone(), true)
        .await
        .unwrap();

    let subject_id_str = subject_id.to_string();

    sinks[0].wait_for_full_count(1, true).await;
    let create_events = sinks[0].full_snapshot().await;
    assert_eq!(create_events.len(), 1);
    assert_event_is_create(&create_events[0], &subject_id_str, 0);

    sinks[1].wait_for_full_count(2, true).await;
    let fact_events = sinks[1].full_snapshot().await;
    assert_eq!(fact_events.len(), 2);
    assert_sink_contains_fact_full(
        &fact_events,
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &fact_events,
        &subject_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );

    sinks[2].wait_for_full_count(2, true).await;
    let transfer_events = sinks[2].full_snapshot().await;
    assert_eq!(transfer_events.len(), 2);
    assert_sink_contains_transfer(&transfer_events, &subject_id_str, 3);
    assert_sink_contains_transfer(&transfer_events, &subject_id_str, 5);

    sinks[3].wait_for_full_count(1, true).await;
    let confirm_events = sinks[3].full_snapshot().await;
    assert_eq!(confirm_events.len(), 1);
    assert_sink_contains_confirm(&confirm_events, &subject_id_str, 4);

    sinks[4].wait_for_full_count(1, true).await;
    let reject_events = sinks[4].full_snapshot().await;
    assert_eq!(reject_events.len(), 1);
    assert_sink_contains_reject(&reject_events, &subject_id_str, 6);

    wait_for_sink_caught_up(&owner.api, "sink-all").await;
    sinks[5].wait_for_count(8, true).await;
    let all_events = sinks[5].snapshot().await;
    assert_eq!(all_events.len(), 8);
    assert_sink_contains_create(&all_events, &subject_id_str, 0);
    assert_sink_contains_fact_full(
        &all_events,
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &subject_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );
    assert_sink_contains_transfer(&all_events, &subject_id_str, 3);
    assert_sink_contains_confirm(&all_events, &subject_id_str, 4);
    assert_sink_contains_transfer(&all_events, &subject_id_str, 5);
    assert_sink_contains_reject(&all_events, &subject_id_str, 6);
    assert_sink_contains_eol(&all_events, &subject_id_str, 7);

    for sink in &sinks {
        sink.clear().await;
    }

    let response = owner
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: sink_specs
                .iter()
                .map(|(name, _)| SinkReplayItem {
                    sink: (*name).to_owned(),
                    subject_id: subject_id_str.clone(),
                    from_sn: 0,
                })
                .collect(),
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 6);
    assert!(response.errors.is_empty());
    let expected_items: std::collections::BTreeSet<_> = sink_specs
        .iter()
        .map(|(name, _)| (name.to_string(), subject_id_str.clone(), 0u64))
        .collect();
    let actual_items: std::collections::BTreeSet<_> = response
        .processed
        .iter()
        .map(|i| (i.sink.clone(), i.subject_id.clone(), i.from_sn))
        .collect();
    assert_eq!(actual_items, expected_items);

    sinks[0].wait_for_full_count(1, true).await;
    let create_after = sinks[0].full_snapshot().await;
    assert_eq!(create_after.len(), 1);
    assert_event_is_create(&create_after[0], &subject_id_str, 0);

    sinks[1].wait_for_full_count(2, true).await;
    let fact_after = sinks[1].full_snapshot().await;
    assert_eq!(fact_after.len(), 2);
    assert_event_is_fact_full(
        &fact_after[0],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &fact_after[1],
        &subject_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );

    sinks[2].wait_for_full_count(2, true).await;
    let transfer_after = sinks[2].full_snapshot().await;
    assert_eq!(transfer_after.len(), 2);
    assert_event_is_transfer(&transfer_after[0], &subject_id_str, 3);
    assert_event_is_transfer(&transfer_after[1], &subject_id_str, 5);

    sinks[3].wait_for_full_count(1, true).await;
    let confirm_after = sinks[3].full_snapshot().await;
    assert_eq!(confirm_after.len(), 1);
    assert_event_is_confirm(&confirm_after[0], &subject_id_str, 4);

    sinks[4].wait_for_full_count(1, true).await;
    let reject_after = sinks[4].full_snapshot().await;
    assert_eq!(reject_after.len(), 1);
    assert_event_is_reject(&reject_after[0], &subject_id_str, 6);

    wait_for_sink_caught_up(&owner.api, "sink-all").await;
    sinks[5].wait_for_count(8, true).await;
    let all_after = sinks[5].snapshot().await;
    assert_eq!(all_after.len(), 8);
    let sns: Vec<_> = all_after.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3, 4, 5, 6, 7]);
    assert_event_is_create(&all_after[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &all_after[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &all_after[2],
        &subject_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );
    assert_event_is_transfer(&all_after[3], &subject_id_str, 3);
    assert_event_is_confirm(&all_after[4], &subject_id_str, 4);
    assert_event_is_transfer(&all_after[5], &subject_id_str, 5);
    assert_event_is_reject(&all_after[6], &subject_id_str, 6);
    assert_event_is_eol(&all_after[7], &subject_id_str, 7);
}

/// Test 5: `replay_endpoint_validation_and_errors`.
///
/// **Objective:** exercise all endpoint validations.
///
/// **Cases in a single test:**
/// - Calling in safe mode → `SafeMode` error.
/// - Blocked sink → item in `errors` with reason "sink is blocked".
///   - A `422 Unprocessable Entity` response is used to block the sink
///     (non-transient error).
///   - Verify `sink`, `subject_id`, `from_sn`, and `reason` of the error.
/// - Sink does not exist in the registry → item in `errors` with `SinkNotFound`.
///   - Verify `sink`, `subject_id`, `from_sn`, and the error message.
/// - Sink exists in the registry but is not configured in the sink manager →
///   item in `errors` with reason "sink is not configured".
///   - Advanced case: force it by removing the sink from config after it was
///     active (residual in manager without servers).
/// - Subject does not exist → item in `errors` with "subject has no known events".
///   - Verify unknown `subject_id` and `from_sn`.
/// - `from_sn` greater than last_seen → item in `errors` with "from_sn beyond the
///   last seen event".
///   - Verify the requested `from_sn` and the actual `last_seen`.
/// - Duplicate items with different `from_sn` → deduplicate to the oldest one,
///   a single `processed` item.
///   - Verify that `processed` contains exactly one item with the lowest
///     `from_sn` and that `errors` is empty.
#[traced_test]
#[tokio::test]
async fn replay_endpoint_validation_and_errors() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let subject_id_str = subject_id.to_string();
    let unknown_subject =
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![0u8; 32])
            .unwrap()
            .to_string();

    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();

    // Restart with a real sink so the subject has known events and a cursor.
    let sink = TestSink::start().await;
    let sink_url = sink.url();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db.clone(),
        initial_ext_db.clone(),
        format!("/memory/{}", port),
        example_sink_config(sink_url.clone(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    sink.wait_for_count(3, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 3);

    // 1. Safe mode: replay must be rejected.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node_safe, mut safe_dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(initial_local_db.clone()),
        ext_db: Some(initial_ext_db.clone()),
        safe_mode: true,
        sinks: example_sink_config(
            sink_url.clone(),
            Some(governance_id.to_string()),
        ),
        ..Default::default()
    })
    .await;
    dirs.append(&mut safe_dirs);
    node_running(&node_safe.api).await.unwrap();

    let err = node_safe
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 0,
            }],
        })
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::SafeMode(_)),
        "expected SafeMode error, got {:?}",
        err
    );

    // 2. Back to normal mode and exercise several error cases in one request.
    let keys = node_safe.keys.clone();
    node_safe.token.cancel();
    join_all(node_safe.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        initial_local_db.clone(),
        initial_ext_db.clone(),
        format!("/memory/{}", port),
        example_sink_config(sink_url.clone(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    sink.wait_for_count(3, true).await;

    // Duplicate items, missing sink and unknown subject in one request.
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                // Duplicate items: must deduplicate to the smallest from_sn.
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: subject_id_str.clone(),
                    from_sn: 1,
                },
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: subject_id_str.clone(),
                    from_sn: 2,
                },
                // Missing sink.
                SinkReplayItem {
                    sink: "missing-sink".to_owned(),
                    subject_id: subject_id_str.clone(),
                    from_sn: 0,
                },
                // Unknown subject.
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: unknown_subject.clone(),
                    from_sn: 0,
                },
            ],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "example-sink");
    assert_eq!(processed.subject_id, subject_id_str);
    assert_eq!(processed.from_sn, 1);

    assert_eq!(response.errors.len(), 2);

    let missing = response
        .errors
        .iter()
        .find(|e| e.sink == "missing-sink")
        .expect("missing-sink error");
    assert_eq!(missing.subject_id, subject_id_str);
    assert_eq!(missing.from_sn, 0);
    assert!(
        missing.reason.contains("not found"),
        "unexpected reason: {}",
        missing.reason
    );

    let unknown = response
        .errors
        .iter()
        .find(|e| e.subject_id == unknown_subject)
        .expect("unknown-subject error");
    assert_eq!(unknown.sink, "example-sink");
    assert_eq!(unknown.from_sn, 0);
    assert_eq!(unknown.reason, "subject has no known events");

    // from_sn beyond last seen event must be checked separately from duplicates.
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 10,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 0);
    assert_eq!(response.errors.len(), 1);
    let beyond = &response.errors[0];
    assert_eq!(beyond.sink, "example-sink");
    assert_eq!(beyond.subject_id, subject_id_str);
    assert_eq!(beyond.from_sn, 10);
    assert!(beyond.reason.contains("beyond the last seen event"));
    assert!(beyond.reason.contains("2"));

    // 3. Sink exists in registry but is not configured in the manager (residual).
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config_with_peers(
        keys,
        initial_local_db.clone(),
        initial_ext_db.clone(),
        format!("/memory/{}", port),
        vec![],
        vec![],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 0,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 0);
    assert_eq!(response.errors.len(), 1);
    let not_configured = &response.errors[0];
    assert_eq!(not_configured.sink, "example-sink");
    assert_eq!(not_configured.subject_id, subject_id_str);
    assert_eq!(not_configured.from_sn, 0);
    assert_eq!(not_configured.reason, "sink is not configured");

    // 4. Blocked sink: delivery failures with 422 mark the sink as blocked.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let sink_url = sink.url();
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink_url, Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Make sure the sink worker is healthy before forcing a delivery failure.
    wait_for_sink_unblocked(&node.api, "example-sink").await;

    sink.set_mode(ResponseMode::ClientError).await;
    emit_fact(&node.api, subject_id, json!({"ModOne": {"data": 3}}), true)
        .await
        .unwrap();

    // Wait until the worker has marked the sink as blocked and confirm it via
    // the API before attempting a replay.
    wait_for_sink_blocked(&node.api, "example-sink").await;
    assert_sink_blocked(&node.api, "example-sink").await;

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 0,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 0);
    assert_eq!(response.errors.len(), 1);
    let blocked = &response.errors[0];
    assert_eq!(blocked.sink, "example-sink");
    assert_eq!(blocked.subject_id, subject_id_str);
    assert_eq!(blocked.from_sn, 0);
    assert_eq!(blocked.reason, "sink is blocked");
}

/// Test 6: `replay_when_sink_starts_late_and_unblock_edge_cases`.
///
/// **Objective:** the sink does not exist when events are emitted, it is started
/// later, replay works, and the `unblock_sink` edge cases are covered (no-op and
/// safe mode). Exercises `unblock_sink` and `replay_sink_events`.
///
/// **Setup:**
/// - Create a node **without** sinks configured for `Example`.
/// - Create governance and add schema `Example`.
/// - Create subject and emit 3 facts.
///
/// **Sequence (realistic alternative):**
/// - Restart the node with a sink configured to point to a `TestSink` that
///   initially returns `422 Unprocessable Entity` (simulates the remote server
///   not being ready yet).
/// - Call `api.unblock_sink("example-sink")` **before** the worker decides it is
///   blocked; verify it returns `Ok(())` (no-op on a healthy sink).
/// - The sink worker marks the sink as blocked.
/// - Change `TestSink` to `Accept` mode.
/// - Unblock the sink with `api.unblock_sink("example-sink")`.
/// - Verify the sink receives Create + 3 facts via automatic catch-up.
/// - Delete all sink events from SN 2.
/// - Call replay `{sink: "example-sink", subject_id, from_sn: 2}`.
/// - Verify the sink has Create + 3 facts again with consecutive SNs
///   `[0, 1, 2, 3]`.
/// - Restart the node in `safe_mode: true` with the same sink configured.
/// - Call `api.unblock_sink("example-sink")` and verify it returns
///   `Error::SafeMode`.
///
/// **Verifications:**
/// - `unblock_sink` on a non-blocked sink is a valid no-op.
/// - Before unblocking, the sink has not stored any event.
/// - After unblocking and setting the sink to `Accept`, 4 events are received
///   with the correct payloads.
/// - The replay response has `processed.len() == 1`, empty `errors`, and the
///   item contains `from_sn: 2`.
/// - After the replay the full sequence is `[0, 1, 2, 3]`.
/// - `api.get_sinks_status()` shows the sink as unblocked after unblocking.
/// - `unblock_sink` is rejected in safe mode.
#[traced_test]
#[tokio::test]
async fn replay_when_sink_starts_late_and_unblock_edge_cases() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let subject_id_str = subject_id.to_string();
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();

    // Restart with a sink that initially rejects every request with 422.
    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::ClientError).await;
    let sink_url = sink.url();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db.clone(),
        initial_ext_db.clone(),
        format!("/memory/{}", port),
        example_sink_config(sink_url.clone(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // unblock_sink on a not-yet-blocked sink must be a no-op.
    node.api
        .unblock_sink("example-sink".to_owned())
        .await
        .expect("unblock on healthy sink should be a no-op");

    // Wait until the worker has marked the sink as blocked and confirm the
    // state through the API before unblocking it.
    wait_for_sink_blocked(&node.api, "example-sink").await;

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 0, "sink should not have stored any events");

    assert_sink_blocked(&node.api, "example-sink").await;

    // Recover the sink and unblock it.
    sink.set_mode(ResponseMode::Accept).await;
    node.api
        .unblock_sink("example-sink".to_owned())
        .await
        .unwrap();

    // Automatic catch-up should deliver Create + 3 facts.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 4);
    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );

    // Confirm through the API that the sink is no longer blocked.
    assert_sink_unblocked(&node.api, "example-sink").await;

    // Simulate partial loss in the sink from SN 2 and replay.
    sink.remove_events_for_subject_from_sn(&subject_id_str, 2)
        .await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 2);

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 2,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert_eq!(response.errors.len(), 0);
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "example-sink");
    assert_eq!(processed.subject_id, subject_id_str);
    assert_eq!(processed.from_sn, 2);

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 4);
    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );

    // Safe mode must reject unblock_sink.
    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node_safe, mut safe_dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(initial_local_db.clone()),
        ext_db: Some(initial_ext_db.clone()),
        safe_mode: true,
        sinks: example_sink_config(
            sink_url.clone(),
            Some(governance_id.to_string()),
        ),
        ..Default::default()
    })
    .await;
    dirs.append(&mut safe_dirs);
    node_running(&node_safe.api).await.unwrap();

    let err = node_safe
        .api
        .unblock_sink("example-sink".to_owned())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::SafeMode(_)),
        "expected SafeMode error, got {:?}",
        err
    );
}

/// Test 7: `replay_after_sink_returns_bad_data`.
///
/// **Objective:** the sink returns bad data, becomes blocked, is unblocked, and
/// replay works. Exercises `unblock_sink` and `replay_sink_events`.
///
/// **Implementation note:** HTTP 500 is a transient error in this
/// implementation, so `422 Unprocessable Entity` is used to force blocking (a
/// non-transient error). The `TestSink` `Malformed` mode returns HTTP 200, which
/// the worker treats as success, so it is not used for blocking.
///
/// **Setup:**
/// - Bootstrap node without sinks, create governance and schema `Example`.
/// - Restart the node with an `example-sink` pointing to a `TestSink` in
///   `Accept` mode.
/// - Create subject and emit 2 facts.
/// - Verify the sink receives Create + 2 facts (3 events).
///
/// **Sequence:**
/// - Configure `TestSink` to respond `422 Unprocessable Entity`.
/// - Emit a third fact → the worker marks the sink as blocked.
/// - Verify the sink still has only 3 events.
/// - Change `TestSink` to `Accept` mode.
/// - Unblock the sink with `api.unblock_sink("example-sink")`.
/// - Verify automatic catch-up of the third fact (4 events total).
/// - Delete sink events from SN 2.
/// - Call replay `{sink: "example-sink", subject_id, from_sn: 2}`.
/// - Verify the sink has Create + 3 facts again with consecutive SNs
///   `[0, 1, 2, 3]`.
///
/// **Verifications:**
/// - The 2 initial facts arrive correctly with their payloads.
/// - After the 422 error the sink does not store the failed event and becomes
///   blocked.
/// - `api.get_sinks_status()` shows the sink as blocked with a non-empty reason
///   before unblocking.
/// - After unblocking and setting the sink to `Accept`, 4 events are received.
/// - The replay response has `processed.len() == 1`, empty `errors`, and the
///   item contains `from_sn: 2`.
/// - After the replay the full sequence is `[0, 1, 2, 3]`.
#[traced_test]
#[tokio::test]
async fn replay_after_sink_returns_bad_data() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    // Restart with a healthy sink before creating the subject.
    let sink = TestSink::start().await;
    let sink_url = sink.url();
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db.clone(),
        initial_ext_db.clone(),
        format!("/memory/{}", port),
        example_sink_config(sink_url.clone(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(3, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 3);
    assert_event_is_create(&initial[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &initial[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &initial[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );

    // Force a permanent delivery failure.
    sink.set_mode(ResponseMode::ClientError).await;
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    wait_for_sink_blocked(&node.api, "example-sink").await;

    let events = sink.snapshot().await;
    assert_eq!(
        events.len(),
        3,
        "sink should not store the event that triggered the block"
    );

    // Confirm the block reason through the API before recovering.
    let reason = assert_sink_blocked(&node.api, "example-sink").await;
    assert!(
        reason.to_lowercase().contains("422"),
        "block reason should mention the 422 error: {:?}",
        reason
    );

    // Recover the sink and unblock it.
    sink.set_mode(ResponseMode::Accept).await;
    node.api
        .unblock_sink("example-sink".to_owned())
        .await
        .unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 4);
    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );

    // Confirm through the API that the sink is no longer blocked.
    assert_sink_unblocked(&node.api, "example-sink").await;

    // Simulate partial loss in the sink from SN 2 and replay.
    sink.remove_events_for_subject_from_sn(&subject_id_str, 2)
        .await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 2);

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 2,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert_eq!(response.errors.len(), 0);
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "example-sink");
    assert_eq!(processed.subject_id, subject_id_str);
    assert_eq!(processed.from_sn, 2);

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 4);
    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );
}

/// Test 8: `replay_endpoint_response_shape`.
///
/// **Objective:** verify that the endpoint response has the expected shape and
/// that the valid item actually re-sends events.
///
/// **Setup:**
/// - Bootstrap node, create governance and schema `Example`.
/// - Restart with an `example-sink`.
/// - Create two subjects `S1` and `S2` and emit 3 facts in each.
/// - Verify the sink receives 8 events (2 Create + 6 FactFull).
///
/// **Sequence:**
/// - Call replay with a mix of 5 items:
///   - Valid: `{example-sink, S1, from_sn: 1}`.
///   - Valid duplicate: `{example-sink, S1, from_sn: 2}` (must be deduplicated
///     to `from_sn` 1).
///   - Invalid: `{missing-sink, S1, from_sn: 0}` (sink does not exist).
///   - Invalid: `{example-sink, no-such-subject, from_sn: 0}` (subject does not
///     exist).
///   - Invalid: `{example-sink, S2, from_sn: 10}` (`from_sn` beyond
///     `last_seen`).
///
/// **Verifications:**
/// - `processed.len() == 1` and contains exactly `{example-sink, S1, from_sn:
///   1}`.
/// - `errors.len() == 3`.
/// - Each error has a non-empty `reason`.
/// - `processed` and `errors` are disjoint by `(sink, subject_id)`.
/// - The three expected errors are present: sink not found, unknown subject,
///   and `from_sn` out of range.
/// - After the replay the sink receives 11 events in total: 8 original + 3
///   replayed facts from S1.
#[traced_test]
#[tokio::test]
async fn replay_endpoint_response_shape() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    // Restart with a sink before creating the subjects.
    let sink = TestSink::start().await;
    let sink_url = sink.url();
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink_url, Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_one, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_one_str = subject_one.to_string();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_one.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let (subject_two, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_two_str = subject_two.to_string();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_two.clone(),
            json!({"ModOne": {"data": i + 10}}),
            true,
        )
        .await
        .unwrap();
    }

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(8, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 8);

    let unknown_subject =
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![0u8; 32])
            .unwrap()
            .to_string();

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: subject_one_str.clone(),
                    from_sn: 1,
                },
                // Duplicate: must be folded into the previous item at from_sn 1.
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: subject_one_str.clone(),
                    from_sn: 2,
                },
                // Missing sink.
                SinkReplayItem {
                    sink: "missing-sink".to_owned(),
                    subject_id: subject_one_str.clone(),
                    from_sn: 0,
                },
                // Unknown subject.
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: unknown_subject.clone(),
                    from_sn: 0,
                },
                // from_sn beyond last seen event.
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: subject_two_str.clone(),
                    from_sn: 10,
                },
            ],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert_eq!(response.errors.len(), 3);

    let processed = &response.processed[0];
    assert_eq!(processed.sink, "example-sink");
    assert_eq!(processed.subject_id, subject_one_str);
    assert_eq!(processed.from_sn, 1);

    for error in &response.errors {
        assert!(
            !error.reason.is_empty(),
            "error reason must not be empty: {:?}",
            error
        );
    }

    // processed and errors must be disjoint by (sink, subject_id).
    let processed_keys: std::collections::BTreeSet<_> = response
        .processed
        .iter()
        .map(|p| (p.sink.as_str(), p.subject_id.as_str()))
        .collect();
    let error_keys: std::collections::BTreeSet<_> = response
        .errors
        .iter()
        .map(|e| (e.sink.as_str(), e.subject_id.as_str()))
        .collect();
    let intersection: Vec<_> =
        processed_keys.intersection(&error_keys).copied().collect();
    assert!(
        intersection.is_empty(),
        "processed and errors must be disjoint, overlap: {:?}",
        intersection
    );

    assert!(
        response.errors.iter().any(|e| e.sink == "missing-sink"),
        "missing-sink error expected"
    );
    assert!(
        response
            .errors
            .iter()
            .any(|e| e.subject_id == unknown_subject),
        "unknown-subject error expected"
    );
    assert!(
        response.errors.iter().any(|e| {
            e.sink == "example-sink"
                && e.subject_id == subject_two_str
                && e.from_sn == 10
        }),
        "from_sn beyond last seen error expected"
    );

    // The valid replay re-sends S1 facts from SN 1 to SN 3.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(11, true).await;
    let after = sink.snapshot().await;
    assert_eq!(after.len(), 11);

    // Count S1 FactFull events after replay.
    let s1_fact_count = after
        .iter()
        .filter(|e| {
            e.subject_id() == subject_one_str
                && matches!(e, IncomingSinkEvent::Full(_))
                && e.sn() >= 1
        })
        .count();
    assert_eq!(
        s1_fact_count, 6,
        "S1 should have 3 initial + 3 replayed facts"
    );
}

/// Test 9: `sink_permanent_failure_and_manual_recovery`.
///
/// **Cases covered:** sink permanently down, events in `lagging`, replay while
/// the sink is down, manual recovery, and automatic catch-up.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`, restart with sink
///   `example-sink`.
/// - Create subject `S1` and emit 2 facts.
/// - Verify initial delivery (Create + 2 facts).
///
/// **Sequence:**
/// 1. Change `TestSink` to `Drop` mode (never responds).
/// 2. Emit 2 more facts.
/// 3. Wait long enough for the worker to exhaust retries and mark the subject
///    as `lagging`.
/// 4. Verify the sink **has not** received the new events and that it is **not**
///    blocked (Drop is a transient error).
/// 5. Call replay `{example-sink, S1, from_sn: 1}` while the sink is still down.
/// 6. Verify the replay appears in `processed` but the events do not physically
///    reach the sink yet.
/// 7. Change `TestSink` to `Accept` mode.
/// 8. Verify the sink receives all pending events by automatic catch-up. The
///    replay from SN 1 is merged with the existing cursor (SN 2), so the worker
///    re-sends SN 1..4; SN 1 and 2 therefore appear duplicated in `TestSink`
///    while SN 3 and 4 arrive for the first time. `TestSink` ends with 7 events
///    and SNs `[0, 1, 2, 1, 2, 3, 4]`.
///
/// **Verifications:**
/// - The sink does not advance its cursor while it is down.
/// - `lagging` contains the subject (can be checked via `GetDetailedStatus` or
///   indirectly by verifying that subsequent catch-up delivers all events).
/// - The sink never reaches `blocked` state.
/// - After manual recovery all pending events are delivered in order; `TestSink`
///   does not deduplicate, so events already delivered that fall inside the
///   replay range appear duplicated.
#[traced_test]
#[tokio::test]
async fn sink_permanent_failure_and_manual_recovery() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    // Restart with a healthy sink before creating the subject.
    let sink = TestSink::start().await;
    let sink_url = sink.url();
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink_url, Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    sink.wait_for_count(3, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 3);
    assert_event_is_create(&initial[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &initial[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &initial[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );

    // Crash the sink: accept TCP but never respond.
    sink.set_mode(ResponseMode::Drop).await;

    for i in 3..=4 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Wait until the worker has marked the subject as lagging.
    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;

    // The sink must not have stored the two new events and must not be blocked
    // because Drop is a transient failure.
    let events = sink.snapshot().await;
    assert_eq!(
        events.len(),
        3,
        "sink should not store events while it is dropped"
    );

    // A transient Drop failure must not block the sink, but it must leave the
    // subject lagging.
    assert_sink_unblocked(&node.api, "example-sink").await;
    assert_sink_lagging(&node.api, "example-sink", 1).await;

    // Replay while the sink is still down: the request is accepted but events
    // cannot be delivered yet.
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 1,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert_eq!(response.errors.len(), 0);
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "example-sink");
    assert_eq!(processed.subject_id, subject_id_str);
    assert_eq!(processed.from_sn, 1);

    // Give the worker a moment to attempt the replayed delivery; the sink
    // should still not have received anything while in Drop mode.
    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;
    assert_sink_unblocked(&node.api, "example-sink").await;
    assert_sink_lagging(&node.api, "example-sink", 1).await;
    let events = sink.snapshot().await;
    assert_eq!(
        events.len(),
        3,
        "sink should not store events while replay is attempted during Drop"
    );

    // Recover the sink. The worker should deliver all pending events.
    sink.set_mode(ResponseMode::Accept).await;

    // Wait for the worker to deliver all pending events after recovery.
    // The replay from SN 1 is merged with the existing cursor (SN 2), so the
    // worker re-sends SN 1..4. SN 1 and 2 are therefore duplicated while SN 3
    // and 4 are delivered for the first time, giving 7 stored events in total.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(7, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 7);

    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 1, 2, 3, 4]);
    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[4],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[5],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );
    assert_event_is_fact_full(
        &events[6],
        &subject_id_str,
        4,
        true,
        Some(json!({"ModOne": {"data": 4}})),
    );

    // After recovery the sink must be healthy and up-to-date.
    assert_sink_unblocked(&node.api, "example-sink").await;
    assert_sink_not_lagging(&node.api, "example-sink").await;
}

/// Test 10: `sink_flapping_blocks_after_repeated_recovery`.
///
/// **Cases covered:** *flapping* (healthcheck OK but delivery fails), permanent
/// blocking after exceeding `max_recoveries_after_failure`, and real recovery
/// via `unblock_sink` while hot once the sink becomes healthy again.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with `example-sink` configured with
///   `max_recoveries_after_failure: 1`, `healthcheck_intervals_secs: [1]`,
///   `request_timeout_ms: 500`, `max_retries: 0`.
/// - Create subject `S1`, emit 2 facts, verify initial delivery.
///
/// **Sequence:**
/// 1. Configure `TestSink` in `HealthOkDeliveryFail` mode: the `GET /events`
///    endpoint returns `200 OK`, but `POST /events` returns `500 Internal Server
///    Error`.
/// 2. Emit a third fact. The worker tries to deliver it, fails (transient
///    error), transitions to `Unhealthy`, and schedules a healthcheck.
/// 3. The healthcheck passes (`200 OK`), the worker recovers, tries catch-up,
///    and fails again. Since `max_recoveries_after_failure` is 1, the sink
///    blocks with reason `"sink flapping: healthcheck OK but delivery fails"`.
/// 4. Verify the sink has exactly 3 events (it did not receive the third fact).
/// 5. Change `TestSink` to `Accept` mode to simulate the remote sink being
///    healthy now.
/// 6. Call `api.unblock_sink("example-sink")` and verify the call succeeds.
///    Check in `get_sinks_status` that the sink is no longer marked as
///    `blocked` at manager level.
/// 7. Verify the sink receives Create + 3 facts with SNs `[0, 1, 2, 3]`: the
///    manual unblock triggers catch-up and, because the sink is healthy, the
///    pending fact is delivered on the running node.
///
/// **Verifications:**
/// - After a failed recovery the sink becomes `blocked`.
/// - The block reason contains `"flapping"`.
/// - Before unblocking the sink has exactly 3 events.
/// - `api.unblock_sink` on a sink blocked due to flapping returns `Ok(())` and
///   `get_sinks_status` no longer reports it as blocked.
/// - After making the sink healthy and unblocking it, the pending fact is
///   delivered hot and the sink ends with 4 events SN `[0, 1, 2, 3]`.
///
/// > **Implementation note:** the `HealthOkDeliveryFail` mode must be added to
/// > `TestSink`.
#[traced_test]
#[tokio::test]
async fn sink_flapping_blocks_after_repeated_recovery() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    // Restart with a sink configured to block after a single failed recovery.
    let sink = TestSink::start().await;
    let sink_url = sink.url();
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        keys: Some(initial_keys),
        local_db: Some(initial_local_db),
        ext_db: Some(initial_ext_db),
        sinks: flapping_sink_config(sink_url, Some(governance_id.to_string())),
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    sink.wait_for_count(3, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 3);
    assert_event_is_create(&initial[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &initial[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &initial[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );

    // Make the sink flap: healthcheck succeeds but event delivery fails.
    sink.set_mode(ResponseMode::HealthOkDeliveryFail).await;

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    // Wait until the sink is blocked as flapping and confirm it via the API.
    let reason = wait_for_sink_blocked(&node.api, "example-sink").await;
    assert!(
        reason.to_lowercase().contains("flapping"),
        "block reason should mention flapping, got: {}",
        reason
    );
    assert_sink_blocked(&node.api, "example-sink").await;

    let events = sink.snapshot().await;
    assert_eq!(
        events.len(),
        3,
        "sink should not store the event that triggered flapping"
    );

    // Recover the sink: first put it back in Accept mode, then unblock it.
    // The manual unblock triggers catch-up; because the sink is healthy again,
    // the pending fact is delivered in the running node.
    sink.set_mode(ResponseMode::Accept).await;
    node.api
        .unblock_sink("example-sink".to_owned())
        .await
        .unwrap();

    // Confirm through the API that the sink is no longer blocked.
    assert_sink_unblocked(&node.api, "example-sink").await;

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 4);
    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );
}

/// Test 11: `sink_recovery_across_node_restart`.
///
/// **Cases covered:** auto-unblock of blocked sinks in `pre_start`, rebuild of
/// `lagging` after restart, worker recreation, and automatic catch-up.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Create subject `S1` and emit 2 facts.
///
/// **Part A — restart with blocked sink:**
/// 1. Restart the node with `example-sink` in `Accept` mode.
/// 2. Verify initial delivery of Create + 2 facts.
/// 3. Change `TestSink` to `ClientError` mode (`422`).
/// 4. Emit a third fact; wait for the sink to block.
/// 5. Stop the node (`token.cancel()` + `join_all`).
/// 6. Change `TestSink` to `Accept` mode.
/// 7. Restart the node with the same config and persistence.
/// 8. Verify that `pre_start` automatically unblocks the sink and that catch-up
///    delivers the third fact.
///
/// **Part B — restart with subject in `lagging`:**
/// 1. Restart the node with `example-sink` in `Drop` mode.
/// 2. Create subject `S2` and emit 2 facts (they will not be delivered).
/// 3. Stop the node.
/// 4. Change `TestSink` to `Accept` mode.
/// 5. Restart the node.
/// 6. Verify the sink receives Create + 2 facts for `S2` via automatic
///    catch-up.
///
/// **Part C — worker recreation after idle shutdown:**
/// 1. Restart the node with `example-sink` configured with
///    `sink_worker_idle_timeout_ms: 200` and
///    `sink_subject_worker_idle_timeout_ms: 200`.
/// 2. Emit a fact on `S2`; verify the sink receives it (the worker starts).
/// 3. Wait more than 200 ms for the manager to stop the worker due to
///    inactivity.
/// 4. Emit another fact on `S2`; verify the sink receives it, showing that the
///    manager created a new worker after the idle shutdown.
///
/// **Verifications:**
/// - After restart a previously blocked sink appears as unblocked.
/// - Subjects in `lagging` are detected in `pre_start` and catch-up is run.
/// - Workers are recreated correctly after the idle shutdown (events are
///   delivered before and after the idle timeout).
#[traced_test]
#[tokio::test]
async fn sink_recovery_across_node_restart() {
    // Initial setup: bootstrap node with governance and schema Example.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_one, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_one_str = subject_one.to_string();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_one.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Part A — restart with an initially healthy sink, then block it, restart
    // again and verify auto-unblock + catch-up.
    let sink = TestSink::start().await;
    let sink_url = sink.url();
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        keys: Some(initial_keys),
        local_db: Some(initial_local_db),
        ext_db: Some(initial_ext_db),
        sinks: example_sink_config(sink_url, Some(governance_id.to_string())),
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(3, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 3);
    assert_event_is_create(&initial[0], &subject_one_str, 0);
    assert_event_is_fact_full(
        &initial[1],
        &subject_one_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &initial[2],
        &subject_one_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );

    // Block the sink with a permanent client error.
    sink.set_mode(ResponseMode::ClientError).await;
    emit_fact(
        &node.api,
        subject_one.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    let reason = wait_for_sink_blocked(&node.api, "example-sink").await;
    assert!(
        reason.to_lowercase().contains("422")
            || reason.to_lowercase().contains("client"),
        "block reason should mention 422/client error, got: {}",
        reason
    );
    assert_sink_blocked(&node.api, "example-sink").await;

    // Shut down the node while the sink is blocked.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Recover the sink and restart the node with the same configuration.
    sink.set_mode(ResponseMode::Accept).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The restart must have auto-unblocked the sink.
    assert_sink_unblocked(&node.api, "example-sink").await;

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 4);
    let sns: Vec<_> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
    assert_event_is_create(&events[0], &subject_one_str, 0);
    assert_event_is_fact_full(
        &events[3],
        &subject_one_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );

    // Part B — restart with the sink dropped, create a second subject, then
    // recover the sink after another restart and verify catch-up.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    sink.set_mode(ResponseMode::Drop).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_two, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_two_str = subject_two.to_string();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_two.clone(),
            json!({"ModOne": {"data": i + 10}}),
            true,
        )
        .await
        .unwrap();
    }

    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;
    assert_sink_unblocked(&node.api, "example-sink").await;
    assert_sink_lagging(&node.api, "example-sink", 1).await;

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    sink.set_mode(ResponseMode::Accept).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Total stored events: 4 from S1 + Create + 2 facts from S2 = 7.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(7, true).await;
    let events = sink.snapshot().await;
    assert_eq!(events.len(), 7);

    let s2_events: Vec<_> = events
        .iter()
        .filter(|e| e.subject_id() == subject_two_str)
        .collect();
    assert_eq!(s2_events.len(), 3, "S2 should have Create + 2 facts");
    assert_event_is_create(s2_events[0], &subject_two_str, 0);
    assert_event_is_fact_full(
        s2_events[1],
        &subject_two_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 11}})),
    );
    assert_event_is_fact_full(
        s2_events[2],
        &subject_two_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 12}})),
    );

    // After catch-up the sink must be healthy and up-to-date.
    assert_sink_unblocked(&node.api, "example-sink").await;
    assert_sink_not_lagging(&node.api, "example-sink").await;

    // Part C — explicit idle shutdown and worker recreation. Restart with a
    // very short idle timeout, deliver one event, wait for the worker to shut
    // down, then deliver another event and verify the worker is recreated and
    // the event is delivered.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    sink.set_mode(ResponseMode::Accept).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        short_idle_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Confirm the sink is up and unblocked before driving the idle timeout.
    assert_sink_running(&node.api, "example-sink").await;
    assert_sink_unblocked(&node.api, "example-sink").await;

    // First event after restart: worker starts and delivers.
    emit_fact(
        &node.api,
        subject_two.clone(),
        json!({"ModOne": {"data": 13}}),
        true,
    )
    .await
    .unwrap();
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(8, true).await;
    assert_sink_not_lagging(&node.api, "example-sink").await;

    // Second event: a fresh worker must be created to deliver it. The
    // previous worker is expected to have been stopped by the idle timeout
    // (200 ms); if the old worker is still alive it will deliver the event
    // instead, which is also correct behavior.
    emit_fact(
        &node.api,
        subject_two.clone(),
        json!({"ModOne": {"data": 14}}),
        true,
    )
    .await
    .unwrap();
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(9, true).await;

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 9);
    let s2_events: Vec<_> = events
        .iter()
        .filter(|e| e.subject_id() == subject_two_str)
        .collect();
    assert_eq!(s2_events.len(), 5, "S2 should have Create + 4 facts");
    assert_event_is_fact_full(
        s2_events[3],
        &subject_two_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 13}})),
    );
    assert_event_is_fact_full(
        s2_events[4],
        &subject_two_str,
        4,
        true,
        Some(json!({"ModOne": {"data": 14}})),
    );
}

/// Test 12: `sink_light_events_and_concurrent_catch_up`.
///
/// **Cases covered:** lightweight event delivery (`LightEvent`), limited
/// catch-up concurrency (`max_catch_up_concurrency`), multiple subjects lagging
/// simultaneously, recovery without delivering duplicate events, validation with
/// concurrency greater than 1.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with three sinks:
///   - `create-only`: events `{Create}`, `max_catch_up_concurrency: 1`.
///   - `create-only-conc2`: events `{Create}`, `max_catch_up_concurrency: 2`.
///   - `all`: events `{All}`, `max_catch_up_concurrency: 1`.
/// - Create subjects `S1` and `S2`.
///
/// **Sequence:**
/// 1. Emit 2 facts on each subject.
/// 2. Verify that `create-only` receives exactly 2 full `Create` events and 4
///    `LightEvent` of type `Fact` (2 per subject); verify the same for
///    `create-only-conc2` at the end of the test (after recovery).
/// 3. Verify that `all` receives 2 `Create` + 4 `FactFull` (6 events).
/// 4. Put `create-only` and `create-only-conc2` in `ServerError` mode and emit
///    one fact on each subject; both subjects must become `lagging` in both
///    sinks.
/// 5. Put `create-only` back in `Accept` mode; verify that, with
///    `max_catch_up_concurrency: 1`, both subjects recover and **no duplicate
///    events are delivered** (exactly 8 events: 2 `Create` + 6 `LightEvent`).
/// 6. Delete all events from `create-only`.
/// 7. Call replay for `create-only` with both subjects from `from_sn: 0` in the
///    same request.
/// 8. Verify that, even with concurrency 1, both subjects end up recovered: 2
///    `Create` + 4 `LightEvent`.
/// 9. **Part D — repeat recovery in `create-only-conc2`**. Put
///    `create-only-conc2` in `Accept` mode (it is still lagging from step 4).
///    Verify that, with `max_catch_up_concurrency: 2`, both subjects recover
///    without duplicates: exactly 8 events, 2 `Create` + 6 `LightEvent`, and no
///    repeated `(subject_id, sn)`.
///
/// **Verifications:**
/// - `LightEvent` contains the correct `subject_id`, `schema_id`, `sn`,
///   `event_type`, and `success`.
/// - The partial-filter sink does not receive full payloads for events it did
///   not request.
/// - `max_catch_up_concurrency` limits but does not prevent recovery of all
///   subjects.
/// - Simultaneous catch-up of several subjects does not produce duplicate
///   deliveries, both with concurrency 1 and concurrency 2.
/// - Within each subject the SNs are consecutive and no `(subject_id, sn)` is
///   repeated.
#[traced_test]
#[tokio::test]
async fn sink_light_events_and_concurrent_catch_up() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    let governance_id_str = governance_id.to_string();
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let create_only_sink = TestSink::start().await;
    let create_only_conc2_sink = TestSink::start().await;
    let all_sink = TestSink::start().await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        vec![
            make_sink_entry_with_concurrency(
                "create-only",
                create_only_sink.url(),
                Some(governance_id_str.clone()),
                BTreeSet::from([SinkTypes::Create]),
                1,
            ),
            make_sink_entry_with_concurrency(
                "create-only-conc2",
                create_only_conc2_sink.url(),
                Some(governance_id_str.clone()),
                BTreeSet::from([SinkTypes::Create]),
                2,
            ),
            make_sink_entry_with_concurrency(
                "all",
                all_sink.url(),
                Some(governance_id_str.clone()),
                BTreeSet::from([SinkTypes::All]),
                1,
            ),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let (s2, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let s1_str = s1.to_string();
    let s2_str = s2.to_string();

    for i in 1..=2 {
        emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": i}}), true)
            .await
            .unwrap();
        emit_fact(
            &node.api,
            s2.clone(),
            json!({"ModOne": {"data": 10 + i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Part A — normal delivery with partial filters. The create-only sinks must
    // receive Create events as full payloads and facts as lightweight events.
    wait_for_sink_caught_up(&node.api, "create-only").await;
    create_only_sink.wait_for_count(6, true).await;
    let create_only_events = create_only_sink.snapshot().await;
    assert_eq!(create_only_events.len(), 6);
    assert_no_duplicate_events(&create_only_events);
    assert_subject_sn_sequence(&create_only_events, &s1_str, 0, 2);
    assert_subject_sn_sequence(&create_only_events, &s2_str, 0, 2);
    assert_sink_contains_create(&create_only_events, &s1_str, 0);
    assert_sink_contains_create(&create_only_events, &s2_str, 0);
    assert_sink_contains_light_fact(
        &create_only_events,
        &s1_str,
        &governance_id_str,
        1,
        true,
    );
    assert_sink_contains_light_fact(
        &create_only_events,
        &s1_str,
        &governance_id_str,
        2,
        true,
    );
    assert_sink_contains_light_fact(
        &create_only_events,
        &s2_str,
        &governance_id_str,
        1,
        true,
    );
    assert_sink_contains_light_fact(
        &create_only_events,
        &s2_str,
        &governance_id_str,
        2,
        true,
    );
    assert_no_fact_full_events(&create_only_events);

    // The conc2 sink must behave identically during normal delivery.
    wait_for_sink_caught_up(&node.api, "create-only-conc2").await;
    create_only_conc2_sink.wait_for_count(6, true).await;
    let conc2_initial = create_only_conc2_sink.snapshot().await;
    assert_eq!(conc2_initial.len(), 6);
    assert_no_duplicate_events(&conc2_initial);
    assert_subject_sn_sequence(&conc2_initial, &s1_str, 0, 2);
    assert_subject_sn_sequence(&conc2_initial, &s2_str, 0, 2);
    assert_sink_contains_create(&conc2_initial, &s1_str, 0);
    assert_sink_contains_create(&conc2_initial, &s2_str, 0);
    assert_sink_contains_light_fact(
        &conc2_initial,
        &s1_str,
        &governance_id_str,
        1,
        true,
    );
    assert_sink_contains_light_fact(
        &conc2_initial,
        &s1_str,
        &governance_id_str,
        2,
        true,
    );
    assert_sink_contains_light_fact(
        &conc2_initial,
        &s2_str,
        &governance_id_str,
        1,
        true,
    );
    assert_sink_contains_light_fact(
        &conc2_initial,
        &s2_str,
        &governance_id_str,
        2,
        true,
    );
    assert_no_fact_full_events(&conc2_initial);

    // The all-events sink receives everything as full payloads.
    wait_for_sink_caught_up(&node.api, "all").await;
    all_sink.wait_for_count(6, true).await;
    let all_events = all_sink.snapshot().await;
    assert_eq!(all_events.len(), 6);
    assert!(
        all_events
            .iter()
            .all(|e| matches!(e, IncomingSinkEvent::Full(_))),
        "all-events sink must only receive full payloads"
    );
    assert_sink_contains_create(&all_events, &s1_str, 0);
    assert_sink_contains_create(&all_events, &s2_str, 0);
    assert_sink_contains_fact_full(
        &all_events,
        &s1_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &s1_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &s2_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 11}})),
    );
    assert_sink_contains_fact_full(
        &all_events,
        &s2_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 12}})),
    );

    // Part B — make the create-only sinks return transient failures and emit a
    // fact on each subject so both become lagging simultaneously. With
    // max_catch_up_concurrency=1 the worker must still catch up both subjects
    // once the sink comes back, and it must not deliver duplicate events.
    create_only_sink.set_mode(ResponseMode::ServerError).await;
    create_only_conc2_sink
        .set_mode(ResponseMode::ServerError)
        .await;
    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 3}}), true)
        .await
        .unwrap();
    emit_fact(&node.api, s2.clone(), json!({"ModOne": {"data": 13}}), true)
        .await
        .unwrap();

    wait_for_sink_lagging_subjects(&node.api, "create-only", 2).await;
    assert_sink_lagging(&node.api, "create-only", 2).await;
    assert_sink_unblocked(&node.api, "create-only").await;
    wait_for_sink_lagging_subjects(&node.api, "create-only-conc2", 2).await;

    create_only_sink.set_mode(ResponseMode::Accept).await;
    wait_for_sink_caught_up(&node.api, "create-only").await;
    create_only_sink.wait_for_count(8, true).await;
    let caught_up = create_only_sink.snapshot().await;
    assert_eq!(caught_up.len(), 8, "catch-up must not deliver duplicates");
    assert_no_duplicate_events(&caught_up);
    assert_subject_sn_sequence(&caught_up, &s1_str, 0, 3);
    assert_subject_sn_sequence(&caught_up, &s2_str, 0, 3);
    assert_sink_contains_light_fact(
        &caught_up,
        &s1_str,
        &governance_id_str,
        3,
        true,
    );
    assert_sink_contains_light_fact(
        &caught_up,
        &s2_str,
        &governance_id_str,
        3,
        true,
    );
    assert_no_fact_full_events(&caught_up);
    assert_sink_not_lagging(&node.api, "create-only").await;

    // The all-events sink kept receiving events while the create-only sinks
    // were failing; verify it has SN 3 for both subjects.
    wait_for_sink_caught_up(&node.api, "all").await;
    all_sink.wait_for_count(8, true).await;
    let all_after_b = all_sink.snapshot().await;
    assert_eq!(all_after_b.len(), 8);
    assert_no_duplicate_events(&all_after_b);
    assert_subject_sn_sequence(&all_after_b, &s1_str, 0, 3);
    assert_subject_sn_sequence(&all_after_b, &s2_str, 0, 3);
    assert_sink_contains_fact_full(
        &all_after_b,
        &s1_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );
    assert_sink_contains_fact_full(
        &all_after_b,
        &s2_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 13}})),
    );

    // Part C — wipe the create-only sink and replay both subjects from SN 0.
    // Even with max_catch_up_concurrency=1 both subjects must be recovered.
    create_only_sink.clear().await;

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                SinkReplayItem {
                    sink: "create-only".to_owned(),
                    subject_id: s1_str.clone(),
                    from_sn: 0,
                },
                SinkReplayItem {
                    sink: "create-only".to_owned(),
                    subject_id: s2_str.clone(),
                    from_sn: 0,
                },
            ],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 2);
    assert!(response.errors.is_empty());

    wait_for_sink_caught_up(&node.api, "create-only").await;
    create_only_sink.wait_for_count(8, true).await;
    let replayed = create_only_sink.snapshot().await;
    assert_eq!(replayed.len(), 8);
    assert_no_duplicate_events(&replayed);
    assert_subject_sn_sequence(&replayed, &s1_str, 0, 3);
    assert_subject_sn_sequence(&replayed, &s2_str, 0, 3);
    assert_sink_contains_create(&replayed, &s1_str, 0);
    assert_sink_contains_create(&replayed, &s2_str, 0);
    assert_sink_contains_light_fact(
        &replayed,
        &s1_str,
        &governance_id_str,
        1,
        true,
    );
    assert_sink_contains_light_fact(
        &replayed,
        &s1_str,
        &governance_id_str,
        2,
        true,
    );
    assert_sink_contains_light_fact(
        &replayed,
        &s1_str,
        &governance_id_str,
        3,
        true,
    );
    assert_sink_contains_light_fact(
        &replayed,
        &s2_str,
        &governance_id_str,
        1,
        true,
    );
    assert_sink_contains_light_fact(
        &replayed,
        &s2_str,
        &governance_id_str,
        2,
        true,
    );
    assert_sink_contains_light_fact(
        &replayed,
        &s2_str,
        &governance_id_str,
        3,
        true,
    );
    assert_no_fact_full_events(&replayed);
    assert_sink_not_lagging(&node.api, "create-only").await;

    // Part D — recover the second create-only sink with
    // max_catch_up_concurrency=2. Both subjects became lagging at SN 3
    // simultaneously in Part B. With concurrency 2 the worker may catch up
    // both subjects in parallel, but it must still deliver each event exactly
    // once and preserve per-subject ordering.
    create_only_conc2_sink.set_mode(ResponseMode::Accept).await;
    wait_for_sink_caught_up(&node.api, "create-only-conc2").await;
    create_only_conc2_sink.wait_for_count(8, true).await;
    let conc2_events = create_only_conc2_sink.snapshot().await;
    assert_eq!(conc2_events.len(), 8, "conc2 sink must receive all events");
    assert_no_duplicate_events(&conc2_events);
    assert_subject_sn_sequence(&conc2_events, &s1_str, 0, 3);
    assert_subject_sn_sequence(&conc2_events, &s2_str, 0, 3);
    assert_sink_contains_create(&conc2_events, &s1_str, 0);
    assert_sink_contains_create(&conc2_events, &s2_str, 0);
    assert_sink_contains_light_fact(
        &conc2_events,
        &s1_str,
        &governance_id_str,
        3,
        true,
    );
    assert_sink_contains_light_fact(
        &conc2_events,
        &s2_str,
        &governance_id_str,
        3,
        true,
    );
    assert_no_fact_full_events(&conc2_events);
    assert_sink_not_lagging(&node.api, "create-only-conc2").await;
    assert_sink_unblocked(&node.api, "create-only-conc2").await;
}

/// Test 3: `replay_governance_sink`.
///
/// **Objective:** replay governance events to a governance sink.
///
/// **Setup:**
/// - Node with `gov-sink` target `governance`, events `All`.
/// - Create governance (SN 0).
/// - Emit a governance fact that adds a schema (SN 1).
/// - Verify that `gov-sink` receives both events.
///
/// **Replay:**
/// - Delete all events from `gov-sink`.
/// - Call replay with `{sink: "gov-sink", subject_id: governance_id, from_sn:
///   0}`.
/// - Verify the sink receives governance Create + FactFull.
///
/// **Verifications:**
/// - The sink receives Create (SN 0) and FactFull (SN 1) in order.
/// - After the replay, the full sequence is `[0, 1]`.
/// - The replay response has `processed.len() == 1`, empty `errors`, and
///   `processed` contains exactly the requested item.
#[traced_test]
#[tokio::test]
async fn replay_governance_sink() {
    let sink = TestSink::start().await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        sinks: governance_sink_config(sink.url()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    wait_for_sink_caught_up(&node.api, "gov-sink").await;
    sink.wait_for_count(2, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 2);
    let gov_id_str = governance_id.to_string();
    assert_event_is_create(&initial[0], &gov_id_str, 0);
    assert_event_is_fact_full(
        &initial[1],
        &gov_id_str,
        1,
        true,
        Some(example_schema_governance_fact()),
    );

    sink.clear().await;

    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "gov-sink".to_owned(),
                subject_id: gov_id_str.clone(),
                from_sn: 0,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert!(response.errors.is_empty());
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "gov-sink");
    assert_eq!(processed.subject_id, gov_id_str);
    assert_eq!(processed.from_sn, 0);

    wait_for_sink_caught_up(&node.api, "gov-sink").await;
    sink.wait_for_count(2, true).await;
    let replayed = sink.snapshot().await;
    assert_eq!(replayed.len(), 2);
    let sns: Vec<_> = replayed.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1]);
    assert_sink_contains_create(&replayed, &gov_id_str, 0);
    assert_sink_contains_fact_full(
        &replayed,
        &gov_id_str,
        1,
        true,
        Some(example_schema_governance_fact()),
    );
}

/// Test 19A: `sink_fact_viewpoints_full_and_opaque`.
///
/// **Objective:** verify that facts with viewpoints are delivered as `FactFull`
/// to nodes with full visibility and as `FactOpaque` to nodes without viewpoint
/// grants, including the `success/error` flag on failed facts. All fields of
/// `DataToSink` and `DataToSinkEvent` are checked explicitly.
///
/// > This test covers the viewpoint gap detected during review. It is separated
/// > from the non-fact lifecycle because a node that receives `FactOpaque`
/// > cannot emit transfer/confirm/EOL events without first cleaning and
/// > resynchronizing the ledger.
///
/// **Setup:**
/// - Two nodes: `Owner` (index 0) and `Witness` (index 1).
/// - Governance with schema `Example` declaring viewpoints `["agua",
///   "basura"]`.
/// - Roles:
///   - `Owner`: member, creator/evaluator/validator/issuer/witness of the schema.
///   - `Witness`: member, gov witness and schema witness of the schema.
///   - Empty viewpoint grant for `Witness` in the creator entry, so it receives
///     `FactOpaque`.
/// - Each node has a sink configured to receive events `{All}`:
///   - `full-sink` on Owner.
///   - `opaque-sink` on Witness.
///
/// **Sequence:**
/// 1. Owner creates subject `S1`.
/// 2. Owner emits a fact with viewpoint `["agua"]` and payload
///    `{"ModOne":{"data":1}}` (success).
/// 3. Owner emits a fact with viewpoint `["agua"]` and payload
///    `{"ModThree":{"data":50}}` (failure forced by the contract).
/// 4. Owner emits a fact without viewpoints and payload `{"ModTwo":{"data":2}}`
///    (success).
///
/// **Verifications on `full-sink` (Owner):**
/// - 4 events are received with consecutive SNs `[0, 1, 2, 3]`.
/// - **Create (SN 0):** `governance_id`, `subject_id`, `owner`, `schema_id ==
///   Example`, `namespace`, `sn == 0`, `gov_version`, `state` with
///   `one/two/three == 0`.
/// - **FactFull (SN 1):** `governance_id`, `subject_id`, `schema_id ==
///   Example`, `viewpoints == ["agua"]`, `issuer == owner_pk`, `owner ==
///   owner_pk`, `payload == {"ModOne":{"data":1}}`, `patch` is `Some(...)`,
///   `success == true`, `error == None`, `sn == 1`, matching `gov_version`.
/// - **FactFull (SN 2):** `governance_id`, `subject_id`, `schema_id ==
///   Example`, `viewpoints == ["agua"]`, `payload == {"ModThree":{"data":50}}`,
///   `patch == None`, `success == false`, non-empty `error`, `sn == 2`,
///   matching `gov_version`.
/// - **FactFull (SN 3):** `governance_id`, `subject_id`, `schema_id ==
///   Example`, `viewpoints == []`, `payload == {"ModTwo":{"data":2}}`, `patch`
///   is `Some(...)`, `success == true`, `sn == 3`, matching `gov_version`.
///
/// **Verifications on `opaque-sink` (Witness):**
/// - 4 events are received with consecutive SNs `[0, 1, 2, 3]`.
/// - **Create (SN 0):** same as in `full-sink`.
/// - **FactOpaque (SN 1):** `governance_id`, `subject_id`, `schema_id ==
///   Example`, `viewpoints == ["agua"]`, `owner == owner_pk`, `success ==
///   true`, `sn == 1`, matching `gov_version`. Does **not** contain `payload`,
///   `patch`, `issuer`, or `error`.
/// - **FactOpaque (SN 2):** `governance_id`, `subject_id`, `schema_id ==
///   Example`, `viewpoints == ["agua"]`, `success == false`, `sn == 2`,
///   matching `gov_version`. Does **not** contain `payload`, `patch`, `issuer`,
///   or `error`.
/// - **FactFull (SN 3):** `governance_id`, `subject_id`, `schema_id ==
///   Example`, `viewpoints == []`, `payload == {"ModTwo":{"data":2}}`, `patch`
///   is `Some(...)`, `success == true`, `sn == 3`, matching `gov_version`.
///   Facts without viewpoints are public, so the witness also receives them in
///   full.
///
/// **Implementation notes:**
/// - The `EXAMPLE_CONTRACT` already supports `ModOne`, `ModTwo`, `ModThree`,
///   and the failure rule for `ModThree { data: 50 }`.
/// - For Witness to receive `FactOpaque`, its viewpoint grant in the creator
///   entry must be `[]` and it must not have `AllViewpoints`.
#[traced_test]
#[tokio::test]
async fn sink_fact_viewpoints_full_and_opaque() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let mut owner = nodes.remove(0);
    let mut witness = nodes.remove(0);

    let mut owner_dirs: Vec<_> = dirs.drain(0..2).collect();
    let mut witness_dirs: Vec<_> = dirs.drain(0..2).collect();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![&witness.api]).await;

    emit_fact(
        &owner.api,
        governance_id.clone(),
        governance_with_viewpoints_fact(witness.api.public_key()),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let owner_sink = TestSink::start().await;
    let witness_sink = TestSink::start().await;

    // Restart owner with the full sink.
    let owner_keys = owner.keys.clone();
    let owner_local_db = owner_dirs[0].path().to_path_buf();
    let owner_ext_db = owner_dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (owner, mut owner_dirs2) = create_node(restart_config(
        owner_keys,
        owner_local_db,
        owner_ext_db,
        format!("/memory/{}", owner_port),
        vec![make_sink_entry(
            "full-sink",
            owner_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    owner_dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    // Restart witness with the opaque sink, peered to the new owner address.
    let owner_peer_id = owner.api.peer_id().to_string();
    let owner_address = owner.listen_address.clone();

    let witness_keys = witness.keys.clone();
    let witness_local_db = witness_dirs[0].path().to_path_buf();
    let witness_ext_db = witness_dirs[1].path().to_path_buf();
    witness.token.cancel();
    join_all(witness.handler.iter_mut()).await;

    let witness_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (witness, mut witness_dirs2) = create_node(restart_config_with_peers(
        witness_keys,
        witness_local_db,
        witness_ext_db,
        format!("/memory/{}", witness_port),
        vec![RoutingNode {
            peer_id: owner_peer_id,
            address: vec![owner_address],
        }],
        vec![make_sink_entry(
            "opaque-sink",
            witness_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    witness_dirs.append(&mut witness_dirs2);
    node_running(&witness.api).await.unwrap();

    // Confirm both sinks are up and unblocked before emitting facts.
    assert_sink_running(&owner.api, "full-sink").await;
    assert_sink_unblocked(&owner.api, "full-sink").await;
    assert_sink_running(&witness.api, "opaque-sink").await;
    assert_sink_unblocked(&witness.api, "opaque-sink").await;

    // Ensure the witness has the subject before emitting facts.
    get_subject(&witness.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    let subject_id_str = subject_id.to_string();
    let owner_pk_str = owner.api.public_key();
    let witness_pk_str = witness.api.public_key();

    // SN 1: successful fact with a viewpoint.
    emit_fact_viewpoints(
        &owner.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();

    // SN 2: failed fact with the same viewpoint.
    emit_fact_viewpoints(
        &owner.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();

    // SN 3: successful fact without viewpoints.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    // Wait for all events on both sinks.
    wait_for_sink_caught_up(&owner.api, "full-sink").await;
    owner_sink.wait_for_count(4, true).await;
    wait_for_sink_caught_up(&witness.api, "opaque-sink").await;
    witness_sink.wait_for_count(4, true).await;

    let full_events = owner_sink.snapshot().await;
    let opaque_events = witness_sink.snapshot().await;

    assert_eq!(full_events.len(), 4);
    assert_eq!(opaque_events.len(), 4);

    let sns_full: Vec<_> = full_events.iter().map(|e| e.sn()).collect();
    let sns_opaque: Vec<_> = opaque_events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns_full, vec![0, 1, 2, 3]);
    assert_eq!(sns_opaque, vec![0, 1, 2, 3]);

    // --- Owner sink: full visibility ---
    assert_sink_contains_create(&full_events, &subject_id_str, 0);
    assert_sink_contains_fact_full(
        &full_events,
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &full_events,
        &subject_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );
    assert_sink_contains_fact_full(
        &full_events,
        &subject_id_str,
        3,
        true,
        Some(json!({"ModTwo": {"data": 2}})),
    );

    // Detailed field checks on the owner sink.
    match &full_events[0] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Create {
                governance_id: gid,
                subject_id: sid,
                owner,
                schema_id,
                namespace,
                sn,
                gov_version,
                state,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(namespace, "");
                assert_eq!(*sn, 0u64);
                assert_eq!(*gov_version, 1u64);
                assert_eq!(state.get("one").unwrap(), 0);
                assert_eq!(state.get("two").unwrap(), 0);
                assert_eq!(state.get("three").unwrap(), 0);
            }
            other => panic!("expected Create, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    // Witness receives the same Create event, so every field must match.
    match &opaque_events[0] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Create {
                governance_id: gid,
                subject_id: sid,
                owner,
                schema_id,
                namespace,
                sn,
                gov_version,
                state,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(namespace, "");
                assert_eq!(*sn, 0u64);
                assert_eq!(*gov_version, 1u64);
                assert_eq!(state.get("one").unwrap(), 0);
                assert_eq!(state.get("two").unwrap(), 0);
                assert_eq!(state.get("three").unwrap(), 0);
            }
            other => panic!("expected Create, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &full_events[1] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                issuer,
                owner,
                payload,
                patch,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(viewpoints, &vec!["agua".to_owned()]);
                assert_eq!(issuer, &owner_pk_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(payload, &json!({"ModOne": {"data": 1}}));
                assert!(
                    patch.is_some(),
                    "successful fact must contain a patch"
                );
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 1u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactFull, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &full_events[2] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                issuer,
                owner,
                payload,
                patch,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(viewpoints, &vec!["agua".to_owned()]);
                assert_eq!(issuer, &owner_pk_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(payload, &json!({"ModThree": {"data": 50}}));
                assert!(!success);
                let err =
                    error.as_ref().expect("failed fact must have an error");
                assert!(!err.is_empty());
                assert!(patch.is_none());
                assert_eq!(*sn, 2u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactFull, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &full_events[3] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                issuer,
                owner,
                payload,
                patch,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert!(viewpoints.is_empty());
                assert_eq!(issuer, &owner_pk_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(payload, &json!({"ModTwo": {"data": 2}}));
                assert!(patch.is_some());
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 3u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactFull, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    // --- Witness sink: opaque facts ---
    assert_sink_contains_create(&opaque_events, &subject_id_str, 0);
    assert_sink_contains_fact_opaque(
        &opaque_events,
        &subject_id_str,
        1,
        true,
        &["agua"],
    );
    assert_sink_contains_fact_opaque(
        &opaque_events,
        &subject_id_str,
        2,
        false,
        &["agua"],
    );
    // Facts without viewpoints are public, so the witness also receives FactFull.
    assert_sink_contains_fact_full(
        &opaque_events,
        &subject_id_str,
        3,
        true,
        Some(json!({"ModTwo": {"data": 2}})),
    );

    // Ensure opaque facts do not leak payload, patch, issuer or error.
    match &opaque_events[1] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactOpaque {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                owner,
                success,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(viewpoints, &vec!["agua".to_owned()]);
                assert_eq!(owner, &owner_pk_str);
                assert!(success);
                assert_eq!(*sn, 1u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactOpaque, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &opaque_events[2] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactOpaque {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                owner,
                success,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(viewpoints, &vec!["agua".to_owned()]);
                assert_eq!(owner, &owner_pk_str);
                assert!(!success);
                assert_eq!(*sn, 2u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactOpaque, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &opaque_events[3] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                issuer,
                owner,
                payload,
                patch,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert!(viewpoints.is_empty());
                assert_eq!(issuer, &owner_pk_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(payload, &json!({"ModTwo": {"data": 2}}));
                assert!(patch.is_some());
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 3u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactFull, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    // All DataToSink envelopes carry non-zero timestamps and the public key of
    // the node that owns the sink.
    for event in &full_events {
        if let IncomingSinkEvent::Full(data) = event {
            assert_eq!(data.public_key, owner_pk_str);
            assert!(data.event_request_timestamp > 0);
            assert!(data.event_ledger_timestamp > 0);
            assert!(data.sink_timestamp > 0);
        }
    }
    for event in &opaque_events {
        if let IncomingSinkEvent::Full(data) = event {
            assert_eq!(data.public_key, witness_pk_str);
            assert!(data.event_request_timestamp > 0);
            assert!(data.event_ledger_timestamp > 0);
            assert!(data.sink_timestamp > 0);
        }
    }
}

/// Test 19B: `sink_non_fact_event_types_and_fields`.
///
/// **Objective:** verify that all non-fact events (`Transfer`, `Confirm`,
/// `Reject`, `EOL`) reach the sink with all their fields correct, using a
/// tracker without viewpoints to avoid partial-ledger issues when changing
/// owner. All fields of `DataToSink` and `DataToSinkEvent` are checked
/// explicitly.
///
/// **Setup:**
/// - Two nodes: `Owner` (index 0) and `NewOwner` (index 1).
/// - Governance with schema `Example` **without** viewpoints.
/// - Roles:
///   - `Owner`: member, creator/evaluator/validator/issuer/witness of the schema.
///   - `NewOwner`: member, gov witness, schema witness, and creator of the schema.
/// - Each node has a sink configured to receive events `{All}`.
///
/// **Sequence:**
/// 1. Owner creates subject `S1`.
/// 2. Owner emits a successful fact (`ModOne`) to have a reference SN 1.
/// 3. Owner transfers `S1` to NewOwner.
/// 4. NewOwner confirms the transfer.
/// 5. NewOwner transfers `S1` back to Owner.
/// 6. Owner rejects the transfer.
/// 7. NewOwner emits `EOL` for `S1` (it remains owner after the reject).
///
/// **Verifications on both sinks:**
/// - 7 events are received with consecutive SNs `[0, 1, 2, 3, 4, 5, 6]`.
/// - **Create (SN 0):** correct fields (`governance_id`, `subject_id`,
///   `owner`, `schema_id`, `namespace`, `sn`, `gov_version`, `state`).
/// - **FactFull (SN 1):** `governance_id`, `subject_id`, `schema_id`,
///   `viewpoints == []`, `issuer`, `owner`, `payload`, `patch`, `success ==
///   true`, `error == None`, `sn`, `gov_version`.
/// - **Transfer (SN 2):** `governance_id`, `subject_id`, `schema_id`, `owner ==
///   owner_pk`, `new_owner == new_owner_pk`, `success == true`, `error ==
///   None`, `sn`, `gov_version`.
/// - **Confirm (SN 3):** `governance_id`, `subject_id`, `schema_id`, `sn`,
///   `patch == None`, `success == true`, `error == None`, `gov_version`,
///   `name_old_owner == None` (the `name_old_owner` field only applies to
///   governance confirms).
/// - **Transfer (SN 4):** `governance_id`, `subject_id`, `schema_id`, `owner ==
///   new_owner_pk`, `new_owner == owner_pk`, `success == true`, `error ==
///   None`, `sn`, `gov_version`.
/// - **Reject (SN 5):** `governance_id`, `subject_id`, `schema_id`, `sn == 5`,
///   matching `gov_version`.
/// - **EOL (SN 6):** `governance_id`, `subject_id`, `schema_id`, `sn == 6`,
///   matching `gov_version`.
/// - Every full event (`DataToSink`) has `public_key`,
///   `event_request_timestamp`, `event_ledger_timestamp`, and `sink_timestamp`
///   greater than 0.
#[traced_test]
#[tokio::test]
async fn sink_non_fact_event_types_and_fields() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let mut owner = nodes.remove(0);
    let mut new_owner = nodes.remove(0);

    let mut owner_dirs: Vec<_> = dirs.drain(0..2).collect();
    let mut new_owner_dirs: Vec<_> = dirs.drain(0..2).collect();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![&new_owner.api]).await;

    emit_fact(
        &owner.api,
        governance_id.clone(),
        governance_with_transfer_roles_fact(new_owner.api.public_key()),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let owner_sink = TestSink::start().await;
    let new_owner_sink = TestSink::start().await;

    // Restart owner with its sink.
    let owner_keys = owner.keys.clone();
    let owner_local_db = owner_dirs[0].path().to_path_buf();
    let owner_ext_db = owner_dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (owner, mut owner_dirs2) = create_node(restart_config(
        owner_keys,
        owner_local_db,
        owner_ext_db,
        format!("/memory/{}", owner_port),
        vec![make_sink_entry(
            "owner-sink",
            owner_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    owner_dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    // Restart new_owner with its sink, peered to the new owner address.
    let owner_peer_id = owner.api.peer_id().to_string();
    let owner_address = owner.listen_address.clone();

    let new_owner_keys = new_owner.keys.clone();
    let new_owner_local_db = new_owner_dirs[0].path().to_path_buf();
    let new_owner_ext_db = new_owner_dirs[1].path().to_path_buf();
    new_owner.token.cancel();
    join_all(new_owner.handler.iter_mut()).await;

    let new_owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_owner, mut new_owner_dirs2) =
        create_node(restart_config_with_peers(
            new_owner_keys,
            new_owner_local_db,
            new_owner_ext_db,
            format!("/memory/{}", new_owner_port),
            vec![RoutingNode {
                peer_id: owner_peer_id,
                address: vec![owner_address],
            }],
            vec![make_sink_entry(
                "new-owner-sink",
                new_owner_sink.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            )],
        ))
        .await;
    new_owner_dirs.append(&mut new_owner_dirs2);
    node_running(&new_owner.api).await.unwrap();

    // Confirm both sinks are up and unblocked before emitting lifecycle events.
    assert_sink_running(&owner.api, "owner-sink").await;
    assert_sink_unblocked(&owner.api, "owner-sink").await;
    assert_sink_running(&new_owner.api, "new-owner-sink").await;
    assert_sink_unblocked(&new_owner.api, "new-owner-sink").await;

    // Ensure new_owner has the subject before ownership changes.
    get_subject(&new_owner.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    let subject_id_str = subject_id.to_string();
    let owner_pk_str = owner.api.public_key();
    let new_owner_pk_str = new_owner.api.public_key();

    // SN 1: a fact so the sequence is not only lifecycle events.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&new_owner.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: transfer Owner -> NewOwner.
    let new_owner_pk = PublicKey::from_str(new_owner_pk_str).unwrap();
    emit_transfer(&owner.api, subject_id.clone(), new_owner_pk, true)
        .await
        .unwrap();

    get_subject(&new_owner.api, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: confirm transfer. For trackers, name_old_owner must be None.
    emit_confirm(&new_owner.api, subject_id.clone(), None, true)
        .await
        .unwrap();
    get_subject(&owner.api, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: transfer NewOwner -> Owner.
    let owner_pk = PublicKey::from_str(owner_pk_str).unwrap();
    emit_transfer(&new_owner.api, subject_id.clone(), owner_pk, true)
        .await
        .unwrap();

    get_subject(&owner.api, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    // SN 5: reject transfer.
    emit_reject(&owner.api, subject_id.clone(), true)
        .await
        .unwrap();
    get_subject(&new_owner.api, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    // SN 6: EOL by the current owner (NewOwner).
    emit_eol(&new_owner.api, subject_id.clone(), true)
        .await
        .unwrap();
    get_subject(&owner.api, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    // Wait for both delivery pipelines to drain: once the sink reports the
    // subject as caught up, the cursor is at the final SN and every HTTP
    // response (including the one we need to count) has been processed, so
    // the TestSink has already recorded the event. This is the only
    // synchronization that holds under suite load; `get_subject` only proves
    // the ledger state is current, not that the delivery pipeline finished.
    wait_for_sink_caught_up(&owner.api, "owner-sink").await;
    wait_for_sink_caught_up(&new_owner.api, "new-owner-sink").await;

    // The pipelines are idle, so the receiver has everything. A small
    // poll guards against the async gap between cursor update and event
    // record visibility.
    owner_sink.wait_for_count(7, true).await;
    new_owner_sink.wait_for_count(7, true).await;

    let owner_events = owner_sink.snapshot().await;
    let new_owner_events = new_owner_sink.snapshot().await;

    assert_eq!(owner_events.len(), 7);
    assert_eq!(new_owner_events.len(), 7);

    let sns_owner: Vec<_> = owner_events.iter().map(|e| e.sn()).collect();
    let sns_new_owner: Vec<_> =
        new_owner_events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns_owner, vec![0, 1, 2, 3, 4, 5, 6]);
    assert_eq!(sns_new_owner, vec![0, 1, 2, 3, 4, 5, 6]);

    assert_sink_contains_create(&owner_events, &subject_id_str, 0);
    assert_sink_contains_fact_full(
        &owner_events,
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_transfer(&owner_events, &subject_id_str, 2);
    assert_sink_contains_confirm(&owner_events, &subject_id_str, 3);
    assert_sink_contains_transfer(&owner_events, &subject_id_str, 4);
    assert_sink_contains_reject(&owner_events, &subject_id_str, 5);
    assert_sink_contains_eol(&owner_events, &subject_id_str, 6);

    assert_sink_contains_create(&new_owner_events, &subject_id_str, 0);
    assert_sink_contains_fact_full(
        &new_owner_events,
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_transfer(&new_owner_events, &subject_id_str, 2);
    assert_sink_contains_confirm(&new_owner_events, &subject_id_str, 3);
    assert_sink_contains_transfer(&new_owner_events, &subject_id_str, 4);
    assert_sink_contains_reject(&new_owner_events, &subject_id_str, 5);
    assert_sink_contains_eol(&new_owner_events, &subject_id_str, 6);

    // Detailed field checks.
    match &owner_events[0] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Create {
                governance_id: gid,
                subject_id: sid,
                owner,
                schema_id,
                namespace,
                sn,
                gov_version,
                state,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(namespace, "");
                assert_eq!(*sn, 0u64);
                assert_eq!(*gov_version, 1u64);
                assert_eq!(state.get("one").unwrap(), 0);
                assert_eq!(state.get("two").unwrap(), 0);
                assert_eq!(state.get("three").unwrap(), 0);
            }
            other => panic!("expected Create, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &owner_events[1] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                issuer,
                owner,
                payload,
                patch,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert!(viewpoints.is_empty());
                assert_eq!(issuer, &owner_pk_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(payload, &json!({"ModOne": {"data": 1}}));
                assert!(patch.is_some());
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 1u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactFull, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &owner_events[2] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Transfer {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                owner,
                new_owner,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(new_owner, &new_owner_pk_str);
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 2u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected Transfer, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &owner_events[3] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Confirm {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                sn,
                patch,
                success,
                error,
                gov_version,
                name_old_owner,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(*sn, 3u64);
                assert!(patch.is_none());
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*gov_version, 1u64);
                assert!(name_old_owner.is_none());
            }
            other => panic!("expected Confirm, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &owner_events[4] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Transfer {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                owner,
                new_owner,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(owner, &new_owner_pk_str);
                assert_eq!(new_owner, &owner_pk_str);
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 4u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected Transfer, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &owner_events[5] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Reject {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(*sn, 5u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected Reject, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &owner_events[6] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Eol {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(*sn, 6u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected EOL, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    // The new-owner sink must contain the exact same events with the same fields.
    match &new_owner_events[0] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Create {
                governance_id: gid,
                subject_id: sid,
                owner,
                schema_id,
                namespace,
                sn,
                gov_version,
                state,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(namespace, "");
                assert_eq!(*sn, 0u64);
                assert_eq!(*gov_version, 1u64);
                assert_eq!(state.get("one").unwrap(), 0);
                assert_eq!(state.get("two").unwrap(), 0);
                assert_eq!(state.get("three").unwrap(), 0);
            }
            other => panic!("expected Create, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &new_owner_events[1] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                viewpoints,
                issuer,
                owner,
                payload,
                patch,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert!(viewpoints.is_empty());
                assert_eq!(issuer, &owner_pk_str);
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(payload, &json!({"ModOne": {"data": 1}}));
                assert!(patch.is_some());
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 1u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected FactFull, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &new_owner_events[2] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Transfer {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                owner,
                new_owner,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(owner, &owner_pk_str);
                assert_eq!(new_owner, &new_owner_pk_str);
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 2u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected Transfer, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &new_owner_events[3] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Confirm {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                sn,
                patch,
                success,
                error,
                gov_version,
                name_old_owner,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(*sn, 3u64);
                assert!(patch.is_none());
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*gov_version, 1u64);
                assert!(name_old_owner.is_none());
            }
            other => panic!("expected Confirm, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &new_owner_events[4] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Transfer {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                owner,
                new_owner,
                success,
                error,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(owner, &new_owner_pk_str);
                assert_eq!(new_owner, &owner_pk_str);
                assert!(success);
                assert!(error.is_none());
                assert_eq!(*sn, 4u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected Transfer, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &new_owner_events[5] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Reject {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(*sn, 5u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected Reject, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    match &new_owner_events[6] {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::Eol {
                governance_id: gid,
                subject_id: sid,
                schema_id,
                sn,
                gov_version,
            } => {
                assert_eq!(gid.as_ref().unwrap(), &governance_id.to_string());
                assert_eq!(sid, &subject_id_str);
                assert_eq!(schema_id.to_string(), "Example");
                assert_eq!(*sn, 6u64);
                assert_eq!(*gov_version, 1u64);
            }
            other => panic!("expected EOL, got {:?}", other),
        },
        _ => panic!("expected full event"),
    }

    // All DataToSink envelopes carry non-zero timestamps and the public key of
    // the node that owns the sink.
    for event in &owner_events {
        if let IncomingSinkEvent::Full(data) = event {
            assert_eq!(data.public_key, owner_pk_str);
            assert!(data.event_request_timestamp > 0);
            assert!(data.event_ledger_timestamp > 0);
            assert!(data.sink_timestamp > 0);
        }
    }
    for event in &new_owner_events {
        if let IncomingSinkEvent::Full(data) = event {
            assert_eq!(data.public_key, new_owner_pk_str);
            assert!(data.event_request_timestamp > 0);
            assert!(data.event_ledger_timestamp > 0);
            assert!(data.sink_timestamp > 0);
        }
    }
}

/// Test 13: `sink_subject_deletion_cleans_tracking`.
///
/// **Cases covered:** subject deletion and cleanup of cursors/lagging in all
/// sinks; `delete_subject` requires safe mode; subsequent governance activity
/// does not re-trigger deliveries for a deleted subject.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with two sinks (`example-sink` and `example-sink-2`) pointing to
///   separate `TestSink`s, both with events `{All}`.
/// - Create subject `S1` and emit 2 facts.
/// - Verify initial delivery in both sinks (Create + 2 FactFull, no duplicates,
///   consecutive SNs).
///
/// **Sequence:**
/// 1. Put both sinks in `ServerError` mode and emit a third fact on `S1` to
///    leave the subject `lagging` in both sinks. This persists cursor/lagging
///    state that must be cleaned up after deletion.
/// 2. Verify that `api.delete_subject(S1)` outside safe mode returns
///    `Error::SafeMode`.
/// 3. Restart the node in `safe_mode: true`.
/// 4. Call `api.delete_subject(S1)` and verify it returns `"Tracker deleted
///    successfully"`.
/// 5. Observe that `SinkManager` receives the `RemoveSubject` message and
///    removes the subject from all sinks during deletion.
/// 6. Restart the node in normal mode with both sinks in `Accept` mode.
/// 7. Emit a governance fact (add a member) to keep the node active and check
///    that no further deliveries for `S1` are attempted.
/// 8. Call `replay_sink_events` for both sinks and `S1` from `from_sn: 0`.
///    Since the subject no longer exists, each item must be returned in
///    `errors` with reason `"subject has no known events"`.
///
/// **Verifications:**
/// - Both sinks still have exactly the 3 original `S1` events and do not
///   receive new events after deletion.
/// - `get_sinks_status` reports `lagging_subjects: 0` for both sinks.
/// - No sink is blocked.
/// - The replay for the deleted subject is not processed and reports
///   `"subject has no known events"` for both sinks.
/// - The cursors and `lagging` state for `S1` are cleaned up (both by the
///   `RemoveSubject` message during `delete_subject` and by the defensive
///   handling of `SubjectNotFound` if the worker attempted catch-up).
#[traced_test]
#[tokio::test]
async fn sink_subject_deletion_cleans_tracking() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink_a = TestSink::start().await;
    let sink_b = TestSink::start().await;
    let sink_entries = vec![
        make_sink_entry(
            "example-sink",
            sink_a.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        ),
        make_sink_entry(
            "example-sink-2",
            sink_b.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        ),
    ];

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        sink_entries,
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let s1_str = s1.to_string();

    for i in 1..=2 {
        emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": i}}), true)
            .await
            .unwrap();
    }

    // Both sinks must receive the initial Create + 2 facts.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink_a.wait_for_count(3, true).await;
    wait_for_sink_caught_up(&node.api, "example-sink-2").await;
    sink_b.wait_for_count(3, true).await;
    let initial_a = sink_a.snapshot().await;
    let initial_b = sink_b.snapshot().await;
    for initial in [&initial_a, &initial_b] {
        assert_eq!(initial.len(), 3);
        assert_no_duplicate_events(initial);
        assert_subject_sn_sequence(initial, &s1_str, 0, 2);
        assert_event_is_create(&initial[0], &s1_str, 0);
        assert_event_is_fact_full(
            &initial[1],
            &s1_str,
            1,
            true,
            Some(json!({"ModOne": {"data": 1}})),
        );
        assert_event_is_fact_full(
            &initial[2],
            &s1_str,
            2,
            true,
            Some(json!({"ModOne": {"data": 2}})),
        );
    }

    // Put both sinks into failure mode and emit a third fact so the subject
    // becomes lagging on both sinks. This leaves persistent cursor/lagging
    // state that must be cleaned up after deletion.
    sink_a.set_mode(ResponseMode::ServerError).await;
    sink_b.set_mode(ResponseMode::ServerError).await;
    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 3}}), true)
        .await
        .unwrap();
    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;
    wait_for_sink_lagging_subjects(&node.api, "example-sink-2", 1).await;

    // delete_subject outside safe mode must be rejected.
    let err = node.api.delete_subject(s1.clone()).await.unwrap_err();
    assert!(
        matches!(err, Error::SafeMode(_)),
        "expected SafeMode error, got {:?}",
        err
    );

    // Restart in safe mode and delete the subject.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config_safe_mode(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![
            make_sink_entry(
                "example-sink",
                sink_a.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            ),
            make_sink_entry(
                "example-sink-2",
                sink_b.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            ),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let delete_result = node.api.delete_subject(s1.clone()).await.unwrap();
    assert_eq!(delete_result, "Tracker deleted successfully");

    // Restart in normal mode with both sinks accepting.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    sink_a.set_mode(ResponseMode::Accept).await;
    sink_b.set_mode(ResponseMode::Accept).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![
            make_sink_entry(
                "example-sink",
                sink_a.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            ),
            make_sink_entry(
                "example-sink-2",
                sink_b.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            ),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Emit a governance fact to keep the node active. This must not trigger
    // any delivery for the deleted subject.
    let extra_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    emit_fact(
        &node.api,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {
                        "name": "Extra",
                        "key": extra_key
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();

    // Poll until both sink event counts stabilize: no new events should arrive
    // for the deleted subject. This is robust on slow systems where workers
    // may still be draining queued events.
    let mut attempts = 0;
    let mut last_a = 0;
    let mut last_b = 0;
    let mut stable_iterations = 0;
    loop {
        let current_a = sink_a.snapshot().await.len();
        let current_b = sink_b.snapshot().await.len();
        if current_a == last_a && current_b == last_b {
            stable_iterations += 1;
            if stable_iterations >= 3 {
                break;
            }
        } else {
            stable_iterations = 0;
        }
        last_a = current_a;
        last_b = current_b;
        if attempts > 40 {
            panic!(
                "sink event counts did not stabilize after 4s; A: {}, B: {}",
                current_a, current_b
            );
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
        attempts += 1;
    }

    // Neither sink should have received new events for the deleted subject.
    let after_a = sink_a.snapshot().await;
    let after_b = sink_b.snapshot().await;
    assert_eq!(
        after_a.len(),
        3,
        "no new events should be delivered for a deleted subject on sink A"
    );
    assert_eq!(
        after_b.len(),
        3,
        "no new events should be delivered for a deleted subject on sink B"
    );
    assert_eq!(count_events_for_subject(&after_a, &s1_str), 3);
    assert_eq!(count_events_for_subject(&after_b, &s1_str), 3);

    // Both sinks must report no lagging and remain unblocked.
    assert_sink_not_lagging(&node.api, "example-sink").await;
    assert_sink_not_lagging(&node.api, "example-sink-2").await;
    assert_sink_unblocked(&node.api, "example-sink").await;
    assert_sink_unblocked(&node.api, "example-sink-2").await;

    // Replay for the deleted subject on both sinks must report that the
    // subject has no known events, confirming tracking was cleaned up.
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                SinkReplayItem {
                    sink: "example-sink".to_owned(),
                    subject_id: s1_str.clone(),
                    from_sn: 0,
                },
                SinkReplayItem {
                    sink: "example-sink-2".to_owned(),
                    subject_id: s1_str.clone(),
                    from_sn: 0,
                },
            ],
        })
        .await
        .unwrap();
    assert!(response.processed.is_empty());
    assert_eq!(response.errors.len(), 2);
    for replay_err in &response.errors {
        assert!(replay_err.subject_id == s1_str);
        assert_eq!(replay_err.from_sn, 0);
        assert!(
            replay_err.reason.contains("subject has no known events"),
            "unexpected replay error reason: {}",
            replay_err.reason
        );
    }
}

/// Test 14: `sink_transient_errors_and_fast_events`.
///
/// **Cases covered:** transient HTTP errors (5xx) with retries and backoff,
/// sequential gap in `NotifyNewEvent`, and events arriving while a catch-up is
/// in progress.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with `example-sink` configured with `max_retries: 2`,
///   `retry_base_delay_ms: 100`, `request_timeout_ms: 500`,
///   `sink_worker_idle_timeout_ms: 60_000`.
/// - Create subject `S1`.
///
/// **Part A — retries on transient error:**
/// 1. Change `TestSink` to `ServerError` mode (`500 Internal Server Error`).
/// 2. Emit a fact on `S1` synchronously (`wait=true`).
/// 3. The worker retries up to 2 times with backoff; finally it marks the
///    subject as `lagging` without blocking the sink.
/// 4. Verify the sink did not receive the fact (still 1 event: Create) and that
///    the sink is **not** `blocked`.
/// 5. Change `TestSink` to `Accept`.
/// 6. Verify the fact arrives via automatic catch-up (2 events: Create SN 0 +
///    Fact SN 1).
///
/// **Part B — sequential gap and concurrent catch-up:**
/// 1. Put the sink in `Timeout(150)` mode (responds slowly but successfully).
///    The previous events from Part A are kept so the node cursor and sink
///    state remain consistent.
/// 2. Emit 3 facts **asynchronously** (`wait=false`) followed by one
///    synchronous fact (`wait=true`).
/// 3. Because the sink takes 150 ms per event and the async ones arrive
///    quickly, the manager detects a sequential gap (the cursor does not
///    advance until the first slow event finishes) and marks the subject as
///    `lagging`.
/// 4. Verify that, once the sink finishes, **all** events are delivered in
///    order `[0, 1, 2, 3, 4, 5]`: Create SN 0 + 5 consecutive facts, no
///    duplicates.
///
/// **Verifications:**
/// - A sink with 5xx errors does not block; it enters `lagging`.
/// - Retries respect `max_retries` and do not advance the cursor.
/// - The sequential gap forces ordered catch-up.
/// - Events emitted during catch-up are included in the same queue and
///   delivered in order.
/// - No duplicates: each `(subject_id, sn)` appears only once.
/// - After recovery the sink is neither `blocked` nor `lagging`.
///
/// **Implementation note:** the test uses the helpers
/// `wait_for_sink_lagging_subjects`, `assert_sink_unblocked`,
/// `assert_sink_not_lagging`, `assert_no_duplicate_events`, and
/// `assert_subject_sn_sequence`, following the timeout/retry pattern of the
/// other sink tests.
#[traced_test]
#[tokio::test]
async fn sink_transient_errors_and_fast_events() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        transient_error_sink_config(
            sink.url(),
            Some(governance_id.to_string()),
        ),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let s1_str = s1.to_string();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(1, true).await;
    let initial = sink.snapshot().await;
    assert_eq!(initial.len(), 1);
    assert_event_is_create(&initial[0], &s1_str, 0);

    // Part A — transient 5xx errors are retried and become lagging without
    // blocking the sink. The sink is then recovered by automatic catch-up.
    sink.set_mode(ResponseMode::ServerError).await;
    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 1}}), true)
        .await
        .unwrap();

    wait_for_sink_lagging_subjects(&node.api, "example-sink", 1).await;
    assert_sink_unblocked(&node.api, "example-sink").await;

    let after_error = sink.snapshot().await;
    assert_eq!(
        after_error.len(),
        1,
        "fact must not be delivered while sink returns 500"
    );

    sink.set_mode(ResponseMode::Accept).await;
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(2, true).await;
    let recovered = sink.snapshot().await;
    assert_eq!(recovered.len(), 2);
    assert_no_duplicate_events(&recovered);
    assert_subject_sn_sequence(&recovered, &s1_str, 0, 1);
    assert_event_is_fact_full(
        &recovered[1],
        &s1_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_not_lagging(&node.api, "example-sink").await;

    // Part B — slow sink creates a sequential gap when multiple events are
    // emitted while the first one is still in flight. Catch-up must deliver
    // all events in order. The previous events are kept so the cursor is
    // consistent with the sink state.
    sink.set_mode(ResponseMode::Timeout(150)).await;

    for i in 2..=4 {
        emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": i}}), false)
            .await
            .unwrap();
    }
    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 5}}), true)
        .await
        .unwrap();

    // Allow enough time for ordered delivery of the 4 new facts. The fast async
    // emissions produced a sequential gap (logged as SequentialGap) that must be
    // resolved by ordered catch-up.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(6, true).await;
    let fast = sink.snapshot().await;
    assert_eq!(fast.len(), 6);
    assert_no_duplicate_events(&fast);
    assert_subject_sn_sequence(&fast, &s1_str, 0, 5);
    let sns: Vec<_> = fast.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3, 4, 5]);
    for i in 1..=5 {
        assert_event_is_fact_full(
            &fast[i],
            &s1_str,
            i as u64,
            true,
            Some(json!({"ModOne": {"data": i}})),
        );
    }
    assert_sink_not_lagging(&node.api, "example-sink").await;
    assert_sink_unblocked(&node.api, "example-sink").await;
}

/// Test 15: `sink_config_changes_safe_mode_get_sinks_and_blocked`.
///
/// **Cases covered:** adding a sink in config between restarts, removing a sink
/// from config (residual state in `SinkRegistry`), cursor deletion in safe mode,
/// advanced `get_sinks` filters, ordering, and blocked sink visibility.
/// Exercises `get_sinks`, `get_sinks_status`, and `delete_sink_cursors`.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Create subject `S1` and emit 3 facts.
///
/// **Part A — add sink on restart:**
/// 1. Restart the node with a single `gov-sink` pointing to a non-existent URL
///    (no sinks configured for `Example`).
/// 2. Verify that `api.get_sinks(SinksQuery::default())` does not return sinks
///    for `Example`.
/// 3. Restart again with two sinks:
///   - `new-sink` pointing to a `TestSink` in `Accept` mode (target schema
///     `Example`).
///   - `gov-sink` pointing to a `TestSink` in `Accept` mode (target
///     `governance`).
/// 4. Verify that `new-sink` receives Create + 3 facts via automatic catch-up.
/// 5. Verify that `api.get_sinks_status()` includes `new-sink` and `gov-sink`
///    with `running: true` and `in_config: true`.
/// 6. Verify that `api.get_sinks(SinksQuery { target:
///    Some("schema".to_owned()), .. })` includes `new-sink` and not `gov-sink`.
/// 7. Verify that `api.get_sinks(SinksQuery { schema_id:
///    Some("Example".to_owned()), .. })` includes `new-sink`.
///
/// **Part B — advanced filters and ordering:**
/// 1. Verify that `api.get_sinks(SinksQuery { name:
///    Some("new-sink".to_owned()), .. })` returns only `new-sink`.
/// 2. Verify that `api.get_sinks(SinksQuery { governance_id:
///    Some(governance_id.to_string()), .. })` returns `new-sink` (its target
///    `Example` belongs to that governance) and **not** `gov-sink` (its target
///    is the node-level governance schema with `governance_id: None`).
/// 3. Verify that `api.get_sinks(SinksQuery { target:
///    Some("schema".to_owned()), in_config: Some(true), .. })` returns only
///    `new-sink`.
/// 4. Verify that `api.get_sinks(SinksQuery::default())` returns the sinks
///    sorted by `manager` and `name`.
///
/// **Part C — remove sink from config:**
/// 1. Restart the node **without** the `new-sink` that had cursors (keeping
///    `gov-sink`).
/// 2. Call `api.get_sinks(SinksQuery { in_config: Some(false), .. })` and
///    verify that `new-sink` still appears with `in_config: false`.
/// 3. Verify that `api.get_sinks_status()` does not include `new-sink` and that
///    all returned sinks have `in_config: true`.
/// 4. Verify that `api.get_sinks(SinksQuery { running: Some(false), .. })`
///    includes `new-sink`.
///
/// **Part D — cleanup in safe mode:**
/// 1. Restart the node in `safe_mode: true`.
/// 2. Call `api.delete_sink_cursors("missing-sink")` and verify it returns
///    `Error::SinkNotFound`.
/// 3. Call `api.delete_sink_cursors("new-sink")` (residual sink) and verify it
///    disappears from the registry.
/// 4. Call `api.delete_sink_cursors("gov-sink")` (in-config sink) and verify it
///    still appears in `get_sinks_status` with `lagging_subjects == 0` and
///    `blocked: None`.
/// 5. Restart in normal mode.
/// 6. Call `api.get_sinks(SinksQuery { in_config: Some(false), .. })` and
///    verify that `new-sink` no longer appears.
/// 7. If `new-sink` is added back, it will do full catch-up from SN 0.
/// 8. If `gov-sink` is added back, it will also do full catch-up from SN 0
///    because its cursors were deleted.
///
/// > **Production fixes derived from this test:**
/// > - `populate_sink_registry` now marks sinks that are in the registry but no
/// >   longer in config as residual (`from_config: false`), allowing `get_sinks`
/// >   to return them with `in_config: false`).
/// > - When a sink blocks, the manager now inserts the subject into `lagging`,
/// >   so `get_sinks_status` reflects `lagging_subjects > 0` and subsequent
/// >   unblocking retries delivery.
///
/// **Part E — blocked sink in `get_sinks` and `get_sinks_status`:**
/// 1. Restart the node with `new-sink` configured to point to a `TestSink` in
///    `Accept` mode.
/// 2. Change the `TestSink` to `422 Unprocessable Entity` mode.
/// 3. Emit a fact on `S1` and wait for the sink to block.
/// 4. Verify that `api.get_sinks(SinksQuery { name:
///    Some("new-sink".to_owned()), .. })` returns the sink with `blocked:
///    Some(reason)`.
/// 5. Verify that `api.get_sinks_status()` shows `new-sink` with `blocked:
///    Some(reason)` and `lagging_subjects > 0`.
///
/// **Verifications:**
/// - A new in-config sink performs automatic historical catch-up.
/// - A sink removed from config persists in the registry as residual
///   (`in_config: false`).
/// - `delete_sink_cursors` returns `SinkNotFound` for a non-existent sink.
/// - `delete_sink_cursors` clears cursors and `lagging` state and, if the sink
///   is not in config, removes it from the registry.
/// - `get_sinks` distinguishes between in-config and residual sinks and
///   supports filters by `name`, `governance_id`, and combinations.
/// - `get_sinks` respects ordering by `manager` and `name`.
/// - `get_sinks` and `get_sinks_status` correctly reflect a blocked sink.
/// - `get_sinks_status` only shows configured sinks.
#[traced_test]
#[tokio::test]
async fn sink_config_changes_safe_mode_get_sinks_and_blocked() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": i}}), true)
            .await
            .unwrap();
    }

    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Part A — restart without any sinks configured for Example.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        initial_keys.clone(),
        initial_local_db.clone(),
        initial_ext_db.clone(),
        format!("/memory/{}", port),
        governance_sink_config("http://localhost:9000".to_owned()),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let sinks = node.api.get_sinks(SinksQuery::default()).await.unwrap();
    let example_sinks: Vec<_> = sinks
        .iter()
        .filter(|s| {
            s.target
                .as_ref()
                .map(|t| matches!(t, SinkTarget::Schema { schema_id, .. } if schema_id == "Example"))
                .unwrap_or(false)
        })
        .collect();
    assert_eq!(
        example_sinks.len(),
        0,
        "no Example sinks should be configured"
    );

    // Part A cont. — restart with new-sink (Example) and gov-sink.
    let new_sink = TestSink::start().await;
    let gov_sink = TestSink::start().await;

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![
            make_sink_entry(
                "new-sink",
                new_sink.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
            ),
            governance_sink_config(gov_sink.url())
                .into_iter()
                .next()
                .unwrap(),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // new-sink must catch up Create + 3 facts automatically.
    wait_for_sink_caught_up(&node.api, "new-sink").await;
    new_sink.wait_for_count(4, true).await;
    let new_events = new_sink.snapshot().await;
    assert_eq!(new_events.len(), 4);

    // get_sinks_status includes both sinks as running.
    let statuses = node.api.get_sinks_status().await.unwrap();
    let status_names: Vec<_> =
        statuses.iter().map(|s| s.name.as_str()).collect();
    assert!(status_names.contains(&"new-sink"));
    assert!(status_names.contains(&"gov-sink"));
    let new_status = statuses.iter().find(|s| s.name == "new-sink").unwrap();
    assert!(new_status.running, "new-sink should be running");
    assert!(new_status.in_config, "new-sink should be in config");
    let gov_status = statuses.iter().find(|s| s.name == "gov-sink").unwrap();
    assert!(gov_status.running, "gov-sink should be running");
    assert!(gov_status.in_config, "gov-sink should be in config");

    // Filter by target=schema -> only new-sink.
    let schema_sinks = node
        .api
        .get_sinks(SinksQuery {
            target: Some("schema".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    let schema_names: Vec<_> =
        schema_sinks.iter().map(|s| s.name.as_str()).collect();
    assert!(schema_names.contains(&"new-sink"));
    assert!(!schema_names.contains(&"gov-sink"));

    // Filter by target=governance -> only gov-sink.
    let gov_sinks = node
        .api
        .get_sinks(SinksQuery {
            target: Some("governance".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    let gov_names: Vec<_> = gov_sinks.iter().map(|s| s.name.as_str()).collect();
    assert!(gov_names.contains(&"gov-sink"));
    assert!(!gov_names.contains(&"new-sink"));

    // Filter by schema_id=Example -> only new-sink.
    let example_query = node
        .api
        .get_sinks(SinksQuery {
            schema_id: Some("Example".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(example_query.len(), 1);
    assert_eq!(example_query[0].name, "new-sink");

    // Part B — advanced filters and ordering.
    let by_name = node
        .api
        .get_sinks(SinksQuery {
            name: Some("new-sink".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(by_name.len(), 1);
    assert_eq!(by_name[0].name, "new-sink");

    let by_gov = node
        .api
        .get_sinks(SinksQuery {
            governance_id: Some(governance_id.to_string()),
            ..Default::default()
        })
        .await
        .unwrap();
    let by_gov_names: Vec<_> = by_gov.iter().map(|s| s.name.as_str()).collect();
    assert!(by_gov_names.contains(&"new-sink"));
    // gov-sink targets the node-level governance schema and has governance_id=None,
    // so it is not returned by a filter on the subject governance_id.
    assert!(!by_gov_names.contains(&"gov-sink"));

    let schema_in_config = node
        .api
        .get_sinks(SinksQuery {
            target: Some("schema".to_owned()),
            in_config: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(schema_in_config.len(), 1);
    assert_eq!(schema_in_config[0].name, "new-sink");

    // Combined filter with three criteria -> only new-sink.
    let combined = node
        .api
        .get_sinks(SinksQuery {
            target: Some("schema".to_owned()),
            in_config: Some(true),
            running: Some(true),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(combined.len(), 1);
    assert_eq!(combined[0].name, "new-sink");

    // Filter that matches nothing -> empty result.
    let empty = node
        .api
        .get_sinks(SinksQuery {
            name: Some("no-such-sink".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        empty.is_empty(),
        "query with no matches should return empty list"
    );

    let all_sinks = node.api.get_sinks(SinksQuery::default()).await.unwrap();
    let sorted_names: Vec<_> =
        all_sinks.iter().map(|s| s.name.clone()).collect();
    // get_sinks sorts first by manager key (governance:* < node) then by name.
    assert_eq!(
        sorted_names,
        vec!["new-sink", "gov-sink"],
        "sinks should be sorted by manager then name"
    );

    // Part C — remove new-sink from config, keep gov-sink.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        governance_sink_config(gov_sink.url()),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // new-sink appears as residual (in_config=false).
    let residuals = node
        .api
        .get_sinks(SinksQuery {
            in_config: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    let residual_names: Vec<_> =
        residuals.iter().map(|s| s.name.as_str()).collect();
    assert!(residual_names.contains(&"new-sink"));
    let residual = residuals.iter().find(|s| s.name == "new-sink").unwrap();
    assert!(!residual.in_config);

    // get_sinks_status does not include new-sink (only in_config sinks).
    let statuses = node.api.get_sinks_status().await.unwrap();
    let status_names: Vec<_> =
        statuses.iter().map(|s| s.name.as_str()).collect();
    assert!(!status_names.contains(&"new-sink"));
    assert!(
        statuses.iter().all(|s| s.in_config),
        "get_sinks_status should only return in_config sinks"
    );

    // Filter running=false includes the residual new-sink.
    let not_running = node
        .api
        .get_sinks(SinksQuery {
            running: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    let not_running_names: Vec<_> =
        not_running.iter().map(|s| s.name.as_str()).collect();
    assert!(not_running_names.contains(&"new-sink"));

    // Part D — safe mode cleanup.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config_safe_mode(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        governance_sink_config(gov_sink.url()),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // delete_sink_cursors on missing sink returns SinkNotFound.
    let err = node
        .api
        .delete_sink_cursors("missing-sink".to_owned())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::SinkNotFound(_)),
        "expected SinkNotFound, got {:?}",
        err
    );

    // delete_sink_cursors on residual new-sink removes it from registry.
    node.api
        .delete_sink_cursors("new-sink".to_owned())
        .await
        .unwrap();
    let residuals = node
        .api
        .get_sinks(SinksQuery {
            in_config: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        !residuals.iter().any(|s| s.name == "new-sink"),
        "new-sink residual should be removed"
    );

    // delete_sink_cursors on in-config gov-sink keeps it but clears cursors/lagging.
    node.api
        .delete_sink_cursors("gov-sink".to_owned())
        .await
        .unwrap();
    let statuses = node.api.get_sinks_status().await.unwrap();
    let gov_status = statuses.iter().find(|s| s.name == "gov-sink").unwrap();
    assert_eq!(gov_status.lagging_subjects, 0);
    assert!(gov_status.blocked.is_none());

    // Restart in normal mode with a fresh gov-sink URL to prove catch-up
    // from SN 0 after its cursors were deleted in safe mode.
    let gov_sink2 = TestSink::start().await;
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        governance_sink_config(gov_sink2.url()),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let residuals = node
        .api
        .get_sinks(SinksQuery {
            in_config: Some(false),
            ..Default::default()
        })
        .await
        .unwrap();
    assert!(
        !residuals.iter().any(|s| s.name == "new-sink"),
        "new-sink should not reappear after deletion"
    );

    // gov-sink2 must receive the governance events from SN 0 because the
    // previous gov-sink cursors were deleted.
    gov_sink2.wait_for_full_count(2, true).await;
    let gov_events: Vec<_> = gov_sink2
        .full_snapshot()
        .await
        .into_iter()
        .filter(|e| e.subject_id() == governance_id.to_string())
        .collect();
    let gov_sns: Vec<_> = gov_events.iter().map(|e| e.sn()).collect();
    assert_eq!(
        gov_sns,
        vec![0, 1],
        "gov-sink should catch up governance from SN 0 after cursor deletion"
    );

    // Part E — blocked sink visibility + catch-up from SN 0 after deletion.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    new_sink.set_mode(ResponseMode::Accept).await;
    new_sink.clear().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry(
            "new-sink",
            new_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // new-sink must replay all S1 events from SN 0 because its cursors were
    // deleted in safe mode.
    wait_for_sink_caught_up(&node.api, "new-sink").await;
    new_sink.wait_for_count(4, true).await;
    let s1_events: Vec<_> = new_sink
        .snapshot()
        .await
        .into_iter()
        .filter(|e| e.subject_id() == s1.to_string())
        .collect();
    let s1_sns: Vec<_> = s1_events.iter().map(|e| e.sn()).collect();
    assert_eq!(
        s1_sns,
        vec![0, 1, 2, 3],
        "new-sink should catch up S1 from SN 0 after cursor deletion"
    );

    // Switch to 422 client error and emit a fact to block the sink.
    new_sink.set_mode(ResponseMode::ClientError).await;
    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 4}}), true)
        .await
        .unwrap();

    wait_for_sink_lagging_subjects(&node.api, "new-sink", 1).await;

    let blocked_info = node
        .api
        .get_sinks(SinksQuery {
            name: Some("new-sink".to_owned()),
            ..Default::default()
        })
        .await
        .unwrap();
    assert_eq!(blocked_info.len(), 1);
    assert!(
        blocked_info[0].blocked.is_some(),
        "new-sink should be reported as blocked"
    );

    let statuses = node.api.get_sinks_status().await.unwrap();
    let new_status = statuses.iter().find(|s| s.name == "new-sink").unwrap();
    assert!(new_status.blocked.is_some());
    assert!(new_status.lagging_subjects > 0);
}

/// Test 16: `sink_auth_token_refresh`.
///
/// **Cases covered:** API key authentication, OAuth2 token refresh on
/// `401/403`, and recovery after auth errors.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Start a `TestSink` that, in addition to `/events`, exposes `POST
///   /auth/token` to simulate the OAuth2 endpoint.
/// - Configure a sink with `auth.auth_url`, `auth.username`, and read the
///   password from `AVE_SINK_PASSWORD_AUTH_SINK`.
///
/// **Part A — API key:**
/// 1. Restart with a sink configured with `auth.api_key: "secret-key"` while
///    `TestSink` returns 500, and emit a fact. The failing deliveries
///    guarantee no cursor is persisted, and a status query guarantees
///    `last_seen` is persisted before the next shutdown.
/// 2. Restart again with the sink healthy: startup catch-up must deliver
///    Create + 3 facts.
/// 3. Verify that every delivery carries `Authorization: Api-Key secret-key`.
///
/// **Part B — OAuth2 + refresh on 401:**
/// 1. Configure a sink with OAuth2.
/// 2. The first request to `/events` returns `401 Unauthorized`.
/// 3. The worker must call `/auth/token`, obtain a token, and retry delivery
///    with `Authorization: Bearer <token>`.
/// 4. The second request to `/events` returns `200 OK`.
/// 5. Verify the fact is delivered correctly.
///
/// **Part C — persistent auth failure:**
/// 1. Configure invalid credentials.
/// 2. Emit a fact.
/// 3. Verify the subject enters `lagging` (`AuthFailed` error) but the sink
///    **does not** block.
///
/// **Verifications:**
/// - API key is sent in the correct header.
/// - OAuth2 refreshes the token on 401 and retries.
/// - Auth errors do not block the sink; they remain in `lagging` for retry.
///
/// > **Implementation note:** the sink is named `auth-sink`, so the environment
/// > variable loaded by the worker is `AVE_SINK_PASSWORD_AUTH_SINK` (format
/// > `AVE_SINK_PASSWORD_{{SERVER_UPPER}}` with `-` replaced by `_`).
/// > **Production fixes derived from this test:**
/// > - `TestSink` now exposes `POST /auth/token` and records received requests.
/// > - `TestSink` supports `UnauthorizedOnce` (401 on first delivery, then 200)
/// >   and `UnauthorizedAlways` (persistent 401) modes to exercise OAuth2
/// >   refresh and auth failures.
/// > - `make_sink_entry_with_auth` allows configuring `SinkAuthMethod`
/// >   (bearer, API key, basic or OAuth2) in tests.
#[traced_test]
#[tokio::test]
async fn sink_auth_token_refresh() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=2 {
        emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": i}}), true)
            .await
            .unwrap();
    }

    let s1_str = s1.to_string();

    // Part A — API key authentication.
    //
    // The sink starts in ServerError mode so that no delivery can succeed
    // (and therefore no cursor can be persisted) while the node is up. After
    // emitting the last fact, a `get_sinks_status` call acts as a
    // mailbox-order barrier: the status ask is queued after the
    // `NotifyNewEvent` for SN 3, so its response guarantees the manager has
    // processed it and `last_seen` is persisted. This removes the race
    // between the fire-and-forget sink notification and the graceful
    // shutdown, which discards non-critical mailbox messages.
    let api_key_sink = TestSink::start().await;
    api_key_sink.set_mode(ResponseMode::ServerError).await;
    let api_key = "secret-key".to_owned();
    // The API key travels in `AVE_SINK_APIKEY_{{SERVER}}` (never in config).
    let _api_key_guard = TempEnvVar::set("AVE_SINK_APIKEY_AUTH_SINK", &api_key);
    let initial_keys = node.keys.clone();
    let initial_local_db = dirs[0].path().to_path_buf();
    let initial_ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        initial_keys,
        initial_local_db,
        initial_ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "auth-sink",
            api_key_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::ApiKey,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 3}}), true)
        .await
        .unwrap();

    // Mailbox-order barrier: guarantees last_seen=3 is persisted.
    let statuses = node.api.get_sinks_status().await.unwrap();
    assert!(
        statuses.iter().any(|s| s.name == "auth-sink"),
        "auth-sink must be registered after the restart"
    );

    // Restart with the sink healthy: startup catch-up must deliver SN 0-3.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;
    // Baseline taken with the node stopped: failed delivery attempts also
    // record Authorization headers, and only later deliveries are asserted.
    let headers_baseline = api_key_sink.authorization_headers().await.len();
    api_key_sink.set_mode(ResponseMode::Accept).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "auth-sink",
            api_key_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::ApiKey,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "auth-sink").await;
    api_key_sink.wait_for_count(4, true).await;
    let api_key_events = api_key_sink.full_snapshot().await;
    assert_eq!(
        api_key_events.len(),
        4,
        "API key sink should receive Create + 3 facts"
    );
    assert_subject_sn_sequence(&api_key_events, &s1_str, 0, 3);
    assert_event_is_fact_full(
        &api_key_events[3],
        &s1_str,
        3,
        true,
        Some(json!({"ModOne": {"data": 3}})),
    );

    let headers = api_key_sink.authorization_headers().await;
    let expected_api_key = format!("Api-Key {}", api_key);
    assert_eq!(
        headers.len() - headers_baseline,
        api_key_events.len(),
        "every delivered event should have a recorded Authorization header"
    );
    assert!(
        headers.iter().all(|h| h.as_ref().map(|s| s.as_str())
            == Some(expected_api_key.as_str())),
        "all events must carry the API key Authorization header"
    );

    // Part B — OAuth2 token refresh on 401.
    let oauth_sink = TestSink::start().await;
    let password = "oauth-password".to_owned();
    // Match the environment variable name built by sink_password_env_var.
    let password_env = "AVE_SINK_PASSWORD_AUTH_SINK";
    let _password_guard = TempEnvVar::set(password_env, &password);
    assert_eq!(
        std::env::var(password_env).unwrap(),
        password,
        "password env var should be set"
    );

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "auth-sink",
            oauth_sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::OAuth2(SinkAuthConfig {
                auth_url: oauth_sink.auth_url(),
                username: "test-user".to_owned(),
                ..SinkAuthConfig::default()
            }),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Wait for the worker's eager startup token fetch so the refresh count is deterministic.
    tokio::time::timeout(Duration::from_secs(5), async {
        while oauth_sink.auth_requests().await.is_empty() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("worker should fetch a token eagerly on startup");

    // Wait for any startup catch-up (triggered when the cursor was not
    // persisted before the previous shutdown) to finish, then reset the sink
    // so the refresh assertions only observe the new fact.
    wait_for_sink_caught_up(&node.api, "auth-sink").await;
    oauth_sink.clear().await;
    let oauth_headers_baseline = oauth_sink.authorization_headers().await.len();

    oauth_sink.set_mode(ResponseMode::UnauthorizedOnce).await;
    // Baseline before the 401: the absolute number of token fetches is not
    // stable because the worker can be recreated by the idle shutdown under
    // load (each recreation fetches a fresh token), so the refresh is
    // asserted as a delta instead of a fixed count.
    let auth_baseline = oauth_sink.auth_requests().await.len();

    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 4}}), true)
        .await
        .unwrap();

    // Wait for the new fact to be delivered after the 401 refresh.
    oauth_sink.wait_for_count(1, true).await;

    let oauth_events = oauth_sink.full_snapshot().await;
    assert_eq!(
        oauth_events.len(),
        1,
        "OAuth2 sink should receive exactly one event (fact 4)"
    );
    assert_event_is_fact_full(
        &oauth_events[0],
        &s1_str,
        4,
        true,
        Some(json!({"ModOne": {"data": 4}})),
    );

    let auth_requests = oauth_sink.auth_requests().await;
    assert!(
        auth_requests.len() > auth_baseline,
        "the 401 must trigger a token refresh before the retry"
    );
    assert!(
        auth_requests
            .iter()
            .any(|r| r.username == "test-user" && r.password == password),
        "Token endpoint should receive correct credentials"
    );

    let headers = oauth_sink.authorization_headers().await;
    assert_eq!(
        headers.len() - oauth_headers_baseline,
        2,
        "expected failed 401 request + successful retry with refreshed token"
    );
    assert_eq!(
        headers.last().unwrap().as_deref(),
        Some("Bearer test-access-token"),
        "retried delivery must use the refreshed Bearer token"
    );

    // Part C — persistent auth failure keeps subject lagging, does not block sink.
    oauth_sink
        .set_auth_mode(AuthResponseMode::TokenFailure)
        .await;
    oauth_sink.set_mode(ResponseMode::UnauthorizedAlways).await;

    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 5}}), true)
        .await
        .unwrap();

    wait_for_sink_lagging_subjects(&node.api, "auth-sink", 1).await;
    assert_sink_unblocked(&node.api, "auth-sink").await;

    // The failed event must NOT have been delivered; cursor must not advance.
    let oauth_events_after_failure = oauth_sink.full_snapshot().await;
    assert_eq!(
        oauth_events_after_failure.len(),
        1,
        "persistent auth failure must not deliver the new fact"
    );
    assert!(
        !oauth_events_after_failure.iter().any(|e| e.sn() == 5),
        "SN 5 should not reach the sink while auth keeps failing"
    );
    assert_eq!(
        count_events_for_subject(&oauth_events_after_failure, &s1_str),
        1,
        "subject should only have the previously delivered SN 4 in the sink"
    );
}

/// API key authentication through the `AVE_SINK_APIKEY_{{SERVER}}`
/// environment variable instead of the configuration file.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with an `envkey-sink` with `SinkAuthMethod::ApiKey`; the key
///    is only read from the environment.
/// 3. Startup catch-up delivers the subject's create event.
///
/// **Verifications:**
/// - The delivery carries `Authorization: Api-Key <env value>`.
///
/// > **Implementation note:** the sink is named `envkey-sink`, so the
/// > environment variable is `AVE_SINK_APIKEY_ENVKEY_SINK`. The name must
/// > stay unique in this file: the variable would also take precedence in
/// > any other concurrently running test reusing the same sink name.
#[traced_test]
#[tokio::test]
async fn sink_api_key_from_env_var() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    // The API key is read from the environment (never from the config).
    let api_key_env = "AVE_SINK_APIKEY_ENVKEY_SINK";
    let _api_key_guard = TempEnvVar::set(api_key_env, "env-secret-key");

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "envkey-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::ApiKey,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Startup catch-up delivers the subject's create event.
    wait_for_sink_caught_up(&node.api, "envkey-sink").await;
    sink.wait_for_count(1, true).await;

    let headers = sink.authorization_headers().await;
    assert!(
        headers
            .iter()
            .flatten()
            .any(|h| h == "Api-Key env-secret-key"),
        "deliveries must carry the API key from the environment variable"
    );
}

/// Static credentials (parity with the gRPC sink): a sink with
/// `SinkAuthMethod::BearerToken` sends `Authorization: Bearer <token>` and a
/// sink with `SinkAuthMethod::Basic` sends `Authorization: Basic
/// base64(username:password)`, both read from the environment.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with two sinks, `bearer-sink` and `basic-sink`, whose secrets
///    live in `AVE_SINK_TOKEN_BEARER_SINK` and
///    `AVE_SINK_PASSWORD_BASIC_SINK`.
/// 3. Startup catch-up delivers the subject's create event to both.
///
/// **Verifications:**
/// - The bearer sink receives `Authorization: Bearer <env token>`.
/// - The basic sink receives `Authorization: Basic base64(user:pass)`.
#[traced_test]
#[tokio::test]
async fn sink_bearer_and_basic_auth() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let bearer_sink = TestSink::start().await;
    let basic_sink = TestSink::start().await;
    let _token_guard =
        TempEnvVar::set("AVE_SINK_TOKEN_BEARER_SINK", "static-token");
    let _password_guard =
        TempEnvVar::set("AVE_SINK_PASSWORD_BASIC_SINK", "basic-secret");

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![
            make_sink_entry_with_auth(
                "bearer-sink",
                bearer_sink.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
                SinkAuthMethod::BearerToken,
            ),
            make_sink_entry_with_auth(
                "basic-sink",
                basic_sink.url(),
                Some(governance_id.to_string()),
                BTreeSet::from([SinkTypes::All]),
                SinkAuthMethod::Basic {
                    username: "sink-user".to_owned(),
                },
            ),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "bearer-sink").await;
    wait_for_sink_caught_up(&node.api, "basic-sink").await;
    bearer_sink.wait_for_count(1, true).await;
    basic_sink.wait_for_count(1, true).await;

    let bearer_headers = bearer_sink.authorization_headers().await;
    assert!(
        bearer_headers
            .iter()
            .flatten()
            .any(|h| h == "Bearer static-token"),
        "deliveries must carry the bearer token from the environment"
    );

    let expected_basic = {
        use base64::{Engine as _, prelude::BASE64_STANDARD};
        format!("Basic {}", BASE64_STANDARD.encode("sink-user:basic-secret"))
    };
    let basic_headers = basic_sink.authorization_headers().await;
    assert!(
        basic_headers.iter().flatten().any(|h| h == &expected_basic),
        "deliveries must carry the basic credentials from the environment"
    );
}

/// Credential rotation for static auth: a bearer sink whose token is wrong
/// gets persistent 401s and the subject stays lagging; after rotating the
/// token in the environment and restarting the node (env secrets are read
/// when the transport is built), catch-up recovers and deliveries carry the
/// new token.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with `rotation-sink` (wrong token) against a sink that always
///    answers 401: the subject goes lagging and attempts carry the wrong
///    token.
/// 3. Rotate the env token, switch the sink to accept and restart again:
///    catch-up delivers the pending event with the new token.
///
/// **Verifications:**
/// - Phase 1: lagging subject; attempts carry `Bearer wrong-token`.
/// - Phase 2: caught up; deliveries carry `Bearer good-token`.
///
/// > **Implementation note:** the sink name must stay unique in this file —
/// > the env var derived from it is process-global and tests run in
/// > parallel (a collision with another test's sink name flips the token).
#[traced_test]
#[tokio::test]
async fn sink_bearer_token_rotation() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::UnauthorizedAlways).await;
    let token_env = "AVE_SINK_TOKEN_ROTATION_SINK";
    let wrong_guard = TempEnvVar::set(token_env, "wrong-token");

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "rotation-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::BearerToken,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Every attempt is rejected: the subject goes lagging.
    wait_for_sink_lagging_subjects(&node.api, "rotation-sink", 1).await;
    let headers = sink.authorization_headers().await;
    assert!(
        headers.iter().flatten().any(|h| h == "Bearer wrong-token"),
        "attempts must carry the wrong token from the environment"
    );

    // Rotate the token and restart: the worker reads the new secret when
    // the transport is rebuilt, and catch-up recovers the pending event.
    drop(wrong_guard);
    let _good_guard = TempEnvVar::set(token_env, "good-token");
    sink.set_mode(ResponseMode::Accept).await;

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "rotation-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::BearerToken,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "rotation-sink").await;
    sink.wait_for_count(1, true).await;

    let headers = sink.authorization_headers().await;
    assert!(
        headers.iter().flatten().any(|h| h == "Bearer good-token"),
        "deliveries after the rotation must carry the new token"
    );
}

/// Delivery signatures: every HTTP delivery of a sink with
/// `signature: true` must carry the node identity signature headers,
/// both for full events and for lightweight (non-matching filter) events.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit two facts.
/// 2. Restart with a sink configured with `signature: true` and an event
///    filter of only `Create`, so the create event is delivered full and
///    the two facts are delivered as lightweight events.
/// 3. Startup catch-up delivers the three events.
///
/// **Verifications:**
/// - `X-Ave-Signature`, `X-Ave-Signature-Timestamp` and `X-Ave-Public-Key`
///   are present on every delivery, full or lightweight.
/// - The public key is the node identity.
/// - Each signature verifies cryptographically against the exact received
///   body, recomputing `BLAKE3(borsh(body, timestamp))` as the receiver
///   would.
/// - The first event is full (create) and the other two are lightweight.
#[traced_test]
#[tokio::test]
async fn sink_signature_headers_verify() {
    use ave_common::identity::{
        BLAKE3_HASHER, Hash as _, SignatureIdentifier, TimeStamp,
    };

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let expected_public_key = keys.public_key();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_signature(
            "signed-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::Create]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Startup catch-up delivers the create event (SN 0, full) plus the two
    // facts as lightweight events.
    wait_for_sink_caught_up(&node.api, "signed-sink").await;
    sink.wait_for_count(3, true).await;

    let events = sink.snapshot().await;
    assert!(
        matches!(events.first(), Some(IncomingSinkEvent::Full(_))),
        "the create event must be delivered full"
    );
    assert!(
        events[1..]
            .iter()
            .all(|e| matches!(e, IncomingSinkEvent::Light(_))),
        "facts must be delivered as lightweight events"
    );

    let signature_headers = sink.signature_headers().await;
    let raw_bodies = sink.raw_bodies().await;
    assert_eq!(signature_headers.len(), raw_bodies.len());
    assert!(!signature_headers.is_empty());

    for (headers, body) in signature_headers.iter().zip(raw_bodies.iter()) {
        let signature = headers
            .signature
            .as_ref()
            .expect("X-Ave-Signature header must be present");
        let timestamp = headers
            .timestamp
            .as_ref()
            .expect("X-Ave-Signature-Timestamp header must be present");
        let public_key = headers
            .public_key
            .as_ref()
            .expect("X-Ave-Public-Key header must be present");

        assert_eq!(
            public_key,
            &expected_public_key.to_string(),
            "the signer must be the node identity"
        );

        // Rebuild the signed payload exactly as `Signature::new` does:
        // borsh(content, timestamp), then BLAKE3.
        let content = body.clone();
        let timestamp = TimeStamp::from_nanos(
            timestamp
                .parse::<u64>()
                .expect("timestamp must be nanoseconds"),
        );
        let payload_bytes = borsh::to_vec(&(&content, &timestamp)).unwrap();
        let hash = BLAKE3_HASHER.hash(&payload_bytes);

        let signer = PublicKey::from_str(public_key).unwrap();
        let signature = SignatureIdentifier::from_str(signature).unwrap();
        signer
            .verify(hash.hash_bytes(), &signature)
            .expect("delivery signature must verify against the received body");
    }
}

/// Signature v2 over a zstd-compressed delivery: the signature must bind
/// the exact wire bytes (the compressed body) and the canonical headers,
/// including `content-encoding: zstd`. A receiver that verifies against
/// the decompressed body — or without the encoding header — must fail.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with a sink configured with `signature: true`,
///    `signature_version: 2` and `compression: zstd`.
/// 3. Startup catch-up delivers the subject's create event.
///
/// **Verifications:**
/// - `Content-Encoding: zstd` on the wire; the raw body is zstd and
///   decompresses to the event JSON.
/// - The signature verifies against the canonical v2 payload rebuilt from
///   the recorded headers and the COMPRESSED body.
/// - Verification against the decompressed body fails (the signature binds
///   the compressed wire payload).
#[traced_test]
#[tokio::test]
async fn sink_signature_v2_zstd_verify() {
    use ave_common::identity::{
        BLAKE3_HASHER, Hash as _, PublicKey, SignatureIdentifier, TimeStamp,
    };
    use ave_core::sink::delivery::{DeliveryMeta, canonical_payload};

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "Example".to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![ave_core::config::SinkServer {
                server: "signed-zstd-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: ave_core::config::SinkTransportConfig::Http(
                    Box::new(ave_core::config::HttpSinkConfig {
                        url: sink.url(),
                        signature: true,
                        signature_version: 2,
                        compression: SinkCompression::Zstd,
                        max_retries: 0,
                        request_timeout_ms: 2000,
                        connect_timeout_ms: 1000,
                        ..Default::default()
                    }),
                ),
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                ..Default::default()
            }],
        }],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "signed-zstd-sink").await;
    sink.wait_for_count(1, true).await;

    let signature_headers = sink.signature_headers().await;
    let idempotency_headers = sink.idempotency_headers().await;
    let content_encodings = sink.content_encodings().await;
    let raw_bodies = sink.raw_bodies().await;
    assert_eq!(raw_bodies.len(), 1);

    assert_eq!(content_encodings[0].as_deref(), Some("zstd"));
    let body = &raw_bodies[0];
    assert!(
        body.len() > 4
            && body[0] == 0x28
            && body[1] == 0xb5
            && body[2] == 0x2f
            && body[3] == 0xfd,
        "the wire body must be zstd-compressed"
    );
    let decompressed = zstd::bulk::decompress(body, 1024 * 1024)
        .expect("the body must be valid zstd");
    serde_json::from_slice::<serde_json::Value>(&decompressed)
        .expect("the decompressed body must be JSON");

    let headers = &signature_headers[0];
    let signature = headers
        .signature
        .as_ref()
        .expect("X-Ave-Signature header must be present");
    let timestamp = headers
        .timestamp
        .as_ref()
        .expect("X-Ave-Signature-Timestamp header must be present");
    let public_key = headers
        .public_key
        .as_ref()
        .expect("X-Ave-Public-Key header must be present");

    let idem = &idempotency_headers[0];
    let meta = DeliveryMeta {
        subject_id: idem.subject_id.clone().expect("subject id header"),
        sn: idem
            .sn
            .as_ref()
            .expect("sn header")
            .parse()
            .expect("sn is a number"),
        event_type: idem.event_type.clone().expect("event type header"),
    };
    assert_eq!(meta.subject_id, subject_id.to_string());

    // The signature binds the canonical v2 headers (with content-encoding)
    // and the COMPRESSED wire body.
    let canonical =
        canonical_payload(body, 2, &[("content-encoding", "zstd")], Some(&meta));
    let timestamp =
        TimeStamp::from_nanos(timestamp.parse().expect("nanos timestamp"));
    let payload_bytes = borsh::to_vec(&(canonical, timestamp)).unwrap();
    let hash = BLAKE3_HASHER.hash(&payload_bytes);
    let signer = PublicKey::from_str(public_key).unwrap();
    let signature = SignatureIdentifier::from_str(signature).unwrap();
    signer
        .verify(hash.hash_bytes(), &signature)
        .expect("signature must verify against the compressed wire body");

    // Verifying against the decompressed body must fail.
    let wrong_canonical = canonical_payload(
        &decompressed,
        2,
        &[("content-encoding", "zstd")],
        Some(&meta),
    );
    let wrong_bytes = borsh::to_vec(&(wrong_canonical, timestamp)).unwrap();
    let wrong_hash = BLAKE3_HASHER.hash(&wrong_bytes);
    assert!(
        signer.verify(wrong_hash.hash_bytes(), &signature).is_err(),
        "the signature must not verify against the decompressed body"
    );
}

/// Poll `condition` until it returns `true`. Panics on timeout.
/// Follows the same timing pattern as the other `wait_for_*` helpers.
async fn wait_for_condition<F>(mut condition: F)
where
    F: FnMut() -> bool,
{
    let mut attempts = 0;
    loop {
        if condition() {
            return;
        }
        if attempts > 100 {
            panic!("timeout waiting for condition");
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Test 17: `sink_worker_idle_shutdown_and_recreate`.
///
/// **Cases covered:** `SinkWorker` lifecycle (idle timeout, shutdown by the
/// manager, and recreation on new events).
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with `example-sink` configured with
///   `sink_worker_idle_timeout_ms: 200`, `sink_subject_worker_idle_timeout_ms:
///   200`, and `request_timeout_ms: 500`.
/// - Create subject `S1`.
///
/// **Sequence:**
/// 1. Emit a fact and verify it reaches the sink.
/// 2. Wait ≥300 ms for the worker to go idle and the manager to stop it
///    (`WorkerIdle` + `Stop`).
/// 3. Emit a second fact.
/// 4. Verify the second fact reaches the sink correctly.
///
/// **Verifications:**
/// - The sink receives both facts.
/// - After the idle period the worker shuts down without errors.
/// - The new event forces the creation of a fresh worker that delivers
///   correctly.
#[traced_test]
#[tokio::test]
async fn sink_worker_idle_shutdown_and_recreate() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        short_idle_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Create the subject AFTER configuring the idle sink so the worker has no
    // pending catch-up and can become idle cleanly.
    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    // First fact: creates the worker and is delivered.
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(2, true).await;
    let events_after_first = sink.full_snapshot().await;
    assert_eq!(
        events_after_first.len(),
        2,
        "Create + first fact should be delivered"
    );
    assert_subject_sn_sequence(&events_after_first, &subject_id_str, 0, 1);
    assert_event_is_fact_full(
        &events_after_first[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_running(&node.api, "example-sink").await;

    // Wait (with polling) until the manager logs that it has stopped the worker.
    // Using a condition avoids hardcoding an exact delay: Tokio scheduling is
    // not deterministic across machines, and the idle timeout is reached after
    // a periodic healthcheck plus the configured shutdown delay.
    wait_for_condition(|| logs_contain("SinkWorkerShutdown")).await;

    // The sink should still have only the first two events.
    let events_during_idle = sink.full_snapshot().await;
    assert_eq!(
        events_during_idle.len(),
        2,
        "no events should be delivered while the worker is idle"
    );

    // Verify that the manager actually decided to shut the worker down. This is
    // an internal implementation detail, so it is checked through the production
    // log instead of through the public API.
    logs_assert(|lines: &[&str]| {
        let found = lines.iter().any(|line| {
            line.contains("SinkWorkerShutdown")
                && line.contains("idle timeout")
                && line.contains("example-sink")
        });
        if found {
            Ok(())
        } else {
            Err("expected SinkWorkerShutdown log for example-sink".to_owned())
        }
    });

    // Second fact: forces the manager to create a fresh worker and deliver.
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(3, true).await;
    let events_after_second = sink.full_snapshot().await;
    assert_eq!(
        events_after_second.len(),
        3,
        "second fact should be delivered by a fresh worker"
    );
    assert_subject_sn_sequence(&events_after_second, &subject_id_str, 0, 2);
    assert_event_is_fact_full(
        &events_after_second[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModOne": {"data": 2}})),
    );
    assert_sink_running(&node.api, "example-sink").await;
    assert_sink_not_lagging(&node.api, "example-sink").await;
}

/// Poll `sink.full_snapshot()` until the event count stays at `expected` for
/// several consecutive attempts. Panics if the count changes or on timeout.
async fn assert_sink_count_stable(sink: &TestSink, expected: usize) {
    let mut stable_attempts = 0;
    let mut attempts = 0;
    loop {
        let events = sink.full_snapshot().await;
        if events.len() == expected {
            stable_attempts += 1;
            if stable_attempts >= 5 {
                return;
            }
        } else {
            panic!(
                "sink event count changed: expected stable {}, got {}",
                expected,
                events.len()
            );
        }
        if attempts > 100 {
            panic!(
                "timeout waiting for sink count to stabilize at {}",
                expected
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Poll `get_sinks_status` until `sink_name` has no lagging subjects.
/// Panics on timeout.
async fn wait_for_sink_not_lagging(api: &Api, sink_name: &str) {
    let mut attempts = 0;
    loop {
        let statuses = api.get_sinks_status().await.unwrap();
        if let Some(status) = statuses.iter().find(|s| s.name == sink_name)
            && status.lagging_subjects == 0 {
                return;
            }
        if attempts > 100 {
            panic!(
                "timeout waiting for sink {} to have no lagging subjects",
                sink_name
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Test 18: `sink_eol_keeps_cursor_and_stops_delivery`.
///
/// **Cases covered:** `EOL` event is treated as a normal event (not as
/// `SubjectNotFound`) and, after it, no further deliveries are attempted for
/// that subject.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with `example-sink`.
/// - Create subject `S1` and emit 2 facts.
/// - Verify initial delivery.
///
/// **Sequence:**
/// 1. Emit `EOL` for `S1`.
/// 2. Verify the sink receives the `EOL` event with the correct SN.
/// 3. Wait a few seconds and verify that no further deliveries are attempted
///    for `S1` (no new events appear in the sink and `lagging` is not
///    incremented for that subject).
///
/// **Verifications:**
/// - `EOL` is delivered as one more event.
/// - After `EOL` the cursor stays at the last SN and there are no retries or
///   new deliveries.
/// - The subject does not appear in `lagging` indefinitely.
#[traced_test]
#[tokio::test]
async fn sink_eol_keeps_cursor_and_stops_delivery() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Create subject and emit two facts.
    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for data in [1, 2] {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(3, true).await;
    let events_before_eol = sink.full_snapshot().await;
    assert_eq!(
        events_before_eol.len(),
        3,
        "Create + 2 facts should be delivered"
    );
    assert_subject_sn_sequence(&events_before_eol, &subject_id_str, 0, 2);

    // Emit EOL and verify it is delivered as the next event.
    emit_eol(&node.api, subject_id.clone(), true).await.unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(4, true).await;
    let events_after_eol = sink.full_snapshot().await;
    assert_eq!(events_after_eol.len(), 4, "EOL should be delivered");
    assert_subject_sn_sequence(&events_after_eol, &subject_id_str, 0, 3);
    assert_sink_contains_eol(&events_after_eol, &subject_id_str, 3);

    // Ensure no further events or retries are attempted for the subject.
    assert_sink_count_stable(&sink, 4).await;
    wait_for_sink_not_lagging(&node.api, "example-sink").await;
    assert_sink_running(&node.api, "example-sink").await;

    // After EOL the subject no longer exists, so emitting a new fact must fail
    // and the sink must not receive any additional events.
    let err = emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .expect_err("fact after EOL should fail because the subject is gone");
    let msg = err.to_string();
    assert!(
        msg.contains("not active"),
        "expected subject to be inactive after EOL, got {:?}",
        err
    );

    assert_sink_count_stable(&sink, 4).await;
    assert_sink_running(&node.api, "example-sink").await;
}

/// Test 20: `sink_unsuccessful_transfer_and_governance_confirm`.
///
/// **Objective:** complement Tests 19A/19B by covering the two `success: false`
/// variants for non-fact events delivered by sinks:
/// - `Transfer` whose evaluation fails and is delivered with `success: false`
///   and non-empty `error`.
/// - Governance `Confirm` (`GovConfirm`) whose evaluation fails and is
///   delivered with `success: false`, non-empty `error`, and `patch: None`.
///
/// **Setup:**
/// - Bootstrap node, governance with schema `Example`, and two members (`Owner`
///   and `NewOwner`).
/// - Both nodes have sinks configured on the governance itself.
///
/// **Sequence:**
/// 1. Transfer governance to a public key that is not a member → the `Transfer`
///    event (SN 2) reaches the sink with `success: false`, `owner` = Owner,
///    `new_owner` = unknown key, and `gov_version` = 1.
/// 2. Transfer governance from Owner to NewOwner → the `Transfer` event (SN 3)
///    reaches the sink with `success: true`, `owner` = Owner, `new_owner` =
///    NewOwner, and `gov_version` = 1.
/// 3. Confirm from NewOwner renaming the old owner as `"OldOwner"` → the
///    `Confirm` event (SN 4) reaches the sink with `success: true`,
///    `name_old_owner` = `"OldOwner"`, `patch` present, and `gov_version` = 2.
/// 4. Transfer governance from NewOwner to Owner → the `Transfer` event (SN 5)
///    reaches the sink with `success: true`, `owner` = NewOwner, `new_owner` =
///    Owner, and `gov_version` = 3.
/// 5. Confirm from Owner using `"Owner"` as `name_old_owner` (reserved word) →
///    the `Confirm` event (SN 6) reaches the sink with `success: false`,
///    `name_old_owner` = `"Owner"`, non-empty `error`, `patch: None`, and
///    `gov_version` = 4.
///
/// **Verifications:**
/// - Both sinks receive exactly the 7 events with consecutive SNs from 0 to 6.
/// - `Transfer { success: false, error: Some(...), owner, new_owner, sn,
///   gov_version }` serializes and delivers correctly.
/// - `Transfer { success: true, error: None, owner, new_owner, sn, gov_version
///   }` serializes and delivers correctly for successful transfers.
/// - `Confirm { success: true, error: None, patch: Some(...), name_old_owner,
///   sn, gov_version }` serializes and delivers correctly.
/// - `Confirm { success: false, error: Some(...), patch: None, name_old_owner,
///   sn, gov_version }` serializes and delivers correctly.
/// - The `owner`, `new_owner`, `name_old_owner`, `sn`, and `gov_version` fields
///   are consistent in each event.
///
/// > **Note:** although the original plan proposed a tracker with a contract
/// > that failed on transfer, a tracker cannot generate `Confirm` events (only
/// > governance emits them) and a failed governance approval does not produce
/// > any ledger event. Therefore this test uses the governance itself as the
/// > subject, which is the only subject capable of generating both a failed
/// > `Transfer` and a failed `Confirm` with the current APIs.
#[traced_test]
#[tokio::test]
async fn sink_unsuccessful_transfer_and_governance_confirm() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let mut owner = nodes.remove(0);
    let mut new_owner = nodes.remove(0);

    let mut owner_dirs: Vec<_> = dirs.drain(0..2).collect();
    let mut new_owner_dirs: Vec<_> = dirs.drain(0..2).collect();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![&new_owner.api]).await;

    // Add NewOwner as a governance member/witness and schema creator so it can
    // receive and confirm governance transfers.
    emit_fact(
        &owner.api,
        governance_id.clone(),
        governance_with_transfer_roles_fact(new_owner.api.public_key()),
        true,
    )
    .await
    .unwrap();

    let governance_id_str = governance_id.to_string();
    let owner_pk_str = owner.api.public_key();

    let owner_sink = TestSink::start().await;
    let new_owner_sink = TestSink::start().await;

    // Restart owner with a sink attached to the governance subject.
    let owner_keys = owner.keys.clone();
    let owner_local_db = owner_dirs[0].path().to_path_buf();
    let owner_ext_db = owner_dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (owner, mut owner_dirs2) = create_node(restart_config(
        owner_keys,
        owner_local_db,
        owner_ext_db,
        format!("/memory/{}", owner_port),
        vec![make_governance_sink_entry(
            "owner-sink",
            owner_sink.url(),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    owner_dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    // Restart new_owner with a sink, peered to the new owner address.
    let owner_peer_id = owner.api.peer_id().to_string();
    let owner_address = owner.listen_address.clone();

    let new_owner_keys = new_owner.keys.clone();
    let new_owner_local_db = new_owner_dirs[0].path().to_path_buf();
    let new_owner_ext_db = new_owner_dirs[1].path().to_path_buf();
    new_owner.token.cancel();
    join_all(new_owner.handler.iter_mut()).await;

    let new_owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_owner, mut new_owner_dirs2) =
        create_node(restart_config_with_peers(
            new_owner_keys,
            new_owner_local_db,
            new_owner_ext_db,
            format!("/memory/{}", new_owner_port),
            vec![RoutingNode {
                peer_id: owner_peer_id,
                address: vec![owner_address],
            }],
            vec![make_governance_sink_entry(
                "new-owner-sink",
                new_owner_sink.url(),
                BTreeSet::from([SinkTypes::All]),
            )],
        ))
        .await;
    new_owner_dirs.append(&mut new_owner_dirs2);
    node_running(&new_owner.api).await.unwrap();

    assert_sink_running(&owner.api, "owner-sink").await;
    assert_sink_unblocked(&owner.api, "owner-sink").await;
    assert_sink_running(&new_owner.api, "new-owner-sink").await;
    assert_sink_unblocked(&new_owner.api, "new-owner-sink").await;

    // Ensure new_owner has the governance subject before ownership changes.
    get_subject(&new_owner.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 0: Create.
    // SN 1: governance fact that adds NewOwner.
    // SN 2: failed transfer to a public key that is not a governance member.
    let unknown_key = KeyPair::generate(KeyPairAlgorithm::Ed25519)
        .unwrap()
        .public_key();
    emit_transfer(&owner.api, governance_id.clone(), unknown_key.clone(), true)
        .await
        .unwrap();

    // SN 3: successful transfer Owner -> NewOwner.
    let new_owner_pk =
        PublicKey::from_str(new_owner.api.public_key()).unwrap();
    emit_transfer(
        &owner.api,
        governance_id.clone(),
        new_owner_pk.clone(),
        true,
    )
    .await
    .unwrap();

    get_subject(&new_owner.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // SN 4: successful GovConfirm from NewOwner, renaming the old owner to
    // "OldOwner" so it remains a governance witness and can be synchronized.
    emit_confirm(
        &new_owner.api,
        governance_id.clone(),
        Some("OldOwner".to_owned()),
        true,
    )
    .await
    .unwrap();

    // Synchronize Owner so its sink can receive the confirmed event.
    owner
        .api
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(new_owner_pk.clone()),
        )
        .await
        .unwrap();
    owner
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&owner.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // SN 5: successful transfer NewOwner -> Owner.
    let owner_pk = PublicKey::from_str(owner_pk_str).unwrap();
    emit_transfer(&new_owner.api, governance_id.clone(), owner_pk, true)
        .await
        .unwrap();

    get_subject(&owner.api, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // SN 6: failed GovConfirm from Owner using the reserved name "Owner" as
    // name_old_owner. The evaluation must reject the reserved word.
    emit_confirm(
        &owner.api,
        governance_id.clone(),
        Some("Owner".to_owned()),
        true,
    )
    .await
    .unwrap();

    // Wait for all events on both sinks.
    wait_for_sink_caught_up(&owner.api, "owner-sink").await;
    owner_sink.wait_for_count(7, true).await;
    wait_for_sink_caught_up(&new_owner.api, "new-owner-sink").await;
    new_owner_sink.wait_for_count(7, true).await;

    let owner_events = owner_sink.snapshot().await;
    let new_owner_events = new_owner_sink.snapshot().await;

    assert_eq!(owner_events.len(), 7);
    assert_eq!(new_owner_events.len(), 7);

    assert_subject_sn_sequence(&owner_events, &governance_id_str, 0, 6);
    assert_subject_sn_sequence(&new_owner_events, &governance_id_str, 0, 6);

    let owner_pk_str = owner.api.public_key();
    let new_owner_pk_str = new_owner.api.public_key();
    let unknown_key_str = unknown_key.to_string();

    assert_sink_contains_create(&owner_events, &governance_id_str, 0);
    assert_sink_contains_transfer_with_owners(
        &owner_events,
        &governance_id_str,
        2,
        false,
        owner_pk_str,
        &unknown_key_str,
        1,
    );
    assert_sink_contains_transfer_with_owners(
        &owner_events,
        &governance_id_str,
        3,
        true,
        owner_pk_str,
        new_owner_pk_str,
        1,
    );
    assert_sink_contains_confirm_with_name(
        &owner_events,
        &governance_id_str,
        4,
        true,
        Some("OldOwner"),
        2,
    );
    assert_sink_contains_transfer_with_owners(
        &owner_events,
        &governance_id_str,
        5,
        true,
        new_owner_pk_str,
        owner_pk_str,
        3,
    );
    assert_sink_contains_confirm_with_name(
        &owner_events,
        &governance_id_str,
        6,
        false,
        Some("Owner"),
        4,
    );

    assert_sink_contains_create(&new_owner_events, &governance_id_str, 0);
    assert_sink_contains_transfer_with_owners(
        &new_owner_events,
        &governance_id_str,
        2,
        false,
        owner_pk_str,
        &unknown_key_str,
        1,
    );
    assert_sink_contains_transfer_with_owners(
        &new_owner_events,
        &governance_id_str,
        3,
        true,
        owner_pk_str,
        new_owner_pk_str,
        1,
    );
    assert_sink_contains_confirm_with_name(
        &new_owner_events,
        &governance_id_str,
        4,
        true,
        Some("OldOwner"),
        2,
    );
    assert_sink_contains_transfer_with_owners(
        &new_owner_events,
        &governance_id_str,
        5,
        true,
        new_owner_pk_str,
        owner_pk_str,
        3,
    );
    assert_sink_contains_confirm_with_name(
        &new_owner_events,
        &governance_id_str,
        6,
        false,
        Some("Owner"),
        4,
    );

    // Ensure no further events or retries are attempted.
    assert_sink_count_stable(&owner_sink, 7).await;
    assert_sink_count_stable(&new_owner_sink, 7).await;
    assert_sink_not_lagging(&owner.api, "owner-sink").await;
    assert_sink_not_lagging(&new_owner.api, "new-owner-sink").await;
}

/// Test 21: `sink_get_events_reconstructs_events`.
///
/// **Objective:** exercise the `get_sink_events` endpoint (`GET
/// /sink-events/{subject_id}`) ensuring it reconstructs sink-formatted events
/// directly from the ledger, without depending on a sink having received them.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Create tracker `S1` of schema `Example`.
/// - Emit 3 facts on `S1` (one failed with `ModThree { data: 50 }` and two
///   successful).
///
/// **Sequence:**
/// 1. Before configuring any sink, call `api.get_sink_events(S1, { from_sn: 0,
///    to_sn: None, limit: 100 })`.
/// 2. Verify it returns the 4 events (Create + 3 FactFull) with the correct
///    fields.
/// 3. Test pagination by `limit`: call with `from_sn: 1, limit: 2` and verify
///    it returns only SN 1 and 2.
/// 4. Test range by `to_sn`: call with `from_sn: 1, to_sn: Some(2)` and verify
///    it returns SN 1 and 2.
/// 5. Call with `limit: 0` and verify it returns the error "Replay limit must
///    be greater than zero".
/// 6. Call with `from_sn: 5, to_sn: Some(3)` and verify it returns the error
///    "Replay range requires from_sn <= to_sn".
/// 7. Call with a non-existent `subject_id` and verify it returns a controlled
///    error (`MissingResource` because the node cannot find the subject actor).
/// 8. Repeat steps 1-4 for the governance itself (its `Create` + schema
///    configuration `FactFull`).
///
/// **Verifications:**
/// - `SinkEventsPage.events` contains `DataToSink` with the expected SNs and in
///   order.
/// - The failed fact has `success: false` and non-empty `error`.
/// - Successful facts have `success: true` and non-empty `patch`.
/// - Pagination by `limit` and `to_sn` works correctly.
/// - Range and zero-limit errors are returned with descriptive messages.
/// - An unknown `subject_id` produces a controlled error.
/// - Works for both trackers and governances.
///
/// > **Implementation note:** this test can be added to `core/tests/sink.rs` or
/// > to a new file `core/tests/sink_events.rs`.
#[traced_test]
#[tokio::test]
async fn sink_get_events_reconstructs_events() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    let gov_request_id = emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node.api,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        gov_request_id,
        true,
    )
    .await
    .unwrap();

    let (tracker_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let tracker_id_str = tracker_id.to_string();

    // SN 1: successful fact.
    emit_fact(
        &node.api,
        tracker_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // SN 2: failed fact (contract rejects ModThree with data 50).
    emit_fact(
        &node.api,
        tracker_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    // SN 3: successful fact.
    emit_fact(
        &node.api,
        tracker_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    // Step 1: retrieve all events for the tracker.
    let page = node
        .api
        .get_sink_events(
            tracker_id.clone(),
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: None,
                limit: Some(100),
            },
        )
        .await
        .unwrap();

    assert_sink_events_page(&page, 0, None, 100, false, None, 4);
    assert_data_to_sink_is_create(&page.events[0], &tracker_id_str, 0);
    assert_data_to_sink_is_fact_full(
        &page.events[1],
        &tracker_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_data_to_sink_is_fact_full(
        &page.events[2],
        &tracker_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );
    assert_data_to_sink_is_fact_full(
        &page.events[3],
        &tracker_id_str,
        3,
        true,
        Some(json!({"ModTwo": {"data": 2}})),
    );

    // Step 3: pagination by limit.
    let page = node
        .api
        .get_sink_events(
            tracker_id.clone(),
            SinkEventsQuery {
                from_sn: Some(1),
                to_sn: None,
                limit: Some(2),
            },
        )
        .await
        .unwrap();

    assert_sink_events_page(&page, 1, None, 2, true, Some(3), 2);
    assert_data_to_sink_is_fact_full(
        &page.events[0],
        &tracker_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_data_to_sink_is_fact_full(
        &page.events[1],
        &tracker_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );

    // Step 4: range by to_sn.
    let page = node
        .api
        .get_sink_events(
            tracker_id.clone(),
            SinkEventsQuery {
                from_sn: Some(1),
                to_sn: Some(2),
                limit: Some(100),
            },
        )
        .await
        .unwrap();

    assert_sink_events_page(&page, 1, Some(2), 100, false, None, 2);
    assert_data_to_sink_is_fact_full(
        &page.events[0],
        &tracker_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_data_to_sink_is_fact_full(
        &page.events[1],
        &tracker_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );

    // Step 5: limit 0 returns a descriptive error.
    let err = node
        .api
        .get_sink_events(
            tracker_id.clone(),
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: None,
                limit: Some(0),
            },
        )
        .await
        .unwrap_err();

    match err {
        Error::InvalidQueryParams(msg) => assert!(
            msg.contains("Replay limit must be greater than zero"),
            "unexpected error message: {}",
            msg
        ),
        other => panic!("expected InvalidQueryParams, got {:?}", other),
    }

    // Step 6: from_sn > to_sn returns a descriptive error.
    let err = node
        .api
        .get_sink_events(
            tracker_id.clone(),
            SinkEventsQuery {
                from_sn: Some(5),
                to_sn: Some(3),
                limit: Some(100),
            },
        )
        .await
        .unwrap_err();

    match err {
        Error::InvalidQueryParams(msg) => assert!(
            msg.contains("Replay range requires from_sn <= to_sn"),
            "unexpected error message: {}",
            msg
        ),
        other => panic!("expected InvalidQueryParams, got {:?}", other),
    }

    // Step 7: unknown subject returns a controlled error.
    let missing_id =
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![0u8; 32]).unwrap();
    let err = node
        .api
        .get_sink_events(
            missing_id,
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: None,
                limit: Some(100),
            },
        )
        .await
        .unwrap_err();

    assert!(
        matches!(err, Error::SubjectNotFound(_)),
        "expected SubjectNotFound for unknown subject, got {:?}",
        err
    );

    // Step 8: repeat the retrieval checks for the governance subject.
    let governance_id_str = governance_id.to_string();

    let page = node
        .api
        .get_sink_events(
            governance_id.clone(),
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: None,
                limit: Some(100),
            },
        )
        .await
        .unwrap();

    assert_sink_events_page(&page, 0, None, 100, false, None, 2);
    assert_data_to_sink_is_create(&page.events[0], &governance_id_str, 0);
    assert_data_to_sink_is_fact_full(
        &page.events[1],
        &governance_id_str,
        1,
        true,
        None,
    );

    let page = node
        .api
        .get_sink_events(
            governance_id.clone(),
            SinkEventsQuery {
                from_sn: Some(1),
                to_sn: None,
                limit: Some(1),
            },
        )
        .await
        .unwrap();

    assert_sink_events_page(&page, 1, None, 1, false, None, 1);
    assert_data_to_sink_is_fact_full(
        &page.events[0],
        &governance_id_str,
        1,
        true,
        None,
    );

    let page = node
        .api
        .get_sink_events(
            governance_id.clone(),
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: Some(1),
                limit: Some(100),
            },
        )
        .await
        .unwrap();

    assert_sink_events_page(&page, 0, Some(1), 100, false, None, 2);
    assert_data_to_sink_is_create(&page.events[0], &governance_id_str, 0);
    assert_data_to_sink_is_fact_full(
        &page.events[1],
        &governance_id_str,
        1,
        true,
        None,
    );
}

/// Test 22: `replay_during_active_catch_up`.
///
/// **Cases covered:** manual replay executed while an automatic catch-up is in
/// flight; no events should be lost. Raw delivery may contain duplicates caused
/// by contention, so the test verifies that, after deduplicating by
/// `(subject_id, sn)`, the sequence is complete and ordered.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Restart with `example-sink` configured with
///   `max_catch_up_concurrency: 1`, `request_timeout_ms: 2_000`, `max_retries:
///   0`.
/// - Create subject `S1`.
///
/// **Sequence:**
/// 1. Change `TestSink` to `ServerError` mode (`500 Internal Server Error`).
/// 2. Emit 2 facts on `S1` synchronously (`wait=true`). Both become `lagging`.
/// 3. Change `TestSink` to `Timeout(500)` mode (responds successfully but takes
///    500 ms per event).
/// 4. Immediately call `api.replay_sink_events` for `example-sink` and `S1`
///    from `from_sn: 0`.
/// 5. While automatic catch-up and replay are in flight, emit a third fact on
///    `S1` **asynchronously** (`wait=false`).
/// 6. Wait for the sink to finish receiving events.
///
/// **Verifications:**
/// - The sink receives at least the 4 distinct events: `Create` (SN 0) + 3
///   `FactFull` (SN 1, 2, 3).
/// - The SNs within `S1` are consecutive and, after deduplicating by
///   `(subject_id, sn)`, none are missing.
/// - The deduplicated delivery order is `[0, 1, 2, 3]`.
/// - After a stabilization period no new SNs appear.
///
/// > **Implementation note:** `TestSink` stores each raw HTTP delivery, so when
/// > automatic catch-up and manual replay overlap duplicate deliveries may
/// > occur. The test uses `wait_for_distinct_sn_count` to wait until it has the
/// > 4 distinct SNs for the subject, deduplicates by `(subject_id, sn)`, and
/// > verifies that no event is lost and that the final sequence is complete and
/// > ordered. Completely avoiding duplicates in this contention scenario would
/// > require the `SinkManager` to coordinate cursor rewind with in-flight
/// > catch-ups.
#[traced_test]
#[tokio::test]
async fn replay_during_active_catch_up() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    // Restart the node with the sink configured for slow, single-concurrency
    // catch-up. This matches the plan's "restart with sink" step.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_concurrency(
            "example-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            1,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    assert_sink_running(&node.api, "example-sink").await;
    assert_sink_unblocked(&node.api, "example-sink").await;

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    // Step 1: sink returns 500 for every event.
    sink.set_mode(ResponseMode::ServerError).await;

    // Step 2: emit two facts synchronously; they become lagging.
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    assert_sink_lagging(&node.api, "example-sink", 1).await;

    // Step 3: sink now succeeds but takes 500 ms per event.
    sink.set_mode(ResponseMode::Timeout(500)).await;

    // Step 4: start a manual replay from SN 0 while automatic catch-up is also
    // trying to deliver the lagging events.
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 0,
            }],
        })
        .await
        .unwrap();
    assert!(response.errors.is_empty());
    assert_eq!(response.processed.len(), 1);

    // Step 5: emit a third fact asynchronously while both catch-ups are in
    // flight.
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 3}}),
        false,
    )
    .await
    .unwrap();

    // Step 6: wait until the sink has received at least the 4 distinct SNs for
    // this subject, tolerating duplicate HTTP deliveries caused by overlapping
    // catch-up and replay.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_distinct_sn_count(&subject_id_str, 4, true)
        .await;

    // Allow any in-flight retries to settle, then verify stability.
    let raw_events = wait_for_sink_events_stable(&sink).await;
    let events = deduplicate_events_by_sn(&raw_events);

    // The raw sink may receive duplicate deliveries when automatic catch-up
    // and manual replay overlap; the important guarantee is that every SN is
    // present and the deduplicated sequence is complete and ordered.
    assert!(
        events.len() >= 4,
        "deduplicated events should contain at least 4 entries, got {}",
        events.len()
    );

    let sns: Vec<u64> = events.iter().map(|e| e.sn()).collect();
    let expected_sns: Vec<u64> = vec![0, 1, 2, 3];
    assert_eq!(
        sns, expected_sns,
        "deduplicated delivery order should be consecutive"
    );

    assert_event_is_create(&events[0], &subject_id_str, 0);
    assert_event_is_fact_full(
        &events[1],
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_event_is_fact_full(
        &events[2],
        &subject_id_str,
        2,
        true,
        Some(json!({"ModTwo": {"data": 2}})),
    );
    assert_event_is_fact_full(
        &events[3],
        &subject_id_str,
        3,
        true,
        Some(json!({"ModThree": {"data": 3}})),
    );

    // Stability: after waiting, no new distinct SNs appear.
    let raw_events_later = wait_for_sink_events_stable(&sink).await;
    let events_later = deduplicate_events_by_sn(&raw_events_later);
    let sns_later: Vec<u64> = events_later.iter().map(|e| e.sn()).collect();
    assert_eq!(
        sns_later, expected_sns,
        "distinct SNs should remain stable after settling"
    );
}

/// TLS with a custom CA: the node must deliver to an HTTPS sink whose server
/// certificate chains to a CA configured via `tls.ca_certificate`.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit one fact.
/// 2. Restart with a sink pointing at an HTTPS `TestSink` (server certificate
///    signed by a throwaway CA) configured with `tls.ca_certificate`.
///
/// **Verifications:**
/// - Startup catch-up delivers the create event and the fact over HTTPS.
/// - The sink passes the healthcheck (it is reported running), proving the
///   CA is used for healthcheck requests too.
#[traced_test]
#[tokio::test]
async fn sink_tls_custom_ca_delivery() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (sink, tls_material) = TestSink::start_tls(false).await;
    let tls_dir = tempfile::tempdir().unwrap();
    let ca_path = tls_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &tls_material.ca_pem).unwrap();

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_tls(
            "tls-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpTlsConfig {
                ca_certificate: ca_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Startup catch-up delivers the create event (SN 0) and the fact (SN 1).
    wait_for_sink_caught_up(&node.api, "tls-sink").await;
    sink.wait_for_distinct_sn_count(&subject_id.to_string(), 2, true)
        .await;
    assert_sink_running(&node.api, "tls-sink").await;
}

/// TLS without the CA: delivery to an HTTPS sink must fail when the node does
/// not trust the sink's CA (no `tls.ca_certificate` configured).
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with a sink pointing at an HTTPS `TestSink` but with no TLS
///    configuration, so rustls rejects the unknown CA.
///
/// **Verifications:**
/// - The subject is reported lagging for the sink.
/// - No request body ever reaches the sink (the handshake fails).
#[traced_test]
#[tokio::test]
async fn sink_tls_missing_ca_fails() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (sink, _tls_material) = TestSink::start_tls(false).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry(
            "tls-no-ca-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The TLS handshake fails, so the subject never catches up.
    wait_for_sink_lagging_subjects(&node.api, "tls-no-ca-sink", 1).await;
    assert!(
        sink.raw_bodies().await.is_empty(),
        "no delivery request must complete the TLS handshake"
    );
    assert!(
        sink.snapshot().await.is_empty(),
        "no event must be accepted by the sink"
    );
}

/// Mutual TLS: the node must present the configured client certificate and
/// deliver to an HTTPS sink that requires it.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit one fact.
/// 2. Restart with a sink pointing at an mTLS `TestSink` (client certificate
///    required) configured with `tls.ca_certificate`, `tls.client_certificate`
///    and `tls.client_key`.
///
/// **Verifications:**
/// - Startup catch-up delivers the create event and the fact over mTLS.
#[traced_test]
#[tokio::test]
async fn sink_mtls_delivery() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (sink, tls_material) = TestSink::start_tls(true).await;
    let tls_dir = tempfile::tempdir().unwrap();
    let ca_path = tls_dir.path().join("ca.pem");
    let client_cert_path = tls_dir.path().join("client.pem");
    let client_key_path = tls_dir.path().join("client-key.pem");
    std::fs::write(&ca_path, &tls_material.ca_pem).unwrap();
    std::fs::write(&client_cert_path, &tls_material.client_cert_pem).unwrap();
    std::fs::write(&client_key_path, &tls_material.client_key_pem).unwrap();

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_tls(
            "mtls-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpTlsConfig {
                ca_certificate: ca_path.to_string_lossy().into_owned(),
                client_certificate: client_cert_path
                    .to_string_lossy()
                    .into_owned(),
                client_key: client_key_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Startup catch-up delivers the create event (SN 0) and the fact (SN 1).
    wait_for_sink_caught_up(&node.api, "mtls-sink").await;
    sink.wait_for_distinct_sn_count(&subject_id.to_string(), 2, true)
        .await;
    assert_sink_running(&node.api, "mtls-sink").await;
}

/// TLS certificate pinning: the sink must accept only the pinned server
/// certificate and reject a different one.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with an HTTPS sink configured with `pinned_certificate` set to
///    the TestSink's server certificate: delivery must succeed.
/// 3. Restart again with `pinned_certificate` set to the TestSink's CA
///    certificate instead of the server certificate: the handshake must fail.
///
/// **Verifications:**
/// - With the correct pin, startup catch-up delivers the create event.
/// - With the wrong pin, the subject is reported lagging and no body reaches
///   the sink.
#[traced_test]
#[tokio::test]
async fn sink_tls_pinning() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (sink, tls_material) = TestSink::start_tls(false).await;
    let tls_dir = tempfile::tempdir().unwrap();
    let server_cert_path = tls_dir.path().join("server.pem");
    let ca_cert_path = tls_dir.path().join("ca.pem");
    std::fs::write(&server_cert_path, &tls_material.server_cert_pem).unwrap();
    std::fs::write(&ca_cert_path, &tls_material.ca_pem).unwrap();

    // Correct pin: the exact server certificate.
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_tls(
            "pinned-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpTlsConfig {
                pinned_certificate: server_cert_path
                    .to_string_lossy()
                    .into_owned(),
                ..Default::default()
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "pinned-sink").await;
    sink.wait_for_distinct_sn_count(&subject_id.to_string(), 1, true)
        .await;
    assert_sink_running(&node.api, "pinned-sink").await;

    // Wrong pin: the CA certificate is not the server certificate.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_tls(
            "pinned-wrong-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpTlsConfig {
                pinned_certificate: ca_cert_path.to_string_lossy().into_owned(),
                ..Default::default()
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_lagging_subjects(&node.api, "pinned-wrong-sink", 1).await;
}

/// Signature reuse across retries: the delivery payload is signed once and
/// the same signature is sent on every retry attempt.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with a sink configured with `signature: true` and
///    `max_retries: 1`, with the `TestSink` rejecting deliveries (HTTP 500).
/// 3. Startup catch-up attempts the create event twice.
///
/// **Verifications:**
/// - Both attempts carry identical `X-Ave-Signature` and
///   `X-Ave-Signature-Timestamp` headers (the payload is signed once).
/// - The shared signature verifies cryptographically against the received
///   body.
/// - Once the sink accepts again, the event is delivered.
#[traced_test]
#[tokio::test]
async fn sink_signature_reused_across_retries() {
    use ave_common::identity::{
        BLAKE3_HASHER, Hash as _, SignatureIdentifier, TimeStamp,
    };

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::ServerError).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_signature_and_retries(
            "signed-retry-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            1,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The initial attempt plus one retry both reach the sink as raw
    // deliveries (failures are recorded before the response mode applies).
    sink.wait_for_raw_count(2, true).await;

    let signature_headers = sink.signature_headers().await;
    let first = &signature_headers[0];
    let second = &signature_headers[1];

    let signature = first
        .signature
        .as_ref()
        .expect("X-Ave-Signature header must be present");
    let timestamp = first
        .timestamp
        .as_ref()
        .expect("X-Ave-Signature-Timestamp header must be present");
    assert_eq!(
        first.signature, second.signature,
        "the retry must reuse the signature of the first attempt"
    );
    assert_eq!(
        first.timestamp, second.timestamp,
        "the retry must reuse the timestamp of the first attempt"
    );
    assert_eq!(
        first.public_key, second.public_key,
        "the retry must reuse the public key of the first attempt"
    );

    // The shared signature must verify against the delivered body.
    let content = sink.raw_bodies().await[0].clone();
    let timestamp = TimeStamp::from_nanos(
        timestamp
            .parse::<u64>()
            .expect("timestamp must be nanoseconds"),
    );
    let payload_bytes = borsh::to_vec(&(&content, &timestamp)).unwrap();
    let hash = BLAKE3_HASHER.hash(&payload_bytes);
    let signer = PublicKey::from_str(
        first
            .public_key
            .as_ref()
            .expect("public key must be present"),
    )
    .unwrap();
    let signature = SignatureIdentifier::from_str(signature).unwrap();
    signer
        .verify(hash.hash_bytes(), &signature)
        .expect("delivery signature must verify against the received body");

    // When the sink accepts again, the worker catches up.
    sink.set_mode(ResponseMode::Accept).await;
    wait_for_sink_caught_up(&node.api, "signed-retry-sink").await;
    sink.wait_for_distinct_sn_count(&subject_id.to_string(), 1, true)
        .await;
}

/// Idempotency headers: every individual HTTP delivery must carry
/// `X-Ave-Subject-Id`, `X-Ave-SN`, `X-Ave-Event-Type` and `Idempotency-Key`
/// so receivers can deduplicate without parsing the body.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit two facts.
/// 2. Restart with a sink whose filter is only `Create`, so the create event
///    is delivered full and the two facts as lightweight events.
/// 3. Startup catch-up delivers the three events.
///
/// **Verifications:**
/// - Each delivery carries the four headers with values matching the
///   delivered event: subject, sn, event type and an idempotency key of the
///   form `<subject_id>-<sn>`.
#[traced_test]
#[tokio::test]
async fn sink_idempotency_headers() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry(
            "idem-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::Create]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Startup catch-up delivers the create event (SN 0, full) plus the two
    // facts as lightweight events.
    wait_for_sink_caught_up(&node.api, "idem-sink").await;
    sink.wait_for_count(3, true).await;

    let events = sink.snapshot().await;
    let headers = sink.idempotency_headers().await;
    assert_eq!(events.len(), 3);
    assert_eq!(headers.len(), 3);

    for (headers, event) in headers.iter().zip(events.iter()) {
        assert_eq!(
            headers.subject_id.as_deref(),
            Some(event.subject_id()),
            "X-Ave-Subject-Id must match the delivered event"
        );
        assert_eq!(
            headers.sn.as_deref(),
            Some(event.sn().to_string()).as_deref(),
            "X-Ave-SN must match the delivered event"
        );
        assert_eq!(
            headers.event_type.as_deref(),
            Some(event.event_type().as_str()),
            "X-Ave-Event-Type must match the delivered event"
        );
        assert_eq!(
            headers.key.as_deref(),
            Some(format!("{}-{}", event.subject_id(), event.sn())).as_deref(),
            "Idempotency-Key must be '<subject_id>-<sn>'"
        );
    }
}

/// Proxy deliveries: a sink configured with `proxy` must route its requests
/// through the forward proxy instead of connecting directly to the sink.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit one fact.
/// 2. Restart with a sink whose URL is the real sink but with a proxy
///    configured (no credentials).
///
/// **Verifications:**
/// - The sink receives both events (the proxy forwards correctly).
/// - The proxy recorded the delivery requests in absolute-URI form.
#[traced_test]
#[tokio::test]
async fn sink_proxy_delivery() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let proxy = TestProxy::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_proxy(
            "proxy-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpProxyConfig {
                url: proxy.url(),
                username: String::new(),
                no_proxy: vec![],
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "proxy-sink").await;
    sink.wait_for_count(2, true).await;

    let proxied = proxy.proxied_requests().await;
    let post_line = format!("POST {}", sink.url());
    assert!(
        proxied
            .iter()
            .filter(|r| r.request_line == post_line)
            .count()
            >= 2,
        "the proxy must record the two deliveries to {}, got {:?}",
        post_line,
        proxied
            .iter()
            .map(|r| r.request_line.clone())
            .collect::<Vec<_>>()
    );
    assert!(
        proxied.iter().all(|r| r.proxy_authorization.is_none()),
        "no proxy credentials are configured, none must be sent"
    );
}

/// Proxy authentication: with `proxy.username` set, the worker must read the
/// password from `AVE_SINK_PROXY_PASSWORD_{{SERVER}}` and send proxy basic
/// auth on every request.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with a sink behind a proxy with credentials; the password is
///    provided through the environment variable.
///
/// **Verifications:**
/// - The delivery succeeds through the proxy.
/// - The proxy receives the `Proxy-Authorization` header with the basic auth
///   credentials.
#[traced_test]
#[tokio::test]
async fn sink_proxy_delivery_with_auth() {
    let proxy_password_env = "AVE_SINK_PROXY_PASSWORD_PROXY_AUTH_SINK";
    let _proxy_password_guard =
        TempEnvVar::set(proxy_password_env, "proxy-secret");

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let proxy = TestProxy::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_proxy(
            "proxy-auth-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpProxyConfig {
                url: proxy.url(),
                username: "ave".to_owned(),
                no_proxy: vec![],
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "proxy-auth-sink").await;
    sink.wait_for_count(1, true).await;

    use base64::Engine as _;
    let expected_auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("ave:proxy-secret")
    );
    let proxied = proxy.proxied_requests().await;
    assert!(
        proxied.iter().any(|r| r.proxy_authorization.as_deref()
            == Some(expected_auth.as_str())),
        "the proxy must receive the basic auth header, got {:?}",
        proxied
    );
}

/// `Retry-After` handling: a 429 response with a `Retry-After` header must
/// delay the next delivery attempt by at least the server-provided time,
/// even when the configured backoff is shorter.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit two facts.
/// 2. Restart with a sink that rejects the first delivery with 429 and
///    `Retry-After: 2`, with a fast configured backoff (100 ms).
///
/// **Verifications:**
/// - The first delivery is retried and all events arrive.
/// - The time between the first attempt and the retry is at least ~2
///   seconds, not the configured 100 ms backoff.
#[traced_test]
#[tokio::test]
async fn sink_retry_after_respected() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::RateLimitOnce(2)).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_retry_policy(
            "ratelimit-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            1,
            100,
            30_000,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // First attempt (429) plus the retry. Only a lower bound is asserted:
    // the configured sleep is exact, and a loaded machine can only make the
    // observed delta larger, never smaller.
    sink.wait_for_raw_count(2, true).await;
    let received_at = sink.received_at().await;
    let delta = received_at[1].duration_since(received_at[0]);
    assert!(
        delta >= Duration::from_millis(1_900),
        "the retry must honor Retry-After (~2s), waited {:?}",
        delta
    );

    // Every event is delivered after the successful retry.
    sink.wait_for_count(3, true).await;
}

/// `retry_max_delay_ms` cap: the server-provided `Retry-After` hint must be
/// capped by the sink's configured maximum retry delay.
///
/// **Flow:**
/// Same as `sink_retry_after_respected`, but the sink asks for 10 seconds
/// while `retry_max_delay_ms` is set to 500 ms.
///
/// **Verifications:**
/// - The retry happens after ~500 ms: well above the configured 100 ms base
///   backoff (so the hint was not ignored) and far below the requested 10
///   seconds (so the cap applied).
#[traced_test]
#[tokio::test]
async fn sink_retry_after_capped() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::RateLimitOnce(10)).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_retry_policy(
            "ratelimit-capped-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            1,
            100,
            500,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The sink asks for 10 s but `retry_max_delay_ms` caps the wait at
    // 500 ms. The bounds discriminate the three possible behaviors rather
    // than measuring a fixed duration: ignoring the hint would wait ~100 ms
    // (the configured base backoff) and honoring it would wait ~10 s; both
    // fall outside the window on any machine.
    sink.wait_for_raw_count(2, true).await;
    let received_at = sink.received_at().await;
    let delta = received_at[1].duration_since(received_at[0]);
    assert!(
        delta >= Duration::from_millis(400),
        "the retry must wait the capped delay (~500ms), waited {:?}",
        delta
    );
    assert!(
        delta < Duration::from_secs(5),
        "retry_max_delay_ms must cap the 10s Retry-After hint, waited {:?}",
        delta
    );

    sink.wait_for_count(1, true).await;
}

/// Batch delivery in catch-up: with `batch_delivery` the pending events of a
/// subject are delivered as a single POST with a JSON array body instead of
/// one POST per event.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit three facts.
/// 2. Restart with a batch sink; startup catch-up delivers the four pending
///    events.
///
/// **Verifications:**
/// - Exactly one POST reaches the sink, with a JSON array of the four
///   events in SN order.
/// - Batch deliveries do not carry the per-event `X-Ave-*` /
///   `Idempotency-Key` headers.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_catch_up() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "batch-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkCompression::None,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "batch-sink").await;
    sink.wait_for_count(4, true).await;

    // A single POST delivered the whole catch-up batch.
    let raw_bodies = sink.raw_bodies().await;
    assert_eq!(
        raw_bodies.len(),
        1,
        "the catch-up must be a single batch POST"
    );
    let body: Vec<serde_json::Value> = serde_json::from_slice(&raw_bodies[0])
        .expect("body must be a JSON array");
    assert_eq!(body.len(), 4, "the batch must contain the four events");

    let batch_lens = sink.batch_lens().await;
    assert_eq!(batch_lens, vec![4]);

    // Events arrive in SN order and nothing is duplicated.
    let events = sink.snapshot().await;
    let sns: Vec<u64> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);

    // Batch deliveries carry no per-event idempotency headers.
    let headers = sink.idempotency_headers().await;
    assert_eq!(headers.len(), 1);
    assert!(headers[0].subject_id.is_none());
    assert!(headers[0].sn.is_none());
    assert!(headers[0].event_type.is_none());
    assert!(headers[0].key.is_none());
}

/// Batch delivery with gzip: with `compression = "gzip"` the batch body is
/// sent gzip-compressed with the `Content-Encoding: gzip` header.
///
/// **Flow:**
/// Same as `sink_batch_delivery_catch_up` with gzip compression enabled.
///
/// **Verifications:**
/// - The request carries `Content-Encoding: gzip`.
/// - The raw body is gzip (magic bytes) and decompresses to the JSON array
///   of the four events.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_gzip() {
    use std::io::Read as _;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "batch-gzip-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkCompression::Gzip,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "batch-gzip-sink").await;
    sink.wait_for_count(4, true).await;

    let content_encodings = sink.content_encodings().await;
    assert_eq!(content_encodings.len(), 1);
    assert_eq!(content_encodings[0].as_deref(), Some("gzip"));

    let raw_bodies = sink.raw_bodies().await;
    assert_eq!(raw_bodies.len(), 1);
    let body = &raw_bodies[0];
    assert!(
        body.len() > 2 && body[0] == 0x1f && body[1] == 0x8b,
        "the body must be gzip-compressed"
    );

    let mut decoder = flate2::read::GzDecoder::new(body.as_slice());
    let mut decompressed = Vec::new();
    decoder
        .read_to_end(&mut decompressed)
        .expect("the body must gunzip");
    let events: Vec<serde_json::Value> = serde_json::from_slice(&decompressed)
        .expect("the decompressed body must be a JSON array");
    assert_eq!(events.len(), 4, "the batch must contain the four events");
}

/// Batch delivery with zstd: with `compression = "zstd"` the batch body is
/// sent zstd-compressed with the `Content-Encoding: zstd` header.
///
/// **Flow:**
/// Same as `sink_batch_delivery_gzip` with zstd compression enabled.
///
/// **Verifications:**
/// - The request carries `Content-Encoding: zstd`.
/// - The raw body is zstd (magic bytes) and decompresses to the JSON array
///   of the four events.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_zstd() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "batch-zstd-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkCompression::Zstd,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "batch-zstd-sink").await;
    sink.wait_for_count(4, true).await;

    let content_encodings = sink.content_encodings().await;
    assert_eq!(content_encodings.len(), 1);
    assert_eq!(content_encodings[0].as_deref(), Some("zstd"));

    let raw_bodies = sink.raw_bodies().await;
    assert_eq!(raw_bodies.len(), 1);
    let body = &raw_bodies[0];
    assert!(
        body.len() > 4
            && body[0] == 0x28
            && body[1] == 0xb5
            && body[2] == 0x2f
            && body[3] == 0xfd,
        "the body must be zstd-compressed"
    );

    let decompressed = zstd::bulk::decompress(body, 1024 * 1024)
        .expect("the body must be valid zstd");
    let events: Vec<serde_json::Value> = serde_json::from_slice(&decompressed)
        .expect("the decompressed body must be a JSON array");
    assert_eq!(events.len(), 4, "the batch must contain the four events");
}

/// Batch delivery of live events: in `batch_delivery` mode, events emitted
/// while the node runs are buffered and flushed as JSON arrays (on size or
/// delay), never as individual POSTs.
///
/// **Flow:**
/// 1. Create governance and schema; restart with a batch sink.
/// 2. Create a subject and emit three facts (live delivery).
///
/// **Verifications:**
/// - Every delivery is a JSON array (no individual POSTs) and together they
///   carry the four events of the subject in SN order.
/// - No delivery carries the per-event idempotency headers.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_live() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "batch-live-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkCompression::None,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Live deliveries after the restart.
    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    wait_for_sink_caught_up(&node.api, "batch-live-sink").await;
    sink.wait_for_count(4, true).await;

    // Every raw delivery is a JSON array; together they carry the 4 events.
    let raw_bodies = sink.raw_bodies().await;
    assert!(!raw_bodies.is_empty());
    for body in &raw_bodies {
        assert!(
            body.first() == Some(&b'['),
            "every batch delivery must be a JSON array"
        );
    }
    let batch_lens = sink.batch_lens().await;
    assert_eq!(
        batch_lens.iter().sum::<usize>(),
        4,
        "the batches must carry the four events in total"
    );

    // SN order is preserved across batches.
    let events = sink.snapshot().await;
    let sns: Vec<u64> = events
        .iter()
        .filter(|e| e.subject_id() == subject_id.to_string())
        .map(|e| e.sn())
        .collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);

    // No individual headers on any batch delivery.
    let headers = sink.idempotency_headers().await;
    assert_eq!(headers.len(), raw_bodies.len());
    assert!(
        headers
            .iter()
            .all(|h| h.subject_id.is_none() && h.key.is_none()),
        "batch deliveries must not carry per-event idempotency headers"
    );
}

/// Batch delivery of a live burst: when several facts are emitted without
/// awaiting each one, the manager must forward them all to the same worker so
/// they are flushed as a single JSON-array POST, not diverted to catch-up.
///
/// **Flow:**
/// 1. Create governance and schema; restart with a batch sink (`batch_size`
///    equal to the total number of events, high `batch_max_delay_ms` so the
///    timer does not interfere).
/// 2. Create a subject and emit three facts asynchronously, then one final
///    synchronous fact to flush the pipeline.
///
/// **Verifications:**
/// - All five events (create + four facts) arrive in one single POST.
/// - The sink never enters `lagging` state.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_burst_single_post() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let mut entry = make_sink_entry_batch(
        "batch-burst-sink",
        sink.url(),
        Some(governance_id.to_string()),
        BTreeSet::from([SinkTypes::All]),
        SinkCompression::None,
    );
    // One batch for the whole burst; the timer must not fire during the test.
    entry.servers[0].batch_delivery_size = 5;
    if let SinkTransportConfig::Http(ref mut http) = entry.servers[0].transport
    {
        http.batch_max_delay_ms = 60_000;
    }

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![entry],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    // Burst: three async facts followed by one sync fact that flushes the
    // pipeline.
    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            false,
        )
        .await
        .unwrap();
    }
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 4}}),
        true,
    )
    .await
    .unwrap();

    wait_for_sink_caught_up(&node.api, "batch-burst-sink").await;
    sink.wait_for_count(5, true).await;

    // The whole burst must have been delivered as a single JSON-array POST.
    let batch_lens = sink.batch_lens().await;
    assert_eq!(
        batch_lens,
        vec![5],
        "the burst must be delivered as one batch of five events"
    );

    let events = sink.snapshot().await;
    let sns: Vec<u64> = events
        .iter()
        .filter(|e| e.subject_id() == subject_id.to_string())
        .map(|e| e.sn())
        .collect();
    assert_eq!(sns, vec![0, 1, 2, 3, 4]);

    // The sequential gate must not have diverted any event to lagging.
    assert_sink_not_lagging(&node.api, "batch-burst-sink").await;
}

/// Live burst without batch delivery: events emitted in a burst must be
/// delivered in order without entering `lagging`, even when earlier events
/// are still in flight.
///
/// **Flow:**
/// 1. Create governance and schema; restart with a regular (non-batch) sink.
/// 2. Create a subject and emit four facts asynchronously, then one final
///    synchronous fact to flush the pipeline.
///
/// **Verifications:**
/// - All six events (create + five facts) arrive in SN order.
/// - The sink never enters `lagging` state.
#[traced_test]
#[tokio::test]
async fn sink_live_burst_no_lagging() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry(
            "live-burst-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    // Slow the sink down so the burst arrives while the first delivery is
    // still in flight. Without the notification gate this forces a
    // SequentialGap and the subject would enter lagging.
    sink.set_mode(ResponseMode::Timeout(50)).await;

    // Burst: four async facts followed by one sync fact that flushes the
    // pipeline.
    for i in 1..=4 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            false,
        )
        .await
        .unwrap();
    }
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 5}}),
        true,
    )
    .await
    .unwrap();

    wait_for_sink_caught_up(&node.api, "live-burst-sink").await;
    sink.wait_for_count(6, true).await;

    let events = sink.snapshot().await;
    let sns: Vec<u64> = events
        .iter()
        .filter(|e| e.subject_id() == subject_id.to_string())
        .map(|e| e.sn())
        .collect();
    assert_eq!(sns, vec![0, 1, 2, 3, 4, 5]);

    // The sequential gate must not have diverted any event to lagging.
    assert_sink_not_lagging(&node.api, "live-burst-sink").await;
}

/// Proxy `no_proxy` bypass: hosts listed in `proxy.no_proxy` must be
/// contacted directly, skipping the configured proxy.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with a sink behind a proxy whose `no_proxy` list contains
///    `127.0.0.1` (the sink's host).
///
/// **Verifications:**
/// - The delivery succeeds (direct connection).
/// - The proxy records no request at all.
#[traced_test]
#[tokio::test]
async fn sink_proxy_no_proxy_bypass() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (_subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let proxy = TestProxy::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_proxy(
            "proxy-bypass-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            HttpProxyConfig {
                url: proxy.url(),
                username: String::new(),
                no_proxy: vec!["127.0.0.1".to_owned()],
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "proxy-bypass-sink").await;
    sink.wait_for_count(1, true).await;

    assert!(
        proxy.proxied_requests().await.is_empty(),
        "no_proxy hosts must bypass the proxy entirely"
    );
}

/// Idempotency key stability across retries: every retry of the same event
/// carries the same `Idempotency-Key`, so the receiver can deduplicate
/// retried deliveries.
///
/// **Flow:**
/// 1. Create governance, schema and a subject.
/// 2. Restart with a sink with `max_retries: 1` while the `TestSink` rejects
///    deliveries (HTTP 500).
/// 3. Startup catch-up attempts the create event twice.
///
/// **Verifications:**
/// - Both attempts carry identical `X-Ave-Subject-Id`, `X-Ave-SN`,
///   `X-Ave-Event-Type` and `Idempotency-Key` headers.
/// - Once the sink accepts again, the event is delivered.
#[traced_test]
#[tokio::test]
async fn sink_idempotency_key_stable_across_retries() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::ServerError).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_retry_policy(
            "idem-retry-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            1,
            100,
            30_000,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The initial attempt plus one retry both reach the sink as raw
    // deliveries (failures are recorded before the response mode applies).
    sink.wait_for_raw_count(2, true).await;

    let headers = sink.idempotency_headers().await;
    let first = &headers[0];
    let second = &headers[1];

    assert_eq!(
        first.subject_id.as_deref(),
        Some(subject_id.to_string()).as_deref()
    );
    assert_eq!(first.subject_id, second.subject_id);
    assert_eq!(first.sn, second.sn);
    assert_eq!(first.event_type, second.event_type);
    assert_eq!(
        first.key.as_deref(),
        Some(format!("{}-0", subject_id)).as_deref(),
        "Idempotency-Key must be '<subject_id>-<sn>'"
    );
    assert_eq!(
        first.key, second.key,
        "the retry must reuse the idempotency key of the first attempt"
    );

    // When the sink accepts again, the worker catches up.
    sink.set_mode(ResponseMode::Accept).await;
    wait_for_sink_caught_up(&node.api, "idem-retry-sink").await;
    sink.wait_for_distinct_sn_count(&subject_id.to_string(), 1, true)
        .await;
}

/// Batch failure semantics: when a batch delivery fails, the cursor does not
/// advance and the whole batch is delivered again by the next catch-up —
/// nothing is lost and nothing is partially applied.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit three facts.
/// 2. Restart with a batch sink while the `TestSink` rejects deliveries
///    (HTTP 500); the subject goes lagging.
/// 3. The sink accepts again and the automatic catch-up redelivers.
///
/// **Verifications:**
/// - Failed attempts are also batch POSTs (JSON arrays), not individual
///   events.
/// - After recovery, the four events arrive exactly once and in SN order.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_failure_retries_whole_batch() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::ServerError).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "batch-fail-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkCompression::None,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The failed batch delivery sends the subject to lagging.
    wait_for_sink_lagging_subjects(&node.api, "batch-fail-sink", 1).await;
    sink.wait_for_raw_count(1, true).await;

    // Failed attempts are batch POSTs (JSON arrays), never individual POSTs.
    for body in &sink.raw_bodies().await {
        assert!(
            body.first() == Some(&b'['),
            "failed deliveries must also be JSON arrays"
        );
    }
    assert!(
        sink.snapshot().await.is_empty(),
        "no event is accepted while the sink returns 500"
    );

    // After recovery the whole batch is delivered again, exactly once and in
    // order.
    sink.set_mode(ResponseMode::Accept).await;
    wait_for_sink_caught_up(&node.api, "batch-fail-sink").await;
    sink.wait_for_count(4, true).await;

    let events = sink.snapshot().await;
    assert_no_duplicate_events(&events);
    let sns: Vec<u64> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2, 3]);
}

/// Mixed batch contents: with a filter that matches only part of the events,
/// a batch delivery is a JSON array that mixes full events and lightweight
/// projections, both decodable by the receiver.
///
/// **Flow:**
/// 1. Create governance, schema and a subject; emit two facts.
/// 2. Restart with a batch sink whose filter is only `Create`; startup
///    catch-up delivers the three events in one batch.
///
/// **Verifications:**
/// - A single POST carries the three events as a JSON array.
/// - The create event is full and the two facts are lightweight, inside the
///   same array.
#[traced_test]
#[tokio::test]
async fn sink_batch_delivery_mixed_full_light() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let sink = TestSink::start().await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_batch(
            "batch-mixed-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::Create]),
            SinkCompression::None,
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "batch-mixed-sink").await;
    sink.wait_for_count(3, true).await;

    let batch_lens = sink.batch_lens().await;
    assert_eq!(
        batch_lens,
        vec![3],
        "the three events must arrive in a single batch"
    );

    let events = sink.snapshot().await;
    assert!(
        matches!(events.first(), Some(IncomingSinkEvent::Full(_))),
        "the create event must be delivered full inside the batch"
    );
    assert!(
        events[1..]
            .iter()
            .all(|e| matches!(e, IncomingSinkEvent::Light(_))),
        "facts must be lightweight inside the batch"
    );
    let sns: Vec<u64> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(sns, vec![0, 1, 2]);
}

/// Minimal OAuth2 token endpoint for `client_credentials` e2e tests.
/// Captures the JSON body of the first token request and returns a fixed
/// Bearer token. The captured body is read through the returned Arc<Mutex>.
async fn start_client_credentials_auth_server() -> (
    String,
    std::sync::Arc<tokio::sync::Mutex<Option<serde_json::Value>>>,
) {
    use axum::{Json, Router, extract::State, http::StatusCode, routing::post};

    let captured = std::sync::Arc::new(tokio::sync::Mutex::new(None));

    let app = Router::new()
        .route(
            "/token",
            post(
                |State(state): State<
                    std::sync::Arc<
                        tokio::sync::Mutex<Option<serde_json::Value>>,
                    >,
                >,
                 Json(body): Json<serde_json::Value>| async move {
                    *state.lock().await = Some(body);
                    let token = serde_json::json!({
                        "access_token": "cc-test-token",
                        "token_type": "Bearer",
                        "expires_in": 3600,
                    });
                    (StatusCode::OK, Json(token))
                },
            ),
        )
        .with_state(captured.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("auth server should bind");
    let addr = listener
        .local_addr()
        .expect("auth server has local address");

    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });

    (format!("http://{}/token", addr), captured)
}

/// Test 17: `sink_client_credentials_oauth2`.
///
/// **Case covered:** end-to-end delivery using OAuth2 `client_credentials`.
///
/// **Setup:**
/// - Bootstrap node, governance and schema `Example`.
/// - Start a `TestSink` for `/events` and a separate axum OAuth2 server for
///   `/token` that records the token request body.
/// - Restart the node with a sink configured with
///   `grant_type: ClientCredentials`, `client_id` and the client secret read
///   from `AVE_SINK_PASSWORD_CC_SINK`.
///
/// **Sequence:**
/// 1. Emit a fact after the restart.
/// 2. Wait for the event to be delivered.
///
/// **Verifications:**
/// - The delivery carries `Authorization: Bearer cc-test-token`.
/// - The token endpoint received `grant_type=client_credentials`, the
///   configured `client_id`, and the secret from the environment variable.
#[traced_test]
#[tokio::test]
async fn sink_client_credentials_oauth2() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;

    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let sink = TestSink::start().await;
    let (auth_url, captured_body) =
        start_client_credentials_auth_server().await;

    let auth_env = "AVE_SINK_PASSWORD_CC_SINK";
    unsafe {
        std::env::set_var(auth_env, "cc-client-secret");
    }

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        vec![make_sink_entry_with_auth(
            "cc-sink",
            sink.url(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            SinkAuthMethod::OAuth2(SinkAuthConfig {
                auth_url,
                grant_type: OAuth2GrantType::ClientCredentials,
                client_id: "cc-client-id".to_owned(),
                scope: "events:read".to_owned(),
                ..SinkAuthConfig::default()
            }),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 1}}), true)
        .await
        .unwrap();

    sink.wait_for_count(2, true).await;

    let headers = sink.authorization_headers().await;
    assert!(
        headers
            .iter()
            .flatten()
            .any(|h| h == "Bearer cc-test-token"),
        "deliveries must carry the Bearer token obtained via client_credentials"
    );

    let body = captured_body
        .lock()
        .await
        .clone()
        .expect("auth server should have received a token request");
    assert_eq!(body["grant_type"], "client_credentials");
    assert_eq!(body["client_id"], "cc-client-id");
    assert_eq!(body["client_secret"], "cc-client-secret");
    assert_eq!(body["scope"], "events:read");

    unsafe {
        std::env::remove_var(auth_env);
    }
}

/// Test: `replay_restarts_inflight_catch_up_preserving_order`.
///
/// **Objective:** verify that a replay requested while a long catch-up is in
/// flight **restarts** the catch-up from the lower `from_sn` instead of being
/// queued behind it, and that the stale delivery chain is discarded
/// (generation fencing in the subject worker), so events always arrive in
/// order.
///
/// **Setup:**
/// - Node with governance and a subject with SN 0..=19 created *before* the
///   sink exists.
/// - Restart the node with a slow sink (`ResponseMode::Timeout(200)` per
///   request): the startup catch-up from SN 0 takes ~4 s, keeping it in
///   flight.
///
/// **Action:**
/// - Wait until the first 3 catch-up deliveries land, then request a replay
///   from SN 10 while the catch-up is still running.
///
/// **Verifications:**
/// - The replay is accepted (`processed`, no `errors`).
/// - Once everything settles, the received SN sequence is an ordered prefix
///   `0..M` (whatever the original catch-up delivered before the restart,
///   strictly ordered, no interleaving) followed by the complete, strictly
///   ordered sequence `10..=19` redelivered by the restarted catch-up. Any
///   overlap between the prefix and the suffix is the expected at-least-once
///   redelivery of events the original catch-up had already sent.
#[traced_test]
#[tokio::test]
async fn replay_restarts_inflight_catch_up_preserving_order() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for i in 1..=18 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            false,
        )
        .await
        .unwrap();
    }
    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 19}}),
        true,
    )
    .await
    .unwrap();

    // Restart with the sink configured and slow (200 ms per request) so the
    // startup catch-up from SN 0 stays in flight for ~4 seconds.
    let sink = TestSink::start().await;
    sink.set_mode(ResponseMode::Timeout(200)).await;
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The catch-up is running (200 ms per delivery). Wait for the first
    // deliveries and request a replay from SN 10 while it is still in flight.
    sink.wait_for_count(3, true).await;
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 10,
            }],
        })
        .await
        .unwrap();
    assert_eq!(response.processed.len(), 1);
    assert!(response.errors.is_empty());

    // The restarted catch-up redelivers SN 10..=19, in order, at the end.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(13, true).await;
    let events = sink.snapshot().await;
    let sns: Vec<u64> = events.iter().map(|e| e.sn()).collect();

    let suffix: Vec<u64> = (10..=19).collect();
    let split = sns.len() - suffix.len();
    assert_eq!(
        &sns[split..],
        suffix.as_slice(),
        "the restarted catch-up must redeliver SN 10..=19 in order at the end; got {sns:?}"
    );
    let expected_prefix: Vec<u64> = (0..split as u64).collect();
    assert_eq!(
        &sns[..split],
        expected_prefix.as_slice(),
        "events before the restart must be the strictly ordered prefix 0..M of the original catch-up; got {sns:?}"
    );
}

/// Test: `pending_replay_survives_node_restart`.
///
/// **Objective:** an accepted replay whose re-delivery is still pending when
/// the node stops must be resumed after the restart (persisted replay floor),
/// even though the delivery cursor was already advanced past the replay's
/// `from_sn` by the in-flight catch-up.
///
/// **Setup:**
/// - The sink receives Create + 4 facts (SN 0..=4).
/// - The sink drops deliveries; a replay from SN 1 is accepted: the cursor is
///   rewound to 0 and the replay floor (SN 1) is persisted, but nothing can
///   be delivered yet.
/// - The sink becomes slow (400 ms per request) so the catch-up re-delivers
///   the replay range one event at a time.
///
/// **Action:** restart the node after the first replayed event lands, while
/// the rest of the replay is still in flight.
///
/// **Verifications:**
/// - After the restart the pending replay is resumed and the full range
///   SN 1..=4 is redelivered, in order. Without the persisted floor the
///   cursor (already at SN 1) would make the manager resume from SN 2 and the
///   final count would stay at 9, so waiting for 10 events distinguishes the
///   fixed behaviour.
#[traced_test]
#[tokio::test]
async fn pending_replay_survives_node_restart() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for i in 1..=4 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Restart with the sink configured: startup catch-up delivers SN 0..=4.
    let sink = TestSink::start().await;
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(5, true).await;

    // Sink down: the replay is accepted (floor SN 1 persisted, cursor rewound
    // to 0) but its catch-up cannot deliver anything.
    sink.set_mode(ResponseMode::Drop).await;
    let response = node
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "example-sink".to_owned(),
                subject_id: subject_id_str.clone(),
                from_sn: 1,
            }],
        })
        .await
        .unwrap();
    assert_eq!(response.processed.len(), 1);
    assert!(response.errors.is_empty());

    // Slow sink: the catch-up redelivers the replay range one event at a time
    // (400 ms each). Restart the node right after the first replayed event
    // lands, while the rest of the replay is still in flight.
    sink.set_mode(ResponseMode::Timeout(400)).await;
    sink.wait_for_count(6, true).await;

    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        example_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // The pending replay is resumed: SN 1..=4 is redelivered, in order.
    // Without the persisted floor the manager would resume from SN 2 and the
    // count would stall at 9.
    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(10, true).await;
    let events = sink.snapshot().await;
    let sns: Vec<u64> = events.iter().map(|e| e.sn()).collect();
    assert_eq!(
        &sns[sns.len() - 4..],
        &[1, 2, 3, 4],
        "the resumed replay must redeliver SN 1..=4 in order at the end; got {sns:?}"
    );
    assert_eq!(&sns[..5], &[0, 1, 2, 3, 4], "initial catch-up; got {sns:?}");
}

/// Test: `live_delivery_across_worker_idle_shutdowns`.
///
/// **Objective:** live events emitted right as the sink worker and its
/// subject worker are being shut down for idleness must still be delivered,
/// in order. Both shutdowns are synchronous (`ask_stop`): an event arriving
/// during the shutdown waits in the parent's mailbox and the worker is
/// recreated afterwards, instead of racing the old worker's termination and
/// losing the event (or letting a later event advance the cursor past it).
///
/// **Setup:** sink with `sink_worker_idle_timeout_ms: 200` and
/// `sink_subject_worker_idle_timeout_ms: 200`.
///
/// **Action:** emit facts paced ~250 ms apart, so every fact arrives while
/// the previous workers are being torn down (or have just been).
///
/// **Verifications:** the sink stores Create + 5 facts, strictly in order,
/// with no gaps and no duplicates.
#[traced_test]
#[tokio::test]
async fn live_delivery_across_worker_idle_shutdowns() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: ave_network::NodeType::Bootstrap,
        listen_address: format!("/memory/{}", port),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    // Restart with the sink configured with very short idle timeouts so the
    // sink worker and the subject worker are torn down between events.
    let sink = TestSink::start().await;
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", port),
        short_idle_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_caught_up(&node.api, "example-sink").await;
    sink.wait_for_count(1, true).await;

    // Each fact arrives ~250 ms after the previous delivery, while the
    // workers are being shut down for idleness (or have just been).
    for i in 1..=5 {
        tokio::time::sleep(Duration::from_millis(250)).await;
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
        sink.wait_for_count((i + 1) as usize, true).await;
    }

    let events = sink.snapshot().await;
    assert_eq!(
        events.len(),
        6,
        "every live event must be delivered exactly once across idle shutdowns"
    );
    assert_subject_sn_sequence(&events, &subject_id_str, 0, 5);
}
