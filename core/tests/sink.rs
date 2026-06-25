mod common;

use std::{collections::BTreeSet, sync::atomic::Ordering};

use ave_common::{
    SinkTarget, SinkTypes,
    bridge::request::{SinkReplayItem, SinkReplayRequest, SinksQuery},
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    sink::{DataToSinkEvent, IncomingSinkEvent, SinkAuthConfig},
};
use ave_core::{Api, config::SinkConfigEntry, error::Error};
use ave_network::NodeType;
use futures::future::join_all;
use serde_json::json;
use std::str::FromStr;
use std::time::Duration;
use tracing_test::traced_test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    create_subject, emit_confirm, emit_eol, emit_fact, emit_fact_viewpoints,
    emit_reject, emit_transfer, get_subject, node_running,
    sink_setup::{
        assert_event_is_confirm, assert_event_is_create, assert_event_is_eol,
        assert_event_is_fact_full, assert_event_is_reject,
        assert_event_is_transfer, assert_no_duplicate_events,
        assert_no_fact_full_events, assert_sink_blocked,
        assert_sink_contains_confirm, assert_sink_contains_create,
        assert_sink_contains_eol, assert_sink_contains_fact_full,
        assert_sink_contains_fact_opaque, assert_sink_contains_light_fact,
        assert_sink_contains_reject, assert_sink_contains_transfer,
        assert_sink_lagging, assert_sink_not_lagging, assert_sink_running,
        assert_sink_unblocked, assert_subject_sn_sequence,
        count_events_for_subject, example_schema_governance_fact,
        example_sink_config, flapping_sink_config, governance_sink_config,
        governance_with_transfer_roles_fact, governance_with_viewpoints_fact,
        make_sink_entry, make_sink_entry_with_auth,
        make_sink_entry_with_concurrency, restart_config,
        restart_config_safe_mode, restart_config_with_peers, sample_sinks,
        short_idle_sink_config, transient_error_sink_config,
        wait_for_sink_blocked, wait_for_sink_lagging_subjects,
        wait_for_sink_unblocked,
    },
    test_sink::{AuthResponseMode, ResponseMode, TestSink},
};
use ave_network::RoutingNode;

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

/// Replay a single subject after the sink loses events.
///
/// Covers Test 1 of `temporal/sink/plan_integration_tests.md`:
/// - normal delivery of Create + facts;
/// - sink failure (simulated by dropping every connection);
/// - automatic catch-up after the sink comes back;
/// - manual replay from the first lost SN.
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

/// Replay events for multiple subjects and sinks in a single request.
///
/// Covers Test 2 of `temporal/sink/plan_integration_tests.md`:
/// - one sink receives all event types (`All`);
/// - a second sink receives only facts (`Fact`);
/// - replay targets specific (sink, subject) pairs, respecting filters.
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

/// Replay respects per-sink event filters.
///
/// Covers Test 4 of `temporal/sink/plan_integration_tests.md`:
/// - sinks for Create, Fact, Transfer, Confirm, Reject and All;
/// - each sink receives only the event types it subscribed to;
/// - replay re-delivers only the matching events.
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
        governance_with_transfer_roles_fact(&new_owner.api.public_key()),
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
        PublicKey::from_str(&new_owner.api.public_key()).unwrap();
    emit_transfer(&owner.api, subject_id.clone(), new_owner_pk, true)
        .await
        .unwrap();

    get_subject(&new_owner.api, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_confirm(&new_owner.api, subject_id.clone(), None, true)
        .await
        .unwrap();

    let owner_pk = PublicKey::from_str(&owner.api.public_key()).unwrap();
    emit_transfer(&new_owner.api, subject_id.clone(), owner_pk, true)
        .await
        .unwrap();

    get_subject(&owner.api, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    emit_reject(&owner.api, subject_id.clone(), true)
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

/// Replay endpoint validations and error cases.
///
/// Covers Test 5 of `temporal/sink/plan_integration_tests.md`:
/// - safe mode rejection;
/// - blocked sink;
/// - missing sink (`SinkNotFound`);
/// - sink registered but not configured in the manager (residual);
/// - unknown subject (`subject has no known events`);
/// - `from_sn` beyond the last seen event;
/// - duplicate items deduplicated to the smallest `from_sn`.
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

/// Sink starts late and unblock edge cases.
///
/// Covers Test 6 of `temporal/sink/plan_integration_tests.md`:
/// - sink configured after events have been emitted;
/// - `unblock_sink` is a no-op on a healthy sink;
/// - blocked sink is unblocked and catches up automatically;
/// - manual replay re-sends lost events;
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

/// Replay after the sink returns bad data (422) and gets blocked.
///
/// Covers Test 7 of `temporal/sink/plan_integration_tests.md`:
/// - normal delivery of Create + 2 facts;
/// - 422 response blocks the sink and the failed event is not stored;
/// - unblock_sink recovers the sink and catch-up delivers the pending fact;
/// - manual replay re-sends events from an intermediate SN.
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

/// Replay endpoint response shape and deduplication.
///
/// Covers Test 8 of `temporal/sink/plan_integration_tests.md`:
/// - response contains exactly one processed item and three errors;
/// - duplicate items are deduplicated to the smallest from_sn;
/// - the valid item really re-sends events to the sink.
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

/// Sink permanently dropped and manual recovery.
///
/// Covers Test 9 of `temporal/sink/plan_integration_tests.md`:
/// - sink in `Drop` mode causes events to become lagging but not blocked;
/// - replay while the sink is down is accepted but does not arrive;
/// - after recovery the sink catches up all pending events in order.
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

/// Flapping sink is blocked after one failed recovery.
///
/// Covers Test 10 of `temporal/sink/plan_integration_tests.md`:
/// - healthcheck passes but delivery fails;
/// - sink is blocked as flapping after max_recoveries_after_failure is exceeded;
/// - unblock_sink restores delivery once the sink is healthy again.
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

/// Recovery of sink state across node restarts.
///
/// Covers Test 11 of `temporal/sink/plan_integration_tests.md`:
/// - a blocked sink is auto-unblocked on restart and catches up;
/// - a subject left lagging before shutdown is caught up after restart.
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
    sink.wait_for_count(8, true).await;
    assert_sink_not_lagging(&node.api, "example-sink").await;

    // Wait longer than the worker idle timeout so the manager stops it.
    tokio::time::sleep(Duration::from_millis(500)).await;

    // Second event: a fresh worker must be created to deliver it.
    emit_fact(
        &node.api,
        subject_two.clone(),
        json!({"ModOne": {"data": 14}}),
        true,
    )
    .await
    .unwrap();
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

/// Lightweight events and concurrent catch-up with limited concurrency.
///
/// Covers Test 12 of `temporal/sink/plan_integration_tests.md`:
/// - sinks with partial filters receive `LightEvent` for non-matching event types;
/// - `max_catch_up_concurrency: 1` still catches up multiple lagging subjects;
/// - `max_catch_up_concurrency: 2` catches up multiple subjects without
///   duplicates or ordering violations;
/// - replay from SN 0 works with limited concurrency;
/// - sinks with different filters do not interfere with each other.
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
    create_only_conc2_sink.set_mode(ResponseMode::ServerError).await;
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

/// Replay governance events through a governance sink.
///
/// Covers Test 3 of `temporal/sink/plan_integration_tests.md`:
/// - normal delivery of Governance Create + FactFull;
/// - manual replay from SN 0 after wiping the sink.
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

/// Facts with viewpoints are delivered as FactFull or FactOpaque depending on
/// the witness grants.
///
/// Covers Test 19A of `temporal/sink/plan_integration_tests.md`:
/// - Create, FactFull and FactOpaque are delivered;
/// - successful and failed facts carry the correct `success`/`error` flags;
/// - opaque facts do not leak payload, patch, issuer or error;
/// - every field of every event is explicitly checked.
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
        governance_with_viewpoints_fact(&witness.api.public_key()),
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
    owner_sink.wait_for_count(4, true).await;
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

/// Non-fact sink event types and field checks.
///
/// Covers Test 19B of `temporal/sink/plan_integration_tests.md`:
/// - Create, Transfer, Confirm, Reject and EOL are delivered;
/// - every relevant field of each event type is checked;
/// - the tracker has no viewpoints, so ownership changes do not require a
///   ledger cleanup/resync.
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
        governance_with_transfer_roles_fact(&new_owner.api.public_key()),
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

    // SN 2: transfer Owner -> NewOwner.
    let new_owner_pk = PublicKey::from_str(&new_owner_pk_str).unwrap();
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

    // SN 4: transfer NewOwner -> Owner.
    let owner_pk = PublicKey::from_str(&owner_pk_str).unwrap();
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

    // SN 6: EOL by the current owner (NewOwner).
    emit_eol(&new_owner.api, subject_id.clone(), true)
        .await
        .unwrap();

    // Wait for all events on both sinks.
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

/// Deleting a subject removes it from sink tracking (cursors and lagging)
/// for all sinks.
///
/// Covers Test 13 of `temporal/sink/plan_integration_tests.md`:
/// - `delete_subject` requires safe mode;
/// - a deleted subject no longer triggers deliveries to any sink;
/// - the sink manager cleans up cursors and lagging state when the subject is
///   deleted (via `RemoveSubject`) and defensively via `SubjectNotFound`.
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
        emit_fact(
            &node.api,
            s1.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Both sinks must receive the initial Create + 2 facts.
    sink_a.wait_for_count(3, true).await;
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

    // Give the sink workers time to process any pending work.
    tokio::time::sleep(Duration::from_secs(2)).await;

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

/// Transient errors, retry backoff, and sequential gaps during fast events.
///
/// Covers Test 14 of `temporal/sink/plan_integration_tests.md`:
/// - HTTP 5xx errors are retried and eventually become `lagging` without
///   blocking the sink;
/// - events emitted while a slow delivery is in flight create a sequential gap
///   that is resolved by ordered catch-up.
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
        transient_error_sink_config(sink.url(), Some(governance_id.to_string())),
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    let (s1, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let s1_str = s1.to_string();

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
        emit_fact(
            &node.api,
            s1.clone(),
            json!({"ModOne": {"data": i}}),
            false,
        )
        .await
        .unwrap();
    }
    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 5}}), true)
        .await
        .unwrap();

    // Allow enough time for ordered delivery of the 4 new facts. The fast async
    // emissions produced a sequential gap (logged as SequentialGap) that must be
    // resolved by ordered catch-up.
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


/// Configuration changes, safe-mode cursor deletion, advanced `get_sinks` filters,
/// and blocked-sink visibility.
///
/// Covers Test 15 of `temporal/sink/plan_integration_tests.md`:
/// - adding a sink between restarts triggers automatic historical catch-up;
/// - removing a sink from config leaves a residual registry entry;
/// - `delete_sink_cursors` works only in safe mode and cleans cursors/lagging;
/// - `get_sinks` supports filters and ordering;
/// - `get_sinks` and `get_sinks_status` reflect blocked sinks.
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
        emit_fact(
            &node.api,
            s1.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
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
            governance_sink_config(gov_sink.url()).into_iter().next().unwrap(),
        ],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // new-sink must catch up Create + 3 facts automatically.
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
    let by_gov_names: Vec<_> =
        by_gov.iter().map(|s| s.name.as_str()).collect();
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

/// Authentication for sinks: API key header, OAuth2 token refresh on 401, and
/// persistent auth failures keeping the subject lagging without blocking the
/// sink.
///
/// Covers Test 16 of `temporal/sink/plan_integration_tests.md`.
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
        emit_fact(
            &node.api,
            s1.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    let s1_str = s1.to_string();

    // Part A — API key authentication.
    let api_key_sink = TestSink::start().await;
    let api_key = "secret-key".to_owned();
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
            SinkAuthConfig {
                auth_url: String::new(),
                username: String::new(),
                api_key: api_key.clone(),
            },
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    emit_fact(&node.api, s1.clone(), json!({"ModOne": {"data": 3}}), true)
        .await
        .unwrap();

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
        headers.len(),
        api_key_events.len(),
        "every delivered event should have a recorded Authorization header"
    );
    assert!(
        headers
            .iter()
            .all(|h| h.as_ref().map(|s| s.as_str()) == Some(expected_api_key.as_str())),
        "all events must carry the API key Authorization header"
    );

    // Part B — OAuth2 token refresh on 401.
    let oauth_sink = TestSink::start().await;
    let password = "oauth-password".to_owned();
    // Match the environment variable name built by sink_password_env_var.
    let password_env = "AVE_SINK_PASSWORD_AUTH_SINK".to_owned();
    unsafe {
        std::env::set_var(&password_env, &password);
    }
    assert_eq!(
        std::env::var(&password_env).unwrap(),
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
            SinkAuthConfig {
                auth_url: oauth_sink.auth_url(),
                username: "test-user".to_owned(),
                api_key: String::new(),
            },
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

    oauth_sink.set_mode(ResponseMode::UnauthorizedOnce).await;

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
    assert_eq!(
        auth_requests.len(),
        2,
        "expected eager token fetch + refresh after 401"
    );
    assert!(
        auth_requests.iter().any(|r| r.username == "test-user" && r.password == password),
        "Token endpoint should receive correct credentials"
    );

    let headers = oauth_sink.authorization_headers().await;
    assert_eq!(
        headers.len(),
        2,
        "expected failed 401 request + successful retry with refreshed token"
    );
    assert_eq!(
        headers.last().unwrap().as_deref(),
        Some("Bearer test-access-token"),
        "retried delivery must use the refreshed Bearer token"
    );

    // Part C — persistent auth failure keeps subject lagging, does not block sink.
    oauth_sink.set_auth_mode(AuthResponseMode::TokenFailure).await;
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

    unsafe {
        std::env::remove_var(&password_env);
    }
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

/// Covers Test 17 of `temporal/sink/plan_integration_tests.md`:
/// - a `SinkWorker` is shut down by the manager after the configured idle timeout;
/// - a new event forces the manager to create a fresh worker;
/// - delivery continues correctly after the recreation.
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
            panic!("timeout waiting for sink count to stabilize at {}", expected);
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
        if let Some(status) = statuses.iter().find(|s| s.name == sink_name) {
            if status.lagging_subjects == 0 {
                return;
            }
        }
        if attempts > 100 {
            panic!("timeout waiting for sink {} to have no lagging subjects", sink_name);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Test 18: EOL keeps cursor and stops delivery.
///
/// Covers Test 18 of `temporal/sink/plan_integration_tests.md`:
/// - EOL is delivered as a normal event.
/// - After EOL, no further deliveries are attempted for the subject.
/// - The subject does not remain in lagging state.
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
