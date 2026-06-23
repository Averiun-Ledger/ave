mod common;

use std::{
    collections::BTreeSet,
    sync::atomic::Ordering,
    time::Duration,
};

use ave_common::{
    bridge::request::{SinkReplayItem, SinkReplayRequest, SinksQuery},
    identity::{DigestIdentifier, HashAlgorithm, PublicKey},
    sink::{DataToSinkEvent, IncomingSinkEvent},
    SinkTypes,
};
use ave_core::{config::SinkConfigEntry, error::Error};
use ave_network::NodeType;
use std::str::FromStr;
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    create_subject, emit_confirm, emit_eol, emit_fact, emit_fact_viewpoints,
    emit_reject, emit_transfer, get_subject, node_running, sink_setup::{
        assert_event_is_confirm, assert_event_is_create, assert_event_is_eol,
        assert_event_is_fact_full, assert_event_is_reject,
        assert_event_is_transfer, assert_sink_contains_confirm,
        assert_sink_contains_create, assert_sink_contains_eol,
        assert_sink_contains_fact_full, assert_sink_contains_fact_opaque,
        assert_sink_contains_reject, assert_sink_contains_transfer,
        count_events_for_subject, example_schema_governance_fact,
        example_sink_config, governance_sink_config,
        governance_with_transfer_roles_fact, governance_with_viewpoints_fact,
        make_sink_entry, restart_config, restart_config_with_peers, sample_sinks,
    },
    test_sink::{ResponseMode, TestSink},
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
};
use ave_network::RoutingNode;

#[test(tokio::test)]
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

#[test(tokio::test)]
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

#[test(tokio::test)]
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

#[test(tokio::test)]
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
#[test(tokio::test)]
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

    let governance_id = create_and_authorize_governance(&node.api, vec![]).await;

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

    // Give the sink worker time to hit the request timeout and mark the sink
    // as lagging for this subject.
    tokio::time::sleep(Duration::from_millis(800)).await;

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
}

/// Replay events for multiple subjects and sinks in a single request.
///
/// Covers Test 2 of `temporal/sink/plan_integration_tests.md`:
/// - one sink receives all event types (`All`);
/// - a second sink receives only facts (`Fact`);
/// - replay targets specific (sink, subject) pairs, respecting filters.
#[test(tokio::test)]
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

    let governance_id = create_and_authorize_governance(&node.api, vec![]).await;

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
        emit_fact(
            &node.api,
            s1.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
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

    sink_fact.wait_for_count(4, true).await;
    let fact_events = sink_fact.snapshot().await;
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

    sink_all
        .remove_events_for_subject_from_sn(&s1_str, 1)
        .await;
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
        all_after.iter().filter(|e| e.event_type() == SinkTypes::Create).count(),
        2
    );

    sink_fact.wait_for_count(4, true).await;
    let fact_after = sink_fact.snapshot().await;
    assert_eq!(fact_after.len(), 4);
    assert!(
        !fact_after.iter().any(|e| e.event_type() == SinkTypes::Create),
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
#[test(tokio::test)]
async fn replay_filters_and_combinations() {
    let (mut nodes, mut dirs) = create_nodes_and_connections(
        CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        },
    )
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

    let (subject_id, _) = create_subject(
        &owner.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
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

    let sinks: Vec<TestSink> =
        futures::future::join_all((0..sink_specs.len()).map(|_| TestSink::start()))
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
    let (new_owner, mut new_owner_dirs2) = create_node(restart_config_with_peers(
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

    emit_reject(&owner.api, subject_id.clone(), true).await.unwrap();

    emit_eol(&new_owner.api, subject_id.clone(), true)
        .await
        .unwrap();

    let subject_id_str = subject_id.to_string();

    sinks[0].wait_for_count(1, true).await;
    let create_events = sinks[0].snapshot().await;
    assert_eq!(create_events.len(), 1);
    assert_event_is_create(&create_events[0], &subject_id_str, 0);

    sinks[1].wait_for_count(2, true).await;
    let fact_events = sinks[1].snapshot().await;
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

    sinks[2].wait_for_count(2, true).await;
    let transfer_events = sinks[2].snapshot().await;
    assert_eq!(transfer_events.len(), 2);
    assert_sink_contains_transfer(&transfer_events, &subject_id_str, 3);
    assert_sink_contains_transfer(&transfer_events, &subject_id_str, 5);

    sinks[3].wait_for_count(1, true).await;
    let confirm_events = sinks[3].snapshot().await;
    assert_eq!(confirm_events.len(), 1);
    assert_sink_contains_confirm(&confirm_events, &subject_id_str, 4);

    sinks[4].wait_for_count(1, true).await;
    let reject_events = sinks[4].snapshot().await;
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

    sinks[0].wait_for_count(1, true).await;
    let create_after = sinks[0].snapshot().await;
    assert_eq!(create_after.len(), 1);
    assert_event_is_create(&create_after[0], &subject_id_str, 0);

    sinks[1].wait_for_count(2, true).await;
    let fact_after = sinks[1].snapshot().await;
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

    sinks[2].wait_for_count(2, true).await;
    let transfer_after = sinks[2].snapshot().await;
    assert_eq!(transfer_after.len(), 2);
    assert_event_is_transfer(&transfer_after[0], &subject_id_str, 3);
    assert_event_is_transfer(&transfer_after[1], &subject_id_str, 5);

    sinks[3].wait_for_count(1, true).await;
    let confirm_after = sinks[3].snapshot().await;
    assert_eq!(confirm_after.len(), 1);
    assert_event_is_confirm(&confirm_after[0], &subject_id_str, 4);

    sinks[4].wait_for_count(1, true).await;
    let reject_after = sinks[4].snapshot().await;
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
#[test(tokio::test)]
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

    let governance_id = create_and_authorize_governance(&node.api, vec![]).await;
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

    // The cursor may already be at the end from previous replays; just give the
    // worker time to start before forcing a delivery failure.
    tokio::time::sleep(Duration::from_millis(500)).await;

    sink.set_mode(ResponseMode::ClientError).await;
    emit_fact(
        &node.api,
        subject_id,
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    // Give the worker time to attempt delivery, retry and mark the sink blocked.
    tokio::time::sleep(Duration::from_millis(1500)).await;

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
#[test(tokio::test)]
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

    let governance_id = create_and_authorize_governance(&node.api, vec![]).await;
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

    // Give the worker time to attempt delivery and mark the sink blocked.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let events = sink.snapshot().await;
    assert_eq!(events.len(), 0, "sink should not have stored any events");

    let statuses = node.api.get_sinks_status().await.unwrap();
    let example_status = statuses
        .iter()
        .find(|s| s.name == "example-sink")
        .expect("example-sink status");
    assert!(
        example_status.blocked.is_some(),
        "sink should be reported as blocked"
    );

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

    let statuses = node.api.get_sinks_status().await.unwrap();
    let example_status = statuses
        .iter()
        .find(|s| s.name == "example-sink")
        .expect("example-sink status");
    assert!(
        example_status.blocked.is_none(),
        "sink should be unblocked after unblock_sink"
    );

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

/// Replay governance events through a governance sink.
///
/// Covers Test 3 of `temporal/sink/plan_integration_tests.md`:
/// - normal delivery of Governance Create + FactFull;
/// - manual replay from SN 0 after wiping the sink.
#[test(tokio::test)]
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

    let governance_id = create_and_authorize_governance(&node.api, vec![]).await;

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
#[test(tokio::test)]
async fn sink_fact_viewpoints_full_and_opaque() {
    let (mut nodes, mut dirs) = create_nodes_and_connections(
        CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        },
    )
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

    let (subject_id, _) = create_subject(
        &owner.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
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
                assert!(patch.is_some(), "successful fact must contain a patch");
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
                let err = error.as_ref().expect("failed fact must have an error");
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
#[test(tokio::test)]
async fn sink_non_fact_event_types_and_fields() {
    let (mut nodes, mut dirs) = create_nodes_and_connections(
        CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        },
    )
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

    let (subject_id, _) = create_subject(
        &owner.api,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
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
    let (new_owner, mut new_owner_dirs2) = create_node(restart_config_with_peers(
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
    let sns_new_owner: Vec<_> = new_owner_events.iter().map(|e| e.sn()).collect();
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
