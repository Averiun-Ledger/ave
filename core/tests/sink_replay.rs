mod common;

use std::{
    collections::BTreeSet,
    sync::atomic::Ordering,
    time::Duration,
};

use ave_common::{
    bridge::request::{SinkReplayItem, SinkReplayRequest},
    identity::PublicKey,
    SinkTypes,
};
use ave_core::config::SinkConfigEntry;
use std::str::FromStr;
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    create_subject, emit_confirm, emit_eol, emit_fact, emit_reject, emit_transfer,
    get_subject, node_running, sink_setup::{
        assert_event_is_confirm, assert_event_is_create, assert_event_is_eol,
        assert_event_is_fact_full, assert_event_is_reject,
        assert_event_is_transfer, assert_sink_contains_confirm,
        assert_sink_contains_create, assert_sink_contains_eol,
        assert_sink_contains_fact_full, assert_sink_contains_reject,
        assert_sink_contains_transfer, count_events_for_subject,
        example_schema_governance_fact, example_sink_config,
        governance_sink_config, governance_with_transfer_roles_fact,
        make_sink_entry, restart_config, restart_config_with_peers,
    },
    test_sink::{ResponseMode, TestSink},
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
};
use ave_network::RoutingNode;

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
