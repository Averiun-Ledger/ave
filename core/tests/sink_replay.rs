mod common;

use std::{
    collections::BTreeSet,
    sync::atomic::Ordering,
    time::Duration,
};

use ave_common::{
    bridge::request::{SinkReplayItem, SinkReplayRequest},
    SinkTypes,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    create_and_authorize_governance, create_node, create_subject, emit_fact,
    node_running, sink_setup::{
        assert_event_is_create, assert_event_is_fact_full,
        assert_sink_contains_create, assert_sink_contains_fact_full,
        count_events_for_subject, example_schema_governance_fact,
        example_sink_config, make_sink_entry, restart_config,
    },
    test_sink::{ResponseMode, TestSink},
    CreateNodeConfig, PORT_COUNTER,
};

/// Replay a single subject after the sink loses events.
///
/// Covers Test 1 of `temporal/sink/plan_integration_tests.md`:
/// - normal delivery of Create + facts;
/// - sink failure (simulated by slow/timeout mode);
/// - automatic catch-up after recovery;
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

    sink.set_mode(ResponseMode::Timeout(3000)).await;

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

    tokio::time::sleep(Duration::from_millis(800)).await;

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

    sink.remove_last(2).await;

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

    sink.wait_for_count(9, true).await;
    let replayed = sink.snapshot().await;
    assert_eq!(replayed.len(), 9);
    assert_event_is_fact_full(
        &replayed[6],
        &subject_id.to_string(),
        5,
        true,
        Some(json!({"ModOne": {"data": 5}})),
    );
    assert_event_is_fact_full(
        &replayed[7],
        &subject_id.to_string(),
        6,
        true,
        Some(json!({"ModOne": {"data": 6}})),
    );
    assert_event_is_fact_full(
        &replayed[8],
        &subject_id.to_string(),
        7,
        true,
        Some(json!({"ModOne": {"data": 7}})),
    );
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
}
