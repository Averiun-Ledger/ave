//! Toolchain pin acceptance (TEST-PIN): only the rejection paths are
//! executable with the single-entry provisional registry — every pin
//! switch test needs a second known pin first (see TASK.md).
mod common;

use ave_common::response::RequestState;
use ave_core::governance::data::GovernanceData;
use common::{
    CreateNodesAndConnectionsConfig, create_and_authorize_governance,
    create_nodes_and_connections, emit_fact, get_events, get_subject,
};
use test_log::test;

use crate::common::wait_request_state;

#[test(tokio::test)]
// TEST-PIN-07: unknown pin string votes a deterministic error. The
// error commits to the ledger as the event outcome (it never builds
// nor rejects unilaterally) and the committed pin does not move.
async fn test_pin_unknown_votes_error() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&nodes[1].api]).await;

    let request_id = emit_fact(
        &node1,
        governance_id.clone(),
        serde_json::json!({ "toolchain": "rust-9.99-ficticio" }),
        false,
    )
    .await
    .unwrap();

    wait_request_state(
        &node1,
        request_id,
        Some(RequestState::Finish),
    )
    .await
    .unwrap();

    // The committed pin did not move.
    let state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let properties: GovernanceData =
        serde_json::from_value(state.properties).unwrap();
    assert_eq!(properties.toolchain, GovernanceData::default().toolchain);

    // The ledger records the deterministic error as the outcome.
    let events = get_events(&node1, governance_id, 2, true).await.unwrap();
    let event = serde_json::to_string(events.last().unwrap()).unwrap();
    assert!(
        event.contains("unknown toolchain pin"),
        "unexpected event outcome: {event}"
    );
}

#[test(tokio::test)]
// TEST-PIN-09: switching to the current pin is a no-op switch and
// votes a deterministic error, even with no other change in the event.
async fn test_pin_same_pin_votes_error() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
    let node1 = nodes[0].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&nodes[1].api]).await;

    let current = GovernanceData::default().toolchain;
    let request_id = emit_fact(
        &node1,
        governance_id.clone(),
        serde_json::json!({ "toolchain": current }),
        false,
    )
    .await
    .unwrap();

    wait_request_state(&node1, request_id, Some(RequestState::Finish))
        .await
        .unwrap();

    let state = get_subject(&node1, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let properties: GovernanceData =
        serde_json::from_value(state.properties).unwrap();
    assert_eq!(properties.toolchain, current);

    let events = get_events(&node1, governance_id, 2, true).await.unwrap();
    let event = serde_json::to_string(events.last().unwrap()).unwrap();
    assert!(
        event.contains("toolchain pin switch to the current pin"),
        "unexpected event outcome: {event}"
    );
}
