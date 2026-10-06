//! Toolchain pin acceptance (TEST-PIN).
mod common;

use ave_common::SchemaType;
use ave_common::response::RequestState;
use ave_core::governance::data::GovernanceData;
use common::{
    CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT, NodeData,
    create_and_authorize_governance, create_nodes_and_connections, emit_fact,
    get_events, get_subject,
};
use test_log::test;

use crate::common::wait_request_state;

async fn three_nodes() -> (Vec<NodeData>, Vec<tempfile::TempDir>) {
    create_nodes_and_connections(CreateNodesAndConnectionsConfig {
        bootstrap: vec![vec![]],
        addressable: vec![vec![0], vec![0]],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await
}

#[test(tokio::test)]
// TEST-PIN-07: unknown pin string votes a deterministic error. The
// error commits to the ledger as the event outcome (it never builds
// nor rejects unilaterally) and the committed pin does not move.
async fn test_pin_unknown_votes_error() {
    let (nodes, _dirs) = three_nodes().await;
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

    wait_request_state(&node1, request_id, Some(RequestState::Finish))
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
// Compilers YES + evaluation NO: same pin WITH committed schemas.
// The compilers build successfully (real votes), yet evaluation
// votes the no-op `Error` and nothing is applied. Each layer decides
// its own concern: builders build, evaluators judge validity.
async fn test_pin_same_pin_with_schemas_votes_error() {
    let (nodes, _dirs) = three_nodes().await;
    let node1 = nodes[0].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&nodes[1].api]).await;
    emit_fact(
        &node1,
        governance_id.clone(),
        example_schema_fact(serde_json::json!({})),
        true,
    )
    .await
    .unwrap();

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

    // Committed pin and schemas untouched despite successful builds.
    let state = get_subject(&node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let properties: GovernanceData =
        serde_json::from_value(state.properties).unwrap();
    assert_eq!(properties.toolchain, current);
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned())),
        "schemas must survive the rejected no-op"
    );

    let events = get_events(&node1, governance_id, 3, true).await.unwrap();
    let event = serde_json::to_string(events.last().unwrap()).unwrap();
    assert!(
        event.contains("toolchain pin switch to the current pin"),
        "unexpected event outcome: {event}"
    );
}

#[test(tokio::test)]
// TEST-PIN-09: switching to the current pin is a no-op switch and
// votes a deterministic error, even with no other change in the event.
async fn test_pin_same_pin_votes_error() {
    let (nodes, _dirs) = three_nodes().await;
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

fn example_schema_fact(extra: serde_json::Value) -> serde_json::Value {
    let mut fact = serde_json::json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": { "one": 0, "two": 0, "three": 0 }
                }
            ]
        }
    });
    for (key, value) in extra.as_object().unwrap() {
        fact[key] = value.clone();
    }
    fact
}

#[test(tokio::test)]
// TEST-PIN-17: same pin plus real changes commits normally — the gate
// must not over-block. Catches a no-op check written too broadly.
async fn test_pin_same_pin_with_changes_commits() {
    let (nodes, _dirs) = three_nodes().await;
    let node1 = nodes[0].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&nodes[1].api]).await;

    let current = GovernanceData::default().toolchain;
    let request_id = emit_fact(
        &node1,
        governance_id.clone(),
        example_schema_fact(serde_json::json!({ "toolchain": current })),
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
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned())),
        "schema change must be applied"
    );

    let events = get_events(&node1, governance_id, 2, true).await.unwrap();
    let event = serde_json::to_string(events.last().unwrap()).unwrap();
    assert!(
        !event.contains("toolchain pin"),
        "no pin error expected, got: {event}"
    );
}

#[test(tokio::test)]
// TEST-PIN-18: unknown pin plus real changes still votes a
// deterministic error — nothing is applied half-way.
async fn test_pin_unknown_with_changes_votes_error() {
    let (nodes, _dirs) = three_nodes().await;
    let node1 = nodes[0].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&nodes[1].api]).await;

    let request_id = emit_fact(
        &node1,
        governance_id.clone(),
        example_schema_fact(
            serde_json::json!({ "toolchain": "rust-9.99-ficticio" }),
        ),
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
    assert_eq!(properties.toolchain, GovernanceData::default().toolchain);
    assert!(
        properties.schemas.is_empty(),
        "no change may be applied on pin error"
    );

    let events = get_events(&node1, governance_id, 2, true).await.unwrap();
    let event = serde_json::to_string(events.last().unwrap()).unwrap();
    assert!(
        event.contains("unknown toolchain pin"),
        "unexpected event outcome: {event}"
    );
}

#[test(tokio::test)]
// TEST-PIN-19: legacy event without the toolchain field commits
// normally and keeps the pin — rolling upgrade safety.
async fn test_pin_absent_field_commits() {
    let (nodes, _dirs) = three_nodes().await;
    let node1 = nodes[0].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&nodes[1].api]).await;

    let request_id = emit_fact(
        &node1,
        governance_id.clone(),
        example_schema_fact(serde_json::json!({})),
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
    assert_eq!(properties.toolchain, GovernanceData::default().toolchain);
    assert!(
        properties
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned())),
        "schema change must be applied"
    );
}

#[test(tokio::test)]
// TEST-PIN-15: an evaluator-only node (no compiler role, no local
// toolchains) votes on pin events like everyone else — the pin never
// demands builds from non-compilers.
async fn test_pin_evaluator_only_ignores_builds() {
    let (nodes, _dirs) = three_nodes().await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&node1, vec![&node2]).await;

    // AveNode2 becomes member, witness and evaluator — but never a
    // compiler and holds no toolchains.
    emit_fact(
        &node1,
        governance_id.clone(),
        serde_json::json!({
            "members": {
                "add": [
                    { "name": "AveNode2", "key": node2.public_key() }
                ]
            },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode2"],
                        "evaluator": ["AveNode2"]
                    }
                }
            }
        }),
        true,
    )
    .await
    .unwrap();
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Unknown pin: both evaluators vote the deterministic error with
    // no build attempt anywhere, and node2 tracks the outcome.
    let request_id = emit_fact(
        &node1,
        governance_id.clone(),
        serde_json::json!({ "toolchain": "rust-9.99-ficticio" }),
        false,
    )
    .await
    .unwrap();

    wait_request_state(&node1, request_id, Some(RequestState::Finish))
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();
    let state = get_subject(&node2, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    let properties: GovernanceData =
        serde_json::from_value(state.properties).unwrap();
    assert_eq!(properties.toolchain, GovernanceData::default().toolchain);
}
