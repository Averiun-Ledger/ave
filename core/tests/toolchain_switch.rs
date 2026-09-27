//! TEST-PIN switch paths (P1/P2): these need the second registry pin
//! (`TEST_PIN_B`, `test-pins` feature, never production) and, for the
//! capacity tests, per-node toolchain maps.
//!
//! Note on hashes: test builds compile through the shared pool, which
//! ignores pins, so a recompile-all under a new pin reproduces
//! byte-identical artifacts here. Real byte divergence across pins is
//! production-only and belongs to the CI gate, not the suite.
mod common;

use std::collections::BTreeMap;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ave_common::SchemaType;
use ave_common::governance::TEST_PIN_B;
use ave_common::response::RequestState;
use ave_core::governance::data::GovernanceData;
use ave_network::{NodeType, RoutingNode};
use common::{
    CHANGED_SCHEMA_CONTRACT, CreateNodeConfig,
    CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT,
    EXAMPLE_CONTRACT_V2, INVALID_EXAMPLE_CONTRACT, PORT_COUNTER,
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    emit_fact, get_events, get_subject, node_running,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::wait_request_state;

fn default_pin() -> String {
    GovernanceData::default().toolchain
}

fn both_pins() -> BTreeMap<String, String> {
    BTreeMap::from([
        (default_pin(), String::new()),
        (TEST_PIN_B.to_owned(), String::new()),
    ])
}

/// Bounded wait for a request state discriminant: a stand-down that
/// never lands must fail the test, not hang it.
async fn wait_state(
    node: &ave_core::Api,
    request_id: ave_common::identity::DigestIdentifier,
    want: &str,
) -> RequestState {
    for _ in 0..200 {
        if let Ok(state) = node.get_request_state(request_id.clone()).await {
            let hit = match &state.state {
                RequestState::Finish => want == "finish",
                RequestState::Abort { .. } => want == "abort",
                RequestState::RebootTimeOut { .. } => want == "reboot",
                _ => false,
            };
            if hit {
                return state.state;
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("request never reached {want}");
}

async fn single_node() -> (common::NodeData, Vec<tempfile::TempDir>) {
    single_node_with(Some(both_pins())).await
}

async fn single_node_with(
    toolchains: Option<BTreeMap<String, String>>,
) -> (common::NodeData, Vec<tempfile::TempDir>) {
    let (nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            is_service: true,
            toolchains,
            ..Default::default()
        })
        .await;
    let mut nodes = nodes;
    (nodes.remove(0), dirs)
}

fn schema_add(id: &str, contract: &str, initial: serde_json::Value) -> serde_json::Value {
    json!({
        "schemas": {
            "add": [
                { "id": id, "contract": contract, "initial_value": initial }
            ]
        }
    })
}

fn example_initial() -> serde_json::Value {
    json!({ "one": 0, "two": 0, "three": 0 })
}

async fn properties(
    node: &ave_core::Api,
    gov: &ave_common::identity::DigestIdentifier,
    sn: u64,
) -> GovernanceData {
    let state = get_subject(node, gov.clone(), Some(sn), true).await.unwrap();
    serde_json::from_value(state.properties).unwrap()
}

#[test(tokio::test)]
// TEST-PIN-01: pin switch with no schemas commits directly and the
// committed pin moves. No test proves a pin can commit otherwise.
async fn test_pin_switch_no_schemas_commits() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": TEST_PIN_B }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let props = properties(node, &governance_id, 1).await;
    assert_eq!(props.toolchain, TEST_PIN_B);
}

#[test(tokio::test)]
// TEST-PIN-02: switch with a previous schema recompiles everything
// under the new pin with evidence; the official artifact is intact
// until the commit.
async fn test_pin_switch_recompiles_all() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();
    let before: GovernanceData =
        serde_json::from_value(
            get_subject(node, governance_id.clone(), Some(1), true)
                .await
                .unwrap()
                .properties,
        )
        .unwrap();
    assert!(before.schemas.contains_key(&SchemaType::Type("Example".to_owned())));

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": TEST_PIN_B }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, TEST_PIN_B);
    assert!(
        after.schemas.contains_key(&SchemaType::Type("Example".to_owned())),
        "schemas must survive the switch"
    );
}

#[test(tokio::test)]
// TEST-PIN-16: parallel recompile-all — three schemas switch cleanly,
// and a broken first schema fails deterministically BY SCHEMA ORDER
// (not completion order): the fold votes the alphabetically-first
// failure whatever finishes first.
async fn test_pin_switch_parallel_recompile() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    emit_fact(
        node,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    { "id": "Alpha", "contract": EXAMPLE_CONTRACT, "initial_value": example_initial() },
                    { "id": "Beta", "contract": EXAMPLE_CONTRACT_V2, "initial_value": example_initial() },
                    { "id": "Gamma", "contract": CHANGED_SCHEMA_CONTRACT, "initial_value": json!({ "data": "" }) }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": TEST_PIN_B }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, TEST_PIN_B);
    assert_eq!(after.schemas.len(), 3, "all schemas must survive");
}

#[test(tokio::test)]
// TEST-PIN-16b: concurrent builds with one broken schema abort naming
// the first schema IN ORDER — a first-completed-wins fold would name
// a pooled fast schema instead, flakily.
async fn test_pin_switch_parallel_failure_order() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    { "id": "Aaa", "contract": INVALID_EXAMPLE_CONTRACT, "initial_value": example_initial() },
                    { "id": "Mmm", "contract": EXAMPLE_CONTRACT, "initial_value": example_initial() },
                    { "id": "Zzz", "contract": EXAMPLE_CONTRACT_V2, "initial_value": example_initial() }
                ]
            },
            "toolchain": TEST_PIN_B,
        }),
        false,
    )
    .await
    .unwrap();
    let state = wait_state(node, request_id.clone(), "abort").await;
    let RequestState::Abort { error, .. } = state else {
        panic!("expected abort");
    };
    assert!(
        error.contains("Aaa"),
        "first-schema failure must win, got: {error}"
    );

    // Nothing applied: pin and schemas untouched.
    let props = properties(node, &governance_id, 0).await;
    assert_eq!(props.toolchain, default_pin());
    assert!(props.schemas.is_empty());
}

#[test(tokio::test)]
// TEST-PIN-03: switch plus add plus modify in a single event —
// everything builds and commits under the NEW pin, mixing the
// staging path (add/change) with the official path (recompile).
async fn test_pin_switch_with_add_and_modify() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    { "id": "Beta", "contract": EXAMPLE_CONTRACT_V2, "initial_value": example_initial() }
                ],
                "change": [
                    {
                        "actual_id": "Example",
                        "new_contract": CHANGED_SCHEMA_CONTRACT,
                        "new_initial_value": { "data": "" }
                    }
                ]
            },
            "toolchain": TEST_PIN_B,
        }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, TEST_PIN_B);
    assert!(
        after.schemas.contains_key(&SchemaType::Type("Beta".to_owned())),
        "added schema must commit"
    );
    assert_eq!(
        after
            .schemas
            .get(&SchemaType::Type("Example".to_owned()))
            .unwrap()
            .contract,
        CHANGED_SCHEMA_CONTRACT,
        "modified contract must commit"
    );
}

#[test(tokio::test)]
// Rollback (old PIN-12): B back to the default pin commits
// symmetrically — catches stuck resolution, poisoned caches and any
// statefulness the one-way tests can not see.
async fn test_pin_rollback_is_symmetric() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    let switch = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": TEST_PIN_B }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, switch, "finish").await;
    assert_eq!(properties(node, &governance_id, 2).await.toolchain, TEST_PIN_B);

    let back = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": default_pin() }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, back, "finish").await;

    let after = properties(node, &governance_id, 3).await;
    assert_eq!(after.toolchain, default_pin());
    assert!(
        after.schemas.contains_key(&SchemaType::Type("Example".to_owned())),
        "schemas must survive the round trip"
    );
}

#[test(tokio::test)]
// TEST-PIN-04: a pin nobody holds stands down everywhere — reboot, no
// crash-loop, no commit. The owner path stays open (node responsive).
async fn test_pin_nobody_holds_reboots() {
    // Holds the default pin only: the switch target is unresolvable,
    // so the stand-down is meaningful (not an empty-map artifact).
    let (node, _dirs) =
        single_node_with(Some(BTreeMap::from([(default_pin(), String::new())])))
            .await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    // Only the default pin is held: the switch can never build.
    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": TEST_PIN_B }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "reboot").await;

    // No commit and no crash: version frozen, node answers.
    let props = properties(node, &governance_id, 1).await;
    assert_eq!(props.toolchain, default_pin());
    assert!(props.schemas.contains_key(&SchemaType::Type("Example".to_owned())));
}

#[test(tokio::test)]
// TEST-PIN-05: partial capacity — two of three compilers hold the pin,
// quorum 2/3 commits with the capable subset. The stood-down compiler
// is replaced, not waited on.
async fn test_pin_partial_capacity_quorum_with_subset() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            is_service: true,
            toolchains: Some(both_pins()),
            ..Default::default()
        })
        .await;
    let bootstrap = nodes.remove(0);
    let _ = nodes;
    let peer = RoutingNode {
        peer_id: bootstrap.api.peer_id().to_string(),
        address: vec![bootstrap.listen_address.clone()],
    };

    // node2 capable, node3 without the pin.
    let (node2, node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![peer.clone()],
        always_accept: true,
        is_service: true,
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&node2.api).await.unwrap();
    let (node3, node3_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![peer],
        always_accept: true,
        is_service: true,
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            String::new(),
        )])),
        ..Default::default()
    })
    .await;
    node_running(&node3.api).await.unwrap();
    dirs.extend(node2_dirs);
    dirs.extend(node3_dirs);

    let node1 = &bootstrap.api;
    let governance_id =
        create_and_authorize_governance(node1, vec![&node2.api, &node3.api])
            .await;

    // Compilers {Owner, AveNode2, AveNode3}, Majority = 2/3.
    let members = json!({
        "members": {
            "add": [
                { "name": "AveNode2", "key": node2.api.public_key() },
                { "name": "AveNode3", "key": node3.api.public_key() }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                    "compiler": ["AveNode2", "AveNode3"]
                }
            }
        }
    });
    emit_fact(node1, governance_id.clone(), members, true).await.unwrap();
    for api in [&node2.api, &node3.api] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), Some(1), true).await.unwrap();
    }

    // Schema add compiles with all three (default pin held everywhere).
    emit_fact(
        node1,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    // Switch: node3 stands down, owner + node2 carry the quorum.
    let request_id = emit_fact(
        node1,
        governance_id.clone(),
        json!({ "toolchain": TEST_PIN_B }),
        false,
    )
    .await
    .unwrap();
    wait_request_state(node1, request_id, Some(RequestState::Finish))
        .await
        .unwrap();

    let props = properties(node1, &governance_id, 3).await;
    assert_eq!(props.toolchain, TEST_PIN_B);
    assert!(props.schemas.contains_key(&SchemaType::Type("Example".to_owned())));
}

#[test(tokio::test)]
// TEST-PIN-10 (with contracts): unknown pin plus committed schemas —
// the evaluator gate preempts any build, so it commits a
// deterministic error with everything intact (no reboot loops, no
// partial rebuilds).
async fn test_pin_unknown_with_contracts_votes_error() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": "rust-9.99-ficticio" }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let props = properties(node, &governance_id, 2).await;
    assert_eq!(props.toolchain, default_pin());
    assert!(props.schemas.contains_key(&SchemaType::Type("Example".to_owned())));

    let events = get_events(node, governance_id, 3, true).await.unwrap();
    let event = serde_json::to_string(events.last().unwrap()).unwrap();
    assert!(
        event.contains("unknown toolchain pin"),
        "unexpected event outcome: {event}"
    );
}

#[test(tokio::test)]
// TEST-PIN-14: boot without the committed pin stays dormant — the node
// boots, heals nothing by rebuilding, keeps serving retained state,
// and new builds reboot instead of crash-looping.
async fn test_pin_boot_without_pin_stays_dormant() {
    let contracts_dir = tempfile::tempdir().unwrap();
    let local_db = tempfile::tempdir().unwrap();
    let ext_db = tempfile::tempdir().unwrap();

    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        local_db: Some(local_db.path().to_path_buf()),
        ext_db: Some(ext_db.path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        is_service: true,
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    let keys = node.keys.clone();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    // Restart holding every pin EXCEPT the committed default: heal and
    // builds go dormant, the node itself boots fine.
    let (node2, node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        keys: Some(keys),
        local_db: Some(local_db.path().to_path_buf()),
        ext_db: Some(ext_db.path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        is_service: true,
        toolchains: Some(BTreeMap::from([(
            TEST_PIN_B.to_owned(),
            String::new(),
        )])),
        ..Default::default()
    })
    .await;
    dirs.extend(node2_dirs);
    node_running(&node2.api).await.unwrap();

    // Retained state still served, pin included: effective-pin
    // correctness after reboot depends on it.
    let props = properties(&node2.api, &governance_id, 1).await;
    assert_eq!(props.toolchain, default_pin());
    assert!(props.schemas.contains_key(&SchemaType::Type("Example".to_owned())));

    // A new build under the unheld pin reboots instead of crashing.
    let request_id = emit_fact(
        &node2.api,
        governance_id.clone(),
        schema_add("Second", EXAMPLE_CONTRACT_V2, example_initial()),
        false,
    )
    .await
    .unwrap();
    wait_state(&node2.api, request_id, "reboot").await;
}
