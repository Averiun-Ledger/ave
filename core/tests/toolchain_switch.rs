//! TEST-PIN switch paths (P1/P2): every switch runs against real
//! registry IDs, never synthetic ones. For the capacity tests,
//! per-node toolchain maps.
//!
//! Test builds go through the shared pool like production builds go
//! through the local toolchain: the pool builds once per
//! (contract, toolchain) with the requested rustup toolchain, so a
//! recompile-all under a new pin reproduces real byte divergence
//! here. The dedicated real-toolchain test pins the byte comparison.
mod common;

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ave_common::SchemaType;
use ave_common::bridge::request::ApprovalStateRes;
use ave_common::identity::{PublicKey, keys::{Ed25519Signer, KeyPair}};
use ave_common::response::RequestState;
use ave_core::governance::data::GovernanceData;
use ave_core::helpers::network::test_faults::{
    FaultAction, FaultDirection, FaultMessage, FaultRule,
};
use ave_core::test_compiler::{ScriptedCompiler, ScriptedTransform};
use ave_network::{NodeType, RoutingNode};
use common::{
    CHANGED_SCHEMA_CONTRACT, CreateNodeConfig, CreateNodesAndConnectionsConfig,
    EXAMPLE_CONTRACT, EXAMPLE_CONTRACT_V2, INVALID_EXAMPLE_CONTRACT,
    PORT_COUNTER, create_and_authorize_governance, create_node,
    create_nodes_and_connections, emit_approve, emit_fact, get_events,
    get_subject, node_running, toolchain_name, wait_artifact_bytes,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::wait_request_state;

/// Second production pin: every switch test runs against real
/// registry IDs, never synthetic ones.
const PIN_198: &str = "rust-1.98.1_sdk-0.8.0_wasm32";

fn default_pin() -> String {
    GovernanceData::default().toolchain
}

fn both_pins() -> BTreeMap<String, String> {
    BTreeMap::from([
        (default_pin(), toolchain_name(&default_pin())),
        (PIN_198.to_owned(), toolchain_name(PIN_198)),
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

fn schema_add(
    id: &str,
    contract: &str,
    initial: serde_json::Value,
) -> serde_json::Value {
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
    let state = get_subject(node, gov.clone(), Some(sn), true)
        .await
        .unwrap();
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
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let props = properties(node, &governance_id, 1).await;
    assert_eq!(props.toolchain, PIN_198);
}

#[test(tokio::test)]
// Capacity vote, negative side: a bare switch nobody can build never
// commits — reboot with the pin untouched, no crash-loop.
async fn test_pin_bare_switch_without_capacity_reboots() {
    let (node, _dirs) = single_node_with(Some(BTreeMap::from([(
        default_pin(),
        toolchain_name(&default_pin()),
    )])))
    .await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "reboot").await;

    let props = properties(node, &governance_id, 0).await;
    assert_eq!(props.toolchain, default_pin());
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
    let before: GovernanceData = serde_json::from_value(
        get_subject(node, governance_id.clone(), Some(1), true)
            .await
            .unwrap()
            .properties,
    )
    .unwrap();
    assert!(
        before
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned())),
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
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
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
            "toolchain": PIN_198,
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
            "toolchain": PIN_198,
        }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Beta".to_owned())),
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
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, switch, "finish").await;
    assert_eq!(properties(node, &governance_id, 2).await.toolchain, PIN_198);

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
        after
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned())),
        "schemas must survive the round trip"
    );
}

#[test(tokio::test)]
// TEST-PIN-06: switch plus modify denied at approval — the previous
// version is never deleted nor overwritten: official bytes identical,
// staging swept, pin and schemas untouched.
async fn test_pin_switch_denied_keeps_previous_version() {
    let contracts_dir = tempfile::tempdir().unwrap();
    // No auto-accept: the deny vote below must decide, not lose a race.
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: false,
        is_service: true,
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    let add = emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        false,
    )
    .await
    .unwrap();
    // Votes only count inside the approval phase: approving earlier
    // loses the vote and stalls the request.
    wait_request_state(node, add.clone(), Some(RequestState::Approval))
        .await
        .unwrap();
    emit_approve(
        node,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        add,
        true,
    )
    .await
    .unwrap();

    let official_name = format!("{governance_id}_Example");
    let before =
        wait_artifact_bytes(contracts_dir.path(), &official_name).await;

    // Switch plus modify: staging must exist before denying, or the
    // sweep below would prove nothing.
    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({
            "schemas": {
                "change": [
                    {
                        "actual_id": "Example",
                        "new_contract": CHANGED_SCHEMA_CONTRACT,
                        "new_initial_value": { "data": "" }
                    }
                ]
            },
            "toolchain": PIN_198,
        }),
        false,
    )
    .await
    .unwrap();
    for _ in 0..200 {
        let staged = std::fs::read_dir(contracts_dir.path())
            .unwrap()
            .filter_map(|entry| {
                let name =
                    entry.unwrap().file_name().to_string_lossy().into_owned();
                name.contains("_temp_staging_").then_some(name)
            })
            .collect::<Vec<_>>();
        if !staged.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // Same for the deny: inside the approval phase, or the vote is lost.
    wait_request_state(node, request_id.clone(), Some(RequestState::Approval))
        .await
        .unwrap();

    emit_approve(
        node,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    // Previous version intact: same bytes, no staging leftovers.
    assert_eq!(
        wait_artifact_bytes(contracts_dir.path(), &official_name).await,
        before
    );
    let staged = std::fs::read_dir(contracts_dir.path())
        .unwrap()
        .filter_map(|entry| {
            let name =
                entry.unwrap().file_name().to_string_lossy().into_owned();
            name.contains("_temp_staging_").then_some(name)
        })
        .collect::<Vec<_>>();
    assert!(
        staged.is_empty(),
        "staging must be swept on abort: {staged:?}"
    );

    // Nothing committed: pin, schemas and contract pin the old ones.
    let state = get_subject(node, governance_id.clone(), None, true)
        .await
        .unwrap();
    let props: GovernanceData =
        serde_json::from_value(state.properties).unwrap();
    assert_eq!(props.toolchain, default_pin());
    assert_eq!(
        props
            .schemas
            .get(&SchemaType::Type("Example".to_owned()))
            .unwrap()
            .contract,
        EXAMPLE_CONTRACT
    );
}

#[test(tokio::test)]
// True divergence (SLOW, minutes): both sides build with REAL
// installed toolchains mapped exactly per registry (1.95 and 1.98.1),
// so the committed anchor changes bytes for real.
async fn test_pin_switch_diverges_bytes_with_real_toolchains() {
    let contracts_dir = tempfile::tempdir().unwrap();
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        is_service: true,
        toolchains: Some(BTreeMap::from([
            (default_pin(), "1.95".to_owned()),
            (PIN_198.to_owned(), "1.98.1".to_owned()),
        ])),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();
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

    let official_name = format!("{governance_id}_Example");
    let before_bytes =
        wait_artifact_bytes(contracts_dir.path(), &official_name).await;

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    // Different toolchain, different bytes, promoted over the old
    // official artifact only at commit.
    let rebuilt_bytes =
        wait_artifact_bytes(contracts_dir.path(), &official_name).await;
    assert_ne!(
        before_bytes, rebuilt_bytes,
        "switch must rebuild bytes under the new toolchain"
    );

    let props = properties(node, &governance_id, 2).await;
    assert_eq!(props.toolchain, PIN_198);
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
}

#[test(tokio::test)]
// Matriz: add-only más switch (sin schemas comprometidos) commitea
// bajo el pin nuevo.
async fn test_pin_switch_with_add_only() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;
    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    { "id": "Beta", "contract": EXAMPLE_CONTRACT, "initial_value": example_initial() }
                ]
            },
            "toolchain": PIN_198,
        }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 1).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Beta".to_owned()))
    );
}

#[test(tokio::test)]
// Matriz: change con el MISMO pin commitea normal bajo el pin
// comprometido (precisión del gate para changes, gemelo del 17).
async fn test_pin_same_pin_with_change_commits() {
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

    let current = default_pin();
    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({
            "schemas": {
                "change": [
                    {
                        "actual_id": "Example",
                        "new_contract": CHANGED_SCHEMA_CONTRACT,
                        "new_initial_value": { "data": "" }
                    }
                ]
            },
            "toolchain": current,
        }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, current);
    assert_eq!(
        after
            .schemas
            .get(&SchemaType::Type("Example".to_owned()))
            .unwrap()
            .contract,
        CHANGED_SCHEMA_CONTRACT
    );
}

#[test(tokio::test)]
// Matriz: cambio solo de initial-value más switch — el artefacto no
// depende del init pero sí del toolchain: reconstruye bajo el pin
// nuevo (force_rebuild) en vez de recargar bytes viejos.
async fn test_pin_switch_with_init_only_change() {
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
                "change": [
                    {
                        "actual_id": "Example",
                        "new_initial_value": { "one": 7, "two": 0, "three": 0 }
                    }
                ]
            },
            "toolchain": PIN_198,
        }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
}

#[test(tokio::test)]
// Matriz: switch pelado denegado — aborta sin tocar nada (pin,
// versión y schemas intactos).
async fn test_pin_bare_switch_denied_changes_nothing() {
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: false,
        is_service: true,
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    let request_id = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_request_state(node, request_id.clone(), Some(RequestState::Approval))
        .await
        .unwrap();
    emit_approve(
        node,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node, governance_id.clone(), None, true)
        .await
        .unwrap();
    let props: GovernanceData =
        serde_json::from_value(state.properties).unwrap();
    assert_eq!(props.toolchain, default_pin());
    assert_eq!(props.version, 0);
    assert!(props.schemas.is_empty());
}

#[test(tokio::test)]
// Matriz: switch más remove — el schema eliminado sale con el evento
// sin compilarse (ni ancla nueva ni bytes servibles para él) y el
// resto reconstruye bajo el pin nuevo.
async fn test_pin_switch_with_remove() {
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
                    { "id": "Beta", "contract": EXAMPLE_CONTRACT_V2, "initial_value": example_initial() }
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
        json!({
            "schemas": { "remove": ["Beta"] },
            "toolchain": PIN_198,
        }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "finish").await;

    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Alpha".to_owned()))
    );
    assert!(
        !after
            .schemas
            .contains_key(&SchemaType::Type("Beta".to_owned()))
    );
}

#[test(tokio::test)]
// TEST-PIN-13: request en vuelo durante el cambio. Un add atascado
// en compilación (pool en hold) retiene el subject; el switch entra
// en cola (InQueue, no solapa: un manager por subject) y al liberar
// commitea el add bajo el pin viejo y el switch reintenta con la
// versión nueva y commitea bajo el nuevo. Nada stale promociona.
async fn test_pin_inflight_add_then_switch() {
    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);
    scripted.hold();

    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        compiler: Some(scripted.node_config()),
        always_accept: true,
        is_service: true,
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();
    let node = &node.api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    // Add atascado: el build llega al pool y ahí se queda.
    let add = emit_fact(
        node,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        false,
    )
    .await
    .unwrap();
    for _ in 0..200 {
        if scripted.compiles_received() >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        scripted.compiles_received() >= 1,
        "add must reach the held pool"
    );

    // Switch detrás: en cola hasta que el add libere el subject.
    let switch = emit_fact(
        node,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_request_state(node, switch.clone(), Some(RequestState::InQueue))
        .await
        .unwrap();

    scripted.release();

    // El add commitea bajo el pin viejo...
    wait_state(node, add, "finish").await;
    let mid = properties(node, &governance_id, 1).await;
    assert_eq!(mid.toolchain, default_pin());
    assert!(
        mid.schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    // ...y el switch, tras reintentar con la versión nueva, bajo el nuevo.
    wait_state(node, switch, "finish").await;
    let after = properties(node, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
}

#[test(tokio::test)]
// TEST-REC-01: muerte a mitad de build (sin parada graciosa: se
// cancela y se abandona, como un kill -9 en lo que al disco
// respecta) y rearranque con las mismas DBs. El evento combina
// switch con add de una fuente NUEVA —su build hace miss en todas
// las cachés y queda en vuelo en el pool en hold— . Al volver: sin
// crash-loop, el switch pendiente termina (commit bajo el pin nuevo
// con artefactos correctos) o aborta limpio (pin intacto, oficial
// intacto). Lo que no puede pasar nunca: commit a medias, crash en
// boot, o servir bytes del pin equivocado.
async fn test_pin_kill_mid_recompile_then_restart() {
    let scripted = ScriptedCompiler::start(ScriptedTransform::Identity);
    scripted.hold();

    let contracts_dir = tempfile::tempdir().unwrap();
    let local_db = tempfile::tempdir().unwrap();
    let ext_db = tempfile::tempdir().unwrap();

    let (node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        compiler: Some(scripted.node_config()),
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
    scripted.release();
    emit_fact(
        &node.api,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    // Switch más add de fuente nueva con el pool en hold: el build
    // del add hace miss en todas las cachés y queda en vuelo. Se
    // mata en ese punto, sin join gracioso.
    scripted.hold();
    let switch = emit_fact(
        &node.api,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    { "id": "Beta", "contract": EXAMPLE_CONTRACT_V2, "initial_value": example_initial() }
                ]
            },
            "toolchain": PIN_198,
        }),
        false,
    )
    .await
    .unwrap();
    for _ in 0..200 {
        if scripted.compiles_received() >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    assert!(
        scripted.compiles_received() >= 2,
        "recompile must reach the held pool before the kill"
    );

    let keys = node.keys.clone();
    node.token.cancel();
    // Sin join: muerte súbita, el estado en disco queda tal cual.
    drop(node.handler);

    let (node2, node2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        compiler: Some(scripted.node_config()),
        keys: Some(keys),
        local_db: Some(local_db.path().to_path_buf()),
        ext_db: Some(ext_db.path().to_path_buf()),
        contracts_path: Some(contracts_dir.path().to_path_buf()),
        always_accept: true,
        is_service: true,
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    dirs.extend(node2_dirs);
    // Boot sin crash-loop con staging a medias en disco.
    node_running(&node2.api).await.unwrap();

    // Al liberar, el switch pendiente termina bajo el pin nuevo con
    // artefactos correctos.
    scripted.release();
    wait_state(&node2.api, switch, "finish").await;

    let after = properties(&node2.api, &governance_id, 2).await;
    assert_eq!(after.toolchain, PIN_198);
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    assert!(
        after
            .schemas
            .contains_key(&SchemaType::Type("Beta".to_owned()))
    );
    // Ambos oficiales sirven bytes: los artefactos existen y son legibles.
    for name in ["Example", "Beta"] {
        let official_name = format!("{governance_id}_{name}");
        let bytes =
            wait_artifact_bytes(contracts_dir.path(), &official_name).await;
        assert!(!bytes.is_empty());
    }
}

#[test(tokio::test)]
// TEST-PIN-04: a pin nobody holds stands down everywhere — reboot, no
// crash-loop, no commit. The owner path stays open (node responsive).
async fn test_pin_nobody_holds_reboots() {
    // Holds the default pin only: the switch target is unresolvable,
    // so the stand-down is meaningful (not an empty-map artifact).
    let (node, _dirs) = single_node_with(Some(BTreeMap::from([(
        default_pin(),
        toolchain_name(&default_pin()),
    )])))
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
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_state(node, request_id, "reboot").await;

    // No commit and no crash: version frozen, node answers.
    let props = properties(node, &governance_id, 1).await;
    assert_eq!(props.toolchain, default_pin());
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
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
            toolchain_name(&default_pin()),
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
    emit_fact(node1, governance_id.clone(), members, true)
        .await
        .unwrap();
    for api in [&node2.api, &node3.api] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
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
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_request_state(node1, request_id, Some(RequestState::Finish))
        .await
        .unwrap();

    let props = properties(node1, &governance_id, 3).await;
    assert_eq!(props.toolchain, PIN_198);
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
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
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

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
            PIN_198.to_owned(),
            toolchain_name(PIN_198),
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
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

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

#[test(tokio::test)]
// TEST-PIN-22: blind proponent. The owner proposes a switch to a pin
// it does not hold (not yet installed): its own compiler votes
// `NoToolchain`, the two capable compilers carry the quorum, and the
// switch commits everywhere — including on the owner, which goes
// dormant serving retained artifacts instead of crashing. This is the
// rollout shape the operator procedure blesses ("no hace falta que
// TODOS lo tengan"); TEST-PIN-05 covers an incapable peer, never the
// incapable requester itself.
async fn test_pin_switch_blind_proponent_commits() {
    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            always_accept: true,
            is_service: true,
            // Owner holds only the current pin.
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            toolchain_name(&default_pin()),
        )])),
            ..Default::default()
        })
        .await;
    let bootstrap = nodes.remove(0);
    let _ = nodes;
    let peer = RoutingNode {
        peer_id: bootstrap.api.peer_id().to_string(),
        address: vec![bootstrap.listen_address.clone()],
    };

    // node2 and node3 hold both pins.
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
        toolchains: Some(both_pins()),
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
    emit_fact(node1, governance_id.clone(), members, true)
        .await
        .unwrap();
    for api in [&node2.api, &node3.api] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
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

    // Switch to a pin the owner does not hold: the owner stands down
    // on its own proposal, node2 + node3 carry the quorum.
    let request_id = emit_fact(
        node1,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_request_state(node1, request_id, Some(RequestState::Finish))
        .await
        .unwrap();

    // Committed everywhere, owner included — dormant, not crashed.
    // (Only peers sync via update_subject; the owner already holds
    // its own commit.)
    node_running(node1).await.unwrap();
    for api in [&node2.api, &node3.api] {
        api.update_subject(governance_id.clone()).await.unwrap();
    }
    let props = properties(node1, &governance_id, 3).await;
    assert_eq!(props.toolchain, PIN_198);
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    for api in [&node2.api, &node3.api] {
        let props = properties(api, &governance_id, 3).await;
        assert_eq!(props.toolchain, PIN_198);
    }
}

#[test(tokio::test)]
// TEST-PIN-23: lying mapping fails the boot loud. A pin mapped at a
// toolchain whose measured version is not the registry entry's never
// becomes a node: `Api::build` errors instead of voting divergent
// bytes under a valid ID later. No builds involved (one rustc spawn).
async fn test_pin_boot_wrong_mapping_fails_loud() {
    let err = common::try_create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        is_service: true,
        toolchains: Some(BTreeMap::from([
            (default_pin(), "1.95.0".to_owned()),
            (PIN_198.to_owned(), "1.95.0".to_owned()),
        ])),
        ..Default::default()
    })
    .await
    .map(|_| ())
    .expect_err("a pin mapped at the wrong toolchain must not boot");
    let msg = format!("{err:?}");
    assert!(
        msg.contains(PIN_198) && msg.contains("1.95.0"),
        "boot error must name the lying mapping, got: {msg}"
    );
}

#[test(tokio::test)]
// TEST-PIN-24: two governances, two pins, one node. The pin selects
// per governance version, never a node-global toolchain: gov1 keeps
// building and committing on the default pin while gov2 lives on
// 1.98.1, both artifacts served. Guards against any future global
// toolchain state leaking across governances (today everything is
// explicit parameters, verified in audit — this pins it).
async fn test_pin_two_governances_two_pins_coexist() {
    let (node, _dirs) = single_node().await;
    let node = &node.api;

    let gov1 = create_and_authorize_governance(node, vec![]).await;
    let gov2 = create_and_authorize_governance(node, vec![]).await;

    emit_fact(
        node,
        gov1.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        node,
        gov2.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();

    // Only gov2 moves.
    let request_id =
        emit_fact(node, gov2.clone(), json!({ "toolchain": PIN_198 }), false)
            .await
            .unwrap();
    wait_request_state(node, request_id, Some(RequestState::Finish))
        .await
        .unwrap();

    let props1 = properties(node, &gov1, 1).await;
    assert_eq!(props1.toolchain, default_pin());
    assert!(
        props1
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    let props2 = properties(node, &gov2, 2).await;
    assert_eq!(props2.toolchain, PIN_198);
    assert!(
        props2
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );

    // gov1 keeps operating under its pin after gov2 moved.
    emit_fact(
        node,
        gov1.clone(),
        schema_add("Second", EXAMPLE_CONTRACT_V2, example_initial()),
        true,
    )
    .await
    .unwrap();
    let props1 = properties(node, &gov1, 2).await;
    assert_eq!(props1.toolchain, default_pin());
    assert!(
        props1
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    assert!(
        props1
            .schemas
            .contains_key(&SchemaType::Type("Second".to_owned()))
    );
    node_running(node).await.unwrap();
}

#[test(tokio::test)]
// TEST-PIN-25: a compiler that stands down for the new pin stays
// live through fetch. Node3 holds compiler+evaluator roles but no
// PIN_198 toolchain: after the switch commits without it, an
// A compiler that stands down for the new pin must survive the
// switch apply instead of crash-looping, and keep serving what it
// holds. Node3 (compiler+evaluator, default pin only) applies the
// switch it can never build under: pre-fix the apply-time artifact
// recovery crashed the node on the unresolvable pin
// (`UnknownToolchainPin` → `crash_system`); now it stays dormant.
// 05 proves the switch commits with a partial quorum; this proves
// the stood-down node lives through it with retained bytes.
// NOTE: cross-node request-state polling is invalid here —
// request IDs are node-local (wall-clock hashed in), so remote
// nodes answer RequestNotFound by design. Liveness is asserted
// through ledger state plus retained artifact bytes instead.
// Pool builds (like 05): the crash needs no real toolchain, only
// an unmapped pin.
async fn test_pin_stood_down_node_survives_switch() {
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

    // Explicit contracts dir for node3: its retained bytes are
    // asserted after the switch.
    let node3_contracts = tempfile::tempdir().unwrap();
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
        contracts_path: Some(node3_contracts.path().to_path_buf()),
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            toolchain_name(&default_pin()),
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

    // Compilers AND evaluators {Owner, AveNode2, AveNode3}.
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
                    "evaluator": ["AveNode2", "AveNode3"],
                    "compiler": ["AveNode2", "AveNode3"]
                }
            }
        }
    });
    emit_fact(node1, governance_id.clone(), members, true)
        .await
        .unwrap();
    for api in [&node2.api, &node3.api] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    }

    // Schema add compiles with all three (default pin held everywhere).
    // Barrier: node3 holds the default-pin bytes, proving it applied
    // the add with anchor and promotion — then its bytes are deleted
    // on purpose. At the switch apply, recovery can not hit any load
    // path and must face the unresolvable pin deterministically (no
    // timing luck): pre-fix it crashed the node (`crash_system` on
    // `UnknownToolchainPin`); now it stays dormant.
    emit_fact(
        node1,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();
    let official_name = format!("{governance_id}_Example");
    let official_dir = node3_contracts
        .path()
        .join("contracts")
        .join(&official_name);
    let stale =
        wait_artifact_bytes(node3_contracts.path(), &official_name).await;
    assert!(!stale.is_empty());
    std::fs::remove_dir_all(&official_dir).unwrap();

    // Switch: node3 stands down, owner + node2 carry the quorum.
    let request_id = emit_fact(
        node1,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        false,
    )
    .await
    .unwrap();
    wait_request_state(node1, request_id, Some(RequestState::Finish))
        .await
        .unwrap();
    let props = properties(node1, &governance_id, 3).await;
    assert_eq!(props.toolchain, PIN_198);

    // Node3 applies the switch it can never build under: alive and
    // tracking the version, with no bytes rebuilt or fetched on its
    // own — dormancy, not decay and not crash-loop. `properties`
    // (bounded) proves liveness: a crashed node answers nothing.
    // (`node_running` would hang, not fail, on a dead node.)
    let props3 = properties(&node3.api, &governance_id, 3).await;
    assert_eq!(props3.toolchain, PIN_198);
    assert!(
        props3
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    assert!(
        std::fs::read(official_dir.join("contract.wasm")).is_err(),
        "a stood-down node rebuilds nothing by itself"
    );
}

#[test(tokio::test)]
// TEST-PIN-26: a pin mapped at a toolchain that is not installed can
// not boot either. 23 covers the lying mapping (wrong version); this
// covers the missing one: the entry is broken either way and the
// boot fails loud before serving anything. Fast: the probe fails
// without any build.
async fn test_pin_boot_missing_toolchain_fails_loud() {
    let err = common::try_create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        is_service: true,
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            "ave-toolchain-that-does-not-exist".to_owned(),
        )])),
        ..Default::default()
    })
    .await
    .map(|_| ())
    .expect_err("a pin mapped at a missing toolchain must not boot");
    let msg = format!("{err:?}");
    assert!(
        msg.contains(&default_pin()),
        "boot error must name the broken mapping, got: {msg}"
    );
}

#[test(tokio::test)]
// Stale restart: a witness down during the switch comes back WITHOUT
// the new pin. It boots live (no crash-loop), syncs the ledger to the
// tip and keeps serving its retained 1.95 artifact, but holds no 1.98
// bytes: without the toolchain it can not build, only retain.
async fn test_pin_restart_without_new_pin_stays_stale_but_live() {
    let owner_contracts = tempfile::tempdir().unwrap();
    let (owner, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        is_service: true,
        contracts_path: Some(owner_contracts.path().to_path_buf()),
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();
    let owner_peer = RoutingNode {
        peer_id: owner.api.peer_id().to_string(),
        address: vec![owner.listen_address.clone()],
    };

    let b_contracts = tempfile::tempdir().unwrap();
    let (mut node_b, mut node_b_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![owner_peer.clone()],
        always_accept: true,
        is_service: true,
        contracts_path: Some(b_contracts.path().to_path_buf()),
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&node_b.api).await.unwrap();
    let node_b_keys = node_b.keys.clone();
    let node_b_local_db = node_b_dirs[0].path().to_path_buf();
    let node_b_ext_db = node_b_dirs[1].path().to_path_buf();
    dirs.append(&mut node_b_dirs);

    let node1 = &owner.api;
    let governance_id =
        create_and_authorize_governance(node1, vec![&node_b.api]).await;

    // B: member and gov witness. Schema roles land together with
    // the schema itself below. B never compiles (no compiler role):
    // it fetches everything it evaluates.
    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    { "name": "AveNodeB", "key": node_b.api.public_key() }
                ]
            },
            "roles": {
                "governance": {
                    "add": { "witness": ["AveNodeB"] }
                }
            }
        }),
        true,
    )
    .await
    .unwrap();
    node_b.api.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&node_b.api, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: schema under the default pin with its roles; B fetches
    // the artifact when it evaluates below.
    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": example_initial()
                    }
                ]
            },
            "roles": {
                "tracker_schemas": {
                    "add": {
                        "issuer": [{ "name": "Owner", "namespace": [] }]
                    }
                },
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                { "name": "Owner", "namespace": [] },
                                { "name": "AveNodeB", "namespace": [] }
                            ],
                            "validator": [
                                { "name": "Owner", "namespace": [] }
                            ],
                            "witness": [
                                { "name": "Owner", "namespace": [] },
                                { "name": "AveNodeB", "namespace": [] }
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_b.api.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&node_b.api, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Tracker on Example: B fetches the 1.95 artifact and votes it,
    // so its bytes below are fetched, not built.
    let (tracker_id, ..) = common::create_subject(
        node1,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();
    get_subject(&node_b.api, tracker_id.clone(), Some(0), true)
        .await
        .unwrap();
    emit_fact(
        node1,
        tracker_id.clone(),
        json!({"ModOne": {"data": 5}}),
        true,
    )
    .await
    .unwrap();
    let b_state = get_subject(&node_b.api, tracker_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(b_state.properties, json!({"one": 5, "two": 0, "three": 0}));

    let official = format!("{governance_id}_Example");
    let b_example_before =
        wait_artifact_bytes(b_contracts.path(), &official).await;

    // B goes down; the switch and a second schema commit without it.
    node_b.token.cancel();
    join_all(node_b.handler.iter_mut()).await;

    emit_fact(
        node1,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    emit_fact(
        node1,
        governance_id.clone(),
        schema_add("Example2", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // Restart stale: same identity and disks, but only the old pin.
    let (node_b2, mut node_b2_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![owner_peer],
        always_accept: true,
        is_service: true,
        keys: Some(node_b_keys),
        local_db: Some(node_b_local_db),
        ext_db: Some(node_b_ext_db),
        contracts_path: Some(b_contracts.path().to_path_buf()),
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            toolchain_name(&default_pin()),
        )])),
        ..Default::default()
    })
    .await;
    dirs.append(&mut node_b2_dirs);
    // Live, no crash-loop without the new toolchain.
    node_running(&node_b2.api).await.unwrap();

    // Ledger sync needs no toolchain: the tip is reachable.
    node_b2.api.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&node_b2.api, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    let props = properties(&node_b2.api, &governance_id, 4).await;
    assert_eq!(props.toolchain, PIN_198);
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example".to_owned()))
    );
    assert!(
        props
            .schemas
            .contains_key(&SchemaType::Type("Example2".to_owned()))
    );

    // The stale node heals by fetching: its Example bytes must be
    // the current anchored ones (owner's 1.98 build), fetched, never
    // built locally without the toolchain. The heal replaces the
    // retained file asynchronously, so wait for the exact bytes.
    let owner_example = std::fs::read(
        owner_contracts
            .path()
            .join("contracts")
            .join(&official)
            .join("contract.wasm"),
    )
    .expect("owner artifact must be on disk");
    assert_ne!(
        owner_example, b_example_before,
        "the switch must rebuild under the new toolchain"
    );
    common::wait_artifact_bytes_eq(
        b_contracts.path(),
        &official,
        &owner_example,
    )
    .await;
    // Nothing built under the new pin: no bytes, no staging.
    assert!(
        !b_contracts
            .path()
            .join("contracts")
            .join(format!("{governance_id}_Example2"))
            .join("contract.wasm")
            .exists(),
        "a node without the new toolchain must hold no 1.98 bytes"
    );

    node_running(&owner.api).await.unwrap();
    node_running(&node_b2.api).await.unwrap();
}

#[test(tokio::test)]
// Fresh join across pins: a node joining after the switch with only
// the new toolchain syncs the full ledger and serves current bytes
// without ever building. Behind nodes are never consulted for
// current bytes (the fetch layer only asks ahead servers, and sync
// sweeps stale files before healing), so stale bytes can never land
// as current: both directions are asserted below.
async fn test_pin_fresh_join_with_only_new_pin_syncs_current() {
    let owner_contracts = tempfile::tempdir().unwrap();
    let (owner, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        is_service: true,
        contracts_path: Some(owner_contracts.path().to_path_buf()),
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();
    let owner_peer = RoutingNode {
        peer_id: owner.api.peer_id().to_string(),
        address: vec![owner.listen_address.clone()],
    };

    // Stale: evaluator/witness/member on Example, but never a gov
    // witness (no auto-advance past the switch) and never a compiler.
    // It fetches 1.95 bytes to evaluate, then freezes with them.
    let stale_contracts = tempfile::tempdir().unwrap();
    let (stale, mut stale_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![owner_peer.clone()],
        always_accept: true,
        is_service: true,
        contracts_path: Some(stale_contracts.path().to_path_buf()),
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            toolchain_name(&default_pin()),
        )])),
        ..Default::default()
    })
    .await;
    node_running(&stale.api).await.unwrap();
    dirs.append(&mut stale_dirs);

    let node1 = &owner.api;
    let node_s = &stale.api;
    let governance_id =
        create_and_authorize_governance(node1, vec![node_s]).await;

    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "members": {
                "add": [{ "name": "Stale", "key": node_s.public_key() }]
            },
            "roles": {
                "tracker_schemas": {
                    "add": {
                        "issuer": [{ "name": "Owner", "namespace": [] }]
                    }
                }
            }
        }),
        true,
    )
    .await
    .unwrap();
    node_s.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node_s, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": example_initial()
                    }
                ]
            },
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                { "name": "Owner", "namespace": [] },
                                { "name": "Stale", "namespace": [] }
                            ],
                            "validator": [
                                { "name": "Owner", "namespace": [] }
                            ],
                            "witness": [
                                { "name": "Owner", "namespace": [] },
                                { "name": "Stale", "namespace": [] }
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    let (tracker_id, ..) = common::create_subject(
        node1,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();
    get_subject(node_s, tracker_id.clone(), Some(0), true)
        .await
        .unwrap();
    emit_fact(
        node1,
        tracker_id.clone(),
        json!({"ModOne": {"data": 5}}),
        true,
    )
    .await
    .unwrap();
    let stale_state = get_subject(node_s, tracker_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(stale_state.properties, json!({"one": 5, "two": 0, "three": 0}));

    // Stale holds 1.95 bytes from here on: no gov witness role, no
    // more updates, no demand. Record them before the switch.
    let official = format!("{governance_id}_Example");
    let stale_bytes =
        wait_artifact_bytes(stale_contracts.path(), &official).await;

    // Switch + member add for the fresh node. Stale never sees them.
    emit_fact(
        node1,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // Freeze the dangerous state deterministically: block byte
    // serving network-wide, then sync the stale node. Its ledger
    // reaches the tip; without servable bytes the stale file is
    // swept, never served as current.
    node1
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    let _ = node_s.update_subject(governance_id.clone()).await;
    get_subject(node_s, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert!(
        !stale_contracts
            .path()
            .join("contracts")
            .join(&official)
            .join("contract.wasm")
            .exists(),
        "sync without byte serving must sweep stale bytes, never serve them"
    );
    node1.test_release_held().await.unwrap();

    let fetch_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let fetch_pk = fetch_keys.public_key().to_string();
    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "members": {
                "add": [{ "name": "Fetch", "key": fetch_pk }]
            },
            "roles": {
                "governance": { "add": { "witness": ["Fetch"] } },
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                { "name": "Fetch", "namespace": [] }
                            ],
                            "witness": [
                                { "name": "Fetch", "namespace": [] }
                            ]
                        },
                        "remove": {
                            "evaluator": [
                                { "name": "Stale", "namespace": [] }
                            ]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // Fresh node, only the new pin: joins after the switch and must
    // end up with 1.98 bytes without ever building. Peered to both
    // servers so the stale one is directly reachable for the fetch.
    let fetch_contracts = tempfile::tempdir().unwrap();
    let (fetch, mut fetch_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![
            owner_peer,
            RoutingNode {
                peer_id: stale.api.peer_id().to_string(),
                address: vec![stale.listen_address.clone()],
            },
        ],
        always_accept: true,
        is_service: true,
        keys: Some(fetch_keys),
        contracts_path: Some(fetch_contracts.path().to_path_buf()),
        toolchains: Some(BTreeMap::from([(
            PIN_198.to_owned(),
            toolchain_name(PIN_198),
        )])),
        ..Default::default()
    })
    .await;
    node_running(&fetch.api).await.unwrap();
    dirs.append(&mut fetch_dirs);
    let node_f = &fetch.api;
    node_f
        .authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(node1.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();

    // Fresh join: full ledger sync plus current bytes, all without
    // building. The swept node has nothing to offer, so everything
    // comes from the updated server.
    node_f.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node_f, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    let owner_bytes =
        wait_artifact_bytes(owner_contracts.path(), &official).await;
    let fetch_bytes =
        wait_artifact_bytes(fetch_contracts.path(), &official).await;
    assert_eq!(fetch_bytes, owner_bytes);
    assert_ne!(fetch_bytes, stale_bytes);

    // Whatever the stale node holds afterwards is current: it either
    // healed to the anchored bytes or holds nothing (never stale).
    let stale_path = stale_contracts
        .path()
        .join("contracts")
        .join(&official)
        .join("contract.wasm");
    if stale_path.exists() {
        let stale_now =
            std::fs::read(&stale_path).expect("stale file must read");
        assert_eq!(
            stale_now, owner_bytes,
            "a healed node serves current bytes, never stale ones"
        );
    }

    node_running(&owner.api).await.unwrap();
    node_running(&stale.api).await.unwrap();
    node_running(&fetch.api).await.unwrap();
}

#[test(tokio::test)]
// Fetch across pins: an evaluator WITHOUT the new toolchain fetches
// the artifact built under it from an updated compiler and evaluates
// with it. Building needs the toolchain; evaluating and serving only
// need the bytes, verified against the ledger anchor either way.
async fn test_pin_evaluator_without_new_pin_fetches_and_evaluates() {
    let owner_contracts = tempfile::tempdir().unwrap();
    let (owner, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        is_service: true,
        contracts_path: Some(owner_contracts.path().to_path_buf()),
        toolchains: Some(both_pins()),
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();
    let owner_peer = RoutingNode {
        peer_id: owner.api.peer_id().to_string(),
        address: vec![owner.listen_address.clone()],
    };

    let eval_contracts = tempfile::tempdir().unwrap();
    let (eval, mut eval_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![owner_peer],
        always_accept: true,
        is_service: true,
        contracts_path: Some(eval_contracts.path().to_path_buf()),
        toolchains: Some(BTreeMap::from([(
            default_pin(),
            toolchain_name(&default_pin()),
        )])),
        ..Default::default()
    })
    .await;
    node_running(&eval.api).await.unwrap();
    dirs.append(&mut eval_dirs);

    let node1 = &owner.api;
    let node2 = &eval.api;
    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    // Eval: member and gov witness. Schema roles for Example2 land
    // together with the schema itself; Eval never compiles (no
    // compiler role anywhere).
    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "members": {
                "add": [{ "name": "Eval", "key": node2.public_key() }]
            },
            "roles": {
                "governance": { "add": { "witness": ["Eval"] } }
            }
        }),
        true,
    )
    .await
    .unwrap();
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // SN 2: schema under the default pin (baseline, same pin).
    emit_fact(
        node1,
        governance_id.clone(),
        schema_add("Example", EXAMPLE_CONTRACT, example_initial()),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // SN 3: switch recompiles it under 1.98.1; SN 4 adds Example2.
    emit_fact(
        node1,
        governance_id.clone(),
        json!({ "toolchain": PIN_198 }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    emit_fact(
        node1,
        governance_id.clone(),
        json!({
            "schemas": {
                "add": [
                    {
                        "id": "Example2",
                        "contract": EXAMPLE_CONTRACT_V2,
                        "initial_value": example_initial()
                    }
                ]
            },
            "roles": {
                "tracker_schemas": {
                    "add": {
                        "issuer": [{ "name": "Owner", "namespace": [] }]
                    }
                },
                "schema": [
                    {
                        "schema_id": "Example2",
                        "add": {
                            "evaluator": [
                                { "name": "Owner", "namespace": [] },
                                { "name": "Eval", "namespace": [] }
                            ],
                            "validator": [
                                { "name": "Owner", "namespace": [] }
                            ],
                            "witness": [
                                { "name": "Owner", "namespace": [] },
                                { "name": "Eval", "namespace": [] }
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(node1, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // Eval tracks the tip without building anything itself.
    node2.update_subject(governance_id.clone()).await.unwrap();
    get_subject(node2, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // Tracker on the 1.98.1 schema: Eval fetches the artifact it can
    // not build and serves/evaluates from the fetched bytes.
    let (tracker_id, ..) = common::create_subject(
        node1,
        governance_id.clone(),
        "Example2",
        "",
        true,
    )
    .await
    .unwrap();
    get_subject(node2, tracker_id.clone(), Some(0), true)
        .await
        .unwrap();

    emit_fact(
        node1,
        tracker_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();
    let state = get_subject(node2, tracker_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 0, "two": 0, "three": 50}));

    // Fetched bytes are the anchored 1.98.1 ones, byte for byte.
    let official = format!("{governance_id}_Example2");
    let owner_bytes =
        wait_artifact_bytes(owner_contracts.path(), &official).await;
    let eval_bytes =
        wait_artifact_bytes(eval_contracts.path(), &official).await;
    assert_eq!(eval_bytes, owner_bytes);

    node_running(&owner.api).await.unwrap();
    node_running(&eval.api).await.unwrap();
}
