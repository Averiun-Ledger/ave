//! Reboot recovery of ephemeral tracker request managers: a kill
//! before the post-validation checkpoint restarts the request from
//! zero, a kill after it resumes distribution with identical bytes.
//! Both must apply the fact exactly once with a contiguous sn.

mod common;

use std::{sync::atomic::Ordering, time::Duration};

use ave_common::{identity::DigestIdentifier, response::RequestState};
use ave_core::Api;
use ave_core::helpers::network::test_faults::{
    FaultAction, FaultDirection, FaultMessage, FaultRule,
};
use ave_network::{NodeType, RoutingNode};
use common::{
    NodeData, assert_tracker_fact_full, create_and_authorize_governance,
    create_nodes_and_connections, create_subject, emit_fact, get_events,
    get_subject, node_running, wait_request,
};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT,
    PORT_COUNTER, create_node,
};

/// Three nodes sharing a governance: the first owns it, the second
/// creates a subject and is the one under test (it reboots
/// mid-request), the third witnesses.
async fn setup() -> (
    NodeData,
    NodeData,
    Vec<tempfile::TempDir>,
    ave_common::identity::DigestIdentifier,
    ave_common::identity::DigestIdentifier,
) {
    let (nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let owner_governance = nodes[0].api.clone();
    let creator = nodes[1].api.clone();
    let witness = nodes[2].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner_governance,
        vec![&creator, &witness],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": creator.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": witness.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "AveNode2", "AveNode3"
                    ]
                }
            },
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "validator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "witness": [
                                {
                                    "name": "AveNode3",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "AveNode2",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Any",
                                    "namespace": []
                                }
                            ]
                        }
                }
            ]
        }
    });

    emit_fact(&owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The creator must see the roles before issuing tracker events.
    let _state = get_subject(&creator, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&creator, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let mut nodes_iter = nodes.into_iter();
    let bootstrap_node = nodes_iter.next().unwrap();
    let owner_node = nodes_iter.next().unwrap();
    (bootstrap_node, owner_node, dirs, governance_id, subject_id)
}

/// Waits until the request parks in `Validation` (or slips to
/// `Distribution` first). A terminal state is a loud failure, never
/// a silent pass: reaching `Finish` before the kill would exercise no
/// recovery at all.
async fn wait_validation_or_distribution(
    api: &Api,
    request_id: DigestIdentifier,
) {
    loop {
        if let Ok(state) = api.get_request_state(request_id.clone()).await {
            match &state.state {
                RequestState::Validation | RequestState::Distribution => {
                    return;
                }
                RequestState::Finish
                | RequestState::Abort { .. }
                | RequestState::Invalid { .. } => {
                    panic!(
                        "request reached terminal state {:?} before the kill",
                        state.state
                    );
                }
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Waits until the request parks in `Distribution` — only the
/// distribution hold makes it wait there. `Finish` before the kill
/// means the hold did not bite and fails loud.
async fn wait_distribution(api: &Api, request_id: DigestIdentifier) {
    loop {
        if let Ok(state) = api.get_request_state(request_id.clone()).await {
            match &state.state {
                RequestState::Distribution => return,
                RequestState::Finish
                | RequestState::Abort { .. }
                | RequestState::Invalid { .. } => {
                    panic!(
                        "request reached terminal state {:?} before the kill",
                        state.state
                    );
                }
                _ => {}
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Stops `node` and boots it back with the same keys and databases,
/// like `updown.rs`: the rebooted node carries no fault rules.
async fn reboot_owner(
    bootstrap: &NodeData,
    mut node: NodeData,
    dirs: &[tempfile::TempDir],
) -> NodeData {
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.api.peer_id().to_string(),
        address: vec![bootstrap.listen_address.clone()],
    }];

    let (node, _) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        keys: Some(node.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();
    node
}

#[test(tokio::test)]
// Kill before the post-validation checkpoint: only the intake
// checkpoint exists, so boot restarts the request from zero and the
// fact lands exactly once.
async fn tracker_request_reboots_from_zero_before_commit() {
    let (bootstrap, owner, dirs, _governance_id, subject_id) = setup().await;

    // Stuck validation cannot commit: a held ValidationRes never
    // lets this node finish it, so the kill below lands pre-commit
    // (first Validation sighting). The distribution hold below is
    // belt and braces: if the kill still landed post-commit, the
    // request parks in Distribution instead of finishing unseen, and
    // the reboot resumes it — same assertions either way.
    for (direction, message) in [
        (FaultDirection::Inbound, FaultMessage::ValidationRes),
        (
            FaultDirection::Outbound,
            FaultMessage::DistributionLastEventReq,
        ),
    ] {
        owner
            .api
            .test_install_fault(FaultRule {
                direction,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Hold,
            })
            .await
            .unwrap();
    }

    let payload = json!({"ModOne": {"data": 1}});
    let request_id =
        emit_fact(&owner.api, subject_id.clone(), payload.clone(), false)
            .await
            .unwrap();
    wait_validation_or_distribution(&owner.api, request_id.clone()).await;

    let owner = reboot_owner(&bootstrap, owner, &dirs).await;

    wait_request(&owner.api, request_id).await.unwrap();

    let state = get_subject(&owner.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let events = get_events(&owner.api, subject_id.clone(), 2, true)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    let last = events.last().unwrap();
    assert_eq!(last.sn, 1);
    assert_tracker_fact_full(&last.event, payload, &[]);
}

#[test(tokio::test)]
// Kill once the committed ledger checkpoint exists: boot resumes
// distribution with identical bytes instead of re-validating, so no
// second sn is ever allocated for the same fact.
async fn tracker_request_resumes_distribution_after_commit() {
    let (bootstrap, owner, dirs, _governance_id, subject_id) = setup().await;

    // Held distribution cannot finish: the manager is stuck in
    // Distribution with its checkpoint durable. Reaching that state
    // is observable, so the kill below always lands post-commit —
    // the tracking update travels after the checkpoint persist.
    owner
        .api
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let payload = json!({"ModOne": {"data": 2}});
    let request_id =
        emit_fact(&owner.api, subject_id.clone(), payload.clone(), false)
            .await
            .unwrap();
    wait_distribution(&owner.api, request_id.clone()).await;

    let owner = reboot_owner(&bootstrap, owner, &dirs).await;

    wait_request(&owner.api, request_id).await.unwrap();

    let state = get_subject(&owner.api, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let events = get_events(&owner.api, subject_id.clone(), 2, true)
        .await
        .unwrap();
    assert_eq!(events.len(), 2);
    let last = events.last().unwrap();
    assert_eq!(last.sn, 1);
    assert_tracker_fact_full(&last.event, payload, &[]);
}
