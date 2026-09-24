//! Integration tests for the approval phase of governance events: a
//! random set of validators collects the approvers' votes, the requester
//! closes the phase building the canonical approval evidence and the
//! validation phase runs afterwards with that evidence inside the
//! validation request, so the event commits (approved or rejected) with
//! the approval evidence anchored in the ledger.

use std::{
    collections::HashSet,
    str::FromStr,
    sync::atomic::Ordering,
    time::{Duration, Instant},
};

mod common;

use ave_common::{
    Namespace, SchemaType,
    bridge::{
        request::{ApprovalState, ApprovalStateRes},
        response::{EvalResDB, RequestEventDB},
    },
    identity::{
        HashAlgorithm, PublicKey, Signature, Signed, TimeStamp, hash_borsh,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
};
use ave_core::{
    Api,
    approval::{request::ApprovalReq, response::ApprovalRes},
    config::ApprovalConfig,
    helpers::network::{
        ActorMessage, NetworkMessage,
        test_faults::{FaultAction, FaultDirection, FaultMessage, FaultRule},
    },
    model::event::{ApprovalData, Protocols},
    subject::RequestSubjectData,
    validation::{
        request::{ActualProtocols, ValidationReq},
        response::ValidationRes,
    },
};

use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT,
    NodeData, PORT_COUNTER, create_and_authorize_governance, create_node,
    create_nodes_and_connections, create_subject, emit_approve, emit_fact,
    get_abort_request, get_events, get_subject, governance_properties,
    node_running, wait_request_state,
};
use futures::future::join_all;
use serde_json::{Value, json};
use tempfile::TempDir;
use test_log::test;

/// A node with an explicit `always_accept` flag, so approver nodes can
/// be manual while the owner auto-accepts.
async fn create_node_with(
    node_type: NodeType,
    always_accept: bool,
    peers: Vec<RoutingNode>,
    approval: Option<ApprovalConfig>,
) -> (NodeData, Vec<TempDir>) {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let (node, dirs) = create_node(CreateNodeConfig {
        node_type,
        listen_address,
        peers,
        always_accept,
        approval,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();
    (node, dirs)
}

/// Bootstrap owner plus two addressable approvers.
async fn owner_and_two_approvers(
    owner_always_accept: bool,
    approvers_always_accept: bool,
) -> (Vec<NodeData>, Vec<TempDir>) {
    let (owner, mut dirs) =
        create_node_with(NodeType::Bootstrap, owner_always_accept, vec![], None)
            .await;
    let mut nodes = vec![owner];
    for _ in 0..2 {
        let peers = vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }];
        let (node, mut node_dirs) = create_node_with(
            NodeType::Addressable,
            approvers_always_accept,
            peers,
            None,
        )
        .await;
        dirs.append(&mut node_dirs);
        nodes.push(node);
    }
    (nodes, dirs)
}

/// Short approval window for deadline-driven tests: 7 s window probed
/// at 1/2/4 s, 1 s keepalive.
fn short_window_approval() -> ApprovalConfig {
    ApprovalConfig {
        min_window_secs: 7,
        probe_schedule_secs: vec![1, 2, 4],
        keepalive_secs: 1,
    }
}

/// A node of the test network with everything needed to kill and
/// restart it keeping its databases. The bootstrap node doubles as the
/// relay every addressable node peers with and is never restarted, so
/// the network addressing survives any other restart.
struct TestNode {
    data: NodeData,
    dirs: Vec<TempDir>,
    always_accept: bool,
    approval: Option<ApprovalConfig>,
}

impl TestNode {
    async fn bootstrap() -> Self {
        let (data, dirs) =
            create_node_with(NodeType::Bootstrap, true, vec![], None).await;
        Self { data, dirs, always_accept: true, approval: None }
    }

    async fn addressable(
        network: &[TestNode],
        always_accept: bool,
        approval: Option<ApprovalConfig>,
    ) -> Self {
        let peers = vec![RoutingNode {
            peer_id: network[0].data.api.peer_id().to_string(),
            address: vec![network[0].data.listen_address.clone()],
        }];
        let (data, dirs) = create_node_with(
            NodeType::Addressable,
            always_accept,
            peers,
            approval.clone(),
        )
        .await;
        Self { data, dirs, always_accept, approval }
    }

    const fn api(&self) -> &Api {
        &self.data.api
    }

    fn public_key(&self) -> PublicKey {
        PublicKey::from_str(self.data.api.public_key()).unwrap()
    }

    /// Graceful stop: cancels the node and waits for its tasks.
    async fn kill(&mut self) {
        self.data.token.cancel();
        join_all(self.data.handler.iter_mut()).await;
    }

    /// Recreates the node with the same identity and databases, peering
    /// with the relay (peer id + listen address).
    async fn restart(&mut self, relay_peer_id: &str, relay_address: &str) {
        let peers = vec![RoutingNode {
            peer_id: relay_peer_id.to_owned(),
            address: vec![relay_address.to_owned()],
        }];
        let (data, new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!(
                "/memory/{}",
                PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
            ),
            peers,
            always_accept: self.always_accept,
            keys: Some(self.data.keys.clone()),
            local_db: Some(self.dirs[0].path().to_path_buf()),
            ext_db: Some(self.dirs[1].path().to_path_buf()),
            approval: self.approval.clone(),
            ..Default::default()
        })
        .await;
        // Both databases were passed in, so no new directories were
        // created; the original ones keep the storage alive.
        drop(new_dirs);
        self.data = data;
        node_running(&self.data.api).await.unwrap();
    }
}

/// Polling with a generous cap for failure-recovery scenarios (the
/// default 30 s of `get_subject` is not enough when reboots and backoff
/// are involved).
async fn wait_subject_sn(
    node: &Api,
    subject_id: ave_common::identity::DigestIdentifier,
    sn: u64,
    max_secs: u64,
) {
    let attempts = max_secs * 10 / 3;
    for _ in 0..attempts {
        if let Ok(state) = node.get_subject_state(subject_id.clone()).await
            && state.sn == sn
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timeout waiting for subject {subject_id} at sn {sn}");
}

/// Polls until the aborted request is recorded: the abort is a tell, so
/// the record lands asynchronously (`get_abort_request` returns as soon
/// as the query answers, even with an empty page).
async fn wait_abort_recorded(
    node: &Api,
    subject_id: ave_common::identity::DigestIdentifier,
    request_id: ave_common::identity::DigestIdentifier,
) {
    for _ in 0..100 {
        let aborts =
            get_abort_request(node, subject_id.clone(), request_id.clone())
                .await
                .unwrap();
        if !aborts.events.is_empty() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    panic!("timeout waiting for the abort record of {request_id}");
}

/// Builds a signed vote for the given approval request, exactly as the
/// approver would send it (used to inject byzantine votes).
fn craft_vote(
    req: &ApprovalReq,
    governance_id: &ave_common::identity::DigestIdentifier,
    byzantine: &KeyPair,
    agrees: bool,
) -> Signed<ApprovalRes> {
    let hasher = HashAlgorithm::Blake3.hasher();
    let approval_req_hash = hash_borsh(&*hasher, req).unwrap();
    let req_subject_data_hash = hash_borsh(
        &*hasher,
        &RequestSubjectData {
            subject_id: req.subject_id.clone(),
            governance_id: governance_id.clone(),
            namespace: Namespace::new(),
            schema_id: SchemaType::Governance,
            sn: req.sn,
            gov_version: req.gov_version,
            signer: req.signer.clone(),
        },
    )
    .unwrap();
    Signed::new(
        ApprovalRes::Response {
            approval_req_hash,
            agrees,
            req_subject_data_hash,
        },
        byzantine,
    )
    .unwrap()
}

/// Delivers a vote to a validator node as if it came from the network.
async fn inject_vote(
    validator: &Api,
    validator_key: &PublicKey,
    governance_id: &ave_common::identity::DigestIdentifier,
    vote: Signed<ApprovalRes>,
    request_id: &ave_common::identity::DigestIdentifier,
    version: u64,
    from: &PublicKey,
) {
    validator
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: request_id.to_string(),
                    version,
                    receiver: validator_key.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/validator"
                    ),
                },
                message: ActorMessage::ApprovalRes { res: Box::new(vote) },
            },
            from,
        )
        .await
        .unwrap();
}

/// Tells a byzantine vote straight into a validator worker's mailbox,
/// retrying until the worker exists: once queued, the worker processes
/// it before anything that arrives at the same mailbox afterwards.
async fn tell_vote_to_worker(
    node: &Api,
    worker_actor: &str,
    vote: Signed<ApprovalRes>,
    request_id: &ave_common::identity::DigestIdentifier,
    version: u64,
    from: &PublicKey,
) {
    for _ in 0..50 {
        if node
            .test_tell_approval_vote(
                worker_actor,
                vote.clone(),
                &request_id.to_string(),
                version,
                from.clone(),
            )
            .await
            .is_ok()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("validator worker {worker_actor} never came up");
}

/// Delivers an approval request probe to an approver node as if it came
/// from `from` over the network.
async fn inject_ask(
    approver: &Api,
    approver_key: &PublicKey,
    governance_id: &ave_common::identity::DigestIdentifier,
    signed_req: Signed<ApprovalReq>,
    request_id: &ave_common::identity::DigestIdentifier,
    version: u64,
    from: &PublicKey,
) {
    approver
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: request_id.to_string(),
                    version,
                    receiver: approver_key.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/approver"
                    ),
                },
                message: ActorMessage::ApprovalReq {
                    req: signed_req,
                    asker_actor: format!(
                        "/user/node/subject_manager/{governance_id}/validator"
                    ),
                },
            },
            from,
        )
        .await
        .unwrap();
}

/// Governance fact that adds the two approver members with approver and
/// witness roles and sets the approve policy to a fixed quorum of 2.
/// Applied under the genesis policy, only the owner's vote is needed.
fn two_approvers_setup(approver_1: &Api, approver_2: &Api) -> Value {
    json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 2
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    })
}

/// Trivial governance change used as the event under approval.
fn add_fake_member(name: &str) -> Value {
    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    json!({
        "members": {
            "add": [
                {
                    "name": name,
                    "key": fake_node
                }
            ]
        }
    })
}

/// The governance event at `sn` committed with the expected approval
/// outcome. `events` must already contain every event up to `sn`.
fn assert_approval_outcome(
    events: &[ave_common::response::LedgerDB],
    sn: usize,
    expected: Option<bool>,
) {
    match &events[sn].event {
        RequestEventDB::GovernanceFact {
            evaluation_response,
            approval_success,
            ..
        } => {
            assert_eq!(*approval_success, expected);
            match evaluation_response {
                EvalResDB::Patch(_) => {}
                other => panic!("unexpected evaluation result: {other:?}"),
            }
        }
        other => panic!("unexpected event at sn {sn}: {other:?}"),
    }
}

#[test(tokio::test)]
// Happy path: every approver auto-accepts, the approval phase closes on
// its own and the validation phase starts right after with the closed
// approval evidence inside the validation request — pinned by holding
// the request itself and inspecting it. No manual intervention and no
// deadline wait.
async fn test_approval_auto_commit_evidence() {
    let (nodes, _dirs) = owner_and_two_approvers(true, true).await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;
    let approver_1_pk = PublicKey::from_str(approver_1.public_key()).unwrap();

    let governance_id = create_and_authorize_governance(
        owner,
        vec![approver_1, approver_2],
    )
    .await;

    // Approver1 doubles as a validator with a fixed quorum of 2, so the
    // validation request always crosses the network.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"],
                    "validator": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Hold the validation request headed to Approver1: once it is held
    // the approval phase is already closed and the evidence must travel
    // inside the request.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ValidationReq,
            peer: Some(approver_1_pk.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // Approvers = {Owner, Approver1, Approver2}, quorum fixed 2: all
    // three auto-accept, the approval closes on its own.
    let json = add_fake_member("AveNode1");
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let signed_req = wait_held_validation_req(owner, &approver_1_pk).await;
    let ValidationReq::Event { actual_protocols, .. } = signed_req.content()
    else {
        panic!("a governance fact must produce an event validation request");
    };
    let ActualProtocols::EvalApprove { approval_data, .. } =
        actual_protocols.as_ref()
    else {
        panic!("the validation request must carry the approval evidence");
    };
    assert!(approval_data.approved);
    // The phase closes the instant the quorum (fixed 2) is reached, so
    // a third vote already in flight may not make it into the evidence.
    assert!(approval_data.approvers_agrees_signatures.len() >= 2);
    owner.test_release_held().await.unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(state.owner, owner.public_key());
    assert!(state.active);
    let properties = common::governance_properties(state.properties);
    assert_eq!(properties.version, 2);
    assert_eq!(properties.members.len(), 4);

    for approver in [approver_1, approver_2] {
        let state =
            get_subject(approver, governance_id.clone(), Some(2), true)
                .await
                .unwrap();
        assert_eq!(state.sn, 2);
    }

    // The ledger evidence shows the approved evaluation and approval.
    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 1, Some(true));
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Manual approval: the request parks in Approval with the votes pending;
// the operators approve and the event commits.
async fn test_approval_manual_pending_to_commit() {
    let (nodes, _dirs) = owner_and_two_approvers(true, false).await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![approver_1, approver_2],
    )
    .await;

    let json = two_approvers_setup(approver_1, approver_2);
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The owner auto-accepts; the request waits for the two manual
    // approvers in the Approval state.
    let request_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    let state =
        wait_request_state(owner, request_id.clone(), Some(RequestState::Approval))
            .await
            .unwrap();
    assert_eq!(state, RequestState::Approval);

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let state =
        wait_request_state(owner, request_id, Some(RequestState::Finish))
            .await
            .unwrap();
    assert_eq!(state, RequestState::Finish);

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = common::governance_properties(state.properties);
    assert_eq!(properties.version, 2);
    assert_eq!(properties.members.len(), 4);

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Rejection commits the event with approved=false: the ledger advances
// but the governance state is not patched.
async fn test_approval_rejection_commits_event() {
    let (nodes, _dirs) = owner_and_two_approvers(true, false).await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![approver_1, approver_2],
    )
    .await;

    let json = two_approvers_setup(approver_1, approver_2);
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let request_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    // The rejected event commits: sn advances, the state does not.
    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = common::governance_properties(state.properties);
    assert_eq!(properties.version, 1);
    assert_eq!(properties.members.len(), 3);
    assert!(!properties.members.contains_key("AveNode1"));

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(false));
}

#[test(tokio::test)]
// Early rejection: once the remaining approvers cannot reach quorum the
// approval closes immediately, without waiting for the approval window
// (300 s in tests): a commit well under that proves the early exit.
async fn test_approval_early_rejection_no_deadline_wait() {
    let (nodes, _dirs) = owner_and_two_approvers(true, false).await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![approver_1, approver_2],
    )
    .await;

    let json = two_approvers_setup(approver_1, approver_2);
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let start = Instant::now();
    let request_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();

    // Owner auto-accepts (1 agree); two rejects make the quorum
    // unreachable (3 - 2 = 1 < 2) and close the approval at once.
    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 60,
        "early rejection must close long before the approval window, took {elapsed:?}"
    );

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(false));
}

#[test(tokio::test)]
// Regression: tracker facts of a non-governance subject follow the same
// flow as before (no approval collection, no Approval state).
async fn test_approval_non_gov_facts_unaffected() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let bootstrap = &nodes[0].api;
    let owner = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![bootstrap]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "boot",
                    "key": bootstrap.public_key()
                },
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
                    "witness": ["boot"]
                }
            },
            "tracker_schemas": {
                "add": {
                    "issuer": [
                        { "name": "Owner", "namespace": [] }
                    ]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "witness": [
                            { "name": "Owner", "namespace": [] },
                            { "name": "boot", "namespace": [] }
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
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(owner, governance_id, "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        owner,
        subject_id.clone(),
        json!({"ModOne": {"data": 100}}),
        true,
    )
    .await
    .unwrap();
    let request_id = emit_fact(
        owner,
        subject_id.clone(),
        json!({"ModOne": {"data": 200}}),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(owner, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        serde_json::json!({"one": 200, "two": 0, "three": 0})
    );

    // The request went straight to Finish, never parking in Approval.
    let state = wait_request_state(owner, request_id, None).await.unwrap();
    assert_eq!(state, RequestState::Finish);

    let state = get_subject(bootstrap, subject_id, Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
}

#[test(tokio::test)]
// The owner is the only approver while a second node is also a
// validator: both validators collect the owner's vote over the network
// like any other approver, and the event commits.
async fn test_approval_owner_is_approver_remote_validator() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let validator = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![validator]).await;

    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1"],
                    "validator": ["Validator1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": validator.public_key()
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Validators = {Owner, Validator1} (majority = 2), approver =
    // {Owner}: the owner votes as an approver and both validators
    // collect that vote during the approval phase.
    let json = add_fake_member("AveNode1");
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = common::governance_properties(state.properties);
    assert_eq!(properties.version, 2);

    let state = get_subject(validator, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test]
// The approval evidence committed in governance events round-trips
// through borsh and serde, both standalone and inside the validation
// request that carries it; the previous timeout-based format no longer
// deserializes.
fn approval_data_serialization_roundtrip() {
    let signer = Ed25519Signer::generate().unwrap();
    let mk_sig = |content: &[u8]| {
        Signature::new(&content.to_vec(), &signer).unwrap()
    };

    let data = ApprovalData {
        approval_req_signature: mk_sig(b"approval request"),
        approval_req_hash: ave_common::identity::hash_borsh(
            &*ave_common::identity::HashAlgorithm::Blake3.hasher(),
            &b"request".to_vec(),
        )
        .unwrap(),
        issued_at: TimeStamp::now(),
        deadline: TimeStamp::now(),
        approvers_agrees_signatures: vec![mk_sig(b"yes"), mk_sig(b"yes 2")],
        approvers_disagrees_signatures: vec![mk_sig(b"no")],
        double_votes: vec![(mk_sig(b"double yes"), mk_sig(b"double no"))],
        approvers_timeouts: vec![(
            KeyPair::Ed25519(signer.clone()).public_key(),
            vec![mk_sig(b"timeout 1"), mk_sig(b"timeout 2")],
        )],
        approved: true,
    };

    // Borsh round-trip is byte-exact.
    let bytes = borsh::to_vec(&data).unwrap();
    let back: ApprovalData = borsh::from_slice(&bytes).unwrap();
    assert_eq!(borsh::to_vec(&back).unwrap(), bytes);

    // Serde round-trip is value-exact.
    let json = serde_json::to_value(&data).unwrap();
    let back: ApprovalData = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);

    // The old evidence format (timeout list, no window timestamps nor
    // double-vote evidence) fails to deserialize.
    let mut old = json.clone();
    let map = old.as_object_mut().unwrap();
    map.remove("issued_at");
    map.remove("deadline");
    map.remove("double_votes");
    map.insert("approvers_timeout".to_owned(), json!([]));
    assert!(serde_json::from_value::<ApprovalData>(old).is_err());

    // Truncated borsh fails too.
    assert!(
        borsh::from_slice::<ApprovalData>(&bytes[..bytes.len() - 1]).is_err()
    );

    // The evidence travels inside the validation request: the approve
    // protocol variants carry the closed `ApprovalData`, which must
    // round-trip byte-exact as part of them.
    let protocols = ActualProtocols::EvalApprove {
        eval_data: ave_core::model::event::EvaluationData {
            eval_req_signature: mk_sig(b"eval request"),
            eval_req_hash: ave_common::identity::hash_borsh(
                &*ave_common::identity::HashAlgorithm::Blake3.hasher(),
                &b"eval request".to_vec(),
            )
            .unwrap(),
            evaluators_signatures: vec![mk_sig(b"eval")],
            response: ave_core::model::event::EvaluationResponse::Error {
                result: ave_core::evaluation::response::EvaluatorError::InternalError(
                    "boom".to_owned(),
                ),
                result_hash: ave_common::identity::hash_borsh(
                    &*ave_common::identity::HashAlgorithm::Blake3.hasher(),
                    &b"eval error".to_vec(),
                )
                .unwrap(),
            },
        },
        approval_data: data,
    };
    let bytes = borsh::to_vec(&protocols).unwrap();
    let back: ActualProtocols = borsh::from_slice(&bytes).unwrap();
    assert_eq!(borsh::to_vec(&back).unwrap(), bytes);
    let json = serde_json::to_value(&protocols).unwrap();
    let back: ActualProtocols = serde_json::from_value(json.clone()).unwrap();
    assert_eq!(serde_json::to_value(&back).unwrap(), json);
}


#[test(tokio::test)]
// Approver offline: its absence is attested at the deadline by the
// approval validators and the event commits accepted once the absent
// count reaches quorum. The window is 7 s, so a commit well under 90 s
// and over 6 s pins the deadline-driven close (2 agrees of quorum 3 can
// never close early). The validation phase afterwards verifies the
// attestations data-only, with its own fresh validator draw.
async fn test_approval_offline_approver_absent_at_deadline() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api();
    let approver = nodes[2].api();

    let governance_id =
        create_and_authorize_governance(owner, vec![approver]).await;

    let ghost = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // Approvers = {Owner, Approver1, Ghost}, quorum fixed 3. Validators =
    // {Owner, Approver1} fixed 2: both collect the votes during the
    // approval phase and both attest the ghost's timeout.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 3 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1"],
                    "approver": ["Approver1", "Ghost"],
                    "validator": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver.public_key()
                },
                {
                    "name": "Ghost",
                    "key": ghost
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Owner and Approver1 vote (2 < 3); Ghost never answers. At the
    // deadline the absent vote counts as acceptance: 2 + 1 >= 3.
    let start = Instant::now();
    emit_fact(owner, governance_id.clone(), add_fake_member("AveNode1"), false)
        .await
        .unwrap();

    wait_subject_sn(owner, governance_id.clone(), 2, 90).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(6) && elapsed < Duration::from_secs(90),
        "deadline-driven close expected around 7 s, took {elapsed:?}"
    );

    let state = get_subject(approver, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // Evidence pin: the ghost never voted, so its absence is attested by
    // the approval collectors (the owner and Approver1) — the timeout
    // entry carries one validator-signed attestation per collector, and
    // no vote appears for the ghost.
    let ghost_pk = PublicKey::from_str(&ghost).unwrap();
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        validation,
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(approval.approvers_agrees_signatures.len(), 2);
    assert!(
        approval
            .approvers_agrees_signatures
            .iter()
            .all(|signature| signature.signer != ghost_pk)
    );
    let (_, attestations) = approval
        .approvers_timeouts
        .iter()
        .find(|(who, _)| *who == ghost_pk)
        .expect("the ghost absence must be attested by validators");
    let attesters: HashSet<PublicKey> = attestations
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    assert_eq!(
        attesters,
        HashSet::from([nodes[1].public_key(), nodes[2].public_key()])
    );
    assert_eq!(validation.validators_signatures.len(), 2);
}

#[test(tokio::test)]
// Deadline tick with zero votes: nothing can close the collection before
// the deadline (no quorum, no early rejection), so the commit around the
// 7 s mark pins the timer firing at the deadline itself. The approval
// phase closes there and only then does the validation phase run.
async fn test_approval_deadline_tick_closes_without_votes() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, false, Some(short)).await);
    let owner = nodes[1].api();

    let governance_id = create_and_authorize_governance(owner, vec![]).await;

    let ghost = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // Approvers = {Owner, Ghost}, quorum fixed 2. The owner is manual:
    // it approves this setup fact but stays silent for the next one.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 2
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["Ghost"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Ghost",
                    "key": ghost
                }
            ]
        }
    });
    let request_id =
        emit_fact(owner, governance_id.clone(), json, true).await.unwrap();
    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    // Nobody votes: at the deadline the two absences reach quorum.
    let start = Instant::now();
    emit_fact(owner, governance_id.clone(), add_fake_member("AveNode1"), false)
        .await
        .unwrap();

    wait_subject_sn(owner, governance_id.clone(), 2, 90).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(6) && elapsed < Duration::from_secs(90),
        "deadline-tick close expected around 7 s, took {elapsed:?}"
    );

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // Evidence pin: nobody voted, so both absences carry their timeout
    // attestation signed by the only validator (the owner itself).
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert!(approval.approvers_agrees_signatures.is_empty());
    assert_eq!(
        approval
            .approvers_timeouts
            .iter()
            .map(|(who, _)| who.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([
            nodes[1].public_key(),
            PublicKey::from_str(&ghost).unwrap()
        ])
    );
    assert!(
        approval
            .approvers_timeouts
            .iter()
            .all(|(_, attestations)| {
                attestations.len() == 1
                    && attestations[0].signer == nodes[1].public_key()
            })
    );
}

#[test(tokio::test)]
// Validator restart mid-collection: the validator is killed right after
// emission (before its ACK) and restarted a few seconds later; the
// requester retries the collection delivery, the validator re-asks the
// approvers (their votes are persisted and resent) and the event
// commits. Validators = {Owner, Validator1} with quorum fixed 2, so the
// selection is deterministic.
async fn test_approval_validator_restart_mid_collection() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    let owner = nodes[1].api().clone();
    let val1_pk = nodes[2].public_key();
    let approver = nodes[3].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), &approver],
    )
    .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": val1_pk
                },
                {
                    "name": "Approver1",
                    "key": approver.public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Emit and kill the remote validator before it can ACK.
    emit_fact(&owner, governance_id.clone(), add_fake_member("AveNode1"), false)
        .await
        .unwrap();
    nodes[2].kill().await;

    tokio::time::sleep(Duration::from_secs(4)).await;
    let relay_peer = nodes[0].data.api.peer_id().to_string();
    let relay_addr = nodes[0].data.listen_address.clone();
    nodes[2].restart(&relay_peer, &relay_addr).await;

    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Validator crash with a reserve in the pool: validators = {Owner,
// Validator1, Validator2} with quorum fixed 2 (two are selected at
// random, one stays in reserve). Validator1 is killed mid-collection:
// when it was selected, the requester drops it after a silent keepalive
// round and replaces it from the reserve; when it was not selected the
// round is unaffected. Either way the approval must complete once the
// manual approver votes.
async fn test_approval_validator_crash_replaced_from_pool() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();
    let approver = nodes[4].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), &approver],
    )
    .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Validator2", "Approver1"],
                    "validator": ["Validator1", "Validator2"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Validator2",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": approver.public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();
    nodes[2].kill().await;

    // Let the keepalive drop the crashed validator and the replacement
    // register as asker, then cast the manual vote.
    tokio::time::sleep(Duration::from_secs(4)).await;
    emit_approve(
        &approver,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Replacement after the deadline expired: nobody votes, so the
// collection closes at the 7 s deadline by absent attestation; the
// crashed validator is dropped once its delivery retry runs out and its
// replacement re-asks the approvers once and, with the deadline already
// lapsed, signs and pushes its own timeout attestation immediately,
// completing the accounting. Selection of two of the three validators is
// random, so the replacement path runs only when Validator1 was
// selected; the commit is deterministic either way.
async fn test_approval_replacement_after_deadline_immediate_close() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    let ghost = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // Approvers = {Owner, Ghost} fixed 2: the owner auto-accepts, the
    // ghost never votes. Validators = {Owner, Validator1, Validator2}
    // fixed 2.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Validator2"],
                    "validator": ["Validator1", "Validator2"],
                    "approver": ["Ghost"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Validator2",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Ghost",
                    "key": ghost
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Owner auto-accepts (1 < 2), Ghost never votes: close at deadline.
    let start = Instant::now();
    emit_fact(&owner, governance_id.clone(), add_fake_member("AveNode1"), false)
        .await
        .unwrap();
    nodes[2].kill().await;

    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(6),
        "collection can only close at the deadline, took {elapsed:?}"
    );

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Requester restart mid-collection: the owner is killed while the
// approval waits for the manual approver and restarted a few seconds
// later; on recovery it re-surveys the validators, receives the
// persisted votes and the event commits.
async fn test_approval_owner_restart_mid_collection() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1, Approver2} fixed 3: the manual Approver2 blocks any
    // early close.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 3 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1", "Approver2"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    nodes[1].kill().await;
    tokio::time::sleep(Duration::from_secs(3)).await;

    // Approver2 votes while the requester is down: its vote is persisted
    // at the approver and resent on the recovery re-survey.
    emit_approve(
        nodes[4].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let relay_peer = nodes[0].data.api.peer_id().to_string();
    let relay_addr = nodes[0].data.listen_address.clone();
    nodes[1].restart(&relay_peer, &relay_addr).await;
    let owner = nodes[1].api().clone();

    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Abort mid-collection: the aborted request leaves no event and the
// next request runs a fresh approval round that commits.
async fn test_approval_owner_abort_mid_collection() {
    let (nodes, _dirs) = owner_and_two_approvers(true, false).await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![approver_1, &nodes[2].api],
    )
    .await;

    let json = two_approvers_setup(approver_1, &nodes[2].api);
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The owner auto-accepts (1 < 2): the request parks in Approval.
    let request_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    let state =
        wait_request_state(owner, request_id.clone(), Some(RequestState::Approval))
            .await
            .unwrap();
    assert_eq!(state, RequestState::Approval);

    owner.manual_request_abort(governance_id.clone()).await.unwrap();

    // The abort is recorded and the ledger did not advance.
    wait_abort_recorded(owner, governance_id.clone(), request_id.clone()).await;
    let state = get_subject(owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // A fresh request commits through a fresh approval round.
    let request_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode2"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(owner, request_id.clone(), Some(RequestState::Approval))
        .await
        .unwrap();
    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    let state = wait_request_state(owner, request_id, Some(RequestState::Finish))
        .await
        .unwrap();
    assert_eq!(state, RequestState::Finish);

    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = governance_properties(state.properties);
    assert!(properties.members.contains_key("AveNode2"));
    assert!(!properties.members.contains_key("AveNode1"));

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Superseded request: a second fact queued behind a parked approval
// becomes active after the abort and commits with its own patch; the
// aborted request's patch never applies.
async fn test_approval_superseded_request_no_mixing() {
    let (nodes, _dirs) = owner_and_two_approvers(true, false).await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![approver_1, &nodes[2].api],
    )
    .await;

    let json = two_approvers_setup(approver_1, &nodes[2].api);
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // First request parks in Approval; the second queues behind it.
    let request_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(owner, request_id.clone(), Some(RequestState::Approval))
        .await
        .unwrap();
    let queued_id = emit_fact(
        owner,
        governance_id.clone(),
        add_fake_member("AveNode2"),
        false,
    )
    .await
    .unwrap();

    owner.manual_request_abort(governance_id.clone()).await.unwrap();

    wait_abort_recorded(owner, governance_id.clone(), request_id.clone()).await;

    // The queued request becomes active and runs its own approval round.
    wait_request_state(owner, queued_id.clone(), Some(RequestState::Approval))
        .await
        .unwrap();
    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        queued_id.clone(),
        false,
    )
    .await
    .unwrap();
    let state = wait_request_state(owner, queued_id, Some(RequestState::Finish))
        .await
        .unwrap();
    assert_eq!(state, RequestState::Finish);

    // sn 2 carries the second fact's patch, not the aborted one's.
    let state = get_subject(owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2);
    let properties = governance_properties(state.properties);
    assert!(properties.members.contains_key("AveNode2"));
    assert!(!properties.members.contains_key("AveNode1"));

    let events = get_events(owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Validator state TTL: the requester disappears past the approval
// deadline plus the keepalive grace, so the remote validator's
// collection expires; on recovery the validator re-collects from the
// approvers (their votes are persisted) and the event commits. The
// purge itself is internal to the validator, so the test pins that it
// does not block the recovery.
async fn test_approval_validator_state_expires_after_ttl() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short)).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1} fixed 2: the manual Approver1 blocks any early close.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The owner auto-accepts (1 < 2): the request parks in Approval.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;
    nodes[1].kill().await;
    // The 7 s deadline plus the 2 x 1 s keepalive grace lapse: the
    // remote validator's collection is long expired.
    tokio::time::sleep(Duration::from_secs(12)).await;

    // The manual approver votes with the requester down: the vote is
    // persisted at the approver and resent on the recovery re-ask.
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let relay_peer = nodes[0].data.api.peer_id().to_string();
    let relay_addr = nodes[0].data.listen_address.clone();
    nodes[1].restart(&relay_peer, &relay_addr).await;
    let owner = nodes[1].api().clone();

    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Late vote after the close: the approval phase closes early with the
// auto-accept votes and the validation request is held before reaching
// the remote validator; a vote injected into the validator afterwards
// finds no collection (purged at the close) and is discarded, and the
// event commits in the first validation round with exactly the votes the
// requester closed with. A manual approver answering its pending
// approval entity once the request is over is likewise a no-op, and the
// next request proceeds normally.
async fn test_approval_late_vote_after_close_ignored() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();
    let owner_pk = nodes[1].public_key();
    let val1_pk = nodes[2].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1, Approver2} fixed 2. Approver2 is manual and silent.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1", "Approver2"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Hold the validation request headed to Validator1: once it is held
    // the approval phase is already closed at the owner while Validator1
    // still keeps its collection (the purge rides on that same held
    // validation request).
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ValidationReq,
            peer: Some(val1_pk.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    wait_held_validation_req(&owner, &val1_pk).await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    // Approver2's vote reaches Validator1 after the close: the
    // collection is still alive there, so the vote is merged and pushed
    // to the owner, whose approval phase is already closed and discards
    // every vote report. The vote echoes the request manager version
    // tracked for the request (the collection gated on it), not the
    // governance version.
    let (req, _) = nodes[4]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let vote = craft_vote(&req, &governance_id, &nodes[4].data.keys, true);
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    inject_vote(
        nodes[2].api(),
        &val1_pk,
        &governance_id,
        vote,
        &request_id,
        version,
        &nodes[4].public_key(),
    )
    .await;

    tokio::time::sleep(Duration::from_secs(1)).await;

    // The validation request flows: Validator1 verifies the closed
    // evidence data-only and signs. No reboot is involved: the whole
    // flow must finish well under a timeout+backoff cycle.
    let released = Instant::now();
    owner.test_release_held().await.unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 60).await;
    assert!(
        released.elapsed() < Duration::from_secs(15),
        "first-round commit expected, took {:?}",
        released.elapsed()
    );

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // Content pin: the committed evidence is exactly what the requester
    // closed with — owner and Approver1 as agrees, Approver2 absent, no
    // double votes, no timeout attestations (early closure) — and the
    // full validator quorum signed that same package. The post-close
    // vote never entered the ledger.
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        validation,
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    let agrees: HashSet<PublicKey> = approval
        .approvers_agrees_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    assert_eq!(
        agrees,
        HashSet::from([owner_pk.clone(), nodes[3].public_key()])
    );
    assert!(approval.approvers_disagrees_signatures.is_empty());
    assert!(approval.double_votes.is_empty());
    assert!(
        approval.approvers_timeouts.is_empty(),
        "early closure must not carry timeout attestations"
    );
    assert!(approval.approved);
    assert_eq!(validation.validators_signatures.len(), 2);

    // Approver2 answers its still-pending approval entity once the
    // request is over: depending on the local cleanup timing this is a
    // no-op or an error; either way the network ignores the late vote.
    tokio::time::sleep(Duration::from_secs(1)).await;
    let _ = nodes[4]
        .api()
        .approve(governance_id.clone(), ApprovalStateRes::Accepted)
        .await;

    // The next request runs its approval round unaffected.
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode2"),
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 3, 90).await;

    let events = get_events(&owner, governance_id.clone(), 4, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 3, Some(true));
}

#[test(tokio::test)]
// Double vote: an approver that signs accept and reject for the same
// request is excluded from the count and the pair is anchored as
// evidence; the remaining approvers count as absent at the deadline and
// the event commits accepted.
async fn test_approval_double_vote_excluded() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, false, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short)).await);
    let owner = nodes[1].api().clone();
    let owner_pk = nodes[1].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Approvers = {Owner, Approver1, Approver2} fixed 2, the owner is
    // the only validator. Everyone is manual.
    let json = two_approvers_setup(nodes[2].api(), nodes[3].api());
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let start = Instant::now();
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // Approver1 accepts legitimately, then a reject signed with the same
    // key goes straight into the mailbox of the ephemeral approval-phase
    // worker that holds the owner's collection for this request: the
    // pair is a double vote and Approver1 is excluded from the count.
    tokio::time::sleep(Duration::from_secs(2)).await;
    emit_approve(
        nodes[2].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    let (req, _) = nodes[2]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let vote = craft_vote(&req, &governance_id, &nodes[2].data.keys, false);
    // The vote must echo the request manager version tracked for the
    // request (the collection gates on it), not the governance version.
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    tell_vote_to_worker(
        &owner,
        &format!("/user/request/{governance_id}/approval/{owner_pk}"),
        vote,
        &request_id,
        version,
        &nodes[2].public_key(),
    )
    .await;

    // 0 agrees, 1 double vote: only the deadline can close the
    // collection, when the two remaining absences reach the quorum of 2.
    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(6),
        "only the deadline can close the collection, took {elapsed:?}"
    );

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // Evidence pin: Approver1 appears in no vote list; the double-vote
    // pair is anchored as the proof of its exclusion and the two silent
    // approvers carry their timeout attestations.
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert!(
        approval.approvers_agrees_signatures.is_empty(),
        "an excluded double voter must not count as an agree"
    );
    assert!(approval.approvers_disagrees_signatures.is_empty());
    assert_eq!(approval.double_votes.len(), 1);
    let (first, second) = &approval.double_votes[0];
    assert_eq!(first.signer, nodes[2].public_key());
    assert_eq!(second.signer, nodes[2].public_key());
    assert_eq!(
        approval
            .approvers_timeouts
            .iter()
            .map(|(approver, _)| approver.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([owner_pk.clone(), nodes[3].public_key()])
    );
}

#[test(tokio::test)]
// Forged approver votes never reach the tally: a vote from a
// non-approver key and a vote with a corrupt signature for a real
// approver go straight into the owner's worker mailbox, both are
// dropped (gates first, signature checked before merging) and the
// request still closes approved on the two honest accepts. Without
// the signature check the forged reject would pair with the honest
// accept into a false double vote.
async fn test_approval_forged_votes_ignored() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, false, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short)).await);
    let owner = nodes[1].api().clone();
    let owner_pk = nodes[1].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Approvers = {Owner, Approver1, Approver2} fixed 2, the owner is
    // the only validator. Everyone is manual.
    let json = two_approvers_setup(nodes[2].api(), nodes[3].api());
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    // (a) vote from a key outside the approver set, (b) reject content
    // carrying a real approver accept signature: the claimed signer
    // passes the membership gates but the signature check drops it.
    // Forged first, while the collection is guaranteed open: the
    // honest votes below would close it and stop the worker.
    let (req, _) = nodes[2]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let outsider = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let outsider_pk = outsider.public_key();
    let foreign = craft_vote(&req, &governance_id, &outsider, true);
    let ApprovalRes::Response {
        approval_req_hash,
        req_subject_data_hash,
        ..
    } = craft_vote(&req, &governance_id, &nodes[2].data.keys, true)
        .content()
        .clone()
    else {
        panic!("expected a response vote");
    };
    let forged = Signed::from_parts(
        ApprovalRes::Response {
            approval_req_hash,
            agrees: false,
            req_subject_data_hash,
        },
        craft_vote(&req, &governance_id, &nodes[2].data.keys, true)
            .signature()
            .clone(),
    );
    assert!(forged.verify().is_err());
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    let worker =
        format!("/user/request/{governance_id}/approval/{owner_pk}");
    tell_vote_to_worker(
        &owner,
        &worker,
        foreign,
        &request_id,
        version,
        &outsider_pk,
    )
    .await;
    tell_vote_to_worker(
        &owner,
        &worker,
        forged,
        &request_id,
        version,
        &nodes[2].public_key(),
    )
    .await;

    for approver in [&nodes[2], &nodes[3]] {
        emit_approve(
            approver.api(),
            governance_id.clone(),
            ApprovalStateRes::Accepted,
            request_id.clone(),
            false,
        )
        .await
        .unwrap();
    }

    // Two honest accepts close the collection: no exclusion, no
    // timeouts, approved.
    wait_subject_sn(&owner, governance_id.clone(), 2, 30).await;
    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(
        approval
            .approvers_agrees_signatures
            .iter()
            .map(|signature| signature.signer.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([nodes[2].public_key(), nodes[3].public_key()])
    );
    assert!(approval.approvers_disagrees_signatures.is_empty());
    assert!(approval.double_votes.is_empty());
    assert!(approval.approvers_timeouts.is_empty());
}

#[test(tokio::test)]
// Forged probes never alter the approver state: a validly signed
// request from a non-owner key and a request with a corrupt signature
// go straight into the approver mailbox, both are dropped (gates and
// signature check), the stored request is untouched and the honest
// vote still commits the event approved.
async fn test_approval_approver_ignores_forged_probes() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short)).await);
    let owner = nodes[1].api().clone();
    let owner_pk = nodes[1].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api()],
    )
    .await;

    // Approvers = {Owner, Approver1} fixed 2, the owner is the only
    // validator. The owner auto-accepts, Approver1 is manual.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": nodes[2].api().public_key()
                }
            ]
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // The real probe lands first: the approver stores it pending.
    tokio::time::sleep(Duration::from_secs(3)).await;
    let (stored, _) = nodes[2]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;

    // (a) valid signature from a non-owner key, (b) corrupt signature:
    // neither may touch the stored request. A different version routes
    // both through the first-delivery gates (same id+version would take
    // the re-ask path, which rightly ignores the content).
    let outsider = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let foreign = Signed::new(stored.clone(), &outsider).unwrap();
    inject_ask(
        nodes[2].api(),
        &nodes[2].public_key(),
        &governance_id,
        foreign,
        &request_id,
        version + 1,
        &outsider.public_key(),
    )
    .await;
    let corrupt = Signed::from_parts(
        stored.clone(),
        craft_vote(&stored, &governance_id, &nodes[2].data.keys, true)
            .signature()
            .clone(),
    );
    assert!(corrupt.verify().is_err());
    inject_ask(
        nodes[2].api(),
        &nodes[2].public_key(),
        &governance_id,
        corrupt,
        &request_id,
        version + 1,
        &owner_pk,
    )
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;

    let (kept, _) = nodes[2]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        hash_borsh(&*HashAlgorithm::Blake3.hasher(), &kept).unwrap(),
        hash_borsh(&*HashAlgorithm::Blake3.hasher(), &stored).unwrap(),
        "forged probes must not touch the stored request"
    );

    emit_approve(
        nodes[2].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 2, 30).await;
    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(
        approval
            .approvers_agrees_signatures
            .iter()
            .map(|signature| signature.signer.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([nodes[1].public_key(), nodes[2].public_key()])
    );
    assert!(approval.double_votes.is_empty());
    assert!(approval.approvers_timeouts.is_empty());
}

#[test(tokio::test)]
// Keepalive asks only carry the approvers still missing evidence: with
// two of three votes already merged, the held asks want exactly the
// silent approver, and the request still closes approved once it
// votes. Held asks are released before the next round so the answered
// validator is never mistaken for dead.
async fn test_approval_status_asks_only_want_missing_votes() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, false, Some(short)).await);
    let owner = nodes[1].api().clone();
    let a2_pk = nodes[4].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Approvers = {Owner, Approver1, Approver2} fixed 3, the only
    // validator is a fourth node. The owner and Approver1 auto-accept,
    // Approver2 stays silent so the collection outlives several
    // keepalive rounds.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 3 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2", "Validator1"],
                    "approver": ["Approver1", "Approver2"],
                    "validator": ["Validator1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                },
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                }
            ]
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    // Hold the owner's outbound asks: the validator keeps collecting
    // and pushing through the unheld paths while the asks pile up.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalStatusReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // Four keepalive rounds pile up; by the last one both auto votes
    // are merged, so the ask wants exactly the silent approver.
    wait_held_count(&owner, 4, 20).await;
    let held = owner.test_held_outbound().await.unwrap();
    let mut wants = vec![];
    for message in &held {
        if let ActorMessage::ApprovalStatusReq { wanted, .. } = &message.message
        {
            wants.push(wanted.clone());
        }
    }
    assert!(wants.len() >= 4, "expected four held asks, got {}", wants.len());
    assert_eq!(wants.pop().unwrap(), Some(HashSet::from([a2_pk])));
    owner.test_release_held().await.unwrap();

    // The silent approver votes: early closure with all three agrees.
    emit_approve(
        nodes[4].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 2, 30).await;
    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(
        approval
            .approvers_agrees_signatures
            .iter()
            .map(|signature| signature.signer.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([
            nodes[1].public_key(),
            nodes[3].public_key(),
            nodes[4].public_key()
        ])
    );
    assert!(approval.approvers_timeouts.is_empty());
}

#[test(tokio::test)]
// Probes are full only once: the owner holds its outbound probes to
// the approver and observes a full request first and hash pings
// afterwards. Released, the approver votes and the event commits.
async fn test_approval_probes_full_once_then_hash() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api()],
    )
    .await;

    // Approvers = {Owner, Approver1} fixed 2, the owner is the only
    // validator. Both auto-accept.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": nodes[2].api().public_key()
                }
            ]
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    for message in [
        FaultMessage::ApprovalReq,
        FaultMessage::ApprovalHashPing,
    ] {
        owner
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Hold,
            })
            .await
            .unwrap();
    }
    let _request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // First probe full, retries hash-only.
    wait_held_count(&owner, 2, 20).await;
    let held = owner.test_held_outbound().await.unwrap();
    let mut shapes = vec![];
    for message in &held {
        match &message.message {
            ActorMessage::ApprovalReq { .. } => shapes.push("full"),
            ActorMessage::ApprovalHashPing { .. } => shapes.push("ping"),
            _ => {}
        }
    }
    assert_eq!(shapes, vec!["full", "ping"]);
    owner.test_release_held().await.unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 30).await;
    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(
        approval
            .approvers_agrees_signatures
            .iter()
            .map(|signature| signature.signer.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([nodes[1].public_key(), nodes[2].public_key()])
    );
    assert!(approval.approvers_timeouts.is_empty());
}

#[test(tokio::test)]
// An approver that misses the full first probe recovers through
// `NeedFull`: its hash-only pings appoint one supplier validator,
// the supplier resends the full request out of schedule, and the
// approver votes. The event commits approved with both agrees.
async fn test_approval_need_full_recovers_missing_request() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api()],
    )
    .await;

    // Approvers = {Owner, Approver1} fixed 2, the owner is the only
    // validator. Both auto-accept.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": nodes[2].api().public_key()
                }
            ]
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    // Drop the first (full) probe to the approver: it only ever sees
    // hash pings and must recover through `NeedFull`.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalReq,
            peer: None,
            remaining: Some(1),
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    let _request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 30).await;
    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(
        approval
            .approvers_agrees_signatures
            .iter()
            .map(|signature| signature.signer.clone())
            .collect::<HashSet<_>>(),
        HashSet::from([nodes[1].public_key(), nodes[2].public_key()])
    );
    assert!(approval.approvers_disagrees_signatures.is_empty());
    assert!(approval.double_votes.is_empty());
    assert!(approval.approvers_timeouts.is_empty());
}

#[test(tokio::test)]
// Stale approver: the approver misses the previous event (its inbound
// distribution push is dropped), answers Unavailable to the next
// request's probe, resynchronizes through the network update channel
// and votes on a later probe; the event commits.
async fn test_approval_stale_approver_unavailable_then_votes() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    let owner = nodes[1].api().clone();
    let approver_2 = nodes[3].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Approvers = {Owner, Approver1, Approver2} fixed 3: every vote is
    // needed, so the collection can only close once the stale approver
    // catches up and votes.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 3 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&approver_2, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Approver2 stops receiving the distribution push of new events.
    nodes[3]
        .api()
        .test_install_fault(FaultRule {
            direction: FaultDirection::Inbound,
            message: FaultMessage::DistributionLastEventReq,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    // The request is built on governance v1: Approver2's local
    // governance is v1, so it votes normally.
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;

    // Approver2 never receives event 2: it stays at sn 1.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let state = approver_2.get_subject_state(governance_id.clone()).await.unwrap();
    assert_eq!(state.sn, 1, "approver2 must be stale before the next fact");

    // The next request is built on v2: Approver2 is behind, answers
    // Unavailable, resynchronizes and votes on a later probe.
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode2"),
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 3, 120).await;

    let events = get_events(&owner, governance_id.clone(), 4, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
    assert_approval_outcome(&events, 3, Some(true));

    // With the fault cleared, Approver2 catches up fully.
    approver_2.test_clear_faults().await.unwrap();
    approver_2.update_subject(governance_id.clone()).await.unwrap();
    let state = get_subject(&approver_2, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 3);
}

#[test(tokio::test)]
// Double vote with partial observation: the reject is injected only
// into the requester's worker while the remote validator observes just
// the legitimate accept. The closed evidence anchors the double-vote
// pair, which accounts for the vote the remote validator saw, so the
// validation verifies data-only and the event commits.
async fn test_approval_double_vote_partial_observation() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();
    let owner_pk = nodes[1].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1, Approver2} fixed 2. Approvers 1 and 2 are manual.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1", "Approver2"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The owner auto-accepts (1 < 2): the request parks in Approval.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    // Approver1's legitimate accept is held at the source so the
    // byzantine reject reaches the requester's worker first: the pair
    // forms deterministically when the accept is released.
    nodes[3]
        .api()
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // Approver1 casts its legitimate accept: it stays held at the
    // source and no validator observes it yet.
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    // A reject signed by Approver1 goes straight into the mailbox of
    // the requester's ephemeral approval-phase worker (the one holding
    // its collection for this request): it is queued before the held
    // accept is released, so the worker always merges the reject first.
    let (req, _) = nodes[3]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let vote = craft_vote(&req, &governance_id, &nodes[3].data.keys, false);
    // The vote must echo the request manager version tracked for the
    // request (the collection gates on it), not the governance version.
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    tell_vote_to_worker(
        &owner,
        &format!("/user/request/{governance_id}/approval/{owner_pk}"),
        vote,
        &request_id,
        version,
        &nodes[3].public_key(),
    )
    .await;

    // The accept flows: the requester's worker merges it against the
    // reject and excludes Approver1; Validator1 observes only the
    // accept.
    nodes[3].api().test_release_held().await.unwrap();

    // Approver2 completes the quorum: the closed evidence carries the
    // double-vote pair, which covers Validator1's observation of the
    // accept.
    emit_approve(
        nodes[4].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // Evidence pin: Approver1 is excluded — the quorum is {Owner,
    // Approver2}, not {Owner, Approver1} — the double-vote pair is
    // anchored as the proof, no timeout attestations exist (early
    // closure) and the validation quorum attested that same package: the
    // pair covers the accept the remote validator observed. If the
    // injected reject never landed, the approval would close at {Owner,
    // Approver1} with no double votes.
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        validation,
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    let agrees: HashSet<PublicKey> = approval
        .approvers_agrees_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    assert_eq!(
        agrees,
        HashSet::from([owner_pk.clone(), nodes[4].public_key()])
    );
    assert!(approval.approvers_disagrees_signatures.is_empty());
    assert_eq!(approval.double_votes.len(), 1);
    let (first, second) = &approval.double_votes[0];
    assert_eq!(first.signer, nodes[3].public_key());
    assert_eq!(second.signer, nodes[3].public_key());
    assert!(
        approval.approvers_timeouts.is_empty(),
        "early closure must not carry timeout attestations"
    );
    assert_eq!(validation.validators_signatures.len(), 2);
}

#[test(tokio::test)]
// Recovery re-survey: the requester restarts with the votes already
// cast at the remaining validator; the status exchange right after the
// collection acknowledgement delivers them and the approval closes at
// once, long before the 300 s window would.
async fn test_approval_owner_recovery_resurvey() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1, Approver2} fixed 2. Everyone manual but Validator1.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1", "Approver2"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();
    get_subject(&owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Nobody votes: the request parks in Approval.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    tokio::time::sleep(Duration::from_secs(1)).await;
    nodes[1].kill().await;

    // Both approvers vote while the requester is down: Validator1
    // collects the quorum on its own.
    for approver in [nodes[3].api().clone(), nodes[4].api().clone()] {
        emit_approve(
            &approver,
            governance_id.clone(),
            ApprovalStateRes::Accepted,
            request_id.clone(),
            false,
        )
        .await
        .unwrap();
    }
    tokio::time::sleep(Duration::from_secs(2)).await;

    let relay_peer = nodes[0].data.api.peer_id().to_string();
    let relay_addr = nodes[0].data.listen_address.clone();
    nodes[1].restart(&relay_peer, &relay_addr).await;
    let owner = nodes[1].api().clone();

    let recovered = Instant::now();
    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;
    // The re-survey closes the collection right away instead of waiting
    // out the 300 s window.
    assert!(
        recovered.elapsed() < Duration::from_secs(90),
        "recovery re-survey must close long before the window, took {:?}",
        recovered.elapsed()
    );

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Role matrix: the approval phase keeps working as other members gain
// validator and approver roles. The governance invariants protect the
// owner's basic roles, so the matrix varies the roles of the other
// members only.
async fn test_approval_owner_role_matrix() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // (a) approvers = {Owner}: auto-commits.
    emit_fact(&owner, governance_id.clone(), add_fake_member("AveNode1"), true)
        .await
        .unwrap();
    get_subject(&owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // (b) Validator1 joins as validator: validators = {Owner,
    // Validator1} (majority 2), approvers still {Owner}.
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1"],
                    "validator": ["Validator1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
    get_subject(&owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // (c) two validators sign, owner-only approval.
    emit_fact(&owner, governance_id.clone(), add_fake_member("AveNode2"), true)
        .await
        .unwrap();
    get_subject(&owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // (d) Approver1 joins as approver: this fact is still approved by
    // the owner alone.
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true).await.unwrap();
    get_subject(&owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    // (e) approvers = {Owner, Approver1} (majority 2): the owner
    // auto-accepts and Approver1 approves manually.
    let request_id =
        emit_fact(&owner, governance_id.clone(), add_fake_member("AveNode3"), true)
            .await
            .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    get_subject(&owner, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    // (f) Approver2 joins as approver and validator: the owner and
    // Approver1 approve (Approver2 is not an approver yet).
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver2"],
                    "validator": ["Approver2"],
                    "approver": ["Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    get_subject(&owner, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    // (g) approvers = {Owner, Approver1, Approver2} (majority 2): the
    // owner and Approver2 auto-accept. Validators = {Owner, Validator1,
    // Approver2} (majority 2): any two of the three sign.
    emit_fact(&owner, governance_id.clone(), add_fake_member("AveNode4"), true)
        .await
        .unwrap();
    let state = get_subject(&owner, governance_id.clone(), Some(7), true)
        .await
        .unwrap();

    let properties = governance_properties(state.properties);
    assert_eq!(properties.version, 7);
    assert_eq!(
        properties.roles_gov.validator,
        ["Approver2", "Owner", "Validator1"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );
    assert_eq!(
        properties.roles_gov.approver,
        ["Approver1", "Approver2", "Owner"]
            .into_iter()
            .map(str::to_owned)
            .collect()
    );

    let events = get_events(&owner, governance_id.clone(), 8, true)
        .await
        .unwrap();
    for sn in 1..=7 {
        assert_approval_outcome(&events, sn, Some(true));
    }
}

#[test(tokio::test)]
// Rogue asker: a member without the validator role re-sends the
// approval request to an approver; the approver's gate only accepts
// asks from governance validators, so the probe is ignored and the
// request stays pending until the legitimate flow closes it.
async fn test_approval_non_validator_ask_ignored() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Approvers = {Owner, Approver1, Approver2} fixed 2; the owner is
    // the only validator. Both remote approvers are manual.
    let json = two_approvers_setup(nodes[2].api(), nodes[3].api());
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The owner auto-accepts (1 < 2): the request parks in Approval.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    // Approver2 (not a validator) re-sends the request to Approver1:
    // the delivery and the re-ask are both ignored by the gate.
    let (req, _) = nodes[2]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let version = req.gov_version;
    let signed_req = Signed::new(req, &nodes[1].data.keys).unwrap();
    for _ in 0..2 {
        inject_ask(
            nodes[2].api(),
            &nodes[2].public_key(),
            &governance_id,
            signed_req.clone(),
            &request_id,
            version,
            &nodes[3].public_key(),
        )
        .await;
    }

    // The request is still pending for Approver1 and the ledger has not
    // advanced.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let pending = nodes[2]
        .api()
        .get_approval(governance_id.clone(), Some(ApprovalState::Pending))
        .await
        .unwrap();
    assert!(pending.is_some());
    let state = get_subject(&owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);

    // The legitimate round closes normally.
    emit_approve(
        nodes[2].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// The approver's validator gate follows governance changes: once a
// member loses the validator role its asks are ignored, while the new
// validator set keeps driving the approval rounds.
async fn test_approval_validator_set_follows_governance_changes() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Validator1 joins as validator, Approver1 as approver.
    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Approvers = {Owner, Approver1} (majority 2): owner auto + manual.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    get_subject(&owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Validator1 loses the validator role.
    let json = json!({
        "roles": {
            "governance": {
                "remove": {
                    "validator": ["Validator1"]
                }
            }
        }
    });
    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    get_subject(&owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    // Approver1 applies the change: its validator set is now {Owner}.
    get_subject(nodes[3].api(), governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // A new request parks in Approval (owner auto-accept, 1 < 2).
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode2"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    // Validator1 is no longer a validator: its ask is ignored.
    let (req, _) = nodes[3]
        .api()
        .get_approval(governance_id.clone(), None)
        .await
        .unwrap()
        .unwrap();
    let version = req.gov_version;
    let signed_req = Signed::new(req, &nodes[1].data.keys).unwrap();
    inject_ask(
        nodes[3].api(),
        &nodes[3].public_key(),
        &governance_id,
        signed_req,
        &request_id,
        version,
        &nodes[2].public_key(),
    )
    .await;

    tokio::time::sleep(Duration::from_secs(2)).await;
    let pending = nodes[3]
        .api()
        .get_approval(governance_id.clone(), Some(ApprovalState::Pending))
        .await
        .unwrap();
    assert!(pending.is_some());

    // The legitimate validator (the owner) closes the round.
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    let state = get_subject(&owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 4);

    let properties = governance_properties(state.properties);
    assert_eq!(
        properties.roles_gov.validator,
        ["Owner"].into_iter().map(str::to_owned).collect()
    );

    let events = get_events(&owner, governance_id.clone(), 5, true)
        .await
        .unwrap();
    for sn in 1..=4 {
        assert_approval_outcome(&events, sn, Some(true));
    }
}

#[test(tokio::test)]
// Pool exhausted: both remote validators are down, so every selection
// round ends with an empty pool and a timeout reboot (5 s backoff in
// tests); once the validators come back a round completes and the event
// commits. The selection of two of the three validators is random, but
// with the two remotes down every combination collapses the same way.
async fn test_approval_pool_exhausted_reboot_recovers() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1, Validator2} fixed 2, approvers =
    // {Owner, Approver1} fixed 2: everyone auto-accepts.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Validator2", "Approver1"],
                    "validator": ["Validator1", "Validator2"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Validator2",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    nodes[2].kill().await;
    nodes[3].kill().await;

    // No remote validator ever acknowledges: the round times out and
    // reboots in a loop.
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(25)).await;

    let relay_peer = nodes[0].data.api.peer_id().to_string();
    let relay_addr = nodes[0].data.listen_address.clone();
    nodes[2].restart(&relay_peer, &relay_addr).await;
    nodes[3].restart(&relay_peer, &relay_addr).await;

    wait_subject_sn(&owner, governance_id.clone(), 2, 300).await;

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Recovery past the deadline: the requester dies right after emission
// and comes back once the 7 s approval window has expired; the recovery
// re-survey finds the votes the remote validator collected and closes
// the collection immediately (the votes attest acceptance and the
// remaining absence counts at the deadline).
async fn test_approval_owner_recovery_after_deadline() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1, Approver2} fixed 2: everyone auto-accepts.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1", "Approver2"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let start = Instant::now();
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();
    nodes[1].kill().await;

    // Approver1 and Approver2 auto-vote: Validator1 collects the quorum
    // while the requester is down. The 7 s deadline lapses.
    tokio::time::sleep(Duration::from_secs(9)).await;

    let relay_peer = nodes[0].data.api.peer_id().to_string();
    let relay_addr = nodes[0].data.listen_address.clone();
    nodes[1].restart(&relay_peer, &relay_addr).await;
    let owner = nodes[1].api().clone();

    wait_subject_sn(&owner, governance_id.clone(), 2, 180).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(6),
        "the collection could only close after the deadline, took {elapsed:?}"
    );

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// Answer wins over timeout: an approver silent for the whole window gets
// its timeout signed and pushed by the validators at the deadline, but
// its late vote lands before the requester closes; the committed evidence
// carries the VOTE and no timeout attestation for that approver. The long
// keepalive keeps status asks out of the way so the held pushes drive the
// exact interleaving deterministically.
async fn test_approval_answer_wins_over_timeout() {
    let config = ApprovalConfig {
        min_window_secs: 7,
        probe_schedule_secs: vec![1, 2, 4],
        keepalive_secs: 3600,
    };
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(config.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(config.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(config)).await);
    let owner = nodes[1].api().clone();
    let validator_1 = nodes[2].api().clone();
    let approver_1 = nodes[3].api().clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&validator_1, &approver_1])
            .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1} fixed 2.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": validator_1.public_key()
                },
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Approver1's answers never leave its node during the window, and the
    // first two vote reports of Validator1 (the relayed owner vote and the
    // timeout attestation for Approver1) are held at the validator.
    approver_1
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    validator_1
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalVoteReport,
            peer: None,
            remaining: Some(2),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let start = Instant::now();
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // Wait until Validator1 holds exactly the relayed owner vote and the
    // timeout attestation for Approver1: the deadline has lapsed and the
    // timeouts are signed, but the requester cannot close (the attestation
    // quorum is 2 and only its local worker reported).
    let mut tries = 0;
    while validator_1.test_held_count().await.unwrap() < 2 {
        tries += 1;
        assert!(
            tries < 200,
            "validator1 never signed and pushed the timeout attestation"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // Approver1's late vote flows: the requester merges it and drops the
    // timeout attestations for the approver — the answer wins.
    approver_1.test_release_held().await.unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 60).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(6),
        "the collection could only close after the deadline, took {elapsed:?}"
    );

    validator_1.test_release_held().await.unwrap();

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // Evidence pin: Approver1 appears with its VOTE; the timeout
    // attestations signed at the deadline never reached the ledger.
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    let agrees: HashSet<PublicKey> = approval
        .approvers_agrees_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    assert_eq!(
        agrees,
        HashSet::from([nodes[1].public_key(), nodes[3].public_key()])
    );
    assert!(
        approval.approvers_timeouts.is_empty(),
        "a late answer wins over the timeout attestations"
    );
    assert!(approval.double_votes.is_empty());
}

/// Polls the node's held outbound traffic until a validation request to
/// `peer` appears and returns its signed content, so the test can craft
/// a consistent signed answer to it.
async fn wait_held_validation_req(
    node: &Api,
    peer: &PublicKey,
) -> Signed<ValidationReq> {
    for _ in 0..100 {
        if let Ok(held) = node.test_held_outbound().await {
            let req = held.iter().find_map(|message| {
                if message.info.receiver != *peer {
                    return None;
                }
                match &message.message {
                    ActorMessage::ValidationReq { req } => Some(req.clone()),
                    _ => None,
                }
            });
            if let Some(req) = req {
                return req;
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    panic!("timeout waiting for a held validation request to {peer}");
}

/// Polls until the node's fault rules hold at least `n` messages.
async fn wait_held_count(node: &Api, n: usize, secs: u64) {
    let start = Instant::now();
    loop {
        if let Ok(count) = node.test_held_count().await
            && count >= n
        {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(secs),
            "timeout waiting for {n} held messages"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

#[test(tokio::test)]
// A final validation response must attest the approval evidence carried
// by the request: a byzantine validator (a key the test owns, with no
// node behind it) signs a final response with no approval hash for a
// request that went through the approval phase. The requester must drop
// it — accepting it would validate the event on a signature over a
// package nobody produced — and the event never commits.
async fn test_validation_response_missing_approval_hash_rejected() {
    let nodes = vec![TestNode::bootstrap().await];
    let owner = nodes[0].api().clone();
    let owner_pk = nodes[0].public_key();

    let governance_id = create_and_authorize_governance(&owner, vec![]).await;

    // The fake validator is a key the test owns: no node runs it. It
    // joins the owner in the governance validation role (the owner's
    // basic governance roles are protected and cannot be removed) with
    // a fixed quorum of 2, so both are always selected. This setup fact
    // is still validated and approved by the owner alone (genesis
    // roles).
    let fake = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let fake_pk = fake.public_key();
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "FakeValidator",
                    "key": fake_pk.to_string()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "validator": ["FakeValidator"]
                }
            }
        },
        "policies": {
            "governance": {
                "change": {
                    "validate": { "fixed": 2 }
                }
            }
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Hold the validation request to the fake validator: it blackholes
    // the traffic and lets the test read the exact signed request.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ValidationReq,
            peer: Some(fake_pk.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // The coordinator exists once the validation request is held.
    let signed_req = wait_held_validation_req(&owner, &fake_pk).await;
    let hasher = HashAlgorithm::Blake3.hasher();
    let vali_req_hash = hash_borsh(&*hasher, &signed_req).unwrap();

    // The forgery: the final response for the right request but without
    // the approval hash, although the held request carries the closed
    // approval evidence, delivered as if it came from the network.
    let forgery = Signed::new(
        ValidationRes::Response {
            vali_req_hash,
            modified_metadata_without_propierties_hash: hash_borsh(
                &*hasher,
                &b"fake metadata".to_vec(),
            )
            .unwrap(),
            propierties_hash: hash_borsh(
                &*hasher,
                &b"fake properties".to_vec(),
            )
            .unwrap(),
            event_request_hash: hash_borsh(
                &*hasher,
                &b"fake request".to_vec(),
            )
            .unwrap(),
            viewpoints_hash: hash_borsh(
                &*hasher,
                &b"fake viewpoints".to_vec(),
            )
            .unwrap(),
            approval_data_hash: None,
        },
        &fake,
    )
    .unwrap();
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    owner
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: request_id.to_string(),
                    version,
                    receiver: owner_pk,
                    receiver_actor: format!(
                        "/user/request/{governance_id}/validation/{fake_pk}"
                    ),
                },
                message: ActorMessage::ValidationRes { res: forgery },
            },
            &fake_pk,
        )
        .await
        .unwrap();

    // The gate drops the response: the fake validator never answers for
    // real, so the fixed quorum of 2 is unreachable and the event never
    // commits (the requester drops it and reboots the phase once the
    // pool runs out). Without the gate the forged response counted as
    // the fake's signature and, together with the owner's honest one,
    // reached quorum: the event committed within seconds.
    tokio::time::sleep(Duration::from_secs(10)).await;
    let state = get_subject(&owner, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(
        state.sn, 1,
        "a response without the approval hash must not validate the event"
    );
}

#[test(tokio::test)]
// A final validation response for a request without an approval
// requirement must carry no approval hash: a byzantine validator (a key
// the test owns, with no node behind it) answers with a well-formed
// response except for an unexpected approval data hash. The requester
// must drop it — accepting it would validate the event on a response
// that attests evidence that does not exist — so the validator never
// answers for real, the phase reboots and a fresh request goes out.
async fn test_validation_unexpected_approval_hash_rejected() {
    let nodes = vec![TestNode::bootstrap().await];
    let owner = nodes[0].api().clone();
    let owner_pk = nodes[0].public_key();

    let governance_id = create_and_authorize_governance(&owner, vec![]).await;

    // Schema setup: the owner keeps every role of "Example" and is
    // issuer for tracker schemas (required to sign fact events).
    let json = json!({
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
            "tracker_schemas": {
                "add": {
                    "issuer": [
                        { "name": "Owner", "namespace": [] }
                    ]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "witness": [
                            { "name": "Owner", "namespace": [] }
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
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    // The fake validator (a key the test owns, no node behind it)
    // becomes the only validator of "Example".
    let fake = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let fake_pk = fake.public_key();
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "FakeValidator",
                    "key": fake_pk.to_string()
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "validator": [
                            { "name": "FakeValidator", "namespace": [] }
                        ]
                    },
                    "remove": {
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Hold every validation request to the fake validator.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ValidationReq,
            peer: Some(fake_pk.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        subject_id.clone(),
        json!({"ModOne": {"data": 100}}),
        false,
    )
    .await
    .unwrap();

    // The coordinator exists once the validation request is held; the
    // held request gives the exact hash the answer must echo.
    let signed_req = wait_held_validation_req(&owner, &fake_pk).await;
    let hasher = HashAlgorithm::Blake3.hasher();
    let vali_req_hash = hash_borsh(&*hasher, &signed_req).unwrap();
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;

    // The forgery: a final response for the right request but carrying
    // an approval data hash although this request has no approval
    // requirement, delivered as if it came from the network.
    let forgery = Signed::new(
        ValidationRes::Response {
            vali_req_hash,
            modified_metadata_without_propierties_hash: hash_borsh(
                &*hasher,
                &b"fake metadata".to_vec(),
            )
            .unwrap(),
            propierties_hash: hash_borsh(
                &*hasher,
                &b"fake properties".to_vec(),
            )
            .unwrap(),
            event_request_hash: hash_borsh(
                &*hasher,
                &b"fake request".to_vec(),
            )
            .unwrap(),
            viewpoints_hash: hash_borsh(
                &*hasher,
                &b"fake viewpoints".to_vec(),
            )
            .unwrap(),
            approval_data_hash: Some(
                hash_borsh(&*hasher, &b"fake approval".to_vec()).unwrap(),
            ),
        },
        &fake,
    )
    .unwrap();
    owner
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: request_id.to_string(),
                    version,
                    receiver: owner_pk,
                    receiver_actor: format!(
                        "/user/request/{subject_id}/validation/{fake_pk}"
                    ),
                },
                message: ActorMessage::ValidationRes { res: forgery },
            },
            &fake_pk,
        )
        .await
        .unwrap();

    // The gate drops the forged response: the fake validator never
    // answers for real, the phase reboots and a fresh validation request
    // is sent (and held). Without the gate the forged response, as the
    // only validator's answer, would validate the event on its own.
    wait_held_count(&owner, 2, 60).await;

    let state = get_subject(&owner, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    assert_eq!(
        state.sn, 0,
        "a response attesting a phantom approval must not validate the event"
    );
}

#[test(tokio::test)]
// Fresh validation set: the approval phase draws its collectors at
// random (observed on the wire below) and the validation phase draws a
// NEW independent set from the same role. Either set may overlap the
// other — verification is data-only — so the event commits with
// whatever validators the second draw picked.
async fn test_approval_validation_uses_fresh_random_set() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api(), nodes[4].api()],
    )
    .await;

    // Validators = {Owner, Validator1, Validator2} fixed 2, approvers =
    // {Owner, Approver1} fixed 2: everyone auto-accepts.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Validator2", "Approver1"],
                    "validator": ["Validator1", "Validator2"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Validator2",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[4].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let role: HashSet<PublicKey> = [
        nodes[1].public_key(),
        nodes[2].public_key(),
        nodes[3].public_key(),
    ]
    .into_iter()
    .collect();

    // Watch the approval collectors on the wire: the draw is two of the
    // three role members, and a local draw (the owner collecting its own
    // request) never crosses the network, so one or two requests are
    // held.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalCollectReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    wait_held_count(&owner, 1, 30).await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let collectors: HashSet<PublicKey> = owner
        .test_held_outbound()
        .await
        .unwrap()
        .iter()
        .map(|message| message.info.receiver.clone())
        .collect();
    owner.test_release_held().await.unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;

    // The observed collectors are a subset of the validation role.
    assert!(!collectors.is_empty());
    assert!(collectors.is_subset(&role));

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));

    // The validation was signed by a full quorum drawn from the role —
    // its own fresh selection, not necessarily the collectors above —
    // over the closed approval evidence.
    let ledger_event = owner
        .test_get_ledger_event(governance_id.clone(), 2)
        .await
        .unwrap();
    let Protocols::GovFact {
        approval: Some(approval),
        validation,
        ..
    } = ledger_event.protocols
    else {
        panic!("expected a governance fact with approval evidence");
    };
    assert!(approval.approved);
    assert_eq!(validation.validators_signatures.len(), 2);
    assert!(
        validation
            .validators_signatures
            .iter()
            .all(|signature| role.contains(&signature.signer))
    );
}

#[test(tokio::test)]
// Collector reuse purge: the same validator collects the approval votes
// and then validates the request — receiving the closed evidence inside
// the validation request purges its collection. A conflicting vote
// injected afterwards is discarded instead of producing a vote report.
async fn test_approval_close_lost_leaves_no_residue() {
    let short = short_window_approval();
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(short)).await);
    let owner = nodes[1].api().clone();
    let val1_pk = nodes[2].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1} fixed 2: everyone auto-accepts, so the approval closes
    // early.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    // Capture the approval request and the request manager version for
    // the probe below.
    let mut probe_req = None;
    for _ in 0..50 {
        if let Some((req, _)) = nodes[3]
            .api()
            .get_approval(governance_id.clone(), None)
            .await
            .unwrap()
        {
            probe_req = Some(req);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let probe_req = probe_req.expect("approver never received the request");
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;

    // The purged collection blocks nothing: the event commits early,
    // long before the 7 s window.
    let start = Instant::now();
    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;
    assert!(
        start.elapsed() < Duration::from_secs(6),
        "early close expected, took {:?}",
        start.elapsed()
    );

    // Validator1 applies the commit too.
    wait_subject_sn(nodes[2].api(), governance_id.clone(), 2, 30).await;

    // Probe the validator: a conflicting vote for the closed request,
    // with any report it could push held at the source. A live
    // collection would merge the double vote and report it; nothing held
    // means the stale collection left no residue.
    nodes[2]
        .api()
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalVoteReport,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    let vote = craft_vote(&probe_req, &governance_id, &nodes[3].data.keys, false);
    inject_vote(
        nodes[2].api(),
        &val1_pk,
        &governance_id,
        vote,
        &request_id,
        version,
        &nodes[3].public_key(),
    )
    .await;
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        nodes[2].api().test_held_count().await.unwrap(),
        0,
        "a purged collection must not report votes"
    );
}

#[test(tokio::test)]
// Governance commit purge: a first request parks in Approval and is
// aborted, leaving volatile state around; a second request commits, and
// the commit obsoletes every leftover — the validators keep no
// collection of the aborted request (an injected vote produces no
// report) and the approver that never voted finds its pending state
// obsolete.
async fn test_approval_governance_commit_purges_stale_state() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    nodes.push(TestNode::addressable(&nodes, false, None).await);
    let owner = nodes[1].api().clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![
            nodes[2].api(),
            nodes[3].api(),
            nodes[4].api(),
            nodes[5].api(),
        ],
    )
    .await;

    // Validators = {Owner, Validator1, Validator2} fixed 2, approvers =
    // {Owner, Approver1, Approver2} fixed 2. Both approvers are manual.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 },
                    "validate": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "Validator1",
                        "Validator2",
                        "Approver1",
                        "Approver2"
                    ],
                    "validator": ["Validator1", "Validator2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Validator2",
                    "key": nodes[3].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[4].api().public_key()
                },
                {
                    "name": "Approver2",
                    "key": nodes[5].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The owner auto-accepts (1 < 2): the first request parks in
    // Approval with collections open and both approvers pending.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();

    // Capture the aborted request's approval data for the probe below.
    let mut probe_req = None;
    for _ in 0..50 {
        if let Some((req, _)) = nodes[4]
            .api()
            .get_approval(governance_id.clone(), None)
            .await
            .unwrap()
        {
            probe_req = Some(req);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let probe_req = probe_req.expect("approver never received the request");
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;

    owner.manual_request_abort(governance_id.clone()).await.unwrap();
    wait_abort_recorded(&owner, governance_id.clone(), request_id.clone()).await;
    let aborted_id = request_id;

    // The second request parks in Approval too; wait until Approver2 is
    // pending for it, then Approver1 completes the quorum.
    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode2"),
        true,
    )
    .await
    .unwrap();
    wait_request_state(
        &owner,
        request_id.clone(),
        Some(RequestState::Approval),
    )
    .await
    .unwrap();
    let mut pending = None;
    for _ in 0..50 {
        pending = nodes[5]
            .api()
            .get_approval(governance_id.clone(), Some(ApprovalState::Pending))
            .await
            .unwrap();
        if pending.is_some() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(pending.is_some(), "approver2 never went pending");

    emit_approve(
        nodes[4].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();
    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;

    // Approver pin: the commit obsoleted Approver2's pending vote.
    let mut obsolete = false;
    for _ in 0..50 {
        if nodes[5]
            .api()
            .get_approval(governance_id.clone(), Some(ApprovalState::Pending))
            .await
            .unwrap()
            .is_none()
        {
            obsolete = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(obsolete, "the commit must obsolete the pending vote");

    // Validator pin: no collection of the aborted request survives —
    // a conflicting vote injected into either remote validator produces
    // no vote report (reports are held at the source to observe them).
    // Wait for both validators to apply the commit first: the governance
    // version bump is what purges their stale collections.
    for validator in [2, 3] {
        wait_subject_sn(nodes[validator].api(), governance_id.clone(), 2, 30)
            .await;
    }
    for validator in [2, 3] {
        nodes[validator]
            .api()
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message: FaultMessage::ApprovalVoteReport,
                peer: None,
                remaining: None,
                action: FaultAction::Hold,
            })
            .await
            .unwrap();
        let vote = craft_vote(
            &probe_req,
            &governance_id,
            &nodes[4].data.keys,
            false,
        );
        inject_vote(
            nodes[validator].api(),
            &nodes[validator].public_key(),
            &governance_id,
            vote,
            &aborted_id,
            version,
            &nodes[4].public_key(),
        )
        .await;
    }
    tokio::time::sleep(Duration::from_secs(2)).await;
    for validator in [2, 3] {
        assert_eq!(
            nodes[validator].api().test_held_count().await.unwrap(),
            0,
            "a purged collection must not report votes"
        );
    }
}

#[test(tokio::test)]
// Evidence delivery with message loss: the approval evidence travels
// inside the validation request, whose delivery has the phase
// coordinator's retry — the first request to the remote validator is
// dropped, the retry delivers it and the event commits without waiting
// for any deadline.
async fn test_approval_evidence_delivery_retried() {
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    nodes.push(TestNode::addressable(&nodes, true, None).await);
    let owner = nodes[1].api().clone();
    let val1_pk = nodes[2].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1} fixed 2: everyone auto-accepts, so the approval closes
    // early and only the validation delivery is exercised.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The first validation request to Validator1 is lost; the
    // coordinator retry (10 s in tests) re-sends it.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ValidationReq,
            peer: Some(val1_pk),
            remaining: Some(1),
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    let start = Instant::now();
    emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 90).await;
    let elapsed = start.elapsed();
    assert!(
        elapsed >= Duration::from_secs(8) && elapsed < Duration::from_secs(90),
        "the retry-driven commit lands around the 10 s retry, took {elapsed:?}"
    );

    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}

#[test(tokio::test)]
// A delayed approval collection request (older issued_at than the live
// one, same request id, different hash) arriving at a validator that
// already holds the live collection for the same subject must not
// supplant it: the stale request is rejected with an Unavailable ack
// that the requester ignores (its hash is not the delivered request's),
// the live collection keeps answering the owner's status asks and the
// request commits without any reboot.
async fn test_approval_stale_collect_does_not_supplant_live_collection() {
    // Long keepalive: the only status traffic is the one this test
    // drives, so held answers can be attributed to the live collection.
    let config = ApprovalConfig {
        min_window_secs: 300,
        probe_schedule_secs: vec![1, 2, 4, 293],
        keepalive_secs: 300,
    };
    let mut nodes = vec![TestNode::bootstrap().await];
    nodes.push(TestNode::addressable(&nodes, true, Some(config.clone())).await);
    nodes.push(TestNode::addressable(&nodes, true, Some(config.clone())).await);
    // Manual approver: the collection stays open until the test votes.
    nodes.push(TestNode::addressable(&nodes, false, Some(config)).await);
    let owner = nodes[1].api().clone();
    let val1_pk = nodes[2].public_key();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![nodes[2].api(), nodes[3].api()],
    )
    .await;

    // Validators = {Owner, Validator1} (majority 2), approvers = {Owner,
    // Approver1} fixed 2. The owner auto-accepts; Approver1 is manual,
    // so the approval stays open until the test casts its vote.
    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": { "fixed": 2 }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Validator1", "Approver1"],
                    "validator": ["Validator1"],
                    "approver": ["Approver1"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Validator1",
                    "key": nodes[2].api().public_key()
                },
                {
                    "name": "Approver1",
                    "key": nodes[3].api().public_key()
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Hold the live collection request so its delivery order against
    // the stale one is fully controlled.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalCollectReq,
            peer: Some(val1_pk.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let request_id = emit_fact(
        &owner,
        governance_id.clone(),
        add_fake_member("AveNode1"),
        false,
    )
    .await
    .unwrap();
    wait_held_count(&owner, 1, 10).await;
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    assert_eq!(version, 0);

    // Hold only the first ack (the live Accepted): the coordinator
    // stays alive waiting for it, so the stale rejection below reaches
    // a live coordinator and must be ignored there too.
    nodes[2]
        .api()
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalCollectAck,
            peer: None,
            remaining: Some(1),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    // The live collection opens at Validator1.
    owner.test_release_held().await.unwrap();

    // Wait for the live request to reach the manual approver (the probe
    // round proves the collection is open) and take its content to
    // craft the stale one.
    let mut live_req = None;
    for _ in 0..50 {
        if let Some((req, _)) = nodes[3]
            .api()
            .get_approval(governance_id.clone(), None)
            .await
            .unwrap()
        {
            live_req = Some(req);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let live_req = live_req.expect("approver never received the request");
    let live_hash =
        hash_borsh(&*HashAlgorithm::Blake3.hasher(), &live_req).unwrap();

    // A delayed duplicate of the same request with an older issued_at:
    // strictly older by the (issued_at, version, request id) order and
    // a different hash. Signed by the owner, so it passes the static
    // checks and reaches the freshness guard.
    let mut stale_req = live_req.clone();
    stale_req.issued_at = TimeStamp::from_nanos(
        live_req.issued_at.as_nanos().saturating_sub(1),
    );
    let stale_signed = Signed::new(stale_req, &nodes[1].data.keys).unwrap();
    nodes[2]
        .api()
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: request_id.to_string(),
                    version,
                    receiver: val1_pk.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/validator"
                    ),
                },
                message: ActorMessage::ApprovalCollectReq {
                    req: stale_signed,
                },
            },
            &nodes[1].public_key(),
        )
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(2)).await;

    // The stale request was rejected without touching anything: its
    // Unavailable ack carries the stale hash, so the live coordinator
    // ignores it — no validator replacement, no reboot.
    let version = owner
        .get_request_state(request_id.clone())
        .await
        .unwrap()
        .version;
    assert_eq!(
        version, 0,
        "the stale collect must not replace the validator nor reboot"
    );

    // The live collection still answers the owner's status asks: a
    // supplanting stale collection would make this ask fall through.
    nodes[2]
        .api()
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ApprovalStatusRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    nodes[2]
        .api()
        .test_inject_inbound(
            NetworkMessage {
                info: ComunicateInfo {
                    request_id: request_id.to_string(),
                    version,
                    receiver: val1_pk.clone(),
                    receiver_actor: format!(
                        "/user/node/subject_manager/{governance_id}/validator"
                    ),
                },
                message: ActorMessage::ApprovalStatusReq {
                    approval_req_hash: live_hash,
                    wanted: None,
                },
            },
            &nodes[1].public_key(),
        )
        .await
        .unwrap();
    wait_held_count(nodes[2].api(), 1, 10).await;
    nodes[2].api().test_release_held().await.unwrap();

    // Approver1 votes: the approval closes with the live collection and
    // the event commits approved.
    emit_approve(
        nodes[3].api(),
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    wait_subject_sn(&owner, governance_id.clone(), 2, 60).await;
    let events = get_events(&owner, governance_id.clone(), 3, true)
        .await
        .unwrap();
    assert_approval_outcome(&events, 2, Some(true));
}
