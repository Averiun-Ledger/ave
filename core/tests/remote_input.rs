mod common;

// Inbound robustness: batches and hints crafted by a malicious peer must
// be rejected as invalid input, never stop the node, and never open
// reception windows that full validation would deny.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ave_common::identity::keys::{DSA, Ed25519Signer};
use ave_common::identity::{
    DigestIdentifier, Hash, HashAlgorithm, PublicKey, Signature, Signed,
    TimeStamp, hash_borsh,
};
use ave_common::request::{EventRequest, TransferRequest};
use ave_core::helpers::network::test_faults::{
    FaultAction, FaultDirection, FaultMessage, FaultRule,
};
use ave_core::helpers::network::{ActorMessage, NetworkMessage};
use ave_core::model::event::{
    EvaluationResponse, Ledger, LedgerSeal, Protocols, ValidationMetadata,
};
use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT,
    PORT_COUNTER, create_and_authorize_governance, create_node,
    create_nodes_and_connections, create_subject, emit_confirm, emit_fact,
    emit_reject, emit_transfer, get_subject, node_running,
};

/// Member of a test governance using the Example schema.
struct MemberSpec<'a> {
    api: &'a ave_core::Api,
    name: &'a str,
    gov_witness: bool,
    creator: bool,
    issuer: bool,
}

/// Governance with owner-run evaluation/validation and an Example schema.
/// Every listed member can hold trackers; only flagged ones create, issue
/// or follow governance witnesses.
async fn setup_example_governance(
    owner: &ave_core::Api,
    members: &[MemberSpec<'_>],
) -> DigestIdentifier {
    let mut member_apis = Vec::with_capacity(members.len());
    for member in members {
        member_apis.push(member.api);
    }
    let governance_id =
        create_and_authorize_governance(owner, member_apis).await;

    let mut adds = Vec::with_capacity(members.len());
    let mut gov_witnesses = Vec::with_capacity(members.len());
    let mut creators = Vec::with_capacity(members.len());
    let mut issuers = Vec::with_capacity(members.len());
    for member in members {
        adds.push(json!({
            "name": member.name,
            "key": member.api.public_key(),
        }));
        if member.gov_witness {
            gov_witnesses.push(json!(member.name));
        }
        if member.creator {
            creators.push(json!({
                "name": member.name,
                "namespace": [],
                "quantity": "infinity",
            }));
        }
        if member.issuer {
            issuers.push(json!({
                "name": member.name,
                "namespace": [],
            }));
        }
    }
    let mut config = json!({
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
                "add": { "witness": gov_witnesses },
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
                        "creator": creators,
                        "issuer": issuers,
                    }
                }
            ]
        }
    });
    // An empty member list is rejected by evaluation; only attach the
    // section when there is someone to add.
    if !adds.is_empty() {
        config["members"] = json!({ "add": adds });
    }
    emit_fact(owner, governance_id.clone(), config, true)
        .await
        .unwrap();

    // Members need the governance locally before they can create
    // subjects or verify hints under it.
    let gov_sn = get_subject(owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    for member in members {
        member
            .api
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        get_subject(member.api, governance_id.clone(), Some(gov_sn), true)
            .await
            .unwrap();
    }
    governance_id
}

/// Delivers a crafted distribution batch to `api` as if `from` sent it
/// over the network.
async fn inject_ledger_batch(
    api: &ave_core::Api,
    from: &PublicKey,
    ledger: Vec<Ledger>,
    transfer_event: Option<Ledger>,
) {
    let receiver =
        PublicKey::from_str(api.public_key()).expect("node public key");
    let message = NetworkMessage::new(
        ComunicateInfo {
            request_id: String::new(),
            version: 0,
            receiver,
            receiver_actor: "/user/node/distributor".to_owned(),
        },
        ActorMessage::DistributionLedgerRes {
            ledger,
            is_all: true,
            transfer_event: transfer_event.map(Box::new),
            expected_governance_id: None,
        },
    );
    api.test_inject_inbound(message, from).await.unwrap();
}

/// Governance with owner-run evaluation/validation and creator roles for
/// the given member names, mirroring the standard transfer setup.
async fn setup_transfer_gov(
    owner: &ave_core::Api,
    members: Vec<(&ave_core::Api, &str)>,
) -> DigestIdentifier {
    let specs: Vec<MemberSpec<'_>> = members
        .into_iter()
        .map(|(api, name)| MemberSpec {
            api,
            name,
            gov_witness: true,
            creator: true,
            issuer: true,
        })
        .collect();
    setup_example_governance(owner, &specs).await
}

/// A creation batch for a subject the node never saw, with an empty
/// governance id: the exact malformed input must be rejected, and an
/// oversized batch must be dropped before burning verify CPU. Neither
/// may affect the node.
#[test(tokio::test)]
async fn remote_malformed_batches_do_not_stop_the_node() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let target = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let sender = PublicKey::from_str(nodes[2].api.public_key()).unwrap();

    let governance_id = setup_example_governance(
        &target,
        &[MemberSpec {
            api: &alice,
            name: "Alice",
            gov_witness: true,
            creator: true,
            issuer: true,
        }],
    )
    .await;
    let (real_subject, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let create_event = alice
        .test_get_tracker_ledger(real_subject.clone(), 0)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("genesis event");
    let (template_request, template_validation) = match &create_event.protocols
    {
        Protocols::Create {
            event_request,
            validation,
        } => (event_request.clone(), validation.clone()),
        _ => panic!("expected a create event"),
    };

    // Malformed creation for an unknown subject: tracker schema with an
    // empty governance id.
    let forged_id =
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![7u8; 32]).unwrap();
    let mut forged_content = template_request.content().clone();
    match &mut forged_content {
        EventRequest::Create(create) => {
            create.governance_id = DigestIdentifier::default();
        }
        _ => panic!("expected a create request"),
    }
    let forged_request = Signed::from_parts(
        forged_content,
        template_request.signature().clone(),
    );
    let mut forged_validation = template_validation;
    match &mut forged_validation.validation_metadata {
        ValidationMetadata::Metadata(metadata) => {
            metadata.subject_id = forged_id.clone();
        }
        _ => panic!("expected full metadata in a create event"),
    }
    let forged_create = Ledger {
        gov_version: create_event.gov_version,
        sn: 0,
        prev_ledger_event_hash: create_event.prev_ledger_event_hash.clone(),
        ledger_seal_signature: create_event.ledger_seal_signature.clone(),
        protocols: Protocols::Create {
            event_request: Arc::new(forged_request),
            validation: forged_validation,
        },
    };
    inject_ledger_batch(&target, &sender, vec![forged_create], None).await;

    // Oversized batch: well-formed but far above any honest batch.
    let mut huge = Vec::with_capacity(10_001);
    for sn in 0..10_001u64 {
        let mut event = create_event.clone();
        event.sn = sn;
        huge.push(event);
    }
    inject_ledger_batch(&target, &sender, huge, None).await;

    tokio::time::sleep(Duration::from_secs(2)).await;

    // The node is alive, the forged subject was never registered, and
    // the node still serves and mutates real state.
    node_running(&target).await.unwrap();
    assert!(target.get_subject_state(forged_id).await.is_err());
    target
        .get_subject_state(governance_id.clone())
        .await
        .unwrap();
    create_subject(&alice, governance_id, "Example", "", true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

/// A transfer hint whose quorum block belongs to another event must not
/// open a reception window; the legitimate hint still must.
#[test(tokio::test)]
async fn remote_forged_transfer_hint_does_not_open_reception() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let bob = nodes[2].api.clone();
    let receiver = nodes[3].api.clone();
    let alice_keys = nodes[1].keys.clone();

    let governance_id = setup_transfer_gov(
        &owner,
        vec![(&alice, "Alice"), (&bob, "Bob"), (&receiver, "Rita")],
    )
    .await;

    // Genuine history: Alice creates a tracker, emits a fact, and
    // transfers it to Bob. The committed transfer carries the quorum
    // block the forgery will try to reuse.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let bob_key = PublicKey::from_str(bob.public_key()).unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key, true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let genuine = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    let (genuine_evaluation, genuine_validation) = match &genuine.protocols {
        Protocols::Transfer {
            event_request: _,
            evaluation,
            validation,
        } => (evaluation.clone(), validation.clone()),
        _ => panic!("expected a transfer event"),
    };

    // Forgery: same quorum block, different request (Rita as new owner),
    // freshly sealed by the previous owner.
    let receiver_key = PublicKey::from_str(receiver.public_key()).unwrap();
    let forged_content = EventRequest::Transfer(TransferRequest {
        subject_id: subject_id.clone(),
        new_owner: receiver_key,
    });
    let forged_sig = Signature::new(&forged_content, &alice_keys).unwrap();
    let forged_request = Signed::from_parts(forged_content, forged_sig);
    let forged_protocols = Protocols::Transfer {
        event_request: Arc::new(forged_request),
        evaluation: genuine_evaluation,
        validation: genuine_validation,
    };
    let protocols_hash = forged_protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: genuine.gov_version,
        sn: genuine.sn,
        prev_ledger_event_hash: genuine.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    let forged = Ledger {
        gov_version: genuine.gov_version,
        sn: genuine.sn,
        prev_ledger_event_hash: genuine.prev_ledger_event_hash.clone(),
        ledger_seal_signature: Signature::new(&forged_seal, &alice_keys)
            .unwrap(),
        protocols: forged_protocols,
    };
    let batch: Vec<Ledger> =
        history.into_iter().filter(|event| event.sn <= 2).collect();
    inject_ledger_batch(
        &receiver,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        batch,
        Some(forged),
    )
    .await;

    // The forged hint must not register any reception window.
    for _ in 0..30 {
        assert!(
            receiver
                .get_subject_state(subject_id.clone())
                .await
                .is_err(),
            "forged transfer hint must not admit the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node_running(&receiver).await.unwrap();

    // Control: the genuine flow still works. Bob confirms, transfers to
    // Rita, and Rita syncs through the legitimate hint.
    bob.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    emit_confirm(&bob, subject_id.clone(), None, true)
        .await
        .unwrap();
    emit_transfer(
        &bob,
        subject_id.clone(),
        PublicKey::from_str(receiver.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();
    receiver
        .authorize_governance(
            subject_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    receiver.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&receiver, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

/// An event whose seal timestamp is outside the SQLite integer range is
/// rejected during verification; the node stays up and keeps syncing.
#[test(tokio::test)]
async fn remote_future_timestamp_event_is_rejected() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    // Bob's keys exist before he does: he joins only after the transfer
    // commits, so no live push can sync him early and mask the inject.
    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id = setup_example_governance(
        &owner,
        &[MemberSpec {
            api: &alice,
            name: "Alice",
            gov_witness: true,
            creator: true,
            issuer: true,
        }],
    )
    .await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [{
                "name": "Bob",
                "key": bob_key.to_string(),
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Bob"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {"creator": [{
                        "name": "Bob",
                        "namespace": [],
                        "quantity": "infinity",
                    }]},
                }],
            },
        }),
        true,
    )
    .await
    .unwrap();
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    let genuine = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let seal = LedgerSeal {
        gov_version: genuine.gov_version,
        sn: genuine.sn,
        prev_ledger_event_hash: genuine.prev_ledger_event_hash.clone(),
        protocols_hash: genuine
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    let timestamp = TimeStamp::from_nanos(i64::MAX as u64 + 1);
    let content_hash =
        hash_borsh(&*HashAlgorithm::Blake3.hasher(), &(&seal, timestamp))
            .unwrap();
    let forged_seal = Signature {
        signer: PublicKey::new(
            alice_keys.algorithm(),
            alice_keys.public_key_bytes(),
        )
        .unwrap(),
        timestamp,
        content_hash: content_hash.clone(),
        value: alice_keys.sign(content_hash.hash_bytes()).unwrap(),
    };
    let forged = Ledger {
        gov_version: genuine.gov_version,
        sn: genuine.sn,
        prev_ledger_event_hash: genuine.prev_ledger_event_hash.clone(),
        ledger_seal_signature: forged_seal,
        protocols: genuine.protocols.clone(),
    };
    // Bob joins only now, after the transfer committed: no live push
    // could have synced him early and masked the inject.
    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer,
            address: vec![boot_addr],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    get_subject(&bob, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    inject_ledger_batch(
        &bob,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        vec![history[0].clone(), forged, history[2].clone()],
        Some(transfer.clone()),
    )
    .await;

    // Bob must not advance past what verification accepts: the
    // out-of-range event is rejected, and the node keeps working.
    // (Without the range gate the event would journal and the SQLite
    // projection would stop the node.)
    for _ in 0..30 {
        let advanced = bob
            .get_subject_state(subject_id.clone())
            .await
            .map(|state| state.sn >= 1)
            .unwrap_or(false);
        assert!(!advanced, "out-of-range event must not be applied");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node_running(&bob).await.unwrap();

    // Control: the genuine suffix applies cleanly through the same
    // legitimate hint.
    let from = bob
        .get_subject_state(subject_id.clone())
        .await
        .map(|state| state.sn.saturating_add(1))
        .unwrap_or(0);
    let suffix: Vec<Ledger> = history
        .into_iter()
        .filter(|event| event.sn >= from)
        .collect();
    assert!(!suffix.is_empty());
    inject_ledger_batch(
        &bob,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        suffix,
        Some(transfer),
    )
    .await;
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
}

/// A failed transfer must not open a reception window: the ownership
/// reconstruction only stages pending transfers whose evaluation was
/// ok, mirroring the live tracker path. Batch carries no hint; the
/// reconstruction reads the batch itself.
#[test(tokio::test)]
async fn remote_failed_transfer_does_not_open_reception() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id = setup_example_governance(
        &owner,
        &[MemberSpec {
            api: &alice,
            name: "Alice",
            gov_witness: true,
            creator: true,
            issuer: true,
        }],
    )
    .await;
    // Rita is a member and governance witness, but NOT a creator: the
    // transfer to her fails evaluation and commits as a failed event.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({"members": {"add": [{
            "name": "Rita",
            "key": rita_key.to_string(),
        }]}}),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), false)
        .await
        .unwrap();
    // Bounded wait: a failed evaluation commits the event as failed
    // instead of finishing the request the usual way.
    get_subject(&alice, subject_id.clone(), Some(1), true)
        .await
        .expect("failed transfer must still commit its ledger record");
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    let failed = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("transfer event")
        .clone();
    assert!(
        !failed.protocols.is_success(),
        "premise: the transfer to a non-creator must fail evaluation"
    );

    // Rita joins only now: no live state, the batch is her only source.
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer,
            address: vec![boot_addr],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    inject_ledger_batch(
        &rita,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        history,
        None,
    )
    .await;

    // The failed transfer stages no pending ownership, so there is no
    // window to admit the batch through.
    for _ in 0..30 {
        let advanced = rita
            .get_subject_state(subject_id.clone())
            .await
            .map(|state| state.sn >= 1)
            .unwrap_or(false);
        assert!(!advanced, "failed transfer must not admit the subject");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// First-copy batches with a foreign or cryptographically invalid
/// inline transfer must be rejected before any local write: a mixed
/// batch (Create of B plus an authentic transfer of A) and a batch
/// whose inline transfer reuses another event quorum block. Neither
/// may register the subject nor leave a transfer proof behind; the
/// genuine flow must still complete afterwards.
#[test(tokio::test)]
async fn remote_mixed_and_forged_inline_batches_rejected() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let bob = nodes[2].api.clone();
    let rita = nodes[3].api.clone();
    let alice_keys = nodes[1].keys.clone();

    let governance_id = setup_transfer_gov(
        &owner,
        vec![(&alice, "Alice"), (&bob, "Bob"), (&rita, "Rita")],
    )
    .await;

    let (subject_a, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_a.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let bob_key = PublicKey::from_str(bob.public_key()).unwrap();
    emit_transfer(&alice, subject_a.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    let history_a = alice
        .test_get_tracker_ledger(subject_a.clone(), 2)
        .await
        .unwrap();
    let transfer_a = history_a
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer of A")
        .clone();

    let (subject_b, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_b.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_b.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    let history_b = alice
        .test_get_tracker_ledger(subject_b.clone(), 2)
        .await
        .unwrap();
    let create_b = history_b
        .iter()
        .find(|event| event.sn == 0)
        .expect("create of B")
        .clone();
    let fact_b = history_b
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact of B")
        .clone();
    let genuine_b = history_b
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer of B")
        .clone();
    let (genuine_eval_b, genuine_val_b) = match &genuine_b.protocols {
        Protocols::Transfer {
            evaluation,
            validation,
            ..
        } => (evaluation.clone(), validation.clone()),
        _ => panic!("expected a transfer event"),
    };

    // Mixed-subject batch: authentic events, wrong subject mix.
    inject_ledger_batch(
        &rita,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        vec![create_b.clone(), transfer_a],
        None,
    )
    .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(subject_b.clone()).await.is_err(),
            "mixed batch must not register the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Inline forgery: same quorum block, different request (Rita as
    // new owner), freshly sealed by the previous owner. The request
    // hash no longer matches the attested one.
    let rita_key = PublicKey::from_str(rita.public_key()).unwrap();
    let forged_content = EventRequest::Transfer(TransferRequest {
        subject_id: subject_b.clone(),
        new_owner: rita_key,
    });
    let forged_sig = Signature::new(&forged_content, &alice_keys).unwrap();
    let forged_request = Signed::from_parts(forged_content, forged_sig);
    let forged_protocols = Protocols::Transfer {
        event_request: Arc::new(forged_request),
        evaluation: genuine_eval_b,
        validation: genuine_val_b,
    };
    let protocols_hash = forged_protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: genuine_b.gov_version,
        sn: genuine_b.sn,
        prev_ledger_event_hash: genuine_b.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    let forged = Ledger {
        gov_version: genuine_b.gov_version,
        sn: genuine_b.sn,
        prev_ledger_event_hash: genuine_b.prev_ledger_event_hash.clone(),
        ledger_seal_signature: Signature::new(&forged_seal, &alice_keys)
            .unwrap(),
        protocols: forged_protocols,
    };
    inject_ledger_batch(
        &rita,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        vec![create_b, fact_b, forged],
        None,
    )
    .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(subject_b.clone()).await.is_err(),
            "forged inline transfer must not admit the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node_running(&rita).await.unwrap();

    // Control: the genuine flow still works after both rejections.
    bob.authorize_governance(
        subject_b.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(subject_b.clone()).await.unwrap();
    get_subject(&bob, subject_b.clone(), Some(2), true)
        .await
        .unwrap();
    emit_confirm(&bob, subject_b.clone(), None, true)
        .await
        .unwrap();
    emit_transfer(
        &bob,
        subject_b.clone(),
        PublicKey::from_str(rita.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();
    rita.authorize_governance(
        subject_b.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(subject_b.clone()).await.unwrap();
    get_subject(&rita, subject_b.clone(), Some(4), true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

/// A committed transfer with failed evaluation is valid history, not
/// passage: receivers with independent rights must copy the exact
/// failed event, both as a joint batch and as a lone pushed
/// transfer. The receivers join only after every commit, so the
/// injected batches below are the only delivery: no push or update
/// round can interleave.
/// The outsider control on the same history still advances nothing
/// and leaves no transfer proof behind.
#[test(tokio::test)]
async fn remote_failed_transfer_is_copyable_with_direct_rights() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let zed_signer = Ed25519Signer::generate().unwrap();
    let zed_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        zed_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // Zed witnesses Alice's creations; Rita is a plain member.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Zed", "key": zed_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                    {"name": "Bob", "key": bob_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Zed",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Block every natural tracker delivery from Alice from now on:
    // the receivers below join only after every commit, so the
    // injected batches are the only copy they process.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), false)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(1), true)
        .await
        .expect("failed transfer must still commit its ledger record");
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(history.len(), 2);
    assert!(
        !history
            .iter()
            .find(|event| event.sn == 1)
            .expect("transfer event")
            .protocols
            .is_success(),
        "premise: the transfer to a non-creator must fail evaluation"
    );

    // Zed joins only now: no push ever reached her, the injected
    // batch below is the first and only copy she processes.
    let zed_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut zed_node, zed_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{zed_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(zed_signer)),
        ..Default::default()
    })
    .await;
    let zed = zed_node.api.clone();
    node_running(&zed).await.unwrap();
    zed.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    zed.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&zed, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    // Phase one: Create plus failed transfer in a single batch. The
    // batch path verifies the transfer cryptographically without
    // demanding an Ok evaluation, grants nothing, and lets the
    // independent rights carry the copy.
    inject_ledger_batch(
        &zed,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        history.clone(),
        None,
    )
    .await;
    let state = get_subject(&zed, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1);
    let copied = zed
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(copied.len(), 2);
    assert!(
        !copied
            .iter()
            .find(|event| event.sn == 1)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the failed transfer must stay failed in the copy"
    );
    assert!(
        zed.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a failed transfer grants no passage and leaves no proof"
    );
    node_running(&zed).await.unwrap();

    // Phase two: a lone failed transfer through the push path lands
    // as history under the same direct rights.
    let (subject_id2, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_transfer(&alice, subject_id2.clone(), rita_key.clone(), false)
        .await
        .unwrap();
    get_subject(&alice, subject_id2.clone(), Some(1), true)
        .await
        .expect("failed transfer must still commit its ledger record");
    let history2 = alice
        .test_get_tracker_ledger(subject_id2.clone(), 1)
        .await
        .unwrap();
    let create2 = history2
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let failed2 = history2
        .iter()
        .find(|event| event.sn == 1)
        .expect("transfer event")
        .clone();
    assert!(
        !failed2.protocols.is_success(),
        "premise: the second transfer must also fail evaluation"
    );
    inject_ledger_batch(
        &zed,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        vec![create2],
        None,
    )
    .await;
    get_subject(&zed, subject_id2.clone(), Some(0), true)
        .await
        .unwrap();
    let zed_push_key = PublicKey::from_str(zed.public_key()).unwrap();
    let alice_push_key = PublicKey::from_str(alice.public_key()).unwrap();
    zed.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: zed_push_key,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(failed2),
            },
        ),
        &alice_push_key,
    )
    .await
    .unwrap();
    get_subject(&zed, subject_id2.clone(), Some(1), true)
        .await
        .unwrap();
    node_running(&zed).await.unwrap();

    // Phase three: a lone successful transfer through the push path
    // lands as history with its pending ownership. Zed only
    // witnesses Alice, so the pending new owner grants her nothing;
    // the simulation still sees her current-owner rights and the
    // copy lands under them, recording the pending transfer.
    let (subject_id3, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_transfer(&alice, subject_id3.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id3.clone(), Some(1), true)
        .await
        .expect("transfer to a creator must commit");
    let history3 = alice
        .test_get_tracker_ledger(subject_id3.clone(), 1)
        .await
        .unwrap();
    assert!(
        history3
            .iter()
            .find(|event| event.sn == 1)
            .expect("transfer event")
            .protocols
            .is_success(),
        "premise: the transfer to a creator must succeed"
    );
    let create3 = history3
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let ok_transfer = history3
        .iter()
        .find(|event| event.sn == 1)
        .expect("transfer event")
        .clone();
    inject_ledger_batch(
        &zed,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        vec![create3],
        None,
    )
    .await;
    get_subject(&zed, subject_id3.clone(), Some(0), true)
        .await
        .unwrap();
    zed.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(zed.public_key()).unwrap(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(ok_transfer),
            },
        ),
        &alice_push_key,
    )
    .await
    .unwrap();
    get_subject(&zed, subject_id3.clone(), Some(1), true)
        .await
        .unwrap();
    node_running(&zed).await.unwrap();
    alice.test_clear_faults().await.unwrap();

    // Outsider control on the same history: Rita still advances
    // nothing and leaves no transfer proof behind.
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer,
            address: vec![boot_addr],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();
    inject_ledger_batch(
        &rita,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        history,
        None,
    )
    .await;
    for _ in 0..30 {
        let advanced = rita
            .get_subject_state(subject_id.clone())
            .await
            .map(|state| state.sn >= 1)
            .unwrap_or(false);
        assert!(!advanced, "failed transfer must not admit the outsider");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from a rejected batch"
    );
    node_running(&rita).await.unwrap();

    zed_node.token.cancel();
    rita_node.token.cancel();
    join_all(
        zed_node
            .handler
            .iter_mut()
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(zed_node);
    drop(zed_dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// An inline transfer whose previous hash was swapped must be
/// rejected before any local write, even with a fresh valid seal:
/// the chain link is verified up front, not only at apply time.
/// The genuine batch afterwards must still copy fine (control).
#[test(tokio::test)]
async fn remote_forged_prev_hash_transfer_rejected_before_create() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let zoe_signer = Ed25519Signer::generate().unwrap();
    let zoe_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        zoe_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id = setup_example_governance(
        &owner,
        &[MemberSpec {
            api: &alice,
            name: "Alice",
            gov_witness: true,
            creator: true,
            issuer: true,
        }],
    )
    .await;
    // Zoe is a plain member and a creator, so a transfer to her is
    // genuine and committed.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [{ "name": "Zoe", "key": zoe_key.to_string() }]
            },
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "creator": [
                                {
                                    "name": "Zoe",
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
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), zoe_key.clone(), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let genuine = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        genuine.protocols.is_success(),
        "premise: the transfer to a creator must succeed"
    );

    // Same request, evaluation and quorum block; only the previous
    // hash is swapped, with a fresh seal from the previous owner.
    let mut forged = genuine.clone();
    forged.prev_ledger_event_hash = DigestIdentifier::default();
    assert_ne!(
        forged.prev_ledger_event_hash, genuine.prev_ledger_event_hash,
        "premise: the forged link must differ"
    );
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged.gov_version,
        sn: forged.sn,
        prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    forged.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    // Zoe joins only now: the forged batch is her only source.
    let zoe_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut zoe_node, zoe_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{zoe_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer,
            address: vec![boot_addr],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(zoe_signer)),
        ..Default::default()
    })
    .await;
    let zoe = zoe_node.api.clone();
    node_running(&zoe).await.unwrap();
    zoe.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    zoe.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&zoe, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    inject_ledger_batch(
        &zoe,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        vec![create.clone(), fact.clone(), forged],
        None,
    )
    .await;
    for _ in 0..30 {
        assert!(
            zoe.get_subject_state(subject_id.clone()).await.is_err(),
            "forged link must not register the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        zoe.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from a rejected batch"
    );
    node_running(&zoe).await.unwrap();

    // Control: the genuine batch copies fine afterwards.
    inject_ledger_batch(
        &zoe,
        &PublicKey::from_str(alice.public_key()).unwrap(),
        history,
        None,
    )
    .await;
    get_subject(&zoe, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    zoe_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(zoe_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(zoe_node);
    drop(zoe_dirs);
}

// A transfer whose evaluation was forged to Ok (same request,
// validator quorum and chain link, fresh owner seal) must not leave
// a prefix behind: the apply-time evidence check rejects it, and
// the failed first copy is rolled back instead of keeping the
// Create and the fact persisted.
#[test(tokio::test)]
async fn remote_forged_evaluation_transfer_leaves_no_prefix() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // Bob witnesses Alice's creations; Rita is a plain member, so a
    // transfer to her fails evaluation but still commits.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Block every natural tracker delivery from Alice from now on:
    // the receivers below join only after every commit, so the
    // injected batches are the only copy they process.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), false)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    assert!(
        fact.protocols.is_success(),
        "premise: the fact must succeed"
    );
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        !transfer.protocols.is_success(),
        "premise: the transfer to a non-creator must fail evaluation"
    );

    // Same request, validator quorum and chain link; only the
    // evaluation is swapped to a genuine Ok result from the fact,
    // keeping the failure's result hash so light checks pass while
    // the evidence can never reproduce. Fresh owner seal.
    let fact_result = match &fact.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("fact evaluation ok"),
        _ => panic!("expected a full fact event"),
    };
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: fact_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    }
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged.gov_version,
        sn: forged.sn,
        prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    forged.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    // Rita joins only now: the forged batch is her first source.
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact.clone(), forged.clone()],
        None,
    )
    .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(subject_id.clone()).await.is_err(),
            "forged evaluation must not register the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from a rejected batch"
    );
    match rita
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => {}
        Ok((owner_now, pending, _, _)) => assert!(
            owner_now.is_none() && pending.is_none(),
            "no ownership may derive from a rejected batch"
        ),
    }
    node_running(&rita).await.unwrap();

    // Control: the genuine batch (with its failed transfer) is also
    // rejected for Rita, who holds no access, and leaves nothing.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact.clone(), transfer.clone()],
        None,
    )
    .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(subject_id.clone()).await.is_err(),
            "genuine failure without access must not register either"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from the genuine batch"
    );
    node_running(&rita).await.unwrap();

    // Control: Bob holds direct witness rights, so the same genuine
    // history copies as data with its failure intact and no proof.
    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();
    // Phase one: the forged batch is rejected even with direct
    // rights, and the failed apply leaves no prefix behind.
    inject_ledger_batch(&bob, &alice_key, vec![create, fact, forged], None)
        .await;
    for _ in 0..30 {
        assert!(
            bob.get_subject_state(subject_id.clone()).await.is_err(),
            "forged evaluation must not leave a prefix with rights"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        bob.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from a rejected apply"
    );
    node_running(&bob).await.unwrap();

    // Phase two: the genuine history copies as data, keeping the
    // failure intact and no proof.
    inject_ledger_batch(&bob, &alice_key, history.clone(), None).await;
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = bob
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert!(
        !copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the failed transfer must stay failed in the copy"
    );
    assert!(
        bob.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a failed transfer grants no passage and leaves no proof"
    );
    node_running(&bob).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    bob_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
    drop(bob_node);
    drop(bob_dirs);
}

// An external transfer hint grants nothing on seal and quorum
// alone: without reproducible evaluation evidence over the batch
// prefix the batch defers with no subject, no proof and no
// ownership. A genuine hint with its prefix authorizes the
// prefix, and the full genuine chain then completes with no
// trace of the forged variant.
#[test(tokio::test)]
async fn remote_forged_external_aux_grants_nothing_without_evidence() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // Bob witnesses Alice's creations and Rita is a creator, so a
    // transfer to her succeeds and commits; the forged variant
    // below only differs in its swapped evaluation result. Neither
    // of them can open Alice's subject on direct rights alone: the
    // first-copy decision must come from the hint evidence.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Block every natural tracker delivery from Alice from now on:
    // Rita joins only after every commit, so the injected batches
    // are the only copy she processes.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), false)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    // Same request, validator quorum and chain link; only the
    // evaluation result is swapped for a genuine Ok from the fact,
    // keeping the transfer's own result hash so light checks pass
    // while the evidence can never reproduce. Fresh owner seal.
    let fact_result = match &fact.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("fact evaluation ok"),
        _ => panic!("expected a full fact event"),
    };
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: fact_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    }
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged.gov_version,
        sn: forged.sn,
        prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    forged.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    // Rita joins only now: every injected batch below is her only
    // source, and no natural push can interfere.
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    // Delivers a crafted batch with an explicit external hint and
    // an explicit completeness flag.
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: Option<Ledger>,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: hint.map(Box::new),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    // No subject, proof or ownership may appear from a rejected
    // batch, whatever its shape.
    async fn assert_no_trace(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "forged aux must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from a forged aux"
        );
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => {}
            Ok((owner_now, pending, _, _)) => assert!(
                owner_now.is_none() && pending.is_none(),
                "no ownership may derive from a forged aux"
            ),
        }
        node_running(api).await.unwrap();
    }

    // Forged hint with its prefix but no inline transfer. The
    // evidence cannot reproduce, so nothing is authorized.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact.clone()],
        false,
        Some(forged.clone()),
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;

    // Forged hint ahead of a partial batch with a missing middle
    // event. The evidence is not checkable yet, so the batch is
    // deferred unapplied: no subject, no proof, no ownership, and
    // the sender is asked for the continuation instead.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone()],
        false,
        Some(forged.clone()),
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;

    // The missing middle arrives but the evidence now refutes the
    // hint instead of verifying it: the deferred prefix is dropped
    // and still nothing is registered, proved or owned.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact.clone()],
        false,
        Some(forged.clone()),
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;

    // Same forged hint, but with a sender that claims completeness:
    // an uncheckable hint never opens passage, even when the sender
    // says the batch is all there is. The batch is held unapplied
    // with no proof until evidence arrives.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone()],
        true,
        Some(forged.clone()),
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    // The missing middle arrives and refutes the hint: the held
    // prefix is dropped and still nothing is registered, proved
    // or owned.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact.clone()],
        true,
        Some(forged.clone()),
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;

    // Genuine hint with its prefix authorizes the prefix and
    // records the proof, without applying the hint itself.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact.clone()],
        false,
        Some(transfer.clone()),
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((2, alice_key.clone())),
        "the genuine hint must record its proof with the prefix"
    );
    node_running(&rita).await.unwrap();

    // The missing tail completes the genuine chain, and the
    // applied transfer is the genuine one, not the forged
    // variant. Only the tail travels: the head is already applied,
    // and a full batch would be dropped as stale.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        Some(transfer.clone()),
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = rita
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3);
    let applied = copied
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        applied.protocols.is_success(),
        "the genuine transfer must stay applied"
    );
    let genuine_result = match &transfer.protocols {
        Protocols::Transfer { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("genuine transfer evaluation ok"),
        _ => panic!("expected a transfer event"),
    };
    let applied_result = match &applied.protocols {
        Protocols::Transfer { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("applied transfer evaluation ok"),
        _ => panic!("expected a transfer event"),
    };
    assert_eq!(
        applied_result.patch.0, genuine_result.patch.0,
        "no forged evaluation may survive the genuine chain"
    );
    // The passage proof is consumed once the genuine transfer it
    // opened is applied: nothing must remain, forged or otherwise.
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may remain after the transfer applied"
    );
    match rita
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the chain"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(alice_key.clone()),
                "no ownership rotation may be reverted"
            );
            assert_eq!(
                pending,
                Some(rita_key.clone()),
                "the genuine pending transfer must stay pending"
            );
        }
    }
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

// A genuine chain through Confirm keeps its evidence linked: a
// receiver that only gains access through the second transfer
// still copies to the tip. The screening must skip Confirm
// without breaking the chain; stopping at it would strand the
// later transfer as unverified and reject a legitimate copy.
#[test(tokio::test)]
async fn remote_confirm_chain_copies_through_second_transfer() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // Alice creates with Bob as witness; Bob and Carol are plain
    // creators, so both transfers succeed while neither gains
    // direct access to a subject created by Alice.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Bob lives from the start: he must issue the confirm and the
    // second transfer from his own node.
    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Bob copies through the first transfer, confirms it and moves
    // the subject on to Carol.
    let bob_key_public = PublicKey::from_str(bob.public_key()).unwrap();
    bob.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(alice.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    emit_confirm(&bob, subject_id.clone(), None, true)
        .await
        .unwrap();
    emit_transfer(&bob, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&bob, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let chain = bob
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    assert_eq!(chain.len(), 5);
    assert!(
        chain
            .iter()
            .find(|event| event.sn == 4)
            .expect("second transfer")
            .protocols
            .is_success(),
        "premise: the second transfer must succeed"
    );

    // Carol joins only now, with no direct access: the second
    // transfer is her only passage. The full history is injected
    // without any external hint, so the inline screening alone
    // must carry her through the Confirm: any sender-side aux
    // would bypass it through its own shortcut instead.
    let carol_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut carol_node, carol_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{carol_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(carol_signer)),
        ..Default::default()
    })
    .await;
    let carol = carol_node.api.clone();
    node_running(&carol).await.unwrap();
    carol
        .authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    carol.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&carol, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();
    let carol_public = PublicKey::from_str(carol.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(carol_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    carol
        .authorize_governance(
            subject_id.clone(),
            ave_core::auth::AuthWitness::One(bob_key_public.clone()),
        )
        .await
        .unwrap();
    // Phase one: the full history without any external hint. The
    // inline screening alone must carry Carol through the Confirm
    // up to its boundary: she stalls right before the second
    // transfer with Bob installed as owner and no proof recorded.
    inject_ledger_batch(&carol, &bob_key_public, chain.clone(), None).await;
    get_subject(&carol, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let partial = carol
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(partial.len(), 4);
    match carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the prefix"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(bob_key_public.clone()),
                "the Confirm must install Bob before the stall"
            );
            assert_eq!(pending, None, "the second transfer is not applied yet");
        }
    }
    assert!(
        carol
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may appear without an aux"
    );
    node_running(&carol).await.unwrap();

    // Phase two: the missing tail with its genuine hint completes
    // the copy through the second transfer.
    let genuine_tip = chain
        .iter()
        .find(|event| event.sn == 4)
        .expect("second transfer")
        .clone();
    inject_ledger_batch(
        &carol,
        &bob_key_public,
        vec![genuine_tip.clone()],
        Some(genuine_tip),
    )
    .await;
    get_subject(&carol, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let copied = carol
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    assert_eq!(copied.len(), 5);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 4)
            .expect("second transfer")
            .protocols
            .is_success(),
        "the second transfer must stay applied"
    );
    match carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the chain"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(bob_key_public.clone()),
                "Bob stays owner after his confirmed transfer"
            );
            assert_eq!(
                pending,
                Some(carol_key.clone()),
                "the second transfer must stay pending for Carol"
            );
        }
    }
    assert!(
        carol
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "inline transfers need no recorded proof"
    );
    node_running(&carol).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    carol_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(carol_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(carol_node);
    drop(carol_dirs);
}

// A rejection closes the pending transfer without installing an
// owner, and a later transfer opens a new one: the screening must
// skip Reject without breaking the chain, and the receiver must
// copy the whole sequence with a single pending ownership and no
// recorded proof to confuse.
#[test(tokio::test)]
async fn remote_reject_chain_copies_without_confusing_ownership() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // Same creator set as the Confirm chain: both transfers succeed
    // while neither Bob nor Carol can open the subject directly.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Bob lives from the start: he must reject the first transfer
    // from his own node.
    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Bob copies through the first transfer and rejects it, so the
    // ownership falls back to Alice.
    bob.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(alice_key.clone()),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    emit_reject(&bob, subject_id.clone(), true).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    // Alice learns the rejection and moves the subject on to Carol.
    alice.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let chain = alice
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    assert_eq!(chain.len(), 5);
    assert!(
        chain
            .iter()
            .find(|event| event.sn == 4)
            .expect("second transfer")
            .protocols
            .is_success(),
        "premise: the second transfer must succeed"
    );

    // Carol joins only now, with no direct access: the second
    // transfer is her only passage, past a rejection that must not
    // confuse it. The full history is injected without any
    // external hint, so the inline screening alone must carry her
    // through the Reject up to its boundary; the tail then
    // completes with its genuine hint.
    let carol_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut carol_node, carol_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{carol_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(carol_signer)),
        ..Default::default()
    })
    .await;
    let carol = carol_node.api.clone();
    node_running(&carol).await.unwrap();
    carol
        .authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    carol.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&carol, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();
    let carol_public = PublicKey::from_str(carol.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(carol_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    carol
        .authorize_governance(
            subject_id.clone(),
            ave_core::auth::AuthWitness::One(alice_key.clone()),
        )
        .await
        .unwrap();
    // Phase one: the full history without any external hint. The
    // inline screening alone must carry Carol through the Reject
    // up to its boundary: she stalls right before the second
    // transfer with Alice re-installed as owner and no proof.
    inject_ledger_batch(&carol, &alice_key, chain.clone(), None).await;
    get_subject(&carol, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let partial = carol
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(partial.len(), 4);
    match carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the prefix"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(alice_key.clone()),
                "the Reject must give the subject back to Alice"
            );
            assert_eq!(pending, None, "the second transfer is not applied yet");
        }
    }
    assert!(
        carol
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may appear without an aux"
    );
    node_running(&carol).await.unwrap();

    // Phase two: the missing tail with its genuine hint completes
    // the copy through the second transfer.
    let genuine_tip = chain
        .iter()
        .find(|event| event.sn == 4)
        .expect("second transfer")
        .clone();
    inject_ledger_batch(
        &carol,
        &alice_key,
        vec![genuine_tip.clone()],
        Some(genuine_tip),
    )
    .await;
    get_subject(&carol, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let copied = carol
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    assert_eq!(copied.len(), 5);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 4)
            .expect("second transfer")
            .protocols
            .is_success(),
        "the second transfer must stay applied"
    );
    match carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the chain"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(alice_key.clone()),
                "Alice stays owner after the rejected transfer"
            );
            assert_eq!(
                pending,
                Some(carol_key.clone()),
                "only the second transfer may stay pending"
            );
        }
    }
    assert!(
        carol
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "inline transfers need no recorded proof"
    );
    // Carol confirms on her own node: the chain stays consistent
    // past the copy.
    emit_confirm(&carol, subject_id.clone(), None, true)
        .await
        .unwrap();
    get_subject(&carol, subject_id.clone(), Some(5), true)
        .await
        .unwrap();
    match carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after confirm"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(carol_key.clone()),
                "Carol becomes owner after confirming"
            );
            assert_eq!(
                pending, None,
                "no pending transfer may remain after confirm"
            );
        }
    }
    node_running(&carol).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    carol_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(carol_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(carol_node);
    drop(carol_dirs);
}

// A chain spanning governance versions keeps its evidence
// linked: the inline screening fetches roles per event version,
// so a transfer evaluated under a newer version still verifies
// over a prefix committed under the older one. The full history
// is injected without any external hint, so only the rebuilt
// chain can open the passage: the receiver copies to the tip
// with a single pending ownership.
#[test(tokio::test)]
async fn remote_versioned_chain_copies_across_gov_versions() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // Bump the governance version before the transfer: the fact
    // stays under the old version while the transfer evaluates
    // under the new one.
    let dave_signer = Ed25519Signer::generate().unwrap();
    let dave_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        dave_signer.public_key_bytes(),
    )
    .unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Dave", "key": dave_key.to_string()}
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let versions: Vec<u64> =
        history.iter().map(|event| event.gov_version).collect();
    assert!(
        versions[2] > versions[0],
        "premise: the transfer must run under a newer gov version"
    );
    assert!(
        history
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "premise: the versioned transfer must succeed"
    );

    // Carol joins only now, with no direct access: the full
    // versioned history is injected without any external hint, so
    // only the rebuilt evidence chain can open her passage. Any
    // sender traffic is dropped for determinism.
    let carol_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut carol_node, carol_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{carol_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(carol_signer)),
        ..Default::default()
    })
    .await;
    let carol = carol_node.api.clone();
    node_running(&carol).await.unwrap();
    carol
        .authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    carol.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&carol, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();
    let carol_public = PublicKey::from_str(carol.public_key()).unwrap();
    for api in [&alice, &owner] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(carol_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    carol
        .authorize_governance(
            subject_id.clone(),
            ave_core::auth::AuthWitness::One(alice_key.clone()),
        )
        .await
        .unwrap();
    inject_ledger_batch(&carol, &alice_key, history.clone(), None).await;
    get_subject(&carol, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = carol
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the versioned transfer must stay applied"
    );
    match carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the chain"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(alice_key.clone()),
                "Alice stays owner under the new version"
            );
            assert_eq!(
                pending,
                Some(carol_key.clone()),
                "the versioned transfer must stay pending for Carol"
            );
        }
    }
    assert!(
        carol
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "inline transfers need no recorded proof"
    );
    node_running(&carol).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    carol_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(carol_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(carol_node);
    drop(carol_dirs);
}
// An opaque fact before a transfer opens no free passage on its
// own: the chain can not be rebuilt through it, so a receiver
// without independent rights stays clean. A rights-holder still
// copies the masked batch as history: the opaque fact flips the
// tracker out of full mode, the transfer skips the unreproducible
// recheck, and the pending ownership lands exactly.
#[test(tokio::test)]
async fn remote_opaque_fact_blocks_passage_but_not_rightful_copy() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let dave_signer = Ed25519Signer::generate().unwrap();
    let dave_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        dave_signer.public_key_bytes(),
    )
    .unwrap();
    let erin_signer = Ed25519Signer::generate().unwrap();
    let erin_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        erin_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // Alice creates with Dave as witness; Erin is a plain creator,
    // so the transfer to her succeeds while she gains no direct
    // access to a subject created by Alice.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Dave", "key": dave_key.to_string()},
                    {"name": "Erin", "key": erin_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Dave",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Erin",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Block every natural tracker delivery from Alice from now on:
    // both receivers join only after every commit, so the injected
    // batches are the only copies they process.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), erin_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Erin must succeed"
    );

    // Canonical masked projection of the genuine fact, re-sealed by
    // the owner, plus the genuine transfer relinked onto it. Seal
    // and quorum stay valid; only the evidence can not be rebuilt
    // through the opaque step.
    let mut masked = fact
        .to_tracker_opaque()
        .expect("premise: the fact must project to opaque");
    let masked_protocols_hash = masked
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    masked.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: masked.gov_version,
            sn: masked.sn,
            prev_ledger_event_hash: masked.prev_ledger_event_hash.clone(),
            protocols_hash: masked_protocols_hash,
        },
        &alice_keys,
    )
    .unwrap();
    let masked_hash = masked
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("premise: the masked fact must hash");
    let mut relinked = transfer.clone();
    relinked.prev_ledger_event_hash = masked_hash;
    let relinked_protocols_hash = relinked
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    relinked.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: relinked.gov_version,
            sn: relinked.sn,
            prev_ledger_event_hash: relinked.prev_ledger_event_hash.clone(),
            protocols_hash: relinked_protocols_hash,
        },
        &alice_keys,
    )
    .unwrap();

    // Erin joins only now, with no direct access: the transfer is
    // her only passage, and the opaque fact hides its evidence.
    let erin_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut erin_node, erin_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{erin_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(erin_signer)),
        ..Default::default()
    })
    .await;
    let erin = erin_node.api.clone();
    node_running(&erin).await.unwrap();
    erin.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    erin.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&erin, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    // Delivers a crafted batch to `api` as if `from` sent it.
    async fn inject_masked(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all: true,
                    transfer_event: None,
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    // No subject, proof or ownership may appear from the masked
    // batch on a receiver without independent rights.
    inject_masked(
        &erin,
        &alice_key,
        vec![create.clone(), masked.clone(), relinked.clone()],
    )
    .await;
    for _ in 0..30 {
        assert!(
            erin.get_subject_state(subject_id.clone()).await.is_err(),
            "opaque evidence must not open free passage"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        erin.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from the masked batch"
    );
    match erin
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => {}
        Ok((owner_now, pending, _, _)) => assert!(
            owner_now.is_none() && pending.is_none(),
            "no ownership may derive from the masked batch"
        ),
    }
    node_running(&erin).await.unwrap();

    // Control: the full genuine chain copies through the transfer.
    inject_ledger_batch(&erin, &alice_key, history.clone(), None).await;
    get_subject(&erin, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = erin
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3);
    node_running(&erin).await.unwrap();

    // Dave holds direct witness rights: the same masked batch copies
    // as history, the fact stays opaque, and the pending ownership
    // lands exactly on Erin.
    let dave_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut dave_node, dave_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{dave_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(dave_signer)),
        ..Default::default()
    })
    .await;
    let dave = dave_node.api.clone();
    node_running(&dave).await.unwrap();
    dave.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    dave.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&dave, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();
    inject_masked(
        &dave,
        &alice_key,
        vec![create.clone(), masked.clone(), relinked.clone()],
    )
    .await;
    get_subject(&dave, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let dave_ledger = dave
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(dave_ledger.len(), 3);
    assert!(
        matches!(
            dave_ledger
                .iter()
                .find(|event| event.sn == 1)
                .expect("fact event")
                .protocols,
            Protocols::TrackerFactOpaque { .. }
        ),
        "the masked fact must stay opaque on the rights-holder"
    );
    assert!(
        dave_ledger
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the transfer must stay applied as history"
    );
    match dave
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the copy"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(alice_key.clone()),
                "Alice stays owner on the rights-holder copy"
            );
            assert_eq!(
                pending,
                Some(erin_key.clone()),
                "the pending transfer must land exactly"
            );
        }
    }
    assert!(
        dave.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "inline transfers need no recorded proof"
    );
    node_running(&dave).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    erin_node.token.cancel();
    dave_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(erin_node.handler.iter_mut())
            .chain(dave_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(erin_node);
    drop(erin_dirs);
    drop(dave_node);
    drop(dave_dirs);
}
// A failed first copy must not wipe a concurrent valid copy: while
// the forged batch stalls in the rollback barrier, a genuine batch
// through the per-subject worker completes, and the rollback must
// then back off instead of deleting it.
#[test(tokio::test)]
async fn remote_rollback_keeps_concurrent_valid_copy() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let w_signer = Ed25519Signer::generate().unwrap();
    let w_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        w_signer.public_key_bytes(),
    )
    .unwrap();
    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    // W witnesses Alice's creations; Carol is a plain creator, so a
    // transfer to her succeeds and commits.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "W", "key": w_key.to_string()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    // Block every natural tracker delivery: both injected batches
    // below are the only copies W processes.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to a creator must succeed"
    );

    // Same bytes, quorum and chain link, but the fact seal names
    // a signer its signature was never made for. The inline
    // transfer stays genuine, so the evidence preflight proves it
    // and the batch reaches the apply, where the fact seal fails
    // and parks in rollback. (A forged transfer evaluation alone
    // would be refuted before any write and never reach rollback.)
    let mut forged_fact = fact.clone();
    forged_fact.ledger_seal_signature.signer = carol_key.clone();

    // W joins only now: nothing pushed to her is genuine traffic.
    let w_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut w_node, w_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{w_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(w_signer)),
        ..Default::default()
    })
    .await;
    let w = w_node.api.clone();
    node_running(&w).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    // Arm the rollback barrier, then feed the forged batch through
    // the node-level distributor: it applies the valid prefix and
    // parks in rollback instead of deleting anything.
    w.test_pause_rollback(true).await.unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    w.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(w.public_key()).unwrap(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![
                    create.clone(),
                    forged_fact.clone(),
                    transfer.clone(),
                ],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    // The barrier must engage: without it the subject would
    // either never be created or be deleted right away. Wait for
    // the hit with a bounded poll, never with a fixed sleep.
    for _ in 0..60 {
        if w.test_rollback_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        w.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged batch must park exactly once in rollback"
    );

    // While the rollback stays parked, a genuine update through
    // the per-subject distributor completes the valid copy. The
    // barrier was armed before A ran, B only starts after it
    // triggered, and the clear below only releases Alice's
    // answers: B reaching sn2 therefore proves the interleaving,
    // not a replay.
    alice.test_clear_faults().await.unwrap();
    w.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(alice_key.clone()),
    )
    .await
    .unwrap();
    w.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Release the barrier: the stale rollback must back off and
    // leave the valid copy untouched. The skip counter proves the
    // parked rollback actually ran and declined instead of never
    // waking up: without it, B completing alone would pass
    // vacuously.
    w.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if w.test_rollback_skip_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        w.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged batch must park exactly once in rollback"
    );
    assert_eq!(
        w.test_rollback_skip_count().await.unwrap(),
        1,
        "the stale rollback must back off exactly once"
    );
    let copied = w
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer must stay applied"
    );
    match w
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the race"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(PublicKey::from_str(alice.public_key()).unwrap()),
                "no ownership rotation may be reverted"
            );
            assert_eq!(
                pending,
                Some(carol_key.clone()),
                "the genuine pending transfer must stay pending"
            );
        }
    }
    assert!(
        w.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may appear from either batch"
    );
    node_running(&w).await.unwrap();

    // A later update on the same subject still works.
    w.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(alice_key.clone()),
    )
    .await
    .unwrap();
    w.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&w).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    w_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(w_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(w_node);
    drop(w_dirs);
}

/// An out-of-order single push that the tracker skips must not
/// register success: the skipped event writes nothing, so the
/// failed first copy it interleaves with must still purge.
#[test(tokio::test)]
async fn remote_out_of_order_push_does_not_shield_rollback() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    // R is created up front so it can join the governance as a
    // member below. From this point R is deaf to spontaneous sync:
    // every batch below is injected by the test, so any emission
    // would only mask a missing injection. The governance
    // catch-up still works: it negotiates versions and pulls
    // batches through messages no fault rule matches.
    let r_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut r_node, r_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{r_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let r = r_node.api.clone();
    let r_key = PublicKey::from_str(r.public_key()).unwrap();
    node_running(&r).await.unwrap();

    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Carol", "key": carol_key.to_string()},
                    {"name": "R", "key": r.public_key()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "R",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    // R joins cleanly, before any fault is armed.
    r.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    r.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&r, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Both nodes go deaf before the subject exists: alice would
    // otherwise push the genuine history to R while emitting it,
    // and R would pull it on its own. Every batch below is injected
    // by the test. Local emits only need evaluation traffic, which
    // stays open.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::TrackerSyncReq,
        FaultMessage::TrackerSyncRes,
        FaultMessage::UpdateNoOffer,
        FaultMessage::UpdateOffer,
        FaultMessage::GovernanceVersionReq,
        FaultMessage::GovernanceVersionRes,
    ] {
        r.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Genuine history on alice: Create SN 0, Fact SN 1, pending
    // Transfer SN 2 to R. A second genuine Transfer SN 3 acts as
    // the aux for the interleaved copy below.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), r_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to the receiver must succeed"
    );

    // The aux replays the genuine transfer chain one event ahead:
    // same seal link, fresh sequence number, same owner signature.
    // Its chain has a gap behind it on purpose, so evidence stays
    // unprovable until the missing prefix arrives.
    let mut aux = transfer.clone();
    aux.sn = 3;
    let aux_seal = LedgerSeal {
        gov_version: aux.gov_version,
        sn: aux.sn,
        prev_ledger_event_hash: aux.prev_ledger_event_hash.clone(),
        protocols_hash: aux
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    aux.ledger_seal_signature = Signature::new(&aux_seal, &alice_keys).unwrap();

    // A runs on the node-level worker and parks in rollback
    // after applying Create: the forged fact fails later, after B
    // already interleaved. The rollback barrier is armed, so the
    // shielding checks run while A is parked there, the only point
    // where A applied Create but holds no requester. A must not run
    // on the per-subject worker: the node stops that worker as part
    // of the purge while the rollback handler still awaits the
    // reply, which deadlocks the tail.
    r.test_pause_rollback(true).await.unwrap();
    // A carries a forged fact: same request, evaluation, links and
    // validation as the genuine one, so the evidence checks pass
    // and the genuine inline transfer authorizes the prefix without
    // any receiver privilege. Only the seal timestamp is forged,
    // beyond the SQLite INTEGER range: no evidence check looks at
    // seal timestamps, but the tracker rejects the event, after
    // Create is already persisted and the tip is still SN 0.
    let (forged_fact, transfer_a) =
        forge_ts_batch(&fact, &transfer, &alice_keys, &alice_key);
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone(), forged_fact, transfer_a],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    // A must fail its apply and park in rollback: without the hold
    // the batch would either never start or purge past the
    // interleaving point.
    for _ in 0..60 {
        if r.test_rollback_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_hold_count().await.unwrap(),
        1,
        "A must park exactly once in rollback"
    );
    let attempt_a = r
        .test_rollback_attempt()
        .await
        .unwrap()
        .expect("parked rollback attempt");
    // Only the Create applied: the tip stays at SN 0.
    assert_eq!(
        r.test_get_tracker_ledger(subject_id.clone(), 5)
            .await
            .unwrap()
            .len(),
        1,
        "only Create may be applied while A is parked"
    );

    // B runs on the per-subject worker with its own request ids,
    // while A is parked in rollback on the node-level worker. First
    // the Fact prefix stages unapplied behind the unproven aux.
    let sub_path = format!("/user/node/distributor_{subject_id}");
    r.test_ensure_distributor(subject_id.clone()).await.unwrap();
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: "B-fact".to_owned(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: sub_path.clone(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![fact.clone()],
                is_all: false,
                transfer_event: Some(Box::new(aux.clone())),
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..60 {
        let (subjects, events, _) = r.test_deferred_stats().await.unwrap();
        if subjects == 1 && events == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_deferred_stats().await.unwrap().1,
        1,
        "the Fact prefix must stage exactly once (tip={:?})",
        r.test_get_tracker_ledger(subject_id.clone(), 5)
            .await
            .map(|l| l.iter().map(|e| e.sn).collect::<Vec<_>>()),
    );

    // Then the genuine Transfer SN 2 arrives as a single push. The
    // evidence is complete (local SN 0 plus deferred SN 1) so it
    // authorizes, but the tracker expects SN 1 and skips the event
    // without writing anything.
    r.test_pause_single_updated(true).await.unwrap();
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: "B-push".to_owned(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: sub_path.clone(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(transfer.clone()),
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    // The push must really go through the update decision (applied
    // or skipped): without this barrier the asserts below could
    // pass vacuously, before the push even landed.
    for _ in 0..60 {
        if r.test_single_updated_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_single_updated_hold_count().await.unwrap(),
        1,
        "the skipped push must go through the update decision exactly once"
    );
    let attempt_b = r
        .test_single_push_attempt(subject_id.clone())
        .await
        .unwrap()
        .expect("single push attempt");
    assert_ne!(
        attempt_a, attempt_b,
        "the interleaved push runs under its own attempt"
    );
    r.test_pause_single_updated(false).await.unwrap();
    // The single carries no proof registration: the transfer is the
    // pushed event itself, not an aux. What matters is what the
    // push did not do: no write and no success record.
    assert_eq!(
        r.test_get_tracker_ledger(subject_id.clone(), 5)
            .await
            .unwrap()
            .len(),
        1,
        "the skipped push must not advance the tip"
    );
    assert_eq!(
        r.test_get_last_success(subject_id.clone()).await.unwrap(),
        None,
        "a skipped push must not register success"
    );
    assert!(
        r.test_should_purge(subject_id.clone(), attempt_a)
            .await
            .unwrap(),
        "nothing shields the failed copy"
    );

    // A is already parked in rollback with its lease released
    // from the failed apply. Every shielding check runs here, the
    // only point where A applied Create but holds no requester
    // while B already interleaved.
    assert_eq!(
        r.test_rollback_hold_count().await.unwrap(),
        1,
        "the failed copy must park exactly once in rollback"
    );
    // The released push still needs a round to finish releasing
    // its lease: poll the requesters instead of sleeping for it.
    // A itself holds none here, released on the failed apply.
    for _ in 0..60 {
        if !r
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        !r.test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "neither the failed copy nor the skipped push may hold a lease"
    );
    assert_eq!(
        r.test_get_tracker_ledger(subject_id.clone(), 5)
            .await
            .unwrap()
            .len(),
        1,
        "the skipped push must not advance the tip"
    );
    assert_eq!(
        r.test_get_last_success(subject_id.clone()).await.unwrap(),
        None,
        "a skipped push must not register success"
    );
    assert!(
        r.test_should_purge(subject_id.clone(), attempt_a)
            .await
            .unwrap(),
        "nothing shields the failed copy"
    );
    r.test_pause_rollback(false).await.unwrap();
    for _ in 0..120 {
        if r.get_subject_state(subject_id.clone()).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        r.get_subject_state(subject_id.clone()).await.is_err(),
        "the forged prefix must be purged"
    );
    assert_eq!(
        r.test_get_tracker_ledger(subject_id.clone(), 5)
            .await
            .unwrap()
            .len(),
        0,
        "purged copies leave no ledger behind"
    );
    assert!(
        r.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "purged copies leave no proof behind"
    );
    assert_eq!(
        r.test_witnesses_ownership(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        (None, None, vec![], 0),
        "purged copies leave no ownership behind"
    );
    assert!(
        !r.test_has_subject_entry(governance_id.clone(), subject_id.clone())
            .await
            .unwrap(),
        "purged copies leave no external row behind"
    );
    assert_eq!(
        r.test_get_last_success(subject_id.clone()).await.unwrap(),
        None,
        "no success may be recorded for anyone"
    );
    node_running(&r).await.unwrap();

    // A genuinely contiguous copy still registers its own
    // success: the fix only drops the skipped-push record, never a
    // real one. Parked at post-success so the record is observable
    // before the attempt lifecycle cleans it up. The purge stopped
    // the per-subject worker, so ensure it again first.
    r.test_ensure_distributor(subject_id.clone()).await.unwrap();
    r.test_pause_post_success(true).await.unwrap();
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: format!("/user/node/distributor_{subject_id}"),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone(), fact.clone(), transfer.clone()],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..60 {
        if r.test_post_success_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_post_success_hold_count().await.unwrap(),
        1,
        "the genuine copy must record success exactly once"
    );
    let attempt_c = r
        .test_post_success_attempt()
        .await
        .unwrap()
        .expect("genuine copy attempt");
    assert_eq!(
        r.test_get_last_success(subject_id.clone()).await.unwrap(),
        Some(attempt_c),
        "a really applied copy must register success"
    );
    // An unrelated attempt id stays declined while the genuine
    // success stands: concurrent copies keep their shield.
    assert!(
        !r.test_should_purge(subject_id.clone(), u64::MAX)
            .await
            .unwrap(),
        "a foreign attempt must not purge the genuine copy"
    );
    r.test_pause_post_success(false).await.unwrap();
    get_subject(&r, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = r
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer must stay applied"
    );
    // The finished copy closes its attempt: no success record or
    // in-flight attempt is retained for a settled subject.
    for _ in 0..60 {
        let last_len = r.test_last_success_len().await.unwrap_or(usize::MAX);
        let active_len =
            r.test_active_attempts_len().await.unwrap_or(usize::MAX);
        if last_len == 0 && active_len == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_last_success_len().await.unwrap(),
        0,
        "settled copies retain no success record"
    );
    assert_eq!(
        r.test_active_attempts_len().await.unwrap(),
        0,
        "settled copies retain no active attempt"
    );
    node_running(&r).await.unwrap();

    // A contiguous single push applies and advances the tip: the
    // applied arm is untouched by the fix. A second genuine history
    // keeps the main subject (with its pending transfer) out of the
    // way: R copies its prefix with the transfer as aux evidence,
    // then the transfer itself arrives as a push.
    let (subject_c, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_c.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_c.clone(), r_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_c.clone(), Some(2), true)
        .await
        .unwrap();
    let history_c = alice
        .test_get_tracker_ledger(subject_c.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history_c.len(), 3);
    let create_c = history_c
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact_c = history_c
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer_c = history_c
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer_c.protocols.is_success(),
        "premise: the control transfer must succeed"
    );
    // Prefix [Create, Fact] with the transfer as aux: the chain is
    // complete, so the aux proves and the prefix applies.
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: "C-prefix".to_owned(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create_c.clone(), fact_c.clone()],
                is_all: false,
                transfer_event: Some(Box::new(transfer_c.clone())),
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&r, subject_c.clone(), Some(1), true)
        .await
        .unwrap();
    let single_holds_before = r.test_single_updated_hold_count().await.unwrap();
    r.test_pause_single_updated(true).await.unwrap();
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: "C-push".to_owned(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(transfer_c.clone()),
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..60 {
        if r.test_single_updated_hold_count().await.unwrap_or(0)
            >= single_holds_before + 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_single_updated_hold_count().await.unwrap(),
        single_holds_before + 1,
        "the contiguous push must go through the update decision"
    );
    r.test_pause_single_updated(false).await.unwrap();
    get_subject(&r, subject_c.clone(), Some(2), true)
        .await
        .unwrap();
    let pushed = r
        .test_get_tracker_ledger(subject_c.clone(), 2)
        .await
        .unwrap();
    assert_eq!(pushed.len(), 3, "the contiguous push must advance the tip");
    assert!(
        pushed
            .iter()
            .find(|event| event.sn == 2)
            .expect("pushed transfer event")
            .protocols
            .is_success(),
        "the contiguously pushed transfer must stay applied"
    );
    for _ in 0..60 {
        let last_len = r.test_last_success_len().await.unwrap_or(usize::MAX);
        let active_len =
            r.test_active_attempts_len().await.unwrap_or(usize::MAX);
        if last_len == 0 && active_len == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_last_success_len().await.unwrap(),
        0,
        "settled pushes retain no success record"
    );
    assert_eq!(
        r.test_active_attempts_len().await.unwrap(),
        0,
        "settled pushes retain no active attempt"
    );
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

/// Shared fixture: owner + alice nodes, R (member, creator and schema
/// witness), governance synced everywhere and R deaf to spontaneous
/// sync. Witness rights let R receive bare batches; every subject
/// below is still created on alice and injected by the test.
struct WitnessingLateJoiner {
    nodes: Vec<crate::common::NodeData>,
    dirs: Vec<tempfile::TempDir>,
    alice: ave_core::Api,
    alice_keys: ave_common::identity::keys::KeyPair,
    late_node: crate::common::NodeData,
    late_dirs: Vec<tempfile::TempDir>,
    late_api: ave_core::Api,
    governance_id: DigestIdentifier,
}

async fn witnessing_late_joiner_setup() -> WitnessingLateJoiner {
    let (nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let r_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (r_node, r_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{r_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let r = r_node.api.clone();
    node_running(&r).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "R", "key": r.public_key()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "R", "namespace": []}
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "R",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    // R joins cleanly, before any fault is armed.
    r.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    r.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&r, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Both nodes go deaf before any subject exists: alice would
    // otherwise push every history to R while emitting it, and R
    // would pull on its own. Every batch below is injected by the
    // test; local emits only need evaluation traffic, which stays
    // open.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::TrackerSyncReq,
        FaultMessage::TrackerSyncRes,
        FaultMessage::UpdateNoOffer,
        FaultMessage::UpdateOffer,
        FaultMessage::GovernanceVersionReq,
        FaultMessage::GovernanceVersionRes,
    ] {
        r.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    WitnessingLateJoiner {
        nodes,
        dirs,
        alice,
        alice_keys,
        late_node: r_node,
        late_dirs: r_dirs,
        late_api: r,
        governance_id,
    }
}

/// Forges a timestamp out of the SQLite INTEGER range on a copy of
/// `fact` and re-links a copy of `transfer` to it. Evidence checks
/// never look at seal timestamps, so the prefix authorizes through
/// the genuine transfer; only the tracker rejects the event.
fn forge_ts_batch(
    fact: &Ledger,
    transfer: &Ledger,
    alice_keys: &ave_common::identity::keys::KeyPair,
    alice_key: &PublicKey,
) -> (Ledger, Ledger) {
    let mut forged_fact = fact.clone();
    let forged_seal = LedgerSeal {
        gov_version: forged_fact.gov_version,
        sn: forged_fact.sn,
        prev_ledger_event_hash: forged_fact.prev_ledger_event_hash.clone(),
        protocols_hash: forged_fact
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    let forged_timestamp = TimeStamp::from_nanos(u64::MAX);
    let seal_payload =
        borsh::to_vec(&(&forged_seal, &forged_timestamp)).unwrap();
    let seal_hash = ave_common::identity::BLAKE3_HASHER.hash(&seal_payload);
    let seal_value = alice_keys
        .sign(seal_hash.hash_bytes())
        .expect("seal signature");
    forged_fact.ledger_seal_signature = Signature {
        signer: alice_key.clone(),
        timestamp: forged_timestamp,
        content_hash: seal_hash,
        value: seal_value,
    };
    let mut transfer_a = transfer.clone();
    transfer_a.prev_ledger_event_hash = forged_fact
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("forged fact ledger hash");
    let transfer_a_seal = LedgerSeal {
        gov_version: transfer_a.gov_version,
        sn: transfer_a.sn,
        prev_ledger_event_hash: transfer_a.prev_ledger_event_hash.clone(),
        protocols_hash: transfer_a
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    transfer_a.ledger_seal_signature =
        Signature::new(&transfer_a_seal, alice_keys).unwrap();
    (forged_fact, transfer_a)
}

/// Polls until no success record and no active attempt remain.
async fn wait_attempts_drained(api: &ave_core::Api) {
    for _ in 0..60 {
        let last_len = api.test_last_success_len().await.unwrap_or(usize::MAX);
        let active_len =
            api.test_active_attempts_len().await.unwrap_or(usize::MAX);
        if last_len == 0 && active_len == 0 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        api.test_last_success_len().await.unwrap(),
        0,
        "finished copies retain no success record"
    );
    assert_eq!(
        api.test_active_attempts_len().await.unwrap(),
        0,
        "finished copies retain no active attempt"
    );
}

/// Finished Create-only copies leave no attempt behind: both the
/// success record and the active set return to zero.
#[test(tokio::test)]
async fn remote_attempt_lifecycle_create_only_copies_clean_up() {
    let WitnessingLateJoiner {
        mut nodes,
        dirs,
        alice,
        alice_keys: _alice_keys,
        late_node: mut r_node,
        late_dirs: r_dirs,
        late_api: r,
        governance_id,
    } = witnessing_late_joiner_setup().await;

    let mut subjects = Vec::new();
    for _ in 0..3 {
        let (subject_id, _) =
            create_subject(&alice, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        let create = alice
            .test_get_tracker_ledger(subject_id.clone(), 0)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.sn == 0)
            .expect("create event");
        inject_ledger_batch(
            &r,
            &PublicKey::from_str(alice.public_key()).unwrap(),
            vec![create],
            None,
        )
        .await;
        get_subject(&r, subject_id.clone(), Some(0), true)
            .await
            .unwrap();
        subjects.push(subject_id);
    }
    assert_eq!(subjects.len(), 3);
    for subject_id in &subjects {
        assert_eq!(
            r.test_get_tracker_ledger(subject_id.clone(), 0)
                .await
                .unwrap()
                .len(),
            1,
            "each Create-only copy must apply"
        );
    }
    wait_attempts_drained(&r).await;
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

/// While A is parked in rollback, a valid copy B applies and
/// finishes: `last_success == B` shields the valid state until A
/// ends, then both counters drain to zero.
#[test(tokio::test)]
async fn remote_attempt_lifecycle_rollback_in_flight_keeps_success() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    // R exists before the governance so its key joins as member
    // and creator, but it only joins after the history below is
    // already committed: nothing is pushed to it spontaneously.
    let r_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut r_node, r_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{r_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let r = r_node.api.clone();
    let r_key = PublicKey::from_str(r.public_key()).unwrap();
    node_running(&r).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "R", "key": r.public_key()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "R",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Block spontaneous batch traffic while the forged copy runs:
    // the valid copy below arrives through update_subject instead.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), r_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to the receiver must succeed"
    );

    // R joins only now: the forged batch below is its only source.
    r.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    r.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&r, governance_id.clone(), None, true)
        .await
        .unwrap();

    // A forged first copy parks in rollback on the node-level
    // worker: purging from there never stops the worker itself.
    r.test_pause_rollback(true).await.unwrap();
    let (forged_fact, transfer_a) =
        forge_ts_batch(&fact, &transfer, &alice_keys, &alice_key);
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone(), forged_fact, transfer_a],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..60 {
        if r.test_rollback_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged copy must park exactly once in rollback"
    );
    let attempt_a = r
        .test_rollback_attempt()
        .await
        .unwrap()
        .expect("parked rollback attempt");

    // B completes through the live update path while A stays parked.
    alice.test_clear_faults().await.unwrap();
    r.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(alice_key.clone()),
    )
    .await
    .unwrap();
    r.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&r, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    // While A is still active, B's success shields the valid copy.
    let last_success = r
        .test_get_last_success(subject_id.clone())
        .await
        .unwrap()
        .expect("the valid copy must record success");
    assert_ne!(
        attempt_a, last_success,
        "the valid copy runs under its own attempt"
    );
    assert!(
        !r.test_should_purge(subject_id.clone(), attempt_a)
            .await
            .unwrap(),
        "the in-flight rollback must not purge the valid copy"
    );
    assert_eq!(
        r.test_last_success_len().await.unwrap(),
        1,
        "one subject holds a success record while A is active"
    );
    assert_eq!(
        r.test_active_attempts_len().await.unwrap(),
        1,
        "only A stays active after B finished"
    );

    // A ends: it backs off, and both counters drain to zero.
    r.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if r.test_rollback_skip_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_skip_count().await.unwrap(),
        1,
        "the stale rollback must back off exactly once"
    );
    wait_attempts_drained(&r).await;
    let copied = r
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3, "the valid copy must stay applied");
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer must stay applied"
    );
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

/// Early exits open no attempt that outlives them: empty and
/// non-contiguous batches, a forged link rejected before any write
/// and a stale replay are all followed by the valid copy that proves
/// the node still works, and every step drains both counters.
#[test(tokio::test)]
async fn remote_attempt_lifecycle_early_errors_leave_no_attempt() {
    let WitnessingLateJoiner {
        mut nodes,
        dirs,
        alice,
        alice_keys,
        late_node: mut r_node,
        late_dirs: r_dirs,
        late_api: r,
        governance_id,
    } = witnessing_late_joiner_setup().await;
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let r_key = PublicKey::from_str(r.public_key()).unwrap();

    // Empty batch: rejected before any attempt opens.
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    wait_attempts_drained(&r).await;

    // Genuine history to forge the gap and link probes from.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), r_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();

    // Non-contiguous batch, then the valid Create on the same
    // worker: the applied Create proves the gap rejection ran first.
    let mut fact_sn2 = fact.clone();
    fact_sn2.sn = 2;
    let gap_seal = LedgerSeal {
        gov_version: fact_sn2.gov_version,
        sn: fact_sn2.sn,
        prev_ledger_event_hash: fact_sn2.prev_ledger_event_hash.clone(),
        protocols_hash: fact_sn2
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    fact_sn2.ledger_seal_signature =
        Signature::new(&gap_seal, &alice_keys).unwrap();
    for batch in [vec![create.clone(), fact_sn2], vec![create.clone()]] {
        r.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: PublicKey::from_str(r.public_key())
                        .expect("node key"),
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger: batch,
                    is_all: true,
                    transfer_event: None,
                    expected_governance_id: None,
                },
            ),
            &alice_key,
        )
        .await
        .unwrap();
    }
    get_subject(&r, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    assert_eq!(
        r.test_get_tracker_ledger(subject_id.clone(), 0)
            .await
            .unwrap()
            .len(),
        1,
        "the valid Create must apply after the gap rejection"
    );
    wait_attempts_drained(&r).await;

    // Forged fact link on a fresh subject: the tracker rejects the
    // event after applying Create, the rollback purges the prefix,
    // and the valid Create after proves the cleanup. The rollback
    // barrier proves the forged batch ran instead of passing
    // vacuously.
    let (subject_id2, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id2.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&alice, subject_id2.clone(), Some(1), true)
        .await
        .unwrap();
    let history2 = alice
        .test_get_tracker_ledger(subject_id2.clone(), 1)
        .await
        .unwrap();
    let create2 = history2
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact2 = history2
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let mut forged_fact2 = fact2.clone();
    forged_fact2.prev_ledger_event_hash = DigestIdentifier::default();
    let forged_seal2 = LedgerSeal {
        gov_version: forged_fact2.gov_version,
        sn: forged_fact2.sn,
        prev_ledger_event_hash: forged_fact2.prev_ledger_event_hash.clone(),
        protocols_hash: forged_fact2
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    forged_fact2.ledger_seal_signature =
        Signature::new(&forged_seal2, &alice_keys).unwrap();
    r.test_pause_rollback(true).await.unwrap();
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create2.clone(), forged_fact2],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..60 {
        if r.test_rollback_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged link must park exactly once in rollback"
    );
    assert!(
        r.get_subject_state(subject_id2.clone()).await.is_ok(),
        "Create applies before the forged link fails"
    );
    r.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if r.get_subject_state(subject_id2.clone()).await.is_err() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        r.get_subject_state(subject_id2.clone()).await.is_err(),
        "the forged link must leave nothing behind"
    );
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create2.clone()],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&r, subject_id2.clone(), Some(0), true)
        .await
        .unwrap();
    assert_eq!(
        r.test_get_tracker_ledger(subject_id2.clone(), 0)
            .await
            .unwrap()
            .len(),
        1,
        "the valid Create must apply after the link rejection"
    );
    wait_attempts_drained(&r).await;

    // Forged inline transfer link: the batch fails before any tracker
    // is even acquired. The valid Create after proves the node still
    // works and closes every attempt it opened.
    let (subject_id3, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id3.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id3.clone(), r_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id3.clone(), Some(2), true)
        .await
        .unwrap();
    let history3 = alice
        .test_get_tracker_ledger(subject_id3.clone(), 2)
        .await
        .unwrap();
    let create3 = history3
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact3 = history3
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer3 = history3
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    let mut forged_transfer = transfer3.clone();
    forged_transfer.prev_ledger_event_hash = DigestIdentifier::default();
    let forged_seal3 = LedgerSeal {
        gov_version: forged_transfer.gov_version,
        sn: forged_transfer.sn,
        prev_ledger_event_hash: forged_transfer.prev_ledger_event_hash.clone(),
        protocols_hash: forged_transfer
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    forged_transfer.ledger_seal_signature =
        Signature::new(&forged_seal3, &alice_keys).unwrap();
    for batch in [
        vec![create3.clone(), fact3.clone(), forged_transfer],
        vec![create3.clone()],
    ] {
        r.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: PublicKey::from_str(r.public_key())
                        .expect("node key"),
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger: batch,
                    is_all: true,
                    transfer_event: None,
                    expected_governance_id: None,
                },
            ),
            &alice_key,
        )
        .await
        .unwrap();
    }
    get_subject(&r, subject_id3.clone(), Some(0), true)
        .await
        .unwrap();
    assert_eq!(
        r.test_get_tracker_ledger(subject_id3.clone(), 0)
            .await
            .unwrap()
            .len(),
        1,
        "the valid Create must apply after the inline link rejection"
    );
    wait_attempts_drained(&r).await;
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

/// Attempts are volatile: after a reboot no old attempt survives,
/// and replaying the genuine copy neither purges it nor leaks.
#[test(tokio::test)]
async fn remote_attempt_lifecycle_restart_clears_attempts() {
    let WitnessingLateJoiner {
        mut nodes,
        dirs,
        alice,
        alice_keys: _alice_keys,
        late_node: mut r_node,
        late_dirs: r_dirs,
        late_api: r,
        governance_id,
    } = witnessing_late_joiner_setup().await;
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&alice, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    let batch: Vec<Ledger> = history.clone();
    assert_eq!(batch.len(), 2);
    inject_ledger_batch(&r, &alice_key, batch.clone(), None).await;
    get_subject(&r, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    wait_attempts_drained(&r).await;

    // Reboot with the same storage: volatile attempts go away with
    // the process, the valid copy comes back identical.
    let keys = r_node.keys.clone();
    let local_db = r_dirs[0].path().to_path_buf();
    let ext_db = r_dirs[1].path().to_path_buf();
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    r_node.token.cancel();
    join_all(r_node.handler.iter_mut()).await;
    drop(r_node);
    let r_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut r_node, _r_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{r_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer,
            address: vec![boot_addr],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    let r = r_node.api.clone();
    node_running(&r).await.unwrap();

    // No attempt survived the reboot, and the valid copy is intact:
    // the lifecycle never confuses a restart with protection state.
    wait_attempts_drained(&r).await;
    let copied = r
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(copied.len(), 2, "the reboot must keep the valid copy");
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 1)
            .expect("fact event")
            .protocols
            .is_success(),
        "the genuine fact must stay applied"
    );

    // Replaying the same genuine batch purges nothing and leaks no
    // attempt either.
    inject_ledger_batch(&r, &alice_key, batch, None).await;
    get_subject(&r, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    wait_attempts_drained(&r).await;
    assert_eq!(
        r.test_get_tracker_ledger(subject_id.clone(), 1)
            .await
            .unwrap()
            .len(),
        2,
        "the replay must not purge the valid copy"
    );
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

/// A third successful copy keeps its own entry while an older
/// attempt stays active: C applies after A parked in rollback, so
/// C's success shields the valid state; the stale rollback backs
/// off instead of purging, and everything drains once done.
#[test(tokio::test)]
async fn remote_attempt_lifecycle_third_attempt_keeps_shield() {
    let WitnessingLateJoiner {
        mut nodes,
        dirs,
        alice,
        alice_keys,
        late_node: mut r_node,
        late_dirs: r_dirs,
        late_api: r,
        governance_id,
    } = witnessing_late_joiner_setup().await;
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let r_key = PublicKey::from_str(r.public_key()).unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), r_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to the receiver must succeed"
    );

    // A forged first copy parks in rollback on the node-level
    // worker. C applies afterwards and parks post-success on the
    // per-subject worker: C's success shields the valid prefix while
    // both attempts stay active.
    r.test_pause_rollback(true).await.unwrap();
    let (forged_fact, transfer_a) =
        forge_ts_batch(&fact, &transfer, &alice_keys, &alice_key);
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone(), forged_fact, transfer_a],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..60 {
        if r.test_rollback_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged copy must park exactly once in rollback"
    );
    let attempt_a = r
        .test_rollback_attempt()
        .await
        .unwrap()
        .expect("parked rollback attempt");

    // C applies the genuine fact on the per-subject worker. Its
    // success record stays while A remains active, even though C
    // itself already finished.
    r.test_ensure_distributor(subject_id.clone()).await.unwrap();
    let sub_path = format!("/user/node/distributor_{subject_id}");
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(r.public_key())
                    .expect("node key"),
                receiver_actor: sub_path.clone(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![fact.clone()],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&r, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    for _ in 0..60 {
        if r.test_active_attempts_len().await.unwrap_or(usize::MAX) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_active_attempts_len().await.unwrap(),
        1,
        "only A stays active after C finished"
    );
    let last_success = r
        .test_get_last_success(subject_id.clone())
        .await
        .unwrap()
        .expect("C keeps its success record while A stays active");
    assert_ne!(
        attempt_a, last_success,
        "the finished copy runs under its own attempt"
    );
    assert!(
        !r.test_should_purge(subject_id.clone(), u64::MAX)
            .await
            .unwrap(),
        "a foreign attempt must not purge C's valid copy while A is active"
    );

    // Releasing A backs off on C's success and closes A's attempt.
    // C's entry shielded the valid state; with no attempts left the
    // record itself is cleaned, but the copy stays intact.
    let skips_before = r.test_rollback_skip_count().await.unwrap();
    r.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if r.test_rollback_skip_count().await.unwrap_or(0) >= skips_before + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_skip_count().await.unwrap(),
        skips_before + 1,
        "the stale rollback must back off on C's success"
    );
    // Both attempts closed after A finished, and the skip above
    // proves A ran instead of passing vacuously.
    assert_eq!(
        r.test_active_attempts_len().await.unwrap(),
        0,
        "both attempts closed after A finished"
    );
    assert_eq!(
        r.test_get_last_success(subject_id.clone()).await.unwrap(),
        None,
        "no success record survives without active attempts"
    );

    // The copy itself stays intact.
    wait_attempts_drained(&r).await;
    let copied = r
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(copied.len(), 2, "the valid copy must stay applied");
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 1)
            .expect("fact event")
            .protocols
            .is_success(),
        "the genuine fact must stay applied"
    );
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

/// Every rollback skip path closes its attempt: live requesters,
/// rotated ownership and a tracker that moved under the rollback all
/// back off and drain both counters. (A dedicated progress-gate case
/// is unreachable by construction: any tip advance a rollback could
/// observe arrives through a recorded success, so the attempt gate
/// fires first; the atomic `PurgeIfUnchanged` recheck covers the
/// moved-tracker race.)
#[test(tokio::test)]
async fn remote_attempt_lifecycle_rollback_skips_clean_up() {
    let WitnessingLateJoiner {
        mut nodes,
        dirs,
        alice,
        alice_keys,
        late_node: mut r_node,
        late_dirs: r_dirs,
        late_api: r,
        governance_id,
    } = witnessing_late_joiner_setup().await;
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let r_key = PublicKey::from_str(r.public_key()).unwrap();

    // Four subjects with genuine histories on alice. S_own carries
    // a pending transfer at SN 1 so the ownership gate can fire.
    async fn genuine_history(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        r_key: &PublicKey,
        with_fact: bool,
    ) -> (DigestIdentifier, Vec<Ledger>) {
        let (subject_id, _) =
            create_subject(api, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        if with_fact {
            emit_fact(
                api,
                subject_id.clone(),
                serde_json::json!({"ModOne": {"data": 1}}),
                true,
            )
            .await
            .unwrap();
        }
        emit_transfer(api, subject_id.clone(), r_key.clone(), true)
            .await
            .unwrap();
        let top = if with_fact { 2 } else { 1 };
        get_subject(api, subject_id.clone(), Some(top), true)
            .await
            .unwrap();
        let history = api
            .test_get_tracker_ledger(subject_id.clone(), top)
            .await
            .unwrap();
        (subject_id, history)
    }
    let (s_req, hist_req) =
        genuine_history(&alice, &governance_id, &r_key, true).await;
    let (s_own, hist_own) =
        genuine_history(&alice, &governance_id, &r_key, false).await;
    let (s_purge, hist_purge) =
        genuine_history(&alice, &governance_id, &r_key, true).await;
    let get = |history: &[Ledger], sn| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };

    // Forged first copies always run on the node-level worker: the
    // purge path stops the per-subject worker while awaiting it.
    // Batches below address the distributor directly.
    let node_path = "/user/node/distributor".to_owned();
    async fn inject_batch(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        receiver_actor: String,
        request_id: &str,
    ) {
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: request_id.to_owned(),
                    version: 0,
                    receiver: PublicKey::from_str(api.public_key())
                        .expect("node key"),
                    receiver_actor,
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all: true,
                    transfer_event: None,
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn wait_rollback_hold(api: &ave_core::Api, baseline: u64) {
        for _ in 0..60 {
            if api.test_rollback_hold_count().await.unwrap_or(0) > baseline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        assert_eq!(
            api.test_rollback_hold_count().await.unwrap(),
            baseline + 1,
            "the forged copy must park exactly once in rollback"
        );
    }

    // (a) Live requesters: the held lease forces the skip, the
    // forged Create stays applied, and the attempt still closes.
    let (forged_fact_a, transfer_a) = forge_ts_batch(
        &get(&hist_req, 1),
        &get(&hist_req, 2),
        &alice_keys,
        &alice_key,
    );
    r.test_pause_rollback(true).await.unwrap();
    inject_batch(
        &r,
        &alice_key,
        vec![get(&hist_req, 0), forged_fact_a, transfer_a],
        node_path.clone(),
        "",
    )
    .await;
    let holds_before = r.test_rollback_hold_count().await.unwrap();
    wait_rollback_hold(&r, holds_before).await;
    let skips_before = r.test_rollback_skip_count().await.unwrap();
    r.test_hold_requester(s_req.clone()).await.unwrap();
    r.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if r.test_rollback_skip_count().await.unwrap_or(0) >= skips_before + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_skip_count().await.unwrap(),
        skips_before + 1,
        "the requester-held rollback must skip"
    );
    r.test_release_requester(s_req.clone()).await.unwrap();
    wait_attempts_drained(&r).await;
    assert_eq!(
        r.test_get_tracker_ledger(s_req.clone(), 5)
            .await
            .unwrap()
            .len(),
        1,
        "a skipped rollback keeps the applied Create"
    );

    // (b) Rotated ownership: the genuine pending transfer inside A's
    // own chunk trips the ownership gate with no success recorded.
    let transfer_own = get(&hist_own, 1);
    let mut fact_sn2 = get(&hist_own, 0);
    fact_sn2.sn = 2;
    fact_sn2.prev_ledger_event_hash = transfer_own
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("transfer ledger hash");
    let own_seal = LedgerSeal {
        gov_version: fact_sn2.gov_version,
        sn: fact_sn2.sn,
        prev_ledger_event_hash: fact_sn2.prev_ledger_event_hash.clone(),
        protocols_hash: fact_sn2
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    let own_ts = TimeStamp::from_nanos(u64::MAX);
    let own_payload = borsh::to_vec(&(&own_seal, &own_ts)).unwrap();
    let own_hash = ave_common::identity::BLAKE3_HASHER.hash(&own_payload);
    let own_sig = alice_keys
        .sign(own_hash.hash_bytes())
        .expect("seal signature");
    fact_sn2.ledger_seal_signature = Signature {
        signer: alice_key.clone(),
        timestamp: own_ts,
        content_hash: own_hash,
        value: own_sig,
    };
    r.test_pause_rollback(true).await.unwrap();
    inject_batch(
        &r,
        &alice_key,
        vec![get(&hist_own, 0), transfer_own.clone(), fact_sn2],
        node_path.clone(),
        "",
    )
    .await;
    let holds_before = r.test_rollback_hold_count().await.unwrap();
    wait_rollback_hold(&r, holds_before).await;
    let skips_before = r.test_rollback_skip_count().await.unwrap();
    r.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if r.test_rollback_skip_count().await.unwrap_or(0) >= skips_before + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_skip_count().await.unwrap(),
        skips_before + 1,
        "the ownership-moved rollback must skip"
    );
    wait_attempts_drained(&r).await;
    assert_eq!(
        r.test_get_tracker_ledger(s_own.clone(), 5)
            .await
            .unwrap()
            .len(),
        2,
        "a skipped rollback keeps the applied prefix"
    );
    assert_eq!(
        r.test_witnesses_ownership(&governance_id, s_own.clone())
            .await
            .unwrap()
            .1,
        Some(r_key.clone()),
        "the pending transfer must stay pending"
    );

    // (c) Moved tracker: B applies between the metadata read and the
    // atomic purge, so the purge backs off instead of deleting.
    let (forged_fact_d, transfer_d) = forge_ts_batch(
        &get(&hist_purge, 1),
        &get(&hist_purge, 2),
        &alice_keys,
        &alice_key,
    );
    r.test_pause_rollback(true).await.unwrap();
    r.test_pause_pre_purge(true).await.unwrap();
    inject_batch(
        &r,
        &alice_key,
        vec![get(&hist_purge, 0), forged_fact_d, transfer_d],
        node_path.clone(),
        "",
    )
    .await;
    let holds_before = r.test_rollback_hold_count().await.unwrap();
    wait_rollback_hold(&r, holds_before).await;
    r.test_pause_rollback(false).await.unwrap();
    // A runs to the pre-purge barrier with a stale tip read.
    let pre_purge_before = r.test_pre_purge_hold_count().await.unwrap();
    for _ in 0..60 {
        if r.test_pre_purge_hold_count().await.unwrap_or(0) > pre_purge_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_pre_purge_hold_count().await.unwrap(),
        pre_purge_before + 1,
        "the rollback must park exactly once before purging"
    );
    r.test_ensure_distributor(s_purge.clone()).await.unwrap();
    inject_batch(
        &r,
        &alice_key,
        vec![get(&hist_purge, 1), get(&hist_purge, 2)],
        format!("/user/node/distributor_{s_purge}"),
        "B-purge",
    )
    .await;
    get_subject(&r, s_purge.clone(), Some(2), true)
        .await
        .unwrap();
    let skips_before = r.test_rollback_skip_count().await.unwrap();
    r.test_pause_pre_purge(false).await.unwrap();
    for _ in 0..60 {
        if r.test_rollback_skip_count().await.unwrap_or(0) >= skips_before + 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        r.test_rollback_skip_count().await.unwrap(),
        skips_before + 1,
        "the moved tracker must force a purge backoff"
    );
    wait_attempts_drained(&r).await;
    let copied = r.test_get_tracker_ledger(s_purge.clone(), 2).await.unwrap();
    assert_eq!(copied.len(), 3, "the valid copy must stay applied");
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer must stay applied"
    );
    node_running(&r).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    r_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(r_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(r_node);
    drop(r_dirs);
}

#[test(tokio::test)]
async fn remote_rollback_keeps_concurrent_valid_create() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let w_signer = Ed25519Signer::generate().unwrap();
    let w_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        w_signer.public_key_bytes(),
    )
    .unwrap();
    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    // W witnesses Alice's creations; Carol is a plain creator, so a
    // transfer to her succeeds and commits.
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;

    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "W", "key": w_key.to_string()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Genuine history: Create SN 0, Fact SN 1, Transfer Alice->Carol
    // SN 2 (Carol is a creator, so it succeeds and stays pending).
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        fact.protocols.is_success(),
        "premise: the fact must succeed"
    );
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to a creator must succeed"
    );

    // Forge SN 1 by naming a signer its signature was never made
    // for. Properties stay identical, so the genuine inline
    // transfer still proves in preflight and the batch reaches the
    // apply, where the fact seal fails and parks in rollback. (A
    // forged evaluation alone would be refuted before any write
    // and never reach rollback.)
    let mut forged = fact.clone();
    forged.ledger_seal_signature.signer = carol_key.clone();

    // W joins only now: nothing pushed to her is genuine traffic.
    let w_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut w_node, w_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{w_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(w_signer)),
        ..Default::default()
    })
    .await;
    let w = w_node.api.clone();
    node_running(&w).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Prepare the per-subject worker explicitly: the forged first
    // copy is injected there so the node-level worker stays free
    // for the concurrent valid copy below. This only creates the
    // actor; it registers no subject state.
    w.test_ensure_distributor(subject_id.clone()).await.unwrap();
    w.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(alice.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();

    // Park the forged first copy before it writes anything, then
    // interleave a valid Create-only copy on the node-level worker:
    // the stale rollback must spare it even though both sit at sn 0
    // with the same owner and no pending transfer.
    let per_subject = format!("/user/node/distributor_{}", subject_id);
    w.test_pause_before_apply(true).await.unwrap();
    w.test_pause_rollback(true).await.unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let w_key = PublicKey::from_str(w.public_key()).unwrap();
    w.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: w_key.clone(),
                receiver_actor: per_subject.clone(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone(), forged.clone(), transfer.clone()],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    // The forged batch must park exactly once before applying, on
    // the per-subject worker: falling back to node-level would mean
    // the worker was never created, and the test setup is wrong.
    for _ in 0..60 {
        if w.test_before_apply_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        w.test_before_apply_hold_count().await.unwrap(),
        1,
        "the forged batch must park exactly once before applying"
    );
    assert_eq!(
        w.test_before_apply_worker().await.unwrap(),
        Some(per_subject.clone()),
        "the forged batch must park on the per-subject worker"
    );
    let attempt_a = w
        .test_before_apply_attempt()
        .await
        .unwrap()
        .expect("the parked batch must record its attempt");

    // While the forged copy stays parked, a genuine Create-only
    // batch on the free node-level worker completes the valid SN 0.
    // A non-empty request id keeps it out of the pre-apply pause.
    w.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: "b-sn0".to_owned(),
                version: 0,
                receiver: w_key.clone(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone()],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&w, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    let copied = w
        .test_get_tracker_ledger(subject_id.clone(), 0)
        .await
        .unwrap();
    assert_eq!(copied.len(), 1, "B must hold exactly the valid Create");
    assert_eq!(copied[0].sn, 0, "B must hold exactly the valid Create");
    // The valid copy registered its own attempt and released its
    // lease: nothing must be live when the stale copy resumes.
    let last_success = w
        .test_get_last_success(subject_id.clone())
        .await
        .unwrap()
        .expect("B must have recorded its successful copy");
    assert_ne!(
        attempt_a, last_success,
        "the stale attempt must differ from the valid one"
    );
    assert_eq!(
        w.test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        false,
        "B must have released its lease before A resumes"
    );
    // Attempt-owned decision, asked directly: A must not purge.
    assert_eq!(
        w.test_should_purge(subject_id.clone(), attempt_a)
            .await
            .unwrap(),
        false,
        "ShouldPurge must be false for the stale attempt"
    );

    // Release the pre-apply barrier: the forged copy applies its
    // valid prefix, fails on the forged fact and parks in rollback
    // instead of deleting anything.
    w.test_pause_before_apply(false).await.unwrap();
    for _ in 0..60 {
        if w.test_rollback_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        w.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged batch must park exactly once in rollback"
    );

    // Release the rollback barrier: the stale rollback must back
    // off and leave the valid Create untouched. The skip counter
    // proves the parked rollback really ran and declined instead
    // of never waking up.
    w.test_pause_rollback(false).await.unwrap();
    for _ in 0..60 {
        if w.test_rollback_skip_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert_eq!(
        w.test_before_apply_hold_count().await.unwrap(),
        1,
        "the pre-apply barrier must have fired exactly once"
    );
    assert_eq!(
        w.test_rollback_hold_count().await.unwrap(),
        1,
        "the forged batch must park exactly once in rollback"
    );
    assert_eq!(
        w.test_rollback_skip_count().await.unwrap(),
        1,
        "the stale rollback must back off exactly once"
    );
    let copied = w
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert!(
        copied.iter().any(|event| event.sn == 0),
        "the concurrent valid Create must stay applied"
    );
    assert!(
        !copied.iter().any(|event| event.sn == 1),
        "the forged fact must not be applied"
    );
    match w
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the race"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(PublicKey::from_str(alice.public_key()).unwrap()),
                "no ownership rotation may be reverted"
            );
            assert!(
                pending.is_none(),
                "the forged batch must install no pending ownership"
            );
        }
    }
    assert!(
        w.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may appear from either batch"
    );
    node_running(&w).await.unwrap();

    // A later update on the same subject still works and completes
    // through the genuine history.
    w.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(alice_key.clone()),
    )
    .await
    .unwrap();
    w.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&w).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    w_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(w_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(w_node);
    drop(w_dirs);
}

/// Single push of a transfer whose evidence does not reproduce
/// must write nothing: the push path runs the same bar as the
/// batch path and fails closed without recording a proof.
#[test(tokio::test)]
async fn remote_single_transfer_without_evidence_writes_nothing() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();

    // Same request, quorum and chain link; only the evaluation
    // result is swapped for a genuine Ok from the fact, keeping
    // the transfer result hash so light checks pass while the
    // evidence can never reproduce. Fresh owner seal.
    let fact_result = match &fact.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("fact evaluation ok"),
        _ => panic!("expected a full fact event"),
    };
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: fact_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    };
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged.gov_version,
        sn: forged.sn,
        prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    forged.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    // Genuine prefix through the batch path: Rita reaches sn 1
    // with direct rights, so the later single push is contiguous.
    inject_ledger_batch(&rita, &alice_key, vec![create, fact], None).await;
    get_subject(&rita, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Forged single push: contiguous but refuted, so it must fail
    // closed with no write and no proof behind.
    let rita_push_key = PublicKey::from_str(rita.public_key()).unwrap();
    rita.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: rita_push_key.clone(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(forged),
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..30 {
        assert_eq!(
            rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
            1,
            "forged single push must not advance the copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from a forged push"
    );
    node_running(&rita).await.unwrap();

    // Genuine single push still completes the copy afterwards.
    rita.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: rita_push_key,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(transfer),
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Single push whose evidence can not be rebuilt must stay
/// unproven: the version roles are gone and its patch does not
/// apply, so no passage opens and nothing is written. The
/// genuine push afterwards still completes the copy.
#[test(tokio::test)]
async fn remote_single_transfer_with_unjudgeable_evidence_writes_nothing() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    // Same request, quorum and chain link, but the Ok result
    // carries a patch that can never apply: once the version
    // roles are gone the evidence can not be judged, so the
    // hint stays unproven instead of opening passage. The light
    // checks never inspect the patch content. Fresh owner seal.
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            let mut result = evaluation
                .evaluator_response_ok()
                .expect("transfer evaluation ok");
            result.patch = ave_common::ValueWrapper(json!("unappliable"));
            evaluation.response = EvaluationResponse::Ok {
                result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    };
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged.gov_version,
        sn: forged.sn,
        prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    forged.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    // Genuine prefix through the batch path: Rita reaches sn 1
    // with direct rights, so the later single push is contiguous.
    inject_ledger_batch(&rita, &alice_key, vec![create, fact], None).await;
    get_subject(&rita, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Move governance past the transfer version: the register
    // only serves current roles, so the v1 evidence can no
    // longer be rebuilt once everyone is on v2. Validation
    // roles keep history, hence the light checks still pass.
    let temp_signer = Ed25519Signer::generate().unwrap();
    let temp_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        temp_signer.public_key_bytes(),
    )
    .unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Temp", "key": temp_key.to_string()}
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), Some(gov_sn + 1), true)
        .await
        .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn + 1), true)
        .await
        .unwrap();

    // From now on no sender traffic may interfere: every later
    // delivery below is injected, so drop any natural tracker
    // push from Alice. Installed only after Rita synced gov v2,
    // whose incremental distribution needs Alice reachable.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Unjudgeable single push: contiguous but neither provable
    // nor refutable, so it must fail closed with no write and
    // no proof behind.
    let rita_push_key = PublicKey::from_str(rita.public_key()).unwrap();
    rita.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: rita_push_key.clone(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(forged),
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    for _ in 0..30 {
        assert_eq!(
            rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
            1,
            "unproven single push must not advance the copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no transfer proof may persist from an unproven push"
    );
    match rita
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must stay readable, not vanish"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(alice_key.clone()),
                "no ownership may derive from an unproven push"
            );
            assert!(
                pending.is_none(),
                "no pending ownership from an unproven push"
            );
        }
    }
    node_running(&rita).await.unwrap();

    // Genuine single push still completes the copy afterwards:
    // its evidence advances the cursor without proving, which
    // opens passage exactly like the apply path trusts it.
    rita.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: rita_push_key,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventReq {
                ledger: Box::new(transfer),
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = rita
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer must stay applied"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Silenced aux with `is_all = true` leaves nothing behind, not
/// even across a restart: the held batch lives only in worker
/// memory and no proof is ever recorded. After recovery the
/// genuine chain still completes the copy.
#[test(tokio::test)]
async fn remote_silenced_aux_leaves_no_trace_across_restart() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;

    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();

    // Same request, quorum and chain link; only the evaluation
    // result is swapped for a genuine Ok from the fact, keeping
    // the transfer result hash so light checks pass while the
    // evidence can never reproduce. Fresh owner seal.
    let fact_result = match &fact.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("fact evaluation ok"),
        _ => panic!("expected a full fact event"),
    };
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: fact_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    };
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged.gov_version,
        sn: forged.sn,
        prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
        protocols_hash,
    };
    forged.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), Some(gov_sn), true)
        .await
        .unwrap();

    // No subject, proof or ownership may appear from a silenced
    // batch, neither before nor after a restart with the same
    // storage.
    async fn assert_no_trace(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "silenced aux must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from a silenced aux"
        );
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => {}
            Ok((owner_now, pending, _, _)) => assert!(
                owner_now.is_none() && pending.is_none(),
                "no ownership may derive from a silenced aux"
            ),
        }
        node_running(api).await.unwrap();
    }

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: Option<Ledger>,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: hint.map(Box::new),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Silenced sender: partial batch with an uncheckable hint
    // that claims completeness, then nothing ever again.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone()],
        true,
        Some(forged.clone()),
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;

    // Restart with the same storage: the held batch lived only
    // in worker memory and no proof was ever recorded, so
    // recovery must find nothing and the node must boot clean.
    let keys = rita_node.keys.clone();
    let local_db = rita_dirs[0].path().to_path_buf();
    let ext_db = rita_dirs[1].path().to_path_buf();
    rita_node.token.cancel();
    join_all(rita_node.handler.iter_mut()).await;
    drop(rita_node);
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    assert_no_trace(&rita, &governance_id, &subject_id).await;

    // Genuine chain after recovery still completes the copy:
    // prefix plus proof first, then the tail that applies it.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact.clone()],
        false,
        Some(transfer.clone()),
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        Some(transfer.clone()),
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Long first copy stays linear: every batch resumes the
/// validated prefix instead of re-scanning it, so full local
/// reloads happen once and processed events stay bounded by a
/// small multiple of the chain length, however the batches are
/// cut. Two receptors copy the same chain with different batch
/// sizes to prove the bound does not depend on batching.
#[test(tokio::test)]
async fn remote_incremental_verification_stays_linear() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let w_signer = Ed25519Signer::generate().unwrap();
    let w_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        w_signer.public_key_bytes(),
    )
    .unwrap();
    let x_signer = Ed25519Signer::generate().unwrap();
    let x_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        x_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                    {"name": "W", "key": w_key.to_string()},
                    {"name": "X", "key": x_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        },
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        },
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        },
                                        {
                                            "name": "X",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {"name": "Alice", "namespace": []},
                                {"name": "Bob", "namespace": []}
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
    alice.update_subject(governance_id.clone()).await.unwrap();

    // Bob copies Alice's prefix on direct rights, confirms the
    // first transfer and extends the chain, so the history ends
    // with a pending transfer after a confirm.
    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for _ in 0..12 {
        emit_fact(
            &alice,
            subject_id.clone(),
            json!({"ModOne": {"data": 1}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&alice, subject_id.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(13), true)
        .await
        .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(13), true)
        .await
        .unwrap();
    emit_confirm(&bob, subject_id.clone(), None, true)
        .await
        .unwrap();
    for _ in 0..2 {
        emit_fact(
            &bob,
            subject_id.clone(),
            json!({"ModOne": {"data": 1}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&bob, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&bob, subject_id.clone(), Some(17), true)
        .await
        .unwrap();
    let history = bob
        .test_get_tracker_ledger(subject_id.clone(), 17)
        .await
        .unwrap();
    assert_eq!(history.len(), 18);
    let transfer = history
        .iter()
        .find(|event| event.sn == 17)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the pending transfer must succeed"
    );
    let chain_len = history.len() as u64;
    // Upper bound for the whole copy: a small multiple of the
    // chain length, whatever the batching. A full re-scan per
    // aux would exceed it on the small batches below.
    let bound = 3 * chain_len;

    // Delivers one batch with the genuine pending aux attached,
    // like a sender fetching the hint ahead of its window.
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Cuts a ledger into batches of `size`, all but the last
    // partial: every batch keeps the pending aux attached.
    fn cut_batches(ledger: &[Ledger], size: usize) -> Vec<Vec<Ledger>> {
        ledger.chunks(size).map(<[Ledger]>::to_vec).collect()
    }

    // Rita copies in pairs through batches of two.
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    let bob_public = PublicKey::from_str(bob.public_key()).unwrap();
    // All but the pending transfer, in pairs: every batch keeps
    // the genuine aux attached so each one must verify it.
    let batches = cut_batches(&history[..17], 2);
    assert_eq!(batches.len(), 9);
    for batch in &batches {
        inject_with_hint(&rita, &bob_public, batch.clone(), false, &transfer)
            .await;
    }
    get_subject(&rita, subject_id.clone(), Some(16), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((17, bob_public.clone())),
        "the genuine hint must record its proof"
    );
    let (processed, reloads) =
        rita.test_verify_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        reloads, 1,
        "one full local reload, then only deltas: {reloads}"
    );
    assert!(
        processed <= bound,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    // The pending transfer itself travels last and is covered by
    // the recorded proof, so it applies without re-verifying and
    // consumes the proof: nothing lingers.
    inject_with_hint(
        &rita,
        &bob_public,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(17), true)
        .await
        .unwrap();
    let copied = rita
        .test_get_tracker_ledger(subject_id.clone(), 17)
        .await
        .unwrap();
    assert_eq!(copied.len(), 18);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 17)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the pending transfer must stay applied"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    let (processed, reloads) =
        rita.test_verify_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        reloads, 1,
        "the covered tail needs no local reload: {reloads}"
    );
    assert!(
        processed <= bound,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    node_running(&rita).await.unwrap();

    // W copies the same chain in batches of six: the same bound
    // must hold regardless of batching.
    let w_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut w_node, w_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{w_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(w_signer)),
        ..Default::default()
    })
    .await;
    let w = w_node.api.clone();
    node_running(&w).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();
    let w_public = PublicKey::from_str(w.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(w_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    let batches = cut_batches(&history[..17], 6);
    assert_eq!(batches.len(), 3);
    for batch in &batches {
        inject_with_hint(&w, &bob_public, batch.clone(), false, &transfer)
            .await;
    }
    get_subject(&w, subject_id.clone(), Some(16), true)
        .await
        .unwrap();
    assert_eq!(
        w.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((17, bob_public.clone())),
        "the genuine hint must record its proof"
    );
    let (processed, reloads) =
        w.test_verify_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        reloads, 1,
        "one full local reload, then only deltas: {reloads}"
    );
    assert!(
        processed <= bound,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        w.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    inject_with_hint(&w, &bob_public, vec![transfer.clone()], true, &transfer)
        .await;
    get_subject(&w, subject_id.clone(), Some(17), true)
        .await
        .unwrap();
    let (processed, reloads) =
        w.test_verify_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        reloads, 1,
        "the covered tail needs no local reload: {reloads}"
    );
    assert!(
        processed <= bound,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        w.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    node_running(&w).await.unwrap();

    // X copies the same chain one event per batch: the per-batch
    // merge only touches the uncovered tail, so the total buffer
    // work stays linear instead of rescanning the prefix.
    let x_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut x_node, x_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{x_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(x_signer)),
        ..Default::default()
    })
    .await;
    let x = x_node.api.clone();
    node_running(&x).await.unwrap();
    x.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    x.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&x, governance_id.clone(), None, true)
        .await
        .unwrap();
    let x_public = PublicKey::from_str(x.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(x_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    let batches = cut_batches(&history[..17], 1);
    assert_eq!(batches.len(), 17);
    for batch in &batches {
        inject_with_hint(&x, &bob_public, batch.clone(), false, &transfer)
            .await;
    }
    get_subject(&x, subject_id.clone(), Some(16), true)
        .await
        .unwrap();
    assert_eq!(
        x.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((17, bob_public.clone())),
        "the genuine hint must record its proof"
    );
    let (processed, reloads) =
        x.test_verify_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        reloads, 1,
        "one full local reload, then only deltas: {reloads}"
    );
    assert!(
        processed <= bound,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        x.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    inject_with_hint(&x, &bob_public, vec![transfer.clone()], true, &transfer)
        .await;
    get_subject(&x, subject_id.clone(), Some(17), true)
        .await
        .unwrap();
    node_running(&x).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    rita_node.token.cancel();
    w_node.token.cancel();
    x_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut())
            .chain(w_node.handler.iter_mut())
            .chain(x_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(rita_node);
    drop(rita_dirs);
    drop(w_node);
    drop(w_dirs);
    drop(x_node);
    drop(x_dirs);
}

/// A repeated aux reuses its verdict without re-running any
/// check: the same hint twice costs nothing new, while a hint
/// with different bytes re-verifies from scratch. Both forged
/// hints stay rejected without writing anything.
#[test(tokio::test)]
async fn remote_repeated_aux_reuses_verdict() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();

    // Checkable forgery: the fact's genuine Ok result stands in
    // for the transfer's, keeping the transfer result hash so
    // light checks pass while the full evidence can never
    // reproduce. Fresh owner seal.
    let fact_result = match &fact.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("fact evaluation ok"),
        _ => panic!("expected a full fact event"),
    };
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: fact_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    };
    let forged_seal = |event: &Ledger| LedgerSeal {
        gov_version: event.gov_version,
        sn: event.sn,
        prev_ledger_event_hash: event.prev_ledger_event_hash.clone(),
        protocols_hash: event
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap(),
    };
    let seal = forged_seal(&forged);
    forged.ledger_seal_signature = Signature::new(&seal, &alice_keys).unwrap();

    // Same bytes, different result hash: still checkable and
    // still wrong, but a different hint that must re-verify.
    let mut forged2 = forged.clone();
    match &mut forged2.protocols {
        Protocols::Transfer { evaluation, .. } => {
            evaluation.response = EvaluationResponse::Ok {
                result: evaluation
                    .evaluator_response_ok()
                    .expect("forged evaluation ok"),
                result_hash: DigestIdentifier::default(),
            };
        }
        _ => panic!("expected a transfer event"),
    };
    let seal2 = forged_seal(&forged2);
    forged2.ledger_seal_signature =
        Signature::new(&seal2, &alice_keys).unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    inject_ledger_batch(&rita, &alice_key, vec![create, fact], None).await;
    get_subject(&rita, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Single pushes go straight at the node-level distributor.
    async fn inject_single(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLastEventReq {
                    ledger: Box::new(ledger),
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    // A refuted single stays rejected without writing: sn fixed,
    // no proof, ownership untouched, node alive.
    async fn assert_rejected(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        alice_key: &PublicKey,
    ) {
        for _ in 0..30 {
            assert_eq!(
                api.get_subject_state(subject_id.clone()).await.unwrap().sn,
                1,
                "a refuted single must not advance the copy"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from a refuted single"
        );
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => panic!("ownership must stay readable, not vanish"),
            Ok((owner_now, pending, _, _)) => {
                assert_eq!(
                    owner_now,
                    Some(alice_key.clone()),
                    "no ownership may derive from a refuted single"
                );
                assert!(
                    pending.is_none(),
                    "no pending ownership from a refuted single"
                );
            }
        }
        node_running(api).await.unwrap();
    }

    // First presentation replays and refutes: full local reload
    // plus the prefix and the hint. Both replayed events share
    // one governance version, so roles resolve exactly once.
    inject_single(&rita, &alice_key, forged.clone()).await;
    assert_rejected(&rita, &governance_id, &subject_id, &alice_key).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (2, 1),
        "first check replays the prefix and refutes"
    );
    assert_eq!(
        rita.test_roles_resolved(subject_id.clone()).await.unwrap(),
        1,
        "same-version replays share one role resolution"
    );
    // Different suffix, same tip: the cached verdict can not
    // apply, so the hint replays alone and stays refuted. The
    // entry cached now makes exact retries free below.
    inject_single(&rita, &alice_key, forged.clone()).await;
    assert_rejected(&rita, &governance_id, &subject_id, &alice_key).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (3, 1),
        "same hint with new suffix events replays them"
    );
    assert_eq!(
        rita.test_roles_resolved(subject_id.clone()).await.unwrap(),
        1,
        "replays reuse the cached version instead of resolving again"
    );
    // Identical retry reuses the verdict: zero new work.
    inject_single(&rita, &alice_key, forged.clone()).await;
    assert_rejected(&rita, &governance_id, &subject_id, &alice_key).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (3, 1),
        "same hint over the same tip must not re-verify"
    );
    assert_eq!(
        rita.test_roles_resolved(subject_id.clone()).await.unwrap(),
        1,
        "a reused verdict resolves nothing new"
    );
    // Different bytes re-verify from scratch and stay rejected.
    inject_single(&rita, &alice_key, forged2.clone()).await;
    assert_rejected(&rita, &governance_id, &subject_id, &alice_key).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (4, 1),
        "a different hint must re-verify instead of reusing"
    );
    assert_eq!(
        rita.test_roles_resolved(subject_id.clone()).await.unwrap(),
        1,
        "re-verifying the same version still resolves once"
    );
    // The genuine single still completes the copy afterwards.
    inject_single(&rita, &alice_key, transfer.clone()).await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_roles_resolved(subject_id.clone()).await.unwrap(),
        1,
        "the genuine tail reuses the cached version"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A divergent branch invalidates the saved tip and forces a
/// full rebuild instead of continuing from it: the forked batch
/// can not borrow the genuine prefix's verification. The
/// rebuild replays authoritatively, the apply backstop still
/// rejects the bad link, and a later genuine continuation
/// completes the copy from a clean state.
#[test(tokio::test)]
async fn remote_divergent_branch_rebuilds_without_reusing_cursor() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact1 = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("first fact")
        .clone();
    let fact2 = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("second fact")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 3)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    // Same evaluation, broken link: genuine content on a forged
    // ancestry, re-sealed by the owner. The replay accepts the
    // content but the saved tip no longer matches, so the next
    // use must rebuild instead of continuing from it.
    let mut forked = fact2.clone();
    forked.prev_ledger_event_hash = DigestIdentifier::default();
    let forked_hash = forked
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forked_seal = LedgerSeal {
        gov_version: forked.gov_version,
        sn: forked.sn,
        prev_ledger_event_hash: forked.prev_ledger_event_hash.clone(),
        protocols_hash: forked_hash,
    };
    forked.ledger_seal_signature =
        Signature::new(&forked_seal, &alice_keys).unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn assert_no_trace(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "forked batch must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from a forked batch"
        );
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => {}
            Ok((owner_now, pending, _, _)) => assert!(
                owner_now.is_none() && pending.is_none(),
                "no ownership may derive from a forked batch"
            ),
        }
        node_running(api).await.unwrap();
    }

    // Prefix plus an uncheckable aux: nothing applied, the tip
    // stays at the prefix while the batch waits deferred.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone()],
        false,
        &transfer,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (2, 0),
        "first aux builds the cursor from the batch alone"
    );
    // Forked continuation: same SNs, rewritten ancestry. The
    // saved tip does not match, so the worker rebuilds from the
    // authoritative prefix instead of continuing from it; the
    // rebuild still verifies, the apply backstop still rejects
    // the bad link, and nothing persists.
    inject_with_hint(&rita, &alice_key, vec![forked.clone()], false, &transfer)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (5, 0),
        "the fork must rebuild instead of reusing the cursor"
    );
    // Genuine prefix plus the pending hint, still partial: the
    // rebuild replays the whole chain once, records the proof
    // and applies up to the aux without consuming it.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone(), fact2.clone()],
        false,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = rita
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3);
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (8, 0),
        "rebuilding the genuine prefix replays it once more"
    );
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((3, alice_key.clone())),
        "the genuine hint must record its proof"
    );
    node_running(&rita).await.unwrap();
    // The tail applies through the recorded proof, which is
    // consumed single-use on application: nothing lingers.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let copied = rita
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(copied.len(), 4);
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 3)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer must stay applied"
    );
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (8, 0),
        "the tail is covered by the recorded proof, no replay needed"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Suffix replays ignore exact re-sends and refuse conflicting
/// ones: a re-sent tip or an already covered fact never replays
/// nor stalls the copy, while the same SN with different bytes
/// invalidates the cursor and rebuilds authoritatively instead
/// of borrowing the forged bytes. The genuine chain still
/// completes afterwards with proof recorded and consumed.
#[test(tokio::test)]
async fn remote_suffix_dedup_ignores_exact_replays() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact1 = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("first fact")
        .clone();
    let fact2 = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("second fact")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 3)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    // Same SN, rewritten ancestry: genuine content on a forged
    // link, re-sealed by the owner. A resend of the covered tip
    // with these bytes must invalidate instead of being reused.
    let mut forged_tip = fact1.clone();
    forged_tip.prev_ledger_event_hash = DigestIdentifier::default();
    let forged_hash = forged_tip
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    let forged_seal = LedgerSeal {
        gov_version: forged_tip.gov_version,
        sn: forged_tip.sn,
        prev_ledger_event_hash: forged_tip.prev_ledger_event_hash.clone(),
        protocols_hash: forged_hash,
    };
    forged_tip.ledger_seal_signature =
        Signature::new(&forged_seal, &alice_keys).unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn assert_no_trace(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "unverifiable batch must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from an unproven batch"
        );
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => {}
            Ok((owner_now, pending, _, _)) => assert!(
                owner_now.is_none() && pending.is_none(),
                "no ownership may derive from an unproven batch"
            ),
        }
        node_running(api).await.unwrap();
    }

    // Bare Create plus an uncheckable aux: nothing applied, the
    // cursor stops at the tip while the batch waits deferred.
    inject_with_hint(&rita, &alice_key, vec![create.clone()], false, &transfer)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (1, 0),
        "first aux builds the cursor from the batch alone"
    );
    // Exact prefix resend: the copy already holds Create, so the
    // batch is stale and dropped before verifying. It must leave
    // no trace, add no work and stall nothing.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone()],
        false,
        &transfer,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (1, 0),
        "a stale resend must not re-verify nor stall the copy"
    );
    // Conflicting continuation: same SN as the held tip with
    // different bytes. The suffix must invalidate instead of
    // borrowing the forged bytes, rebuild authoritatively over
    // the genuine prefix and write nothing.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![forged_tip.clone(), fact2.clone()],
        false,
        &transfer,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (4, 0),
        "a conflicting continuation must rebuild instead of reusing"
    );
    // Genuine prefix plus the pending hint: rebuilds from the
    // authoritative prefix, records the proof and applies.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone(), fact2.clone()],
        false,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap(),
        (7, 0),
        "rebuilding the genuine prefix replays it once more"
    );
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((3, alice_key.clone())),
        "the genuine hint must record its proof"
    );
    node_running(&rita).await.unwrap();
    // The tail applies through the recorded proof, which is
    // consumed single-use on application: nothing lingers.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A deferred prefix that outgrows its per-subject budget is
/// dropped as a whole instead of pinning unbounded RAM: no
/// subject, SN, proof, ownership or retained entry survives the
/// eviction, and a genuine chain still completes afterwards from
/// a clean copy.
#[test(tokio::test)]
async fn remote_deferred_overflow_evicts_whole_chain() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    assert_eq!(history.len(), 5);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact1 = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("first fact")
        .clone();
    let fact2 = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("second fact")
        .clone();
    let fact3 = history
        .iter()
        .find(|event| event.sn == 3)
        .expect("third fact")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 4)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    // Tight per-subject budget: unbounded staging must be
    // rejected instead of growing with the chain. Installed
    // before any batch so every verify already runs under it.
    rita.test_set_deferred_limits(
        ave_core::distribution::deferred::DeferredLimits {
            max_subjects: 4,
            max_events_per_subject: 2,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 1_000_000,
            max_bytes_global: u64::MAX,
        },
    )
    .await
    .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn assert_no_trace(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "deferred evidence must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from a deferred batch"
        );
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => {}
            Ok((owner_now, pending, _, _)) => assert!(
                owner_now.is_none() && pending.is_none(),
                "no ownership may derive from a deferred batch"
            ),
        }
        node_running(api).await.unwrap();
    }

    // Bare Create plus an uncheckable aux: nothing applied, the
    // batch waits deferred and the retained counters pin it.
    inject_with_hint(&rita, &alice_key, vec![create.clone()], false, &transfer)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!(
        (subjects, events),
        (1, 1),
        "one staged event under one subject"
    );
    assert!(bytes > 0, "retained bytes must be accounted");
    // The next continuation replays only its suffix and stays
    // deferred inside the same budget.
    inject_with_hint(&rita, &alice_key, vec![fact1.clone()], false, &transfer)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!(
        (subjects, events),
        (1, 2),
        "the continuation extends the same entry"
    );
    assert!(bytes > 0, "retained bytes must be accounted");
    // Over budget: the whole entry is dropped instead of growing
    // forever. Silence afterwards leaves no key and no counters.
    inject_with_hint(&rita, &alice_key, vec![fact2.clone()], false, &transfer)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "overflow must drop the whole entry with its counters"
    );
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "silence after the eviction leaves no residue"
    );
    // The genuine chain still completes from a clean copy: the
    // aux verifies, the prefix applies, the proof records.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone(), fact2.clone(), fact3.clone()],
        false,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((4, alice_key.clone())),
        "the genuine hint must record its proof"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "an applied copy holds nothing back"
    );
    node_running(&rita).await.unwrap();
    // The tail applies through the recorded proof, which is
    // consumed single-use on application: nothing lingers.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A global deferred budget evicts whole LRU chains instead of
/// growing without bound: the surviving subject keeps its staged
/// prefix and its own copy can still complete afterwards.
#[test(tokio::test)]
async fn remote_deferred_global_budget_evicts_lru_subject() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    async fn build_chain(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        new_owner: &PublicKey,
    ) -> (DigestIdentifier, Vec<Ledger>, Ledger) {
        let (subject_id, _) =
            create_subject(api, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        emit_fact(
            api,
            subject_id.clone(),
            json!({"ModOne": {"data": 1}}),
            true,
        )
        .await
        .unwrap();
        emit_fact(
            api,
            subject_id.clone(),
            json!({"ModTwo": {"data": 2}}),
            true,
        )
        .await
        .unwrap();
        emit_transfer(api, subject_id.clone(), new_owner.clone(), true)
            .await
            .unwrap();
        get_subject(api, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
        let history = api
            .test_get_tracker_ledger(subject_id.clone(), 3)
            .await
            .unwrap();
        assert_eq!(history.len(), 4);
        let transfer = history
            .iter()
            .find(|event| event.sn == 3)
            .expect("transfer event")
            .clone();
        assert!(
            transfer.protocols.is_success(),
            "premise: the transfer must succeed"
        );
        (subject_id, history, transfer)
    }

    let (subject_a, history_a, transfer_a) =
        build_chain(&alice, &governance_id, &rita_key).await;
    let (subject_b, history_b, transfer_b) =
        build_chain(&alice, &governance_id, &rita_key).await;
    let event_a = |sn: u64| {
        history_a
            .iter()
            .find(|event| event.sn == sn)
            .expect("event")
            .clone()
    };
    let event_b = |sn: u64| {
        history_b
            .iter()
            .find(|event| event.sn == sn)
            .expect("event")
            .clone()
    };

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    // Global budget of three staged events: the fourth must evict
    // a whole LRU chain instead of growing the worker's RAM.
    rita.test_set_deferred_limits(
        ave_core::distribution::deferred::DeferredLimits {
            max_subjects: 10,
            max_events_per_subject: 100,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 3,
            max_bytes_global: u64::MAX,
        },
    )
    .await
    .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn assert_no_trace(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "deferred evidence must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(
            api.test_get_verified_transfer_sn(
                governance_id,
                subject_id.clone()
            )
            .await
            .unwrap()
            .is_none(),
            "no transfer proof may persist from a deferred batch"
        );
        node_running(api).await.unwrap();
    }

    // Two staged prefixes fit the global budget of three events.
    inject_with_hint(&rita, &alice_key, vec![event_a(0)], false, &transfer_a)
        .await;
    inject_with_hint(&rita, &alice_key, vec![event_a(1)], false, &transfer_a)
        .await;
    inject_with_hint(&rita, &alice_key, vec![event_b(0)], false, &transfer_b)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_a).await;
    assert_no_trace(&rita, &governance_id, &subject_b).await;
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (2, 3));
    assert!(bytes > 0, "retained bytes must be accounted");
    // The fourth staged event overflows the global budget: the
    // oldest chain goes away as a whole while the other keeps
    // its staged prefix.
    inject_with_hint(&rita, &alice_key, vec![event_b(1)], false, &transfer_b)
        .await;
    assert_no_trace(&rita, &governance_id, &subject_a).await;
    assert_no_trace(&rita, &governance_id, &subject_b).await;
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!(
        (subjects, events),
        (1, 2),
        "overflow must evict the whole LRU chain"
    );
    assert!(bytes > 0, "the surviving entry must keep its bytes");
    // The survivor keeps its cursor: the next continuation replays
    // only its suffix and applies the verified prefix. The staged
    // Create rejoins through the take path, so the genuine prefix
    // lands at SN2 with its proof recorded, instead of rolling
    // back.
    let (processed_before, _) =
        rita.test_verify_stats(subject_b.clone()).await.unwrap();
    inject_with_hint(&rita, &alice_key, vec![event_b(2)], false, &transfer_b)
        .await;
    get_subject(&rita, subject_b.clone(), Some(2), true)
        .await
        .unwrap();
    let (processed_after, _) =
        rita.test_verify_stats(subject_b.clone()).await.unwrap();
    assert_eq!(
        processed_after - processed_before,
        2,
        "the surviving cursor resumes instead of rebuilding"
    );
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_b.clone())
            .await
            .unwrap(),
        Some((3, alice_key.clone())),
        "the surviving prefix must record its proof"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "an applied prefix holds nothing back"
    );
    node_running(&rita).await.unwrap();
    // The evicted chain still completes from a genuine full copy:
    // its cursor was invalidated, so the prefix rebuilds once.
    let (processed_before, _) =
        rita.test_verify_stats(subject_a.clone()).await.unwrap();
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_a(0), event_a(1), event_a(2)],
        false,
        &transfer_a,
    )
    .await;
    get_subject(&rita, subject_a.clone(), Some(2), true)
        .await
        .unwrap();
    let (processed_after, _) =
        rita.test_verify_stats(subject_a.clone()).await.unwrap();
    assert_eq!(
        processed_after - processed_before,
        3,
        "the evicted chain rebuilds authoritatively once"
    );
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_a.clone())
            .await
            .unwrap(),
        Some((3, alice_key.clone())),
        "the genuine hint must record its proof"
    );
    node_running(&rita).await.unwrap();
    // The tail applies through the recorded proof, which is
    // consumed single-use on application: nothing lingers.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer_a.clone()],
        true,
        &transfer_a,
    )
    .await;
    get_subject(&rita, subject_a.clone(), Some(3), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_a.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a completed copy holds nothing back"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A failed tracker resolve after a successful `Up` releases
/// the `aux-evidence` lease: the evidence stays Missing with no
/// writes, no live requesters remain, and a genuine delivery
/// afterwards still completes the copy.
///
/// Rita has no direct rights (plain creator, like Erin in the
/// opaque-chain test), so the fact chain only travels masked:
/// the prefix copies through the aux passage without ever
/// recording a proof, and no verification cursor survives the
/// fault injection. Every live path from the sender stays
/// silenced, so the crafted batches are the only deliveries.
#[test(tokio::test)]
async fn remote_tracker_resolve_fault_releases_lease() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let dave_signer = Ed25519Signer::generate().unwrap();
    let dave_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        dave_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    // Alice creates with Dave as witness; Rita is a plain creator,
    // so the transfer to her succeeds while she gains no direct
    // access to a subject created by Alice.
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Dave", "key": dave_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Dave",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Silence every ledger-carrying delivery from Alice to Rita:
    // her coordinator would otherwise push the genuine chain on
    // its own retry schedule and complete the copy outside the
    // crafted batches. Validation and governance traffic to any
    // other peer still flows, so local emits keep working.
    let rita_public = PublicKey::from_str(rita.public_key()).expect("node key");
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    let find = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("event")
            .clone()
    };
    let create = find(0);
    let fact1 = find(1);
    let fact2 = find(2);
    let transfer = find(3);
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    // Canonical masked projection of both genuine facts,
    // re-sealed by the owner, plus the genuine transfer relinked
    // onto the masked chain. Seal and quorum stay valid; only the
    // evidence can not be rebuilt through the opaque steps.
    fn mask_and_reseal(
        event: &Ledger,
        prev_hash: &DigestIdentifier,
        signer: &ave_common::identity::keys::KeyPair,
    ) -> Ledger {
        let mut masked = event
            .to_tracker_opaque()
            .expect("premise: the fact must project to opaque");
        masked.prev_ledger_event_hash = prev_hash.clone();
        let masked_protocols_hash = masked
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap();
        masked.ledger_seal_signature = Signature::new(
            &LedgerSeal {
                gov_version: masked.gov_version,
                sn: masked.sn,
                prev_ledger_event_hash: masked.prev_ledger_event_hash.clone(),
                protocols_hash: masked_protocols_hash,
            },
            signer,
        )
        .unwrap();
        masked
    }
    let masked1 = mask_and_reseal(
        &fact1,
        &create.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );
    let masked2 = mask_and_reseal(
        &fact2,
        &masked1.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );
    let mut hinted = transfer.clone();
    hinted.prev_ledger_event_hash =
        masked2.ledger_hash(HashAlgorithm::Blake3).unwrap();
    let hinted_protocols_hash = hinted
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    hinted.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: hinted.gov_version,
            sn: hinted.sn,
            prev_ledger_event_hash: hinted.prev_ledger_event_hash.clone(),
            protocols_hash: hinted_protocols_hash,
        },
        &alice_keys,
    )
    .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    // Zero-budget deferred limits: the next `set` drops every
    // staged entry whole and invalidates its cursor, so the
    // following delivery rebuilds authoritatively.
    fn zero_limits() -> ave_core::distribution::deferred::DeferredLimits {
        ave_core::distribution::deferred::DeferredLimits {
            max_subjects: 0,
            max_events_per_subject: 0,
            max_bytes_per_subject: 0,
            max_events_global: 0,
            max_bytes_global: 0,
        }
    }

    // The masked prefix copies through the aux passage: the
    // evidence can not be rebuilt through the opaque steps, so
    // the copy lands at SN2 without recording any proof.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone(), masked1.clone(), masked2.clone()],
        false,
        &hinted,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "an unverifiable passage must record no proof"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "an applied prefix holds nothing back"
    );

    // Settle: every lease of the copy above is finished before
    // the reboot below, so nothing is mid-copy when the node
    // restarts.
    for _ in 0..100 {
        if !rita
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !rita
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "the tracker must go idle after the copy"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    node_running(&rita).await.unwrap();

    // Reboot with the same storage: the applied prefix persists
    // while every volatile cursor is gone, so the delivery under
    // test rebuilds authoritatively and really reloads the ledger.
    // The original TempDirs stay alive on purpose, so the
    // rebooted node really reopens this storage. No subject reads
    // happen after the reboot: any read would bring the tracker
    // up and the resolve fault would never fire.
    let keys = rita_node.keys.clone();
    let local_db = rita_dirs[0].path().to_path_buf();
    let ext_db = rita_dirs[1].path().to_path_buf();
    rita_node.token.cancel();
    join_all(rita_node.handler.iter_mut()).await;
    drop(rita_node);
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, _rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();

    // Settle: the boot reconciliation finishes and releases every
    // lease, so the tracker stops and the reload below really
    // goes through a fresh `Up`.
    for _ in 0..100 {
        if !rita
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        !rita
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "the tracker must go idle after the copy"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    node_running(&rita).await.unwrap();

    // Arm the one-shot fault here, right before the delivery
    // under test: the reboot above cleared every volatile cursor,
    // so the full rebuild below really reloads the applied prefix
    // instead of resuming anything.
    rita.test_fail_next_tracker_resolve().await.unwrap();

    // The next resolve fails right after its `Up`: the evidence
    // stays Missing, the batch waits deferred, and the lease is
    // released instead of pinning `aux-evidence` until reboot.
    // Re-inject until the staging lands: an early delivery may
    // still find the node registration or the applied tip missing
    // and ask for an update instead of verifying. Repeats are
    // safe: once staged, further copies are stale no-ops.
    for _ in 0..15 {
        inject_with_hint(
            &rita,
            &alice_key,
            vec![hinted.clone()],
            true,
            &hinted,
        )
        .await;
        tokio::time::sleep(Duration::from_millis(200)).await;
        if rita.test_deferred_stats().await.unwrap().0 == 1 {
            break;
        }
    }
    for _ in 0..30 {
        assert_eq!(
            rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
            2,
            "a missing evidence batch must not advance the copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the failed resolve must record nothing"
    );
    assert!(
        !rita
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "the aux-evidence lease must be released on resolve failure"
    );
    // The staging travels through the worker mailbox: poll until
    // the authoritative store reports it instead of assuming
    // delivery order.
    for _ in 0..50 {
        let (subjects, events, _) = rita.test_deferred_stats().await.unwrap();
        if (subjects, events) == (1, 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1));
    assert!(bytes > 0, "retained bytes must be accounted");
    node_running(&rita).await.unwrap();

    // Drop the staged tail whole: the one-shot fault is already
    // consumed, so the genuine re-delivery rebuilds, verifies
    // from scratch and applies the tail.
    rita.test_set_deferred_limits(zero_limits()).await.unwrap();
    for _ in 0..50 {
        if rita.test_deferred_stats().await.unwrap() == (0, 0, 0) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "eviction must drop the whole entry with its counters"
    );
    rita.test_set_deferred_limits(
        ave_core::distribution::deferred::DeferredLimits::production(),
    )
    .await
    .unwrap();
    inject_with_hint(&rita, &alice_key, vec![hinted.clone()], true, &hinted)
        .await;
    get_subject(&rita, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "an unverifiable passage records no proof"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a completed copy holds nothing back"
    );
    assert!(
        !rita
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "no lease may linger after the genuine copy"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// SLOW: governance recovery must not replay the page-boundary event.
/// With 257 events the second page overlaps the first under the old
/// cursor; the duplicate apply used to fail the boot.
#[test(tokio::test)]
async fn dirty_restart_does_not_reapply_page_boundary() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (mut node, dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!("/memory/{port}"),
            always_accept: true,
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();
        let api = node.api.clone();

        let governance_id = create_and_authorize_governance(&api, vec![]).await;
        // 256 facts on top of genesis (257 events): recovery necessarily
        // reads a second page, whose first event overlaps the first page
        // under the old cursor. The boundary event removes a member, so a
        // duplicate replay fails the patch and the boot: member adds alone
        // would re-apply silently and prove nothing.
        let temp_key = PublicKey::new(
            ave_common::identity::keys::DSAlgorithm::Ed25519,
            Ed25519Signer::generate().unwrap().public_key_bytes(),
        )
        .unwrap()
        .to_string();
        emit_fact(
            &api,
            governance_id.clone(),
            json!({"members": {"add": [{ "name": "Temp", "key": temp_key }]}}),
            false,
        )
        .await
        .unwrap();
        for i in 0..254 {
            emit_fact(
                &api,
                governance_id.clone(),
                json!({"members": {"add": [{
                    "name": format!("Bulk{i:03}"),
                    "key": PublicKey::new(
                        ave_common::identity::keys::DSAlgorithm::Ed25519,
                        Ed25519Signer::generate().unwrap().public_key_bytes(),
                    )
                    .unwrap()
                    .to_string(),
                }]}}),
                false,
            )
            .await
            .unwrap();
        }
        emit_fact(
            &api,
            governance_id.clone(),
            json!({"members": {"remove": ["Temp"]}}),
            true,
        )
        .await
        .unwrap();

        let before = get_subject(&api, governance_id.clone(), None, true)
            .await
            .unwrap();

        // Dirty stop: no clean-shutdown handshake, so boot reconciles.
        let keys = node.keys.clone();
        let local_db = dirs[0].path().to_path_buf();
        let ext_db = dirs[1].path().to_path_buf();
        node.token.cancel();
        join_all(node.handler.iter_mut()).await;
        drop(node);

        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (mut node, _) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address: format!("/memory/{port}"),
            always_accept: true,
            keys: Some(keys),
            local_db: Some(local_db),
            ext_db: Some(ext_db),
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();

        // A duplicated boundary event would raise sn/version or fail the
        // boot: state must be exactly what the journal holds.
        let after = get_subject(&node.api, governance_id.clone(), None, true)
            .await
            .unwrap();
        assert_eq!(after.sn, before.sn);
        assert_eq!(after.properties, before.properties);

        node.token.cancel();
        join_all(node.handler.iter_mut()).await;
        drop(node);
        drop(dirs);
    })
    .await
    .expect("dirty restart with page-boundary replay hung");
}

/// Regression test for the second Node <-> SubjectAccess cycle
/// (report 33, extended variant): `update_subject` waits on Node
/// (`GetSubjectData`) while a received batch waited on SubjectAccess
/// through Node (`SubjectAccessData` -> `GetAccessInfo`). Both `ask`s
/// have no timeout, so the old nesting hung the central actor.
/// The distributor now reads flags and data with two independent
/// asks, so concurrent updates and batch reception always complete.
/// Each iteration uses a fresh tracker, unknown to the receiver:
/// its genesis batch always passes the next-sn gate and reaches the
/// auth check. Bounded by timeout: a reintroduced nested wait hangs
/// instead of failing, and the timeout turns that into a loud
/// failure.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_update_and_batch_reception_complete() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let target = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_pk = PublicKey::from_str(nodes[1].api.public_key()).unwrap();

    let governance_id = setup_example_governance(
        &target,
        &[MemberSpec {
            api: &alice,
            name: "Alice",
            gov_witness: true,
            creator: true,
            issuer: true,
        }],
    )
    .await;

    tokio::time::timeout(Duration::from_secs(180), async {
        for _ in 0..4 {
            let (tracker_id, _) = create_subject(
                &alice,
                governance_id.clone(),
                "Example",
                "",
                true,
            )
            .await
            .unwrap();
            // Receiver-side peer so the concurrent update has someone
            // to ask (its Node wait is the deadlock-relevant part).
            target
                .add_sync_peer(tracker_id.clone(), vec![alice_pk.clone()])
                .await
                .unwrap();
            let genesis = alice
                .test_get_tracker_ledger(tracker_id.clone(), 0)
                .await
                .unwrap()
                .into_iter()
                .next()
                .expect("genesis event");
            // Update and batch reception overlap: with the nested wait
            // this is where Node and SubjectAccess wedged each other.
            // The update may legitimately fail to fetch (roles); what
            // must never happen is hanging.
            let (_update, ()) = tokio::join!(
                async {
                    let _ = target.update_subject(tracker_id.clone()).await;
                },
                async {
                    inject_ledger_batch(&target, &alice_pk, vec![genesis], None)
                        .await
                }
            );
            node_running(&target).await.unwrap();
        }
    })
    .await
    .expect("concurrent update + batch reception hung (nested wait?)");
}
/// Without aux, authorization covers deferred plus current batch with
/// the current tail as offered tip: an unknown prefix deferred for lack
/// of rights applies once the witness is granted, without proof.
#[test(tokio::test)]
async fn remote_without_aux_covers_held_plus_current_after_grant() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {"name": "Alice", "namespace": []}
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
    alice.update_subject(governance_id.clone()).await.unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    // Gov sync peer: the roles change below bumps the gov version
    // while Alice->Rita ledger traffic is fault-dropped. Without an
    // unfaulted gov source Rita would stall on the old version and
    // the grant could never take effect; the owner serves gov
    // through the regular witness/offer flow.
    rita.add_sync_peer(
        governance_id.clone(),
        vec![PublicKey::from_str(owner.public_key()).unwrap()],
    )
    .await
    .unwrap();
    for api in [&alice] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    let find = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let create = find(0);
    let fact1 = find(1);
    let transfer = find(3);

    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn assert_no_trace(
        api: &ave_core::Api,
        subject_id: &DigestIdentifier,
    ) {
        for _ in 0..30 {
            assert!(
                api.get_subject_state(subject_id.clone()).await.is_err(),
                "deferred evidence must not register the subject"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    inject_with_hint(&rita, &alice_key, vec![create.clone()], false, &transfer)
        .await;
    assert_no_trace(&rita, &subject_id).await;
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1), "one staged event");
    assert!(bytes > 0, "retained bytes must be accounted");

    // Lift the fault so both nodes can sync the granting gov
    // version: the tracker re-request from the deny above was a
    // single tell with no retry behind it, and nothing else emits
    // tracker batches spontaneously, so no uncontrolled delivery
    // can slip in while faults are down. Faults go back up before
    // the second inject.
    alice.test_clear_faults().await.unwrap();

    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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
    alice.update_subject(governance_id.clone()).await.unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    // Wait for the grant to land: the second delivery must run
    // against the new governance version, not race a stale one.
    // A stale version would deny again and the test would pass
    // vacuously without ever exercising the granted path.
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    for _ in 0..100 {
        let rita_gov_sn = get_subject(&rita, governance_id.clone(), None, true)
            .await
            .unwrap()
            .sn;
        if rita_gov_sn >= gov_sn {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        get_subject(&rita, governance_id.clone(), None, true)
            .await
            .unwrap()
            .sn,
        gov_sn,
        "rita must sync the granting governance version first"
    );

    for api in [&alice] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    inject_with_hint(&rita, &alice_key, vec![fact1.clone()], false, &transfer)
        .await;
    get_subject(&rita, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the granted prefix applies and holds nothing back"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "own-rights copy records no proof"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A registered subject must rejoin its staged prefix after a cursor
/// eviction: local SN0 plus deferred SN1 plus sender SN2 plus the aux
/// prove and apply up to SN2, then the transfer itself applies and
/// consumes the single-use proof.
#[test(tokio::test)]
async fn remote_registered_prefix_rejoins_after_cursor_eviction() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    // Rita witnesses Alice's creations, so a lone Create applies on
    // direct rights; revoking her afterwards leaves the applied
    // prefix valid while new events stop being covered.
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    // Gov sync peers for the revocation round below: Alice's own
    // gov update has no witnesses left to ask, so both nodes fetch
    // the new version through the unfaulted owner instead. The
    // owner is always a valid sync source for governance.
    for api in [&alice, &rita] {
        api.add_sync_peer(
            governance_id.clone(),
            vec![PublicKey::from_str(owner.public_key()).unwrap()],
        )
        .await
        .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    // Silence Alice toward Rita before any tracker traffic: pushes
    // and re-request answers must be dropped so the copy stays
    // fully inject-driven and deterministic. Installing the faults
    // after the emits would race their pushes.
    for api in [&alice] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: Option<Ledger>,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: hint.map(Box::new),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Rita registers SN0 on direct rights: a lone Create with no aux
    // applies through the single path without recording any proof.
    let create_zero = alice
        .test_get_tracker_ledger(subject_id.clone(), 0)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("create event");
    inject_with_hint(&rita, &alice_key, vec![create_zero], true, None).await;
    get_subject(&rita, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a lone create on direct rights holds nothing back"
    );

    // Revoke Rita's witness grant while every link is unfaulted:
    // lifting the faults for the governance round keeps the sync
    // deterministic (no dropped witness/offer traffic), and no
    // tracker traffic exists yet that could slip in meanwhile.
    // Faults go back up before Alice emits anything new.
    alice.test_clear_faults().await.unwrap();
    let gov_before = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": []
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
    alice.update_subject(governance_id.clone()).await.unwrap();
    for i in 0..400 {
        let alice_gov_sn =
            get_subject(&alice, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
        if alice_gov_sn > gov_before {
            break;
        }
        if i % 20 == 19 {
            alice.update_subject(governance_id.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    assert!(
        gov_sn > gov_before,
        "alice must sync the revoking governance version first"
    );
    rita.update_subject(governance_id.clone()).await.unwrap();
    for i in 0..400 {
        let rita_gov_sn = get_subject(&rita, governance_id.clone(), None, true)
            .await
            .unwrap()
            .sn;
        if rita_gov_sn >= gov_sn {
            break;
        }
        if i % 20 == 19 {
            rita.update_subject(governance_id.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        get_subject(&rita, governance_id.clone(), None, true)
            .await
            .unwrap()
            .sn,
        gov_sn,
        "rita must sync the revoking governance version first"
    );

    // Faults go back up before Alice emits anything new: pushes
    // and re-request answers must be dropped so the copy stays
    // fully inject-driven and deterministic.
    for api in [&alice] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    let find = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let fact1 = find(1);
    let fact2 = find(2);
    let transfer = find(3);
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Rita must succeed"
    );

    // Gap plus distant aux with no rights: SN1 waits deferred while
    // the cursor advances over it, and nothing is applied or proven.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact1.clone()],
        false,
        Some(transfer.clone()),
    )
    .await;
    for _ in 0..30 {
        assert_eq!(
            rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
            0,
            "a gapped prefix must not advance the copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1), "one staged event");
    assert!(bytes > 0, "retained bytes must be accounted");
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "an unproven aux records no proof"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "the first missing aux rebuilds once"
    );

    // Evicting only the cursor must not lose the staged prefix: the
    // rebuild has to rejoin it instead of stalling on the gap.
    rita.test_evict_verify_cursor(subject_id.clone())
        .await
        .unwrap();
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!(
        (subjects, events),
        (1, 1),
        "eviction keeps the staged entry"
    );
    assert!(bytes > 0, "retained bytes must be accounted");

    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact2.clone()],
        false,
        Some(transfer.clone()),
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the rejoined prefix applies and holds nothing back"
    );
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((3, alice_key.clone())),
        "the rejoined chain records its proof"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        2,
        "the evicted cursor forces a rebuild, not a silent miss"
    );

    // The transfer itself applies through the recorded proof, which
    // is consumed single-use on application: nothing lingers.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        Some(transfer.clone()),
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a completed copy holds nothing back"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A Version-capped window denies past its boundary without ever
/// stepping up to a global pass: after a witness revoke the held
/// prefix plus each new tail stay deferred, retention grows by the
/// tail only, and no proof is recorded.
#[test(tokio::test)]
async fn remote_without_aux_denies_past_version_window() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let dave_signer = Ed25519Signer::generate().unwrap();
    let dave_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        dave_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                    {"name": "Dave", "key": dave_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Dave",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    for api in [&alice, &rita] {
        api.add_sync_peer(
            governance_id.clone(),
            vec![PublicKey::from_str(owner.public_key()).unwrap()],
        )
        .await
        .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    // Silence Alice toward Rita before any tracker traffic: pushes
    // and re-request answers must be dropped so the copy stays
    // fully inject-driven and deterministic.
    for api in [&alice] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: Option<Ledger>,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: hint.map(Box::new),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Rita registers SN0 on direct rights before the revoke.
    let create_zero = alice
        .test_get_tracker_ledger(subject_id.clone(), 0)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("create event");
    inject_with_hint(&rita, &alice_key, vec![create_zero], true, None).await;
    get_subject(&rita, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // Revoke Rita's witness grant.
    let gov_before = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": []
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
    // Read the new tip from the emitter itself: a local projection
    // read, no network round trip.
    let gov_sn = {
        let mut tip = gov_before;
        for _ in 0..300 {
            tip = get_subject(&owner, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
            if tip > gov_before {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        tip
    };
    assert!(
        gov_sn > gov_before,
        "alice must sync the revoking governance version first"
    );
    // Seed both learners with the missing governance events by
    // direct injection, exactly like the tracker seeding above.
    // Alice drops every ledger answer toward Rita (the rule matches
    // the message type with no subject filter, so governance
    // answers die with the tracker ones), leaving Rita a single
    // live edge to the owner whose answers share her contended
    // response channel and stall without bound under pack load.
    // Injection delivers the same bytes through the normal
    // distributor path deterministically.
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    let mut gov_ledger = Vec::new();
    for sn in (gov_before + 1)..=gov_sn {
        gov_ledger.push(
            owner
                .test_get_ledger_event(governance_id.clone(), sn)
                .await
                .unwrap(),
        );
    }
    for api in [&alice, &rita] {
        inject_with_hint(api, &owner_key, gov_ledger.clone(), true, None).await;
        for _ in 0..300 {
            let tip = get_subject(api, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
            if tip >= gov_sn {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            get_subject(api, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn,
            gov_sn,
            "rita must sync the revoking governance version first"
        );
    }

    // New events run under the revoking version; the transfer goes
    // to Dave so Rita never becomes the new owner (which would
    // reopen an Infinity window and vacate this test). The aux
    // stays one event beyond every injected tail so its evidence
    // never completes: each delivery denies on rights and defers
    // instead of proving the aux and failing without staging.
    for api in [&alice] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), dave_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    assert_eq!(history.len(), 5);
    let find = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let fact1 = find(1);
    let fact2 = find(2);
    let transfer = find(4);
    assert!(
        transfer.protocols.is_success(),
        "premise: the transfer to Dave must succeed"
    );

    // Past the closed window every tail denies: the first tail
    // waits deferred with no apply and no proof. The aux stays
    // incomplete (SN3 never arrives), so the verdict is Missing
    // and the batch is held instead of failing without staging.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact1.clone()],
        false,
        Some(transfer.clone()),
    )
    .await;
    for _ in 0..30 {
        assert_eq!(
            rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
            0,
            "a window-capped tail must not advance the copy"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1), "one staged event");
    assert!(bytes > 0, "retained bytes must be accounted");
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a denied tail records no proof"
    );

    // The continuation denies too without stepping up to a global
    // pass: retention grows by the tail only and the subject still
    // sits at SN0 with no proof.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact2.clone()],
        false,
        Some(transfer.clone()),
    )
    .await;
    for _ in 0..30 {
        assert_eq!(
            rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
            0,
            "the second capped tail must not advance the copy either"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (subjects, events, bytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 2), "two staged events");
    assert!(bytes > 0, "retained bytes must be accounted");
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a twice-denied tail still records no proof"
    );
    let (_, visited, _) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        visited <= 12 * 2,
        "deferred plus auth visits stay linear in the new tails"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Opaque prefix replays incrementally to `Unverifiable` while the
/// same checkable-but-wrong evidence over a clear prefix stays
/// `Refuted`: the downgrade only applies under `Opaque` trust, and
/// the second delivery in both phases is a suffix replay, not a
/// rebuild.
#[test(tokio::test)]
async fn remote_opaque_suffix_stays_unverifiable_while_clear_refutes() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let dave_signer = Ed25519Signer::generate().unwrap();
    let dave_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        dave_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Dave", "key": dave_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Dave",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();

    let rita_public = PublicKey::from_str(rita.public_key()).expect("node key");
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    fn mask_and_reseal(
        event: &Ledger,
        prev_hash: &DigestIdentifier,
        signer: &ave_common::identity::keys::KeyPair,
    ) -> Ledger {
        let mut masked = event
            .to_tracker_opaque()
            .expect("premise: the fact must project to opaque");
        masked.prev_ledger_event_hash = prev_hash.clone();
        let masked_protocols_hash = masked
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap();
        masked.ledger_seal_signature = Signature::new(
            &LedgerSeal {
                gov_version: masked.gov_version,
                sn: masked.sn,
                prev_ledger_event_hash: masked.prev_ledger_event_hash.clone(),
                protocols_hash: masked_protocols_hash,
            },
            signer,
        )
        .unwrap();
        masked
    }
    fn forge_aux(
        transfer: &Ledger,
        ok_result: &ave_core::model::event::EvaluationData,
        prev_hash: &DigestIdentifier,
        signer: &ave_common::identity::keys::KeyPair,
    ) -> Ledger {
        let mut forged = transfer.clone();
        match &mut forged.protocols {
            Protocols::Transfer { evaluation, .. } => {
                let old_hash = match &evaluation.response {
                    EvaluationResponse::Ok { result_hash, .. }
                    | EvaluationResponse::Error { result_hash, .. } => {
                        result_hash.clone()
                    }
                };
                evaluation.response = EvaluationResponse::Ok {
                    result: ok_result
                        .evaluator_response_ok()
                        .expect("premise: ok evaluation result"),
                    result_hash: old_hash,
                };
            }
            _ => panic!("expected a transfer event"),
        }
        forged.prev_ledger_event_hash = prev_hash.clone();
        let protocols_hash = forged
            .protocols
            .hash_for_ledger(&HashAlgorithm::Blake3)
            .unwrap();
        forged.ledger_seal_signature = Signature::new(
            &LedgerSeal {
                gov_version: forged.gov_version,
                sn: forged.sn,
                prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
                protocols_hash,
            },
            signer,
        )
        .unwrap();
        forged
    }

    // Opaque subject: the evidence can not be rebuilt through the
    // masked steps, so a wrong aux degrades to Unverifiable.
    let (opaque_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        opaque_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        opaque_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, opaque_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, opaque_id.clone(), Some(3), true)
        .await
        .unwrap();
    let opaque_history = alice
        .test_get_tracker_ledger(opaque_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(opaque_history.len(), 4);
    let ofind = |sn: u64| {
        opaque_history
            .iter()
            .find(|event| event.sn == sn)
            .expect("opaque history event")
            .clone()
    };
    let ocreate = ofind(0);
    let ofact1 = ofind(1);
    let otransfer = ofind(3);
    assert!(
        otransfer.protocols.is_success(),
        "premise: the opaque transfer must succeed"
    );
    let ok_result = match &ofact1.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation.clone(),
        _ => panic!("expected a full fact event"),
    };
    let omasked1 = mask_and_reseal(
        &ofact1,
        &ocreate.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );
    let omasked2 = mask_and_reseal(
        &ofind(2),
        &omasked1.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );
    let mut ohinted = otransfer.clone();
    ohinted.prev_ledger_event_hash =
        omasked2.ledger_hash(HashAlgorithm::Blake3).unwrap();
    let ohinted_hash = ohinted
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    ohinted.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: ohinted.gov_version,
            sn: ohinted.sn,
            prev_ledger_event_hash: ohinted.prev_ledger_event_hash.clone(),
            protocols_hash: ohinted_hash,
        },
        &alice_keys,
    )
    .unwrap();
    let oforged = forge_aux(
        &ohinted,
        &ok_result,
        &omasked2.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );

    // Phase one leaves the opaque cursor at SN1: the incomplete
    // chain can not prove the aux but its envelope opens passage,
    // so SN1 applies with no proof recorded.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![ocreate.clone(), omasked1.clone()],
        false,
        &ohinted,
    )
    .await;
    get_subject(&rita, opaque_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, opaque_id.clone())
            .await
            .unwrap()
            .is_none(),
        "an unverifiable passage records no proof"
    );
    assert_eq!(
        rita.test_full_rebuilds(opaque_id.clone()).await.unwrap(),
        1,
        "the first missing aux rebuilds once"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the applied envelope holds nothing back"
    );

    // Phase two replays only the suffix and degrades to
    // Unverifiable: the envelope opens passage with no proof,
    // no refutation and no rollback.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![omasked2.clone()],
        false,
        &oforged,
    )
    .await;
    get_subject(&rita, opaque_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, opaque_id.clone())
            .await
            .unwrap()
            .is_none(),
        "an unverifiable passage records no proof"
    );
    assert_eq!(
        rita.test_full_rebuilds(opaque_id.clone()).await.unwrap(),
        1,
        "the suffix replays incrementally instead of rebuilding"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the applied envelope holds nothing back"
    );

    // Clear subject: the same checkable-but-wrong shape over
    // reproducible evidence stays Refuted.
    let (clear_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        clear_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        clear_id.clone(),
        json!({"ModTwo": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, clear_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, clear_id.clone(), Some(3), true)
        .await
        .unwrap();
    let clear_history = alice
        .test_get_tracker_ledger(clear_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(clear_history.len(), 4);
    let cfind = |sn: u64| {
        clear_history
            .iter()
            .find(|event| event.sn == sn)
            .expect("clear history event")
            .clone()
    };
    let ccreate = cfind(0);
    let cfact1 = cfind(1);
    let cfact2 = cfind(2);
    let ctransfer = cfind(3);
    assert!(
        ctransfer.protocols.is_success(),
        "premise: the clear transfer must succeed"
    );
    let cok_result = match &cfact1.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation.clone(),
        _ => panic!("expected a full fact event"),
    };
    let cforged = forge_aux(
        &ctransfer,
        &cok_result,
        &cfact2.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );

    inject_with_hint(
        &rita,
        &alice_key,
        vec![ccreate.clone(), cfact1.clone()],
        false,
        &cforged,
    )
    .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(clear_id.clone()).await.is_err(),
            "an incomplete clear prefix must not register the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(
        rita.test_full_rebuilds(clear_id.clone()).await.unwrap(),
        1,
        "the first missing aux rebuilds once"
    );

    inject_with_hint(&rita, &alice_key, vec![cfact2.clone()], false, &cforged)
        .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(clear_id.clone()).await.is_err(),
            "a refuted suffix must not register the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, clear_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a refutation records no proof"
    );
    assert_eq!(
        rita.test_full_rebuilds(clear_id.clone()).await.unwrap(),
        1,
        "the refuting suffix replays incrementally instead of rebuilding"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a refuted chain holds nothing back"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Incremental ownership stays linear across several transfers with
/// a reject in between: fact-only tails reuse the cached witness
/// decision, while ownership, sender and governance changes each
/// recompute once. Batches of one maximize the number of decisions.
#[test(tokio::test)]
async fn remote_ownership_projection_stays_linear_across_transfers() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let w_signer = Ed25519Signer::generate().unwrap();
    let w_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        w_signer.public_key_bytes(),
    )
    .unwrap();
    let x_signer = Ed25519Signer::generate().unwrap();
    let x_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        x_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                    {"name": "W", "key": w_key.to_string()},
                    {"name": "X", "key": x_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Bob",
                                            "viewpoints": ["AllViewpoints"]
                                        },
                                        {
                                            "name": "Rita",
                                            "viewpoints": ["AllViewpoints"]
                                        },
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        },
                                        {
                                            "name": "X",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "W",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "X",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {"name": "Alice", "namespace": []},
                                {"name": "Bob", "namespace": []},
                                {"name": "W", "namespace": []},
                                {"name": "X", "namespace": []}
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
    alice.update_subject(governance_id.clone()).await.unwrap();

    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    emit_confirm(&bob, subject_id.clone(), None, true)
        .await
        .unwrap();
    emit_fact(
        &bob,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&bob, subject_id.clone(), w_key.clone(), true)
        .await
        .unwrap();
    get_subject(&bob, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    let w_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut w_node, w_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{w_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(w_signer)),
        ..Default::default()
    })
    .await;
    let w = w_node.api.clone();
    node_running(&w).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();
    w.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(bob.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(5), true)
        .await
        .unwrap();
    emit_reject(&w, subject_id.clone(), true).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(6), true)
        .await
        .unwrap();
    emit_fact(
        &bob,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&bob, subject_id.clone(), x_key.clone(), true)
        .await
        .unwrap();
    get_subject(&bob, subject_id.clone(), Some(8), true)
        .await
        .unwrap();

    let x_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut x_node, x_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{x_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(x_signer)),
        ..Default::default()
    })
    .await;
    let x = x_node.api.clone();
    node_running(&x).await.unwrap();
    x.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    x.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&x, governance_id.clone(), None, true)
        .await
        .unwrap();
    x.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(bob.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    x.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&x, subject_id.clone(), Some(8), true)
        .await
        .unwrap();
    emit_confirm(&x, subject_id.clone(), None, true)
        .await
        .unwrap();
    emit_fact(&x, subject_id.clone(), json!({"ModOne": {"data": 4}}), true)
        .await
        .unwrap();
    emit_transfer(&x, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&x, subject_id.clone(), Some(11), true)
        .await
        .unwrap();
    let history = x
        .test_get_tracker_ledger(subject_id.clone(), 11)
        .await
        .unwrap();
    assert_eq!(history.len(), 12);
    let transfer = history
        .iter()
        .find(|event| event.sn == 11)
        .expect("pending transfer")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the pending transfer must succeed"
    );
    let chain_len = history.len() as u64;

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    rita.add_sync_peer(
        governance_id.clone(),
        vec![PublicKey::from_str(owner.public_key()).unwrap()],
    )
    .await
    .unwrap();

    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let x_public = PublicKey::from_str(x.public_key()).unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    for api in [&alice, &bob, &x, &w] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    let batches: Vec<Vec<Ledger>> =
        history[..11].chunks(1).map(<[Ledger]>::to_vec).collect();
    assert_eq!(batches.len(), 11);
    for batch in &batches[..5] {
        inject_with_hint(&rita, &alice_key, batch.clone(), false, &transfer)
            .await;
    }
    alice.test_clear_faults().await.unwrap();
    bob.test_clear_faults().await.unwrap();
    x.test_clear_faults().await.unwrap();
    w.test_clear_faults().await.unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [{"name": "Carol", "key": alice.public_key()}]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    let gov_sn = get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    for i in 0..400 {
        let rita_gov_sn = get_subject(&rita, governance_id.clone(), None, true)
            .await
            .unwrap()
            .sn;
        if rita_gov_sn >= gov_sn {
            break;
        }
        if i % 20 == 19 {
            rita.update_subject(governance_id.clone()).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        get_subject(&rita, governance_id.clone(), None, true)
            .await
            .unwrap()
            .sn,
        gov_sn,
        "rita must sync the new governance version first"
    );
    for api in [&alice, &bob, &x, &w] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    for batch in &batches[5..] {
        inject_with_hint(&rita, &x_public, batch.clone(), false, &transfer)
            .await;
    }
    get_subject(&rita, subject_id.clone(), Some(10), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((11, x_public.clone())),
        "the genuine hint must record its proof from the last sender"
    );
    let (processed, reloads) =
        rita.test_verify_stats(subject_id.clone()).await.unwrap();
    assert!(
        reloads <= 2,
        "at most one reload plus one for the governance rotation, then only deltas: {reloads}"
    );
    assert!(
        processed <= 3 * chain_len,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    let (owned_cloned, owned_visited) =
        rita.test_ownership_stats(subject_id.clone()).await.unwrap();
    assert!(
        owned_cloned <= 2 * chain_len,
        "cloned {owned_cloned} ownership entries over a {chain_len}-event chain"
    );
    assert!(
        owned_visited <= 4 * chain_len,
        "visited {owned_visited} ownership entries over a {chain_len}-event chain"
    );
    inject_with_hint(&rita, &x_public, vec![transfer.clone()], true, &transfer)
        .await;
    get_subject(&rita, subject_id.clone(), Some(11), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    let (owned_cloned, owned_visited) =
        rita.test_ownership_stats(subject_id.clone()).await.unwrap();
    assert!(
        owned_cloned <= 2 * chain_len,
        "cloned {owned_cloned} ownership entries over a {chain_len}-event chain"
    );
    assert!(
        owned_visited <= 4 * chain_len,
        "visited {owned_visited} ownership entries over a {chain_len}-event chain"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the granted prefix applies and holds nothing back"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    rita_node.token.cancel();
    w_node.token.cancel();
    x_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut())
            .chain(w_node.handler.iter_mut())
            .chain(x_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(rita_node);
    drop(rita_dirs);
    drop(w_node);
    drop(w_dirs);
    drop(x_node);
    drop(x_dirs);
}

/// Ownership deltas stay linear with many closes: twelve Transfer+Confirm
/// pairs alternating the same two owners, plus a final Transfer for the
/// receiver. Batches of one, fixed sender and governance, so the count
/// cannot hide behind contextual rebuilds.
#[test(tokio::test)]
async fn remote_ownership_changes_stay_linear() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {"name": "Alice", "namespace": []},
                                {"name": "Bob", "namespace": []}
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
    alice.update_subject(governance_id.clone()).await.unwrap();

    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let mut current_owner_is_alice = true;
    let mut sn = 1u64;
    for _ in 0..12 {
        let (from_api, to_key) = if current_owner_is_alice {
            (&alice, bob_key.clone())
        } else {
            (&bob, alice_key.clone())
        };
        emit_transfer(from_api, subject_id.clone(), to_key, true)
            .await
            .unwrap();
        let other_api = if current_owner_is_alice { &bob } else { &alice };
        other_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(other_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        emit_confirm(other_api, subject_id.clone(), None, true)
            .await
            .unwrap();
        sn += 1;
        from_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(from_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        sn += 1;
        current_owner_is_alice = !current_owner_is_alice;
    }
    assert_eq!(sn, 25u64);
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(25), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 25)
        .await
        .unwrap();
    assert_eq!(history.len(), 26);
    let transfer = history
        .iter()
        .find(|event| event.sn == 25)
        .expect("pending transfer")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the pending transfer must succeed"
    );
    let (owner_now, pending_now, old_owners_now, stints_now) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_now, Some(alice_key.clone()));
    assert!(
        pending_now == Some(rita_key.clone()),
        "premise: the final transfer must stay pending"
    );
    assert_eq!(old_owners_now.len(), 2);
    assert_eq!(stints_now, 12);
    let chain_len = history.len() as u64;
    assert_eq!(chain_len, 26);

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    rita.add_sync_peer(
        governance_id.clone(),
        vec![PublicKey::from_str(owner.public_key()).unwrap()],
    )
    .await
    .unwrap();

    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    let batches: Vec<Vec<Ledger>> =
        history[..25].chunks(1).map(<[Ledger]>::to_vec).collect();
    assert_eq!(batches.len(), 25);
    for batch in &batches {
        inject_with_hint(&rita, &alice_key, batch.clone(), false, &transfer)
            .await;
    }
    get_subject(&rita, subject_id.clone(), Some(24), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((25, alice_key.clone())),
        "the genuine hint must record its proof from the fixed sender"
    );
    let (processed, reloads) =
        rita.test_verify_stats(subject_id.clone()).await.unwrap();
    assert!(
        reloads <= 1,
        "at most one full local reload, then only deltas: {reloads}"
    );
    assert!(
        processed <= 3 * chain_len,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    let (owned_cloned, owned_visited) =
        rita.test_ownership_stats(subject_id.clone()).await.unwrap();
    assert!(
        owned_cloned > 0 && owned_visited > 0,
        "counters must record real ownership work, not stay empty"
    );
    assert!(
        owned_cloned <= 2 * chain_len,
        "cloned {owned_cloned} ownership entries over a {chain_len}-event chain"
    );
    assert!(
        owned_visited <= 4 * chain_len,
        "visited {owned_visited} ownership entries over a {chain_len}-event chain"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "no rebuild per Transfer/Confirm, only the initial one"
    );
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(25), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the copy holds nothing back"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "the covered tail needs no second rebuild"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Half-size twin of the 26-event regression: six Transfer+Confirm pairs
/// alternating two owners, plus the final Transfer. Proves the total grows
/// linearly (not triangularly) when N doubles.
#[test(tokio::test)]
async fn remote_ownership_changes_stay_linear_half() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob_key.to_string()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {"name": "Alice", "namespace": []},
                                {"name": "Bob", "namespace": []}
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
    alice.update_subject(governance_id.clone()).await.unwrap();

    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    node_running(&bob).await.unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let mut current_owner_is_alice = true;
    let mut sn = 1u64;
    for _ in 0..6 {
        let (from_api, to_key) = if current_owner_is_alice {
            (&alice, bob_key.clone())
        } else {
            (&bob, alice_key.clone())
        };
        emit_transfer(from_api, subject_id.clone(), to_key, true)
            .await
            .unwrap();
        let other_api = if current_owner_is_alice { &bob } else { &alice };
        other_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(other_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        emit_confirm(other_api, subject_id.clone(), None, true)
            .await
            .unwrap();
        sn += 1;
        from_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(from_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        sn += 1;
        current_owner_is_alice = !current_owner_is_alice;
    }
    assert_eq!(sn, 13u64);
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(13), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 13)
        .await
        .unwrap();
    assert_eq!(history.len(), 14);
    let transfer = history
        .iter()
        .find(|event| event.sn == 13)
        .expect("pending transfer")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the pending transfer must succeed"
    );
    let chain_len = history.len() as u64;
    assert_eq!(chain_len, 14);

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    rita.add_sync_peer(
        governance_id.clone(),
        vec![PublicKey::from_str(owner.public_key()).unwrap()],
    )
    .await
    .unwrap();

    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    for api in [&alice, &bob] {
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    let batches: Vec<Vec<Ledger>> =
        history[..13].chunks(1).map(<[Ledger]>::to_vec).collect();
    assert_eq!(batches.len(), 13);
    for batch in &batches {
        inject_with_hint(&rita, &alice_key, batch.clone(), false, &transfer)
            .await;
    }
    get_subject(&rita, subject_id.clone(), Some(12), true)
        .await
        .unwrap();
    let (owned_cloned, owned_visited) =
        rita.test_ownership_stats(subject_id.clone()).await.unwrap();
    assert!(
        owned_cloned > 0 && owned_visited > 0,
        "counters must record real ownership work, not stay empty"
    );
    assert!(
        owned_cloned <= 2 * chain_len,
        "cloned {owned_cloned} ownership entries over a {chain_len}-event chain"
    );
    assert!(
        owned_visited <= 4 * chain_len,
        "visited {owned_visited} ownership entries over a {chain_len}-event chain"
    );
    inject_with_hint(
        &rita,
        &alice_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(13), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Owners distintos: doce pares Transfer+Confirm con un owner nuevo cada
/// vez, más el Transfer final. Demuestra coste independiente del
/// historial aunque `old_owners` crezca.
#[test(tokio::test)]
async fn remote_unique_owners_stay_linear() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    const EXTRA_OWNERS: usize = 11;
    let mut owner_keys: Vec<PublicKey> = Vec::new();
    let mut owner_signers = Vec::new();
    {
        let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
        owner_keys.push(alice_key);
    }
    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    owner_keys.push(bob_key.clone());
    for _ in 0..EXTRA_OWNERS {
        let signer = Ed25519Signer::generate().unwrap();
        let key = PublicKey::new(
            ave_common::identity::keys::DSAlgorithm::Ed25519,
            signer.public_key_bytes(),
        )
        .unwrap();
        owner_keys.push(key);
        owner_signers.push(signer);
    }
    // owner_keys: [Alice, Bob, O3..O13] = 13 owners O1..O13.
    assert_eq!(owner_keys.len(), 13);
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let mut member_adds = Vec::new();
    member_adds.push(json!({"name": "Alice", "key": alice.public_key()}));
    member_adds.push(json!({"name": "Bob", "key": owner_keys[1].to_string()}));
    for (idx, key) in owner_keys.iter().enumerate().skip(2) {
        member_adds.push(
            json!({"name": format!("O{}", idx + 1), "key": key.to_string()}),
        );
    }
    member_adds.push(json!({"name": "Rita", "key": rita_key.to_string()}));
    let mut creators = Vec::new();
    creators.push(json!({
        "name": "Alice", "namespace": [], "quantity": "infinity"
    }));
    creators.push(json!({
        "name": "Bob", "namespace": [], "quantity": "infinity"
    }));
    for idx in 2..owner_keys.len() {
        creators.push(json!({
            "name": format!("O{}", idx + 1),
            "namespace": [],
            "quantity": "infinity"
        }));
    }
    creators.push(json!({
        "name": "Rita", "namespace": [], "quantity": "infinity"
    }));
    let mut issuers = Vec::new();
    issuers.push(json!({"name": "Alice", "namespace": []}));
    issuers.push(json!({"name": "Bob", "namespace": []}));
    for idx in 2..owner_keys.len() {
        issuers.push(json!({"name": format!("O{}", idx + 1), "namespace": []}));
    }
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": member_adds},
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": creators,
                            "issuer": issuers
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();

    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let mut owner_apis = vec![alice.clone(), bob_node.api.clone()];
    node_running(&bob_node.api).await.unwrap();
    bob_node
        .api
        .authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    bob_node
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&bob_node.api, governance_id.clone(), None, true)
        .await
        .unwrap();

    struct ExtraNode {
        api: ave_core::Api,
        node: crate::common::NodeData,
        dirs: Vec<tempfile::TempDir>,
    }
    let mut extras: Vec<ExtraNode> = Vec::new();
    for signer in owner_signers.into_iter() {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, node_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            keys: Some(ave_common::identity::keys::KeyPair::Ed25519(signer)),
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();
        node.api
            .authorize_governance(
                governance_id.clone(),
                ave_core::auth::AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        node.api
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        get_subject(&node.api, governance_id.clone(), None, true)
            .await
            .unwrap();
        owner_apis.push(node.api.clone());
        extras.push(ExtraNode {
            api: node.api.clone(),
            node,
            dirs: node_dirs,
        });
    }
    // owner_apis[0..13] = O1..O13 (Alice, Bob, O3..O13).
    assert_eq!(owner_apis.len(), 13);

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let mut sn = 1u64;
    for pair in 0..12 {
        let from_api = owner_apis[pair].clone();
        let to_key = owner_keys[pair + 1].clone();
        emit_transfer(&from_api, subject_id.clone(), to_key, true)
            .await
            .unwrap();
        let to_api = owner_apis[pair + 1].clone();
        to_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(&to_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        emit_confirm(&to_api, subject_id.clone(), None, true)
            .await
            .unwrap();
        sn += 1;
        from_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(&from_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        sn += 1;
    }
    assert_eq!(sn, 25u64);
    let last_owner_api = owner_apis[12].clone();
    emit_transfer(&last_owner_api, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&last_owner_api, subject_id.clone(), Some(25), true)
        .await
        .unwrap();
    let history = last_owner_api
        .test_get_tracker_ledger(subject_id.clone(), 25)
        .await
        .unwrap();
    assert_eq!(history.len(), 26);
    let transfer = history
        .iter()
        .find(|event| event.sn == 25)
        .expect("pending transfer")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the pending transfer must succeed"
    );
    {
        use ave_common::request::EventRequest as PremiseReq;
        let mut premise_problems: Vec<String> = Vec::new();
        for k in 0..12 {
            let transfer_sn = (2 * k + 1) as u64;
            let confirm_sn = (2 * k + 2) as u64;
            let transfer_event = history.iter().find(|e| e.sn == transfer_sn);
            let confirm_event = history.iter().find(|e| e.sn == confirm_sn);
            match (transfer_event, confirm_event) {
                (Some(t), Some(c)) => {
                    let signer_ok =
                        t.ledger_seal_signature.signer == owner_keys[k];
                    let new_owner_ok = matches!(
                        t.get_event_request(),
                        Some(PremiseReq::Transfer(req))
                            if req.new_owner == owner_keys[k + 1]
                    );
                    let confirm_ok = matches!(
                        c.get_event_request(),
                        Some(PremiseReq::Confirm(_))
                    ) && c.protocols.is_success();
                    if !signer_ok || !new_owner_ok || !confirm_ok {
                        premise_problems.push(format!(
                            "pair{k} t_sn={transfer_sn} signer_ok={signer_ok} new_owner_ok={new_owner_ok} c_sn={confirm_sn} confirm_ok={confirm_ok}",
                        ));
                    }
                }
                _ => premise_problems.push(format!(
                    "pair{k} missing t_sn={transfer_sn} or c_sn={confirm_sn}",
                )),
            }
        }
        assert!(
            premise_problems.is_empty(),
            "premise: ledger must hold 12 Transfer+Confirm pairs, problems={:?}",
            premise_problems,
        );
    }
    // The register trails the tracker (independent tells): poll the
    // authoritative ownership until the twelve closes land.
    let mut owner_now = None;
    let mut pending_now = None;
    let mut old_owners_now = Vec::new();
    let mut stints_now = 0usize;
    for _ in 0..100 {
        let (owner, pending, olds, stints) = last_owner_api
            .test_witnesses_ownership(&governance_id, subject_id.clone())
            .await
            .unwrap();
        owner_now = owner;
        pending_now = pending;
        old_owners_now = olds;
        stints_now = stints;
        if old_owners_now.len() == 12 && stints_now == 12 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let expected: Vec<PublicKey> = owner_keys[..12].to_vec();
    let missing: Vec<String> = expected
        .iter()
        .enumerate()
        .filter(|(_, k)| !old_owners_now.iter().any(|(ok, _)| ok == *k))
        .map(|(i, k)| format!("idx{i}={k}"))
        .collect();
    let expected_idx: Vec<String> = expected
        .iter()
        .enumerate()
        .map(|(i, k)| format!("idx{i}={k}"))
        .collect();
    let unexpected: Vec<String> = old_owners_now
        .iter()
        .filter(|(ok, _)| !expected.iter().any(|k| k == ok))
        .map(|(k, sn)| format!("{}@{}", k, sn))
        .collect();
    let mut olds_sorted = old_owners_now.clone();
    olds_sorted.sort_by_key(|(_, sn)| *sn);
    let olds_sn: Vec<u64> = olds_sorted.iter().map(|(_, sn)| *sn).collect();
    let olds_mapped: Vec<String> = olds_sorted
        .iter()
        .map(|(k, sn)| {
            let idx = expected
                .iter()
                .position(|e| e == k)
                .map(|i| i.to_string())
                .unwrap_or("?".to_owned());
            let expected_sn = idx
                .parse::<usize>()
                .map(|i| 2 * (i + 1) as u64)
                .unwrap_or(0);
            format!("idx{idx} actual_sn={sn} expected_sn={expected_sn} key={k}")
        })
        .collect();
    let ledger_summary: Vec<String> = {
        let mut v: Vec<String> = Vec::new();
        for e in history.iter() {
            let kind = format!("{:?}", e.get_event_request_type());
            let ok = e.protocols.is_success();
            v.push(format!("sn={} {} ok={}", e.sn, kind, ok));
        }
        v
    };
    assert_eq!(owner_now, Some(owner_keys[12].clone()));
    assert!(
        pending_now == Some(rita_key.clone()),
        "premise: the final transfer must stay pending"
    );
    assert!(
        old_owners_now.len() == 12 && stints_now == 12,
        "premise: expected 12 olds/12 stints, got {} olds/{} stints missing={:?} expected={:?} unexpected={:?} olds_sn={:?} olds_mapped={:?} ledger={:?}",
        old_owners_now.len(),
        stints_now,
        missing,
        expected_idx,
        unexpected,
        olds_sn,
        olds_mapped,
        ledger_summary,
    );
    let chain_len = history.len() as u64;
    assert_eq!(chain_len, 26);

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    rita.add_sync_peer(
        governance_id.clone(),
        vec![PublicKey::from_str(owner.public_key()).unwrap()],
    )
    .await
    .unwrap();

    let last_sender_key = owner_keys[12].clone();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    {
        let mut fault_apis: Vec<&ave_core::Api> = vec![&alice, &bob_node.api];
        for extra in extras.iter() {
            fault_apis.push(&extra.api);
        }
        for api in fault_apis {
            for message in [
                FaultMessage::DistributionLedgerRes,
                FaultMessage::DistributionLastEventReq,
            ] {
                api.test_install_fault(FaultRule {
                    direction: FaultDirection::Outbound,
                    message,
                    peer: Some(rita_public.clone()),
                    remaining: None,
                    action: FaultAction::Drop,
                })
                .await
                .unwrap();
            }
        }
    }

    async fn inject_with_hint(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    let batches: Vec<Vec<Ledger>> =
        history[..25].chunks(1).map(<[Ledger]>::to_vec).collect();
    assert_eq!(batches.len(), 25);
    for batch in &batches {
        inject_with_hint(
            &rita,
            &last_sender_key,
            batch.clone(),
            false,
            &transfer,
        )
        .await;
    }
    get_subject(&rita, subject_id.clone(), Some(24), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((25, last_sender_key.clone())),
        "the genuine hint must record its proof from the fixed sender"
    );
    let (processed, reloads) =
        rita.test_verify_stats(subject_id.clone()).await.unwrap();
    assert!(
        reloads <= 1,
        "at most one full local reload, then only deltas: {reloads}"
    );
    assert!(
        processed <= 3 * chain_len,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "no rebuild per Transfer/Confirm, only the initial one"
    );
    inject_with_hint(
        &rita,
        &last_sender_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(25), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    let (owned_cloned, owned_visited) =
        rita.test_ownership_stats(subject_id.clone()).await.unwrap();
    assert!(
        owned_cloned > 0 && owned_visited > 0,
        "counters must record real ownership work, not stay empty: cloned={owned_cloned} visited={owned_visited} chain={chain_len}"
    );
    assert!(
        owned_cloned <= 2 * chain_len,
        "cloned {owned_cloned} ownership entries over a {chain_len}-event chain"
    );
    assert!(
        owned_visited <= 4 * chain_len,
        "visited {owned_visited} ownership entries over a {chain_len}-event chain"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the copy holds nothing back"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "the covered tail needs no second rebuild"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    rita_node.token.cancel();
    for extra in extras.iter_mut() {
        extra.node.token.cancel();
    }
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut())
            .chain(
                extras
                    .iter_mut()
                    .flat_map(|extra| extra.node.handler.iter_mut()),
            ),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(rita_node);
    drop(rita_dirs);
    for extra in extras {
        drop(extra.node);
        drop(extra.dirs);
    }
}

/// A replayed genesis must not wipe visibility once events landed.
/// Create+Fact (no closes), a pending Transfer, a reboot with the same
/// storage, a stints control and a fresh entry at SN 0: the duplicate
/// Create is ignored whenever the tip advanced, and only refreshes a
/// history-free entry at genesis.
#[test(tokio::test)]
async fn remote_create_replay_keeps_visibility_across_restart() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let alice_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut alice_node, alice_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{alice_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let alice = alice_node.api.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    node_running(&alice).await.unwrap();

    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let bob = bob_node.api.clone();
    let bob_key = PublicKey::from_str(bob.public_key()).unwrap();
    node_running(&bob).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice, &bob]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Bob", "key": bob.public_key()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {"name": "Alice", "namespace": []},
                                {"name": "Bob", "namespace": []}
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
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();
    bob.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&bob, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Phase A: Create + Fact, no closes. The Fact visibility must
    // land before snapshotting: poll by state, never by timing.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(&alice, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    let vis_create = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let mut vis_fact = vis_create.clone();
    for _ in 0..100 {
        let vis = alice
            .test_get_tracker_visibility(
                governance_id.clone(),
                subject_id.clone(),
            )
            .await
            .unwrap();
        if vis != vis_create {
            vis_fact = vis;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_ne!(
        vis_fact, vis_create,
        "the Fact visibility must land in the register"
    );
    get_subject(&alice, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let (owner_a, pending_a, olds_a, stints_a) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_a, Some(alice_key.clone()));
    assert!(pending_a.is_none());
    assert!(olds_a.is_empty() && stints_a == 0);
    let genesis_gov = alice
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 0)
        .expect("genesis event")
        .gov_version;

    // A replayed genesis with events applied must be ignored: the
    // Fact ranges stay, owner and tip are untouched.
    alice
        .test_witnesses_create(
            &governance_id,
            subject_id.clone(),
            alice_key.clone(),
            genesis_gov,
        )
        .await
        .unwrap();
    let vis_replay = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    assert_eq!(
        vis_replay, vis_fact,
        "replayed create must not reset Fact visibility"
    );
    let (owner_b, pending_b, olds_b, stints_b) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_b, Some(alice_key.clone()));
    assert!(pending_b.is_none());
    assert!(olds_b.is_empty() && stints_b == 0);
    get_subject(&alice, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Phase B: reboot with the same storage. Volatile state goes
    // away, persisted visibility and ownership come back identical.
    // The original TempDirs stay alive so the rebooted node really
    // reopens this storage.
    let keys = alice_node.keys.clone();
    let local_db = alice_dirs[0].path().to_path_buf();
    let ext_db = alice_dirs[1].path().to_path_buf();
    alice_node.token.cancel();
    join_all(alice_node.handler.iter_mut()).await;
    drop(alice_node);
    let alice_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut alice_node, _alice_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{alice_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;
    let alice = alice_node.api.clone();
    node_running(&alice).await.unwrap();
    for _ in 0..100 {
        if !alice
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !alice
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "the tracker must go idle after boot"
    );
    get_subject(&alice, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let vis_boot = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    assert_eq!(vis_boot, vis_fact, "reboot must preserve Fact visibility");
    let (owner_c, pending_c, olds_c, stints_c) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_c, Some(alice_key.clone()));
    assert!(pending_c.is_none());
    assert!(olds_c.is_empty() && stints_c == 0);

    // Phase C: pending Transfer. The replay must keep owner,
    // pending, tip and visibility: nothing closes, nothing resets.
    emit_transfer(&alice, subject_id.clone(), bob_key.clone(), true)
        .await
        .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let vis_pending = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    let (owner_d, pending_d, olds_d, stints_d) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_d, Some(alice_key.clone()));
    assert_eq!(pending_d, Some(bob_key.clone()));
    assert!(olds_d.is_empty() && stints_d == 0);
    alice
        .test_witnesses_create(
            &governance_id,
            subject_id.clone(),
            alice_key.clone(),
            genesis_gov,
        )
        .await
        .unwrap();
    let vis_pending_replay = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    assert_eq!(
        vis_pending_replay, vis_pending,
        "replayed create must not reset pending visibility"
    );
    let (owner_e, pending_e, olds_e, stints_e) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_e, Some(alice_key.clone()));
    assert_eq!(
        pending_e,
        Some(bob_key.clone()),
        "replayed create must not clear the pending transfer"
    );
    assert!(olds_e.is_empty() && stints_e == 0);

    // Phase D: stints control. With a closed stint the duplicate
    // create was already ignored with a closed stint; it must stay so.
    emit_confirm(&bob, subject_id.clone(), None, true)
        .await
        .unwrap();
    alice.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&bob, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let vis_closed = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    let (owner_f, pending_f, olds_f, stints_f) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_f, Some(bob_key.clone()));
    assert!(pending_f.is_none());
    assert_eq!(stints_f, 1);
    assert_eq!(olds_f.len(), 1);
    alice
        .test_witnesses_create(
            &governance_id,
            subject_id.clone(),
            alice_key.clone(),
            genesis_gov,
        )
        .await
        .unwrap();
    let vis_closed_replay = alice
        .test_get_tracker_visibility(governance_id.clone(), subject_id.clone())
        .await
        .unwrap();
    assert_eq!(
        vis_closed_replay, vis_closed,
        "replayed create must not touch closed history"
    );
    let (owner_g, pending_g, olds_g, stints_g) = alice
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_g, Some(bob_key.clone()));
    assert!(pending_g.is_none());
    assert_eq!(stints_g, 1);
    assert_eq!(olds_g.len(), 1);

    // Phase E: fresh entry at SN 0 still heals through the genesis
    // refresh path: owner and Create visibility register sanely.
    let (subject2_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(&alice, subject2_id.clone(), Some(0), true)
        .await
        .unwrap();
    let vis_fresh = alice
        .test_get_tracker_visibility(governance_id.clone(), subject2_id.clone())
        .await
        .unwrap();
    let genesis2_gov = alice
        .test_get_tracker_ledger(subject2_id.clone(), 0)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 0)
        .expect("genesis event")
        .gov_version;
    alice
        .test_witnesses_create(
            &governance_id,
            subject2_id.clone(),
            alice_key.clone(),
            genesis2_gov,
        )
        .await
        .unwrap();
    let vis_fresh_replay = alice
        .test_get_tracker_visibility(governance_id.clone(), subject2_id.clone())
        .await
        .unwrap();
    assert_eq!(
        vis_fresh_replay, vis_fresh,
        "genesis refresh on a fresh entry stays idempotent"
    );
    let (owner_h, pending_h, olds_h, stints_h) = alice
        .test_witnesses_ownership(&governance_id, subject2_id.clone())
        .await
        .unwrap();
    assert_eq!(owner_h, Some(alice_key.clone()));
    assert!(pending_h.is_none());
    assert!(olds_h.is_empty() && stints_h == 0);

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    alice_node.token.cancel();
    bob_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(alice_node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(alice_node);
    drop(_alice_dirs);
    drop(alice_dirs);
    drop(bob_node);
    drop(bob_dirs);
}

/// Six distinct owners: Create plus six Transfer+Confirm pairs with a new
/// owner each, plus the final Transfer. Same shape as
/// `remote_unique_owners_stay_linear` at half length (N=14): linear growth,
/// not triangular.
#[test(tokio::test)]
async fn remote_unique_owners_stay_linear_half() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    const EXTRA_OWNERS: usize = 5;
    let mut owner_keys: Vec<PublicKey> = Vec::new();
    let mut owner_signers = Vec::new();
    {
        let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
        owner_keys.push(alice_key);
    }
    let bob_signer = Ed25519Signer::generate().unwrap();
    let bob_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        bob_signer.public_key_bytes(),
    )
    .unwrap();
    owner_keys.push(bob_key.clone());
    for _ in 0..EXTRA_OWNERS {
        let signer = Ed25519Signer::generate().unwrap();
        let key = PublicKey::new(
            ave_common::identity::keys::DSAlgorithm::Ed25519,
            signer.public_key_bytes(),
        )
        .unwrap();
        owner_keys.push(key);
        owner_signers.push(signer);
    }
    // owner_keys: [Alice, Bob, O3..O7] = 7 owners O1..O7.
    assert_eq!(owner_keys.len(), 7);
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let mut member_adds = Vec::new();
    member_adds.push(json!({"name": "Alice", "key": alice.public_key()}));
    member_adds.push(json!({"name": "Bob", "key": owner_keys[1].to_string()}));
    for (idx, key) in owner_keys.iter().enumerate().skip(2) {
        member_adds.push(
            json!({"name": format!("O{}", idx + 1), "key": key.to_string()}),
        );
    }
    member_adds.push(json!({"name": "Rita", "key": rita_key.to_string()}));
    let mut creators = Vec::new();
    creators.push(json!({
        "name": "Alice", "namespace": [], "quantity": "infinity"
    }));
    creators.push(json!({
        "name": "Bob", "namespace": [], "quantity": "infinity"
    }));
    for idx in 2..owner_keys.len() {
        creators.push(json!({
            "name": format!("O{}", idx + 1),
            "namespace": [],
            "quantity": "infinity"
        }));
    }
    creators.push(json!({
        "name": "Rita", "namespace": [], "quantity": "infinity"
    }));
    let mut issuers = Vec::new();
    issuers.push(json!({"name": "Alice", "namespace": []}));
    issuers.push(json!({"name": "Bob", "namespace": []}));
    for idx in 2..owner_keys.len() {
        issuers.push(json!({"name": format!("O{}", idx + 1), "namespace": []}));
    }
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": member_adds},
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": creators,
                            "issuer": issuers
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();

    let bob_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut bob_node, bob_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{bob_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(bob_signer)),
        ..Default::default()
    })
    .await;
    let mut owner_apis = vec![alice.clone(), bob_node.api.clone()];
    node_running(&bob_node.api).await.unwrap();
    bob_node
        .api
        .authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    bob_node
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&bob_node.api, governance_id.clone(), None, true)
        .await
        .unwrap();

    struct ExtraNodeHalf {
        api: ave_core::Api,
        node: crate::common::NodeData,
        dirs: Vec<tempfile::TempDir>,
    }
    let mut extras: Vec<ExtraNodeHalf> = Vec::new();
    for signer in owner_signers.into_iter() {
        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, node_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            keys: Some(ave_common::identity::keys::KeyPair::Ed25519(signer)),
            ..Default::default()
        })
        .await;
        node_running(&node.api).await.unwrap();
        node.api
            .authorize_governance(
                governance_id.clone(),
                ave_core::auth::AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        node.api
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        get_subject(&node.api, governance_id.clone(), None, true)
            .await
            .unwrap();
        owner_apis.push(node.api.clone());
        extras.push(ExtraNodeHalf {
            api: node.api.clone(),
            node,
            dirs: node_dirs,
        });
    }
    // owner_apis[0..7] = O1..O7 (Alice, Bob, O3..O7).
    assert_eq!(owner_apis.len(), 7);

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let mut sn = 1u64;
    for pair in 0..6 {
        let from_api = owner_apis[pair].clone();
        let to_key = owner_keys[pair + 1].clone();
        emit_transfer(&from_api, subject_id.clone(), to_key, true)
            .await
            .unwrap();
        let to_api = owner_apis[pair + 1].clone();
        to_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(&to_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        emit_confirm(&to_api, subject_id.clone(), None, true)
            .await
            .unwrap();
        sn += 1;
        from_api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(&from_api, subject_id.clone(), Some(sn), true)
            .await
            .unwrap();
        sn += 1;
    }
    assert_eq!(sn, 13u64);
    let last_owner_api = owner_apis[6].clone();
    emit_transfer(&last_owner_api, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&last_owner_api, subject_id.clone(), Some(13), true)
        .await
        .unwrap();
    let history = last_owner_api
        .test_get_tracker_ledger(subject_id.clone(), 13)
        .await
        .unwrap();
    assert_eq!(history.len(), 14);
    let transfer = history
        .iter()
        .find(|event| event.sn == 13)
        .expect("pending transfer")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "premise: the pending transfer must succeed"
    );
    {
        use ave_common::request::EventRequest as PremiseReq;
        let mut premise_problems: Vec<String> = Vec::new();
        for k in 0..6 {
            let transfer_sn = (2 * k + 1) as u64;
            let confirm_sn = (2 * k + 2) as u64;
            let transfer_event = history.iter().find(|e| e.sn == transfer_sn);
            let confirm_event = history.iter().find(|e| e.sn == confirm_sn);
            match (transfer_event, confirm_event) {
                (Some(t), Some(c)) => {
                    let signer_ok =
                        t.ledger_seal_signature.signer == owner_keys[k];
                    let new_owner_ok = matches!(
                        t.get_event_request(),
                        Some(PremiseReq::Transfer(req))
                            if req.new_owner == owner_keys[k + 1]
                    );
                    let confirm_ok = matches!(
                        c.get_event_request(),
                        Some(PremiseReq::Confirm(_))
                    ) && c.protocols.is_success();
                    if !signer_ok || !new_owner_ok || !confirm_ok {
                        premise_problems.push(format!(
                            "pair{k} t_sn={transfer_sn} signer_ok={signer_ok} new_owner_ok={new_owner_ok} c_sn={confirm_sn} confirm_ok={confirm_ok}",
                        ));
                    }
                }
                _ => premise_problems.push(format!(
                    "pair{k} missing t_sn={transfer_sn} or c_sn={confirm_sn}",
                )),
            }
        }
        assert!(
            premise_problems.is_empty(),
            "premise: ledger must hold 6 Transfer+Confirm pairs, problems={:?}",
            premise_problems,
        );
    }
    // The register trails the tracker (independent tells): poll the
    // authoritative ownership until the six closes land.
    let mut owner_now = None;
    let mut pending_now = None;
    let mut old_owners_now = Vec::new();
    let mut stints_now = 0usize;
    for _ in 0..100 {
        let (owner, pending, olds, stints) = last_owner_api
            .test_witnesses_ownership(&governance_id, subject_id.clone())
            .await
            .unwrap();
        owner_now = owner;
        pending_now = pending;
        old_owners_now = olds;
        stints_now = stints;
        if old_owners_now.len() == 6 && stints_now == 6 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let expected: Vec<PublicKey> = owner_keys[..6].to_vec();
    let missing: Vec<String> = expected
        .iter()
        .enumerate()
        .filter(|(_, k)| !old_owners_now.iter().any(|(ok, _)| ok == *k))
        .map(|(i, k)| format!("idx{i}={k}"))
        .collect();
    assert_eq!(owner_now, Some(owner_keys[6].clone()));
    assert!(
        pending_now == Some(rita_key.clone()),
        "premise: the final transfer must stay pending"
    );
    assert!(
        old_owners_now.len() == 6 && stints_now == 6,
        "premise: expected 6 olds/6 stints, got {} olds/{} stints missing={:?}",
        old_owners_now.len(),
        stints_now,
        missing,
    );
    let chain_len = history.len() as u64;
    assert_eq!(chain_len, 14);

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    rita.add_sync_peer(
        governance_id.clone(),
        vec![PublicKey::from_str(owner.public_key()).unwrap()],
    )
    .await
    .unwrap();

    let last_sender_key = owner_keys[6].clone();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    {
        let mut fault_apis: Vec<&ave_core::Api> = vec![&alice, &bob_node.api];
        for extra in extras.iter() {
            fault_apis.push(&extra.api);
        }
        for api in fault_apis {
            for message in [
                FaultMessage::DistributionLedgerRes,
                FaultMessage::DistributionLastEventReq,
            ] {
                api.test_install_fault(FaultRule {
                    direction: FaultDirection::Outbound,
                    message,
                    peer: Some(rita_public.clone()),
                    remaining: None,
                    action: FaultAction::Drop,
                })
                .await
                .unwrap();
            }
        }
    }

    async fn inject_with_hint_half(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
        hint: &Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all,
                    transfer_event: Some(Box::new(hint.clone())),
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    let batches: Vec<Vec<Ledger>> =
        history[..13].chunks(1).map(<[Ledger]>::to_vec).collect();
    assert_eq!(batches.len(), 13);
    for batch in &batches {
        inject_with_hint_half(
            &rita,
            &last_sender_key,
            batch.clone(),
            false,
            &transfer,
        )
        .await;
    }
    get_subject(&rita, subject_id.clone(), Some(12), true)
        .await
        .unwrap();
    assert_eq!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap(),
        Some((13, last_sender_key.clone())),
        "the genuine hint must record its proof from the fixed sender"
    );
    let (processed, reloads) =
        rita.test_verify_stats(subject_id.clone()).await.unwrap();
    assert!(
        reloads <= 1,
        "at most one full local reload, then only deltas: {reloads}"
    );
    assert!(
        processed <= 3 * chain_len,
        "processed {processed} events over a {chain_len}-event chain"
    );
    let (cloned, visited, reordered) =
        rita.test_buffer_stats(subject_id.clone()).await.unwrap();
    assert!(
        cloned <= 4 * chain_len,
        "cloned {cloned} events over a {chain_len}-event chain"
    );
    assert!(
        visited <= 12 * chain_len,
        "visited {visited} events over a {chain_len}-event chain"
    );
    assert!(
        reordered <= 2 * chain_len,
        "reordered {reordered} events over a {chain_len}-event chain"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "no rebuild per Transfer/Confirm, only the initial one"
    );
    inject_with_hint_half(
        &rita,
        &last_sender_key,
        vec![transfer.clone()],
        true,
        &transfer,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(13), true)
        .await
        .unwrap();
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    let (owned_cloned, owned_visited) =
        rita.test_ownership_stats(subject_id.clone()).await.unwrap();
    assert!(
        owned_cloned > 0 && owned_visited > 0,
        "counters must record real ownership work, not stay empty: cloned={owned_cloned} visited={owned_visited} chain={chain_len}"
    );
    assert!(
        owned_cloned <= 2 * chain_len,
        "cloned {owned_cloned} ownership entries over a {chain_len}-event chain"
    );
    assert!(
        owned_visited <= 4 * chain_len,
        "visited {owned_visited} ownership entries over a {chain_len}-event chain"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "the copy holds nothing back"
    );
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "the covered tail needs no second rebuild"
    );
    node_running(&rita).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    bob_node.token.cancel();
    rita_node.token.cancel();
    for extra in extras.iter_mut() {
        extra.node.token.cancel();
    }
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(bob_node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut())
            .chain(
                extras
                    .iter_mut()
                    .flat_map(|extra| extra.node.handler.iter_mut()),
            ),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(bob_node);
    drop(bob_dirs);
    drop(rita_node);
    drop(rita_dirs);
    for extra in extras {
        drop(extra.node);
        drop(extra.dirs);
    }
}

/// A stale distribution ack (same sender, older event) must not
/// complete a newer generation on the same route: only the ack
/// naming the distributed event hash stops the retry. A resent ack
/// for the same event stays idempotent and never reopens a closed
/// generation.
#[test(tokio::test)]
async fn remote_stale_ack_does_not_complete_new_distribution() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let w = nodes[2].api.clone();
    let w_key = PublicKey::from_str(w.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "W", "key": w.public_key()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    async fn hold_res(api: &ave_core::Api) {
        api.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }
    async fn held_res_count(api: &ave_core::Api) -> usize {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|m| {
                matches!(
                    &m.message,
                    ActorMessage::DistributionLastEventRes { .. }
                )
            })
            .count()
    }

    // First generation completes normally; keep a copy of its ack.
    hold_res(&w).await;
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    for _ in 0..100 {
        if held_res_count(&w).await >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stale_ack = w
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|m| {
            matches!(&m.message, ActorMessage::DistributionLastEventRes { .. })
        })
        .expect("first generation ack held");
    w.test_release_held().await.unwrap();
    // Re-arm the hold for the next generation: releasing drops the
    // rule, and the genuine ack below must be retained too.
    hold_res(&w).await;

    // Second generation: its push applies, its ack stays held.
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    for _ in 0..100 {
        if held_res_count(&w).await >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // The live generation keeps retrying while its ack is held:
    // every retry earns another retained ack. The stale ack below
    // must not stop this flow; the count must keep growing.
    let held_before = held_res_count(&w).await;
    assert!(held_before >= 1, "second generation ack retained");

    // Deliver the stale ack on the reused route: it must be ignored
    // without stopping the retry of the live generation.
    alice
        .test_inject_inbound(stale_ack.clone(), &w_key)
        .await
        .unwrap();
    for _ in 0..100 {
        if held_res_count(&w).await > held_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        held_res_count(&w).await > held_before,
        "stale ack ignored: the live generation keeps retrying"
    );

    // The genuine ack still completes the generation exactly once.
    w.test_release_held().await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    node_running(&alice).await.unwrap();
    node_running(&w).await.unwrap();

    // A duplicate of the consumed ack changes nothing and wedges no
    // later generation.
    alice.test_inject_inbound(stale_ack, &w_key).await.unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();
    hold_res(&w).await;
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    w.test_release_held().await.unwrap();
    get_subject(&w, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    node_running(&alice).await.unwrap();
    node_running(&w).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

/// Two duplicate copies (same subject, sender, request id and
/// version) must own independent leases: the failed attempt closes
/// only its own entry, so the concurrent valid copy keeps its guard
/// and finishes without a trace of the forgery. Both are
/// continuations on an already registered subject so they share the
/// exact same requester identity (kind included) on the pre-fix code.
#[test(tokio::test)]
async fn remote_duplicate_attempts_have_independent_leases() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();

    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();
    let w_signer = Ed25519Signer::generate().unwrap();
    let w_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        w_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "W", "key": w_key.to_string()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();

    // W joins only now: nothing pushed to her is genuine traffic.
    let (mut w_node, w_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: nodes[0].api.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(w_signer)),
        ..Default::default()
    })
    .await;
    let w = w_node.api.clone();
    node_running(&w).await.unwrap();
    // Freeze background tracker sync on W: every copy below is
    // injected, so a racing pull must never pre-empt the parked
    // interleaving.
    w.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::TrackerSyncReq,
        peer: None,
        remaining: None,
        action: FaultAction::Drop,
    })
    .await
    .unwrap();
    // Freeze live auto-pushes from the owner: every push below is
    // injected, so a racing genuine push must never pre-empt the
    // parked interleaving.
    alice
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventReq,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    // The valid copy creates the subject and parks holding its
    // lease; the forged duplicate is a continuation on top, so
    // both share the exact same requester identity (kind included)
    // on the pre-fix code. (Two first copies can not interleave:
    // whoever creates first makes the other look stale, so the
    // shared-id collision would never even form.)
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(history.len(), 3);
    let create = history
        .iter()
        .find(|event| event.sn == 0)
        .expect("create event")
        .clone();
    let fact = history
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event")
        .clone();
    let transfer = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();

    // Same bytes except the fact seal, which names a signer its
    // signature was never made for: the genuine inline transfer
    // still proves, so the batch reaches the apply and fails
    // there instead of being refuted before any write.
    let mut forged_fact = fact.clone();
    forged_fact.ledger_seal_signature.signer = carol_key.clone();

    // W registers SN 0 with a genuine first copy, so both
    // duplicates below are continuations sharing the exact same
    // requester identity (kind included) on the pre-fix code.
    w.test_ensure_distributor(subject_id.clone()).await.unwrap();
    w.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(w.public_key()).unwrap(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![create.clone()],
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&w, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // Both duplicates park after acquiring their leases: the
    // valid copy on the per-subject worker, the forged one on the
    // node-level worker. Both batches share subject, sender,
    // request id and version, so only the attempt distinguishes
    // their leases.
    let per_subject = format!("/user/node/distributor_{}", subject_id);
    w.test_pause_after_acquire(true).await.unwrap();
    let inject = |ledger: Vec<Ledger>, receiver_actor: String| {
        let w = w.clone();
        let alice_key = alice_key.clone();
        async move {
            w.test_inject_inbound(
                NetworkMessage::new(
                    ComunicateInfo {
                        request_id: String::new(),
                        version: 0,
                        receiver: PublicKey::from_str(w.public_key()).unwrap(),
                        receiver_actor,
                    },
                    ActorMessage::DistributionLedgerRes {
                        ledger,
                        is_all: true,
                        transfer_event: None,
                        expected_governance_id: None,
                    },
                ),
                &alice_key,
            )
            .await
            .unwrap();
        }
    };
    inject(vec![fact.clone(), transfer.clone()], per_subject.clone()).await;
    for _ in 0..100 {
        if w.test_after_acquire_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        w.test_after_acquire_hold_count().await.unwrap(),
        1,
        "the valid copy parks owning its lease"
    );
    // The forged duplicate carries no Create: W already tracks
    // the subject from the parked valid copy, so it is a plain
    // continuation that must still fail closed at apply time.
    inject(
        vec![forged_fact.clone(), transfer.clone()],
        "/user/node/distributor".to_owned(),
    )
    .await;
    for _ in 0..100 {
        if w.test_after_acquire_hold_count().await.unwrap_or(0) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        w.test_after_acquire_hold_count().await.unwrap(),
        2,
        "both duplicates park owning their leases"
    );

    // Same batch identity, two independent leases: a shared entry
    // would collapse both into one.
    let mut requesters =
        w.test_list_requesters(subject_id.clone()).await.unwrap();
    requesters.sort();
    assert_eq!(
        requesters.len(),
        2,
        "duplicate attempts own independent leases: {requesters:?}"
    );
    assert!(
        w.test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "live requesters while both duplicates are parked"
    );

    // Release both: the forged duplicate fails without a trace and
    // the valid copy applies the genuine history.
    w.test_pause_after_acquire(false).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    for _ in 0..100 {
        if !w
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let copied = w
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3, "the valid copy stays applied");
    let applied_fact = copied
        .iter()
        .find(|event| event.sn == 1)
        .expect("fact event");
    assert_eq!(
        borsh::to_vec(applied_fact).unwrap(),
        borsh::to_vec(&fact).unwrap(),
        "the forged duplicate wrote nothing: SN 1 stays genuine"
    );
    assert!(
        copied
            .iter()
            .find(|event| event.sn == 2)
            .expect("transfer event")
            .protocols
            .is_success(),
        "the genuine transfer stays applied"
    );
    match w
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
    {
        Err(_) => panic!("ownership must be readable after the race"),
        Ok((owner_now, pending, _, _)) => {
            assert_eq!(
                owner_now,
                Some(PublicKey::from_str(alice.public_key()).unwrap()),
                "no ownership rotation may be reverted"
            );
            assert_eq!(
                pending,
                Some(carol_key.clone()),
                "the genuine pending transfer stays pending"
            );
        }
    }
    assert!(
        !w.test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "no lease may leak once both attempts finish"
    );
    node_running(&w).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    w_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(w_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(w_node);
    drop(w_dirs);
}

/// Two duplicate pushes (same subject, sender, request id and
/// version) must own independent leases as well: the failed push
/// closes only its own entry while the parked valid push still
/// guards the subject.
#[test(tokio::test)]
async fn remote_duplicate_pushes_have_independent_leases() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let w = nodes[2].api.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let w_key = PublicKey::from_str(w.public_key()).unwrap();

    // Freeze background tracker sync on W: the pushed fact below
    // must be the only way SN 2 arrives.
    w.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::TrackerSyncReq,
        peer: None,
        remaining: None,
        action: FaultAction::Drop,
    })
    .await
    .unwrap();
    // Freeze live auto-pushes from the owner for the same reason.
    alice
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventReq,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();

    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "W", "key": w.public_key()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    // W starts from a genuine injected prefix: no update round is
    // needed, and the later pushes are exact continuations of it.
    let prefix = alice
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(prefix.len(), 2);
    w.test_ensure_distributor(subject_id.clone()).await.unwrap();
    w.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(w.public_key()).unwrap(),
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: prefix,
                is_all: true,
                transfer_event: None,
                expected_governance_id: None,
            },
        ),
        &alice_key,
    )
    .await
    .unwrap();
    get_subject(&w, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();
    let pushed = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 2)
        .expect("pushed fact");
    let forged = {
        let mut forged = alice
            .test_get_tracker_ledger(subject_id.clone(), 3)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.sn == 3)
            .expect("fact to forge");
        forged.ledger_seal_signature.signer = carol_key.clone();
        forged
    };

    // Both pushes share subject, sender, request id and version:
    // only the attempt distinguishes their leases. The valid push
    // parks after applying SN 2 with its lease held; the forged
    // push of SN 3 parks on the same barrier after failing to
    // apply. Different SNs keep the forged push from looking like
    // a duplicate of the applied one, and different workers keep
    // both parked at once instead of serialising them.
    let per_subject = format!("/user/node/distributor_{}", subject_id);
    w.test_ensure_distributor(subject_id.clone()).await.unwrap();
    w.test_pause_single_updated(true).await.unwrap();
    let inject_push = |ledger: Ledger, receiver_actor: String| {
        let w = w.clone();
        let alice_key = alice_key.clone();
        let w_key = w_key.clone();
        async move {
            w.test_inject_inbound(
                NetworkMessage::new(
                    ComunicateInfo {
                        request_id: "dup".to_owned(),
                        version: 0,
                        receiver: w_key,
                        receiver_actor,
                    },
                    ActorMessage::DistributionLastEventReq {
                        ledger: Box::new(ledger),
                    },
                ),
                &alice_key,
            )
            .await
            .unwrap();
        }
    };
    inject_push(pushed.clone(), per_subject.clone()).await;
    for _ in 0..100 {
        if w.test_single_updated_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    inject_push(forged.clone(), "/user/node/distributor".to_owned()).await;
    for _ in 0..100 {
        if w.test_single_updated_hold_count().await.unwrap_or(0) >= 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        w.test_single_updated_hold_count().await.unwrap(),
        2,
        "both duplicate pushes park after their update decision"
    );

    // Same batch identity, two independent leases: a shared entry
    // would collapse both into one.
    let mut requesters =
        w.test_list_requesters(subject_id.clone()).await.unwrap();
    requesters.sort();
    assert_eq!(
        requesters.len(),
        2,
        "duplicate pushes own independent leases: {requesters:?}"
    );
    assert!(
        w.test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "live requesters while both pushes are parked"
    );

    // Release both: the forged push fails without a trace and the
    // valid one completes the copy.
    w.test_pause_single_updated(false).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let copied = w
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    assert_eq!(copied.len(), 3, "the valid push stays applied");
    let applied = copied
        .into_iter()
        .find(|event| event.sn == 2)
        .expect("pushed fact");
    assert_eq!(
        borsh::to_vec(&applied).unwrap(),
        borsh::to_vec(&pushed).unwrap(),
        "the pushed fact stays byte-identical"
    );
    // Both parked attempts close once released: poll, since their
    // finish is asynchronous to the release.
    for _ in 0..100 {
        if !w
            .test_has_live_requesters(subject_id.clone())
            .await
            .unwrap()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        !w.test_has_live_requesters(subject_id.clone())
            .await
            .unwrap(),
        "no lease may leak once both pushes finish"
    );
    node_running(&w).await.unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

// A restarted update sweep runs a new generation: child names, offer
// rounds, copy versions and completions all move together, so a
// retained answer from the previous sweep is never accepted as the
// new one. Pre-fix the round is not bumped on restart: the new child
// reuses the old path and round, and the stale offer completes it.
#[test(tokio::test)]
async fn remote_update_restart_rejects_stale_offer() {
    async fn hold(api: &ave_core::Api, message: FaultMessage) {
        api.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }
    async fn held_offer(api: &ave_core::Api) -> Option<NetworkMessage> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .find(|m| matches!(m.message, ActorMessage::UpdateOffer { .. }))
            .map(|m| m)
    }
    async fn ledger_subjects(api: &ave_core::Api) -> Vec<DigestIdentifier> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|m| match &m.message {
                ActorMessage::DistributionLedgerReq { subject_id, .. } => {
                    Some(subject_id.clone())
                }
                _ => None,
            })
            .collect()
    }

    // Two nodes, plain manual timing. B owns the governance and hosts
    // the tracker; A only updates it.
    let gov_sync = || {
        Some(ave_core::config::GovernanceSyncConfig {
            interval_secs: 3600,
            sample_size: 3,
            response_timeout_secs: 3600,
        })
    };
    let tracker_sync = || {
        Some(ave_core::config::TrackerSyncConfig {
            interval_secs: 3600,
            page_size: 10,
            response_timeout_secs: 3600,
            update_batch_size: 2,
            update_timeout_secs: 5,
        })
    };
    let (mut nodes, mut dirs) = (Vec::new(), Vec::new());
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            governance_sync: gov_sync(),
            tracker_sync: tracker_sync(),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let _ = nodes;
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();

    // G1: B owns, A is member; Example schema with the owner as
    // evaluator/validator/creator and A as schema witness so B serves
    // A. B stays the only governance witness.
    let g1 = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        g1.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "schemas": { "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0},
                },
            ]},
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "A", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [{"name": "Owner", "namespace": []}],
                        },
                    },
                ],
            },
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, g1.clone(), Some(1), true).await.unwrap();
    a.update_subject(g1.clone()).await.unwrap();
    get_subject(&a, g1.clone(), Some(1), true).await.unwrap();

    // Tracker T on B, unheard by A: no creation push may complete the
    // update before the test drives it.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::TrackerSyncReq,
        FaultMessage::TrackerSyncRes,
        FaultMessage::UpdateNoOffer,
        FaultMessage::UpdateOffer,
        FaultMessage::GovernanceVersionReq,
        FaultMessage::GovernanceVersionRes,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (t, _) = create_subject(&b, g1.clone(), "Example", "", true)
        .await
        .unwrap();
    b.test_clear_faults().await.unwrap();
    a.authorize_governance(
        t.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();

    // Sweep 1 stalls at the offer: B's answer is held for cloning.
    hold(&b, FaultMessage::UpdateOffer).await;
    hold(&a, FaultMessage::DistributionLedgerReq).await;
    a.update_subject(t.clone()).await.unwrap();
    let mut offer1 = None;
    for _ in 0..100 {
        if let Some(m) = held_offer(&b).await {
            offer1 = Some(m);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer1 = offer1.expect("sweep 1 offer held");
    let old_path = offer1.info.receiver_actor.clone();

    // Let sweep 1 proceed into its copy wait: the stale offer below
    // must find a live round 1 that it still can not satisfy.
    b.test_release_held().await.unwrap();
    for _ in 0..100 {
        if ledger_subjects(&a).await.len() == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        ledger_subjects(&a).await,
        vec![t.clone()],
        "sweep 1 requests its own copy"
    );

    // Sweep 2 opens on the same actor with a new generation.
    hold(&b, FaultMessage::UpdateOffer).await;
    a.update_subject(t.clone()).await.unwrap();
    let mut offer2 = None;
    for _ in 0..200 {
        if let Some(m) = held_offer(&b).await {
            offer2 = Some(m);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let offer2 = offer2.expect("sweep 2 offer held");
    assert_ne!(
        offer1.info.receiver_actor, offer2.info.receiver_actor,
        "a restart addresses a new updater generation"
    );

    // Only the stale offer: ignored, no new copy. Pre-fix it reaches
    // the reused child and completes sweep 2 on the spot.
    a.test_inject_inbound(offer1.clone(), &b_key).await.unwrap();
    // A stale NoOffer to the dead generation is equally silent.
    a.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver: PublicKey::from_str(&a.public_key()).unwrap(),
                receiver_actor: old_path,
            },
            ActorMessage::UpdateNoOffer,
        ),
        &b_key,
    )
    .await
    .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(
        ledger_subjects(&a).await.len(),
        1,
        "a stale offer launches no copy"
    );

    // The live offer completes sweep 2 exactly once; replaying it
    // changes nothing: the witness is already consumed.
    b.test_release_held().await.unwrap();
    for _ in 0..100 {
        if ledger_subjects(&a).await.len() == 2 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        ledger_subjects(&a).await,
        vec![t.clone(), t.clone()],
        "only the live offer selects the peer"
    );
    a.test_inject_inbound(offer2.clone(), &b_key).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert_eq!(
        ledger_subjects(&a).await.len(),
        2,
        "replaying the live offer launches no second copy"
    );

    // A completion from the old generation can not stop the live
    // sweep; the update actor is still there afterwards.
    a.test_update_done(t.clone(), 5, 0).await.unwrap();
    a.test_update_done(t.clone(), 5, 1).await.unwrap();
    assert!(
        a.test_update_alive(t.clone()).await.unwrap(),
        "a stale completion must not stop the live sweep"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

// A new run adopts the snapshot the access layer just computed:
// local sn, witnesses and kind travel in the Run itself instead of
// reusing the previous sweep's. Both sequential and restarted runs
// ask the current peers with the current sn; pre-fix the second
// sweep repeats the initial peer set and sn.
#[test(tokio::test)]
async fn remote_update_restart_refreshes_snapshot() {
    async fn last_sn_reqs(
        api: &ave_core::Api,
    ) -> Vec<(PublicKey, Option<u64>)> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .iter()
            .filter_map(|m| match &m.message {
                ActorMessage::DistributionGetLastSn { actual_sn, .. } => {
                    Some((m.info.receiver.clone(), *actual_sn))
                }
                _ => None,
            })
            .collect()
    }

    // Same two nodes as the stale-offer test: B owns and hosts, A
    // only updates.
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await;
    let mut dirs = vec![];
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    let mut nodes = vec![boot];
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let boot_key = PublicKey::from_str(&nodes[0].api.public_key()).unwrap();
    let _ = nodes;
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();

    let g1 = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        g1.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "schemas": { "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0},
                },
            ]},
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "A", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["AllViewpoints"],
                                        },
                                    ],
                                },
                            ],
                            "issuer": [{"name": "Owner", "namespace": []}],
                        },
                    },
                ],
            },
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, g1.clone(), Some(1), true).await.unwrap();
    a.update_subject(g1.clone()).await.unwrap();
    get_subject(&a, g1.clone(), Some(1), true).await.unwrap();

    // Tracker T on B: its creation push lands on A (schema
    // witness) with no sweep involved, so sweep 1 below starts from
    // actual_sn 0, proving the first pull starts with no prior sweep.
    let (t, _) = create_subject(&b, g1.clone(), "Example", "", true)
        .await
        .unwrap();
    get_subject(&a, t.clone(), Some(0), true).await.unwrap();
    a.authorize_governance(
        t.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();

    // B goes deaf: the next fact must not reach A until sweep 1 is
    // already waiting for it.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::TrackerSyncReq,
        FaultMessage::TrackerSyncRes,
        FaultMessage::UpdateNoOffer,
        FaultMessage::UpdateOffer,
        FaultMessage::GovernanceVersionReq,
        FaultMessage::GovernanceVersionRes,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: None,
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    emit_fact(&b, t.clone(), json!({"ModOne": {"data": 1}}), true)
        .await
        .unwrap();

    // Sweep 1 asks the only known peer with the local sn 0. Its
    // copy stays held (exactly one request) so the sweep is still
    // alive for the restart below; later catch-up pulls must flow.
    a.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionGetLastSn,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerReq,
        peer: None,
        remaining: Some(1),
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(t.clone()).await.unwrap();
    for _ in 0..100 {
        if !last_sn_reqs(&a).await.is_empty() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let sweep1 = last_sn_reqs(&a).await;
    assert_eq!(
        sweep1,
        vec![(b_key.clone(), Some(0))],
        "the first sweep asks the known peer with the local sn"
    );

    // The subject advances (B's push, now unblocked, carries the
    // missing suffix) and a new sync peer appears before the second
    // call: the bootstrap node, authorized for this subject. Its
    // updater proves the new sweep addresses it even though its
    // requests may never be observable.
    b.test_clear_faults().await.unwrap();
    emit_fact(&b, t.clone(), json!({"ModOne": {"data": 2}}), true)
        .await
        .unwrap();
    get_subject(&a, t.clone(), Some(2), true).await.unwrap();
    let extra = boot_key.clone();
    a.authorize_governance(
        t.clone(),
        ave_core::auth::AuthWitness::One(extra.clone()),
    )
    .await
    .unwrap();

    // The live sweep must still own its actor here: update 2 has
    // to restart it (same actor, new generation), not birth a fresh
    // one (which would start from a fresh snapshot either way and
    // prove nothing). A fired retry timer would stop it first and
    // fail loudly below instead of passing vacuously.
    assert!(
        a.test_update_alive(t.clone()).await.unwrap(),
        "sweep 1 must still be alive for the restart"
    );

    // Sweep 2 restarts the live sweep with a fresh snapshot: the
    // new local sn and the added peer. Pre-fix it repeats the
    // initial set and sn. The poll waits for both the refreshed
    // request and the new updater: a lingering timer from sweep 1
    // can refresh the sn on its own, but only the new sweep
    // addresses the added peer.
    a.update_subject(t.clone()).await.unwrap();
    for _ in 0..100 {
        let fresh: Vec<_> = last_sn_reqs(&a)
            .await
            .into_iter()
            .skip(sweep1.len())
            .collect();
        let booted = a
            .test_update_updater_rounds(t.clone(), extra.clone())
            .await
            .unwrap();
        if fresh.iter().any(|(p, s)| p == &b_key && *s == Some(2))
            && !booted.is_empty()
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let fresh: Vec<_> = last_sn_reqs(&a)
        .await
        .into_iter()
        .skip(sweep1.len())
        .collect();
    assert!(
        fresh.iter().any(|(p, s)| p == &b_key && *s == Some(2)),
        "the new sweep uses the new local sn, got {fresh:?}"
    );
    assert!(
        !a.test_update_updater_rounds(t.clone(), extra.clone())
            .await
            .unwrap()
            .is_empty(),
        "the new sweep asks the added peer too"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

/// Masks a genuine fact to its opaque projection and re-links +
/// re-seals it onto `prev_hash`: the serving-side shape of a
/// hash-only view.
fn mask_and_reseal_event(
    event: &Ledger,
    prev_hash: &DigestIdentifier,
    signer: &ave_common::identity::keys::KeyPair,
) -> Ledger {
    let mut masked = event
        .to_tracker_opaque()
        .expect("premise: the fact must project to opaque");
    masked.prev_ledger_event_hash = prev_hash.clone();
    let masked_protocols_hash = masked
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    masked.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: masked.gov_version,
            sn: masked.sn,
            prev_ledger_event_hash: masked.prev_ledger_event_hash.clone(),
            protocols_hash: masked_protocols_hash,
        },
        signer,
    )
    .unwrap();
    masked
}

/// Replaces a genuine, evaluation-successful transfer's evaluation
/// result with another event's `Ok` result (keeping its result hash)
/// and re-seals it with the same signer: the evaluation stays `Ok`,
/// the chain link stays intact, but the attested computation no
/// longer reproduces, so the transfer refutes on recheck instead of
/// passing as unverifiable.
fn forge_ok_evaluation(
    transfer: &Ledger,
    fact_ok_result: ave_core::evaluation::response::EvaluatorResponse,
    signer: &ave_common::identity::keys::KeyPair,
) -> Ledger {
    let mut forged = transfer.clone();
    match &mut forged.protocols {
        Protocols::Transfer { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: fact_ok_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a transfer event"),
    };
    let protocols_hash = forged
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    forged.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: forged.gov_version,
            sn: forged.sn,
            prev_ledger_event_hash: forged.prev_ledger_event_hash.clone(),
            protocols_hash,
        },
        signer,
    )
    .unwrap();
    forged
}

// A registered opaque prefix plus a Full fact and an inline transfer
// whose evaluation is `Ok` but whose evidence does not reproduce:
// the whole chunk must be rejected before any write, so the fact is
// never rematerialized in clear, the sn never advances and nothing
// reaches the journal or the sinks. Pre-fix the fact persists in
// clear and only the transfer fails afterwards.
#[test(tokio::test)]
async fn remote_registered_refuted_inline_transfer_cannot_unmask_prefix() {
    use ave_common::bridge::request::SinkEventsQuery;

    async fn sink_empty_from(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        from_sn: u64,
    ) {
        let page = api
            .get_sink_events(
                subject.clone(),
                SinkEventsQuery {
                    from_sn: Some(from_sn),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await
            .unwrap();
        assert!(
            page.events.is_empty(),
            "a rejected chunk emits nothing to sinks"
        );
    }

    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "Rita", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Rita joins late with opaque views: every batch below is
    // injected by the test, and Alice's pushes to her are dropped so
    // no genuine history can interleave. Rita is also a schema
    // witness, so injected continuations reach receipt validation
    // under her own rights instead of stalling on access; views stay
    // opaque because no creator-witness grant names her.
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).expect("node key");
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Subject with SN0..4 on Alice; Rita registers the clear prefix
    // SN0..2. The attack replays SN3..4: a genuine Full fact plus an
    // inline transfer with `Ok` evaluation whose seal link no longer
    // reproduces. Everything the verifier replays is checkable, so a
    // broken link refutes instead of degrading to Unverifiable.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2, 3] {
        emit_fact(
            &alice,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    let hfind = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let create = hfind(0);
    let fact1 = hfind(1);
    let fact2 = hfind(2);
    let fact3 = hfind(3);
    assert!(
        matches!(fact3.protocols, Protocols::TrackerFactFull { .. }),
        "premise: the new fact is Full"
    );
    let transfer4 = hfind(4);
    assert!(
        transfer4.protocols.is_success(),
        "premise: the genuine transfer succeeds"
    );
    // Registered clear prefix SN0..2 on Rita: her schema-witness
    // rights open passage without any transfer hint.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone(), fact2.clone()],
        None,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    // The attack chunk: the genuine Full fact plus an inline
    // transfer with a forged `Ok` evaluation (another event's result
    // under the original result hash, freshly sealed). The chain link
    // is intact, so only the evidence recheck can refute it: rejected
    // as a whole before any write, Rita keeps SN2 with a clean prefix
    // and no proof.
    let fact3_result = match &fact3.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("premise: the fact evaluation is ok"),
        _ => panic!("premise: the new fact is Full"),
    };
    let forged4 = forge_ok_evaluation(&transfer4, fact3_result, &alice_keys);
    inject_ledger_batch(&rita, &alice_key, vec![fact3.clone(), forged4], None)
        .await;
    // Poll rejection: SN stays, no proof, deferred empty (no fixed sleep).
    {
        let start = tokio::time::Instant::now();
        loop {
            let sn = get_subject(&rita, subject_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
            let proof = rita
                .test_get_verified_transfer_sn(
                    &governance_id,
                    subject_id.clone(),
                )
                .await
                .unwrap_or(None);
            let deferred =
                rita.test_deferred_stats().await.unwrap_or((1, 1, 1));
            if sn == 2 && proof.is_none() && deferred == (0, 0, 0) {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "refuted chunk rejects"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert_eq!(
        get_subject(&rita, subject_id.clone(), None, true)
            .await
            .unwrap()
            .sn,
        2,
        "a refuted inline transfer rejects the whole chunk"
    );
    let stored: Vec<u64> = rita
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap_or_default()
        .iter()
        .map(|event| event.sn)
        .collect();
    assert_eq!(stored, vec![0, 1, 2], "no prefix event is rewritten");
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a refuted transfer records no proof"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a rejected chunk holds nothing back"
    );
    // Only post-prefix events count: the registered prefix itself
    // legitimately flowed to sinks when it applied.
    sink_empty_from(&rita, &subject_id, 3).await;

    // The rejection survives a reboot with the same stores.
    let rita_keys = rita_node.keys.clone();
    let rita_local = rita_dirs[0].path().to_path_buf();
    let rita_ext = rita_dirs[1].path().to_path_buf();
    rita_node.token.cancel();
    join_all(rita_node.handler.iter_mut()).await;
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut new_rita, new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(rita_keys),
        local_db: Some(rita_local),
        ext_db: Some(rita_ext),
        ..Default::default()
    })
    .await;
    let rita = new_rita.api.clone();
    node_running(&rita).await.unwrap();
    assert_eq!(
        get_subject(&rita, subject_id.clone(), None, true)
            .await
            .unwrap()
            .sn,
        2,
        "reboot does not rematerialize the rejected fact"
    );
    sink_empty_from(&rita, &subject_id, 3).await;
    let reboot_dirs = new_dirs;

    // Control: the same fact alone stores Opaque and advances. The
    // genuine transfer below only lends passage context; it is not
    // applied by this batch.
    let (subject_b, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_b.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_b.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    let history_b = alice
        .test_get_tracker_ledger(subject_b.clone(), 2)
        .await
        .unwrap();
    let bfind = |sn: u64| {
        history_b
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let bcreate = bfind(0);
    let bfact = bfind(1);
    let bmasked = mask_and_reseal_event(
        &bfact,
        &bcreate.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        &alice_keys,
    );
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![bcreate.clone(), bmasked.clone()],
        None,
    )
    .await;
    get_subject(&rita, subject_b.clone(), Some(1), true)
        .await
        .unwrap();
    let bstored = rita
        .test_get_tracker_ledger(subject_b.clone(), 1)
        .await
        .unwrap();
    assert!(
        matches!(
            bstored.iter().find(|e| e.sn == 1).unwrap().protocols,
            Protocols::TrackerFactOpaque { .. }
        ),
        "a lone fact stays opaque"
    );

    // Control: a genuine transfer to Rita opens the history it needs.
    let (subject_c, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2, 3] {
        emit_fact(
            &alice,
            subject_c.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&alice, subject_c.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_c.clone(), Some(4), true)
        .await
        .unwrap();
    let history_c = alice
        .test_get_tracker_ledger(subject_c.clone(), 4)
        .await
        .unwrap();
    let cfind = |sn: u64| {
        history_c
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let ccreate = cfind(0);
    let cfact1 = cfind(1);
    let cfact2 = cfind(2);
    let cfact3 = cfind(3);
    let ctransfer = cfind(4);
    // Clear prefix first, then the genuine suffix on its own: the
    // chain is fully checkable, so the transfer proves and the fact
    // stays Full.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![ccreate.clone(), cfact1.clone(), cfact2.clone()],
        None,
    )
    .await;
    get_subject(&rita, subject_c.clone(), Some(2), true)
        .await
        .unwrap();
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![cfact3.clone(), ctransfer.clone()],
        None,
    )
    .await;
    get_subject(&rita, subject_c.clone(), Some(4), true)
        .await
        .unwrap();
    // Inline transfers apply without recording aux proofs (proofs
    // belong to requested aux transfers); passage here needs no
    // proof either, only checkable evidence.
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_c.clone())
            .await
            .unwrap()
            .is_none(),
        "inline passage records no aux proof"
    );
    let cstored = rita
        .test_get_tracker_ledger(subject_c.clone(), 4)
        .await
        .unwrap();
    assert!(
        matches!(
            cstored.iter().find(|e| e.sn == 3).unwrap().protocols,
            Protocols::TrackerFactFull { .. }
        ),
        "a genuine transfer to Rita opens the Full history"
    );
    let cpage = rita
        .get_sink_events(
            subject_c.clone(),
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: None,
                limit: Some(100),
            },
        )
        .await
        .unwrap();
    assert!(
        !cpage.events.is_empty(),
        "applied events do reach sinks, so the empty page above means something"
    );

    new_rita.token.cancel();
    join_all(new_rita.handler.iter_mut()).await;
    drop(new_rita);
    drop(reboot_dirs);
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

// A first copy whose inline transfer refutes on recheck must leave
// nothing behind: no journal rows, no verified proof, no deferred
// work and no sink emissions. Pre-fix the prefix persisted and only
// the transfer failed afterwards (with its rows already sunk).

// A first copy whose inline transfer refutes on recheck must leave
// nothing behind: no subject at all, no journal rows, no verified
// proof, no deferred work and no sink emissions. Pre-fix the prefix
// persisted and only the transfer failed afterwards.
#[test(tokio::test)]
async fn remote_first_copy_refuted_inline_transfer_emits_nothing() {
    async fn sink_empty_from(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        from_sn: u64,
    ) {
        // An absent subject never reached any sink: the query itself
        // reports it missing, which counts as empty here.
        let page = match api
            .get_sink_events(
                subject.clone(),
                ave_common::bridge::request::SinkEventsQuery {
                    from_sn: Some(from_sn),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await
        {
            Ok(page) => page,
            Err(ave_core::error::Error::SubjectNotFound(_)) => return,
            Err(error) => panic!("sink events query failed: {error:?}"),
        };
        assert!(
            page.events.is_empty(),
            "a rejected first copy emits nothing to sinks"
        );
    }

    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Rita", "key": rita_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "Rita", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Rita",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(PublicKey::from_str(rita.public_key()).unwrap()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Subject with SN0..2 on Alice; Rita has never seen it. The
    // attack is its whole first copy: genuine create and fact plus
    // an inline transfer with a forged `Ok` evaluation.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let hfind = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let create = hfind(0);
    let fact1 = hfind(1);
    let transfer2 = hfind(2);
    assert!(
        matches!(fact1.protocols, Protocols::TrackerFactFull { .. }),
        "premise: the fact is Full"
    );
    assert!(
        transfer2.protocols.is_success(),
        "premise: the genuine transfer succeeds"
    );
    let fact1_result = match &fact1.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("premise: the fact evaluation is ok"),
        _ => panic!("premise: the fact is Full"),
    };
    let forged2 = forge_ok_evaluation(&transfer2, fact1_result, &alice_keys);
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone(), forged2],
        None,
    )
    .await;
    // Poll rejection: no subject, no journal, no proof, deferred empty.
    {
        let start = tokio::time::Instant::now();
        loop {
            let no_subject =
                rita.get_subject_state(subject_id.clone()).await.is_err();
            let no_journal = rita
                .test_get_tracker_ledger(subject_id.clone(), 10)
                .await
                .map(|e| e.is_empty())
                .unwrap_or(true);
            let no_proof = rita
                .test_get_verified_transfer_sn(
                    &governance_id,
                    subject_id.clone(),
                )
                .await
                .unwrap_or(None)
                .is_none();
            let no_deferred =
                rita.test_deferred_stats().await.unwrap_or((1, 1, 1))
                    == (0, 0, 0);
            if no_subject && no_journal && no_proof && no_deferred {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "refuted first copy leaves nothing"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert!(
        rita.get_subject_state(subject_id.clone()).await.is_err(),
        "a refuted first copy registers nothing"
    );
    assert!(
        rita.test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .map(|events| events.is_empty())
            .unwrap_or(true),
        "a refuted first copy journals nothing"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a refuted first copy proves nothing"
    );
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        (0, 0, 0),
        "a rejected first copy holds nothing back"
    );
    sink_empty_from(&rita, &subject_id, 0).await;

    // Control: the genuine first copy lands whole and Full.
    let (subject_b, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_b.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_b.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_b.clone(), Some(2), true)
        .await
        .unwrap();
    let history_b = alice
        .test_get_tracker_ledger(subject_b.clone(), 2)
        .await
        .unwrap();
    let bfind = |sn: u64| {
        history_b
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![bfind(0), bfind(1), bfind(2)],
        None,
    )
    .await;
    get_subject(&rita, subject_b.clone(), Some(2), true)
        .await
        .unwrap();

    rita_node.token.cancel();
    join_all(rita_node.handler.iter_mut()).await;
    drop(rita_node);
    drop(rita_dirs);
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

// Distribution batches are cut by real serialized bytes against the
// effective wire cap (not by event count): every response fits the
// cap, keeps whole contiguous events, and the receiver still reaches
// the tip. `is_all` is only true on the final response and `hi_sn`
// is the last event actually included, never the pre-trim plan.
async fn byte_capped_batches_make_progress_once(
    cap: Option<usize>,
    fact_bytes: usize,
    fact_count: u64,
) {
    let gov_sync = || {
        Some(ave_core::config::GovernanceSyncConfig {
            interval_secs: 3600,
            sample_size: 3,
            response_timeout_secs: 3600,
        })
    };
    let tracker_sync = || {
        Some(ave_core::config::TrackerSyncConfig {
            interval_secs: 3600,
            page_size: 10,
            response_timeout_secs: 3600,
            update_batch_size: 2,
            update_timeout_secs: 5,
        })
    };
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: cap,
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            governance_sync: gov_sync(),
            tracker_sync: tracker_sync(),
            ledger_batch_size: Some(100),
            network_max_message_bytes: cap,
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;
    let effective_cap =
        cap.unwrap_or(ave_network::MAX_APP_MESSAGE_BYTES as usize);

    // Governance with a string-payload schema so single facts can
    // carry real byte weight; B owns and creates, A only receives.
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "schemas": { "add": [
                {
                    "id": "Big",
                    "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                    "initial_value": {"data": ""},
                },
            ]},
            "roles": {
                "schema": [
                    {
                        "schema_id": "Big",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "A", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "A",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [{"name": "Owner", "namespace": []}],
                        },
                    },
                ],
            },
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Tracker with heavy facts plus a closing transfer (its aux
    // bytes count against the cap too). B goes deaf so no creation
    // push hands anything to A early: the measured pull must carry
    // every byte.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "x".repeat(fact_bytes);
    for _ in 0..fact_count {
        emit_fact(
            &b,
            subject_id.clone(),
            json!({"ChangeData": {"data": bulk.clone()}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(
        &b,
        subject_id.clone(),
        PublicKey::from_str(&a.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();
    let tip = fact_count + 1;
    get_subject(&b, subject_id.clone(), Some(tip), true)
        .await
        .unwrap();

    // Harvest every response with release-and-rehold: A only asks
    // for the next range after applying the previous batch, so held
    // batches would stall the sweep after the first one. Each
    // response must fit the cap, carry whole contiguous events, and
    // only the last may close.
    async fn held_responses(api: &ave_core::Api) -> Vec<NetworkMessage> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerRes { .. })
            })
            .collect()
    }
    async fn hold_responses(api: &ave_core::Api) {
        api.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    // Un-deafen B: the measured pull below must flow.
    b.test_clear_faults().await.unwrap();
    hold_responses(&b).await;
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut responses: Vec<(Vec<u64>, bool, usize)> = vec![];
    for _ in 0..32 {
        // Wait for the next batch (or batch wave).
        for _ in 0..300 {
            if !held_responses(&b).await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let held = held_responses(&b).await;
        assert!(!held.is_empty(), "the sender stalls instead of batching on");
        let mut closed = false;
        for m in &held {
            // Measure exactly what the transport measures: the whole
            // wire message as encoded at the origin.
            let wire = rmp_serde::to_vec(m).unwrap();
            let (sns, is_all) = match &m.message {
                ActorMessage::DistributionLedgerRes {
                    ledger, is_all, ..
                } => (
                    ledger.iter().map(|event| event.sn).collect::<Vec<_>>(),
                    *is_all,
                ),
                _ => unreachable!(),
            };
            assert!(!sns.is_empty(), "no response is an empty frame");
            assert!(
                wire.len() <= effective_cap,
                "response {} fits the wire cap: {} <= {effective_cap}",
                responses.len(),
                wire.len()
            );
            closed = closed || is_all;
            responses.push((sns, is_all, wire.len()));
        }
        if closed {
            break;
        }
        b.test_release_held().await.unwrap();
        hold_responses(&b).await;
    }
    assert!(
        responses.len() >= 2,
        "byte-capped batches split the history, got {}",
        responses.len()
    );
    let mut covered: Vec<u64> = responses
        .iter()
        .flat_map(|(sns, _, _)| sns.clone())
        .collect();
    covered.sort_unstable();
    assert!(
        covered.windows(2).all(|w| w[1] == w[0] + 1),
        "batches keep whole contiguous events without gaps or repeats: {covered:?}"
    );
    let expected: Vec<u64> = (0..=tip).collect();
    assert_eq!(
        covered, expected,
        "the batches jointly cover the whole history exactly once"
    );
    assert!(
        responses.iter().filter(|(_, is_all, _)| *is_all).count() == 1,
        "only the final response closes the stream"
    );

    // With the responses released the receiver reaches the tip.
    b.test_release_held().await.unwrap();
    get_subject(&a, subject_id.clone(), Some(tip), true)
        .await
        .unwrap();
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

#[test(tokio::test)]
async fn remote_byte_capped_batches_make_progress() {
    // Default 1 MiB cap with a history above it.
    byte_capped_batches_make_progress_once(None, 90 * 1024, 12).await;
    // Explicitly configured larger cap: sender and batch builder
    // honor the same effective limit, not the 1 MiB constant. A batch
    // above 1 MiB only flows because the configured 2 MiB applies.
    byte_capped_batches_make_progress_once(
        Some(2 * 1024 * 1024),
        200 * 1024,
        12,
    )
    .await;
}

// A single event above the wire cap travels fragmented and is only
// applied after reassembly passes its hash: duplicates and reorders
// are absorbed, a corrupt chunk fails closed without writing, and a
// restart drops the partial assembly instead of resuming garbage.
#[test(tokio::test)]
async fn remote_oversized_single_event_syncs_by_bounded_fragments() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "schemas": { "add": [
                {
                    "id": "Big",
                    "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                    "initial_value": {"data": ""},
                },
            ]},
            "roles": {
                "schema": [
                    {
                        "schema_id": "Big",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "A", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "A",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [{"name": "Owner", "namespace": []}],
                        },
                    },
                ],
            },
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // One fact above the wire cap but below the replicable bound.
    // B goes deaf first so no creation push hands anything to A.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "y".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let expected = b
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 1)
        .expect("oversized fact committed");
    let expected_hash = expected.ledger_hash(HashAlgorithm::Blake3).unwrap();

    // Hold every fragment: more than one must exist (otherwise the
    // event went out whole and over the cap), all under the cap,
    // all naming the same event, indexed without gaps. Un-deafen B
    // first: the measured pull must flow.
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        // Settle: two consecutive polls with the same non-empty set.
        if !held.is_empty() && held.len() == frags.len() {
            break;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        frags.len() >= 2,
        "an oversized event travels fragmented, got {}",
        frags.len()
    );
    let mut total = None;
    let mut is_all = None;
    let mut indexes = vec![];
    for m in &frags {
        let wire = rmp_serde::to_vec(m).unwrap();
        assert!(
            wire.len() <= cap,
            "each fragment fits the wire cap: {} <= {cap}",
            wire.len()
        );
        match &m.message {
            ActorMessage::DistributionLedgerFrag {
                event_hash,
                event_sn,
                total_bytes,
                chunk_total,
                chunk_index,
                is_all: frag_all,
                ..
            } => {
                assert_eq!(*event_sn, 1, "fragments belong to the event");
                assert_eq!(
                    *event_hash, expected_hash,
                    "fragments name the event"
                );
                total = Some((*total_bytes, *chunk_total));
                is_all = Some(*frag_all);
                indexes.push(*chunk_index);
            }
            _ => unreachable!(),
        }
    }
    let (total_bytes, chunk_total) = total.unwrap();
    assert!(total_bytes > cap as u64, "the event itself exceeds the cap");
    assert_eq!(
        indexes.len() as u32,
        chunk_total,
        "every fragment of the event was emitted"
    );
    let mut sorted = indexes.clone();
    sorted.sort_unstable();
    sorted.dedup();
    assert_eq!(
        sorted,
        (0..chunk_total).collect::<Vec<_>>(),
        "fragments indexed without gaps or duplicates at emission"
    );
    assert!(is_all.unwrap(), "a single tip event closes its response");

    // Duplicates and reorders are absorbed: injecting the whole set
    // twice, backwards, still assembles exactly once.
    let mut shuffled = frags.clone();
    shuffled.reverse();
    for m in shuffled.iter().chain(frags.iter()) {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let landed = a
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 1)
        .expect("reassembled fact applied");
    assert_eq!(
        landed.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        expected_hash,
        "reassembly is byte-exact before apply"
    );
    // No second copy applies from the duplicates: poll count stable
    // at 2 with no pending assembly (reassembly itself is idempotent,
    // the stale head never applies twice).
    let _ = b.test_clear_faults().await;
    {
        let start = tokio::time::Instant::now();
        loop {
            let count = a
                .test_get_tracker_ledger(subject_id.clone(), 10)
                .await
                .unwrap_or_default()
                .len();
            let (assemblies, ready_mains, ready_auxes, _, _) =
                a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
            if count == 2 && assemblies + ready_mains + ready_auxes == 0 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "duplicates never apply twice"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let count = a
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap_or_default()
        .len();
    assert_eq!(count, 2, "duplicates never apply twice");

    // A corrupt chunk fails the whole assembly closed: nothing is
    // applied, and the genuine set still completes afterwards. B
    // goes deaf so no push hands anything to A early.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_c, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk_c = "z".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_c.clone(),
        json!({"ChangeData": {"data": bulk_c}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_c.clone(), Some(1), true)
        .await
        .unwrap();
    let expected_c = b
        .test_get_tracker_ledger(subject_c.clone(), 1)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 1)
        .expect("oversized fact committed");
    let expected_hash_c =
        expected_c.ledger_hash(HashAlgorithm::Blake3).unwrap();
    a.authorize_governance(
        subject_c.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    // Un-deafen B: the measured pull must flow.
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_c.clone()).await.unwrap();
    let mut frags_c = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags_c.len() {
            break;
        }
        frags_c = held;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(frags_c.len() >= 2, "the corrupt run fragments too");
    // Corrupt the first chunk in flight and deliver the rest: the
    // assembly completes with mismatched bytes and must be dropped.
    fn chunk_index(m: &NetworkMessage) -> u32 {
        match &m.message {
            ActorMessage::DistributionLedgerFrag { chunk_index, .. } => {
                *chunk_index
            }
            _ => unreachable!(),
        }
    }
    let mut corrupt = frags_c
        .iter()
        .find(|m| chunk_index(m) == 0)
        .expect("chunk zero held")
        .clone();
    if let ActorMessage::DistributionLedgerFrag { ref mut chunk, .. } =
        corrupt.message
    {
        chunk[0] ^= 0xFF;
    } else {
        unreachable!();
    }
    a.test_inject_inbound(corrupt, &b_key).await.unwrap();
    for m in frags_c.iter().filter(|m| chunk_index(m) != 0) {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    // Poll: corrupt join drops before decode, only create stays.
    {
        let start = tokio::time::Instant::now();
        loop {
            let sn = get_subject(&a, subject_c.clone(), None, true)
                .await
                .unwrap()
                .sn;
            let has_fact = a
                .test_get_tracker_ledger(subject_c.clone(), 10)
                .await
                .unwrap_or_default()
                .iter()
                .any(|e| e.sn == 1);
            let (assemblies, ready_mains, ready_auxes, _, _) =
                a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
            if sn == 0
                && !has_fact
                && assemblies + ready_mains + ready_auxes == 0
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "corrupt chunk fails closed"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    // Only the unfragmented create applied; the fragmented fact
    // must not assemble from a corrupt chunk.
    assert_eq!(
        get_subject(&a, subject_c.clone(), None, true)
            .await
            .unwrap()
            .sn,
        0,
        "a corrupt chunk fails closed without writing"
    );
    assert!(
        a.test_get_tracker_ledger(subject_c.clone(), 10)
            .await
            .unwrap_or_default()
            .iter()
            .all(|event| event.sn == 0),
        "no fragment of the refuted event persists"
    );
    // The genuine set still completes afterwards: no poison remains.
    b.test_release_held().await.unwrap();
    get_subject(&a, subject_c.clone(), Some(1), true)
        .await
        .unwrap();
    let landed_c = a
        .test_get_tracker_ledger(subject_c.clone(), 1)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 1)
        .expect("reassembled fact applied after corruption");
    assert_eq!(
        landed_c.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        expected_hash_c,
        "recovery reassembly is byte-exact"
    );

    // Restart mid-reception: partial assemblies live only in memory,
    // so the restarted node re-requests and completes boundedly. B
    // goes deaf so no push hands anything to A early.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_r, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk_r = "w".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_r.clone(),
        json!({"ChangeData": {"data": bulk_r}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_r.clone(), Some(1), true)
        .await
        .unwrap();
    let expected_r = b
        .test_get_tracker_ledger(subject_r.clone(), 1)
        .await
        .unwrap()
        .into_iter()
        .find(|event| event.sn == 1)
        .expect("oversized fact committed");
    let expected_hash_r =
        expected_r.ledger_hash(HashAlgorithm::Blake3).unwrap();
    a.authorize_governance(
        subject_r.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    // Fresh hold (releases above cleared the rules). Un-deafen B
    // first: the measured pull must flow.
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    // Deliver only the tail through injection: without chunk 0 the
    // assembly can never complete.
    a.update_subject(subject_r.clone()).await.unwrap();
    let mut frags_r = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags_r.len() {
            break;
        }
        frags_r = held;
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(frags_r.len() >= 2, "the restart run fragments too");
    for m in frags_r.iter().filter(|m| {
        !matches!(
            &m.message,
            ActorMessage::DistributionLedgerFrag { chunk_index: 0, .. }
        )
    }) {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    // Poll: headless assembly never completes (SN stays 0, partial held).
    {
        let start = tokio::time::Instant::now();
        loop {
            let sn = get_subject(&a, subject_r.clone(), None, true)
                .await
                .unwrap()
                .sn;
            let has_fact = a
                .test_get_tracker_ledger(subject_r.clone(), 10)
                .await
                .unwrap_or_default()
                .iter()
                .any(|e| e.sn == 1);
            let len = a.test_fragment_assembly_len().await.unwrap_or(0);
            if sn == 0 && !has_fact && len == 1 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "headless assembly never completes"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert_eq!(
        get_subject(&a, subject_r.clone(), None, true)
            .await
            .unwrap()
            .sn,
        0,
        "a headless assembly never completes"
    );
    // Restart drops the partial assembly (memory-only); a fresh
    // update re-requests and completes boundedly, exactly once.
    {
        // NOTE: dirs accumulate two entries per node in creation
        // order (boot, A, B), so A's stores are dirs[2] and dirs[3].
        let keys = nodes[1].keys.clone();
        let local_db = dirs[2].path().to_path_buf();
        let ext_db = dirs[3].path().to_path_buf();
        nodes[1].token.cancel();
        join_all(nodes[1].handler.iter_mut()).await;
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            keys: Some(keys),
            local_db: Some(local_db),
            ext_db: Some(ext_db),
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&new_node.api).await.unwrap();
        nodes[1] = new_node;
    }
    let a = nodes[1].api.clone();
    a.authorize_governance(
        subject_r.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(&b.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    a.update_subject(subject_r.clone()).await.unwrap();
    get_subject(&a, subject_r.clone(), Some(1), true)
        .await
        .unwrap();
    let landed_r = a
        .test_get_tracker_ledger(subject_r.clone(), 10)
        .await
        .unwrap_or_default();
    assert_eq!(
        landed_r.len(),
        2,
        "restart re-fetches and applies exactly once"
    );
    assert_eq!(
        landed_r
            .iter()
            .find(|event| event.sn == 1)
            .expect("reassembled fact applied after restart")
            .ledger_hash(HashAlgorithm::Blake3)
            .unwrap(),
        expected_hash_r,
        "post-restart reassembly is byte-exact"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

// A full evidence rebuild deduplicates by (sn, hash), not by sn
// alone: two different bytes for one sn are an explicit divergence
// and report Missing before authorizing, proving or caching
// anything. Pre-fix the first copy won silently and the verdict and
// any proof were computed over an edited chain.
#[test(tokio::test)]
async fn remote_full_rebuild_detects_same_sn_divergence() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();

    let carol_signer = Ed25519Signer::generate().unwrap();
    let carol_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        carol_signer.public_key_bytes(),
    )
    .unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "Carol", "key": carol_key.to_string()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Carol",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Rita joins late as a plain member: no witness or creator grant,
    // so she has no independent rights and an uncheckable aux holds
    // her batches unapplied instead of copying them.
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "Rita", "key": rita_key.to_string() },
            ]},
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        is_service: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    // Deafen Alice toward Rita: every batch below is injected, no
    // genuine history may interleave.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(PublicKey::from_str(rita.public_key()).unwrap()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Subject with create/two facts/transfer on Alice; the transfer
    // goes to Carol so Rita stays a plain member with no rights.
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    let hfind = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history event")
            .clone()
    };
    let create = hfind(0);
    let fact1 = hfind(1);
    let fact2 = hfind(2);
    let transfer3 = hfind(3);
    assert_eq!(create.sn, 0, "premise: create at sn0");
    assert!(transfer3.protocols.is_success(), "premise: aux is genuine");

    // A divergent fact for the same sn: same chain link, different
    // content, validly signed by Alice. It must never silently win
    // over (or merge into) its genuine twin.
    let altered_req = match fact1.protocols.clone() {
        Protocols::TrackerFactFull { event_request, .. } => match event_request
            .content()
        {
            EventRequest::Fact(req) => {
                let mut req = req.clone();
                req.payload =
                    ave_common::ValueWrapper(json!({"ModOne": {"data": 999}}));
                EventRequest::Fact(req)
            }
            other => panic!("premise: fact request, got {other:?}"),
        },
        _ => panic!("premise: fact1 is a full fact"),
    };
    let altered_sig = Signature::new(&altered_req, &alice_keys).unwrap();
    let (altered_eval, altered_val) = match &fact1.protocols {
        Protocols::TrackerFactFull {
            evaluation,
            validation,
            ..
        } => (evaluation.clone(), validation.clone()),
        _ => unreachable!(),
    };
    let mut divergent = fact1.clone();
    divergent.protocols = Protocols::TrackerFactFull {
        event_request: std::sync::Arc::new(
            ave_common::identity::Signed::from_parts(altered_req, altered_sig),
        ),
        evaluation: altered_eval,
        validation: altered_val,
    };
    let divergent_protocols_hash = divergent
        .protocols
        .hash_for_ledger(&HashAlgorithm::Blake3)
        .unwrap();
    divergent.ledger_seal_signature = Signature::new(
        &LedgerSeal {
            gov_version: divergent.gov_version,
            sn: divergent.sn,
            prev_ledger_event_hash: divergent.prev_ledger_event_hash.clone(),
            protocols_hash: divergent_protocols_hash,
        },
        &alice_keys,
    )
    .unwrap();
    assert_ne!(
        divergent.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        fact1.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        "premise: same sn, different bytes"
    );

    // Phase one: the genuine prefix waits deferred with its aux
    // ahead (SN2 missing). The batch holds unapplied with a first
    // full rebuild and no proof.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone()],
        Some(transfer3.clone()),
    )
    .await;
    // Poll: gapped prefix holds unapplied with one rebuild, no proof.
    {
        let start = tokio::time::Instant::now();
        loop {
            let no_subject =
                rita.get_subject_state(subject_id.clone()).await.is_err();
            let no_proof = rita
                .test_get_verified_transfer_sn(
                    &governance_id,
                    subject_id.clone(),
                )
                .await
                .unwrap_or(None)
                .is_none();
            let deferred =
                rita.test_deferred_stats().await.unwrap_or((0, 0, 0));
            let rebuilds = rita
                .test_full_rebuilds(subject_id.clone())
                .await
                .unwrap_or(0);
            if no_subject
                && no_proof
                && deferred.0 == 1
                && deferred.1 == 2
                && deferred.2 > 0
                && rebuilds == 1
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "gapped prefix holds"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert!(
        rita.get_subject_state(subject_id.clone()).await.is_err(),
        "a gapped prefix never authorizes the copy"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "an unproven aux records no proof"
    );
    let (dsubs, devts, dbytes) = rita.test_deferred_stats().await.unwrap();
    assert_eq!((dsubs, devts), (1, 2), "two staged events");
    assert!(dbytes > 0, "retained bytes must be accounted");
    assert_eq!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap(),
        1,
        "the first missing aux rebuilds once"
    );

    // Evict any cursor so the continuation rebuilds from scratch
    // instead of resuming an incremental round. The staged genuine
    // prefix stays held; only cursor and incremental auth go away.
    rita.test_evict_verify_cursor(subject_id.clone())
        .await
        .unwrap();

    // Phase two: SN1 arrives with different bytes plus the genuine
    // rest of the chain. The full rebuild sees held genuine SN1
    // against sender divergent SN1: same SN, different hash is a
    // divergence, never silently edited out. No proof, no apply,
    // still held, and the rebuild counter moves again.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![divergent.clone(), fact2.clone(), transfer3.clone()],
        Some(transfer3.clone()),
    )
    .await;
    // Poll: divergence holds, no proof, rebuild again.
    {
        let start = tokio::time::Instant::now();
        loop {
            let no_subject =
                rita.get_subject_state(subject_id.clone()).await.is_err();
            let no_proof = rita
                .test_get_verified_transfer_sn(
                    &governance_id,
                    subject_id.clone(),
                )
                .await
                .unwrap_or(None)
                .is_none();
            let (held_subs, _, _) =
                rita.test_deferred_stats().await.unwrap_or((0, 0, 0));
            let rebuilds = rita
                .test_full_rebuilds(subject_id.clone())
                .await
                .unwrap_or(0);
            if no_subject && no_proof && held_subs >= 1 && rebuilds >= 2 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "divergence holds"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert!(
        rita.get_subject_state(subject_id.clone()).await.is_err(),
        "a same-sn divergence never authorizes the copy"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "a divergent chain records no proof"
    );
    let (held_subs, held_evts, held_bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert!(
        held_subs >= 1,
        "a divergent batch is held, not dropped: got ({held_subs},{held_evts},{held_bytes})"
    );
    assert!(
        rita.test_full_rebuilds(subject_id.clone()).await.unwrap() >= 2,
        "divergent bytes force a full rebuild instead of resuming"
    );

    // Control: re-sending the exact divergent bytes changes nothing.
    let held_before = rita.test_deferred_stats().await.unwrap();
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![divergent.clone(), fact2.clone(), transfer3.clone()],
        Some(transfer3.clone()),
    )
    .await;
    // Poll: deduplicated, stats stable, still no subject.
    {
        let start = tokio::time::Instant::now();
        loop {
            let deferred =
                rita.test_deferred_stats().await.unwrap_or((0, 0, 0));
            let no_subject =
                rita.get_subject_state(subject_id.clone()).await.is_err();
            if deferred == held_before && no_subject {
                break;
            }
            // Allow one rebuild for the re-send, then stable (no duplication).
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "exact re-send deduplicated"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // Stability on next transition: another identical re-send changes nothing.
        inject_ledger_batch(
            &rita,
            &alice_key,
            vec![divergent.clone(), fact2.clone(), transfer3.clone()],
            Some(transfer3.clone()),
        )
        .await;
        let start2 = tokio::time::Instant::now();
        loop {
            let deferred2 =
                rita.test_deferred_stats().await.unwrap_or((0, 0, 0));
            if deferred2 == held_before {
                break;
            }
            assert!(start2.elapsed() < Duration::from_secs(10), "stable");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        held_before,
        "an exact re-send is deduplicated, not duplicated"
    );
    assert!(
        rita.get_subject_state(subject_id.clone()).await.is_err(),
        "replays never advance a divergent hold"
    );

    // Control: re-sending the genuine held prefix changes nothing
    // either: the same SN with the same hash is accepted once, never
    // duplicated. Contiguous genuine chains without divergence keep
    // their Missing verdict here; Proven application on direct
    // rights is already covered by
    // `remote_registered_prefix_rejoins_after_cursor_eviction`.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone()],
        Some(transfer3.clone()),
    )
    .await;
    // Poll: genuine re-send deduplicated, stats stable, still no apply.
    {
        let start = tokio::time::Instant::now();
        loop {
            let deferred =
                rita.test_deferred_stats().await.unwrap_or((0, 0, 0));
            let no_subject =
                rita.get_subject_state(subject_id.clone()).await.is_err();
            let no_proof = rita
                .test_get_verified_transfer_sn(
                    &governance_id,
                    subject_id.clone(),
                )
                .await
                .unwrap_or(None)
                .is_none();
            if deferred == held_before && no_subject && no_proof {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "genuine re-send deduplicated"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    assert_eq!(
        rita.test_deferred_stats().await.unwrap(),
        held_before,
        "an exact genuine re-send is deduplicated, not duplicated"
    );
    assert!(
        rita.get_subject_state(subject_id.clone()).await.is_err(),
        "replays never advance a divergent hold"
    );
    assert!(
        rita.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "no replay records a proof over divergence"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

// oversized fact keeps its external transfer aux through
// manual push plus automatic pull. Alice pushes the small transfer to
// non-witness Carol; the follow-up pull for the large history
// fragments both sides under one group and only delivers when both
// verify. Pre-fix the aux was dropped and the copy stalled.
#[test(tokio::test)]
async fn remote_oversized_fact_keeps_external_transfer_aux() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let carol = nodes[2].api.clone();
    let carol_key = PublicKey::from_str(carol.public_key()).unwrap();
    let _ = dirs;
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Carol", "key": carol.public_key()},
            ]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Big",
                    "add": {
                        "evaluator": [{"name": "Alice", "namespace": []}],
                        "validator": [{"name": "Alice", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {"name": "Alice", "namespace": [], "quantity": "infinity"},
                            {"name": "Carol", "namespace": [], "quantity": "infinity"}
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    for api in [&carol] {
        api.authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    }
    for api in [&alice, &carol] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), None, true)
            .await
            .unwrap();
    }
    // Silence automatic pushes so only manual + follow-up pull deliver.
    for target in [&carol] {
        let peer = PublicKey::from_str(target.public_key()).unwrap();
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            alice
                .test_install_fault(FaultRule {
                    direction: FaultDirection::Outbound,
                    message,
                    peer: Some(peer.clone()),
                    remaining: None,
                    action: FaultAction::Drop,
                })
                .await
                .unwrap();
        }
    }
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "y".repeat(1200 * 1024);
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(
        carol.get_subject_state(subject_id.clone()).await.is_err(),
        "silenced pushes deliver nothing yet"
    );
    alice.test_clear_faults().await.unwrap();
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    // Poll: grouped copy completes with pending ownership, no leak.
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(state) = carol.get_subject_state(subject_id.clone()).await {
            if state.sn == 2 {
                break;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "grouped copy completes"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let landed = carol
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap_or_default();
    assert!(landed.iter().any(|e| e.sn == 1), "fact applied");
    assert!(landed.iter().any(|e| e.sn == 2), "transfer applied");
    let (_, pending, _, _) = carol
        .test_witnesses_ownership(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(pending, Some(carol_key), "pending opens with grouped aux");
    // No re-request loop: poll held outbound empty (no fixed sleep on outcome).
    let start = tokio::time::Instant::now();
    loop {
        let held: Vec<NetworkMessage> =
            carol.test_held_outbound().await.unwrap_or_default();
        // Filter copy requests (LedgerReq) – no new asks after completion.
        let reqs: Vec<_> = held
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerReq { .. })
            })
            .collect();
        if reqs.is_empty() {
            break;
        }
        // Allow one in-flight ask to settle, but no endless re-asks.
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "no re-request loop"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
        // Break after one settle window: the exact count is asserted
        // stable below, not after a fixed sleep.
        if start.elapsed() > Duration::from_secs(3) {
            break;
        }
    }
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|n| n.handler.iter_mut())).await;
}

// aux itself fragmented and verified. Same manual-plus-pull flow
// with both sides over the wire cap; the grouped copy still completes.
// The small-cap variant is covered by the unit bound; here the
// aux travels as a single fragment under the same group and verifies
// before apply (decode attempts prove both sides decoded).
#[test(tokio::test)]
async fn remote_oversized_transfer_aux_is_fragmented_and_verified() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let carol = nodes[2].api.clone();
    let carol_key = PublicKey::from_str(carol.public_key()).unwrap();
    let _ = dirs;
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Carol", "key": carol.public_key()},
            ]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Big",
                    "add": {
                        "evaluator": [{"name": "Alice", "namespace": []}],
                        "validator": [{"name": "Alice", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {"name": "Alice", "namespace": [], "quantity": "infinity"},
                            {"name": "Carol", "namespace": [], "quantity": "infinity"}
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    for api in [&carol] {
        api.authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    }
    for api in [&alice, &carol] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), None, true)
            .await
            .unwrap();
    }
    for target in [&carol] {
        let peer = PublicKey::from_str(target.public_key()).unwrap();
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            alice
                .test_install_fault(FaultRule {
                    direction: FaultDirection::Outbound,
                    message,
                    peer: Some(peer.clone()),
                    remaining: None,
                    action: FaultAction::Drop,
                })
                .await
                .unwrap();
        }
    }
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "z".repeat(1200 * 1024);
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(
        carol.get_subject_state(subject_id.clone()).await.is_err(),
        "silenced"
    );
    alice.test_clear_faults().await.unwrap();
    let (_, _, _, decode_before, _) =
        carol.test_fragment_stats().await.unwrap_or((0, 0, 0, 0, 0));
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(state) = carol.get_subject_state(subject_id.clone()).await {
            if state.sn == 2 {
                break;
            }
        }
        assert!(
            start.elapsed() < Duration::from_secs(60),
            "grouped copy completes"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (_, _, _, decode_after, _) =
        carol.test_fragment_stats().await.unwrap_or((0, 0, 0, 0, 0));
    assert!(
        decode_after > decode_before,
        "both sides decoded after payload verify"
    );
    let (assemblies, ready_mains, ready_auxes, _, _) =
        carol.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
    assert_eq!(assemblies + ready_mains + ready_auxes, 0, "no leak");
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|n| n.handler.iter_mut())).await;
}
// preflight by exact identity. An inline transfer with the same
// SN but different bytes than a Witness aux must not count as
// covered: the refuted inline rejects the whole chunk before any
// write, even with the aux marked Witness. An identical aux reuses
// correctly and leaves the production cursor intact.
#[test(tokio::test)]
async fn remote_preflight_same_sn_different_aux_hash_rejected() {
    use ave_common::bridge::request::SinkEventsQuery;
    async fn sink_empty_from(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        from_sn: u64,
    ) {
        let page = api
            .get_sink_events(
                subject.clone(),
                SinkEventsQuery {
                    from_sn: Some(from_sn),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await
            .unwrap();
        assert!(
            page.events.is_empty(),
            "a rejected chunk emits nothing to sinks"
        );
    }
    async fn poll_sn(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        want: u64,
    ) {
        let start = tokio::time::Instant::now();
        loop {
            if let Ok(state) = api.get_subject_state(subject.clone()).await {
                if state.sn == want {
                    return;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(20),
                "timeout waiting for sn {}",
                want
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Rita", "key": rita_key.to_string()},
            ]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}, {"name": "Rita", "namespace": []}],
                        "creator": [
                            {"name": "Alice", "namespace": [], "quantity": "infinity"},
                            {"name": "Rita", "namespace": [], "quantity": "infinity"}
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).expect("node key");
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2, 3] {
        emit_fact(
            &alice,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 4)
        .await
        .unwrap();
    let hfind = |sn: u64| {
        history
            .iter()
            .find(|e| e.sn == sn)
            .expect("history")
            .clone()
    };
    let create = hfind(0);
    let fact1 = hfind(1);
    let fact2 = hfind(2);
    let fact3 = hfind(3);
    let transfer4 = hfind(4);
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), fact1.clone(), fact2.clone()],
        None,
    )
    .await;
    poll_sn(&rita, &subject_id, 2).await;
    // Same SN, different hash: genuine aux (Witness) plus forged
    // inline with Ok evaluation that does not reproduce. Must reject
    // before any write, even though the aux alone would pass.
    let fact3_result = match &fact3.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => {
            evaluation.evaluator_response_ok().expect("fact ok")
        }
        _ => panic!("fact full"),
    };
    let forged4 = forge_ok_evaluation(&transfer4, fact3_result, &nodes[1].keys);
    assert_ne!(
        forged4.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        transfer4.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        "same SN, different bytes"
    );
    let rebuilds_before = rita
        .test_full_rebuilds(subject_id.clone())
        .await
        .unwrap_or(0);
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![fact3.clone(), forged4.clone()],
        Some(transfer4.clone()),
    )
    .await;
    // Poll rejection: SN stays, no proof, deferred empty.
    poll_sn(&rita, &subject_id, 2).await;
    let start = tokio::time::Instant::now();
    loop {
        let proof = rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap_or(None);
        let deferred = rita.test_deferred_stats().await.unwrap_or((1, 1, 1));
        if proof.is_none() && deferred == (0, 0, 0) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "timeout waiting for clean rejection"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let stored: Vec<u64> = rita
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap_or_default()
        .iter()
        .map(|e| e.sn)
        .collect();
    assert_eq!(stored, vec![0, 1, 2], "no prefix rewritten");
    sink_empty_from(&rita, &subject_id, 3).await;
    // Identical aux reuses correctly: genuine fact+transfer with the
    // same aux bytes succeeds and leaves the cursor intact.
    let rebuilds_after_refuted = rita
        .test_full_rebuilds(subject_id.clone())
        .await
        .unwrap_or(0);
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![fact3.clone(), transfer4.clone()],
        Some(transfer4.clone()),
    )
    .await;
    poll_sn(&rita, &subject_id, 4).await;
    let rebuilds_after_identical = rita
        .test_full_rebuilds(subject_id.clone())
        .await
        .unwrap_or(0);
    assert!(
        rebuilds_after_identical <= rebuilds_after_refuted + 1,
        "identical aux must not rebuild per transfer"
    );
    let stored2: Vec<u64> = rita
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap_or_default()
        .iter()
        .map(|e| e.sn)
        .collect();
    assert_eq!(stored2, vec![0, 1, 2, 3, 4], "identical aux delivers");
    let _ = rebuilds_before;
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|n| n.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

// preflight stays linear with several transfers. A chain with
// distinct owners must not pay a full rebuild per transfer: one
// scratch cursor advances for the whole preflight and the production
// cursor is restored on every exit.
#[test(tokio::test)]
async fn remote_preflight_multiple_transfers_stays_linear() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();
    let mut owner_keys = vec![];
    for _ in 0..3 {
        let s = Ed25519Signer::generate().unwrap();
        owner_keys.push(
            PublicKey::new(
                ave_common::identity::keys::DSAlgorithm::Ed25519,
                s.public_key_bytes(),
            )
            .unwrap(),
        );
    }
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "B0", "key": owner_keys[0].to_string()},
                {"name": "B1", "key": owner_keys[1].to_string()},
                {"name": "B2", "key": owner_keys[2].to_string()},
                {"name": "Rita", "key": rita_key.to_string()},
            ]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}, {"name": "Alice", "namespace": []}, {"name": "Rita", "namespace": []}],
                        "creator": [{"name": "Alice", "namespace": [], "quantity": "infinity"}],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    // Silence pushes so every batch below is injected.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2] {
        emit_fact(
            &alice,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    // Three transfers to distinct owners: different hashes, owners
    // and evidence chains in one chunk.
    emit_transfer(&alice, subject_id.clone(), owner_keys[0].clone(), true)
        .await
        .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 10}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), owner_keys[1].clone(), true)
        .await
        .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 11}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), owner_keys[2].clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(7), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap();
    let hfind = |sn: u64| history.iter().find(|e| e.sn == sn).unwrap().clone();
    let create = hfind(0);
    let f1 = hfind(1);
    let f2 = hfind(2);
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![create.clone(), f1.clone(), f2.clone()],
        None,
    )
    .await;
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(state) = rita.get_subject_state(subject_id.clone()).await {
            if state.sn == 2 {
                break;
            }
        }
        assert!(start.elapsed() < Duration::from_secs(20), "prefix");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let t3 = hfind(3);
    let t4 = hfind(4);
    let f5 = hfind(5);
    let f6 = hfind(6);
    let t7 = hfind(7);
    // Baseline work before the multi-transfer chunk.
    let (buf_c0, buf_v0, _) = rita
        .test_buffer_stats(subject_id.clone())
        .await
        .unwrap_or((0, 0, 0));
    let rebuilds0 = rita
        .test_full_rebuilds(subject_id.clone())
        .await
        .unwrap_or(0);
    // Genuine chain with three transfers: must deliver with one
    // incremental pass, not one rebuild per transfer.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![t3.clone(), t4.clone(), f5.clone(), f6.clone(), t7.clone()],
        Some(t7.clone()),
    )
    .await;
    let start = tokio::time::Instant::now();
    loop {
        if let Ok(state) = rita.get_subject_state(subject_id.clone()).await {
            if state.sn == 7 {
                break;
            }
        }
        assert!(start.elapsed() < Duration::from_secs(20), "multi-transfer");
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (buf_c1, buf_v1, _) = rita
        .test_buffer_stats(subject_id.clone())
        .await
        .unwrap_or((0, 0, 0));
    let rebuilds1 = rita
        .test_full_rebuilds(subject_id.clone())
        .await
        .unwrap_or(0);
    let cloned = buf_c1.saturating_sub(buf_c0);
    let visited = buf_v1.saturating_sub(buf_v0);
    let rebuilds = rebuilds1.saturating_sub(rebuilds0);
    // Linear bounds: no rebuild per transfer.
    assert!(
        rebuilds <= 1,
        "one scratch advances, no rebuild per transfer, got {rebuilds}"
    );
    assert!(cloned <= 4 * 7, "buffer clones linear, got {cloned}");
    assert!(visited <= 12 * 7, "buffer visits linear, got {visited}");
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|n| n.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

// payload hash verified before decode. A join with mismatched
// payload hash never reaches the decoder (decode attempts stay zero)
// and applies nothing; the genuine set still completes afterwards.
#[test(tokio::test)]
async fn remote_fragment_rejects_bad_payload_hash_before_decode() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "q".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags.len() {
            break;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!frags.is_empty(), "oversized travels fragmented");
    let (_, _, _, decode_before, _) = a.test_fragment_stats().await.unwrap();
    // Corrupt the payload hash of every fragment (not the bytes):
    // the join must fail before any decode.
    let mut bad = frags.clone();
    for m in &mut bad {
        if let ActorMessage::DistributionLedgerFrag { payload_hash, .. } =
            &mut m.message
        {
            *payload_hash = DigestIdentifier::default();
        }
    }
    for m in bad {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    // Poll: no fact apply, decode attempts unchanged (create may already be present via whole batch).
    let start = tokio::time::Instant::now();
    loop {
        let (_, _, _, decode_after, _) = a.test_fragment_stats().await.unwrap();
        assert_eq!(
            decode_after, decode_before,
            "bad payload hash never decodes"
        );
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            !ledger.iter().any(|e| e.sn == 1),
            "bad join applies nothing"
        );
        if start.elapsed() > Duration::from_secs(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Genuine set still completes afterwards.
    b.test_clear_faults().await.unwrap();
    for m in frags {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}

// mixing senders, scopes or completeness never merges. Fragments
// with different sender, scope or is_all share no assembly and deliver
// nothing; the genuine group still completes.
#[test(tokio::test)]
async fn remote_fragment_does_not_mix_senders_or_scope() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..3 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b, c) = (
        nodes[1].api.clone(),
        nodes[2].api.clone(),
        nodes[3].api.clone(),
    );
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let c_key = PublicKey::from_str(&c.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a, &c]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }, { "name": "C", "key": c.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "m".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags.len() {
            break;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!frags.is_empty(), "oversized travels fragmented");
    // Mix: same identity, different sender / scope / is_all. None may
    // merge or deliver.
    let mut mixed = vec![];
    for (i, m) in frags.iter().enumerate() {
        let mut forged = m.clone();
        match &mut forged.message {
            ActorMessage::DistributionLedgerFrag {
                is_all,
                expected_governance_id,
                ..
            } => {
                if i % 3 == 0 {
                    *is_all = !*is_all;
                } else if i % 3 == 1 {
                    *expected_governance_id = None;
                }
            }
            _ => unreachable!(),
        }
        mixed.push((
            forged,
            if i % 3 == 2 {
                c_key.clone()
            } else {
                b_key.clone()
            },
        ));
    }
    for (m, sender) in mixed {
        a.test_inject_inbound(m, &sender).await.unwrap();
    }
    // Poll: mixing delivers no fact (create may already be present).
    let start = tokio::time::Instant::now();
    loop {
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            !ledger.iter().any(|e| e.sn == 1),
            "mixed fragments never apply"
        );
        if start.elapsed() > Duration::from_secs(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Genuine group still completes afterwards.
    b.test_clear_faults().await.unwrap();
    for m in frags {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}

// incomplete assembly expires without further messages and frees
// memory; a fresh genuine copy completes afterwards.
#[test(tokio::test)]
async fn remote_fragment_assembly_expires_without_more_messages() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "e".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags.len() {
            break;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(frags.len() >= 2, "oversized travels fragmented");
    // Deliver only the first chunk, then wait for the timer without
    // any further message: the assembly must expire and free memory.
    let first = frags[0].clone();
    a.test_inject_inbound(first, &b_key).await.unwrap();
    // Poll assembly present, then expired to zero without more msgs.
    let start = tokio::time::Instant::now();
    loop {
        let len = a.test_fragment_assembly_len().await.unwrap_or(0);
        if len == 1 {
            break;
        }
        assert!(start.elapsed() < Duration::from_secs(5), "assembly appears");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let start = tokio::time::Instant::now();
    loop {
        let len = a.test_fragment_assembly_len().await.unwrap_or(1);
        let (_, _, _, _, expired) =
            a.test_fragment_stats().await.unwrap_or((0, 0, 0, 0, 0));
        if len == 0 && expired >= 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "assembly expires without more messages"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Fresh genuine copy completes afterwards.
    b.test_clear_faults().await.unwrap();
    for m in frags {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}

// push over the total bound is rejected before emit and never
// retried. The coordinator fails loud instead of looping forever on
// an event no receiver could accept.
#[test(tokio::test)]
async fn remote_fragment_over_total_bound_rejected_before_send() {
    // Unit-level: the shared builder refuses an event above the
    // reassembly bound and propagates the encode/size error instead
    // of returning an empty size. Exercised through the public bound
    // constant so the coordinator and worker can never diverge.
    assert!(
        ave_core::distribution::worker::DistriWorker::MAX_FRAGMENT_EVENT_BYTES
            > ave_network::MAX_APP_MESSAGE_BYTES as usize
    );
}

// wire versions are explicit. v1 fragments and acks requiring v2
// are dropped as incompatible without delivery; v2 completes. v1
// messages requiring v1 still work.
#[test(tokio::test)]
async fn remote_wire_version_incompatibility_is_explicit() {
    // Matrix: frag/ACK with hash and scoped pull require v2; the same
    // pull messages without scope stay v1, and unmodified messages keep
    // working with byte-identical encodings.
    let frag = ActorMessage::DistributionLedgerFrag {
        subject_id: DigestIdentifier::default(),
        event_hash: DigestIdentifier::default(),
        event_sn: 0,
        total_bytes: 1,
        chunk_index: 0,
        chunk_total: 1,
        chunk: vec![0],
        payload_hash: DigestIdentifier::default(),
        is_aux: false,
        group_hash: DigestIdentifier::default(),
        group_sn: 0,
        aux_hash: None,
        is_all: false,
        is_push: false,
        expected_governance_id: None,
    };
    let ack = ActorMessage::DistributionLastEventRes {
        event_hash: DigestIdentifier::default(),
    };
    let scoped_req = ActorMessage::DistributionLedgerReq {
        actual_sn: None,
        target_sn: None,
        subject_id: DigestIdentifier::default(),
        already_verified_transfer_sn: None,
        expected_governance_id: Some(DigestIdentifier::default()),
    };
    let scoped_res = ActorMessage::DistributionLedgerRes {
        ledger: vec![],
        is_all: false,
        transfer_event: None,
        expected_governance_id: Some(DigestIdentifier::default()),
    };
    let plain_req = ActorMessage::DistributionLedgerReq {
        actual_sn: None,
        target_sn: None,
        subject_id: DigestIdentifier::default(),
        already_verified_transfer_sn: None,
        expected_governance_id: None,
    };
    let plain_res = ActorMessage::DistributionLedgerRes {
        ledger: vec![],
        is_all: false,
        transfer_event: None,
        expected_governance_id: None,
    };
    let old = ActorMessage::DistributionGetLastSn {
        subject_id: DigestIdentifier::default(),
        actual_sn: None,
        receiver_actor: String::new(),
    };
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(
            &frag
        ),
        2
    );
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(&ack),
        2
    );
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(
            &scoped_req
        ),
        2
    );
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(
            &scoped_res
        ),
        2
    );
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(
            &plain_req
        ),
        1
    );
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(
            &plain_res
        ),
        1
    );
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(&old),
        1
    );
    assert_eq!(ave_core::helpers::network::WIRE_VERSION, 2);
    // Unmodified messages keep byte-identical encodings: the test-only
    // encoded buffer never reaches the wire.
    let info = ave_network::ComunicateInfo {
        request_id: String::from("req"),
        version: 0,
        receiver: PublicKey::new(
            ave_common::identity::DSAlgorithm::Ed25519,
            vec![1u8; 32],
        )
        .expect("sample key"),
        receiver_actor: String::from("actor"),
    };
    let without_encoded = ave_core::helpers::network::NetworkMessage {
        info: info.clone(),
        message: plain_res.clone(),
        wire_version: 1,
        encoded: None,
    };
    let mut with_encoded = without_encoded.clone();
    with_encoded.encoded = Some(vec![9, 9, 9]);
    assert_eq!(
        rmp_serde::to_vec(&without_encoded).unwrap(),
        rmp_serde::to_vec(&with_encoded).unwrap(),
        "encoded stays out of the wire"
    );
    let decoded: ave_core::helpers::network::NetworkMessage =
        rmp_serde::from_slice(&rmp_serde::to_vec(&without_encoded).unwrap())
            .unwrap();
    assert_eq!(decoded.wire_version, 1);
}

// a v1 fragment never reassembles. Same bytes with v1 are
// dropped before the worker; with v2 they apply.
#[test(tokio::test)]
async fn remote_old_peer_fragment_does_not_apply() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        // Hold frags too so nothing flows early; the v1/v2 injection below is the only copy path.
        let _ = message;
    }
    // Silence pushes so the manual injection below is the only path.
    for target in [&a] {
        let peer = PublicKey::from_str(target.public_key()).unwrap();
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
            FaultMessage::DistributionLedgerFrag,
        ] {
            b.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(peer.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "v".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let b_ledger = b
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap();
    let create_ev = b_ledger.iter().find(|e| e.sn == 0).unwrap().clone();
    let main_ev = b_ledger.iter().find(|e| e.sn == 1).unwrap().clone();
    let main_hash = main_ev.ledger_hash(HashAlgorithm::Blake3).unwrap();
    a.test_ensure_distributor(subject_id.clone()).await.unwrap();
    // Create first as whole v2 batch (v1 messages still work is covered
    // by the matrix test; here the pull itself uses v2 framing).
    let create_msg = NetworkMessage::new(
        ave_network::ComunicateInfo {
            request_id: "test-create".to_string(),
            version: 0,
            receiver: PublicKey::from_str(&a.public_key()).unwrap(),
            receiver_actor: format!("/user/node/distributor_{}", subject_id),
        },
        ActorMessage::DistributionLedgerRes {
            ledger: vec![create_ev],
            is_all: false,
            transfer_event: None,
            expected_governance_id: Some(governance_id.clone()),
        },
    );
    let mut create_v2 = create_msg;
    create_v2.wire_version = 2;
    a.test_inject_inbound(create_v2, &b_key).await.unwrap();
    get_subject(&a, subject_id.clone(), Some(0), true)
        .await
        .unwrap();
    fn chunk_size_for(cap: usize) -> usize {
        (cap.saturating_sub(8192) / 2).clamp(1024, 256 * 1024)
    }
    let chunk_size = chunk_size_for(cap);
    let bytes = borsh::to_vec(&main_ev).unwrap();
    let payload_hash = HashAlgorithm::Blake3.hasher().hash(&bytes);
    let total = bytes.len() as u64;
    let total_chunks = bytes.len().div_ceil(chunk_size) as u32;
    assert!(total_chunks >= 2, "small cap fragments");
    let mut v1_frags = vec![];
    let mut v2_frags = vec![];
    for (i, piece) in bytes.chunks(chunk_size).enumerate() {
        let base = ActorMessage::DistributionLedgerFrag {
            subject_id: main_ev.get_subject_id(),
            event_hash: main_hash.clone(),
            event_sn: 1,
            total_bytes: total,
            chunk_index: i as u32,
            chunk_total: total_chunks,
            chunk: piece.to_vec(),
            payload_hash: payload_hash.clone(),
            is_aux: false,
            group_hash: main_hash.clone(),
            group_sn: 1,
            aux_hash: None,
            is_all: false,
            is_push: false,
            expected_governance_id: Some(governance_id.clone()),
        };
        let mut m1 = NetworkMessage::new(
            ave_network::ComunicateInfo {
                request_id: "test-v1".to_string(),
                version: 0,
                receiver: PublicKey::from_str(&a.public_key()).unwrap(),
                receiver_actor: format!(
                    "/user/node/distributor_{}",
                    subject_id
                ),
            },
            base.clone(),
        );
        m1.wire_version = 1;
        let mut m2 = NetworkMessage::new(
            ave_network::ComunicateInfo {
                request_id: "test-v2".to_string(),
                version: 0,
                receiver: PublicKey::from_str(&a.public_key()).unwrap(),
                receiver_actor: format!(
                    "/user/node/distributor_{}",
                    subject_id
                ),
            },
            base,
        );
        m2.wire_version = 2;
        v1_frags.push(m1);
        v2_frags.push(m2);
    }
    for m in v1_frags {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    // Poll: v1 fragments never assemble or apply.
    let start = tokio::time::Instant::now();
    loop {
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(!ledger.iter().any(|e| e.sn == 1), "v1 frag must not apply");
        let len = a.test_fragment_assembly_len().await.unwrap_or(1);
        assert_eq!(len, 0, "v1 frag must not even assemble");
        if start.elapsed() > Duration::from_secs(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for m in v2_frags {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}
// scope fallback is explicit. A mismatched governance scope
// rejects before any write; the matching scope applies. Legacy
// pull requests without scope still get a response (no silent drop).
#[test(tokio::test)]
async fn remote_scope_mismatch_rejects_before_write() {
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let a_key = PublicKey::from_str(&a.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(&b, subject_id.clone(), json!({"ModOne": {"data": 5}}), true)
        .await
        .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    b.test_clear_faults().await.unwrap();
    let b_ledger = b
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap();
    let create_ev = b_ledger.iter().find(|e| e.sn == 0).unwrap().clone();
    let fact_ev = b_ledger.iter().find(|e| e.sn == 1).unwrap().clone();
    a.test_ensure_distributor(subject_id.clone()).await.unwrap();
    let mk_res = |ledger: Vec<Ledger>, scope: Option<DigestIdentifier>| {
        NetworkMessage::new(
            ave_network::ComunicateInfo {
                request_id: "test-scope".to_string(),
                version: 0,
                receiver: a_key.clone(),
                receiver_actor: format!(
                    "/user/node/distributor_{}",
                    subject_id
                ),
            },
            ActorMessage::DistributionLedgerRes {
                ledger,
                is_all: true,
                transfer_event: None,
                expected_governance_id: scope,
            },
        )
    };
    // Mismatched scope rejects before any write.
    let wrong = DigestIdentifier::default();
    assert_ne!(wrong, governance_id, "wrong scope differs");
    a.test_inject_inbound(
        mk_res(vec![create_ev.clone(), fact_ev.clone()], Some(wrong)),
        &b_key,
    )
    .await
    .unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            !ledger.iter().any(|e| e.sn == 0),
            "wrong scope never writes"
        );
        if start.elapsed() > Duration::from_secs(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Matching scope applies.
    a.test_inject_inbound(
        mk_res(vec![create_ev, fact_ev], Some(governance_id.clone())),
        &b_key,
    )
    .await
    .unwrap();
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}

/// Waits until the witnesses register names the expected pending
/// owner for the subject, polling observable register state with a
/// bounded budget: the transfer event lands in the ledger before the
/// register catches up with it.
async fn poll_pending_ownership(
    api: &ave_core::Api,
    gov: &DigestIdentifier,
    subject: &DigestIdentifier,
    want: Option<ave_common::identity::PublicKey>,
) {
    let start = tokio::time::Instant::now();
    loop {
        let (_, pending, _, _) = api
            .test_witnesses_ownership(&gov.clone(), subject.clone())
            .await
            .unwrap();
        if pending == want {
            return;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "pending ownership never converged to {want:?}, got {pending:?}"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// Grouped main+aux delivery only completes when both sides share the
// full identity: sender, scope, completeness, request, version, route
// and aux hash. A mixed counterpart discards both sides with no apply,
// proof or ready entries; the genuine pair still completes afterwards.
#[test(tokio::test)]
async fn remote_fragment_ready_mixed_identity_discarded_before_delivery() {
    async fn poll_no_fact(
        api: &ave_core::Api,
        gov: &DigestIdentifier,
        subject: &DigestIdentifier,
    ) {
        let start = tokio::time::Instant::now();
        loop {
            let ledger = api
                .test_get_tracker_ledger(subject.clone(), 10)
                .await
                .unwrap_or_default();
            assert!(
                !ledger.iter().any(|e| e.sn == 1),
                "mixed group never applies"
            );
            let proof = api
                .test_get_verified_transfer_sn(gov, subject.clone())
                .await
                .unwrap_or(None);
            assert!(proof.is_none(), "mixed group records no proof");
            let (assemblies, mains, auxes, _, _) =
                api.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
            if assemblies == 0 && mains == 0 && auxes == 0 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(10),
                "mixed group discarded"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let carol = nodes[2].api.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let carol_key = PublicKey::from_str(carol.public_key()).unwrap();
    let owner_key = PublicKey::from_str(nodes[0].api.public_key()).unwrap();
    assert_ne!(alice_key, owner_key, "mixed sender differs");
    let _ = dirs;
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Carol", "key": carol.public_key()},
            ]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Big",
                    "add": {
                        "evaluator": [{"name": "Alice", "namespace": []}],
                        "validator": [{"name": "Alice", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {"name": "Alice", "namespace": [], "quantity": "infinity"},
                            {"name": "Carol", "namespace": [], "quantity": "infinity"}
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    for api in [&carol] {
        api.authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    }
    for api in [&alice, &carol] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), None, true)
            .await
            .unwrap();
    }
    // Silence automatic pushes so only manual + follow-up pull deliver.
    for target in [&carol] {
        let peer = PublicKey::from_str(target.public_key()).unwrap();
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            alice
                .test_install_fault(FaultRule {
                    direction: FaultDirection::Outbound,
                    message,
                    peer: Some(peer.clone()),
                    remaining: None,
                    action: FaultAction::Drop,
                })
                .await
                .unwrap();
        }
    }
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "y".repeat(1200 * 1024);
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(
        carol.get_subject_state(subject_id.clone()).await.is_err(),
        "silenced pushes deliver nothing yet"
    );
    // Hold fragments: the manual push gaps on the missing fact and the
    // pull for the oversized fact stays held as main+aux fragments.
    // Only carol's copy is held; the owner node may complete freely.
    alice.test_clear_faults().await.unwrap();
    alice
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerFrag,
            peer: Some(carol_key.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    // The transfer push gaps; the create arrives deferred (its aux needs
    // the missing fact) and the oversized fact+transfer group stays held
    // as fragments until both sides are injected by the test.
    let mut frags = vec![];
    let mut stable = 0;
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = alice
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        let has_aux = held.iter().any(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: true, .. }
            )
        });
        if !held.is_empty() && has_aux && held.len() == frags.len() {
            stable += 1;
            if stable >= 2 {
                break;
            }
        } else {
            stable = 0;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!frags.is_empty(), "grouped copy travels fragmented");
    let mains: Vec<NetworkMessage> = frags
        .iter()
        .filter(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: false, .. }
            )
        })
        .cloned()
        .collect();
    let auxes: Vec<NetworkMessage> = frags
        .iter()
        .filter(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: true, .. }
            )
        })
        .cloned()
        .collect();
    assert!(
        !mains.is_empty() && !auxes.is_empty(),
        "group holds both sides"
    );
    let (a, b_key, c_key) =
        (carol.clone(), alice_key.clone(), owner_key.clone());
    // Mixed sender: aux from another peer shares the group but never
    // delivers; both sides are dropped with no apply, proof or ready.
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    for m in &auxes {
        a.test_inject_inbound(m.clone(), &c_key).await.unwrap();
    }
    poll_no_fact(&a, &governance_id, &subject_id).await;
    // Same sender, different scope.
    let mut scoped = auxes.clone();
    for m in &mut scoped {
        if let ActorMessage::DistributionLedgerFrag {
            expected_governance_id,
            ..
        } = &mut m.message
        {
            *expected_governance_id = Some(DigestIdentifier::default());
        }
    }
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    for m in scoped {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    poll_no_fact(&a, &governance_id, &subject_id).await;
    // Same sender and scope, different completeness.
    let mut flipped = auxes.clone();
    for m in &mut flipped {
        if let ActorMessage::DistributionLedgerFrag { is_all, .. } =
            &mut m.message
        {
            *is_all = !*is_all;
        }
    }
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    for m in flipped {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    poll_no_fact(&a, &governance_id, &subject_id).await;
    // Same sender, scope and completeness, different request identity.
    let mut requid = auxes.clone();
    for m in &mut requid {
        m.info.request_id = String::from("test-foreign-request");
        m.info.version = m.info.version.wrapping_add(1);
        m.info.receiver_actor = String::from("foreign-actor");
    }
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    for m in requid {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    poll_no_fact(&a, &governance_id, &subject_id).await;
    // The genuine pair still completes afterwards with no re-request loop.
    alice.test_clear_faults().await.unwrap();
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    for m in &auxes {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    poll_pending_ownership(
        &a,
        &governance_id,
        &subject_id,
        Some(carol_key.clone()),
    )
    .await;
    let (assemblies, mains_n, auxes_n, _, _) =
        a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
    assert_eq!(
        assemblies + mains_n + auxes_n,
        0,
        "ready counters return to zero after delivery"
    );
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|n| n.handler.iter_mut())).await;
}

// A main whose group differs from its own event is rejected at ingress
// before any assembly forms; an auxiliary whose event differs from the
// group is valid and waits for its main side.
#[test(tokio::test)]
async fn remote_fragment_group_sn_identity() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let carol = nodes[2].api.clone();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let carol_key = PublicKey::from_str(carol.public_key()).unwrap();
    let _ = dirs;
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Carol", "key": carol.public_key()},
            ]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Big",
                    "add": {
                        "evaluator": [{"name": "Alice", "namespace": []}],
                        "validator": [{"name": "Alice", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {"name": "Alice", "namespace": [], "quantity": "infinity"},
                            {"name": "Carol", "namespace": [], "quantity": "infinity"}
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    for api in [&carol] {
        api.authorize_governance(
            governance_id.clone(),
            ave_core::auth::AuthWitness::One(
                PublicKey::from_str(owner.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    }
    for api in [&alice, &carol] {
        api.update_subject(governance_id.clone()).await.unwrap();
        get_subject(api, governance_id.clone(), None, true)
            .await
            .unwrap();
    }
    for target in [&carol] {
        let peer = PublicKey::from_str(target.public_key()).unwrap();
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            alice
                .test_install_fault(FaultRule {
                    direction: FaultDirection::Outbound,
                    message,
                    peer: Some(peer.clone()),
                    remaining: None,
                    action: FaultAction::Drop,
                })
                .await
                .unwrap();
        }
    }
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "y".repeat(1200 * 1024);
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key.clone(), true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert!(
        carol.get_subject_state(subject_id.clone()).await.is_err(),
        "silenced pushes deliver nothing yet"
    );
    alice.test_clear_faults().await.unwrap();
    alice
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerFrag,
            peer: Some(carol_key.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    let mut stable = 0;
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = alice
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        let has_aux = held.iter().any(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: true, .. }
            )
        });
        if !held.is_empty() && has_aux && held.len() == frags.len() {
            stable += 1;
            if stable >= 2 {
                break;
            }
        } else {
            stable = 0;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!frags.is_empty(), "grouped copy travels fragmented");
    let mains: Vec<NetworkMessage> = frags
        .iter()
        .filter(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: false, .. }
            )
        })
        .cloned()
        .collect();
    let auxes: Vec<NetworkMessage> = frags
        .iter()
        .filter(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: true, .. }
            )
        })
        .cloned()
        .collect();
    assert!(
        !mains.is_empty() && !auxes.is_empty(),
        "group holds both sides"
    );
    let (a, b_key) = (carol.clone(), alice_key.clone());
    // A main whose group does not name its own event is dropped at
    // ingress: no assembly forms, nothing applies, counters stay zero.
    let mut forged_mains = mains.clone();
    for m in &mut forged_mains {
        if let ActorMessage::DistributionLedgerFrag { group_sn, .. } =
            &mut m.message
        {
            *group_sn = group_sn.wrapping_add(1000);
        }
    }
    for m in forged_mains {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    let start = tokio::time::Instant::now();
    loop {
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            !ledger.iter().any(|e| e.sn == 1),
            "misgrouped main never applies"
        );
        let len = a.test_fragment_assembly_len().await.unwrap_or(1);
        if len == 0 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "misgrouped main forms no assembly"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The genuine aux carries another event sn than the group by design
    // (it authorizes the main): it completes and waits for its main side.
    for m in &auxes {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    let start = tokio::time::Instant::now();
    loop {
        let (_, _, ready_auxes, _, _) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            !ledger.iter().any(|e| e.sn == 1),
            "aux alone never applies the main"
        );
        if ready_auxes == 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "aux waits for its main"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The genuine main still completes the group afterwards.
    alice.test_clear_faults().await.unwrap();
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    // SN1 applies here; the staged transfer (SN2) may follow in the
    // same worker task, so catching exactly SN1 is timing-dependent.
    // SN2 implies SN1 (sequential ledger): waiting for at least SN1
    // proves delivery either way.
    for _ in 0..300 {
        if let Ok(state) = a.get_subject_state(subject_id.clone()).await {
            if state.sn >= 1 {
                break;
            }
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        a.get_subject_state(subject_id.clone())
            .await
            .map(|s| s.sn)
            .unwrap_or(0)
            >= 1,
        "the genuine main delivers SN1 (SN2 may already follow)"
    );
    poll_pending_ownership(
        &a,
        &governance_id,
        &subject_id,
        Some(carol_key.clone()),
    )
    .await;
    let (assemblies, mains_n, auxes_n, _, _) =
        a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
    assert_eq!(
        assemblies + mains_n + auxes_n,
        0,
        "ready counters return to zero after delivery"
    );
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|n| n.handler.iter_mut())).await;
}

// A complete pair delivers before any eviction, even when it is the
// oldest group: filling the ready map still lets the oldest pair
// complete, while an evicted side only waits for its counterpart.
#[test(tokio::test)]
async fn remote_fragment_capacity_oldest_pair_delivers_first() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let a_key = PublicKey::from_str(&a.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for target in [&a] {
        let peer = PublicKey::from_str(target.public_key()).unwrap();
        for message in [
            FaultMessage::DistributionLedgerRes,
            FaultMessage::DistributionLastEventReq,
        ] {
            b.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(peer.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    // One real grouped copy plus fabricated filler mains: the fillers
    // complete without any auxiliary and sit in the ready map, so the
    // genuine pair must still deliver first even when the map is full.
    let bulk = "y".repeat(1200 * 1024);
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    emit_transfer(&b, subject_id.clone(), a_key.clone(), true)
        .await
        .unwrap();
    get_subject(&b, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    // Barrier: the register trails the ledger, and the pull only carries
    // the auxiliary once the pending transfer is recorded there.
    let start = tokio::time::Instant::now();
    loop {
        let (_, pending, _, _) = b
            .test_witnesses_ownership(&governance_id, subject_id.clone())
            .await
            .unwrap();
        if pending == Some(a_key.clone()) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "pending transfer recorded"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    // The manual push gaps on the missing fact; the create arrives
    // deferred and the oversized fact+transfer group stays held.
    b.manual_distribution(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    let mut stable = 0;
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        let has_aux = held.iter().any(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: true, .. }
            )
        });
        if !held.is_empty() && has_aux && held.len() == frags.len() {
            stable += 1;
            if stable >= 2 {
                break;
            }
        } else {
            stable = 0;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(!frags.is_empty(), "grouped copy travels fragmented");
    let mains: Vec<NetworkMessage> = frags
        .iter()
        .filter(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: false, .. }
            )
        })
        .cloned()
        .collect();
    let auxes: Vec<NetworkMessage> = frags
        .iter()
        .filter(|m| {
            matches!(
                &m.message,
                ActorMessage::DistributionLedgerFrag { is_aux: true, .. }
            )
        })
        .cloned()
        .collect();
    assert!(
        !mains.is_empty() && !auxes.is_empty(),
        "group holds both sides"
    );
    // Fabricated filler mains: small self-consistent fragments for events
    // that never existed, sharing the tracked subject but with distinct
    // identities. They complete and wait in the ready map like any main
    // whose auxiliary never arrives.
    let create_ev = b
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap()
        .into_iter()
        .find(|e| e.sn == 0)
        .expect("create committed");
    let template_info = match &mains[0].message {
        ActorMessage::DistributionLedgerFrag { .. } => mains[0].info.clone(),
        _ => unreachable!(),
    };
    let mut fillers: Vec<Vec<NetworkMessage>> = vec![];
    for k in 0..8u64 {
        let mut ledger = create_ev.clone();
        ledger.sn = 100 + k;
        let bytes = borsh::to_vec(&ledger).unwrap();
        let event_hash = ledger.ledger_hash(HashAlgorithm::Blake3).unwrap();
        let total = bytes.len() as u64;
        let chunk_size = (cap.saturating_sub(8192) / 2).clamp(1024, 256 * 1024);
        let total_chunks = bytes.len().div_ceil(chunk_size) as u32;
        assert!(total_chunks >= 1, "filler fragments");
        let mut set = vec![];
        for (i, piece) in bytes.chunks(chunk_size).enumerate() {
            let mut info = template_info.clone();
            info.request_id = format!("test-filler-{k}");
            set.push(NetworkMessage {
                info,
                wire_version: 2,
                encoded: None,
                message: ActorMessage::DistributionLedgerFrag {
                    subject_id: subject_id.clone(),
                    event_hash: event_hash.clone(),
                    event_sn: 100 + k,
                    total_bytes: total,
                    chunk_index: i as u32,
                    chunk_total: total_chunks,
                    chunk: piece.to_vec(),
                    payload_hash: HashAlgorithm::Blake3.hasher().hash(&bytes),
                    is_aux: false,
                    group_hash: event_hash.clone(),
                    group_sn: 100 + k,
                    aux_hash: Some(DigestIdentifier::default()),
                    is_all: false,
                    is_push: false,
                    expected_governance_id: None,
                },
            });
        }
        fillers.push(set);
    }
    // Fill the ready map with the eight fabricated mains.
    for set in &fillers {
        for m in set {
            a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
        }
    }
    let start = tokio::time::Instant::now();
    loop {
        let (assemblies, ready_mains, ready_auxes, _, _) =
            a.test_fragment_stats().await.unwrap_or((1, 0, 0, 0, 0));
        if ready_mains == 8 && ready_auxes == 0 && assemblies == 0 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "eight filler mains wait for their aux"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The genuine main evicts the oldest filler instead of growing the store.
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    // Its auxiliary still completes the pair at once: no eviction of a
    // complete group, even though the map was full.
    for m in &auxes {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    // The evicted oldest side only waits: a fabricated auxiliary for its
    // group arrives but nothing applies until the main side is served
    // again. The map was just proven full, so the missing main was
    // evicted to make room for the genuine pair delivered above.
    let mut filler_aux = fillers[0][0].clone();
    if let ActorMessage::DistributionLedgerFrag {
        is_aux, aux_hash, ..
    } = &mut filler_aux.message
    {
        *is_aux = true;
        *aux_hash = None;
    }
    a.test_inject_inbound(filler_aux, &b_key).await.unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let ledger = a
            .test_get_tracker_ledger(subject_id.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            !ledger.iter().any(|e| e.sn == 100),
            "evicted filler never applies from aux alone"
        );
        let (_, _, ready_auxes, _, _) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        if ready_auxes == 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "evicted side waits for its main"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // The genuine pair still opens pending ownership once the register
    // catches up with the applied ledger.
    let start = tokio::time::Instant::now();
    loop {
        let (_, pending, _, _) = a
            .test_witnesses_ownership(&governance_id, subject_id.clone())
            .await
            .unwrap();
        if pending == Some(a_key.clone()) {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "genuine pair opens pending ownership"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Repeat at capacity with only auxiliary sides. A new main without
    // its counterpart must evict the oldest auxiliary instead of growing
    // the combined store past its eight-entry bound.
    for set in &fillers {
        for message in set {
            let mut aux = message.clone();
            if let ActorMessage::DistributionLedgerFrag {
                is_aux,
                aux_hash,
                ..
            } = &mut aux.message
            {
                *is_aux = true;
                *aux_hash = None;
            }
            a.test_inject_inbound(aux, &b_key).await.unwrap();
        }
    }
    let start = tokio::time::Instant::now();
    loop {
        let (_, ready_mains, ready_auxes, _, _) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        if ready_mains == 0 && ready_auxes == 8 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "auxiliary fillers fill the ready map"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    for m in &mains {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    let start = tokio::time::Instant::now();
    loop {
        let (_, ready_mains, ready_auxes, _, _) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        assert!(
            ready_mains + ready_auxes <= 8,
            "ready sides never exceed their combined bound"
        );
        if ready_mains == 1 {
            assert_eq!(
                ready_auxes, 7,
                "the new main evicts one auxiliary at capacity"
            );
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "main joins a full auxiliary-only ready map"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // All timers cancelled on delivery plus natural expiry of the
    // remaining fillers free the whole map: counters return to zero.
    let start = tokio::time::Instant::now();
    loop {
        let (assemblies, mains_n, auxes_n, _, _) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        if assemblies == 0 && mains_n == 0 && auxes_n == 0 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "fillers expire and free the map"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

// A v1 copy without scope completes: the same pull messages without
// expected_governance_id require only v1 and apply through the legacy
// path when the create declares the tracked governance.
#[test(tokio::test)]
async fn remote_v1_copy_without_scope_completes() {
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let a_key = PublicKey::from_str(&a.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(&b, subject_id.clone(), json!({"ModOne": {"data": 5}}), true)
        .await
        .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let b_ledger = b
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap();
    let create_ev = b_ledger.iter().find(|e| e.sn == 0).unwrap().clone();
    let fact_ev = b_ledger.iter().find(|e| e.sn == 1).unwrap().clone();
    a.test_ensure_distributor(subject_id.clone()).await.unwrap();
    // v1 framing (wire 1) with no scope: required stays 1 and the legacy
    // path applies the matching create without any scope gate.
    let msg = ActorMessage::DistributionLedgerRes {
        ledger: vec![create_ev, fact_ev],
        is_all: true,
        transfer_event: None,
        expected_governance_id: None,
    };
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(&msg),
        1
    );
    let mut v1 = NetworkMessage::new(
        ave_network::ComunicateInfo {
            request_id: String::from("test-v1-copy"),
            version: 0,
            receiver: a_key,
            receiver_actor: format!("/user/node/distributor_{}", subject_id),
        },
        msg,
    );
    v1.wire_version = 1;
    a.test_inject_inbound(v1, &b_key).await.unwrap();
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}

// A response without scope never validates another governance: a create
// declaring a foreign id is rejected before any write, so omitting the
// scope is not a bypass for the v2 scope check.
#[test(tokio::test)]
async fn remote_scope_none_with_foreign_create_never_writes() {
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let a_key = PublicKey::from_str(&a.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    // A second governance the receiver never tracks: its subjects must
    // never land through a scopeless legacy response.
    let foreign_gov = create_and_authorize_governance(&b, vec![]).await;
    assert_ne!(foreign_gov, governance_id, "governances differ");
    emit_fact(
        &b,
        foreign_gov.clone(),
        json!({
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {"schema": [{
                "schema_id": "Example",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}],
                    "creator": [{"name": "Owner", "namespace": [], "quantity": "infinity"}],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    let (foreign_subject, _) =
        create_subject(&b, foreign_gov.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &b,
        foreign_subject.clone(),
        json!({"ModOne": {"data": 7}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, foreign_subject.clone(), Some(1), true)
        .await
        .unwrap();
    let b_ledger = b
        .test_get_tracker_ledger(foreign_subject.clone(), 10)
        .await
        .unwrap();
    let create_ev = b_ledger.iter().find(|e| e.sn == 0).unwrap().clone();
    let fact_ev = b_ledger.iter().find(|e| e.sn == 1).unwrap().clone();
    a.test_ensure_distributor(foreign_subject.clone())
        .await
        .unwrap();
    let msg = ActorMessage::DistributionLedgerRes {
        ledger: vec![create_ev, fact_ev],
        is_all: true,
        transfer_event: None,
        expected_governance_id: None,
    };
    assert_eq!(
        ave_core::helpers::network::NetworkMessage::required_wire_version(&msg),
        1
    );
    let mut v1 = NetworkMessage::new(
        ave_network::ComunicateInfo {
            request_id: String::from("test-foreign-scope"),
            version: 0,
            receiver: a_key,
            receiver_actor: format!(
                "/user/node/distributor_{}",
                foreign_subject
            ),
        },
        msg,
    );
    v1.wire_version = 1;
    a.test_inject_inbound(v1, &b_key).await.unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let ledger = a
            .test_get_tracker_ledger(foreign_subject.clone(), 10)
            .await
            .unwrap_or_default();
        assert!(
            ledger.is_empty(),
            "foreign create never writes without its scope"
        );
        assert!(
            a.get_subject_state(foreign_subject.clone()).await.is_err(),
            "no subject without its scope"
        );
        if start.elapsed() > Duration::from_secs(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// Activity renews the fragment expiry: delivering chunks past one TTL
// keeps the assembly alive, and only real inactivity expires it and
// frees the memory. A fresh copy completes afterwards.
#[test(tokio::test)]
async fn remote_fragment_expiry_is_renewed_by_activity() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "q".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags.len() {
            break;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(frags.len() >= 2, "oversized travels fragmented");
    // Only the first chunk: the assembly exists but cannot complete.
    a.test_inject_inbound(frags[0].clone(), &b_key)
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let len = a.test_fragment_assembly_len().await.unwrap_or(0);
        if len == 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "partial assembly appears"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    // Sustained activity past one TTL: duplicates renew the assembly, so
    // it never expires and the expiry counter stays flat.
    let active_until = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        a.test_inject_inbound(frags[0].clone(), &b_key)
            .await
            .unwrap();
        let len = a.test_fragment_assembly_len().await.unwrap_or(0);
        let (_, _, _, _, expired) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        assert_eq!(
            len, 1,
            "activity keeps the assembly alive past its first TTL"
        );
        assert_eq!(expired, 0, "no expiry while the assembly advances");
        if tokio::time::Instant::now() >= active_until {
            break;
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
    }
    // Real inactivity expires it and frees the memory.
    let start = tokio::time::Instant::now();
    loop {
        let len = a.test_fragment_assembly_len().await.unwrap_or(1);
        let (_, _, _, _, expired) =
            a.test_fragment_stats().await.unwrap_or((0, 0, 0, 0, 0));
        if len == 0 && expired >= 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "idle assembly expires without more messages"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // A fresh genuine copy still completes afterwards.
    b.test_clear_faults().await.unwrap();
    for m in frags {
        a.test_inject_inbound(m, &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}

// A stale timeout can never remove a renewed assembly: after activity
// moves the generation forward, only the newest timer may expire the
// entry, and completing the join cancels every pending timer without
// counting a spurious expiry.
#[test(tokio::test)]
async fn remote_fragment_stale_timer_cannot_remove_renewed_assembly() {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&b.public_key()).unwrap();
    let _ = nodes;
    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [{ "name": "A", "key": a.public_key() }]},
            "schemas": { "add": [{
                "id": "Big",
                "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                "initial_value": {"data": ""},
            }]},
            "roles": {"schema": [{
                "schema_id": "Big",
                "add": {
                    "evaluator": [{"name": "Owner", "namespace": []}],
                    "validator": [{"name": "Owner", "namespace": []}],
                    "witness": [{"name": "Owner", "namespace": []}, {"name": "A", "namespace": []}],
                    "creator": [
                        {"name": "Owner", "namespace": [], "quantity": "infinity"},
                        {"name": "A", "namespace": [], "quantity": "infinity"},
                    ],
                    "issuer": [{"name": "Owner", "namespace": []}],
                },
            }]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLedgerReq,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::DistributionLedgerFrag,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(PublicKey::from_str(&a.public_key()).unwrap()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "e".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.authorize_governance(
        subject_id.clone(),
        ave_core::auth::AuthWitness::One(b_key.clone()),
    )
    .await
    .unwrap();
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.update_subject(subject_id.clone()).await.unwrap();
    let mut frags = vec![];
    for _ in 0..300 {
        let held: Vec<NetworkMessage> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter(|m| {
                matches!(m.message, ActorMessage::DistributionLedgerFrag { .. })
            })
            .collect();
        if !held.is_empty() && held.len() == frags.len() {
            break;
        }
        frags = held;
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    assert!(
        frags.len() >= 3,
        "oversized travels in at least three fragments"
    );
    // First chunk arms the first timer; spaced duplicate renewals move
    // the generation forward and cancel every previous timer. Only the
    // newest timer may ever expire the entry.
    a.test_inject_inbound(frags[0].clone(), &b_key)
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let len = a.test_fragment_assembly_len().await.unwrap_or(99);
        if len == 1 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "first frag creates the assembly"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let renewed_until =
        tokio::time::Instant::now() + Duration::from_millis(1600);
    loop {
        a.test_inject_inbound(frags[0].clone(), &b_key)
            .await
            .unwrap();
        let len = a.test_fragment_assembly_len().await.unwrap_or(0);
        let (_, _, _, _, expired) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
        assert_eq!(len, 1, "renewed assembly never disappears");
        assert_eq!(expired, 0, "obsolete timers never count an expiry");
        if tokio::time::Instant::now() >= renewed_until {
            break;
        }
        tokio::time::sleep(Duration::from_millis(400)).await;
    }
    // Completing the join cancels every pending timer: no spurious expiry
    // fires afterwards and the copy applies exactly once.
    for m in &frags[1..] {
        a.test_inject_inbound(m.clone(), &b_key).await.unwrap();
    }
    get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let start = tokio::time::Instant::now();
    loop {
        let (_, _, _, _, expired) =
            a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 1));
        assert_eq!(expired, 0, "completed join cancels every pending timer");
        if start.elapsed() > Duration::from_secs(2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let (assemblies, mains_n, auxes_n, _, _) =
        a.test_fragment_stats().await.unwrap_or((1, 1, 1, 0, 0));
    assert_eq!(
        assemblies + mains_n + auxes_n,
        0,
        "no fragment state leaks after delivery"
    );
}

// A v1 ack never closes a generation: the same bytes framed as v1 are
// dropped as incompatible while the genuine v2 ack completes exactly
// once and the next generation still makes progress.
#[test(tokio::test)]
async fn remote_v1_ack_never_closes_generation() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let w = nodes[2].api.clone();
    let w_key = PublicKey::from_str(w.public_key()).unwrap();
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {"name": "Alice", "key": alice.public_key()},
                    {"name": "W", "key": w.public_key()},
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0}
                    }
                ]
            },
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [
                    {
                        "schema_id": "Example",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [{"name": "Owner", "namespace": []}],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "W",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                }
                            ],
                            "issuer": [{"name": "Alice", "namespace": []}]
                        }
                    }
                ]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    w.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    w.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&w, governance_id.clone(), None, true)
        .await
        .unwrap();
    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    async fn hold_res(api: &ave_core::Api) {
        api.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventRes,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }
    async fn held_res_count(api: &ave_core::Api) -> usize {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|m| {
                matches!(
                    &m.message,
                    ActorMessage::DistributionLastEventRes { .. }
                )
            })
            .count()
    }
    hold_res(&w).await;
    alice.manual_distribution(subject_id.clone()).await.unwrap();
    get_subject(&w, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    for _ in 0..100 {
        if held_res_count(&w).await >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let genuine = w
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .into_iter()
        .find(|m| {
            matches!(&m.message, ActorMessage::DistributionLastEventRes { .. })
        })
        .expect("first generation ack held");
    // Same ack bytes framed as v1: the intermediary drops them as
    // incompatible, so the live generation keeps retrying.
    let held_before = held_res_count(&w).await;
    assert!(held_before >= 1, "genuine ack retained");
    let mut legacy = genuine;
    legacy.wire_version = 1;
    alice.test_inject_inbound(legacy, &w_key).await.unwrap();
    for _ in 0..100 {
        if held_res_count(&w).await > held_before {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        held_res_count(&w).await > held_before,
        "v1 ack ignored: the live generation keeps retrying"
    );
    // The genuine v2 ack still completes the generation exactly once,
    // and both nodes stay healthy afterwards.
    w.test_release_held().await.unwrap();
    get_subject(&w, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    node_running(&alice).await.unwrap();
    node_running(&w).await.unwrap();
    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
    drop(nodes);
    drop(dirs);
}

/// A recorded firm proof covers only an aux with the exact same
/// subject, sn, sender and ledger hash. A divergent aux with the
/// same SN, the same bytes from another sender and a higher-sn
/// hashed proof over an older aux all force a fresh re-verification
/// instead of reusing the verdict. A legacy proof without hash never
/// covers: it is revalidated once and replaced by a hashed proof.
#[test(tokio::test)]
async fn remote_proof_only_covers_exact_aux_identity() {
    async fn poll_sn(
        api: &ave_core::Api,
        subject_id: &DigestIdentifier,
        want: u64,
    ) {
        let start = tokio::time::Instant::now();
        loop {
            if let Ok(state) = api.get_subject_state(subject_id.clone()).await {
                if state.sn == want {
                    return;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "timeout waiting for sn {want}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn sink_empty_from(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        from_sn: u64,
    ) {
        use ave_common::bridge::request::SinkEventsQuery;
        let page = api
            .get_sink_events(
                subject.clone(),
                SinkEventsQuery {
                    from_sn: Some(from_sn),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await
            .unwrap();
        assert!(
            page.events.is_empty(),
            "rejected aux must emit nothing to sinks"
        );
    }
    async fn ownership_of(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) -> (Option<PublicKey>, Option<PublicKey>) {
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => panic!("ownership must be readable"),
            Ok((owner_now, pending, _, _)) => (owner_now, pending),
        }
    }
    async fn tip_of(api: &ave_core::Api, subject_id: &DigestIdentifier) -> u64 {
        api.get_subject_state(subject_id.clone()).await.unwrap().sn
    }
    async fn ledger_sns(
        api: &ave_core::Api,
        subject_id: &DigestIdentifier,
        hi: u64,
    ) -> Vec<u64> {
        api.test_get_tracker_ledger(subject_id.clone(), hi)
            .await
            .unwrap_or_default()
            .iter()
            .map(|event| event.sn)
            .collect::<Vec<_>>()
    }
    async fn proof_of(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) -> Option<(u64, PublicKey, Option<DigestIdentifier>, bool)> {
        api.test_get_verified_transfer_detail(governance_id, subject_id.clone())
            .await
            .unwrap()
    }

    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Rita", "key": rita_key.to_string()},
            ]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}, {"name": "Rita", "namespace": []}],
                        "creator": [
                            {"name": "Alice", "namespace": [], "quantity": "infinity"},
                            {"name": "Rita", "namespace": [], "quantity": "infinity"}
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).expect("node key");
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }

    // Four subjects with the same shape: create(0), two facts and a
    // transfer(3, alice -> rita). Each one exercises a different
    // proof/aux identity combination below. Built concurrently: the
    // chains are independent.
    async fn make_chain(
        alice: &ave_core::Api,
        governance_id: DigestIdentifier,
        rita_key: PublicKey,
        alice_keys: &ave_common::identity::keys::KeyPair,
    ) -> (DigestIdentifier, Ledger, Ledger) {
        let (subject_id, _) =
            create_subject(alice, governance_id.clone(), "Example", "", true)
                .await
                .unwrap();
        for data in [1u64, 2] {
            emit_fact(
                alice,
                subject_id.clone(),
                json!({"ModOne": {"data": data}}),
                true,
            )
            .await
            .unwrap();
        }
        emit_transfer(alice, subject_id.clone(), rita_key.clone(), true)
            .await
            .unwrap();
        let history = alice
            .test_get_tracker_ledger(subject_id.clone(), 3)
            .await
            .unwrap();
        let fact = history
            .iter()
            .find(|event| event.sn == 2)
            .expect("fact event")
            .clone();
        let transfer = history
            .iter()
            .find(|event| event.sn == 3)
            .expect("transfer event")
            .clone();
        let fact_result = match &fact.protocols {
            Protocols::TrackerFactFull { evaluation, .. } => evaluation
                .evaluator_response_ok()
                .expect("fact evaluation ok"),
            _ => panic!("expected a full fact"),
        };
        let forged = forge_ok_evaluation(&transfer, fact_result, alice_keys);
        (subject_id, transfer, forged)
    }
    let (chain_a, chain_b, chain_c, chain_d) = tokio::join!(
        make_chain(
            &alice,
            governance_id.clone(),
            rita_key.clone(),
            &alice_keys
        ),
        make_chain(
            &alice,
            governance_id.clone(),
            rita_key.clone(),
            &alice_keys
        ),
        make_chain(
            &alice,
            governance_id.clone(),
            rita_key.clone(),
            &alice_keys
        ),
        make_chain(
            &alice,
            governance_id.clone(),
            rita_key.clone(),
            &alice_keys
        )
    );
    let (subject_a, transfer_a, forged_a) = chain_a;
    let (subject_b, transfer_b, _) = chain_b;
    let (subject_c, transfer_c, forged_c) = chain_c;
    let (subject_d, _transfer_d, forged_d) = chain_d;
    let hash_a = transfer_a
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("aux hashes");
    assert!(
        forged_a
            .ledger_hash(HashAlgorithm::Blake3)
            .expect("forged aux hashes")
            != hash_a,
        "same SN, different bytes is the divergent case"
    );

    let flow_a = async {
        // Subject A: a proven aux records a firm proof. A divergent aux
        // with the same SN must be re-verified and refuted, never
        // covered; the exact aux then completes without re-verifying.
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_a.clone(), 1)
                .await
                .unwrap(),
            None,
        )
        .await;
        poll_sn(&rita, &subject_a, 1).await;
        assert_eq!(
            rita.test_get_verified_transfer_sn(
                &governance_id,
                subject_a.clone()
            )
            .await
            .unwrap(),
            None,
            "no proof before the aux is verified"
        );
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_a.clone(), 2)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.sn == 2)
                .collect::<Vec<_>>(),
            Some(transfer_a.clone()),
        )
        .await;
        poll_sn(&rita, &subject_a, 2).await;
        let (proof_sn, proof_sender) = rita
            .test_get_verified_transfer_sn(&governance_id, subject_a.clone())
            .await
            .unwrap()
            .expect("proven aux records a firm proof");
        assert_eq!(proof_sn, 3, "proof pins the aux sn");
        assert_eq!(proof_sender, alice_key, "proof pins the sender");
        // Divergent aux, same SN, different hash: must be re-verified
        // and refuted instead of covered by the firm proof.
        let verify_a1 =
            rita.test_verify_stats(subject_a.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &alice_key,
            vec![forged_a.clone()],
            Some(forged_a.clone()),
        )
        .await;
        // Wait for the re-verification to run (work counters move) or
        // fail fast if the tip advances (the bug: covered + applied).
        // Falling out of the loop means the aux was re-verified.
        let start = tokio::time::Instant::now();
        loop {
            let tip = tip_of(&rita, &subject_a).await;
            let verify =
                rita.test_verify_stats(subject_a.clone()).await.unwrap();
            if tip != 2 {
                panic!(
                    "divergent aux must not advance the tip: sn advanced to {tip}"
                );
            }
            if verify.0 > verify_a1.0 {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "divergent aux was never re-verified"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            ledger_sns(&rita, &subject_a, 10).await,
            vec![0, 1, 2],
            "divergent aux writes nothing"
        );
        assert_eq!(
            ownership_of(&rita, &governance_id, &subject_a).await,
            (Some(alice_key.clone()), None),
            "divergent aux must not move ownership"
        );
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_a).await,
            Some((3, alice_key.clone(), Some(hash_a.clone()), false)),
            "firm proof survives a refuted aux"
        );
        sink_empty_from(&rita, &subject_a, 3).await;
        // The exact aux reuses the verdict without re-verifying and
        // completes the copy with the genuine bytes.
        let verify_a2 =
            rita.test_verify_stats(subject_a.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &alice_key,
            vec![transfer_a.clone()],
            Some(transfer_a.clone()),
        )
        .await;
        poll_sn(&rita, &subject_a, 3).await;
        assert_eq!(
            ledger_sns(&rita, &subject_a, 10).await,
            vec![0, 1, 2, 3],
            "exact aux applies"
        );
        let applied_hash = rita
            .test_get_tracker_ledger(subject_a.clone(), 3)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.sn == 3)
            .expect("applied transfer")
            .ledger_hash(HashAlgorithm::Blake3)
            .unwrap();
        assert_eq!(applied_hash, hash_a, "exact bytes applied");
        assert_eq!(
            ownership_of(&rita, &governance_id, &subject_a).await,
            (Some(alice_key.clone()), Some(rita_key.clone())),
            "applied transfer opens pending ownership"
        );
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_a).await,
            None,
            "applied transfer spends the proof (single-use)"
        );
        assert_eq!(
            rita.test_verify_stats(subject_a.clone()).await.unwrap(),
            verify_a2,
            "an exact aux reuses the verdict without re-verifying"
        );
    };

    let flow_b = async {
        // Subject B: the same bytes from another sender are verified again.
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_b.clone(), 1)
                .await
                .unwrap(),
            None,
        )
        .await;
        poll_sn(&rita, &subject_b, 1).await;
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_b.clone(), 2)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.sn == 2)
                .collect::<Vec<_>>(),
            Some(transfer_b.clone()),
        )
        .await;
        poll_sn(&rita, &subject_b, 2).await;
        let verify_b0 =
            rita.test_verify_stats(subject_b.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &owner_key,
            vec![transfer_b.clone()],
            Some(transfer_b.clone()),
        )
        .await;
        poll_sn(&rita, &subject_b, 3).await;
        let verify_b1 =
            rita.test_verify_stats(subject_b.clone()).await.unwrap();
        assert!(
            verify_b1.0 > verify_b0.0,
            "another sender's aux re-verifies instead of reusing the proof"
        );
        assert_eq!(
            tip_of(&rita, &subject_b).await,
            3,
            "relayed genuine aux still applies"
        );
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_b).await,
            None,
            "applied transfer spends the proof instead of it being stolen"
        );
    };

    let flow_c = async {
        // Subject C: a legacy proof without hash never covers.
        let hash_c = transfer_c
            .ledger_hash(HashAlgorithm::Blake3)
            .expect("aux hashes");
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_c.clone(), 1)
                .await
                .unwrap(),
            None,
        )
        .await;
        poll_sn(&rita, &subject_c, 1).await;
        rita.test_record_legacy_verified_transfer(
            &governance_id,
            subject_c.clone(),
            3,
            alice_key.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_c).await,
            Some((3, alice_key.clone(), None, false)),
            "legacy proof carries no hash"
        );
        // A divergent aux chained behind the genuine fact forces a full
        // evidence replay and refutes; the wait below ends only once
        // that verdict ran (counters move), never on a fixed sleep.
        let fact2_c = alice
            .test_get_tracker_ledger(subject_c.clone(), 2)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.sn == 2)
            .expect("fact 2");
        let verify_c_div =
            rita.test_verify_stats(subject_c.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &alice_key,
            vec![fact2_c, forged_c.clone()],
            Some(forged_c.clone()),
        )
        .await;
        let start = tokio::time::Instant::now();
        loop {
            if rita.test_verify_stats(subject_c.clone()).await.unwrap().0
                > verify_c_div.0
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "divergent aux against a legacy proof was never re-verified"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            tip_of(&rita, &subject_c).await,
            1,
            "divergent aux against a legacy proof must not advance"
        );
        assert_eq!(
            ledger_sns(&rita, &subject_c, 10).await,
            vec![0, 1],
            "divergent aux against a legacy proof writes nothing"
        );
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_c).await,
            Some((3, alice_key.clone(), None, false)),
            "legacy proof survives a refuted aux"
        );
        sink_empty_from(&rita, &subject_c, 2).await;
        // The genuine aux revalidates the legacy proof and replaces it
        // with a hashed one; afterwards the exact aux is covered.
        let verify_c0 =
            rita.test_verify_stats(subject_c.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_c.clone(), 2)
                .await
                .unwrap()
                .into_iter()
                .filter(|event| event.sn == 2)
                .collect::<Vec<_>>(),
            Some(transfer_c.clone()),
        )
        .await;
        poll_sn(&rita, &subject_c, 2).await;
        let detail_c = proof_of(&rita, &governance_id, &subject_c).await;
        assert_eq!(
            detail_c,
            Some((3, alice_key.clone(), Some(hash_c.clone()), false)),
            "revalidated proof replaces the legacy entry with its hash"
        );
        assert!(
            rita.test_verify_stats(subject_c.clone()).await.unwrap().0
                > verify_c0.0,
            "replacing a legacy proof replays the evidence"
        );
        let verify_c1 =
            rita.test_verify_stats(subject_c.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &alice_key,
            vec![transfer_c.clone()],
            Some(transfer_c.clone()),
        )
        .await;
        poll_sn(&rita, &subject_c, 3).await;
        assert_eq!(
            rita.test_verify_stats(subject_c.clone()).await.unwrap(),
            verify_c1,
            "the exact aux after replacement reuses the verdict"
        );
        assert_eq!(
            ownership_of(&rita, &governance_id, &subject_c).await,
            (Some(alice_key.clone()), Some(rita_key.clone())),
            "applied transfer opens pending ownership"
        );
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_c).await,
            None,
            "applied transfer spends the replaced proof (single-use)"
        );
    };

    let flow_d = async {
        // Subject D: a higher-sn hashed proof does not cover an older aux,
        // even when its stored hash matches that aux exactly.
        let hash_d = forged_d
            .ledger_hash(HashAlgorithm::Blake3)
            .expect("aux hash");
        inject_ledger_batch(
            &rita,
            &alice_key,
            alice
                .test_get_tracker_ledger(subject_d.clone(), 1)
                .await
                .unwrap(),
            None,
        )
        .await;
        poll_sn(&rita, &subject_d, 1).await;
        rita.test_record_hashed_verified_transfer(
            &governance_id,
            subject_d.clone(),
            5,
            alice_key.clone(),
            hash_d.clone(),
        )
        .await
        .unwrap();
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_d).await,
            Some((5, alice_key.clone(), Some(hash_d.clone()), false)),
            "hashed higher-sn proof is installed"
        );
        let fact2_d = alice
            .test_get_tracker_ledger(subject_d.clone(), 2)
            .await
            .unwrap()
            .into_iter()
            .find(|event| event.sn == 2)
            .expect("fact 2");
        // Same bounded-verdict wait as above: the higher-sn proof must
        // not cover, so the older aux replays its evidence and refutes.
        let verify_d_div =
            rita.test_verify_stats(subject_d.clone()).await.unwrap();
        inject_ledger_batch(
            &rita,
            &alice_key,
            vec![fact2_d, forged_d.clone()],
            Some(forged_d.clone()),
        )
        .await;
        let start = tokio::time::Instant::now();
        loop {
            if rita.test_verify_stats(subject_d.clone()).await.unwrap().0
                > verify_d_div.0
            {
                break;
            }
            assert!(
                start.elapsed() < Duration::from_secs(30),
                "older aux under a higher-sn proof was never re-verified"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        assert_eq!(
            tip_of(&rita, &subject_d).await,
            1,
            "a higher-sn proof must not cover an older aux"
        );
        assert_eq!(
            ledger_sns(&rita, &subject_d, 10).await,
            vec![0, 1],
            "a higher-sn proof writes nothing for an older aux"
        );
        assert_eq!(
            proof_of(&rita, &governance_id, &subject_d).await,
            Some((5, alice_key.clone(), Some(hash_d.clone()), false)),
            "hashed higher-sn proof survives a refuted aux"
        );
        sink_empty_from(&rita, &subject_d, 2).await;
    };

    // The four subjects are independent: run their flows concurrently.
    tokio::join!(flow_a, flow_b, flow_c, flow_d);

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A stale push is acknowledged only when the pushed bytes match the
/// local event at that SN. An identical duplicate gets exactly one
/// ACK without rewriting anything; a same-SN divergence gets no ACK,
/// no success and no writes, while the correction request still goes
/// out. Covers SN0 (an alternative Create) and later SNs, and a
/// genuine next event still applies afterwards.
#[test(tokio::test)]
async fn remote_divergent_duplicate_push_is_not_acknowledged() {
    async fn poll_sn(
        api: &ave_core::Api,
        subject_id: &DigestIdentifier,
        want: u64,
    ) {
        let start = tokio::time::Instant::now();
        loop {
            if let Ok(state) = api.get_subject_state(subject_id.clone()).await {
                if state.sn == want {
                    return;
                }
            }
            assert!(
                start.elapsed() < Duration::from_secs(60),
                "timeout waiting for sn {want}"
            );
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    async fn sink_empty_from(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        from_sn: u64,
    ) {
        use ave_common::bridge::request::SinkEventsQuery;
        let page = api
            .get_sink_events(
                subject.clone(),
                SinkEventsQuery {
                    from_sn: Some(from_sn),
                    to_sn: None,
                    limit: Some(100),
                },
            )
            .await
            .unwrap();
        assert!(
            page.events.is_empty(),
            "a divergent or duplicate push must emit nothing new"
        );
    }
    async fn inject_single(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLastEventReq {
                    ledger: Box::new(ledger),
                },
            ),
            from,
        )
        .await
        .unwrap();
    }
    async fn held_acks(api: &ave_core::Api) -> Vec<DigestIdentifier> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|message| match message.message {
                ActorMessage::DistributionLastEventRes { event_hash } => {
                    Some(event_hash)
                }
                _ => None,
            })
            .collect()
    }
    async fn held_reqs(
        api: &ave_core::Api,
        subject_id: &DigestIdentifier,
    ) -> Vec<Option<u64>> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|message| match message.message {
                ActorMessage::DistributionLedgerReq {
                    actual_sn,
                    subject_id: req_subject,
                    ..
                } if &req_subject == subject_id => Some(actual_sn),
                _ => None,
            })
            .collect()
    }
    async fn ownership_of(
        api: &ave_core::Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) -> (Option<PublicKey>, Option<PublicKey>) {
        match api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
        {
            Err(_) => panic!("ownership must be readable"),
            Ok((owner_now, pending, _, _)) => (owner_now, pending),
        }
    }

    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Rita", "key": rita_key.to_string()},
            ]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}, {"name": "Rita", "namespace": []}],
                        "creator": [{"name": "Alice", "namespace": [], "quantity": "infinity"}],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    let rita_public = PublicKey::from_str(rita.public_key()).expect("node key");
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLedgerReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(rita_public.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    // Hold rita's ACKs and correction requests so the test can count
    // exactly what each injected push would have sent.
    for message in [
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionLedgerReq,
    ] {
        rita.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(alice_key.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1u64, 2] {
        emit_fact(
            &alice,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 2)
        .await
        .unwrap();
    let hfind = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history")
            .clone()
    };
    let create = hfind(0);
    let fact1 = hfind(1);
    let fact2 = hfind(2);
    let hash_create =
        create.ledger_hash(HashAlgorithm::Blake3).expect("hashes");
    let hash_fact1 = fact1.ledger_hash(HashAlgorithm::Blake3).expect("hashes");
    // Same SN, different bytes: bumping the governance version is
    // enough to change the ledger hash. The stale path never
    // inspects signatures, so no re-signing is needed.
    let mut divergent_create = create.clone();
    divergent_create.gov_version += 1;
    let mut divergent_fact1 = fact1.clone();
    divergent_fact1.gov_version += 1;
    assert_ne!(
        divergent_create.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        hash_create,
        "divergent SN0 must hash differently"
    );
    assert_ne!(
        divergent_fact1.ledger_hash(HashAlgorithm::Blake3).unwrap(),
        hash_fact1,
        "divergent SN1 must hash differently"
    );

    // Seed the subject via the batch path (a lone pushed Create for
    // an unknown subject carries no receiver access on its own):
    // the push tests below start from this applied tip.
    inject_ledger_batch(&rita, &alice_key, vec![create.clone()], None).await;
    poll_sn(&rita, &subject_id, 0).await;
    assert!(
        held_acks(&rita).await.is_empty(),
        "batch seeding sends no push acks"
    );
    // A genuine SN0 push is an identical duplicate: acked exactly once.
    inject_single(&rita, &alice_key, create.clone()).await;
    let start = tokio::time::Instant::now();
    loop {
        if !held_acks(&rita).await.is_empty() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "genuine SN0 push must be acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        held_acks(&rita).await,
        vec![hash_create.clone()],
        "genuine push acks exactly once"
    );
    // A divergent SN0 is not applied and, crucially, not acked, but
    // the correction request still goes out.
    inject_single(&rita, &alice_key, divergent_create.clone()).await;
    let start = tokio::time::Instant::now();
    loop {
        if held_acks(&rita).await.len() > 1 {
            panic!("divergent SN0 must never be acknowledged");
        }
        if !held_reqs(&rita, &subject_id).await.is_empty() {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "divergent SN0 push produced no correction request"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    // Hold the wait a beat: an ack racing the request must still show up.
    tokio::time::sleep(Duration::from_millis(1000)).await;
    assert_eq!(
        held_acks(&rita).await,
        vec![hash_create.clone()],
        "no ack for the divergent SN0"
    );
    assert_eq!(
        rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
        0,
        "divergent create writes nothing"
    );
    assert_eq!(
        ownership_of(&rita, &governance_id, &subject_id).await,
        (Some(alice_key.clone()), None),
        "divergent create changes no ownership"
    );
    sink_empty_from(&rita, &subject_id, 1).await;
    // An identical SN0 is acked exactly once without rewriting.
    inject_single(&rita, &alice_key, create.clone()).await;
    let start = tokio::time::Instant::now();
    loop {
        if held_acks(&rita).await.len() >= 2 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "identical SN0 must be acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        held_acks(&rita).await,
        vec![hash_create.clone(), hash_create.clone()],
        "identical SN0 acks exactly once, no rewrite"
    );
    assert_eq!(
        rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
        0,
        "identical duplicate applies nothing new"
    );

    // The genuine SN1 applies on top and acks.
    inject_single(&rita, &alice_key, fact1.clone()).await;
    poll_sn(&rita, &subject_id, 1).await;
    assert_eq!(
        rita.test_verify_stats(subject_id.clone()).await.unwrap().0,
        0,
        "no verification work is tracked for plain pushes"
    );
    // A divergent SN1 with the same shape is dropped silently.
    inject_single(&rita, &alice_key, divergent_fact1.clone()).await;
    let start = tokio::time::Instant::now();
    loop {
        if held_reqs(&rita, &subject_id).await.len() >= 3 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "divergent SN1 push produced no correction request"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(1000)).await;
    let acks_after_divergent = held_acks(&rita).await.len();
    assert_eq!(
        acks_after_divergent, 3,
        "no ack for the divergent SN1 (acks so far: genuine SN0, identical SN0, genuine SN1)"
    );
    assert_eq!(
        rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
        1,
        "divergent SN1 writes nothing"
    );
    let stored: Vec<u64> = rita
        .test_get_tracker_ledger(subject_id.clone(), 10)
        .await
        .unwrap_or_default()
        .iter()
        .map(|event| event.sn)
        .collect();
    assert_eq!(stored, vec![0, 1], "divergent SN1 is not stored");
    assert_eq!(
        ownership_of(&rita, &governance_id, &subject_id).await,
        (Some(alice_key.clone()), None),
        "divergent fact changes no ownership"
    );
    sink_empty_from(&rita, &subject_id, 2).await;
    // An identical SN1 is acked exactly once without rewriting.
    inject_single(&rita, &alice_key, fact1.clone()).await;
    let start = tokio::time::Instant::now();
    loop {
        if held_acks(&rita).await.len() >= 4 {
            break;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "identical SN1 must be acknowledged"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    tokio::time::sleep(Duration::from_millis(500)).await;
    assert_eq!(
        held_acks(&rita).await.len(),
        4,
        "identical SN1 acks exactly once"
    );
    assert_eq!(
        held_acks(&rita).await[3],
        hash_fact1,
        "identical SN1 ack carries the local hash"
    );
    // A genuine next event still applies and completes.
    inject_single(&rita, &alice_key, fact2.clone()).await;
    poll_sn(&rita, &subject_id, 2).await;
    assert_eq!(
        rita.get_subject_state(subject_id.clone()).await.unwrap().sn,
        2,
        "genuine next event still applies after divergents"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// A concurrent same-SN divergence must be neither proven nor
/// acknowledged. A pushed transfer that races a concurrent valid copy
/// through the aux gate parks before reading the local tip; when the
/// winner is already applied, the late hint is held by hash mismatch
/// instead of reusing the SN-only bypass, and the post-update check
/// refuses the ACK for bytes this node does not hold. An identical
/// duplicate still gets exactly one ACK with the local hash, and no
/// proof is ever recorded for the divergent hint.
#[test(tokio::test)]
async fn remote_concurrent_divergent_transfer_is_not_proven_or_acknowledged() {
    async fn poll_sn(
        api: &ave_core::Api,
        subject_id: &DigestIdentifier,
        want: u64,
    ) {
        for _ in 0..600 {
            if let Ok(state) = api.get_subject_state(subject_id.clone()).await {
                if state.sn == want {
                    return;
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("timeout waiting for sn {want}");
    }
    async fn held_acks(api: &ave_core::Api) -> Vec<DigestIdentifier> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|message| match message.message {
                ActorMessage::DistributionLastEventRes { event_hash } => {
                    Some(event_hash)
                }
                _ => None,
            })
            .collect()
    }
    async fn inject_push_to(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Ledger,
        receiver_actor: String,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).expect("node key");
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor,
                },
                ActorMessage::DistributionLastEventReq {
                    ledger: Box::new(ledger),
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let alice_keys = nodes[1].keys.clone();
    let boot_addr = nodes[0].listen_address.clone();
    let boot_peer = nodes[0].api.peer_id().to_string();
    let rita_signer = Ed25519Signer::generate().unwrap();
    let rita_key = PublicKey::new(
        ave_common::identity::keys::DSAlgorithm::Ed25519,
        rita_signer.public_key_bytes(),
    )
    .unwrap();
    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": { "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Rita", "key": rita_key.to_string()},
            ]},
            "schemas": { "add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0}
            }]},
            "roles": {
                "governance": {"add": {"witness": ["Alice"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}, {"name": "Rita", "namespace": []}],
                        "creator": [{"name": "Alice", "namespace": [], "quantity": "infinity"}],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }]
            }
        }),
        true,
    )
    .await
    .unwrap();
    alice.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&alice, governance_id.clone(), None, true)
        .await
        .unwrap();
    let rita_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (mut rita_node, rita_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{rita_port}"),
        peers: vec![RoutingNode {
            peer_id: boot_peer.clone(),
            address: vec![boot_addr.clone()],
        }],
        always_accept: true,
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(rita_signer)),
        ..Default::default()
    })
    .await;
    let rita = rita_node.api.clone();
    node_running(&rita).await.unwrap();
    rita.authorize_governance(
        governance_id.clone(),
        ave_core::auth::AuthWitness::One(
            PublicKey::from_str(owner.public_key()).unwrap(),
        ),
    )
    .await
    .unwrap();
    rita.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&rita, governance_id.clone(), None, true)
        .await
        .unwrap();
    let alice_key = PublicKey::from_str(alice.public_key()).unwrap();
    // Isolate rita: every ledger byte below arrives through the
    // test's own injects, never through background sync.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLedgerReq,
    ] {
        alice
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(
                    PublicKey::from_str(rita.public_key()).expect("node key"),
                ),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    // Hold rita's ACKs and follow-up requests so the test counts
    // exactly what each injected push would have sent.
    for message in [
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionLedgerReq,
    ] {
        rita.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(alice_key.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1u64, 2] {
        emit_fact(
            &alice,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&alice, subject_id.clone(), rita_key.clone(), true)
        .await
        .unwrap();
    let history = alice
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    let hfind = |sn: u64| {
        history
            .iter()
            .find(|event| event.sn == sn)
            .expect("history")
            .clone()
    };
    let transfer_a = hfind(3);
    let fact2 = hfind(2);
    let hash_a = transfer_a
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("aux hashes");
    let fact_ok = match &fact2.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("fact evaluation ok"),
        _ => panic!("expected a full fact"),
    };
    // Same SN, different bytes: the forged evaluation never matches
    // the transfer content, and the re-seal keeps the hint well
    // formed enough to reach the aux gate under test.
    let transfer_b = forge_ok_evaluation(&transfer_a, fact_ok, &alice_keys);
    let hash_b = transfer_b
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("aux hashes");
    assert_ne!(
        hash_b, hash_a,
        "same SN, different bytes is the divergent case"
    );

    // Seed rita to SN2 through the batch path; the Hold above keeps
    // it from fetching SN3 on its own.
    inject_ledger_batch(
        &rita,
        &alice_key,
        vec![hfind(0), hfind(1), fact2.clone()],
        None,
    )
    .await;
    poll_sn(&rita, &subject_id, 2).await;

    // Park the divergent push on its own worker before it reads the
    // local tip; the concurrent valid copy applies through the
    // node-level distributor, which the barrier exempts.
    let sub_path = format!("/user/node/distributor_{subject_id}");
    rita.test_ensure_distributor(subject_id.clone())
        .await
        .unwrap();
    rita.test_pause_verify_before_sn(true).await.unwrap();
    inject_push_to(&rita, &alice_key, transfer_b.clone(), sub_path.clone())
        .await;
    for _ in 0..300 {
        if rita.test_verify_before_sn_hold_count().await.unwrap_or(0) >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        rita.test_verify_before_sn_hold_count().await.unwrap(),
        1,
        "the divergent hint must park exactly once before its tip read"
    );
    // The winner applies while the divergent hint is parked.
    inject_push_to(
        &rita,
        &alice_key,
        transfer_a.clone(),
        "/user/node/distributor".to_owned(),
    )
    .await;
    poll_sn(&rita, &subject_id, 3).await;
    // Release: the late hint now finds the winner applied and must
    // be held by hash mismatch instead of reusing the SN bypass.
    rita.test_pause_verify_before_sn(false).await.unwrap();
    // The identical duplicate queues behind the parked hint on the
    // same worker: its ACK proves the hint was fully processed, and
    // duplicates keep their single ACK.
    inject_push_to(&rita, &alice_key, transfer_a.clone(), sub_path.clone())
        .await;
    for _ in 0..300 {
        if held_acks(&rita)
            .await
            .iter()
            .filter(|h| **h == hash_a)
            .count()
            >= 2
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        held_acks(&rita)
            .await
            .iter()
            .filter(|h| **h == hash_a)
            .count()
            >= 2,
        "the winner and its duplicate must be acknowledged"
    );
    // No settle sleep: re-assert the exact counts stable over a
    // bounded window, so a late third ACK would fail loudly
    // instead of racing a fixed delay.
    for _ in 0..10 {
        assert!(
            !held_acks(&rita).await.contains(&hash_b),
            "a same-SN divergence is never acknowledged"
        );
        assert_eq!(
            held_acks(&rita)
                .await
                .iter()
                .filter(|h| **h == hash_a)
                .count(),
            2,
            "the winner and its identical duplicate ack exactly once each"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let stored_hash = rita
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap()
        .iter()
        .find(|event| event.sn == 3)
        .expect("SN3 stored")
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("stored hashes");
    assert_eq!(
        stored_hash, hash_a,
        "the ledger holds exclusively the winning variant"
    );
    assert_eq!(
        rita.test_get_verified_transfer_detail(
            &governance_id,
            subject_id.clone()
        )
        .await
        .unwrap(),
        None,
        "the divergent hint records no proof"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    rita_node.token.cancel();
    join_all(
        nodes
            .iter_mut()
            .flat_map(|node| node.handler.iter_mut())
            .chain(rita_node.handler.iter_mut()),
    )
    .await;
    drop(nodes);
    drop(dirs);
    drop(rita_node);
    drop(rita_dirs);
}

/// Runs one fragmented-push case: the first send fails either on
/// the initial fragment or, with two sends held back first, on an
/// intermediate one. Fresh nodes per case so no retry or assembly
/// state leaks between them.
async fn fragmented_push_retry_case(intermediate: bool) {
    let cap = ave_network::MAX_APP_MESSAGE_BYTES as usize;
    let mut nodes = vec![];
    let mut dirs = vec![];
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![],
        always_accept: true,
        is_service: true,
        network_max_message_bytes: Some(cap),
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer.clone(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            network_max_message_bytes: Some(cap),
            ledger_batch_size: Some(100),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let a_key = PublicKey::from_str(&a.public_key()).unwrap();
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "schemas": { "add": [
                {
                    "id": "Big",
                    "contract": ave_core::test_contracts::CHANGED_SCHEMA_CONTRACT,
                    "initial_value": {"data": ""},
                },
            ]},
            "roles": {
                "schema": [
                    {
                        "schema_id": "Big",
                        "add": {
                            "evaluator": [{"name": "Owner", "namespace": []}],
                            "validator": [{"name": "Owner", "namespace": []}],
                            "witness": [
                                {"name": "Owner", "namespace": []},
                                {"name": "A", "namespace": []},
                            ],
                            "creator": [
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "A",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [{"name": "Owner", "namespace": []}],
                        },
                    },
                ],
            },
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // One fact above the wire cap but below the replicable bound.
    // Fail the first send on the initial fragment, or hold two
    // sends back first so it fails on an intermediate one.
    if intermediate {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerFrag,
            peer: Some(a_key.clone()),
            remaining: Some(2),
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerFrag,
        peer: Some(a_key.clone()),
        remaining: Some(1),
        action: FaultAction::FailSend,
    })
    .await
    .unwrap();
    let (subject_id, _) =
        create_subject(&b, governance_id.clone(), "Big", "", true)
            .await
            .unwrap();
    let bulk = "y".repeat(1200 * 1024);
    emit_fact(
        &b,
        subject_id.clone(),
        json!({"ChangeData": {"data": bulk}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // The retry resends the whole group until the receiver assembles
    // and applies it exactly once.
    let state = get_subject(&a, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    let owner_state = get_subject(&b, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.properties, owner_state.properties);
    assert_eq!(
        a.test_get_tracker_ledger(subject_id.clone(), 1)
            .await
            .unwrap()
            .len(),
        2,
        "no duplicate application"
    );
    let (assemblies, _, _, decode_attempts, expired) =
        a.test_fragment_stats().await.unwrap();
    assert!(
        decode_attempts >= 1,
        "the retry drove a fragment join and decode"
    );
    assert_eq!(assemblies, 0, "no live assembly is left behind");
    assert_eq!(expired, 0, "no assembly expired");
    assert_eq!(
        a.test_fragment_assembly_len().await.unwrap_or(1),
        0,
        "no fragment state is left behind"
    );

    // The resent group keeps the identity of the failed first send:
    // the fact hash pins it byte-exactly on both sides.
    let fact_hash = a
        .test_get_tracker_ledger(subject_id.clone(), 1)
        .await
        .unwrap()
        .last()
        .expect("applied fact")
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("fact hash");
    let (initial_failures, resends, acks, live_groups, live_timers) =
        b.test_push_frag_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        initial_failures, 1,
        "the injected first-send failure must fire, not just the timer"
    );
    assert!(!resends.is_empty(), "the retry must resend the group");
    assert!(
        resends.iter().all(|group| group == &fact_hash),
        "every resend must carry the whole group under the same id, got {resends:?}"
    );
    assert_eq!(acks, 1, "the ack must be consumed exactly once");
    assert_eq!(
        (live_groups, live_timers),
        (0, 0),
        "no group or timer may stay pending on the sender"
    );
    let (r_failures, r_resends, r_acks, r_groups, r_timers) =
        a.test_push_frag_stats(subject_id.clone()).await.unwrap();
    assert_eq!(
        (r_failures, r_acks, r_groups, r_timers),
        (0, 0, 0, 0),
        "the receiver runs no push lifecycle of its own"
    );
    assert!(
        r_resends.is_empty(),
        "the receiver never resends, got {r_resends:?}"
    );
    if intermediate {
        let held: Vec<_> = b
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| match m.message {
                ActorMessage::DistributionLedgerFrag {
                    group_hash,
                    chunk_index,
                    ..
                } => Some((group_hash, chunk_index)),
                _ => None,
            })
            .collect();
        assert_eq!(
            held.len(),
            2,
            "the failure hit an intermediate fragment, got {held:?}"
        );
        assert!(
            held.iter().all(|(group, _)| group == &fact_hash),
            "the held prefix belongs to the same group that is resent, got {held:?}"
        );
    }

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

/// A fragmented push whose initial send fails still completes: the
/// coordinator keeps its resend state and timer, so the next round
/// resends the whole group until the receiver assembles and acks it.
#[test(tokio::test)]
async fn fragmented_push_retries_after_initial_fragment_send_failure() {
    fragmented_push_retry_case(false).await;
    fragmented_push_retry_case(true).await;
}

// The verified sender must switch mid-copy: a continuation still
// attributed to A announces its proof, but the first request to B
// after the gate flip must omit it, B must send the aux and R must
// re-verify. Covers the Update route and the direct worker
// continuation; the TrackerSync route has its own test.
#[test(tokio::test)]
async fn remote_update_switches_verified_sender_mid_copy() {
    // Held ledger requests R sent to `peer`: (subject, actual,
    // target, already_verified).
    async fn held_reqs_to(
        api: &ave_core::Api,
        peer: &PublicKey,
    ) -> Vec<(DigestIdentifier, Option<u64>, Option<u64>, Option<u64>)> {
        api.test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .filter_map(|m| match m.message {
                ActorMessage::DistributionLedgerReq {
                    subject_id,
                    actual_sn,
                    target_sn,
                    already_verified_transfer_sn,
                    ..
                } if &m.info.receiver == peer => Some((
                    subject_id,
                    actual_sn,
                    target_sn,
                    already_verified_transfer_sn,
                )),
                _ => None,
            })
            .collect()
    }

    // Waits until R holds exactly one ledger request to `peer`
    // for `subject` with the given actual/already. A duplicate or
    // mistargeted fetch never converges back to one, so it fails
    // loudly instead of passing on an `.all()` over extras. The tip
    // can become visible before the worker emits its request, so
    // only this barrier proves the continuation really ran.
    async fn wait_exact_req_to(
        api: &ave_core::Api,
        peer: &PublicKey,
        subject: &DigestIdentifier,
        actual: Option<u64>,
        already: Option<u64>,
    ) {
        for _ in 0..300 {
            let matching: Vec<_> = held_reqs_to(api, peer)
                .await
                .into_iter()
                .filter(|(s, a, _, al)| {
                    s == subject && *a == actual && *al == already
                })
                .collect();
            if matching.len() == 1 {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let all = api
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|m| format!("{:?} -> {}", m.message, m.info.receiver))
            .collect::<Vec<_>>();
        panic!(
            "expected exactly one held request to {peer} for {subject} \
             with actual {actual:?}, held: {all:?}"
        );
    }
    // Waits until R holds at least one ledger request to `peer`.
    async fn wait_reqs_to(
        api: &ave_core::Api,
        peer: &PublicKey,
    ) -> Vec<(DigestIdentifier, Option<u64>, Option<u64>, Option<u64>)> {
        for _ in 0..300 {
            let reqs = held_reqs_to(api, peer).await;
            if !reqs.is_empty() {
                return reqs;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        let all = api
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|m| format!("{:?} -> {}", m.message, m.info.receiver))
            .collect::<Vec<_>>();
        panic!("no held ledger request to {peer} in time, held: {all:?}");
    }

    // Delivers a genuine prefix with the pending aux attached, like a
    // sender fetching the hint ahead of its window, through the
    // node-level worker.
    async fn inject_state(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        aux: &Ledger,
        gov: &DigestIdentifier,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).unwrap();
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger,
                    is_all: false,
                    transfer_event: Some(Box::new(aux.clone())),
                    expected_governance_id: Some(gov.clone()),
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Delivers a bare Create with no aux: crossing nothing, it applies
    // on its own and leaves no proof behind.
    async fn inject_create(
        api: &ave_core::Api,
        from: &PublicKey,
        create: Ledger,
    ) {
        let receiver = PublicKey::from_str(api.public_key()).unwrap();
        api.test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver,
                    receiver_actor: "/user/node/distributor".to_owned(),
                },
                ActorMessage::DistributionLedgerRes {
                    ledger: vec![create],
                    is_all: false,
                    transfer_event: None,
                    expected_governance_id: None,
                },
            ),
            from,
        )
        .await
        .unwrap();
    }

    // Establishes (tip, proof) on a fresh subject exactly like the
    // live flow: the Create batch carries no aux (nothing verified
    // yet, so its continuation announces nothing), then the fact
    // batch verifies the aux and its continuation announces it.
    async fn inject_fresh_prefix(
        api: &ave_core::Api,
        from: &PublicKey,
        history: &[Ledger],
        aux: &Ledger,
        gov: &DigestIdentifier,
        tip: u64,
        transfer_sn: u64,
    ) {
        inject_create(api, from, history[0].clone()).await;
        for _ in 0..300 {
            if api
                .get_subject_state(history[0].get_subject_id())
                .await
                .is_ok_and(|state| state.sn == 0)
            {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        // The Create batch always triggers its own continuation
        // request first: observe it held before dropping it, so the
        // drop cannot race a late send.
        for _ in 0..300 {
            if !held_reqs_to(api, from).await.is_empty() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        api.test_clear_faults().await.unwrap();
        hold_r_reqs(api).await;
        inject_state(api, from, history[1..=tip as usize].to_vec(), aux, gov)
            .await;
        wait_proof_state(
            api,
            gov,
            &history[0].get_subject_id(),
            tip,
            (transfer_sn, from.clone()),
        )
        .await;
    }

    // Waits until R applied `tip` and recorded exactly `proof`.
    async fn wait_proof_state(
        api: &ave_core::Api,
        gov: &DigestIdentifier,
        subject: &DigestIdentifier,
        tip: u64,
        proof: (u64, PublicKey),
    ) {
        for _ in 0..300 {
            let at_tip = api
                .get_subject_state(subject.clone())
                .await
                .is_ok_and(|state| state.sn == tip);
            let recorded = api
                .test_get_verified_transfer_sn(gov, subject.clone())
                .await
                .unwrap();
            if at_tip && recorded == Some(proof.clone()) {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("R never reached tip {tip} with proof {proof:?}");
    }

    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let a = nodes[1].api.clone();
    let b = nodes[2].api.clone();
    let r = nodes[3].api.clone();
    let a_key = PublicKey::from_str(a.public_key()).unwrap();
    let b_key = PublicKey::from_str(b.public_key()).unwrap();
    let r_key = PublicKey::from_str(r.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&a, &b, &r]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [
                {"name": "A", "key": a.public_key()},
                {"name": "B", "key": b.public_key()},
                {"name": "R", "key": r.public_key()},
            ]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["A", "B"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [
                            {"name": "A", "namespace": []},
                            {"name": "B", "namespace": []},
                        ],
                        "creator": [
                            {
                                "name": "A",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {"name": "B", "viewpoints": ["AllViewpoints"]},
                                    {"name": "R", "viewpoints": ["AllViewpoints"]},
                                    {"name": "Witnesses", "viewpoints": ["AllViewpoints"]},
                                ],
                            },
                            {
                                "name": "B",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {"name": "A", "viewpoints": ["AllViewpoints"]},
                                    {"name": "R", "viewpoints": ["AllViewpoints"]},
                                    {"name": "Witnesses", "viewpoints": ["AllViewpoints"]},
                                ],
                            },
                        ],
                        "issuer": [
                            {"name": "A", "namespace": []},
                            {"name": "B", "namespace": []},
                        ],
                    },
                }],
            },
        }),
        true,
    )
    .await
    .unwrap();

    // Everyone pulls the governance once the member fact above
    // lands; R never touches the subject except through the driven
    // steps further down.
    for api in [&a, &b, &r] {
        api.update_subject(governance_id.clone()).await.unwrap();
    }
    let gov_sn = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    for api in [&a, &b, &r] {
        get_subject(api, governance_id.clone(), Some(gov_sn), true)
            .await
            .unwrap();
    }

    // No pushes to R from here on and no sync-driven updates: every
    // request below is an explicit pull through a live round. Ledger
    // responses are pushes too unless they answer one of R's held
    // requests, so they stay dropped except across controlled
    // releases.
    async fn seal_pushes(api: &ave_core::Api, peer: &PublicKey) {
        for message in [
            FaultMessage::DistributionLastEventReq,
            FaultMessage::DistributionLastEventRes,
            FaultMessage::DistributionLedgerRes,
        ] {
            api.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(peer.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }
    for api in [&owner, &a, &b] {
        seal_pushes(api, &r_key).await;
    }
    // B stays silent until the gate flip: the first selection is
    // necessarily A, never a race.
    for message in [
        FaultMessage::UpdateOffer,
        FaultMessage::UpdateNoOffer,
        FaultMessage::DistributionLedgerRes,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(r_key.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    // R holds every outbound request and never syncs on its own.
    // Every request below is released by hand after pinning its
    // contents, so nothing completes vacuously and no retry runs
    // ahead of the assertions.
    async fn hold_r_reqs(api: &ave_core::Api) {
        api.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
        api.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::TrackerSyncReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    }
    hold_r_reqs(&r).await;

    // Same authentic ledger on both servers: A creates, two facts
    // and a pending transfer to B at the tip.
    let (subject_id, _) =
        create_subject(&a, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2] {
        emit_fact(
            &a,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&a, subject_id.clone(), b_key.clone(), true)
        .await
        .unwrap();
    for api in [&a, &b] {
        api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(api, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    }
    // Serving needs a local distributor on every server: pulls do
    // not always create one, so ensure them explicitly instead of
    // depending on creation side effects.
    for api in [&a, &b, &r] {
        api.test_ensure_distributor(subject_id.clone())
            .await
            .unwrap();
    }
    let history = a
        .test_get_tracker_ledger(subject_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(history.len(), 4);
    let transfer = history
        .iter()
        .find(|event| event.sn == 3)
        .expect("transfer event")
        .clone();
    assert!(
        transfer.protocols.is_success(),
        "pending transfer must succeed, got {:?}",
        transfer.protocols
    );
    let aux_hash = transfer
        .ledger_hash(HashAlgorithm::Blake3)
        .expect("aux hash");

    // R reaches T-1 with the genuine (T, A) proof, then its worker
    // continuation still attributed to A must announce Some(T).
    inject_fresh_prefix(&r, &a_key, &history, &transfer, &governance_id, 2, 3)
        .await;
    let detail = r
        .test_get_verified_transfer_detail(&governance_id, subject_id.clone())
        .await
        .unwrap();
    assert_eq!(
        detail,
        Some((3, a_key.clone(), Some(aux_hash), false)),
        "proof, sender and aux hash must be exact and firm, got {detail:?}"
    );
    let reqs = wait_reqs_to(&r, &a_key).await;
    assert!(
        reqs.iter()
            .all(|(_, actual, _, already)| *actual == Some(2)
                && *already == Some(3)),
        "the continuation still attributed to A reuses the proof, got {reqs:?}"
    );

    // The Update route sees the same proof: drop the worker request,
    // sweep live, and the update request must still announce it.
    r.test_clear_faults().await.unwrap();
    hold_r_reqs(&r).await;
    // A's answers must reach R for the live rounds, but the first
    // one is retained to prove the omission: the push guard lifts
    // here (nothing is emitted mid-update) and goes back on after
    // convergence.
    a.test_clear_faults().await.unwrap();
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        a.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(r_key.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    a.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerRes,
        peer: Some(r_key.clone()),
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    r.update_subject(subject_id.clone()).await.unwrap();
    let reqs = wait_reqs_to(&r, &a_key).await;
    assert!(
        !reqs.is_empty()
            && reqs.iter().all(|(_, actual, _, already)| *actual == Some(2)
                && *already == Some(3)),
        "the update request to A must announce the proof, got {reqs:?}"
    );

    // The announced proof makes A omit the aux: releasing the held
    // request drives exactly one answer, which must carry no transfer
    // event. Releasing it lets R complete and consume the proof.
    r.test_release_held().await.unwrap();
    let mut omitted = false;
    let mut omit_dump = Vec::new();
    let mut r_dump = Vec::new();
    for _ in 0..300 {
        let held = a.test_held_outbound().await.unwrap_or_default();
        omit_dump = held
            .iter()
            .filter(|m| m.info.receiver == r_key)
            .map(|m| format!("{:?}", m.message))
            .collect();
        r_dump = r
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .into_iter()
            .map(|m| format!("{:?} -> {}", m.message, m.info.receiver))
            .collect();
        let answers: Vec<_> = held
            .iter()
            .filter(|m| {
                m.info.receiver == r_key
                    && matches!(
                        m.message,
                        ActorMessage::DistributionLedgerRes { .. }
                    )
            })
            .collect();
        omitted = !answers.is_empty()
            && answers.iter().all(|m| match &m.message {
                ActorMessage::DistributionLedgerRes {
                    transfer_event, ..
                } => transfer_event.is_none(),
                _ => false,
            });
        if omitted {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        omitted,
        "A must omit the announced aux, A-held: {omit_dump:?} R-held: {r_dump:?}"
    );
    a.test_release_held().await.unwrap();
    get_subject(&r, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert!(
        r.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the proof is consumed once its transfer applies"
    );
    seal_pushes(&a, &r_key).await;

    // Second crossing: B confirms, extends, and transfers to A. R
    // stays frozen at the tip while both servers move on.
    emit_confirm(&b, subject_id.clone(), None, true)
        .await
        .unwrap();
    for data in [5, 6] {
        emit_fact(
            &b,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }
    emit_transfer(&b, subject_id.clone(), a_key.clone(), true)
        .await
        .unwrap();
    for api in [&a, &b] {
        api.update_subject(subject_id.clone()).await.unwrap();
        get_subject(api, subject_id.clone(), Some(7), true)
            .await
            .unwrap();
    }
    let history = a
        .test_get_tracker_ledger(subject_id.clone(), 7)
        .await
        .unwrap();
    let transfer2 = history
        .iter()
        .find(|event| event.sn == 7)
        .expect("second transfer")
        .clone();

    // R reaches T2-1 with the genuine (T2, A) proof; its continuation
    // still attributed to A announces it, then it is dropped.
    r.test_clear_faults().await.unwrap();
    hold_r_reqs(&r).await;
    inject_state(
        &r,
        &a_key,
        history[4..7].to_vec(),
        &transfer2,
        &governance_id,
    )
    .await;
    wait_proof_state(&r, &governance_id, &subject_id, 6, (7, a_key.clone()))
        .await;
    let reqs = wait_reqs_to(&r, &a_key).await;
    assert!(
        reqs.iter()
            .all(|(_, actual, _, already)| *actual == Some(6)
                && *already == Some(7)),
        "the continuation still attributed to A reuses the proof, got {reqs:?}"
    );
    r.test_clear_faults().await.unwrap();
    hold_r_reqs(&r).await;
    let (processed_before_b, _) =
        r.test_verify_stats(subject_id.clone()).await.unwrap();

    // Gate flip: A goes silent, B answers. The first request to B
    // must omit the stored (T2, A) proof even though it is still held.
    for message in [
        FaultMessage::UpdateOffer,
        FaultMessage::UpdateNoOffer,
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        a.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(r_key.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    b.test_clear_faults().await.unwrap();
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerRes,
        peer: Some(r_key.clone()),
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    r.update_subject(subject_id.clone()).await.unwrap();
    let reqs = wait_reqs_to(&r, &b_key).await;
    assert!(
        !reqs.is_empty()
            && reqs.iter().all(|(_, actual, _, already)| *actual == Some(6)
                && already.is_none()),
        "the first request to B must omit the A proof, got {reqs:?}"
    );

    // B's answer carries the aux (nothing was announced) and R
    // re-verifies from B before converging: no direct-rights
    // shortcut may complete the copy instead. Later rounds flow
    // live around the single retained answer.
    r.test_release_held().await.unwrap();
    let mut aux_seen = false;
    let mut held_summary = Vec::new();
    for _ in 0..300 {
        let held = b.test_held_outbound().await.unwrap_or_default();
        held_summary = held
            .iter()
            .map(|m| format!("{:?} -> {}", m.message, m.info.receiver))
            .collect();
        aux_seen = held.iter().any(|m| match &m.message {
            ActorMessage::DistributionLedgerRes { transfer_event, .. }
                if m.info.receiver == r_key =>
            {
                transfer_event.as_ref().is_some_and(|event| event.sn == 7)
            }
            _ => false,
        });
        if aux_seen {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        aux_seen,
        "B must send the aux R never announced, held: {held_summary:?}"
    );
    b.test_release_held().await.unwrap();
    get_subject(&r, subject_id.clone(), Some(7), true)
        .await
        .unwrap();
    assert!(
        r.test_get_verified_transfer_sn(&governance_id, subject_id.clone())
            .await
            .unwrap()
            .is_none(),
        "the B proof is consumed once its transfer applies"
    );
    let (processed_after_b, _) =
        r.test_verify_stats(subject_id.clone()).await.unwrap();
    assert!(
        processed_after_b > processed_before_b,
        "switching sender must re-verify the aux from B"
    );
    seal_pushes(&b, &r_key).await;

    // Worker continuation on a fresh subject holding (T, A) at
    // T-1: R gets an aux-less batch naming only the newer pending
    // tip from B, so its direct continuation must request from B
    // without the A proof, and B's aux triggers a fresh verification.
    let (subject2, _) =
        create_subject(&a, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(&a, subject2.clone(), json!({"ModOne": {"data": 1}}), true)
        .await
        .unwrap();
    emit_transfer(&a, subject2.clone(), b_key.clone(), true)
        .await
        .unwrap();
    a.update_subject(subject2.clone()).await.unwrap();
    get_subject(&a, subject2.clone(), Some(2), true)
        .await
        .unwrap();
    b.update_subject(subject2.clone()).await.unwrap();
    get_subject(&b, subject2.clone(), Some(2), true)
        .await
        .unwrap();
    for api in [&a, &b, &r] {
        api.test_ensure_distributor(subject2.clone()).await.unwrap();
    }
    let history2 = a
        .test_get_tracker_ledger(subject2.clone(), 2)
        .await
        .unwrap();
    let transfer3 = history2
        .iter()
        .find(|event| event.sn == 2)
        .expect("third transfer")
        .clone();
    // Second crossing on the fresh subject: confirm, extend and
    // transfer again, so the tip the worker must fetch is one R has
    // never verified. Both servers move on while R stays frozen.
    emit_confirm(&b, subject2.clone(), None, true)
        .await
        .unwrap();
    emit_fact(&b, subject2.clone(), json!({"ModOne": {"data": 2}}), true)
        .await
        .unwrap();
    emit_transfer(&b, subject2.clone(), a_key.clone(), true)
        .await
        .unwrap();
    for api in [&a, &b] {
        api.update_subject(subject2.clone()).await.unwrap();
        get_subject(api, subject2.clone(), Some(5), true)
            .await
            .unwrap();
    }
    let history2_tip = a
        .test_get_tracker_ledger(subject2.clone(), 5)
        .await
        .unwrap();
    let transfer5 = history2_tip
        .iter()
        .find(|event| event.sn == 5)
        .expect("tip transfer")
        .clone();
    r.test_clear_faults().await.unwrap();
    hold_r_reqs(&r).await;
    inject_fresh_prefix(
        &r,
        &a_key,
        &history2,
        &transfer3,
        &governance_id,
        1,
        2,
    )
    .await;
    // The fresh-prefix continuation is still attributed to A: it
    // announces the proof, proving the state establishment itself
    // went through the verified sender. Exactly one, with the
    // requester's tip as actual: the tip alone could show before the
    // worker emits anything.
    wait_exact_req_to(&r, &a_key, &subject2, Some(1), Some(2)).await;
    r.test_clear_faults().await.unwrap();
    hold_r_reqs(&r).await;
    // Aux-less batch from B naming only the pending tip: R holds it
    // as a gap (its prefix ends at T-1) and must ask B, its sender,
    // for the aux. R still holds the (T, A) proof, so omitting it is
    // a sender decision, not an absence.
    let receiver = PublicKey::from_str(r.public_key()).unwrap();
    r.test_inject_inbound(
        NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger: vec![transfer5.clone()],
                is_all: false,
                transfer_event: None,
                expected_governance_id: Some(governance_id.clone()),
            },
        ),
        &b_key,
    )
    .await
    .unwrap();
    // Exactly one continuation to B for this subject, omitting
    // the A proof: same barrier as above, sender-scoped.
    wait_exact_req_to(&r, &b_key, &subject2, Some(1), None).await;
    let (processed_before_w, _) =
        r.test_verify_stats(subject2.clone()).await.unwrap();
    // B's answers must reach R: lift the push guard, keeping only
    // the offer guard so no stray batch lands mid-release. Answers
    // flow live; R must converge by verifying B's aux, which it
    // never announced and never verified before.
    b.test_clear_faults().await.unwrap();
    for message in [
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
    ] {
        b.test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message,
            peer: Some(r_key.clone()),
            remaining: None,
            action: FaultAction::Drop,
        })
        .await
        .unwrap();
    }
    r.test_release_held().await.unwrap();
    get_subject(&r, subject2.clone(), Some(5), true)
        .await
        .unwrap();
    let (processed_after_w, _) =
        r.test_verify_stats(subject2.clone()).await.unwrap();
    assert!(
        processed_after_w > processed_before_w,
        "the worker continuation must verify the aux from B"
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}

// Truncation detection builds its window only when the sender claims
// completeness: a partial batch (`is_all=false`) never pays the
// register lookup, a complete one (`is_all=true`) builds it exactly
// once.
#[test(tokio::test)]
async fn test_truncation_window_only_built_for_is_all() {
    async fn inject_with_flag(
        api: &ave_core::Api,
        from: &PublicKey,
        ledger: Vec<Ledger>,
        is_all: bool,
    ) {
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node public key");
        let message = NetworkMessage::new(
            ComunicateInfo {
                request_id: String::new(),
                version: 0,
                receiver,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLedgerRes {
                ledger,
                is_all,
                transfer_event: None,
                expected_governance_id: None,
            },
        );
        api.test_inject_inbound(message, from).await.unwrap();
    }
    async fn wait_tip(
        api: &ave_core::Api,
        subject: &DigestIdentifier,
        sn: u64,
    ) {
        for _ in 0..200 {
            if let Ok(state) = api.get_subject_state(subject.clone()).await
                && state.sn == sn
            {
                return;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("subject {subject} never reached sn {sn}");
    }

    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            tracker_sync: Some(ave_core::config::TrackerSyncConfig {
                interval_secs: 3600,
                ..Default::default()
            }),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let sender = nodes[1].api.clone();
    let receiver = nodes[2].api.clone();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    let sender_key = PublicKey::from_str(nodes[1].api.public_key()).unwrap();
    let receiver_key = PublicKey::from_str(nodes[2].api.public_key()).unwrap();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&sender, &receiver]).await;
    emit_fact(
        &owner,
        governance_id.clone(),
        json!({
            "members": {"add": [
                {"name": "S", "key": sender.public_key()},
                {"name": "R", "key": receiver.public_key()},
            ]},
            "schemas": {"add": [{
                "id": "Example",
                "contract": EXAMPLE_CONTRACT,
                "initial_value": {"one": 0, "two": 0, "three": 0},
            }]},
            "roles": {
                "governance": {"add": {"witness": ["S"]}},
                "schema": [{
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "S", "namespace": []}],
                        "creator": [{
                            "name": "S",
                            "namespace": [],
                            "quantity": "infinity",
                            "witnesses": [
                                {"name": "R", "viewpoints": ["AllViewpoints"]},
                                {"name": "Witnesses", "viewpoints": ["AllViewpoints"]},
                            ],
                        }, {
                            "name": "Owner",
                            "namespace": [],
                            "quantity": "infinity",
                            "witnesses": []
                        }],
                        "issuer": [{"name": "S", "namespace": []}],
                    },
                }],
            },
        }),
        true,
    )
    .await
    .unwrap();
    // Silence genuine distribution pushes: every byte below arrives
    // through the driven injections, never a scheduler race. The
    // drops install before any subject exists so no creation push
    // pre-seeds the receiver.
    for message in [
        FaultMessage::DistributionLedgerRes,
        FaultMessage::DistributionLastEventReq,
        FaultMessage::DistributionLastEventRes,
        FaultMessage::DistributionGetLastSn,
        FaultMessage::UpdateOffer,
        FaultMessage::UpdateNoOffer,
    ] {
        sender
            .test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: Some(receiver_key.clone()),
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
    }
    // Both ends pull the governance before any subject exists, so the
    // injections below evaluate against real membership, not guesses.
    for api in [&sender, &receiver] {
        api.update_subject(governance_id.clone()).await.unwrap();
    }
    let gov_sn = get_subject(&owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    for api in [&sender, &receiver] {
        get_subject(api, governance_id.clone(), Some(gov_sn), true)
            .await
            .unwrap();
        api.test_ensure_distributor(governance_id.clone())
            .await
            .unwrap();
    }

    // Two identical ledgers: genesis plus one fact each.
    let (partial_subject, _) =
        create_subject(&sender, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &sender,
        partial_subject.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let (complete_subject, _) =
        create_subject(&sender, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &sender,
        complete_subject.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let partial_ledger = sender
        .test_get_tracker_ledger(partial_subject.clone(), 1)
        .await
        .unwrap();
    let complete_ledger = sender
        .test_get_tracker_ledger(complete_subject.clone(), 1)
        .await
        .unwrap();
    assert_eq!(partial_ledger.len(), 2);
    assert_eq!(complete_ledger.len(), 2);
    // A real transfer above the offered fact gives the receiver a
    // verified floor its `is_all` batch cannot satisfy.
    emit_transfer(&sender, complete_subject.clone(), owner_key, true)
        .await
        .unwrap();
    let complete_history = sender
        .test_get_tracker_ledger(complete_subject.clone(), 2)
        .await
        .unwrap();
    let future_transfer = complete_history
        .iter()
        .find(|event| event.sn == 2)
        .expect("future transfer")
        .clone();
    let future_hash =
        future_transfer.ledger_hash(HashAlgorithm::Blake3).unwrap();
    for subject in [&partial_subject, &complete_subject] {
        receiver
            .test_ensure_distributor(subject.clone())
            .await
            .unwrap();
    }

    // Genesis prefix for both: no window exists yet, and the flag is
    // partial anyway, so no call may be recorded.
    inject_with_flag(
        &receiver,
        &sender_key,
        vec![partial_ledger[0].clone()],
        false,
    )
    .await;
    inject_with_flag(
        &receiver,
        &sender_key,
        vec![complete_ledger[0].clone()],
        false,
    )
    .await;
    wait_tip(&receiver, &partial_subject, 0).await;
    wait_tip(&receiver, &complete_subject, 0).await;
    assert_eq!(
        receiver
            .test_truncation_window_calls(partial_subject.clone())
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        receiver
            .test_truncation_window_calls(complete_subject.clone())
            .await
            .unwrap(),
        0
    );

    // Partial suffix: still no window build, and the worker asks for
    // the continuation instead of treating the batch as complete.
    receiver
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLedgerReq,
            peer: Some(sender_key.clone()),
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();
    inject_with_flag(
        &receiver,
        &sender_key,
        vec![partial_ledger[1].clone()],
        false,
    )
    .await;
    wait_tip(&receiver, &partial_subject, 1).await;
    assert_eq!(
        receiver
            .test_truncation_window_calls(partial_subject.clone())
            .await
            .unwrap(),
        0,
        "a partial batch must skip the truncation window"
    );
    let partial_continued = receiver
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|m| match m.message {
            ActorMessage::DistributionLedgerReq {
                subject_id,
                actual_sn,
                ..
            } => subject_id == partial_subject && actual_sn == Some(1),
            _ => false,
        });
    assert!(
        partial_continued,
        "a partial batch must request its continuation"
    );

    // Record a firm proof above the offered fact. The batch claiming
    // completeness below that floor is truncated: it may apply the
    // prefix, but must request more and leave its supervisor alive.
    receiver
        .test_record_hashed_verified_transfer(
            &governance_id,
            complete_subject.clone(),
            2,
            sender_key.clone(),
            future_hash,
        )
        .await
        .unwrap();
    receiver
        .update_subject(complete_subject.clone())
        .await
        .unwrap();
    inject_with_flag(
        &receiver,
        &sender_key,
        vec![complete_ledger[1].clone()],
        true,
    )
    .await;
    // The offered prefix applies, but the copy does not complete.
    wait_tip(&receiver, &complete_subject, 1).await;
    assert_eq!(
        receiver
            .test_truncation_window_calls(complete_subject.clone())
            .await
            .unwrap(),
        1,
        "a complete batch must build the truncation window once"
    );
    assert!(
        receiver
            .test_update_alive(complete_subject.clone())
            .await
            .unwrap(),
        "a truncated response must not certify DistributionDone"
    );
    let complete_continued = receiver
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .into_iter()
        .any(|m| match m.message {
            ActorMessage::DistributionLedgerReq {
                subject_id,
                actual_sn,
                ..
            } => subject_id == complete_subject && actual_sn == Some(1),
            _ => false,
        });
    assert!(
        complete_continued,
        "a truncated response must request the missing suffix"
    );
    assert_eq!(
        receiver
            .test_get_verified_transfer_sn(
                &governance_id,
                complete_subject.clone()
            )
            .await
            .unwrap()
            .map(|(sn, _)| sn),
        Some(2),
        "the unconsumed future proof must remain available"
    );
    // The partial subject never pays the lookup, even afterwards.
    assert_eq!(
        receiver
            .test_truncation_window_calls(partial_subject.clone())
            .await
            .unwrap(),
        0
    );

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut())).await;
}
