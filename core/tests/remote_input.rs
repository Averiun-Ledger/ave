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
    DigestIdentifier, HashAlgorithm, PublicKey, Signature, Signed, TimeStamp,
    hash_borsh,
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
    let alice_keys = nodes[1].keys.clone();
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

    // Same request, validator quorum and chain link; only the
    // evaluation is swapped to a genuine Ok result from the fact.
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
                ledger: vec![create.clone(), fact.clone(), forged.clone()],
                is_all: true,
                transfer_event: None,
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
    let alice_keys = nodes[1].keys.clone();
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

    // Forge SN 1 by swapping in the transfer's Ok result while
    // keeping the fact's own result hash: light checks pass, only
    // the evaluation recheck can catch it. Fresh owner seal over the
    // genuine chain link.
    let transfer_result = match &transfer.protocols {
        Protocols::Transfer { evaluation, .. } => evaluation
            .evaluator_response_ok()
            .expect("transfer evaluation ok"),
        _ => panic!("expected a transfer event"),
    };
    let mut forged = fact.clone();
    match &mut forged.protocols {
        Protocols::TrackerFactFull { evaluation, .. } => {
            let old_hash = match &evaluation.response {
                EvaluationResponse::Ok { result_hash, .. }
                | EvaluationResponse::Error { result_hash, .. } => {
                    result_hash.clone()
                }
            };
            evaluation.response = EvaluationResponse::Ok {
                result: transfer_result,
                result_hash: old_hash,
            };
        }
        _ => panic!("expected a full fact event"),
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
    get_subject(&alice, subject_id.clone(), Some(4), true).await.unwrap();
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
    rita
        .authorize_governance(
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
    rita
        .test_set_deferred_limits(
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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
    inject_with_hint(
        &rita,
        &alice_key,
        vec![create.clone()],
        false,
        &transfer,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!(
        (subjects, events),
        (1, 1),
        "one staged event under one subject"
    );
    assert!(bytes > 0, "retained bytes must be accounted");
    // The next continuation replays only its suffix and stays
    // deferred inside the same budget.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact1.clone()],
        false,
        &transfer,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_id).await;
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!(
        (subjects, events),
        (1, 2),
        "the continuation extends the same entry"
    );
    assert!(bytes > 0, "retained bytes must be accounted");
    // Over budget: the whole entry is dropped instead of growing
    // forever. Silence afterwards leaves no key and no counters.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![fact2.clone()],
        false,
        &transfer,
    )
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
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_id.clone()
            )
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
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_id.clone()
            )
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
        get_subject(api, subject_id.clone(), Some(3), true).await.unwrap();
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
    rita
        .authorize_governance(
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
    rita
        .test_set_deferred_limits(
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_a(0)],
        false,
        &transfer_a,
    )
    .await;
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_a(1)],
        false,
        &transfer_a,
    )
    .await;
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_b(0)],
        false,
        &transfer_b,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_a).await;
    assert_no_trace(&rita, &governance_id, &subject_b).await;
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (2, 3));
    assert!(bytes > 0, "retained bytes must be accounted");
    // The fourth staged event overflows the global budget: the
    // oldest chain goes away as a whole while the other keeps
    // its staged prefix.
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_b(1)],
        false,
        &transfer_b,
    )
    .await;
    assert_no_trace(&rita, &governance_id, &subject_a).await;
    assert_no_trace(&rita, &governance_id, &subject_b).await;
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
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
    let (processed_before, _) = rita
        .test_verify_stats(subject_b.clone())
        .await
        .unwrap();
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_b(2)],
        false,
        &transfer_b,
    )
    .await;
    get_subject(&rita, subject_b.clone(), Some(2), true).await.unwrap();
    let (processed_after, _) = rita
        .test_verify_stats(subject_b.clone())
        .await
        .unwrap();
    assert_eq!(
        processed_after - processed_before,
        2,
        "the surviving cursor resumes instead of rebuilding"
    );
    assert_eq!(
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_b.clone()
            )
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
    let (processed_before, _) = rita
        .test_verify_stats(subject_a.clone())
        .await
        .unwrap();
    inject_with_hint(
        &rita,
        &alice_key,
        vec![event_a(0), event_a(1), event_a(2)],
        false,
        &transfer_a,
    )
    .await;
    get_subject(&rita, subject_a.clone(), Some(2), true).await.unwrap();
    let (processed_after, _) = rita
        .test_verify_stats(subject_a.clone())
        .await
        .unwrap();
    assert_eq!(
        processed_after - processed_before,
        3,
        "the evicted chain rebuilds authoritatively once"
    );
    assert_eq!(
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_a.clone()
            )
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
    get_subject(&rita, subject_a.clone(), Some(3), true).await.unwrap();
    assert!(
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_a.clone()
            )
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
    rita
        .authorize_governance(
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
    let rita_public =
        PublicKey::from_str(rita.public_key()).expect("node key");
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
    get_subject(&alice, subject_id.clone(), Some(3), true).await.unwrap();
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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
    get_subject(&rita, subject_id.clone(), Some(2), true).await.unwrap();
    assert!(
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_id.clone()
            )
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
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_id.clone()
            )
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
        let (subjects, events, _) =
            rita.test_deferred_stats().await.unwrap();
        if (subjects, events) == (1, 1) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
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
    rita
        .test_set_deferred_limits(
            ave_core::distribution::deferred::DeferredLimits::production(),
        )
        .await
        .unwrap();
    inject_with_hint(
        &rita,
        &alice_key,
        vec![hinted.clone()],
        true,
        &hinted,
    )
    .await;
    get_subject(&rita, subject_id.clone(), Some(3), true).await.unwrap();
    assert!(
        rita
            .test_get_verified_transfer_sn(
                &governance_id,
                subject_id.clone()
            )
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
    rita
        .authorize_governance(
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
    rita
        .add_sync_peer(
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
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
        let rita_gov_sn =
            get_subject(&rita, governance_id.clone(), None, true)
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
        rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
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
    rita
        .authorize_governance(
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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
    for _ in 0..200 {
        let alice_gov_sn =
            get_subject(&alice, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
        if alice_gov_sn > gov_before {
            break;
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
    for _ in 0..200 {
        let rita_gov_sn =
            get_subject(&rita, governance_id.clone(), None, true)
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
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1), "one staged event");
    assert!(bytes > 0, "retained bytes must be accounted");
    assert!(
        rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
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
    rita.test_evict_verify_cursor(subject_id.clone()).await.unwrap();
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1), "eviction keeps the staged entry");
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
        rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
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
        rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
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
    rita
        .authorize_governance(
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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

    // Revoke Rita's witness grant while every link is unfaulted.
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
    for _ in 0..200 {
        let alice_gov_sn =
            get_subject(&alice, governance_id.clone(), None, true)
                .await
                .unwrap()
                .sn;
        if alice_gov_sn > gov_before {
            break;
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
    for _ in 0..200 {
        let rita_gov_sn =
            get_subject(&rita, governance_id.clone(), None, true)
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
        "rita must sync the revoking governance version first"
    );

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
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 1), "one staged event");
    assert!(bytes > 0, "retained bytes must be accounted");
    assert!(
        rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
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
    let (subjects, events, bytes) =
        rita.test_deferred_stats().await.unwrap();
    assert_eq!((subjects, events), (1, 2), "two staged events");
    assert!(bytes > 0, "retained bytes must be accounted");
    assert!(
        rita
            .test_get_verified_transfer_sn(&governance_id, subject_id.clone())
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
    rita
        .authorize_governance(
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

    let rita_public =
        PublicKey::from_str(rita.public_key()).expect("node key");
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
        let receiver =
            PublicKey::from_str(api.public_key()).expect("node key");
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
    get_subject(&alice, opaque_id.clone(), Some(3), true).await.unwrap();
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
        rita
            .test_get_verified_transfer_sn(&governance_id, opaque_id.clone())
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
        rita
            .test_get_verified_transfer_sn(&governance_id, opaque_id.clone())
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
    get_subject(&alice, clear_id.clone(), Some(3), true).await.unwrap();
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

    inject_with_hint(
        &rita,
        &alice_key,
        vec![cfact2.clone()],
        false,
        &cforged,
    )
    .await;
    for _ in 0..30 {
        assert!(
            rita.get_subject_state(clear_id.clone()).await.is_err(),
            "a refuted suffix must not register the subject"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        rita
            .test_get_verified_transfer_sn(&governance_id, clear_id.clone())
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
