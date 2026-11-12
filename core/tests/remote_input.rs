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
    Ledger, LedgerSeal, Protocols, ValidationMetadata,
};
use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, EXAMPLE_CONTRACT,
    PORT_COUNTER, create_and_authorize_governance, create_node,
    create_nodes_and_connections, create_subject, emit_confirm, emit_fact,
    emit_transfer, get_subject, node_running,
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
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(
            zed_signer,
        )),
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
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(
            rita_signer,
        )),
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
