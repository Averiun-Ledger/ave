mod common;

// Inbound robustness: batches and hints crafted by a malicious peer must
// be rejected as invalid input, never stop the node, and never open
// reception windows that full validation would deny.

use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signature, Signed, TimeStamp,
    hash_borsh,
};
use ave_common::identity::keys::{DSA, Ed25519Signer};
use ave_common::request::{EventRequest, TransferRequest};
use ave_core::helpers::network::{ActorMessage, NetworkMessage};
use ave_core::model::event::{
    Ledger, LedgerSeal, Protocols, ValidationMetadata,
};
use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    EXAMPLE_CONTRACT, PORT_COUNTER, CreateNodeConfig,
    CreateNodesAndConnectionsConfig, create_and_authorize_governance,
    create_node, create_nodes_and_connections, create_subject, emit_confirm,
    emit_fact, emit_transfer, get_subject, node_running,
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
    emit_fact(owner, governance_id.clone(), config, true).await.unwrap();

    // Members need the governance locally before they can create
    // subjects or verify hints under it.
    let gov_sn = get_subject(owner, governance_id.clone(), None, true)
        .await
        .unwrap()
        .sn;
    for member in members {
        member.api.update_subject(governance_id.clone()).await.unwrap();
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
    let (mut nodes, dirs) = create_nodes_and_connections(
        CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        },
    )
    .await;
    let target = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let sender =
        PublicKey::from_str(nodes[2].api.public_key()).unwrap();

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
    let (real_subject, _) = create_subject(
        &alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();
    let create_event = alice
        .test_get_tracker_ledger(real_subject.clone(), 0)
        .await
        .unwrap()
        .into_iter()
        .next()
        .expect("genesis event");
    let (template_request, template_validation) =
        match &create_event.protocols {
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
        prev_ledger_event_hash: create_event
            .prev_ledger_event_hash
            .clone(),
        ledger_seal_signature: create_event
            .ledger_seal_signature
            .clone(),
        protocols: Protocols::Create {
            event_request: Arc::new(forged_request),
            validation: forged_validation,
        },
    };
    inject_ledger_batch(&target, &sender, vec![forged_create], None)
        .await;

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
    target.get_subject_state(governance_id.clone()).await.unwrap();
    create_subject(&alice, governance_id, "Example", "", true)
        .await
        .unwrap();

    for node in nodes.iter_mut() {
        node.token.cancel();
    }
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut()))
        .await;
    drop(nodes);
    drop(dirs);
}

/// A transfer hint whose quorum block belongs to another event must not
/// open a reception window; the legitimate hint still must.
#[test(tokio::test)]
async fn remote_forged_transfer_hint_does_not_open_reception() {
    let (mut nodes, dirs) = create_nodes_and_connections(
        CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        },
    )
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
    let (subject_id, _) = create_subject(
        &alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
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
    emit_transfer(&alice, subject_id.clone(), bob_key, true).await.unwrap();
    let history = alice.test_get_tracker_ledger(subject_id.clone(), 2).await.unwrap();
    assert_eq!(history.len(), 3);
    let genuine = history
        .iter()
        .find(|event| event.sn == 2)
        .expect("transfer event")
        .clone();
    let (genuine_evaluation, genuine_validation) = match &genuine.protocols
    {
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
            receiver.get_subject_state(subject_id.clone()).await.is_err(),
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
    get_subject(&bob, subject_id.clone(), Some(2), true).await.unwrap();
    emit_confirm(&bob, subject_id.clone(), None, true).await.unwrap();
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
    join_all(nodes.iter_mut().flat_map(|node| node.handler.iter_mut()))
        .await;
    drop(nodes);
    drop(dirs);
}

/// An event whose seal timestamp is outside the SQLite integer range is
/// rejected during verification; the node stays up and keeps syncing.
#[test(tokio::test)]
async fn remote_future_timestamp_event_is_rejected() {
    let (mut nodes, dirs) = create_nodes_and_connections(
        CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        },
    )
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
    let (subject_id, _) = create_subject(
        &alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
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
    let history =
        alice.test_get_tracker_ledger(subject_id.clone(), 2).await.unwrap();
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
    let content_hash = hash_borsh(
        &*HashAlgorithm::Blake3.hasher(),
        &(&seal, timestamp),
    )
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
        keys: Some(ave_common::identity::keys::KeyPair::Ed25519(
            bob_signer,
        )),
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
    get_subject(&bob, subject_id.clone(), Some(2), true).await.unwrap();

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

/// SLOW: governance recovery must not replay the page-boundary event.
/// With 257 events the second page overlaps the first under the old
/// cursor; the duplicate apply used to fail the boot.
#[test(tokio::test)]
async fn dirty_restart_does_not_reapply_page_boundary() {
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

    let before =
        get_subject(&api, governance_id.clone(), None, true).await.unwrap();

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
}
