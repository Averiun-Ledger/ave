mod common;

use std::{collections::HashSet, str::FromStr, sync::atomic::Ordering};

use ave_common::{
    bridge::request::{EventsQuery, SinkEventsQuery},
    identity::{DigestIdentifier, KeyPair, PublicKey, keys::Ed25519Signer},
};
use ave_core::error::Error;
use ave_network::NodeType;
use futures::future::join_all;
use serde_json::json;
use test_log::test;

use crate::common::{
    CreateNodeConfig, PORT_COUNTER, create_and_authorize_governance,
    create_node, create_subject, emit_fact, emit_transfer, get_subject,
    node_running, wait_request,
};

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQo=";

/// Helper: configura una gobernanza con schema "Example1", miembro "node1" y
/// roles necesarios para que el miembro pueda recibir transferencias.
async fn setup_governance_with_example_schema(
    owner: &ave_core::Api,
    transfer_member_pk: &str,
) -> DigestIdentifier {
    let governance_id = create_and_authorize_governance(owner, vec![]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "node1",
                    "key": transfer_member_pk
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example1",
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
            "schema": [
                {
                    "schema_id": "Example1",
                    "add": {
                        "evaluator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "witness": [
                            { "name": "Owner", "namespace": [] },
                            { "name": "node1", "namespace": [] }
                        ],
                        "creator": [
                            { "name": "Owner", "namespace": [], "quantity": "infinity" },
                            { "name": "node1", "namespace": [], "quantity": "infinity" }
                        ],
                        "issuer": [
                            { "name": "Owner", "namespace": [] }
                        ]
                    }
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    wait_request(owner, request_id).await.unwrap();

    governance_id
}

/// Helper: reinicia un nodo preservando keys y DBs, con safe_mode configurable.
async fn restart_node_with_safe_mode(
    node: &mut common::NodeData,
    dirs: &mut Vec<tempfile::TempDir>,
    safe_mode: bool,
) {
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();

    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);

    let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers: vec![],
        safe_mode,
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ..Default::default()
    })
    .await;

    dirs.append(&mut new_dirs);
    node_running(&new_node.api).await.unwrap();

    *node = new_node;
}

#[test(tokio::test)]
async fn safe_mode_tracker_delete_removes_tracker_from_views_and_query_data() {
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let owner = &node.api;

    let witness_keypair = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let witness_pk = witness_keypair.public_key().to_string();

    let governance_id =
        setup_governance_with_example_schema(owner, &witness_pk).await;

    let (tracker_id, _) =
        create_subject(owner, governance_id.clone(), "Example1", "", true)
            .await
            .unwrap();

    // Emit a fact on the tracker
    let json = json!({"ModOne": {"data": 1}});
    let request_id = emit_fact(owner, tracker_id.clone(), json, true)
        .await
        .unwrap();
    wait_request(owner, request_id).await.unwrap();

    // Transfer the tracker
    emit_transfer(
        owner,
        tracker_id.clone(),
        PublicKey::from_str(&witness_pk).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _ = get_subject(owner, tracker_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Restart in safe mode
    restart_node_with_safe_mode(&mut node, &mut dirs, true).await;
    let owner = &node.api;

    // Verify tracker exists before delete
    let state = owner.get_subject_state(tracker_id.clone()).await.unwrap();
    assert_eq!(state.subject_id, tracker_id.to_string());

    let subjects = owner
        .all_subjs(governance_id.clone(), None, None)
        .await
        .unwrap();
    assert!(
        subjects
            .iter()
            .any(|s| s.subject_id == tracker_id.to_string())
    );

    let transfers = owner.get_pending_transfers().await.unwrap();
    assert!(transfers.iter().any(|t| t.subject_id == tracker_id));

    // Delete tracker in safe mode
    owner
        .delete_subject(tracker_id.clone())
        .await
        .expect("tracker delete failed");

    // Verify tracker is gone from all views
    let err = owner
        .get_subject_state(tracker_id.clone())
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::SubjectNotFound(_)),
        "expected SubjectNotFound, got {:?}",
        err
    );

    let subjects = owner
        .all_subjs(governance_id.clone(), None, None)
        .await
        .unwrap();
    assert!(
        !subjects
            .iter()
            .any(|s| s.subject_id == tracker_id.to_string())
    );

    let transfers = owner.get_pending_transfers().await.unwrap();
    assert!(!transfers.iter().any(|t| t.subject_id == tracker_id));

    // After deletion the DBs are purged; both endpoints may return NoEventsFound
    // or SubjectNotFound/MissingResource depending on whether the actor is gone.
    let events_err = owner
        .get_events(
            tracker_id.clone(),
            EventsQuery {
                quantity: Some(50),
                page: Some(0),
                reverse: Some(false),
                event_request_ts: None,
                event_ledger_ts: None,
                sink_ts: None,
                event_type: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            events_err,
            Error::NoEventsFound(_)
                | Error::SubjectNotFound(_)
                | Error::MissingResource { .. }
        ),
        "unexpected events error: {:?}",
        events_err
    );

    let sink_err = owner
        .get_sink_events(
            tracker_id.clone(),
            SinkEventsQuery {
                from_sn: Some(0),
                to_sn: None,
                limit: None,
            },
        )
        .await
        .unwrap_err();
    assert!(
        matches!(
            sink_err,
            Error::NoEventsFound(_)
                | Error::SubjectNotFound(_)
                | Error::MissingResource { .. }
        ),
        "unexpected sink error: {:?}",
        sink_err
    );

    // Verify governance still exists
    let gov_state = owner
        .get_subject_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(gov_state.subject_id, governance_id.to_string());

    // Restart without safe mode and verify persistence
    restart_node_with_safe_mode(&mut node, &mut dirs, false).await;
    let owner = &node.api;

    let err = owner
        .get_subject_state(tracker_id.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SubjectNotFound(_)));

    let gov_state = owner
        .get_subject_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(gov_state.subject_id, governance_id.to_string());
}

#[test(tokio::test)]
async fn safe_mode_tracker_delete_clears_pending_transfer_and_serializes_global_delete()
 {
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let owner = &node.api;

    let witness_keypair = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let witness_pk = witness_keypair.public_key().to_string();

    let governance_id =
        setup_governance_with_example_schema(owner, &witness_pk).await;

    let (tracker_id, _) =
        create_subject(owner, governance_id.clone(), "Example1", "", true)
            .await
            .unwrap();

    // Add 6 facts
    for i in 1..=6 {
        let json = json!({"ModOne": {"data": i}});
        let request_id = emit_fact(owner, tracker_id.clone(), json, true)
            .await
            .unwrap();
        wait_request(owner, request_id).await.unwrap();
    }

    // Create a second tracker to interleave concurrent deletes
    let (second_tracker_id, _) =
        create_subject(owner, governance_id.clone(), "Example1", "", true)
            .await
            .unwrap();

    // Transfer the first tracker
    emit_transfer(
        owner,
        tracker_id.clone(),
        PublicKey::from_str(&witness_pk).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _ = get_subject(owner, tracker_id.clone(), Some(7), true)
        .await
        .unwrap();

    // Restart in safe mode
    restart_node_with_safe_mode(&mut node, &mut dirs, true).await;
    let owner = &node.api;

    // Verify pending transfer exists for the first tracker
    let transfers = owner.get_pending_transfers().await.unwrap();
    assert!(transfers.iter().any(|t| t.subject_id == tracker_id));

    // Launch 12 concurrent deletes alternating between the two trackers.
    // Because delete_subject uses a global lock (begin_subject_deletion),
    // only one delete can proceed at a time; the rest must return
    // InvalidRequestState("subject deletion already in progress...").
    let delete_futures: Vec<_> = (0..12)
        .map(|index| {
            let subject_id = if index % 2 == 0 {
                tracker_id.clone()
            } else {
                second_tracker_id.clone()
            };
            let api = owner.clone();
            async move { api.delete_subject(subject_id).await }
        })
        .collect();

    let results = join_all(delete_futures).await;

    let ok_count = results.iter().filter(|r| r.is_ok()).count();
    let conflict_count = results.iter().filter(|r| {
        matches!(
            r,
            Err(Error::InvalidRequestState(msg)) if msg.contains("deletion already in progress")
        )
    }).count();

    assert!(
        ok_count >= 1,
        "expected at least 1 successful delete, got {}",
        ok_count
    );
    assert!(
        conflict_count >= 1,
        "expected at least 1 concurrent delete conflict, got {}",
        conflict_count
    );

    // Ensure the transferred tracker is deleted (it may or may not have been
    // the one that won the race). If it still exists, delete it now.
    if owner.get_subject_state(tracker_id.clone()).await.is_ok() {
        owner
            .delete_subject(tracker_id.clone())
            .await
            .expect("manual tracker delete failed");
    }

    // Verify pending transfer for the transferred tracker is cleared
    let transfers = owner.get_pending_transfers().await.unwrap();
    assert!(
        !transfers.iter().any(|t| t.subject_id == tracker_id),
        "pending transfer for tracker should have been cleared"
    );
}

#[test(tokio::test)]
async fn safe_mode_governance_delete_lists_pending_trackers() {
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let owner = &node.api;

    let witness_keypair = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let witness_pk = witness_keypair.public_key().to_string();

    let governance_id =
        setup_governance_with_example_schema(owner, &witness_pk).await;

    let mut tracker_ids = Vec::new();
    for i in 1..=3 {
        let (tracker_id, _) =
            create_subject(owner, governance_id.clone(), "Example1", "", true)
                .await
                .unwrap();
        let json = json!({"ModOne": {"data": i}});
        let request_id = emit_fact(owner, tracker_id.clone(), json, true)
            .await
            .unwrap();
        wait_request(owner, request_id).await.unwrap();
        tracker_ids.push(tracker_id);
    }

    // Restart in safe mode
    restart_node_with_safe_mode(&mut node, &mut dirs, true).await;
    let owner = &node.api;

    // Verify governance exists
    let gov_state = owner
        .get_subject_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(gov_state.subject_id, governance_id.to_string());

    let subjects = owner
        .all_subjs(governance_id.clone(), None, None)
        .await
        .unwrap();
    assert_eq!(subjects.len(), tracker_ids.len());
    for tid in &tracker_ids {
        assert!(subjects.iter().any(|s| s.subject_id == tid.to_string()));
    }

    // Attempt to delete governance with trackers
    let err = owner
        .delete_subject(governance_id.clone())
        .await
        .unwrap_err();
    match err {
        Error::GovernanceHasTrackers {
            governance_id: gid,
            trackers,
        } => {
            assert_eq!(gid, governance_id.to_string());
            let expected: HashSet<_> =
                tracker_ids.iter().map(|t| t.to_string()).collect();
            let actual: HashSet<_> = trackers.into_iter().collect();
            assert_eq!(expected, actual);
        }
        other => panic!("expected GovernanceHasTrackers, got {:?}", other),
    }
}

#[test(tokio::test)]
async fn safe_mode_governance_delete_removes_views_after_trackers_are_deleted()
{
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        peers: vec![],
        always_accept: true,
        ..Default::default()
    })
    .await;
    let owner = &node.api;

    let witness_keypair = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let witness_pk = witness_keypair.public_key().to_string();

    let governance_id =
        setup_governance_with_example_schema(owner, &witness_pk).await;

    let mut tracker_ids = Vec::new();
    for i in 1..=3 {
        let (tracker_id, _) =
            create_subject(owner, governance_id.clone(), "Example1", "", true)
                .await
                .unwrap();
        let json = json!({"ModOne": {"data": i}});
        let request_id = emit_fact(owner, tracker_id.clone(), json, true)
            .await
            .unwrap();
        wait_request(owner, request_id).await.unwrap();
        tracker_ids.push(tracker_id);
    }

    // Restart in safe mode
    restart_node_with_safe_mode(&mut node, &mut dirs, true).await;
    let owner = &node.api;

    // Verify governance exists
    let govs = owner.all_govs(None).await.unwrap();
    assert!(
        govs.iter()
            .any(|g| g.governance_id == governance_id.to_string())
    );

    // Delete all trackers first
    for tracker_id in &tracker_ids {
        owner
            .delete_subject(tracker_id.clone())
            .await
            .expect("tracker delete failed");
    }

    // Now delete governance
    owner
        .delete_subject(governance_id.clone())
        .await
        .expect("governance delete failed");

    // Verify governance is gone
    let err = owner
        .get_subject_state(governance_id.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SubjectNotFound(_)));

    let govs = owner.all_govs(None).await.unwrap();
    assert!(
        !govs
            .iter()
            .any(|g| g.governance_id == governance_id.to_string())
    );

    let err = owner
        .all_subjs(governance_id.clone(), None, None)
        .await
        .unwrap_err();
    assert!(
        matches!(err, Error::GovernanceNotFound(_)),
        "expected GovernanceNotFound, got {:?}",
        err
    );

    // Restart without safe mode and verify persistence
    restart_node_with_safe_mode(&mut node, &mut dirs, false).await;
    let owner = &node.api;

    let err = owner
        .get_subject_state(governance_id.clone())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SubjectNotFound(_)));

    let govs = owner.all_govs(None).await.unwrap();
    assert!(
        !govs
            .iter()
            .any(|g| g.governance_id == governance_id.to_string())
    );
}
