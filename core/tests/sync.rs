mod common;

use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_core::{
    Api,
    config::GovernanceSyncConfig,
    helpers::network::{
        ActorMessage, NetworkMessage,
        test_faults::{FaultAction, FaultDirection, FaultMessage, FaultRule},
    },
};
use ave_network::{NodeType, RoutingNode};
use common::{
    create_and_authorize_governance, create_node, emit_fact, get_subject,
    node_running, CreateNodeConfig,
};
use serde_json::json;
use std::collections::HashSet;
use std::str::FromStr;
use std::sync::atomic::Ordering;
use std::time::Duration;
use test_log::test;

use crate::common::PORT_COUNTER;

/// Nodes with short governance-sync ticks (TTL = 10 ticks): the stale
/// target test would take ~2 minutes with default intervals.
async fn create_sync_nodes(
) -> (Vec<common::NodeData>, Vec<tempfile::TempDir>) {
    let gov_sync = || {
        Some(GovernanceSyncConfig {
            interval_secs: 1,
            sample_size: 3,
            response_timeout_secs: 5,
        })
    };
    let mut nodes = vec![];
    let mut dirs = vec![];

    // Bootstrap (plain routing, default intervals).
    let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen = format!("/memory/{port}");
    let (boot, mut d) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: listen.clone(),
        peers: vec![],
        always_accept: true,
        is_service: true,
        ..Default::default()
    })
    .await;
    dirs.append(&mut d);
    node_running(&boot.api).await.unwrap();
    nodes.push(boot);
    let boot_addr = listen;

    // Two addressable service nodes with fast sync ticks.
    for _ in 0..2 {
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let listen = format!("/memory/{port}");
        let (node, mut d) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: listen,
            peers: vec![RoutingNode {
                peer_id: nodes[0].api.peer_id().to_string(),
                address: vec![boot_addr.clone()],
            }],
            always_accept: true,
            is_service: true,
            governance_sync: gov_sync(),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    (nodes, dirs)
}

async fn hold_outbound(api: &Api, message: FaultMessage) {
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

/// Counts held outbound messages of one kind.
async fn held_count(api: &Api, message: FaultMessage) -> usize {
    api.test_held_outbound()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|m| {
            matches!(&m.message,
                ActorMessage::DistributionLedgerReq { .. }
                    if message == FaultMessage::DistributionLedgerReq
            )
        })
        .count()
}

async fn wait_held_ledger_reqs(api: &Api, at_least: usize, timeout_secs: u64) {
    for _ in 0..timeout_secs * 2 {
        if held_count(api, FaultMessage::DistributionLedgerReq).await >= at_least {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!(
        "only {} held ledger requests, wanted at least {}",
        held_count(api, FaultMessage::DistributionLedgerReq).await,
        at_least
    );
}

// SYNC-01: an update target that never resolves must not pin the sync
// forever. B announces v2 and then its ledger never arrives; after the
// target TTL the node must open a fresh round (second ledger-request
// wave) instead of no-op-ing on the stale target.
#[test(tokio::test)]
async fn test_sync_stale_target_resweeps() {
    let (nodes, _dirs) = create_sync_nodes().await;
    let boot_key = nodes[0].api.public_key();
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let _ = nodes;

    let governance_id =
        create_and_authorize_governance(&b, vec![&a]).await;

    // v1: both members, B a gov witness (the only sync candidate).
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "roles": { "governance": { "add": {
                "witness": ["A"],
            }}},
        }),
        true,
    )
    .await
    .unwrap();
    // B applies its own facts locally on emit: no update needed,
    // and it must know the v1 membership before serving A.
    get_subject(&b, governance_id.clone(), Some(1), true).await.unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true).await.unwrap();

    // From here A must never receive ledger, neither pulled nor
    // pushed (batch or last-event): hold its outbound ledger requests
    // (countable waves) and all of B's ledger-carrying pushes, so
    // B's ledger can never complete the update while version answers
    // still flow.
    hold_outbound(&a, FaultMessage::DistributionLedgerReq).await;
    hold_outbound(&b, FaultMessage::DistributionLedgerRes).await;
    hold_outbound(&b, FaultMessage::DistributionLastEventReq).await;
    hold_outbound(&b, FaultMessage::DistributionLastEventRes).await;

    // v2 moves on B only; A stays stale at v1.
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "Ghost", "key": boot_key },
            ]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(2), true).await.unwrap();

    // Wave 1: A learns v2 and fires its update. Then silence: the
    // ledger never arrives, the version never moves.
    // Wave 1: A learns v2 and fires its update. Then silence: the
    // ledger never arrives, the version never moves.
    wait_held_ledger_reqs(&a, 1, 20).await;

    // Wave 2 (after the 10-tick target TTL): A drops the stale target
    // and opens a fresh round. Pre-fix this never happens.
    wait_held_ledger_reqs(&a, 2, 60).await;

    // And it never "succeeded": A is still at v1.
    get_subject(&a, governance_id.clone(), Some(1), true).await.unwrap();

    // Wave 2 (after the 10-tick target TTL): A drops the stale target
    // and opens a fresh round. Pre-fix this never happens.
    wait_held_ledger_reqs(&a, 2, 60).await;

    // And it never "succeeded": A is still at v1.
    get_subject(&a, governance_id.clone(), Some(1), true).await.unwrap();
}

// SYNC-06: a peer repeating next_cursor must not hold the fetch cycle
// (and the tick loop) forever. 100 forged single-item pages hit the
// per-cycle cap; the next cycle resumes from the saved cursor.
#[test(tokio::test)]
async fn test_sync_page_cap_and_resume() {
    let (nodes, _dirs) = create_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key =
        PublicKey::from_str(&nodes[2].api.public_key()).unwrap();
    let a_key = PublicKey::from_str(&nodes[1].api.public_key()).unwrap();
    let _ = nodes;

    let governance_id =
        create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "roles": { "governance": { "add": {
                "witness": ["A"],
            }}},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true).await.unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true).await.unwrap();

    // A's own fetch requests are held (observable + countable); forged
    // responses are injected straight into its tracker_sync actor.
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    let sync_actor =
        format!("/user/node/subject_manager/{governance_id}/tracker_sync");

    // First genuine fetch: wait until A asks B, learn its nonce.
    let first_nonce = wait_tracker_fetch(&a, &b_key, None).await;

    // 100 forged pages, all empty with the SAME cursor (the repeating
    // peer attack): each must trigger exactly one more fetch. Only
    // never-seen nonces count: anything else is a stale replay, not
    // progress.
    let cursor = DigestIdentifier::default();
    let mut seen = HashSet::from([first_nonce]);
    let mut nonce = first_nonce;
    for i in 0..100 {
        inject_sync_page(&a, &a_key, &b_key, &sync_actor, nonce, cursor.clone()).await;
        nonce = wait_tracker_fetch_unseen(&a, &b_key, &seen).await;
        seen.insert(nonce);
        assert_eq!(
            seen.len(),
            i + 2,
            "fetch #{i} did not produce a fresh request"
        );
    }

    // Let the next tick fire (10s interval): with the cap, the
    // cycle ended at 100 pages and the new cycle resumes from the
    // saved cursor. Without the cap, the cycle would still be open
    // (or restarts from scratch with no cursor).
    tokio::time::sleep(Duration::from_secs(12)).await;
    let fetches = tracker_fetch_full(&a, &b_key).await;
    // Exactly the initial 100 plus at most the one resume fetch.
    assert!(
        fetches.len() <= 101,
        "runaway pagination: {} fetches",
        fetches.len()
    );
    // Every fetch after the first continues after the forged cursor:
    // no rescan from scratch, no loop past the budget.
    assert!(
        fetches.len() >= 100,
        "expected the full 100-fetch cycle, got {}",
        fetches.len()
    );
    for (i, after) in fetches.iter().enumerate().skip(1) {
        assert_eq!(
            *after,
            Some(cursor.clone()),
            "fetch #{i} must resume after the saved cursor"
        );
    }
}

// SYNC-08: the serving gate. A stranger (non-member) asking for
// our witness list gets silence; a member gets an answer. Proves the
// gate without needing any tick: requests are injected straight into
// A's tracker_sync actor and A's outbound answers are held.
#[test(tokio::test)]
async fn test_sync_serving_gate() {
    let (nodes, _dirs) = create_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let a_key = PublicKey::from_str(&nodes[1].api.public_key()).unwrap();
    let b_key = PublicKey::from_str(&nodes[2].api.public_key()).unwrap();
    let stranger_key = {
        use ave_common::identity::keys::{Ed25519Signer, KeyPair};
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key()
    };
    let _ = nodes;

    let governance_id =
        create_and_authorize_governance(&b, vec![&a]).await;
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "A", "key": a.public_key() },
            ]},
            "roles": { "governance": { "add": {
                "witness": ["A"],
            }}},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(1), true).await.unwrap();

    // A's answers are held so silence vs response is observable.
    hold_outbound(&a, FaultMessage::TrackerSyncRes).await;
    let sync_actor =
        format!("/user/node/subject_manager/{governance_id}/tracker_sync");
    // Stranger first: nothing may come back.
    inject_sync_req(&a, &a_key, &stranger_key, &governance_id, &sync_actor)
        .await;
    tokio::time::sleep(Duration::from_secs(3)).await;
    let silent = a
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .iter()
        .filter(|m| {
            matches!(&m.message, ActorMessage::TrackerSyncRes { .. })
        })
        .count();
    assert_eq!(silent, 0, "stranger got a sync answer");

    // Member: answered.
    inject_sync_req(&a, &a_key, &b_key, &governance_id, &sync_actor).await;
    for _ in 0..20 {
        let answers = a
            .test_held_outbound()
            .await
            .unwrap_or_default()
            .iter()
            .filter(|m| {
                matches!(&m.message, ActorMessage::TrackerSyncRes { .. })
            })
            .count();
        if answers > 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("member got no sync answer");
}

/// Injects a forged sync-list request as if `from` asked `api` for
/// its witness subjects.
async fn inject_sync_req(
    api: &Api,
    receiver: &PublicKey,
    from: &PublicKey,
    governance_id: &DigestIdentifier,
    sync_actor: &str,
) {
    let message = NetworkMessage::new(
        ave_network::ComunicateInfo {
            request_id: String::new(),
            version: 0,
            receiver: receiver.clone(),
            receiver_actor: sync_actor.to_owned(),
        },
        ActorMessage::TrackerSyncReq {
            subject_id: governance_id.clone(),
            request_nonce: 7,
            governance_version: 1,
            after_subject_id: None,
            limit: 10,
            receiver_actor: sync_actor.to_owned(),
        },
    );
    api.test_inject_inbound(message, from).await.unwrap();
}

/// All held TrackerSyncReq cursors A sent to `peer`, in order
/// (first = initial fetch with no cursor).
async fn tracker_fetch_full(
    api: &Api,
    peer: &PublicKey,
) -> Vec<Option<DigestIdentifier>> {
    api.test_held_outbound()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|m| match &m.message {
            ActorMessage::TrackerSyncReq {
                after_subject_id, ..
            } if &m.info.receiver == peer => {
                Some(after_subject_id.clone())
            }
            _ => None,
        })
        .collect()
}

/// Waits for a TrackerSyncReq to `peer` with a nonce not in `seen`.
/// Returns it. Stale replays never satisfy this.
async fn wait_tracker_fetch_unseen(
    api: &Api,
    peer: &PublicKey,
    seen: &HashSet<u64>,
) -> u64 {
    for _ in 0..120 {
        let fresh: Vec<u64> = tracker_fetch_nonces(api, peer)
            .await
            .into_iter()
            .filter(|n| !seen.contains(n))
            .collect();
        if let Some(last) = fresh.last() {
            return *last;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no fresh tracker fetch in time");
}

/// Held TrackerSyncReq nonces A sent to `peer`, in order.
async fn tracker_fetch_nonces(api: &Api, peer: &PublicKey) -> Vec<u64> {
    api.test_held_outbound()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|m| match &m.message {
            ActorMessage::TrackerSyncReq { request_nonce, .. }
                if &m.info.receiver == peer =>
            {
                Some(*request_nonce)
            }
            _ => None,
        })
        .collect()
}

/// Waits for a TrackerSyncReq to `peer` with a nonce different from
/// `after` (None = any first one). Returns its nonce.
async fn wait_tracker_fetch(
    api: &Api,
    peer: &PublicKey,
    after: Option<u64>,
) -> u64 {
    for _ in 0..60 {
        let mut nonces = tracker_fetch_nonces(api, peer).await;
        nonces.retain(|n| Some(*n) != after);
        if let Some(last) = nonces.last() {
            return *last;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("no tracker fetch to peer in time");
}

/// Injects a forged empty sync page and returns nothing; use
/// `wait_tracker_fetch` for the follow-up request it triggers.
async fn inject_sync_page(
    api: &Api,
    receiver: &PublicKey,
    from: &PublicKey,
    sync_actor: &str,
    nonce: u64,
    cursor: DigestIdentifier,
) {
    let message = NetworkMessage::new(
        ave_network::ComunicateInfo {
            request_id: String::new(),
            version: 0,
            receiver: receiver.clone(),
            receiver_actor: sync_actor.to_owned(),
        },
        ActorMessage::TrackerSyncRes {
            request_nonce: nonce,
            governance_version: 1,
            items: vec![],
            next_cursor: Some(cursor),
        },
    );
    api.test_inject_inbound(message, from).await.unwrap();
}


