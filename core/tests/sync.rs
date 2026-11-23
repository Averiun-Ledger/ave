mod common;

use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_core::{
    Api,
    config::{GovernanceSyncConfig, TrackerSyncConfig},
    helpers::network::{
        ActorMessage, NetworkMessage,
        test_faults::{FaultAction, FaultDirection, FaultMessage, FaultRule},
    },
};
use ave_network::{NodeType, RoutingNode};
use common::{
    CreateNodeConfig, create_and_authorize_governance, create_node,
    create_subject, emit_fact, get_subject, node_running,
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
async fn create_sync_nodes() -> (Vec<common::NodeData>, Vec<tempfile::TempDir>)
{
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
    let tracker_sync = || {
        Some(TrackerSyncConfig {
            interval_secs: 1,
            page_size: 10,
            response_timeout_secs: 5,
            update_batch_size: 2,
            update_timeout_secs: 5,
        })
    };
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
            tracker_sync: tracker_sync(),
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
    for _ in 0..timeout_secs * 10 {
        if held_count(api, FaultMessage::DistributionLedgerReq).await
            >= at_least
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!(
        "only {} held ledger requests, wanted at least {}",
        held_count(api, FaultMessage::DistributionLedgerReq).await,
        at_least
    );
}

// An update target that never resolves must not pin the sync
// forever. B announces v2 and then its ledger never arrives; after the
// target TTL the node must open a fresh round (second ledger-request
// wave) instead of no-op-ing on the stale target.
#[test(tokio::test)]
async fn test_sync_stale_target_resweeps() {
    let (nodes, _dirs) = create_sync_nodes().await;
    let boot_key = nodes[0].api.public_key();
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;

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
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

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
    get_subject(&b, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    // Wave 1: A learns v2 and fires its update. Then silence: the
    // ledger never arrives, the version never moves.
    // Wave 1: A learns v2 and fires its update. Then silence: the
    // ledger never arrives, the version never moves.
    wait_held_ledger_reqs(&a, 1, 20).await;

    // Wave 2 (after the 10-tick target TTL): A drops the stale target
    // and opens a fresh round. Pre-fix this never happens.
    wait_held_ledger_reqs(&a, 2, 60).await;

    // And it never "succeeded": A is still at v1.
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Wave 2 (after the 10-tick target TTL): A drops the stale target
    // and opens a fresh round. Pre-fix this never happens.
    wait_held_ledger_reqs(&a, 2, 60).await;

    // And it never "succeeded": A is still at v1.
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
}

// A peer repeating next_cursor must not hold the fetch cycle
// (and the tick loop) forever. 100 forged single-item pages hit the
// per-cycle cap; the next cycle resumes from the saved cursor.
#[test(tokio::test)]
async fn test_sync_page_cap_and_resume() {
    let (nodes, _dirs) = create_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let b_key = PublicKey::from_str(&nodes[2].api.public_key()).unwrap();
    let a_key = PublicKey::from_str(&nodes[1].api.public_key()).unwrap();
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
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
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

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
        inject_sync_page(
            &a,
            &a_key,
            &b_key,
            &sync_actor,
            nonce,
            cursor.clone(),
        )
        .await;
        nonce = wait_tracker_fetch_unseen(&a, &b_key, &seen).await;
        seen.insert(nonce);
        assert_eq!(
            seen.len(),
            i + 2,
            "fetch #{i} did not produce a fresh request"
        );
    }

    // Let the next tick fire (1s interval in these nodes): with the
    // cap, the cycle ended at 100 pages and the new cycle resumes
    // from the saved cursor. Without the cap, the cycle would still
    // be open (or restarts from scratch with no cursor).
    tokio::time::sleep(Duration::from_secs(4)).await;
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

// The serving gate. A stranger (non-member) asking for
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

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
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
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // A's answers are held so silence vs response is observable.
    hold_outbound(&a, FaultMessage::TrackerSyncRes).await;
    // B's background fetches are held too: with fast tracker ticks B
    // would fetch from A mid-window and A's legitimate member answer
    // would pollute the stranger-silence count below.
    hold_outbound(&b, FaultMessage::TrackerSyncReq).await;
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
        .filter(|m| matches!(&m.message, ActorMessage::TrackerSyncRes { .. }))
        .count();
    assert_eq!(silent, 0, "stranger got a sync answer");

    // Member: answered.
    inject_sync_req(&a, &a_key, &b_key, &governance_id, &sync_actor).await;
    for _ in 0..100 {
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
        tokio::time::sleep(Duration::from_millis(100)).await;
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
            } if &m.info.receiver == peer => Some(after_subject_id.clone()),
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
    for _ in 0..600 {
        let fresh: Vec<u64> = tracker_fetch_nonces(api, peer)
            .await
            .into_iter()
            .filter(|n| !seen.contains(n))
            .collect();
        if let Some(last) = fresh.last() {
            return *last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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
    for _ in 0..300 {
        let mut nonces = tracker_fetch_nonces(api, peer).await;
        nonces.retain(|n| Some(*n) != after);
        if let Some(last) = nonces.last() {
            return *last;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
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

/// Nodes with manual version-sync ticks (long intervals, long
/// timeouts): no round opens or closes unless the test drives it,
/// so interleavings are exact.
async fn create_manual_sync_nodes()
-> (Vec<common::NodeData>, Vec<tempfile::TempDir>) {
    let gov_sync = || {
        Some(GovernanceSyncConfig {
            interval_secs: 3600,
            sample_size: 3,
            response_timeout_secs: 3600,
        })
    };
    let tracker_sync = || {
        Some(TrackerSyncConfig {
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
            tracker_sync: tracker_sync(),
            ..Default::default()
        })
        .await;
        dirs.append(&mut d);
        node_running(&node.api).await.unwrap();
        nodes.push(node);
    }
    (nodes, dirs)
}

/// A timeout queued by an older round must not close the active
/// one: it must not cancel its timer, drain its pending peers or
/// change backoff. Only the matching round may close, exactly once.
#[test(tokio::test)]
async fn sync_stale_round_timeout_does_not_close_new_round() {
    let (nodes, _dirs) = create_manual_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
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
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Both nodes sit at v1: a completed round with all answers and
    // no superior version reports idle exactly once.
    assert_eq!(
        a.test_version_sync_idle_count(governance_id.clone())
            .await
            .unwrap(),
        0,
        "no idle before any round completes"
    );

    // Hold B's answers so rounds 1 and 2 stay open with B pending.
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::GovernanceVersionRes,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();
    a.test_version_sync_tick(governance_id.clone())
        .await
        .unwrap();
    a.test_version_sync_tick(governance_id.clone())
        .await
        .unwrap();
    // Round 2 is now open with B pending; round 1 never closed.
    // A timeout from round 1 (and its duplicate) must be ignored:
    // it must not close round 2, drain B or touch backoff.
    a.test_version_sync_stale_timeout(governance_id.clone(), 1)
        .await
        .unwrap();
    a.test_version_sync_stale_timeout(governance_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(
        a.test_version_sync_idle_count(governance_id.clone())
            .await
            .unwrap(),
        0,
        "a stale timeout is not an idle proof"
    );

    // The genuine answers still complete round 2: every selected
    // peer answered and none is ahead, so idle is reported once.
    b.test_release_held().await.unwrap();
    for _ in 0..100 {
        if a.test_version_sync_idle_count(governance_id.clone())
            .await
            .unwrap_or(0)
            >= 1
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        a.test_version_sync_idle_count(governance_id.clone())
            .await
            .unwrap(),
        1,
        "the live round still completes after the stale timeout"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

/// Unanswered peers, failed sends and backed-off peers never prove
/// the tip: only a round where every selected peer answered and none
/// is ahead may report idle once per version.
#[test(tokio::test)]
async fn sync_unanswered_peers_never_prove_idle() {
    let (nodes, _dirs) = create_manual_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
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
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // Both nodes sit at v1: B is A's only sync candidate. Flip A
    // to `has_boot_nodes == false` (test-only override, topology
    // unchanged) so the pre-fix code would certify silence as idle
    // here: with known peers that must never happen.
    a.test_version_sync_set_has_boot_nodes(governance_id.clone(), false)
        .await
        .unwrap();
    async fn idle_count(api: &Api, gov: &DigestIdentifier) -> u64 {
        api.test_version_sync_idle_count(gov.clone()).await.unwrap()
    }
    assert_eq!(idle_count(&a, &governance_id).await, 0);

    // Hold B's answers: every round below times out unanswered.
    b.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::GovernanceVersionRes,
        peer: None,
        remaining: None,
        action: FaultAction::Hold,
    })
    .await
    .unwrap();

    // Round 1 times out with B pending: silence is not a tip proof.
    a.test_version_sync_tick(governance_id.clone())
        .await
        .unwrap();
    a.test_version_sync_stale_timeout(governance_id.clone(), 1)
        .await
        .unwrap();
    assert_eq!(
        idle_count(&a, &governance_id).await,
        0,
        "unanswered peers never prove idle"
    );

    // Round 2 finds B backed off from that silence and selects
    // nobody: an empty selection with known peers is still not a
    // tip proof.
    a.test_version_sync_tick(governance_id.clone())
        .await
        .unwrap();
    // Barrier ensures the tick was processed (ticks are tells): empty
    // selection with known peers closes immediately with no timer, no
    // fixed wait needed (no answers can arrive: B is held and backed
    // off, and no other peer exists).
    let _ = a
        .test_version_sync_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(
        idle_count(&a, &governance_id).await,
        0,
        "backed-off peers never prove idle"
    );

    // Round 3 selects B again (backoff expired) but every send
    // fails: failed sends are not answers either.
    a.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::GovernanceVersionReq,
        peer: None,
        remaining: None,
        action: FaultAction::FailSend,
    })
    .await
    .unwrap();
    a.test_version_sync_tick(governance_id.clone())
        .await
        .unwrap();
    a.test_version_sync_stale_timeout(governance_id.clone(), 3)
        .await
        .unwrap();
    assert_eq!(
        idle_count(&a, &governance_id).await,
        0,
        "failed sends never prove idle"
    );
    a.test_clear_faults().await.unwrap();

    // Control: with answers flowing, a round where every selected
    // peer answers and none is ahead reports idle exactly once.
    b.test_release_held().await.unwrap();
    a.test_version_sync_tick(governance_id.clone())
        .await
        .unwrap();
    for _ in 0..100 {
        if idle_count(&a, &governance_id).await >= 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        idle_count(&a, &governance_id).await,
        1,
        "a fully answered round with no superior peer reports idle once"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

/// Forged sync page with an explicit version and items, answering
/// `nonce` as if `from` sent it. Lets the test prove version
/// scoping with exact request counts.
async fn inject_sync_page_versioned(
    api: &Api,
    receiver: &PublicKey,
    from: &PublicKey,
    sync_actor: &str,
    nonce: u64,
    version: u64,
    items: Vec<ave_core::governance::witnesses_register::CurrentWitnessSubject>,
    cursor: Option<DigestIdentifier>,
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
            governance_version: version,
            items,
            next_cursor: cursor,
        },
    );
    api.test_inject_inbound(message, from).await.unwrap();
}

/// Governance versions of every held TrackerSyncReq A sent to `peer`.
async fn tracker_fetch_versions(api: &Api, peer: &PublicKey) -> Vec<u64> {
    api.test_held_outbound()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|m| match &m.message {
            ActorMessage::TrackerSyncReq {
                governance_version, ..
            } if &m.info.receiver == peer => Some(*governance_version),
            _ => None,
        })
        .collect()
}

// A page carrying a higher governance version than the round (and
// the local node) must be discarded, never adopted: no refetch at
// the higher version, no update, no new requests. Only pages where
// response == active == local versions process. Bounds are exact
// request counts, never timeouts.
#[test(tokio::test)]
async fn sync_higher_page_version_does_not_spin() {
    use ave_common::identity::HashAlgorithm;

    let (nodes, _dirs) = create_manual_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let a_key = PublicKey::from_str(&nodes[1].api.public_key()).unwrap();
    let b_key = PublicKey::from_str(&nodes[2].api.public_key()).unwrap();
    let _ = nodes;

    let governance_id = create_and_authorize_governance(&b, vec![&a]).await;
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
    get_subject(&b, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    // A's fetches and copy requests are held: observable, countable,
    // and never delivered, so no genuine traffic pollutes the counts.
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    hold_outbound(&a, FaultMessage::DistributionLedgerReq).await;
    let sync_actor =
        format!("/user/node/subject_manager/{governance_id}/tracker_sync");

    // Round 1 at v1: exactly one fetch.
    a.test_tracker_sync_tick(governance_id.clone())
        .await
        .unwrap();
    let f1 = wait_tracker_fetch(&a, &b_key, None).await;
    assert_eq!(tracker_fetch_versions(&a, &b_key).await, vec![1]);

    // Forged v2 page answering F1, with an item demanding an update
    // (unknown subject, target 5): discarded whole — no v2 refetch,
    // no update, no new requests. Pre-fix this mints a fetch at v2
    // via `max`, and the next v2 page would spin fetch/update
    // forever without hitting the page cap.
    let ghost =
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![7u8; 32]).unwrap();
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        f1,
        2,
        vec![
            ave_core::governance::witnesses_register::CurrentWitnessSubject {
                subject_id: ghost,
                target_sn: 5,
            },
        ],
        None,
    )
    .await;
    // Barrier ensures the forged page was processed (tells are ordered
    // before asks): no fixed wait needed. Poll the final state plus
    // absence of growth on the next transition (Round 2 below) instead
    // of assuming termination after an arbitrary sleep.
    let _ = a
        .test_tracker_sync_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        1,
        "a higher-version page must not mint requests"
    );
    assert!(
        !tracker_fetch_versions(&a, &b_key).await.contains(&2),
        "the higher version must never be adopted as our own"
    );
    assert_eq!(
        held_count(&a, FaultMessage::DistributionLedgerReq).await,
        0,
        "a discarded page launches no updates"
    );

    // Round 2: the equal version is accepted, the empty page
    // completes the cycle with no follow-up fetch.
    a.test_tracker_sync_tick(governance_id.clone())
        .await
        .unwrap();
    let seen = HashSet::from([f1]);
    let f2 = wait_tracker_fetch_unseen(&a, &b_key, &seen).await;
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        f2,
        1,
        vec![],
        None,
    )
    .await;
    // Barrier ensures the accepted page completed (no follow-up fetch).
    let _ = a
        .test_tracker_sync_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        2,
        "an accepted page completes without refetch"
    );

    // Round 3: an older version is stale and dropped the same way.
    a.test_tracker_sync_tick(governance_id.clone())
        .await
        .unwrap();
    let seen = HashSet::from([f1, f2]);
    let f3 = wait_tracker_fetch_unseen(&a, &b_key, &seen).await;
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        f3,
        0,
        vec![],
        None,
    )
    .await;
    // Barrier ensures the stale page was dropped (no new fetch).
    let _ = a
        .test_tracker_sync_state(governance_id.clone())
        .await
        .unwrap();
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        3,
        "a stale page must not mint requests either"
    );

    // Round 4: once the local governance reaches v2, v2 pages
    // process again. Unblock the copy flow first (the held ledger
    // requests are dropped, not delivered: no stale replays).
    // NOTE: the v2 fact must really bump the version (a new member),
    // not just the SN: a no-op fact leaves the actor at v1.
    a.test_clear_faults().await.unwrap();
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    let fresh_key = {
        use ave_common::identity::keys::{Ed25519Signer, KeyPair};
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key()
    };
    emit_fact(
        &b,
        governance_id.clone(),
        json!({
            "members": { "add": [
                { "name": "C", "key": fresh_key.to_string() },
            ]},
        }),
        true,
    )
    .await
    .unwrap();
    get_subject(&b, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    a.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&a, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    a.test_tracker_sync_tick(governance_id.clone())
        .await
        .unwrap();
    let f4 = wait_tracker_fetch(&a, &b_key, None).await;
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        f4,
        2,
        vec![],
        None,
    )
    .await;
    tokio::time::sleep(Duration::from_millis(500)).await;
    let versions = tracker_fetch_versions(&a, &b_key).await;
    assert_eq!(versions.len(), 1, "exactly the round-4 fetch");
    assert_eq!(versions, vec![2], "round 4 fetches at the new local v2");
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

// A sync page is only a hint: repeated subjects collapse into a
// single copy request, and subjects tracked under another
// governance never produce one. A Create arriving under the wrong
// scope is rejected before any write. Exact request counts bound
// every step; planning a page mints no new fetches.
#[test(tokio::test)]
async fn sync_page_items_are_deduplicated_and_scoped() {
    fn item(
        subject_id: DigestIdentifier,
        target_sn: u64,
    ) -> ave_core::governance::witnesses_register::CurrentWitnessSubject {
        ave_core::governance::witnesses_register::CurrentWitnessSubject {
            subject_id,
            target_sn,
        }
    }

    let (nodes, _dirs) = create_manual_sync_nodes().await;
    let (a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let a_key = PublicKey::from_str(&nodes[1].api.public_key()).unwrap();
    let b_key = PublicKey::from_str(&nodes[2].api.public_key()).unwrap();
    let _ = nodes;

    // G1 is the synced scope, G2 the foreign one. A is member of
    // both and holds both locally, so the scope check — not missing
    // state or authorization — is what drops G2 items. Pre-fix the
    // same membership would authorize the copy. B stays the only
    // governance witness (majority of one): its tracker creates are
    // self-contained and never wait on A. Both govs carry the
    // Example schema with the owner (B's node) as creator, so B can
    // host the trackers below. B is already a member under the
    // reserved "Owner" name: re-adding its key would reject the
    // whole fact as a duplicate.
    async fn witness_setup(node: &Api, gov: &DigestIdentifier, peer_key: &str) {
        emit_fact(
            node,
            gov.clone(),
            json!({
                "members": { "add": [
                    { "name": "A", "key": peer_key },
                ]},
                "schemas": { "add": [
                    {
                        "id": "Example",
                        "contract": ave_core::test_contracts::EXAMPLE_CONTRACT,
                        "initial_value": {"one": 0, "two": 0, "three": 0},
                    },
                ]},
                "roles": {
                    "governance": { "add": {"witness": ["A"]}},
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
    }
    let g1 = create_and_authorize_governance(&b, vec![&a]).await;
    witness_setup(&b, &g1, &a.public_key()).await;
    get_subject(&b, g1.clone(), Some(1), true).await.unwrap();
    let g2 = create_and_authorize_governance(&b, vec![&a]).await;
    witness_setup(&b, &g2, &a.public_key()).await;
    get_subject(&b, g2.clone(), Some(1), true).await.unwrap();
    a.update_subject(g1.clone()).await.unwrap();
    get_subject(&a, g1.clone(), Some(1), true).await.unwrap();
    a.update_subject(g2.clone()).await.unwrap();
    get_subject(&a, g2.clone(), Some(1), true).await.unwrap();

    // Trackers on B: U and X1 under G1, X2 under G2. A holds none:
    // B goes deaf first, or its creation push (A is now a schema
    // witness) would hand every tracker to A before the test.
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
    let (u, _) = create_subject(&b, g1.clone(), "Example", "", true)
        .await
        .unwrap();
    let (x1, _) = create_subject(&b, g1.clone(), "Example", "", true)
        .await
        .unwrap();
    let (x2, _) = create_subject(&b, g2.clone(), "Example", "", true)
        .await
        .unwrap();

    // Phase A (counting): every copy request is held. The same
    // unknown subject thrice plus a foreign-governance id must yield
    // exactly one request: dedup collapses U, the scope check drops
    // G2 before any local work. Pre-fix this mints 4 (3 + 1).
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    hold_outbound(&a, FaultMessage::DistributionLedgerReq).await;
    let sync_actor = format!("/user/node/subject_manager/{g1}/tracker_sync");
    a.test_tracker_sync_tick(g1.clone()).await.unwrap();
    let f1 = wait_tracker_fetch(&a, &b_key, None).await;
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        f1,
        1,
        vec![
            item(u.clone(), 0),
            item(u.clone(), 0),
            item(u.clone(), 0),
            item(g2.clone(), 5),
        ],
        None,
    )
    .await;
    // Barrier ensures the page was fully processed (tells ordered before asks):
    // deduplication happens once during planning, never via retry.
    let _ = a.test_tracker_sync_state(g1.clone()).await.unwrap();
    assert_eq!(
        held_count(&a, FaultMessage::DistributionLedgerReq).await,
        1,
        "three appearances of one subject plus a foreign id mint exactly one copy request"
    );
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        1,
        "planning a page mints no new fetches"
    );

    // Let the held request through: B hears again first (its
    // drops only covered creation pushes), then the release
    // delivers U's request and F1. U lands, the round completes.
    b.test_clear_faults().await.unwrap();
    a.test_release_held().await.unwrap();
    get_subject(&a, u.clone(), Some(0), true).await.unwrap();

    // Phase B (scope enforcement): X2 (foreign Create) and X1
    // (in-scope Create) ride one page with the copy flow open. X1
    // must land at its tip; X2 must never persist, register
    // ownership or open a worker; no new fetch may fire. (The phase-A
    // fetch left the held list on release, so exactly one held fetch
    // — round 2's — is the bound here.)
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    let mut f2 = None;
    for _ in 0..90 {
        a.test_tracker_sync_tick(g1.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;
        if let Some(n) = tracker_fetch_nonces(&a, &b_key)
            .await
            .into_iter()
            .find(|n| *n != f1)
        {
            f2 = Some(n);
            break;
        }
    }
    let f2 = f2.expect("round 2 fetch after U completes");
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        f2,
        1,
        vec![item(x2.clone(), 0), item(x1.clone(), 0)],
        None,
    )
    .await;
    get_subject(&a, x1.clone(), Some(0), true).await.unwrap();
    // Barrier ensures the mixed page was fully processed (x1 applied,
    // x2 rejected) with no follow-up fetch.
    let _ = a.test_tracker_sync_state(g1.clone()).await.unwrap();
    assert!(
        a.get_subject_state(x2.clone()).await.is_err(),
        "a Create under another governance is rejected before any write"
    );
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        1,
        "rejecting a foreign Create mints no new fetches"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}

// A page retained from a previous incarnation must never answer the
// new one: nonces start from a fresh random value per incarnation,
// so a stale peer/nonce/version triple matches nothing. Only the
// live page produces copy requests.
#[test(tokio::test)]
async fn sync_stale_page_from_previous_incarnation_is_ignored() {
    use ave_common::identity::HashAlgorithm;

    fn item(
        subject_id: DigestIdentifier,
        target_sn: u64,
    ) -> ave_core::governance::witnesses_register::CurrentWitnessSubject {
        ave_core::governance::witnesses_register::CurrentWitnessSubject {
            subject_id,
            target_sn,
        }
    }

    async fn deaf(node: &Api) {
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
            node.test_install_fault(FaultRule {
                direction: FaultDirection::Outbound,
                message,
                peer: None,
                remaining: None,
                action: FaultAction::Drop,
            })
            .await
            .unwrap();
        }
    }

    let (mut nodes, mut dirs) = create_manual_sync_nodes().await;
    let boot_peer = nodes[0].api.peer_id().to_string();
    let boot_addr = nodes[0].listen_address.clone();
    let (mut a, b) = (nodes[1].api.clone(), nodes[2].api.clone());
    let a_key = PublicKey::from_str(&nodes[1].api.public_key()).unwrap();
    let b_key = PublicKey::from_str(&nodes[2].api.public_key()).unwrap();

    // G1 with the Example schema: B (owner) hosts, A is member and
    // schema witness so B serves it. B is the only governance
    // witness: its creates stay self-contained.
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
                    "contract": ave_core::test_contracts::EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0},
                },
            ]},
            "roles": {
                "governance": { "add": {"witness": ["A"]}},
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

    // Tracker T on B, unheard by A: B goes deaf so no creation push
    // hands it over early.
    deaf(&b).await;
    let (t, _) = create_subject(&b, g1.clone(), "Example", "", true)
        .await
        .unwrap();
    b.test_clear_faults().await.unwrap();

    // First incarnation: one fetch, first nonce. Held, never served.
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    hold_outbound(&a, FaultMessage::DistributionLedgerReq).await;
    a.test_tracker_sync_tick(g1.clone()).await.unwrap();
    let n1 = wait_tracker_fetch(&a, &b_key, None).await;
    let stale_subject =
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![9u8; 32]).unwrap();
    let sync_actor = format!("/user/node/subject_manager/{g1}/tracker_sync");

    // Restart A keeping keys and stores: same identity, new
    // incarnation. Holds live in the dead registry: arm them again.
    // NOTE: `dirs` accumulates two entries per node in creation
    // order (boot, A, B), so A's stores are dirs[2] and dirs[3].
    {
        debug_assert_eq!(dirs.len(), 6);
        let node = &mut nodes[1];
        let keys = node.keys.clone();
        let local_db = dirs[2].path().to_path_buf();
        let ext_db = dirs[3].path().to_path_buf();
        node.token.cancel();
        futures::future::join_all(node.handler.iter_mut()).await;
        let port: u16 = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let (new_node, mut new_dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Addressable,
            listen_address: format!("/memory/{port}"),
            peers: vec![RoutingNode {
                peer_id: boot_peer,
                address: vec![boot_addr],
            }],
            always_accept: true,
            is_service: true,
            keys: Some(keys),
            local_db: Some(local_db),
            ext_db: Some(ext_db),
            governance_sync: Some(GovernanceSyncConfig {
                interval_secs: 3600,
                sample_size: 3,
                response_timeout_secs: 3600,
            }),
            tracker_sync: Some(TrackerSyncConfig {
                interval_secs: 3600,
                page_size: 10,
                response_timeout_secs: 3600,
                update_batch_size: 2,
                update_timeout_secs: 5,
            }),
            ..Default::default()
        })
        .await;
        dirs.append(&mut new_dirs);
        node_running(&new_node.api).await.unwrap();
        *node = new_node;
        a = nodes[1].api.clone();
    }
    hold_outbound(&a, FaultMessage::TrackerSyncReq).await;
    hold_outbound(&a, FaultMessage::DistributionLedgerReq).await;

    // The fresh incarnation rebuilds sync actors lazily: poll a
    // manual tick until the first fetch of the new life appears.
    // Ticks are no-ops unless the actor exists and is idle, so no
    // nonce is consumed by waiting.
    let mut n1_new = None;
    for _ in 0..90 {
        let _ = a.test_tracker_sync_tick(g1.clone()).await;
        tokio::time::sleep(Duration::from_secs(1)).await;
        if let Some(nonce) =
            tracker_fetch_nonces(&a, &b_key).await.into_iter().next()
        {
            n1_new = Some(nonce);
            break;
        }
    }
    let n1_new = n1_new.expect("restarted node fetches again");
    assert_ne!(
        n1, n1_new,
        "a new incarnation must not reuse the old first nonce"
    );

    // The retained page answers nothing: no state change, no copies,
    // no new fetch. Only nonces never seen satisfy a fetch.
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        n1,
        1,
        vec![item(stale_subject, 5)],
        None,
    )
    .await;
    // Barrier ensures the stale page was processed (discarded, no copies, no new fetch).
    let _ = a.test_tracker_sync_state(g1.clone()).await.unwrap();
    assert_eq!(
        held_count(&a, FaultMessage::DistributionLedgerReq).await,
        0,
        "a stale page must not launch copies"
    );
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        1,
        "a stale page must not mint requests"
    );

    // The live page answers: exactly its item produces a copy, and
    // the cycle holds no other request.
    inject_sync_page_versioned(
        &a,
        &a_key,
        &b_key,
        &sync_actor,
        n1_new,
        1,
        vec![item(t.clone(), 0)],
        None,
    )
    .await;
    for _ in 0..100 {
        if held_count(&a, FaultMessage::DistributionLedgerReq).await == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let subjects: Vec<DigestIdentifier> = a
        .test_held_outbound()
        .await
        .unwrap_or_default()
        .iter()
        .filter_map(|m| match &m.message {
            ActorMessage::DistributionLedgerReq { subject_id, .. } => {
                Some(subject_id.clone())
            }
            _ => None,
        })
        .collect();
    assert_eq!(
        subjects,
        vec![t.clone()],
        "only the live page item produces a copy request"
    );
    // Barrier ensures the live page was fully processed with no follow-up fetch.
    let _ = a.test_tracker_sync_state(g1.clone()).await.unwrap();
    assert_eq!(
        tracker_fetch_nonces(&a, &b_key).await.len(),
        1,
        "answering the live page mints no extra fetch"
    );
    node_running(&a).await.unwrap();
    node_running(&b).await.unwrap();
}
