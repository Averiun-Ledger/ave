use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response, TimerKey,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use rand::seq::IteratorRandom;
use tracing::{Span, debug, info_span, warn};

use crate::auth::{SubjectAccess, SubjectAccessMessage, SubjectAccessResponse};
use crate::helpers::network::{
    ActorMessage, NetworkMessage, delivery_of, service::NetworkSender,
};
use crate::metrics::try_core_metrics;
use ave_network::ComunicateInfo;

use super::{Governance, GovernanceMessage};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpdateTarget {
    pub peer: PublicKey,
    pub version: u64,
}

/// Constructor parameters for the version sync worker, grouped so the
/// call signature stays readable.
#[derive(Debug, Clone)]
pub struct GovernanceVersionSyncConfig {
    pub governance_id: DigestIdentifier,
    pub our_key: Arc<PublicKey>,
    pub network: Arc<NetworkSender>,
    pub local_version: u64,
    pub sample_size: usize,
    pub tick_interval: Duration,
    pub response_timeout: Duration,
    pub has_boot_nodes: bool,
}

#[derive(Debug, Clone)]
pub enum GovernanceVersionSyncMessage {
    RefreshGovernance {
        version: u64,
        governance_peers: HashSet<PublicKey>,
    },
    Tick,
    RoundTimeout,
    PeerVersion {
        peer: PublicKey,
        version: u64,
    },
}

impl Message for GovernanceVersionSyncMessage {}

#[derive(Debug, Clone)]
pub enum GovernanceVersionSyncResponse {
    None,
}

impl Response for GovernanceVersionSyncResponse {}

pub struct GovernanceVersionSync {
    governance_id: DigestIdentifier,
    our_key: Arc<PublicKey>,
    network: Arc<NetworkSender>,
    local_version: u64,
    sample_size: usize,
    tick_interval: Duration,
    response_timeout: Duration,
    governance_peers: HashSet<PublicKey>,
    pending_peers: HashSet<PublicKey>,
    update_target: Option<UpdateTarget>,
    has_boot_nodes: bool,
    round_open: bool,
    pending_timeout: Option<TimerKey>,
    round: u64,
    peer_backoff: SyncPeerBackoff,
    /// When the current `update_target` was adopted. A target that
    /// never resolves (dead peer, failed distribution) must not pin
    /// the sync forever: once stale, the next tick drops it and opens
    /// a fresh round (SYNC-01).
    target_set_at: Option<Instant>,
    /// Last local version an idle round was reported for. Idle is a
    /// state, not an event: re-notifying every tick is noise
    /// (SYNC-05).
    idle_notified_at_version: Option<u64>,
}

/// Ticks a stale update target may survive without our version
/// moving before the next tick drops it and re-sweeps.
const MAX_STALE_TARGET_ROUNDS: u32 = 10;

/// Most rounds a quiet peer sits out. 1,2,4,8,16 rounds of skip for
/// 1,2,3,4,5+ consecutive silences; any answer resets to zero.
const MAX_BACKOFF_ROUNDS: u64 = 16;

/// Consecutive-failure backoff for sync peers: a peer that goes quiet
/// sits out a few rounds instead of burning one timeout per cycle.
/// Any answer resets it at once — temporary drops are forgiven on the
/// spot, only sustained silence is skipped (SYNC-09). Entries die
/// with success or when the peer leaves the known set, so a dead peer
/// costs one small map entry, never a ban.
#[derive(Debug, Clone, Default)]
pub(crate) struct SyncPeerBackoff {
    failures: HashMap<PublicKey, u32>,
    skip_until_round: HashMap<PublicKey, u64>,
}

impl SyncPeerBackoff {
    fn backoff_rounds(failures: u32) -> u64 {
        (1u64 << failures.saturating_sub(1).min(4)).min(MAX_BACKOFF_ROUNDS)
    }

    pub(crate) fn is_backed_off(
        &self,
        peer: &PublicKey,
        round: u64,
    ) -> bool {
        self.skip_until_round
            .get(peer)
            .is_some_and(|until| round < *until)
    }

    pub(crate) fn note_success(&mut self, peer: &PublicKey) {
        self.failures.remove(peer);
        self.skip_until_round.remove(peer);
    }

    pub(crate) fn note_failure(&mut self, peer: &PublicKey, round: u64) {
        let failures = self.failures.get(peer).unwrap_or(&0) + 1;
        self.failures.insert(peer.clone(), failures);
        // Sits out exactly the next `backoff_rounds` rounds: with
        // `now < skip_until`, that needs the +1 (the failing round
        // itself is already over).
        self.skip_until_round.insert(
            peer.clone(),
            round + Self::backoff_rounds(failures) + 1,
        );
    }

    pub(crate) fn prune(&mut self, known: &HashSet<PublicKey>) {
        self.failures.retain(|peer, _| known.contains(peer));
        self.skip_until_round
            .retain(|peer, _| known.contains(peer));
    }
}

impl GovernanceVersionSync {
    pub fn new(config: GovernanceVersionSyncConfig) -> Self {
        let GovernanceVersionSyncConfig {
            governance_id,
            our_key,
            network,
            local_version,
            sample_size,
            tick_interval,
            response_timeout,
            has_boot_nodes,
        } = config;
        Self {
            governance_id,
            our_key,
            network,
            local_version,
            sample_size: sample_size.max(1),
            tick_interval,
            response_timeout,
            governance_peers: HashSet::new(),
            pending_peers: HashSet::new(),
            update_target: None,
            has_boot_nodes,
            round_open: false,
            pending_timeout: None,
            round: 0,
            peer_backoff: SyncPeerBackoff::default(),
            target_set_at: None,
            idle_notified_at_version: None,
        }
    }

    fn schedule_tick(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        ctx.schedule_once(
            self.tick_interval,
            GovernanceVersionSyncMessage::Tick,
        )?;
        Ok(())
    }

    fn schedule_timeout(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Some(key) = self.pending_timeout.take() {
            ctx.cancel_timer(key);
        }
        let key = ctx.schedule_once(
            self.response_timeout,
            GovernanceVersionSyncMessage::RoundTimeout,
        )?;
        self.pending_timeout = Some(key);
        Ok(())
    }

    fn cancel_timeout(&mut self, ctx: &ActorContext<Self>) {
        if let Some(key) = self.pending_timeout.take() {
            ctx.cancel_timer(key);
        }
    }

    fn refresh_governance(
        &mut self,
        version: u64,
        mut governance_peers: HashSet<PublicKey>,
    ) {
        governance_peers.remove(&*self.our_key);
        self.peer_backoff.prune(&governance_peers);
        if version != self.local_version {
            // New version, new idle state: a past idle report says
            // nothing about this one.
            self.idle_notified_at_version = None;
        }
        self.local_version = version;
        self.governance_peers = governance_peers;

        if self
            .update_target
            .as_ref()
            .is_some_and(|target| target.version <= version)
        {
            self.update_target = None;
            self.target_set_at = None;
        }
    }

    /// Drops an update target that never resolved: the peer may be
    /// gone or the distribution may have failed silently, and no new
    /// round opens while a target is set. Returns true when a stale
    /// target was dropped.
    fn drop_stale_target(&mut self) -> bool {
        let Some(set_at) = self.target_set_at else {
            return false;
        };
        if self.update_target.is_none()
            || set_at.elapsed()
                < self.tick_interval * MAX_STALE_TARGET_ROUNDS
        {
            return false;
        }
        if let Some(target) = self.update_target.take() {
            warn!(
                governance_id = %self.governance_id,
                peer = %target.peer,
                version = target.version,
                "Update target never resolved, dropping it and re-sweeping"
            );
        }
        self.target_set_at = None;
        true
    }

    /// Reports an idle round at most once per local version: idle
    /// is a state, and every tick re-proving it would spam the
    /// governance actor with full acquisition passes (SYNC-05).
    async fn maybe_notify_idle_round(
        &mut self,
        ctx: &ActorContext<Self>,
    ) {
        if self.idle_notified_at_version != Some(self.local_version) {
            self.idle_notified_at_version = Some(self.local_version);
            self.notify_idle_round(ctx).await;
        }
    }

    async fn trigger_update_if_needed(
        &mut self,
        ctx: &ActorContext<Self>,
        notify_idle: bool,
    ) -> Result<(), ActorError> {
        let Some(UpdateTarget { peer, .. }) = self.update_target.clone() else {
            if notify_idle {
                // The round proved this node is at the tip: either every
                // selected peer answered and none is ahead, or the node
                // is verifiably alone on the network. Deferred artifact
                // acquisitions are due if any are pending.
                self.maybe_notify_idle_round(ctx).await;
            }
            return Ok(());
        };

        let info = ComunicateInfo {
            receiver: peer,
            request_id: String::default(),
            version: 0,
            receiver_actor: format!(
                "/user/node/distributor_{}",
                self.governance_id
            ),
        };

        let message = ActorMessage::DistributionLedgerReq {
            actual_sn: Some(self.local_version),
            target_sn: None,
            subject_id: self.governance_id.clone(),
            already_verified_transfer_sn: None,
        };
        self.network
            .send_command(ave_network::CommandHelper::SendMessage {
                delivery: delivery_of(&message),
                message: NetworkMessage::new(info, message),
            })
            .await
    }

    /// A completed round with no update needed means this node is
    /// at the tip — tell the governance actor that deferred artifact
    /// acquisitions (if any) are due. Covers a reboot with pending
    /// markers where no distribution round will ever fire.
    async fn notify_idle_round(&self, ctx: &ActorContext<Self>) {
        match ctx.get_parent::<Governance>().await {
            Ok(governance) => {
                if let Err(error) =
                    governance.tell(GovernanceMessage::SyncRoundIdle).await
                {
                    debug!(
                        governance_id = %self.governance_id,
                        error = %error,
                        "Failed to notify idle sync round to governance"
                    );
                }
            }
            Err(error) => {
                debug!(
                    governance_id = %self.governance_id,
                    error = %error,
                    "Governance actor not found for idle sync round"
                );
            }
        }
    }

    async fn get_sync_peers(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<HashSet<PublicKey>, ActorError> {
        let access_path = ActorPath::from("/user/node/auth");
        let access = ctx
            .system()
            .get_actor::<SubjectAccess>(&access_path)
            .await?;
        match access
            .ask(SubjectAccessMessage::GetSyncPeers {
                subject_id: self.governance_id.clone(),
            })
            .await
        {
            Ok(SubjectAccessResponse::Peers(mut peers)) => {
                peers.remove(&*self.our_key);
                Ok(peers)
            }
            Ok(_) => Ok(HashSet::new()),
            Err(ActorError::Functional { .. }) => Ok(HashSet::new()),
            Err(error) => Err(error),
        }
    }

    fn select_peers(
        &mut self,
        sync_peers: HashSet<PublicKey>,
    ) -> Vec<PublicKey> {
        let mut peers = self.governance_peers.clone();
        peers.extend(sync_peers);
        peers.remove(&*self.our_key);
        // Forget peers that left the known set; skip the ones still
        // sitting out a silence backoff.
        self.peer_backoff.prune(&peers);
        peers.retain(|peer| !self.peer_backoff.is_backed_off(peer, self.round));

        if peers.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        peers
            .iter()
            .cloned()
            .sample(&mut rng, self.sample_size.min(peers.len()))
    }

    fn peer_version(&mut self, peer: PublicKey, version: u64) -> bool {
        if !self.round_open || !self.pending_peers.remove(&peer) {
            return false;
        }
        // It answered: whatever the version says, the peer is alive —
        // forgive any silence backoff on the spot.
        self.peer_backoff.note_success(&peer);

        if version <= self.local_version {
            return self.pending_peers.is_empty();
        }

        let should_replace = self
            .update_target
            .as_ref()
            .is_none_or(|target| version > target.version);
        if should_replace {
            self.update_target = Some(UpdateTarget { peer, version });
            self.target_set_at = Some(Instant::now());
        }

        self.pending_peers.is_empty()
    }

    async fn handle_tick(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // A target that never resolved pins the sync: drop it once
        // stale so this tick opens a fresh round instead of
        // no-op-ing forever (SYNC-01).
        self.drop_stale_target();
        if self.update_target.is_some() {
            self.schedule_tick(ctx)?;
            return Ok(());
        }
        self.round += 1;

        let sync_peers = match self.get_sync_peers(ctx).await {
            Ok(peers) => peers,
            Err(e) => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_governance_version_sync_failure(
                        "sync_peers_failed",
                    );
                }
                return Err(e);
            }
        };
        let peers = self.select_peers(sync_peers);

        if peers.is_empty() {
            // Nobody to compare against. Only a node with no configured
            // boot nodes may treat this as an idle round: it is
            // verifiably alone, so nothing newer is reachable. With
            // configured peers the empty set proves nothing (discovery
            // may be incomplete) and must never count as idle.
            if !self.has_boot_nodes {
                self.maybe_notify_idle_round(ctx).await;
            }
            self.schedule_tick(ctx)?;
            return Ok(());
        }

        self.pending_peers = peers.into_iter().collect();
        self.round_open = !self.pending_peers.is_empty();

        for peer in self.pending_peers.clone() {
            let message = NetworkMessage::new(
                ComunicateInfo {
                    receiver: peer.clone(),
                    request_id: String::default(),
                    version: 0,
                    receiver_actor: format!(
                        "/user/node/distributor_{}",
                        self.governance_id
                    ),
                },
                ActorMessage::GovernanceVersionReq {
                    subject_id: self.governance_id.clone(),
                    receiver_actor: ctx.path().to_string(),
                },
            );

            if let Err(error) = self
                .network
                .send_command(ave_network::CommandHelper::SendMessage {
                    delivery: delivery_of(&message.message),
                    message,
                })
                .await
            {
                warn!(
                    governance_id = %self.governance_id,
                    peer = %peer,
                    error = %error,
                    "Failed to send governance version request"
                );
                self.pending_peers.remove(&peer);
            }
        }

        if self.pending_peers.is_empty()
            && let Some(metrics) = try_core_metrics()
        {
            metrics.observe_governance_version_sync_failure(
                "all_peers_unreachable",
            );
        }

        debug!(
            governance_id = %self.governance_id,
            local_version = self.local_version,
            selected_peers = self.pending_peers.len(),
            "Governance version sync tick"
        );

        // The actual network request/response path is integrated later.
        self.schedule_timeout(ctx)?;
        self.schedule_tick(ctx)?;

        Ok(())
    }
}

#[async_trait]
impl Actor for GovernanceVersionSync {
    type Event = ();
    type Message = GovernanceVersionSyncMessage;
    type Response = GovernanceVersionSyncResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("GovernanceVersionSync"),
            |parent| info_span!(parent: parent, "GovernanceVersionSync"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.schedule_tick(ctx)?;
        Ok(())
    }
}

impl NotPersistentActor for GovernanceVersionSync {}

#[async_trait]
impl Handler<Self> for GovernanceVersionSync {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: GovernanceVersionSyncMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<GovernanceVersionSyncResponse, ActorError> {
        match msg {
            GovernanceVersionSyncMessage::RefreshGovernance {
                version,
                governance_peers,
            } => {
                self.refresh_governance(version, governance_peers);
            }
            GovernanceVersionSyncMessage::Tick => {
                if let Err(error) = self.handle_tick(ctx).await {
                    warn!(
                        governance_id = %self.governance_id,
                        error = %error,
                        "Governance version sync tick failed"
                    );
                    // A failed tick must still arm the next one: the
                    // consumed timer was the only one, and without it
                    // the sync dies silently (SYNC-02).
                    if let Err(e) = self.schedule_tick(ctx) {
                        warn!(
                            governance_id = %self.governance_id,
                            error = %e,
                            "Failed to reschedule sync tick after error"
                        );
                    }
                }
            }
            GovernanceVersionSyncMessage::RoundTimeout => {
                self.cancel_timeout(ctx);
                if self.round_open {
                    self.round_open = false;
                    // Whoever never answered goes quieter next rounds;
                    // whoever did already forgave itself in
                    // `peer_version`.
                    for peer in self.pending_peers.drain() {
                        self.peer_backoff.note_failure(&peer, self.round);
                    }
                    // An expired round means at least one selected peer
                    // never answered. Silence only counts as an idle
                    // round on a node with no configured boot nodes:
                    // verifiably alone, nobody can be ahead. With
                    // configured peers a silent peer may still be ahead
                    // (partition, slow discovery), so the round may only
                    // fire an already known update target.
                    let notify_idle = !self.has_boot_nodes;
                    if let Err(error) =
                        self.trigger_update_if_needed(ctx, notify_idle).await
                    {
                        if let Some(metrics) = try_core_metrics() {
                            metrics.observe_governance_version_sync_failure(
                                "trigger_update_failed",
                            );
                        }
                        warn!(
                            governance_id = %self.governance_id,
                            error = %error,
                            "Failed to trigger governance update after round timeout"
                        );
                    }
                }
            }
            GovernanceVersionSyncMessage::PeerVersion { peer, version } => {
                if self.peer_version(peer.clone(), version) {
                    self.cancel_timeout(ctx);
                    self.round_open = false;
                    if let Err(error) =
                        self.trigger_update_if_needed(ctx, true).await
                    {
                        if let Some(metrics) = try_core_metrics() {
                            metrics.observe_governance_version_sync_failure(
                                "trigger_update_failed",
                            );
                        }
                        warn!(
                            governance_id = %self.governance_id,
                            error = %error,
                            "Failed to trigger governance update after round completion"
                        );
                    }
                } else if version > self.local_version
                    && self.governance_peers.contains(&peer)
                    && self
                        .update_target
                        .as_ref()
                        .is_none_or(|target| version > target.version)
                {
                    // Late but valuable: the round already closed, yet
                    // a known peer is ahead of us (and of any target).
                    // Adopt it and fire the update now instead of
                    // dropping the intel until the next tick (SYNC-03).
                    // Not an idle proof, so no idle notify.
                    self.peer_backoff.note_success(&peer);
                    self.update_target =
                        Some(UpdateTarget { peer, version });
                    self.target_set_at = Some(Instant::now());
                    if let Err(error) =
                        self.trigger_update_if_needed(ctx, false).await
                    {
                        warn!(
                            governance_id = %self.governance_id,
                            error = %error,
                            "Failed to trigger governance update after late peer version"
                        );
                    }
                }
            }
        }

        Ok(GovernanceVersionSyncResponse::None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::identity::keys::{Ed25519Signer, KeyPair};

    fn peer() -> PublicKey {
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key()
    }

    #[test]
    fn backoff_skips_more_rounds_per_silence_and_forgives() {
        let mut backoff = SyncPeerBackoff::default();
        let p = peer();
        assert!(!backoff.is_backed_off(&p, 0));

        backoff.note_failure(&p, 0);
        assert!(backoff.is_backed_off(&p, 0));
        assert!(backoff.is_backed_off(&p, 1));
        assert!(!backoff.is_backed_off(&p, 2));

        backoff.note_failure(&p, 1);
        assert!(backoff.is_backed_off(&p, 2));
        assert!(backoff.is_backed_off(&p, 3));
        assert!(!backoff.is_backed_off(&p, 4));

        // Five silences saturate at the cap, never more.
        for round in 2..7 {
            backoff.note_failure(&p, round);
        }
        assert!(backoff.is_backed_off(&p, 22));
        assert!(!backoff.is_backed_off(&p, 23));

        // One answer wipes everything: temporary drops are forgiven.
        backoff.note_success(&p);
        assert!(!backoff.is_backed_off(&p, 7));
    }

    #[test]
    fn backoff_prune_forgets_gone_peers() {
        let mut backoff = SyncPeerBackoff::default();
        let (a, b) = (peer(), peer());
        backoff.note_failure(&a, 0);
        backoff.note_failure(&b, 0);
        backoff.prune(&HashSet::from([a.clone()]));
        assert!(backoff.is_backed_off(&a, 0));
        assert!(!backoff.is_backed_off(&b, 0));
    }
}
