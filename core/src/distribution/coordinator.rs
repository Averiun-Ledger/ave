use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, IntervalStrategy,
    Message, NotPersistentActor, RetryActor, RetryMessage, Strategy, TimerKey,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage,
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::{common::crash_system, event::Ledger, network::RetryNetwork},
    system::ConfigHelper,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{Distribution, DistributionMessage, error::DistributorError};

pub struct DistriCoordinator {
    pub node_key: PublicKey,
    pub network: Arc<NetworkSender>,
    /// Hash of the exact event bytes sent on this route, computed
    /// with the configured algorithm. A response is accepted only
    /// when it names this hash: the sender alone can not close a
    /// newer generation with an older ack, while a resent ack for
    /// this same event stays idempotent.
    pub(crate) expected_event_hash: Option<DigestIdentifier>,
    /// Fragments of an oversized event awaiting their ack, with the
    /// resend timer and tries left. `None` in single-message mode.
    pub(crate) frag_pending: Option<FragSendState>,
    pub(crate) frag_timer: Option<TimerKey>,
}

/// Resend state for an oversized pushed event: the fragments go out
/// together and are resent together until the hash-verified ack
/// arrives or the tries run out.
pub(crate) struct FragSendState {
    frags: Vec<ActorMessage>,
    request_id: String,
    receiver_actor: String,
    tries_left: u32,
}

/// Test-only push-fragment lifecycle counters, shared across
/// coordinators via the `push_frag_stats` helper. Records, per
/// subject, failed initial sends, resent group identities, consumed
/// acks and live fragment groups/timers. A test proves the injected
/// first-send failure really fired, the retry resent the whole group
/// under the same identity, the ack was consumed exactly once and
/// nothing stays pending on either side. Zero cost in production:
/// the struct, helper and every call site only exist under
/// `#[cfg(feature = "test")]`.
#[cfg(feature = "test")]
#[derive(Debug, Default)]
pub(crate) struct PushFragStatsRegistry {
    initial_failures: std::collections::HashMap<DigestIdentifier, u64>,
    resends: std::collections::HashMap<DigestIdentifier, Vec<DigestIdentifier>>,
    acks: std::collections::HashMap<DigestIdentifier, u64>,
    live_groups: std::collections::HashMap<DigestIdentifier, i64>,
    live_timers: std::collections::HashMap<DigestIdentifier, i64>,
}

#[cfg(feature = "test")]
pub(crate) type SharedPushFragStats =
    std::sync::Arc<std::sync::Mutex<PushFragStatsRegistry>>;

#[cfg(feature = "test")]
impl PushFragStatsRegistry {
    pub(crate) fn note_initial_failure(
        &mut self,
        subject_id: &DigestIdentifier,
    ) {
        *self.initial_failures.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn note_resend(
        &mut self,
        subject_id: &DigestIdentifier,
        group_hash: DigestIdentifier,
    ) {
        self.resends
            .entry(subject_id.clone())
            .or_default()
            .push(group_hash);
    }

    pub(crate) fn note_ack(&mut self, subject_id: &DigestIdentifier) {
        *self.acks.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn note_group_open(&mut self, subject_id: &DigestIdentifier) {
        *self.live_groups.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn note_group_closed(&mut self, subject_id: &DigestIdentifier) {
        *self.live_groups.entry(subject_id.clone()).or_default() -= 1;
    }

    pub(crate) fn note_timer_armed(&mut self, subject_id: &DigestIdentifier) {
        *self.live_timers.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn note_timer_gone(&mut self, subject_id: &DigestIdentifier) {
        *self.live_timers.entry(subject_id.clone()).or_default() -= 1;
    }

    pub(crate) fn snapshot(
        &self,
        subject_id: &DigestIdentifier,
    ) -> (u64, Vec<DigestIdentifier>, u64, i64, i64) {
        (
            self.initial_failures.get(subject_id).copied().unwrap_or(0),
            self.resends.get(subject_id).cloned().unwrap_or_default(),
            self.acks.get(subject_id).copied().unwrap_or(0),
            self.live_groups.get(subject_id).copied().unwrap_or(0),
            self.live_timers.get(subject_id).copied().unwrap_or(0),
        )
    }
}

#[cfg(feature = "test")]
impl DistriCoordinator {
    fn push_stats(ctx: &ActorContext<Self>) -> Option<SharedPushFragStats> {
        ctx.system()
            .get_helper::<SharedPushFragStats>("push_frag_stats")
    }

    /// Subject and group identity carried by a fragment batch: the
    /// coordinator itself never stores them, so tests read them off
    /// the wire frames it already holds.
    fn frag_identity(
        frags: &[ActorMessage],
    ) -> Option<(DigestIdentifier, DigestIdentifier)> {
        match frags.first()? {
            ActorMessage::DistributionLedgerFrag {
                subject_id,
                group_hash,
                ..
            } => Some((subject_id.clone(), group_hash.clone())),
            _ => None,
        }
    }

    fn note_initial_failure(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_initial_failure(subject_id);
        }
    }

    fn note_resend(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        group_hash: DigestIdentifier,
    ) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_resend(subject_id, group_hash);
        }
    }

    fn note_ack(ctx: &ActorContext<Self>, subject_id: &DigestIdentifier) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_ack(subject_id);
        }
    }

    fn note_group_open(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_group_open(subject_id);
        }
    }

    fn note_group_closed(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_group_closed(subject_id);
        }
    }

    fn note_timer_armed(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_timer_armed(subject_id);
        }
    }

    fn note_timer_gone(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) = Self::push_stats(ctx)
            && let Ok(mut stats) = stats.lock()
        {
            stats.note_timer_gone(subject_id);
        }
    }
}

#[async_trait]
impl Actor for DistriCoordinator {
    type Event = ();
    type Message = DistriCoordinatorMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("DistriCoordinator", id),
            |parent_span| info_span!(parent: parent_span, "DistriCoordinator", id),
        )
    }
}

#[derive(Debug, Clone)]
pub enum DistriCoordinatorMessage {
    EndRetry,
    FragRetry,
    // Enviar a un nodo la replicación.
    NetworkDistribution {
        request_id: String,
        ledger: Box<Ledger>,
    },
    // The node the replica was sent to acknowledged receipt,
    // naming the event it received. Only the matching generation
    // completes; anything else is a stale or forged ack that must
    // leave the retry alive.
    NetworkResponse {
        sender: PublicKey,
        event_hash: DigestIdentifier,
    },
}

impl Message for DistriCoordinatorMessage {}

impl NotPersistentActor for DistriCoordinator {}

impl DistriCoordinator {
    /// Shared timeout close for both modes: the retry (or the
    /// fragments) never got their verified ack, so the witness
    /// leaves the pending set recorded as unacked.
    async fn finish_with_timeout(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // Test-only lifecycles mirror the transitions below, so a
        // leaked group or timer fails the suites instead of hiding.
        #[cfg(feature = "test")]
        let subject_id = self
            .frag_pending
            .as_ref()
            .and_then(|pending| Self::frag_identity(&pending.frags))
            .map(|(subject_id, _)| subject_id);
        if let Some(key) = self.frag_timer.take() {
            ctx.cancel_timer(key);
            #[cfg(feature = "test")]
            if let Some(subject_id) = &subject_id {
                Self::note_timer_gone(ctx, subject_id);
            }
        }
        #[cfg(feature = "test")]
        if let Some(subject_id) = &subject_id {
            Self::note_group_closed(ctx, subject_id);
        }
        self.frag_pending = None;
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("distribution", "witness_timeout");
        }
        warn!(
            msg_type = "Coordinator",
            node_key = %self.node_key,
            "Retry exhausted, notifying parent and stopping"
        );

        match ctx.get_parent::<Distribution>().await {
            Ok(distribution_actor) => {
                if let Err(e) = distribution_actor
                    .tell(DistributionMessage::Timeout {
                        sender: self.node_key.clone(),
                    })
                    .await
                {
                    error!(
                        msg_type = "Coordinator",
                        node_key = %self.node_key,
                        "Failed to notify parent distribution actor after retry exhausted"
                    );
                    crash_system(ctx, e).await;
                } else {
                    debug!(
                        msg_type = "Coordinator",
                        node_key = %self.node_key,
                        "Parent distribution actor notified of retry exhaustion"
                    );
                }
            }
            Err(e) => {
                error!(
                    msg_type = "Coordinator",
                    node_key = %self.node_key,
                    error = %e,
                    "Failed to get parent distribution actor after retry exhausted"
                );
                crash_system(ctx, e).await;
            }
        }

        ctx.stop(None).await;
        Ok(())
    }

    /// Arms the fragment resend timer with the same cadence as the
    /// single-message retry.
    fn arm_frag_timer(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        #[cfg(feature = "test")]
        let subject_id = self
            .frag_pending
            .as_ref()
            .and_then(|pending| Self::frag_identity(&pending.frags))
            .map(|(subject_id, _)| subject_id);
        if let Some(key) = self.frag_timer.take() {
            ctx.cancel_timer(key);
            #[cfg(feature = "test")]
            if let Some(subject_id) = &subject_id {
                Self::note_timer_gone(ctx, subject_id);
            }
        }
        #[cfg(any(test, feature = "test"))]
        let interval = Duration::from_secs(2);
        #[cfg(not(any(test, feature = "test")))]
        let interval = Duration::from_secs(30);
        let key =
            ctx.schedule_once(interval, DistriCoordinatorMessage::FragRetry)?;
        self.frag_timer = Some(key);
        #[cfg(feature = "test")]
        if let Some(subject_id) = &subject_id {
            Self::note_timer_armed(ctx, subject_id);
        }
        Ok(())
    }

    /// Sends every fragment with the route identity the ack must
    /// come back on. Each frame is validated by the sender check,
    /// so an oversize computation here fails loud instead of
    /// looping.
    async fn send_frags(
        &self,
        frags: &[ActorMessage],
        request_id: &str,
        receiver_actor: &str,
    ) -> Result<(), ActorError> {
        for frag in frags {
            let message = NetworkMessage::new(
                ComunicateInfo {
                    request_id: request_id.to_owned(),
                    version: 0,
                    receiver: self.node_key.clone(),
                    receiver_actor: receiver_actor.to_owned(),
                },
                frag.clone(),
            );
            self.network
                .send_command(ave_network::CommandHelper::SendMessage {
                    delivery: crate::helpers::network::delivery_of(frag),
                    message,
                })
                .await?;
        }
        Ok(())
    }

    /// Fragmented send for an event that exceeds the wire cap: split
    /// by identity, resent together until the hash-verified ack, and
    /// closed through the same parent timeout when exhausted.
    async fn send_fragmented(
        &mut self,
        ctx: &mut ActorContext<Self>,
        config: &ConfigHelper,
        request_id: String,
        receiver_actor: String,
        ledger: Box<Ledger>,
    ) -> Result<(), ActorError> {
        use super::worker::DistriWorker;

        let subject_id = ledger.get_subject_id();
        let sn = ledger.sn;
        let Some(expected) = self.expected_event_hash.clone() else {
            error!(
                msg_type = "NetworkDistribution",
                subject_id = %subject_id,
                sn = sn,
                "Missing ack identity for fragmented event"
            );
            return Err(ActorError::Functional {
                description: "Missing ack identity for fragmented event"
                    .to_owned(),
            });
        };
        // Same total bound as the pull path: an event that can
        // never be accepted must fail before the first send instead
        // of retrying forever.
        let probe_bytes =
            borsh::to_vec(&*ledger).map_err(|e| ActorError::Functional {
                description: format!("Can not encode fragmented event: {e}"),
            })?;
        if probe_bytes.len() as u64
            > DistriWorker::MAX_FRAGMENT_EVENT_BYTES as u64
        {
            return Err(ActorError::Functional {
                description: format!(
                    "Fragmented event ({} bytes) exceeds the reassembly bound ({} bytes)",
                    probe_bytes.len(),
                    DistriWorker::MAX_FRAGMENT_EVENT_BYTES
                ),
            });
        }
        let chunk_size =
            DistriWorker::fragment_chunk_size(config.max_message_bytes);
        let frags = DistriWorker::build_event_fragments(
            &ledger,
            config.hash_algorithm,
            chunk_size,
            super::worker::FragmentSpec {
                subject_id: subject_id.clone(),
                group_hash: expected.clone(),
                group_sn: sn,
                is_aux: false,
                aux_hash: None,
                is_all: true,
                is_push: true,
                expected_governance_id: None,
            },
        )?;
        let frag_count = frags.len();
        #[cfg(any(test, feature = "test"))]
        let tries = 2u32;
        #[cfg(not(any(test, feature = "test")))]
        let tries = 3u32;
        // Install the resend state and its timer before the first
        // send: a failure there must behave like any retry round
        // (log and keep the group for the next round) instead of
        // killing the coordinator with nothing armed.
        self.frag_pending = Some(FragSendState {
            frags,
            request_id,
            receiver_actor,
            tries_left: tries,
        });
        #[cfg(feature = "test")]
        Self::note_group_open(ctx, &subject_id);
        if let Err(e) = self.arm_frag_timer(ctx) {
            error!(
                msg_type = "NetworkDistribution",
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Failed to arm fragment retry"
            );
            return Err(crash_system(ctx, e).await);
        }
        if let Err(e) = {
            let pending = self.frag_pending.as_ref().ok_or_else(|| {
                ActorError::Functional {
                    description: "Fragment retry state missing".to_owned(),
                }
            })?;
            self.send_frags(
                &pending.frags,
                &pending.request_id,
                &pending.receiver_actor,
            )
            .await
        } {
            warn!(
                msg_type = "NetworkDistribution",
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Initial fragment send failed, keeping retry alive"
            );
            #[cfg(feature = "test")]
            Self::note_initial_failure(ctx, &subject_id);
        }

        debug!(
            msg_type = "NetworkDistribution",
            subject_id = %subject_id,
            sn = sn,
            node_key = %self.node_key,
            chunks = frag_count,
            "Oversized event fragmented for distribution"
        );
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for DistriCoordinator {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: DistriCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            DistriCoordinatorMessage::EndRetry => {
                self.finish_with_timeout(ctx).await?;
            }
            DistriCoordinatorMessage::FragRetry => {
                // The retry timer fired: consume its arm here; the
                // re-arm below counts a fresh one. Taking first keeps
                // a fired key from being double-counted at re-arm.
                #[cfg(feature = "test")]
                if self.frag_timer.take().is_some()
                    && let Some(pending) = self.frag_pending.as_ref()
                    && let Some((subject_id, _)) =
                        Self::frag_identity(&pending.frags)
                {
                    Self::note_timer_gone(ctx, &subject_id);
                }
                let Some(mut pending) = self.frag_pending.take() else {
                    return Ok(());
                };
                if pending.tries_left == 0 {
                    #[cfg(feature = "test")]
                    if let Some((subject_id, _)) =
                        Self::frag_identity(&pending.frags)
                    {
                        Self::note_group_closed(ctx, &subject_id);
                    }
                    self.finish_with_timeout(ctx).await?;
                    return Ok(());
                }
                pending.tries_left = pending.tries_left.saturating_sub(1);
                // Best effort resend: a failed fragment rides the
                // next retry, and exhaustion still closes loudly
                // through the timeout below. The whole group goes out
                // together under its original identity.
                #[cfg(feature = "test")]
                if let Some((subject_id, group_hash)) =
                    Self::frag_identity(&pending.frags)
                {
                    Self::note_resend(ctx, &subject_id, group_hash);
                }
                if let Err(e) = self
                    .send_frags(
                        &pending.frags,
                        &pending.request_id,
                        &pending.receiver_actor,
                    )
                    .await
                {
                    warn!(
                        msg_type = "FragRetry",
                        node_key = %self.node_key,
                        error = %e,
                        "Failed to resend fragments, keeping retry alive"
                    );
                }
                self.frag_pending = Some(pending);
                if let Err(e) = self.arm_frag_timer(ctx) {
                    error!(
                        msg_type = "FragRetry",
                        node_key = %self.node_key,
                        error = %e,
                        "Failed to rearm fragment retry"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            DistriCoordinatorMessage::NetworkDistribution {
                request_id,
                ledger,
            } => {
                let subject_id = ledger.get_subject_id();
                let sn = ledger.sn;

                // Bind this generation to the exact event bytes on
                // the wire (already projected per recipient by the
                // parent): the ack must name it back.
                let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config")
                else {
                    error!(
                        msg_type = "NetworkDistribution",
                        subject_id = %subject_id,
                        sn = sn,
                        "Config helper not found while binding ack identity"
                    );
                    return Err(ActorError::Helper {
                        name: "config".to_owned(),
                        reason: "Not found".to_owned(),
                    });
                };
                match ledger.ledger_hash(config.hash_algorithm) {
                    Ok(event_hash) => {
                        self.expected_event_hash = Some(event_hash);
                    }
                    Err(e) => {
                        error!(
                            msg_type = "NetworkDistribution",
                            subject_id = %subject_id,
                            sn = sn,
                            error = %e,
                            "Failed to hash distributed event"
                        );
                        return Err(ActorError::Functional {
                            description: format!(
                                "Can not hash distributed event: {e}"
                            ),
                        });
                    }
                }

                let receiver_actor =
                    format!("/user/node/distributor_{}", subject_id);

                // An event that fits the cap travels whole with the
                // usual retry; an oversized one is fragmented by
                // identity instead of looping on a batch the
                // transport must drop.
                let probe = NetworkMessage::new(
                    ComunicateInfo {
                        request_id: request_id.to_string(),
                        version: 0,
                        receiver: self.node_key.clone(),
                        receiver_actor: receiver_actor.clone(),
                    },
                    ActorMessage::DistributionLastEventReq {
                        ledger: ledger.clone(),
                    },
                );
                let fits = rmp_serde::to_vec(&probe)
                    .map(|bytes| bytes.len() <= config.max_message_bytes)
                    .unwrap_or(false);
                if !fits {
                    return self
                        .send_fragmented(
                            ctx,
                            &config,
                            request_id,
                            receiver_actor,
                            ledger,
                        )
                        .await;
                }

                let message = NetworkMessage::new(
                    ComunicateInfo {
                        request_id: request_id.to_string(),
                        version: 0,
                        receiver: self.node_key.clone(),
                        receiver_actor,
                    },
                    ActorMessage::DistributionLastEventReq { ledger },
                );

                let target = RetryNetwork::new(self.network.clone());

                #[cfg(any(test, feature = "test"))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    2,
                    Duration::from_secs(2),
                ));
                #[cfg(not(any(test, feature = "test")))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    3,
                    Duration::from_secs(30),
                ));

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    DistriCoordinatorMessage::EndRetry,
                );

                let retry = match ctx
                    .create_child::<RetryActor<RetryNetwork>, _>(
                        "retry",
                        retry_actor,
                    )
                    .await
                {
                    Ok(retry) => retry,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkDistribution",
                            subject_id = %subject_id,
                            sn = sn,
                            node_key = %self.node_key,
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkDistribution",
                        subject_id = %subject_id,
                        sn = sn,
                        node_key = %self.node_key,
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(crash_system(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkDistribution",
                    subject_id = %subject_id,
                    sn = sn,
                    node_key = %self.node_key,
                    request_id = %request_id,
                    "Distribution retry initiated"
                );
            }
            DistriCoordinatorMessage::NetworkResponse {
                sender,
                event_hash,
            } => {
                if sender != self.node_key {
                    error!(
                        msg_type = "NetworkResponse",
                        sender = %sender,
                        expected = %self.node_key,
                        "Unexpected sender in network response"
                    );
                    return Err(DistributorError::UnexpectedSender.into());
                }
                if self.expected_event_hash.as_ref() != Some(&event_hash) {
                    // Stale ack from a previous generation on this
                    // route, or a mismatched claim: ignore it without
                    // touching the retry, the parent or this actor.
                    warn!(
                        msg_type = "NetworkResponse",
                        sender = %sender,
                        expected = ?self.expected_event_hash,
                        received = %event_hash,
                        "Ignoring ack for another event generation"
                    );
                    return Ok(());
                }

                // The verified ack completes this generation in both
                // modes: drop any fragment resend timer alongside the
                // retry actor below.
                #[cfg(feature = "test")]
                let ack_identity = self
                    .frag_pending
                    .as_ref()
                    .and_then(|pending| Self::frag_identity(&pending.frags));
                if let Some(key) = self.frag_timer.take() {
                    ctx.cancel_timer(key);
                    #[cfg(feature = "test")]
                    if let Some((subject_id, _)) = &ack_identity {
                        Self::note_timer_gone(ctx, subject_id);
                    }
                }
                #[cfg(feature = "test")]
                if let Some((subject_id, _)) = &ack_identity {
                    Self::note_group_closed(ctx, subject_id);
                    Self::note_ack(ctx, subject_id);
                }
                self.frag_pending = None;

                match ctx.get_parent::<Distribution>().await {
                    Ok(distribution_actor) => {
                        if let Err(e) = distribution_actor
                            .tell(DistributionMessage::Response {
                                sender: sender.clone(),
                            })
                            .await
                        {
                            error!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                error = %e,
                                "Failed to notify parent distribution actor"
                            );
                            return Err(crash_system(ctx, e).await);
                        }
                    }
                    Err(e) => {
                        error!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Failed to get parent distribution actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                }

                'retry: {
                    let Ok(retry) = ctx
                        .get_child::<RetryActor<RetryNetwork>>("retry")
                        .await
                    else {
                        debug!(
                            msg_type = "NetworkResponse",
                            sender = %sender,
                            "Retry actor not found while closing distribution coordinator"
                        );
                        break 'retry;
                    };

                    if let Err(e) = retry.tell(RetryMessage::End).await {
                        warn!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Failed to end retry actor, stopping anyway"
                        );
                        break 'retry;
                    };
                }

                debug!(
                    msg_type = "NetworkResponse",
                    sender = %sender,
                    "Distribution acknowledged, stopping distributor"
                );

                ctx.stop(None).await;
            }
        };

        Ok(())
    }
}
