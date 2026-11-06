//! SinkWorker: ephemeral worker actor that sends events to external HTTP sinks.
//!
//! Lifecycle: the SinkWorker reports inactivity to the parent SinkManager via
//! WorkerIdle.  The MANAGER decides when to stop the worker (after a
//! configurable idle timeout).  The worker NEVER self-destructs.

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler, Message,
    NotPersistentActor, OverflowStrategy, Response, TimerKey,
};
use serde::{Deserialize, Serialize};
use tracing::{debug, error, info_span, warn};

use crate::config::SinkServer;
use crate::sink::SinkError;
use crate::sink::extract_sn;
use crate::sink::manager::{
    SendResult, SinkManager, SinkManagerMessage, SinkWorkerError,
};
use crate::sink::transport::{NodeSigner, SinkTransport};
use ave_common::DataToSink;

// ---------------------------------------------------------------------------
// Test instrumentation
// ---------------------------------------------------------------------------

/// Test-only count of pending-queue elements scanned by the linear
/// admission/dedup searches, per sink: enqueuing Q distinct subjects
/// while the slots stay busy scans Q(Q-1)/2 elements. Lets regression
/// tests assert that catch-up admission does not walk the queue.
/// Keyed by sink name so tests sharing a process do not pollute each
/// other.
#[cfg(feature = "test")]
static PENDING_SCAN_COMPARISONS: std::sync::LazyLock<
    std::sync::Mutex<HashMap<String, u64>>,
> = std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

/// Test-only: reset the pending-scan counter for one sink.
#[cfg(feature = "test")]
pub fn test_reset_pending_scan_comparisons(sink: &str) {
    if let Ok(mut counts) = PENDING_SCAN_COMPARISONS.lock() {
        counts.remove(sink);
    }
}

/// Test-only: read the pending-scan counter for one sink.
#[cfg(feature = "test")]
pub fn test_pending_scan_comparisons(sink: &str) -> u64 {
    PENDING_SCAN_COMPARISONS
        .lock()
        .map(|counts| counts.get(sink).copied().unwrap_or(0))
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkWorkerMessage {
    NotifyNewEvent(Arc<DataToSink>),
    HealthCheck,
    CatchUp {
        subject_id: String,
        from_sn: u64,
    },
    /// Reset flapping counter when the sink is manually unblocked.
    ResetRecoveries,
    /// Clear the blocked state when the sink is manually unblocked.
    ClearBlocked,
    /// Parent tells the worker to stop (manager-controlled lifecycle).
    Stop,
    // -- Mensajes internos (de los hijos) --
    DeliveryResult {
        subject_id: String,
        sn: u64,
        result: crate::sink::manager::SendResult,
        count: u64,
    },
    CatchUpProgress {
        subject_id: String,
        sn: u64,
        result: crate::sink::manager::SendResult,
        count: u64,
    },
    CatchUpCompleted {
        subject_id: String,
    },
    /// Idle-timeout shutdown of a subject worker. Carries the generation of
    /// the schedule that emitted it: the timer can fire after a newer
    /// schedule cancelled-and-replaced it (the message was already in the
    /// mailbox), and only the latest generation may stop the child.
    ChildShutdown {
        subject_id: String,
        generation: u64,
    },
}

impl Message for SinkWorkerMessage {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkWorkerResponse {
    Ok,
}

impl Response for SinkWorkerResponse {}

// ---------------------------------------------------------------------------
// SinkSubjectWorkerError
// ---------------------------------------------------------------------------

/// Errors reported by a `SinkSubjectWorker` to its parent `SinkWorker` via
/// `emit_error`.
#[derive(Debug, Clone)]
pub enum SinkSubjectWorkerError {
    /// Event delivery failed (transient or unhealthy).
    DeliveryFailed {
        subject_id: String,
        sn: u64,
        reason: String,
        /// `true` when the failure happened during catch-up, which requires
        /// removing the subject from `in_catch_up`.
        from_catch_up: bool,
        /// Events covered by the failed delivery (batch size, 1 for single
        /// deliveries); used to settle the live in-flight accounting.
        count: u64,
    },
    /// Authentication failed and the event could not be delivered.
    AuthFailed {
        subject_id: String,
        sn: u64,
        error: String,
        /// `true` when the failure happened during catch-up.
        from_catch_up: bool,
        /// Events covered by the failed delivery (see `DeliveryFailed`).
        count: u64,
    },
    /// The sink is blocked due to a permanent error.
    Blocked {
        subject_id: String,
        sn: u64,
        reason: String,
    },
    /// The subject no longer exists (deleted).
    SubjectNotFound {
        subject_id: String,
        sn: u64,
        /// `true` when the subject was not found during catch-up.
        from_catch_up: bool,
    },
}

// ---------------------------------------------------------------------------
// Pending catch-ups
// ---------------------------------------------------------------------------

/// FIFO queue of subjects waiting for a catch-up slot once
/// `max_catch_up_concurrency` allows it, with an index for O(1)
/// dedup: admitting Q subjects while the slots stay busy used to
/// scan Q(Q-1)/2 ids. Both structures are updated together: every id
/// in `order` has an entry in `from_sn` and vice versa.
#[derive(Debug, Default)]
struct PendingCatchUps {
    /// Admission order (FIFO).
    order: VecDeque<String>,
    /// Lowest requested `from_sn` per queued subject.
    from_sn: HashMap<String, u64>,
}

impl PendingCatchUps {
    fn len(&self) -> usize {
        self.order.len()
    }

    fn is_empty(&self) -> bool {
        self.order.is_empty()
    }

    fn contains(&self, subject_id: &str) -> bool {
        self.from_sn.contains_key(subject_id)
    }

    /// Queue a subject, or rewind its queued `from_sn` to the lower
    /// one (a replay that rewound the cursor must rewind the queued
    /// catch-up too, like the in-flight restart).
    fn insert_or_rewind(&mut self, subject_id: &str, from_sn: u64) {
        if let Some(queued_from) = self.from_sn.get_mut(subject_id) {
            *queued_from = (*queued_from).min(from_sn);
        } else {
            self.from_sn.insert(subject_id.to_owned(), from_sn);
            self.order.push_back(subject_id.to_owned());
        }
    }

    fn push_front(&mut self, subject_id: String, from_sn: u64) {
        self.from_sn.insert(subject_id.clone(), from_sn);
        self.order.push_front(subject_id);
    }

    fn pop_front(&mut self) -> Option<(String, u64)> {
        loop {
            let subject_id = self.order.pop_front()?;
            // Every queued id has a map entry (all three writers
            // update both together): skip defensively instead of
            // stranding the queue behind a desynced head.
            if let Some(from_sn) = self.from_sn.remove(&subject_id) {
                return Some((subject_id, from_sn));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Healthcheck state
// ---------------------------------------------------------------------------

enum HealthcheckState {
    Healthy,
    Unhealthy { next_interval_idx: usize },
}

/// Returns catch-ups stalled past `timeout`, removing them from the
/// in-flight maps. Pure so the watchdog decision is unit-testable
/// without an actor context; the caller requeues the result (deduped,
/// idempotent redelivery).
fn stalled_catch_ups(
    in_catch_up: &mut HashMap<String, u64>,
    catch_up_started: &mut HashMap<String, Instant>,
    now: Instant,
    timeout: Duration,
) -> Vec<(String, u64)> {
    let mut stalled = Vec::new();
    in_catch_up.retain(|subject_id, from_sn| {
        let stale = catch_up_started
            .get(subject_id)
            .is_none_or(|started| now.duration_since(*started) >= timeout);
        if stale {
            stalled.push((subject_id.clone(), *from_sn));
            catch_up_started.remove(subject_id);
            false
        } else {
            true
        }
    });
    stalled
}

impl std::fmt::Debug for HealthcheckState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy => write!(f, "Healthy"),
            Self::Unhealthy { next_interval_idx } => {
                write!(f, "Unhealthy(next_interval_idx={})", next_interval_idx)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

/// Ephemeral worker actor responsible for real-time and catch-up delivery
/// to a single external sink endpoint.  The parent SinkManager controls
/// its lifecycle (creation and destruction).
pub struct SinkWorker {
    pub sink_name: String,
    pub server: SinkServer,
    client: Arc<dyn SinkTransport>,
    last_activity: Instant,
    /// `true` when the worker has already reported idle to the manager since the
    /// last real activity. Prevents redundant `WorkerIdle` messages while the
    /// manager is in the process of shutting the worker down.
    idle_reported: bool,
    healthcheck_state: HealthcheckState,
    /// Subjects with a catch-up in progress, mapped to the `from_sn` the
    /// current catch-up started from. A new catch-up request with a lower
    /// `from_sn` (e.g. a replay that rewound the cursor) restarts the
    /// in-flight catch-up so events are re-delivered in order.
    in_catch_up: HashMap<String, u64>,
    /// When each `in_catch_up` entry started: the stall watchdog
    /// requeues entries without completion past the configured
    /// timeout (a dropped internal signal must not wedge a
    /// concurrency slot forever).
    catch_up_started: HashMap<String, Instant>,
    /// Live events dispatched to each subject worker but not yet reported
    /// back (success or failure). A subject worker handling these events is
    /// working, not idle: the child shutdown timer and the worker's own
    /// idle report must not treat it as inactive. Entries are decremented
    /// by every terminal report (`DeliveryResult`, delivery/auth errors)
    /// and cleared wholesale when the sink goes unhealthy or blocked — the
    /// events they covered are then recovered through lagging + catch-up.
    live_in_flight: HashMap<String, u64>,
    blocked: Option<String>,
    /// Number of times the sink has "recovered" via healthcheck without
    /// a successful delivery.  Used to detect flapping sinks (LEV-2).
    recoveries_after_failure: u32,
    /// F-5: Timer key for the pending healthcheck timer.  Cancelling the key
    /// aborts the timer before it sends `HealthCheck`.
    pending_healthcheck: Option<TimerKey>,
    /// Consecutive healthcheck failures since the last success. The sink is
    /// only declared unhealthy when this reaches
    /// `server.healthcheck_max_failures`.
    healthcheck_failures: u32,
    active_subject_workers: HashMap<
        String,
        ActorRef<crate::sink::subject_worker::SinkSubjectWorker>,
    >,
    /// F-5: Timer keys for pending child shutdown timers, with the
    /// generation of each schedule so stale timer messages (emitted before
    /// a cancel-and-rearm) are discarded instead of killing a live child.
    pending_child_shutdowns: HashMap<String, (TimerKey, u64)>,
    /// Monotonic counter stamping every child shutdown schedule.
    next_child_shutdown_generation: u64,
    /// Subjects waiting for a catch-up slot once `max_catch_up_concurrency`
    /// allows it.
    pending_catch_ups: PendingCatchUps,
    /// `true` when this worker handles governance events (parent is under Node),
    /// `false` when it handles tracker events (parent is under Governance).
    is_governance: bool,
}

impl std::fmt::Debug for SinkWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkWorker")
            .field("sink_name", &self.sink_name)
            .field("server", &self.server.server)
            .field("healthcheck_state", &self.healthcheck_state)
            .field("in_catch_up_len", &self.in_catch_up.len())
            .field("pending_catch_ups_len", &self.pending_catch_ups.len())
            .field("blocked", &self.blocked.is_some())
            .finish()
    }
}

impl NotPersistentActor for SinkWorker {}

#[async_trait]
impl Actor for SinkWorker {
    type Message = SinkWorkerMessage;
    type Response = SinkWorkerResponse;
    type Event = ();
    type SinkEvent = ();
    type ChildError = SinkSubjectWorkerError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<tracing::Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("sink_worker", id),
            |parent_span| info_span!(parent: parent_span, "sink_worker", id),
        )
    }

    /// Fail instead of blocking the sender when the mailbox is full: the
    /// delivery chain is cyclic (manager ⇄ worker ⇄ subject worker), so
    /// backpressure can deadlock it. A failed `tell` surfaces immediately
    /// and the subject is recovered via lagging/catch-up from the ledger —
    /// nothing is lost, at most redelivered (idempotency-key).
    fn mailbox_overflow_strategy() -> OverflowStrategy {
        OverflowStrategy::Fail
    }

    /// Same generous shutdown deadlines as the subject workers below:
    /// stopping here waits out their own grace first.
    fn stop_timeout() -> Option<Duration> {
        Some(crate::sink::SINK_SHUTDOWN_GRACE)
    }

    fn mailbox_drain_timeout() -> Duration {
        crate::sink::SINK_SHUTDOWN_GRACE
    }

    fn event_drain_timeout() -> Duration {
        crate::sink::SINK_SHUTDOWN_GRACE
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // Transport startup logic (HTTP: eager OAuth2 token fetch).
        // Best-effort in background: awaiting it here blocks the whole
        // node boot on an unreachable broker (the node creation ask
        // times out while e.g. Kafka metadata retries), while a failure
        // never prevents the worker from starting anyway. The task dies
        // with the actor; the healthcheck covers a failed warm-up.
        let client = self.client.clone();
        let sink_name = self.sink_name.clone();
        ctx.spawn(async move {
            if let Err(e) = client.warm_up().await {
                error!(msg_type = "TokenRefresh", sink = %sink_name, error = %e, "Failed to refresh token on startup");
            }
        });

        // Schedule first healthcheck after configurable startup delay + jitter.
        let startup_delay =
            crate::sink::add_jitter(self.server.startup_healthcheck_delay_secs);
        ctx.schedule_once(
            Duration::from_secs(startup_delay),
            SinkWorkerMessage::HealthCheck,
        )?;
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for SinkWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkWorkerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<SinkWorkerResponse, ActorError> {
        match msg {
            SinkWorkerMessage::NotifyNewEvent(data) => {
                if let Some(ref _reason) = self.blocked {
                    return Ok(SinkWorkerResponse::Ok);
                }

                if matches!(
                    self.healthcheck_state,
                    HealthcheckState::Unhealthy { .. }
                ) {
                    let (subject_id, _schema_id) =
                        data.payload.get_subject_schema();
                    let sn = extract_sn(&data);
                    match ctx.get_parent::<SinkManager>().await {
                        Ok(parent) => {
                            if let Err(e) = parent
                                .emit_error(SinkWorkerError::DeliveryFailed {
                                    sink: self.sink_name.clone(),
                                    subject_id: subject_id.clone(),
                                    sn,
                                    reason: "sink unhealthy".into(),
                                })
                                .await
                            {
                                error!(msg_type = "ReportUnhealthy", sink = %self.sink_name, error = %e, "Failed to report unhealthy event");
                            }
                        }
                        Err(e) => {
                            error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                        }
                    }
                    return Ok(SinkWorkerResponse::Ok);
                }

                self.last_activity = Instant::now();
                self.idle_reported = false;
                let (subject_id, _schema_id) =
                    data.payload.get_subject_schema();

                let child_ref = match self
                    .ensure_subject_worker(&subject_id, ctx)
                    .await
                {
                    Ok(child_ref) => child_ref,
                    Err(e) => {
                        // Same recovery as a dead subject worker (below):
                        // notify the manager so it resets its notification
                        // cursor and recovers the event via catch-up instead
                        // of losing it silently.
                        error!(
                            msg_type = "EnsureSubjectWorker",
                            sink = %self.sink_name,
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to ensure subject worker for live delivery"
                        );
                        self.recover_unreachable_subject_worker(
                            &subject_id,
                            ctx,
                        )
                        .await;
                        return Err(e);
                    }
                };
                if let Err(e) = child_ref
                    .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::DeliverEvent(
                        Arc::clone(&data),
                    ))
                    .await
                {
                    // The subject worker died between ensure and tell; drop the
                    // stale reference so the next event recreates it, and notify
                    // the manager so it resets its notification cursor and
                    // recovers any lost event via catch-up.
                    self.recover_unreachable_subject_worker(&subject_id, ctx)
                        .await;
                    return Err(e);
                }

                *self.live_in_flight.entry(subject_id.clone()).or_insert(0) +=
                    1;
                self.schedule_child_shutdown(ctx, subject_id.clone());

                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::HealthCheck => {
                // Stall watchdog first: a dropped internal signal leaves
                // the catch-up marked in-flight with no completion coming.
                if let Err(e) = self.sweep_stalled_catch_ups(ctx).await {
                    error!(msg_type = "SweepStalledCatchUps", sink = %self.sink_name, error = %e, "Failed to sweep stalled catch-ups");
                }
                match self.client.health_check().await {
                    Ok(()) => {
                        self.healthcheck_failures = 0;
                        if let HealthcheckState::Unhealthy { .. } =
                            self.healthcheck_state
                        {
                            self.recoveries_after_failure += 1;
                            if self.recoveries_after_failure
                                < self.server.max_recoveries_after_failure
                            {
                                self.healthcheck_state =
                                    HealthcheckState::Healthy;
                                self.live_in_flight.clear();
                                self.broadcast_to_children(
                                    crate::sink::subject_worker::SinkSubjectWorkerMessage::Resume,
                                    ctx,
                                )
                                .await;
                                match ctx.get_parent::<SinkManager>().await {
                                    Ok(parent) => {
                                        if let Err(e) = parent
                                            .tell(SinkManagerMessage::SinkRecovered {
                                                sink: self.sink_name.clone(),
                                            })
                                            .await
                                        {
                                            error!(msg_type = "ReportRecovered", sink = %self.sink_name, error = %e, "Failed to report sink recovered");
                                        }
                                    }
                                    Err(e) => {
                                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                                    }
                                }
                            } else {
                                // Flapping threshold exceeded: healthcheck works but delivery
                                // keeps failing.  This is a permanent sink misconfiguration
                                // (wrong URL, endpoint missing, etc.).  Block the sink.
                                let blocked_reason =
                                    "sink flapping: healthcheck OK but delivery fails".to_owned();
                                warn!(
                                    msg_type = "FlappingSinkBlocked",
                                    sink = %self.sink_name,
                                    recoveries = %self.recoveries_after_failure,
                                    "Sink healthcheck OK but delivery keeps failing; blocking sink"
                                );
                                self.blocked = Some(blocked_reason.clone());
                                self.broadcast_to_children(
                                    crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop,
                                    ctx,
                                )
                                .await;
                                self.active_subject_workers.clear();
                                self.in_catch_up.clear();
                                self.catch_up_started.clear();
                                self.live_in_flight.clear();
                                match ctx.get_parent::<SinkManager>().await {
                                    Ok(parent) => {
                                        if let Err(e) = parent
                                            .emit_error(
                                                SinkWorkerError::Blocked {
                                                    sink: self
                                                        .sink_name
                                                        .clone(),
                                                    subject_id: String::new(),
                                                    sn: 0,
                                                    reason: blocked_reason,
                                                },
                                            )
                                            .await
                                        {
                                            error!(msg_type = "ReportBlocked", sink = %self.sink_name, error = %e, "Failed to report blocked sink");
                                        }
                                    }
                                    Err(e) => {
                                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                                    }
                                }
                            }
                        }
                        // Schedule the next periodic healthcheck as long as the
                        // sink remains unblocked.  This keeps the worker reporting
                        // its idle state to the manager so inactive workers can be
                        // shut down and recreated on demand.
                        if self.blocked.is_none() {
                            let delay_secs =
                                crate::sink::healthcheck_delay_secs(
                                    &self.server.healthcheck_intervals_secs,
                                    0,
                                );
                            let delay_secs =
                                crate::sink::add_jitter(delay_secs);
                            self.schedule_healthcheck(ctx, delay_secs);
                        }
                    }
                    Err(_) => {
                        self.healthcheck_failures += 1;
                        let idx = match self.healthcheck_state {
                            HealthcheckState::Healthy => {
                                (self.healthcheck_failures - 1) as usize
                            }
                            HealthcheckState::Unhealthy {
                                next_interval_idx,
                            } => next_interval_idx,
                        };
                        let intervals = &self.server.healthcheck_intervals_secs;
                        let last_idx = intervals.len().saturating_sub(1);
                        let delay_secs =
                            crate::sink::healthcheck_delay_secs(intervals, idx);
                        let delay_secs = crate::sink::add_jitter(delay_secs);
                        if self.healthcheck_failures
                            < self.server.healthcheck_max_failures
                        {
                            // Tolerate isolated healthcheck failures: a slow
                            // GET must not pause the delivery pipeline. Retry
                            // with the escalating backoff and only declare the
                            // sink unhealthy when the streak is reached.
                            debug!(
                                msg_type = "HealthcheckFailure",
                                sink = %self.sink_name,
                                streak = %self.healthcheck_failures,
                                max = %self.server.healthcheck_max_failures,
                                "Healthcheck failed; retrying before declaring the sink unhealthy"
                            );
                        } else {
                            self.healthcheck_state =
                                HealthcheckState::Unhealthy {
                                    next_interval_idx: (idx + 1).min(last_idx),
                                };
                            // Paused children silently drop queued events and
                            // a best-effort flush failure reports nothing, so
                            // live accounting can no longer be settled per
                            // report: abandon it here. Every event covered is
                            // re-delivered through lagging + catch-up.
                            self.live_in_flight.clear();
                            self.broadcast_to_children(
                                crate::sink::subject_worker::SinkSubjectWorkerMessage::Pause,
                                ctx,
                            )
                            .await;
                        }

                        self.schedule_healthcheck(ctx, delay_secs);
                    }
                }
                // Report idle state to parent so manager can decide on shutdown.
                if Instant::now().duration_since(self.last_activity)
                    >= Duration::from_millis(
                        self.server.sink_worker_idle_timeout_ms,
                    )
                {
                    self.report_idle(ctx).await;
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::CatchUp {
                subject_id,
                from_sn,
            } => {
                if let Some(ref _reason) = self.blocked {
                    self.report_catch_up_rejected(subject_id, ctx).await;
                    return Ok(SinkWorkerResponse::Ok);
                }

                if matches!(
                    self.healthcheck_state,
                    HealthcheckState::Unhealthy { .. }
                ) {
                    self.report_catch_up_rejected(subject_id, ctx).await;
                    return Ok(SinkWorkerResponse::Ok);
                }

                if let Some(&current_from) = self.in_catch_up.get(&subject_id) {
                    if from_sn < current_from {
                        // A lower from_sn (e.g. a replay that rewound the
                        // cursor mid-flight) restarts the catch-up: the
                        // subject worker bumps its generation, dropping the
                        // stale delivery chain, and re-delivers from from_sn
                        // so events keep their order.
                        self.track_catch_up_start(&subject_id, from_sn);
                        let child_ref = match self
                            .ensure_subject_worker(&subject_id, ctx)
                            .await
                        {
                            Ok(child_ref) => child_ref,
                            Err(e) => {
                                error!(
                                    msg_type = "EnsureSubjectWorker",
                                    sink = %self.sink_name,
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to ensure subject worker for catch-up restart"
                                );
                                self.recover_unreachable_subject_worker(
                                    &subject_id,
                                    ctx,
                                )
                                .await;
                                return Ok(SinkWorkerResponse::Ok);
                            }
                        };
                        if let Err(e) = child_ref
                            .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::CatchUpBatch {
                                from_sn,
                                batch_size: self.server.catch_up_batch_size,
                            })
                            .await
                        {
                            error!(
                                msg_type = "CatchUpBatch",
                                sink = %self.sink_name,
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to send catch-up batch to subject worker"
                            );
                            self.recover_unreachable_subject_worker(
                                &subject_id, ctx,
                            )
                            .await;
                            return Ok(SinkWorkerResponse::Ok);
                        }
                        self.schedule_child_shutdown(ctx, subject_id.clone());
                    }
                    // from_sn >= current_from: already covered by the
                    // in-flight catch-up, nothing to do.
                    return Ok(SinkWorkerResponse::Ok);
                }

                if self.in_catch_up.len()
                    >= self.server.max_catch_up_concurrency
                {
                    // Already queued: a lower from_sn (e.g. a replay that
                    // rewound the cursor) must rewind the queued catch-up
                    // too, like the in-flight restart above — otherwise the
                    // events below the queued from_sn are never delivered
                    // while the manager's cursor advances past them.
                    self.pending_catch_ups
                        .insert_or_rewind(&subject_id, from_sn);
                    return Ok(SinkWorkerResponse::Ok);
                }

                self.track_catch_up_start(&subject_id, from_sn);
                // Reset flapping counter: the sink has accepted a new catch-up
                // attempt, so previous healthchecks that passed during the
                // failure are no longer evidence of a broken sink. If the
                // catch-up keeps failing, the next healthcheck increments
                // the counter again; if it succeeds, `DeliveryResult Success`
                // confirms the recovery.
                self.recoveries_after_failure = 0;
                self.last_activity = Instant::now();
                self.idle_reported = false;

                let child_ref =
                    match self.ensure_subject_worker(&subject_id, ctx).await {
                        Ok(child_ref) => child_ref,
                        Err(e) => {
                            error!(
                                msg_type = "EnsureSubjectWorker",
                                sink = %self.sink_name,
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to ensure subject worker for catch-up"
                            );
                            self.recover_unreachable_subject_worker(
                                &subject_id,
                                ctx,
                            )
                            .await;
                            return Ok(SinkWorkerResponse::Ok);
                        }
                    };
                if let Err(e) = child_ref
                    .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::CatchUpBatch {
                        from_sn,
                        batch_size: self.server.catch_up_batch_size,
                    })
                    .await
                {
                    error!(
                        msg_type = "CatchUpBatch",
                        sink = %self.sink_name,
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to send catch-up batch to subject worker"
                    );
                    self.recover_unreachable_subject_worker(&subject_id, ctx)
                        .await;
                    return Ok(SinkWorkerResponse::Ok);
                }

                self.schedule_child_shutdown(ctx, subject_id.clone());

                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::DeliveryResult {
                subject_id,
                sn,
                result,
                count,
            } => {
                self.last_activity = Instant::now();
                self.idle_reported = false;
                self.cancel_child_shutdown(ctx, &subject_id);
                if let Some(in_flight) =
                    self.live_in_flight.get_mut(&subject_id)
                {
                    *in_flight = in_flight.saturating_sub(count);
                    if *in_flight == 0 {
                        self.live_in_flight.remove(&subject_id);
                    }
                }
                if matches!(result, SendResult::Success) {
                    self.recoveries_after_failure = 0;
                    if matches!(
                        self.healthcheck_state,
                        HealthcheckState::Unhealthy { .. }
                    ) {
                        self.healthcheck_state = HealthcheckState::Healthy;
                        // Reports lost in the unhealthy window can never
                        // settle: drop the counters (late reports are
                        // tolerated, catch-up re-delivers).
                        self.live_in_flight.clear();
                        // Paused children drop events while unhealthy:
                        // resume them like the healthcheck path does, or
                        // the recovery stays silent until the next cycle.
                        self.broadcast_to_children(
                            crate::sink::subject_worker::SinkSubjectWorkerMessage::Resume,
                            ctx,
                        )
                        .await;
                        match ctx.get_parent::<SinkManager>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .tell(SinkManagerMessage::SinkRecovered {
                                        sink: self.sink_name.clone(),
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportRecovered", sink = %self.sink_name, error = %e, "Failed to report sink recovered");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                            }
                        }
                    }
                    match ctx.get_parent::<SinkManager>().await {
                        Ok(parent) => {
                            if let Err(e) = parent
                                .tell(SinkManagerMessage::UpdateProgress {
                                    sink: self.sink_name.clone(),
                                    subject_id: subject_id.clone(),
                                    sn,
                                    result: SendResult::Success,
                                    count,
                                })
                                .await
                            {
                                error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report progress");
                            }
                        }
                        Err(e) => {
                            error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                        }
                    }
                    self.schedule_child_shutdown(ctx, subject_id);
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::CatchUpProgress {
                subject_id,
                sn,
                result,
                count,
            } => {
                self.last_activity = Instant::now();
                self.idle_reported = false;
                self.cancel_child_shutdown(ctx, &subject_id);
                if matches!(result, SendResult::Success) {
                    match ctx.get_parent::<SinkManager>().await {
                        Ok(parent) => {
                            if let Err(e) = parent
                                .tell(SinkManagerMessage::UpdateProgress {
                                    sink: self.sink_name.clone(),
                                    subject_id: subject_id.clone(),
                                    sn,
                                    result: SendResult::Success,
                                    count,
                                })
                                .await
                            {
                                error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report progress");
                            }
                        }
                        Err(e) => {
                            error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                        }
                    }
                    self.schedule_child_shutdown(ctx, subject_id);
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::CatchUpCompleted { subject_id } => {
                self.untrack_catch_up(&subject_id);
                self.cancel_child_shutdown(ctx, &subject_id);
                // A blocked sink must not start new catch-ups: any pending work
                // will be drained once the operator unblocks the sink.
                if self.blocked.is_none() {
                    self.try_start_pending_catch_ups(ctx).await?;
                }
                match ctx.get_parent::<SinkManager>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .tell(SinkManagerMessage::CatchUpCompleted {
                                sink: self.sink_name.clone(),
                                subject_id: subject_id.clone(),
                            })
                            .await
                        {
                            error!(
                                msg_type = "ReportCatchUpCompleted",
                                sink = %self.sink_name,
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to report catch-up completed to manager"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            msg_type = "GetParent",
                            sink = %self.sink_name,
                            error = %e,
                            "Failed to get parent manager"
                        );
                    }
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::ChildShutdown {
                subject_id,
                generation,
            } => {
                // Discard a stale timer: it was emitted before a newer
                // schedule cancelled-and-replaced it, so stopping the child
                // now could destroy deliveries queued in its mailbox.
                match self.pending_child_shutdowns.get(&subject_id) {
                    Some((_, current)) if *current == generation => {
                        self.pending_child_shutdowns.remove(&subject_id);
                    }
                    _ => {
                        return Ok(SinkWorkerResponse::Ok);
                    }
                }
                // A child with an in-flight catch-up is not idle: lifting a
                // cold subject or a slow ack can legitimately take longer
                // than the reap timeout. Stopping it here would abort the
                // catch-up silently (the manager keeps its in-flight mark
                // and does not retry), so leave it alone: the catch-up ends
                // through its own bounded paths (progress, completion or a
                // reported error) and the child becomes reapable then.
                if self.in_catch_up.contains_key(&subject_id) {
                    return Ok(SinkWorkerResponse::Ok);
                }
                // Same for live deliveries: a slow ack may outlast the reap
                // timeout with more events already queued in the child's
                // mailbox. Stopping the child would discard them silently
                // (they are not critical) and they would only come back
                // through the death-watch recovery ~20s later.
                if self.live_in_flight.contains_key(&subject_id) {
                    return Ok(SinkWorkerResponse::Ok);
                }
                if let Some(child_ref) =
                    self.active_subject_workers.remove(&subject_id)
                {
                    // Wait for the child to confirm shutdown: only then is its
                    // actor path free, so a `create_child` for a subsequent
                    // event of the same subject cannot fail with "already
                    // exists". The child is idle by definition (the shutdown
                    // timer fired), so this returns immediately.
                    if let Err(e) = child_ref.ask_stop().await {
                        error!(
                            msg_type = "ChildShutdown",
                            sink = %self.sink_name,
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to confirm subject worker shutdown"
                        );
                    }
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::ResetRecoveries => {
                self.recoveries_after_failure = 0;
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::ClearBlocked => {
                self.blocked = None;
                // A manual unblock means the operator considers the sink ready to
                // retry.  Clear the unhealthy state so that catch-up requests
                // sent after unblocking are accepted immediately instead of
                // being ignored until a healthcheck runs, and restart the
                // healthcheck chain: while blocked it dies (a successful check
                // does not reschedule), and without a fresh schedule the worker
                // would never run the idle check again — the manager could not
                // idle-kill it — nor monitor the sink's health.
                self.healthcheck_state = HealthcheckState::Healthy;
                self.healthcheck_failures = 0;
                let delay_secs = crate::sink::healthcheck_delay_secs(
                    &self.server.healthcheck_intervals_secs,
                    0,
                );
                let delay_secs = crate::sink::add_jitter(delay_secs);
                self.schedule_healthcheck(ctx, delay_secs);
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::Stop => {
                ctx.stop(None).await;
                Ok(SinkWorkerResponse::Ok)
            }
        }
    }

    async fn on_child_error(
        &mut self,
        error: SinkSubjectWorkerError,
        ctx: &mut ActorContext<Self>,
    ) {
        match error {
            SinkSubjectWorkerError::DeliveryFailed {
                subject_id,
                sn,
                reason,
                from_catch_up,
                count,
            } => {
                if from_catch_up {
                    self.untrack_catch_up(&subject_id);
                } else if let Some(in_flight) =
                    self.live_in_flight.get_mut(&subject_id)
                {
                    *in_flight = in_flight.saturating_sub(count);
                    if *in_flight == 0 {
                        self.live_in_flight.remove(&subject_id);
                    }
                }
                if self.blocked.is_none()
                    && !matches!(
                        self.healthcheck_state,
                        HealthcheckState::Unhealthy { .. }
                    )
                {
                    self.healthcheck_state = HealthcheckState::Unhealthy {
                        next_interval_idx: 0,
                    };
                    let delay_secs = crate::sink::healthcheck_delay_secs(
                        &self.server.healthcheck_intervals_secs,
                        0,
                    );
                    let delay_secs = crate::sink::add_jitter(delay_secs);
                    self.schedule_healthcheck(ctx, delay_secs);
                }
                self.schedule_child_shutdown(ctx, subject_id.clone());
                match ctx.get_parent::<SinkManager>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .emit_error(SinkWorkerError::DeliveryFailed {
                                sink: self.sink_name.clone(),
                                subject_id: subject_id.clone(),
                                sn,
                                reason: reason.clone(),
                            })
                            .await
                        {
                            error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report delivery failed");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                    }
                }
            }
            SinkSubjectWorkerError::AuthFailed {
                subject_id,
                sn,
                error,
                from_catch_up,
                count,
            } => {
                if from_catch_up {
                    self.untrack_catch_up(&subject_id);
                    if self.blocked.is_none()
                        && !matches!(
                            self.healthcheck_state,
                            HealthcheckState::Unhealthy { .. }
                        )
                    {
                        self.healthcheck_state = HealthcheckState::Unhealthy {
                            next_interval_idx: 0,
                        };
                        let delay_secs = crate::sink::healthcheck_delay_secs(
                            &self.server.healthcheck_intervals_secs,
                            0,
                        );
                        let delay_secs = crate::sink::add_jitter(delay_secs);
                        self.schedule_healthcheck(ctx, delay_secs);
                    }
                } else if let Some(in_flight) =
                    self.live_in_flight.get_mut(&subject_id)
                {
                    *in_flight = in_flight.saturating_sub(count);
                    if *in_flight == 0 {
                        self.live_in_flight.remove(&subject_id);
                    }
                }
                self.schedule_child_shutdown(ctx, subject_id.clone());
                match ctx.get_parent::<SinkManager>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .emit_error(SinkWorkerError::AuthFailed {
                                sink: self.sink_name.clone(),
                                subject_id: subject_id.clone(),
                                sn,
                                error: error.clone(),
                            })
                            .await
                        {
                            error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report auth failed");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                    }
                }
            }
            SinkSubjectWorkerError::Blocked {
                subject_id,
                sn,
                reason,
            } => {
                self.blocked = Some(reason.clone());
                self.broadcast_to_children(
                    crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop,
                    ctx,
                )
                .await;
                self.active_subject_workers.clear();
                self.in_catch_up.clear();
                self.catch_up_started.clear();
                self.live_in_flight.clear();
                match ctx.get_parent::<SinkManager>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .emit_error(SinkWorkerError::Blocked {
                                sink: self.sink_name.clone(),
                                subject_id: subject_id.clone(),
                                sn,
                                reason: reason.clone(),
                            })
                            .await
                        {
                            error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report blocked");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                    }
                }
            }
            SinkSubjectWorkerError::SubjectNotFound {
                subject_id,
                sn,
                from_catch_up,
            } => {
                if from_catch_up {
                    self.untrack_catch_up(&subject_id);
                    // A freed slot must not strand queued catch-ups:
                    // drain like the completion path. Blocked sinks
                    // stay drained on unblock.
                    if self.blocked.is_none()
                        && let Err(e) =
                            self.try_start_pending_catch_ups(ctx).await
                    {
                        error!(msg_type = "DrainPendingCatchUps", sink = %self.sink_name, error = %e, "Failed to drain pending catch-ups after subject not found");
                    }
                }
                // A deleted subject can have no live work in flight.
                self.live_in_flight.remove(&subject_id);
                self.schedule_child_shutdown(ctx, subject_id.clone());
                match ctx.get_parent::<SinkManager>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .emit_error(SinkWorkerError::SubjectNotFound {
                                sink: self.sink_name.clone(),
                                subject_id: subject_id.clone(),
                                sn,
                            })
                            .await
                        {
                            error!(msg_type = "ReportSubjectNotFound", sink = %self.sink_name, error = %e, "Failed to report subject not found");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
                    }
                }
            }
        }
    }
}

impl SinkWorker {
    /// F-5: Schedule a healthcheck after `delay_secs`, cancelling any
    /// previously scheduled healthcheck to avoid redundant checks.
    fn schedule_healthcheck(
        &mut self,
        ctx: &ActorContext<Self>,
        delay_secs: u64,
    ) {
        if let Some(key) = self.pending_healthcheck.take() {
            ctx.cancel_timer(key);
        }
        match ctx.schedule_once(
            Duration::from_secs(delay_secs),
            SinkWorkerMessage::HealthCheck,
        ) {
            Ok(key) => {
                self.pending_healthcheck = Some(key);
            }
            Err(e) => {
                error!(
                    msg_type = "ScheduleHealthcheck",
                    sink = %self.sink_name,
                    error = %e,
                    "Failed to schedule healthcheck"
                );
            }
        }
    }

    fn schedule_child_shutdown(
        &mut self,
        ctx: &ActorContext<Self>,
        subject_id: String,
    ) {
        let timeout_ms = self.server.sink_subject_worker_idle_timeout_ms;
        self.next_child_shutdown_generation += 1;
        let generation = self.next_child_shutdown_generation;
        if let Some((key, _)) = self.pending_child_shutdowns.remove(&subject_id)
        {
            ctx.cancel_timer(key);
        }
        match ctx.schedule_once(
            Duration::from_millis(timeout_ms),
            SinkWorkerMessage::ChildShutdown {
                subject_id: subject_id.clone(),
                generation,
            },
        ) {
            Ok(key) => {
                self.pending_child_shutdowns
                    .insert(subject_id, (key, generation));
            }
            Err(e) => {
                error!(
                    msg_type = "ScheduleChildShutdown",
                    sink = %self.sink_name,
                    subject_id = %subject_id,
                    error = %e,
                    "Failed to schedule child shutdown"
                );
            }
        }
    }

    fn cancel_child_shutdown(
        &mut self,
        ctx: &ActorContext<Self>,
        subject_id: &str,
    ) {
        if let Some((key, _)) = self.pending_child_shutdowns.remove(subject_id)
        {
            ctx.cancel_timer(key);
        }
    }

    async fn ensure_subject_worker(
        &mut self,
        subject_id: &str,
        ctx: &mut ActorContext<Self>,
    ) -> Result<
        ActorRef<crate::sink::subject_worker::SinkSubjectWorker>,
        ActorError,
    > {
        self.cancel_child_shutdown(ctx, subject_id);
        if let Some(worker) = self.active_subject_workers.get(subject_id) {
            return Ok(worker.clone());
        }
        let worker = crate::sink::subject_worker::SinkSubjectWorker::new(
            self.sink_name.clone(),
            self.server.clone(),
            Arc::clone(&self.client),
            self.is_governance,
        );
        let child_ref = match ctx.create_child(subject_id, worker).await {
            Ok(child_ref) => child_ref,
            // A concurrent ensure won the race: reuse the winner
            // instead of failing the delivery.
            Err(ActorError::Exists { .. }) => {
                ctx.get_child::<crate::sink::subject_worker::SinkSubjectWorker>(
                    subject_id,
                )
                .await?
            }
            Err(e) => return Err(e),
        };
        self.active_subject_workers
            .insert(subject_id.to_string(), child_ref.clone());
        Ok(child_ref)
    }

    /// Tracks a catch-up start in both maps; the watchdog needs the
    /// timestamp, the admission checks need the `from_sn`.
    fn track_catch_up_start(&mut self, subject_id: &str, from_sn: u64) {
        self.in_catch_up.insert(subject_id.to_owned(), from_sn);
        self.catch_up_started
            .insert(subject_id.to_owned(), Instant::now());
    }

    /// Forgets a catch-up in both maps (completion, failure, restart,
    /// child teardown).
    fn untrack_catch_up(&mut self, subject_id: &str) {
        self.in_catch_up.remove(subject_id);
        self.catch_up_started.remove(subject_id);
    }

    /// Requeues catch-ups running past the stall timeout: one of their
    /// internal signals was dropped and will never arrive. Redelivery
    /// is idempotent, so a false positive only repeats work.
    async fn sweep_stalled_catch_ups(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let stall_timeout =
            Duration::from_secs(self.server.catch_up_stall_timeout_secs);
        let now = Instant::now();
        let stalled = stalled_catch_ups(
            &mut self.in_catch_up,
            &mut self.catch_up_started,
            now,
            stall_timeout,
        );
        for (subject_id, from_sn) in stalled {
            warn!(
                msg_type = "StalledCatchUpRequeued",
                sink = %self.sink_name,
                subject_id = %subject_id,
                from_sn = from_sn,
                "Catch-up without completion past stall timeout, requeueing"
            );
            if !self.pending_catch_ups.contains(&subject_id) {
                self.pending_catch_ups.push_front(subject_id, from_sn);
            }
        }
        self.try_start_pending_catch_ups(ctx).await
    }

    /// Start pending catch-ups while there is free concurrency capacity.
    async fn try_start_pending_catch_ups(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.blocked.is_some() {
            return Ok(());
        }
        while let Some((subject_id, from_sn)) =
            self.pending_catch_ups.pop_front()
        {
            if self.in_catch_up.contains_key(&subject_id) {
                continue;
            }
            if self.in_catch_up.len() >= self.server.max_catch_up_concurrency {
                self.pending_catch_ups.push_front(subject_id, from_sn);
                break;
            }
            self.track_catch_up_start(&subject_id, from_sn);
            self.last_activity = Instant::now();
            self.idle_reported = false;
            match self.ensure_subject_worker(&subject_id, ctx).await {
                Ok(child_ref) => {
                    if let Err(e) = child_ref
                        .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::CatchUpBatch {
                            from_sn,
                            batch_size: self.server.catch_up_batch_size,
                        })
                        .await
                    {
                        error!(
                            msg_type = "CatchUpBatch",
                            sink = %self.sink_name,
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to send catch-up batch to subject worker"
                        );
                        self.recover_unreachable_subject_worker(
                            &subject_id, ctx,
                        )
                        .await;
                    } else {
                        self.schedule_child_shutdown(ctx, subject_id);
                    }
                }
                Err(e) => {
                    error!(
                        msg_type = "EnsureSubjectWorker",
                        sink = %self.sink_name,
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to ensure subject worker for pending catch-up"
                    );
                    self.recover_unreachable_subject_worker(&subject_id, ctx)
                        .await;
                }
            }
        }
        Ok(())
    }

    async fn broadcast_to_children(
        &mut self,
        msg: crate::sink::subject_worker::SinkSubjectWorkerMessage,
        ctx: &ActorContext<Self>,
    ) {
        let mut dead = Vec::new();
        for (subject_id, child_ref) in &self.active_subject_workers {
            if child_ref.tell(msg.clone()).await.is_err() {
                dead.push(subject_id.clone());
            }
        }
        for subject_id in dead {
            self.active_subject_workers.remove(&subject_id);
        }
        // Also cancel any pending shutdowns for children we're broadcasting to
        if matches!(
            msg,
            crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop
        ) {
            let keys: Vec<String> =
                self.pending_child_shutdowns.keys().cloned().collect();
            for subject_id in keys {
                self.cancel_child_shutdown(ctx, &subject_id);
            }
        }
    }

    pub async fn new(
        sink_name: String,
        server: SinkServer,
        is_governance: bool,
        signer: Option<NodeSigner>,
        node_public_key: String,
    ) -> Result<Self, SinkError> {
        let client = crate::sink::build_transport(
            &server,
            signer,
            Some(&node_public_key),
        )
        .await?;
        Ok(Self {
            sink_name,
            server,
            client,
            last_activity: Instant::now(),
            idle_reported: false,
            healthcheck_state: HealthcheckState::Healthy,
            in_catch_up: HashMap::new(),
            catch_up_started: HashMap::new(),
            live_in_flight: HashMap::new(),
            blocked: None,
            recoveries_after_failure: 0,
            pending_healthcheck: None,
            healthcheck_failures: 0,
            active_subject_workers: HashMap::new(),
            pending_child_shutdowns: HashMap::new(),
            next_child_shutdown_generation: 0,
            pending_catch_ups: PendingCatchUps::default(),
            is_governance,
        })
    }

    /// Recover from an unreachable subject worker: drop the stale reference,
    /// roll back any in-flight catch-up marker, and notify the manager so it
    /// resets its notification state and re-drives the subject via catch-up
    /// (the manager clears `catch_up_in_flight` on `SubjectWorkerRestarted`).
    async fn recover_unreachable_subject_worker(
        &mut self,
        subject_id: &str,
        ctx: &ActorContext<Self>,
    ) {
        self.active_subject_workers.remove(subject_id);
        self.untrack_catch_up(subject_id);
        match ctx.get_parent::<SinkManager>().await {
            Ok(parent) => {
                if let Err(err) = parent
                    .emit_error(SinkWorkerError::SubjectWorkerRestarted {
                        sink: self.sink_name.clone(),
                        subject_id: subject_id.to_owned(),
                    })
                    .await
                {
                    error!(
                        msg_type = "ReportSubjectWorkerRestarted",
                        sink = %self.sink_name,
                        subject_id = %subject_id,
                        error = %err,
                        "Failed to report subject worker restart"
                    );
                }
            }
            Err(err) => {
                error!(
                    msg_type = "GetParent",
                    sink = %self.sink_name,
                    subject_id = %subject_id,
                    error = %err,
                    "Failed to get parent manager on subject worker restart"
                );
            }
        }
    }

    /// Notify the manager that a catch-up request could not be started
    /// because the sink is blocked or unhealthy. This clears the in-flight
    /// flag so recovery can retry later.
    async fn report_catch_up_rejected(
        &self,
        subject_id: String,
        ctx: &ActorContext<Self>,
    ) {
        match ctx.get_parent::<SinkManager>().await {
            Ok(parent) => {
                if let Err(e) = parent
                    .tell(SinkManagerMessage::CatchUpRejected {
                        sink: self.sink_name.clone(),
                        subject_id,
                    })
                    .await
                {
                    error!(msg_type = "ReportCatchUpRejected", sink = %self.sink_name, error = %e, "Failed to report catch-up rejected");
                }
            }
            Err(e) => {
                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent manager");
            }
        }
    }

    /// Report idle state to parent manager.  The manager decides whether to
    /// stop this worker after a configurable timeout.
    ///
    /// A worker with pending or in-flight catch-ups is NOT idle: it still has
    /// work to do, so it must remain alive.  The report is sent at most once
    /// per idle period to avoid duplicate shutdown timers while the manager is
    /// stopping the worker.
    async fn report_idle(&mut self, ctx: &ActorContext<Self>) {
        if !self.pending_catch_ups.is_empty()
            || !self.in_catch_up.is_empty()
            || !self.live_in_flight.is_empty()
        {
            return;
        }
        if self.idle_reported {
            return;
        }
        match ctx.get_parent::<SinkManager>().await {
            Ok(parent) => {
                // Latch only on delivery: a lost report must be retried,
                // not suppressed forever.
                if parent
                    .tell(SinkManagerMessage::WorkerIdle {
                        sink: self.sink_name.clone(),
                    })
                    .await
                    .is_ok()
                {
                    self.idle_reported = true;
                } else {
                    error!(msg_type = "ReportIdle", sink = %self.sink_name, "Failed to report idle to parent");
                }
            }
            Err(e) => {
                error!(msg_type = "ReportIdle", sink = %self.sink_name, error = %e, "Failed to report idle to parent");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stalled_catch_up_is_requeued_once_and_fresh_one_stays() {
        let timeout = Duration::from_secs(600);
        let now = Instant::now();
        let mut in_catch_up = HashMap::from([
            ("stalled".to_owned(), 7u64),
            ("fresh".to_owned(), 3u64),
        ]);
        let mut started = HashMap::from([
            ("stalled".to_owned(), now - Duration::from_secs(601)),
            ("fresh".to_owned(), now),
        ]);
        let stalled =
            stalled_catch_ups(&mut in_catch_up, &mut started, now, timeout);
        assert_eq!(stalled, vec![("stalled".to_owned(), 7)]);
        assert_eq!(in_catch_up.len(), 1);
        assert!(in_catch_up.contains_key("fresh"));

        // Missing timestamp also counts as stalled (never completes).
        in_catch_up.insert("orphan".to_owned(), 9);
        let stalled =
            stalled_catch_ups(&mut in_catch_up, &mut started, now, timeout);
        assert_eq!(stalled, vec![("orphan".to_owned(), 9)]);
        assert_eq!(in_catch_up.len(), 1);
    }
}
