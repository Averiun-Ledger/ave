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
    NotPersistentActor, Response, TimerKey,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info_span, warn};

use crate::config::SinkServer;
use crate::sink::SinkError;
use crate::sink::extract_sn;
use crate::sink::manager::{
    SendResult, SinkManager, SinkManagerMessage, SinkWorkerError,
};
use crate::sink::transport::{NodeSigner, SinkTransport};
use ave_common::DataToSink;

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
    ChildShutdown {
        subject_id: String,
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
    },
    /// Authentication failed and the event could not be delivered.
    AuthFailed {
        subject_id: String,
        sn: u64,
        error: String,
        /// `true` when the failure happened during catch-up.
        from_catch_up: bool,
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
// Healthcheck state
// ---------------------------------------------------------------------------

enum HealthcheckState {
    Healthy,
    Unhealthy { next_interval_idx: usize },
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
    blocked: Option<String>,
    /// Number of times the sink has "recovered" via healthcheck without
    /// a successful delivery.  Used to detect flapping sinks (LEV-2).
    recoveries_after_failure: u32,
    /// F-5: Timer key for the pending healthcheck timer.  Cancelling the key
    /// aborts the timer before it sends `HealthCheck`.
    pending_healthcheck: Option<TimerKey>,
    active_subject_workers: HashMap<
        String,
        ActorRef<crate::sink::subject_worker::SinkSubjectWorker>,
    >,
    /// F-5: Timer keys for pending child shutdown timers.
    pending_child_shutdowns: HashMap<String, TimerKey>,
    /// Subjects waiting for a catch-up slot once `max_catch_up_concurrency`
    /// allows it.
    pending_catch_ups: VecDeque<(String, u64)>,
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

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // Transport startup logic (HTTP: eager OAuth2 token fetch).
        // A failure is logged but does not prevent the worker from starting.
        if let Err(e) = self.client.warm_up().await {
            error!(msg_type = "TokenRefresh", sink = %self.sink_name, error = %e, "Failed to refresh token on startup");
        }

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

                let child_ref =
                    self.ensure_subject_worker(&subject_id, ctx).await?;
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
                    self.active_subject_workers.remove(&subject_id);
                    match ctx.get_parent::<SinkManager>().await {
                        Ok(parent) => {
                            if let Err(err) = parent
                                .emit_error(
                                    SinkWorkerError::SubjectWorkerRestarted {
                                        sink: self.sink_name.clone(),
                                        subject_id: subject_id.clone(),
                                    },
                                )
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
                    return Err(e);
                }

                self.schedule_child_shutdown(ctx, subject_id.clone());

                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::HealthCheck => {
                match self.client.health_check().await {
                    Ok(()) => {
                        if let HealthcheckState::Unhealthy { .. } =
                            self.healthcheck_state
                        {
                            self.recoveries_after_failure += 1;
                            if self.recoveries_after_failure
                                < self.server.max_recoveries_after_failure
                            {
                                self.healthcheck_state =
                                    HealthcheckState::Healthy;
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
                            let delay_secs = self
                                .server
                                .healthcheck_intervals_secs
                                .first()
                                .copied()
                                .unwrap_or(60);
                            let delay_secs =
                                crate::sink::add_jitter(delay_secs);
                            self.schedule_healthcheck(ctx, delay_secs);
                        }
                    }
                    Err(_) => {
                        let idx = match self.healthcheck_state {
                            HealthcheckState::Healthy => 0,
                            HealthcheckState::Unhealthy {
                                next_interval_idx,
                            } => next_interval_idx,
                        };
                        let intervals = &self.server.healthcheck_intervals_secs;
                        let last_idx = intervals.len().saturating_sub(1);
                        let delay_secs = intervals
                            .get(idx.min(last_idx))
                            .copied()
                            .unwrap_or(60);
                        let delay_secs = crate::sink::add_jitter(delay_secs);
                        self.healthcheck_state = HealthcheckState::Unhealthy {
                            next_interval_idx: (idx + 1).min(last_idx),
                        };
                        self.broadcast_to_children(
                            crate::sink::subject_worker::SinkSubjectWorkerMessage::Pause,
                            ctx,
                        )
                        .await;

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
                        self.in_catch_up.insert(subject_id.clone(), from_sn);
                        let child_ref = self
                            .ensure_subject_worker(&subject_id, ctx)
                            .await?;
                        child_ref
                            .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::CatchUpBatch {
                                from_sn,
                                batch_size: self.server.catch_up_batch_size,
                            })
                            .await?;
                        self.schedule_child_shutdown(ctx, subject_id.clone());
                    }
                    // from_sn >= current_from: already covered by the
                    // in-flight catch-up, nothing to do.
                    return Ok(SinkWorkerResponse::Ok);
                }

                if self.in_catch_up.len()
                    >= self.server.max_catch_up_concurrency
                {
                    if !self
                        .pending_catch_ups
                        .iter()
                        .any(|(id, _)| id == &subject_id)
                    {
                        self.pending_catch_ups.push_back((subject_id, from_sn));
                    }
                    return Ok(SinkWorkerResponse::Ok);
                }

                self.in_catch_up.insert(subject_id.clone(), from_sn);
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
                    self.ensure_subject_worker(&subject_id, ctx).await?;
                child_ref
                    .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::CatchUpBatch {
                        from_sn,
                        batch_size: self.server.catch_up_batch_size,
                    })
                    .await?;

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
                if matches!(result, SendResult::Success) {
                    self.recoveries_after_failure = 0;
                    if matches!(
                        self.healthcheck_state,
                        HealthcheckState::Unhealthy { .. }
                    ) {
                        self.healthcheck_state = HealthcheckState::Healthy;
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
                self.in_catch_up.remove(&subject_id);
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
            SinkWorkerMessage::ChildShutdown { subject_id } => {
                self.in_catch_up.remove(&subject_id);
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
                self.pending_child_shutdowns.remove(&subject_id);
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::ResetRecoveries => {
                self.recoveries_after_failure = 0;
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::ClearBlocked => {
                self.blocked = None;
                // A manual unblock means the operator considers the sink ready to
                // retry.  Clear the unhealthy state and any pending healthcheck
                // so that catch-up requests sent after unblocking are accepted
                // immediately instead of being ignored until a healthcheck runs.
                self.healthcheck_state = HealthcheckState::Healthy;
                if let Some(key) = self.pending_healthcheck.take() {
                    ctx.cancel_timer(key);
                }
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
            } => {
                if from_catch_up {
                    self.in_catch_up.remove(&subject_id);
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
                    let delay_secs = self
                        .server
                        .healthcheck_intervals_secs
                        .first()
                        .copied()
                        .unwrap_or(30);
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
            } => {
                if from_catch_up {
                    self.in_catch_up.remove(&subject_id);
                    if self.blocked.is_none()
                        && !matches!(
                            self.healthcheck_state,
                            HealthcheckState::Unhealthy { .. }
                        )
                    {
                        self.healthcheck_state = HealthcheckState::Unhealthy {
                            next_interval_idx: 0,
                        };
                        let delay_secs = self
                            .server
                            .healthcheck_intervals_secs
                            .first()
                            .copied()
                            .unwrap_or(30);
                        let delay_secs = crate::sink::add_jitter(delay_secs);
                        self.schedule_healthcheck(ctx, delay_secs);
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
                    self.in_catch_up.remove(&subject_id);
                }
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
        if let Some(key) = self.pending_child_shutdowns.remove(&subject_id) {
            ctx.cancel_timer(key);
        }
        match ctx.schedule_once(
            Duration::from_millis(timeout_ms),
            SinkWorkerMessage::ChildShutdown {
                subject_id: subject_id.clone(),
            },
        ) {
            Ok(key) => {
                self.pending_child_shutdowns.insert(subject_id, key);
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
        if let Some(key) = self.pending_child_shutdowns.remove(subject_id) {
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
        let child_ref = ctx.create_child(subject_id, worker).await?;
        self.active_subject_workers
            .insert(subject_id.to_string(), child_ref.clone());
        Ok(child_ref)
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
                self.pending_catch_ups.push_front((subject_id, from_sn));
                break;
            }
            self.in_catch_up.insert(subject_id.clone(), from_sn);
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
                        self.in_catch_up.remove(&subject_id);
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
                    self.in_catch_up.remove(&subject_id);
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
        let client =
            crate::sink::build_transport(&server, signer, Some(&node_public_key))
                .await?;
        Ok(Self {
            sink_name,
            server,
            client,
            last_activity: Instant::now(),
            idle_reported: false,
            healthcheck_state: HealthcheckState::Healthy,
            in_catch_up: HashMap::new(),
            blocked: None,
            recoveries_after_failure: 0,
            pending_healthcheck: None,
            active_subject_workers: HashMap::new(),
            pending_child_shutdowns: HashMap::new(),
            pending_catch_ups: VecDeque::new(),
            is_governance,
        })
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
        if !self.pending_catch_ups.is_empty() || !self.in_catch_up.is_empty() {
            return;
        }
        if self.idle_reported {
            return;
        }
        self.idle_reported = true;
        match ctx.get_parent::<SinkManager>().await {
            Ok(parent) => {
                let _ = parent
                    .tell(SinkManagerMessage::WorkerIdle {
                        sink: self.sink_name.clone(),
                    })
                    .await;
            }
            Err(e) => {
                error!(msg_type = "ReportIdle", sink = %self.sink_name, error = %e, "Failed to report idle to parent");
            }
        }
    }
}
