//! SinkWorker: ephemeral worker actor that sends events to external HTTP sinks.
//!
//! Lifecycle: the SinkWorker reports inactivity to the parent SinkManager via
//! WorkerIdle.  The MANAGER decides when to stop the worker (after a
//! configurable idle timeout).  The worker NEVER self-destructs.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler, Message, NotPersistentActor,
    Response,
};
use serde::{Deserialize, Serialize};
use tokio_util::sync::CancellationToken;
use tracing::{error, info_span, warn};

use crate::config::SinkServer;
use crate::sink::http::SinkHttpClient;
use crate::sink::manager::{SinkManager, SinkManagerMessage, SendResult};
use crate::sink::extract_sn;
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
    },
    CatchUpProgress {
        subject_id: String,
        sn: u64,
        result: crate::sink::manager::SendResult,
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
    client: Arc<SinkHttpClient>,
    last_activity: Instant,
    healthcheck_state: HealthcheckState,
    in_catch_up: HashSet<String>,
    blocked: Option<String>,
    /// Number of times the sink has "recovered" via healthcheck without
    /// a successful delivery.  Used to detect flapping sinks (LEV-2).
    recoveries_after_failure: u32,
    /// F-5: Cancellation token for the pending healthcheck timer.  Cancelling
    /// the token aborts the timer *before* it sends `HealthCheck`, eliminating
    /// the race between `abort()` and a task that has already woken up.
    pending_healthcheck: Option<CancellationToken>,
    active_subject_workers: HashMap<String, ActorRef<crate::sink::subject_worker::SinkSubjectWorker>>,
    /// F-5: Cancellation tokens for pending child shutdown timers.  Each token
    /// is shared between the worker and the spawned timer task.
    pending_child_shutdowns: HashMap<String, CancellationToken>,
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
    type ChildError = ActorError;
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
        // If the sink has auth config, try to obtain a token eagerly on startup.
        if let Some(ref auth) = self.server.auth
            && !auth.auth_url.is_empty()
            && !auth.username.is_empty()
        {
            let password = std::env::var(
                crate::sink::http::sink_password_env_var(&self.sink_name)
            ).unwrap_or_default();
            if !password.is_empty() {
                match crate::sink::obtain_token(
                    &auth.auth_url,
                    &auth.username,
                    &password,
                )
                .await
                {
                    Ok(token) => {
                        let mut guard = self.client.cached_token.write().await;
                        *guard = Some(token);
                    }
                    Err(e) => {
                        error!(msg_type = "TokenRefresh", sink = %self.sink_name, error = %e, "Failed to refresh token on startup");
                    }
                }
            }
        }

        // Schedule first healthcheck after configurable startup delay + jitter.
        let self_ref = ctx.reference().await?;
        let startup_delay = crate::sink::add_jitter(self.server.startup_healthcheck_delay_secs);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(startup_delay)).await;
            let _ = self_ref.tell(SinkWorkerMessage::HealthCheck).await;
        });
        Ok(())
    }
}

#[async_trait]
impl Handler<SinkWorker> for SinkWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkWorkerMessage,
        ctx: &mut ActorContext<SinkWorker>,
    ) -> Result<SinkWorkerResponse, ActorError> {
        match msg {
            SinkWorkerMessage::NotifyNewEvent(data) => {
                if let Some(ref _reason) = self.blocked {
                    return Ok(SinkWorkerResponse::Ok);
                }

                if matches!(self.healthcheck_state, HealthcheckState::Unhealthy { .. }) {
                    let (subject_id, _schema_id) = data.payload.get_subject_schema();
                    let sn = extract_sn(&data);
                    match ctx.get_parent::<SinkManager>().await {
                        Ok(parent) => {
                            if let Err(e) = parent
                                .tell(SinkManagerMessage::UpdateProgress {
                                    sink: self.sink_name.clone(),
                                    subject_id,
                                    sn,
                                    result: SendResult::Failed("sink unhealthy".into()),
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
                let (subject_id, _schema_id) = data.payload.get_subject_schema();

                let child_ref = self.ensure_subject_worker(&subject_id, ctx).await?;
                child_ref
                    .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::DeliverEvent(
                        Arc::clone(&data),
                    ))
                    .await?;

                self.schedule_child_shutdown(subject_id.clone(), ctx.reference().await?);

                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::HealthCheck => {
                match self.client.health_check().await {
                    Ok(()) => {
                        if let HealthcheckState::Unhealthy { .. } = self.healthcheck_state {
                            self.recoveries_after_failure += 1;
                            if self.recoveries_after_failure < self.server.max_recoveries_after_failure {
                                self.healthcheck_state = HealthcheckState::Healthy;
                                self.broadcast_to_children(
                                    crate::sink::subject_worker::SinkSubjectWorkerMessage::Resume,
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
                                warn!(
                                    msg_type = "FlappingSinkBlocked",
                                    sink = %self.sink_name,
                                    recoveries = %self.recoveries_after_failure,
                                    "Sink healthcheck OK but delivery keeps failing; blocking sink"
                                );
                                self.blocked = Some("sink flapping: healthcheck OK but delivery fails".to_owned());
                                self.broadcast_to_children(
                                    crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop,
                                )
                                .await;
                                self.active_subject_workers.clear();
                                self.in_catch_up.clear();
                                match ctx.get_parent::<SinkManager>().await {
                                    Ok(parent) => {
                                        if let Err(e) = parent
                                            .tell(SinkManagerMessage::UpdateProgress {
                                                sink: self.sink_name.clone(),
                                                subject_id: String::new(),
                                                sn: 0,
                                                result: SendResult::Blocked(self.blocked.clone().unwrap()),
                                            })
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
                    }
                    Err(_) => {
                        let idx = match self.healthcheck_state {
                            HealthcheckState::Healthy => 0,
                            HealthcheckState::Unhealthy { next_interval_idx } => next_interval_idx,
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
                        )
                        .await;

                        let self_ref = ctx.reference().await?;
                        self.schedule_healthcheck(self_ref, delay_secs);
                    }
                }
                // Report idle state to parent so manager can decide on shutdown.
                if Instant::now().duration_since(self.last_activity)
                    >= Duration::from_millis(self.server.sink_worker_idle_timeout_ms)
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
                    return Ok(SinkWorkerResponse::Ok);
                }

                if matches!(self.healthcheck_state, HealthcheckState::Unhealthy { .. }) {
                    return Ok(SinkWorkerResponse::Ok);
                }

                if self.in_catch_up.len() >= self.server.max_catch_up_concurrency
                    && !self.in_catch_up.contains(&subject_id)
                {
                    return Ok(SinkWorkerResponse::Ok);
                }

                self.in_catch_up.insert(subject_id.clone());
                self.last_activity = Instant::now();

                let child_ref = self.ensure_subject_worker(&subject_id, ctx).await?;
                child_ref
                    .tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::CatchUpBatch {
                        from_sn,
                        batch_size: self.server.batch_size,
                    })
                    .await?;

                self.schedule_child_shutdown(subject_id.clone(), ctx.reference().await?);

                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::DeliveryResult {
                subject_id,
                sn,
                result,
            } => {
                self.last_activity = Instant::now();
                self.cancel_child_shutdown(&subject_id);
                match result {
                    SendResult::Success => {
                        self.recoveries_after_failure = 0;
                        if matches!(self.healthcheck_state, HealthcheckState::Unhealthy { .. }) {
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
                    }
                    SendResult::AuthFailed(ref err) => {
                        match ctx.get_parent::<SinkManager>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .tell(SinkManagerMessage::UpdateProgress {
                                        sink: self.sink_name.clone(),
                                        subject_id: subject_id.clone(),
                                        sn,
                                        result: SendResult::AuthFailed(err.clone()),
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
                    }
                    SendResult::Blocked(ref reason) => {
                        self.blocked = Some(reason.clone());
                        match ctx.get_parent::<SinkManager>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .tell(SinkManagerMessage::UpdateProgress {
                                        sink: self.sink_name.clone(),
                                        subject_id: subject_id.clone(),
                                        sn,
                                        result: SendResult::Blocked(reason.clone()),
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
                        self.broadcast_to_children(
                            crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop,
                        )
                        .await;
                        self.active_subject_workers.clear();
                        self.in_catch_up.clear();
                    }
                    SendResult::Failed(ref reason) => {
                        if self.blocked.is_none()
                            && !matches!(self.healthcheck_state, HealthcheckState::Unhealthy { .. })
                        {
                            self.healthcheck_state = HealthcheckState::Unhealthy { next_interval_idx: 0 };
                            let self_ref = ctx.reference().await?;
                            let delay_secs = self.server.healthcheck_intervals_secs.first().copied().unwrap_or(30);
                            let delay_secs = crate::sink::add_jitter(delay_secs);
                            self.schedule_healthcheck(self_ref, delay_secs);
                        }
                        match ctx.get_parent::<SinkManager>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .tell(SinkManagerMessage::UpdateProgress {
                                        sink: self.sink_name.clone(),
                                        subject_id: subject_id.clone(),
                                        sn,
                                        result: SendResult::Failed(reason.clone()),
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
                    }
                    SendResult::SubjectNotFound => {}
                }
                if !matches!(result, SendResult::Blocked(_)) {
                    self.schedule_child_shutdown(subject_id, ctx.reference().await?);
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::CatchUpProgress {
                subject_id,
                sn,
                result,
            } => {
                self.last_activity = Instant::now();
                self.cancel_child_shutdown(&subject_id);
                let result_clone = result.clone();
                match ctx.get_parent::<SinkManager>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .tell(SinkManagerMessage::UpdateProgress {
                                sink: self.sink_name.clone(),
                                subject_id: subject_id.clone(),
                                sn,
                                result: result_clone,
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
                match &result {
                    SendResult::Blocked(reason) => {
                        self.blocked = Some(reason.clone());
                        self.broadcast_to_children(
                            crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop,
                        )
                        .await;
                        self.active_subject_workers.clear();
                        self.in_catch_up.clear();
                    }
                    SendResult::Failed(_) | SendResult::AuthFailed(_) => {
                        self.in_catch_up.remove(&subject_id);
                        if self.blocked.is_none()
                            && !matches!(self.healthcheck_state, HealthcheckState::Unhealthy { .. })
                        {
                            self.healthcheck_state = HealthcheckState::Unhealthy { next_interval_idx: 0 };
                            let self_ref = ctx.reference().await?;
                            let delay_secs = self.server.healthcheck_intervals_secs.first().copied().unwrap_or(30);
                            let delay_secs = crate::sink::add_jitter(delay_secs);
                            self.schedule_healthcheck(self_ref, delay_secs);
                        }
                    }
                    SendResult::SubjectNotFound => {
                        self.in_catch_up.remove(&subject_id);
                    }
                    SendResult::Success => {}
                }
                if !matches!(result, SendResult::Blocked(_)) {
                    self.schedule_child_shutdown(subject_id, ctx.reference().await?);
                }
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::CatchUpCompleted { subject_id } => {
                self.in_catch_up.remove(&subject_id);
                self.cancel_child_shutdown(&subject_id);
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::ChildShutdown { subject_id } => {
                self.in_catch_up.remove(&subject_id);
                if let Some(child_ref) = self.active_subject_workers.remove(&subject_id) {
                    let _ = child_ref.tell(crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop).await;
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
                Ok(SinkWorkerResponse::Ok)
            }
            SinkWorkerMessage::Stop => {
                ctx.stop(None).await;
                Ok(SinkWorkerResponse::Ok)
            }
        }
    }
}

impl SinkWorker {
    /// F-5: Schedule a healthcheck after `delay_secs`, cancelling any
    /// previously scheduled healthcheck to avoid redundant checks.
    fn schedule_healthcheck(&mut self, self_ref: ActorRef<SinkWorker>, delay_secs: u64) {
        if let Some(token) = self.pending_healthcheck.take() {
            token.cancel();
        }
        let token = CancellationToken::new();
        let token_for_task = token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {
                    if !token_for_task.is_cancelled() {
                        let _ = self_ref.tell(SinkWorkerMessage::HealthCheck).await;
                    }
                }
                _ = token_for_task.cancelled() => {
                    // Timer was cancelled — do nothing.
                }
            }
        });
        self.pending_healthcheck = Some(token);
    }

    fn schedule_child_shutdown(&mut self, subject_id: String, self_ref: ActorRef<Self>) {
        let timeout_ms = self.server.sink_subject_worker_idle_timeout_ms;
        if let Some(token) = self.pending_child_shutdowns.remove(&subject_id) {
            token.cancel();
        }
        let sid = subject_id.clone();
        let token = CancellationToken::new();
        let token_for_task = token.clone();
        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(timeout_ms)) => {
                    if !token_for_task.is_cancelled() {
                        let _ = self_ref.tell(SinkWorkerMessage::ChildShutdown { subject_id: sid }).await;
                    }
                }
                _ = token_for_task.cancelled() => {
                    // Timer was cancelled — do nothing.
                }
            }
        });
        self.pending_child_shutdowns.insert(subject_id, token);
    }

    fn cancel_child_shutdown(&mut self, subject_id: &str) {
        if let Some(token) = self.pending_child_shutdowns.remove(subject_id) {
            token.cancel();
        }
    }

    async fn ensure_subject_worker(
        &mut self,
        subject_id: &str,
        ctx: &mut ActorContext<Self>,
    ) -> Result<ActorRef<crate::sink::subject_worker::SinkSubjectWorker>, ActorError> {
        self.cancel_child_shutdown(subject_id);
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
        self.active_subject_workers.insert(subject_id.to_string(), child_ref.clone());
        Ok(child_ref)
    }

    async fn broadcast_to_children(
        &mut self,
        msg: crate::sink::subject_worker::SinkSubjectWorkerMessage,
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
        if matches!(msg, crate::sink::subject_worker::SinkSubjectWorkerMessage::Stop) {
            let keys: Vec<String> = self.pending_child_shutdowns.keys().cloned().collect();
            for subject_id in keys {
                self.cancel_child_shutdown(&subject_id);
            }
        }
    }

    pub fn new(
        sink_name: String,
        server: SinkServer,
        is_governance: bool,
    ) -> Self {
        let client = Arc::new(SinkHttpClient::new(server.clone()));
        Self {
            sink_name,
            server,
            client,
            last_activity: Instant::now(),
            healthcheck_state: HealthcheckState::Healthy,
            in_catch_up: HashSet::new(),
            blocked: None,
            recoveries_after_failure: 0,
            pending_healthcheck: None,
            active_subject_workers: HashMap::new(),
            pending_child_shutdowns: HashMap::new(),
            is_governance,
        }
    }

    /// Report idle state to parent manager.  The manager decides whether to
    /// stop this worker after a configurable timeout.
    async fn report_idle(&self, ctx: &mut ActorContext<Self>) {
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


