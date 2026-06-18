//! SinkManager: persistent actor that tracks cursors and manages SinkWorkers.
//!
//! Instanced once under the Node (for governance events) and once under each
//! Governance (for tracker events).

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{error, info, info_span, warn};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Event, Handler,
    LightPersistence, Message, PersistentActor, Response,
};
use ave_common::DataToSink;

use ave_common::sink::{
    default_sink_healthcheck_intervals_secs, default_sink_worker_idle_timeout_ms, SinkServer,
};

use crate::db::Storable;
use crate::sink::worker::{SinkWorker, SinkWorkerMessage};
use crate::sink::extract_sn;
use crate::system::ConfigHelper;

// ---------------------------------------------------------------------------
// InitParams
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct SinkManagerInitParams {
    /// Sinks relevant to this manager (filtered by schema_id upstream).
    pub sinks: Vec<SinkServer>,
    /// `true` when this manager is instanced under the Node (handles
    /// governance events). `false` when under a Governance (handles
    /// tracker events).
    pub is_governance: bool,
}

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkManagerMessage {
    NotifyNewEvent(Arc<DataToSink>),
    UpdateProgress {
        sink: String,
        subject_id: String,
        sn: u64,
        result: SendResult,
    },
    SinkRecovered {
        sink: String,
    },
    UnblockSink {
        sink: String,
    },
    /// Safe Mode only: delete all persisted cursors and transient state for a sink.
    DeleteSinkCursors {
        sink: String,
    },
    GetStatus,
    GetDetailedStatus,
    /// Worker reports it has been idle for sink_worker_idle_timeout_ms.
    WorkerIdle {
        sink: String,
    },
    /// Remove all tracking state for a subject that has been deleted.
    RemoveSubject {
        subject_id: String,
    },
    /// Worker reports that a subject catch-up has completed.
    CatchUpCompleted {
        sink: String,
        subject_id: String,
    },
}

impl Message for SinkManagerMessage {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkManagerResponse {
    Ok,
    Status(Vec<SinkStatus>),
    DetailedStatus(SinkManagerDetailedStatus),
}

impl Response for SinkManagerResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkStatus {
    pub sink: String,
    pub blocked: Option<String>,
    pub lagging_subjects: usize,
    pub active: bool,
}

/// Detailed runtime + configuration snapshot of a sink manager.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkManagerDetailedStatus {
    pub is_governance: bool,
    pub governance_id: Option<String>,
    pub sinks: Vec<SinkStatus>,
    pub servers: BTreeMap<String, SinkServer>,
}

// ---------------------------------------------------------------------------
// SendResult
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SendResult {
    Success,
    /// The subject no longer exists (deleted). EOL is a normal event, not SubjectNotFound.
    SubjectNotFound,
}

// ---------------------------------------------------------------------------
// SinkWorkerError
// ---------------------------------------------------------------------------

/// Errors reported by a `SinkWorker` to its parent `SinkManager` via `emit_error`.
#[derive(Debug, Clone)]
pub enum SinkWorkerError {
    /// Event delivery failed (transient or unhealthy).
    DeliveryFailed {
        sink: String,
        subject_id: String,
        sn: u64,
        reason: String,
    },
    /// Authentication failed and the event could not be delivered.
    AuthFailed {
        sink: String,
        subject_id: String,
        sn: u64,
        error: String,
    },
    /// The sink is blocked due to a permanent error.
    Blocked {
        sink: String,
        subject_id: String,
        sn: u64,
        reason: String,
    },
    /// The subject no longer exists (deleted).
    SubjectNotFound {
        sink: String,
        subject_id: String,
        sn: u64,
    },
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize)]
pub enum SinkManagerEvent {
    CursorUpdated {
        sink: String,
        subject_id: String,
        sn: u64,
    },
    CursorRemoved {
        sink: String,
        subject_id: String,
    },
    LastSeenUpdated {
        subject_id: String,
        sn: u64,
    },
    LastSeenRemoved {
        subject_id: String,
    },
    SinkRecovered {
        sink: String,
    },
    SinkBlocked {
        sink: String,
        reason: String,
    },
    SinkUnblocked {
        sink: String,
    },
    /// Safe Mode only: all cursors and transient state for a sink have been deleted.
    SinkCursorsDeleted {
        sink: String,
    },
}

impl Event for SinkManagerEvent {}

// ---------------------------------------------------------------------------
// Actor state
// ---------------------------------------------------------------------------

#[derive(Serialize, Deserialize, Clone)]
pub struct SinkManager {
    // === Persisted fields ===
    cursors: BTreeMap<(String, String), u64>, // (sink_name, subject_id) -> sn_sent
    last_seen: BTreeMap<String, u64>,         // subject_id -> sn_last
    active_sinks: BTreeSet<String>,           // sink names active in config
    version: u64,

    // === Transient fields (reconstructed on startup) ===
    #[serde(skip)]
    sink_servers: BTreeMap<String, SinkServer>, // sink_name -> config (from node/gov config)
    #[serde(skip)]
    lagging: BTreeMap<String, HashSet<String>>, // sink_name -> outdated subject_ids
    #[serde(skip)]
    store_params: Option<SinkManagerInitParams>, // saved for pre_start
    #[serde(skip)]
    blocked_sinks: BTreeMap<String, String>, // sink_name -> reason
    /// `true` when this manager handles governance events (under Node),
    /// `false` when it handles tracker events (under Governance).
    #[serde(skip)]
    is_governance: bool,
    /// F-5: Cancellation tokens for pending worker shutdown timers.  Each token
    /// is shared between the manager and the spawned timer task; cancelling the
    /// token aborts the timer *before* it sends `Stop`, eliminating the race
    /// between `abort()` and a task that has already woken up.
    #[serde(skip)]
    pending_worker_shutdowns: HashMap<String, CancellationToken>,
    /// Cancellation tokens for pending healthcheck timers.  When a sink has
    /// lagging subjects but no active worker, the manager schedules periodic
    /// healthchecks using `healthcheck_intervals_secs` to detect recovery.
    #[serde(skip)]
    pending_healthchecks: HashMap<String, CancellationToken>,
}

impl std::fmt::Debug for SinkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkManager")
            .field("cursors", &self.cursors)
            .field("last_seen", &self.last_seen)
            .field("active_sinks", &self.active_sinks)
            .field("version", &self.version)
            .field("sink_servers", &self.sink_servers.keys().collect::<Vec<_>>())
            .field("lagging", &self.lagging)
            .field("blocked_sinks", &self.blocked_sinks.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BorshSerialize for SinkManager {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.cursors, writer)?;
        BorshSerialize::serialize(&self.last_seen, writer)?;
        BorshSerialize::serialize(&self.active_sinks, writer)?;
        BorshSerialize::serialize(&self.version, writer)?;
        BorshSerialize::serialize(&self.blocked_sinks, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for SinkManager {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> std::io::Result<Self> {
        let cursors = BTreeMap::<(String, String), u64>::deserialize_reader(reader)?;
        let last_seen = BTreeMap::<String, u64>::deserialize_reader(reader)?;
        let active_sinks = BTreeSet::<String>::deserialize_reader(reader)?;
        let version = u64::deserialize_reader(reader)?;
        // Backward compatibility: old snapshots may not include blocked_sinks.
        let blocked_sinks = match BTreeMap::<String, String>::deserialize_reader(reader) {
            Ok(v) => v,
            Err(e) => {
                warn!(msg_type = "BorshCompat", field = "blocked_sinks", error = %e, "Using default for missing field");
                BTreeMap::new()
            }
        };
        Ok(Self {
            cursors,
            last_seen,
            active_sinks,
            version,
            sink_servers: BTreeMap::new(),
            lagging: BTreeMap::new(),
            store_params: None,
            blocked_sinks,
            is_governance: false, // default from BorshDeserialize, will be overridden by create_initial
            pending_worker_shutdowns: HashMap::new(),
            pending_healthchecks: HashMap::new(),
        })
    }
}

// ---------------------------------------------------------------------------
// PersistentActor
// ---------------------------------------------------------------------------

impl PersistentActor for SinkManager {
    type Persistence = LightPersistence;
    type InitParams = SinkManagerInitParams;
    type State = Self;

    fn create_initial(params: Self::InitParams) -> Self {
        let mut active_sinks = BTreeSet::new();
        let mut sink_servers = BTreeMap::new();
        for sink in &params.sinks {
            active_sinks.insert(sink.server.clone());
            sink_servers.insert(sink.server.clone(), sink.clone());
        }
        Self {
            cursors: BTreeMap::new(),
            last_seen: BTreeMap::new(),
            active_sinks,
            version: 1,
            sink_servers,
            lagging: BTreeMap::new(),
            store_params: Some(params.clone()),
            blocked_sinks: BTreeMap::new(),
            is_governance: params.is_governance,
            pending_worker_shutdowns: HashMap::new(),
            pending_healthchecks: HashMap::new(),
        }
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            SinkManagerEvent::CursorUpdated { sink, subject_id, sn } => {
                inner.cursors.insert((sink.clone(), subject_id.clone()), *sn);
            }
            SinkManagerEvent::CursorRemoved { sink, subject_id } => {
                inner.cursors.remove(&(sink.clone(), subject_id.clone()));
            }
            SinkManagerEvent::LastSeenUpdated { subject_id, sn } => {
                inner.last_seen.insert(subject_id.clone(), *sn);
            }
            SinkManagerEvent::LastSeenRemoved { subject_id } => {
                inner.last_seen.remove(subject_id);
            }
            SinkManagerEvent::SinkRecovered { sink } => {
                inner.active_sinks.insert(sink.clone());
            }
            SinkManagerEvent::SinkBlocked { sink, reason } => {
                inner.blocked_sinks.insert(sink.clone(), reason.clone());
            }
            SinkManagerEvent::SinkUnblocked { sink } => {
                inner.blocked_sinks.remove(sink);
            }
            SinkManagerEvent::SinkCursorsDeleted { sink } => {
                inner.cursors.retain(|(s, _), _| s != sink);
                inner.lagging.remove(sink);
                inner.blocked_sinks.remove(sink);
            }
        }
        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        Arc::new(Self {
            cursors: self.cursors.clone(),
            last_seen: self.last_seen.clone(),
            active_sinks: self.active_sinks.clone(),
            version: self.version,
            sink_servers: self.sink_servers.clone(),
            lagging: self.lagging.clone(),
            store_params: self.store_params.clone(),
            blocked_sinks: self.blocked_sinks.clone(),
            is_governance: self.is_governance,
            pending_worker_shutdowns: HashMap::new(),
            pending_healthchecks: HashMap::new(),
        })
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        let state = &*state;
        self.cursors.clone_from(&state.cursors);
        self.last_seen.clone_from(&state.last_seen);
        self.active_sinks.clone_from(&state.active_sinks);
        self.version = state.version;
        self.blocked_sinks.clone_from(&state.blocked_sinks);
    }
}

impl Storable for SinkManager {}

// ---------------------------------------------------------------------------
// Actor lifecycle
// ---------------------------------------------------------------------------

#[async_trait]
impl Actor for SinkManager {
    type Message = SinkManagerMessage;
    type Response = SinkManagerResponse;
    type Event = SinkManagerEvent;
    type SinkEvent = ();
    type ChildError = SinkWorkerError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<tracing::Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("sink_manager"),
            |parent_span| info_span!(parent: parent_span, "sink_manager"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let params = self.store_params.take().ok_or_else(|| ActorError::Functional {
            description: "SinkManager missing init params".to_owned(),
        })?;

        // Validate sink server name uniqueness.
        let mut seen = HashSet::new();
        for sink in &params.sinks {
            if !seen.insert(sink.server.clone()) {
                return Err(ActorError::Functional {
                    description: format!("Duplicate sink server name: {}", sink.server),
                });
            }
        }

        // Init store. Parent key is derived from the actor path so that
        // NodeSinkManager and each Governance SinkManager have separate stores.
        if let Err(e) = self.init_store("sink", Some(ctx.path().parent().key().to_owned()), false, ctx).await {
            error!(msg_type = "InitStore", error = %e, "Failed to initialize sink manager store");
            return Err(e);
        }

        // Rebuild sink_servers from init params (current config at creation time).
        let mut sink_servers = BTreeMap::new();
        for sink in &params.sinks {
            sink_servers.insert(sink.server.clone(), sink.clone());
        }

        self.active_sinks = sink_servers.keys().cloned().collect();
        self.sink_servers = sink_servers;

        // Rebuild lagging set: for every subject and every active sink,
        // check if cursor is behind last_seen.
        self.rebuild_lagging();

        // Auto-unblock all sinks on startup: the operator may have fixed the
        // sink while the node was down, so we retry permanent failures.
        // This is expressed as events so that the state remains the source of
        // truth after recovery.
        let blocked: Vec<String> = self.blocked_sinks.keys().cloned().collect();
        if !blocked.is_empty() {
            info!(
                msg_type = "AutoUnblock",
                count = %blocked.len(),
                "Unblocking all sinks on startup to retry permanent failures"
            );
            for sink in blocked {
                self.persist(SinkManagerEvent::SinkUnblocked { sink }, ctx)
                    .await?;
            }
        }

        // In safe mode we only need the manager alive (it holds the cursors).
        // Workers are ephemeral and would be idle anyway because no new events
        // are processed, so we skip creating them.
        let safe_mode = if let Some(config) = ctx
            .system()
            .get_helper::<ConfigHelper>("config")
            .await
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if !safe_mode {
            for sink_name in self.sink_servers.keys().cloned().collect::<Vec<_>>() {
                match self.ensure_worker(&sink_name, ctx).await {
                    Ok(_) => {
                        info!(msg_type = "StartWorker", sink = %sink_name, "SinkWorker started");
                    }
                    Err(e) => {
                        error!(msg_type = "StartWorker", sink = %sink_name, error = %e, "Failed to start SinkWorker");
                    }
                }
            }

            // Trigger catch-up for any subjects that are behind. This is
            // essential when a new sink is added to the configuration: all
            // existing subjects will have no cursor for it and must be brought
            // up to date incrementally.
            let lagging: Vec<(String, Vec<String>)> = self
                .lagging
                .iter()
                .map(|(sink, subjects)| (sink.clone(), subjects.iter().cloned().collect()))
                .collect();
            for (sink_name, subjects) in lagging {
                if let Err(e) = self.handle_request_catch_up(sink_name.clone(), subjects, ctx).await {
                    error!(
                        msg_type = "StartupCatchUp",
                        sink = %sink_name,
                        error = %e,
                        "Failed to trigger startup catch-up"
                    );
                }
            }
        }

        info!(
            msg_type = "Start",
            safe_mode = %safe_mode,
            active_sinks = %self.active_sinks.len(),
            lagging_subjects = %self.lagging.values().map(|s| s.len()).sum::<usize>(),
            "SinkManager started"
        );

        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Handler
// ---------------------------------------------------------------------------

#[async_trait]
impl Handler<SinkManager> for SinkManager {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkManagerMessage,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<SinkManagerResponse, ActorError> {
        match msg {
            SinkManagerMessage::NotifyNewEvent(data) => {
                self.handle_notify_new_event(data, ctx).await?;
            }
            SinkManagerMessage::UpdateProgress {
                sink,
                subject_id,
                sn,
                result,
            } => {
                self.handle_update_progress(sink, subject_id, sn, result, ctx)
                    .await?;
            }
            SinkManagerMessage::SinkRecovered { sink } => {
                self.handle_sink_recovered(sink, ctx).await?;
            }
            SinkManagerMessage::UnblockSink { sink } => {
                self.handle_unblock_sink(sink, ctx).await?;
            }
            SinkManagerMessage::DeleteSinkCursors { sink } => {
                self.handle_delete_sink_cursors(sink, ctx).await?;
            }
            SinkManagerMessage::GetStatus => {
                return Ok(SinkManagerResponse::Status(self.build_sink_statuses()));
            }
            SinkManagerMessage::GetDetailedStatus => {
                let governance_id = if self.is_governance {
                    None
                } else {
                    Some(ctx.path().parent().key().to_string())
                };
                return Ok(SinkManagerResponse::DetailedStatus(
                    SinkManagerDetailedStatus {
                        is_governance: self.is_governance,
                        governance_id,
                        sinks: self.build_sink_statuses(),
                        servers: self.sink_servers.clone(),
                    },
                ));
            }
            SinkManagerMessage::WorkerIdle { sink } => {
                self.schedule_worker_shutdown(sink, ctx);
            }
            SinkManagerMessage::RemoveSubject { subject_id } => {
                self.handle_remove_subject(&subject_id, ctx).await?;
            }
            SinkManagerMessage::CatchUpCompleted { sink, subject_id } => {
                self.handle_catch_up_completed(sink, subject_id, ctx)
                    .await?;
            }
        }
        Ok(SinkManagerResponse::Ok)
    }

    async fn on_child_error(
        &mut self,
        error: SinkWorkerError,
        ctx: &mut ActorContext<SinkManager>,
    ) {
        match error {
            SinkWorkerError::DeliveryFailed {
                sink,
                subject_id,
                sn,
                reason,
            } => {
                error!(msg_type = "DeliveryFailed", sink = %sink, subject_id = %subject_id, sn = %sn, reason = %reason, "Sink delivery failed");
                self.try_insert_lagging(&sink, subject_id);
                // If the sink has lagging subjects, schedule periodic healthchecks
                // to detect when the sink recovers.  The worker will be idle and
                // destroyed soon; the healthcheck timer recreates it periodically.
                if self.lagging.get(&sink).map(|s| !s.is_empty()).unwrap_or(false) {
                    self.schedule_healthcheck(sink, ctx);
                }
            }
            SinkWorkerError::AuthFailed {
                sink,
                subject_id,
                sn,
                error,
            } => {
                // CR-3: Do NOT advance cursor on auth failure — the event will be
                // retried once credentials are fixed (via catch-up / lagging).
                error!(
                    msg_type = "AuthFailed",
                    sink = %sink,
                    subject_id = %subject_id,
                    sn = %sn,
                    error = %error,
                    "Auth failure; event kept in lagging for retry"
                );
                self.try_insert_lagging(&sink, subject_id.clone());
                if let Some(subjects) = self.lagging.get(&sink).cloned() {
                    let subjects: Vec<String> = subjects.into_iter().collect();
                    if !subjects.is_empty() {
                        let sink_for_log = sink.clone();
                        if let Err(e) = self.handle_request_catch_up(sink, subjects, ctx).await {
                            error!(msg_type = "AuthFailedCatchUp", sink = %sink_for_log, error = %e, "Failed to trigger catch-up after auth failure");
                        }
                    }
                }
            }
            SinkWorkerError::Blocked {
                sink,
                subject_id,
                sn,
                reason,
            } => {
                error!(
                    msg_type = "SinkBlocked",
                    sink = %sink,
                    subject_id = %subject_id,
                    sn = %sn,
                    reason = %reason,
                    "Sink blocked due to permanent error; operator intervention required"
                );
                if let Err(e) = self
                    .persist(
                        SinkManagerEvent::SinkBlocked {
                            sink: sink.clone(),
                            reason: reason.clone(),
                        },
                        ctx,
                    )
                    .await
                {
                    error!(msg_type = "PersistBlocked", sink = %sink, error = %e, "Failed to persist blocked sink");
                }
            }
            SinkWorkerError::SubjectNotFound {
                sink,
                subject_id,
                sn,
            } => {
                if let Err(e) = self
                    .handle_update_progress(
                        sink,
                        subject_id,
                        sn,
                        SendResult::SubjectNotFound,
                        ctx,
                    )
                    .await
                {
                    error!(msg_type = "SubjectNotFound", error = %e, "Failed to update progress for deleted subject");
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Internal logic
// ---------------------------------------------------------------------------

impl SinkManager {
    fn build_sink_statuses(&self) -> Vec<SinkStatus> {
        let mut all_sinks: HashSet<String> = HashSet::new();
        all_sinks.extend(self.sink_servers.keys().cloned());
        all_sinks.extend(self.cursors.keys().map(|(sink, _)| sink.clone()));
        all_sinks.extend(self.lagging.keys().cloned());
        all_sinks.extend(self.blocked_sinks.keys().cloned());
        all_sinks
            .iter()
            .map(|sink_name| SinkStatus {
                sink: sink_name.clone(),
                blocked: self.blocked_sinks.get(sink_name).cloned(),
                lagging_subjects: self
                    .lagging
                    .get(sink_name)
                    .map(|s| s.len())
                    .unwrap_or(0),
                active: self.active_sinks.contains(sink_name),
            })
            .collect()
    }

    fn try_insert_lagging(&mut self, sink: &str, subject_id: String) {
        self.lagging
            .entry(sink.to_string())
            .or_default()
            .insert(subject_id);
    }

    fn rebuild_lagging(&mut self) {
        self.lagging.clear();
        let active_sinks: Vec<String> = self.active_sinks.iter().cloned().collect();
        for sink_name in active_sinks {
            let mut outdated = Vec::new();
            let last_seen: Vec<(String, u64)> = self.last_seen.iter().map(|(k, &v)| (k.clone(), v)).collect();
            for (subject_id, last_sn) in last_seen {
                let cursor_sn = self
                    .cursors
                    .get(&(sink_name.clone(), subject_id.clone()))
                    .copied();
                // CR-4: If there is no cursor at all, the subject is outdated even
                // when last_sn == 0 (e.g. a Create event that failed before cursor
                // could be persisted).  Otherwise, outdated means cursor < last_sn.
                let is_outdated = match cursor_sn {
                    Some(sn) => sn < last_sn,
                    None => true,
                };
                if is_outdated {
                    outdated.push(subject_id);
                }
            }
            for subject_id in outdated {
                self.try_insert_lagging(&sink_name, subject_id);
            }
        }
    }

    async fn ensure_worker(
        &mut self,
        sink_name: &str,
        ctx: &mut ActorContext<Self>,
    ) -> Result<ActorRef<SinkWorker>, ActorError> {
        let child_name = format!("worker_{}", sink_name);
        match ctx.get_child::<SinkWorker>(&child_name).await {
            Ok(worker) => Ok(worker),
            Err(_) => {
                let server = self.sink_servers.get(sink_name)
                    .ok_or_else(|| ActorError::Functional {
                        description: format!("Sink server {} not found", sink_name),
                    })?;
                let worker = SinkWorker::new(
                    sink_name.to_owned(),
                    server.clone(),
                    self.is_governance,
                );
                ctx.create_child(&child_name, worker).await
            }
        }
    }

    /// F-5: Schedule worker shutdown after idle timeout.  Manager controls lifecycle.
    /// Cancels any pending shutdown for this worker before scheduling a new one,
    /// preventing race conditions where a worker is destroyed while processing events.
    fn schedule_worker_shutdown(&mut self, sink_name: String, ctx: &ActorContext<Self>) {
        // Cancel any existing shutdown timer for this worker
        if let Some(token) = self.pending_worker_shutdowns.remove(&sink_name) {
            token.cancel();
        }
        let child_name = format!("worker_{}", sink_name);
        let shutdown_after_ms = self.sink_servers.get(&sink_name)
            .map(|s| s.sink_worker_idle_timeout_ms)
            .unwrap_or_else(default_sink_worker_idle_timeout_ms);
        let system = ctx.system().clone();
        let token = CancellationToken::new();
        let token_for_task = token.clone();
        ctx.spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(shutdown_after_ms)) => {
                    // Only send Stop if the token was NOT cancelled.
                    if !token_for_task.is_cancelled()
                        && let Ok(worker) = system.get_actor::<SinkWorker>(&ActorPath::from(child_name)).await
                    {
                        let _ = worker.tell(SinkWorkerMessage::Stop).await;
                    }
                }
                _ = token_for_task.cancelled() => {
                    // Timer was cancelled — do nothing.
                }
            }
        });
        // Keep the token for explicit per-sink cancellation.  The actor will
        // abort all spawned tasks automatically on stop/restart.
        self.pending_worker_shutdowns.insert(sink_name, token);
    }

    /// Cancel pending worker shutdown timer for the given sink.
    fn cancel_worker_shutdown(&mut self, sink_name: &str) {
        if let Some(token) = self.pending_worker_shutdowns.remove(sink_name) {
            token.cancel();
        }
    }

    /// Schedule a periodic healthcheck for a sink that has lagging subjects.
    /// The manager creates a worker, sends HealthCheck, and reschedules using
    /// `healthcheck_intervals_secs`.  Cancelled when the sink recovers.
    fn schedule_healthcheck(&mut self, sink_name: String, ctx: &ActorContext<Self>) {
        if let Some(token) = self.pending_healthchecks.remove(&sink_name) {
            token.cancel();
        }
        let intervals = self.sink_servers.get(&sink_name)
            .map(|s| s.healthcheck_intervals_secs.clone())
            .unwrap_or_else(default_sink_healthcheck_intervals_secs);
        let system = ctx.system().clone();
        let token = CancellationToken::new();
        let token_for_task = token.clone();
        let sink_name_for_task = sink_name.clone();
        ctx.spawn(async move {
            let mut interval_idx = 0usize;
            let last_idx = intervals.len().saturating_sub(1);
            loop {
                let delay_secs = intervals.get(interval_idx.min(last_idx)).copied().unwrap_or(60);
                let delay_secs = crate::sink::add_jitter(delay_secs);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {
                        if token_for_task.is_cancelled() {
                            break;
                        }
                        let child_name = format!("worker_{}", sink_name_for_task);
                        if let Ok(worker) = system.get_actor::<SinkWorker>(&ActorPath::from(child_name)).await {
                            let _ = worker.tell(SinkWorkerMessage::HealthCheck).await;
                        }
                        interval_idx = (interval_idx + 1).min(last_idx);
                    }
                    _ = token_for_task.cancelled() => {
                        break;
                    }
                }
            }
        });
        self.pending_healthchecks.insert(sink_name, token);
    }

    /// Cancel pending healthcheck timer for the given sink.
    fn cancel_healthcheck(&mut self, sink_name: &str) {
        if let Some(token) = self.pending_healthchecks.remove(sink_name) {
            token.cancel();
        }
    }

    async fn handle_notify_new_event(
        &mut self,
        data: Arc<DataToSink>,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        let subject_id = data.payload.get_subject_schema().0;
        let sn = extract_sn(&data);

        // Update last_seen. The actual mutation happens in apply(); here we
        // only decide whether the event needs to be persisted.
        let prev_last = self.last_seen.get(&subject_id).copied().unwrap_or(0);
        if sn >= prev_last {
            self.persist(
                SinkManagerEvent::LastSeenUpdated {
                    subject_id: subject_id.clone(),
                    sn,
                },
                ctx,
            )
            .await?;
        }

        // Notify all workers (filtering is done by the worker).
        // Omit blocked sinks entirely — the operator must unblock them manually.
        let sink_names: Vec<String> = self.sink_servers.keys().cloned().collect();
        for sink_name in &sink_names {
            if self.blocked_sinks.contains_key(sink_name) {
                continue;
            }
            // F-2: If the subject is already lagging for this sink, do NOT send
            // NotifyNewEvent. Trigger catch-up for this specific subject so the
            // worker can drain pending events (including this one) in order.
            let is_lagging = self.lagging
                .get(sink_name)
                .map(|s| s.contains(&subject_id))
                .unwrap_or(false);
            if is_lagging {
                if let Err(e) = self
                    .handle_request_catch_up(sink_name.clone(), vec![subject_id.clone()], ctx)
                    .await
                {
                    error!(
                        msg_type = "NotifyCatchUp",
                        sink = %sink_name,
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to trigger catch-up for lagging subject"
                    );
                }
                continue;
            }

            // Sequential delivery check: the next event must be exactly cursor+1
            // (or 0 if no cursor exists). If there's a gap, the subject must
            // enter lagging so catch-up delivers missing events in order.
            let cursor_sn = self.cursors.get(&(sink_name.clone(), subject_id.clone())).copied();
            let expected_sn = match cursor_sn {
                Some(sn) => sn + 1,
                None => 0,
            };
            if sn != expected_sn {
                warn!(
                    msg_type = "SequentialGap",
                    sink = %sink_name,
                    subject_id = %subject_id,
                    sn = %sn,
                    expected = %expected_sn,
                    cursor = ?cursor_sn,
                    "Gap detected; subject entering lagging for ordered catch-up"
                );
                self.try_insert_lagging(sink_name, subject_id.clone());
                if let Err(e) = self
                    .handle_request_catch_up(sink_name.clone(), vec![subject_id.clone()], ctx)
                    .await
                {
                    error!(
                        msg_type = "GapCatchUp",
                        sink = %sink_name,
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to trigger catch-up after sequential gap"
                    );
                }
                continue;
            }

            match self.ensure_worker(sink_name, ctx).await {
                Ok(worker_ref) => {
                    // Cancel pending shutdown before sending event to prevent race
                    // where worker dies while processing.
                    self.cancel_worker_shutdown(sink_name);
                    if let Err(e) = worker_ref
                        .tell(SinkWorkerMessage::NotifyNewEvent(Arc::clone(&data)))
                        .await
                    {
                        error!(msg_type = "NotifyWorker", sink = %sink_name, error = %e, "Failed to notify worker");
                        self.lagging
                            .entry(sink_name.clone())
                            .or_default()
                            .insert(subject_id.clone());
                    }
                }
                Err(e) => {
                    error!(msg_type = "EnsureWorker", sink = %sink_name, error = %e, "Failed to ensure worker");
                    self.lagging
                        .entry(sink_name.clone())
                        .or_default()
                        .insert(subject_id.clone());
                }
            }
        }

        Ok(())
    }

    async fn handle_update_progress(
        &mut self,
        sink: String,
        subject_id: String,
        sn: u64,
        result: SendResult,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        match result {
            SendResult::Success => {
                self.persist(
                    SinkManagerEvent::CursorUpdated {
                        sink: sink.clone(),
                        subject_id: subject_id.clone(),
                        sn,
                    },
                    ctx,
                )
                .await?;

                // Only remove the subject from lagging once the cursor has
                // caught up with the last seen event. This prevents out-of-order
                // or duplicate delivery if new events arrive while a catch-up is
                // still in progress.
                let last_sn = self.last_seen.get(&subject_id).copied().unwrap_or(0);
                if sn >= last_sn
                    && let Some(set) = self.lagging.get_mut(&sink)
                {
                    set.remove(&subject_id);
                    if set.is_empty() {
                        self.lagging.remove(&sink);
                    }
                }
            }
            SendResult::SubjectNotFound => {
                // MED-2: Subject was deleted — clean up tracking state.
                // EOL does NOT trigger this; EOL events are delivered normally.
                info!(msg_type = "SubjectNotFound", sink = %sink, subject_id = %subject_id, "Removing deleted subject from lagging/cursors");
                if let Some(set) = self.lagging.get_mut(&sink) {
                    set.remove(&subject_id);
                    if set.is_empty() {
                        self.lagging.remove(&sink);
                    }
                }
                // Persistent state is only mutated in apply().
                self.persist(
                    SinkManagerEvent::CursorRemoved {
                        sink: sink.clone(),
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await?;
                self.persist(
                    SinkManagerEvent::LastSeenRemoved {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await?;
            }
        }
        Ok(())
    }

    async fn handle_catch_up_completed(
        &mut self,
        sink: String,
        subject_id: String,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        let cursor_sn = self
            .cursors
            .get(&(sink.clone(), subject_id.clone()))
            .copied();
        let last_sn = self.last_seen.get(&subject_id).copied().unwrap_or(0);

        if cursor_sn.is_some_and(|cursor| cursor >= last_sn) {
            if let Some(set) = self.lagging.get_mut(&sink) {
                set.remove(&subject_id);
                if set.is_empty() {
                    self.lagging.remove(&sink);
                }
            }
        } else if !self.blocked_sinks.contains_key(&sink) {
            // last_seen moved forward while catch-up was running; keep going.
            info!(
                msg_type = "CatchUpContinue",
                sink = %sink,
                subject_id = %subject_id,
                cursor = ?cursor_sn,
                last_sn = %last_sn,
                "Continuing catch-up because new events arrived while catch-up was in progress"
            );
            if let Err(e) = self
                .handle_request_catch_up(sink.clone(), vec![subject_id.clone()], ctx)
                .await
            {
                error!(
                    msg_type = "CatchUpCompletedRetry",
                    sink = %sink,
                    subject_id = %subject_id,
                    error = %e,
                    "Failed to continue catch-up after completion"
                );
            }
        }
        Ok(())
    }

    async fn handle_request_catch_up(
        &mut self,
        sink: String,
        subjects: Vec<String>,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        if self.blocked_sinks.contains_key(&sink) {
            return Ok(());
        }
        let worker_ref = match self.ensure_worker(&sink, ctx).await {
            Ok(worker) => worker,
            Err(e) => {
                error!(msg_type = "EnsureWorker", sink = %sink, error = %e, "Failed to ensure worker for catch-up");
                return Err(ActorError::Functional {
                    description: format!("No worker available for sink {}", sink),
                });
            }
        };

        // Cancel pending shutdown before sending catch-up to prevent race
        // where worker dies while processing.
        self.cancel_worker_shutdown(&sink);

        for subject_id in subjects {
            let from_sn = match self
                .cursors
                .get(&(sink.clone(), subject_id.clone()))
                .copied()
            {
                Some(sn) => sn + 1,
                None => 0,
            };

            if let Err(e) = worker_ref
                .tell(SinkWorkerMessage::CatchUp {
                    subject_id,
                    from_sn,
                })
                .await
            {
                error!(msg_type = "CatchUp", sink = %sink, error = %e, "Failed to send catch-up request to worker");
            }
        }
        Ok(())
    }

    async fn handle_sink_recovered(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        if self.blocked_sinks.contains_key(&sink) {
            return Ok(());
        }
        info!(msg_type = "SinkRecovered", sink = %sink, "Sink recovered, triggering catch-up");
        self.active_sinks.insert(sink.clone());

        // Cancel periodic healthcheck — the sink is healthy again.
        self.cancel_healthcheck(&sink);

        // Rebuild lagging before launching catch-up to detect any subjects
        // that may have fallen behind without being explicitly tracked.
        self.rebuild_lagging();

        if let Some(subjects) = self.lagging.get(&sink).cloned() {
            self.handle_request_catch_up(sink.clone(), subjects.into_iter().collect(), ctx)
                .await?;
        }

        self.persist(SinkManagerEvent::SinkRecovered { sink }, ctx)
            .await?;
        Ok(())
    }

    async fn handle_unblock_sink(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        if self.blocked_sinks.contains_key(&sink) {
            info!(msg_type = "SinkUnblocked", sink = %sink, "Sink manually unblocked by operator");
            self.persist(SinkManagerEvent::SinkUnblocked { sink: sink.clone() }, ctx).await?;
            // Reset flapping counter in the worker so that the first healthcheck
            // after unblock can trigger SinkRecovered and catch-up.
            if let Ok(worker) = self.ensure_worker(&sink, ctx).await {
                // Cancel pending shutdown before sending messages to prevent race
                self.cancel_worker_shutdown(&sink);
                let _ = worker
                    .tell(crate::sink::worker::SinkWorkerMessage::ResetRecoveries)
                    .await;
                let _ = worker
                    .tell(crate::sink::worker::SinkWorkerMessage::ClearBlocked)
                    .await;
            }
            // Rebuild lagging for this sink and trigger catch-up to catch up on missed events.
            let subjects_to_add: Vec<String> = self.last_seen.iter().filter_map(|(subject_id, &last_sn)| {
                let cursor_sn = self
                    .cursors
                    .get(&(sink.clone(), subject_id.clone()))
                    .copied();
                let is_outdated = match cursor_sn {
                    Some(sn) => sn < last_sn,
                    None => true,
                };
                if is_outdated {
                    Some(subject_id.clone())
                } else {
                    None
                }
            }).collect();
            for subject_id in subjects_to_add {
                self.try_insert_lagging(&sink, subject_id);
            }
            if let Some(subjects) = self.lagging.get(&sink).cloned() {
                let subjects: Vec<String> = subjects.into_iter().collect();
                if !subjects.is_empty() {
                    self.handle_request_catch_up(sink, subjects, ctx).await?;
                }
            }
        }
        Ok(())
    }

    async fn handle_delete_sink_cursors(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        // Double-check Safe Mode at the actor level: this operation is only valid
        // while the node is running in safe mode. In safe mode there are no
        // workers running, so we only need to clean persisted/transient state.
        let safe_mode = if let Some(config) = ctx
            .system()
            .get_helper::<ConfigHelper>("config")
            .await
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if !safe_mode {
            return Err(ActorError::Functional {
                description: "DeleteSinkCursors is only available in safe mode".to_owned(),
            });
        }

        info!(
            msg_type = "DeleteSinkCursors",
            sink = %sink,
            "Deleting all sink cursors in Safe Mode"
        );

        let had_cursors = self.cursors.keys().any(|(s, _)| s == &sink);

        // The event is the source of truth: apply() will remove cursors,
        // lagging and blocked state for this sink. We must NOT mutate those
        // fields here.
        self.persist(
            SinkManagerEvent::SinkCursorsDeleted { sink: sink.clone() },
            ctx,
        )
        .await?;

        info!(
            msg_type = "SinkCursorsDeleted",
            sink = %sink,
            had_cursors = %had_cursors,
            "Sink cursors deleted in Safe Mode"
        );

        Ok(())
    }

    async fn handle_remove_subject(
        &mut self,
        subject_id: &str,
        ctx: &mut ActorContext<SinkManager>,
    ) -> Result<(), ActorError> {
        info!(msg_type = "RemoveSubject", subject_id = %subject_id, "Removing subject from all sinks");

        // Collect all sinks that have this subject in cursors or lagging.
        let mut affected_sinks: HashSet<String> = HashSet::new();

        // Remove from lagging.
        let sinks_with_subject: Vec<String> = self.lagging
            .iter()
            .filter(|(_, subjects)| subjects.contains(subject_id))
            .map(|(sink, _)| sink.clone())
            .collect();
        for sink in sinks_with_subject {
            affected_sinks.insert(sink.clone());
            if let Some(set) = self.lagging.get_mut(&sink) {
                set.remove(subject_id);
                if set.is_empty() {
                    self.lagging.remove(&sink);
                }
            }
        }

        // Remove cursors. The actual deletion happens in apply().
        let sinks_with_cursor: Vec<String> = self.cursors
            .keys()
            .filter(|(_, sid)| sid == subject_id)
            .map(|(sink, _)| sink.clone())
            .collect();
        for sink in sinks_with_cursor {
            affected_sinks.insert(sink.clone());
            self.persist(
                SinkManagerEvent::CursorRemoved {
                    sink,
                    subject_id: subject_id.to_string(),
                },
                ctx,
            )
            .await?;
        }

        // Remove last_seen. The actual deletion happens in apply().
        if self.last_seen.contains_key(subject_id) {
            self.persist(
                SinkManagerEvent::LastSeenRemoved {
                    subject_id: subject_id.to_string(),
                },
                ctx,
            )
            .await?;
        }

        Ok(())
    }
}
