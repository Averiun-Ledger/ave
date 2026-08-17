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
use tracing::{debug, error, info, info_span, warn};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Event, Handler,
    LightPersistence, Message, PersistentActor, Response,
};
use ave_common::{
    DataToSink,
    bridge::request::SinkReplayItem,
    bridge::response::{SinkReplayError, SinkReplayResponse},
};

use ave_common::sink::{
    SinkServer, SinkTransportConfig, default_sink_healthcheck_intervals_secs,
    default_sink_worker_idle_timeout_ms,
};

use crate::db::Storable;
use crate::metrics::try_core_metrics;
use crate::node::Node;
use crate::sink::NodeSigner;
use crate::sink::extract_sn;
use crate::sink::transport::build_transport;
use crate::sink::worker::{SinkWorker, SinkWorkerMessage};
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
    /// Public key of the node hosting this manager. Used by the Kafka
    /// transport to derive a per-node default `transactional.id`.
    pub node_public_key: String,
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
        count: u64,
    },
    SinkRecovered {
        sink: String,
    },
    UnblockSink {
        sink: String,
    },
    /// Safe Mode only: reset all persisted cursors and transient state for a sink.
    ResetSinkCursors {
        sink: String,
    },
    GetStatus,
    GetDetailedStatus,
    /// Worker reports it has been idle for sink_worker_idle_timeout_ms.
    WorkerIdle {
        sink: String,
    },
    /// Death-watch notification: a sink worker has stopped.  Any event
    /// notified to the worker but not yet delivered is lost silently
    /// (non-critical messages are discarded during graceful shutdown), so
    /// the manager re-evaluates cursors against last_seen for the sink.
    WorkerStopped {
        sink: String,
    },
    /// Idle-timeout shutdown of a sink worker. Processed inside the manager's
    /// mailbox so the handler can wait for the worker to confirm shutdown
    /// (`ask_stop`): a subsequent event then recreates the worker instead of
    /// racing the old one's termination and losing the event.
    WorkerShutdownTimeout {
        sink: String,
        generation: u64,
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
    /// Worker reports that a catch-up request could not be started (e.g. the
    /// sink is unhealthy or blocked). The manager must clear the in-flight flag
    /// so recovery can retry later.
    CatchUpRejected {
        sink: String,
        subject_id: String,
    },
    /// Manual replay: resend events from `from_sn` up to the last seen event
    /// for the given subject/sink pairs. Only available outside safe mode.
    ReplayEvents {
        requests: Vec<SinkReplayItem>,
    },
    /// Non-persistent end-to-end test of a sink: health check + test payload
    /// delivery without advancing cursors.
    TestSink {
        sink: String,
    },
    /// Node has finished starting all its children. Governance sinks can now
    /// start workers and catch-up because governance actors are guaranteed to
    /// be available.
    StartupReady,
    /// Periodic healthcheck tick for a sink with lagging subjects. Routed
    /// through the manager's mailbox so the worker reference is resolved (or
    /// the worker recreated) at fire time — a captured `ActorRef` would keep
    /// firing at a dead worker forever.
    HealthcheckTick {
        sink: String,
    },
}

impl Message for SinkManagerMessage {}

/// Failure of a non-persistent sink test ([`SinkManagerMessage::TestSink`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkTestError {
    /// The sink is registered but has no server configuration (e.g. a
    /// residual sink whose config entry was removed).
    NotConfigured,
    /// Node-side failure while preparing the test (signer, transport
    /// construction).
    Internal(String),
    /// The test delivery itself failed (health check or payload).
    Delivery(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkManagerResponse {
    Ok,
    Status(Vec<SinkStatus>),
    DetailedStatus(SinkManagerDetailedStatus),
    ReplayResult(SinkReplayResponse),
    TestResult(Result<(), SinkTestError>),
}

impl Response for SinkManagerResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SinkStatus {
    pub sink: String,
    pub blocked: Option<String>,
    pub lagging_subjects: usize,
    pub active: bool,
    pub last_error: Option<String>,
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
    /// The per-subject worker died unexpectedly and was recreated. The manager
    /// must reset its notification cursor so events lost in the dead worker
    /// are recovered by catch-up instead of skipped by the sequential gate.
    SubjectWorkerRestarted { sink: String, subject_id: String },
}

// ---------------------------------------------------------------------------
// Event
// ---------------------------------------------------------------------------

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
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
    /// A replay was accepted and its re-delivery is still pending. Persisted
    /// so a node restart cannot silently drop it.
    ReplayRegistered {
        sink: String,
        subject_id: String,
        from_sn: u64,
    },
    /// A catch-up starting at or below the floor of a registered replay has
    /// completed, so the replay is fully re-delivered.
    ReplayCompleted {
        sink: String,
        subject_id: String,
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
    /// Accepted replays whose re-delivery is still pending, mapped to the
    /// minimum `from_sn` to redeliver. Persisted (via Borsh) so a node
    /// restart cannot silently drop an accepted replay: on startup each floor
    /// triggers a catch-up from that SN. Cleared when a catch-up starting at
    /// or below the floor completes.
    #[serde(skip)]
    replay_floors: BTreeMap<(String, String), u64>, // (sink, subject_id) -> min from_sn
    /// `true` when this manager handles governance events (under Node),
    /// `false` when it handles tracker events (under Governance).
    #[serde(skip)]
    is_governance: bool,
    /// Public key of the node hosting this manager, from the init params.
    #[serde(skip)]
    node_public_key: String,
    /// F-5: Cancellation tokens for pending worker shutdown timers.  Each token
    /// is shared between the manager and the spawned timer task; cancelling the
    /// token aborts the timer *before* it sends `Stop`, eliminating the race
    /// between `abort()` and a task that has already woken up. The generation
    /// stamps each schedule so a stale timeout message (already in the mailbox
    /// when the timer was cancelled and re-armed) is discarded instead of
    /// killing a worker with fresh activity.
    #[serde(skip)]
    pending_worker_shutdowns: HashMap<String, (CancellationToken, u64)>,
    /// Monotonic counter stamping every worker shutdown schedule.
    #[serde(skip)]
    next_worker_shutdown_generation: u64,
    /// Cancellation tokens for pending healthcheck timers.  When a sink has
    /// lagging subjects but no active worker, the manager schedules periodic
    /// healthchecks using `healthcheck_intervals_secs` to detect recovery.
    #[serde(skip)]
    pending_healthchecks: HashMap<String, CancellationToken>,
    /// Subjects for which a catch-up has been requested but not yet completed,
    /// mapped to the `from_sn` the in-flight catch-up started from. Prevents
    /// duplicate catch-up triggers from sending the same event twice while the
    /// first catch-up is still in flight, and lets requests that rewind below
    /// that start (e.g. a replay) restart the in-flight catch-up so the whole
    /// range is re-delivered in order.
    #[serde(skip)]
    catch_up_in_flight: HashMap<(String, String), u64>, // (sink, subject_id) -> in-flight from_sn
    /// Re-delivery catch-ups (e.g. replays) that were rejected by the worker
    /// while the sink was unhealthy/blocked, mapped to the minimum `from_sn`
    /// to redeliver. The normal lagging path cannot retry them because the
    /// cursor is already ahead. Drained when a catch-up completes or the sink
    /// recovers / is unblocked.
    #[serde(skip)]
    pending_catch_ups: HashMap<(String, String), u64>, // (sink, subject_id) -> min from_sn
    /// Highest SN already forwarded to a sink/subject worker. Used for the
    /// sequential gate instead of the delivery cursor so that live batching
    /// can accumulate events while earlier events are still buffered. Not
    /// persisted: it is rebuilt from forwarded events and reset to the cursor
    /// on worker restart/recovery.
    #[serde(skip)]
    last_notified: HashMap<(String, String), u64>, // (sink, subject_id) -> sn
    /// Last error reported by a sink worker for this sink. Kept in memory only:
    /// it is cleared when the sink recovers, is unblocked, or has no lagging
    /// subjects left.
    #[serde(skip)]
    last_errors: HashMap<String, String>, // sink_name -> last error message
}

impl std::fmt::Debug for SinkManager {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkManager")
            .field("cursors", &self.cursors)
            .field("last_seen", &self.last_seen)
            .field("active_sinks", &self.active_sinks)
            .field("version", &self.version)
            .field(
                "sink_servers",
                &self.sink_servers.keys().collect::<Vec<_>>(),
            )
            .field("lagging", &self.lagging)
            .field(
                "blocked_sinks",
                &self.blocked_sinks.keys().collect::<Vec<_>>(),
            )
            .field("last_errors", &self.last_errors.keys().collect::<Vec<_>>())
            .finish()
    }
}

impl BorshSerialize for SinkManager {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.cursors, writer)?;
        BorshSerialize::serialize(&self.last_seen, writer)?;
        BorshSerialize::serialize(&self.active_sinks, writer)?;
        BorshSerialize::serialize(&self.version, writer)?;
        BorshSerialize::serialize(&self.blocked_sinks, writer)?;
        BorshSerialize::serialize(&self.replay_floors, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for SinkManager {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        let cursors =
            BTreeMap::<(String, String), u64>::deserialize_reader(reader)?;
        let last_seen = BTreeMap::<String, u64>::deserialize_reader(reader)?;
        let active_sinks = BTreeSet::<String>::deserialize_reader(reader)?;
        let version = u64::deserialize_reader(reader)?;
        // Backward compatibility: old snapshots may not include blocked_sinks.
        let blocked_sinks = match BTreeMap::<String, String>::deserialize_reader(
            reader,
        ) {
            Ok(v) => v,
            Err(e) => {
                warn!(msg_type = "BorshCompat", field = "blocked_sinks", error = %e, "Using default for missing field");
                BTreeMap::new()
            }
        };
        // Backward compatibility: old snapshots may not include replay_floors.
        let replay_floors =
            match BTreeMap::<(String, String), u64>::deserialize_reader(reader)
            {
                Ok(v) => v,
                Err(e) => {
                    warn!(msg_type = "BorshCompat", field = "replay_floors", error = %e, "Using default for missing field");
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
            replay_floors,
            is_governance: false, // default from BorshDeserialize, will be overridden by create_initial
            node_public_key: String::new(), // same: re-derived from init params
            pending_worker_shutdowns: HashMap::new(),
            next_worker_shutdown_generation: 0,
            pending_healthchecks: HashMap::new(),
            catch_up_in_flight: HashMap::new(),
            pending_catch_ups: HashMap::new(),
            last_notified: HashMap::new(),
            last_errors: HashMap::new(),
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
            replay_floors: BTreeMap::new(),
            is_governance: params.is_governance,
            node_public_key: params.node_public_key,
            pending_worker_shutdowns: HashMap::new(),
            next_worker_shutdown_generation: 0,
            pending_healthchecks: HashMap::new(),
            catch_up_in_flight: HashMap::new(),
            pending_catch_ups: HashMap::new(),
            last_notified: HashMap::new(),
            last_errors: HashMap::new(),
        }
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            SinkManagerEvent::CursorUpdated {
                sink,
                subject_id,
                sn,
            } => {
                inner
                    .cursors
                    .insert((sink.clone(), subject_id.clone()), *sn);
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
                inner.last_errors.remove(sink);
                inner.replay_floors.retain(|(s, _), _| s != sink);
            }
            SinkManagerEvent::ReplayRegistered {
                sink,
                subject_id,
                from_sn,
            } => {
                inner
                    .replay_floors
                    .entry((sink.clone(), subject_id.clone()))
                    .and_modify(|floor| *floor = (*floor).min(*from_sn))
                    .or_insert(*from_sn);
            }
            SinkManagerEvent::ReplayCompleted { sink, subject_id } => {
                inner
                    .replay_floors
                    .remove(&(sink.clone(), subject_id.clone()));
            }
        }

        if let Some(metrics) = try_core_metrics() {
            match event {
                SinkManagerEvent::SinkBlocked { sink, .. } => {
                    metrics.set_sink_blocked(sink, true);
                }
                SinkManagerEvent::SinkUnblocked { sink }
                | SinkManagerEvent::SinkCursorsDeleted { sink } => {
                    metrics.set_sink_blocked(sink, false);
                    if matches!(
                        event,
                        SinkManagerEvent::SinkCursorsDeleted { .. }
                    ) {
                        metrics.set_sink_lagging_subjects(sink, 0);
                        metrics.set_sink_lagging_events(sink, 0);
                        metrics.set_sink_lag_max_distance(sink, 0);
                    }
                }
                _ => {}
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
            replay_floors: self.replay_floors.clone(),
            is_governance: self.is_governance,
            node_public_key: self.node_public_key.clone(),
            pending_worker_shutdowns: HashMap::new(),
            next_worker_shutdown_generation: 0,
            pending_healthchecks: HashMap::new(),
            catch_up_in_flight: self.catch_up_in_flight.clone(),
            pending_catch_ups: self.pending_catch_ups.clone(),
            last_notified: self.last_notified.clone(),
            last_errors: self.last_errors.clone(),
        })
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        let state = &*state;
        self.cursors.clone_from(&state.cursors);
        self.last_seen.clone_from(&state.last_seen);
        self.active_sinks.clone_from(&state.active_sinks);
        self.version = state.version;
        self.blocked_sinks.clone_from(&state.blocked_sinks);
        self.replay_floors.clone_from(&state.replay_floors);
        // `apply` also mutates these two (e.g. `SinkCursorsDeleted` clears
        // them); skipping them here would silently drop the mutation.
        self.lagging.clone_from(&state.lagging);
        self.last_errors.clone_from(&state.last_errors);
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

    fn get_span(
        _id: &str,
        parent_span: Option<tracing::Span>,
    ) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("sink_manager"),
            |parent_span| info_span!(parent: parent_span, "sink_manager"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let params =
            self.store_params
                .take()
                .ok_or_else(|| ActorError::Functional {
                    description: "SinkManager missing init params".to_owned(),
                })?;

        // `is_governance` is set by `create_initial` and survives recovery
        // because `set_state` does not overwrite transient fields. Re-derive it
        // from the init params here so the decision below is robust even if the
        // recovery path changes in the future.
        self.is_governance = params.is_governance;
        self.node_public_key = params.node_public_key.clone();

        // Validate sink server name uniqueness.
        let mut seen = HashSet::new();
        for sink in &params.sinks {
            if !seen.insert(sink.server.clone()) {
                return Err(ActorError::Functional {
                    description: format!(
                        "Duplicate sink server name: {}",
                        sink.server
                    ),
                });
            }
        }

        // Init store. Parent key is derived from the actor path so that
        // NodeSinkManager and each Governance SinkManager have separate stores.
        if let Err(e) = self
            .init_store(
                "sink",
                Some(ctx.path().parent().key().to_owned()),
                false,
                ctx,
            )
            .await
        {
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
        let safe_mode = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config")
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        // Tracker sink managers live under a Governance actor, which is only
        // created after the governance itself is up, so they can start workers
        // and catch-up immediately. The node-level governance sink manager is
        // created before the SubjectManager has bootstrapped governances, so it
        // must wait for Node::StartupReady.
        if !safe_mode && !self.is_governance {
            self.start_workers_and_catch_up(ctx).await;
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
impl Handler<Self> for SinkManager {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkManagerMessage,
        ctx: &mut ActorContext<Self>,
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
                count,
            } => {
                self.handle_update_progress(
                    sink, subject_id, sn, result, count, ctx,
                )
                .await?;
            }
            SinkManagerMessage::SinkRecovered { sink } => {
                self.handle_sink_recovered(sink, ctx).await?;
            }
            SinkManagerMessage::UnblockSink { sink } => {
                self.handle_unblock_sink(sink, ctx).await?;
            }
            SinkManagerMessage::ResetSinkCursors { sink } => {
                self.handle_reset_sink_cursors(sink, ctx).await?;
            }
            SinkManagerMessage::GetStatus => {
                return Ok(SinkManagerResponse::Status(
                    self.build_sink_statuses(),
                ));
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
                // The worker is idle and will be stopped. Any catch-up it may
                // have had in flight is no longer running, so clear the flag
                // so recovery can retry with a fresh worker.
                self.catch_up_in_flight.retain(|(s, _), _| s != &sink);
                self.schedule_worker_shutdown(sink, ctx).await;
            }
            SinkManagerMessage::WorkerStopped { sink } => {
                self.handle_worker_stopped(sink, ctx).await?;
            }
            SinkManagerMessage::RemoveSubject { subject_id } => {
                self.handle_remove_subject(&subject_id, ctx).await?;
            }
            SinkManagerMessage::CatchUpCompleted { sink, subject_id } => {
                self.handle_catch_up_completed(sink, subject_id, ctx)
                    .await?;
            }
            SinkManagerMessage::CatchUpRejected { sink, subject_id } => {
                let rejected_from = self
                    .catch_up_in_flight
                    .remove(&(sink.clone(), subject_id.clone()));
                // If the rejected catch-up was a re-delivery starting at or
                // below the cursor (e.g. a replay), lagging will never retry
                // it because the cursor is already ahead: queue it back so it
                // is drained once the sink recovers. Ranges above the cursor
                // are retried through the normal lagging path.
                if let Some(from_sn) = rejected_from {
                    let cursor_sn = self
                        .cursors
                        .get(&(sink.clone(), subject_id.clone()))
                        .copied();
                    if cursor_sn.is_some_and(|cursor| from_sn <= cursor) {
                        self.pending_catch_ups
                            .entry((sink.clone(), subject_id.clone()))
                            .and_modify(|pending| {
                                *pending = (*pending).min(from_sn)
                            })
                            .or_insert(from_sn);
                    }
                }
                // Ensure the subject is marked as lagging so recovery will retry
                // the catch-up once the sink becomes available again.
                self.try_insert_lagging(&sink, subject_id);
            }
            SinkManagerMessage::ReplayEvents { requests } => {
                let response = self.handle_replay_events(requests, ctx).await?;
                return Ok(SinkManagerResponse::ReplayResult(response));
            }
            SinkManagerMessage::TestSink { sink } => {
                let result = self.handle_test_sink(&sink, ctx).await;
                return Ok(SinkManagerResponse::TestResult(result));
            }
            SinkManagerMessage::StartupReady => {
                self.handle_startup_ready(ctx).await?;
            }
            SinkManagerMessage::WorkerShutdownTimeout { sink, generation } => {
                // Discard a stale timeout: it was emitted before the timer
                // was cancelled and re-armed by newer activity, so stopping
                // the worker now could destroy in-flight work.
                match self.pending_worker_shutdowns.get(&sink) {
                    Some((_, current)) if *current == generation => {
                        self.pending_worker_shutdowns.remove(&sink);
                    }
                    _ => {
                        return Ok(SinkManagerResponse::Ok);
                    }
                }
                let child_name = format!("worker_{}", sink);
                if let Ok(worker) =
                    ctx.get_child::<SinkWorker>(&child_name).await
                {
                    debug!(
                        msg_type = "SinkWorkerShutdown",
                        sink = %sink,
                        reason = "idle timeout",
                        "Sink worker shutting down after idle timeout"
                    );
                    // Wait for the worker to confirm shutdown: only then is
                    // its actor path free, so a subsequent event recreates it
                    // instead of racing the old worker's termination and
                    // losing the event. The worker is idle by definition (the
                    // shutdown timer fired), so this returns quickly. The
                    // death-watch (WorkerStopped) recovers anything pending.
                    if let Err(e) = worker.ask_stop().await {
                        error!(
                            msg_type = "SinkWorkerShutdown",
                            sink = %sink,
                            error = %e,
                            "Failed to confirm sink worker shutdown"
                        );
                    }
                }
            }
            SinkManagerMessage::HealthcheckTick { sink } => {
                // Skip when the sink left the config, is blocked, or has
                // nothing lagging (recovery/block cancel the timer anyway;
                // these guards cover the stale-tick race).
                if !self.sink_servers.contains_key(&sink)
                    || self.blocked_sinks.contains_key(&sink)
                {
                    return Ok(SinkManagerResponse::Ok);
                }
                if !self.lagging.get(&sink).is_some_and(|s| !s.is_empty()) {
                    return Ok(SinkManagerResponse::Ok);
                }
                // Resolve the worker at fire time, recreating it if it was
                // idle-killed: a lagging sink must keep being monitored or
                // its recovery is never detected.
                match self.ensure_worker(&sink, ctx).await {
                    Ok(worker) => {
                        self.cancel_worker_shutdown(&sink);
                        if let Err(e) =
                            worker.tell(SinkWorkerMessage::HealthCheck).await
                        {
                            error!(msg_type = "HealthcheckTick", sink = %sink, error = %e, "Failed to forward healthcheck to worker");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "HealthcheckTick", sink = %sink, error = %e, "Failed to ensure worker for healthcheck");
                    }
                }
            }
        }
        Ok(SinkManagerResponse::Ok)
    }

    async fn on_child_error(
        &mut self,
        error: SinkWorkerError,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Some(metrics) = try_core_metrics() {
            match &error {
                SinkWorkerError::DeliveryFailed { sink, .. } => {
                    metrics.observe_sink_event(sink, "delivery_failed");
                }
                SinkWorkerError::AuthFailed { sink, .. } => {
                    metrics.observe_sink_event(sink, "auth_failed");
                }
                SinkWorkerError::Blocked { sink, .. } => {
                    metrics.observe_sink_event(sink, "blocked");
                }
                SinkWorkerError::SubjectNotFound { sink, .. } => {
                    metrics.observe_sink_event(sink, "subject_not_found");
                }
                SinkWorkerError::SubjectWorkerRestarted { .. } => {
                    // No metric: this is a lifecycle signal, not a delivery
                    // outcome.
                }
            }
        }

        match error {
            SinkWorkerError::SubjectWorkerRestarted { sink, subject_id } => {
                info!(
                    msg_type = "SubjectWorkerRestarted",
                    sink = %sink,
                    subject_id = %subject_id,
                    "Subject worker recreated; resetting notification state"
                );
                // Any catch-up that was in flight in the dead worker is lost;
                // clear the flag so a fresh catch-up can be scheduled.
                self.catch_up_in_flight
                    .remove(&(sink.clone(), subject_id.clone()));
                self.reset_last_notified_for_subject(&sink, &subject_id);

                // If the cursor is behind last_seen, events were lost or the
                // subject was lagging; ensure catch-up recovers them in order.
                // CR-4: no cursor at all means outdated even when last_sn == 0
                // (e.g. a Create that failed before the cursor was persisted).
                let cursor_sn = self
                    .cursors
                    .get(&(sink.clone(), subject_id.clone()))
                    .copied();
                let last_sn =
                    self.last_seen.get(&subject_id).copied().unwrap_or(0);
                let is_outdated = cursor_sn.is_none_or(|sn| sn < last_sn);
                if is_outdated {
                    self.try_insert_lagging(&sink, subject_id.clone());
                    if let Err(e) = self
                        .handle_request_catch_up(
                            sink.clone(),
                            vec![subject_id.clone()],
                            ctx,
                        )
                        .await
                    {
                        error!(
                            msg_type = "RestartCatchUp",
                            sink = %sink,
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to trigger catch-up after subject worker restart"
                        );
                    }
                }
            }
            SinkWorkerError::DeliveryFailed {
                sink,
                subject_id,
                sn,
                reason,
            } => {
                error!(msg_type = "DeliveryFailed", sink = %sink, subject_id = %subject_id, sn = %sn, reason = %reason, "Sink delivery failed");
                self.last_errors.insert(sink.clone(), reason.clone());
                self.catch_up_in_flight
                    .remove(&(sink.clone(), subject_id.clone()));
                self.try_insert_lagging(&sink, subject_id.clone());
                // If the sink has lagging subjects, schedule periodic healthchecks
                // to detect when the sink recovers.  The worker will be idle and
                // destroyed soon; the healthcheck timer recreates it periodically.
                if self
                    .lagging
                    .get(&sink)
                    .map(|s| !s.is_empty())
                    .unwrap_or(false)
                {
                    self.schedule_healthcheck(sink, ctx).await;
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
                self.last_errors.insert(sink.clone(), error.clone());
                self.catch_up_in_flight
                    .remove(&(sink.clone(), subject_id.clone()));
                self.try_insert_lagging(&sink, subject_id.clone());
                if let Some(subjects) = self.lagging.get(&sink).cloned() {
                    let subjects: Vec<String> = subjects.into_iter().collect();
                    if !subjects.is_empty() {
                        let sink_for_log = sink.clone();
                        if let Err(e) = self
                            .handle_request_catch_up(sink, subjects, ctx)
                            .await
                        {
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
                self.catch_up_in_flight.retain(|(s, _), _| s != &sink);
                // Cancel any periodic healthcheck: the sink is now blocked and
                // will not recover until the operator unblocks it.
                self.cancel_healthcheck(&sink);
                // Keep the subject lagging so it is retried when the operator
                // unblocks the sink. Sink-wide blocks (e.g. flapping) carry an
                // empty subject_id: there is no real subject to recover, and
                // inserting `""` would make `handle_unblock_sink` request a
                // phantom catch-up for a subject that does not exist.
                if !subject_id.is_empty() {
                    self.try_insert_lagging(&sink, subject_id);
                }
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
                self.catch_up_in_flight
                    .remove(&(sink.clone(), subject_id.clone()));
                if let Err(e) = self
                    .handle_update_progress(
                        sink,
                        subject_id,
                        sn,
                        SendResult::SubjectNotFound,
                        1,
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
                last_error: self.last_errors.get(sink_name).cloned(),
            })
            .collect()
    }

    /// Compute the SN distance between `last_seen` and the sink cursor for a
    /// subject. A missing cursor means the subject is one event behind even if
    /// `last_seen == 0`, matching the outdated logic in `rebuild_lagging`.
    fn sink_lag_distance(&self, sink: &str, subject_id: &str) -> u64 {
        let last_sn = self.last_seen.get(subject_id).copied().unwrap_or(0);
        match self
            .cursors
            .get(&(sink.to_owned(), subject_id.to_owned()))
            .copied()
        {
            Some(cursor) if cursor >= last_sn => 0,
            Some(cursor) => last_sn - cursor,
            None => last_sn + 1,
        }
    }

    fn sink_lagging_totals(&self, sink: &str) -> (usize, u64, u64) {
        let Some(subjects) = self.lagging.get(sink) else {
            return (0, 0, 0);
        };
        let count = subjects.len();
        if count == 0 {
            return (0, 0, 0);
        }
        let mut total = 0u64;
        let mut max = 0u64;
        for subject_id in subjects {
            let distance = self.sink_lag_distance(sink, subject_id);
            total = total.saturating_add(distance);
            max = max.max(distance);
        }
        (count, total, max)
    }

    fn update_sink_lag_metrics(&self, sink: &str) {
        let Some(metrics) = try_core_metrics() else {
            return;
        };
        let (count, total, max) = self.sink_lagging_totals(sink);
        metrics.set_sink_lagging_subjects(sink, count as i64);
        metrics.set_sink_lagging_events(sink, total as i64);
        metrics.set_sink_lag_max_distance(sink, max as i64);
    }

    fn try_insert_lagging(&mut self, sink: &str, subject_id: String) {
        let set = self.lagging.entry(sink.to_string()).or_default();
        set.insert(subject_id);
        self.update_sink_lag_metrics(sink);
    }

    fn remove_lagging_subject(&mut self, sink: &str, subject_id: &str) {
        if let Some(set) = self.lagging.get_mut(sink) {
            set.remove(subject_id);
            if set.is_empty() {
                self.lagging.remove(sink);
                self.last_errors.remove(sink);
            }
        }
        self.update_sink_lag_metrics(sink);
    }

    /// Reset the notification cursor for a single subject to the delivery
    /// cursor. Called when a worker is recreated or catch-up state changes, so
    /// that events lost in a dead worker are not skipped by the sequential gate.
    fn reset_last_notified_for_subject(
        &mut self,
        sink: &str,
        subject_id: &str,
    ) {
        let key = (sink.to_string(), subject_id.to_string());
        if let Some(cursor) = self.cursors.get(&key).copied() {
            self.last_notified.insert(key, cursor);
        } else {
            self.last_notified.remove(&key);
        }
    }

    /// Reset the notification cursor for every subject of a sink to its
    /// delivery cursor. Used when a sink worker stops or is recreated.
    fn reset_last_notified_for_sink(&mut self, sink: &str) {
        self.last_notified.retain(|(s, _), _| s != sink);
        for ((s, subject_id), cursor) in self.cursors.iter() {
            if s == sink {
                self.last_notified
                    .insert((s.clone(), subject_id.clone()), *cursor);
            }
        }
    }

    fn rebuild_lagging(&mut self) {
        self.lagging.clear();
        let active_sinks: Vec<String> =
            self.active_sinks.iter().cloned().collect();
        for sink_name in &active_sinks {
            let mut outdated = Vec::new();
            let last_seen: Vec<(String, u64)> = self
                .last_seen
                .iter()
                .map(|(k, &v)| (k.clone(), v))
                .collect();
            for (subject_id, last_sn) in last_seen {
                let cursor_sn = self
                    .cursors
                    .get(&(sink_name.clone(), subject_id.clone()))
                    .copied();
                // CR-4: If there is no cursor at all, the subject is outdated even
                // when last_sn == 0 (e.g. a Create event that failed before cursor
                // could be persisted).  Otherwise, outdated means cursor < last_sn.
                let is_outdated = cursor_sn.is_none_or(|sn| sn < last_sn);
                if is_outdated {
                    outdated.push(subject_id);
                }
            }
            for subject_id in outdated {
                self.try_insert_lagging(sink_name, subject_id);
            }
        }

        for sink_name in &active_sinks {
            self.update_sink_lag_metrics(sink_name);
        }

        // Drop stale last-error entries for sinks that no longer have lagging
        // subjects. Errors for sinks that are still behind remain visible.
        self.last_errors.retain(|sink, _| {
            self.lagging
                .get(sink)
                .map(|s| !s.is_empty())
                .unwrap_or(false)
        });
    }

    /// Start workers for every configured sink and trigger catch-up for any
    /// subjects that are behind. Errors are logged but not propagated, because
    /// a single failing sink or catch-up must not prevent the manager from
    /// starting the rest.
    async fn start_workers_and_catch_up(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) {
        for sink_name in Vec::from_iter(self.sink_servers.keys().cloned()) {
            if let Err(e) = self.ensure_worker(&sink_name, ctx).await {
                error!(
                    msg_type = "StartWorker",
                    sink = %sink_name,
                    error = %e,
                    "Failed to start SinkWorker"
                );
            }
        }

        // Trigger catch-up for any subjects that are behind. This is
        // essential when a new sink is added to the configuration: all
        // existing subjects will have no cursor for it and must be brought
        // up to date incrementally.
        let lagging: Vec<(String, Vec<String>)> = self
            .lagging
            .iter()
            .map(|(sink, subjects)| {
                (sink.clone(), subjects.iter().cloned().collect())
            })
            .collect();
        for (sink_name, subjects) in lagging {
            if let Err(e) = self
                .handle_request_catch_up(sink_name.clone(), subjects, ctx)
                .await
            {
                error!(
                    msg_type = "StartupCatchUp",
                    sink = %sink_name,
                    error = %e,
                    "Failed to trigger startup catch-up"
                );
            }
        }

        // Re-deliver replays that were accepted but not completed before the
        // restart. The normal lagging path cannot cover them when the cursor
        // was already advanced past the floor by another catch-up.
        let replay_floors: Vec<(String, String, u64)> = self
            .replay_floors
            .iter()
            .map(|((sink, subject_id), from_sn)| {
                (sink.clone(), subject_id.clone(), *from_sn)
            })
            .collect();
        for (sink_name, subject_id, from_sn) in replay_floors {
            if self.blocked_sinks.contains_key(&sink_name) {
                continue;
            }
            info!(
                msg_type = "ReplayResume",
                sink = %sink_name,
                subject_id = %subject_id,
                from_sn = %from_sn,
                "Resuming pending replay after node restart"
            );
            if let Err(e) = self
                .send_catch_up(sink_name.clone(), subject_id, from_sn, ctx)
                .await
            {
                error!(
                    msg_type = "ReplayResume",
                    sink = %sink_name,
                    error = %e,
                    "Failed to resume pending replay after node restart"
                );
            }
        }
    }

    /// Start workers and trigger catch-up for the node-level governance sink
    /// manager. This is called by Node once all children (including
    /// SubjectManager and its governances) have been started, so catch-up
    /// queries can find the governance actors.
    async fn handle_startup_ready(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let safe_mode = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config")
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if !safe_mode {
            self.start_workers_and_catch_up(ctx).await;
        }

        Ok(())
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
                let server =
                    self.sink_servers.get(sink_name).ok_or_else(|| {
                        ActorError::Functional {
                            description: format!(
                                "Sink server {} not found",
                                sink_name
                            ),
                        }
                    })?;
                // Only sinks with signature enabled need the node identity to
                // sign deliveries.
                let signer = match &server.transport {
                    SinkTransportConfig::Http(http) if http.signature => {
                        let node = ctx
                            .system()
                            .get_actor::<Node>(&ActorPath::from("/user/node"))
                            .await?;
                        Some(NodeSigner::new(node))
                    }
                    SinkTransportConfig::Kafka(kafka) if kafka.signature => {
                        let node = ctx
                            .system()
                            .get_actor::<Node>(&ActorPath::from("/user/node"))
                            .await?;
                        Some(NodeSigner::new(node))
                    }
                    SinkTransportConfig::Grpc(grpc) if grpc.signature => {
                        let node = ctx
                            .system()
                            .get_actor::<Node>(&ActorPath::from("/user/node"))
                            .await?;
                        Some(NodeSigner::new(node))
                    }
                    _ => None,
                };
                let worker = SinkWorker::new(
                    sink_name.to_owned(),
                    server.clone(),
                    self.is_governance,
                    signer,
                    self.node_public_key.clone(),
                )
                .await
                .map_err(|e| ActorError::Functional {
                    description: format!(
                        "Failed to create sink worker for {}: {}",
                        sink_name, e
                    ),
                })?;
                let worker_ref = ctx.create_child(&child_name, worker).await?;
                // Death-watch: if the worker stops while a notification is in
                // flight (e.g. racing its own idle shutdown), the manager
                // re-evaluates cursors and recovers any lost event via
                // catch-up.
                let sink_for_watch = sink_name.to_owned();
                if let Err(e) = ctx
                    .watch(&worker_ref, move |_| {
                        SinkManagerMessage::WorkerStopped {
                            sink: sink_for_watch.clone(),
                        }
                    })
                    .await
                {
                    error!(msg_type = "WatchWorker", sink = %sink_name, error = %e, "Failed to watch sink worker");
                }
                // Reset notification cursors for this sink: any events notified
                // to the previous worker but not yet delivered are lost, so they
                // must be recovered by catch-up rather than skipped by the gate.
                self.reset_last_notified_for_sink(sink_name);
                Ok(worker_ref)
            }
        }
    }

    /// F-5: Schedule worker shutdown after idle timeout.  Manager controls lifecycle.
    /// Cancels any pending shutdown for this worker before scheduling a new one,
    /// preventing race conditions where a worker is destroyed while processing events.
    async fn schedule_worker_shutdown(
        &mut self,
        sink_name: String,
        ctx: &ActorContext<Self>,
    ) {
        // Cancel any existing shutdown timer for this worker
        if let Some((token, _)) =
            self.pending_worker_shutdowns.remove(&sink_name)
        {
            token.cancel();
        }
        let child_name = format!("worker_{}", sink_name);
        if ctx.get_child::<SinkWorker>(&child_name).await.is_err() {
            // Worker is no longer alive; nothing to shut down.
            return;
        }
        let shutdown_after_ms = self
            .sink_servers
            .get(&sink_name)
            .map(|s| s.sink_worker_idle_timeout_ms)
            .unwrap_or_else(default_sink_worker_idle_timeout_ms);
        let self_ref = match ctx.reference().await {
            Ok(self_ref) => self_ref,
            Err(e) => {
                error!(msg_type = "ScheduleWorkerShutdown", sink = %sink_name, error = %e, "Failed to get self reference for worker shutdown timer");
                return;
            }
        };
        self.next_worker_shutdown_generation += 1;
        let generation = self.next_worker_shutdown_generation;
        let token = CancellationToken::new();
        let token_for_task = token.clone();
        let sink_name_for_msg = sink_name.clone();
        let sink_name_for_log = sink_name.clone();
        ctx.spawn(async move {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_millis(shutdown_after_ms)) => {
                    // Only fire if the token was NOT cancelled.
                    if !token_for_task.is_cancelled() {
                        // Route the shutdown through the manager's mailbox so
                        // the worker is stopped synchronously (ask_stop) and
                        // events can never race its termination.
                        if let Err(e) = self_ref
                            .tell(SinkManagerMessage::WorkerShutdownTimeout {
                                sink: sink_name_for_msg,
                                generation,
                            })
                            .await
                        {
                            error!(msg_type = "SinkWorkerShutdown", sink = %sink_name_for_log, error = %e, "Failed to send worker shutdown timeout to manager");
                        }
                    }
                }
                _ = token_for_task.cancelled() => {
                    // Timer was cancelled — do nothing.
                }
            }
        });
        // Keep the token for explicit per-sink cancellation.  The actor will
        // abort all spawned tasks automatically on stop/restart.
        self.pending_worker_shutdowns
            .insert(sink_name, (token, generation));
    }

    /// Cancel pending worker shutdown timer for the given sink.
    fn cancel_worker_shutdown(&mut self, sink_name: &str) {
        if let Some((token, _)) =
            self.pending_worker_shutdowns.remove(sink_name)
        {
            token.cancel();
        }
    }

    /// A sink worker has stopped (death-watch).  An event notified to the
    /// worker while it was already stopping is lost silently — non-critical
    /// messages are discarded during graceful shutdown and `tell` reports
    /// success as long as the mailbox accepts the message — so re-evaluate
    /// every subject cursor against last_seen for this sink and recover
    /// whatever is pending via catch-up (which recreates the worker).
    /// On a normal idle shutdown with everything delivered this is a no-op.
    async fn handle_worker_stopped(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // Drop the shutdown timer for the dead worker: cancel it if it was
        // still pending (abnormal stop), no-op if it already fired.
        if let Some((token, _)) = self.pending_worker_shutdowns.remove(&sink) {
            token.cancel();
        }
        // Any catch-up running in the dead worker is no longer running.
        self.catch_up_in_flight.retain(|(s, _), _| s != &sink);
        // Events notified to the dead worker but not yet delivered are lost;
        // reset notification cursors so the gate does not skip them.
        self.reset_last_notified_for_sink(&sink);

        let mut outdated = Vec::new();
        for (subject_id, &last_sn) in &self.last_seen {
            let cursor_sn = self
                .cursors
                .get(&(sink.clone(), subject_id.clone()))
                .copied();
            // Same rule as rebuild_lagging (CR-4): no cursor means outdated
            // even when last_sn == 0.
            let is_outdated = cursor_sn.is_none_or(|sn| sn < last_sn);
            if is_outdated {
                outdated.push(subject_id.clone());
            }
        }
        if outdated.is_empty() {
            return Ok(());
        }

        info!(
            msg_type = "WorkerStoppedPending",
            sink = %sink,
            subjects = %outdated.len(),
            "Worker stopped with undelivered events; recovering via catch-up"
        );
        for subject_id in &outdated {
            self.try_insert_lagging(&sink, subject_id.clone());
        }
        if self.blocked_sinks.contains_key(&sink) {
            // Keep the subjects lagging until the operator unblocks the sink.
            return Ok(());
        }
        self.handle_request_catch_up(sink, outdated, ctx).await
    }

    /// Schedule a periodic healthcheck for a sink that has lagging subjects.
    /// The task self-tells `HealthcheckTick` through the manager's mailbox,
    /// where the worker reference is resolved (or the worker recreated) at
    /// fire time — capturing the `ActorRef` here would keep firing tells at
    /// a dead worker forever. Cancelled when the sink recovers or is blocked.
    async fn schedule_healthcheck(
        &mut self,
        sink_name: String,
        ctx: &ActorContext<Self>,
    ) {
        if let Some(token) = self.pending_healthchecks.remove(&sink_name) {
            token.cancel();
        }
        let intervals = self
            .sink_servers
            .get(&sink_name)
            .map(|s| s.healthcheck_intervals_secs.clone())
            .unwrap_or_else(default_sink_healthcheck_intervals_secs);
        let self_ref = match ctx.reference().await {
            Ok(self_ref) => self_ref,
            Err(e) => {
                error!(msg_type = "ScheduleHealthcheck", sink = %sink_name, error = %e, "Failed to get self reference for healthcheck timer");
                return;
            }
        };
        let token = CancellationToken::new();
        let token_for_task = token.clone();
        let sink_name_for_task = sink_name.clone();
        ctx.spawn(async move {
            let mut interval_idx = 0usize;
            loop {
                let delay_secs =
                    crate::sink::healthcheck_delay_secs(&intervals, interval_idx);
                let delay_secs = crate::sink::add_jitter(delay_secs);
                tokio::select! {
                    _ = tokio::time::sleep(Duration::from_secs(delay_secs)) => {
                        if token_for_task.is_cancelled() {
                            break;
                        }
                        if let Err(e) = self_ref
                            .tell(SinkManagerMessage::HealthcheckTick {
                                sink: sink_name_for_task.clone(),
                            })
                            .await
                        {
                            error!(msg_type = "HealthcheckTick", sink = %sink_name_for_task, error = %e, "Failed to send healthcheck tick to manager");
                        }
                        interval_idx = interval_idx.saturating_add(1);
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
        ctx: &mut ActorContext<Self>,
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
        let sink_names: Vec<String> =
            self.sink_servers.keys().cloned().collect();
        for sink_name in &sink_names {
            if self.blocked_sinks.contains_key(sink_name) {
                continue;
            }
            // F-2: If the subject is already lagging for this sink, do NOT send
            // NotifyNewEvent and do NOT trigger catch-up here. The subject may
            // still have an in-flight delivery for the expected SN; launching
            // catch-up now would duplicate that SN. Catch-up is started once the
            // cursor advances (handle_update_progress), when the sink recovers
            // (handle_sink_recovered), or when a running catch-up completes
            // (handle_catch_up_completed).
            let is_lagging = self
                .lagging
                .get(sink_name)
                .map(|s| s.contains(&subject_id))
                .unwrap_or(false);
            if is_lagging {
                continue;
            }

            // Sequential delivery check: the next event must be exactly the
            // last forwarded SN + 1 (or cursor+1 if nothing has been forwarded
            // yet). Using `last_notified` instead of the delivery cursor lets
            // batching workers buffer multiple live events while earlier events
            // are still in flight. The cursor is only used as a fallback after
            // a worker restart, so events lost in a dead worker are recovered
            // by catch-up instead of skipped.
            let cursor_sn = self
                .cursors
                .get(&(sink_name.clone(), subject_id.clone()))
                .copied();
            let expected_sn = self
                .last_notified
                .get(&(sink_name.clone(), subject_id.clone()))
                .copied()
                .or(cursor_sn)
                .map(|sn| sn + 1)
                .unwrap_or(0);
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
                // Do not trigger catch-up immediately: the in-flight delivery
                // for the expected SN may still be running. Catch-up will be
                // started once that delivery reports success and the cursor
                // advances (see handle_update_progress).
                self.try_insert_lagging(sink_name, subject_id.clone());
                continue;
            }

            match self.ensure_worker(sink_name, ctx).await {
                Ok(worker_ref) => {
                    // Cancel pending shutdown before sending event to prevent race
                    // where worker dies while processing.
                    self.cancel_worker_shutdown(sink_name);
                    if let Err(e) = worker_ref
                        .tell(SinkWorkerMessage::NotifyNewEvent(Arc::clone(
                            &data,
                        )))
                        .await
                    {
                        error!(msg_type = "NotifyWorker", sink = %sink_name, error = %e, "Failed to notify worker");
                        self.lagging
                            .entry(sink_name.clone())
                            .or_default()
                            .insert(subject_id.clone());
                    } else {
                        self.last_notified.insert(
                            (sink_name.clone(), subject_id.clone()),
                            sn,
                        );
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
        count: u64,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Some(metrics) = try_core_metrics() {
            match result {
                SendResult::Success => {
                    metrics.observe_sink_event_n(&sink, "success", count)
                }
                SendResult::SubjectNotFound => {
                    metrics.observe_sink_event(&sink, "subject_not_found");
                }
            }
        }

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
                let last_sn =
                    self.last_seen.get(&subject_id).copied().unwrap_or(0);
                let is_lagging = self
                    .lagging
                    .get(&sink)
                    .map(|s| s.contains(&subject_id))
                    .unwrap_or(false);
                if sn >= last_sn && is_lagging {
                    self.remove_lagging_subject(&sink, &subject_id);
                    self.reset_last_notified_for_subject(&sink, &subject_id);
                } else if is_lagging && sn < last_sn {
                    // The subject is lagging and a new event just advanced the
                    // cursor. Start catch-up from the next SN so any events
                    // emitted while a delivery was in flight are recovered in
                    // order without duplicating the SN that was in flight.
                    self.reset_last_notified_for_subject(&sink, &subject_id);
                    if let Err(e) = self
                        .handle_request_catch_up(
                            sink.clone(),
                            vec![subject_id.clone()],
                            ctx,
                        )
                        .await
                    {
                        error!(
                            msg_type = "ProgressCatchUp",
                            sink = %sink,
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to trigger catch-up after cursor progress"
                        );
                    }
                }
            }
            SendResult::SubjectNotFound => {
                // MED-2: Subject was deleted — clean up tracking state.
                // EOL does NOT trigger this; EOL events are delivered normally.
                info!(msg_type = "SubjectNotFound", sink = %sink, subject_id = %subject_id, "Removing deleted subject from lagging/cursors");
                self.remove_lagging_subject(&sink, &subject_id);
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
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let cursor_sn = self
            .cursors
            .get(&(sink.clone(), subject_id.clone()))
            .copied();
        let last_sn = self.last_seen.get(&subject_id).copied().unwrap_or(0);
        let finished_from = self
            .catch_up_in_flight
            .remove(&(sink.clone(), subject_id.clone()));
        // Reset notification cursor to the delivery cursor: from now on new live
        // events will be gated against the delivered state.
        self.reset_last_notified_for_subject(&sink, &subject_id);

        // A catch-up that started at or below a registered replay floor has
        // re-delivered the replay range: mark the replay as completed.
        let replay_covered = self
            .replay_floors
            .get(&(sink.clone(), subject_id.clone()))
            .is_some_and(|floor| {
                finished_from.is_some_and(|from| from <= *floor)
            });
        if replay_covered {
            self.persist(
                SinkManagerEvent::ReplayCompleted {
                    sink: sink.clone(),
                    subject_id: subject_id.clone(),
                },
                ctx,
            )
            .await?;
        }

        let up_to_date = cursor_sn.is_some_and(|cursor| cursor >= last_sn);
        if up_to_date {
            self.remove_lagging_subject(&sink, &subject_id);
        }

        // A re-delivery queued after a rejection (e.g. a replay rejected by
        // the unhealthy worker) must run now so its range is delivered.
        let pending_from_sn = self
            .pending_catch_ups
            .remove(&(sink.clone(), subject_id.clone()));

        if let Some(from_sn) = pending_from_sn {
            if self.blocked_sinks.contains_key(&sink) {
                // Keep the request queued: it will be drained when a catch-up
                // completes after the sink is unblocked.
                self.pending_catch_ups
                    .insert((sink.clone(), subject_id.clone()), from_sn);
            } else {
                info!(
                    msg_type = "CatchUpPending",
                    sink = %sink,
                    subject_id = %subject_id,
                    from_sn = %from_sn,
                    "Launching catch-up requested while another was in flight"
                );
                if let Err(e) = self
                    .send_catch_up(
                        sink.clone(),
                        subject_id.clone(),
                        from_sn,
                        ctx,
                    )
                    .await
                {
                    error!(
                        msg_type = "CatchUpPendingFailed",
                        sink = %sink,
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to launch pending catch-up after completion"
                    );
                }
            }
        } else if !up_to_date && !self.blocked_sinks.contains_key(&sink) {
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
                .handle_request_catch_up(
                    sink.clone(),
                    vec![subject_id.clone()],
                    ctx,
                )
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

    async fn handle_replay_events(
        &mut self,
        requests: Vec<SinkReplayItem>,
        ctx: &mut ActorContext<Self>,
    ) -> Result<SinkReplayResponse, ActorError> {
        // Defensive check: replay is a manual mutation and must not run in safe mode.
        let safe_mode = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config")
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if safe_mode {
            return Err(ActorError::Functional {
                description: "ReplayEvents is not available in safe mode"
                    .to_owned(),
            });
        }

        // Deduplicate by (sink, subject_id), keeping the smallest from_sn so that
        // a single catch-up covers all requested ranges for the same pair.
        let mut dedup: HashMap<(String, String), u64> =
            HashMap::with_capacity(requests.len());
        for item in &requests {
            dedup
                .entry((item.sink.clone(), item.subject_id.clone()))
                .and_modify(|sn| *sn = (*sn).min(item.from_sn))
                .or_insert(item.from_sn);
        }
        let unique_requests: Vec<SinkReplayItem> = dedup
            .into_iter()
            .map(|((sink, subject_id), from_sn)| SinkReplayItem {
                sink,
                subject_id,
                from_sn,
            })
            .collect();

        let mut processed = Vec::with_capacity(unique_requests.len());
        let mut errors = Vec::new();
        let mut valid_by_sink: HashMap<String, Vec<SinkReplayItem>> =
            HashMap::new();

        for item in unique_requests {
            if self.blocked_sinks.contains_key(&item.sink) {
                error!(
                    msg_type = "ReplayBlocked",
                    sink = %item.sink,
                    subject_id = %item.subject_id,
                    from_sn = %item.from_sn,
                    "Skipping replay because sink is blocked"
                );
                errors.push(SinkReplayError {
                    sink: item.sink,
                    subject_id: item.subject_id,
                    from_sn: item.from_sn,
                    reason: "sink is blocked".to_owned(),
                });
                continue;
            }

            if !self.sink_servers.contains_key(&item.sink) {
                error!(
                    msg_type = "ReplaySinkNotConfigured",
                    sink = %item.sink,
                    subject_id = %item.subject_id,
                    from_sn = %item.from_sn,
                    "Skipping replay because sink is not configured"
                );
                errors.push(SinkReplayError {
                    sink: item.sink,
                    subject_id: item.subject_id,
                    from_sn: item.from_sn,
                    reason: "sink is not configured".to_owned(),
                });
                continue;
            }

            let last_sn = match self.last_seen.get(&item.subject_id).copied() {
                Some(sn) => sn,
                None => {
                    error!(
                        msg_type = "ReplaySubjectUnknown",
                        sink = %item.sink,
                        subject_id = %item.subject_id,
                        from_sn = %item.from_sn,
                        "Skipping replay because subject has no known events"
                    );
                    errors.push(SinkReplayError {
                        sink: item.sink,
                        subject_id: item.subject_id,
                        from_sn: item.from_sn,
                        reason: "subject has no known events".to_owned(),
                    });
                    continue;
                }
            };

            if item.from_sn > last_sn {
                error!(
                    msg_type = "ReplayFromSnOutOfRange",
                    sink = %item.sink,
                    subject_id = %item.subject_id,
                    from_sn = %item.from_sn,
                    last_sn = %last_sn,
                    "Skipping replay because from_sn is beyond the last seen event"
                );
                errors.push(SinkReplayError {
                    sink: item.sink,
                    subject_id: item.subject_id,
                    from_sn: item.from_sn,
                    reason: format!(
                        "from_sn {} is beyond the last seen event {}",
                        item.from_sn, last_sn
                    ),
                });
                continue;
            }

            // Rewind cursor so catch-up will deliver from `from_sn` onwards.
            if item.from_sn == 0 {
                self.persist(
                    SinkManagerEvent::CursorRemoved {
                        sink: item.sink.clone(),
                        subject_id: item.subject_id.clone(),
                    },
                    ctx,
                )
                .await?;
            } else {
                self.persist(
                    SinkManagerEvent::CursorUpdated {
                        sink: item.sink.clone(),
                        subject_id: item.subject_id.clone(),
                        sn: item.from_sn - 1,
                    },
                    ctx,
                )
                .await?;
            }

            // Register the replay as pending so a node restart cannot drop
            // it: on startup each floor triggers a catch-up from that SN.
            self.persist(
                SinkManagerEvent::ReplayRegistered {
                    sink: item.sink.clone(),
                    subject_id: item.subject_id.clone(),
                    from_sn: item.from_sn,
                },
                ctx,
            )
            .await?;

            self.try_insert_lagging(&item.sink, item.subject_id.clone());
            valid_by_sink
                .entry(item.sink.clone())
                .or_default()
                .push(item);
        }

        // Launch a single catch-up per sink with all valid subjects.
        for (sink, items) in valid_by_sink {
            let subject_ids: Vec<String> =
                items.iter().map(|item| item.subject_id.clone()).collect();

            if let Err(e) = self
                .handle_request_catch_up(sink.clone(), subject_ids, ctx)
                .await
            {
                warn!(
                    msg_type = "ReplayCatchUpFailed",
                    sink = %sink,
                    error = %e,
                    "Failed to trigger catch-up for replay; subjects remain in lagging"
                );
            }

            for item in items {
                info!(
                    msg_type = "ReplayAccepted",
                    sink = %item.sink,
                    subject_id = %item.subject_id,
                    from_sn = %item.from_sn,
                    "Replay item accepted; catch-up will resend events"
                );
                processed.push(item);
            }
        }

        Ok(SinkReplayResponse { processed, errors })
    }

    async fn handle_test_sink(
        &self,
        sink_name: &str,
        ctx: &ActorContext<Self>,
    ) -> Result<(), SinkTestError> {
        let server = match self.sink_servers.get(sink_name) {
            Some(server) => server.clone(),
            None => {
                return Err(SinkTestError::NotConfigured);
            }
        };

        let signer = match &server.transport {
            SinkTransportConfig::Http(http) if http.signature => {
                match ctx
                    .system()
                    .get_actor::<Node>(&ActorPath::from("/user/node"))
                    .await
                {
                    Ok(node) => Some(NodeSigner::new(node)),
                    Err(e) => {
                        return Err(SinkTestError::Internal(format!(
                            "failed to get node actor for sink test: {}",
                            e
                        )));
                    }
                }
            }
            SinkTransportConfig::Kafka(kafka) if kafka.signature => {
                match ctx
                    .system()
                    .get_actor::<Node>(&ActorPath::from("/user/node"))
                    .await
                {
                    Ok(node) => Some(NodeSigner::new(node)),
                    Err(e) => {
                        return Err(SinkTestError::Internal(format!(
                            "failed to get node actor for sink test: {}",
                            e
                        )));
                    }
                }
            }
            SinkTransportConfig::Grpc(grpc) if grpc.signature => {
                match ctx
                    .system()
                    .get_actor::<Node>(&ActorPath::from("/user/node"))
                    .await
                {
                    Ok(node) => Some(NodeSigner::new(node)),
                    Err(e) => {
                        return Err(SinkTestError::Internal(format!(
                            "failed to get node actor for sink test: {}",
                            e
                        )));
                    }
                }
            }
            _ => None,
        };

        let transport = build_transport(
            &server,
            signer,
            Some(self.node_public_key.as_str()),
        )
        .await
        .map_err(|e| {
            SinkTestError::Internal(format!(
                "failed to build sink transport: {}",
                e
            ))
        })?;

        transport.test().await.map_err(|e| {
            warn!(
                msg_type = "SinkTestFailed",
                sink = %sink_name,
                error = %e,
                "Sink test delivery failed"
            );
            SinkTestError::Delivery(format!("sink test failed: {}", e))
        })
    }

    async fn handle_request_catch_up(
        &mut self,
        sink: String,
        subjects: Vec<String>,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.blocked_sinks.contains_key(&sink) {
            return Ok(());
        }

        for subject_id in subjects {
            let last_sn = self.last_seen.get(&subject_id).copied().unwrap_or(0);
            let cursor_sn = self
                .cursors
                .get(&(sink.clone(), subject_id.clone()))
                .copied();
            let from_sn = cursor_sn.map_or(0, |sn| sn + 1);

            // If the cursor is already up-to-date, there is nothing to catch up.
            if cursor_sn.is_some_and(|sn| sn >= last_sn) {
                continue;
            }

            let in_flight_key = (sink.clone(), subject_id.clone());
            if let Some(&in_flight_from) =
                self.catch_up_in_flight.get(&in_flight_key)
            {
                // A lower from_sn (e.g. a replay that rewound the cursor
                // mid-flight) merges with the in-flight catch-up by
                // restarting it from the lower SN so the whole range is
                // re-delivered in order; anything else is already covered
                // by the in-flight catch-up.
                if from_sn < in_flight_from
                    && let Err(e) = self
                        .send_catch_up(sink.clone(), subject_id, from_sn, ctx)
                        .await
                {
                    error!(msg_type = "CatchUp", sink = %sink, error = %e, "Failed to send catch-up restart to worker");
                }
                continue;
            }

            if let Err(e) = self
                .send_catch_up(sink.clone(), subject_id, from_sn, ctx)
                .await
            {
                error!(msg_type = "CatchUp", sink = %sink, error = %e, "Failed to send catch-up request to worker");
            }
        }
        Ok(())
    }

    /// Ensures the sink worker is running and sends it a catch-up request for
    /// `subject_id` starting at `from_sn`, marking the pair as in flight.
    async fn send_catch_up(
        &mut self,
        sink: String,
        subject_id: String,
        from_sn: u64,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let worker_ref = self.ensure_worker(&sink, ctx).await?;

        // Cancel pending shutdown before sending catch-up to prevent race
        // where worker dies while processing.
        self.cancel_worker_shutdown(&sink);

        self.catch_up_in_flight
            .insert((sink.clone(), subject_id.clone()), from_sn);
        if let Err(e) = worker_ref
            .tell(SinkWorkerMessage::CatchUp {
                subject_id: subject_id.clone(),
                from_sn,
            })
            .await
        {
            self.catch_up_in_flight.remove(&(sink, subject_id));
            return Err(e);
        }
        Ok(())
    }

    /// Launches catch-ups that were queued while the sink was unavailable
    /// (e.g. a replay rejected by an unhealthy worker). Subjects with an
    /// in-flight catch-up are left queued: their pending range is drained
    /// when that catch-up completes.
    async fn drain_pending_catch_ups(
        &mut self,
        sink: &str,
        ctx: &mut ActorContext<Self>,
    ) {
        let pending: Vec<(String, u64)> = self
            .pending_catch_ups
            .iter()
            .filter(|((s, _), _)| s == sink)
            .map(|((_, subject_id), from_sn)| (subject_id.clone(), *from_sn))
            .collect();
        for (subject_id, from_sn) in pending {
            let key = (sink.to_string(), subject_id.clone());
            if self.catch_up_in_flight.contains_key(&key) {
                continue;
            }
            self.pending_catch_ups.remove(&key);
            if let Err(e) = self
                .send_catch_up(
                    sink.to_string(),
                    subject_id.clone(),
                    from_sn,
                    ctx,
                )
                .await
            {
                error!(
                    msg_type = "CatchUpPendingFailed",
                    sink = %sink,
                    subject_id = %subject_id,
                    error = %e,
                    "Failed to launch queued catch-up after sink recovery"
                );
                self.pending_catch_ups.insert(key, from_sn);
            }
        }
    }

    async fn handle_sink_recovered(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.blocked_sinks.contains_key(&sink) {
            return Ok(());
        }
        info!(msg_type = "SinkRecovered", sink = %sink, "Sink recovered, triggering catch-up");
        self.active_sinks.insert(sink.clone());
        self.last_errors.remove(&sink);

        // Cancel periodic healthcheck — the sink is healthy again.
        self.cancel_healthcheck(&sink);

        // Rebuild lagging before launching catch-up to detect any subjects
        // that may have fallen behind without being explicitly tracked.
        self.rebuild_lagging();

        if let Some(subjects) = self.lagging.get(&sink).cloned() {
            self.handle_request_catch_up(
                sink.clone(),
                subjects.into_iter().collect(),
                ctx,
            )
            .await?;
        }

        // Launch any catch-ups queued while the sink was down (e.g. replays
        // rejected by the unhealthy worker).
        self.drain_pending_catch_ups(&sink, ctx).await;

        self.persist(SinkManagerEvent::SinkRecovered { sink }, ctx)
            .await?;
        Ok(())
    }

    async fn handle_unblock_sink(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.blocked_sinks.contains_key(&sink) {
            info!(msg_type = "SinkUnblocked", sink = %sink, "Sink manually unblocked by operator");
            self.last_errors.remove(&sink);
            // Cancel any stale healthcheck timer before unblocking. A fresh
            // worker will be created below and will run its own healthchecks if
            // needed.
            self.cancel_healthcheck(&sink);
            self.persist(
                SinkManagerEvent::SinkUnblocked { sink: sink.clone() },
                ctx,
            )
            .await?;
            // Reset flapping counter in the worker so that the first healthcheck
            // after unblock can trigger SinkRecovered and catch-up.
            if let Ok(worker) = self.ensure_worker(&sink, ctx).await {
                // Cancel pending shutdown before sending messages to prevent race
                self.cancel_worker_shutdown(&sink);
                // If these tells fail the worker is dying mid-shutdown; its
                // replacement starts fresh (unblocked, zero recoveries), and
                // the persisted `blocked_sinks` (already updated above) is the
                // source of truth, so the states cannot diverge. A live
                // blocked worker has an idle mailbox, so `MailboxFull` is not
                // reachable here — anything else is logged for visibility.
                if let Err(e) = worker
                    .tell(
                        crate::sink::worker::SinkWorkerMessage::ResetRecoveries,
                    )
                    .await
                {
                    error!(msg_type = "ResetRecoveries", sink = %sink, error = %e, "Failed to reset worker flapping counter on unblock");
                }
                if let Err(e) = worker
                    .tell(crate::sink::worker::SinkWorkerMessage::ClearBlocked)
                    .await
                {
                    error!(msg_type = "ClearBlocked", sink = %sink, error = %e, "Failed to clear worker blocked state on unblock");
                }
            }
            // Rebuild lagging for this sink and trigger catch-up to catch up on missed events.
            let subjects_to_add: Vec<String> = self
                .last_seen
                .iter()
                .filter_map(|(subject_id, &last_sn)| {
                    let cursor_sn = self
                        .cursors
                        .get(&(sink.clone(), subject_id.clone()))
                        .copied();
                    let is_outdated = cursor_sn.is_none_or(|sn| sn < last_sn);
                    if is_outdated {
                        Some(subject_id.clone())
                    } else {
                        None
                    }
                })
                .collect();
            for subject_id in subjects_to_add {
                self.try_insert_lagging(&sink, subject_id);
            }
            if let Some(subjects) = self.lagging.get(&sink).cloned() {
                let subjects: Vec<String> = subjects.into_iter().collect();
                if !subjects.is_empty() {
                    self.handle_request_catch_up(sink.clone(), subjects, ctx)
                        .await?;
                }
            }
            // Launch any catch-ups queued while the sink was blocked.
            self.drain_pending_catch_ups(&sink, ctx).await;
        }
        Ok(())
    }

    async fn handle_reset_sink_cursors(
        &mut self,
        sink: String,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // Double-check Safe Mode at the actor level: this operation is only valid
        // while the node is running in safe mode. In safe mode there are no
        // workers running, so we only need to clean persisted/transient state.
        let safe_mode = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config")
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
                description: "ResetSinkCursors is only available in safe mode"
                    .to_owned(),
            });
        }

        info!(
            msg_type = "ResetSinkCursors",
            sink = %sink,
            "Resetting all sink cursors in Safe Mode"
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
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        info!(msg_type = "RemoveSubject", subject_id = %subject_id, "Removing subject from all sinks");

        // Remove from lagging.
        let sinks_with_subject: Vec<String> = self
            .lagging
            .iter()
            .filter(|(_, subjects)| subjects.contains(subject_id))
            .map(|(sink, _)| sink.clone())
            .collect();
        for sink in sinks_with_subject {
            if let Some(set) = self.lagging.get_mut(&sink) {
                set.remove(subject_id);
                if set.is_empty() {
                    self.lagging.remove(&sink);
                }
            }
        }

        // Remove cursors. The actual deletion happens in apply().
        let sinks_with_cursor: Vec<String> = self
            .cursors
            .keys()
            .filter(|(_, sid)| sid == subject_id)
            .map(|(sink, _)| sink.clone())
            .collect();
        for sink in sinks_with_cursor {
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

        // Clear any in-flight catch-up for the deleted subject so it does not
        // block future catch-ups for other subjects.
        self.catch_up_in_flight
            .retain(|(_, sid), _| sid != subject_id);
        self.pending_catch_ups
            .retain(|(_, sid), _| sid != subject_id);

        // Complete any pending replay for the deleted subject so a restart
        // does not resume a replay for a subject that no longer exists.
        let sinks_with_floor: Vec<String> = self
            .replay_floors
            .keys()
            .filter(|(_, sid)| sid == subject_id)
            .map(|(sink, _)| sink.clone())
            .collect();
        for sink in sinks_with_floor {
            self.persist(
                SinkManagerEvent::ReplayCompleted {
                    sink,
                    subject_id: subject_id.to_string(),
                },
                ctx,
            )
            .await?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manager_with_state(
        cursors: BTreeMap<(String, String), u64>,
        last_seen: BTreeMap<String, u64>,
    ) -> SinkManager {
        SinkManager {
            cursors,
            last_seen,
            active_sinks: BTreeSet::new(),
            version: 1,
            sink_servers: BTreeMap::new(),
            lagging: BTreeMap::new(),
            store_params: None,
            blocked_sinks: BTreeMap::new(),
            replay_floors: BTreeMap::new(),
            is_governance: false,
            node_public_key: String::new(),
            pending_worker_shutdowns: HashMap::new(),
            next_worker_shutdown_generation: 0,
            pending_healthchecks: HashMap::new(),
            catch_up_in_flight: HashMap::new(),
            pending_catch_ups: HashMap::new(),
            last_notified: HashMap::new(),
            last_errors: HashMap::new(),
        }
    }

    #[test]
    fn sink_lag_distance_with_missing_cursor_counts_one_event() {
        let mut last_seen = BTreeMap::new();
        last_seen.insert("sub".to_owned(), 0);
        let manager = manager_with_state(BTreeMap::new(), last_seen);

        // No cursor at all means the Create event (sn 0) is still pending.
        assert_eq!(manager.sink_lag_distance("sink", "sub"), 1);
    }

    #[test]
    fn sink_lag_distance_with_cursor_behind_last_seen() {
        let mut cursors = BTreeMap::new();
        cursors.insert(("sink".to_owned(), "sub".to_owned()), 2);
        let mut last_seen = BTreeMap::new();
        last_seen.insert("sub".to_owned(), 5);
        let manager = manager_with_state(cursors, last_seen);

        assert_eq!(manager.sink_lag_distance("sink", "sub"), 3);
    }

    #[test]
    fn sink_lag_distance_zero_when_fully_caught_up() {
        let mut cursors = BTreeMap::new();
        cursors.insert(("sink".to_owned(), "sub".to_owned()), 5);
        let mut last_seen = BTreeMap::new();
        last_seen.insert("sub".to_owned(), 5);
        let manager = manager_with_state(cursors, last_seen);

        assert_eq!(manager.sink_lag_distance("sink", "sub"), 0);
    }

    #[test]
    fn sink_lagging_totals_aggregate_distances() {
        let mut cursors = BTreeMap::new();
        cursors.insert(("sink".to_owned(), "a".to_owned()), 2); // lag 3
        cursors.insert(("sink".to_owned(), "b".to_owned()), 4); // lag 1
        // c is missing, last_seen 0 -> lag 1
        let mut last_seen = BTreeMap::new();
        last_seen.insert("a".to_owned(), 5);
        last_seen.insert("b".to_owned(), 5);
        last_seen.insert("c".to_owned(), 0);

        let mut manager = manager_with_state(cursors, last_seen);
        manager.lagging.insert(
            "sink".to_owned(),
            HashSet::from(["a".to_owned(), "b".to_owned(), "c".to_owned()]),
        );

        let (count, total, max) = manager.sink_lagging_totals("sink");
        assert_eq!(count, 3);
        assert_eq!(total, 5); // 3 + 1 + 1
        assert_eq!(max, 3);
    }
}
