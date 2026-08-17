//! SinkSubjectWorker: ephemeral child actor that handles a single subject.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, OverflowStrategy, Response, TimerKey,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info_span, warn};

use crate::config::{SinkServer, SinkTransportConfig};
use crate::sink::SinkError;
use crate::sink::extract_sn;
use crate::sink::manager::SendResult;
use crate::sink::transport::SinkTransport;
use crate::sink::worker::{
    SinkSubjectWorkerError, SinkWorker, SinkWorkerMessage,
};
use ave_common::{DataToSink, IncomingSinkEvent, LightEvent, SinkTypes};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkSubjectWorkerMessage {
    DeliverEvent(Arc<DataToSink>),
    /// Starts or restarts a catch-up from `from_sn`. Only sent by the parent
    /// worker: bumps the catch-up generation, invalidating any in-flight
    /// delivery chain from a previous catch-up so events always arrive in
    /// order and stale batches are dropped.
    CatchUpBatch {
        from_sn: u64,
        batch_size: usize,
    },
    /// Continues the current catch-up with the next batch. Self-sent by the
    /// subject worker; dropped if `generation` no longer matches the current
    /// catch-up generation (i.e. the catch-up was restarted meanwhile).
    ContinueCatchUp {
        from_sn: u64,
        batch_size: usize,
        generation: u64,
    },
    ProcessNextEvent {
        data: Arc<DataToSink>,
        remaining: Vec<DataToSink>,
        generation: u64,
    },
    /// Flush the buffered live events (only used in `batch_delivery` mode).
    FlushBatch,
    Pause,
    Resume,
    Stop,
}
impl Message for SinkSubjectWorkerMessage {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkSubjectWorkerResponse {
    Ok,
}
impl Response for SinkSubjectWorkerResponse {}

// ---------------------------------------------------------------------------
// Actor
// ---------------------------------------------------------------------------

pub struct SinkSubjectWorker {
    sink_name: String,
    server: SinkServer,
    client: Arc<dyn SinkTransport>,
    paused: bool,
    /// `true` when this worker handles governance events (parent SinkManager
    /// is under Node). `false` when it handles tracker events (parent is under
    /// Governance).
    is_governance: bool,
    /// Batch delivery mode (HTTP `batch_delivery`): live events are buffered
    /// and flushed as a single JSON-array `POST`, and catch-up batches are
    /// sent whole instead of event by event.
    batch_delivery: bool,
    /// Maximum time a live event waits in the buffer before it is flushed.
    batch_max_delay_ms: u64,
    /// Live events buffered for the next batch flush.
    pending: Vec<IncomingSinkEvent>,
    /// Active `FlushBatch` timer, if any. Stored so it can be cancelled when
    /// the buffer is flushed inline, preventing stale timers from firing.
    flush_timer: Option<TimerKey>,
    /// Current catch-up generation. Bumped on every `CatchUpBatch` from the
    /// parent worker; self-chained `ProcessNextEvent`/`ContinueCatchUp`
    /// messages carrying an older generation are dropped, which makes
    /// catch-up restarts (e.g. a replay rewinding below the in-flight
    /// catch-up) deterministic and keeps delivery order.
    catch_up_generation: u64,
    /// `true` while this worker holds a `SubjectManager::Up` requester for
    /// its subject (lifted for catch-up ledger reads). Every successful `Up`
    /// must be paired with a `Finish` or the subject stays resident in
    /// memory forever.
    subject_lifted: bool,
}

impl std::fmt::Debug for SinkSubjectWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkSubjectWorker")
            .field("sink_name", &self.sink_name)
            .field("server", &self.server.server)
            .field("paused", &self.paused)
            .field("batch_delivery", &self.batch_delivery)
            .finish()
    }
}

impl NotPersistentActor for SinkSubjectWorker {}

#[async_trait]
impl Actor for SinkSubjectWorker {
    type Message = SinkSubjectWorkerMessage;
    type Response = SinkSubjectWorkerResponse;
    type Event = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<tracing::Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("sink_subject_worker", id),
            |parent_span| info_span!(parent: parent_span, "sink_subject_worker", id),
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

    /// Safety net: if the worker stops with the subject still lifted (idle
    /// shutdown, live-delivery-only era, system stop), pair the `Up` with
    /// its `Finish` so the subject can be unloaded from memory.
    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.release_subject(ctx).await;
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for SinkSubjectWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkSubjectWorkerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<SinkSubjectWorkerResponse, ActorError> {
        match msg {
            SinkSubjectWorkerMessage::DeliverEvent(data) => {
                if self.paused {
                    return Ok(SinkSubjectWorkerResponse::Ok);
                }

                if self.batch_delivery {
                    self.pending
                        .push(self.to_incoming_event(Arc::clone(&data)));
                    if self.pending.len() >= self.server.batch_delivery_size {
                        self.flush_pending(ctx, false).await;
                    } else if self.flush_timer.is_none() {
                        match ctx.schedule_once(
                            Duration::from_millis(self.batch_max_delay_ms),
                            SinkSubjectWorkerMessage::FlushBatch,
                        ) {
                            Ok(key) => self.flush_timer = Some(key),
                            Err(e) => {
                                error!(msg_type = "ScheduleFlush", sink = %self.sink_name, error = %e, "Failed to schedule batch flush; flushing inline");
                                self.flush_pending(ctx, false).await;
                            }
                        }
                    }
                    return Ok(SinkSubjectWorkerResponse::Ok);
                }

                let (subject_id, _schema_id) =
                    data.payload.get_subject_schema();
                let sn = extract_sn(&data);

                let send_result = if self.sends_full(&data) {
                    self.client.send(Arc::clone(&data)).await
                } else {
                    self.client
                        .send_light(LightEvent::from(data.as_ref()))
                        .await
                };

                match send_result {
                    Ok(()) => {
                        self.report_success(ctx, subject_id, sn, false, 1).await
                    }
                    Err(e) => {
                        self.report_error(ctx, subject_id, sn, e, false, 1)
                            .await
                    }
                }

                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::CatchUpBatch {
                from_sn,
                batch_size,
            } => {
                self.catch_up_generation += 1;
                let generation = self.catch_up_generation;
                self.run_catch_up_batch(from_sn, batch_size, generation, ctx)
                    .await?;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::ContinueCatchUp {
                from_sn,
                batch_size,
                generation,
            } => {
                if generation != self.catch_up_generation {
                    return Ok(SinkSubjectWorkerResponse::Ok);
                }
                self.run_catch_up_batch(from_sn, batch_size, generation, ctx)
                    .await?;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::ProcessNextEvent {
                data,
                remaining,
                generation,
            } => {
                let (subject_id, _schema_id) =
                    data.payload.get_subject_schema();
                let sn = extract_sn(&data);
                if generation != self.catch_up_generation {
                    return Ok(SinkSubjectWorkerResponse::Ok);
                }

                let send_result = if self.sends_full(&data) {
                    self.client.send(Arc::clone(&data)).await
                } else {
                    self.client
                        .send_light(LightEvent::from(data.as_ref()))
                        .await
                };

                match send_result {
                    Ok(()) => {
                        self.report_success(
                            ctx,
                            subject_id.clone(),
                            sn,
                            true,
                            1,
                        )
                        .await;

                        if !remaining.is_empty() {
                            let mut remaining = remaining;
                            let next_event = remaining.remove(0);
                            let self_ref = ctx.reference().await?;
                            if let Err(e) = self_ref
                                .tell(SinkSubjectWorkerMessage::ProcessNextEvent {
                                    data: Arc::new(next_event),
                                    remaining,
                                    generation,
                                })
                                .await
                            {
                                error!(msg_type = "ProcessNextEvent", sink = %self.sink_name, error = %e, "Failed to send ProcessNextEvent to self");
                            }
                        } else {
                            let self_ref = ctx.reference().await?;
                            if let Err(e) = self_ref
                                .tell(
                                    SinkSubjectWorkerMessage::ContinueCatchUp {
                                        from_sn: sn + 1,
                                        batch_size: self
                                            .server
                                            .catch_up_batch_size,
                                        generation,
                                    },
                                )
                                .await
                            {
                                error!(msg_type = "ContinueCatchUp", sink = %self.sink_name, error = %e, "Failed to send ContinueCatchUp to self");
                            }
                        }
                    }
                    Err(e) => {
                        // The whole chain stops on failure: the subject goes
                        // back to lagging and catch-up retries it later.
                        self.report_error(ctx, subject_id, sn, e, true, 1)
                            .await;
                    }
                }

                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::FlushBatch => {
                self.flush_pending(ctx, false).await;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::Pause => {
                // Flush best-effort so buffered events are not held in memory
                // while paused, without blocking on retries against a sink we
                // already know is unhealthy.
                self.flush_pending(ctx, true).await;
                self.paused = true;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::Resume => {
                self.paused = false;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::Stop => {
                // Best-effort flush: a single attempt during teardown. The
                // cursor guarantees re-delivery via catch-up when the sink
                // comes back; retries here would delay actor shutdown.
                self.flush_pending(ctx, true).await;
                ctx.stop(None).await;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
        }
    }
}

/// Outcome of a catch-up query against the ledger. Distinguishing a
/// genuinely deleted subject from a transient failure matters: the manager
/// deletes the cursor and the shared `last_seen` on `NotFound`, so a
/// transient hiccup must never take that path.
enum SubjectQuery {
    /// Events read from the ledger.
    Events(Vec<DataToSink>),
    /// The subject genuinely does not exist (deleted).
    NotFound,
    /// Transient failure (actor unavailable, ask error/timeout): the
    /// subject stays lagging and the catch-up is retried later.
    Unavailable,
}

impl SinkSubjectWorker {
    pub fn new(
        sink_name: String,
        server: SinkServer,
        client: Arc<dyn SinkTransport>,
        is_governance: bool,
    ) -> Self {
        let (batch_delivery, batch_max_delay_ms) = match &server.transport {
            SinkTransportConfig::Http(http) => {
                (http.batch_delivery, http.batch_max_delay_ms)
            }
            SinkTransportConfig::Kafka(kafka) => {
                (kafka.batch_delivery, kafka.batch_max_delay_ms)
            }
            SinkTransportConfig::Grpc(grpc) => {
                (grpc.batch_delivery, grpc.batch_max_delay_ms)
            }
        };
        Self {
            sink_name,
            server,
            client,
            paused: false,
            is_governance,
            batch_delivery,
            batch_max_delay_ms,
            pending: Vec::new(),
            flush_timer: None,
            catch_up_generation: 0,
            subject_lifted: false,
        }
    }

    /// Release the subject lifted by catch-up ledger reads: every successful
    /// `SubjectManager::Up` must be paired with a `Finish` or the subject
    /// stays resident in memory forever (one dangling requester per sink per
    /// subject). Idempotent; a failed `Finish` only leaves the subject up
    /// until node shutdown (the requester set is in-memory only).
    async fn release_subject(&mut self, ctx: &ActorContext<Self>) {
        if !self.subject_lifted {
            return;
        }
        self.subject_lifted = false;
        let subject_id = ctx.path().key().to_owned();
        let requester = format!("sink:{}:{}", self.sink_name, subject_id);
        let Ok(digest) =
            subject_id.parse::<ave_common::identity::DigestIdentifier>()
        else {
            return;
        };
        let path = ActorPath::from("/user/node/subject_manager");
        match ctx
            .system()
            .get_actor::<crate::node::subject_manager::SubjectManager>(&path)
            .await
        {
            Ok(subject_manager) => {
                if let Err(e) = subject_manager
                    .ask(crate::node::subject_manager::SubjectManagerMessage::Finish {
                        subject_id: digest,
                        requester,
                    })
                    .await
                {
                    error!(msg_type = "ReleaseSubject", sink = %self.sink_name, subject_id = %subject_id, error = %e, "Failed to finish subject lift");
                }
            }
            Err(e) => {
                error!(msg_type = "ReleaseSubject", sink = %self.sink_name, subject_id = %subject_id, error = %e, "Failed to get subject manager for finish");
            }
        }
    }

    /// Queries the subject for the next catch-up batch starting at `from_sn`
    /// and delivers it (whole batch in `batch_delivery` mode, event by event
    /// otherwise), chaining the continuation with the given `generation`.
    async fn run_catch_up_batch(
        &mut self,
        from_sn: u64,
        batch_size: usize,
        generation: u64,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let subject_id = ctx.path().key().to_owned();
        let events = match self
            .query_subject(&subject_id, from_sn, batch_size, ctx)
            .await
        {
            SubjectQuery::Events(events) => events,
            SubjectQuery::NotFound => {
                self.release_subject(ctx).await;
                match ctx.get_parent::<SinkWorker>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .emit_error(
                                SinkSubjectWorkerError::SubjectNotFound {
                                    subject_id,
                                    sn: 0,
                                    from_catch_up: true,
                                },
                            )
                            .await
                        {
                            error!(msg_type = "ReportSubjectNotFound", sink = %self.sink_name, error = %e, "Failed to report subject not found");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                    }
                }
                return Ok(());
            }
            SubjectQuery::Unavailable => {
                // Transient query failure: report it as a failed catch-up so
                // the subject stays lagging and the manager retries later.
                // The cursor and the shared `last_seen` are NOT touched —
                // wiping them on a hiccup would lose events permanently.
                self.release_subject(ctx).await;
                match ctx.get_parent::<SinkWorker>().await {
                    Ok(parent) => {
                        if let Err(e) = parent
                            .emit_error(
                                SinkSubjectWorkerError::DeliveryFailed {
                                    subject_id,
                                    sn: from_sn,
                                    reason: "catch-up ledger query \
                                             unavailable (transient)"
                                        .to_owned(),
                                    from_catch_up: true,
                                    count: 0,
                                },
                            )
                            .await
                        {
                            error!(msg_type = "ReportCatchUpUnavailable", sink = %self.sink_name, error = %e, "Failed to report catch-up query failure");
                        }
                    }
                    Err(e) => {
                        error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                    }
                }
                return Ok(());
            }
        };

        if events.is_empty() {
            // Catch-up finished: release the subject lift before reporting.
            self.release_subject(ctx).await;
            match ctx.get_parent::<SinkWorker>().await {
                Ok(parent) => {
                    if let Err(e) = parent
                        .tell(SinkWorkerMessage::CatchUpCompleted {
                            subject_id,
                        })
                        .await
                    {
                        error!(msg_type = "ReportCatchUpCompleted", sink = %self.sink_name, error = %e, "Failed to report catch-up completed");
                    }
                }
                Err(e) => {
                    error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                }
            }
            return Ok(());
        }

        if self.batch_delivery {
            let incoming: Vec<IncomingSinkEvent> = events
                .into_iter()
                .map(|e| self.to_incoming_event(Arc::new(e)))
                .collect();
            // `events` is not empty (checked above).
            let first_sn =
                incoming.first().map_or(from_sn, IncomingSinkEvent::sn);
            let last_sn =
                incoming.last().map_or(first_sn, IncomingSinkEvent::sn);
            let count = incoming.len() as u64;

            match self.client.send_batch(incoming).await {
                Ok(()) => {
                    self.report_success(
                        ctx,
                        subject_id.clone(),
                        last_sn,
                        true,
                        count,
                    )
                    .await;
                    let self_ref = ctx.reference().await?;
                    if let Err(e) = self_ref
                        .tell(SinkSubjectWorkerMessage::ContinueCatchUp {
                            from_sn: last_sn + 1,
                            batch_size: self.server.catch_up_batch_size,
                            generation,
                        })
                        .await
                    {
                        error!(msg_type = "ContinueCatchUp", sink = %self.sink_name, error = %e, "Failed to send ContinueCatchUp to self");
                    }
                }
                Err(e) => {
                    self.report_error(
                        ctx, subject_id, first_sn, e, true, count,
                    )
                    .await;
                }
            }
            return Ok(());
        }

        let mut events = events;
        let event = events.remove(0);
        let remaining = events;
        let self_ref = ctx.reference().await?;
        if let Err(e) = self_ref
            .tell(SinkSubjectWorkerMessage::ProcessNextEvent {
                data: Arc::new(event),
                remaining,
                generation,
            })
            .await
        {
            error!(msg_type = "ProcessNextEvent", sink = %self.sink_name, error = %e, "Failed to send ProcessNextEvent to self");
        }
        Ok(())
    }

    /// Whether the event is delivered with its full payload (`events` filter
    /// match) or as a light projection.
    fn sends_full(&self, data: &DataToSink) -> bool {
        let event_type = SinkTypes::from(data);
        self.server.events.contains(&event_type)
            || self.server.events.contains(&SinkTypes::All)
    }

    /// Build the wire representation of an event, honoring the sink's
    /// `events` filter (full payload or light projection).
    fn to_incoming_event(&self, data: Arc<DataToSink>) -> IncomingSinkEvent {
        if self.sends_full(&data) {
            IncomingSinkEvent::Full(data)
        } else {
            IncomingSinkEvent::Light(LightEvent::from(data.as_ref()))
        }
    }

    /// Send the buffered live events as a single batch delivery and report
    /// the outcome to the parent worker. No-op when the buffer is empty.
    ///
    /// When `best_effort` is `true` (Pause/Stop teardown), a single attempt is
    /// made, failures are only logged, and success advances the cursor so the
    /// subject does not pay catch-up for events already delivered.
    async fn flush_pending(
        &mut self,
        ctx: &ActorContext<Self>,
        best_effort: bool,
    ) {
        if let Some(key) = self.flush_timer.take() {
            ctx.cancel_timer(key);
        }
        let events = std::mem::take(&mut self.pending);
        let Some(first) = events.first() else {
            return;
        };
        let subject_id = first.subject_id().to_owned();
        let first_sn = first.sn();
        let last_sn = events.last().map_or(first_sn, IncomingSinkEvent::sn);
        let count = events.len() as u64;

        if best_effort {
            if let Err(e) = self.client.send_batch_best_effort(events).await {
                warn!(
                    msg_type = "FlushBestEffortFailed",
                    sink = %self.sink_name,
                    subject_id = %subject_id,
                    error = %e,
                    "Best-effort flush failed during teardown; will recover via catch-up"
                );
            } else {
                self.report_success(ctx, subject_id, last_sn, false, count)
                    .await;
            }
        } else {
            match self.client.send_batch(events).await {
                Ok(()) => {
                    self.report_success(ctx, subject_id, last_sn, false, count)
                        .await
                }
                Err(e) => {
                    self.report_error(
                        ctx, subject_id, first_sn, e, false, count,
                    )
                    .await
                }
            }
        }
    }

    /// Report a successful delivery to the parent worker: `DeliveryResult`
    /// for live events, `CatchUpProgress` during catch-up. `count` is the
    /// number of events actually delivered (batch size for batch flushes, 1
    /// for individual deliveries).
    async fn report_success(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: String,
        sn: u64,
        from_catch_up: bool,
        count: u64,
    ) {
        let message = if from_catch_up {
            SinkWorkerMessage::CatchUpProgress {
                subject_id,
                sn,
                result: SendResult::Success,
                count,
            }
        } else {
            SinkWorkerMessage::DeliveryResult {
                subject_id,
                sn,
                result: SendResult::Success,
                count,
            }
        };
        match ctx.get_parent::<SinkWorker>().await {
            Ok(parent) => {
                if let Err(e) = parent.tell(message).await {
                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report delivery result");
                }
            }
            Err(e) => {
                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
            }
        }
    }

    /// Report a delivery failure to the parent worker following the sink
    /// error taxonomy: auth failures send the subject to lagging, retryable
    /// network failures are retried via catch-up and permanent failures
    /// block the sink. `count` is the number of events covered by the
    /// failed delivery (batch size for batch flushes, 1 for individual
    /// deliveries), used to settle the parent's live in-flight accounting.
    async fn report_error(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: String,
        sn: u64,
        error: SinkError,
        from_catch_up: bool,
        count: u64,
    ) {
        let worker_error = match error {
            e @ SinkError::Auth { .. } => SinkSubjectWorkerError::AuthFailed {
                subject_id,
                sn,
                error: e.to_string(),
                from_catch_up,
                count,
            },
            e @ SinkError::Delivery {
                retryable: true, ..
            } => SinkSubjectWorkerError::DeliveryFailed {
                subject_id,
                sn,
                reason: e.to_string(),
                from_catch_up,
                count,
            },
            // Delivery { retryable: false } | ClientBuild | Rejected | Shutdown
            e => SinkSubjectWorkerError::Blocked {
                subject_id,
                sn,
                reason: e.to_string(),
            },
        };
        match ctx.get_parent::<SinkWorker>().await {
            Ok(parent) => {
                if let Err(e) = parent.emit_error(worker_error).await {
                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report delivery error");
                }
            }
            Err(e) => {
                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
            }
        }
    }

    async fn query_subject(
        &mut self,
        subject_id: &str,
        from_sn: u64,
        batch_size: usize,
        ctx: &ActorContext<Self>,
    ) -> SubjectQuery {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            subject_id
        ));
        if self.is_governance {
            // Governances are always in memory once created, so a missing
            // actor means the governance was genuinely deleted.
            if let Ok(actor) = ctx
                .system()
                .get_actor::<crate::governance::Governance>(&path)
                .await
            {
                match actor
                    .ask(crate::governance::GovernanceMessage::GetSinkEvents {
                        from_sn,
                        batch_size,
                    })
                    .await
                {
                    Ok(crate::governance::GovernanceResponse::SinkEvents(
                        events,
                    )) => SubjectQuery::Events(events),
                    // A governance always holds at least its Create event, so
                    // a failed query is transient, never "not found".
                    other => {
                        error!(msg_type = "CatchUpQuery", subject_id = %subject_id, response = ?other.is_err(), "Governance catch-up query failed");
                        SubjectQuery::Unavailable
                    }
                }
            } else {
                error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "Governance not found for catch-up query");
                SubjectQuery::NotFound
            }
        } else {
            // Trackers may not be in memory; lift via SubjectManager::Up first.
            let subject_manager_path =
                ActorPath::from("/user/node/subject_manager");
            let Ok(subject_manager) = ctx
                .system()
                .get_actor::<crate::node::subject_manager::SubjectManager>(
                    &subject_manager_path,
                )
                .await
            else {
                error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "SubjectManager unavailable for catch-up query");
                return SubjectQuery::Unavailable;
            };
            let requester = format!("sink:{}:{}", self.sink_name, subject_id);
            let subject_id_digest = match subject_id
                .parse::<ave_common::identity::DigestIdentifier>(
            ) {
                Ok(d) => d,
                Err(_) => {
                    error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "Invalid subject_id format");
                    return SubjectQuery::NotFound;
                }
            };
            if !matches!(
                subject_manager
                    .ask(crate::node::subject_manager::SubjectManagerMessage::Up {
                        subject_id: subject_id_digest,
                        requester,
                        create_ledger: None,
                    })
                    .await,
                Ok(crate::node::subject_manager::SubjectManagerResponse::Up)
            ) {
                // Up failing (timeout, store error, overloaded node) is
                // transient: the subject may well exist.
                error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "SubjectManager::Up failed");
                return SubjectQuery::Unavailable;
            }
            self.subject_lifted = true;
            let Ok(actor) = ctx
                .system()
                .get_actor::<crate::tracker::Tracker>(&path)
                .await
            else {
                error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "Tracker not found after Up");
                return SubjectQuery::Unavailable;
            };
            match actor
                .ask(crate::tracker::TrackerMessage::GetSinkEvents {
                    from_sn,
                    batch_size,
                })
                .await
            {
                Ok(crate::tracker::TrackerResponse::SinkEvents(events)) => {
                    SubjectQuery::Events(events)
                }
                _ => {
                    // Distinguish a deleted subject (Up recreates a phantom
                    // tracker whose store is empty) from a transient query
                    // failure: a subject that exists always has at least its
                    // Create event, i.e. a last ledger entry.
                    match actor
                        .ask(crate::tracker::TrackerMessage::GetLastLedger)
                        .await
                    {
                        Ok(crate::tracker::TrackerResponse::LastLedger {
                            ledger_event,
                        }) if ledger_event.is_none() => SubjectQuery::NotFound,
                        _ => SubjectQuery::Unavailable,
                    }
                }
            }
        }
    }
}
