//! SinkSubjectWorker: ephemeral child actor that handles a single subject.

use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response,
};
use serde::{Deserialize, Serialize};
use tracing::{error, info_span};

use crate::config::SinkServer;
use crate::sink::SinkError;
use crate::sink::extract_sn;
use crate::sink::http::SinkHttpClient;
use crate::sink::worker::{
    SinkSubjectWorkerError, SinkWorker, SinkWorkerMessage,
};
use ave_common::{DataToSink, LightEvent, SinkTypes};

// ---------------------------------------------------------------------------
// Messages
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkSubjectWorkerMessage {
    DeliverEvent(Arc<DataToSink>),
    CatchUpBatch {
        from_sn: u64,
        batch_size: usize,
    },
    ProcessNextEvent {
        data: Arc<DataToSink>,
        remaining: Vec<DataToSink>,
    },
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
    client: Arc<SinkHttpClient>,
    paused: bool,
    /// `true` when this worker handles governance events (parent SinkManager
    /// is under Node). `false` when it handles tracker events (parent is under
    /// Governance).
    is_governance: bool,
}

impl std::fmt::Debug for SinkSubjectWorker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SinkSubjectWorker")
            .field("sink_name", &self.sink_name)
            .field("server", &self.server.server)
            .field("paused", &self.paused)
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
}

#[async_trait]
impl Handler<SinkSubjectWorker> for SinkSubjectWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkSubjectWorkerMessage,
        ctx: &mut ActorContext<SinkSubjectWorker>,
    ) -> Result<SinkSubjectWorkerResponse, ActorError> {
        match msg {
            SinkSubjectWorkerMessage::DeliverEvent(data) => {
                if self.paused {
                    return Ok(SinkSubjectWorkerResponse::Ok);
                }

                let (subject_id, _schema_id) =
                    data.payload.get_subject_schema();
                let sn = extract_sn(&data);
                let event_type = SinkTypes::from(data.as_ref());

                let send_full = self.server.events.contains(&event_type)
                    || self.server.events.contains(&SinkTypes::All);
                let send_result = if send_full {
                    self.client.send_data_to_sink(Arc::clone(&data)).await
                } else {
                    let light = LightEvent::from(data.as_ref());
                    self.client.send_light_event(light).await
                };

                match send_result {
                    Ok(()) => match ctx.get_parent::<SinkWorker>().await {
                        Ok(parent) => {
                            if let Err(e) = parent
                                    .tell(SinkWorkerMessage::DeliveryResult {
                                        subject_id,
                                        sn,
                                        result: crate::sink::manager::SendResult::Success,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report delivery result");
                                }
                        }
                        Err(e) => {
                            error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                        }
                    },
                    Err(e) if e.is_auth_recoverable() => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(
                                        SinkSubjectWorkerError::AuthFailed {
                                            subject_id,
                                            sn,
                                            error: e.to_string(),
                                            from_catch_up: false,
                                        },
                                    )
                                    .await
                                {
                                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report auth failed");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                    }
                    Err(SinkError::TokenParse(ref msg)) => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(SinkSubjectWorkerError::AuthFailed {
                                        subject_id,
                                        sn,
                                        error: format!("failed to parse token response: {}", msg),
                                        from_catch_up: false,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report auth failed");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                    }
                    Err(e) if !e.is_transient() => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(
                                        SinkSubjectWorkerError::Blocked {
                                            subject_id,
                                            sn,
                                            reason: e.to_string(),
                                        },
                                    )
                                    .await
                                {
                                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report blocked");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                    }
                    Err(e) => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(SinkSubjectWorkerError::DeliveryFailed {
                                        subject_id,
                                        sn,
                                        reason: e.to_string(),
                                        from_catch_up: false,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportProgress", sink = %self.sink_name, error = %e, "Failed to report delivery failed");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                    }
                }

                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::CatchUpBatch {
                from_sn,
                batch_size,
            } => {
                let subject_id = ctx.path().key().to_owned();
                let events = match self
                    .query_subject(&subject_id, from_sn, batch_size, ctx)
                    .await
                {
                    Some(events) => events,
                    None => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(SinkSubjectWorkerError::SubjectNotFound {
                                        subject_id,
                                        sn: 0,
                                        from_catch_up: true,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportSubjectNotFound", sink = %self.sink_name, error = %e, "Failed to report subject not found");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                        return Ok(SinkSubjectWorkerResponse::Ok);
                    }
                };

                if events.is_empty() {
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
                    return Ok(SinkSubjectWorkerResponse::Ok);
                }

                let mut events = events;
                let event = events.remove(0);
                let remaining = events;
                let self_ref = ctx.reference().await?;
                if let Err(e) = self_ref
                    .tell(SinkSubjectWorkerMessage::ProcessNextEvent {
                        data: Arc::new(event),
                        remaining,
                    })
                    .await
                {
                    error!(msg_type = "ProcessNextEvent", sink = %self.sink_name, error = %e, "Failed to send ProcessNextEvent to self");
                }
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::ProcessNextEvent { data, remaining } => {
                let (subject_id, _schema_id) =
                    data.payload.get_subject_schema();
                let sn = extract_sn(&data);
                let event_type = SinkTypes::from(data.as_ref());

                let send_full = self.server.events.contains(&event_type)
                    || self.server.events.contains(&SinkTypes::All);
                let send_result = if send_full {
                    self.client.send_data_to_sink(Arc::clone(&data)).await
                } else {
                    let light = LightEvent::from(data.as_ref());
                    self.client.send_light_event(light).await
                };

                match send_result {
                    Ok(()) => match ctx.get_parent::<SinkWorker>().await {
                        Ok(parent) => {
                            if let Err(e) = parent
                                    .tell(SinkWorkerMessage::CatchUpProgress {
                                        subject_id: subject_id.clone(),
                                        sn,
                                        result: crate::sink::manager::SendResult::Success,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportCatchUpProgress", sink = %self.sink_name, error = %e, "Failed to report catch-up progress");
                                }
                        }
                        Err(e) => {
                            error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                        }
                    },
                    Err(e) if e.is_auth_recoverable() => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(
                                        SinkSubjectWorkerError::AuthFailed {
                                            subject_id: subject_id.clone(),
                                            sn,
                                            error: e.to_string(),
                                            from_catch_up: true,
                                        },
                                    )
                                    .await
                                {
                                    error!(msg_type = "ReportCatchUpProgress", sink = %self.sink_name, error = %e, "Failed to report catch-up progress");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                        return Ok(SinkSubjectWorkerResponse::Ok);
                    }
                    Err(SinkError::TokenParse(ref msg)) => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(SinkSubjectWorkerError::AuthFailed {
                                        subject_id: subject_id.clone(),
                                        sn,
                                        error: format!("failed to parse token response: {}", msg),
                                        from_catch_up: true,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportCatchUpProgress", sink = %self.sink_name, error = %e, "Failed to report catch-up progress");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                        return Ok(SinkSubjectWorkerResponse::Ok);
                    }
                    Err(e) if !e.is_transient() => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(
                                        SinkSubjectWorkerError::Blocked {
                                            subject_id: subject_id.clone(),
                                            sn,
                                            reason: e.to_string(),
                                        },
                                    )
                                    .await
                                {
                                    error!(msg_type = "ReportCatchUpProgress", sink = %self.sink_name, error = %e, "Failed to report catch-up progress");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                        return Ok(SinkSubjectWorkerResponse::Ok);
                    }
                    Err(e) => {
                        match ctx.get_parent::<SinkWorker>().await {
                            Ok(parent) => {
                                if let Err(e) = parent
                                    .emit_error(SinkSubjectWorkerError::DeliveryFailed {
                                        subject_id: subject_id.clone(),
                                        sn,
                                        reason: e.to_string(),
                                        from_catch_up: true,
                                    })
                                    .await
                                {
                                    error!(msg_type = "ReportCatchUpProgress", sink = %self.sink_name, error = %e, "Failed to report catch-up progress");
                                }
                            }
                            Err(e) => {
                                error!(msg_type = "GetParent", sink = %self.sink_name, error = %e, "Failed to get parent worker");
                            }
                        }
                        return Ok(SinkSubjectWorkerResponse::Ok);
                    }
                }

                if !remaining.is_empty() {
                    let mut remaining = remaining;
                    let next_event = remaining.remove(0);
                    let self_ref = ctx.reference().await?;
                    if let Err(e) = self_ref
                        .tell(SinkSubjectWorkerMessage::ProcessNextEvent {
                            data: Arc::new(next_event),
                            remaining,
                        })
                        .await
                    {
                        error!(msg_type = "ProcessNextEvent", sink = %self.sink_name, error = %e, "Failed to send ProcessNextEvent to self");
                    }
                } else {
                    let self_ref = ctx.reference().await?;
                    if let Err(e) = self_ref
                        .tell(SinkSubjectWorkerMessage::CatchUpBatch {
                            from_sn: sn + 1,
                            batch_size: self.server.batch_size,
                        })
                        .await
                    {
                        error!(msg_type = "CatchUpBatch", sink = %self.sink_name, error = %e, "Failed to send CatchUpBatch to self");
                    }
                }

                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::Pause => {
                self.paused = true;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::Resume => {
                self.paused = false;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
            SinkSubjectWorkerMessage::Stop => {
                ctx.stop(None).await;
                Ok(SinkSubjectWorkerResponse::Ok)
            }
        }
    }
}

impl SinkSubjectWorker {
    pub fn new(
        sink_name: String,
        server: SinkServer,
        client: Arc<SinkHttpClient>,
        is_governance: bool,
    ) -> Self {
        Self {
            sink_name,
            server,
            client,
            paused: false,
            is_governance,
        }
    }

    async fn query_subject(
        &self,
        subject_id: &str,
        from_sn: u64,
        batch_size: usize,
        ctx: &mut ActorContext<SinkSubjectWorker>,
    ) -> Option<Vec<DataToSink>> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            subject_id
        ));
        if self.is_governance {
            // Governances are always in memory; access directly.
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
                    )) => Some(events),
                    _ => None,
                }
            } else {
                error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "Governance not found for catch-up query");
                None
            }
        } else {
            // Trackers may not be in memory; lift via SubjectManager::Up first.
            let subject_manager_path =
                ActorPath::from("/user/node/subject_manager");
            if let Ok(subject_manager) = ctx
                .system()
                .get_actor::<crate::node::subject_manager::SubjectManager>(
                    &subject_manager_path,
                )
                .await
            {
                let requester =
                    format!("sink:{}:{}", self.sink_name, subject_id);
                let subject_id_digest =
                    match subject_id
                        .parse::<ave_common::identity::DigestIdentifier>()
                    {
                        Ok(d) => d,
                        Err(_) => {
                            error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "Invalid subject_id format");
                            return None;
                        }
                    };
                if let Ok(crate::node::subject_manager::SubjectManagerResponse::Up) = subject_manager
                    .ask(crate::node::subject_manager::SubjectManagerMessage::Up {
                        subject_id: subject_id_digest,
                        requester,
                        create_ledger: None,
                    })
                    .await
                {
                    if let Ok(actor) = ctx.system().get_actor::<crate::tracker::Tracker>(&path).await {
                        match actor
                            .ask(crate::tracker::TrackerMessage::GetSinkEvents {
                                from_sn,
                                batch_size,
                            })
                            .await
                        {
                            Ok(crate::tracker::TrackerResponse::SinkEvents(events)) => Some(events),
                            _ => None,
                        }
                    } else {
                        error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "Tracker not found after Up");
                        None
                    }
                } else {
                    error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "SubjectManager::Up failed");
                    None
                }
            } else {
                error!(msg_type = "CatchUpQuery", subject_id = %subject_id, "SubjectManager not found");
                None
            }
        }
    }
}
