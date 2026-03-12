use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::SchemaType;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::model::common::emit_fail;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterDataSubj {
    pub schema_id: SchemaType,
    pub active: bool,
    pub namespace: String,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegisterDataGov {
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct Register;

#[derive(Debug, Clone)]
pub enum RegisterMessage {
    RegisterGov {
        gov_id: String,
        name: Option<String>,
        description: Option<String>,
    },
    EOLGov {
        gov_id: String,
    },
    RegisterSubj {
        gov_id: String,
        subject_id: String,
        schema_id: SchemaType,
        namespace: String,
        name: Option<String>,
        description: Option<String>,
    },
    EOLSubj {
        gov_id: String,
        subj_id: String,
    },
}

impl Message for RegisterMessage {
    fn is_critical(&self) -> bool {
        true
    }
}

#[derive(Debug, Clone)]
pub enum RegisterResponse {
    None,
}

impl Response for RegisterResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RegisterEvent {
    RegisterGov {
        gov_id: String,
        data: RegisterDataGov,
    },
    EOLGov {
        gov_id: String,
    },
    RegisterSubj {
        gov_id: String,
        subject_id: String,
        data: RegisterDataSubj,
    },
    EOLSubj {
        gov_id: String,
        subj_id: String,
    },
}

impl Event for RegisterEvent {}

impl NotPersistentActor for Register {}

#[async_trait]
impl Actor for Register {
    type Event = RegisterEvent;
    type Message = RegisterMessage;
    type Response = RegisterResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Register"),
            |parent_span| info_span!(parent: parent_span, "Register"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Register {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RegisterMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<RegisterResponse, ActorError> {
        let event = match msg {
            RegisterMessage::RegisterGov {
                gov_id,
                description,
                name,
            } => {
                debug!(
                    msg_type = "RegisterGov",
                    gov_id = %gov_id,
                    "Governance registration enqueued"
                );
                RegisterEvent::RegisterGov {
                    gov_id,
                    data: RegisterDataGov {
                        active: true,
                        name,
                        description,
                    },
                }
            }
            RegisterMessage::EOLGov { gov_id } => {
                debug!(
                    msg_type = "EOLGov",
                    gov_id = %gov_id,
                    "Governance EOL enqueued"
                );
                RegisterEvent::EOLGov { gov_id }
            }
            RegisterMessage::RegisterSubj {
                gov_id,
                subject_id,
                schema_id,
                namespace,
                name,
                description,
            } => {
                debug!(
                    msg_type = "RegisterSubj",
                    gov_id = %gov_id,
                    subject_id = %subject_id,
                    schema_id = %schema_id,
                    "Subject registration enqueued"
                );
                RegisterEvent::RegisterSubj {
                    gov_id,
                    subject_id,
                    data: RegisterDataSubj {
                        schema_id,
                        active: true,
                        namespace,
                        name,
                        description,
                    },
                }
            }
            RegisterMessage::EOLSubj { gov_id, subj_id } => {
                debug!(
                    msg_type = "EOLSubj",
                    gov_id = %gov_id,
                    subj_id = %subj_id,
                    "Subject EOL enqueued"
                );
                RegisterEvent::EOLSubj { gov_id, subj_id }
            }
        };

        self.on_event(event, ctx).await;
        Ok(RegisterResponse::None)
    }

    async fn on_event(
        &mut self,
        event: RegisterEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = ctx.publish_event(event.clone()).await {
            error!(error = %e, event = ?event, "Failed to publish register event");
            emit_fail(ctx, e).await;
        } else {
            debug!(event = ?event, "Register event published successfully");
        }
    }
}
