use std::fmt::Display;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::{DataToSink, DataToSinkEvent, identity::TimeStamp};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::{model::common::emit_fail, subject::Metadata};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SinkData {
    pub public_key: String,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd,
)]
pub enum SinkTypes {
    Create,
    Fact,
    Transfer,
    Confirm,
    Reject,
    EOL,
    Abort,
    All,
}

impl Display for SinkTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "Create"),
            Self::Fact => write!(f, "Fact"),
            Self::Transfer => write!(f, "Transfer"),
            Self::Confirm => write!(f, "Confirm"),
            Self::Reject => write!(f, "Reject"),
            Self::EOL => write!(f, "EOL"),
            Self::Abort => write!(f, "Abort"),
            Self::All => write!(f, "All"),
        }
    }
}

impl From<&DataToSink> for SinkTypes {
    fn from(value: &DataToSink) -> Self {
        match value.event {
            DataToSinkEvent::Create { .. } => Self::Create,
            DataToSinkEvent::Fact { .. } => Self::Fact,
            DataToSinkEvent::Transfer { .. } => Self::Transfer,
            DataToSinkEvent::Confirm { .. } => Self::Confirm,
            DataToSinkEvent::Reject { .. } => Self::Reject,
            DataToSinkEvent::Eol { .. } => Self::EOL,
            DataToSinkEvent::Abort { .. } => Self::Abort,
        }
    }
}

impl From<String> for SinkTypes {
    fn from(value: String) -> Self {
        match value.trim() {
            "Create" => Self::Create,
            "Fact" => Self::Fact,
            "Transfer" => Self::Transfer,
            "Confirm" => Self::Confirm,
            "Reject" => Self::Reject,
            "EOL" => Self::EOL,
            "Abort" => Self::Abort,
            _ => Self::All,
        }
    }
}

impl SinkDataMessage {
    pub fn get_subject_schema(&self) -> (String, String) {
        match self {
            Self::UpdateState(metadata) => (
                metadata.subject_id.to_string(),
                metadata.schema_id.to_string(),
            ),
            Self::Event { event, .. } => match &**event {
                DataToSinkEvent::Create {
                    subject_id,
                    schema_id,
                    ..
                }
                | DataToSinkEvent::Fact {
                    subject_id,
                    schema_id,
                    ..
                }
                | DataToSinkEvent::Transfer {
                    subject_id,
                    schema_id,
                    ..
                }
                | DataToSinkEvent::Confirm {
                    subject_id,
                    schema_id,
                    ..
                }
                | DataToSinkEvent::Reject {
                    subject_id,
                    schema_id,
                    ..
                }
                | DataToSinkEvent::Eol {
                    subject_id,
                    schema_id,
                    ..
                }
                | DataToSinkEvent::Abort {
                    subject_id,
                    schema_id,
                    ..
                } => (subject_id.clone(), schema_id.to_string()),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkDataMessage {
    UpdateState(Box<Metadata>),
    Event {
        event: Box<DataToSinkEvent>,
        event_request_timestamp: u64,
        event_ledger_timestamp: u64,
    },
}

impl Message for SinkDataMessage {}

impl NotPersistentActor for SinkData {}

#[derive(Debug, Clone)]
pub enum SinkDataResponse {
    None,
}

impl Response for SinkDataResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkDataEvent {
    Event(Box<DataToSink>),
    State(Box<Metadata>),
}

impl Event for SinkDataEvent {}

#[async_trait]
impl Actor for SinkData {
    type Event = SinkDataEvent;
    type Message = SinkDataMessage;
    type Response = SinkDataResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("SinkData"),
            |parent_span| info_span!(parent: parent_span, "SinkData"),
        )
    }
}

#[async_trait]
impl Handler<Self> for SinkData {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SinkDataMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<SinkDataResponse, ActorError> {
        let (subject_id, schema_id) = msg.get_subject_schema();
        let msg_type = match &msg {
            SinkDataMessage::UpdateState(..) => "UpdateState",
            SinkDataMessage::Event { event, .. } => match &**event {
                DataToSinkEvent::Create { .. } => "Create",
                DataToSinkEvent::Fact { .. } => "Fact",
                DataToSinkEvent::Transfer { .. } => "Transfer",
                DataToSinkEvent::Confirm { .. } => "Confirm",
                DataToSinkEvent::Reject { .. } => "Reject",
                DataToSinkEvent::Eol { .. } => "EOL",
                DataToSinkEvent::Abort { .. } => "Abort",
            },
        };

        let event = match msg {
            SinkDataMessage::UpdateState(metadata) => {
                SinkDataEvent::State(metadata)
            }
            SinkDataMessage::Event {
                event,
                event_request_timestamp,
                event_ledger_timestamp,
            } => SinkDataEvent::Event(Box::new(DataToSink {
                event: *event,
                public_key: self.public_key.clone(),
                event_request_timestamp,
                event_ledger_timestamp,
                sink_timestamp: TimeStamp::now().as_nanos(),
            })),
        };

        self.on_event(event, ctx).await;

        debug!(
            msg_type = msg_type,
            subject_id = %subject_id,
            schema_id = %schema_id,
            public_key = %self.public_key,
            "Sink data event processed"
        );

        Ok(SinkDataResponse::None)
    }

    async fn on_event(
        &mut self,
        event: SinkDataEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        let (subject_id, schema_id) = match &event {
            SinkDataEvent::Event(data_to_sink) => {
                data_to_sink.event.get_subject_schema()
            }
            SinkDataEvent::State(metadata) => (
                metadata.subject_id.to_string(),
                metadata.schema_id.to_string(),
            ),
        };
        if let Err(e) = ctx.publish_event(event.clone()).await {
            error!(
                error = %e,
                subject_id = %subject_id,
                schema_id = %schema_id,
                public_key = %self.public_key,
                "Failed to publish sink data event"
            );
            emit_fail(ctx, e).await;
        } else {
            debug!(
                subject_id = %subject_id,
                schema_id = %schema_id,
                "Sink data event published successfully"
            );
        }
    }
}
