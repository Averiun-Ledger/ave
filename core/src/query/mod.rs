use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::{identity::DigestIdentifier, response::{LedgerDB, PaginatorAborts, PaginatorEvents, SubjectDB, TimeRange}};
use serde::{Deserialize, Serialize};
use tracing::{Span, info_span};

use crate::helpers::db::{
    ExternalDB, Querys
};

pub struct Query {
    db: Arc<ExternalDB>,
}

impl Query {
    pub fn new(db: Arc<ExternalDB>) -> Self {
        Self { db }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum QueryMessage {
    GetEvents {
        subject_id: DigestIdentifier,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
        event_request_ts: Option<TimeRange>,
        event_ledger_ts: Option<TimeRange>,
        sink_ts: Option<TimeRange>,
    },
    GetAborts {
        subject_id: DigestIdentifier,
        request_id: Option<String>,
        sn: Option<u64>,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    },
    GetEventSn {
        subject_id: DigestIdentifier,
        sn: u64,
    },
    GetFirstOrEndEvents {
        subject_id: DigestIdentifier,
        quantity: Option<u64>,
        reverse: Option<bool>,
    },
    GetSubject {
        subject_id: DigestIdentifier,
    },
}

impl Message for QueryMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum QueryResponse {
    Error(String),
    PagEvents(PaginatorEvents),
    PagAborts(PaginatorAborts),
    Event(LedgerDB),
    Events(Vec<LedgerDB>),
    Subject(SubjectDB),
}

impl Response for QueryResponse {}

impl NotPersistentActor for Query {}

#[async_trait]
impl Actor for Query {
    type Message = QueryMessage;
    type Event = ();
    type Response = QueryResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Query")
        } else {
            info_span!("Query")
        }
    }

}

#[async_trait]
impl Handler<Query> for Query {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: QueryMessage,
        _ctx: &mut ave_actors::ActorContext<Query>,
    ) -> Result<QueryResponse, ActorError> {
        match msg {
            QueryMessage::GetEvents { subject_id, quantity, page, reverse, event_request_ts, event_ledger_ts, sink_ts } => {
                match self.db.get_events(&subject_id.to_string(), quantity, page, reverse, event_request_ts, event_ledger_ts, sink_ts).await {
                    Ok(data) => Ok(QueryResponse::PagEvents(data)),
                    Err(e) => Ok(QueryResponse::Error(e.to_string()))
                }
            },
            QueryMessage::GetAborts { subject_id, request_id, sn, quantity, page, reverse } => {
                match self.db.get_aborts(&subject_id.to_string(), request_id, sn, quantity, page, reverse).await {
                    Ok(data) => Ok(QueryResponse::PagAborts(data)),
                    Err(e) => Ok(QueryResponse::Error(e.to_string()))
                }
            },
            QueryMessage::GetEventSn { subject_id, sn } => {
                match self.db.get_event_sn(&subject_id.to_string(), sn).await {
                    Ok(data) => Ok(QueryResponse::Event(data)),
                    Err(e) => Ok(QueryResponse::Error(e.to_string()))
                }
            },
            QueryMessage::GetFirstOrEndEvents { subject_id, quantity, reverse } => {
                match self.db.get_first_or_end_events(&subject_id.to_string(), quantity, reverse).await {
                    Ok(data) => Ok(QueryResponse::Events(data)),
                    Err(e) => Ok(QueryResponse::Error(e.to_string()))
                }
            },
            QueryMessage::GetSubject { subject_id } => {
                match self.db.get_subject_state(&subject_id.to_string()).await {
                    Ok(data) => Ok(QueryResponse::Subject(data)),
                    Err(e) => Ok(QueryResponse::Error(e.to_string()))
                }
            },
        }
    }
}
