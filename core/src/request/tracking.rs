use std::num::NonZeroUsize;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::{
    identity::DigestIdentifier,
    response::{RequestInfo, RequestInfoExtend, RequestState},
};
use borsh::{BorshDeserialize, BorshSerialize};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

#[derive(Clone, Debug)]
pub struct RequestTracking {
    cache: LruCache<DigestIdentifier, RequestInfo>,
}

impl RequestTracking {
    pub fn new(size: usize) -> Self {
        let size = if size == 0 { 100 } else { size };

        Self {
            cache: LruCache::new(NonZeroUsize::new(size).expect("size > 0")),
        }
    }
}

impl NotPersistentActor for RequestTracking {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RequestTrackingMessage {
    UpdateState {
        request_id: DigestIdentifier,
        state: RequestState,
    },
    UpdateVersion {
        request_id: DigestIdentifier,
        version: u64,
    },
    AllRequests,
    SearchRequest(DigestIdentifier),
}

#[derive(Debug, Clone)]
pub enum RequestTrackingResponse {
    Ok,
    AllInfo(Vec<RequestInfoExtend>),
    Info(RequestInfo),
    NotFound,
}

impl Response for RequestTrackingResponse {}

impl Message for RequestTrackingMessage {}

#[async_trait]
impl Actor for RequestTracking {
    type Message = RequestTrackingMessage;
    type Event = RequestTrackingEvent;
    type Response = RequestTrackingResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RequestTracking")
        } else {
            info_span!("RequestTracking")
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RequestTrackingEvent {
    pub request_id: String,
    pub subject_id: String,
    pub sn: Option<u64>,
    pub error: String,
    pub who: String,
    pub abort_type: String,
}

impl Event for RequestTrackingEvent {}

#[async_trait]
impl Handler<RequestTracking> for RequestTracking {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RequestTrackingMessage,
        ctx: &mut ave_actors::ActorContext<RequestTracking>,
    ) -> Result<RequestTrackingResponse, ActorError> {
        match msg {
            RequestTrackingMessage::AllRequests => {
                let count = self.cache.len();
                debug!(
                    msg_type = "AllRequests",
                    requests_count = count,
                    "Retrieving all tracked requests"
                );
                Ok(RequestTrackingResponse::AllInfo(
                    self.cache.iter().map(|x| RequestInfoExtend { request_id: x.0.to_string(), state: x.1.state.clone(), version: x.1.version.clone() }).collect(),
                ))
            }
            RequestTrackingMessage::UpdateState { request_id, state } => {
                if let Some(info) = self.cache.get_mut(&request_id) {
                    let old_state = info.state.clone();
                    info.state = state.clone();
                    debug!(
                        msg_type = "UpdateState",
                        request_id = %request_id,
                        old_state = ?old_state,
                        new_state = ?state,
                        "Request state updated"
                    );
                } else {
                    self.cache.put(
                        request_id.clone(),
                        RequestInfo {
                            state: state.clone(),
                            version: 0,
                        },
                    );

                    debug!(
                        msg_type = "UpdateState",
                        request_id = %request_id,
                        state = ?state,
                        "New request tracked"
                    );
                };

                let event = match state {
                    RequestState::Invalid {
                        subject_id,
                        who,
                        sn,
                        error,
                    } => Some(RequestTrackingEvent {
                        request_id: request_id.to_string(),
                        abort_type: "Invalid".to_string(),
                        error,
                        sn,
                        subject_id,
                        who,
                    }),
                    RequestState::Abort {
                        subject_id,
                        who,
                        sn,
                        error,
                    } => Some(RequestTrackingEvent {
                        request_id: request_id.to_string(),
                        abort_type: "Abort".to_string(),
                        error,
                        sn,
                        subject_id,
                        who,
                    }),
                    _ => None,
                };

                if let Some(event) = event {
                    self.on_event(event, ctx).await;
                }

                Ok(RequestTrackingResponse::Ok)
            }
            RequestTrackingMessage::UpdateVersion {
                request_id,
                version,
            } => {
                if let Some(info) = self.cache.get_mut(&request_id) {
                    let old_version = info.version;
                    info.version = version;
                    debug!(
                        msg_type = "UpdateVersion",
                        request_id = %request_id,
                        old_version = old_version,
                        new_version = version,
                        "Request version updated"
                    );
                } else {
                    warn!(
                        msg_type = "UpdateVersion",
                        request_id = %request_id,
                        version = version,
                        "Request not found in cache"
                    );
                };

                Ok(RequestTrackingResponse::Ok)
            }
            RequestTrackingMessage::SearchRequest(request_id) => {
                if let Some(info) = self.cache.get(&request_id) {
                    debug!(
                        msg_type = "SearchRequest",
                        request_id = %request_id,
                        state = ?info.state,
                        version = info.version,
                        "Request found in cache"
                    );
                    Ok(RequestTrackingResponse::Info(info.clone()))
                } else {
                    debug!(
                        msg_type = "SearchRequest",
                        request_id = %request_id,
                        "Request not found in cache"
                    );
                    Ok(RequestTrackingResponse::NotFound)
                }
            }
        }
    }

    async fn on_event(
        &mut self,
        event: RequestTrackingEvent,
        ctx: &mut ActorContext<RequestTracking>,
    ) {
        if let Err(e) = ctx.publish_event(event).await {
            error!(
                error = %e,
                "Failed to publish event"
            );
            ctx.system().stop_system();
        };
    }
}
