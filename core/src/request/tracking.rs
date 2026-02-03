use std::num::NonZeroUsize;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message, NotPersistentActor,
    Response,
};
use ave_common::{response::{RequestInfo, RequestState}};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, info_span, warn};

#[derive(Clone, Debug)]
pub struct RequestTracking {
    cache: LruCache<String, RequestInfo>,
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
        request_id: String,
        state: RequestState,
        error: Option<String>,
    },
    UpdateVersion {
        request_id: String,
        version: u64,
    },
    AllRequests,
    SearchRequest(String),
}

#[derive(Debug, Clone)]
pub enum RequestTrackingResponse {
    Ok,
    AllInfo(Vec<RequestInfo>),
    Info(RequestInfo),
    NotFound,
}

impl Response for RequestTrackingResponse {}

impl Message for RequestTrackingMessage {}

#[async_trait]
impl Actor for RequestTracking {
    type Message = RequestTrackingMessage;
    type Event = ();
    type Response = RequestTrackingResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RequestTracking", id = id)
        } else {
            info_span!("RequestTracking", id = id)
        }
    }
}

#[async_trait]
impl Handler<RequestTracking> for RequestTracking {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RequestTrackingMessage,
        _ctx: &mut ave_actors::ActorContext<RequestTracking>,
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
                    self.cache.iter().map(|x| x.1.clone()).collect(),
                ))
            }
            RequestTrackingMessage::UpdateState {
                request_id,
                state,
                error,
            } => {
                if let Some(info) = self.cache.get_mut(&request_id) {
                    let old_state = info.state.clone();
                    info.state = state.clone();
                    if let Some(ref err) = error {
                        info.error = error.clone();
                        warn!(
                            msg_type = "UpdateState",
                            request_id = %request_id,
                            old_state = ?old_state,
                            new_state = ?state,
                            error = %err,
                            "Request state updated with error"
                        );
                    } else {
                        debug!(
                            msg_type = "UpdateState",
                            request_id = %request_id,
                            old_state = ?old_state,
                            new_state = ?state,
                            "Request state updated"
                        );
                    }
                } else {
                    if let Some(ref err) = error {
                        warn!(
                            msg_type = "UpdateState",
                            request_id = %request_id,
                            state = ?state,
                            error = %err,
                            "New request tracked with error"
                        );
                    } else {
                        debug!(
                            msg_type = "UpdateState",
                            request_id = %request_id,
                            state = ?state,
                            "New request tracked"
                        );
                    }
                    self.cache.put(
                        request_id,
                        RequestInfo {
                            state,
                            version: 0,
                            error,
                        },
                    );
                };

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
}
