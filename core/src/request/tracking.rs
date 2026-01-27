use std::num::NonZeroUsize;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message, NotPersistentActor,
    Response,
};
use ave_common::response::{RequestInfo, RequestState};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span};

const TARGET_TRACKING: &str = "Ave-Request-RequestTracking";

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
    SearchRequest(String),
}

#[derive(Debug, Clone)]
pub enum RequestTrackingResponse {
    Ok,
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
            RequestTrackingMessage::UpdateState {
                request_id,
                state,
                error,
            } => {
                if let Some(info) = self.cache.get_mut(&request_id) {
                    info.state = state;
                    if error.is_some() {
                        info.error = error;
                    }
                } else {
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
                    info.version = version;
                } else {
                    error!(
                        TARGET_TRACKING,
                        "An attempt was made to update the version of a request that is not registered. {}",
                        request_id
                    );
                };

                Ok(RequestTrackingResponse::Ok)
            }
            RequestTrackingMessage::SearchRequest(request_id) => {
                if let Some(info) = self.cache.get(&request_id) {
                    Ok(RequestTrackingResponse::Info(info.clone()))
                } else {
                    Ok(RequestTrackingResponse::NotFound)
                }
            }
        }
    }
}
