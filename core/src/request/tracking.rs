use std::num::NonZeroUsize;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::{
    identity::{DigestIdentifier, PublicKey},
    response::{RequestInfo, RequestInfoExtend, RequestState},
};
use borsh::{BorshDeserialize, BorshSerialize};
use lru::LruCache;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, info_span, warn};

#[derive(Clone, Debug)]
pub struct RequestTracking {
    cache: LruCache<DigestIdentifier, RequestInfo>,
}

impl RequestTracking {
    pub fn new(size: usize) -> Self {
        let size = if size == 0 { 100 } else { size };

        // `size` is non-zero by construction; the fallback below only
        // silences the type system and never runs.
        debug_assert!(size > 0);
        let size = NonZeroUsize::new(size).unwrap_or(NonZeroUsize::MIN);
        Self {
            cache: LruCache::new(size),
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
    /// System watchdog incident (node monitoring, NOT a request
    /// verdict): published to sinks (the query database records it
    /// in `aborts` with `abort_type` "Watchdog") without touching
    /// the request cache below.
    WatchdogIncident {
        request_id: DigestIdentifier,
        subject_id: DigestIdentifier,
        gov_version: u64,
        who: PublicKey,
        detail: String,
        phase: &'static str,
        expected_secs: u64,
        elapsed_secs: u64,
        node_version: String,
        timestamp_nanos: u64,
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
    type SinkEvent = RequestTrackingEvent;
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("RequestTracking"),
            |parent_span| info_span!(parent: parent_span, "RequestTracking"),
        )
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
    /// Watchdog incidents only (`None` for request aborts): phase
    /// that stopped producing.
    pub watchdog_phase: Option<String>,
    /// Watchdog incidents only: budget seconds the phase was given.
    pub watchdog_expected_secs: Option<u64>,
    /// Watchdog incidents only: seconds actually elapsed.
    pub watchdog_elapsed_secs: Option<u64>,
    /// Watchdog incidents only: binary version that fired.
    pub watchdog_node_version: Option<String>,
    /// Watchdog incidents only: wall-clock fire time.
    pub watchdog_timestamp_nanos: Option<u64>,
}

/// Marker telling the query database to file the record in
/// `watchdog_incidents` instead of `aborts`: a node-monitoring
/// event is not a request verdict and must never mix with them.
pub const WATCHDOG_ABORT_TYPE: &str = "Watchdog";

impl RequestTrackingEvent {
    /// Watchdog incidents reuse `sn` to carry `gov_version` and
    /// `error` to carry the diagnosis sentence, so the struct shape
    /// (and its Borsh encoding) stays frozen. Read incidents only
    /// through these accessors, never via `sn`/`error` directly.
    pub fn incident_gov_version(&self) -> u64 {
        self.sn.unwrap_or(0)
    }

    /// See [`RequestTrackingEvent::incident_gov_version`].
    pub fn incident_detail(&self) -> &str {
        &self.error
    }
}

impl Event for RequestTrackingEvent {}

#[async_trait]
impl Handler<Self> for RequestTracking {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: RequestTrackingMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
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
                    self.cache
                        .iter()
                        .map(|x| RequestInfoExtend {
                            request_id: x.0.to_string(),
                            state: x.1.state.clone(),
                            version: x.1.version,
                        })
                        .collect(),
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
                        watchdog_phase: None,
                        watchdog_expected_secs: None,
                        watchdog_elapsed_secs: None,
                        watchdog_node_version: None,
                        watchdog_timestamp_nanos: None,
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
                        watchdog_phase: None,
                        watchdog_expected_secs: None,
                        watchdog_elapsed_secs: None,
                        watchdog_node_version: None,
                        watchdog_timestamp_nanos: None,
                    }),
                    _ => None,
                };

                if let Some(event) = event {
                    self.on_event(event, ctx).await;
                }

                Ok(RequestTrackingResponse::Ok)
            }
            RequestTrackingMessage::WatchdogIncident {
                request_id,
                subject_id,
                gov_version,
                who,
                detail,
                phase,
                expected_secs,
                elapsed_secs,
                node_version,
                timestamp_nanos,
            } => {
                // System incident, not a request verdict: straight to
                // sinks (query database `watchdog_incidents` table)
                // without touching the request cache.
                self.on_event(
                    RequestTrackingEvent {
                        request_id: request_id.to_string(),
                        abort_type: WATCHDOG_ABORT_TYPE.to_owned(),
                        error: detail,
                        sn: Some(gov_version),
                        subject_id: subject_id.to_string(),
                        who: who.to_string(),
                        watchdog_phase: Some(phase.to_owned()),
                        watchdog_expected_secs: Some(expected_secs),
                        watchdog_elapsed_secs: Some(elapsed_secs),
                        watchdog_node_version: Some(node_version),
                        watchdog_timestamp_nanos: Some(timestamp_nanos),
                    },
                    ctx,
                )
                .await;

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
                self.cache.get(&request_id).map_or_else(
                    || {
                        debug!(
                            msg_type = "SearchRequest",
                            request_id = %request_id,
                            "Request not found in cache"
                        );
                        Ok(RequestTrackingResponse::NotFound)
                    },
                    |info| {
                        debug!(
                            msg_type = "SearchRequest",
                            request_id = %request_id,
                            state = ?info.state,
                            version = info.version,
                            "Request found in cache"
                        );
                        Ok(RequestTrackingResponse::Info(info.clone()))
                    },
                )
            }
        }
    }

    async fn on_event(
        &mut self,
        event: RequestTrackingEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        ctx.publish_all(event);
    }
}
