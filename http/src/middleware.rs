use std::time::Duration;
use tower_http::{classify::ServerErrorsFailureClass, trace::TraceLayer};
use tracing::{Span, debug, info_span, trace, warn};

const TARGET: &str = "ave::http";

use axum::{
    Router,
    body::Bytes,
    extract::{MatchedPath, Request},
    http::HeaderMap,
    response::Response,
};

pub fn tower_trace(routes: Router) -> Router {
    routes.layer(
        TraceLayer::new_for_http()
            .make_span_with(|request: &Request<_>| {
                let matched_path = request
                    .extensions()
                    .get::<MatchedPath>()
                    .map(MatchedPath::as_str);

                info_span!(
                    "http_request",
                    method = %request.method(),
                    matched_path,
                )
            })
            .on_request(|request: &Request<_>, _span: &Span| {
                debug!(
                    target: TARGET,
                    method = %request.method(),
                    path = %request.uri().path(),
                    "request received"
                )
            })
            .on_response(
                |response: &Response, latency: Duration, _span: &Span| {
                    debug!(
                        target: TARGET,
                        status = response.status().as_u16(),
                        latency_ms = latency.as_millis(),
                        "response sent"
                    )
                },
            )
            .on_body_chunk(|chunk: &Bytes, _latency: Duration, _span: &Span| {
                trace!(target: TARGET, bytes = chunk.len(), "sending body chunk")
            })
            .on_eos(
                |_trailers: Option<&HeaderMap>,
                 stream_duration: Duration,
                 _span: &Span| {
                    trace!(
                        target: TARGET,
                        duration_ms = stream_duration.as_millis(),
                        "stream closed"
                    )
                },
            )
            .on_failure(
                |error: ServerErrorsFailureClass,
                 latency: Duration,
                 _span: &Span| {
                    warn!(
                        target: TARGET,
                        error = %error,
                        latency_ms = latency.as_millis(),
                        "request failed"
                    )
                },
            ),
    )
}
