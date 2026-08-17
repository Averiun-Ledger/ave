use std::sync::Arc;

use axum::{
    Extension, Router, http::StatusCode, response::IntoResponse, routing::get,
};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::sync::Mutex;

pub async fn handler_prometheus_data(
    Extension(state): Extension<Arc<Mutex<Registry>>>,
) -> impl IntoResponse {
    let mut body = String::new();
    let registry = state.lock().await;
    if let Err(e) = encode(&mut body, &registry) {
        // A 200 with an error body would be scraped as valid (but empty)
        // metrics and the failure would be invisible in monitoring.
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
            format!("Error encoding Prometheus metrics: {}", e),
        );
    };

    (
        StatusCode::OK,
        [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

pub fn build_routes(registry: Arc<Mutex<Registry>>) -> Router {
    Router::new()
        .route("/metrics", get(handler_prometheus_data))
        .layer(Extension(registry))
}
