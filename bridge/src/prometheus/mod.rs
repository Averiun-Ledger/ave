use std::sync::Arc;

use axum::{Extension, Router, response::IntoResponse, routing::get};
use prometheus_client::{encoding::text::encode, registry::Registry};
use tokio::sync::Mutex;

pub async fn handler_prometheus_data(
    Extension(state): Extension<Arc<Mutex<Registry>>>,
) -> impl IntoResponse {
    let mut body = String::new();
    let registry = state.lock().await;
    if let Err(e) = encode(&mut body, &*registry) {
        return (
            [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
            format!("Error encoding Prometheus metrics: {}", e),
        );
    };

    (
        [("Content-Type", "text/plain; version=0.0.4; charset=utf-8")],
        body,
    )
}

pub fn build_routes(registry: Arc<Mutex<Registry>>) -> Router {
    Router::new()
        .route("/metrics", get(handler_prometheus_data))
        .layer(Extension(registry))
}
