use super::store::AuthStore;
use axum::{
    extract::FromRequestParts,
    http::{request::Parts, StatusCode},
    response::{IntoResponse, Response},
    Json,
};
use serde::Serialize;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Extractor that validates API key from X-API-Key header
///
/// Usage in handlers:
/// ```
/// async fn my_handler(
///     _auth: ApiKeyAuth,  // Validates automatically
///     // ... other extractors
/// ) -> Result<...> {
///     // Handler code
/// }
/// ```
pub struct ApiKeyAuth;

#[derive(Serialize)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::UNAUTHORIZED, Json(self)).into_response()
    }
}

impl<S> FromRequestParts<S> for ApiKeyAuth
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send {
        async move {
            // Check if authentication is enabled
            let auth_store = parts.extensions.get::<Arc<RwLock<AuthStore>>>().cloned();

            // If auth is disabled, allow all requests
            if auth_store.is_none() {
                return Ok(ApiKeyAuth);
            }

            // Auth is enabled - validate API key
            let api_key = parts
                .headers
                .get("X-API-Key")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_string())
                .ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse {
                            error: "Missing X-API-Key header".to_string(),
                        }),
                    )
                })?;

            // Validate the API key
            let store_arc = auth_store.unwrap();
            let store = store_arc.read().await;
            if store.validate_key(&api_key) {
                Ok(ApiKeyAuth)
            } else {
                Err((
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Invalid or expired API key".to_string(),
                    }),
                ))
            }
        }
    }
}
