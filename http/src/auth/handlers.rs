use super::store::AuthStore;
use axum::{Extension, Json, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;
use utoipa::ToSchema;

#[derive(Debug, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct LoginResponse {
    pub api_key: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

/// Login
///
/// Authenticates a user with username and password, returning an API key.
/// The API key must be included in the `X-API-Key` header for all subsequent requests.
///
/// # Parameters
///
/// * `Extension(auth_store): Extension<Arc<RwLock<AuthStore>>>` - The authentication store
/// * `Json(req): Json<LoginRequest>` - Login credentials (username and password)
///
/// # Returns
///
/// * `Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)>` - API key on success, error on failure
#[utoipa::path(
    post,
    path = "/auth/login",
    operation_id = "Login",
    tag = "Authentication",
    request_body(
        content = LoginRequest,
        content_type = "application/json",
        description = "User credentials"
    ),
    responses(
        (status = 200, description = "Login successful", body = LoginResponse,
        example = json!(
            {
                "api_key": "ave_v1_kT9mPqR7sLnX2wY5eH8jB4vC6fG1dA"
            }
        )),
        (status = 401, description = "Invalid credentials", body = ErrorResponse,
        example = json!(
            {
                "error": "Invalid username or password"
            }
        )),
    )
)]
pub async fn login(
    Extension(auth_store): Extension<Arc<RwLock<AuthStore>>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let mut store = auth_store.write().await;

    match store.login(&req.username, &req.password) {
        Some(api_key) => Ok(Json(LoginResponse { api_key })),
        None => Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse {
                error: "Invalid username or password".to_string(),
            }),
        )),
    }
}
