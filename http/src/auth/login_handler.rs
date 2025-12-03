// Ave HTTP Auth System - Login Handler
//
// Database-backed login endpoint that returns full authentication context

use super::database::{AuthDatabase, DatabaseError};
use super::models::{ErrorResponse, LoginRequest, LoginResponse, UserInfo};
use axum::{Extension, Json, http::StatusCode};
use std::sync::Arc;

/// Convert DatabaseError to HTTP response tuple
fn db_error_to_response(
    err: DatabaseError,
) -> (StatusCode, Json<ErrorResponse>) {
    let (status, message) = match err {
        DatabaseError::NotFoundError(msg) => (StatusCode::NOT_FOUND, msg),
        DatabaseError::DuplicateError(msg) => (StatusCode::CONFLICT, msg),
        DatabaseError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
        DatabaseError::PermissionDenied(msg) => (StatusCode::UNAUTHORIZED, msg),
        DatabaseError::AccountLocked(msg) => (StatusCode::UNAUTHORIZED, msg),
        DatabaseError::RateLimitExceeded(msg) => {
            (StatusCode::TOO_MANY_REQUESTS, msg)
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    (status, Json(ErrorResponse { error: message }))
}

/// Login endpoint - authenticate with username/password and get API key
///
/// This is the primary authentication endpoint. Users provide their username
/// and password, and if successful, receive a new API key that can be used
/// for subsequent requests.
///
/// The API key is only shown once - store it securely!
#[utoipa::path(
    post,
    path = "/login",
    operation_id = "login",
    tag = "Authentication",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful, API key returned", body = LoginResponse),
        (status = 401, description = "Invalid credentials or account locked", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn login(
    Extension(db): Extension<Arc<AuthDatabase>>,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    // Verify credentials and get user
    let user = db
        .verify_credentials(&req.username, &req.password)
        .map_err(|e| {
            // Log failed login attempt
            let _ = db.create_audit_log(
                None, // No user_id for failed login
                None, // No API key yet
                "login_failed",
                Some("auth"),
                None,
                Some("/login"),
                Some("POST"),
                None, // IP address would come from middleware
                None, // User agent would come from middleware
                None,
                Some(&format!("Failed login for username: {}", req.username)),
                false,
                Some(&e.to_string()),
            );

            db_error_to_response(e)
        })?;

    // Get user's roles
    let roles = db.get_user_roles(user.id).map_err(db_error_to_response)?;

    // Get user's permissions
    let permissions = db
        .calculate_user_permissions(user.id)
        .map_err(db_error_to_response)?;

    // Create API key for this session
    let (api_key, key_info) = db
        .create_api_key(
            user.id,
            Some(&format!("{}_session", user.username)),
            None, // No description
            None, // Use role's default TTL
        )
        .map_err(db_error_to_response)?;

    // Build user info
    let user_info = UserInfo {
        id: user.id,
        username: user.username.clone(),
        is_superadmin: user.is_superadmin,
        is_active: user.is_active,
        failed_login_attempts: user.failed_login_attempts,
        locked_until: user.locked_until,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        roles,
    };

    // Log successful login
    let _ = db.create_audit_log(
        Some(user.id),
        Some(key_info.id),
        "login_success",
        Some("auth"),
        None,
        Some("/login"),
        Some("POST"),
        None,
        None,
        None,
        Some(&format!("User {} logged in successfully", user.username)),
        true,
        None,
    );

    Ok(Json(LoginResponse {
        api_key,
        user: user_info,
        permissions,
    }))
}
