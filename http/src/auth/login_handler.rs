// Ave HTTP Auth System - Login Handler
//
// Database-backed login endpoint that returns full authentication context

use super::database::{AuthDatabase, DatabaseError};
use super::models::{ErrorResponse, LoginRequest, LoginResponse, UserInfo};
use axum::{
    Extension, Json,
    extract::ConnectInfo,
    http::{HeaderMap, StatusCode},
};
use serde::Deserialize;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

const TARGET: &str = "ave::http::auth";

/// Convert DatabaseError to HTTP response tuple
fn db_error_to_response(
    err: DatabaseError,
) -> (StatusCode, Json<ErrorResponse>) {
    let (status, message) = match err {
        DatabaseError::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
        DatabaseError::Duplicate(msg) => (StatusCode::CONFLICT, msg),
        DatabaseError::Validation(msg) => (StatusCode::BAD_REQUEST, msg),
        DatabaseError::PermissionDenied(msg) => (StatusCode::UNAUTHORIZED, msg),
        DatabaseError::AccountLocked(msg) => (StatusCode::UNAUTHORIZED, msg),
        DatabaseError::RateLimitExceeded(msg) => {
            (StatusCode::TOO_MANY_REQUESTS, msg)
        }
        DatabaseError::PasswordChangeRequired(msg) => {
            (StatusCode::FORBIDDEN, msg)
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
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let (ip_address, user_agent) = extract_request_meta(&headers, addr);

    // SECURITY FIX: Check rate limit BEFORE credential verification
    // This prevents brute force attacks by limiting requests per IP
    db.check_rate_limit(
        None, // No API key for pre-auth requests
        ip_address.as_deref(),
        "/login".into(),
    )
    .map_err(|e| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!("Rate limit exceeded: {}", e),
            }),
        )
    })?;

    // Verify credentials and get user
    let user = db
        .verify_credentials(&req.username, &req.password)
        .map_err(|e| {
            warn!(
                target: TARGET,
                username = %req.username,
                ip = ?ip_address,
                error = %e,
                "login failed"
            );

            // Log failed login attempt
            if let Err(ae) = db.create_audit_log(
                crate::auth::database_audit::AuditLogParams {
                    user_id: None,    // No user_id for failed login
                    api_key_id: None, // No API key yet
                    action_type: "login_failed",
                    endpoint: Some("/login"),
                    http_method: Some("POST"),
                    ip_address: ip_address.as_deref(),
                    user_agent: user_agent.as_deref(),
                    request_id: None,
                    details: Some(&format!(
                        "Failed login for username: {}",
                        req.username
                    )),
                    success: false,
                    error_message: Some(&e.to_string()),
                },
            ) {
                warn!(target: TARGET, error = %ae, "failed to write login audit log");
            }

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
            true, // management key
        )
        .map_err(db_error_to_response)?;

    // Build user info
    let user_info = UserInfo {
        id: user.id,
        username: user.username.clone(),
        is_active: user.is_active,
        must_change_password: user.must_change_password,
        failed_login_attempts: user.failed_login_attempts,
        locked_until: user.locked_until,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        roles,
    };

    // Log successful login
    if let Err(e) =
        db.create_audit_log(crate::auth::database_audit::AuditLogParams {
            user_id: Some(user.id),
            api_key_id: Some(&key_info.id),
            action_type: "login_success",
            endpoint: Some("/login"),
            http_method: Some("POST"),
            ip_address: ip_address.as_deref(),
            user_agent: user_agent.as_deref(),
            request_id: None,
            details: Some(&format!(
                "User {} logged in successfully",
                user.username
            )),
            success: true,
            error_message: None,
        })
    {
        warn!(target: TARGET, error = %e, "failed to write login audit log");
    }

    Ok(Json(LoginResponse {
        api_key,
        user: user_info,
        permissions,
    }))
}

#[derive(Deserialize, utoipa::ToSchema)]
pub struct ChangePasswordRequest {
    pub username: String,
    pub current_password: String,
    pub new_password: String,
}

fn extract_request_meta(
    headers: &HeaderMap,
    addr: SocketAddr,
) -> (Option<String>, Option<String>) {
    // SECURITY FIX: Use socket address directly instead of trusting client headers
    // X-Forwarded-For can be spoofed by attackers to bypass rate limiting
    // Only trust proxy headers if explicitly configured (future enhancement)
    let ip_address = Some(addr.ip().to_string());

    let user_agent = headers
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    (ip_address, user_agent)
}

/// Endpoint to change password when it is required (no API key needed)
#[utoipa::path(
    post,
    path = "/change-password",
    operation_id = "changePassword",
    tag = "Authentication",
    request_body = ChangePasswordRequest,
    responses(
        (status = 200, description = "Password changed"),
        (status = 400, description = "Invalid password", body = ErrorResponse),
        (status = 403, description = "Forbidden", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn change_password(
    Extension(db): Extension<Arc<AuthDatabase>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let (ip_address, _user_agent) = extract_request_meta(&headers, addr);

    // SECURITY FIX: Check rate limit BEFORE credential verification
    // This prevents brute force attacks on password change endpoint
    db.check_rate_limit(
        None, // No API key for pre-auth requests
        ip_address.as_deref(),
        "/change-password".into(),
    )
    .map_err(|e| {
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!("Rate limit exceeded: {}", e),
            }),
        )
    })?;

    db.change_password_with_credentials(
        &req.username,
        &req.current_password,
        &req.new_password,
    )
    .map_err(db_error_to_response)?;

    Ok(StatusCode::OK)
}
