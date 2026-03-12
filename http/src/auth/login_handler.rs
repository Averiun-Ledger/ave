// Ave HTTP Auth System - Login Handler
//
// Database-backed login endpoint that returns full authentication context

use super::database::{AuthDatabase, DatabaseError};
use super::http_api::{
    DatabaseErrorMapping, db_error_to_response as shared_db_error_to_response,
};
use super::models::{ErrorResponse, LoginRequest, LoginResponse, UserInfo};
use super::request_meta;
use ave_bridge::ProxyConfig;
use axum::{Extension, Json, extract::ConnectInfo, http::StatusCode};
use serde::Deserialize;
use std::time::Instant;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

const TARGET: &str = "ave::http::auth";

/// Convert DatabaseError to HTTP response tuple
fn db_error_to_response(
    err: DatabaseError,
) -> (StatusCode, Json<ErrorResponse>) {
    shared_db_error_to_response(err, DatabaseErrorMapping::login())
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
    Extension(proxy): Extension<Arc<ProxyConfig>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_meta =
        request_meta::extract_request_meta(&headers, addr, &proxy);
    let ip_address = request_meta.ip_address;
    let user_agent = request_meta.user_agent;
    let request_started = Instant::now();
    let mut db_operations = 0u64;

    // SECURITY FIX: Check rate limit BEFORE credential verification
    // This prevents brute force attacks by limiting requests per IP
    let pre_auth_ip = ip_address.clone();
    db.run_blocking("login_pre_auth_rate_limit", move |db| {
        db.check_rate_limit(None, pre_auth_ip.as_deref(), Some("/login"))
    })
    .await
    .map_err(|e| {
        db.record_request_db_metrics(
            "login",
            db_operations + 1,
            request_started.elapsed(),
        );
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!("Rate limit exceeded: {}", e),
            }),
        )
    })?;
    db_operations += 1;

    let login_username = req.username.clone();
    let login_password = req.password.clone();
    let login_ip = ip_address.clone();
    let login_user_agent = user_agent.clone();
    let (user, roles, permissions, api_key) = db
        .run_blocking("login_session", move |db| {
            let user = db.verify_credentials_transactional(
                &login_username,
                &login_password,
                login_ip.as_deref(),
                login_user_agent.as_deref(),
            )?;
            let roles = db.get_user_roles(user.id)?;
            let permissions = db.calculate_user_permissions(user.id)?;
            let session_name = format!("{}_session", user.username);
            let audit_details =
                format!("User {} logged in successfully", user.username);
            let (api_key, _key_info) = db
                .issue_management_api_key_transactional(
                    user.id,
                    Some(&session_name),
                    None,
                    None,
                    Some(crate::auth::database_audit::AuditLogParams {
                        user_id: Some(user.id),
                        api_key_id: None,
                        action_type: "login_success",
                        endpoint: Some("/login"),
                        http_method: Some("POST"),
                        ip_address: login_ip.as_deref(),
                        user_agent: login_user_agent.as_deref(),
                        request_id: None,
                        details: Some(&audit_details),
                        success: true,
                        error_message: None,
                    }),
                )?;

            Ok((user, roles, permissions, api_key))
        })
        .await
        .map_err(|e| {
            db.record_request_db_metrics(
                "login",
                db_operations + 1,
                request_started.elapsed(),
            );
            warn!(
                target: TARGET,
                username = %req.username,
                ip = ?ip_address,
                error = %e,
                "login failed"
            );
            db_error_to_response(e)
        })?;
    db_operations += 1;
    db.record_request_db_metrics(
        "login",
        db_operations,
        request_started.elapsed(),
    );

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
    Extension(proxy): Extension<Arc<ProxyConfig>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<ChangePasswordRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let request_meta =
        request_meta::extract_request_meta(&headers, addr, &proxy);
    let ip_address = request_meta.ip_address;
    let request_started = Instant::now();
    let mut db_operations = 0u64;

    // SECURITY FIX: Check rate limit BEFORE credential verification
    // This prevents brute force attacks on password change endpoint
    let pre_auth_ip = ip_address.clone();
    db.run_blocking("change_password_pre_auth_rate_limit", move |db| {
        db.check_rate_limit(
            None,
            pre_auth_ip.as_deref(),
            Some("/change-password"),
        )
    })
    .await
    .map_err(|e| {
        db.record_request_db_metrics(
            "change_password",
            db_operations + 1,
            request_started.elapsed(),
        );
        (
            StatusCode::TOO_MANY_REQUESTS,
            Json(ErrorResponse {
                error: format!("Rate limit exceeded: {}", e),
            }),
        )
    })?;
    db_operations += 1;

    let username = req.username.clone();
    let current_password = req.current_password.clone();
    let new_password = req.new_password.clone();
    db.run_blocking("change_password_with_credentials", move |db| {
        db.change_password_with_credentials(
            &username,
            &current_password,
            &new_password,
        )
    })
    .await
    .map_err(|e| {
        db.record_request_db_metrics(
            "change_password",
            db_operations + 1,
            request_started.elapsed(),
        );
        db_error_to_response(e)
    })?;
    db_operations += 1;
    db.record_request_db_metrics(
        "change_password",
        db_operations,
        request_started.elapsed(),
    );

    Ok(StatusCode::OK)
}
