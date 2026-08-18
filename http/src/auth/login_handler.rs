// Ave HTTP Auth System - Login Handler
//
// Database-backed login endpoint that returns full authentication context

use super::database::AuthDatabase;
use super::http_api::{
    DatabaseErrorMapping, db_error_to_response, rate_limit_error_response,
    request_result_from_status,
};
use super::models::{ErrorResponse, LoginRequest, LoginResponse, UserInfo};
use super::request_meta;
use crate::extract::ApiJson;
use ave_bridge::ProxyConfig;
use axum::{Extension, Json, extract::ConnectInfo, http::StatusCode};
use serde::Deserialize;
use std::time::Instant;
use std::{net::SocketAddr, sync::Arc};
use tracing::warn;

const TARGET: &str = "ave::http::auth";

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
        (status = 429, description = "Rate limit exceeded", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn login(
    Extension(db): Extension<Arc<AuthDatabase>>,
    Extension(proxy): Extension<Arc<ProxyConfig>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    ApiJson(req): ApiJson<LoginRequest>,
) -> Result<Json<LoginResponse>, (StatusCode, Json<ErrorResponse>)> {
    let request_meta =
        request_meta::extract_request_meta(&headers, addr, &proxy);
    let ip_address = request_meta.ip_address;
    let user_agent = request_meta.user_agent;
    let request_started = Instant::now();

    // SECURITY FIX: Check rate limit BEFORE credential verification
    // This prevents brute force attacks by limiting requests per IP
    let pre_auth_ip = ip_address.clone();
    db.run_blocking("login_pre_auth_rate_limit", move |db| {
        db.check_rate_limit(None, pre_auth_ip.as_deref(), Some("/login"))
    })
    .await
    .map_err(|e| {
        let response = rate_limit_error_response(e);
        db.record_request_metrics(
            "login",
            request_result_from_status(response.0),
            request_started.elapsed(),
        );
        response
    })?;

    let login_username = req.username.clone();
    let login_password = req.password.clone();
    let login_ip = ip_address.clone();
    let login_user_agent = user_agent.clone();
    let (user, roles, permissions, api_key) = db
        .run_blocking("login_session", move |db| {
            let session_name = format!("{}_session", login_username);
            // Verify, snapshot roles/permissions and issue the key in a
            // single transaction: a concurrent reset or revoke-all cannot
            // slip in between and leave the new key alive.
            db.login_transactional(
                &login_username,
                &login_password,
                login_ip.as_deref(),
                login_user_agent.as_deref(),
                &session_name,
            )
        })
        .await
        .map_err(|e| {
            warn!(
                target: TARGET,
                username = %req.username,
                ip = ?ip_address,
                error = %e,
                "login failed"
            );
            let response =
                db_error_to_response(e, DatabaseErrorMapping::login());
            db.record_request_metrics(
                "login",
                request_result_from_status(response.0),
                request_started.elapsed(),
            );
            response
        })?;
    db.record_request_metrics("login", "success", request_started.elapsed());

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
        (status = 401, description = "Invalid credentials or password change not required", body = ErrorResponse),
        (status = 429, description = "Rate limit exceeded", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    )
)]
pub async fn change_password(
    Extension(db): Extension<Arc<AuthDatabase>>,
    Extension(proxy): Extension<Arc<ProxyConfig>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    ApiJson(req): ApiJson<ChangePasswordRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    let request_meta =
        request_meta::extract_request_meta(&headers, addr, &proxy);
    let ip_address = request_meta.ip_address;
    let user_agent = request_meta.user_agent;
    let request_started = Instant::now();

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
        let response = rate_limit_error_response(e);
        db.record_request_metrics(
            "change_password",
            request_result_from_status(response.0),
            request_started.elapsed(),
        );
        response
    })?;

    let username = req.username.clone();
    let current_password = req.current_password.clone();
    let new_password = req.new_password.clone();
    db.run_blocking("change_password_with_credentials", move |db| {
        db.change_password_with_credentials_transactional(
            &username,
            &current_password,
            &new_password,
            ip_address.as_deref(),
            user_agent.as_deref(),
        )
    })
    .await
    .map_err(|e| {
        let response = db_error_to_response(e, DatabaseErrorMapping::login());
        db.record_request_metrics(
            "change_password",
            request_result_from_status(response.0),
            request_started.elapsed(),
        );
        response
    })?;
    db.record_request_metrics(
        "change_password",
        "success",
        request_started.elapsed(),
    );

    Ok(StatusCode::OK)
}
