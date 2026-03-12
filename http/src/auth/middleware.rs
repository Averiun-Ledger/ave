// Ave HTTP Auth System - Middleware
//
// Authentication and authorization middleware for Axum

use crate::auth::middleware::uuid::Uuid;

use super::database::{AuthDatabase, DatabaseError};
use super::models::{AuthContext, ErrorResponse};
use super::request_meta;
use ave_bridge::ProxyConfig;
use axum::{
    Json,
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};
use rand::RngExt;
use std::fmt::Display;
use std::time::Instant;
use std::{net::SocketAddr, sync::Arc};
use tracing::{error, warn};

const TARGET: &str = "ave::http::auth";

// =============================================================================
// API KEY AUTHENTICATION EXTRACTOR
// =============================================================================

/// New API key authentication extractor that uses the database
///
/// This extractor validates the API key and provides full auth context.
/// Use this instead of the legacy ApiKeyAuth.
pub struct ApiKeyAuthNew;

impl<S> FromRequestParts<S> for ApiKeyAuthNew
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        // Check if auth database is available
        let auth_db = parts.extensions.get::<Arc<AuthDatabase>>().cloned();

        // If no auth database, auth is disabled - allow request
        let Some(db) = auth_db else {
            return Ok(Self);
        };
        let request_started = Instant::now();
        let mut db_operations = 0u64;

        // Auth is enabled - validate API key
        let api_key = parts
            .headers
            .get("X-API-Key")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "Missing X-API-Key header".to_string(),
                    }),
                )
            })?;

        // SECURITY FIX: Extract IP from socket address, not client headers
        // X-Forwarded-For and X-Real-IP can be spoofed to bypass rate limiting
        let ip_address = match (
            parts.extensions.get::<ConnectInfo<SocketAddr>>(),
            parts.extensions.get::<Arc<ProxyConfig>>(),
        ) {
            (Some(conn), Some(proxy)) => request_meta::resolve_client_ip(
                &parts.headers,
                conn.0,
                proxy.as_ref(),
            )
            .map(|ip| ip.to_string()),
            (Some(conn), None) => Some(conn.0.ip().to_string()),
            _ => None,
        };

        // SECURITY FIX: Pre-authentication rate limiting by IP
        // Check rate limit BEFORE verifying credentials to prevent brute force attacks
        let pre_auth_ip = ip_address.clone();
        let pre_auth_result = db
            .run_blocking("pre_auth_rate_limit", move |db| {
                db.check_rate_limit(
                    None,
                    pre_auth_ip.as_deref(),
                    Some("/auth/*"),
                )
            })
            .await;
        db_operations += 1;
        pre_auth_result.map_err(|e| {
            db.record_request_db_metrics(
                "api_key_auth",
                db_operations,
                request_started.elapsed(),
            );
            {
                warn!(
                    target: TARGET,
                    ip = ?ip_address,
                    error = %e,
                    "pre-auth rate limit exceeded"
                );
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: format!("Rate limit exceeded: {}", e),
                    }),
                )
            }
        })?;

        let request_path = parts.uri.path().to_string();
        let auth_api_key = api_key.to_string();
        let auth_ip = ip_address.clone();
        let auth_ctx = db
            .run_blocking("authenticate_api_key_request", move |db| {
                db.authenticate_api_key_request(
                    &auth_api_key,
                    auth_ip.as_deref(),
                    &request_path,
                )
            })
            .await
            .map_err(|e| match e {
                DatabaseError::RateLimitExceeded(message) => {
                    db.record_request_db_metrics(
                        "api_key_auth",
                        db_operations + 1,
                        request_started.elapsed(),
                    );
                    warn!(
                        target: TARGET,
                        ip = ?ip_address,
                        error = %message,
                        "authenticated request rate limited"
                    );
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        Json(ErrorResponse { error: message }),
                    )
                }
                DatabaseError::PasswordChangeRequired(message) => {
                    db.record_request_db_metrics(
                        "api_key_auth",
                        db_operations + 1,
                        request_started.elapsed(),
                    );
                    warn!(
                        target: TARGET,
                        ip = ?ip_address,
                        error = %message,
                        "api key blocked pending password change"
                    );
                    (
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse { error: message }),
                    )
                }
                DatabaseError::PermissionDenied(_)
                | DatabaseError::AccountLocked(_) => {
                    db.record_request_db_metrics(
                        "api_key_auth",
                        db_operations + 1,
                        request_started.elapsed(),
                    );
                    warn!(
                        target: TARGET,
                        ip = ?ip_address,
                        error = %e,
                        "api key authentication failed"
                    );
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse {
                            error: format!("Authentication failed: {}", e),
                        }),
                    )
                }
                other => {
                    db.record_request_db_metrics(
                        "api_key_auth",
                        db_operations + 1,
                        request_started.elapsed(),
                    );
                    error!(
                        target: TARGET,
                        ip = ?ip_address,
                        error = %other,
                        "authentication pipeline failed"
                    );
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        Json(ErrorResponse {
                            error:
                                "Internal error while authenticating request"
                                    .to_string(),
                        }),
                    )
                }
            })?;
        db_operations += 1;
        db.record_request_db_metrics(
            "api_key_auth",
            db_operations,
            request_started.elapsed(),
        );

        // Store auth context in request extensions for later use
        parts.extensions.insert(Arc::new(auth_ctx));

        Ok(Self)
    }
}

// =============================================================================
// AUTH CONTEXT EXTRACTOR
// =============================================================================

/// Extractor for getting the AuthContext from request extensions
///
/// This should be used after ApiKeyAuthNew to access user information and permissions.
pub struct AuthContextExtractor(pub Arc<AuthContext>);

impl<S> FromRequestParts<S> for AuthContextExtractor
where
    S: Send + Sync,
{
    type Rejection = (StatusCode, Json<ErrorResponse>);

    async fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        let auth_ctx = parts
            .extensions
            .get::<Arc<AuthContext>>()
            .cloned()
            .ok_or_else(|| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: "No authentication context found".to_string(),
                    }),
                )
            })?;

        Ok(Self(auth_ctx))
    }
}

// =============================================================================
// PERMISSION CHECK FUNCTION
// =============================================================================

/// Helper function to check if user has permission
///
/// Returns 403 Forbidden if permission is denied
pub fn check_permission(
    auth_ctx: &AuthContext,
    resource: &str,
    action: &str,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    if !auth_ctx.has_permission(resource, action) {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: format!("Permission denied: {} on {}", action, resource),
            }),
        ));
    }
    Ok(())
}

// =============================================================================
// AUDIT LOGGING MIDDLEWARE
// =============================================================================

/// Middleware for audit logging
pub async fn audit_log_middleware(
    auth_ctx: Option<Arc<AuthContext>>,
    auth_db: Option<Arc<AuthDatabase>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let request_id = uuid::Uuid::new_v4().to_string();

    // SECURITY FIX: Get IP from socket address only, ignore client headers
    // X-Forwarded-For and X-Real-IP can be spoofed
    let request_meta =
        match (
            req.extensions().get::<ConnectInfo<SocketAddr>>(),
            req.extensions().get::<Arc<ProxyConfig>>(),
        ) {
            (Some(conn), Some(proxy)) => request_meta::extract_request_meta(
                req.headers(),
                conn.0,
                proxy.as_ref(),
            ),
            (Some(conn), None) => request_meta::RequestMeta {
                ip_address: Some(conn.0.ip().to_string()),
                user_agent: req.headers().get("User-Agent").and_then(|value| {
                    value.to_str().ok().map(ToOwned::to_owned)
                }),
            },
            _ => request_meta::RequestMeta {
                ip_address: None,
                user_agent: req.headers().get("User-Agent").and_then(|value| {
                    value.to_str().ok().map(ToOwned::to_owned)
                }),
            },
        };
    let ip_address = request_meta.ip_address;
    let user_agent = request_meta.user_agent;

    // Process request
    let response = next.run(req).await;

    // Avoid double logging for login (explicitly logged elsewhere)
    if path == "/login" {
        return response;
    }

    // Log to audit if database is available
    if let Some(db) = auth_db {
        let success = response.status().is_success();
        let error_message = if !success {
            Some(format!("HTTP {}", response.status()))
        } else {
            None
        };

        // If we have auth_ctx, use normal logging
        if let Some(ctx) = auth_ctx {
            let ctx = (*ctx).clone();
            let path_for_log = path.clone();
            let method_for_log = method.clone();
            let ip_for_log = ip_address.clone();
            let user_agent_for_log = user_agent.clone();
            let request_id_for_log = request_id.clone();
            let error_for_log = error_message.clone();
            if let Err(e) = db
                .run_blocking("log_api_request", move |db| {
                    db.log_api_request(
                        &ctx,
                        crate::auth::database_audit::ApiRequestParams {
                            path: &path_for_log,
                            method: &method_for_log,
                            ip_address: ip_for_log.as_deref(),
                            user_agent: user_agent_for_log.as_deref(),
                            request_id: &request_id_for_log,
                            success,
                            error_message: error_for_log.as_deref(),
                        },
                    )
                })
                .await
            {
                error!(target: TARGET, error = %e, "failed to write request audit log");
            }
        } else {
            // No auth context - log as unauthenticated request
            let path_for_log = path.clone();
            let method_for_log = method.clone();
            let ip_for_log = ip_address.clone();
            let user_agent_for_log = user_agent.clone();
            let request_id_for_log = request_id.clone();
            let error_for_log = error_message.clone();
            let details = format!("{} {}", method, path);
            if let Err(e) = db
                .run_blocking("create_unauthenticated_audit_log", move |db| {
                    db.create_audit_log(
                        crate::auth::database_audit::AuditLogParams {
                            user_id: None,
                            api_key_id: None,
                            action_type: if success {
                                "unauthenticated_request_success"
                            } else {
                                "unauthenticated_request_failed"
                            },
                            endpoint: Some(&path_for_log),
                            http_method: Some(&method_for_log),
                            ip_address: ip_for_log.as_deref(),
                            user_agent: user_agent_for_log.as_deref(),
                            request_id: Some(&request_id_for_log),
                            details: Some(&details),
                            success,
                            error_message: error_for_log.as_deref(),
                        },
                    )
                })
                .await
            {
                error!(target: TARGET, error = %e, "failed to write audit log");
            }
        }
    }

    response
}

// Need to add uuid dependency
// For now, let's create a simple request ID generator
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub const fn new_v4() -> Self {
            Self
        }
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut rng = rand::rng();

        write!(
            f,
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u16>(),
            rng.random::<u64>() & 0xFFFF_FFFF_FFFF,
        )
    }
}
