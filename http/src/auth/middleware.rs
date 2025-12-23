// Ave HTTP Auth System - Middleware
//
// Authentication and authorization middleware for Axum

use crate::auth::middleware::uuid::Uuid;

use super::database::AuthDatabase;
use super::models::{AuthContext, ErrorResponse};
use axum::{
    Json,
    extract::{ConnectInfo, FromRequestParts, Request},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::Response,
};
use std::fmt::Display;
use std::{net::SocketAddr, sync::Arc};

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
            return Ok(ApiKeyAuthNew);
        };

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
        let ip_address = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|conn| conn.0.ip().to_string());

        // SECURITY FIX: Pre-authentication rate limiting by IP
        // Check rate limit BEFORE verifying credentials to prevent brute force attacks
        db.check_rate_limit(None, ip_address.as_deref(), Some("/auth/*"))
            .map_err(|e| {
                (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(ErrorResponse {
                        error: format!("Rate limit exceeded: {}", e),
                    }),
                )
            })?;

        let mut auth_ctx = db.verify_api_key(api_key).map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: format!("Authentication failed: {}", e),
                }),
            )
        })?;

        auth_ctx.ip_address = ip_address.clone();

        // Update API key last used
        let _ =
            db.update_api_key_usage(&auth_ctx.api_key_id, ip_address.as_deref());

        // Post-authentication rate limit (per API key)
        db.check_rate_limit(
            Some(&auth_ctx.api_key_id),
            ip_address.as_deref(),
            parts.uri.path().into(),
        )
        .map_err(|e| {
            (
                StatusCode::TOO_MANY_REQUESTS,
                Json(ErrorResponse {
                    error: format!("Rate limit exceeded: {}", e),
                }),
            )
        })?;

        // Store auth context in request extensions for later use
        parts.extensions.insert(Arc::new(auth_ctx));

        Ok(ApiKeyAuthNew)
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

        Ok(AuthContextExtractor(auth_ctx))
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
    let ip_address = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|c| c.0.ip().to_string());

    // Get user agent
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Process request
    let response = next.run(req).await;

    // Avoid double logging for login (explicitly logged elsewhere)
    if path == "/login" {
        return response;
    }

    // Log to audit if database is available and logging is enabled
    if let (Some(db), Some(ctx)) = (auth_db, auth_ctx) {
        let success = response.status().is_success();
        let error_message = if !success {
            Some(format!("HTTP {}", response.status()))
        } else {
            None
        };

        let _ = db.log_api_request(
            &ctx,
            crate::auth::database_audit::ApiRequestParams {
                path: &path,
                method: &method,
                ip_address: ip_address.as_deref(),
                user_agent: user_agent.as_deref(),
                request_id: &request_id,
                success,
                error_message: error_message.as_deref(),
            },
        );
    }

    response
}

// Need to add uuid dependency
// For now, let's create a simple request ID generator
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }
    }
}

impl Display for Uuid {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use rand::Rng;
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
