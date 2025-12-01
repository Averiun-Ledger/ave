// Ave HTTP Auth System - Middleware
//
// Authentication and authorization middleware for Axum

use super::database::AuthDatabase;
use super::models::{AuthContext, ErrorResponse};
use axum::{
    Json,
    extract::{FromRequestParts, Request},
    http::{StatusCode, request::Parts},
    middleware::Next,
    response::{IntoResponse, Response},
};
use std::sync::Arc;

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

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        async move {
            // Check if auth database is available
            let auth_db = parts.extensions.get::<Arc<AuthDatabase>>().cloned();

            // If no auth database, auth is disabled - allow request
            if auth_db.is_none() {
                return Ok(ApiKeyAuthNew);
            }

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

            // Verify API key and get auth context
            let db = auth_db.unwrap();
            let mut auth_ctx = db.verify_api_key(api_key).map_err(|e| {
                (
                    StatusCode::UNAUTHORIZED,
                    Json(ErrorResponse {
                        error: format!("Authentication failed: {}", e),
                    }),
                )
            })?;

            // Extract IP address
            let ip_address = parts
                .headers
                .get("X-Forwarded-For")
                .and_then(|v| v.to_str().ok())
                .or_else(|| {
                    parts.headers.get("X-Real-IP").and_then(|v| v.to_str().ok())
                })
                .map(|s| s.to_string());

            auth_ctx.ip_address = ip_address.clone();

            // Update API key last used
            let _ = db.update_api_key_usage(
                auth_ctx.api_key_id,
                ip_address.as_deref(),
            );

            // Check rate limit
            db.check_rate_limit(
                Some(auth_ctx.api_key_id),
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

    fn from_request_parts(
        parts: &mut Parts,
        _state: &S,
    ) -> impl std::future::Future<Output = Result<Self, Self::Rejection>> + Send
    {
        async move {
            let auth_ctx = parts
                .extensions
                .get::<Arc<AuthContext>>()
                .cloned()
                .ok_or_else(|| {
                    (
                        StatusCode::UNAUTHORIZED,
                        Json(ErrorResponse {
                            error: "No authentication context found"
                                .to_string(),
                        }),
                    )
                })?;

            Ok(AuthContextExtractor(auth_ctx))
        }
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

    // Get IP address from headers
    let ip_address = req
        .headers()
        .get("X-Forwarded-For")
        .and_then(|v| v.to_str().ok())
        .or_else(|| {
            req.headers().get("X-Real-IP").and_then(|v| v.to_str().ok())
        })
        .map(|s| s.to_string());

    // Get user agent
    let user_agent = req
        .headers()
        .get("User-Agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // Process request
    let response = next.run(req).await;

    // Log to audit if database is available and logging is enabled
    if let (Some(db), Some(ctx)) = (auth_db, auth_ctx) {
        if db.config.session.log_all_requests {
            let success = response.status().is_success();
            let error_message = if !success {
                Some(format!("HTTP {}", response.status()))
            } else {
                None
            };

            let _ = db.create_audit_log(
                Some(ctx.user_id),
                Some(ctx.api_key_id),
                "api_request",
                None,
                None,
                Some(&path),
                Some(&method),
                ip_address.as_deref(),
                user_agent.as_deref(),
                Some(&request_id),
                None,
                success,
                error_message.as_deref(),
            );
        }
    }

    response
}

// =============================================================================
// READ-ONLY MODE MIDDLEWARE
// =============================================================================

/// Middleware to enforce read-only mode
pub async fn read_only_middleware(
    auth_db: Option<Arc<AuthDatabase>>,
    req: Request,
    next: Next,
) -> Response {
    // Check if read-only mode is enabled
    if let Some(db) = auth_db {
        if let Ok(true) = db.is_read_only_mode() {
            // Only allow GET, HEAD, OPTIONS
            if !matches!(
                req.method(),
                &axum::http::Method::GET
                    | &axum::http::Method::HEAD
                    | &axum::http::Method::OPTIONS
            ) {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(ErrorResponse {
                        error: "System is in read-only mode".to_string(),
                    }),
                )
                    .into_response();
            }
        }
    }

    next.run(req).await
}

// Need to add uuid dependency
// For now, let's create a simple request ID generator
mod uuid {
    pub struct Uuid;

    impl Uuid {
        pub fn new_v4() -> Self {
            Uuid
        }

        pub fn to_string(&self) -> String {
            use rand::Rng;
            let mut rng = rand::thread_rng();
            format!(
                "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
                rng.r#gen::<u32>(),
                rng.r#gen::<u16>(),
                rng.r#gen::<u16>(),
                rng.r#gen::<u16>(),
                rng.r#gen::<u64>() & 0xFFFF_FFFF_FFFF,
            )
        }
    }
}
