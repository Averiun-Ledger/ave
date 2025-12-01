// Ave HTTP Auth System - API Key Endpoint Handlers
//
// REST API endpoints for API key management

use super::database::{AuthDatabase, DatabaseError};
use super::middleware::{AuthContextExtractor, check_permission};
use super::models::*;
use axum::{Extension, Json, extract::{Path, Query}, http::StatusCode};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;

/// Convert DatabaseError to HTTP response tuple
fn db_error_to_response(
    err: DatabaseError,
) -> (StatusCode, Json<ErrorResponse>) {
    let (status, message) = match err {
        DatabaseError::NotFoundError(msg) => (StatusCode::NOT_FOUND, msg),
        DatabaseError::DuplicateError(msg) => (StatusCode::CONFLICT, msg),
        DatabaseError::ValidationError(msg) => (StatusCode::BAD_REQUEST, msg),
        DatabaseError::PermissionDenied(msg) => (StatusCode::FORBIDDEN, msg),
        DatabaseError::AccountLocked(msg) => (StatusCode::FORBIDDEN, msg),
        DatabaseError::RateLimitExceeded(msg) => {
            (StatusCode::TOO_MANY_REQUESTS, msg)
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    (status, Json(ErrorResponse { error: message }))
}

// =============================================================================
// API KEY MANAGEMENT ENDPOINTS (ADMIN)
// =============================================================================

/// Create API key for a user (admin)
#[utoipa::path(
    post,
    path = "/admin/api-keys/user/{user_id}",
    operation_id = "createApiKeyForUser",
    tag = "API Key Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created successfully", body = CreateApiKeyResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn create_api_key_for_user(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<
    (StatusCode, Json<CreateApiKeyResponse>),
    (StatusCode, Json<ErrorResponse>),
> {
    // Check permission
    check_permission(&auth_ctx, "api_keys", "create")?;

    let (api_key, key_info) = db
        .create_api_key(
            user_id,
            req.name.as_deref(),
            req.description.as_deref(),
            None, // No custom prefix for admin-created keys
            req.expires_in_seconds,
        )
        .map_err(db_error_to_response)?;

    let response = CreateApiKeyResponse { api_key, key_info };

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "api_key_created",
        Some("api_key"),
        Some(&response.key_info.id.to_string()),
        Some(&format!("/admin/api-keys/user/{}", user_id)),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok((StatusCode::CREATED, Json(response)))
}

/// List all API keys (admin)
#[utoipa::path(
    get,
    path = "/admin/api-keys",
    operation_id = "listAllApiKeys",
    tag = "API Key Management",
    params(
        ("include_revoked" = Option<bool>, Query, description = "Include revoked keys")
    ),
    responses(
        (status = 200, description = "List of API keys", body = Vec<ApiKeyInfo>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_all_api_keys(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(params): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyInfo>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "api_keys", "list")?;

    let keys = db
        .list_all_api_keys(params.include_revoked.unwrap_or(false))
        .map_err(db_error_to_response)?;

    Ok(Json(keys))
}

#[derive(Deserialize, ToSchema)]
pub struct ListApiKeysQuery {
    pub include_revoked: Option<bool>,
}

/// List API keys for a user (admin)
#[utoipa::path(
    get,
    path = "/admin/api-keys/user/{user_id}",
    operation_id = "listUserApiKeys",
    tag = "API Key Management",
    params(
        ("user_id" = i64, Path, description = "User ID"),
        ("include_revoked" = Option<bool>, Query, description = "Include revoked keys")
    ),
    responses(
        (status = 200, description = "List of user API keys", body = Vec<ApiKeyInfo>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_user_api_keys_admin(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
    Query(params): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyInfo>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "api_keys", "list")?;

    let keys = db
        .list_user_api_keys(user_id, params.include_revoked.unwrap_or(false))
        .map_err(db_error_to_response)?;

    Ok(Json(keys))
}

/// Get API key info (admin)
#[utoipa::path(
    get,
    path = "/admin/api-keys/{key_id}",
    operation_id = "getApiKey",
    tag = "API Key Management",
    params(
        ("key_id" = i64, Path, description = "API Key ID")
    ),
    responses(
        (status = 200, description = "API key information", body = ApiKeyInfo),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_api_key(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(key_id): Path<i64>,
) -> Result<Json<ApiKeyInfo>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "api_keys", "read")?;

    let key_info = db.get_api_key_info(key_id).map_err(db_error_to_response)?;

    Ok(Json(key_info))
}

/// Revoke API key (admin)
#[utoipa::path(
    delete,
    path = "/admin/api-keys/{key_id}",
    operation_id = "revokeApiKey",
    tag = "API Key Management",
    params(
        ("key_id" = i64, Path, description = "API Key ID")
    ),
    request_body = RevokeApiKeyRequest,
    responses(
        (status = 204, description = "API key revoked successfully"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn revoke_api_key(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(key_id): Path<i64>,
    Json(req): Json<RevokeApiKeyRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "api_keys", "delete")?;

    db.revoke_api_key(key_id, Some(auth_ctx.user_id), req.reason.as_deref())
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "api_key_revoked",
        Some("api_key"),
        Some(&key_id.to_string()),
        Some(&format!("/admin/api-keys/{}", key_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Rotate an existing API key (admin)
#[utoipa::path(
    post,
    path = "/admin/api-keys/{key_id}/rotate",
    operation_id = "rotateApiKey",
    tag = "API Key Management",
    params(
        ("key_id" = i64, Path, description = "API Key ID")
    ),
    request_body = RotateApiKeyRequest,
    responses(
        (status = 201, description = "API key rotated successfully", body = CreateApiKeyResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn rotate_api_key(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(key_id): Path<i64>,
    Json(req): Json<RotateApiKeyRequest>,
) -> Result<(StatusCode, Json<CreateApiKeyResponse>), (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "api_keys", "create")?;

    // Fetch existing key for user and defaults
    let existing = db
        .get_api_key_info(key_id)
        .map_err(db_error_to_response)?;

    // Revoke old key first
    db.revoke_api_key(
        key_id,
        Some(auth_ctx.user_id),
        req.reason.as_deref(),
    )
    .map_err(db_error_to_response)?;

    // Create replacement key
    let (api_key, key_info) = db
        .create_api_key(
            existing.user_id,
            req.name
                .as_deref()
                .or(existing.name.as_deref()),
            req.description
                .as_deref()
                .or(existing.description.as_deref()),
            None,
            req.expires_in_seconds,
        )
        .map_err(db_error_to_response)?;

    let response = CreateApiKeyResponse { api_key, key_info };

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "api_key_rotated",
        Some("api_key"),
        Some(&key_id.to_string()),
        Some(&format!("/admin/api-keys/{}/rotate", key_id)),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok((StatusCode::CREATED, Json(response)))
}

// =============================================================================
// MY API KEYS ENDPOINTS (NON-ADMIN)
// =============================================================================

/// Create own API key
#[utoipa::path(
    post,
    path = "/me/api-keys",
    operation_id = "createMyApiKey",
    tag = "My Account",
    request_body = CreateApiKeyRequest,
    responses(
        (status = 201, description = "API key created successfully", body = CreateApiKeyResponse),
        (status = 400, description = "Invalid request", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn create_my_api_key(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Json(req): Json<CreateApiKeyRequest>,
) -> Result<
    (StatusCode, Json<CreateApiKeyResponse>),
    (StatusCode, Json<ErrorResponse>),
> {
    let (api_key, key_info) = db
        .create_api_key(
            auth_ctx.user_id,
            req.name.as_deref(),
            req.description.as_deref(),
            None,
            req.expires_in_seconds,
        )
        .map_err(db_error_to_response)?;

    let response = CreateApiKeyResponse { api_key, key_info };

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "api_key_created",
        Some("api_key"),
        Some(&response.key_info.id.to_string()),
        Some("/me/api-keys"),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok((StatusCode::CREATED, Json(response)))
}

/// List own API keys
#[utoipa::path(
    get,
    path = "/me/api-keys",
    operation_id = "listMyApiKeys",
    tag = "My Account",
    params(
        ("include_revoked" = Option<bool>, Query, description = "Include revoked keys")
    ),
    responses(
        (status = 200, description = "List of own API keys", body = Vec<ApiKeyInfo>),
    ),
    security(("api_key" = []))
)]
pub async fn list_my_api_keys(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(params): Query<ListApiKeysQuery>,
) -> Result<Json<Vec<ApiKeyInfo>>, (StatusCode, Json<ErrorResponse>)> {
    let keys = db
        .list_user_api_keys(
            auth_ctx.user_id,
            params.include_revoked.unwrap_or(false),
        )
        .map_err(db_error_to_response)?;

    Ok(Json(keys))
}

/// Revoke own API key
#[utoipa::path(
    delete,
    path = "/me/api-keys/{key_id}",
    operation_id = "revokeMyApiKey",
    tag = "My Account",
    params(
        ("key_id" = i64, Path, description = "API Key ID")
    ),
    request_body = RevokeApiKeyRequest,
    responses(
        (status = 204, description = "API key revoked successfully"),
        (status = 403, description = "Cannot revoke other user's key", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn revoke_my_api_key(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(key_id): Path<i64>,
    Json(req): Json<RevokeApiKeyRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Verify the key belongs to the user
    let key_info = db.get_api_key_info(key_id).map_err(db_error_to_response)?;

    if key_info.user_id != auth_ctx.user_id {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Cannot revoke another user's API key".to_string(),
            }),
        ));
    }

    // Cannot revoke the current key
    if key_id == auth_ctx.api_key_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot revoke the currently used API key".to_string(),
            }),
        ));
    }

    db.revoke_api_key(key_id, Some(auth_ctx.user_id), req.reason.as_deref())
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "api_key_revoked",
        Some("api_key"),
        Some(&key_id.to_string()),
        Some(&format!("/me/api-keys/{}", key_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}
