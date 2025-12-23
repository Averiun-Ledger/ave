// Ave HTTP Auth System - System and Introspection Handlers
//
// Endpoints for resources, actions, audit logs, and user introspection

use super::database::{AuthDatabase, DatabaseError};
use super::middleware::{AuthContextExtractor, check_permission};
use super::models::*;
use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
use std::sync::Arc;

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
// RESOURCES AND ACTIONS
// =============================================================================

/// List all resources
#[utoipa::path(
    get,
    path = "/admin/resources",
    operation_id = "listResources",
    tag = "System",
    responses(
        (status = 200, description = "List of resources", body = Vec<Resource>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_resources(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<Vec<Resource>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let resources = db.list_resources().map_err(db_error_to_response)?;

    Ok(Json(resources))
}

/// List all actions
#[utoipa::path(
    get,
    path = "/admin/actions",
    operation_id = "listActions",
    tag = "System",
    responses(
        (status = 200, description = "List of actions", body = Vec<Action>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_actions(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<Vec<Action>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let actions = db.list_actions().map_err(db_error_to_response)?;

    Ok(Json(actions))
}

// =============================================================================
// AUDIT LOGS
// =============================================================================

/// Query audit logs
#[utoipa::path(
    get,
    path = "/admin/audit-logs",
    operation_id = "queryAuditLogs",
    tag = "Audit Logs",
    params(
        ("user_id" = Option<i64>, Query, description = "Filter by user ID"),
        ("api_key_id" = Option<String>, Query, description = "Filter by API key ID"),
        ("endpoint" = Option<String>, Query, description = "Filter by endpoint path"),
        ("http_method" = Option<String>, Query, description = "Filter by HTTP method"),
        ("ip_address" = Option<String>, Query, description = "Filter by IP address"),
        ("user_agent" = Option<String>, Query, description = "Filter by User-Agent"),
        ("success" = Option<bool>, Query, description = "Filter by success status"),
        ("start_timestamp" = Option<i64>, Query, description = "Start timestamp (Unix)"),
        ("end_timestamp" = Option<i64>, Query, description = "End timestamp (Unix)"),
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "Audit log entries", body = Vec<AuditLog>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn query_audit_logs(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<Vec<AuditLog>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let logs = db.query_audit_logs(&query).map_err(db_error_to_response)?;

    Ok(Json(logs))
}

/// Get audit log statistics
#[utoipa::path(
    get,
    path = "/admin/audit-logs/stats",
    operation_id = "getAuditStats",
    tag = "Audit Logs",
    params(
        ("days" = Option<u32>, Query, description = "Number of days to include (default 7)")
    ),
    responses(
        (status = 200, description = "Audit statistics"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_audit_stats(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(params): Query<AuditStatsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let stats = db
        .get_audit_stats(params.days.unwrap_or(7))
        .map_err(db_error_to_response)?;

    Ok(Json(stats))
}

#[derive(serde::Deserialize, utoipa::ToSchema)]
pub struct AuditStatsQuery {
    pub days: Option<u32>,
}

// =============================================================================
// SYSTEM CONFIG
// =============================================================================

/// List system configuration
#[utoipa::path(
    get,
    path = "/admin/config",
    operation_id = "listSystemConfig",
    tag = "System",
    responses(
        (status = 200, description = "System configuration", body = Vec<SystemConfig>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_system_config(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<Vec<SystemConfig>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let config = db.list_system_config().map_err(db_error_to_response)?;

    Ok(Json(config))
}

/// Update system configuration value
#[utoipa::path(
    put,
    path = "/admin/config/{key}",
    operation_id = "updateSystemConfig",
    tag = "System",
    params(
        ("key" = String, Path, description = "Configuration key")
    ),
    request_body = UpdateSystemConfigRequest,
    responses(
        (status = 200, description = "Configuration updated", body = SystemConfig),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Configuration key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn update_system_config(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(key): Path<String>,
    Json(req): Json<UpdateSystemConfigRequest>,
) -> Result<Json<SystemConfig>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "put")?;

    let config = db
        .update_system_config(
            &key,
            &req.value.to_string(),
            Some(auth_ctx.user_id),
        )
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "config_updated",
        endpoint: Some(&format!("/admin/config/{}", key)),
        http_method: Some("PUT"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&req).unwrap_or_default()),
        success: true,
        error_message: None,
    });

    Ok(Json(config))
}

// =============================================================================
// USER INTROSPECTION
// =============================================================================

/// Get current user information
#[utoipa::path(
    get,
    path = "/me",
    operation_id = "getMe",
    tag = "My Account",
    responses(
        (status = 200, description = "Current user information", body = UserInfo),
    ),
    security(("api_key" = []))
)]
pub async fn get_me(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorResponse>)> {
    let user = db
        .get_user_by_id(auth_ctx.user_id)
        .map_err(db_error_to_response)?;
    let roles = db
        .get_user_roles(auth_ctx.user_id)
        .map_err(db_error_to_response)?;

    let user_info = UserInfo {
        id: user.id,
        username: user.username,
        is_superadmin: user.is_superadmin,
        is_active: user.is_active,
        must_change_password: user.must_change_password,
        failed_login_attempts: user.failed_login_attempts,
        locked_until: user.locked_until,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        roles,
    };

    Ok(Json(user_info))
}

/// Get current user's permissions
#[utoipa::path(
    get,
    path = "/me/permissions",
    operation_id = "getMyPermissions",
    tag = "My Account",
    responses(
        (status = 200, description = "User's effective permissions", body = Vec<Permission>),
    ),
    security(("api_key" = []))
)]
pub async fn get_my_permissions(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
) -> Json<Vec<Permission>> {
    // Permissions are already calculated and stored in AuthContext
    Json(auth_ctx.permissions.clone())
}

/// Get detailed permission information
#[utoipa::path(
    get,
    path = "/me/permissions/detailed",
    operation_id = "getMyPermissionsDetailed",
    tag = "My Account",
    responses(
        (status = 200, description = "Detailed permission information", body = DetailedPermissionsResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_my_permissions_detailed(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<DetailedPermissionsResponse>, (StatusCode, Json<ErrorResponse>)>
{
    // Get role permissions
    let mut role_permissions = Vec::new();
    for role_name in &auth_ctx.roles {
        if let Ok(role) = db.get_role_by_name(role_name)
            && let Ok(perms) = db.get_role_permissions(role.id)
        {
            role_permissions.push(RolePermissionsInfo {
                role_name: role_name.clone(),
                permissions: perms,
            });
        }
    }

    // Get user-specific permission overrides
    let user_overrides = db
        .get_user_permissions(auth_ctx.user_id)
        .unwrap_or_default();

    let response = DetailedPermissionsResponse {
        user_id: auth_ctx.user_id,
        username: auth_ctx.username.clone(),
        is_superadmin: auth_ctx.is_superadmin,
        roles: auth_ctx.roles.clone(),
        role_permissions,
        user_overrides,
        effective_permissions: auth_ctx.permissions.clone(),
    };

    Ok(Json(response))
}

/// Get rate limit statistics
#[utoipa::path(
    get,
    path = "/admin/rate-limits/stats",
    operation_id = "getRateLimitStats",
    tag = "Audit Logs",
    params(
        ("hours" = Option<u32>, Query, description = "Time window in hours (default 24)")
    ),
    responses(
        (status = 200, description = "Rate limit statistics"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_rate_limit_stats(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(query): Query<RateLimitStatsQuery>,
) -> Result<Json<serde_json::Value>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_system", "get")?;

    let hours = query.hours.unwrap_or(24);

    let stats = db
        .get_rate_limit_stats(None, hours)
        .map_err(db_error_to_response)?;
    Ok(Json(stats))
}

#[derive(serde::Deserialize)]
pub struct RateLimitStatsQuery {
    pub hours: Option<u32>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct DetailedPermissionsResponse {
    pub user_id: i64,
    pub username: String,
    pub is_superadmin: bool,
    pub roles: Vec<String>,
    pub role_permissions: Vec<RolePermissionsInfo>,
    pub user_overrides: Vec<Permission>,
    pub effective_permissions: Vec<Permission>,
}

#[derive(serde::Serialize, utoipa::ToSchema)]
pub struct RolePermissionsInfo {
    pub role_name: String,
    pub permissions: Vec<Permission>,
}
