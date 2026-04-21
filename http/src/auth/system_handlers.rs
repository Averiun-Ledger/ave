// Ave HTTP Auth System - System and Introspection Handlers
//
// Endpoints for resources, actions, audit logs, and user introspection

use super::VALIDATION_LIMITS;
use super::database::AuthDatabase;
use super::http_api::{DatabaseErrorMapping, HttpErrorResponse, run_db};
use super::middleware::{AuthContextExtractor, check_permission};
use super::models::*;
use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
use std::sync::Arc;

fn normalize_pagination(
    query: &PaginationQuery,
    default_limit: i64,
    max_limit: i64,
) -> Result<(i64, i64), HttpErrorResponse> {
    let limit = match query.limit {
        Some(limit) if limit > 0 && limit <= max_limit => limit,
        Some(limit) if limit <= 0 => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!("Limit must be positive (got {})", limit),
                }),
            ));
        }
        Some(limit) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Limit must not exceed {} (got {})",
                        max_limit, limit
                    ),
                }),
            ));
        }
        None => default_limit,
    };

    let offset = match query.offset {
        Some(offset) if offset >= 0 => offset,
        Some(offset) => {
            return Err((
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse {
                    error: format!(
                        "Offset must be non-negative (got {})",
                        offset
                    ),
                }),
            ));
        }
        None => 0,
    };

    Ok((limit, offset))
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

    let resources = run_db(
        &db,
        "list_resources",
        DatabaseErrorMapping::admin(),
        move |db| db.list_resources(),
    )
    .await?;

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

    let actions = run_db(
        &db,
        "list_actions",
        DatabaseErrorMapping::admin(),
        move |db| db.list_actions(),
    )
    .await?;

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
        (status = 200, description = "Audit log entries", body = AuditLogPage),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn query_audit_logs(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(query): Query<AuditLogQuery>,
) -> Result<Json<AuditLogPage>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let logs = run_db(
        &db,
        "query_audit_logs",
        DatabaseErrorMapping::admin(),
        move |db| db.query_audit_logs_page(&query),
    )
    .await?;

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
        (status = 200, description = "Audit statistics", body = AuditStats),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_audit_stats(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(params): Query<AuditStatsQuery>,
) -> Result<Json<AuditStats>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let days = params.days.unwrap_or(7);
    let stats = run_db(
        &db,
        "get_audit_stats",
        DatabaseErrorMapping::admin(),
        move |db| db.get_audit_stats(days),
    )
    .await?;

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
    params(
        ("limit" = Option<i64>, Query, description = "Maximum number of results"),
        ("offset" = Option<i64>, Query, description = "Offset for pagination")
    ),
    responses(
        (status = 200, description = "System configuration", body = SystemConfigPage),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_system_config(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(query): Query<PaginationQuery>,
) -> Result<Json<SystemConfigPage>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_system", "get")?;

    let (limit, offset) = normalize_pagination(
        &query,
        VALIDATION_LIMITS.system_config_default_limit,
        VALIDATION_LIMITS.system_config_max_limit,
    )?;
    let config = run_db(
        &db,
        "list_system_config",
        DatabaseErrorMapping::admin(),
        move |db| db.list_system_config(),
    )
    .await?;
    let total = config.len() as i64;
    let start = offset.min(total) as usize;
    let end = (offset + limit).min(total) as usize;
    let items = config[start..end].to_vec();

    Ok(Json(SystemConfigPage {
        has_more: offset + (items.len() as i64) < total,
        items,
        limit,
        offset,
        total,
    }))
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

    let endpoint = format!("/admin/config/{}", key);
    let value = req.value.clone();
    let updated_key = key.clone();
    let user_id = auth_ctx.user_id;
    let api_key_id = auth_ctx.api_key_id.clone();
    let ip_address = auth_ctx.ip_address.clone();
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let config = run_db(
        &db,
        "update_system_config",
        DatabaseErrorMapping::admin(),
        move |db| {
            db.update_system_config_typed_transactional(
                &updated_key,
                &value,
                Some(user_id),
                Some(crate::auth::database_audit::AuditLogParams {
                    user_id: Some(user_id),
                    api_key_id: Some(&api_key_id),
                    action_type: "config_updated",
                    endpoint: Some(&endpoint),
                    http_method: Some("PUT"),
                    ip_address: ip_address.as_deref(),
                    user_agent: None,
                    request_id: None,
                    details: Some(&audit_details),
                    success: true,
                    error_message: None,
                }),
            )
        },
    )
    .await?;

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
    let user_id = auth_ctx.user_id;
    let user_info =
        run_db(&db, "get_me", DatabaseErrorMapping::admin(), move |db| {
            let user = db.get_user_by_id(user_id)?;
            let roles = db.get_user_roles(user_id)?;

            Ok(UserInfo {
                id: user.id,
                username: user.username,
                is_active: user.is_active,
                must_change_password: user.must_change_password,
                failed_login_attempts: user.failed_login_attempts,
                locked_until: user.locked_until,
                last_login_at: user.last_login_at,
                created_at: user.created_at,
                roles,
            })
        })
        .await?;

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
    let roles = auth_ctx.roles.clone();
    let user_id = auth_ctx.user_id;
    let (role_permissions, user_overrides) = run_db(
        &db,
        "get_my_permissions_detailed",
        DatabaseErrorMapping::admin(),
        move |db| {
            let mut role_permissions = Vec::new();
            for role_name in &roles {
                if let Ok(role) = db.get_role_by_name(role_name)
                    && let Ok(perms) = db.get_role_permissions(role.id)
                {
                    role_permissions.push(RolePermissionsInfo {
                        role_name: role_name.clone(),
                        permissions: perms,
                    });
                }
            }

            let user_overrides =
                db.get_user_permissions(user_id).unwrap_or_default();

            Ok((role_permissions, user_overrides))
        },
    )
    .await?;

    let response = DetailedPermissionsResponse {
        user_id: auth_ctx.user_id,
        username: auth_ctx.username.clone(),
        is_superadmin: auth_ctx.is_superadmin(),
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
        (status = 200, description = "Rate limit statistics", body = RateLimitStats),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_rate_limit_stats(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(query): Query<RateLimitStatsQuery>,
) -> Result<Json<RateLimitStats>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_system", "get")?;

    let hours = query.hours.unwrap_or(24);

    let stats = run_db(
        &db,
        "get_rate_limit_stats",
        DatabaseErrorMapping::admin(),
        move |db| db.get_rate_limit_details(hours),
    )
    .await?;
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
