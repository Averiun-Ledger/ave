// Ave HTTP Auth System - Admin Endpoint Handlers
//
// REST API endpoints for user, role, permission, and API key management

use super::database::{AuthDatabase, DatabaseError};
use super::middleware::{AuthContextExtractor, check_permission};
use super::models::*;
use axum::{Extension, Json, extract::{Path, Query}, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use utoipa::ToSchema;

// =============================================================================
// ERROR HANDLING
// =============================================================================

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
        DatabaseError::PasswordChangeRequired(msg) => {
            (StatusCode::FORBIDDEN, msg)
        }
        _ => (StatusCode::INTERNAL_SERVER_ERROR, err.to_string()),
    };

    (status, Json(ErrorResponse { error: message }))
}

// =============================================================================
// USER MANAGEMENT ENDPOINTS
// =============================================================================

/// Create a new user
#[utoipa::path(
    post,
    path = "/admin/users",
    operation_id = "createUser",
    tag = "User Management",
    request_body = CreateUserRequest,
    responses(
        (status = 201, description = "User created successfully", body = UserInfo),
        (status = 400, description = "Invalid request or validation error", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 409, description = "Username already exists", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn create_user(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Json(req): Json<CreateUserRequest>,
) -> Result<(StatusCode, Json<UserInfo>), (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "post")?;

    // Create user
    let user = db
        .create_user(
            &req.username,
            &req.password,
            req.is_superadmin.unwrap_or(false),
            req.role_ids.clone(),
            Some(auth_ctx.user_id),
            req.must_change_password,
        )
        .map_err(db_error_to_response)?;

    // Get user info with roles
    let roles = db.get_user_roles(user.id).map_err(db_error_to_response)?;

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

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "user_created",
        Some("/admin/users"),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok((StatusCode::CREATED, Json(user_info)))
}

/// List all users
#[utoipa::path(
    get,
    path = "/admin/users",
    operation_id = "listUsers",
    tag = "User Management",
    params(
        ("include_inactive" = Option<bool>, Query, description = "Include inactive users")
    ),
    responses(
        (status = 200, description = "List of users", body = Vec<UserInfo>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_users(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Query(params): Query<ListUsersQuery>,
) -> Result<Json<Vec<UserInfo>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "get")?;

    let users = db
        .list_users(params.include_inactive.unwrap_or(false))
        .map_err(db_error_to_response)?;

    Ok(Json(users))
}

#[derive(Deserialize, ToSchema)]
pub struct ListUsersQuery {
    pub include_inactive: Option<bool>,
}

/// Get user by ID
#[utoipa::path(
    get,
    path = "/admin/users/{user_id}",
    operation_id = "getUser",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User information", body = UserInfo),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_user(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "get")?;

    let user = db.get_user_by_id(user_id).map_err(db_error_to_response)?;
    let roles = db.get_user_roles(user_id).map_err(db_error_to_response)?;

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

/// Update user
#[utoipa::path(
    put,
    path = "/admin/users/{user_id}",
    operation_id = "updateUser",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    request_body = UpdateUserRequest,
    responses(
        (status = 200, description = "User updated successfully", body = UserInfo),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn update_user(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
    Json(req): Json<UpdateUserRequest>,
) -> Result<Json<UserInfo>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "put")?;

    // Update user
    let user = db
        .update_user(user_id, req.password.as_deref(), req.is_active)
        .map_err(db_error_to_response)?;

    // Update roles if provided
    if let Some(role_ids) = &req.role_ids {
        // Remove all current roles
        let current_roles =
            db.get_user_roles(user_id).map_err(db_error_to_response)?;
        for role_name in current_roles {
            if let Ok(role) = db.get_role_by_name(&role_name) {
                let _ = db.remove_role_from_user(user_id, role.id);
            }
        }

        // Assign new roles
        for role_id in role_ids {
            db.assign_role_to_user(user_id, *role_id, Some(auth_ctx.user_id))
                .map_err(db_error_to_response)?;
        }
    }

    let roles = db.get_user_roles(user_id).map_err(db_error_to_response)?;

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
        roles
    };

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "user_updated",
        Some(&format!("/admin/users/{}", user_id)),
        Some("PUT"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok(Json(user_info))
}

#[derive(Deserialize, ToSchema)]
pub struct ResetPasswordRequest {
    pub password: String,
}

/// Reset a user's password (forces change on next login)
#[utoipa::path(
    post,
    path = "/admin/users/{user_id}/password",
    operation_id = "resetUserPassword",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    request_body = ResetPasswordRequest,
    responses(
        (status = 200, description = "Password reset, must change on next login"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn reset_user_password(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
    Json(req): Json<ResetPasswordRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_users", "post")?;

    db.admin_reset_password(user_id, &req.password)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "user_password_reset",
        Some(&format!("/admin/users/{}/password", user_id)),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        None,
        true,
        None,
    );

    Ok(StatusCode::OK)
}

/// Delete user
#[utoipa::path(
    delete,
    path = "/admin/users/{user_id}",
    operation_id = "deleteUser",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    responses(
        (status = 204, description = "User deleted successfully"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn delete_user(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "delete")?;

    // Cannot delete yourself
    if user_id == auth_ctx.user_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot delete your own account".to_string(),
            }),
        ));
    }

    db.delete_user(user_id).map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "user_deleted",
        Some(&format!("/admin/users/{}", user_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        None,
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Assign role to user
#[utoipa::path(
    post,
    path = "/admin/users/{user_id}/roles/{role_id}",
    operation_id = "assignRole",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID"),
        ("role_id" = i64, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Role assigned successfully"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User or role not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn assign_role(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path((user_id, role_id)): Path<(i64, i64)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "all")?;

    db.assign_role_to_user(user_id, role_id, Some(auth_ctx.user_id))
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "role_assigned",
        Some(&format!("/admin/users/{}/roles/{}", user_id, role_id)),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&format!(r#"{{"role_id": {}}}"#, role_id)),
        true,
        None,
    );

    Ok(StatusCode::OK)
}

/// Remove role from user
#[utoipa::path(
    delete,
    path = "/admin/users/{user_id}/roles/{role_id}",
    operation_id = "removeRole",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID"),
        ("role_id" = i64, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role removed successfully"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User or role not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn remove_role(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path((user_id, role_id)): Path<(i64, i64)>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_users", "all")?;

    db.remove_role_from_user(user_id, role_id)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "role_removed",
        Some(&format!("/admin/users/{}/roles/{}", user_id, role_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&format!(r#"{{"role_id": {}}}"#, role_id)),
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

// =============================================================================
// ROLE MANAGEMENT ENDPOINTS
// =============================================================================

/// Create a new role
#[utoipa::path(
    post,
    path = "/admin/roles",
    operation_id = "createRole",
    tag = "Role Management",
    request_body = CreateRoleRequest,
    responses(
        (status = 201, description = "Role created successfully", body = Role),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 409, description = "Role name already exists", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn create_role(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Json(req): Json<CreateRoleRequest>,
) -> Result<(StatusCode, Json<Role>), (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "post")?;

    let role = db
        .create_role(
            &req.name,
            req.description.as_deref(),
            req.default_ttl_seconds,
        )
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "role_created",
        Some("/admin/roles"),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok((StatusCode::CREATED, Json(role)))
}

/// List all roles
#[utoipa::path(
    get,
    path = "/admin/roles",
    operation_id = "listRoles",
    tag = "Role Management",
    responses(
        (status = 200, description = "List of roles", body = Vec<RoleInfo>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_roles(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<Vec<RoleInfo>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "get")?;

    let roles = db.list_roles().map_err(db_error_to_response)?;

    Ok(Json(roles))
}

/// Get role by ID
#[utoipa::path(
    get,
    path = "/admin/roles/{role_id}",
    operation_id = "getRole",
    tag = "Role Management",
    params(
        ("role_id" = i64, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Role information", body = Role),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_role(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(role_id): Path<i64>,
) -> Result<Json<Role>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "get")?;

    let role = db.get_role_by_id(role_id).map_err(db_error_to_response)?;

    Ok(Json(role))
}

/// Update role
#[utoipa::path(
    put,
    path = "/admin/roles/{role_id}",
    operation_id = "updateRole",
    tag = "Role Management",
    params(
        ("role_id" = i64, Path, description = "Role ID")
    ),
    request_body = UpdateRoleRequest,
    responses(
        (status = 200, description = "Role updated successfully", body = Role),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied or system role", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn update_role(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(role_id): Path<i64>,
    Json(req): Json<UpdateRoleRequest>,
) -> Result<Json<Role>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "put")?;

    let role = db
        .update_role(
            role_id,
            req.description.as_deref(),
            req.default_ttl_seconds,
        )
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "role_updated",
        Some(&format!("/admin/roles/{}", role_id)),
        Some("PUT"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok(Json(role))
}

/// Delete role
#[utoipa::path(
    delete,
    path = "/admin/roles/{role_id}",
    operation_id = "deleteRole",
    tag = "Role Management",
    params(
        ("role_id" = i64, Path, description = "Role ID")
    ),
    responses(
        (status = 204, description = "Role deleted successfully"),
        (status = 403, description = "Permission denied or system role", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn delete_role(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(role_id): Path<i64>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "delete")?;

    db.delete_role(role_id).map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "role_deleted",
        Some(&format!("/admin/roles/{}", role_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        None,
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Get role permissions
#[utoipa::path(
    get,
    path = "/admin/roles/{role_id}/permissions",
    operation_id = "getRolePermissions",
    tag = "Role Management",
    params(
        ("role_id" = i64, Path, description = "Role ID")
    ),
    responses(
        (status = 200, description = "Role permissions", body = Vec<Permission>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Role not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_role_permissions(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(role_id): Path<i64>,
) -> Result<Json<Vec<Permission>>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "get")?;

    let permissions = db
        .get_role_permissions(role_id)
        .map_err(db_error_to_response)?;

    Ok(Json(permissions))
}

/// Set role permission
#[utoipa::path(
    post,
    path = "/admin/roles/{role_id}/permissions",
    operation_id = "setRolePermission",
    tag = "Role Management",
    params(
        ("role_id" = i64, Path, description = "Role ID")
    ),
    request_body = SetPermissionRequest,
    responses(
        (status = 200, description = "Permission set successfully"),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Role, resource, or action not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn set_role_permission(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(role_id): Path<i64>,
    Json(req): Json<SetPermissionRequest>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "all")?;

    db.set_role_permission(role_id, &req.resource, &req.action, req.allowed)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "permission_set",
        Some(&format!("/admin/roles/{}/permissions", role_id)),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok(StatusCode::OK)
}

/// Get user-specific permission overrides
#[utoipa::path(
    get,
    path = "/admin/users/{user_id}/permissions",
    operation_id = "getUserPermissions",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    responses(
        (status = 200, description = "User permission overrides", body = [Permission]),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_user_permissions(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
) -> Result<Json<Vec<Permission>>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_users", "get")?;

    // Ensure user exists
    db.get_user_by_id(user_id).map_err(db_error_to_response)?;

    let permissions = db
        .get_user_permissions(user_id)
        .map_err(db_error_to_response)?;

    Ok(Json(permissions))
}

/// Set or update a user-specific permission override
#[utoipa::path(
    post,
    path = "/admin/users/{user_id}/permissions",
    operation_id = "setUserPermission",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID")
    ),
    request_body = Permission,
    responses(
        (status = 200, description = "Permission set"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn set_user_permission(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
    Json(req): Json<Permission>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_users", "all")?;

    // Ensure user exists
    db.get_user_by_id(user_id).map_err(db_error_to_response)?;

    db.set_user_permission(
        user_id,
        &req.resource,
        &req.action,
        req.allowed,
        Some(auth_ctx.user_id),
    )
    .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "user_permission_set",
        Some(&format!("/admin/users/{}/permissions", user_id)),
        Some("POST"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&req).unwrap_or_default()),
        true,
        None,
    );

    Ok(StatusCode::OK)
}

/// Remove a user-specific permission override
#[utoipa::path(
    delete,
    path = "/admin/users/{user_id}/permissions",
    operation_id = "removeUserPermission",
    tag = "User Management",
    params(
        ("user_id" = i64, Path, description = "User ID"),
        ("resource" = String, Query, description = "Resource name"),
        ("action" = String, Query, description = "Action name")
    ),
    responses(
        (status = 204, description = "Permission removed"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "User not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn remove_user_permission(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(user_id): Path<i64>,
    Query(params): Query<RemovePermissionQuery>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_users", "all")?;

    // Ensure user exists
    db.get_user_by_id(user_id).map_err(db_error_to_response)?;

    db.remove_user_permission(user_id, &params.resource, &params.action)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "user_permission_removed",
        Some(&format!("/admin/users/{}/permissions", user_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&params).unwrap_or_default()),
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

/// Remove role permission
#[utoipa::path(
    delete,
    path = "/admin/roles/{role_id}/permissions",
    operation_id = "removeRolePermission",
    tag = "Role Management",
    params(
        ("role_id" = i64, Path, description = "Role ID"),
        ("resource" = String, Query, description = "Resource name"),
        ("action" = String, Query, description = "Action name")
    ),
    responses(
        (status = 204, description = "Permission removed successfully"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Role, resource, or action not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn remove_role_permission(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(role_id): Path<i64>,
    Query(params): Query<RemovePermissionQuery>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_roles", "all")?;

    db.remove_role_permission(role_id, &params.resource, &params.action)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(
        Some(auth_ctx.user_id),
        Some(auth_ctx.api_key_id),
        "permission_removed",
        Some(&format!("/admin/roles/{}/permissions", role_id)),
        Some("DELETE"),
        auth_ctx.ip_address.as_deref(),
        None,
        None,
        Some(&serde_json::to_string(&params).unwrap_or_default()),
        true,
        None,
    );

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct RemovePermissionQuery {
    pub resource: String,
    pub action: String,
}
