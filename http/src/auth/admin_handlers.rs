// Ave HTTP Auth System - Admin Endpoint Handlers
//
// REST API endpoints for user, role, permission, and API key management

use super::database::{AuthDatabase, DatabaseError};
use super::middleware::{AuthContextExtractor, check_permission};
use super::models::*;
use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
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

/// Check if a user has the superadmin role
fn is_superadmin_user(
    db: &AuthDatabase,
    user: &User,
) -> Result<bool, (StatusCode, Json<ErrorResponse>)> {
    let roles = db.get_user_roles(user.id).map_err(db_error_to_response)?;
    Ok(roles.iter().any(|r| r == "superadmin"))
}

/// Get superadmin role ID from database
fn get_superadmin_role_id(
    db: &AuthDatabase,
) -> Result<Option<i64>, (StatusCode, Json<ErrorResponse>)> {
    let role_id = db
        .lock_conn()
        .map_err(db_error_to_response)?
        .query_row(
            "SELECT id FROM roles WHERE name = 'superadmin'",
            [],
            |row| row.get(0)
        )
        .ok();
    Ok(role_id)
}

/// Validate superadmin role assignment
/// Returns Ok(()) if assignment is allowed, Err otherwise
fn validate_superadmin_assignment(
    db: &AuthDatabase,
    auth_ctx: &AuthContext,
    target_user_id: i64,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Only superadmin can assign superadmin role
    if !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can assign superadmin role".to_string(),
            }),
        ));
    }

    // Get target user to check if already superadmin
    let target_user = db.get_user_by_id(target_user_id).map_err(db_error_to_response)?;
    let is_target_already_superadmin = is_superadmin_user(db, &target_user)?;

    if !is_target_already_superadmin {
        // Trying to make someone else superadmin - verify only one exists
        let existing_superadmin_count = db.count_superadmins()
            .map_err(db_error_to_response)?;

        if existing_superadmin_count > 0 {
            return Err((
                StatusCode::CONFLICT,
                Json(ErrorResponse {
                    error: "A superadmin already exists. Only one superadmin is allowed.".to_string(),
                }),
            ));
        }
    }

    Ok(())
}

/// Validate superadmin role removal
/// Returns Ok(()) if removal is allowed, Err otherwise
fn validate_superadmin_removal(
    db: &AuthDatabase,
    auth_ctx: &AuthContext,
    target_user_id: i64,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    // Only superadmin can remove superadmin role
    if !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can remove superadmin role".to_string(),
            }),
        ));
    }

    // Get target user
    let target_user = db.get_user_by_id(target_user_id).map_err(db_error_to_response)?;

    // Check if target is superadmin
    if is_superadmin_user(db, &target_user)? {
        // Cannot remove superadmin role from the only superadmin
        let superadmin_count = db.count_superadmins()
            .map_err(db_error_to_response)?;

        if superadmin_count <= 1 {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Cannot remove superadmin role from the only superadmin. System must have at least one superadmin.".to_string(),
                }),
            ));
        }
    }

    Ok(())
}

/// Determine if a user has admin-level permissions (superadmin role or admin resources)
fn is_admin_account(
    db: &AuthDatabase,
    user: &User,
) -> Result<bool, (StatusCode, Json<ErrorResponse>)> {
    // Check if user has superadmin role
    if is_superadmin_user(db, user)? {
        return Ok(true);
    }

    let admin_resources = [
        "admin_users",
        "admin_roles",
        "admin_api_key",
        "admin_system",
        "user_api_key",
    ];

    let effective_permissions = db
        .get_effective_permissions(user.id)
        .map_err(db_error_to_response)?;

    Ok(effective_permissions.iter().any(|perm| {
        perm.allowed && admin_resources.contains(&perm.resource.as_str())
    }))
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

    // SECURITY FIX: Enforce single superadmin rule
    // Check if trying to assign superadmin role
    if let Some(ref role_ids) = req.role_ids {
        let superadmin_role_id: Option<i64> = db
            .lock_conn()
            .ok()
            .and_then(|conn| {
                conn.query_row(
                    "SELECT id FROM roles WHERE name = 'superadmin'",
                    [],
                    |row| row.get(0)
                ).ok()
            });

        if let Some(sa_role_id) = superadmin_role_id {
            if role_ids.contains(&sa_role_id) {
                // Only one superadmin is allowed in the system
                // Only the current superadmin can attempt this operation
                if !auth_ctx.is_superadmin() {
                    return Err((
                        StatusCode::FORBIDDEN,
                        Json(ErrorResponse {
                            error: "Only superadmin can assign superadmin role".to_string(),
                        }),
                    ));
                }

                // Verify that no other superadmin exists
                let existing_superadmin_count = db.count_superadmins()
                    .map_err(db_error_to_response)?;

                if existing_superadmin_count > 0 {
                    return Err((
                        StatusCode::CONFLICT,
                        Json(ErrorResponse {
                            error: "A superadmin already exists. Only one superadmin is allowed.".to_string(),
                        }),
                    ));
                }
            }
        }
    }

    // Create user
    let user = db
        .create_user(
            &req.username,
            &req.password,
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
        is_active: user.is_active,
        must_change_password: user.must_change_password,
        failed_login_attempts: user.failed_login_attempts,
        locked_until: user.locked_until,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        roles,
    };

    // Audit log
    // SECURITY FIX: Sanitize request to avoid logging password
    let audit_details = serde_json::json!({
        "username": req.username,
        "role_ids": req.role_ids,
        "must_change_password": req.must_change_password,
    });
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "user_created",
        endpoint: Some("/admin/users"),
        http_method: Some("POST"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&audit_details.to_string()),
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Protect superadmin account
    let target_user = db.get_user_by_id(user_id).map_err(db_error_to_response)?;
    let is_target_superadmin = is_superadmin_user(&db, &target_user)?;

    if is_target_superadmin {
        // Prevent deactivating superadmin
        if req.is_active == Some(false) {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Cannot deactivate superadmin account".to_string(),
                }),
            ));
        }

        // SECURITY FIX: Prevent non-superadmin from changing superadmin's password
        // This prevents privilege escalation via password reset
        if req.password.is_some() && !auth_ctx.is_superadmin() {
            return Err((
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Only superadmin can change superadmin's password".to_string(),
                }),
            ));
        }
    }

    // Update user
    let user = db
        .update_user(user_id, req.password.as_deref(), req.is_active)
        .map_err(db_error_to_response)?;

    // Update roles if provided
    if let Some(role_ids) = &req.role_ids {
        // SECURITY FIX: Protect superadmin role assignment and removal
        let superadmin_role_id = get_superadmin_role_id(&db)?;

        if let Some(sa_role_id) = superadmin_role_id {
            // Check if target user currently has superadmin role
            let is_target_currently_superadmin = is_superadmin_user(&db, &target_user)?;

            // Validate if trying to ADD superadmin role
            if role_ids.contains(&sa_role_id) {
                validate_superadmin_assignment(&db, &auth_ctx, user_id)?;
            }
            // Validate if trying to REMOVE superadmin role (user has it but new roles don't)
            else if is_target_currently_superadmin {
                // Trying to remove superadmin role via update
                validate_superadmin_removal(&db, &auth_ctx, user_id)?;
            }
        }

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
        is_active: user.is_active,
        must_change_password: user.must_change_password,
        failed_login_attempts: user.failed_login_attempts,
        locked_until: user.locked_until,
        last_login_at: user.last_login_at,
        created_at: user.created_at,
        roles,
    };

    // Audit log
    // SECURITY FIX: Sanitize request to avoid logging password
    let audit_details = serde_json::json!({
        "is_active": req.is_active,
        "role_ids": req.role_ids,
        "password_changed": req.password.is_some(),
    });
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "user_updated",
        endpoint: Some(&format!("/admin/users/{}", user_id)),
        http_method: Some("PUT"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&audit_details.to_string()),
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Protect superadmin account
    let target_user = db.get_user_by_id(user_id).map_err(db_error_to_response)?;
    if is_superadmin_user(&db, &target_user)? && !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can reset superadmin password".to_string(),
            }),
        ));
    }

    db.admin_reset_password(user_id, &req.password)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "user_password_reset",
        endpoint: Some(&format!("/admin/users/{}/password", user_id)),
        http_method: Some("POST"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: None,
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Protect superadmin account from deletion
    let target_user = db.get_user_by_id(user_id).map_err(db_error_to_response)?;
    if is_superadmin_user(&db, &target_user)? {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Cannot delete superadmin account".to_string(),
            }),
        ));
    }

    db.delete_user(user_id).map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "user_deleted",
        endpoint: Some(&format!("/admin/users/{}", user_id)),
        http_method: Some("DELETE"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: None,
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Protect superadmin role assignment
    let superadmin_role_id = get_superadmin_role_id(&db)?;

    if let Some(sa_role_id) = superadmin_role_id {
        if role_id == sa_role_id {
            validate_superadmin_assignment(&db, &auth_ctx, user_id)?;
        }
    }

    db.assign_role_to_user(user_id, role_id, Some(auth_ctx.user_id))
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "role_assigned",
        endpoint: Some(&format!("/admin/users/{}/roles/{}", user_id, role_id)),
        http_method: Some("POST"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&format!(r#"{{"role_id": {}}}"#, role_id)),
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Protect superadmin role removal
    let superadmin_role_id = get_superadmin_role_id(&db)?;

    if let Some(sa_role_id) = superadmin_role_id {
        if role_id == sa_role_id {
            validate_superadmin_removal(&db, &auth_ctx, user_id)?;
        }
    }

    db.remove_role_from_user(user_id, role_id)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "role_removed",
        endpoint: Some(&format!("/admin/users/{}/roles/{}", user_id, role_id)),
        http_method: Some("DELETE"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&format!(r#"{{"role_id": {}}}"#, role_id)),
        success: true,
        error_message: None,
    });

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
        .create_role(&req.name, req.description.as_deref())
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "role_created",
        endpoint: Some("/admin/roles"),
        http_method: Some("POST"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&req).unwrap_or_default()),
        success: true,
        error_message: None,
    });

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
        .update_role(role_id, req.description.as_deref())
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "role_updated",
        endpoint: Some(&format!("/admin/roles/{}", role_id)),
        http_method: Some("PUT"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&req).unwrap_or_default()),
        success: true,
        error_message: None,
    });

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
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "role_deleted",
        endpoint: Some(&format!("/admin/roles/{}", role_id)),
        http_method: Some("DELETE"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: None,
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Prevent privilege escalation via role permission modification
    // Only superadmin can modify role permissions to prevent users from
    // granting themselves additional privileges by editing their own roles
    if !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can modify role permissions".to_string(),
            }),
        ));
    }

    db.set_role_permission(role_id, &req.resource, &req.action, req.allowed)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "permission_set",
        endpoint: Some(&format!("/admin/roles/{}/permissions", role_id)),
        http_method: Some("POST"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&req).unwrap_or_default()),
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Prevent non-superadmin from modifying their own permissions
    // Superadmins are exempt because they get permissions implicitly (always have all)
    if user_id == auth_ctx.user_id && !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot modify your own permissions".to_string(),
            }),
        ));
    }

    // Ensure user exists
    let target_user = db.get_user_by_id(user_id).map_err(db_error_to_response)?;

    // SECURITY FIX: Prevent non-superadmin from modifying other admin's permissions
    // Only superadmins can modify permissions of other admins (separation of duties)
    if !auth_ctx.is_superadmin() && is_admin_account(&db, &target_user)? {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can modify permissions of other admins".to_string(),
            }),
        ));
    }

    db.set_user_permission(
        user_id,
        &req.resource,
        &req.action,
        req.allowed,
        Some(auth_ctx.user_id),
    )
    .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "user_permission_set",
        endpoint: Some(&format!("/admin/users/{}/permissions", user_id)),
        http_method: Some("POST"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&req).unwrap_or_default()),
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Prevent non-superadmin from modifying their own permissions
    // Superadmins are exempt because they get permissions implicitly (always have all)
    if user_id == auth_ctx.user_id && !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot modify your own permissions".to_string(),
            }),
        ));
    }

    // Ensure user exists
    let target_user = db.get_user_by_id(user_id).map_err(db_error_to_response)?;

    // SECURITY FIX: Prevent non-superadmin from modifying other admin's permissions
    if !auth_ctx.is_superadmin() && is_admin_account(&db, &target_user)? {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can modify permissions of other admins".to_string(),
            }),
        ));
    }

    db.remove_user_permission(user_id, &params.resource, &params.action)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "user_permission_removed",
        endpoint: Some(&format!("/admin/users/{}/permissions", user_id)),
        http_method: Some("DELETE"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&params).unwrap_or_default()),
        success: true,
        error_message: None,
    });

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

    // SECURITY FIX: Prevent privilege escalation via role permission modification
    // Only superadmin can modify role permissions to prevent users from
    // granting themselves additional privileges by editing their own roles
    if !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can modify role permissions".to_string(),
            }),
        ));
    }

    db.remove_role_permission(role_id, &params.resource, &params.action)
        .map_err(db_error_to_response)?;

    // Audit log
    let _ = db.create_audit_log(crate::auth::database_audit::AuditLogParams {
        user_id: Some(auth_ctx.user_id),
        api_key_id: Some(&auth_ctx.api_key_id),
        action_type: "permission_removed",
        endpoint: Some(&format!("/admin/roles/{}/permissions", role_id)),
        http_method: Some("DELETE"),
        ip_address: auth_ctx.ip_address.as_deref(),
        user_agent: None,
        request_id: None,
        details: Some(&serde_json::to_string(&params).unwrap_or_default()),
        success: true,
        error_message: None,
    });

    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize, Serialize, ToSchema)]
pub struct RemovePermissionQuery {
    pub resource: String,
    pub action: String,
}
