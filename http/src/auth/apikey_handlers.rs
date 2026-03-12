// Ave HTTP Auth System - API Key Endpoint Handlers
//
// REST API endpoints for API key management

use super::database::{AuthDatabase, DatabaseError};
use super::http_api::{DatabaseErrorMapping, run_db as shared_run_db};
use super::middleware::{AuthContextExtractor, check_permission};
use super::models::*;
use axum::{
    Extension, Json,
    extract::{Path, Query},
    http::StatusCode,
};
use serde::Deserialize;
use std::sync::Arc;
use utoipa::ToSchema;

async fn run_db<T, F>(
    db: &Arc<AuthDatabase>,
    operation: &'static str,
    work: F,
) -> Result<T, (StatusCode, Json<ErrorResponse>)>
where
    T: Send + 'static,
    F: FnOnce(AuthDatabase) -> Result<T, DatabaseError> + Send + 'static,
{
    shared_run_db(db, operation, DatabaseErrorMapping::admin(), work).await
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
    check_permission(&auth_ctx, "admin_api_key", "post")?;

    // SECURITY FIX: Prevent API key impersonation
    // Only superadmin can create keys for other users
    if user_id != auth_ctx.user_id && !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can create API keys for other users"
                    .to_string(),
            }),
        ));
    }

    let name = req.name.clone();
    let description = req.description.clone();
    let expires_in_seconds = req.expires_in_seconds;
    let actor_user_id = auth_ctx.user_id;
    let actor_api_key_id = auth_ctx.api_key_id.clone();
    let actor_ip_address = auth_ctx.ip_address.clone();
    let endpoint = format!("/admin/api-keys/user/{}", user_id);
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let (api_key, key_info) =
        run_db(&db, "create_api_key_for_user", move |db| {
            db.create_api_key_transactional(
                user_id,
                Some(&name),
                description.as_deref(),
                expires_in_seconds,
                false,
                Some(crate::auth::database_audit::AuditLogParams {
                    user_id: Some(actor_user_id),
                    api_key_id: Some(&actor_api_key_id),
                    action_type: "api_key_created",
                    endpoint: Some(&endpoint),
                    http_method: Some("POST"),
                    ip_address: actor_ip_address.as_deref(),
                    user_agent: None,
                    request_id: None,
                    details: Some(&audit_details),
                    success: true,
                    error_message: None,
                }),
            )
        })
        .await?;

    let response = CreateApiKeyResponse { api_key, key_info };

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
    check_permission(&auth_ctx, "admin_api_key", "get")?;

    let include_revoked = params.include_revoked.unwrap_or(false);
    let keys = run_db(&db, "list_all_api_keys", move |db| {
        db.list_all_api_keys(include_revoked)
    })
    .await?;

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
    check_permission(&auth_ctx, "admin_api_key", "get")?;

    let include_revoked = params.include_revoked.unwrap_or(false);
    let keys = run_db(&db, "list_user_api_keys_admin", move |db| {
        db.list_user_api_keys(user_id, include_revoked)
    })
    .await?;

    Ok(Json(keys))
}

/// Get API key info (admin)
#[utoipa::path(
    get,
    path = "/admin/api-keys/{id}",
    operation_id = "getApiKey",
    tag = "API Key Management",
    params(
        ("id" = String, Path, description = "API Key ID (UUID)")
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
    Path(id): Path<String>,
) -> Result<Json<ApiKeyInfo>, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_api_key", "get")?;

    let key_info =
        run_db(&db, "get_api_key", move |db| db.get_api_key_info(&id)).await?;

    Ok(Json(key_info))
}

/// Revoke API key (admin)
#[utoipa::path(
    delete,
    path = "/admin/api-keys/{id}",
    operation_id = "revokeApiKey",
    tag = "API Key Management",
    params(
        ("id" = String, Path, description = "API Key ID (UUID)")
    ),
    request_body(content = RevokeApiKeyRequest, description = "Optional revocation reason", content_type = "application/json"),
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
    Path(id): Path<String>,
    req: Option<Json<RevokeApiKeyRequest>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    // Check permission
    check_permission(&auth_ctx, "admin_api_key", "delete")?;

    // SECURITY FIX: Prevent revoking the currently used API key
    if id == auth_ctx.api_key_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot revoke the currently used API key".to_string(),
            }),
        ));
    }

    // SECURITY FIX: Prevent API key DoS by revoking other users' keys
    // Get the key to check ownership
    let lookup_id = id.clone();
    let key_info = run_db(&db, "get_api_key_for_revoke", move |db| {
        db.get_api_key_info(&lookup_id)
    })
    .await?;

    // Only superadmin can revoke keys of other users
    if key_info.user_id != auth_ctx.user_id && !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can revoke API keys of other users"
                    .to_string(),
            }),
        ));
    }

    let reason = req.as_ref().and_then(|r| r.reason.clone());
    let audit_details = req
        .as_ref()
        .map(|r| serde_json::to_string(&r.0).unwrap_or_default())
        .unwrap_or_default();
    let revoke_id = id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    run_db(&db, "revoke_api_key", move |db| {
        db.revoke_api_key_transactional(
            &revoke_id,
            Some(auth_ctx_for_db.user_id),
            reason.as_deref(),
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "api_key_revoked",
                endpoint: Some(&format!("/admin/api-keys/{}", revoke_id)),
                http_method: Some("DELETE"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Rotate an existing API key (admin)
#[utoipa::path(
    post,
    path = "/admin/api-keys/{id}/rotate",
    operation_id = "rotateApiKey",
    tag = "API Key Management",
    params(
        ("id" = String, Path, description = "API Key ID (UUID)")
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
    Path(id): Path<String>,
    req: Option<Json<RotateApiKeyRequest>>,
) -> Result<
    (StatusCode, Json<CreateApiKeyResponse>),
    (StatusCode, Json<ErrorResponse>),
> {
    // Check permission
    check_permission(&auth_ctx, "admin_api_key", "post")?;

    // Fetch existing key for user and defaults
    let lookup_id = id.clone();
    let existing = run_db(&db, "get_api_key_for_rotate", move |db| {
        db.get_api_key_info(&lookup_id)
    })
    .await?;

    // SECURITY FIX: Prevent API key theft via rotation of other users' keys
    // Only superadmin can rotate keys of other users
    if existing.user_id != auth_ctx.user_id && !auth_ctx.is_superadmin() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only superadmin can rotate API keys of other users"
                    .to_string(),
            }),
        ));
    }

    // Extract request body or use defaults
    let req = req.as_ref().map(|r| &r.0);
    let audit_details = serde_json::to_string(&req).unwrap_or_default();

    let existing_id = existing.id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    let req_name = req.and_then(|r| r.name.clone());
    let req_description = req.and_then(|r| r.description.clone());
    let req_expires = req.and_then(|r| r.expires_in_seconds);
    let req_reason = req.and_then(|r| r.reason.clone());
    let rotate_endpoint = format!("/admin/api-keys/{}/rotate", id);
    let (api_key, key_info) = run_db(&db, "rotate_api_key", move |db| {
        db.rotate_api_key_transactional(
            &existing_id,
            req_name.as_deref(),
            req_description.as_deref(),
            req_expires,
            Some(auth_ctx_for_db.user_id),
            req_reason.as_deref(),
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "api_key_rotated",
                endpoint: Some(&rotate_endpoint),
                http_method: Some("POST"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    let response = CreateApiKeyResponse { api_key, key_info };

    Ok((StatusCode::CREATED, Json(response)))
}

/// Create usage plan (admin)
#[utoipa::path(
    post,
    path = "/admin/usage-plans",
    operation_id = "createUsagePlan",
    tag = "API Key Management",
    request_body = CreateUsagePlanRequest,
    responses(
        (status = 201, description = "Usage plan created successfully", body = UsagePlan),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 409, description = "Plan already exists", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn create_usage_plan(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Json(req): Json<CreateUsagePlanRequest>,
) -> Result<(StatusCode, Json<UsagePlan>), (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "post")?;

    let plan_id = req.id.clone();
    let plan_name = req.name.clone();
    let description = req.description.clone();
    let monthly_events = req.monthly_events;
    let auth_ctx_for_db = auth_ctx.clone();
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let plan = run_db(&db, "create_usage_plan", move |db| {
        db.create_usage_plan_transactional(
            &plan_id,
            &plan_name,
            description.as_deref(),
            monthly_events,
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "usage_plan_created",
                endpoint: Some("/admin/usage-plans"),
                http_method: Some("POST"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    Ok((StatusCode::CREATED, Json(plan)))
}

/// List usage plans (admin)
#[utoipa::path(
    get,
    path = "/admin/usage-plans",
    operation_id = "listUsagePlans",
    tag = "API Key Management",
    responses(
        (status = 200, description = "List usage plans", body = Vec<UsagePlan>),
        (status = 403, description = "Permission denied", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn list_usage_plans(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
) -> Result<Json<Vec<UsagePlan>>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "get")?;

    let plans =
        run_db(&db, "list_usage_plans", move |db| db.list_usage_plans())
            .await?;
    Ok(Json(plans))
}

/// Get usage plan by id (admin)
#[utoipa::path(
    get,
    path = "/admin/usage-plans/{plan_id}",
    operation_id = "getUsagePlan",
    tag = "API Key Management",
    params(
        ("plan_id" = String, Path, description = "Usage plan id")
    ),
    responses(
        (status = 200, description = "Usage plan", body = UsagePlan),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Plan not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_usage_plan(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(plan_id): Path<String>,
) -> Result<Json<UsagePlan>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "get")?;

    let plan =
        run_db(&db, "get_usage_plan", move |db| db.get_usage_plan(&plan_id))
            .await?;
    Ok(Json(plan))
}

/// Update usage plan (admin)
#[utoipa::path(
    put,
    path = "/admin/usage-plans/{plan_id}",
    operation_id = "updateUsagePlan",
    tag = "API Key Management",
    params(
        ("plan_id" = String, Path, description = "Usage plan id")
    ),
    request_body = UpdateUsagePlanRequest,
    responses(
        (status = 200, description = "Updated usage plan", body = UsagePlan),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 409, description = "Plan name already exists", body = ErrorResponse),
        (status = 404, description = "Plan not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn update_usage_plan(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(plan_id): Path<String>,
    Json(req): Json<UpdateUsagePlanRequest>,
) -> Result<Json<UsagePlan>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "put")?;

    let req_name = req.name.clone();
    let req_description = req.description.clone();
    let req_monthly_events = req.monthly_events;
    let update_plan_id = plan_id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let plan = run_db(&db, "update_usage_plan", move |db| {
        db.update_usage_plan_transactional(
            &update_plan_id,
            req_name.as_deref(),
            req_description.as_deref(),
            req_monthly_events,
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "usage_plan_updated",
                endpoint: Some(&format!("/admin/usage-plans/{}", plan_id)),
                http_method: Some("PUT"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    Ok(Json(plan))
}

/// Delete usage plan (admin)
#[utoipa::path(
    delete,
    path = "/admin/usage-plans/{plan_id}",
    operation_id = "deleteUsagePlan",
    tag = "API Key Management",
    params(
        ("plan_id" = String, Path, description = "Usage plan id")
    ),
    responses(
        (status = 204, description = "Usage plan deleted"),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "Plan not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn delete_usage_plan(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(plan_id): Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "delete")?;

    let delete_plan_id = plan_id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    run_db(&db, "delete_usage_plan", move |db| {
        db.delete_usage_plan_transactional(
            &delete_plan_id,
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "usage_plan_deleted",
                endpoint: Some(&format!("/admin/usage-plans/{}", plan_id)),
                http_method: Some("DELETE"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(
                    &serde_json::json!({ "plan_id": plan_id }).to_string(),
                ),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    Ok(StatusCode::NO_CONTENT)
}

/// Assign (or clear) usage plan from API key (admin)
#[utoipa::path(
    put,
    path = "/admin/api-keys/{id}/plan",
    operation_id = "assignApiKeyPlan",
    tag = "API Key Management",
    params(
        ("id" = String, Path, description = "API key id")
    ),
    request_body = AssignApiKeyPlanRequest,
    responses(
        (status = 200, description = "API key plan updated", body = ApiKeyInfo),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "API key or plan not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn assign_api_key_plan(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(id): Path<String>,
    Json(req): Json<AssignApiKeyPlanRequest>,
) -> Result<Json<ApiKeyInfo>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "put")?;

    let plan_id = req.plan_id.clone();
    let auth_ctx_user_id = auth_ctx.user_id;
    let assign_id = id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let updated = run_db(&db, "assign_api_key_plan", move |db| {
        db.assign_api_key_plan_transactional(
            &assign_id,
            plan_id.as_deref(),
            Some(auth_ctx_user_id),
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "api_key_plan_updated",
                endpoint: Some(&format!("/admin/api-keys/{}/plan", id)),
                http_method: Some("PUT"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )?;
        db.get_api_key_info(&assign_id)
    })
    .await?;
    Ok(Json(updated))
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct QuotaStatusQuery {
    pub usage_month: Option<String>,
}

/// Get monthly quota status for API key (admin)
#[utoipa::path(
    get,
    path = "/admin/api-keys/{id}/quota",
    operation_id = "getApiKeyQuotaStatus",
    tag = "API Key Management",
    params(
        ("id" = String, Path, description = "API key id"),
        ("usage_month" = Option<String>, Query, description = "UTC month in YYYY-MM")
    ),
    responses(
        (status = 200, description = "API key quota status", body = ApiKeyQuotaStatus),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_api_key_quota_status(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(id): Path<String>,
    Query(params): Query<QuotaStatusQuery>,
) -> Result<Json<ApiKeyQuotaStatus>, (StatusCode, Json<ErrorResponse>)> {
    check_permission(&auth_ctx, "admin_api_key", "get")?;

    let usage_month = params.usage_month.clone();
    let status = run_db(&db, "get_api_key_quota_status", move |db| {
        db.get_api_key_quota_status(&id, usage_month.as_deref())
    })
    .await?;

    Ok(Json(status))
}

/// Add monthly quota extension for API key (admin)
#[utoipa::path(
    post,
    path = "/admin/api-keys/{id}/quota-extensions",
    operation_id = "addApiKeyQuotaExtension",
    tag = "API Key Management",
    params(
        ("id" = String, Path, description = "API key id")
    ),
    request_body = CreateQuotaExtensionRequest,
    responses(
        (status = 201, description = "Quota extension created", body = QuotaExtensionInfo),
        (status = 400, description = "Invalid request", body = ErrorResponse),
        (status = 403, description = "Permission denied", body = ErrorResponse),
        (status = 404, description = "API key not found", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn add_api_key_quota_extension(
    AuthContextExtractor(auth_ctx): AuthContextExtractor,
    Extension(db): Extension<Arc<AuthDatabase>>,
    Path(id): Path<String>,
    Json(req): Json<CreateQuotaExtensionRequest>,
) -> Result<
    (StatusCode, Json<QuotaExtensionInfo>),
    (StatusCode, Json<ErrorResponse>),
> {
    check_permission(&auth_ctx, "admin_api_key", "post")?;

    let extra_events = req.extra_events;
    let usage_month = req.usage_month.clone();
    let reason = req.reason.clone();
    let auth_ctx_user_id = auth_ctx.user_id;
    let quota_key_id = id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let extension = run_db(&db, "add_api_key_quota_extension", move |db| {
        db.add_quota_extension_transactional(
            &quota_key_id,
            extra_events,
            usage_month.as_deref(),
            reason.as_deref(),
            Some(auth_ctx_user_id),
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "api_key_quota_extension_created",
                endpoint: Some(&format!(
                    "/admin/api-keys/{}/quota-extensions",
                    id
                )),
                http_method: Some("POST"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    Ok((StatusCode::CREATED, Json(extension)))
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
    // Only management key (login) can manage service keys
    if !auth_ctx.is_management_key {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only management API key can create service keys".into(),
            }),
        ));
    }

    // Require permission to manage personal API keys
    if !auth_ctx.has_permission("user_api_key", "post") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "User is not allowed to manage personal API keys".into(),
            }),
        ));
    }

    let name = req.name.clone();
    let description = req.description.clone();
    let expires_in_seconds = req.expires_in_seconds;
    let user_id = auth_ctx.user_id;
    let actor_api_key_id = auth_ctx.api_key_id.clone();
    let actor_ip_address = auth_ctx.ip_address.clone();
    let audit_details = serde_json::to_string(&req).unwrap_or_default();
    let (api_key, key_info) = run_db(&db, "create_my_api_key", move |db| {
        db.create_api_key_transactional(
            user_id,
            Some(&name),
            description.as_deref(),
            expires_in_seconds,
            false,
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(user_id),
                api_key_id: Some(&actor_api_key_id),
                action_type: "api_key_created",
                endpoint: Some("/me/api-keys"),
                http_method: Some("POST"),
                ip_address: actor_ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    let response = CreateApiKeyResponse { api_key, key_info };

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
    if !auth_ctx.is_management_key {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only management API key can list service keys".into(),
            }),
        ));
    }

    if !auth_ctx.has_permission("user_api_key", "get") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "User is not allowed to view personal API keys".into(),
            }),
        ));
    }

    let user_id = auth_ctx.user_id;
    let include_revoked = params.include_revoked.unwrap_or(false);
    let keys = run_db(&db, "list_my_api_keys", move |db| {
        db.list_user_api_keys(user_id, include_revoked)
    })
    .await?;

    Ok(Json(keys))
}

/// Revoke own API key
#[utoipa::path(
    delete,
    path = "/me/api-keys/{name}",
    operation_id = "revokeMyApiKey",
    tag = "My Account",
    params(
        ("name" = String, Path, description = "API Key name")
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
    Path(name): Path<String>,
    req: Option<Json<RevokeApiKeyRequest>>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    if !auth_ctx.is_management_key {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Only management API key can revoke service keys".into(),
            }),
        ));
    }

    if !auth_ctx.has_permission("user_api_key", "delete") {
        return Err((
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "User is not allowed to revoke personal API keys".into(),
            }),
        ));
    }

    // Verify the key belongs to the user and is active by name
    let user_id = auth_ctx.user_id;
    let lookup_name = name.clone();
    let key_info = run_db(&db, "get_active_api_key_by_name", move |db| {
        db.get_active_api_key_by_name(user_id, &lookup_name)
    })
    .await?;

    // Cannot revoke the current key
    if key_info.id == auth_ctx.api_key_id {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot revoke the currently used API key".to_string(),
            }),
        ));
    }

    // Prevent revoking management key
    if key_info.is_management {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse {
                error: "Cannot revoke the management API key".to_string(),
            }),
        ));
    }

    let reason = req.as_ref().and_then(|r| r.reason.clone());
    let audit_details = req
        .as_ref()
        .map(|r| serde_json::to_string(&r.0).unwrap_or_default())
        .unwrap_or_default();
    let revoke_id = key_info.id.clone();
    let auth_ctx_for_db = auth_ctx.clone();
    let endpoint = format!("/me/api-keys/{}", name);
    run_db(&db, "revoke_my_api_key", move |db| {
        db.revoke_api_key_transactional(
            &revoke_id,
            Some(auth_ctx_for_db.user_id),
            reason.as_deref(),
            Some(crate::auth::database_audit::AuditLogParams {
                user_id: Some(auth_ctx_for_db.user_id),
                api_key_id: Some(&auth_ctx_for_db.api_key_id),
                action_type: "api_key_revoked",
                endpoint: Some(&endpoint),
                http_method: Some("DELETE"),
                ip_address: auth_ctx_for_db.ip_address.as_deref(),
                user_agent: None,
                request_id: None,
                details: Some(&audit_details),
                success: true,
                error_message: None,
            }),
        )
    })
    .await?;

    Ok(StatusCode::NO_CONTENT)
}
