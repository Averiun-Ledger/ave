// Ave HTTP Auth System - Data Models
//
// This module defines the core data structures for the authentication and authorization system.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};
use utoipa::ToSchema;

fn serialize_ts<S>(ts: &i64, serializer: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    serialize_ts_opt(&Some(*ts), serializer)
}

fn serialize_ts_opt<S>(
    ts: &Option<i64>,
    serializer: S,
) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    let formatted = ts
        .and_then(|v| {
            OffsetDateTime::from_unix_timestamp(v)
                .ok()
                .and_then(|dt| dt.format(&Rfc3339).ok())
        })
        .unwrap_or_default();
    serializer.serialize_str(&formatted)
}

// =============================================================================
// COMMON ERROR RESPONSE
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ErrorResponse {
    pub error: String,
}

impl IntoResponse for ErrorResponse {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(self)).into_response()
    }
}

// =============================================================================
// USER MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct User {
    pub id: i64,
    pub username: String,
    #[serde(skip_serializing)]
    pub password_hash: String,
    pub is_active: bool,
    pub is_deleted: bool,
    pub must_change_password: bool,
    pub failed_login_attempts: i32,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub locked_until: Option<i64>,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub last_login_at: Option<i64>,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct UserInfo {
    /// User ID
    pub id: i64,
    /// Username
    pub username: String,
    /// Is account active
    pub is_active: bool,
    /// Must change password on next login
    pub must_change_password: bool,
    /// Failed login attempts
    pub failed_login_attempts: i32,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub locked_until: Option<i64>,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub last_login_at: Option<i64>,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
    /// Roles assigned to this user
    pub roles: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateUserRequest {
    pub username: String,
    pub password: String,
    pub role_ids: Option<Vec<i64>>,
    pub must_change_password: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateUserRequest {
    pub password: Option<String>,
    pub is_active: Option<bool>,
    pub role_ids: Option<Vec<i64>>,
}

// =============================================================================
// ROLE MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Role {
    pub id: i64,
    pub name: Option<String>,
    pub description: Option<String>,
    pub is_system: bool,
    pub is_deleted: bool,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub updated_at: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct RoleInfo {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
    pub permission_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateRoleRequest {
    pub name: String,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateRoleRequest {
    pub description: Option<String>,
}

// =============================================================================
// RESOURCE AND ACTION MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Resource {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Action {
    pub id: i64,
    pub name: String,
    pub description: Option<String>,
    pub is_system: bool,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
}

// =============================================================================
// PERMISSION MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Permission {
    pub resource: String,
    pub action: String,
    pub allowed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct SetPermissionRequest {
    pub resource: String,
    pub action: String,
    pub allowed: bool,
}

// =============================================================================
// API KEY MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ApiKeyInfo {
    /// UUID identifier - serves as both public ID and primary key
    pub id: String,
    #[serde(skip_serializing)]
    pub user_id: i64,
    pub username: String,
    pub key_prefix: String,
    pub name: String,
    pub description: Option<String>,
    pub is_management: bool,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub created_at: i64,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub expires_at: Option<i64>,
    pub revoked: bool,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub revoked_at: Option<i64>,
    pub revoked_reason: Option<String>,
    #[serde(serialize_with = "serialize_ts_opt", skip_deserializing)]
    pub last_used_at: Option<i64>,
    pub last_used_ip: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct CreateApiKeyRequest {
    pub name: String,
    pub description: Option<String>,
    pub expires_in_seconds: Option<i64>,
}

/// Request payload for rotating an API key
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RotateApiKeyRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    pub expires_in_seconds: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct CreateApiKeyResponse {
    pub api_key: String,
    pub key_info: ApiKeyInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct RevokeApiKeyRequest {
    pub reason: Option<String>,
}

// =============================================================================
// AUDIT LOG MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AuditLog {
    pub id: i64,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub timestamp: i64,
    pub user_id: Option<i64>,
    pub api_key_id: Option<String>,
    pub action_type: String,
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub request_id: Option<String>,
    pub details: Option<String>,
    pub success: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AuditLogQuery {
    pub user_id: Option<i64>,
    pub api_key_id: Option<String>,
    pub endpoint: Option<String>,
    pub http_method: Option<String>,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
    pub success: Option<bool>,
    pub start_timestamp: Option<i64>,
    pub end_timestamp: Option<i64>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

// =============================================================================
// AUTHENTICATION MODELS
// =============================================================================

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct LoginResponse {
    pub api_key: String,
    pub user: UserInfo,
    pub permissions: Vec<Permission>,
}

// =============================================================================
// AUTH CONTEXT (Internal use, not for API)
// =============================================================================

#[derive(Debug, Clone)]
pub struct AuthContext {
    pub user_id: i64,
    pub username: String,
    pub roles: Vec<String>,
    pub permissions: Vec<Permission>,
    pub api_key_id: String,  // UUID
    pub is_management_key: bool,
    pub ip_address: Option<String>,
}

impl AuthContext {
    /// Check if user has the superadmin role
    pub fn is_superadmin(&self) -> bool {
        self.roles.iter().any(|r| r == "superadmin")
    }

    /// Check if user has permission for a specific resource and action
    pub fn has_permission(&self, resource: &str, action: &str) -> bool {
        // Superadmin role always has all permissions
        if self.is_superadmin() {
            return true;
        }

        // Check permissions list
        // Denials take precedence over allows
        let mut has_allow = false;
        let mut has_deny = false;

        for perm in &self.permissions {
            if perm.resource != resource {
                continue;
            }

            // "all" acts as wildcard over actions
            if perm.action != action && perm.action != "all" {
                continue;
            }

            if perm.allowed {
                has_allow = true;
            } else {
                has_deny = true;
            }
        }

        // If there's an explicit deny, return false
        if has_deny {
            return false;
        }

        // Otherwise return true if there's an allow
        has_allow
    }
}

// =============================================================================
// SYSTEM CONFIG MODELS
// =============================================================================

#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SystemConfig {
    pub key: String,
    pub value: String,
    pub description: Option<String>,
    #[serde(serialize_with = "serialize_ts", skip_deserializing)]
    pub updated_at: i64,
    pub updated_by: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct UpdateSystemConfigRequest {
    pub value: i64,
}
