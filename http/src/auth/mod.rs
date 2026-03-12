// Ave HTTP Auth System
//
// Complete authentication and authorization system with:
// - Users, roles, and permissions
// - API key management with expiration
// - Audit logging
// - Rate limiting
// - Account lockout
// - SQLite-based storage

pub mod crypto;
pub mod database;
mod database_apikeys;
pub mod database_audit;
mod database_ext;
mod database_quota;
mod db_runtime;
mod http_api;
#[cfg(feature = "prometheus")]
mod metrics;
pub mod middleware;
pub mod models;
pub(crate) mod request_meta;
mod system_config;

// Handler modules
pub mod admin_handlers;
pub mod apikey_handlers;
pub mod integration;
pub mod login_handler;
pub mod system_handlers;

use std::{sync::Arc, time::Duration};

use ave_bridge::{
    MachineSpec, auth::AuthConfig, settings::command::build_auth_password,
};
// Re-exports for convenience
pub use database::AuthDatabase;
use tokio::time::interval;
use tracing::{error, info, warn};

use crate::auth::integration::{
    cleanup_old_data, initialize_auth_database, log_auth_statistics,
};

const TARGET: &str = "ave::http";

pub(crate) struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_uppercase: bool,
    pub require_lowercase: bool,
    pub require_digit: bool,
    pub require_special: bool,
}

pub(crate) struct ValidationLimits {
    pub role_name_max_length: usize,
    pub role_description_max_length: usize,
    pub usage_plan_id_max_length: usize,
    pub usage_plan_name_max_length: usize,
    pub users_default_limit: i64,
    pub users_max_limit: i64,
    pub audit_logs_default_limit: i64,
    pub audit_logs_max_limit: i64,
    pub system_config_default_limit: i64,
    pub system_config_max_limit: i64,
}

pub(crate) struct MaintenanceLimits {
    pub audit_cleanup_batch_size: i64,
    pub rate_limit_cleanup_batch_size: i64,
    pub expired_api_key_cleanup_batch_size: i64,
}

pub(crate) const PASSWORD_POLICY: PasswordPolicy = PasswordPolicy {
    min_length: 8,
    max_length: 128,
    require_uppercase: true,
    require_lowercase: true,
    require_digit: true,
    require_special: true,
};

pub(crate) const VALIDATION_LIMITS: ValidationLimits = ValidationLimits {
    role_name_max_length: 100,
    role_description_max_length: 500,
    usage_plan_id_max_length: 64,
    usage_plan_name_max_length: 100,
    users_default_limit: 100,
    users_max_limit: 1000,
    audit_logs_default_limit: 100,
    audit_logs_max_limit: 1000,
    system_config_default_limit: 50,
    system_config_max_limit: 200,
};

pub(crate) const MAINTENANCE_LIMITS: MaintenanceLimits = MaintenanceLimits {
    audit_cleanup_batch_size: 1_000,
    rate_limit_cleanup_batch_size: 1_000,
    expired_api_key_cleanup_batch_size: 500,
};

pub async fn build_auth(
    auth_config: &AuthConfig,
    password: &str,
    spec: Option<MachineSpec>,
) -> Result<Option<Arc<AuthDatabase>>, String> {
    if auth_config.enable {
        let mut auth_password = password.to_string();
        if auth_password.is_empty() {
            auth_password = build_auth_password();
        }

        if auth_password.is_empty() {
            error!(
                target: TARGET,
                "auth system is enabled but superadmin password is not configured"
            );
            return Err(
                "authentication is enabled but the superadmin password is not configured"
                    .to_string(),
            );
        }

        let db = initialize_auth_database(auth_config, &auth_password, spec)
            .await
            .map_err(|e| {
                error!(target: TARGET, error = %e, "failed to initialize auth system");
                e
            })?;

        info!(target: TARGET, "authentication system enabled");
        log_auth_statistics(&db).await;
        // Background maintenance: cleanup audit logs, rate limits, expired API keys
        let maintenance_db = db.clone();
        tokio::spawn(async move {
            let mut ticker = interval(Duration::from_secs(3600));
            loop {
                ticker.tick().await;
                if let Err(e) = cleanup_old_data(&maintenance_db).await {
                    warn!(target: TARGET, error = %e, "maintenance task failed");
                }
            }
        });
        Ok(Some(db))
    } else {
        Ok(None)
    }
}

/// Validate password against policy
pub(crate) fn validate_password(
    password: &str,
    policy: &PasswordPolicy,
) -> Result<(), String> {
    if password.len() < policy.min_length {
        return Err(format!(
            "Password must be at least {} characters long",
            policy.min_length
        ));
    }

    if password.len() > policy.max_length {
        return Err(format!(
            "Password must be at most {} characters long",
            policy.max_length
        ));
    }

    if policy.require_uppercase && !password.chars().any(|c| c.is_uppercase()) {
        return Err(
            "Password must contain at least one uppercase letter".to_string()
        );
    }

    if policy.require_lowercase && !password.chars().any(|c| c.is_lowercase()) {
        return Err(
            "Password must contain at least one lowercase letter".to_string()
        );
    }

    if policy.require_digit && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }

    if policy.require_special && !password.chars().any(|c| !c.is_alphanumeric())
    {
        return Err(
            "Password must contain at least one special character".to_string()
        );
    }

    Ok(())
}
