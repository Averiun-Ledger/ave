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
pub mod middleware;
pub mod models;

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
const MIN_LENGTH: usize = 8;
const MAX_LENGTH: usize = 128;
const REQUIRE_UPPERCASE: bool = true;
const REQUIRE_LOWERCASE: bool = true;
const REQUIRE_DIGIT: bool = true;
const REQUIRE_SPECIAL: bool = true;

pub async fn build_auth(
    auth_config: &AuthConfig,
    password: &str,
    spec: Option<MachineSpec>,
) -> Option<Arc<AuthDatabase>> {
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
            return None;
        }

        let db = initialize_auth_database(auth_config, &auth_password, spec)
            .await
            .map_err(|e| {
                error!(target: TARGET, error = %e, "failed to initialize auth system");
            })
            .expect("Can not initialize auth database");

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
        Some(db)
    } else {
        None
    }
}

/// Validate password against policy
pub fn validate_password(password: &str) -> Result<(), String> {
    if password.len() < MIN_LENGTH {
        return Err(format!(
            "Password must be at least {} characters long",
            MIN_LENGTH
        ));
    }

    if password.len() > MAX_LENGTH {
        return Err(format!(
            "Password must be at most {} characters long",
            MAX_LENGTH
        ));
    }

    if REQUIRE_UPPERCASE && !password.chars().any(|c| c.is_uppercase()) {
        return Err(
            "Password must contain at least one uppercase letter".to_string()
        );
    }

    if REQUIRE_LOWERCASE && !password.chars().any(|c| c.is_lowercase()) {
        return Err(
            "Password must contain at least one lowercase letter".to_string()
        );
    }

    if REQUIRE_DIGIT && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err("Password must contain at least one digit".to_string());
    }

    if REQUIRE_SPECIAL && !password.chars().any(|c| !c.is_alphanumeric()) {
        return Err(
            "Password must contain at least one special character".to_string()
        );
    }

    Ok(())
}
