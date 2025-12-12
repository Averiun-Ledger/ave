// Ave HTTP Auth System - Integration Helper
//
// This module provides helper functions to integrate the auth system into the server

use super::database::AuthDatabase;
use ave_bridge::auth::AuthConfig;
use std::sync::Arc;
use tracing::{error, info};

const TARGET: &str = "AveHttpAuth";

/// Initialize the authentication database
///
/// This function creates and initializes the auth database.
/// Note: Migrations and superadmin bootstrap are handled automatically by AuthDatabase::new()
/// Returns an Arc-wrapped database ready for use
pub async fn initialize_auth_database(
    config: &AuthConfig,
    password: &str,
) -> Result<Arc<AuthDatabase>, String> {
    if !config.enable {
        return Err("Authentication system is disabled".to_string());
    }

    info!(
        TARGET,
        "Initializing authentication database at: {}",
        config.database_path.display()
    );

    // Initialize database (runs migrations and bootstraps superadmin automatically)
    let db = AuthDatabase::new(config.clone(), password)
        .map_err(|e| format!("Failed to initialize auth database: {}", e))?;

    info!(TARGET, "Authentication database initialized successfully");

    // Log configuration summary
    info!(TARGET, "Auth System Configuration:");
    info!(TARGET, "  - Database: {}", config.database_path.display());
    info!(
        TARGET,
        "  - API Key TTL: {} seconds", config.api_key.default_ttl_seconds
    );
    info!(
        TARGET,
        "  - Rate Limiting: {}",
        if config.rate_limit.enable {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        TARGET,
        "  - Audit Logging: {}",
        if config.session.audit_enable {
            "enabled"
        } else {
            "disabled"
        }
    );
    info!(
        TARGET,
        "  - Account Lockout: {} max attempts", config.lockout.max_attempts
    );

    Ok(Arc::new(db))
}

/// Log authentication statistics
///
/// This function logs useful information about the current state of the auth system
pub async fn log_auth_statistics(db: &AuthDatabase) {
    // Get total users
    match db.list_users(false) {
        Ok(users) => {
            info!(TARGET, "Total active users: {}", users.len());
        }
        Err(e) => {
            error!(TARGET, "Failed to get user count: {}", e);
        }
    }

    // Get total roles
    match db.list_roles() {
        Ok(roles) => {
            info!(TARGET, "Total roles: {}", roles.len());
        }
        Err(e) => {
            error!(TARGET, "Failed to get role count: {}", e);
        }
    }

    // Get audit stats for last 7 days
    match db.get_audit_stats(7) {
        Ok(stats) => {
            info!(TARGET, "Audit stats (last 7 days): {}", stats);
        }
        Err(e) => {
            error!(TARGET, "Failed to get audit stats: {}", e);
        }
    }
}

/// Cleanup task for old data
///
/// This function should be called periodically (e.g., daily) to clean up:
/// - Old audit logs
/// - Expired rate limit entries
pub async fn cleanup_old_data(db: &AuthDatabase) -> Result<(), String> {
    // Clean up old audit logs
    if db.config.session.audit_retention_days > 0 {
        match db.cleanup_old_audit_logs(db.config.session.audit_retention_days)
        {
            Ok(deleted) => {
                if deleted > 0 {
                    info!(
                        TARGET,
                        "Cleaned up {} old audit log entries", deleted
                    );
                }
            }
            Err(e) => {
                error!(TARGET, "Failed to cleanup audit logs: {}", e);
            }
        }
    }

    // Clean up expired API keys
    match db.cleanup_expired_api_keys() {
        Ok(deleted) => {
            if deleted > 0 {
                info!(TARGET, "Cleaned up {} expired API keys", deleted);
            }
        }
        Err(e) => {
            error!(TARGET, "Failed to cleanup expired API keys: {}", e);
        }
    }

    // Clean up old rate limit entries
    match db.cleanup_rate_limits() {
        Ok(deleted) => {
            if deleted > 0 {
                info!(TARGET, "Cleaned up {} old rate limit entries", deleted);
            }
        }
        Err(e) => {
            error!(TARGET, "Failed to cleanup rate limits: {}", e);
        }
    }

    Ok(())
}

// Tests moved to /tests directory
