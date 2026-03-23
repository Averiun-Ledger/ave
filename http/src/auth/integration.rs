// Ave HTTP Auth System - Integration Helper
//
// This module provides helper functions to integrate the auth system into the server

use super::database::AuthDatabase;
use ave_bridge::{MachineSpec, auth::AuthConfig};
use std::sync::Arc;
use tracing::{debug, error, info};

const TARGET: &str = "ave::http::auth";

/// Initialize the authentication database
///
/// This function creates and initializes the auth database.
/// Note: Migrations and superadmin bootstrap are handled automatically by AuthDatabase::new()
/// Returns an Arc-wrapped database ready for use
pub async fn initialize_auth_database(
    config: &AuthConfig,
    password: &str,
    spec: Option<MachineSpec>,
) -> Result<Arc<AuthDatabase>, String> {
    if !config.enable {
        return Err("Authentication system is disabled".to_string());
    }

    info!(
        target: TARGET,
        path = %config.database_path.display(),
        "initializing authentication database"
    );

    // Initialize database (runs migrations and bootstraps superadmin automatically)
    let db = AuthDatabase::new(config.clone(), password, spec)
        .map_err(|e| format!("Failed to initialize auth database: {}", e))?;

    info!(
        target: TARGET,
        path = %config.database_path.display(),
        api_key_ttl_s = config.api_key.default_ttl_seconds,
        rate_limiting = config.rate_limit.enable,
        audit_logging = config.session.audit_enable,
        lockout_max_attempts = config.lockout.max_attempts,
        "authentication database initialized"
    );

    Ok(Arc::new(db))
}

/// Log authentication statistics
///
/// This function logs useful information about the current state of the auth system
pub async fn log_auth_statistics(db: &AuthDatabase) {
    // Get total users (using a high limit to get all users for statistics)
    match db.list_users(false, 10000, 0) {
        Ok(users) => {
            debug!(target: TARGET, count = users.len(), "active users");
        }
        Err(e) => {
            error!(target: TARGET, error = %e, "failed to get user count");
        }
    }

    match db.list_roles() {
        Ok(roles) => {
            debug!(target: TARGET, count = roles.len(), "roles");
        }
        Err(e) => {
            error!(target: TARGET, error = %e, "failed to get role count");
        }
    }

    match db.get_audit_stats(7) {
        Ok(stats) => {
            debug!(target: TARGET, stats = %stats, "audit stats (last 7 days)");
        }
        Err(e) => {
            error!(target: TARGET, error = %e, "failed to get audit stats");
        }
    }

    let metrics = db.metrics_snapshot();
    debug!(
        target: TARGET,
        primary_lock_wait_count = metrics.primary_lock_wait_count,
        primary_lock_wait_avg_ms = metrics.primary_lock_wait_avg_ms,
        primary_lock_wait_max_ms = metrics.primary_lock_wait_max_ms,
        maintenance_lock_wait_count = metrics.maintenance_lock_wait_count,
        maintenance_lock_wait_avg_ms = metrics.maintenance_lock_wait_avg_ms,
        maintenance_lock_wait_max_ms = metrics.maintenance_lock_wait_max_ms,
        transaction_count = metrics.transaction_count,
        transaction_avg_ms = metrics.transaction_avg_ms,
        transaction_max_ms = metrics.transaction_max_ms,
        blocking_queue_wait_count = metrics.blocking_queue_wait_count,
        blocking_queue_wait_avg_ms = metrics.blocking_queue_wait_avg_ms,
        blocking_queue_wait_max_ms = metrics.blocking_queue_wait_max_ms,
        blocking_rejections_total = metrics.blocking_rejections_total,
        blocking_task_count = metrics.blocking_task_count,
        blocking_task_avg_ms = metrics.blocking_task_avg_ms,
        blocking_task_max_ms = metrics.blocking_task_max_ms,
        request_count = metrics.request_count,
        avg_request_db_ms = metrics.avg_request_db_ms,
        max_request_db_ms = metrics.max_request_db_ms,
        "auth db metrics snapshot"
    );
}

/// Cleanup task for old data
///
/// This function should be called periodically (e.g., daily) to clean up:
/// - Old audit logs
/// - Expired rate limit entries
pub async fn cleanup_old_data(db: &AuthDatabase) -> Result<(), String> {
    let db = db.clone();
    tokio::task::spawn_blocking(move || cleanup_old_data_blocking(&db))
        .await
        .map_err(|e| format!("cleanup task join error: {}", e))?
}

fn cleanup_old_data_blocking(db: &AuthDatabase) -> Result<(), String> {
    // Clean up old audit logs by time
    let audit_retention_days = db.audit_retention_days();
    if audit_retention_days > 0 {
        match db.cleanup_old_audit_logs(audit_retention_days) {
            Ok(deleted) if deleted > 0 => {
                debug!(target: TARGET, deleted, "cleaned up expired audit log entries");
            }
            Ok(_) => {}
            Err(e) => {
                error!(target: TARGET, error = %e, "failed to clean up audit logs by time");
            }
        }
    }

    let audit_max_entries = db.audit_max_entries();
    if audit_max_entries > 0 {
        match db.cleanup_excess_audit_logs(audit_max_entries) {
            Ok(deleted) if deleted > 0 => {
                debug!(
                    target: TARGET,
                    deleted,
                    limit = audit_max_entries,
                    "evicted excess audit log entries (LRU)"
                );
            }
            Ok(_) => {}
            Err(e) => {
                error!(target: TARGET, error = %e, "failed to clean up excess audit logs");
            }
        }
    }

    match db.cleanup_expired_api_keys() {
        Ok(deleted) if deleted > 0 => {
            debug!(target: TARGET, deleted, "cleaned up expired API keys");
        }
        Ok(_) => {}
        Err(e) => {
            error!(target: TARGET, error = %e, "failed to clean up expired API keys");
        }
    }

    match db.cleanup_rate_limits() {
        Ok(deleted) if deleted > 0 => {
            debug!(target: TARGET, deleted, "cleaned up stale rate limit entries");
        }
        Ok(_) => {}
        Err(e) => {
            error!(target: TARGET, error = %e, "failed to clean up rate limit entries");
        }
    }

    let metrics = db.metrics_snapshot();
    debug!(
        target: TARGET,
        primary_lock_wait_count = metrics.primary_lock_wait_count,
        primary_lock_wait_avg_ms = metrics.primary_lock_wait_avg_ms,
        primary_lock_wait_max_ms = metrics.primary_lock_wait_max_ms,
        maintenance_lock_wait_count = metrics.maintenance_lock_wait_count,
        maintenance_lock_wait_avg_ms = metrics.maintenance_lock_wait_avg_ms,
        maintenance_lock_wait_max_ms = metrics.maintenance_lock_wait_max_ms,
        transaction_count = metrics.transaction_count,
        transaction_avg_ms = metrics.transaction_avg_ms,
        transaction_max_ms = metrics.transaction_max_ms,
        blocking_queue_wait_count = metrics.blocking_queue_wait_count,
        blocking_queue_wait_avg_ms = metrics.blocking_queue_wait_avg_ms,
        blocking_queue_wait_max_ms = metrics.blocking_queue_wait_max_ms,
        blocking_rejections_total = metrics.blocking_rejections_total,
        blocking_task_count = metrics.blocking_task_count,
        blocking_task_avg_ms = metrics.blocking_task_avg_ms,
        blocking_task_max_ms = metrics.blocking_task_max_ms,
        request_count = metrics.request_count,
        avg_request_db_ms = metrics.avg_request_db_ms,
        max_request_db_ms = metrics.max_request_db_ms,
        "auth db metrics snapshot"
    );

    Ok(())
}

// Tests moved to /tests directory
