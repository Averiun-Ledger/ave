// Ave HTTP Auth System - Common Test Utilities
//
// Shared utilities and helpers for all auth tests

use std::fs;
use std::path::PathBuf;

use ave_bridge::auth::{ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig};
use ave_http::auth::database::AuthDatabase;

pub fn create_temp_dir() -> String {
    let path = temp_dir();

    if fs::metadata(&path).is_err() {
        fs::create_dir_all(&path).unwrap();
    }
    path
}

fn temp_dir() -> String {
    let dir = tempfile::tempdir().expect("Can not create temporal directory.");
    dir.path().to_str().unwrap().to_owned()
}

/// Create a test database with default configuration
pub fn create_test_db() -> AuthDatabase {

    let config = AuthConfig {
        enable: true,
        database_path: PathBuf::from(create_temp_dir()).join("test.db"),
        superadmin: "admin".to_string(),
        api_key: ApiKeyConfig {
            default_ttl_seconds: 0,
            max_keys_per_user: 10,
            allow_custom_prefix: false,
            revoke_on_role_change: true,
        },
        lockout: LockoutConfig {
            max_attempts: 5,
            duration_seconds: 900,
            reset_on_success: true,
        },
        rate_limit: RateLimitConfig {
            enable: true,
            window_seconds: 60,
            max_requests: 100,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
        },
        session: SessionConfig {
            audit_enable: true,
            audit_retention_days: 90,
            log_success: true,
            log_failures: true,
            log_all_requests: false,
        },
    };

    let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

    db
}
