// Ave HTTP Auth System - Common Test Utilities
//
// Shared utilities and helpers for all auth tests

use std::fs;
use std::path::PathBuf;

use ave_http::auth::config::*;
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
        enabled: true,
        database_path: PathBuf::from(create_temp_dir()).join("test.db"),
        superadmin: Some(SuperadminConfig {
            username: "admin".to_string(),
            password: "AdminPass123!".to_string(),
        }),
        password_policy: PasswordPolicy {
            min_length: 8,
            require_uppercase: true,
            require_lowercase: true,
            require_digit: true,
            require_special: false,
            expiration_days: 0,
        },
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
            enabled: true,
            window_seconds: 60,
            max_requests: 100,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
        },
        session: SessionConfig {
            audit_enabled: true,
            audit_retention_days: 90,
            log_success: true,
            log_failures: true,
            log_all_requests: false,
        },
    };

    let db = AuthDatabase::new(config).unwrap();

    db
}
