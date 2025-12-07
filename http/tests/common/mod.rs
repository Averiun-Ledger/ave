// Ave HTTP Auth System - Common Test Utilities
//
// Shared utilities and helpers for all auth tests

use std::sync::atomic::{AtomicU16, Ordering};

use ave_bridge::{Bridge, auth::{
    ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig,
}};
use ave_http::auth::database::AuthDatabase;
use tempfile::TempDir;
use tokio::task::JoinHandle;

// Port counter to avoid collisions between tests running in parallel
pub static PORT_COUNTER: AtomicU16 = AtomicU16::new(7000);

/// Create a test database with default configuration
pub fn create_test_db() -> (AuthDatabase, TempDir) {
    let dir = tempfile::tempdir().expect("Can not create temporal directory.");
    let path = dir.path().to_path_buf();

    let config = AuthConfig {
        enable: true,
        database_path: path,
        superadmin: "admin".to_string(),
        api_key: ApiKeyConfig {
            default_ttl_seconds: 0,
            max_keys_per_user: 10,
        },
        lockout: LockoutConfig {
            max_attempts: 5,
            duration_seconds: 900,
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
            log_all_requests: false,
        },
    };

    let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

    (db, dir)
}

pub async fn create_bridge() -> (Bridge, Vec<JoinHandle<()>>, Vec<TempDir>) {
    // Create temporary directories for databases (each test gets its own)
    let ave_db_temp_dir = tempfile::tempdir().expect("ave_db temp dir");
    let external_db_temp_dir =
        tempfile::tempdir().expect("external_db temp dir");
    let contracts_temp_dir = tempfile::tempdir().expect("contracts temp dir");
    let keys_dir = tempfile::tempdir().expect("contracts temp dir");

    let ave_db_path = ave_db_temp_dir.path().to_string_lossy().to_string();
    let external_db_path =
        external_db_temp_dir.path().to_string_lossy().to_string();
    let contracts_path =
        contracts_temp_dir.path().to_string_lossy().to_string();
    let keys_path = keys_dir.path().to_string_lossy().to_string();

    let mut vec_dir = vec![];
    vec_dir.push(ave_db_temp_dir);
    vec_dir.push(external_db_temp_dir);
    vec_dir.push(contracts_temp_dir);
    vec_dir.push(keys_dir);

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    // Create bridge config with memory transport and unique database paths
    let bridge_config_json = format!(
        r#"
        {{
        "keys_path": "{}",
        "prometheus": "127.0.0.1:0",
        "node": {{
            "always_accept": true,
            "ave_db": "{}",
            "external_db": "{}",
            "contracts_path": "{}",
            "network": {{
            "node_type": "Bootstrap",
            "listen_addresses": [
                "/memory/{}"
            ]
            }}
        }},
        "logging": {{
            "output": {{
            "stdout": true,
            "file": false,
            "api": false
            }}
        }},
        "auth": {{
            "enable": false
        }},
        "http": {{
            "enable_doc": false
        }}
        }}
        "#,
        keys_path, ave_db_path, external_db_path, contracts_path, port
    );

    let bridge_config: ave_bridge::config::Config =
        serde_json::from_str(&bridge_config_json)
            .expect("Failed to parse bridge config");

    // Build the bridge
    let (bridge, _runners) =
        Bridge::build(&bridge_config, "test", "test", None)
            .await
            .expect("Failed to create bridge");

    (bridge, _runners, vec_dir)
}
