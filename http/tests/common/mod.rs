// Ave HTTP Auth System - Common Test Utilities
//
// Shared utilities and helpers for all auth tests

use std::net::SocketAddr;
use std::sync::{
    Arc,
    atomic::{AtomicU16, Ordering},
};

use ave_bridge::{
    Bridge,
    auth::{
        ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig,
    },
};
use ave_http::{
    auth::{build_auth, database::AuthDatabase},
    server::build_routes,
};
use futures::future::join_all;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;

// Port counter to avoid collisions between tests running in parallel
#[allow(dead_code)]
static PORT_COUNTER: AtomicU16 = AtomicU16::new(7000);

/// Create a test database with default configuration
#[allow(dead_code)]
pub fn create_test_db() -> (AuthDatabase, TempDir) {
    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let path = dir.path().to_path_buf();

    let config = AuthConfig {
        enable: true,
        durability: false,
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
            max_requests: 10000, // Very high limit for tests to avoid blocking
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![], // No sensitive endpoints in basic tests
        },
        session: SessionConfig {
            audit_enable: true,
            audit_retention_days: 90,
            audit_max_entries: 1_000_000,
        },
    };

    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    (db, dir)
}

#[allow(dead_code)]
pub struct TestServer {
    addr: SocketAddr,
    memory_port: u16,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    #[allow(dead_code)]
    pub async fn build(
        enable_auth: bool,
        always_accept: bool,
        node: Option<(String, u16)>,
    ) -> (Self, Vec<TempDir>) {
        // Create temporary directories for databases (each test gets its own)
        let ave_db_temp_dir = tempfile::tempdir().expect("ave_db temp dir");
        let external_db_temp_dir =
            tempfile::tempdir().expect("external_db temp dir");
        let contracts_temp_dir =
            tempfile::tempdir().expect("contracts temp dir");
        let keys_dir = tempfile::tempdir().expect("contracts temp dir");
        let auth_dir = tempfile::tempdir().expect("contracts temp dir");

        let ave_db_path = ave_db_temp_dir.path().to_string_lossy().to_string();
        let external_db_path =
            external_db_temp_dir.path().to_string_lossy().to_string();
        let contracts_path =
            contracts_temp_dir.path().to_string_lossy().to_string();
        let keys_path = keys_dir.path().to_string_lossy().to_string();
        let auth_path = auth_dir.path().to_string_lossy().to_string();

        let mut vec_dir = vec![];
        vec_dir.push(ave_db_temp_dir);
        vec_dir.push(external_db_temp_dir);
        vec_dir.push(contracts_temp_dir);
        vec_dir.push(keys_dir);
        vec_dir.push(auth_dir);

        let boot_nodes = if let Some((peer_id, node_port)) = node {
            format!(
                r#"
            ,
                "boot_nodes": [
                    {{
                        "peer_id": "{peer_id}",
                        "address": ["/memory/{node_port}"]
                    }}
                ]
            "#
            )
        } else {
            "".to_string()
        };

        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        // Create bridge config with memory transport and unique database paths
        let bridge_config_json = format!(
            r#"
        {{
        "keys_path": "{keys_path}",
        "node": {{
            "is_service": true,
            "tracking_size": 200,
            "always_accept": {always_accept},
            "internal_db": {{ "db": "{ave_db_path}" }},
            "external_db": {{ "db": "{external_db_path}" }},
            "contracts_path": "{contracts_path}",
            "network": {{
                "node_type": "Bootstrap",
                "listen_addresses": [
                    "/memory/{port}"
        ]{boot_nodes}
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
            "enable": {enable_auth},
            "superadmin": "admin",
            "database_path": "{auth_path}",
            "api_key": {{
                "default_ttl_seconds": 3600,
                "max_keys_per_user": 20
            }},
            "lockout": {{
                "max_attempts": 3,
                "duration_seconds": 60
            }},
            "rate_limit": {{
                "enable": true,
                "window_seconds": 60,
                "max_requests": 10000,
                "limit_by_key": true,
                "limit_by_ip": true,
                "cleanup_interval_seconds": 1800
            }},
            "session": {{
                "audit_enable": true,
                "audit_retention_days": 30,
                "audit_max_entries": 1000000
            }}
        }},
        "http": {{
            "enable_doc": false
        }}
        }}
        "#
        );

        let bridge_config: ave_bridge::config::Config =
            serde_json::from_str(&bridge_config_json)
                .expect("Failed to parse bridge config");

        let (bridge, runners) =
            Bridge::build(&bridge_config, "test", "", "", None)
                .await
                .expect("Failed to create bridge");

        let auth_db: Option<Arc<AuthDatabase>> =
            build_auth(&bridge_config.auth, "AdminPass123!", None).await;

        let registry = bridge.registry().clone();
        // Build the REAL router using the actual server code
        let app = build_routes(false, bridge, auth_db, registry);

        // Bind to a random available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the server
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async move {
                join_all(runners).await;
            })
            .await
            .expect("Can not run axum server");
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        (
            Self {
                addr,
                memory_port: port,
                _handle: handle,
            },
            vec_dir,
        )
    }

    #[allow(dead_code)]
    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    #[allow(dead_code)]
    pub fn get_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    #[allow(dead_code)]
    pub fn memory_port(&self) -> u16 {
        self.memory_port
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

#[allow(dead_code)]
pub async fn make_request(
    client: &Client,
    url: &str,
    method: &str,
    api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut req = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        _ => panic!("Unsupported method: {}", method),
    };

    if let Some(key) = api_key {
        req = req.header("X-API-Key", key);
    }

    if let Some(b) = body {
        req = req.json(&b);
    }

    let resp = req.send().await.expect("Failed to send request");
    let status = resp.status();
    let text = resp.text().await.expect("Failed to read response");
    let json: Value = serde_json::from_str(&text).unwrap_or(json!({}));

    (status, json)
}

#[allow(dead_code)]
pub async fn login(
    server: &TestServer,
    client: &Client,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let (status, body) = make_request(
        client,
        &server.url("/login"),
        "POST",
        None,
        Some(json!({
            "username": username,
            "password": password
        })),
    )
    .await;

    if status == StatusCode::OK {
        Ok(body["api_key"].as_str().unwrap_or("").to_string())
    } else {
        Err(format!(
            "Login failed: {}",
            body["error"].as_str().unwrap_or("unknown")
        ))
    }
}
