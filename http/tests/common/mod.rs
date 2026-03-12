// Ave HTTP Auth System - Common Test Utilities
//
// Shared utilities and helpers for all auth tests

use std::io::ErrorKind;
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
use axum::{
    Router,
    body::{Body, to_bytes},
    extract::ConnectInfo,
    http::{Method, Request},
};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tower::ServiceExt;

pub trait TestDbExt {
    fn create_user(
        &self,
        username: &str,
        password: &str,
        role_ids: Option<Vec<i64>>,
        created_by: Option<i64>,
        must_change_password: Option<bool>,
    ) -> Result<
        ave_http::auth::models::User,
        ave_http::auth::database::DatabaseError,
    >;

    fn update_user(
        &self,
        user_id: i64,
        password: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<
        ave_http::auth::models::User,
        ave_http::auth::database::DatabaseError,
    >;

    fn delete_user(
        &self,
        user_id: i64,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn assign_role_to_user(
        &self,
        user_id: i64,
        role_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn remove_role_from_user(
        &self,
        user_id: i64,
        role_id: i64,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn admin_reset_password(
        &self,
        user_id: i64,
        new_password: &str,
    ) -> Result<
        ave_http::auth::models::User,
        ave_http::auth::database::DatabaseError,
    >;

    fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<
        ave_http::auth::models::Role,
        ave_http::auth::database::DatabaseError,
    >;

    fn update_role(
        &self,
        role_id: i64,
        description: Option<&str>,
    ) -> Result<
        ave_http::auth::models::Role,
        ave_http::auth::database::DatabaseError,
    >;

    fn delete_role(
        &self,
        role_id: i64,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn set_role_permission(
        &self,
        role_id: i64,
        resource: &str,
        action: &str,
        allowed: bool,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn remove_role_permission(
        &self,
        role_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn set_user_permission(
        &self,
        user_id: i64,
        resource: &str,
        action: &str,
        allowed: bool,
        granted_by: Option<i64>,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn remove_user_permission(
        &self,
        user_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn create_usage_plan(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        monthly_events: i64,
    ) -> Result<
        ave_http::auth::models::UsagePlan,
        ave_http::auth::database::DatabaseError,
    >;

    fn update_usage_plan(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        monthly_events: Option<i64>,
    ) -> Result<
        ave_http::auth::models::UsagePlan,
        ave_http::auth::database::DatabaseError,
    >;

    fn delete_usage_plan(
        &self,
        id: &str,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn assign_api_key_plan(
        &self,
        key_id: &str,
        plan_id: Option<&str>,
        assigned_by: Option<i64>,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;

    fn add_quota_extension(
        &self,
        key_id: &str,
        extra_events: i64,
        usage_month: Option<&str>,
        reason: Option<&str>,
        created_by: Option<i64>,
    ) -> Result<
        ave_http::auth::models::QuotaExtensionInfo,
        ave_http::auth::database::DatabaseError,
    >;

    fn revoke_api_key(
        &self,
        key_id: &str,
        revoked_by: Option<i64>,
        reason: Option<&str>,
    ) -> Result<(), ave_http::auth::database::DatabaseError>;
}

impl TestDbExt for AuthDatabase {
    fn create_user(
        &self,
        username: &str,
        password: &str,
        role_ids: Option<Vec<i64>>,
        created_by: Option<i64>,
        must_change_password: Option<bool>,
    ) -> Result<
        ave_http::auth::models::User,
        ave_http::auth::database::DatabaseError,
    > {
        self.create_user_transactional(
            username,
            password,
            role_ids,
            created_by,
            must_change_password,
            None,
        )
    }

    fn update_user(
        &self,
        user_id: i64,
        password: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<
        ave_http::auth::models::User,
        ave_http::auth::database::DatabaseError,
    > {
        self.update_user_with_roles_transactional(
            user_id, password, is_active, None, None, None,
        )
    }

    fn delete_user(
        &self,
        user_id: i64,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.delete_user_transactional(user_id, None)
    }

    fn assign_role_to_user(
        &self,
        user_id: i64,
        role_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.assign_role_to_user_transactional(
            user_id,
            role_id,
            assigned_by,
            None,
        )
    }

    fn remove_role_from_user(
        &self,
        user_id: i64,
        role_id: i64,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.remove_role_from_user_transactional(user_id, role_id, None)
    }

    fn admin_reset_password(
        &self,
        user_id: i64,
        new_password: &str,
    ) -> Result<
        ave_http::auth::models::User,
        ave_http::auth::database::DatabaseError,
    > {
        self.admin_reset_password_transactional(user_id, new_password, None)
    }

    fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<
        ave_http::auth::models::Role,
        ave_http::auth::database::DatabaseError,
    > {
        self.create_role_transactional(name, description, None)
    }

    fn update_role(
        &self,
        role_id: i64,
        description: Option<&str>,
    ) -> Result<
        ave_http::auth::models::Role,
        ave_http::auth::database::DatabaseError,
    > {
        self.update_role_transactional(role_id, description, None)
    }

    fn delete_role(
        &self,
        role_id: i64,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.delete_role_transactional(role_id, None)
    }

    fn set_role_permission(
        &self,
        role_id: i64,
        resource: &str,
        action: &str,
        allowed: bool,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.set_role_permission_transactional(
            role_id, resource, action, allowed, None,
        )
    }

    fn remove_role_permission(
        &self,
        role_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.remove_role_permission_transactional(
            role_id, resource, action, None,
        )
    }

    fn set_user_permission(
        &self,
        user_id: i64,
        resource: &str,
        action: &str,
        allowed: bool,
        granted_by: Option<i64>,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.set_user_permission_transactional(
            user_id, resource, action, allowed, granted_by, None,
        )
    }

    fn remove_user_permission(
        &self,
        user_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.remove_user_permission_transactional(
            user_id, resource, action, None,
        )
    }

    fn create_usage_plan(
        &self,
        id: &str,
        name: &str,
        description: Option<&str>,
        monthly_events: i64,
    ) -> Result<
        ave_http::auth::models::UsagePlan,
        ave_http::auth::database::DatabaseError,
    > {
        self.create_usage_plan_transactional(
            id,
            name,
            description,
            monthly_events,
            None,
        )
    }

    fn update_usage_plan(
        &self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        monthly_events: Option<i64>,
    ) -> Result<
        ave_http::auth::models::UsagePlan,
        ave_http::auth::database::DatabaseError,
    > {
        self.update_usage_plan_transactional(
            id,
            name,
            description,
            monthly_events,
            None,
        )
    }

    fn delete_usage_plan(
        &self,
        id: &str,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.delete_usage_plan_transactional(id, None)
    }

    fn assign_api_key_plan(
        &self,
        key_id: &str,
        plan_id: Option<&str>,
        assigned_by: Option<i64>,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.assign_api_key_plan_transactional(
            key_id,
            plan_id,
            assigned_by,
            None,
        )
    }

    fn add_quota_extension(
        &self,
        key_id: &str,
        extra_events: i64,
        usage_month: Option<&str>,
        reason: Option<&str>,
        created_by: Option<i64>,
    ) -> Result<
        ave_http::auth::models::QuotaExtensionInfo,
        ave_http::auth::database::DatabaseError,
    > {
        self.add_quota_extension_transactional(
            key_id,
            extra_events,
            usage_month,
            reason,
            created_by,
            None,
        )
    }

    fn revoke_api_key(
        &self,
        key_id: &str,
        revoked_by: Option<i64>,
        reason: Option<&str>,
    ) -> Result<(), ave_http::auth::database::DatabaseError> {
        self.revoke_api_key_transactional(key_id, revoked_by, reason, None)
    }
}

// Port counter to avoid collisions between tests running in parallel
static PORT_COUNTER: AtomicU16 = AtomicU16::new(7000);

/// Create a test database with default configuration
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
            prefix: "ave_node_".to_string(),
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

pub struct TestServer {
    addr: SocketAddr,
    memory_port: u16,
    handle: JoinHandle<()>,
    runners: Vec<JoinHandle<()>>,
}

impl Drop for TestServer {
    fn drop(&mut self) {
        self.handle.abort();
        for runner in &self.runners {
            runner.abort();
        }
    }
}

pub struct TestApp {
    app: Router,
    memory_port: u16,
    runners: Vec<JoinHandle<()>>,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        for runner in &self.runners {
            runner.abort();
        }
    }
}

async fn build_test_router(
    enable_auth: bool,
    always_accept: bool,
    node: Option<(String, u16)>,
) -> (Router, Vec<TempDir>, u16, Vec<JoinHandle<()>>) {
    let ave_db_temp_dir = tempfile::tempdir().expect("ave_db temp dir");
    let external_db_temp_dir =
        tempfile::tempdir().expect("external_db temp dir");
    let contracts_temp_dir = tempfile::tempdir().expect("contracts temp dir");
    let keys_dir = tempfile::tempdir().expect("contracts temp dir");
    let auth_dir = tempfile::tempdir().expect("contracts temp dir");

    let ave_db_path = ave_db_temp_dir.path().to_string_lossy().to_string();
    let external_db_path =
        external_db_temp_dir.path().to_string_lossy().to_string();
    let contracts_path =
        contracts_temp_dir.path().to_string_lossy().to_string();
    let keys_path = keys_dir.path().to_string_lossy().to_string();
    let auth_path = auth_dir.path().to_string_lossy().to_string();

    let vec_dir = vec![
        ave_db_temp_dir,
        external_db_temp_dir,
        contracts_temp_dir,
        keys_dir,
        auth_dir,
    ];

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
        String::new()
    };

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
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
        Bridge::build(&bridge_config, "test", "", "", None, None)
            .await
            .expect("Failed to create bridge");

    let auth_db: Option<Arc<AuthDatabase>> =
        build_auth(&bridge_config.auth, "AdminPass123!", None)
            .await
            .expect("failed to build auth");

    let registry = bridge.registry().clone();
    #[cfg(feature = "prometheus")]
    if let Some(db) = auth_db.as_ref() {
        let mut registry_guard = registry.lock().await;
        db.register_prometheus_metrics(&mut registry_guard);
    }
    let app = build_routes(
        false,
        bridge_config.http.proxy.clone(),
        bridge,
        auth_db,
        registry,
    );

    (app, vec_dir, port, runners)
}

impl TestServer {
    pub async fn build(
        enable_auth: bool,
        always_accept: bool,
        node: Option<(String, u16)>,
    ) -> Option<(Self, Vec<TempDir>)> {
        let (app, vec_dir, port, runners) =
            build_test_router(enable_auth, always_accept, node).await;

        // Bind to a random available port
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == ErrorKind::PermissionDenied => {
                eprintln!(
                    "skipping HTTP integration test: local TCP bind not permitted"
                );
                return None;
            }
            Err(err) => panic!("failed to bind test listener: {err}"),
        };
        let addr = listener.local_addr().unwrap();

        // Spawn the server
        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("Can not run axum server");
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Some((
            Self {
                addr,
                memory_port: port,
                handle,
                runners,
            },
            vec_dir,
        ))
    }

    pub fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }

    pub fn get_url(&self) -> String {
        format!("http://{}", self.addr)
    }

    pub fn memory_port(&self) -> u16 {
        self.memory_port
    }
}

impl TestApp {
    pub async fn build(
        enable_auth: bool,
        always_accept: bool,
        node: Option<(String, u16)>,
    ) -> (Self, Vec<TempDir>) {
        let (app, vec_dir, memory_port, runners) =
            build_test_router(enable_auth, always_accept, node).await;

        (
            Self {
                app,
                memory_port,
                runners,
            },
            vec_dir,
        )
    }

    pub fn memory_port(&self) -> u16 {
        self.memory_port
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

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

pub async fn make_app_request(
    app: &TestApp,
    path: &str,
    method: &str,
    api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let method = match method {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        _ => panic!("Unsupported method: {}", method),
    };

    let mut req = Request::builder().method(method).uri(path);

    if let Some(key) = api_key {
        req = req.header("X-API-Key", key);
    }

    let body = if let Some(value) = body {
        req = req.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value).expect("request body json"))
    } else {
        Body::empty()
    };

    let mut req = req.body(body).expect("request build");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3000))));

    let resp = app.app.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body");
    let json = serde_json::from_slice(&bytes).unwrap_or(json!({}));

    (status, json)
}

pub async fn make_app_request_raw(
    app: &TestApp,
    path: &str,
    method: &str,
    api_key: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, String) {
    let method = match method {
        "GET" => Method::GET,
        "POST" => Method::POST,
        "PUT" => Method::PUT,
        "DELETE" => Method::DELETE,
        "PATCH" => Method::PATCH,
        _ => panic!("Unsupported method: {}", method),
    };

    let mut req = Request::builder().method(method).uri(path);

    if let Some(key) = api_key {
        req = req.header("X-API-Key", key);
    }

    let body = if let Some(value) = body {
        req = req.header("content-type", "application/json");
        Body::from(serde_json::to_vec(&value).expect("request body json"))
    } else {
        Body::empty()
    };

    let mut req = req.body(body).expect("request build");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 3000))));

    let resp = app.app.clone().oneshot(req).await.expect("request failed");
    let status = resp.status();
    let bytes = to_bytes(resp.into_body(), usize::MAX)
        .await
        .expect("response body");
    let body = String::from_utf8(bytes.to_vec()).expect("utf8 response body");

    (status, body)
}

pub async fn login_app(
    app: &TestApp,
    username: &str,
    password: &str,
) -> Result<String, String> {
    let (status, body) = make_app_request(
        app,
        "/login",
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
