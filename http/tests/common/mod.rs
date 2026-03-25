// Ave HTTP Auth System - Common Test Utilities
//
// Shared utilities and helpers for all auth tests

use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::path::PathBuf;
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
use futures::future::join_all;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
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

pub fn parse_route_catalog(
    source: &str,
    macro_name: &str,
) -> BTreeSet<(String, String)> {
    let start = format!("macro_rules! {macro_name}");
    let mut inside = false;
    let mut routes = BTreeSet::new();

    for line in source.lines() {
        let trimmed = line.trim();
        if !inside {
            if trimmed.starts_with(&start) {
                inside = true;
            }
            continue;
        }

        if trimmed == "};" {
            break;
        }

        if let Some(args) = trimmed
            .strip_prefix("$callback!(")
            .and_then(|rest| rest.strip_suffix(");"))
        {
            let parts: Vec<_> = args.split(',').map(str::trim).collect();
            if parts.len() < 3 {
                continue;
            }
            let method = match parts[1] {
                "external_get" => "get",
                other => other,
            };
            let path = parts[2].trim_matches('"');
            routes.insert((method.to_string(), path.to_string()));
        }
    }

    routes
}

pub fn server_main_route_catalog() -> BTreeSet<(String, String)> {
    parse_route_catalog(
        include_str!("../../src/server.rs"),
        "main_route_catalog",
    )
}

pub fn server_auth_route_catalog() -> BTreeSet<(String, String)> {
    parse_route_catalog(
        include_str!("../../src/server.rs"),
        "auth_route_catalog",
    )
}

pub fn server_public_auth_route_catalog() -> BTreeSet<(String, String)> {
    parse_route_catalog(
        include_str!("../../src/server.rs"),
        "public_auth_route_catalog",
    )
}

pub fn materialize_role_test_path(method: &str, path: &str) -> String {
    let subject_id = "JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI";
    let request_id = "JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI";
    let governance_id = "JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI";

    match (method, path) {
        ("get", "/subjects") => "/subjects?active=true".to_string(),
        ("get", "/events/{subject_id}") => {
            format!("/events/{subject_id}?quantity=10&page=1")
        }
        ("get", "/events-first-last/{subject_id}") => {
            format!("/events-first-last/{subject_id}?quantity=5")
        }
        ("get", "/admin/users") => {
            "/admin/users?include_inactive=false".to_string()
        }
        ("get", "/admin/api-keys/user/{user_id}") => {
            "/admin/api-keys/user/999?include_revoked=false".to_string()
        }
        ("get", "/admin/api-keys") => {
            "/admin/api-keys?include_revoked=false".to_string()
        }
        ("delete", "/admin/users/{user_id}/permissions") => {
            "/admin/users/999/permissions?resource=test&action=get".to_string()
        }
        ("post", "/admin/users/{user_id}/roles/{role_id}") => {
            "/admin/users/999/roles/2".to_string()
        }
        ("delete", "/admin/users/{user_id}/roles/{role_id}") => {
            "/admin/users/999/roles/2".to_string()
        }
        (_, "/admin/roles/{role_id}") => "/admin/roles/999".to_string(),
        ("get", "/admin/roles/{role_id}/permissions") => {
            "/admin/roles/999/permissions".to_string()
        }
        ("post", "/admin/roles/{role_id}/permissions") => {
            "/admin/roles/999/permissions".to_string()
        }
        ("delete", "/admin/roles/{role_id}/permissions") => {
            "/admin/roles/999/permissions?resource=test&action=get".to_string()
        }
        ("get", "/admin/audit-logs") => {
            "/admin/audit-logs?limit=10".to_string()
        }
        ("get", "/admin/audit-logs/stats") => {
            "/admin/audit-logs/stats?days=7".to_string()
        }
        ("get", "/admin/rate-limits/stats") => {
            "/admin/rate-limits/stats?hours=24".to_string()
        }
        ("get", "/me/api-keys") => {
            "/me/api-keys?include_revoked=false".to_string()
        }
        _ => path
            .replace("{subject_id}", subject_id)
            .replace("{request_id}", request_id)
            .replace("{governance_id}", governance_id)
            .replace("{sn}", "1")
            .replace("{user_id}", "999")
            .replace("{role_id}", "2")
            .replace("{key_id}", "999")
            .replace("{plan_id}", "test_plan")
            .replace("{name}", "test_key")
            .replace("{key}", "test_key"),
    }
}

pub fn role_test_request_body(method: &str, path: &str) -> Option<Value> {
    match (method, path) {
        ("patch", "/approval/{subject_id}") => Some(json!("Accepted")),
        ("put", "/auth/{subject_id}") => {
            Some(json!(["ExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI"]))
        }
        ("post", "/request") => Some(json!({"request": {}, "signature": null})),
        ("post", "/login") => {
            Some(json!({"username": "admin", "password": "AdminPass123!"}))
        }
        ("post", "/change-password") => Some(json!({
            "username": "admin",
            "old_password": "WrongPass123!",
            "new_password": "AdminPass123!"
        })),
        ("post", "/admin/users") => {
            Some(json!({"username": "test", "password": "Test123!"}))
        }
        ("put", "/admin/users/{user_id}") => {
            Some(json!({"password": "NewPass123!"}))
        }
        ("post", "/admin/users/{user_id}/permissions") => {
            Some(json!({"resource": "test", "action": "get", "allowed": true}))
        }
        ("post", "/admin/users/{user_id}/password") => {
            Some(json!({"password": "NewPass123!"}))
        }
        ("post", "/admin/roles") => Some(json!({"name": "test_role"})),
        ("put", "/admin/roles/{role_id}") => {
            Some(json!({"description": "updated"}))
        }
        ("post", "/admin/roles/{role_id}/permissions") => {
            Some(json!({"resource": "test", "action": "get", "allowed": true}))
        }
        ("post", "/admin/api-keys/user/{user_id}") => {
            Some(json!({"name": "test_key"}))
        }
        ("delete", "/admin/api-keys/{key_id}") => {
            Some(json!({"reason": "test"}))
        }
        ("post", "/admin/api-keys/{key_id}/rotate") => {
            Some(json!({"name": "rotated_key"}))
        }
        ("put", "/admin/api-keys/{key_id}/plan") => {
            Some(json!({"plan_id": "test_plan"}))
        }
        ("post", "/admin/api-keys/{key_id}/quota-extensions") => {
            Some(json!({"extra_events": 100, "reason": "test"}))
        }
        ("post", "/admin/usage-plans") => Some(json!({
            "id": "test_plan",
            "name": "Test plan",
            "monthly_events": 1000
        })),
        ("put", "/admin/usage-plans/{plan_id}") => Some(json!({
            "name": "Updated plan",
            "monthly_events": 2000
        })),
        ("put", "/admin/config/{key}") => Some(json!({"value": 1234})),
        ("post", "/me/api-keys") => {
            Some(json!({"name": "test_key", "description": "test"}))
        }
        _ => None,
    }
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
    graceful_token: CancellationToken,
    handle: Option<JoinHandle<()>>,
    runners: Vec<JoinHandle<()>>,
}

#[derive(Debug, Clone)]
pub struct TestPersistencePaths {
    pub ave_db_path: PathBuf,
    pub external_db_path: PathBuf,
    pub contracts_path: PathBuf,
    pub keys_path: PathBuf,
    pub auth_path: PathBuf,
}

impl TestPersistencePaths {
    pub fn from_tempdirs(dirs: &[TempDir]) -> Self {
        assert!(
            dirs.len() >= 5,
            "expected at least 5 tempdirs (ave_db, ext_db, contracts, keys, auth)"
        );

        Self {
            ave_db_path: dirs[0].path().to_path_buf(),
            external_db_path: dirs[1].path().to_path_buf(),
            contracts_path: dirs[2].path().to_path_buf(),
            keys_path: dirs[3].path().to_path_buf(),
            auth_path: dirs[4].path().to_path_buf(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct TestServerOptions {
    pub enable_auth: bool,
    pub always_accept: bool,
    pub node: Option<(String, u16)>,
    pub safe_mode: bool,
    pub node_type: String,
    pub persistence: Option<TestPersistencePaths>,
}

impl Default for TestServerOptions {
    fn default() -> Self {
        Self {
            enable_auth: true,
            always_accept: false,
            node: None,
            safe_mode: false,
            node_type: "Bootstrap".to_string(),
            persistence: None,
        }
    }
}

pub struct TestApp {
    app: Router,
    memory_port: u16,
    graceful_token: CancellationToken,
    runners: Vec<JoinHandle<()>>,
}

impl Drop for TestApp {
    fn drop(&mut self) {
        self.graceful_token.cancel();
        for runner in &self.runners {
            runner.abort();
        }
    }
}

async fn build_test_router(
    enable_auth: bool,
    always_accept: bool,
    node: Option<(String, u16)>,
) -> (
    Router,
    Vec<TempDir>,
    u16,
    Vec<JoinHandle<()>>,
    CancellationToken,
) {
    build_test_router_with_options(TestServerOptions {
        enable_auth,
        always_accept,
        node,
        ..Default::default()
    })
    .await
}

async fn build_test_router_with_options(
    options: TestServerOptions,
) -> (
    Router,
    Vec<TempDir>,
    u16,
    Vec<JoinHandle<()>>,
    CancellationToken,
) {
    let TestServerOptions {
        enable_auth,
        always_accept,
        node,
        safe_mode,
        node_type,
        persistence,
    } = options;

    let (
        ave_db_path,
        external_db_path,
        contracts_path,
        keys_path,
        auth_path,
        vec_dir,
    ) = if let Some(paths) = persistence {
        (
            paths.ave_db_path.to_string_lossy().to_string(),
            paths.external_db_path.to_string_lossy().to_string(),
            paths.contracts_path.to_string_lossy().to_string(),
            paths.keys_path.to_string_lossy().to_string(),
            paths.auth_path.to_string_lossy().to_string(),
            vec![],
        )
    } else {
        let ave_db_temp_dir = tempfile::tempdir().expect("ave_db temp dir");
        let external_db_temp_dir =
            tempfile::tempdir().expect("external_db temp dir");
        let contracts_temp_dir =
            tempfile::tempdir().expect("contracts temp dir");
        let keys_dir = tempfile::tempdir().expect("keys temp dir");
        let auth_dir = tempfile::tempdir().expect("auth temp dir");

        let ave_db_path = ave_db_temp_dir.path().to_string_lossy().to_string();
        let external_db_path =
            external_db_temp_dir.path().to_string_lossy().to_string();
        let contracts_path =
            contracts_temp_dir.path().to_string_lossy().to_string();
        let keys_path = keys_dir.path().to_string_lossy().to_string();
        let auth_path = auth_dir.path().to_string_lossy().to_string();

        (
            ave_db_path,
            external_db_path,
            contracts_path,
            keys_path,
            auth_path,
            vec![
                ave_db_temp_dir,
                external_db_temp_dir,
                contracts_temp_dir,
                keys_dir,
                auth_dir,
            ],
        )
    };

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
            "safe_mode": {safe_mode},
            "internal_db": {{ "db": "{ave_db_path}" }},
            "external_db": {{ "db": "{external_db_path}" }},
            "contracts_path": "{contracts_path}",
            "network": {{
                "node_type": "{node_type}",
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
    let graceful_token = bridge.graceful_token().clone();

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

    (app, vec_dir, port, runners, graceful_token)
}

impl TestServer {
    pub async fn build(
        enable_auth: bool,
        always_accept: bool,
        node: Option<(String, u16)>,
    ) -> Option<(Self, Vec<TempDir>)> {
        let (app, vec_dir, port, runners, graceful_token) =
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
                graceful_token,
                handle: Some(handle),
                runners,
            },
            vec_dir,
        ))
    }

    pub async fn build_with_options(
        options: TestServerOptions,
    ) -> Option<(Self, Vec<TempDir>)> {
        let (app, vec_dir, port, runners, graceful_token) =
            build_test_router_with_options(options).await;

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

        let handle = tokio::spawn(async move {
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .await
            .expect("Can not run axum server");
        });

        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Some((
            Self {
                addr,
                memory_port: port,
                graceful_token,
                handle: Some(handle),
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

    pub async fn shutdown(mut self) {
        self.graceful_token.cancel();
        let runners = std::mem::take(&mut self.runners);
        let _ = join_all(runners).await;

        if let Some(handle) = self.handle.take() {
            handle.abort();
            let _ = handle.await;
        }
    }
}

impl TestApp {
    pub async fn build(
        enable_auth: bool,
        always_accept: bool,
        node: Option<(String, u16)>,
    ) -> (Self, Vec<TempDir>) {
        let (app, vec_dir, memory_port, runners, graceful_token) =
            build_test_router(enable_auth, always_accept, node).await;

        (
            Self {
                app,
                memory_port,
                graceful_token,
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

pub const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

pub async fn create_governance(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/request"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "create",
                "data": {
                    "name": "Governance",
                    "description": "A governance",
                    "schema_id": "governance"
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "request creation failed: {body}");
    body
}

pub async fn add_example_schema_to_governance(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    governance_id: &str,
    public_key: &str,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/request"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "fact",
                "data": {
                    "subject_id": governance_id,
                    "payload": {
                        "members": {
                            "add": [
                                {
                                    "name": "node1",
                                    "key": public_key
                                }
                            ]
                        },
                        "schemas": {
                            "add": [
                                {
                                    "id": "Example1",
                                    "contract": EXAMPLE_CONTRACT,
                                    "initial_value": {
                                        "one": 0,
                                        "two": 0,
                                        "three": 0
                                    }
                                }
                            ]
                        },
                        "roles": {
                            "schema": [
                                {
                                    "schema_id": "Example1",
                                    "add": {
                                        "evaluator": [{"name": "Owner", "namespace": []}],
                                        "validator": [{"name": "Owner", "namespace": []}],
                                        "witness": [{"name": "Owner", "namespace": []}],
                                        "creator": [
                                            {"name": "Owner", "namespace": [], "quantity": "infinity"},
                                            {"name": "node1", "namespace": [], "quantity": "infinity"}
                                        ],
                                        "issuer": [{"name": "Owner", "namespace": []}]
                                    }
                                }
                            ]
                        }
                    }
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "schema fact failed: {body}");
    body
}

pub async fn create_subject(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    governance_id: &str,
    schema_id: &str,
    name: &str,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/request"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "create",
                "data": {
                    "name": name,
                    "description": "A subject",
                    "schema_id": schema_id,
                    "governance_id": governance_id
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "subject creation failed: {body}");
    body
}

pub async fn add_governance_member_as_witness(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    governance_id: &str,
    public_key: &str,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/request"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "fact",
                "data": {
                    "subject_id": governance_id,
                    "payload": {
                        "members": {
                            "add": [
                                {
                                    "name": "Node1",
                                    "key": public_key
                                }
                            ]
                        },
                        "roles": {
                            "governance": {
                                "add": {
                                    "witness": ["Node1"]
                                }
                            }
                        }
                    }
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "governance fact failed: {body}");
    body
}

pub async fn add_tracker_fact_mod_one(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    subject_id: &str,
    data: u32,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/request"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "fact",
                "data": {
                    "subject_id": subject_id,
                    "payload": {
                        "ModOne": {
                            "data": data
                        }
                    }
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "tracker fact failed: {body}");
    body
}

pub async fn transfer_subject(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    subject_id: &str,
    new_owner: &str,
) -> Value {
    let (status, body) = make_request(
        client,
        &server.url("/request"),
        "POST",
        api_key,
        Some(json!({
            "request": {
                "event": "transfer",
                "data": {
                    "subject_id": subject_id,
                    "new_owner": new_owner
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "transfer request failed: {body}");
    body
}

pub async fn wait_request_finish(
    client: &Client,
    server: &TestServer,
    api_key: Option<&str>,
    request_id: &str,
) {
    for _ in 0..60 {
        let (status, body) = make_request(
            client,
            &server.url(&format!("/request/{request_id}")),
            "GET",
            api_key,
            None,
        )
        .await;
        assert!(status.is_success(), "request status failed: {body}");
        if body["state"] == "Finish" {
            tokio::time::sleep(tokio::time::Duration::from_secs(1)).await;
            return;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
    }

    panic!("request {request_id} did not finish in time");
}
