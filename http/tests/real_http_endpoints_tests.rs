// Ave HTTP Auth System - Real HTTP Integration Tests
//
// Tests that launch a REAL HTTP server and make actual HTTP requests to it
// Based on the comprehensive test script test_api_endpoints.sh
//
// These tests use the REAL server::build_routes() function, so any changes
// to the server code are immediately reflected in these tests.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU16, Ordering};

use ave_bridge::{
    Bridge,
    auth::{AuthConfig, RateLimitConfig},
};
use ave_http::auth::database::AuthDatabase;
use ave_http::server::build_routes;
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use tokio::net::TcpListener;

use crate::common::PORT_COUNTER;

mod common;

// =============================================================================
// Test Infrastructure
// =============================================================================

struct TestServer {
    addr: SocketAddr,
    _handle: tokio::task::JoinHandle<()>,
}

impl TestServer {
    async fn new() -> Self {
        Self::with_config(
            20, // max_requests for rate limiting
            3,  // max_attempts for lockout
            60, // lockout duration_seconds
        )
        .await
    }

    async fn with_config(
        max_requests: u32,
        max_attempts: u32,
        lockout_duration_secs: u64,
    ) -> Self {
        // Get unique ports for this test (bridge network + prometheus)
        let bridge_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let prometheus_port = 3050 + bridge_port - 7000; // Offset from base prometheus port

        // Create temporary directories for databases (each test gets its own)
        let auth_temp_dir = tempfile::tempdir().expect("auth temp dir");
        let ave_db_temp_dir = tempfile::tempdir().expect("ave_db temp dir");
        let external_db_temp_dir =
            tempfile::tempdir().expect("external_db temp dir");
        let contracts_temp_dir =
            tempfile::tempdir().expect("contracts temp dir");

        let auth_db_path = auth_temp_dir.path().to_path_buf();
        let ave_db_path = ave_db_temp_dir.path().to_string_lossy().to_string();
        let external_db_path =
            external_db_temp_dir.path().to_string_lossy().to_string();
        let contracts_path =
            contracts_temp_dir.path().to_string_lossy().to_string();

        // Keep temp dirs alive for the duration of the test
        std::mem::forget(auth_temp_dir);
        std::mem::forget(ave_db_temp_dir);
        std::mem::forget(external_db_temp_dir);
        std::mem::forget(contracts_temp_dir);

        // Create test database with specific configuration
        let mut auth_config = AuthConfig::default();
        auth_config.enable = true;
        auth_config.superadmin = "admin".to_string();
        auth_config.database_path = auth_db_path;

        // Configure rate limiting as per test requirements
        auth_config.rate_limit = RateLimitConfig {
            max_requests,
            window_seconds: 60,
            ..RateLimitConfig::default()
        };

        // Clone auth_config for bridge config before moving it
        let auth_config_for_bridge = auth_config.clone();

        let auth_db =
            Arc::new(AuthDatabase::new(auth_config, "AdminPass123!").unwrap());

        // Set system config values (lockout, API key defaults, audit settings)
        let _ = auth_db.update_system_config(
            "max_login_attempts",
            &max_attempts.to_string(),
            None,
        );
        let _ = auth_db.update_system_config(
            "lockout_duration_seconds",
            &lockout_duration_secs.to_string(),
            None,
        );
        let _ = auth_db.update_system_config(
            "default_api_key_ttl_seconds",
            "3600",
            None,
        );
        let _ =
            auth_db.update_system_config("max_api_keys_per_user", "20", None);
        let _ = auth_db.update_system_config(
            "audit_log_retention_days",
            "30",
            None,
        );

        // Create REAL bridge config matching production setup but using memory transport for tests
        let bridge_config_json = format!(
            r#"
                {{
                "keys_path": "/tmp/key_{}",
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
                    "stdout": false,
                    "file": false,
                    "api": false
                    }},
                    "file_path": "/tmp/test-log",
                    "rotation": "hourly",
                    "max_size": 52428800,
                    "max_files": 5
                }},
                "http": {{
                    "enable_doc": false
                }}
                }}
            "#,
            bridge_port,
            ave_db_path,
            external_db_path,
            contracts_path,
            bridge_port
        );

        let mut bridge_config: ave_bridge::config::Config =
            serde_json::from_str(&bridge_config_json)
                .expect("Failed to parse bridge config");

        // Override auth config with our test database config
        bridge_config.auth = auth_config_for_bridge;
        // Use unique prometheus port to avoid conflicts
        bridge_config.prometheus = format!("127.0.0.1:{}", prometheus_port);

        let (bridge, _runners) =
            Bridge::build(&bridge_config, "test", "test", None)
                .await
                .expect("Failed to create bridge");

        // Build the REAL router using the actual server code
        let app = build_routes(false, bridge, Some(auth_db));

        // Bind to a random available port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        // Spawn the server
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        // Give the server a moment to start
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;

        Self {
            addr,
            _handle: handle,
        }
    }

    fn url(&self, path: &str) -> String {
        format!("http://{}{}", self.addr, path)
    }
}

// =============================================================================
// Helper Functions
// =============================================================================

async fn make_request(
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

async fn login(
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

// =============================================================================
// PHASE 1: AUTHENTICATION TESTS
// =============================================================================

#[tokio::test]
async fn test_login_success() {
    let server = TestServer::new().await;
    let client = Client::new();

    let result = login(&server, &client, "admin", "AdminPass123!").await;
    assert!(result.is_ok(), "Admin login should succeed");
    assert!(!result.unwrap().is_empty(), "API key should not be empty");
}

#[tokio::test]
async fn test_login_wrong_password() {
    let server = TestServer::new().await;
    let client = Client::new();

    let (status, body) = make_request(
        &client,
        &server.url("/login"),
        "POST",
        None,
        Some(json!({"username": "admin", "password": "wrongpass"})),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_login_nonexistent_user() {
    let server = TestServer::new().await;
    let client = Client::new();

    let (status, _) = make_request(
        &client,
        &server.url("/login"),
        "POST",
        None,
        Some(json!({"username": "nonexistent", "password": "pass"})),
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

// =============================================================================
// PHASE 2: USER MANAGEMENT TESTS
// =============================================================================

#[tokio::test]
async fn test_list_users() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/users"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
    assert!(!body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_create_user() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let username =
        format!("testuser_{}", chrono::Utc::now().timestamp_millis());
    let (status, body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({
            "username": username,
            "password": "TestPass123!",
            "is_superadmin": false
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["username"], username);
    assert_eq!(body["is_superadmin"], false);
}

#[tokio::test]
async fn test_create_user_duplicate() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let username =
        format!("duplicate_{}", chrono::Utc::now().timestamp_millis());

    // Create first time
    let (status1, _) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    assert_eq!(status1, StatusCode::CREATED);

    // Try to create again
    let (status2, body2) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;

    assert_eq!(status2, StatusCode::CONFLICT);
    assert!(body2["error"].as_str().unwrap().contains("already exists"));
}

#[tokio::test]
async fn test_create_user_weak_password() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": "weakpassuser", "password": "password"})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    let error_msg = body["error"].as_str().unwrap().to_lowercase();
    assert!(
        error_msg.contains("password")
            || error_msg.contains("uppercase")
            || error_msg.contains("lowercase")
            || error_msg.contains("digit")
            || error_msg.contains("special")
    );
}

#[tokio::test]
async fn test_get_user_by_id() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Get admin user (ID 1)
    let (status, body) = make_request(
        &client,
        &server.url("/admin/users/1"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "admin");
    assert_eq!(body["is_superadmin"], true);
}

#[tokio::test]
async fn test_update_user() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create user
    let username =
        format!("updatetest_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = create_body["id"].as_i64().unwrap();

    // Update user
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/users/{}", user_id)),
        "PUT",
        Some(&api_key),
        Some(json!({"is_active": false})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["is_active"], false);
}

#[tokio::test]
async fn test_delete_user() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create user
    let username =
        format!("deletetest_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = create_body["id"].as_i64().unwrap();

    // Delete user
    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/users/{}", user_id)),
        "DELETE",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify user is deleted
    let (status2, _) = make_request(
        &client,
        &server.url(&format!("/admin/users/{}", user_id)),
        "GET",
        Some(&api_key),
        None,
    )
    .await;
    assert_eq!(status2, StatusCode::NOT_FOUND);
}

// =============================================================================
// PHASE 3: ROLE MANAGEMENT TESTS
// =============================================================================

#[tokio::test]
async fn test_list_roles() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[tokio::test]
async fn test_create_role() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let rolename =
        format!("testrole_{}", chrono::Utc::now().timestamp_millis());
    let (status, body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename, "description": "Test role"})),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["name"], rolename);
}

#[tokio::test]
async fn test_create_role_duplicate() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let rolename = format!("duprole_{}", chrono::Utc::now().timestamp_millis());

    // Create first
    make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;

    // Try duplicate
    let (status, body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert!(body["error"].as_str().unwrap().contains("already exists"));
}

#[tokio::test]
async fn test_get_role() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create role
    let rolename = format!("getrole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Get role
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/roles/{}", role_id)),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], rolename);
}

#[tokio::test]
async fn test_update_role() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create role
    let rolename =
        format!("updaterole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Update role
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/roles/{}", role_id)),
        "PUT",
        Some(&api_key),
        Some(json!({"description": "Updated description"})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["description"], "Updated description");
}

#[tokio::test]
async fn test_delete_role() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create role
    let rolename =
        format!("deleterole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Delete role
    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/roles/{}", role_id)),
        "DELETE",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

// =============================================================================
// PHASE 4: PERMISSION TESTS
// =============================================================================

#[tokio::test]
async fn test_list_resources() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/resources"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
    assert!(!body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_list_actions() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/actions"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
    assert!(!body.as_array().unwrap().is_empty());
}

#[tokio::test]
async fn test_set_role_permission() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create role
    let rolename =
        format!("permrole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Set permission
    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/roles/{}/permissions", role_id)),
        "POST",
        Some(&api_key),
        Some(json!({"resource": "users", "action": "read", "allowed": true})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[tokio::test]
async fn test_get_role_permissions() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create role
    let rolename =
        format!("getperms_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Get permissions
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/roles/{}/permissions", role_id)),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

// =============================================================================
// PHASE 5: API KEY MANAGEMENT TESTS
// =============================================================================

#[tokio::test]
async fn test_list_all_api_keys() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/api-keys"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[tokio::test]
async fn test_create_api_key_for_user() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create user first
    let username =
        format!("apikeytest_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    // Create API key
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/user/{}", user_id)),
        "POST",
        Some(&api_key),
        Some(json!({"name": "testkey", "description": "Test API key"})),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(body["api_key"].as_str().is_some());
    assert!(!body["api_key"].as_str().unwrap().is_empty());
}

#[tokio::test]
async fn test_get_api_key_info() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create user and API key
    let username = format!("keyinfo_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let (_, key_body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/user/{}", user_id)),
        "POST",
        Some(&api_key),
        Some(json!({"name": "infokey"})),
    )
    .await;
    let key_id = key_body["key_info"]["id"].as_i64().unwrap();

    // Get key info
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{}", key_id)),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "infokey");
}

#[tokio::test]
async fn test_revoke_api_key() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create user and API key
    let username =
        format!("revoketest_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let (_, key_body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/user/{}", user_id)),
        "POST",
        Some(&api_key),
        Some(json!({"name": "revokekey"})),
    )
    .await;
    let key_id = key_body["key_info"]["id"].as_i64().unwrap();

    // Revoke key
    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{}", key_id)),
        "DELETE",
        Some(&api_key),
        Some(json!({"reason": "Test revocation"})),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn test_rotate_api_key() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    // Create user and API key
    let username =
        format!("rotatetest_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let (_, key_body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/user/{}", user_id)),
        "POST",
        Some(&api_key),
        Some(json!({"name": "rotatekey"})),
    )
    .await;
    let key_id = key_body["key_info"]["id"].as_i64().unwrap();
    let old_key = key_body["api_key"].as_str().unwrap();

    // Rotate key
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{}/rotate", key_id)),
        "POST",
        Some(&api_key),
        Some(json!({"reason": "Test rotation"})),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert!(body["api_key"].as_str().is_some());
    assert_ne!(body["api_key"].as_str().unwrap(), old_key);
}

// =============================================================================
// PHASE 6: USER INTROSPECTION TESTS
// =============================================================================

#[tokio::test]
async fn test_get_me() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) =
        make_request(&client, &server.url("/me"), "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "admin");
    assert_eq!(body["is_superadmin"], true);
}

#[tokio::test]
async fn test_get_my_permissions() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/me/permissions"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[tokio::test]
async fn test_get_my_permissions_detailed() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/me/permissions/detailed"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["user_id"].is_number());
    assert_eq!(body["username"], "admin");
}

// =============================================================================
// PHASE 7: AUDIT LOG TESTS
// =============================================================================

#[tokio::test]
async fn test_query_audit_logs() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/audit-logs"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[tokio::test]
async fn test_get_audit_stats() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/audit-logs/stats"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["total_logs"].is_number());
}

#[tokio::test]
async fn test_get_rate_limit_stats() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/rate-limits/stats"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    // Rate limit stats may return empty array or object depending on activity
    assert!(body.is_array() || body.is_object());
}

// =============================================================================
// PHASE 8: SYSTEM CONFIG TESTS
// =============================================================================

#[tokio::test]
async fn test_list_system_config() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/config"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[tokio::test]
async fn test_update_system_config() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/config/read_only_mode"),
        "PUT",
        Some(&api_key),
        Some(json!({"value": "0"})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["key"], "read_only_mode");
    assert_eq!(body["value"], "0");
}

// =============================================================================
// PHASE 9: ERROR HANDLING TESTS
// =============================================================================

#[tokio::test]
async fn test_protected_endpoint_without_auth() {
    let server = TestServer::new().await;
    let client = Client::new();

    let (status, body) =
        make_request(&client, &server.url("/admin/users"), "GET", None, None)
            .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_invalid_api_key() {
    let server = TestServer::new().await;
    let client = Client::new();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/users"),
        "GET",
        Some("invalid_key_12345"),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_get_nonexistent_user() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/users/999999"),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_create_user_empty_username() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/users"),
        "POST",
        Some(&api_key),
        Some(json!({"username": "", "password": "TestPass123!"})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().is_some());
}

#[tokio::test]
async fn test_create_role_empty_name() {
    let server = TestServer::new().await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/admin/roles"),
        "POST",
        Some(&api_key),
        Some(json!({"name": ""})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().is_some());
}
