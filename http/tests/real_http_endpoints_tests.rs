// Ave HTTP Auth System - Real HTTP Integration Tests
//
// Tests that launch a REAL HTTP server and make actual HTTP requests to it
// Based on the comprehensive test script test_api_endpoints.sh
//
// These tests use the REAL server::build_routes() function, so any changes
// to the server code are immediately reflected in these tests.

use reqwest::{Client, StatusCode};
use serde_json::json;

use crate::common::{TestServer, login, make_request};
use test_log::test;

mod common;

// =============================================================================
// PHASE 1: AUTHENTICATION TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_login_success() {
    let (server, _dir) = TestServer::build(true, true, None).await;
    let client = Client::new();

    let result = login(&server, &client, "admin", "AdminPass123!").await;
    assert!(result.is_ok(), "Admin login should succeed");
    assert!(!result.unwrap().is_empty(), "API key should not be empty");
}

#[test(tokio::test)]
async fn test_login_wrong_password() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_login_nonexistent_user() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_list_users() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_user() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
            "password": "TestPass123!"
        })),
    )
    .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(body["username"], username);
    // Verify user has no superadmin role
    assert!(
        body["roles"].as_array().unwrap().is_empty()
            || !body["roles"]
                .as_array()
                .unwrap()
                .iter()
                .any(|r| r == "superadmin")
    );
}

#[test(tokio::test)]
async fn test_create_user_duplicate() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_user_weak_password() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_user_by_id() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
    // Verify admin has superadmin role
    assert!(
        body["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "superadmin")
    );
}

#[test(tokio::test)]
async fn test_update_user() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_delete_user() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_list_roles() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_role() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_role_duplicate() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_role() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_update_role() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_delete_role() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_list_resources() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_list_actions() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_set_role_permission() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
        Some(json!({"resource": "node_subject", "action": "get", "allowed": true})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[test(tokio::test)]
async fn test_get_role_permissions() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_list_all_api_keys() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_api_key_for_user() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_api_key_info() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
    let id = key_body["key_info"]["id"].as_str().unwrap();

    // Get key info
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{}", id)),
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["name"], "infokey");
}

#[test(tokio::test)]
async fn test_revoke_api_key() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
    let id = key_body["key_info"]["id"].as_str().unwrap();

    // Revoke key
    let (status, _) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{}", id)),
        "DELETE",
        Some(&api_key),
        Some(json!({"reason": "Test revocation"})),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[test(tokio::test)]
async fn test_rotate_api_key() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
    let id = key_body["key_info"]["id"].as_str().unwrap();
    let old_key = key_body["api_key"].as_str().unwrap();

    // Rotate key
    let (status, body) = make_request(
        &client,
        &server.url(&format!("/admin/api-keys/{}/rotate", id)),
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

#[test(tokio::test)]
async fn test_get_me() {
    let (server, _dir) = TestServer::build(true, true, None).await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, body) =
        make_request(&client, &server.url("/me"), "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["username"], "admin");
    // Verify admin has superadmin role
    assert!(
        body["roles"]
            .as_array()
            .unwrap()
            .iter()
            .any(|r| r == "superadmin")
    );
}

#[test(tokio::test)]
async fn test_get_my_permissions() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_my_permissions_detailed() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_query_audit_logs() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_audit_stats() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_rate_limit_stats() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_list_system_config() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_update_system_config() {
    let (server, _dir) = TestServer::build(true, true, None).await;
    let client = Client::new();
    let api_key = login(&server, &client, "admin", "AdminPass123!")
        .await
        .unwrap();

    let (status, _) = make_request(
        &client,
        &server.url("/admin/config/max_login_attempts"),
        "PUT",
        Some(&api_key),
        Some(json!({"value": 10})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

// =============================================================================
// PHASE 9: ERROR HANDLING TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_protected_endpoint_without_auth() {
    let (server, _dir) = TestServer::build(true, true, None).await;
    let client = Client::new();

    let (status, body) =
        make_request(&client, &server.url("/admin/users"), "GET", None, None)
            .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[test(tokio::test)]
async fn test_invalid_api_key() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_get_nonexistent_user() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_user_empty_username() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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

#[test(tokio::test)]
async fn test_create_role_empty_name() {
    let (server, _dir) = TestServer::build(true, true, None).await;
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
