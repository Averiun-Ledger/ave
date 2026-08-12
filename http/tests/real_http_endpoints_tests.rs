// Ave HTTP Auth System - Router Integration Tests
//
// Tests that exercise the real HTTP router through oneshot requests.
// Based on the comprehensive test script test_api_endpoints.sh.
//
// These tests use the real server::build_routes() function, so any changes
// to the router are immediately reflected here without requiring a listener.

use reqwest::StatusCode;
use serde_json::json;

use crate::common::{
    TestApp, login_app, make_app_request, materialize_role_test_path,
    role_test_request_body, server_auth_route_catalog,
    server_public_auth_route_catalog,
};
use test_log::test;

pub mod common;

// =============================================================================
// PHASE 1: AUTHENTICATION TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_login_success() {
    let (app, _dir) = TestApp::build(true, true, None).await;

    let result = login_app(&app, "admin", "AdminPass123!").await;
    assert!(result.is_ok(), "Admin login should succeed");
    assert!(!result.unwrap().is_empty(), "API key should not be empty");
}

#[test(tokio::test)]
async fn test_login_wrong_password() {
    let (app, _dir) = TestApp::build(true, true, None).await;

    let (status, body) = make_app_request(
        &app,
        "/login",
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
    let (app, _dir) = TestApp::build(true, true, None).await;

    let (status, _) = make_app_request(
        &app,
        "/login",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/admin/users", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!body.as_array().unwrap().is_empty());
}

#[test(tokio::test)]
async fn test_create_user() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let username =
        format!("testuser_{}", chrono::Utc::now().timestamp_millis());
    let (status, body) = make_app_request(
        &app,
        "/admin/users",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let username =
        format!("duplicate_{}", chrono::Utc::now().timestamp_millis());

    // Create first time
    let (status1, _) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    assert_eq!(status1, StatusCode::CREATED);

    // Try to create again
    let (status2, body2) = make_app_request(
        &app,
        "/admin/users",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/users",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Get admin user (ID 1)
    let (status, body) =
        make_app_request(&app, "/admin/users/1", "GET", Some(&api_key), None)
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user
    let username =
        format!("updatetest_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = create_body["id"].as_i64().unwrap();

    // Update user
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/users/{}", user_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user
    let username =
        format!("deletetest_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = create_body["id"].as_i64().unwrap();

    // Delete user
    let (status, _) = make_app_request(
        &app,
        &format!("/admin/users/{}", user_id),
        "DELETE",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    // Verify user is deleted
    let (status2, _) = make_app_request(
        &app,
        &format!("/admin/users/{}", user_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/admin/roles", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[test(tokio::test)]
async fn test_create_role() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let rolename =
        format!("testrole_{}", chrono::Utc::now().timestamp_millis());
    let (status, body) = make_app_request(
        &app,
        "/admin/roles",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let rolename = format!("duprole_{}", chrono::Utc::now().timestamp_millis());

    // Create first
    make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;

    // Try duplicate
    let (status, body) = make_app_request(
        &app,
        "/admin/roles",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create role
    let rolename = format!("getrole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Get role
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/roles/{}", role_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create role
    let rolename =
        format!("updaterole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Update role
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/roles/{}", role_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create role
    let rolename =
        format!("deleterole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Delete role
    let (status, _) = make_app_request(
        &app,
        &format!("/admin/roles/{}", role_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/admin/resources", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!body.as_array().unwrap().is_empty());
}

#[test(tokio::test)]
async fn test_list_actions() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/admin/actions", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(!body.as_array().unwrap().is_empty());
}

#[test(tokio::test)]
async fn test_set_role_permission() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create role
    let rolename =
        format!("permrole_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Set permission
    let (status, _) = make_app_request(
        &app,
        &format!("/admin/roles/{}/permissions", role_id),
        "POST",
        Some(&api_key),
        Some(json!({"resource": "node_subject", "action": "get", "allowed": true})),
    )
    .await;

    assert_eq!(status, StatusCode::OK);
}

#[test(tokio::test)]
async fn test_get_role_permissions() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create role
    let rolename =
        format!("getperms_{}", chrono::Utc::now().timestamp_millis());
    let (_, create_body) = make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": &rolename})),
    )
    .await;
    let role_id = create_body["id"].as_i64().unwrap();

    // Get permissions
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/roles/{}/permissions", role_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/admin/api-keys", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[test(tokio::test)]
async fn test_create_api_key_for_user() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user first
    let username =
        format!("apikeytest_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    // Create API key
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/user/{}", user_id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user and API key
    let username = format!("keyinfo_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let (_, key_body) = make_app_request(
        &app,
        &format!("/admin/api-keys/user/{}", user_id),
        "POST",
        Some(&api_key),
        Some(json!({"name": "infokey"})),
    )
    .await;
    let id = key_body["key_info"]["id"].as_str().unwrap();

    // Get key info
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}", id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user and API key
    let username =
        format!("revoketest_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let (_, key_body) = make_app_request(
        &app,
        &format!("/admin/api-keys/user/{}", user_id),
        "POST",
        Some(&api_key),
        Some(json!({"name": "revokekey"})),
    )
    .await;
    let id = key_body["key_info"]["id"].as_str().unwrap();

    // Revoke key
    let (status, _) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}", id),
        "DELETE",
        Some(&api_key),
        Some(json!({"reason": "Test revocation"})),
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[test(tokio::test)]
async fn test_rotate_api_key() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user and API key
    let username =
        format!("rotatetest_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let (_, key_body) = make_app_request(
        &app,
        &format!("/admin/api-keys/user/{}", user_id),
        "POST",
        Some(&api_key),
        Some(json!({"name": "rotatekey"})),
    )
    .await;
    let id = key_body["key_info"]["id"].as_str().unwrap();
    let old_key = key_body["api_key"].as_str().unwrap();

    // Rotate key
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}/rotate", id),
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/me", "GET", Some(&api_key), None).await;

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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/me/permissions", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().is_some());
}

#[test(tokio::test)]
async fn test_get_my_permissions_detailed() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/me/permissions/detailed",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/audit-logs",
        "GET",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().is_some());
    assert!(body["limit"].is_number());
    assert!(body["offset"].is_number());
    assert!(body["total"].is_number());
    assert!(body["has_more"].is_boolean());
}

#[test(tokio::test)]
async fn test_get_audit_stats() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/audit-logs/stats",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/rate-limits/stats",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) =
        make_app_request(&app, "/admin/config", "GET", Some(&api_key), None)
            .await;

    assert_eq!(status, StatusCode::OK);
    assert!(body["items"].as_array().is_some());
    assert!(body["limit"].is_number());
    assert!(body["offset"].is_number());
    assert!(body["total"].is_number());
    assert!(body["has_more"].is_boolean());
}

#[test(tokio::test)]
async fn test_update_system_config() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, _) = make_app_request(
        &app,
        "/admin/config/max_login_attempts",
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
    let (app, _dir) = TestApp::build(true, true, None).await;

    let (status, body) =
        make_app_request(&app, "/admin/users", "GET", None, None).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(body["error"].as_str().is_some());
}

#[test(tokio::test)]
async fn test_invalid_api_key() {
    let (app, _dir) = TestApp::build(true, true, None).await;

    let (status, body) = make_app_request(
        &app,
        "/admin/users",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/users/999999",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/users",
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
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let (status, body) = make_app_request(
        &app,
        "/admin/roles",
        "POST",
        Some(&api_key),
        Some(json!({"name": ""})),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().is_some());
}

#[test]
fn real_http_endpoint_tests_cover_declared_auth_routes() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let (app, _dir) = TestApp::build(true, true, None).await;
        let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

        let mut catalog = server_auth_route_catalog();
        catalog.extend(server_public_auth_route_catalog());

        for (method, path) in catalog {
            let materialized = materialize_role_test_path(&method, &path);
            assert!(
                !materialized.contains('{'),
                "real_http route still has unresolved placeholders: {method} {path} -> {materialized}"
            );

            let auth = match path.as_str() {
                "/login" | "/change-password" => None,
                _ => Some(api_key.as_str()),
            };
            let body = role_test_request_body(&method, &path);
            let http_method = method.to_ascii_uppercase();
            let (status, response_body) =
                make_app_request(&app, &materialized, &http_method, auth, body)
                    .await;

            assert_ne!(
                status,
                StatusCode::METHOD_NOT_ALLOWED,
                "auth route not mounted for {method} {path}: {response_body}"
            );
            assert!(
                status != StatusCode::INTERNAL_SERVER_ERROR
                    && status != StatusCode::BAD_GATEWAY,
                "auth route crashed for {method} {path}: {response_body}"
            );
        }
    });
}

// =============================================================================
// QUOTA ENFORCEMENT TESTS
// =============================================================================

/// A service key with a monthly quota of 10 must succeed on exactly 10
/// requests and be rejected on the 11th. This also guards against the
/// authentication pipeline consuming quota more than once per request
/// (the layer and the handler both extracting `ApiKeyAuthNew`).
#[test(tokio::test)]
async fn test_service_key_monthly_quota_enforced_once_per_request() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let mgmt_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Plan with a monthly quota of 10 events
    let (status, body) = make_app_request(
        &app,
        "/admin/usage-plans",
        "POST",
        Some(&mgmt_key),
        Some(json!({
            "id": "plan_quota_10",
            "name": "plan_quota_10",
            "monthly_events": 10
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "plan creation: {body}");

    // Service key for the admin user
    let (status, body) = make_app_request(
        &app,
        "/me/api-keys",
        "POST",
        Some(&mgmt_key),
        Some(json!({"name": "quota_service"})),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "service key creation: {body}");
    let service_key = body["api_key"].as_str().unwrap().to_string();
    let service_key_id = body["key_info"]["id"].as_str().unwrap().to_string();

    // Assign the plan to the service key
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{service_key_id}/plan"),
        "PUT",
        Some(&mgmt_key),
        Some(json!({"plan_id": "plan_quota_10"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "plan assignment: {body}");

    // Exactly 10 requests must succeed, one quota unit per request
    for i in 1..=10 {
        let (status, body) =
            make_app_request(&app, "/peer-id", "GET", Some(&service_key), None)
                .await;
        assert_eq!(status, StatusCode::OK, "request {i} must succeed: {body}");
    }

    // The 11th request exceeds the monthly quota
    let (status, body) =
        make_app_request(&app, "/peer-id", "GET", Some(&service_key), None)
            .await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "request 11 must be rejected: {body}"
    );

    // Usage must reflect exactly 10 consumed events
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{service_key_id}/quota"),
        "GET",
        Some(&mgmt_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "quota status: {body}");
    assert_eq!(
        body["used_events"].as_i64(),
        Some(10),
        "each request must consume exactly one quota unit"
    );
}

// =============================================================================
// PASSWORD CHANGE AUDIT TESTS
// =============================================================================

/// A password change (success or failure) must be written to the audit log
/// in the same transaction as the change itself.
#[test(tokio::test)]
async fn test_change_password_writes_audit_events() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let mgmt_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // User with a pending forced password change
    let (status, body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&mgmt_key),
        Some(json!({
            "username": "audit_pw_user",
            "password": "OldPass123!",
            "must_change_password": true
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {body}");
    let user_id = body["id"].as_i64().unwrap();

    // Failed attempt: wrong current password
    let (status, body) = make_app_request(
        &app,
        "/change-password",
        "POST",
        None,
        Some(json!({
            "username": "audit_pw_user",
            "current_password": "WrongPass123!",
            "new_password": "NewPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "wrong password: {body}");

    // Successful change
    let (status, body) = make_app_request(
        &app,
        "/change-password",
        "POST",
        None,
        Some(json!({
            "username": "audit_pw_user",
            "current_password": "OldPass123!",
            "new_password": "NewPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "password change: {body}");

    // The failure must be audited
    let (status, body) = make_app_request(
        &app,
        "/admin/audit-logs?endpoint=/change-password&success=false",
        "GET",
        Some(&mgmt_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit query failed: {body}");
    let items = body["items"].as_array().unwrap();
    assert!(
        items
            .iter()
            .any(|i| i["action_type"] == "password_change_failed"),
        "missing password_change_failed audit event: {body}"
    );

    // The success must be audited and attributed to the user
    let (status, body) = make_app_request(
        &app,
        "/admin/audit-logs?endpoint=/change-password&success=true",
        "GET",
        Some(&mgmt_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "audit query success: {body}");
    let items = body["items"].as_array().unwrap();
    assert!(
        items.iter().any(|i| i["action_type"] == "password_changed"
            && i["user_id"] == user_id),
        "missing password_changed audit event for user {user_id}: {body}"
    );
}

/// The documented 400s of the revoke endpoints: the key used for the request
/// cannot be revoked (admin route), and the management key cannot be revoked
/// through the self-service route.
#[test(tokio::test)]
async fn test_revoke_currently_used_key_returns_400() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let mgmt_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Locate the management key in use
    let (status, body) =
        make_app_request(&app, "/me/api-keys", "GET", Some(&mgmt_key), None)
            .await;
    assert_eq!(status, StatusCode::OK, "list keys: {body}");
    let management = body
        .as_array()
        .unwrap()
        .iter()
        .find(|k| k["is_management"] == true)
        .expect("management key in list")
        .clone();
    let key_id = management["id"].as_str().unwrap();
    let key_name = management["name"].as_str().unwrap();

    // Admin route: revoking the key in use is a 400, not a 204
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{key_id}"),
        "DELETE",
        Some(&mgmt_key),
        Some(json!({"reason": "self revocation"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "revoking the key in use must be rejected: {body}"
    );

    // Self-service route: the management key cannot be revoked either
    let (status, body) = make_app_request(
        &app,
        &format!("/me/api-keys/{key_name}"),
        "DELETE",
        Some(&mgmt_key),
        Some(json!({"reason": "self revocation"})),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "revoking the management key must be rejected: {body}"
    );

    // The key must still work after both failed attempts
    let (status, body) =
        make_app_request(&app, "/me", "GET", Some(&mgmt_key), None).await;
    assert_eq!(status, StatusCode::OK, "key must stay active: {body}");
}
