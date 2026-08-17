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
    TestApp, TestServerOptions, login_app, make_app_raw_body_request,
    make_app_request, make_app_request_raw, materialize_role_test_path,
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
        &format!("/admin/api-keys/{}?reason=Test%20revocation", id),
        "DELETE",
        Some(&api_key),
        None,
    )
    .await;

    assert_eq!(status, StatusCode::NO_CONTENT);

    // The reason travels in the query string and must be persisted
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}", id),
        "GET",
        Some(&api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get revoked key: {body}");
    assert_eq!(body["revoked"], true);
    assert_eq!(body["revoked_reason"], "Test revocation");
}

/// A revoked API key must be rejected with a generic 401 body: the specific
/// reason (revoked, expired, inactive account…) never leaves the server.
#[test(tokio::test)]
async fn test_revoked_key_gets_generic_401() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user and API key
    let username =
        format!("generic401_{}", chrono::Utc::now().timestamp_millis());
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
        Some(json!({"name": "generic401_key"})),
    )
    .await;
    let key_id = key_body["key_info"]["id"].as_str().unwrap();
    let service_key = key_body["api_key"].as_str().unwrap().to_string();

    // The key authenticates (a fresh user holds no roles, so /me is 403 —
    // proving the 401 after revocation comes from authentication).
    let (status, _) =
        make_app_request(&app, "/me", "GET", Some(&service_key), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Revoke the key
    let (status, _) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}?reason=compromised", key_id),
        "DELETE",
        Some(&api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The revoked key gets a generic 401 without the specific reason
    let (status, body) =
        make_app_request(&app, "/me", "GET", Some(&service_key), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Invalid API key");
}

/// Deleting a user must invalidate their API keys: a key of a deleted user
/// gets the same generic 401 as a revoked or unknown key.
#[test(tokio::test)]
async fn test_deleted_user_key_gets_generic_401() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create user and API key
    let username =
        format!("deleted401_{}", chrono::Utc::now().timestamp_millis());
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
        Some(json!({"name": "deleteduser_key"})),
    )
    .await;
    let service_key = key_body["api_key"].as_str().unwrap().to_string();

    // The key authenticates (a fresh user holds no roles, so /me is 403 —
    // proving the 401 after deletion comes from authentication).
    let (status, _) =
        make_app_request(&app, "/me", "GET", Some(&service_key), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Delete the user
    let (status, _) = make_app_request(
        &app,
        &format!("/admin/users/{}", user_id),
        "DELETE",
        Some(&api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    // The deleted user's key gets a generic 401
    let (status, body) =
        make_app_request(&app, "/me", "GET", Some(&service_key), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Invalid API key");
}

/// Failed attempts on /change-password feed the same lockout counter as
/// /login: after max_attempts wrong current passwords, even the correct
/// credentials are rejected with the generic 401.
#[test(tokio::test)]
async fn test_change_password_attempts_lock_account() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // Create a user that must change password on first login
    let username =
        format!("lockout_cp_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&api_key),
        Some(json!({
            "username": &username,
            "password": "TestPass123!",
            "must_change_password": true
        })),
    )
    .await;
    assert!(user_body["id"].is_i64(), "create user: {user_body}");

    // The test config locks the account after 5 failed attempts
    for attempt in 1..=5 {
        let (status, body) = make_app_request(
            &app,
            "/change-password",
            "POST",
            None,
            Some(json!({
                "username": &username,
                "current_password": "WrongPass123!",
                "new_password": "NewPass123!"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "attempt {attempt}");
        assert_eq!(body["error"], "Invalid username or password");
    }

    // The account is locked: even the correct current password is rejected
    let (status, body) = make_app_request(
        &app,
        "/change-password",
        "POST",
        None,
        Some(json!({
            "username": &username,
            "current_password": "TestPass123!",
            "new_password": "NewPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Invalid username or password");
}

/// The login response must report exactly what the server enforces: when two
/// roles contest the same (resource, action), aggregation is allow-wins and
/// the client sees a single row.
#[test(tokio::test)]
async fn test_login_reports_allow_wins_permissions() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let admin_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let suffix = chrono::Utc::now().timestamp_millis();
    let username = format!("loginallow_{}", suffix);

    // Two roles contesting the same pair: one allows, one denies
    let mut role_ids = Vec::new();
    for (name, allowed) in [
        (format!("allow_role_{}", suffix), true),
        (format!("deny_role_{}", suffix), false),
    ] {
        let (status, body) = make_app_request(
            &app,
            "/admin/roles",
            "POST",
            Some(&admin_key),
            Some(json!({"name": name})),
        )
        .await;
        assert_eq!(status, StatusCode::CREATED, "create role: {body}");
        let role_id = body["id"].as_i64().unwrap();
        role_ids.push(role_id);

        let (status, body) = make_app_request(
            &app,
            &format!("/admin/roles/{}/permissions", role_id),
            "POST",
            Some(&admin_key),
            Some(json!({
                "resource": "node_subject",
                "action": "get",
                "allowed": allowed
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "set role permission: {body}");
    }

    // User with both roles
    let (status, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&admin_key),
        Some(json!({
            "username": &username,
            "password": "TestPass123!",
            "must_change_password": false
        })),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "create user: {user_body}");
    let user_id = user_body["id"].as_i64().unwrap();

    for role_id in &role_ids {
        let (status, body) = make_app_request(
            &app,
            &format!("/admin/users/{}/roles/{}", user_id, role_id),
            "POST",
            Some(&admin_key),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "assign role: {body}");
    }

    // Login: the contested pair appears exactly once, allowed
    let (status, body) = make_app_request(
        &app,
        "/login",
        "POST",
        None,
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login: {body}");

    let contested: Vec<&serde_json::Value> = body["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["resource"] == "node_subject" && p["action"] == "get")
        .collect();
    assert_eq!(contested.len(), 1, "exactly one row: {contested:?}");
    assert_eq!(contested[0]["allowed"], true, "allow-wins");
}

/// Concurrent updates to the same user must all succeed: write transactions
/// are Immediate, so writers serialize on the busy timeout instead of
/// failing mid-transaction with SQLITE_BUSY_SNAPSHOT (a 500).
#[test(tokio::test)]
async fn test_concurrent_user_updates_never_fail_with_500() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let admin_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let username =
        format!("concurrent_upd_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&admin_key),
        Some(json!({
            "username": &username,
            "password": "TestPass123!",
            "must_change_password": false
        })),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    let updates: Vec<_> = (0..8)
        .map(|i| {
            let app = &app;
            let admin_key = &admin_key;
            async move {
                make_app_request(
                    app,
                    &format!("/admin/users/{}", user_id),
                    "PUT",
                    Some(admin_key),
                    Some(json!({"is_active": i % 2 == 0})),
                )
                .await
            }
        })
        .collect();
    for (i, (status, body)) in futures::future::join_all(updates)
        .await
        .into_iter()
        .enumerate()
    {
        assert_eq!(status, StatusCode::OK, "update {i} failed: {body}");
    }

    // The user ends in a consistent state, whichever update landed last
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/users/{}", user_id),
        "GET",
        Some(&admin_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "get user: {body}");
    assert!(body["is_active"].is_boolean());
}

/// A password reset revokes every key of the user: a management key issued
/// by a login just before the reset must not survive it.
#[test(tokio::test)]
async fn test_password_reset_kills_freshly_issued_key() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let admin_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let username =
        format!("resetkills_{}", chrono::Utc::now().timestamp_millis());
    let (_, user_body) = make_app_request(
        &app,
        "/admin/users",
        "POST",
        Some(&admin_key),
        Some(json!({
            "username": &username,
            "password": "TestPass123!",
            "must_change_password": false
        })),
    )
    .await;
    let user_id = user_body["id"].as_i64().unwrap();

    // The user logs in and gets a management key
    let (status, body) = make_app_request(
        &app,
        "/login",
        "POST",
        None,
        Some(json!({"username": &username, "password": "TestPass123!"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login: {body}");
    let user_key = body["api_key"].as_str().unwrap().to_string();

    // The key authenticates (403 on /me: fresh user without roles, but the
    // key itself is valid)
    let (status, _) =
        make_app_request(&app, "/me", "GET", Some(&user_key), None).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Admin resets the password
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/users/{}/password", user_id),
        "POST",
        Some(&admin_key),
        Some(json!({"password": "NewPass123!"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "reset password: {body}");

    // The key issued before the reset is dead
    let (status, body) =
        make_app_request(&app, "/me", "GET", Some(&user_key), None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body["error"], "Invalid API key");

    // The reset forces a password change on next login
    let (status, _) = make_app_request(
        &app,
        "/login",
        "POST",
        None,
        Some(json!({"username": &username, "password": "NewPass123!"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "change required");

    // After the forced change, login works again
    let (status, body) = make_app_request(
        &app,
        "/change-password",
        "POST",
        None,
        Some(json!({
            "username": &username,
            "current_password": "NewPass123!",
            "new_password": "FinalPass123!"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "change password: {body}");

    let (status, body) = make_app_request(
        &app,
        "/login",
        "POST",
        None,
        Some(json!({"username": &username, "password": "FinalPass123!"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "login after change: {body}");
    assert!(body["api_key"].as_str().is_some());
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

/// Rotating the key that authenticates the request is forbidden: the rotation
/// revokes the old key and would kill the caller's own session mid-request.
#[test(tokio::test)]
async fn test_rotate_current_api_key_is_rejected() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    // The fresh app holds exactly one management key: the login one
    let (status, body) =
        make_app_request(&app, "/me/api-keys", "GET", Some(&api_key), None)
            .await;
    assert_eq!(status, StatusCode::OK, "list own keys: {body}");
    let id = body[0]["id"].as_str().unwrap();

    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}/rotate", id),
        "POST",
        Some(&api_key),
        Some(json!({"reason": "self rotation"})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["error"], "Cannot rotate the currently used API key");
}

/// A malformed JSON body on rotate must be rejected with the canonical
/// `{"error": "…"}` shape, not with axum's plain-text rejection.
#[test(tokio::test)]
async fn test_rotate_api_key_malformed_body_gets_canonical_error() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let username =
        format!("rotatemalf_{}", chrono::Utc::now().timestamp_millis());
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
        Some(json!({"name": "rotatemalformed"})),
    )
    .await;
    let id = key_body["key_info"]["id"].as_str().unwrap();

    let (status, body) = make_app_raw_body_request(
        &app,
        &format!("/admin/api-keys/{}/rotate", id),
        "POST",
        Some(&api_key),
        "application/json",
        b"{\"name\":".to_vec(),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        body["error"].as_str().is_some(),
        "canonical error body expected: {body}"
    );
}

/// The rotation body is optional: without one, the new key inherits the
/// defaults of the old key.
#[test(tokio::test)]
async fn test_rotate_api_key_without_body() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let api_key = login_app(&app, "admin", "AdminPass123!").await.unwrap();

    let username =
        format!("rotatenobody_{}", chrono::Utc::now().timestamp_millis());
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
        Some(json!({"name": "rotatenobody"})),
    )
    .await;
    let id = key_body["key_info"]["id"].as_str().unwrap();
    let old_key = key_body["api_key"].as_str().unwrap();

    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{}/rotate", id),
        "POST",
        Some(&api_key),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "rotate without body: {body}");
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

    // Admin route: revoking the key in use is a 400, not a 204
    let (status, body) = make_app_request(
        &app,
        &format!("/admin/api-keys/{key_id}?reason=self%20revocation"),
        "DELETE",
        Some(&mgmt_key),
        None,
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
        &format!("/me/api-keys/{key_id}?reason=self%20revocation"),
        "DELETE",
        Some(&mgmt_key),
        None,
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

// =============================================================================
// ERROR SHAPE NORMALIZATION
// =============================================================================

/// Every error response of the API — including framework-level rejections —
/// must carry the canonical `{"error": "…"}` body with a standards-based
/// status code.
///
/// **Sequence:**
/// 1. Unknown route -> 404.
/// 2. Known path with a method missing from the catalog -> 403 (auth and
///    permission checks run before method negotiation).
/// 3. Invalid query parameter -> 400.
/// 4. Malformed JSON body -> 400.
/// 5. Wrong `Content-Type` -> 415.
/// 6. Well-formed JSON that does not match the schema -> 422.
/// 7. Body larger than 2 MiB -> 413.
#[test(tokio::test)]
async fn test_http_error_responses_have_canonical_shape() {
    let (app, _dir) = TestApp::build(true, true, None).await;
    let admin_key = login_app(&app, "admin", "AdminPass123!")
        .await
        .expect("admin login");

    let cases: [(&str, &str, Option<(&str, Vec<u8>)>, StatusCode); 7] = [
        // Unknown route.
        ("/no-such-route", "GET", None, StatusCode::NOT_FOUND),
        // Known path, method not in the catalog: the permission layer denies
        // before method negotiation.
        ("/sinks/example-sink", "DELETE", None, StatusCode::FORBIDDEN),
        // Invalid query parameter.
        (
            "/sinks?in_config=notabool",
            "GET",
            None,
            StatusCode::BAD_REQUEST,
        ),
        // Malformed JSON body.
        (
            "/requests",
            "POST",
            Some(("application/json", b"{".to_vec())),
            StatusCode::BAD_REQUEST,
        ),
        // Wrong content type.
        (
            "/requests",
            "POST",
            Some(("text/plain", b"{}".to_vec())),
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
        ),
        // Well-formed JSON that does not match the expected schema.
        (
            "/requests",
            "POST",
            Some(("application/json", b"{\"unexpected\": true}".to_vec())),
            StatusCode::UNPROCESSABLE_ENTITY,
        ),
        // Body larger than the 2 MiB limit.
        (
            "/requests",
            "POST",
            Some(("application/json", vec![b'x'; 3 * 1024 * 1024])),
            StatusCode::PAYLOAD_TOO_LARGE,
        ),
    ];

    for (path, method, raw, expected) in cases {
        let (status, body) = match raw {
            Some((content_type, raw_body)) => {
                make_app_raw_body_request(
                    &app,
                    path,
                    method,
                    Some(&admin_key),
                    content_type,
                    raw_body,
                )
                .await
            }
            None => {
                make_app_request(&app, path, method, Some(&admin_key), None)
                    .await
            }
        };
        assert_eq!(status, expected, "{method} {path} must return {expected}");
        assert!(
            body["error"].is_string(),
            "{method} {path} must return the canonical error body, got: {body}"
        );
    }
}

/// The documentation routes (`/doc/`, `/api-docs/openapi.json`) are merged
/// outside the layered router, so they stay public even with auth enabled.
/// If a refactor ever mounts them inside the layered router, the permission
/// layer would reject them (no catalog entry → 403) or demand credentials —
/// this test guards that invariant, while the control assertion proves the
/// layer still protects the protected routes.
#[test(tokio::test)]
async fn test_doc_routes_stay_public_with_auth_enabled() {
    let (app, _dir) = TestApp::build_with_options(TestServerOptions {
        enable_auth: true,
        always_accept: true,
        enable_doc: true,
        ..Default::default()
    })
    .await;

    let (status, body) =
        make_app_request_raw(&app, "/api-docs/openapi.json", "GET", None, None)
            .await;
    assert_eq!(status, StatusCode::OK, "openapi.json: {body}");
    assert!(
        body.contains("\"openapi\""),
        "openapi.json must serve the spec: {body}"
    );

    let (status, body) =
        make_app_request_raw(&app, "/doc/", "GET", None, None).await;
    assert_eq!(status, StatusCode::OK, "doc UI: {body}");

    // Control: a protected route without credentials is still rejected.
    let (status, _) = make_app_request(&app, "/me", "GET", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
