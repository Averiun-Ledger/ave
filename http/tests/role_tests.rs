// Ave HTTP Auth System - Role Change Tests
//
// Tests for role changes and their effects on API keys and permissions

mod common;

use ave_http::auth::database::DatabaseError;
use reqwest::{Client, StatusCode};
use serde_json::json;
use test_log::test;

#[test(tokio::test)]
async fn test_api_keys_revoked_when_role_added() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, _) = db
        .create_api_key(user.id, Some("key1"), None, None, false)
        .unwrap();

    // Verify key works
    assert!(db.verify_api_key(&api_key).is_ok());

    let role = db.create_role("editor", None).unwrap();
    db.assign_role_to_user(user.id, role.id, None).unwrap();

    // API key should be revoked
    let result = db.verify_api_key(&api_key);
    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_api_keys_revoked_when_role_removed() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    db.assign_role_to_user(user.id, role.id, None).unwrap();

    let (api_key, _) = db
        .create_api_key(user.id, Some("key1"), None, None, false)
        .unwrap();

    // Verify key works
    assert!(db.verify_api_key(&api_key).is_ok());

    // Remove role from user
    db.remove_role_from_user(user.id, role.id).unwrap();

    // API key should be revoked
    let result = db.verify_api_key(&api_key);
    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_permissions_change_when_role_added() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    // Role has read permission
    db.set_role_permission(role.id, "node_subject", "get", true)
        .unwrap();

    // User doesn't have permission yet
    let perms_before = db.get_user_effective_permissions(user.id).unwrap();
    assert!(!perms_before.iter().any(|p| p.resource == "node_subject"
        && p.action == "get"
        && p.allowed));

    // Assign role
    db.assign_role_to_user(user.id, role.id, None).unwrap();

    // User should now have permission
    let perms_after = db.get_user_effective_permissions(user.id).unwrap();
    assert!(perms_after.iter().any(|p| p.resource == "node_subject"
        && p.action == "get"
        && p.allowed));
}

#[test(tokio::test)]
async fn test_permissions_change_when_role_removed() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    // Role has update permission
    db.set_role_permission(role.id, "node_request", "post", true)
        .unwrap();
    db.assign_role_to_user(user.id, role.id, None).unwrap();

    // User has permission
    let perms_before = db.get_user_effective_permissions(user.id).unwrap();
    assert!(perms_before.iter().any(|p| p.resource == "node_request"
        && p.action == "post"
        && p.allowed));

    // Remove role
    db.remove_role_from_user(user.id, role.id).unwrap();

    // User should no longer have permission
    let perms_after = db.get_user_effective_permissions(user.id).unwrap();
    assert!(!perms_after.iter().any(|p| p.resource == "node_request"
        && p.action == "post"
        && p.allowed));
}

#[test(tokio::test)]
async fn test_multiple_role_changes() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key1, _) = db
        .create_api_key(user.id, Some("key1"), None, None, false)
        .unwrap();

    let role1 = db.create_role("role1", None).unwrap();
    db.assign_role_to_user(user.id, role1.id, None).unwrap();

    // First key should be revoked
    assert!(matches!(
        db.verify_api_key(&api_key1),
        Err(DatabaseError::PermissionDenied(_))
    ));

    // Create new key
    let (api_key2, _) = db
        .create_api_key(user.id, Some("key2"), None, None, false)
        .unwrap();

    let role2 = db.create_role("role2", None).unwrap();
    db.assign_role_to_user(user.id, role2.id, None).unwrap();

    // Second key should be revoked
    assert!(matches!(
        db.verify_api_key(&api_key2),
        Err(DatabaseError::PermissionDenied(_))
    ));

    // First key still revoked
    assert!(matches!(
        db.verify_api_key(&api_key1),
        Err(DatabaseError::PermissionDenied(_))
    ));
}

#[test(tokio::test)]
async fn test_user_with_multiple_roles_permission_merge() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role1 = db.create_role("reader", None).unwrap();
    let role2 = db.create_role("writer", None).unwrap();

    // role1 grants read
    db.set_role_permission(role1.id, "node_subject", "get", true)
        .unwrap();

    // role2 grants update
    db.set_role_permission(role2.id, "node_subject", "post", true)
        .unwrap();

    // Assign both roles
    db.assign_role_to_user(user.id, role1.id, None).unwrap();
    db.assign_role_to_user(user.id, role2.id, None).unwrap();

    // User should have both permissions
    let perms = db.get_user_effective_permissions(user.id).unwrap();

    assert!(perms.iter().any(|p| p.resource == "node_subject"
        && p.action == "get"
        && p.allowed));
    assert!(perms.iter().any(|p| p.resource == "node_subject"
        && p.action == "post"
        && p.allowed));
}

#[test(tokio::test)]
async fn test_user_override_persists_through_role_changes() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // User has explicit deny
    db.set_user_permission(user.id, "admin_users", "delete", false, None)
        .unwrap();

    // Add role that grants delete
    let role = db.create_role("user_admin", None).unwrap();
    db.set_role_permission(role.id, "admin_users", "delete", true)
        .unwrap();
    db.assign_role_to_user(user.id, role.id, None).unwrap();

    // User override should still deny
    let perms = db.get_user_effective_permissions(user.id).unwrap();
    let perm = perms
        .iter()
        .find(|p| p.resource == "admin_users" && p.action == "delete")
        .unwrap();

    assert!(!perm.allowed);
}

#[test(tokio::test)]
async fn test_role_permission_modification_affects_all_users() {
    let (db, _dirs) = common::create_test_db();

    let user1 = db
        .create_user("user1", "TestPass123!", None, None, Some(false))
        .unwrap();
    let user2 = db
        .create_user("user2", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    db.assign_role_to_user(user1.id, role.id, None).unwrap();
    db.assign_role_to_user(user2.id, role.id, None).unwrap();

    // Grant permission to role
    db.set_role_permission(role.id, "node_subject", "post", true)
        .unwrap();

    // Both users should have the permission
    let perms1 = db.get_user_effective_permissions(user1.id).unwrap();
    let perms2 = db.get_user_effective_permissions(user2.id).unwrap();

    assert!(perms1.iter().any(|p| p.resource == "node_subject"
        && p.action == "post"
        && p.allowed));
    assert!(perms2.iter().any(|p| p.resource == "node_subject"
        && p.action == "post"
        && p.allowed));

    // Revoke permission from role
    db.set_role_permission(role.id, "node_subject", "post", false)
        .unwrap();

    // Both users should lose the permission
    let perms1 = db.get_user_effective_permissions(user1.id).unwrap();
    let perms2 = db.get_user_effective_permissions(user2.id).unwrap();

    assert!(!perms1.iter().any(|p| p.resource == "node_subject"
        && p.action == "post"
        && p.allowed));
    assert!(!perms2.iter().any(|p| p.resource == "node_subject"
        && p.action == "post"
        && p.allowed));
}

#[test(tokio::test)]
async fn test_deny_permission_overrides_multiple_allows() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role1 = db.create_role("role1", None).unwrap();
    let role2 = db.create_role("role2", None).unwrap();

    // Both roles grant permission
    db.set_role_permission(role1.id, "node_subject", "delete", true)
        .unwrap();
    db.set_role_permission(role2.id, "node_subject", "delete", true)
        .unwrap();

    db.assign_role_to_user(user.id, role1.id, None).unwrap();
    db.assign_role_to_user(user.id, role2.id, None).unwrap();

    // User-specific deny
    db.set_user_permission(user.id, "node_subject", "delete", false, None)
        .unwrap();

    // Deny should override both role allows
    let perms = db.get_user_effective_permissions(user.id).unwrap();
    let perm = perms
        .iter()
        .find(|p| p.resource == "node_subject" && p.action == "delete")
        .unwrap();

    assert!(!perm.allowed);
}

#[test(tokio::test)]
async fn test_deleted_roles_removed_from_users() {
    let (db, _dirs) = common::create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("temp_role", None).unwrap();

    db.assign_role_to_user(user.id, role.id, None).unwrap();

    // User has the role
    let roles_before = db.get_user_roles(user.id).unwrap();
    assert!(roles_before.contains(&"temp_role".to_string()));

    // Delete role
    db.delete_role(role.id).unwrap();

    // User should no longer have the role
    let roles_after = db.get_user_roles(user.id).unwrap();
    assert!(!roles_after.contains(&"temp_role".to_string()));
}

// =============================================================================
// ENDPOINT ACCESS TESTS BY ROLE
// =============================================================================

/// Helper to check if a status code indicates access was granted
fn has_access(status: StatusCode) -> bool {
    // 401 = Unauthorized, 403 = Forbidden -> NO ACCESS
    // Everything else including 404 (resource not found but endpoint accessible) -> HAS ACCESS
    // 404 means the user has permission to access the endpoint, but the resource doesn't exist
    !matches!(status, StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN)
}

/// Test all Node (business logic) endpoints
async fn test_node_endpoints(
    client: &Client,
    base_url: &str,
    api_key: &str,
    default_access: bool,
    overrides: &[(&str, &str, bool)],
) {
    let endpoints = vec![
        // Node-System (node_system)
        ("GET", "/public-key", None),
        ("GET", "/peer-id", None),
        ("GET", "/network-state", None),
        // Node-Management (node_management) - /config requires node_management:get
        ("GET", "/config", None),
        // Node-Subject (node_subject) - reads
        (
            "GET",
            "/state/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        (
            "GET",
            "/events/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?quantity=10&page=1",
            None,
        ),
        (
            "GET",
            "/events/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI/1",
            None,
        ),
        (
            "GET",
            "/events-first-last/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?quantity=5",
            None,
        ),
        (
            "GET",
            "/aborts/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        ("GET", "/subjects?active=true", None),
        (
            "GET",
            "/subjects/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?active=true",
            None,
        ),
        ("GET", "/approval", None),
        (
            "GET",
            "/approval/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        ("GET", "/auth", None),
        (
            "GET",
            "/auth/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        ("GET", "/pending-transfers", None),
        // Node-Subject (node_subject) - writes
        (
            "PATCH",
            "/approval/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            Some(json!("Accepted")),
        ),
        (
            "PUT",
            "/auth/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            Some(json!(["ExxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI"])),
        ),
        (
            "DELETE",
            "/auth/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        (
            "POST",
            "/request-abort/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        (
            "POST",
            "/update/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        (
            "POST",
            "/manual-distribution/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        // Node-Request (node_request)
        (
            "POST",
            "/request",
            Some(json!({"request": {}, "signature": null})),
        ),
        ("GET", "/request", None),
        (
            "GET",
            "/request/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
        ("GET", "/requests-in-manager", None),
        (
            "GET",
            "/requests-in-manager/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            None,
        ),
    ];

    for (method, path, body) in endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&body.unwrap_or(json!({}))),
            "PUT" => client.put(&url).json(&body.unwrap_or(json!({}))),
            "PATCH" => client.patch(&url).json(&body.unwrap_or(json!({}))),
            "DELETE" => client.delete(&url),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let expected_access = overrides
            .iter()
            .find(|(m, p, _)| *m == method && *p == path)
            .map(|(_, _, allow)| *allow)
            .unwrap_or(default_access);

        let access = has_access(status);

        assert_eq!(
            access, expected_access,
            "{} {} - Expected access: {}, Got status: {} (access: {})",
            method, path, expected_access, status, access
        );
    }
}

/// Test all User endpoints (/me/...)
async fn test_user_endpoints(
    client: &Client,
    base_url: &str,
    api_key: &str,
    should_have_access: bool,
    is_management_key: bool,
) {
    let endpoints = vec![
        ("GET", "/me", None),
        ("GET", "/me/permissions", None),
        ("GET", "/me/permissions/detailed", None),
    ];

    for (method, path, body) in endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&body.unwrap_or(json!({}))),
            "DELETE" => client.delete(&url),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let access = has_access(status);

        assert_eq!(
            access, should_have_access,
            "{} {} - Expected access: {}, Got status: {} (access: {})",
            method, path, should_have_access, status, access
        );
    }

    // Test /me/api-keys endpoints - only accessible with management keys
    let api_key_endpoints = vec![
        ("GET", "/me/api-keys?include_revoked=false", None),
        (
            "POST",
            "/me/api-keys",
            Some(json!({"name": "test_key", "description": "test"})),
        ),
        ("DELETE", "/me/api-keys/test_key", None),
    ];

    for (method, path, body) in api_key_endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&body.unwrap_or(json!({}))),
            "DELETE" => client.delete(&url),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let access = has_access(status);

        // Service keys should NOT have access to /me/api-keys endpoints
        let expected_access = should_have_access && is_management_key;

        assert_eq!(
            access, expected_access,
            "{} {} (is_management: {}) - Expected access: {}, Got status: {} (access: {})",
            method, path, is_management_key, expected_access, status, access
        );
    }
}

/// Test all Admin-Users endpoints
async fn test_admin_users_endpoints(
    client: &Client,
    base_url: &str,
    api_key: &str,
    should_have_access: bool,
) {
    let endpoints = vec![
        ("GET", "/admin/users?include_inactive=false", None),
        (
            "POST",
            "/admin/users",
            Some(json!({"username": "test", "password": "Test123!"})),
        ),
        ("GET", "/admin/users/999", None),
        (
            "PUT",
            "/admin/users/999",
            Some(json!({"password": "NewPass123!"})),
        ),
        ("DELETE", "/admin/users/999", None),
        // Use role ID 2 instead of 1 (superadmin) to avoid permission issues
        ("POST", "/admin/users/999/roles/2", None),
        ("DELETE", "/admin/users/999/roles/2", None),
        ("GET", "/admin/users/999/permissions", None),
        (
            "POST",
            "/admin/users/999/permissions",
            Some(json!({"resource": "test", "action": "get", "allowed": true})),
        ),
        (
            "DELETE",
            "/admin/users/999/permissions?resource=test&action=get",
            None,
        ),
        (
            "POST",
            "/admin/users/999/password",
            Some(json!({"password": "NewPass123!"})),
        ),
    ];

    for (method, path, body) in endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&body.unwrap_or(json!({}))),
            "PUT" => client.put(&url).json(&body.unwrap_or(json!({}))),
            "DELETE" => client.delete(&url),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let access = has_access(status);

        assert_eq!(
            access, should_have_access,
            "{} {} - Expected access: {}, Got status: {} (access: {})",
            method, path, should_have_access, status, access
        );
    }
}

/// Test all Admin-Roles endpoints
async fn test_admin_roles_endpoints(
    client: &Client,
    base_url: &str,
    api_key: &str,
    should_have_access: bool,
    is_superadmin: bool,
) {
    let endpoints = vec![
        // Role CRUD operations - anyone with admin_roles permission can do these
        ("GET", "/admin/roles", None, should_have_access),
        (
            "POST",
            "/admin/roles",
            Some(json!({"name": "test_role"})),
            should_have_access,
        ),
        ("GET", "/admin/roles/999", None, should_have_access),
        (
            "PUT",
            "/admin/roles/999",
            Some(json!({"description": "updated"})),
            should_have_access,
        ),
        ("DELETE", "/admin/roles/999", None, should_have_access),
        (
            "GET",
            "/admin/roles/999/permissions",
            None,
            should_have_access,
        ),
        // Role permission modification - ONLY superadmin can do these
        // Non-superadmin will get 403 Forbidden (blocked by security check)
        (
            "POST",
            "/admin/roles/999/permissions",
            Some(json!({"resource": "test", "action": "get", "allowed": true})),
            should_have_access && is_superadmin,
        ),
        (
            "DELETE",
            "/admin/roles/999/permissions?resource=test&action=get",
            None,
            should_have_access && is_superadmin,
        ),
    ];

    for (method, path, body, expected_access) in endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&body.unwrap_or(json!({}))),
            "PUT" => client.put(&url).json(&body.unwrap_or(json!({}))),
            "DELETE" => client.delete(&url),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let access = has_access(status);

        assert_eq!(
            access, expected_access,
            "{} {} - Expected access: {}, Got status: {} (access: {})",
            method, path, expected_access, status, access
        );
    }
}

/// Test all Admin-ApiKey endpoints
async fn test_admin_apikeys_endpoints(
    client: &Client,
    base_url: &str,
    api_key: &str,
    should_have_access: bool,
    is_superadmin: bool,
) {
    let endpoints = vec![
        // GET endpoints - work for any admin with admin_api_key:get permission
        (
            "GET",
            "/admin/api-keys/user/999?include_revoked=false",
            None,
            should_have_access,
        ),
        (
            "GET",
            "/admin/api-keys?include_revoked=false",
            None,
            should_have_access,
        ),
        ("GET", "/admin/api-keys/999", None, should_have_access),
        // POST create for other user (user 999):
        // - Non-superadmin: Gets 403 Forbidden (blocked by ownership check) → NO ACCESS
        // - Superadmin: Gets 404 Not Found (user doesn't exist) → HAS ACCESS
        (
            "POST",
            "/admin/api-keys/user/999",
            Some(json!({"name": "test_key"})),
            should_have_access && is_superadmin,
        ),
        // DELETE/rotate for non-existent key (999):
        // - Gets 404 Not Found (key doesn't exist, checked before ownership) → HAS ACCESS
        // - Anyone with the permission will get 404
        (
            "DELETE",
            "/admin/api-keys/999",
            Some(json!({"reason": "test"})),
            should_have_access,
        ),
        (
            "POST",
            "/admin/api-keys/999/rotate",
            Some(json!({"name": "rotated_key"})),
            should_have_access,
        ),
    ];

    for (method, path, body, expected_access) in endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "POST" => client.post(&url).json(&body.unwrap_or(json!({}))),
            "DELETE" => client.delete(&url).json(&body.unwrap_or(json!({}))),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let access = has_access(status);

        assert_eq!(
            access, expected_access,
            "{} {} - Expected access: {}, Got status: {} (access: {})",
            method, path, expected_access, status, access
        );
    }
}

/// Test all Admin-System endpoints
async fn test_admin_system_endpoints(
    client: &Client,
    base_url: &str,
    api_key: &str,
    should_have_access: bool,
) {
    let endpoints = vec![
        ("GET", "/admin/resources", None),
        ("GET", "/admin/actions", None),
        ("GET", "/admin/audit-logs?limit=10", None),
        ("GET", "/admin/audit-logs/stats?days=7", None),
        ("GET", "/admin/rate-limits/stats?hours=24", None),
        ("GET", "/admin/config", None),
        (
            "PUT",
            "/admin/config/test_key",
            Some(json!({"value": 1234})),
        ),
    ];

    for (method, path, body) in endpoints {
        let url = format!("{}{}", base_url, path);
        let request = match method {
            "GET" => client.get(&url),
            "PUT" => client.put(&url).json(&body.unwrap_or(json!({}))),
            _ => panic!("Unsupported method: {}", method),
        };

        let response =
            request.header("X-API-Key", api_key).send().await.unwrap();
        let status = response.status();
        let access = has_access(status);

        assert_eq!(
            access, should_have_access,
            "{} {} - Expected access: {}, Got status: {} (access: {})",
            method, path, should_have_access, status, access
        );
    }
}

#[test(tokio::test)]
async fn test_superadmin_all_endpoints_access() {
    let (server, _dirs) = common::TestServer::build(true, false, None).await;
    let client = Client::new();
    let base_url = server.url("");

    // Login as default admin (which is a superadmin)
    let (status, login_response) = common::make_request(
        &client,
        &server.url("/login"),
        "POST",
        None,
        Some(json!({"username": "admin", "password": "AdminPass123!"})),
    )
    .await;

    assert!(status.is_success(), "Login failed with status: {}", status);
    let mgmt_key = login_response["api_key"]
        .as_str()
        .expect("No api_key in login response")
        .to_string();

    // Create service key using management key
    let (status, service_key_response) = common::make_request(
        &client,
        &server.url("/me/api-keys"),
        "POST",
        Some(&mgmt_key),
        Some(json!({"name": "service_test"})),
    )
    .await;

    assert!(
        status.is_success(),
        "Service key creation failed with status: {}",
        status
    );
    let service_key = service_key_response["api_key"]
        .as_str()
        .expect("No api_key in service key response")
        .to_string();

    // Test with management key - should have access to EVERYTHING
    test_node_endpoints(&client, &base_url, &mgmt_key, true, &[]).await;
    test_user_endpoints(&client, &base_url, &mgmt_key, true, true).await;
    test_admin_users_endpoints(&client, &base_url, &mgmt_key, true).await;
    test_admin_roles_endpoints(&client, &base_url, &mgmt_key, true, true).await;
    test_admin_apikeys_endpoints(&client, &base_url, &mgmt_key, true, true)
        .await;
    test_admin_system_endpoints(&client, &base_url, &mgmt_key, true).await;

    // Test with service key - should have access to node endpoints and /me (except /me/api-keys)
    // but NO access to /admin/* endpoints (service keys cannot carry admin permissions)
    test_node_endpoints(&client, &base_url, &service_key, true, &[]).await;
    test_user_endpoints(&client, &base_url, &service_key, true, false).await;
    test_admin_users_endpoints(&client, &base_url, &service_key, false).await;
    test_admin_roles_endpoints(&client, &base_url, &service_key, false, true)
        .await;
    test_admin_apikeys_endpoints(&client, &base_url, &service_key, false, true)
        .await;
    test_admin_system_endpoints(&client, &base_url, &service_key, false).await;
}

#[test(tokio::test)]

async fn test_admin_role_endpoints_access() {
    let (server, _dirs) = common::TestServer::build(true, false, None).await;
    let client = Client::new();
    let base_url = server.url("");

    // Login as default admin to create test user
    let login_response: serde_json::Value = client
        .post(&server.url("/login"))
        .json(&json!({"username": "admin", "password": "AdminPass123!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let admin_api_key = login_response["api_key"].as_str().unwrap();

    // Get Admin role ID
    let roles_response: serde_json::Value = client
        .get(&server.url("/admin/roles"))
        .header("X-API-Key", admin_api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let admin_role_id = roles_response
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "admin")
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Create test user with Admin role via HTTP
    let _create_user_response: serde_json::Value = client
        .post(&server.url("/admin/users"))
        .header("X-API-Key", admin_api_key)
        .json(&json!({
            "username": "test_admin_user",
            "password": "TestPass123!",
            "is_superadmin": false,
            "role_ids": [admin_role_id],
            "must_change_password": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Login as test admin user to get management key
    let test_login_response: serde_json::Value = client
        .post(&server.url("/login"))
        .json(
            &json!({"username": "test_admin_user", "password": "TestPass123!"}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let test_mgmt_key = test_login_response["api_key"].as_str().unwrap();

    // Create service key via /me/api-keys
    let service_key_response: serde_json::Value = client
        .post(&server.url("/me/api-keys"))
        .header("X-API-Key", test_mgmt_key)
        .json(&json!({
            "name": "service_key",
            "is_management": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    eprintln!(
        "ADMIN TEST - Service key response: {:?}",
        service_key_response
    );
    let test_service_key = service_key_response["api_key"].as_str().unwrap();

    // Admin should have access to:
    // - User resources
    // - All Admin-* resources
    // But NOT to Node-* resources

    // Test with management key
    test_user_endpoints(&client, &base_url, test_mgmt_key, true, true).await;
    test_admin_users_endpoints(&client, &base_url, test_mgmt_key, true).await;
    test_admin_roles_endpoints(&client, &base_url, test_mgmt_key, true, false)
        .await;
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        true,
        false,
    )
    .await;
    test_admin_system_endpoints(&client, &base_url, test_mgmt_key, true).await;
    // admin does NOT have node_management:get, so /config is blocked
    test_node_endpoints(&client, &base_url, test_mgmt_key, false, &[]).await; // Should NOT have any node access

    // Test with service key - service keys strip node management permissions,
    // so /config is NOT accessible even for admin service keys
    test_user_endpoints(&client, &base_url, test_service_key, true, false)
        .await;
    test_admin_users_endpoints(&client, &base_url, test_service_key, false)
        .await;
    test_admin_roles_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await;
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await;
    test_admin_system_endpoints(&client, &base_url, test_service_key, false)
        .await;
    test_node_endpoints(&client, &base_url, test_service_key, false, &[]).await; // No node or admin_system access
}

#[test(tokio::test)]

async fn test_sender_role_endpoints_access() {
    let (server, _dirs) = common::TestServer::build(true, false, None).await;
    let client = Client::new();
    let base_url = server.url("");

    // Login as default admin to create test user
    let login_response: serde_json::Value = client
        .post(&server.url("/login"))
        .json(&json!({"username": "admin", "password": "AdminPass123!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let admin_api_key = login_response["api_key"].as_str().unwrap();

    // Get Sender role ID
    let roles_response: serde_json::Value = client
        .get(&server.url("/admin/roles"))
        .header("X-API-Key", admin_api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let sender_role_id = roles_response
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "sender")
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Create test user with Sender role via HTTP
    let _create_user_response: serde_json::Value = client
        .post(&server.url("/admin/users"))
        .header("X-API-Key", admin_api_key)
        .json(&json!({
            "username": "test_sender_user",
            "password": "TestPass123!",
            "is_superadmin": false,
            "role_ids": [sender_role_id],
            "must_change_password": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Login as test sender user to get management key
    let test_login_response: serde_json::Value = client
            .post(&server.url("/login"))
            .json(&json!({"username": "test_sender_user", "password": "TestPass123!"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    let test_mgmt_key = test_login_response["api_key"].as_str().unwrap();

    // Create service key via /me/api-keys
    let service_key_response: serde_json::Value = client
        .post(&server.url("/me/api-keys"))
        .header("X-API-Key", test_mgmt_key)
        .json(&json!({
            "name": "service_key",
            "is_management": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let test_service_key = service_key_response["api_key"].as_str().unwrap();

    // Sender should have access to:
    // - User resources (all actions)
    // - Node-Request (get, post only)
    // But NOT to other Node-* resources or Admin-* resources

    let sender_node_access = [
        // node_request:post
        ("POST", "/request", true),
        // node_request:get
        ("GET", "/request", true),
        (
            "GET",
            "/request/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/requests-in-manager", true),
        (
            "GET",
            "/requests-in-manager/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        // node_subject:get
        (
            "GET",
            "/state/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        (
            "GET",
            "/events/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?quantity=10&page=1",
            true,
        ),
        (
            "GET",
            "/events/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI/1",
            true,
        ),
        (
            "GET",
            "/events-first-last/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?quantity=5",
            true,
        ),
        (
            "GET",
            "/aborts/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/subjects?active=true", true),
        (
            "GET",
            "/subjects/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?active=true",
            true,
        ),
        ("GET", "/approval", true),
        (
            "GET",
            "/approval/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/auth", true),
        (
            "GET",
            "/auth/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/pending-transfers", true),
        // node_system:get
        ("GET", "/public-key", true),
        ("GET", "/peer-id", true),
        ("GET", "/network-state", true),
        // /config requires node_management:get - sender does NOT have it
    ];

    // Test with management key - limited Node access
    test_user_endpoints(&client, &base_url, test_mgmt_key, true, true).await;
    test_node_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        false,
        &sender_node_access,
    )
    .await; // Only Node-Request should pass
    test_admin_users_endpoints(&client, &base_url, test_mgmt_key, false).await; // Should NOT have access
    test_admin_roles_endpoints(&client, &base_url, test_mgmt_key, false, false)
        .await; // Should NOT have access
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_system_endpoints(&client, &base_url, test_mgmt_key, false).await; // Should NOT have access

    // Test with service key
    test_user_endpoints(&client, &base_url, test_service_key, true, false)
        .await;
    test_node_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        &sender_node_access,
    )
    .await; // Only Node-Request should pass
    test_admin_users_endpoints(&client, &base_url, test_service_key, false)
        .await; // Should NOT have access
    test_admin_roles_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_system_endpoints(&client, &base_url, test_service_key, false)
        .await; // Should NOT have access
}

#[test(tokio::test)]

async fn test_manager_role_endpoints_access() {
    let (server, _dirs) = common::TestServer::build(true, false, None).await;
    let client = Client::new();
    let base_url = server.url("");

    // Login as default admin to create test user
    let login_response: serde_json::Value = client
        .post(&server.url("/login"))
        .json(&json!({"username": "admin", "password": "AdminPass123!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let admin_api_key = login_response["api_key"].as_str().unwrap();

    // Get Manager role ID
    let roles_response: serde_json::Value = client
        .get(&server.url("/admin/roles"))
        .header("X-API-Key", admin_api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let manager_role_id = roles_response
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "manager")
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Create test user with Manager role via HTTP
    let _create_user_response: serde_json::Value = client
        .post(&server.url("/admin/users"))
        .header("X-API-Key", admin_api_key)
        .json(&json!({
            "username": "test_manager_user",
            "password": "TestPass123!",
            "is_superadmin": false,
            "role_ids": [manager_role_id],
            "must_change_password": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Login as test manager user to get management key
    let test_login_response: serde_json::Value = client
            .post(&server.url("/login"))
            .json(&json!({"username": "test_manager_user", "password": "TestPass123!"}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();

    let test_mgmt_key = test_login_response["api_key"].as_str().unwrap();

    // Create service key via /me/api-keys
    let service_key_response: serde_json::Value = client
        .post(&server.url("/me/api-keys"))
        .header("X-API-Key", test_mgmt_key)
        .json(&json!({
            "name": "service_key",
            "is_management": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let test_service_key = service_key_response["api_key"].as_str().unwrap();

    // Manager should have access to:
    // - User resources (all actions)
    // - Node-Request (all actions)
    // - Node-Subject (all actions)
    // - Node-System (all actions)
    // But NOT to Node-Keys or Admin-* resources

    // Manager has node_request:all, node_subject:all, node_system:all, node_management:get
    let manager_overrides: &[(&str, &str, bool)] = &[];

    // Test with management key - full Node access including /config
    test_user_endpoints(&client, &base_url, test_mgmt_key, true, true).await;
    test_node_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        true,
        manager_overrides,
    )
    .await;
    test_admin_users_endpoints(&client, &base_url, test_mgmt_key, false).await; // Should NOT have access
    test_admin_roles_endpoints(&client, &base_url, test_mgmt_key, false, false)
        .await; // Should NOT have access
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_system_endpoints(&client, &base_url, test_mgmt_key, false).await; // Should NOT have access

    // Test with service key
    test_user_endpoints(&client, &base_url, test_service_key, true, false)
        .await;
    test_node_endpoints(
        &client,
        &base_url,
        test_service_key,
        true,
        manager_overrides,
    )
    .await;
    test_admin_users_endpoints(&client, &base_url, test_service_key, false)
        .await; // Should NOT have access
    test_admin_roles_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_system_endpoints(&client, &base_url, test_service_key, false)
        .await; // Should NOT have access
}

#[test(tokio::test)]
async fn test_data_role_endpoints_access() {
    let (server, _dirs) = common::TestServer::build(true, false, None).await;
    let client = Client::new();
    let base_url = server.url("");

    // Login as default admin to create test user
    let login_response: serde_json::Value = client
        .post(&server.url("/login"))
        .json(&json!({"username": "admin", "password": "AdminPass123!"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let admin_api_key = login_response["api_key"].as_str().unwrap();

    // Get Data role ID
    let roles_response: serde_json::Value = client
        .get(&server.url("/admin/roles"))
        .header("X-API-Key", admin_api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let data_role_id = roles_response
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["name"] == "data")
        .unwrap()["id"]
        .as_i64()
        .unwrap();

    // Create test user with Data role via HTTP
    let _create_user_response: serde_json::Value = client
        .post(&server.url("/admin/users"))
        .header("X-API-Key", admin_api_key)
        .json(&json!({
            "username": "test_data_user",
            "password": "TestPass123!",
            "is_superadmin": false,
            "role_ids": [data_role_id],
            "must_change_password": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    // Login as test data user to get management key
    let test_login_response: serde_json::Value = client
        .post(&server.url("/login"))
        .json(
            &json!({"username": "test_data_user", "password": "TestPass123!"}),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let test_mgmt_key = test_login_response["api_key"].as_str().unwrap();

    // Create service key via /me/api-keys
    let service_key_response: serde_json::Value = client
        .post(&server.url("/me/api-keys"))
        .header("X-API-Key", test_mgmt_key)
        .json(&json!({
            "name": "service_key",
            "is_management": false
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();

    let test_service_key = service_key_response["api_key"].as_str().unwrap();

    // Data should have access to:
    // - User resources (all actions)
    // - Node-Request (get only - read-only)
    // - Node-Subject (get only - read-only)
    // - Node-System (get only - read-only)
    // But NOT to Node-Keys or Admin-* resources

    let data_read_access = [
        // node_system:get
        ("GET", "/public-key", true),
        ("GET", "/peer-id", true),
        ("GET", "/network-state", true),
        // /config requires node_management:get - data does NOT have it
        // node_subject:get
        (
            "GET",
            "/state/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        (
            "GET",
            "/events/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?quantity=10&page=1",
            true,
        ),
        (
            "GET",
            "/events/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI/1",
            true,
        ),
        (
            "GET",
            "/events-first-last/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?quantity=5",
            true,
        ),
        (
            "GET",
            "/aborts/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/subjects?active=true", true),
        (
            "GET",
            "/subjects/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI?active=true",
            true,
        ),
        ("GET", "/approval", true),
        (
            "GET",
            "/approval/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/auth", true),
        (
            "GET",
            "/auth/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/pending-transfers", true),
        // node_request:get
        ("GET", "/request", true),
        (
            "GET",
            "/request/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
        ("GET", "/requests-in-manager", true),
        (
            "GET",
            "/requests-in-manager/JxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxI",
            true,
        ),
    ];

    // Test with management key - read-only Node access
    test_user_endpoints(&client, &base_url, test_mgmt_key, true, true).await;
    test_node_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        false,
        &data_read_access,
    )
    .await; // Read-only node/system access
    test_admin_users_endpoints(&client, &base_url, test_mgmt_key, false).await; // Should NOT have access
    test_admin_roles_endpoints(&client, &base_url, test_mgmt_key, false, false)
        .await; // Should NOT have access
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_mgmt_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_system_endpoints(&client, &base_url, test_mgmt_key, false).await; // Should NOT have access

    // Test with service key
    test_user_endpoints(&client, &base_url, test_service_key, true, false)
        .await;
    test_node_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        &data_read_access,
    )
    .await; // Read-only node/system access
    test_admin_users_endpoints(&client, &base_url, test_service_key, false)
        .await; // Should NOT have access
    test_admin_roles_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_apikeys_endpoints(
        &client,
        &base_url,
        test_service_key,
        false,
        false,
    )
    .await; // Should NOT have access
    test_admin_system_endpoints(&client, &base_url, test_service_key, false)
        .await; // Should NOT have access
}
