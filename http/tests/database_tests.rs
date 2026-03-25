// Ave HTTP Auth System - Database Integration Tests
//
// Comprehensive tests for user management, roles, API keys, and permissions

pub mod common;
use common::TestDbExt;

use std::sync::{Arc, Barrier};

use ave_bridge::auth::RateLimitConfig;
use ave_http::auth::database::DatabaseError;
use ave_http::auth::models::*;
use test_log::test;

use crate::common::create_test_db;

use ave_bridge::auth::{
    ApiKeyConfig, AuthConfig, EndpointRateLimit, LockoutConfig, SessionConfig,
};
use ave_http::auth::{RotateApiKeyParams, database::AuthDatabase};
use tempfile::TempDir;
use std::collections::BTreeSet;

#[test]
fn database_tests_route_inputs_exist_in_http_catalog() {
    let mut catalog = common::server_main_route_catalog();
    catalog.extend(common::server_auth_route_catalog());
    catalog.extend(common::server_public_auth_route_catalog());

    let expected: BTreeSet<(String, String)> = [
        ("get".to_string(), "/peer-id".to_string()),
        ("post".to_string(), "/login".to_string()),
        ("post".to_string(), "/change-password".to_string()),
    ]
    .into_iter()
    .collect();

    let missing: Vec<_> = expected.difference(&catalog).cloned().collect();
    assert!(
        missing.is_empty(),
        "Database tests reference routes that do not exist in server.rs: {missing:?}"
    );
}

async fn create_test_db_with_rate_limit(
    rate_limit: RateLimitConfig,
) -> (AuthDatabase, TempDir) {
    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let path = dir.path().to_path_buf();

    let config = AuthConfig {
        durability: false,
        enable: true,
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
        rate_limit,
        session: SessionConfig {
            audit_enable: true,
            audit_retention_days: 90,
            audit_max_entries: 1_000_000,
        },
    };

    (
        AuthDatabase::new(config, "AdminPass123!", None).unwrap(),
        dir,
    )
}

// =============================================================================
// USER MANAGEMENT TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_create_user_success() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    assert_eq!(user.username, "testuser");
    assert!(user.is_active);
    assert_eq!(user.failed_login_attempts, 0);
}

#[test(tokio::test)]
async fn test_create_user_duplicate() {
    let (db, _dirs) = create_test_db();

    db.create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let result =
        db.create_user("testuser", "TestPass123!", None, None, Some(false));

    assert!(matches!(result, Err(DatabaseError::Duplicate(_))));
}

#[test(tokio::test)]
async fn test_get_user_by_id() {
    let (db, _dirs) = create_test_db();

    let created = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let fetched = db.get_user_by_id(created.id).unwrap();

    assert_eq!(fetched.username, "testuser");
    assert_eq!(fetched.id, created.id);
}

#[test(tokio::test)]
async fn test_update_user() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // Update password
    db.update_user(user.id, Some("NewPass456!"), None).unwrap();

    // Verify new password works
    let result = db.verify_credentials("testuser", "NewPass456!");
    assert!(result.is_ok());
}

#[test(tokio::test)]
async fn test_deactivate_user() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // Deactivate
    db.update_user(user.id, None, Some(false)).unwrap();

    // Should not be able to login
    let result = db.verify_credentials("testuser", "TestPass123!");
    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_list_users() {
    let (db, _dirs) = create_test_db();

    db.create_user("user1", "TestPass123!", None, None, Some(false))
        .unwrap();
    db.create_user("user2", "TestPass123!", None, None, Some(false))
        .unwrap();

    let users = db.list_users(false, 100, 0).unwrap();

    // At least 3 users (admin + user1 + user2)
    assert!(users.len() >= 3);
}

#[test(tokio::test)]
async fn test_list_users_pagination() {
    let (db, _dirs) = create_test_db();

    // Create 5 test users
    for i in 1..=5 {
        db.create_user(
            &format!("user{}", i),
            "TestPass123!",
            None,
            None,
            Some(false),
        )
        .unwrap();
    }

    // Test limit
    let page1 = db.list_users(false, 2, 0).unwrap();
    assert_eq!(page1.len(), 2, "First page should have 2 users");

    // Test offset
    let page2 = db.list_users(false, 2, 2).unwrap();
    assert_eq!(page2.len(), 2, "Second page should have 2 users");

    // Verify different users on different pages
    assert_ne!(
        page1[0].username, page2[0].username,
        "Pages should have different users"
    );

    // Test getting all users
    let all_users = db.list_users(false, 100, 0).unwrap();
    assert!(
        all_users.len() >= 6,
        "Should have at least 6 users (admin + 5 created)"
    );

    // Test offset beyond available users
    let beyond = db.list_users(false, 10, 100).unwrap();
    assert_eq!(beyond.len(), 0, "Offset beyond users should return empty");

    // Test limit of 1
    let single = db.list_users(false, 1, 0).unwrap();
    assert_eq!(single.len(), 1, "Limit 1 should return exactly 1 user");
}

#[test(tokio::test)]
async fn test_delete_user() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    db.delete_user(user.id).unwrap();

    // Should not be able to get deleted user
    let result = db.get_user_by_id(user.id);
    assert!(matches!(result, Err(DatabaseError::NotFound(_))));
}

#[test(tokio::test)]
async fn test_recreate_username_after_soft_delete() {
    let (db, _dirs) = create_test_db();

    let deleted_user = db
        .create_user("reusable_user", "TestPass123!", None, None, Some(false))
        .unwrap();

    db.delete_user(deleted_user.id).unwrap();

    let recreated_user = db
        .create_user("reusable_user", "TestPass123!", None, None, Some(false))
        .unwrap();

    assert_ne!(recreated_user.id, deleted_user.id);
    assert_eq!(recreated_user.username, "reusable_user");
    assert!(matches!(
        db.get_user_by_id(deleted_user.id),
        Err(DatabaseError::NotFound(_))
    ));
}

// =============================================================================
// AUTHENTICATION TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_verify_credentials_success() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // Force password change requirement
    db.admin_reset_password(user.id, "NewPass456!").unwrap();

    // Change password with different value
    db.change_password_with_credentials(
        "testuser",
        "NewPass456!",
        "FinalPass789!",
    )
    .unwrap();

    let user = db.verify_credentials("testuser", "FinalPass789!").unwrap();
    assert_eq!(user.username, "testuser");
}

#[test(tokio::test)]
async fn test_verify_credentials_wrong_password() {
    let (db, _dirs) = create_test_db();

    db.create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    let result = db.verify_credentials("testuser", "WrongPassword");
    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_account_lockout_after_failed_attempts() {
    let (db, _dirs) = create_test_db();

    db.create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // 5 failed attempts (lockout threshold)
    for _ in 0..5 {
        let _ = db.verify_credentials("testuser", "WrongPassword");
    }

    // Even correct password should fail now (generic error to avoid enumeration)
    let result = db.verify_credentials("testuser", "TestPass123!");
    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_failed_attempts_reset_on_success() {
    let (db, _dirs) = create_test_db();

    db.create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // 2 failed attempts
    let _ = db.verify_credentials("testuser", "Wrong1");
    let _ = db.verify_credentials("testuser", "Wrong2");

    // Successful login resets counter
    db.verify_credentials("testuser", "TestPass123!").unwrap();

    // Can fail 5 more times before lockout
    for _ in 0..4 {
        let _ = db.verify_credentials("testuser", "Wrong");
    }

    // Should still work
    let result = db.verify_credentials("testuser", "TestPass123!");
    assert!(result.is_ok());
}

// =============================================================================
// ROLE MANAGEMENT TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_create_role() {
    let (db, _dirs) = create_test_db();

    let role = db.create_role("editor", Some("Editor role")).unwrap();

    assert_eq!(role.name.unwrap(), "editor");
    assert_eq!(role.description, Some("Editor role".to_string()));
}

#[test(tokio::test)]
async fn test_create_role_duplicate() {
    let (db, _dirs) = create_test_db();

    db.create_role("editor", None).unwrap();
    let result = db.create_role("editor", None);

    assert!(matches!(result, Err(DatabaseError::Duplicate(_))));
}

#[test(tokio::test)]
async fn test_assign_role_to_user() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    db.assign_role_to_user(user.id, role.id, None).unwrap();

    let roles = db.get_user_roles(user.id).unwrap();
    assert!(roles.contains(&"editor".to_string()));
}

#[test(tokio::test)]
async fn test_remove_role_from_user() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    db.assign_role_to_user(user.id, role.id, None).unwrap();
    db.remove_role_from_user(user.id, role.id).unwrap();

    let roles = db.get_user_roles(user.id).unwrap();
    assert!(!roles.contains(&"editor".to_string()));
}

#[test(tokio::test)]
async fn test_user_with_multiple_roles() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role1 = db.create_role("editor", None).unwrap();
    let role2 = db.create_role("viewer", None).unwrap();

    db.assign_role_to_user(user.id, role1.id, None).unwrap();
    db.assign_role_to_user(user.id, role2.id, None).unwrap();

    let roles = db.get_user_roles(user.id).unwrap();
    assert!(roles.contains(&"editor".to_string()));
    assert!(roles.contains(&"viewer".to_string()));
}

#[test(tokio::test)]
async fn test_delete_role() {
    let (db, _dirs) = create_test_db();

    let role = db.create_role("temp_role", None).unwrap();

    db.delete_role(role.id).unwrap();

    let result = db.get_role_by_name("temp_role");
    assert!(matches!(result, Err(DatabaseError::NotFound(_))));
}

// =============================================================================
// API KEY TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_create_api_key() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    let (api_key, key_info) = db
        .create_api_key(user.id, Some("test_key"), None, None, false)
        .unwrap();

    assert!(!api_key.is_empty());
    assert_eq!(key_info.name, "test_key".to_string());
    assert!(!key_info.revoked);
}

#[test(tokio::test)]
async fn test_management_key_does_not_count_toward_service_key_limit() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = AuthConfig::default();
    config.enable = true;
    config.database_path = tmp_dir.path().to_path_buf();
    config.api_key.default_ttl_seconds = 0;
    config.api_key.max_keys_per_user = 1;
    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("limit_test_user", "TestPass123!", None, None, Some(false))
        .unwrap();

    let (_management_key, management_info) = db
        .create_api_key(user.id, Some("limit_test_session"), None, None, true)
        .unwrap();
    assert!(management_info.is_management);

    let service_key =
        db.create_api_key(user.id, Some("service_key_1"), None, None, false);
    assert!(
        service_key.is_ok(),
        "service key quota should ignore active management keys"
    );
}

#[test(tokio::test)]
async fn test_verify_api_key_success() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, _) = db
        .create_api_key(user.id, Some("key_verify"), None, None, false)
        .unwrap();

    let context = db
        .authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();

    assert_eq!(context.username, "testuser");
    assert_eq!(context.user_id, user.id);
}

#[test(tokio::test)]
async fn test_verify_api_key_invalid() {
    let (db, _dirs) = create_test_db();

    let result =
        db.authenticate_api_key_request("invalid_key_12345", None, "/peer-id");

    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_api_key_expiration() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // Create key with 1 second TTL
    let (api_key, _) = db
        .create_api_key(user.id, Some("ttl1"), None, Some(1), false)
        .unwrap();

    // Should work immediately
    assert!(
        db.authenticate_api_key_request(&api_key, None, "/peer-id")
            .is_ok()
    );

    // Wait for expiration

    std::thread::sleep(std::time::Duration::from_secs(2));

    loop {
        let result =
            db.authenticate_api_key_request(&api_key, None, "/peer-id");

        if matches!(result, Err(DatabaseError::PermissionDenied(_))) {
            break;
        } else {
            std::thread::sleep(std::time::Duration::from_secs(1));
        }
    }
}

#[test(tokio::test)]
async fn test_api_key_ttl_uses_system_default_when_absent_or_zero() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = AuthConfig::default();
    config.enable = true;
    config.database_path = tmp_dir.path().to_path_buf();
    config.api_key.default_ttl_seconds = 100;
    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // No TTL provided -> should use system default
    let (_, info1) = db
        .create_api_key(user.id, Some("default1"), None, None, false)
        .unwrap();
    assert_eq!(info1.expires_at, Some(info1.created_at + 100));

    // TTL = 0 provided -> should NEVER expire (explicit permanent key)
    let (_, info2) = db
        .create_api_key(user.id, Some("default2"), None, Some(0), false)
        .unwrap();
    assert_eq!(
        info2.expires_at, None,
        "TTL=0 should create permanent key (never expires)"
    );
}

#[test(tokio::test)]
async fn test_api_key_ttl_capped_by_system_default_and_user_when_no_system() {
    // System TTL caps user-provided TTL
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = AuthConfig::default();
    config.enable = true;
    config.database_path = tmp_dir.path().to_path_buf();
    config.api_key.default_ttl_seconds = 50;
    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    let (_, capped) = db
        .create_api_key(user.id, Some("capped"), None, Some(100), false)
        .unwrap();
    assert_eq!(capped.expires_at, Some(capped.created_at + 50));

    // When system TTL is 0, user TTL is honored
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = AuthConfig::default();
    config.enable = true;
    config.database_path = tmp_dir.path().to_path_buf();
    config.api_key.default_ttl_seconds = 0;
    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("testuser2", "TestPass123!", None, None, Some(false))
        .unwrap();

    let (_, info) = db
        .create_api_key(user.id, Some("capped2"), None, Some(30), false)
        .unwrap();
    assert_eq!(info.expires_at, Some(info.created_at + 30));
}

#[test(tokio::test)]
async fn test_update_system_config_applies_api_key_ttl_immediately() {
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = AuthConfig::default();
    config.enable = true;
    config.database_path = tmp_dir.path().to_path_buf();
    config.api_key.default_ttl_seconds = 0;
    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("hotttl", "TestPass123!", None, None, Some(false))
        .unwrap();

    db.update_system_config("api_key_default_ttl_seconds", "45", Some(1))
        .unwrap();

    let (_, info) = db
        .create_api_key(user.id, Some("runtime-ttl"), None, None, false)
        .unwrap();
    assert_eq!(info.expires_at, Some(info.created_at + 45));
}

#[test(tokio::test)]
async fn test_update_system_config_applies_legacy_api_key_ttl_backfill_immediately()
 {
    let tmp_dir = tempfile::tempdir().unwrap();
    let mut config = AuthConfig::default();
    config.enable = true;
    config.database_path = tmp_dir.path().to_path_buf();
    config.api_key.default_ttl_seconds = 0;
    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("legacyttl", "TestPass123!", None, None, Some(false))
        .unwrap();

    let (api_key, info) = db
        .create_api_key(user.id, Some("legacy-runtime-ttl"), None, None, false)
        .unwrap();
    assert_eq!(info.expires_at, None);

    db.update_system_config("api_key_default_ttl_seconds", "1", Some(1))
        .unwrap();

    std::thread::sleep(std::time::Duration::from_secs(2));
    let deleted = db.cleanup_expired_api_keys().unwrap();
    assert!(deleted >= 1);
    assert!(matches!(
        db.authenticate_api_key_request(&api_key, None, "/peer-id"),
        Err(DatabaseError::PermissionDenied(_))
    ));
}

#[test(tokio::test)]
async fn test_update_system_config_applies_rate_limit_immediately() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("ratelive", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_, key_info) = db
        .create_api_key(user.id, Some("ratelive"), None, None, false)
        .unwrap();

    db.update_system_config("rate_limit_window_seconds", "60", Some(1))
        .unwrap();
    db.update_system_config("rate_limit_max_requests", "1", Some(1))
        .unwrap();

    assert!(
        db.check_rate_limit(
            Some(&key_info.id),
            Some("127.0.0.1"),
            Some("/runtime-rate-limit")
        )
        .unwrap()
    );
    assert!(matches!(
        db.check_rate_limit(
            Some(&key_info.id),
            Some("127.0.0.1"),
            Some("/runtime-rate-limit")
        ),
        Err(DatabaseError::RateLimitExceeded(_))
    ));
}

#[test(tokio::test)]
async fn test_update_system_config_applies_lockout_immediately() {
    let (db, _dirs) = create_test_db();

    db.update_system_config("max_login_attempts", "1", Some(1))
        .unwrap();
    db.update_system_config("lockout_duration_seconds", "60", Some(1))
        .unwrap();

    db.create_user("hotlockout", "TestPass123!", None, None, Some(false))
        .unwrap();

    assert!(matches!(
        db.verify_credentials("hotlockout", "WrongPass123!"),
        Err(DatabaseError::PermissionDenied(_))
    ));
    assert!(matches!(
        db.verify_credentials("hotlockout", "TestPass123!"),
        Err(DatabaseError::PermissionDenied(_))
    ));
}

#[test(tokio::test)]
async fn test_revoke_api_key() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("revoke"), None, None, false)
        .unwrap();

    // Revoke the key
    db.revoke_api_key(&key_info.id, None, None).unwrap();

    // Should no longer verify
    let result = db.authenticate_api_key_request(&api_key, None, "/peer-id");
    assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
}

#[test(tokio::test)]
async fn test_management_key_creation_rolls_back_on_error() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("mgmt_atomic", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (old_api_key, old_key_info) = db
        .create_api_key(user.id, Some("mgmt_session"), None, None, true)
        .unwrap();

    let result = db.create_api_key(
        user.id,
        Some("mgmt_session_invalid"),
        None,
        Some(-1),
        true,
    );
    assert!(matches!(result, Err(DatabaseError::Validation(_))));

    let old_key_info = db.get_api_key_info(&old_key_info.id).unwrap();
    assert!(
        !old_key_info.revoked,
        "existing management key should remain active after rollback"
    );
    assert!(
        db.authenticate_api_key_request(&old_api_key, None, "/peer-id")
            .is_ok()
    );
}

#[test(tokio::test)]
async fn test_issue_management_key_transactional_writes_audit_and_replaces_key()
{
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("mgmt_audit", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (old_api_key, old_key_info) = db
        .create_api_key(user.id, Some("mgmt_session"), None, None, true)
        .unwrap();

    let (new_api_key, new_key_info) = db
        .issue_management_api_key_transactional(
            user.id,
            Some("mgmt_session"),
            None,
            None,
            Some(ave_http::auth::database_audit::AuditLogParams {
                user_id: Some(user.id),
                api_key_id: None,
                action_type: "login_success",
                endpoint: Some("/login"),
                http_method: Some("POST"),
                ip_address: Some("127.0.0.1"),
                user_agent: Some("test-agent"),
                request_id: None,
                details: Some("issued management key"),
                success: true,
                error_message: None,
            }),
        )
        .unwrap();

    assert_ne!(new_key_info.id, old_key_info.id);
    assert!(
        db.authenticate_api_key_request(&new_api_key, None, "/peer-id")
            .is_ok()
    );
    assert!(matches!(
        db.authenticate_api_key_request(&old_api_key, None, "/peer-id"),
        Err(DatabaseError::PermissionDenied(_))
    ));

    let old_key_info = db.get_api_key_info(&old_key_info.id).unwrap();
    assert!(old_key_info.revoked);

    let logs = db
        .query_audit_logs(&AuditLogQuery {
            user_id: Some(user.id),
            api_key_id: Some(new_key_info.id.clone()),
            endpoint: Some("/login".to_string()),
            http_method: Some("POST".to_string()),
            ip_address: None,
            user_agent: None,
            success: Some(true),
            start_timestamp: None,
            end_timestamp: None,
            limit: Some(10),
            offset: Some(0),
            exclude_user_id: None,
            exclude_api_key_id: None,
            exclude_ip_address: None,
            exclude_endpoint: None,
        })
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action_type, "login_success");
}

#[test(tokio::test)]
async fn test_rotate_api_key_rolls_back_on_error() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("rotate_atomic", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (old_api_key, old_key_info) = db
        .create_api_key(user.id, Some("rotate_me"), None, None, false)
        .unwrap();

    let result = db.rotate_api_key_transactional(RotateApiKeyParams {
        key_id: &old_key_info.id,
        name: Some("invalid/name"),
        description: None,
        expires_in_seconds: None,
        revoked_by: Some(user.id),
        reason: Some("test rollback"),
        audit: None,
    });
    assert!(matches!(result, Err(DatabaseError::Validation(_))));

    let old_key_info = db.get_api_key_info(&old_key_info.id).unwrap();
    assert!(
        !old_key_info.revoked,
        "original key should remain active after failed rotation"
    );
    assert!(
        db.authenticate_api_key_request(&old_api_key, None, "/peer-id")
            .is_ok()
    );
}

#[test(tokio::test)]
async fn test_rotate_api_key_transactional_writes_audit() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("rotate_audit", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_old_api_key, old_key_info) = db
        .create_api_key(user.id, Some("rotate_me"), None, None, false)
        .unwrap();

    let (_new_api_key, new_key_info) = db
        .rotate_api_key_transactional(RotateApiKeyParams {
            key_id: &old_key_info.id,
            name: None,
            description: None,
            expires_in_seconds: None,
            revoked_by: Some(user.id),
            reason: Some("test rotate"),
            audit: Some(ave_http::auth::database_audit::AuditLogParams {
                user_id: Some(user.id),
                api_key_id: Some(&old_key_info.id),
                action_type: "api_key_rotated",
                endpoint: Some("/admin/api-keys/test/rotate"),
                http_method: Some("POST"),
                ip_address: Some("127.0.0.1"),
                user_agent: None,
                request_id: None,
                details: Some("{\"reason\":\"test rotate\"}"),
                success: true,
                error_message: None,
            }),
        })
        .unwrap();

    assert_ne!(new_key_info.id, old_key_info.id);
    assert!(db.get_api_key_info(&old_key_info.id).unwrap().revoked);

    let logs = db
        .query_audit_logs(&AuditLogQuery {
            user_id: Some(user.id),
            api_key_id: Some(old_key_info.id.clone()),
            endpoint: Some("/admin/api-keys/test/rotate".to_string()),
            http_method: Some("POST".to_string()),
            ip_address: None,
            user_agent: None,
            success: Some(true),
            start_timestamp: None,
            end_timestamp: None,
            limit: Some(10),
            offset: Some(0),
            exclude_user_id: None,
            exclude_api_key_id: None,
            exclude_ip_address: None,
            exclude_endpoint: None,
        })
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].action_type, "api_key_rotated");
}

#[test(tokio::test)]
async fn test_list_user_api_keys() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    db.create_api_key(user.id, Some("key1"), None, None, false)
        .unwrap();
    db.create_api_key(user.id, Some("key2"), None, None, false)
        .unwrap();

    let keys = db.list_user_api_keys(user.id, false).unwrap();

    assert_eq!(keys.len(), 2);
}

#[test(tokio::test)]
async fn test_api_key_last_used_tracking() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("tracking"), None, None, false)
        .unwrap();

    assert!(key_info.last_used_at.is_none());

    // Use the key
    db.authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();

    // Check it was tracked
    let keys = db.list_user_api_keys(user.id, false).unwrap();
    let used_key = keys.iter().find(|k| k.id == key_info.id).unwrap();

    assert!(used_key.last_used_at.is_some());
}

#[test(tokio::test)]
async fn test_authenticate_api_key_request_updates_last_used_ip() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("auth_pipeline", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("pipeline"), None, None, false)
        .unwrap();

    let ctx = db
        .authenticate_api_key_request(&api_key, Some("127.0.0.1"), "/peer-id")
        .unwrap();

    assert_eq!(ctx.api_key_id, key_info.id);
    assert_eq!(ctx.ip_address.as_deref(), Some("127.0.0.1"));

    let updated = db.get_api_key_info(&key_info.id).unwrap();
    assert!(updated.last_used_at.is_some());
    assert_eq!(updated.last_used_ip.as_deref(), Some("127.0.0.1"));
}

#[test(tokio::test)]
async fn test_apply_ttl_to_legacy_api_keys() {
    let dir = tempfile::tempdir().expect("auth temp dir");
    let path = dir.path().to_path_buf();
    let base_config = AuthConfig {
        durability: false,
        enable: true,
        database_path: path.clone(),
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
            max_requests: 10_000,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
        },
        session: SessionConfig {
            audit_enable: true,
            audit_retention_days: 90,
            audit_max_entries: 1_000_000,
        },
    };

    let db =
        AuthDatabase::new(base_config.clone(), "AdminPass123!", None).unwrap();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_, key_info) = db
        .create_api_key(user.id, Some("perm_effective"), None, None, false)
        .unwrap();

    // Verify no expiration was set
    let info = db.get_api_key_info(&key_info.id).unwrap();
    assert!(info.expires_at.is_none());

    drop(db);

    // Re-open the same database with a runtime default TTL so cleanup backfills
    let mut cleanup_config = base_config;
    cleanup_config.api_key.default_ttl_seconds = 100;
    let db = AuthDatabase::new(cleanup_config, "AdminPass123!", None).unwrap();
    let _ = db.cleanup_expired_api_keys().unwrap();
    let info = db.get_api_key_info(&key_info.id).unwrap();

    assert_eq!(info.expires_at, Some(info.created_at + 100));
}

#[test(tokio::test)]
async fn test_api_key_without_plan_has_unlimited_monthly_quota() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("quota_unlimited", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("no_plan"), None, None, false)
        .unwrap();

    for _ in 0..550 {
        db.authenticate_api_key_request(&api_key, None, "/peer-id")
            .unwrap();
    }

    let status = db.get_api_key_quota_status(&key_info.id, None).unwrap();
    assert!(!status.has_quota);
    assert!(status.plan_id.is_none());
    assert!(status.effective_limit.is_none());
    assert_eq!(status.used_events, 550);
}

#[test(tokio::test)]
async fn test_monthly_quota_enforced_when_plan_assigned() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("quota_limited", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("with_plan"), None, None, false)
        .unwrap();

    db.create_usage_plan("basic", "Basic", None, 2).unwrap();
    db.assign_api_key_plan(&key_info.id, Some("basic"), Some(1))
        .unwrap();

    db.authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();
    db.authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();

    let third = db.authenticate_api_key_request(&api_key, None, "/peer-id");
    assert!(matches!(third, Err(DatabaseError::RateLimitExceeded(_))));

    let status = db.get_api_key_quota_status(&key_info.id, None).unwrap();
    assert!(status.has_quota);
    assert_eq!(status.plan_id.as_deref(), Some("basic"));
    assert_eq!(status.effective_limit, Some(2));
    assert_eq!(status.used_events, 2);
    assert_eq!(status.remaining_events, Some(0));
}

#[test(tokio::test)]
async fn test_monthly_quota_concurrent_requests_respect_limit() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user(
            "quota_concurrent",
            "TestPass123!",
            None,
            None,
            Some(false),
        )
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("quota_concurrent"), None, None, false)
        .unwrap();

    db.create_usage_plan("single", "Single", None, 1).unwrap();
    db.assign_api_key_plan(&key_info.id, Some("single"), Some(1))
        .unwrap();

    let workers = 4;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let db = db.clone();
        let barrier = Arc::clone(&barrier);
        let api_key = api_key.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            db.authenticate_api_key_request(&api_key, None, "/peer-id")
        }));
    }

    let mut allowed = 0;
    let mut rejected = 0;

    for handle in handles {
        match handle.join().unwrap() {
            Ok(_) => allowed += 1,
            Err(DatabaseError::RateLimitExceeded(_)) => rejected += 1,
            other => panic!("unexpected concurrent quota result: {:?}", other),
        }
    }

    assert_eq!(allowed, 1);
    assert_eq!(rejected, workers - 1);

    let status = db.get_api_key_quota_status(&key_info.id, None).unwrap();
    assert_eq!(status.used_events, 1);
    assert_eq!(status.remaining_events, Some(0));
}

#[test(tokio::test)]
async fn test_quota_extension_adds_capacity() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("quota_extension", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, key_info) = db
        .create_api_key(user.id, Some("ext_plan"), None, None, false)
        .unwrap();

    db.create_usage_plan("starter", "Starter", None, 2).unwrap();
    db.assign_api_key_plan(&key_info.id, Some("starter"), Some(1))
        .unwrap();

    db.authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();
    db.authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();
    assert!(matches!(
        db.authenticate_api_key_request(&api_key, None, "/peer-id"),
        Err(DatabaseError::RateLimitExceeded(_))
    ));

    db.add_quota_extension(
        &key_info.id,
        500,
        None,
        Some("manual extension"),
        Some(1),
    )
    .unwrap();

    db.authenticate_api_key_request(&api_key, None, "/peer-id")
        .unwrap();
    let status = db.get_api_key_quota_status(&key_info.id, None).unwrap();
    assert_eq!(status.plan_limit, Some(2));
    assert_eq!(status.extensions_total, 500);
    assert_eq!(status.effective_limit, Some(502));
    assert_eq!(status.used_events, 3);
}

#[test(tokio::test)]
async fn test_cannot_assign_plan_to_management_key() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("quota_mgmt_plan", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_api_key, mgmt_key_info) = db
        .create_api_key(user.id, Some("mgmt_key"), None, None, true)
        .unwrap();

    db.create_usage_plan("mgmt_test", "Mgmt test", None, 10)
        .unwrap();

    let result =
        db.assign_api_key_plan(&mgmt_key_info.id, Some("mgmt_test"), Some(1));
    assert!(matches!(result, Err(DatabaseError::Validation(_))));
}

#[test(tokio::test)]
async fn test_management_key_does_not_consume_monthly_quota() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("quota_mgmt_skip", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (api_key, mgmt_key_info) = db
        .create_api_key(user.id, Some("mgmt_key2"), None, None, true)
        .unwrap();

    for _ in 0..20 {
        db.authenticate_api_key_request(&api_key, None, "/peer-id")
            .unwrap();
    }

    let status = db
        .get_api_key_quota_status(&mgmt_key_info.id, None)
        .unwrap();
    assert!(!status.has_quota);
    assert!(status.plan_id.is_none());
    assert_eq!(status.used_events, 0);
}

#[test(tokio::test)]
async fn test_transfer_api_key_quota_state_moves_plan_usage_and_extensions() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("quota_rotation", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (old_api_key, old_key_info) = db
        .create_api_key(user.id, Some("old_rotation_key"), None, None, false)
        .unwrap();
    db.create_usage_plan("rotation", "Rotation", None, 5)
        .unwrap();
    db.assign_api_key_plan(&old_key_info.id, Some("rotation"), Some(1))
        .unwrap();
    db.authenticate_api_key_request(&old_api_key, None, "/peer-id")
        .unwrap();
    db.add_quota_extension(&old_key_info.id, 3, None, Some("carry"), Some(1))
        .unwrap();

    let (_new_api_key, new_key_info) = db
        .rotate_api_key_transactional(RotateApiKeyParams {
            key_id: &old_key_info.id,
            name: Some("new_rotation_key"),
            description: None,
            expires_in_seconds: None,
            revoked_by: Some(1),
            reason: Some("rotation"),
            audit: None,
        })
        .unwrap();

    let new_status =
        db.get_api_key_quota_status(&new_key_info.id, None).unwrap();
    assert!(new_status.has_quota);
    assert_eq!(new_status.plan_id.as_deref(), Some("rotation"));
    assert_eq!(new_status.used_events, 1);
    assert_eq!(new_status.extensions_total, 3);
    assert_eq!(new_status.effective_limit, Some(8));

    let old_info = db.get_api_key_info(&old_key_info.id).unwrap();
    assert!(old_info.plan_id.is_none());

    let old_status =
        db.get_api_key_quota_status(&old_key_info.id, None).unwrap();
    assert!(!old_status.has_quota);
    assert_eq!(old_status.used_events, 0);
    assert_eq!(old_status.extensions_total, 0);
}

#[test(tokio::test)]
async fn test_update_usage_plan_duplicate_name_returns_duplicate() {
    let (db, _dirs) = create_test_db();

    db.create_usage_plan("starter", "Starter", None, 10)
        .unwrap();
    db.create_usage_plan("pro", "Pro", None, 100).unwrap();

    let result = db.update_usage_plan("starter", Some("Pro"), None, None);
    assert!(matches!(result, Err(DatabaseError::Duplicate(_))));
}

// =============================================================================
// PERMISSION TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_set_role_permission() {
    let (db, _dirs) = create_test_db();

    let role = db.create_role("editor", None).unwrap();

    // Grant read permission on subjects
    db.set_role_permission(role.id, "node_subject", "get", true)
        .unwrap();

    let permissions = db.get_role_permissions(role.id).unwrap();

    let perm = permissions
        .iter()
        .find(|p| p.resource == "node_subject" && p.action == "get")
        .unwrap();

    assert!(perm.allowed);
}

#[test(tokio::test)]
async fn test_set_user_permission_override() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();

    // Set user-specific permission
    db.set_user_permission(user.id, "admin_users", "put", false, None)
        .unwrap();

    let permissions = db.get_user_permissions(user.id).unwrap();

    let perm = permissions
        .iter()
        .find(|p| p.resource == "admin_users" && p.action == "put")
        .unwrap();

    assert!(!perm.allowed);
}

#[test(tokio::test)]
async fn test_user_effective_permissions() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    // Role grants read on events
    db.set_role_permission(role.id, "node_subject", "get", true)
        .unwrap();
    db.assign_role_to_user(user.id, role.id, None).unwrap();

    let permissions = db.get_user_effective_permissions(user.id).unwrap();

    let perm = permissions
        .iter()
        .find(|p| p.resource == "node_subject" && p.action == "get");

    assert!(perm.is_some());
    assert!(perm.unwrap().allowed);
}

#[test(tokio::test)]
async fn test_user_override_denies_role_permission() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let role = db.create_role("editor", None).unwrap();

    // Role grants permission
    db.set_role_permission(role.id, "node_subject", "delete", true)
        .unwrap();
    db.assign_role_to_user(user.id, role.id, None).unwrap();

    // User override denies it
    db.set_user_permission(user.id, "node_subject", "delete", false, None)
        .unwrap();

    let permissions = db.get_user_effective_permissions(user.id).unwrap();

    let perm = permissions
        .iter()
        .find(|p| p.resource == "node_subject" && p.action == "delete")
        .unwrap();

    assert!(!perm.allowed);
}

// =============================================================================
// RATE LIMITING TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_rate_limit_within_limit() {
    let (db, _dirs) = create_test_db();

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_, key_info) = db
        .create_api_key(user.id, Some("rate1"), None, None, false)
        .unwrap();

    // Make 10 requests (well under limit of 100)
    for _ in 0..10 {
        let result = db.check_rate_limit(
            Some(&key_info.id),
            Some("127.0.0.1"),
            Some("/api/test"),
        );
        assert!(result.is_ok());
    }
}

#[test(tokio::test)]
async fn test_rate_limit_exceeded() {
    let rate_limit = RateLimitConfig {
        enable: true,
        window_seconds: 60,
        max_requests: 100,
        limit_by_key: true,
        limit_by_ip: true,
        cleanup_interval_seconds: 3600,
        sensitive_endpoints: vec![],
    };

    let (db, _dirs) = create_test_db_with_rate_limit(rate_limit).await;

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_, key_info) = db
        .create_api_key(user.id, Some("rate2"), None, None, false)
        .unwrap();

    // Hit rate limit (100 requests)
    for _ in 0..100 {
        let _ = db.check_rate_limit(
            Some(&key_info.id),
            Some("127.0.0.1"),
            Some("/api/test"),
        );
    }

    // 101st request should fail
    let result = db.check_rate_limit(
        Some(&key_info.id),
        Some("127.0.0.1"),
        Some("/api/test"),
    );
    assert!(matches!(result, Err(DatabaseError::RateLimitExceeded(_))));
}

#[test(tokio::test)]
async fn test_rate_limit_concurrent_requests_respect_limit() {
    let rate_limit = RateLimitConfig {
        enable: true,
        window_seconds: 60,
        max_requests: 1,
        limit_by_key: true,
        limit_by_ip: true,
        cleanup_interval_seconds: 3600,
        sensitive_endpoints: vec![],
    };

    let (db, _dirs) = create_test_db_with_rate_limit(rate_limit).await;

    let user = db
        .create_user(
            "rate_limit_concurrent",
            "TestPass123!",
            None,
            None,
            Some(false),
        )
        .unwrap();
    let (_, key_info) = db
        .create_api_key(user.id, Some("rate_concurrent"), None, None, false)
        .unwrap();

    let workers = 4;
    let barrier = Arc::new(Barrier::new(workers));
    let mut handles = Vec::with_capacity(workers);

    for _ in 0..workers {
        let db = db.clone();
        let barrier = Arc::clone(&barrier);
        let key_id = key_info.id.clone();
        handles.push(std::thread::spawn(move || {
            barrier.wait();
            db.check_rate_limit(
                Some(&key_id),
                Some("127.0.0.1"),
                Some("/api/test"),
            )
        }));
    }

    let mut allowed = 0;
    let mut rejected = 0;

    for handle in handles {
        match handle.join().unwrap() {
            Ok(true) => allowed += 1,
            Err(DatabaseError::RateLimitExceeded(_)) => rejected += 1,
            other => {
                panic!("unexpected concurrent rate limit result: {:?}", other)
            }
        }
    }

    assert_eq!(allowed, 1);
    assert_eq!(rejected, workers - 1);
}

#[test(tokio::test)]
async fn test_rate_limit_by_ip_only() {
    let rate_limit = RateLimitConfig {
        enable: true,
        window_seconds: 60,
        max_requests: 2,
        limit_by_key: false,
        limit_by_ip: true,
        cleanup_interval_seconds: 3600,
        sensitive_endpoints: vec![],
    };

    let (db, _dirs) = create_test_db_with_rate_limit(rate_limit).await;

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_, key1) = db
        .create_api_key(user.id, Some("rlip1"), None, None, false)
        .unwrap();
    let (_, key2) = db
        .create_api_key(user.id, Some("rlip2"), None, None, false)
        .unwrap();

    // Two requests from same IP should pass
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("127.0.0.1"),
            Some("/api/test")
        )
        .is_ok()
    );
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("127.0.0.1"),
            Some("/api/test")
        )
        .is_ok()
    );

    // Third request from same IP but different key should exceed (IP-only limit)
    let result = db.check_rate_limit(
        Some(&key2.id),
        Some("127.0.0.1"),
        Some("/api/test"),
    );
    assert!(matches!(result, Err(DatabaseError::RateLimitExceeded(_))));
}

#[test(tokio::test)]
async fn test_rate_limit_by_key_only() {
    let rate_limit = RateLimitConfig {
        enable: true,
        window_seconds: 60,
        max_requests: 1,
        limit_by_key: true,
        limit_by_ip: false,
        cleanup_interval_seconds: 3600,
        sensitive_endpoints: vec![],
    };

    let (db, _dirs) = create_test_db_with_rate_limit(rate_limit).await;

    let user = db
        .create_user("testuser", "TestPass123!", None, None, Some(false))
        .unwrap();
    let (_, key_info) = db
        .create_api_key(user.id, Some("rlkey"), None, None, false)
        .unwrap();

    // First request from any IP should pass
    assert!(
        db.check_rate_limit(
            Some(&key_info.id),
            Some("10.0.0.1"),
            Some("/api/test")
        )
        .is_ok()
    );

    // Second request with the same key but different IP should still be limited
    let result = db.check_rate_limit(
        Some(&key_info.id),
        Some("10.0.0.2"),
        Some("/api/test"),
    );
    assert!(matches!(result, Err(DatabaseError::RateLimitExceeded(_))));
}

#[test(tokio::test)]
async fn test_rate_limit_by_both_key_and_ip() {
    let rate_limit = RateLimitConfig {
        enable: true,
        window_seconds: 60,
        max_requests: 2,
        limit_by_key: true,
        limit_by_ip: true,
        cleanup_interval_seconds: 3600,
        sensitive_endpoints: vec![],
    };

    let (db, _dirs) = create_test_db_with_rate_limit(rate_limit).await;

    let user1 = db
        .create_user("user1", "TestPass123!", None, None, Some(false))
        .unwrap();
    let user2 = db
        .create_user("user2", "TestPass123!", None, None, Some(false))
        .unwrap();

    let (_, key1) = db
        .create_api_key(user1.id, Some("key1"), None, None, false)
        .unwrap();
    let (_, key2) = db
        .create_api_key(user2.id, Some("key2"), None, None, false)
        .unwrap();

    // Scenario 1: Same key, different IPs - each IP should have independent limit
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("10.0.0.1"),
            Some("/api/test")
        )
        .is_ok(),
        "First request from key1@10.0.0.1 should pass"
    );
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("10.0.0.1"),
            Some("/api/test")
        )
        .is_ok(),
        "Second request from key1@10.0.0.1 should pass"
    );
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("10.0.0.1"),
            Some("/api/test")
        )
        .is_err(),
        "Third request from key1@10.0.0.1 should exceed limit"
    );

    // Same key from different IP should work (independent counter)
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("10.0.0.2"),
            Some("/api/test")
        )
        .is_ok(),
        "First request from key1@10.0.0.2 should pass (different IP)"
    );
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("10.0.0.2"),
            Some("/api/test")
        )
        .is_ok(),
        "Second request from key1@10.0.0.2 should pass"
    );

    // Scenario 2: Different keys, same IP - each key should have independent limit
    assert!(
        db.check_rate_limit(
            Some(&key2.id),
            Some("192.168.1.1"),
            Some("/api/test")
        )
        .is_ok(),
        "First request from key2@192.168.1.1 should pass"
    );
    assert!(
        db.check_rate_limit(
            Some(&key2.id),
            Some("192.168.1.1"),
            Some("/api/test")
        )
        .is_ok(),
        "Second request from key2@192.168.1.1 should pass"
    );
    assert!(
        db.check_rate_limit(
            Some(&key2.id),
            Some("192.168.1.1"),
            Some("/api/test")
        )
        .is_err(),
        "Third request from key2@192.168.1.1 should exceed limit"
    );

    // Different key from same IP should work (independent counter)
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("192.168.1.1"),
            Some("/api/test")
        )
        .is_ok(),
        "First request from key1@192.168.1.1 should pass (different key)"
    );

    // Scenario 3: Verify that limit is per (key, IP) combination
    // key1 from 10.0.0.2 already has 2 requests, should fail on 3rd
    assert!(
        db.check_rate_limit(
            Some(&key1.id),
            Some("10.0.0.2"),
            Some("/api/test")
        )
        .is_err(),
        "Third request from key1@10.0.0.2 should exceed limit"
    );
}

// =============================================================================
// AUDIT LOG TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_audit_logging_disabled() {
    let session = SessionConfig {
        audit_enable: false,
        audit_retention_days: 90,
        audit_max_entries: 1_000_000,
    };

    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let path = dir.path().to_path_buf();

    let config = AuthConfig {
        durability: false,
        enable: true,
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
            max_requests: 100,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
        },
        session,
    };

    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    // Attempt to log should be a no-op when audit is disabled
    let log_id = db
        .create_audit_log(ave_http::auth::database_audit::AuditLogParams {
            user_id: None,
            api_key_id: None,
            action_type: "login",
            endpoint: Some("/login"),
            http_method: Some("POST"),
            ip_address: None,
            user_agent: None,
            request_id: None,
            details: None,
            success: true,
            error_message: None,
        })
        .unwrap();
    assert_eq!(log_id, 0);

    let query = AuditLogQuery {
        user_id: None,
        api_key_id: None,
        endpoint: None,
        http_method: None,
        ip_address: None,
        success: None,
        user_agent: None,
        start_timestamp: None,
        end_timestamp: None,
        limit: None,
        offset: None,
        exclude_user_id: None,
        exclude_api_key_id: None,
        exclude_ip_address: None,
        exclude_endpoint: None,
    };

    let logs = db.query_audit_logs(&query).unwrap();
    assert!(logs.is_empty());
}

#[test(tokio::test)]
async fn test_log_api_request_enabled() {
    let mut config = AuthConfig::default();

    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let path = dir.path().to_path_buf();

    config.enable = true;
    config.session.audit_enable = true;
    config.database_path = path;

    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("apiuser", "Pass123!", None, None, Some(false))
        .unwrap();
    let (_, key) = db
        .create_api_key(user.id, Some("test_key"), None, None, false)
        .unwrap();

    let ctx = AuthContext {
        user_id: user.id,
        username: user.username.clone(),
        roles: vec![],
        permissions: vec![],
        api_key_id: key.id,
        is_management_key: false,
        ip_address: Some("127.0.0.1".to_string()),
    };

    let log_id = db
        .log_api_request(
            &ctx,
            ave_http::auth::database_audit::ApiRequestParams {
                path: "/api/test",
                method: "GET",
                ip_address: ctx.ip_address.as_deref(),
                user_agent: Some("tester"),
                request_id: "req-123",
                success: true,
                error_message: None,
            },
        )
        .unwrap();
    assert_ne!(log_id, 0);

    let query = AuditLogQuery {
        user_id: Some(user.id),
        api_key_id: None,
        endpoint: None,
        http_method: None,
        ip_address: None,
        success: Some(true),
        start_timestamp: None,
        user_agent: None,
        end_timestamp: None,
        limit: None,
        offset: None,
        exclude_user_id: None,
        exclude_api_key_id: None,
        exclude_ip_address: None,
        exclude_endpoint: None,
    };

    let logs = db.query_audit_logs(&query).unwrap();
    assert_eq!(logs.len(), 1);
    assert_eq!(logs[0].endpoint.as_deref(), Some("/api/test"));
    assert_eq!(logs[0].http_method.as_deref(), Some("GET"));
}

#[test(tokio::test)]
async fn test_log_api_request_always_enabled() {
    // SECURITY: Audit logging is now ALWAYS enabled for full traceability
    // This test verifies that all requests are logged regardless of config
    let mut config = AuthConfig::default();

    let dir = tempfile::tempdir().expect("Can not create temporal directory");
    let path = dir.path().to_path_buf();

    config.enable = true;
    config.session.audit_enable = true;
    config.database_path = path;

    let db = AuthDatabase::new(config, "AdminPass123!", None).unwrap();

    let user = db
        .create_user("apiuser", "Pass123!", None, None, Some(false))
        .unwrap();
    let (_, key) = db
        .create_api_key(user.id, Some("test_key2"), None, None, false)
        .unwrap();

    let ctx = AuthContext {
        user_id: user.id,
        username: user.username.clone(),
        roles: vec![],
        permissions: vec![],
        api_key_id: key.id,
        is_management_key: false,
        ip_address: Some("127.0.0.1".to_string()),
    };

    let log_id = db
        .log_api_request(
            &ctx,
            ave_http::auth::database_audit::ApiRequestParams {
                path: "/api/test",
                method: "POST",
                ip_address: ctx.ip_address.as_deref(),
                user_agent: None,
                request_id: "req-456",
                success: false,
                error_message: Some("HTTP 500"),
            },
        )
        .unwrap();
    // Verify log was created (log_id > 0 means it was logged)
    assert!(log_id > 0, "Audit logging should always be active");

    let query = AuditLogQuery {
        user_id: Some(user.id),
        api_key_id: None,
        endpoint: None,
        http_method: None,
        ip_address: None,
        success: None,
        start_timestamp: None,
        user_agent: None,
        end_timestamp: None,
        limit: None,
        offset: None,
        exclude_user_id: None,
        exclude_api_key_id: None,
        exclude_ip_address: None,
        exclude_endpoint: None,
    };

    let logs = db.query_audit_logs(&query).unwrap();
    assert_eq!(logs.len(), 1, "Should have logged exactly one request");
    assert_eq!(logs[0].endpoint.as_deref(), Some("/api/test"));
    assert_eq!(logs[0].http_method.as_deref(), Some("POST"));
}

// =============================================================================
// SYSTEM CONFIG TESTS
// =============================================================================

#[test(tokio::test)]
async fn test_list_system_config() {
    let (db, _dirs) = create_test_db();

    let config = db.list_system_config().unwrap();

    // Should expose system config entries
    assert!(!config.is_empty());
}

#[test(tokio::test)]
async fn test_update_system_config() {
    let (db, _dirs) = create_test_db();

    let result = db.update_system_config("unknown_key", "1", None);

    assert!(result.is_err());
}

/// Test endpoint-specific rate limiting with sensitive endpoints
#[test(tokio::test)]
async fn test_endpoint_specific_rate_limiting() {
    let rate_limit = RateLimitConfig {
        enable: true,
        window_seconds: 60,
        max_requests: 100, // Default limit: 100 requests
        limit_by_key: false,
        limit_by_ip: true,
        cleanup_interval_seconds: 3600,
        sensitive_endpoints: vec![
            EndpointRateLimit {
                endpoint: "/login".to_string(),
                max_requests: 5, // Login limited to 5 requests
                window_seconds: None, // Use default window
            },
            EndpointRateLimit {
                endpoint: "/change-password".to_string(),
                max_requests: 3, // Password change limited to 3 requests
                window_seconds: Some(120), // Custom 2-minute window
            },
        ],
    };

    let (db, _dirs) = create_test_db_with_rate_limit(rate_limit).await;

    // Test 1: Regular endpoint should allow 100 requests
    for i in 1..=100 {
        assert!(
            db.check_rate_limit(None, Some("1.2.3.4"), Some("/api/regular"))
                .is_ok(),
            "Regular endpoint request {} should pass",
            i
        );
    }

    // 101st request should fail
    let result =
        db.check_rate_limit(None, Some("1.2.3.4"), Some("/api/regular"));
    assert!(
        matches!(result, Err(DatabaseError::RateLimitExceeded(_))),
        "Regular endpoint should be rate limited at 100 requests"
    );

    // Test 2: /login endpoint should only allow 5 requests
    for i in 1..=5 {
        assert!(
            db.check_rate_limit(None, Some("2.3.4.5"), Some("/login"))
                .is_ok(),
            "/login request {} should pass",
            i
        );
    }

    // 6th request should fail
    let result = db.check_rate_limit(None, Some("2.3.4.5"), Some("/login"));
    assert!(
        matches!(result, Err(DatabaseError::RateLimitExceeded(_))),
        "/login should be rate limited at 5 requests"
    );

    // Test 3: /change-password should only allow 3 requests
    for i in 1..=3 {
        assert!(
            db.check_rate_limit(
                None,
                Some("3.4.5.6"),
                Some("/change-password")
            )
            .is_ok(),
            "/change-password request {} should pass",
            i
        );
    }

    // 4th request should fail
    let result =
        db.check_rate_limit(None, Some("3.4.5.6"), Some("/change-password"));
    assert!(
        matches!(result, Err(DatabaseError::RateLimitExceeded(_))),
        "/change-password should be rate limited at 3 requests"
    );

    // Test 4: Different IP should have independent limits
    assert!(
        db.check_rate_limit(None, Some("4.5.6.7"), Some("/login"))
            .is_ok(),
        "Different IP should have independent /login limit"
    );
}
