// Ave HTTP Auth System - Database Integration Tests
//
// Comprehensive tests for user management, roles, API keys, and permissions

mod common;

use ave_bridge::auth::RateLimitConfig;
use ave_http::auth::database::DatabaseError;
use ave_http::auth::models::*;

#[cfg(test)]
mod tests {
    use crate::common::create_test_db;

    use super::*;

    use ave_bridge::auth::{
        ApiKeyConfig, AuthConfig, EndpointRateLimit, LockoutConfig, SessionConfig,
    };
    use ave_http::auth::database::AuthDatabase;
    use tempfile::TempDir;

    fn create_test_db_with_rate_limit(
        rate_limit: RateLimitConfig,
    ) -> (AuthDatabase, TempDir) {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory.");
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
            rate_limit,
            session: SessionConfig {
                audit_enable: true,
                audit_retention_days: 90,
                log_all_requests: false,
            },
        };

        (AuthDatabase::new(config, "AdminPass123!").unwrap(), dir)
    }

    // =============================================================================
    // USER MANAGEMENT TESTS
    // =============================================================================

    #[test]
    fn test_create_user_success() {
        let (db, _dirs) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        assert_eq!(user.username, "testuser");
        assert!(user.is_active);
        assert_eq!(user.failed_login_attempts, 0);
    }

    #[test]
    fn test_create_user_duplicate() {
        let (db, _dirs) = create_test_db();

        db.create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        let result =
            db.create_user("testuser", "TestPass123!", None, None, Some(false));

        assert!(matches!(result, Err(DatabaseError::DuplicateError(_))));
    }

    #[test]
    fn test_get_user_by_id() {
        let (db, _dirs) = create_test_db();

        let created = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        let fetched = db.get_user_by_id(created.id).unwrap();

        assert_eq!(fetched.username, "testuser");
        assert_eq!(fetched.id, created.id);
    }

    #[test]
    fn test_update_user() {
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

    #[test]
    fn test_deactivate_user() {
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

    #[test]
    fn test_list_users() {
        let (db, _dirs) = create_test_db();

        db.create_user("user1", "TestPass123!", None, None, Some(false))
            .unwrap();
        db.create_user("user2", "TestPass123!", None, None, Some(false))
            .unwrap();

        let users = db.list_users(false, 100, 0).unwrap();

        // At least 3 users (admin + user1 + user2)
        assert!(users.len() >= 3);
    }

    #[test]
    fn test_list_users_pagination() {
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

    #[test]
    fn test_delete_user() {
        let (db, _dirs) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        db.delete_user(user.id).unwrap();

        // Should not be able to get deleted user
        let result = db.get_user_by_id(user.id);
        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    // =============================================================================
    // AUTHENTICATION TESTS
    // =============================================================================

    #[test]
    fn test_verify_credentials_success() {
        let (db, _dirs) = create_test_db();

        let user = db.create_user("testuser", "TestPass123!", None, None, Some(false))
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

    #[test]
    fn test_verify_credentials_wrong_password() {
        let (db, _dirs) = create_test_db();

        db.create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        let result = db.verify_credentials("testuser", "WrongPassword");
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_account_lockout_after_failed_attempts() {
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

    #[test]
    fn test_failed_attempts_reset_on_success() {
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

    #[test]
    fn test_create_role() {
        let (db, _dirs) = create_test_db();

        let role = db.create_role("editor", Some("Editor role")).unwrap();

        assert_eq!(role.name.unwrap(), "editor");
        assert_eq!(role.description, Some("Editor role".to_string()));
    }

    #[test]
    fn test_create_role_duplicate() {
        let (db, _dirs) = create_test_db();

        db.create_role("editor", None).unwrap();
        let result = db.create_role("editor", None);

        assert!(matches!(result, Err(DatabaseError::DuplicateError(_))));
    }

    #[test]
    fn test_assign_role_to_user() {
        let (db, _dirs) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        let role = db.create_role("editor", None).unwrap();

        db.assign_role_to_user(user.id, role.id, None).unwrap();

        let roles = db.get_user_roles(user.id).unwrap();
        assert!(roles.contains(&"editor".to_string()));
    }

    #[test]
    fn test_remove_role_from_user() {
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

    #[test]
    fn test_user_with_multiple_roles() {
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

    #[test]
    fn test_delete_role() {
        let (db, _dirs) = create_test_db();

        let role = db.create_role("temp_role", None).unwrap();

        db.delete_role(role.id).unwrap();

        let result = db.get_role_by_name("temp_role");
        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    // =============================================================================
    // API KEY TESTS
    // =============================================================================

    #[test]
    fn test_create_api_key() {
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

    #[test]
    fn test_verify_api_key_success() {
        let (db, _dirs) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        let (api_key, _) = db
            .create_api_key(user.id, Some("key_verify"), None, None, false)
            .unwrap();

        let context = db.verify_api_key(&api_key).unwrap();

        assert_eq!(context.username, "testuser");
        assert_eq!(context.user_id, user.id);
    }

    #[test]
    fn test_verify_api_key_invalid() {
        let (db, _dirs) = create_test_db();

        let result = db.verify_api_key("invalid_key_12345");

        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_api_key_expiration() {
        let (db, _dirs) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Create key with 1 second TTL
        let (api_key, _) = db
            .create_api_key(user.id, Some("ttl1"), None, Some(1), false)
            .unwrap();

        // Should work immediately
        assert!(db.verify_api_key(&api_key).is_ok());

        // Wait for expiration
        
        std::thread::sleep(std::time::Duration::from_secs(2));

        loop {
            let result = db.verify_api_key(&api_key);

            if matches!(result, Err(DatabaseError::PermissionDenied(_))) {
                break;
            } else {
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
        }
    }

    #[test]
    fn test_api_key_ttl_uses_system_default_when_absent_or_zero() {
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut config = AuthConfig::default();
        config.enable = true;
        config.database_path = tmp_dir.path().to_path_buf();
        config.api_key.default_ttl_seconds = 100;
        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

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
        assert_eq!(info2.expires_at, None, "TTL=0 should create permanent key (never expires)");
    }

    #[test]
    fn test_api_key_ttl_capped_by_system_default_and_user_when_no_system() {
        // System TTL caps user-provided TTL
        let tmp_dir = tempfile::tempdir().unwrap();
        let mut config = AuthConfig::default();
        config.enable = true;
        config.database_path = tmp_dir.path().to_path_buf();
        config.api_key.default_ttl_seconds = 50;
        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

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
        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

        let user = db
            .create_user("testuser2", "TestPass123!", None, None, Some(false))
            .unwrap();

        let (_, info) = db
            .create_api_key(user.id, Some("capped2"), None, Some(30), false)
            .unwrap();
        assert_eq!(info.expires_at, Some(info.created_at + 30));
    }

    #[test]
    fn test_revoke_api_key() {
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
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_list_user_api_keys() {
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

    #[test]
    fn test_api_key_last_used_tracking() {
        let (db, _dirs) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        let (api_key, key_info) = db
            .create_api_key(user.id, Some("tracking"), None, None, false)
            .unwrap();

        assert!(key_info.last_used_at.is_none());

        // Use the key
        db.verify_api_key(&api_key).unwrap();

        // Check it was tracked
        let keys = db.list_user_api_keys(user.id, false).unwrap();
        let used_key = keys.iter().find(|k| k.id == key_info.id).unwrap();

        assert!(used_key.last_used_at.is_some());
    }

    #[test]
    fn test_apply_ttl_to_legacy_api_keys() {
        let (mut db, _dir) = create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        let (_, key_info) = db
            .create_api_key(user.id, Some("perm_effective"), None, None, false)
            .unwrap();

        // Verify no expiration was set
        let info = db.get_api_key_info(&key_info.id).unwrap();
        assert!(info.expires_at.is_none());

        // Enable TTL and run cleanup to backfill
        db.set_default_api_key_ttl(100);

        let _ = db.cleanup_expired_api_keys().unwrap();
        let info = db.get_api_key_info(&key_info.id).unwrap();

        assert_eq!(info.expires_at, Some(info.created_at + 100));
    }

    // =============================================================================
    // PERMISSION TESTS
    // =============================================================================

    #[test]
    fn test_set_role_permission() {
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

    #[test]
    fn test_set_user_permission_override() {
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

    #[test]
    fn test_user_effective_permissions() {
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

    #[test]
    fn test_user_override_denies_role_permission() {
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

    #[test]
    fn test_rate_limit_within_limit() {
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

    #[test]
    fn test_rate_limit_exceeded() {
        let rate_limit = RateLimitConfig {
            enable: true,
            window_seconds: 60,
            max_requests: 100,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
        };

        let (db, _dirs) = create_test_db_with_rate_limit(rate_limit);

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

    #[test]
    fn test_rate_limit_by_ip_only() {
        let rate_limit = RateLimitConfig {
            enable: true,
            window_seconds: 60,
            max_requests: 2,
            limit_by_key: false,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
        };

        let (db, _dirs) = create_test_db_with_rate_limit(rate_limit);

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

    #[test]
    fn test_rate_limit_by_key_only() {
        let rate_limit = RateLimitConfig {
            enable: true,
            window_seconds: 60,
            max_requests: 1,
            limit_by_key: true,
            limit_by_ip: false,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
        };

        let (db, _dirs) = create_test_db_with_rate_limit(rate_limit);

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

    #[test]
    fn test_rate_limit_by_both_key_and_ip() {
        let rate_limit = RateLimitConfig {
            enable: true,
            window_seconds: 60,
            max_requests: 2,
            limit_by_key: true,
            limit_by_ip: true,
            cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
        };

        let (db, _dirs) = create_test_db_with_rate_limit(rate_limit);

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
            db.check_rate_limit(Some(&key1.id), Some("10.0.0.1"), Some("/api/test"))
                .is_ok(),
            "First request from key1@10.0.0.1 should pass"
        );
        assert!(
            db.check_rate_limit(Some(&key1.id), Some("10.0.0.1"), Some("/api/test"))
                .is_ok(),
            "Second request from key1@10.0.0.1 should pass"
        );
        assert!(
            db.check_rate_limit(Some(&key1.id), Some("10.0.0.1"), Some("/api/test"))
                .is_err(),
            "Third request from key1@10.0.0.1 should exceed limit"
        );

        // Same key from different IP should work (independent counter)
        assert!(
            db.check_rate_limit(Some(&key1.id), Some("10.0.0.2"), Some("/api/test"))
                .is_ok(),
            "First request from key1@10.0.0.2 should pass (different IP)"
        );
        assert!(
            db.check_rate_limit(Some(&key1.id), Some("10.0.0.2"), Some("/api/test"))
                .is_ok(),
            "Second request from key1@10.0.0.2 should pass"
        );

        // Scenario 2: Different keys, same IP - each key should have independent limit
        assert!(
            db.check_rate_limit(Some(&key2.id), Some("192.168.1.1"), Some("/api/test"))
                .is_ok(),
            "First request from key2@192.168.1.1 should pass"
        );
        assert!(
            db.check_rate_limit(Some(&key2.id), Some("192.168.1.1"), Some("/api/test"))
                .is_ok(),
            "Second request from key2@192.168.1.1 should pass"
        );
        assert!(
            db.check_rate_limit(Some(&key2.id), Some("192.168.1.1"), Some("/api/test"))
                .is_err(),
            "Third request from key2@192.168.1.1 should exceed limit"
        );

        // Different key from same IP should work (independent counter)
        assert!(
            db.check_rate_limit(Some(&key1.id), Some("192.168.1.1"), Some("/api/test"))
                .is_ok(),
            "First request from key1@192.168.1.1 should pass (different key)"
        );

        // Scenario 3: Verify that limit is per (key, IP) combination
        // key1 from 10.0.0.2 already has 2 requests, should fail on 3rd
        assert!(
            db.check_rate_limit(Some(&key1.id), Some("10.0.0.2"), Some("/api/test"))
                .is_err(),
            "Third request from key1@10.0.0.2 should exceed limit"
        );
    }

    // =============================================================================
    // AUDIT LOG TESTS
    // =============================================================================

    #[test]
    fn test_audit_logging_disabled() {
        let session = SessionConfig {
            audit_enable: false,
            audit_retention_days: 90,
            log_all_requests: true,
        };

        let dir =
            tempfile::tempdir().expect("Can not create temporal directory.");
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
            sensitive_endpoints: vec![],
            },
            session,
        };

        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

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
        };

        let logs = db.query_audit_logs(&query).unwrap();
        assert!(logs.is_empty());
    }

    #[test]
    fn test_log_api_request_enabled() {
        let mut config = AuthConfig::default();

        let dir =
            tempfile::tempdir().expect("Can not create temporal directory.");
        let path = dir.path().to_path_buf();

        config.enable = true;
        config.session.audit_enable = true;
        config.session.log_all_requests = true;
        config.database_path = path;

        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

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
        };

        let logs = db.query_audit_logs(&query).unwrap();
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].endpoint.as_deref(), Some("/api/test"));
        assert_eq!(logs[0].http_method.as_deref(), Some("GET"));
    }

    #[test]
    fn test_log_api_request_disabled() {
        let mut config = AuthConfig::default();

        let dir =
            tempfile::tempdir().expect("Can not create temporal directory.");
        let path = dir.path().to_path_buf();

        config.enable = true;
        config.session.audit_enable = true;
        config.session.log_all_requests = false;
        config.database_path = path;

        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

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
        assert_eq!(log_id, 0);

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
        };

        let logs = db.query_audit_logs(&query).unwrap();
        assert!(logs.is_empty());
    }

    // =============================================================================
    // SYSTEM CONFIG TESTS
    // =============================================================================

    #[test]
    fn test_list_system_config() {
        let (db, _dirs) = create_test_db();

        let config = db.list_system_config().unwrap();

        // Should have at least read_only config
        assert!(!config.is_empty());
    }

    #[test]
    fn test_update_system_config() {
        let (db, _dirs) = create_test_db();

        let result = db.update_system_config("read_only_mode", "1", None);

        assert!(result.is_err());
    }

    /// Test endpoint-specific rate limiting with sensitive endpoints
    #[test]
    fn test_endpoint_specific_rate_limiting() {
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

        let (db, _dirs) = create_test_db_with_rate_limit(rate_limit);

        // Test 1: Regular endpoint should allow 100 requests
        for i in 1..=100 {
            assert!(
                db.check_rate_limit(None, Some("1.2.3.4"), Some("/api/regular"))
                    .is_ok(),
                "Regular endpoint request {} should pass", i
            );
        }

        // 101st request should fail
        let result = db.check_rate_limit(None, Some("1.2.3.4"), Some("/api/regular"));
        assert!(
            matches!(result, Err(DatabaseError::RateLimitExceeded(_))),
            "Regular endpoint should be rate limited at 100 requests"
        );

        // Test 2: /login endpoint should only allow 5 requests
        for i in 1..=5 {
            assert!(
                db.check_rate_limit(None, Some("2.3.4.5"), Some("/login"))
                    .is_ok(),
                "/login request {} should pass", i
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
                db.check_rate_limit(None, Some("3.4.5.6"), Some("/change-password"))
                    .is_ok(),
                "/change-password request {} should pass", i
            );
        }

        // 4th request should fail
        let result = db.check_rate_limit(None, Some("3.4.5.6"), Some("/change-password"));
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
}
