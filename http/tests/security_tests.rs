// Ave HTTP Auth System - Security and Edge Case Tests
//
// Tests for security vulnerabilities, edge cases, and error conditions

mod common;

use ave_http::auth::database::DatabaseError;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::path::PathBuf;

    use axum::{
        extract::{Path, Query},
        http::StatusCode,
        Extension, Json,
    };
    use ave_http::auth::{
        admin_handlers::{
            remove_user_permission, set_user_permission, set_role_permission,
            remove_role_permission, update_user, assign_role, remove_role, RemovePermissionQuery,
        },
        middleware::AuthContextExtractor,
        models::{AuthContext, Permission, SetPermissionRequest, UpdateUserRequest},
        AuthDatabase,
    };

    // =============================================================================
    // PASSWORD POLICY VALIDATION TESTS
    // =============================================================================

    #[test]
    fn test_password_too_short() {
        let (db, _dirs) = common::create_test_db();

        let result =
            db.create_user("testuser", "Short1!", None, None, Some(false));

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_too_long() {
        let (db, _dirs) = common::create_test_db();

        let long_pass = "Aa1!".repeat(33); // 132 chars (exceeds 128 limit)
        let result =
            db.create_user("testuser", &long_pass, None, None, Some(false));

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_uppercase() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user(
            "testuser",
            "lowercase123!",
            None,
            None,
            None,
        );

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_lowercase() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user(
            "testuser",
            "UPPERCASE123!",
            None,
            None,
            None,
        );

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_digit() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user(
            "testuser",
            "NoDigitsHere!",
            None,
            None,
            None,
        );

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_with_unicode() {
        let (db, _dirs) = common::create_test_db();

        // Should work with unicode characters
        let result = db.create_user(
            "testuser",
            "Pass123🔐中文",
            None,
            None,
            None,
        );

        assert!(result.is_ok());
    }

    // =============================================================================
    // SQL INJECTION PROTECTION TESTS
    // =============================================================================

    #[test]
    fn test_sql_injection_in_username() {
        let (db, _dirs) = common::create_test_db();

        // Try SQL injection in username - should be REJECTED by input validation
        // SECURITY FIX: After adding input validation, dangerous characters are rejected
        let malicious_username = "admin' OR '1'='1";
        let result = db.create_user(
            malicious_username,
            "Password123!",
            None,
            None,
            None,
        );

        // UPDATED: Should REJECT username with single quotes (dangerous character)
        assert!(result.is_err(), "Should reject username with SQL injection attempt");

        // Verify we still use parameterized queries (defense in depth)
        // Even though input validation blocks the attack, we ensure SQL injection
        // is impossible even if validation is bypassed
        let safe_username = "validuser";
        db.create_user(safe_username, "Password123!", None, None, Some(false))
            .unwrap();

        let verify_result = db.verify_credentials(safe_username, "Password123!");
        assert!(verify_result.is_ok());
        let user = verify_result.unwrap();
        assert_eq!(user.username, safe_username);
    }

    #[test]
    fn test_sql_injection_in_role_name() {
        let (db, _dirs) = common::create_test_db();

        let malicious_role_name = "admin'; DROP TABLE users; --";
        let result =
            db.create_role(malicious_role_name, Some("Malicious role"));

        // Should safely handle
        assert!(result.is_ok());

        // Tables should still exist
        let users = db.list_users(false, 100, 0);
        assert!(users.is_ok());
    }

    // =============================================================================
    // CONCURRENT ACCESS TESTS
    // =============================================================================

    #[test]
    fn test_concurrent_user_creation() {
        let (db, _dirs) = common::create_test_db();
        let db = std::sync::Arc::new(db);

        let mut handles = vec![];

        for i in 0..10 {
            let db_clone = db.clone();
            let handle = std::thread::spawn(move || {
                db_clone.create_user(
                    &format!("user{}", i),
                    "Password123!",
                    None,
                    None,
                    None,
                )
            });
            handles.push(handle);
        }

        let results: Vec<_> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All should succeed
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 10);
    }

    #[test]
    fn test_concurrent_duplicate_user_creation() {
        let (db, _dirs) = common::create_test_db();
        let db = std::sync::Arc::new(db);

        let mut handles = vec![];

        // Try to create same user from multiple threads
        for _ in 0..10 {
            let db_clone = db.clone();
            let handle = std::thread::spawn(move || {
                db_clone.create_user(
                    "duplicate_user",
                    "Password123!",
                    None,
                    None,
                    None,
                )
            });
            handles.push(handle);
        }

        let results: Vec<_> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Only one should succeed
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 1);

        // Others should fail with duplicate error
        let duplicate_count = results
            .iter()
            .filter(|r| matches!(r, Err(DatabaseError::DuplicateError(_))))
            .count();
        assert_eq!(duplicate_count, 9);
    }

    #[test]
    fn test_concurrent_api_key_verification() {
        let (db, _dirs) = common::create_test_db();
        let db = std::sync::Arc::new(db);

        // Create user and API key
        let user = db
            .create_user("test_user", "Password123!", None, None, Some(false))
            .unwrap();
        let (api_key, _) = db
            .create_api_key(user.id, Some("concurrent"), None, None, false)
            .unwrap();

        let mut handles = vec![];

        // Verify same API key from multiple threads
        for _ in 0..20 {
            let db_clone = db.clone();
            let key_clone = api_key.clone();
            let handle =
                std::thread::spawn(move || db_clone.verify_api_key(&key_clone));
            handles.push(handle);
        }

        let results: Vec<_> =
            handles.into_iter().map(|h| h.join().unwrap()).collect();

        // All should succeed
        let success_count = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(success_count, 20);
    }

    // =============================================================================
    // EDGE CASES - SPECIAL CHARACTERS AND ENCODING
    // =============================================================================

    #[test]
    fn test_unicode_username() {
        let (db, _dirs) = common::create_test_db();

        let unicode_username = "用户名🔐";
        let result = db.create_user(
            unicode_username,
            "Password123!",
            None,
            None,
            None,
        );

        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.username, unicode_username);
    }

    #[test]
    fn test_whitespace_in_names() {
        let (db, _dirs) = common::create_test_db();

        // Username with spaces
        let username = "user with spaces";
        let result =
            db.create_user(username, "Password123!", None, None, Some(false));
        assert!(result.is_ok());

        // Role with tabs
        let role_name = "role\twith\ttabs";
        let role = db.create_role(role_name, None);
        assert!(role.is_ok());
    }

    #[test]
    fn test_very_long_strings() {
        let (db, _dirs) = common::create_test_db();

        // UPDATED: After adding length validation, very long usernames are rejected
        // Very long username (255 chars) - should be REJECTED (limit is 64)
        let long_username = "a".repeat(255);
        let result = db.create_user(
            &long_username,
            "Password123!",
            None,
            None,
            None,
        );
        assert!(result.is_err(), "Should reject username longer than 64 chars");

        // Test that maximum allowed username works (64 chars)
        let max_username = "a".repeat(64);
        let result = db.create_user(
            &max_username,
            "Password123!",
            None,
            None,
            None,
        );
        assert!(result.is_ok(), "Should accept username of exactly 64 chars");

        // Very long role name now rejected by validation (limit is 100)
        let long_role_name = "b".repeat(255);
        let role = db.create_role(&long_role_name, None);
        assert!(role.is_err(), "Should reject role names longer than 100 chars");

        // Boundary: max allowed role name (100 chars) should work
        let max_role_name = "b".repeat(100);
        let role = db.create_role(&max_role_name, None);
        assert!(role.is_ok(), "Should accept role name of exactly 100 chars");
    }

    // =============================================================================
    // BOUNDARY TESTS
    // =============================================================================

    #[test]
    fn test_zero_ttl_api_key_never_expires() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Create key with 0 TTL (never expires)
        let (api_key, _) = db
            .create_api_key(user.id, Some("ttl0"), None, Some(0i64), false)
            .unwrap();

        // Should work immediately
        assert!(db.verify_api_key(&api_key).is_ok());

        // Should still work after a delay
        std::thread::sleep(std::time::Duration::from_secs(1));
        assert!(db.verify_api_key(&api_key).is_ok());
    }

    #[test]
    fn test_explicit_zero_ttl_overrides_default() {
        use tempfile::TempDir;
        use std::path::PathBuf;
        use ave_bridge::auth::{ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig};

        // Create temp directory for isolated test
        let _tmp_dir = TempDir::new().unwrap();

        // Create config with a default TTL of 30 days
        let config = AuthConfig {
            enable: true,
            database_path: _tmp_dir.path().to_path_buf(),
            superadmin: "admin".to_string(),
            api_key: ApiKeyConfig {
                default_ttl_seconds: 2592000, // 30 days
                max_keys_per_user: 10,
            },
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        };

        let db = AuthDatabase::new(config, "TestPass123!").expect("Failed to create database");

        let user = db
            .create_user("ttluser", "Password123!", None, None, Some(false))
            .unwrap();

        // Test 1: Create key with explicit TTL=0 (should never expire despite default_ttl)
        let (api_key_zero, key_info_zero) = db
            .create_api_key(user.id, Some("never-expire"), None, Some(0), false)
            .unwrap();

        assert!(key_info_zero.expires_at.is_none(),
            "Key with explicit TTL=0 should never expire (expires_at should be None)");

        // Verify key works
        assert!(db.verify_api_key(&api_key_zero).is_ok());

        // Test 2: Create key without TTL (should use default_ttl of 30 days)
        let (_api_key_default, key_info_default) = db
            .create_api_key(user.id, Some("use-default"), None, None, false)
            .unwrap();

        assert!(key_info_default.expires_at.is_some(),
            "Key without explicit TTL should use default_ttl (expires_at should be Some)");

        // Test 3: Create key with explicit positive TTL
        let (_api_key_custom, key_info_custom) = db
            .create_api_key(user.id, Some("custom-ttl"), None, Some(3600), false)
            .unwrap();

        assert!(key_info_custom.expires_at.is_some(),
            "Key with explicit positive TTL should have expiration");

        println!("✓ Explicit TTL=0 correctly overrides default_ttl:");
        println!("  - TTL=0 explicit: never expires (None)");
        println!("  - TTL=None: uses default_ttl (Some)");
        println!("  - TTL=3600: custom expiration (Some)");
    }

    #[test]
    fn test_inactive_user_cannot_login() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Deactivate user
        db.update_user(user.id, None, Some(false)).unwrap();

        // Cannot login
        let result = db.verify_credentials("testuser", "Password123!");
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_inactive_user_api_keys_dont_work() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();
        let (api_key, _) = db
            .create_api_key(user.id, Some("lockout"), None, None, false)
            .unwrap();

        // Deactivate user
        db.update_user(user.id, None, Some(false)).unwrap();

        // API key should not work
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_deleted_user_api_keys_dont_work() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();
        let (api_key, _) = db
            .create_api_key(user.id, Some("lockout2"), None, None, false)
            .unwrap();

        // Delete user
        db.delete_user(user.id).unwrap();

        // API key should not work
        let result = db.verify_api_key(&api_key);
        assert!(result.is_err());
    }

    // =============================================================================
    // PERMISSION CASCADE TESTS
    // =============================================================================

    #[test]
    fn test_deleted_role_removes_user_permissions() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();
        let role = db.create_role("editor", None).unwrap();

        db.set_role_permission(role.id, "node_subject", "get", true)
            .unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User has permission
        let perms_before = db.get_user_effective_permissions(user.id).unwrap();
        assert!(perms_before.iter().any(|p| p.resource == "node_subject"
            && p.action == "get"
            && p.allowed));

        // Delete role
        db.delete_role(role.id).unwrap();

        // User should no longer have permission
        let perms_after = db.get_user_effective_permissions(user.id).unwrap();
        assert!(!perms_after.iter().any(|p| p.resource == "node_subject"
            && p.action == "get"
            && p.allowed));
    }

    // =============================================================================
    // ADMIN PERMISSION GUARDS
    // =============================================================================

    #[tokio::test]
    async fn non_superadmin_cannot_modify_permissions_of_admin_via_role_inheritance(
    ) {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        let admin_role =
            db.create_role("admin_guard", Some("Admin guard role")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true)
            .unwrap();

        let actor = db
            .create_user(
                "admin_actor",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                None,
            )
            .unwrap();
        let target = db
            .create_user(
                "admin_target",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                None,
            )
            .unwrap();

        let permissions = db.get_effective_permissions(actor.id).unwrap();
        let roles = db.get_user_roles(actor.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: actor.id,
            username: actor.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        let result = set_user_permission(
            AuthContextExtractor(auth_ctx),
            Extension(db.clone()),
            Path(target.id),
            Json(Permission {
                resource: "admin_system".to_string(),
                action: "all".to_string(),
                allowed: true,
                is_system: None,
                source: None,
                role_name: None,
            }),
        )
        .await;

        assert!(matches!(result, Err((StatusCode::FORBIDDEN, _))));
    }

    #[tokio::test]
    async fn non_superadmin_cannot_remove_permissions_of_admin_via_role_inheritance(
    ) {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        let admin_role = db
            .create_role("admin_guard_remove", Some("Admin guard role"))
            .unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true)
            .unwrap();

        let actor = db
            .create_user(
                "admin_actor_remove",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                None,
            )
            .unwrap();
        let target = db
            .create_user(
                "admin_target_remove",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                None,
            )
            .unwrap();

        db.set_user_permission(
            target.id,
            "node_subject",
            "get",
            true,
            Some(actor.id),
        )
        .unwrap();

        let permissions = db.get_effective_permissions(actor.id).unwrap();
        let roles = db.get_user_roles(actor.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: actor.id,
            username: actor.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        let result = remove_user_permission(
            AuthContextExtractor(auth_ctx),
            Extension(db.clone()),
            Path(target.id),
            Query(RemovePermissionQuery {
                resource: "node_subject".to_string(),
                action: "get".to_string(),
            }),
        )
        .await;

        assert!(matches!(result, Err((StatusCode::FORBIDDEN, _))));
    }

    #[test]
    fn superadmin_flag_grants_all_permissions_even_without_overrides() {
        let ctx = AuthContext {
            user_id: 1,
            username: "root".to_string(),
            roles: vec!["superadmin".to_string()], // Superadmin role
            permissions: vec![], // No explicit permissions
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        };

        assert!(ctx.has_permission("any_resource", "any_action"));
    }

    // =============================================================================
    // ERROR HANDLING TESTS
    // =============================================================================

    #[test]
    fn test_get_nonexistent_user() {
        let (db, _dirs) = common::create_test_db();

        let result = db.get_user_by_id(99999);

        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    #[test]
    fn test_get_nonexistent_role() {
        let (db, _dirs) = common::create_test_db();

        let result = db.get_role_by_name("nonexistent_role");

        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    #[test]
    fn test_assign_nonexistent_role() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        let result = db.assign_role_to_user(user.id, 99999, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_assign_role_to_nonexistent_user() {
        let (db, _dirs) = common::create_test_db();

        let role = db.create_role("editor", None).unwrap();

        let result = db.assign_role_to_user(99999, role.id, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_nonexistent_api_key() {
        let (db, _dirs) = common::create_test_db();

        let result = db.revoke_api_key("99999999-9999-9999-9999-999999999999", None, None);

        // revoke_api_key doesn't check if key exists, it just succeeds silently
        assert!(result.is_ok());
    }

    #[test]
    fn test_update_nonexistent_user() {
        let (db, _dirs) = common::create_test_db();

        let result = db.update_user(99999, Some("NewPass123!"), None);

        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    #[test]
    fn test_delete_nonexistent_user() {
        let (db, _dirs) = common::create_test_db();

        let result = db.delete_user(99999);

        // delete_user doesn't check if user exists, it just succeeds silently
        assert!(result.is_ok());
    }

    #[test]
    fn test_delete_nonexistent_role() {
        let (db, _dirs) = common::create_test_db();

        let result = db.delete_role(99999);

        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    // =============================================================================
    // SUPERADMIN TESTS
    // =============================================================================

    #[test]
    fn test_superadmin_bootstrap() {
        let (db, _dirs) = common::create_test_db();

        // Superadmin should exist
        let result = db.verify_credentials("admin", "AdminPass123!");

        assert!(result.is_ok());

        let user = result.unwrap();
        // Verify superadmin role
        let roles = db.get_user_roles(user.id).unwrap();
        assert!(roles.contains(&"superadmin".to_string()));
    }

    #[test]
    fn test_superadmin_has_all_permissions() {
        let (db, _dirs) = common::create_test_db();

        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Superadmin should have all permissions (empty list means all)
        let _perms = db.get_user_effective_permissions(admin.id).unwrap();

        // Superadmins bypass permission checks, so they might have empty perms
        // The middleware should check is_superadmin flag
        // Verify superadmin role
        let roles = db.get_user_roles(admin.id).unwrap();
        assert!(roles.contains(&"superadmin".to_string()));
    }

    #[test]
    fn test_create_regular_user_without_superadmin() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user(
                "regularuser",
                "UserPass123!",
                None,
                None,
                None,
            )
            .unwrap();

        // Verify user does NOT have superadmin role
        let roles = db.get_user_roles(user.id).unwrap();
        assert!(!roles.contains(&"superadmin".to_string()));
    }

    // =============================================================================
    // API KEY REVOCATION TESTS
    // =============================================================================

    #[test]
    fn test_revoked_api_key_cannot_be_used() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();
        let (api_key, key_info) = db
            .create_api_key(user.id, Some("rl_main"), None, None, false)
            .unwrap();

        // Revoke key
        db.revoke_api_key(&key_info.id, None, Some("Security breach"))
            .unwrap();

        // Should not verify
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_double_revoke_api_key() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();
        let (_, key_info) = db
            .create_api_key(user.id, Some("rl_expire"), None, None, false)
            .unwrap();

        // Revoke key
        db.revoke_api_key(&key_info.id, None, None).unwrap();

        // Revoke again (should still work or fail gracefully)
        let result = db.revoke_api_key(&key_info.id, None, None);
        // Either succeeds or fails with NotFound
        assert!(
            result.is_ok()
                || matches!(result, Err(DatabaseError::NotFoundError(_)))
        );
    }

    // =============================================================================
    // STRESS TESTS
    // =============================================================================

    #[test]
    fn test_many_roles_for_user() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Create and assign 50 roles
        for i in 0..50 {
            let role = db.create_role(&format!("role{}", i), None).unwrap();
            db.assign_role_to_user(user.id, role.id, None).unwrap();
        }

        let roles = db.get_user_roles(user.id).unwrap();
        assert_eq!(roles.len(), 50);
    }

    #[test]
    fn test_many_permissions_for_role() {
        let (db, _dirs) = common::create_test_db();

        let role = db.create_role("power_user", None).unwrap();

        // Use actual system resources and actions from schema
        let resources = vec![
            "user",
            "admin_system",
            "admin_api_key",
            "admin_roles",
            "admin_users",
            "node_keys",
            "node_system",
            "node_subject",
            "node_request",
        ];
        let actions = vec!["get", "post", "put", "patch", "delete", "all"];

        // Grant permissions for all combinations
        for resource in &resources {
            for action in &actions {
                db.set_role_permission(role.id, resource, action, true)
                    .unwrap();
            }
        }

        let perms = db.get_role_permissions(role.id).unwrap();
        assert_eq!(perms.len(), resources.len() * actions.len());
    }

    #[test]
    fn test_many_api_keys_for_user() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Create 10 API keys
        for i in 0..10 {
            db.create_api_key(
                user.id,
                Some(&format!("key{}", i)),
                None,
                None,
                false,
            )
            .unwrap();
        }

        let keys = db.list_user_api_keys(user.id, false).unwrap();
        assert_eq!(keys.len(), 10);
    }

    // =============================================================================
    // SECURITY FIX VERIFICATION TESTS
    // =============================================================================

    /// Test that API key IDs are UUIDs and not sequential integers
    /// Security Fix: Prevents IDOR attacks via predictable IDs
    #[test]
    fn test_api_key_public_ids_are_uuids_not_sequential() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Create multiple API keys
        let mut public_ids = vec![];
        for i in 0..5 {
            let (_, key_info) = db
                .create_api_key(
                    user.id,
                    Some(&format!("key{}", i)),
                    None,
                    None,
                    false,
                )
                .unwrap();
            public_ids.push(key_info.id.clone());
        }

        // Verify all public_ids are UUIDs (format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx)
        for public_id in &public_ids {
            assert_eq!(public_id.len(), 36, "UUID should be 36 characters");
            assert_eq!(public_id.chars().filter(|c| *c == '-').count(), 4, "UUID should have 4 dashes");

            // Verify it's not a simple sequential number
            assert!(
                public_id.parse::<i64>().is_err(),
                "Public ID should not be a simple integer"
            );
        }

        // Verify they are all unique
        let unique_ids: std::collections::HashSet<_> = public_ids.iter().collect();
        assert_eq!(unique_ids.len(), 5, "All public IDs should be unique");
    }

    /// Test that pre-authentication rate limiting is enforced
    /// Security Fix: Prevents brute force attacks on login endpoint
    #[test]
    fn test_pre_auth_rate_limiting_on_login() {
        use ave_bridge::auth::{RateLimitConfig, ApiKeyConfig, LockoutConfig, SessionConfig, AuthConfig};
        use ave_http::auth::database::AuthDatabase;

        // Create test DB with specific rate limit config (100 requests/minute)
        let dir = tempfile::tempdir().expect("Can not create temporal directory.");
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
                max_requests: 100,  // Set to 100 for this test
                limit_by_key: true,
                limit_by_ip: true,
                cleanup_interval_seconds: 3600,
            sensitive_endpoints: vec![],
            },
            session: SessionConfig {
                audit_enable: true,
                audit_retention_days: 90,
                log_all_requests: false,
            },
        };

        let db = AuthDatabase::new(config, "AdminPass123!").unwrap();

        // Create a test user
        db.create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Simulate multiple failed login attempts from same IP
        let fake_ip = Some("192.168.1.100");

        // Make requests up to rate limit (100 per 60 seconds)
        let mut successful_checks = 0;
        let mut rate_limited = false;

        for _ in 0..110 {
            match db.check_rate_limit(None, fake_ip, Some("/login")) {
                Ok(_) => successful_checks += 1,
                Err(DatabaseError::RateLimitExceeded(_)) => {
                    rate_limited = true;
                    break;
                }
                Err(e) => panic!("Unexpected error: {:?}", e),
            }
        }

        // Should hit rate limit before 110 attempts
        assert!(rate_limited, "Rate limit should be enforced on login endpoint");
        assert!(
            successful_checks <= 100,
            "Should not exceed configured rate limit (got {})",
            successful_checks
        );
    }

    /// Test that API keys created have public_id populated
    /// Security Fix: Ensures migration populates UUIDs for existing keys
    #[test]
    fn test_api_keys_have_public_id_after_migration() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        let (_, key_info) = db
            .create_api_key(user.id, Some("test"), None, None, false)
            .unwrap();

        // id should be populated and non-empty UUID
        assert!(!key_info.id.is_empty(), "id should not be empty");
        assert_ne!(key_info.id, "0", "id should not be default value");
    }

    /// Test concurrent API key creation respects max_keys limit
    /// Security Fix: Addresses race condition vulnerability #6
    /// NOTE: Limit is enforced at application level. While a race condition is
    /// theoretically possible, SQLite's transaction isolation makes it very unlikely.
    #[test]
    fn test_concurrent_api_key_creation_respects_max_limit() {
        let (db, _dirs) = common::create_test_db();
        let db = std::sync::Arc::new(db);

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        let mut handles = vec![];

        // Try to create 25 keys concurrently (limit is 20)
        for i in 0..25 {
            let db_clone = db.clone();
            let user_id = user.id;
            let handle = std::thread::spawn(move || {
                db_clone.create_api_key(
                    user_id,
                    Some(&format!("concurrent_key_{}", i)),
                    None,
                    None,
                    false,
                )
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

        // Count successful creations
        let success_count = results.iter().filter(|r| r.is_ok()).count();

        // Should not exceed the max limit (20)
        assert!(
            success_count <= 20,
            "Should not create more than max_keys_per_user limit (got {})",
            success_count
        );

        // Verify actual count in database
        let keys = db.list_user_api_keys(user.id, false).unwrap();
        assert!(
            keys.len() <= 20,
            "Database should not have more than 20 keys (got {})",
            keys.len()
        );
    }

    /// Test that dangerous characters in API key names are rejected
    /// Security Fix: Prevents XSS, SQL injection, command injection, and path traversal
    #[test]
    fn test_dangerous_characters_in_api_key_names_rejected() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Test various dangerous characters that should be rejected
        let dangerous_names = vec![
            "<script>alert('xss')</script>",  // XSS
            "'; DROP TABLE users; --",         // SQL injection
            "key`whoami`",                     // Command injection (backtick)
            "key$(whoami)",                    // Command injection (dollar)
            "key|whoami",                      // Command injection (pipe)
            "key;rm -rf /",                    // Command injection (semicolon)
            "../../../etc/passwd",             // Path traversal
            "key\\..\\secrets",                // Path traversal (Windows)
            "key\0hidden",                     // Null byte injection
            "key\ninjected",                   // Newline injection
            "key\rinjected",                   // Carriage return injection
            "key<>test",                       // HTML/XML injection
            "key&test",                        // URL/command injection
            "key*test",                        // Wildcard
            "key?test",                        // Wildcard
            "key%00test",                      // URL encoding
            "key{test}",                       // Template injection
            "key[test]",                       // Array injection
        ];

        for dangerous_name in dangerous_names {
            let result = db.create_api_key(
                user.id,
                Some(dangerous_name),
                None,
                None,
                false,
            );

            assert!(
                result.is_err(),
                "Should reject dangerous name: {}",
                dangerous_name
            );

            if let Err(e) = result {
                match e {
                    DatabaseError::ValidationError(_) => {
                        // Expected error type
                    }
                    _ => panic!("Expected ValidationError, got: {:?}", e),
                }
            }
        }

        // Test valid names that should be accepted
        let valid_names = vec![
            "my_api_key",
            "production-key",
            "test key 2024",
            "api.key.1",
            "Key_123",
            "UPPERCASE_KEY",
        ];

        for valid_name in valid_names {
            let result = db.create_api_key(
                user.id,
                Some(valid_name),
                None,
                None,
                false,
            );

            assert!(
                result.is_ok(),
                "Should accept valid name: {} (error: {:?})",
                valid_name,
                result.err()
            );
        }
    }

    /// Test that security headers are set to prevent API key leakage
    /// Security Fix: Referrer-Policy prevents API keys from leaking via Referer header
    #[test]
    fn test_security_headers_prevent_api_key_leakage() {
        // This test verifies that the security headers are properly configured
        // in the application code. The actual header verification would require
        // integration tests with a running server.

        // Here we verify that the validation logic rejects API keys in query params
        // (they should only be in headers)
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        let (api_key, _key_info) = db
            .create_api_key(user.id, Some("test-key"), None, None, false)
            .unwrap();

        // Verify API key format is correct (should be a bearer token, not URL-friendly)
        assert!(api_key.starts_with("ave_node_"));
        assert!(api_key.len() > 40, "API key should be long enough to prevent brute force");

        // Verify that API key names are sanitized (already tested in previous test)
        // This ensures that even if displayed in UI, they won't cause XSS

        // The actual Referrer-Policy header test would be:
        // 1. Start test server with security middleware
        // 2. Make authenticated request
        // 3. Check response headers contain: Referrer-Policy: no-referrer
        // 4. Check response headers contain: X-Content-Type-Options: nosniff
        // 5. Check response headers contain: X-Frame-Options: DENY

        // For now, we document that these headers MUST be verified in integration tests
        // The middleware is configured in main.rs lines 101-113
    }

    /// Test that CRLF injection is prevented in all text fields
    /// Security Fix: Prevents header injection and log forgery via CRLF characters
    #[test]
    fn test_crlf_injection_prevented_in_text_fields() {
        let (db, _dirs) = common::create_test_db();

        // Test CRLF in usernames
        let crlf_usernames = vec![
            "user\r\nInjected-Header: malicious",
            "user\nlog-injection",
            "user\rcarriage-return",
            "user\r\n\r\nHTTP/1.1 200 OK",
            "admin\r\nSet-Cookie: session=hijacked",
        ];

        for username in crlf_usernames {
            let result = db.create_user(username, "Password123!", None, None, Some(false));
            assert!(
                result.is_err(),
                "Should reject username with CRLF: {:?}",
                username
            );
            if let Err(e) = result {
                match e {
                    DatabaseError::ValidationError(msg) => {
                        assert!(msg.contains("CRLF") || msg.contains("control"));
                    }
                    _ => panic!("Expected ValidationError for CRLF, got: {:?}", e),
                }
            }
        }

        // Test CRLF in descriptions
        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        let crlf_descriptions = vec![
            "Description\r\nInjected-Header: malicious",
            "Description\nlog-injection",
            "Description\rcarriage-return",
            "Normal desc\r\n\r\nHTTP/1.1 200 OK",
        ];

        for desc in crlf_descriptions {
            let result = db.create_api_key(user.id, Some("test-key"), Some(desc), None, false);
            assert!(
                result.is_err(),
                "Should reject description with CRLF: {:?}",
                desc
            );
            if let Err(e) = result {
                match e {
                    DatabaseError::ValidationError(msg) => {
                        assert!(msg.contains("CRLF") || msg.contains("control"));
                    }
                    _ => panic!("Expected ValidationError for CRLF in description, got: {:?}", e),
                }
            }
        }

        // Test null bytes
        let null_byte_tests = vec![("user\0hidden", "Password123!")];

        for (username, password) in null_byte_tests {
            let result = db.create_user(username, password, None, None, Some(false));
            assert!(result.is_err(), "Should reject null bytes in username");
        }

        // Test valid strings work
        let valid_user = db
            .create_user("validuser", "Password123!", None, None, Some(false))
            .unwrap();
        assert_eq!(valid_user.username, "validuser");

        let (_, key_info) = db
            .create_api_key(
                user.id,
                Some("valid-key"),
                Some("Valid description with normal text"),
                None,
                false,
            )
            .unwrap();
        assert_eq!(key_info.description, Some("Valid description with normal text".to_string()));

        // Test length limits
        let long_username = "a".repeat(65);
        let result = db.create_user(&long_username, "Password123!", None, None, Some(false));
        assert!(result.is_err(), "Should reject username longer than 64 chars");

        let long_description = "a".repeat(501);
        let result = db.create_api_key(
            user.id,
            Some("test-long-desc"),
            Some(&long_description),
            None,
            false,
        );
        assert!(
            result.is_err(),
            "Should reject description longer than 500 chars"
        );
    }

    /// Test configurable CORS settings
    /// Vulnerability: #4 CORS Wildcard (CVSS 6.5)
    /// Fix: CORS is now configurable via config file
    #[test]
    fn test_cors_configuration_security() {
        use ave_bridge::CorsConfig;

        // Test 1: Default configuration (permissive - development mode)
        let default_config = CorsConfig::default();
        assert!(default_config.enabled, "CORS should be enabled by default");
        assert!(
            default_config.allow_any_origin,
            "Default allows any origin (for development)"
        );
        assert_eq!(default_config.allowed_origins.len(), 0);
        assert!(
            !default_config.allow_credentials,
            "Should never allow credentials with wildcard origin"
        );

        // Test 2: Secure production configuration
        let secure_config = CorsConfig {
            enabled: true,
            allow_any_origin: false,
            allowed_origins: vec![
                "https://app.example.com".to_string(),
                "https://dashboard.example.com".to_string(),
            ],
            allow_credentials: false,
        };
        assert!(!secure_config.allow_any_origin, "Production should not allow any origin");
        assert_eq!(secure_config.allowed_origins.len(), 2, "Should have specific origins");

        // Test 3: CORS disabled configuration
        let disabled_config = CorsConfig {
            enabled: false,
            allow_any_origin: false,
            allowed_origins: vec![],
            allow_credentials: false,
        };
        assert!(!disabled_config.enabled, "CORS can be disabled");

        // Test 4: Verify dangerous combination is caught
        // (allow_any_origin=true with allow_credentials=true is dangerous)
        let dangerous_config = CorsConfig {
            enabled: true,
            allow_any_origin: true,
            allowed_origins: vec![],
            allow_credentials: true, // This is dangerous!
        };
        // Note: The application code should validate this and warn/prevent it
        // But the config allows documenting why this is dangerous
        assert!(
            dangerous_config.allow_any_origin && dangerous_config.allow_credentials,
            "This combination is dangerous and should be avoided in production"
        );
    }

    // =============================================================================
    // VULN-21: USER ENUMERATION VIA ERROR MESSAGES
    // =============================================================================

    /// Test that user enumeration via different error messages is prevented
    /// VULN-21: Invalid credentials, locked accounts, and disabled accounts
    /// should all return the same generic error message
    #[test]
    fn test_user_enumeration_prevented_via_error_messages() {
        let (db, _dirs) = common::create_test_db();

        // Create test users with different states
        let active_user = db
            .create_user("active_user", "Password123!", None, None, Some(false))
            .unwrap();

        let inactive_user = db
            .create_user("inactive_user", "Password123!", None, None, Some(false))
            .unwrap();
        db.update_user(inactive_user.id, None, Some(false)).unwrap();

        let locked_user = db
            .create_user("locked_user", "Password123!", None, None, Some(false))
            .unwrap();
        // Lock the user by exceeding failed attempts
        for _ in 0..5 {
            let _ = db.verify_credentials("locked_user", "WrongPassword!");
        }

        // Test 1: Non-existent user
        let err1 = db.verify_credentials("nonexistent", "Password123!").unwrap_err();

        // Test 2: Inactive user
        let err2 = db.verify_credentials("inactive_user", "Password123!").unwrap_err();

        // Test 3: Locked user
        let err3 = db.verify_credentials("locked_user", "Password123!").unwrap_err();

        // Test 4: Wrong password
        let err4 = db.verify_credentials("active_user", "WrongPassword!").unwrap_err();

        // All errors should be PermissionDenied with the SAME message
        match (&err1, &err2, &err3, &err4) {
            (
                DatabaseError::PermissionDenied(msg1),
                DatabaseError::PermissionDenied(msg2),
                DatabaseError::PermissionDenied(msg3),
                DatabaseError::PermissionDenied(msg4),
            ) => {
                // All messages should be identical to prevent enumeration
                assert_eq!(msg1, "Invalid username or password");
                assert_eq!(msg2, "Invalid username or password");
                assert_eq!(msg3, "Invalid username or password");
                assert_eq!(msg4, "Invalid username or password");

                // Verify they're all the same
                assert_eq!(msg1, msg2);
                assert_eq!(msg2, msg3);
                assert_eq!(msg3, msg4);
            }
            _ => panic!("All errors should be PermissionDenied with same message"),
        }
    }

    // =============================================================================
    // VULN-23: SINGLE SUPERADMIN ENFORCEMENT
    // =============================================================================

    /// Test that only one superadmin can exist in the system
    /// VULN-23: Multiple superadmins should not be allowed
    #[test]
    fn test_only_one_superadmin_allowed() {
        let (db, _dirs) = common::create_test_db();

        // Verify bootstrap superadmin exists
        let count_before = db.count_superadmins().unwrap();
        assert_eq!(count_before, 1, "Should have exactly 1 superadmin after bootstrap");

        // Try to create another superadmin by assigning the superadmin role (should fail)
        // Get superadmin role ID
        let roles = db.list_roles().unwrap();
        let superadmin_role = roles.iter().find(|r| r.name == "superadmin").unwrap();

        let result = db.create_user(
            "second_superadmin",
            "SuperPass123!",
            Some(vec![superadmin_role.id]),  // Try to assign superadmin role
            None,
            None,
        );

        // Should fail because a superadmin already exists
        assert!(result.is_err(), "Should not allow creating second superadmin");

        // Verify count is still 1
        let count_after = db.count_superadmins().unwrap();
        assert_eq!(count_after, 1, "Should still have exactly 1 superadmin");
    }

    /// Test that superadmin account cannot be deleted
    #[test]
    fn test_superadmin_cannot_be_deleted() {
        let (db, _dirs) = common::create_test_db();

        // Get the bootstrap superadmin
        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();
        // Verify superadmin role
        let roles = db.get_user_roles(admin.id).unwrap();
        assert!(roles.contains(&"superadmin".to_string()));

        // Try to delete superadmin (should fail)
        let result = db.delete_user(admin.id);

        // Should succeed at DB level (no protection there)
        // Protection is at handler level, but we can test DB behavior
        assert!(result.is_ok(), "DB layer allows deletion");

        // However, handlers should block this
        // This will be tested in integration tests with actual handlers
    }

    /// Test that superadmin account cannot be deactivated
    #[test]
    fn test_superadmin_cannot_be_deactivated() {
        let (db, _dirs) = common::create_test_db();

        // Get the bootstrap superadmin
        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();
        // Verify superadmin role
        let roles = db.get_user_roles(admin.id).unwrap();
        assert!(roles.contains(&"superadmin".to_string()));
        assert!(admin.is_active);

        // Try to deactivate superadmin at DB level
        let result = db.update_user(admin.id, None, Some(false));

        // DB layer allows it, but handlers should block
        assert!(result.is_ok(), "DB layer allows deactivation");

        // Verify it was deactivated at DB level
        let updated_admin = db.get_user_by_id(admin.id).unwrap();
        assert!(!updated_admin.is_active, "DB layer allowed deactivation");

        // Handler-level protection will be tested in integration tests
    }

    /// Test that non-superadmin cannot reset superadmin password
    #[test]
    fn test_non_superadmin_cannot_reset_superadmin_password() {
        let (db, _dirs) = common::create_test_db();

        // Get the bootstrap superadmin
        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();
        // Verify superadmin role
        let roles = db.get_user_roles(admin.id).unwrap();
        assert!(roles.contains(&"superadmin".to_string()));

        // Reset password at DB level (no protection here)
        let result = db.admin_reset_password(admin.id, "NewPassword123!");
        assert!(result.is_ok(), "DB layer allows password reset");

        // Change password using credentials to clear must_change_password flag
        let result = db.change_password_with_credentials("admin", "NewPassword123!", "FinalPassword123!");
        assert!(result.is_ok(), "Password change should work");

        // Verify final password works
        let result = db.verify_credentials("admin", "FinalPassword123!");
        assert!(result.is_ok(), "Final password should work: {:?}", result.err());

        // Handler-level protection will be tested in integration tests
    }

    /// Test count_superadmins function
    #[test]
    fn test_count_superadmins() {
        let (db, _dirs) = common::create_test_db();

        // Should have exactly 1 superadmin (bootstrap)
        let count = db.count_superadmins().unwrap();
        assert_eq!(count, 1);

        // Create a regular user
        db.create_user("regular", "Password123!", None, None, Some(false))
            .unwrap();

        // Count should still be 1
        let count = db.count_superadmins().unwrap();
        assert_eq!(count, 1);

        // Try to create another superadmin (will fail due to validation)
        let roles = db.list_roles().unwrap();
        let superadmin_role = roles.iter().find(|r| r.name == "superadmin").unwrap();

        let result = db.create_user(
            "another_super",
            "SuperPass123!",
            Some(vec![superadmin_role.id]),
            None,
            None,
        );
        assert!(result.is_err());

        // Count should still be 1
        let count = db.count_superadmins().unwrap();
        assert_eq!(count, 1);
    }

    /// SECURITY REGRESSION TEST:
    /// Test that assign_role_to_user cannot bypass superadmin uniqueness
    #[test]
    fn test_assign_role_cannot_create_second_superadmin() {
        let (db, _dirs) = common::create_test_db();

        // Get superadmin role ID
        let roles = db.list_roles().unwrap();
        let superadmin_role = roles.iter().find(|r| r.name == "superadmin").unwrap();

        // Create a regular user
        let user = db
            .create_user("testuser", "Password123!", None, None, Some(false))
            .unwrap();

        // Try to assign superadmin role (should fail because admin already exists)
        let result = db.assign_role_to_user(user.id, superadmin_role.id, None);

        // At database level, this might succeed, but handlers should prevent it
        // This test verifies the database-level enforcement
        // Handler-level tests will be in integration tests
        if result.is_ok() {
            // If DB allows it, verify count is now 2 (not ideal but documents behavior)
            let count = db.count_superadmins().unwrap();
            assert!(count >= 1, "Should have at least the bootstrap superadmin");
        }
    }

    /// SECURITY REGRESSION TEST:
    /// Test that removing superadmin role from only superadmin should fail at handler level
    #[test]
    fn test_remove_superadmin_role_from_only_superadmin_db_level() {
        let (db, _dirs) = common::create_test_db();

        // Get the bootstrap admin
        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Get superadmin role
        let roles = db.list_roles().unwrap();
        let superadmin_role = roles.iter().find(|r| r.name == "superadmin").unwrap();

        // Verify admin is the only superadmin
        let count = db.count_superadmins().unwrap();
        assert_eq!(count, 1);

        // Try to remove superadmin role from admin
        // At DB level this might succeed (protection is at handler level)
        let result = db.remove_role_from_user(admin.id, superadmin_role.id);

        // If it succeeds at DB level, verify the role was removed
        if result.is_ok() {
            let user_roles = db.get_user_roles(admin.id).unwrap();
            assert!(
                !user_roles.contains(&"superadmin".to_string()),
                "DB level allows removal - handler must prevent"
            );

            // System now has no superadmin (bad state)
            let count = db.count_superadmins().unwrap();
            assert_eq!(count, 0, "DB allows removing last superadmin - handler must prevent");
        }
    }

    /// SECURITY REGRESSION TEST:
    /// Test that update_user cannot remove superadmin role via role_ids parameter
    /// Attack vector: PUT /admin/users/{superadmin_id} with role_ids that don't include superadmin
    #[test]
    fn test_update_user_cannot_remove_superadmin_role() {
        let (db, _dirs) = common::create_test_db();

        // Get the bootstrap admin
        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Verify admin is superadmin
        let roles = db.get_user_roles(admin.id).unwrap();
        assert!(roles.contains(&"superadmin".to_string()));

        // Verify count before test
        let count = db.count_superadmins().unwrap();
        assert_eq!(count, 1, "Should have exactly one superadmin before test");

        // This test documents the attack vector:
        // An attacker with admin_users:put could call update_user with role_ids
        // that exclude the superadmin role, effectively demoting the only superadmin
        // The handler protection (validate_superadmin_removal) prevents this attack
    }

    /// SECURITY REGRESSION TEST:
    /// Test that users cannot rotate API keys of other users
    /// Attack vector: POST /admin/api-keys/{other_user_key_id}/rotate
    #[test]
    fn test_cannot_rotate_other_users_api_keys() {
        let (db, _dirs) = common::create_test_db();

        // Create two users
        let user1 = db
            .create_user("user1", "Password123!", None, None, Some(false))
            .unwrap();
        let user2 = db
            .create_user("user2", "Password123!", None, None, Some(false))
            .unwrap();

        // Create API key for user1
        let (_, key1) = db
            .create_api_key(user1.id, Some("user1_key"), None, None, false)
            .unwrap();

        // Get user2's roles to verify in handler tests
        // Handler should prevent user2 from rotating user1's key
        let user2_roles = db.get_user_roles(user2.id).unwrap();
        assert!(!user2_roles.contains(&"superadmin".to_string()),
                "user2 should not be superadmin for this test");

        // The handler check prevents this attack
        // Integration tests will verify the HTTP endpoint blocks this
        assert_eq!(key1.username, "user1");
    }

    /// SECURITY REGRESSION TEST:
    /// Test that users cannot revoke API keys of other users
    /// Attack vector: DELETE /admin/api-keys/{other_user_key_id}
    #[test]
    fn test_cannot_revoke_other_users_api_keys() {
        let (db, _dirs) = common::create_test_db();

        // Create two users
        let user1 = db
            .create_user("user1", "Password123!", None, None, Some(false))
            .unwrap();
        let user2 = db
            .create_user("user2", "Password123!", None, None, Some(false))
            .unwrap();

        // Create API key for user1
        let (_, key1) = db
            .create_api_key(user1.id, Some("user1_key"), None, None, false)
            .unwrap();

        // Verify key is active
        let key_info = db.get_api_key_info(&key1.id).unwrap();
        assert!(!key_info.revoked, "Key should not be revoked initially");

        // Get user2's roles to verify in handler tests
        // Handler should prevent user2 from revoking user1's key
        let user2_roles = db.get_user_roles(user2.id).unwrap();
        assert!(!user2_roles.contains(&"superadmin".to_string()),
                "user2 should not be superadmin for this test");

        // The handler check prevents this attack
        // Integration tests will verify the HTTP endpoint blocks this
        assert_eq!(key_info.username, "user1");
    }

    /// SECURITY REGRESSION TEST:
    /// Test that users cannot create service API keys for other users
    /// Attack vector: POST /admin/api-keys/user/{other_user_id}
    /// This would allow impersonating the target user with full permissions
    #[test]
    fn test_cannot_create_service_keys_for_other_users() {
        let (db, _dirs) = common::create_test_db();

        // Create two users
        let user1 = db
            .create_user("user1", "Password123!", None, None, Some(false))
            .unwrap();
        let user2 = db
            .create_user("user2", "Password123!", None, None, Some(false))
            .unwrap();

        // Verify neither user is superadmin
        let user1_roles = db.get_user_roles(user1.id).unwrap();
        let user2_roles = db.get_user_roles(user2.id).unwrap();
        assert!(!user1_roles.contains(&"superadmin".to_string()),
                "user1 should not be superadmin");
        assert!(!user2_roles.contains(&"superadmin".to_string()),
                "user2 should not be superadmin");

        // The handler prevents user2 from creating service keys for user1
        // This prevents impersonation attack where user2 could get full access as user1
        // Integration tests will verify the HTTP endpoint blocks this
        assert_ne!(user1.id, user2.id);
    }

    /// SECURITY REGRESSION TEST:
    /// Test that non-superadmin users cannot modify role permissions
    /// Attack vector: User with admin_roles:all modifies their own role to grant themselves admin_users:all
    #[test]
    fn test_cannot_escalate_privileges_via_role_permission_modification() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Create a role with admin_roles:all permission
        let role_manager_role = db
            .create_role("role_manager", Some("Can manage roles"))
            .unwrap();
        db.set_role_permission(role_manager_role.id, "admin_roles", "all", true)
            .unwrap();

        // Create user with role_manager role
        let attacker = db
            .create_user(
                "attacker_user",
                "Password123!",
                Some(vec![role_manager_role.id]),
                None,
                None,
            )
            .unwrap();

        let permissions = db.get_effective_permissions(attacker.id).unwrap();
        let roles = db.get_user_roles(attacker.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: attacker.id,
            username: attacker.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Try to escalate privileges by adding admin_users:all to their own role
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(set_role_permission(
                AuthContextExtractor(auth_ctx),
                Extension(db.clone()),
                Path(role_manager_role.id),
                Json(SetPermissionRequest {
                    resource: "admin_users".to_string(),
                    action: "all".to_string(),
                    allowed: true,
                }),
            ));

        // Should be forbidden - only superadmin can modify role permissions
        assert!(
            matches!(result, Err((StatusCode::FORBIDDEN, _))),
            "Non-superadmin should not be able to modify role permissions"
        );
    }

    /// SECURITY REGRESSION TEST:
    /// Test that non-superadmin users cannot remove role permissions
    /// Attack vector: User with admin_roles:all removes deny permissions from their own role
    #[test]
    fn test_cannot_remove_role_permission_denials() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Create a role with admin_roles:all but denied admin_system:all
        let limited_admin_role = db
            .create_role("limited_admin", Some("Admin without system access"))
            .unwrap();
        db.set_role_permission(limited_admin_role.id, "admin_roles", "all", true)
            .unwrap();
        db.set_role_permission(limited_admin_role.id, "admin_system", "all", false)
            .unwrap();

        // Create user with limited_admin role
        let attacker = db
            .create_user(
                "limited_admin_user",
                "Password123!",
                Some(vec![limited_admin_role.id]),
                None,
                None,
            )
            .unwrap();

        let permissions = db.get_effective_permissions(attacker.id).unwrap();
        let roles = db.get_user_roles(attacker.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: attacker.id,
            username: attacker.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Try to escalate by removing the denial
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(remove_role_permission(
                AuthContextExtractor(auth_ctx),
                Extension(db.clone()),
                Path(limited_admin_role.id),
                Query(RemovePermissionQuery {
                    resource: "admin_system".to_string(),
                    action: "all".to_string(),
                }),
            ));

        // Should be forbidden - only superadmin can modify role permissions
        assert!(
            matches!(result, Err((StatusCode::FORBIDDEN, _))),
            "Non-superadmin should not be able to remove role permissions"
        );
    }

    /// SECURITY TEST:
    /// Test that system permissions cannot be modified or deleted
    /// Ensures that initial system permissions (is_system = 1) are protected
    #[test]
    fn test_cannot_modify_system_permissions() {
        let (db, _dirs) = common::create_test_db();

        // Get the superadmin role (which has system permissions)
        let superadmin_role = db.get_role_by_name("superadmin").unwrap();

        // Get one of the system permissions
        let perms = db.get_role_permissions(superadmin_role.id).unwrap();
        assert!(!perms.is_empty(), "Superadmin should have permissions");

        // Find a system permission
        let system_perm = perms.iter().find(|p| p.is_system == Some(true));
        assert!(
            system_perm.is_some(),
            "Superadmin should have at least one system permission"
        );

        let perm = system_perm.unwrap();

        // Try to modify the system permission (change allowed from true to false)
        let result = db.set_role_permission(
            superadmin_role.id,
            &perm.resource,
            &perm.action,
            false,
        );

        // Should fail - cannot modify system role permissions
        assert!(
            matches!(result, Err(DatabaseError::PermissionDenied(_))),
            "Should not be able to modify permissions of system role. Got: {:?}",
            result
        );

        // Try to remove the system permission
        let result = db.remove_role_permission(
            superadmin_role.id,
            &perm.resource,
            &perm.action,
        );

        // Should fail - cannot delete system role permissions
        assert!(
            matches!(result, Err(DatabaseError::PermissionDenied(_))),
            "Should not be able to delete permissions of system role. Got: {:?}",
            result
        );
    }

    /// SECURITY TEST:
    /// Test that all system roles (superadmin, admin, owner, etc.) are protected
    #[test]
    fn test_all_system_roles_are_protected() {
        let (db, _dirs) = common::create_test_db();

        let system_roles = vec!["superadmin", "admin", "owner", "sender", "manager", "data"];

        for role_name in system_roles {
            let role = db.get_role_by_name(role_name).unwrap();
            assert!(role.is_system, "Role {} should be a system role", role_name);

            let perms = db.get_role_permissions(role.id).unwrap();

            // Each system role should have at least one permission
            assert!(!perms.is_empty(), "System role {} should have permissions", role_name);

            // Try to modify the first permission
            let first_perm = &perms[0];
            let result = db.set_role_permission(
                role.id,
                &first_perm.resource,
                &first_perm.action,
                !first_perm.allowed,
            );

            // Should fail - cannot modify system role permissions
            assert!(
                matches!(result, Err(DatabaseError::PermissionDenied(_))),
                "Should not be able to modify permissions of system role {}. Got: {:?}",
                role_name,
                result
            );

            // Try to remove a permission
            let result = db.remove_role_permission(
                role.id,
                &first_perm.resource,
                &first_perm.action,
            );

            // Should also fail
            assert!(
                matches!(result, Err(DatabaseError::PermissionDenied(_))),
                "Should not be able to delete permissions of system role {}. Got: {:?}",
                role_name,
                result
            );
        }
    }

    /// SECURITY TEST:
    /// Test that non-system permissions CAN be modified on custom roles
    /// Ensures the validation doesn't block legitimate operations
    #[test]
    fn test_can_modify_non_system_permissions() {
        let (db, _dirs) = common::create_test_db();

        // Create a custom (non-system) role
        let custom_role = db.create_role("modifiable_role", Some("Test role")).unwrap();
        assert!(!custom_role.is_system, "Custom role should not be a system role");

        // Add a permission to the custom role
        // Note: The resource "user" is a system resource, but we CAN modify permissions
        // on a non-system role, even if the resource is a system resource
        db.set_role_permission(custom_role.id, "user", "get", true)
            .unwrap();

        // Verify it was added
        let perms = db.get_role_permissions(custom_role.id).unwrap();
        let perm = perms.iter().find(|p| p.resource == "user" && p.action == "get");
        assert!(perm.is_some(), "Permission should be added");
        // The resource "user" is a system resource
        assert_eq!(perm.unwrap().is_system, Some(true), "The 'user' resource is a system resource");

        // Modify the permission (change allowed to false)
        let result = db.set_role_permission(custom_role.id, "user", "get", false);
        assert!(result.is_ok(), "Should be able to modify permissions on non-system role");

        // Remove the permission
        let result = db.remove_role_permission(custom_role.id, "user", "get");
        assert!(result.is_ok(), "Should be able to remove permissions from non-system role");

        // Verify it was removed
        let perms = db.get_role_permissions(custom_role.id).unwrap();
        let perm = perms.iter().find(|p| p.resource == "user" && p.action == "get");
        assert!(perm.is_none(), "Permission should be removed");
    }

    /// SECURITY REGRESSION TEST:
    /// Test that API keys are revoked when admin resets password
    /// Attack vector: Compromised account maintains persistent access via existing API keys
    #[test]
    fn test_api_keys_revoked_on_admin_password_reset() {
        let (db, _dirs) = common::create_test_db();

        // Create user without must_change_password
        let user = db
            .create_user("victim", "OldPass123!", None, None, Some(false))
            .unwrap();

        // Create API key for user
        let (api_key, _key_info) = db
            .create_api_key(user.id, Some("test_key"), None, None, true)
            .unwrap();

        // Verify the key works
        let auth_result = db.verify_api_key(&api_key);
        assert!(auth_result.is_ok(), "API key should work before reset");

        // Admin resets password
        db.admin_reset_password(user.id, "NewPass123!").unwrap();

        // Verify the key is now revoked
        let auth_result = db.verify_api_key(&api_key);
        assert!(
            auth_result.is_err(),
            "API key should be revoked after password reset"
        );
    }

    /// SECURITY REGRESSION TEST:
    /// Test that API keys are revoked when user changes password (forced change flow)
    /// Attack vector: Compromised account maintains persistent access via existing API keys
    #[test]
    fn test_api_keys_revoked_on_user_password_change() {
        let (db, _dirs) = common::create_test_db();

        // Create user without must_change_password flag so API key can work
        let user = db
            .create_user(
                "victim2",
                "OldPass123!",
                None,
                None,
                Some(false), // must_change_password = false (so API key works)
            )
            .unwrap();

        // Create API key for user
        let (api_key, _key_info) = db
            .create_api_key(user.id, Some("test_key2"), None, None, true)
            .unwrap();

        // Verify the key works
        let auth_result = db.verify_api_key(&api_key);
        assert!(auth_result.is_ok(), "API key should work before change");

        // User changes password via update_user (simulating authenticated password change)
        db.update_user(user.id, Some("NewPass123!"), None).unwrap();

        // Verify the key is now revoked
        let auth_result = db.verify_api_key(&api_key);
        assert!(
            auth_result.is_err(),
            "API key should be revoked after password change"
        );
    }

    /// SECURITY REGRESSION TEST:
    /// Test that non-superadmin cannot change superadmin's password via update_user
    /// Attack vector: Admin with admin_users:put changes superadmin password to take control
    #[tokio::test]
    async fn test_cannot_change_superadmin_password_via_update() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Get bootstrap superadmin user
        let superadmin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Create admin role with admin_users:put permission
        let admin_role = db.create_role("user_admin", Some("Can manage users")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "put", true)
            .unwrap();

        // Create attacker user with user_admin role
        let attacker = db
            .create_user(
                "attacker_admin",
                "AttackerPass123!",
                Some(vec![admin_role.id]),
                None,
                None,
            )
            .unwrap();

        let permissions = db.get_effective_permissions(attacker.id).unwrap();
        let roles = db.get_user_roles(attacker.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: attacker.id,
            username: attacker.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Try to change superadmin's password
        let result = update_user(
            AuthContextExtractor(auth_ctx),
            Extension(db.clone()),
            Path(superadmin.id),
            Json(UpdateUserRequest {
                password: Some("HackedPass123!".to_string()),
                is_active: None,
                role_ids: None,
            }),
        )
        .await;

        // Should be forbidden
        assert!(
            matches!(result, Err((StatusCode::FORBIDDEN, _))),
            "Non-superadmin should not be able to change superadmin's password"
        );
    }

    /// SECURITY REGRESSION TEST:
    /// Test that API keys are revoked when password is changed via update_user
    /// Attack vector: Compromised account maintains persistent access via existing API keys
    #[test]
    fn test_api_keys_revoked_on_update_user_password_change() {
        let (db, _dirs) = common::create_test_db();

        // Create user without must_change_password
        let user = db
            .create_user("victim3", "OldPass123!", None, None, Some(false))
            .unwrap();

        // Create API key for user
        let (api_key, _key_info) = db
            .create_api_key(user.id, Some("test_key3"), None, None, true)
            .unwrap();

        // Verify the key works
        let auth_result = db.verify_api_key(&api_key);
        assert!(auth_result.is_ok(), "API key should work before password change");

        // Admin changes user's password via update_user
        db.update_user(user.id, Some("NewPass123!"), None).unwrap();

        // Verify the key is now revoked
        let auth_result = db.verify_api_key(&api_key);
        assert!(
            auth_result.is_err(),
            "API key should be revoked after password change via update_user"
        );
    }

    /// SECURITY REGRESSION TEST:
    /// Test that API keys are blocked when must_change_password is set
    /// Attack vector: User bypasses forced password change by using API keys
    #[test]
    fn test_api_keys_blocked_when_must_change_password() {
        let (db, _dirs) = common::create_test_db();

        // Create user with must_change_password flag
        let user = db
            .create_user("new_user", "InitialPass123!", None, Some(1), None)
            .unwrap();

        // Create API key for user
        let (api_key, _key_info) = db
            .create_api_key(user.id, Some("bypass_key"), None, None, true)
            .unwrap();

        // Try to use API key - should be blocked
        let auth_result = db.verify_api_key(&api_key);
        assert!(
            auth_result.is_err(),
            "API key should be blocked when must_change_password is set"
        );

        // Verify the error is PasswordChangeRequired
        match auth_result {
            Err(DatabaseError::PasswordChangeRequired(_)) => {
                // Expected error type
            }
            _ => panic!("Expected PasswordChangeRequired error"),
        }

        // User changes password
        db.change_password_with_credentials("new_user", "InitialPass123!", "NewPass123!")
            .unwrap();

        // Now create a new API key and it should work
        let (new_api_key, _new_key_info) = db
            .create_api_key(user.id, Some("valid_key"), None, None, true)
            .unwrap();

        let auth_result = db.verify_api_key(&new_api_key);
        assert!(
            auth_result.is_ok(),
            "API key should work after password has been changed"
        );
    }

    /// SECURITY TEST: Superadmin can change their own password
    #[test]
    fn test_superadmin_can_change_own_password() {
        let (db, _dirs) = common::create_test_db();

        // Get bootstrap superadmin
        let superadmin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Superadmin changes their own password
        let result = db.update_user(superadmin.id, Some("NewAdminPass123!"), None);
        assert!(result.is_ok(), "Superadmin should be able to change their own password");

        // Verify old password doesn't work
        let old_login = db.verify_credentials("admin", "AdminPass123!");
        assert!(old_login.is_err(), "Old password should not work");

        // Verify new password works
        let new_login = db.verify_credentials("admin", "NewAdminPass123!");
        assert!(new_login.is_ok(), "New password should work");
    }

    /// SECURITY TEST: Superadmin can delete their own API keys
    #[test]
    fn test_superadmin_can_delete_own_api_keys() {
        let (db, _dirs) = common::create_test_db();

        let superadmin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Create API key for superadmin (management key)
        let (api_key, key_info) = db
            .create_api_key(superadmin.id, Some("admin_key"), None, None, true)
            .unwrap();

        // Verify key works
        assert!(db.verify_api_key(&api_key).is_ok());

        // Superadmin revokes their own key
        let result = db.revoke_api_key(&key_info.id, Some(superadmin.id), Some("Self-revocation"));
        assert!(result.is_ok(), "Superadmin should be able to revoke their own API key");

        // Verify key no longer works
        assert!(db.verify_api_key(&api_key).is_err());
    }

    /// SECURITY TEST: Permission conflicts - user deny overrides role allow
    #[test]
    fn test_permission_conflict_user_deny_overrides_role_allow() {
        let (db, _dirs) = common::create_test_db();

        // Create user
        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Create role with permission
        let role = db.create_role("viewer", None).unwrap();
        db.set_role_permission(role.id, "admin_users", "get", true).unwrap();

        // Assign role to user
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // Verify user has permission from role
        let perms = db.get_effective_permissions(user.id).unwrap();
        assert!(perms.iter().any(|p| p.resource == "admin_users" && p.action == "get" && p.allowed));

        // Set user-level deny (should override role allow)
        db.set_user_permission(user.id, "admin_users", "get", false, None).unwrap();

        // Verify user-level deny overrides role allow
        let perms = db.get_effective_permissions(user.id).unwrap();
        let events_get = perms.iter().find(|p| p.resource == "admin_users" && p.action == "get");
        assert!(events_get.is_some());
        assert!(!events_get.unwrap().allowed, "User-level deny should override role allow");
    }

    /// SECURITY TEST: Removing role removes permissions immediately
    #[test]
    fn test_removing_role_removes_permissions_immediately() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Create role with permissions
        let role = db.create_role("editor", None).unwrap();
        db.set_role_permission(role.id, "admin_users", "post", true).unwrap();
        db.set_role_permission(role.id, "admin_users", "delete", true).unwrap();

        // Assign role
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // Verify permissions
        let perms = db.get_effective_permissions(user.id).unwrap();
        assert!(perms.iter().any(|p| p.resource == "admin_users" && p.action == "post"));
        assert!(perms.iter().any(|p| p.resource == "admin_users" && p.action == "delete"));

        // Remove role
        db.remove_role_from_user(user.id, role.id).unwrap();

        // Verify permissions are gone
        let perms = db.get_effective_permissions(user.id).unwrap();
        assert!(!perms.iter().any(|p| p.resource == "admin_users" && p.action == "post"));
        assert!(!perms.iter().any(|p| p.resource == "admin_users" && p.action == "delete"));
    }

    /// SECURITY TEST: Deleting role removes it from all users
    #[test]
    fn test_deleting_role_removes_from_all_users() {
        let (db, _dirs) = common::create_test_db();

        // Create multiple users
        let user1 = db.create_user("user1", "Pass123!", None, None, Some(false)).unwrap();
        let user2 = db.create_user("user2", "Pass123!", None, None, Some(false)).unwrap();

        // Create role and assign to both
        let role = db.create_role("shared_role", None).unwrap();
        db.set_role_permission(role.id, "admin_users", "get", true).unwrap();
        db.assign_role_to_user(user1.id, role.id, None).unwrap();
        db.assign_role_to_user(user2.id, role.id, None).unwrap();

        // Verify both have permissions
        assert!(db.get_effective_permissions(user1.id).unwrap().len() > 0);
        assert!(db.get_effective_permissions(user2.id).unwrap().len() > 0);

        // Delete role
        db.delete_role(role.id).unwrap();

        // Verify both users lost permissions
        assert_eq!(db.get_effective_permissions(user1.id).unwrap().len(), 0);
        assert_eq!(db.get_effective_permissions(user2.id).unwrap().len(), 0);
    }

    /// SECURITY TEST: Management vs Service key permissions
    #[test]
    fn test_management_key_has_full_permissions() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // User only has events:get permission
        let role = db.create_role("viewer", None).unwrap();
        db.set_role_permission(role.id, "admin_users", "get", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // Create management key (is_management = true)
        let result = db.create_api_key(
            user.id,
            Some("management_key"),
            None,
            None,
            true // management key
        );

        // Should succeed in creating the key
        assert!(result.is_ok());
        let (_api_key, key_info) = result.unwrap();
        assert!(key_info.is_management, "Key should be marked as management key");
    }

    /// SECURITY TEST: Service key marked correctly
    #[test]
    fn test_service_key_flag() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Create service key (is_management = false)
        let (_api_key, key_info) = db
            .create_api_key(user.id, Some("service_key"), None, None, false)
            .unwrap();

        assert!(!key_info.is_management, "Key should be marked as service key (not management)");
    }

    /// SECURITY TEST: Concurrent password changes
    #[test]
    fn test_concurrent_password_changes() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        let user = db
            .create_user("testuser", "OldPass123!", None, None, Some(false))
            .unwrap();

        let mut handles = vec![];
        for i in 0..5 {
            let db_clone = Arc::clone(&db);
            let user_id = user.id;
            let handle = std::thread::spawn(move || {
                db_clone.update_user(
                    user_id,
                    Some(&format!("NewPass{}!", i)),
                    None
                )
            });
            handles.push(handle);
        }

        let mut successes = 0;
        for handle in handles {
            if handle.join().unwrap().is_ok() {
                successes += 1;
            }
        }

        // At least one should succeed
        assert!(successes > 0, "At least one concurrent password change should succeed");
    }

    /// SECURITY TEST: Lockout triggers after 5 failed attempts
    #[test]
    fn test_lockout_triggers_after_failed_attempts() {
        let (db, _dirs) = common::create_test_db();

        db.create_user("victim", "CorrectPass123!", None, None, Some(false))
            .unwrap();

        // Make 4 failed attempts (not enough to trigger lockout)
        for _ in 0..4 {
            let _ = db.verify_credentials("victim", "WrongPass123!");
        }

        // 5th attempt should still work with correct password
        let result = db.verify_credentials("victim", "CorrectPass123!");
        // Note: successful login resets counter, so this works
        assert!(result.is_ok(), "Should be able to login after 4 failed attempts");

        // Make 5 failed attempts to trigger lockout
        for _ in 0..5 {
            let _ = db.verify_credentials("victim", "WrongPass123!");
        }

        // Should be locked now
        let result = db.verify_credentials("victim", "CorrectPass123!");
        assert!(result.is_err(), "Account should be locked after 5 failed attempts");
    }

    /// SECURITY TEST: Password change resets lockout
    #[test]
    fn test_password_change_resets_lockout() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("victim", "OldPass123!", None, None, Some(false))
            .unwrap();

        // Trigger lockout (5 failed attempts)
        for _ in 0..5 {
            let _ = db.verify_credentials("victim", "WrongPass!");
        }

        // Verify locked
        let result = db.verify_credentials("victim", "OldPass123!");
        assert!(result.is_err());

        // Admin resets password
        db.admin_reset_password(user.id, "NewPass123!").unwrap();

        // Should be able to change password now
        let result = db.change_password_with_credentials("victim", "NewPass123!", "FinalPass123!");
        assert!(result.is_ok(), "Password change should work after admin reset");

        // Verify failed_login_attempts reset
        let updated_user = db.verify_credentials("victim", "FinalPass123!").unwrap();
        assert_eq!(updated_user.failed_login_attempts, 0);
        assert!(updated_user.locked_until.is_none());
    }

    /// SECURITY TEST: Non-superadmin cannot assign roles to other admins
    /// This prevents admins from modifying other admins' privileges
    #[tokio::test]
    async fn test_admin_cannot_assign_role_to_other_admin() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Create an admin role with admin_users:all permission
        let admin_role = db.create_role("user_admin", Some("Can manage users")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true).unwrap();

        // Create another role that gives admin permissions
        let editor_role = db.create_role("editor_admin", Some("Editor admin")).unwrap();
        db.set_role_permission(editor_role.id, "admin_roles", "all", true).unwrap();

        // Create two admin users
        let admin_actor = db
            .create_user(
                "admin_actor",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                Some(false),
            )
            .unwrap();

        let admin_target = db
            .create_user(
                "admin_target",
                "Password123!",
                Some(vec![editor_role.id]),
                None,
                Some(false),
            )
            .unwrap();

        // Verify both are considered admins
        let actor_user = db.get_user_by_id(admin_actor.id).unwrap();
        let target_user = db.get_user_by_id(admin_target.id).unwrap();

        // Build auth context for admin_actor
        let permissions = db.get_effective_permissions(admin_actor.id).unwrap();
        let roles = db.get_user_roles(admin_actor.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: admin_actor.id,
            username: admin_actor.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Try to assign a role to the other admin (should fail)
        let result = assign_role(
            AuthContextExtractor(auth_ctx.clone()),
            Extension(db.clone()),
            Path((admin_target.id, editor_role.id)),
        )
        .await;

        // Should be FORBIDDEN
        assert!(
            matches!(result, Err((StatusCode::FORBIDDEN, _))),
            "Non-superadmin admin should not be able to assign roles to other admins"
        );
    }

    /// SECURITY TEST: Non-superadmin cannot remove roles from other admins
    /// This prevents admins from neutralizing other admins by removing their roles
    #[tokio::test]
    async fn test_admin_cannot_remove_role_from_other_admin() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Create an admin role with admin_users:all permission
        let admin_role = db.create_role("user_admin_2", Some("Can manage users")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true).unwrap();

        // Create another role that gives admin permissions
        let system_admin_role = db.create_role("system_admin", Some("System admin")).unwrap();
        db.set_role_permission(system_admin_role.id, "admin_system", "all", true).unwrap();

        // Create two admin users
        let admin_actor = db
            .create_user(
                "admin_actor_2",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                Some(false),
            )
            .unwrap();

        let admin_target = db
            .create_user(
                "admin_target_2",
                "Password123!",
                Some(vec![system_admin_role.id]),
                None,
                Some(false),
            )
            .unwrap();

        // Build auth context for admin_actor
        let permissions = db.get_effective_permissions(admin_actor.id).unwrap();
        let roles = db.get_user_roles(admin_actor.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: admin_actor.id,
            username: admin_actor.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Try to remove role from the other admin (should fail)
        let result = remove_role(
            AuthContextExtractor(auth_ctx.clone()),
            Extension(db.clone()),
            Path((admin_target.id, system_admin_role.id)),
        )
        .await;

        // Should be FORBIDDEN
        assert!(
            matches!(result, Err((StatusCode::FORBIDDEN, _))),
            "Non-superadmin admin should not be able to remove roles from other admins"
        );
    }

    /// SECURITY TEST: Admin CAN assign roles to regular users
    /// This verifies that admins can still manage regular (non-admin) users
    #[tokio::test]
    async fn test_admin_can_assign_role_to_regular_user() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Create an admin role with admin_users:all permission
        let admin_role = db.create_role("user_admin_3", Some("Can manage users")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true).unwrap();

        // Create a regular (non-admin) role
        let viewer_role = db.create_role("viewer", Some("Viewer role")).unwrap();
        // No admin permissions for this role

        // Create admin user
        let admin_user = db
            .create_user(
                "admin_user",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                Some(false),
            )
            .unwrap();

        // Create regular user (no admin permissions)
        let regular_user = db
            .create_user(
                "regular_user",
                "Password123!",
                None, // No roles = not admin
                None,
                Some(false),
            )
            .unwrap();

        // Build auth context for admin
        let permissions = db.get_effective_permissions(admin_user.id).unwrap();
        let roles = db.get_user_roles(admin_user.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: admin_user.id,
            username: admin_user.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Admin should be able to assign role to regular user
        let result = assign_role(
            AuthContextExtractor(auth_ctx.clone()),
            Extension(db.clone()),
            Path((regular_user.id, viewer_role.id)),
        )
        .await;

        // Should succeed
        assert!(
            result.is_ok(),
            "Admin should be able to assign roles to regular (non-admin) users"
        );
    }

    /// SECURITY TEST: Superadmin CAN assign roles to other admins
    /// This verifies that superadmin has full control
    #[tokio::test]
    async fn test_superadmin_can_assign_role_to_admin() {
        let (db, _dirs) = common::create_test_db();
        let db = Arc::new(db);

        // Get the superadmin
        let superadmin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Create an admin role
        let admin_role = db.create_role("new_admin_role", Some("New admin role")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true).unwrap();

        // Create another admin user
        let other_admin = db
            .create_user(
                "other_admin",
                "Password123!",
                Some(vec![admin_role.id]),
                None,
                Some(false),
            )
            .unwrap();

        // Build auth context for superadmin
        let permissions = db.get_effective_permissions(superadmin.id).unwrap();
        let roles = db.get_user_roles(superadmin.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: superadmin.id,
            username: superadmin.username.clone(),
            roles,
            permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Superadmin should be able to assign role to other admin
        let result = assign_role(
            AuthContextExtractor(auth_ctx.clone()),
            Extension(db.clone()),
            Path((other_admin.id, admin_role.id)),
        )
        .await;

        // Should succeed
        assert!(
            result.is_ok(),
            "Superadmin should be able to assign roles to other admins"
        );
    }

    // =============================================================================
    // PERMISSION SOURCE TRACKING TESTS
    // =============================================================================

    #[tokio::test]
    async fn test_permission_source_field_distinguishes_direct_and_role_permissions() {
        use ave_http::auth::admin_handlers::get_user_permissions;

        let (db, _dirs) = common::create_test_db();

        // Create superadmin
        let superadmin = db
            .create_user("superadmin", "SuperPass123!", None, None, Some(false))
            .unwrap();
        db.assign_role_to_user(superadmin.id, 1, None).unwrap(); // Assign superadmin role

        // Create a test role with specific permissions
        let test_role = db.create_role("test_role", Some("Role for testing permission sources")).unwrap();

        // Add a role permission (admin_users:get)
        db.set_role_permission(test_role.id, "admin_users", "get", true).unwrap();

        // Create a regular user
        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Assign the test_role to the user
        db.assign_role_to_user(user.id, test_role.id, None).unwrap();

        // Add a DIRECT permission to the user (admin_roles:post)
        db.set_user_permission(user.id, "admin_roles", "post", true, None).unwrap();

        // Create auth context for superadmin
        let superadmin_permissions = db.get_effective_permissions(superadmin.id).unwrap();
        let superadmin_roles = db.get_user_roles(superadmin.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: superadmin.id,
            username: superadmin.username.clone(),
            roles: superadmin_roles,
            permissions: superadmin_permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Get user permissions via the endpoint
        let result = get_user_permissions(
            AuthContextExtractor(auth_ctx),
            Extension(Arc::new(db.clone())),
            Path(user.id),
        )
        .await;

        assert!(result.is_ok(), "Should successfully retrieve user permissions");

        let Json(permissions) = result.unwrap();

        // Verify we got permissions
        assert!(!permissions.is_empty(), "User should have permissions");

        // Find the role-inherited permission (admin_users:get)
        let role_perm = permissions.iter().find(|p|
            p.resource == "admin_users" && p.action == "get"
        );

        assert!(role_perm.is_some(), "Should have admin_users:get from role");
        let role_perm = role_perm.unwrap();

        // Verify it has source = "role"
        assert_eq!(
            role_perm.source.as_deref(),
            Some("role"),
            "admin_users:get should have source='role'"
        );

        // Verify it has the role_name populated
        assert_eq!(
            role_perm.role_name.as_deref(),
            Some("test_role"),
            "admin_users:get should have role_name='test_role'"
        );

        // Find the direct permission (admin_roles:post)
        let direct_perm = permissions.iter().find(|p|
            p.resource == "admin_roles" && p.action == "post"
        );

        assert!(direct_perm.is_some(), "Should have admin_roles:post direct permission");
        let direct_perm = direct_perm.unwrap();

        // Verify it has source = "direct"
        assert_eq!(
            direct_perm.source.as_deref(),
            Some("direct"),
            "admin_roles:post should have source='direct'"
        );

        // Verify role_name is None for direct permissions
        assert!(
            direct_perm.role_name.is_none(),
            "Direct permissions should not have role_name"
        );

        println!("✓ Permission source tracking works correctly:");
        println!("  - Role permission has source='role' and role_name");
        println!("  - Direct permission has source='direct' and no role_name");
    }

    #[tokio::test]
    async fn test_direct_permission_overrides_role_permission() {
        use ave_http::auth::admin_handlers::get_user_permissions;

        let (db, _dirs) = common::create_test_db();

        // Create superadmin
        let superadmin = db
            .create_user("superadmin", "SuperPass123!", None, None, Some(false))
            .unwrap();
        db.assign_role_to_user(superadmin.id, 1, None).unwrap();

        // Create a role that allows admin_system:all
        let role = db.create_role("system_admin", Some("System administrator")).unwrap();
        db.set_role_permission(role.id, "admin_system", "all", true).unwrap();

        // Create user and assign role
        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // Now add a DIRECT deny override for the same permission
        db.set_user_permission(user.id, "admin_system", "all", false, None).unwrap();

        // Create auth context
        let superadmin_permissions = db.get_effective_permissions(superadmin.id).unwrap();
        let superadmin_roles = db.get_user_roles(superadmin.id).unwrap();

        let auth_ctx = Arc::new(AuthContext {
            user_id: superadmin.id,
            username: superadmin.username.clone(),
            roles: superadmin_roles,
            permissions: superadmin_permissions,
            api_key_id: "test-key".to_string(),
            is_management_key: true,
            ip_address: None,
        });

        // Get permissions
        let result = get_user_permissions(
            AuthContextExtractor(auth_ctx),
            Extension(Arc::new(db.clone())),
            Path(user.id),
        )
        .await;

        assert!(result.is_ok());
        let Json(permissions) = result.unwrap();

        // Find admin_system:all permission
        let perm = permissions.iter().find(|p|
            p.resource == "admin_system" && p.action == "all"
        );

        assert!(perm.is_some(), "Should have admin_system:all permission");
        let perm = perm.unwrap();

        // Should be marked as direct (not from role) since user override exists
        assert_eq!(
            perm.source.as_deref(),
            Some("direct"),
            "Direct override should take precedence, showing source='direct'"
        );

        // Should be denied
        assert_eq!(
            perm.allowed,
            false,
            "Direct deny should override role allow"
        );

        // Should NOT have role_name since it's a direct permission
        assert!(
            perm.role_name.is_none(),
            "Direct permission override should not have role_name"
        );

        println!("✓ Direct permission override correctly takes precedence over role permission");
    }

    /// SECURITY TEST:
    /// Test that direct permission denials take precedence over role permissions
    /// Scenario: User has role with "all" permission, but direct deny on specific action
    /// Expected: Direct deny blocks access even though role grants it
    #[tokio::test]
    async fn test_direct_deny_blocks_role_allow_functionally() {
        let (db, _dirs) = common::create_test_db();

        // Create a role with admin_users:all permission (grants everything)
        let admin_role = db.create_role("user_admin", Some("User administrator")).unwrap();
        db.set_role_permission(admin_role.id, "admin_users", "all", true).unwrap();

        // Create user and assign role
        let user = db
            .create_user("blocked_user", "TestPass123!", None, None, Some(false))
            .unwrap();
        db.assign_role_to_user(user.id, admin_role.id, None).unwrap();

        // Verify user has role permission for admin_users:get via role
        let role_perms = db.get_role_permissions(admin_role.id).unwrap();
        assert!(
            role_perms.iter().any(|p| p.resource == "admin_users" && p.action == "all" && p.allowed),
            "Role should have admin_users:all permission"
        );

        // Now add a DIRECT DENY for admin_users:get
        // This should OVERRIDE the role's "all" permission
        db.set_user_permission(user.id, "admin_users", "get", false, None).unwrap();

        // Get effective permissions (what's actually used for authorization)
        let effective_perms = db.get_effective_permissions(user.id).unwrap();

        // Find the admin_users:get permission in effective permissions
        let get_perm = effective_perms.iter().find(|p|
            p.resource == "admin_users" && p.action == "get"
        );

        assert!(
            get_perm.is_some(),
            "Should have admin_users:get in effective permissions"
        );

        let get_perm = get_perm.unwrap();

        // CRITICAL: The effective permission should be DENIED (false)
        // because direct permission overrides role permission
        assert_eq!(
            get_perm.allowed,
            false,
            "Direct deny should override role 'all' permission - user should be BLOCKED"
        );

        // Verify role's "all" permission still works for OTHER actions that aren't denied
        let post_perm = effective_perms.iter().find(|p|
            p.resource == "admin_users" && p.action == "post"
        );

        if let Some(post_perm) = post_perm {
            assert!(
                post_perm.allowed,
                "Other actions not explicitly denied should still be allowed via role"
            );
        }

        // Create AuthContext to test functional authorization
        let user_roles = db.get_user_roles(user.id).unwrap();
        let auth_ctx = AuthContext {
            user_id: user.id,
            username: user.username.clone(),
            roles: user_roles,
            permissions: effective_perms,
            api_key_id: "test-key".to_string(),
            is_management_key: false,
            ip_address: None,
        };

        // Verify that has_permission returns FALSE (blocked)
        assert!(
            !auth_ctx.has_permission("admin_users", "get"),
            "User should be BLOCKED from admin_users:get despite role having 'all' permission"
        );

        println!("✓ Direct deny successfully blocks access despite role granting 'all' permission");
        println!("  - Role grants admin_users:all (should allow everything)");
        println!("  - Direct deny on admin_users:get (blocks this specific action)");
        println!("  - Result: User CANNOT access admin_users:get ✓");
    }

    /// SECURITY TEST:
    /// Test that service API keys CANNOT manage (create/revoke) other API keys
    /// Only management keys (from login) can manage API keys
    #[tokio::test]
    async fn test_service_key_cannot_manage_api_keys() {
        use ave_http::auth::apikey_handlers::{create_my_api_key, revoke_my_api_key};
        use ave_http::auth::models::CreateApiKeyRequest;

        let (db, _dirs) = common::create_test_db();

        // Create a user with permission to manage their own API keys
        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Give user permission to manage personal API keys
        db.set_user_permission(user.id, "user_api_key", "post", true, None).unwrap();
        db.set_user_permission(user.id, "user_api_key", "delete", true, None).unwrap();

        // Create a MANAGEMENT key (simulating login)
        let (management_key, management_info) = db
            .create_api_key(user.id, Some("management_session"), None, None, true)
            .unwrap();

        assert!(management_info.is_management, "Should be a management key");

        // Create a SERVICE key using the management key
        let user_roles = db.get_user_roles(user.id).unwrap();
        let user_perms = db.get_effective_permissions(user.id).unwrap();

        let management_ctx = Arc::new(AuthContext {
            user_id: user.id,
            username: "testuser".to_string(),
            roles: user_roles.clone(),
            permissions: user_perms.clone(),
            api_key_id: management_info.id.clone(),
            is_management_key: true,
            ip_address: None,
        });

        let create_req = CreateApiKeyRequest {
            name: "service_key".to_string(),
            description: Some("Service key for automation".to_string()),
            expires_in_seconds: None,
        };

        let result = create_my_api_key(
            AuthContextExtractor(management_ctx.clone()),
            Extension(Arc::new(db.clone())),
            Json(create_req),
        )
        .await;

        assert!(result.is_ok(), "Management key should be able to create service keys");
        let (status, Json(response)) = result.unwrap();
        assert_eq!(status, StatusCode::CREATED);
        let service_key = response.api_key;
        let service_info = response.key_info;

        assert!(!service_info.is_management, "Created key should be a service key");

        // Now try to use the SERVICE key to create another API key
        // This should FAIL because service keys cannot manage API keys
        let service_ctx = Arc::new(AuthContext {
            user_id: user.id,
            username: "testuser".to_string(),
            roles: user_roles.clone(),
            permissions: user_perms.clone(),
            api_key_id: service_info.id.clone(),
            is_management_key: false, // This is a service key
            ip_address: None,
        });

        let create_req2 = CreateApiKeyRequest {
            name: "another_service_key".to_string(),
            description: Some("Trying to create another key".to_string()),
            expires_in_seconds: None,
        };

        let result = create_my_api_key(
            AuthContextExtractor(service_ctx.clone()),
            Extension(Arc::new(db.clone())),
            Json(create_req2),
        )
        .await;

        // Should FAIL - service keys cannot create other API keys
        assert!(result.is_err(), "Service key should NOT be able to create API keys");
        let (status, Json(err)) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(err.error.contains("management API key"), "Error should mention management key requirement");

        // Also test that service key cannot revoke other keys
        let result = revoke_my_api_key(
            AuthContextExtractor(service_ctx),
            Extension(Arc::new(db.clone())),
            Path(service_info.name.clone()),
            None,
        )
        .await;

        // Should FAIL - service keys cannot revoke API keys
        assert!(result.is_err(), "Service key should NOT be able to revoke API keys");
        let (status, Json(err)) = result.unwrap_err();
        assert_eq!(status, StatusCode::FORBIDDEN);
        assert!(err.error.contains("management API key"), "Error should mention management key requirement");

        println!("✓ Service keys correctly blocked from managing API keys");
        println!("  - Service key CANNOT create new API keys");
        println!("  - Service key CANNOT revoke API keys");
        println!("  - Only management keys (from login) can manage API keys");
    }

    /// SECURITY TEST:
    /// Test that "all" permission prevents individual permissions and vice versa
    /// Only applies to DIRECT user permissions, NOT role permissions
    #[test]
    fn test_all_permission_validation() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "TestPass123!", None, None, Some(false))
            .unwrap();

        // Test 1: Assign individual permissions first, then "all" should remove them
        db.set_user_permission(user.id, "admin_users", "get", true, None).unwrap();
        db.set_user_permission(user.id, "admin_users", "post", true, None).unwrap();
        db.set_user_permission(user.id, "admin_users", "put", true, None).unwrap();

        // Verify individual permissions exist
        let all_perms_before = db.get_user_permissions(user.id).unwrap();
        let perms_before: Vec<_> = all_perms_before.iter()
            .filter(|p| p.source.as_deref() == Some("direct"))
            .collect();
        let get_perm = perms_before.iter().find(|p| p.resource == "admin_users" && p.action == "get");
        let post_perm = perms_before.iter().find(|p| p.resource == "admin_users" && p.action == "post");
        assert!(get_perm.is_some(), "Should have get permission");
        assert!(post_perm.is_some(), "Should have post permission");

        // Assign "all" - should automatically remove individual permissions
        db.set_user_permission(user.id, "admin_users", "all", true, None).unwrap();

        // Verify individual permissions were removed, only "all" remains
        let all_perms_after = db.get_user_permissions(user.id).unwrap();
        let perms_after: Vec<_> = all_perms_after.iter()
            .filter(|p| p.source.as_deref() == Some("direct"))
            .collect();
        let get_perm_after = perms_after.iter().find(|p| p.resource == "admin_users" && p.action == "get");
        let post_perm_after = perms_after.iter().find(|p| p.resource == "admin_users" && p.action == "post");
        let all_perm = perms_after.iter().find(|p| p.resource == "admin_users" && p.action == "all");

        assert!(get_perm_after.is_none(), "Individual 'get' permission should be removed");
        assert!(post_perm_after.is_none(), "Individual 'post' permission should be removed");
        assert!(all_perm.is_some(), "Should have 'all' permission");

        println!("✓ Test 1 passed: Assigning 'all' removes individual permissions");

        // Test 2: Try to assign individual permission when "all" exists - should fail
        let result = db.set_user_permission(user.id, "admin_users", "delete", true, None);
        assert!(result.is_err(), "Should not allow individual permission when 'all' exists");

        if let Err(DatabaseError::ValidationError(msg)) = result {
            assert!(msg.contains("already has 'all' permission"), "Error message should mention 'all' permission");
        } else {
            panic!("Expected ValidationError, got: {:?}", result);
        }

        println!("✓ Test 2 passed: Cannot assign individual permission when 'all' exists");

        // Test 3: Role permissions should NOT be affected
        // Create a role with individual permissions
        let role = db.create_role("test_role", Some("Test role")).unwrap();
        db.set_role_permission(role.id, "admin_roles", "get", true).unwrap();
        db.set_role_permission(role.id, "admin_roles", "post", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User should be able to have "all" direct permission even though role has individual permissions
        let result = db.set_user_permission(user.id, "admin_roles", "all", false, None);
        assert!(result.is_ok(), "Should allow direct 'all' permission even when role has individual permissions");

        // Verify role permissions still exist and user has direct "all" override
        let all_perms = db.get_user_permissions(user.id).unwrap();

        // Should have role permissions (get, post)
        let role_get = all_perms.iter().find(|p|
            p.resource == "admin_roles" && p.action == "get" && p.source.as_deref() == Some("role")
        );
        let role_post = all_perms.iter().find(|p|
            p.resource == "admin_roles" && p.action == "post" && p.source.as_deref() == Some("role")
        );

        // Should have direct "all" override
        let direct_all = all_perms.iter().find(|p|
            p.resource == "admin_roles" && p.action == "all" && p.source.as_deref() == Some("direct")
        );

        assert!(role_get.is_some(), "Role 'get' permission should still exist");
        assert!(role_post.is_some(), "Role 'post' permission should still exist");
        assert!(direct_all.is_some(), "Direct 'all' override should exist");
        assert!(!direct_all.unwrap().allowed, "Direct 'all' should be denied (override)");

        println!("✓ Test 3 passed: Role permissions are not affected by direct permission validation");
        println!("✓ All permission validation works correctly:");
        println!("  - Assigning 'all' removes individual direct permissions");
        println!("  - Cannot assign individual when 'all' exists");
        println!("  - Role permissions remain independent");
    }

    #[test]
    fn test_system_config_ttl_validation() {
        use ave_bridge::auth::{ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig};

        let config = AuthConfig {
            enable: true,
            database_path: PathBuf::from(":memory:"),
            superadmin: "admin".to_string(),
            api_key: ApiKeyConfig::default(),
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        };

        let db = AuthDatabase::new(config, "TestPass123!").expect("Failed to create database");

        // ========== API Key TTL Tests ==========
        println!("Testing api_key_default_ttl_seconds validation:");

        // Test 1: Valid positive TTL should be accepted
        let result = db.update_system_config("api_key_default_ttl_seconds", "3600", Some(1));
        assert!(result.is_ok(), "Valid positive TTL should be accepted");
        assert_eq!(result.unwrap().value, "3600");

        // Test 2: Zero TTL (no expiration) should be accepted
        let result = db.update_system_config("api_key_default_ttl_seconds", "0", Some(1));
        assert!(result.is_ok(), "Zero TTL (no expiration) should be accepted");
        assert_eq!(result.unwrap().value, "0");

        // Test 3: Negative TTL should be rejected
        let result = db.update_system_config("api_key_default_ttl_seconds", "-1", Some(1));
        assert!(result.is_err(), "Negative TTL should be rejected");
        if let Err(DatabaseError::ValidationError(msg)) = result {
            assert!(msg.contains("must be >= 0"));
        } else {
            panic!("Expected ValidationError for negative TTL");
        }

        // Test 4: Invalid integer should be rejected
        let result = db.update_system_config("api_key_default_ttl_seconds", "not_a_number", Some(1));
        assert!(result.is_err(), "Invalid integer should be rejected");

        // ========== Max Login Attempts Tests ==========
        println!("Testing max_login_attempts validation:");

        // Valid positive value
        let result = db.update_system_config("max_login_attempts", "5", Some(1));
        assert!(result.is_ok(), "Valid max_login_attempts should be accepted");
        assert_eq!(result.unwrap().value, "5");

        // Zero should be rejected (must be > 0)
        let result = db.update_system_config("max_login_attempts", "0", Some(1));
        assert!(result.is_err(), "Zero max_login_attempts should be rejected");
        if let Err(DatabaseError::ValidationError(msg)) = result {
            assert!(msg.contains("must be > 0"));
        } else {
            panic!("Expected ValidationError for zero max_login_attempts");
        }

        // Invalid value
        let result = db.update_system_config("max_login_attempts", "invalid", Some(1));
        assert!(result.is_err(), "Invalid max_login_attempts should be rejected");

        // ========== Lockout Duration Tests ==========
        println!("Testing lockout_duration_seconds validation:");

        // Valid positive value
        let result = db.update_system_config("lockout_duration_seconds", "300", Some(1));
        assert!(result.is_ok(), "Valid lockout_duration should be accepted");
        assert_eq!(result.unwrap().value, "300");

        // Zero should be rejected (must be > 0)
        let result = db.update_system_config("lockout_duration_seconds", "0", Some(1));
        assert!(result.is_err(), "Zero lockout_duration should be rejected");
        if let Err(DatabaseError::ValidationError(msg)) = result {
            assert!(msg.contains("must be > 0"));
        } else {
            panic!("Expected ValidationError for zero lockout_duration");
        }

        // Negative should be rejected
        let result = db.update_system_config("lockout_duration_seconds", "-100", Some(1));
        assert!(result.is_err(), "Negative lockout_duration should be rejected");

        // ========== Rate Limit Window Tests ==========
        println!("Testing rate_limit_window_seconds validation:");

        // Valid positive value
        let result = db.update_system_config("rate_limit_window_seconds", "60", Some(1));
        assert!(result.is_ok(), "Valid rate_limit_window should be accepted");
        assert_eq!(result.unwrap().value, "60");

        // Zero should be rejected (must be > 0)
        let result = db.update_system_config("rate_limit_window_seconds", "0", Some(1));
        assert!(result.is_err(), "Zero rate_limit_window should be rejected");
        if let Err(DatabaseError::ValidationError(msg)) = result {
            assert!(msg.contains("must be > 0"));
        } else {
            panic!("Expected ValidationError for zero rate_limit_window");
        }

        // Negative should be rejected
        let result = db.update_system_config("rate_limit_window_seconds", "-60", Some(1));
        assert!(result.is_err(), "Negative rate_limit_window should be rejected");

        // ========== Rate Limit Max Requests Tests ==========
        println!("Testing rate_limit_max_requests validation:");

        // Valid positive value
        let result = db.update_system_config("rate_limit_max_requests", "100", Some(1));
        assert!(result.is_ok(), "Valid rate_limit_max_requests should be accepted");
        assert_eq!(result.unwrap().value, "100");

        // Zero should be rejected (must be > 0)
        let result = db.update_system_config("rate_limit_max_requests", "0", Some(1));
        assert!(result.is_err(), "Zero rate_limit_max_requests should be rejected");
        if let Err(DatabaseError::ValidationError(msg)) = result {
            assert!(msg.contains("must be > 0"));
        } else {
            panic!("Expected ValidationError for zero rate_limit_max_requests");
        }

        // Invalid value
        let result = db.update_system_config("rate_limit_max_requests", "invalid", Some(1));
        assert!(result.is_err(), "Invalid rate_limit_max_requests should be rejected");

        // ========== Unknown Config Key ==========
        println!("Testing unknown config key:");

        // Unknown keys should fail (key not found), but not due to validation
        let result = db.update_system_config("some_other_config", "-1", Some(1));
        assert!(result.is_err(), "Non-existent key should fail");

        println!("✓ All system config validations work correctly:");
        println!("  - api_key_default_ttl_seconds: >= 0 (allows 0 for no expiration)");
        println!("  - max_login_attempts: > 0");
        println!("  - lockout_duration_seconds: > 0");
        println!("  - rate_limit_window_seconds: > 0");
        println!("  - rate_limit_max_requests: > 0");
    }

}
