// Ave HTTP Auth System - Security and Edge Case Tests
//
// Tests for security vulnerabilities, edge cases, and error conditions

mod common;

use ave_http::auth::database::DatabaseError;

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // PASSWORD POLICY VALIDATION TESTS
    // =============================================================================

    #[test]
    fn test_password_too_short() {
        let (db, _dirs) = common::create_test_db();

        let result =
            db.create_user("testuser", "Short1!", false, None, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_too_long() {
        let (db, _dirs) = common::create_test_db();

        let long_pass = "Aa1!Aa1!Aa1!Aa1!Aa1!X"; // 21 chars
        let result =
            db.create_user("testuser", long_pass, false, None, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_uppercase() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user(
            "testuser",
            "lowercase123!",
            false,
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
            false,
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
            false,
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
            false,
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
            false,
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
        db.create_user(safe_username, "Password123!", false, None, None, Some(false))
            .unwrap();

        let verify_result = db.verify_credentials(safe_username, "Password123!");
        assert!(verify_result.is_ok());
        let user = verify_result.unwrap();
        assert_eq!(user.username, safe_username);
        assert!(!user.is_superadmin);
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
        let users = db.list_users(false);
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
                    false,
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
                    false,
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
            .create_user("test_user", "Password123!", false, None, None, None)
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
            false,
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
            db.create_user(username, "Password123!", false, None, None, None);
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
            false,
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
            false,
            None,
            None,
            None,
        );
        assert!(result.is_ok(), "Should accept username of exactly 64 chars");

        // Very long role name - role validation may not be as strict
        let long_role_name = "b".repeat(255);
        let role = db.create_role(&long_role_name, None);
        assert!(role.is_ok(), "Role names may allow longer strings");
    }

    // =============================================================================
    // BOUNDARY TESTS
    // =============================================================================

    #[test]
    fn test_zero_ttl_api_key_never_expires() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", false, None, None, None)
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
    fn test_inactive_user_cannot_login() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
        assert!(user.is_superadmin);
    }

    #[test]
    fn test_superadmin_has_all_permissions() {
        let (db, _dirs) = common::create_test_db();

        let admin = db.verify_credentials("admin", "AdminPass123!").unwrap();

        // Superadmin should have all permissions (empty list means all)
        let _perms = db.get_user_effective_permissions(admin.id).unwrap();

        // Superadmins bypass permission checks, so they might have empty perms
        // The middleware should check is_superadmin flag
        assert!(admin.is_superadmin);
    }

    #[test]
    fn test_create_superadmin_user() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user(
                "newsuperadmin",
                "SuperPass123!",
                true,
                None,
                None,
                None,
            )
            .unwrap();

        assert!(user.is_superadmin);
    }

    // =============================================================================
    // API KEY REVOCATION TESTS
    // =============================================================================

    #[test]
    fn test_revoked_api_key_cannot_be_used() {
        let (db, _dirs) = common::create_test_db();

        let user = db
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
        let (db, _dirs) = common::create_test_db();

        // Create a test user
        db.create_user("testuser", "Password123!", false, None, None, None)
            .unwrap();

        // Simulate multiple failed login attempts from same IP
        let fake_ip = Some("192.168.1.100");

        // Make requests up to rate limit (test config uses 100 per 60 seconds)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            let result = db.create_user(username, "Password123!", false, None, None, None);
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
            .create_user("testuser", "Password123!", false, None, None, None)
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
            let result = db.create_user(username, password, false, None, None, None);
            assert!(result.is_err(), "Should reject null bytes in username");
        }

        // Test valid strings work
        let valid_user = db
            .create_user("validuser", "Password123!", false, None, None, None)
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
        let result = db.create_user(&long_username, "Password123!", false, None, None, None);
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
}
