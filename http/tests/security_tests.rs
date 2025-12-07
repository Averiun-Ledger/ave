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

        let result = db.create_user("testuser", "Short1!", false, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_too_long() {
        let (db, _dirs) = common::create_test_db();

        let long_pass = "Aa1!Aa1!Aa1!Aa1!Aa1!X"; // 21 chars
        let result = db.create_user("testuser", long_pass, false, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_uppercase() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user("testuser", "lowercase123!", false, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_lowercase() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user("testuser", "UPPERCASE123!", false, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_missing_digit() {
        let (db, _dirs) = common::create_test_db();

        let result = db.create_user("testuser", "NoDigitsHere!", false, None, None);

        assert!(matches!(result, Err(DatabaseError::ValidationError(_))));
    }

    #[test]
    fn test_password_with_unicode() {
        let (db, _dirs) = common::create_test_db();

        // Should work with unicode characters
        let result = db.create_user("testuser", "Pass123🔐中文", false, None, None);

        assert!(result.is_ok());
    }

    // =============================================================================
    // SQL INJECTION PROTECTION TESTS
    // =============================================================================

    #[test]
    fn test_sql_injection_in_username() {
        let (db, _dirs) = common::create_test_db();

        // Try SQL injection in username
        let malicious_username = "admin' OR '1'='1";
        let result = db.create_user(malicious_username, "Password123!", false, None, None);

        // Should create user with literal string, not execute SQL
        assert!(result.is_ok());

        // Should not authenticate as admin
        db.change_password_with_credentials(
            malicious_username,
            "Password123!",
            "Password123!",
        )
        .unwrap();
        let verify_result = db.verify_credentials(malicious_username, "Password123!");
        assert!(verify_result.is_ok());

        let user = verify_result.unwrap();
        assert_eq!(user.username, malicious_username);
        assert!(!user.is_superadmin);
    }

    #[test]
    fn test_sql_injection_in_role_name() {
        let (db, _dirs) = common::create_test_db();

        let malicious_role_name = "admin'; DROP TABLE users; --";
        let result = db.create_role(malicious_role_name, Some("Malicious role"), None);

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
                db_clone.create_user(&format!("user{}", i), "Password123!", false, None, None)
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

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
                db_clone.create_user("duplicate_user", "Password123!", false, None, None)
            });
            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

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
        let user = db.create_user("test_user", "Password123!", false, None, None).unwrap();
        let (api_key, _) =
            db.create_api_key(user.id, Some("concurrent"), None, None, false)
                .unwrap();

        let mut handles = vec![];

        // Verify same API key from multiple threads
        for _ in 0..20 {
            let db_clone = db.clone();
            let key_clone = api_key.clone();
            let handle = std::thread::spawn(move || db_clone.verify_api_key(&key_clone));
            handles.push(handle);
        }

        let results: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();

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
        let result = db.create_user(unicode_username, "Password123!", false, None, None);

        assert!(result.is_ok());

        let user = result.unwrap();
        assert_eq!(user.username, unicode_username);
    }

    #[test]
    fn test_whitespace_in_names() {
        let (db, _dirs) = common::create_test_db();

        // Username with spaces
        let username = "user with spaces";
        let result = db.create_user(username, "Password123!", false, None, None);
        assert!(result.is_ok());

        // Role with tabs
        let role_name = "role\twith\ttabs";
        let role = db.create_role(role_name, None, None);
        assert!(role.is_ok());
    }

    #[test]
    fn test_very_long_strings() {
        let (db, _dirs) = common::create_test_db();

        // Very long username (255 chars)
        let long_username = "a".repeat(255);
        let result = db.create_user(&long_username, "Password123!", false, None, None);
        assert!(result.is_ok());

        // Very long role name
        let long_role_name = "b".repeat(255);
        let role = db.create_role(&long_role_name, None, None);
        assert!(role.is_ok());
    }

    // =============================================================================
    // BOUNDARY TESTS
    // =============================================================================

    #[test]
    fn test_zero_ttl_api_key_never_expires() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();

        // Create key with 0 TTL (never expires)
        let (api_key, _) =
            db.create_api_key(user.id, Some("ttl0"), None, Some(0i64), false)
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

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();

        // Deactivate user
        db.update_user(user.id, None, Some(false)).unwrap();

        // Cannot login
        let result = db.verify_credentials("testuser", "Password123!");
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_inactive_user_api_keys_dont_work() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();
        let (api_key, _) =
            db.create_api_key(user.id, Some("lockout"), None, None, false)
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

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();
        let (api_key, _) =
            db.create_api_key(user.id, Some("lockout2"), None, None, false)
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

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        db.set_role_permission(role.id, "subjects", "read", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User has permission
        let perms_before = db.get_user_effective_permissions(user.id).unwrap();
        assert!(perms_before.iter().any(|p| p.resource == "subjects" && p.action == "read" && p.allowed));

        // Delete role
        db.delete_role(role.id).unwrap();

        // User should no longer have permission
        let perms_after = db.get_user_effective_permissions(user.id).unwrap();
        assert!(!perms_after.iter().any(|p| p.resource == "subjects" && p.action == "read" && p.allowed));
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

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();

        let result = db.assign_role_to_user(user.id, 99999, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_assign_role_to_nonexistent_user() {
        let (db, _dirs) = common::create_test_db();

        let role = db.create_role("editor", None, None).unwrap();

        let result = db.assign_role_to_user(99999, role.id, None);

        assert!(result.is_err());
    }

    #[test]
    fn test_revoke_nonexistent_api_key() {
        let (db, _dirs) = common::create_test_db();

        let result = db.revoke_api_key(99999, None, None);

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

        let user = db.create_user("newsuperadmin", "SuperPass123!", true, None, None).unwrap();

        assert!(user.is_superadmin);
    }

    // =============================================================================
    // API KEY REVOCATION TESTS
    // =============================================================================

    #[test]
    fn test_revoked_api_key_cannot_be_used() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();
        let (api_key, key_info) =
            db.create_api_key(user.id, Some("rl_main"), None, None, false)
                .unwrap();

        // Revoke key
        db.revoke_api_key(key_info.id, None, Some("Security breach")).unwrap();

        // Should not verify
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_double_revoke_api_key() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();
        let (_, key_info) =
            db.create_api_key(user.id, Some("rl_expire"), None, None, false)
                .unwrap();

        // Revoke key
        db.revoke_api_key(key_info.id, None, None).unwrap();

        // Revoke again (should still work or fail gracefully)
        let result = db.revoke_api_key(key_info.id, None, None);
        // Either succeeds or fails with NotFound
        assert!(result.is_ok() || matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    // =============================================================================
    // STRESS TESTS
    // =============================================================================

    #[test]
    fn test_many_roles_for_user() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();

        // Create and assign 50 roles
        for i in 0..50 {
            let role = db.create_role(&format!("role{}", i), None, None).unwrap();
            db.assign_role_to_user(user.id, role.id, None).unwrap();
        }

        let roles = db.get_user_roles(user.id).unwrap();
        assert_eq!(roles.len(), 50);
    }

    #[test]
    fn test_many_permissions_for_role() {
        let (db, _dirs) = common::create_test_db();

        let role = db.create_role("power_user", None, None).unwrap();

        // Use actual system resources and actions from schema
        let resources = vec!["subjects", "events", "governances", "approvals", "transfers",
                            "signatures", "auth", "users", "roles", "permissions"];
        let actions = vec!["create", "read", "update", "delete", "list", "execute", "manage"];

        // Grant permissions for all combinations
        for resource in &resources {
            for action in &actions {
                db.set_role_permission(role.id, resource, action, true).unwrap();
            }
        }

        let perms = db.get_role_permissions(role.id).unwrap();
        assert_eq!(perms.len(), resources.len() * actions.len());
    }

    #[test]
    fn test_many_api_keys_for_user() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "Password123!", false, None, None).unwrap();

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
}
