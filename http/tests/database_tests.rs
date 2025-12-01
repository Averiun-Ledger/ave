// Ave HTTP Auth System - Database Integration Tests
//
// Comprehensive tests for user management, roles, API keys, and permissions

mod common;

use ave_http::auth::database::DatabaseError;
use ave_http::auth::models::*;

#[cfg(test)]
mod tests {
    use super::*;

    // =============================================================================
    // USER MANAGEMENT TESTS
    // =============================================================================

    #[test]
    fn test_create_user_success() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        assert_eq!(user.username, "testuser");
        assert!(!user.is_superadmin);
        assert!(user.is_active);
        assert_eq!(user.failed_login_attempts, 0);
    }

    #[test]
    fn test_create_user_duplicate() {
        let db = common::create_test_db();

        db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let result = db.create_user("testuser", "TestPass123!", false, None, None);

        assert!(matches!(result, Err(DatabaseError::DuplicateError(_))));
    }

    #[test]
    fn test_get_user_by_id() {
        let db = common::create_test_db();

        let created = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let fetched = db.get_user_by_id(created.id).unwrap();

        assert_eq!(fetched.username, "testuser");
        assert_eq!(fetched.id, created.id);
    }

    #[test]
    fn test_update_user() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        // Update password
        db.update_user(user.id, Some("NewPass456!"), None).unwrap();

        // Verify new password works
        let result = db.verify_credentials("testuser", "NewPass456!");
        assert!(result.is_ok());
    }

    #[test]
    fn test_deactivate_user() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        // Deactivate
        db.update_user(user.id, None, Some(false)).unwrap();

        // Should not be able to login
        let result = db.verify_credentials("testuser", "TestPass123!");
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_list_users() {
        let db = common::create_test_db();

        db.create_user("user1", "TestPass123!", false, None, None).unwrap();
        db.create_user("user2", "TestPass123!", false, None, None).unwrap();

        let users = db.list_users(false).unwrap();

        // At least 3 users (admin + user1 + user2)
        assert!(users.len() >= 3);
    }

    #[test]
    fn test_delete_user() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

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
        let db = common::create_test_db();

        db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        let user = db.verify_credentials("testuser", "TestPass123!").unwrap();
        assert_eq!(user.username, "testuser");
    }

    #[test]
    fn test_verify_credentials_wrong_password() {
        let db = common::create_test_db();

        db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        let result = db.verify_credentials("testuser", "WrongPassword");
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_account_lockout_after_failed_attempts() {
        let db = common::create_test_db();

        db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        // 5 failed attempts (lockout threshold)
        for _ in 0..5 {
            let _ = db.verify_credentials("testuser", "WrongPassword");
        }

        // Even correct password should fail now
        let result = db.verify_credentials("testuser", "TestPass123!");
        assert!(matches!(result, Err(DatabaseError::AccountLocked(_))));
    }

    #[test]
    fn test_failed_attempts_reset_on_success() {
        let db = common::create_test_db();

        db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

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
        let db = common::create_test_db();

        let role = db.create_role("editor", Some("Editor role"), None).unwrap();

        assert_eq!(role.name, "editor");
        assert_eq!(role.description, Some("Editor role".to_string()));
    }

    #[test]
    fn test_create_role_duplicate() {
        let db = common::create_test_db();

        db.create_role("editor", None, None).unwrap();
        let result = db.create_role("editor", None, None);

        assert!(matches!(result, Err(DatabaseError::DuplicateError(_))));
    }

    #[test]
    fn test_assign_role_to_user() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        db.assign_role_to_user(user.id, role.id, None).unwrap();

        let roles = db.get_user_roles(user.id).unwrap();
        assert!(roles.contains(&"editor".to_string()));
    }

    #[test]
    fn test_remove_role_from_user() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        db.assign_role_to_user(user.id, role.id, None).unwrap();
        db.remove_role_from_user(user.id, role.id).unwrap();

        let roles = db.get_user_roles(user.id).unwrap();
        assert!(!roles.contains(&"editor".to_string()));
    }

    #[test]
    fn test_user_with_multiple_roles() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role1 = db.create_role("editor", None, None).unwrap();
        let role2 = db.create_role("viewer", None, None).unwrap();

        db.assign_role_to_user(user.id, role1.id, None).unwrap();
        db.assign_role_to_user(user.id, role2.id, None).unwrap();

        let roles = db.get_user_roles(user.id).unwrap();
        assert!(roles.contains(&"editor".to_string()));
        assert!(roles.contains(&"viewer".to_string()));
    }

    #[test]
    fn test_delete_role() {
        let db = common::create_test_db();

        let role = db.create_role("temp_role", None, None).unwrap();

        db.delete_role(role.id).unwrap();

        let result = db.get_role_by_name("temp_role");
        assert!(matches!(result, Err(DatabaseError::NotFoundError(_))));
    }

    // =============================================================================
    // API KEY TESTS
    // =============================================================================

    #[test]
    fn test_create_api_key() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        let (api_key, key_info) = db.create_api_key(user.id, Some("test_key"), None, None, None).unwrap();

        assert!(!api_key.is_empty());
        assert_eq!(key_info.name, Some("test_key".to_string()));
        assert!(!key_info.revoked);
    }

    #[test]
    fn test_verify_api_key_success() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (api_key, _) = db.create_api_key(user.id, None, None, None, None).unwrap();

        let context = db.verify_api_key(&api_key).unwrap();

        assert_eq!(context.username, "testuser");
        assert_eq!(context.user_id, user.id);
    }

    #[test]
    fn test_verify_api_key_invalid() {
        let db = common::create_test_db();

        let result = db.verify_api_key("invalid_key_12345");

        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_api_key_expiration() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        // Create key with 1 second TTL
        let (api_key, _) = db.create_api_key(user.id, None, None, None, Some(1)).unwrap();

        // Should work immediately
        assert!(db.verify_api_key(&api_key).is_ok());

        // Wait for expiration
        std::thread::sleep(std::time::Duration::from_secs(2));

        // Should fail after expiration
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_revoke_api_key() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (api_key, key_info) = db.create_api_key(user.id, None, None, None, None).unwrap();

        // Revoke the key
        db.revoke_api_key(key_info.id, None, None).unwrap();

        // Should no longer verify
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_list_user_api_keys() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        db.create_api_key(user.id, Some("key1"), None, None, None).unwrap();
        db.create_api_key(user.id, Some("key2"), None, None, None).unwrap();

        let keys = db.list_user_api_keys(user.id, false).unwrap();

        assert_eq!(keys.len(), 2);
    }

    #[test]
    fn test_api_key_last_used_tracking() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (api_key, key_info) = db.create_api_key(user.id, None, None, None, None).unwrap();

        assert!(key_info.last_used_at.is_none());

        // Use the key
        db.verify_api_key(&api_key).unwrap();

        // Check it was tracked
        let keys = db.list_user_api_keys(user.id, false).unwrap();
        let used_key = keys.iter().find(|k| k.id == key_info.id).unwrap();

        assert!(used_key.last_used_at.is_some());
    }

    // =============================================================================
    // PERMISSION TESTS
    // =============================================================================

    #[test]
    fn test_set_role_permission() {
        let db = common::create_test_db();

        let role = db.create_role("editor", None, None).unwrap();

        // Grant read permission on subjects
        db.set_role_permission(role.id, "subjects", "read", true).unwrap();

        let permissions = db.get_role_permissions(role.id).unwrap();

        let perm = permissions.iter()
            .find(|p| p.resource == "subjects" && p.action == "read")
            .unwrap();

        assert!(perm.allowed);
    }

    #[test]
    fn test_set_user_permission_override() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        // Set user-specific permission
        db.set_user_permission(user.id, "users", "update", false, None).unwrap();

        let permissions = db.get_user_permissions(user.id).unwrap();

        let perm = permissions.iter()
            .find(|p| p.resource == "users" && p.action == "update")
            .unwrap();

        assert!(!perm.allowed);
    }

    #[test]
    fn test_user_effective_permissions() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        // Role grants read on events
        db.set_role_permission(role.id, "events", "read", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        let permissions = db.get_user_effective_permissions(user.id).unwrap();

        let perm = permissions.iter()
            .find(|p| p.resource == "events" && p.action == "read");

        assert!(perm.is_some());
        assert!(perm.unwrap().allowed);
    }

    #[test]
    fn test_user_override_denies_role_permission() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        // Role grants permission
        db.set_role_permission(role.id, "subjects", "delete", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User override denies it
        db.set_user_permission(user.id, "subjects", "delete", false, None).unwrap();

        let permissions = db.get_user_effective_permissions(user.id).unwrap();

        let perm = permissions.iter()
            .find(|p| p.resource == "subjects" && p.action == "delete")
            .unwrap();

        assert!(!perm.allowed);
    }

    // =============================================================================
    // RATE LIMITING TESTS
    // =============================================================================

    #[test]
    fn test_rate_limit_within_limit() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (_, key_info) = db.create_api_key(user.id, None, None, None, None).unwrap();

        // Make 10 requests (well under limit of 100)
        for _ in 0..10 {
            let result = db.check_rate_limit(Some(key_info.id), Some("127.0.0.1"), Some("/api/test"));
            assert!(result.is_ok());
        }
    }

    #[test]
    fn test_rate_limit_exceeded() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (_, key_info) = db.create_api_key(user.id, None, None, None, None).unwrap();

        // Hit rate limit (100 requests)
        for _ in 0..100 {
            let _ = db.check_rate_limit(Some(key_info.id), Some("127.0.0.1"), Some("/api/test"));
        }

        // 101st request should fail
        let result = db.check_rate_limit(Some(key_info.id), Some("127.0.0.1"), Some("/api/test"));
        assert!(matches!(result, Err(DatabaseError::RateLimitExceeded(_))));
    }

    // =============================================================================
    // AUDIT LOG TESTS
    // =============================================================================

    #[test]
    fn test_create_audit_log() {
        let db = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        db.create_audit_log(
            Some(user.id),
            None,
            "user_created",
            Some("user"),
            Some(&user.id.to_string()),
            Some("/admin/users"),
            Some("POST"),
            Some("127.0.0.1"),
            None,
            None,
            None,
            true,
            None,
        ).unwrap();

        let query = AuditLogQuery {
            user_id: Some(user.id),
            action_type: None,
            resource_type: None,
            success: None,
            start_timestamp: None,
            end_timestamp: None,
            limit: None,
            offset: None,
        };

        let logs = db.query_audit_logs(&query).unwrap();
        assert!(!logs.is_empty());
    }

    #[test]
    fn test_query_audit_logs_by_action() {
        let db = common::create_test_db();

        db.create_audit_log(
            None, None, "login", None, None, None, None, None, None, None, None, true, None
        ).unwrap();

        let query = AuditLogQuery {
            user_id: None,
            action_type: Some("login".to_string()),
            resource_type: None,
            success: None,
            start_timestamp: None,
            end_timestamp: None,
            limit: None,
            offset: None,
        };

        let logs = db.query_audit_logs(&query).unwrap();
        assert!(!logs.is_empty());
    }

    // =============================================================================
    // SYSTEM CONFIG TESTS
    // =============================================================================

    #[test]
    fn test_list_system_config() {
        let db = common::create_test_db();

        let config = db.list_system_config().unwrap();

        // Should have at least read_only config
        assert!(!config.is_empty());
    }

    #[test]
    fn test_update_system_config() {
        let db = common::create_test_db();

        let updated = db.update_system_config("read_only_mode", "1", None).unwrap();

        assert_eq!(updated.key, "read_only_mode");
        assert_eq!(updated.value, "1");
    }
}
