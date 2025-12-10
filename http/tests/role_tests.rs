// Ave HTTP Auth System - Role Change Tests
//
// Tests for role changes and their effects on API keys and permissions

mod common;

use ave_http::auth::database::DatabaseError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_api_keys_revoked_when_role_added() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (api_key, _) =
            db.create_api_key(user.id, Some("key1"), None, None, false).unwrap();

        // Verify key works
        assert!(db.verify_api_key(&api_key).is_ok());

        let role = db.create_role("editor", None, None).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // API key should be revoked
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_api_keys_revoked_when_role_removed() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        db.assign_role_to_user(user.id, role.id, None).unwrap();

        let (api_key, _) =
            db.create_api_key(user.id, Some("key1"), None, None, false).unwrap();

        // Verify key works
        assert!(db.verify_api_key(&api_key).is_ok());

        // Remove role from user
        db.remove_role_from_user(user.id, role.id).unwrap();

        // API key should be revoked
        let result = db.verify_api_key(&api_key);
        assert!(matches!(result, Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_permissions_change_when_role_added() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        // Role has read permission
        db.set_role_permission(role.id, "subjects", "get", true).unwrap();

        // User doesn't have permission yet
        let perms_before = db.get_user_effective_permissions(user.id).unwrap();
        assert!(!perms_before.iter().any(|p| p.resource == "subjects" && p.action == "get" && p.allowed));

        // Assign role
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User should now have permission
        let perms_after = db.get_user_effective_permissions(user.id).unwrap();
        assert!(perms_after.iter().any(|p| p.resource == "subjects" && p.action == "get" && p.allowed));
    }

    #[test]
    fn test_permissions_change_when_role_removed() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        // Role has update permission
        db.set_role_permission(role.id, "events", "post", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User has permission
        let perms_before = db.get_user_effective_permissions(user.id).unwrap();
        assert!(perms_before.iter().any(|p| p.resource == "events" && p.action == "post" && p.allowed));

        // Remove role
        db.remove_role_from_user(user.id, role.id).unwrap();

        // User should no longer have permission
        let perms_after = db.get_user_effective_permissions(user.id).unwrap();
        assert!(!perms_after.iter().any(|p| p.resource == "events" && p.action == "post" && p.allowed));
    }

    #[test]
    fn test_multiple_role_changes() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let (api_key1, _) =
            db.create_api_key(user.id, Some("key1"), None, None, false).unwrap();

        let role1 = db.create_role("role1", None, None).unwrap();
        db.assign_role_to_user(user.id, role1.id, None).unwrap();

        // First key should be revoked
        assert!(matches!(db.verify_api_key(&api_key1), Err(DatabaseError::PermissionDenied(_))));

        // Create new key
        let (api_key2, _) =
            db.create_api_key(user.id, Some("key2"), None, None, false).unwrap();

        let role2 = db.create_role("role2", None, None).unwrap();
        db.assign_role_to_user(user.id, role2.id, None).unwrap();

        // Second key should be revoked
        assert!(matches!(db.verify_api_key(&api_key2), Err(DatabaseError::PermissionDenied(_))));

        // First key still revoked
        assert!(matches!(db.verify_api_key(&api_key1), Err(DatabaseError::PermissionDenied(_))));
    }

    #[test]
    fn test_user_with_multiple_roles_permission_merge() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role1 = db.create_role("reader", None, None).unwrap();
        let role2 = db.create_role("writer", None, None).unwrap();

        // role1 grants read
        db.set_role_permission(role1.id, "subjects", "get", true).unwrap();

        // role2 grants update
        db.set_role_permission(role2.id, "subjects", "post", true).unwrap();

        // Assign both roles
        db.assign_role_to_user(user.id, role1.id, None).unwrap();
        db.assign_role_to_user(user.id, role2.id, None).unwrap();

        // User should have both permissions
        let perms = db.get_user_effective_permissions(user.id).unwrap();

        assert!(perms.iter().any(|p| p.resource == "subjects" && p.action == "get" && p.allowed));
        assert!(perms.iter().any(|p| p.resource == "subjects" && p.action == "post" && p.allowed));
    }

    #[test]
    fn test_user_override_persists_through_role_changes() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();

        // User has explicit deny
        db.set_user_permission(user.id, "users", "delete", false, None).unwrap();

        // Add role that grants delete
        let role = db.create_role("user_admin", None, None).unwrap();
        db.set_role_permission(role.id, "users", "delete", true).unwrap();
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // User override should still deny
        let perms = db.get_user_effective_permissions(user.id).unwrap();
        let perm = perms.iter()
            .find(|p| p.resource == "users" && p.action == "delete")
            .unwrap();

        assert!(!perm.allowed);
    }

    #[test]
    fn test_role_permission_modification_affects_all_users() {
        let (db, _dirs) = common::create_test_db();

        let user1 = db.create_user("user1", "TestPass123!", false, None, None).unwrap();
        let user2 = db.create_user("user2", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("editor", None, None).unwrap();

        db.assign_role_to_user(user1.id, role.id, None).unwrap();
        db.assign_role_to_user(user2.id, role.id, None).unwrap();

        // Grant permission to role
        db.set_role_permission(role.id, "subjects", "post", true).unwrap();

        // Both users should have the permission
        let perms1 = db.get_user_effective_permissions(user1.id).unwrap();
        let perms2 = db.get_user_effective_permissions(user2.id).unwrap();

        assert!(perms1.iter().any(|p| p.resource == "subjects" && p.action == "post" && p.allowed));
        assert!(perms2.iter().any(|p| p.resource == "subjects" && p.action == "post" && p.allowed));

        // Revoke permission from role
        db.set_role_permission(role.id, "subjects", "post", false).unwrap();

        // Both users should lose the permission
        let perms1 = db.get_user_effective_permissions(user1.id).unwrap();
        let perms2 = db.get_user_effective_permissions(user2.id).unwrap();

        assert!(!perms1.iter().any(|p| p.resource == "subjects" && p.action == "post" && p.allowed));
        assert!(!perms2.iter().any(|p| p.resource == "subjects" && p.action == "post" && p.allowed));
    }

    #[test]
    fn test_deny_permission_overrides_multiple_allows() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role1 = db.create_role("role1", None, None).unwrap();
        let role2 = db.create_role("role2", None, None).unwrap();

        // Both roles grant permission
        db.set_role_permission(role1.id, "subjects", "delete", true).unwrap();
        db.set_role_permission(role2.id, "subjects", "delete", true).unwrap();

        db.assign_role_to_user(user.id, role1.id, None).unwrap();
        db.assign_role_to_user(user.id, role2.id, None).unwrap();

        // User-specific deny
        db.set_user_permission(user.id, "subjects", "delete", false, None).unwrap();

        // Deny should override both role allows
        let perms = db.get_user_effective_permissions(user.id).unwrap();
        let perm = perms.iter()
            .find(|p| p.resource == "subjects" && p.action == "delete")
            .unwrap();

        assert!(!perm.allowed);
    }

    #[test]
    fn test_deleted_roles_removed_from_users() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("temp_role", None, None).unwrap();

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

    #[test]
    fn test_role_with_ttl() {
        let (db, _dirs) = common::create_test_db();

        let user = db.create_user("testuser", "TestPass123!", false, None, None).unwrap();
        let role = db.create_role("temp_editor", None, Some(2)).unwrap(); // 2 second TTL

        // Assign role
        db.assign_role_to_user(user.id, role.id, None).unwrap();

        // Should have role immediately
        let roles = db.get_user_roles(user.id).unwrap();
        assert!(roles.contains(&"temp_editor".to_string()));

        // Note: TTL expiration would need to be implemented in get_user_roles
        // For now, this test verifies that roles with TTL can be created and assigned
        // The actual TTL enforcement would happen at query time
    }
}
