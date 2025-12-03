// Ave HTTP Auth System - Database Layer Extensions
//
// This module extends the database layer with additional operations

use super::database::{AuthDatabase, DatabaseError};
use super::models::*;
use rusqlite::{OptionalExtension, Result as SqliteResult, params};

// =============================================================================
// ROLE OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Internal: Get role by ID without acquiring lock
    pub(crate) fn get_role_by_id_internal(
        conn: &rusqlite::Connection,
        role_id: i64,
    ) -> Result<Role, DatabaseError> {
        conn.query_row(
            "SELECT id, name, description, default_ttl_seconds, is_system, is_deleted,
                    created_at, updated_at
             FROM roles
             WHERE id = ?1 AND is_deleted = 0",
            params![role_id],
            |row| {
                Ok(Role {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    default_ttl_seconds: row.get(3)?,
                    is_system: row.get(4)?,
                    is_deleted: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFoundError(format!("Role with id {} not found", role_id)))
    }

    /// Internal: Get role by name without acquiring lock
    pub(crate) fn get_role_by_name_internal(
        conn: &rusqlite::Connection,
        name: &str,
    ) -> Result<Role, DatabaseError> {
        conn.query_row(
            "SELECT id, name, description, default_ttl_seconds, is_system, is_deleted,
                    created_at, updated_at
             FROM roles
             WHERE name = ?1 AND is_deleted = 0",
            params![name],
            |row| {
                Ok(Role {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    default_ttl_seconds: row.get(3)?,
                    is_system: row.get(4)?,
                    is_deleted: row.get(5)?,
                    created_at: row.get(6)?,
                    updated_at: row.get(7)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFoundError(format!("Role '{}' not found", name)))
    }

    /// Create a new role
    pub fn create_role(
        &self,
        name: &str,
        description: Option<&str>,
        default_ttl_seconds: Option<i64>,
    ) -> Result<Role, DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if role already exists
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM roles WHERE name = ?1 AND is_deleted = 0)",
                params![name],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        if exists {
            return Err(DatabaseError::DuplicateError(format!(
                "Role '{}' already exists",
                name
            )));
        }

        conn.execute(
            "INSERT INTO roles (name, description, default_ttl_seconds)
             VALUES (?1, ?2, ?3)",
            params![name, description, default_ttl_seconds],
        )
        .map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        let role_id = conn.last_insert_rowid();
        Self::get_role_by_id_internal(&conn, role_id)
    }

    /// Get role by ID
    pub fn get_role_by_id(&self, role_id: i64) -> Result<Role, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_role_by_id_internal(&conn, role_id)
    }

    /// Get role by name
    pub fn get_role_by_name(&self, name: &str) -> Result<Role, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_role_by_name_internal(&conn, name)
    }

    /// List all roles
    pub fn list_roles(&self) -> Result<Vec<RoleInfo>, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut stmt = conn.prepare(
            "SELECT r.id, r.name, r.description, r.default_ttl_seconds, r.is_system, r.created_at,
                    (SELECT COUNT(*) FROM role_permissions WHERE role_id = r.id) as permission_count
             FROM roles r
             WHERE r.is_deleted = 0
             ORDER BY r.name"
        ).map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let roles = stmt
            .query_map([], |row| {
                Ok(RoleInfo {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    default_ttl_seconds: row.get(3)?,
                    is_system: row.get(4)?,
                    created_at: row.get(5)?,
                    permission_count: row.get(6)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(roles)
    }

    /// Update role
    pub fn update_role(
        &self,
        role_id: i64,
        description: Option<&str>,
        default_ttl_seconds: Option<i64>,
    ) -> Result<Role, DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if role is system role
        let role = Self::get_role_by_id_internal(&conn, role_id)?;
        if role.is_system {
            return Err(DatabaseError::PermissionDenied(
                "Cannot modify system role".to_string(),
            ));
        }

        if let Some(desc) = description {
            conn.execute(
                "UPDATE roles SET description = ?1 WHERE id = ?2",
                params![desc, role_id],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        if let Some(ttl) = default_ttl_seconds {
            conn.execute(
                "UPDATE roles SET default_ttl_seconds = ?1 WHERE id = ?2",
                params![ttl, role_id],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        Self::get_role_by_id_internal(&conn, role_id)
    }

    /// Delete role (soft delete)
    pub fn delete_role(&self, role_id: i64) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if role is system role
        let role = Self::get_role_by_id_internal(&conn, role_id)?;
        if role.is_system {
            return Err(DatabaseError::PermissionDenied(
                "Cannot delete system role".to_string(),
            ));
        }

        conn.execute(
            "UPDATE roles SET is_deleted = 1 WHERE id = ?1",
            params![role_id],
        )
        .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Ok(())
    }
}

// =============================================================================
// RESOURCE AND ACTION OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Internal: Get resource by name without acquiring lock
    fn get_resource_by_name_internal(
        conn: &rusqlite::Connection,
        name: &str,
    ) -> Result<Resource, DatabaseError> {
        conn.query_row(
            "SELECT id, name, description, is_system, created_at
             FROM resources
             WHERE name = ?1",
            params![name],
            |row| {
                Ok(Resource {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_system: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| {
            DatabaseError::NotFoundError(format!(
                "Resource '{}' not found",
                name
            ))
        })
    }

    /// Internal: Get action by name without acquiring lock
    fn get_action_by_name_internal(
        conn: &rusqlite::Connection,
        name: &str,
    ) -> Result<Action, DatabaseError> {
        conn.query_row(
            "SELECT id, name, description, is_system, created_at
             FROM actions
             WHERE name = ?1",
            params![name],
            |row| {
                Ok(Action {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_system: row.get(3)?,
                    created_at: row.get(4)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| {
            DatabaseError::NotFoundError(format!("Action '{}' not found", name))
        })
    }

    /// List all resources
    pub fn list_resources(&self) -> Result<Vec<Resource>, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, description, is_system, created_at
             FROM resources
             ORDER BY name",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let resources = stmt
            .query_map([], |row| {
                Ok(Resource {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_system: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(resources)
    }

    /// List all actions
    pub fn list_actions(&self) -> Result<Vec<Action>, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT id, name, description, is_system, created_at
             FROM actions
             ORDER BY name",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let actions = stmt
            .query_map([], |row| {
                Ok(Action {
                    id: row.get(0)?,
                    name: row.get(1)?,
                    description: row.get(2)?,
                    is_system: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(actions)
    }

}

// =============================================================================
// PERMISSION OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Set role permission
    pub fn set_role_permission(
        &self,
        role_id: i64,
        resource: &str,
        action: &str,
        allowed: bool,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        // Get resource and action IDs
        let resource_id = Self::get_resource_by_name_internal(&conn, resource)?.id;
        let action_id = Self::get_action_by_name_internal(&conn, action)?.id;

        // Insert or replace permission
        conn.execute(
            "INSERT OR REPLACE INTO role_permissions (role_id, resource_id, action_id, allowed)
             VALUES (?1, ?2, ?3, ?4)",
            params![role_id, resource_id, action_id, allowed],
        ).map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        Ok(())
    }

    /// Remove role permission
    pub fn remove_role_permission(
        &self,
        role_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        let resource_id = Self::get_resource_by_name_internal(&conn, resource)?.id;
        let action_id = Self::get_action_by_name_internal(&conn, action)?.id;

        conn.execute(
            "DELETE FROM role_permissions
             WHERE role_id = ?1 AND resource_id = ?2 AND action_id = ?3",
            params![role_id, resource_id, action_id],
        )
        .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        Ok(())
    }

    /// Get role permissions
    pub fn get_role_permissions(
        &self,
        role_id: i64,
    ) -> Result<Vec<Permission>, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT res.name, act.name, rp.allowed
             FROM role_permissions rp
             INNER JOIN resources res ON rp.resource_id = res.id
             INNER JOIN actions act ON rp.action_id = act.id
             WHERE rp.role_id = ?1
             ORDER BY res.name, act.name",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let permissions = stmt
            .query_map(params![role_id], |row| {
                Ok(Permission {
                    resource: row.get(0)?,
                    action: row.get(1)?,
                    allowed: row.get(2)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(permissions)
    }

    /// Set user permission (override)
    pub fn set_user_permission(
        &self,
        user_id: i64,
        resource: &str,
        action: &str,
        allowed: bool,
        granted_by: Option<i64>,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        let resource_id = Self::get_resource_by_name_internal(&conn, resource)?.id;
        let action_id = Self::get_action_by_name_internal(&conn, action)?.id;

        conn.execute(
            "INSERT OR REPLACE INTO user_permissions (user_id, resource_id, action_id, allowed, granted_by)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![user_id, resource_id, action_id, allowed, granted_by],
        ).map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        Ok(())
    }

    /// Remove user permission
    pub fn remove_user_permission(
        &self,
        user_id: i64,
        resource: &str,
        action: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        let resource_id = Self::get_resource_by_name_internal(&conn, resource)?.id;
        let action_id = Self::get_action_by_name_internal(&conn, action)?.id;

        conn.execute(
            "DELETE FROM user_permissions
             WHERE user_id = ?1 AND resource_id = ?2 AND action_id = ?3",
            params![user_id, resource_id, action_id],
        )
        .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        Ok(())
    }

    /// Get user permissions (direct overrides only)
    pub fn get_user_permissions(
        &self,
        user_id: i64,
    ) -> Result<Vec<Permission>, DatabaseError> {
        let conn = self.lock_conn()?;

        let mut stmt = conn
            .prepare(
                "SELECT res.name, act.name, up.allowed
             FROM user_permissions up
             INNER JOIN resources res ON up.resource_id = res.id
             INNER JOIN actions act ON up.action_id = act.id
             WHERE up.user_id = ?1
             ORDER BY res.name, act.name",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let permissions = stmt
            .query_map(params![user_id], |row| {
                Ok(Permission {
                    resource: row.get(0)?,
                    action: row.get(1)?,
                    allowed: row.get(2)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(permissions)
    }

    /// Get effective permissions for a user (role + user overrides)
    pub fn get_effective_permissions(
        &self,
        user_id: i64,
    ) -> Result<Vec<Permission>, DatabaseError> {
        let conn = self.lock_conn()?;

        // Query that combines role permissions and user overrides
        // User permissions take precedence over role permissions
        let mut stmt = conn.prepare(
            "SELECT DISTINCT res.name, act.name,
                COALESCE(
                    (SELECT allowed FROM user_permissions up2
                     WHERE up2.user_id = ?1 AND up2.resource_id = res.id AND up2.action_id = act.id),
                    (SELECT MAX(CASE WHEN rp.allowed THEN 1 ELSE 0 END)
                     FROM role_permissions rp
                     INNER JOIN user_roles ur ON rp.role_id = ur.role_id
                     WHERE ur.user_id = ?1 AND rp.resource_id = res.id AND rp.action_id = act.id)
                ) as allowed
             FROM resources res
             CROSS JOIN actions act
             WHERE allowed IS NOT NULL
             ORDER BY res.name, act.name"
        ).map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let permissions = stmt
            .query_map(params![user_id], |row| {
                Ok(Permission {
                    resource: row.get(0)?,
                    action: row.get(1)?,
                    allowed: row.get(2)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(permissions)
    }

    /// Get effective permissions for a user
    /// This combines role permissions with user-specific permission overrides
    pub fn get_user_effective_permissions(
        &self,
        user_id: i64,
    ) -> Result<Vec<Permission>, DatabaseError> {
        let conn = self.lock_conn()?;

        // Get all effective permissions combining role permissions and user overrides
        let mut stmt = conn
            .prepare(
                "SELECT DISTINCT r.name as resource, a.name as action,
                    COALESCE(up.allowed, rp.allowed, 0) as allowed
             FROM resources r
             CROSS JOIN actions a
             LEFT JOIN user_roles ur ON ur.user_id = ?1
             LEFT JOIN roles ro ON ro.id = ur.role_id AND ro.is_deleted = 0
             LEFT JOIN role_permissions rp ON rp.role_id = ro.id
                                           AND rp.resource_id = r.id
                                           AND rp.action_id = a.id
             LEFT JOIN user_permissions up ON up.user_id = ?1
                                           AND up.resource_id = r.id
                                           AND up.action_id = a.id
             WHERE (rp.allowed IS NOT NULL OR up.allowed IS NOT NULL)
             ORDER BY r.name, a.name",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let permissions = stmt
            .query_map(params![user_id], |row| {
                Ok(Permission {
                    resource: row.get(0)?,
                    action: row.get(1)?,
                    allowed: row.get(2)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(permissions)
    }
}
