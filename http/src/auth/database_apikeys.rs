// Ave HTTP Auth System - API Key Database Operations
//
// This module provides database operations for API keys

use super::crypto::{
    extract_key_prefix, generate_api_key, hash_api_key,
};
use super::database::{AuthDatabase, DatabaseError};
use super::models::*;
use rusqlite::{OptionalExtension, Result as SqliteResult, params};

// =============================================================================
// API KEY OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Internal: Get API key info by ID without acquiring lock
    fn get_api_key_info_internal(
        conn: &rusqlite::Connection,
        key_id: i64,
    ) -> Result<ApiKeyInfo, DatabaseError> {

        conn.query_row(
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             WHERE k.id = ?1",
            params![key_id],
            |row| {
                Ok(ApiKeyInfo {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    username: row.get(2)?,
                    key_prefix: row.get(3)?,
                    name: row.get(4)?,
                    description: row.get(5)?,
                    created_at: row.get(6)?,
                    expires_at: row.get(7)?,
                    revoked: row.get(8)?,
                    revoked_at: row.get(9)?,
                    revoked_reason: row.get(10)?,
                    last_used_at: row.get(11)?,
                    last_used_ip: row.get(12)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFoundError(format!("API key {} not found", key_id)))
    }

    /// Get API key info by ID
    pub fn get_api_key_info(
        &self,
        key_id: i64,
    ) -> Result<ApiKeyInfo, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_api_key_info_internal(&conn, key_id)
    }

    /// Create a new API key for a user
    pub fn create_api_key(
        &self,
        user_id: i64,
        name: Option<&str>,
        description: Option<&str>,
        expires_in_seconds: Option<i64>,
    ) -> Result<(String, ApiKeyInfo), DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if user exists and is active
        let user = AuthDatabase::get_user_by_id_internal(&conn, user_id)?;
        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "User account is not active".to_string(),
            ));
        }

        // Check max keys per user limit
        if self.config.api_key.max_keys_per_user > 0 {
            let key_count: i64 = conn
                .query_row(
                    "SELECT COUNT(*) FROM api_keys WHERE user_id = ?1 AND revoked = 0",
                    params![user_id],
                    |row| row.get(0),
                )
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            if key_count >= self.config.api_key.max_keys_per_user as i64 {
                return Err(DatabaseError::ValidationError(format!(
                    "Maximum number of API keys ({}) reached for this user",
                    self.config.api_key.max_keys_per_user
                )));
            }
        }

        // Generate API key
        let api_key = generate_api_key();

        // Extract visible prefix
        let key_prefix = extract_key_prefix(&api_key);

        // Hash the key for storage
        let key_hash = hash_api_key(&api_key);

        // Calculate expiration
        let now = Self::now();
        let config_ttl = self.config.api_key.default_ttl_seconds;
        let effective_ttl = match expires_in_seconds {
            Some(ttl) if ttl > 0 => {
                if config_ttl > 0 {
                    Some(std::cmp::min(ttl, config_ttl))
                } else {
                    Some(ttl)
                }
            }
            Some(0) | None => {
                if config_ttl > 0 {
                    Some(config_ttl)
                } else {
                    None
                }
            }
            _ => None,
        };
        let expires_at = effective_ttl.map(|ttl| now + ttl);

        // Insert API key
        conn.execute(
            "INSERT INTO api_keys (user_id, key_hash, key_prefix, name, description, expires_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![user_id, key_hash, key_prefix, name, description, expires_at],
        ).map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        let key_id = conn.last_insert_rowid();

        // Get key info
        let key_info = Self::get_api_key_info_internal(&conn, key_id)?;

        Ok((api_key, key_info))
    }

    /// List API keys for a user
    pub fn list_user_api_keys(
        &self,
        user_id: i64,
        include_revoked: bool,
    ) -> Result<Vec<ApiKeyInfo>, DatabaseError> {
        let conn = self.lock_conn()?;

        let query = if include_revoked {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             WHERE k.user_id = ?1
             ORDER BY k.created_at DESC"
        } else {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             WHERE k.user_id = ?1 AND k.revoked = 0
             ORDER BY k.created_at DESC"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let keys = stmt
            .query_map(params![user_id], |row| {
                Ok(ApiKeyInfo {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    username: row.get(2)?,
                    key_prefix: row.get(3)?,
                    name: row.get(4)?,
                    description: row.get(5)?,
                    created_at: row.get(6)?,
                    expires_at: row.get(7)?,
                    revoked: row.get(8)?,
                    revoked_at: row.get(9)?,
                    revoked_reason: row.get(10)?,
                    last_used_at: row.get(11)?,
                    last_used_ip: row.get(12)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(keys)
    }

    /// List all API keys (admin)
    pub fn list_all_api_keys(
        &self,
        include_revoked: bool,
    ) -> Result<Vec<ApiKeyInfo>, DatabaseError> {
        let conn = self.lock_conn()?;

        let query = if include_revoked {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             ORDER BY k.created_at DESC"
        } else {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             WHERE k.revoked = 0
             ORDER BY k.created_at DESC"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let keys = stmt
            .query_map([], |row| {
                Ok(ApiKeyInfo {
                    id: row.get(0)?,
                    user_id: row.get(1)?,
                    username: row.get(2)?,
                    key_prefix: row.get(3)?,
                    name: row.get(4)?,
                    description: row.get(5)?,
                    created_at: row.get(6)?,
                    expires_at: row.get(7)?,
                    revoked: row.get(8)?,
                    revoked_at: row.get(9)?,
                    revoked_reason: row.get(10)?,
                    last_used_at: row.get(11)?,
                    last_used_ip: row.get(12)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(keys)
    }

    /// Revoke an API key
    pub fn revoke_api_key(
        &self,
        key_id: i64,
        revoked_by: Option<i64>,
        reason: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        let now = Self::now();

        conn.execute(
            "UPDATE api_keys
             SET revoked = 1, revoked_at = ?1, revoked_by = ?2, revoked_reason = ?3
             WHERE id = ?4",
            params![now, revoked_by, reason, key_id],
        ).map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Ok(())
    }

    /// Revoke all API keys for a user
    /// Internal: Revoke all API keys for a user without acquiring lock
    pub(crate) fn revoke_user_api_keys_internal(
        conn: &rusqlite::Connection,
        user_id: i64,
        revoked_by: Option<i64>,
        reason: &str,
    ) -> Result<(), DatabaseError> {
        let now = Self::now();

        conn.execute(
            "UPDATE api_keys
             SET revoked = 1, revoked_at = ?1, revoked_by = ?2, revoked_reason = ?3
             WHERE user_id = ?4 AND revoked = 0",
            params![now, revoked_by, reason, user_id],
        ).map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Ok(())
    }

    /// Verify an API key and return AuthContext
    pub fn verify_api_key(
        &self,
        api_key: &str,
    ) -> Result<AuthContext, DatabaseError> {
        let conn = self.lock_conn()?;

        let key_hash = hash_api_key(api_key);

        // Get API key from database
        let (key_id, user_id, revoked, expires_at): (
            i64,
            i64,
            bool,
            Option<i64>,
        ) = conn
            .query_row(
                "SELECT id, user_id, revoked, expires_at
                 FROM api_keys
                 WHERE key_hash = ?1",
                params![key_hash],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .ok_or_else(|| {
                DatabaseError::PermissionDenied("Invalid API key".to_string())
            })?;

        // Check if revoked
        if revoked {
            return Err(DatabaseError::PermissionDenied(
                "API key has been revoked".to_string(),
            ));
        }

        // Check if expired
        if let Some(exp) = expires_at {
            let now = Self::now();
            if exp < now {
                return Err(DatabaseError::PermissionDenied(
                    "API key has expired".to_string(),
                ));
            }
        }

        // Get user
        let user = AuthDatabase::get_user_by_id_internal(&conn, user_id)?;

        // Check if user is active
        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "User account is not active".to_string(),
            ));
        }

        // Check if account is locked
        if let Some(locked_until) = user.locked_until {
            if locked_until > Self::now() {
                return Err(DatabaseError::AccountLocked(
                    "Account is temporarily locked".to_string(),
                ));
            }
        }

        // Get user roles
        let roles = AuthDatabase::get_user_roles_internal(&conn, user_id)?;

        // Update last used timestamp
        let now = Self::now();
        conn.execute(
            "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
            params![now, key_id],
        ).ok(); // Ignore errors on usage tracking

        // Get effective permissions - need to drop lock first
        drop(conn);
        let permissions = self.get_effective_permissions(user_id)?;

        Ok(AuthContext {
            user_id,
            username: user.username,
            is_superadmin: user.is_superadmin,
            roles,
            permissions,
            api_key_id: key_id,
            ip_address: None,
        })
    }

    /// Update API key last used timestamp and IP
    pub fn update_api_key_usage(
        &self,
        key_id: i64,
        ip_address: Option<&str>,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        let now = Self::now();

        conn.execute(
            "UPDATE api_keys SET last_used_at = ?1, last_used_ip = ?2 WHERE id = ?3",
            params![now, ip_address, key_id],
        ).map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Ok(())
    }

    /// Delete expired API keys
    pub fn cleanup_expired_api_keys(&self) -> Result<usize, DatabaseError> {
        let conn = self.lock_conn()?;

        let now = Self::now();

        // If a default TTL is configured, backfill expires_at for legacy keys
        if self.config.api_key.default_ttl_seconds > 0 {
            conn.execute(
                "UPDATE api_keys
                 SET expires_at = created_at + ?1
                 WHERE expires_at IS NULL AND revoked = 0",
                params![self.config.api_key.default_ttl_seconds],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        let deleted = conn
            .execute(
                "DELETE FROM api_keys
             WHERE expires_at IS NOT NULL AND expires_at < ?1",
                params![now],
            )
            .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        Ok(deleted)
    }
}
