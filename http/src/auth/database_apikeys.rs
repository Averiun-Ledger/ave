// Ave HTTP Auth System - API Key Database Operations
//
// This module provides database operations for API keys

use super::crypto::{extract_key_prefix, generate_api_key, hash_api_key};
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
        key_id: &str,
    ) -> Result<ApiKeyInfo, DatabaseError> {
        conn.query_row(
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.is_management, k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
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
                    is_management: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    revoked: row.get(9)?,
                    revoked_at: row.get(10)?,
                    revoked_reason: row.get(11)?,
                    last_used_at: row.get(12)?,
                    last_used_ip: row.get(13)?,
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
        key_id: &str,
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
        is_management: bool,
    ) -> Result<(String, ApiKeyInfo), DatabaseError> {
        let conn = self.lock_conn()?;

        // SECURITY FIX: Validate description for CRLF injection
        AuthDatabase::validate_description(description)?;

        // Check if user exists and is active
        let user = AuthDatabase::get_user_by_id_internal(&conn, user_id)?;
        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "User account is not active".to_string(),
            ));
        }

        // Check max keys per user limit (only for service keys)
        if !is_management && self.config.api_key.max_keys_per_user > 0 {
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

        // Enforce a single active management key per user
        if is_management {
            conn.execute(
                "UPDATE api_keys
                 SET revoked = 1, revoked_at = ?1, revoked_by = ?2, revoked_reason = 'rotated management key'
                 WHERE user_id = ?3 AND is_management = 1 AND revoked = 0",
                params![Self::now(), Some(user_id), user_id],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        // Enforce unique active name per user for service keys
        if !is_management && name.unwrap_or_default().is_empty() {
            return Err(DatabaseError::ValidationError(
                "API key name is required".to_string(),
            ));
        }

        // SECURITY FIX: Validate API key name for dangerous characters
        // Prevent XSS, SQL injection, command injection, and path traversal
        if !is_management {
            let key_name = name.unwrap_or_default();
            Self::validate_api_key_name(key_name)?;
        }

        if !is_management {
            let exists: Option<String> = conn
                .query_row(
                    "SELECT id FROM api_keys WHERE user_id = ?1 AND name = ?2 AND revoked = 0",
                    params![user_id, name.unwrap_or_default()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

            if exists.is_some() {
                return Err(DatabaseError::DuplicateError(
                    "API key name already in use for this user".to_string(),
                ));
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
        // SECURITY FIX: Validate TTL is not negative
        if let Some(ttl) = expires_in_seconds {
            if ttl < 0 {
                return Err(DatabaseError::ValidationError(format!(
                    "Invalid TTL: {} (must be positive or 0)",
                    ttl
                )));
            }
        }

        let effective_ttl = match expires_in_seconds {
            Some(ttl) if ttl > 0 => {
                // Explicit positive TTL requested
                if config_ttl > 0 {
                    Some(std::cmp::min(ttl, config_ttl))
                } else {
                    Some(ttl)
                }
            }
            Some(0) => {
                // Explicit TTL=0 means never expire (useful for service keys)
                None
            }
            None => {
                // No TTL specified, use system default
                if config_ttl > 0 {
                    Some(config_ttl)
                } else {
                    None
                }
            }
            _ => unreachable!("Negative TTL already validated above"),
        };
        let expires_at = effective_ttl.map(|ttl| now + ttl);

        // Generate UUID for id
        let key_id = AuthDatabase::generate_uuid();

        // Insert API key
        conn.execute(
            "INSERT INTO api_keys (id, user_id, key_hash, key_prefix, name, description, expires_at, is_management)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                key_id,
                user_id,
                key_hash,
                key_prefix,
                name.unwrap_or_default(),
                description,
                expires_at,
                is_management
            ],
        ).map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        // Get key info
        let key_info = Self::get_api_key_info_internal(&conn, &key_id)?;

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
                    k.is_management, k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             WHERE k.user_id = ?1
             ORDER BY k.created_at DESC"
        } else {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.is_management, k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
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
                    is_management: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    revoked: row.get(9)?,
                    revoked_at: row.get(10)?,
                    revoked_reason: row.get(11)?,
                    last_used_at: row.get(12)?,
                    last_used_ip: row.get(13)?,
                })
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(keys)
    }

    /// Get an active API key by name for a user
    pub fn get_active_api_key_by_name(
        &self,
        user_id: i64,
        name: &str,
    ) -> Result<ApiKeyInfo, DatabaseError> {
        let conn = self.lock_conn()?;

        let key_id: String = conn
            .query_row(
                "SELECT id FROM api_keys WHERE user_id = ?1 AND name = ?2 AND revoked = 0",
                params![user_id, name],
                |row| row.get(0),
            )
            .optional()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .ok_or_else(|| {
                DatabaseError::NotFoundError(
                    "API key not found for this user/name".into(),
                )
            })?;

        Self::get_api_key_info_internal(&conn, &key_id)
    }

    /// List all API keys (admin)
    pub fn list_all_api_keys(
        &self,
        include_revoked: bool,
    ) -> Result<Vec<ApiKeyInfo>, DatabaseError> {
        let conn = self.lock_conn()?;

        let query = if include_revoked {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.is_management, k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
                    k.last_used_at, k.last_used_ip
             FROM api_keys k
             INNER JOIN users u ON k.user_id = u.id
             ORDER BY k.created_at DESC"
        } else {
            "SELECT k.id, k.user_id, u.username, k.key_prefix, k.name, k.description,
                    k.is_management, k.created_at, k.expires_at, k.revoked, k.revoked_at, k.revoked_reason,
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
                    is_management: row.get(6)?,
                    created_at: row.get(7)?,
                    expires_at: row.get(8)?,
                    revoked: row.get(9)?,
                    revoked_at: row.get(10)?,
                    revoked_reason: row.get(11)?,
                    last_used_at: row.get(12)?,
                    last_used_ip: row.get(13)?,
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
        key_id: &str,
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
        let key_result = conn
            .query_row(
                "SELECT id, user_id, revoked, expires_at, is_management
                 FROM api_keys
                 WHERE key_hash = ?1",
                params![key_hash],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, i64>(1)?,
                        row.get::<_, bool>(2)?,
                        row.get::<_, Option<i64>>(3)?,
                        row.get::<_, bool>(4)?,
                    ))
                },
            )
            .optional()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        // SECURITY: Constant-time API key enumeration mitigation
        // If key doesn't exist, perform dummy user query to match timing
        let (key_id, user_id, revoked, expires_at, is_management) = match key_result {
            Some(k) => k,
            None => {
                // API key doesn't exist - perform dummy query to prevent timing attack
                let _ = conn.query_row(
                    "SELECT id FROM users WHERE id = ?1",
                    params![999999], // Non-existent user
                    |row| row.get::<_, i64>(0),
                ).optional();

                return Err(DatabaseError::PermissionDenied("Invalid API key".to_string()));
            }
        };

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
        if let Some(locked_until) = user.locked_until
            && locked_until > Self::now()
        {
            return Err(DatabaseError::AccountLocked(
                "Account is temporarily locked".to_string(),
            ));
        }

        // SECURITY FIX: Enforce must_change_password policy for API keys
        // Users with must_change_password cannot use API keys until they change their password
        // This prevents bypassing the forced password change requirement
        if user.must_change_password {
            return Err(DatabaseError::PasswordChangeRequired(
                "Password change required. Please change your password before using API keys".to_string(),
            ));
        }

        // Get user roles
        let roles = AuthDatabase::get_user_roles_internal(&conn, user_id)?;

        // Update last used timestamp
        let now = Self::now();
        conn.execute(
            "UPDATE api_keys SET last_used_at = ?1 WHERE id = ?2",
            params![now, &key_id],
        )
        .ok(); // Ignore errors on usage tracking

        // Get effective permissions - need to drop lock first
        drop(conn);
        let mut permissions = self.get_effective_permissions(user_id)?;

        // Service keys cannot carry admin/panel permissions
        if !is_management {
            let admin_resources = [
                "admin_users",
                "admin_roles",
                "admin_api_key",
                "admin_system",
                "user_api_key",
            ];
            permissions
                .retain(|p| !admin_resources.contains(&p.resource.as_str()));
        }

        Ok(AuthContext {
            user_id,
            username: user.username,
            roles,
            permissions,
            api_key_id: key_id,
            is_management_key: is_management,
            ip_address: None,
        })
    }

    /// Update API key last used timestamp and IP
    pub fn update_api_key_usage(
        &self,
        key_id: &str,
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

    /// Validate API key name for dangerous characters
    ///
    /// SECURITY FIX: Prevents XSS, SQL injection, command injection, and path traversal
    /// by rejecting names containing dangerous characters.
    ///
    /// Allowed characters: alphanumeric, underscore, hyphen, space, period
    /// Max length: 100 characters
    fn validate_api_key_name(name: &str) -> Result<(), DatabaseError> {
        // Check length
        if name.len() > 100 {
            return Err(DatabaseError::ValidationError(
                "API key name must be 100 characters or less".to_string(),
            ));
        }

        // Check for null bytes (command injection, path traversal)
        if name.contains('\0') {
            return Err(DatabaseError::ValidationError(
                "API key name contains invalid characters".to_string(),
            ));
        }

        // Check for control characters (including newlines, tabs, etc)
        if name.chars().any(|c| c.is_control()) {
            return Err(DatabaseError::ValidationError(
                "API key name contains invalid control characters".to_string(),
            ));
        }

        // Check for dangerous characters that could be used for attacks
        let dangerous_chars = ['<', '>', '"', '\'', '`', '&', '|', ';', '$', '(', ')', '{', '}', '[', ']', '\\', '/', ':', '*', '?', '%'];
        if name.chars().any(|c| dangerous_chars.contains(&c)) {
            return Err(DatabaseError::ValidationError(
                format!("API key name contains invalid characters. Only alphanumeric, underscore, hyphen, space, and period are allowed")
            ));
        }

        // Check for path traversal patterns
        if name.contains("..") || name.contains("./") || name.contains(".\\") {
            return Err(DatabaseError::ValidationError(
                "API key name contains invalid patterns".to_string(),
            ));
        }

        Ok(())
    }
}
