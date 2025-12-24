// Ave HTTP Auth System - Database Layer
//
// This module provides the database access layer for the auth system using SQLite

use crate::auth::validate_password;

use super::crypto::hash_password;
use super::models::*;
use ave_bridge::auth::AuthConfig;
use rusqlite::{Connection, OptionalExtension, Result as SqliteResult, params};
use std::{
    fs,
    path::Path,
    sync::{Arc, Mutex, MutexGuard},
};
use thiserror::Error;
use tracing::{debug, info};

// =============================================================================
// ERROR TYPE
// =============================================================================

#[derive(Debug, Error, Clone)]
pub enum DatabaseError {
    #[error("Initialization error: {0}")]
    InitializationError(String),

    #[error("Connection error: {0}")]
    ConnectionError(String),

    #[error("Migration error: {0}")]
    MigrationError(String),

    #[error("Query error: {0}")]
    QueryError(String),

    #[error("Insert error: {0}")]
    InsertError(String),

    #[error("Update error: {0}")]
    UpdateError(String),

    #[error("Delete error: {0}")]
    DeleteError(String),

    #[error("Validation error: {0}")]
    ValidationError(String),

    #[error("Crypto error: {0}")]
    CryptoError(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("Account locked: {0}")]
    AccountLocked(String),

    #[error("Rate limit exceeded: {0}")]
    RateLimitExceeded(String),

    #[error("Not found: {0}")]
    NotFoundError(String),

    #[error("Duplicate: {0}")]
    DuplicateError(String),

    #[error("Password change required: {0}")]
    PasswordChangeRequired(String),
}

// =============================================================================
// DATABASE SERVICE
// =============================================================================

// Dummy password hash for timing attack mitigation
// This is a real Argon2id hash generated with the same parameters as user passwords
// to ensure identical verification cost whether user exists or not
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$6bLVReaW/buHRwX6rLPCJA$KNXZtbxs0tqTOOuCkWFPldX2ri4wFgAVVFJqixUK/Kw";

/// Thread-safe database service for auth operations
#[derive(Clone)]
pub struct AuthDatabase {
    pub(crate) connection: Arc<Mutex<Connection>>,
    pub(crate) config: Arc<AuthConfig>,
}

impl AuthDatabase {
    /// Get a locked database connection with error handling
    pub(crate) fn lock_conn(
        &self,
    ) -> Result<MutexGuard<'_, Connection>, DatabaseError> {
        self.connection.lock().map_err(|e| {
            DatabaseError::ConnectionError(format!("DB lock poisoned: {}", e))
        })
    }

    /// Create a new AuthDatabase instance
    ///
    /// This will:
    /// 1. Create the database file if it doesn't exist
    /// 2. Run migrations to set up the schema
    /// 3. Bootstrap the superadmin account if configured
    pub fn new(
        config: AuthConfig,
        password: &str,
    ) -> Result<Self, DatabaseError> {
        // Create parent directory if it doesn't exist
        let path = config.database_path.clone();
        if !Path::new(&path).exists() {
            fs::create_dir_all(&path).map_err(|e| {
                DatabaseError::InitializationError(format!(
                    "Can not create auth dir: {}",
                    e
                ))
            })?;
        }

        let path = path.join("auth.db");

        // Open connection
        let connection = Connection::open(&path)
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        // Enable foreign keys
        connection
            .execute("PRAGMA foreign_keys = ON", [])
            .map_err(|e| DatabaseError::ConnectionError(e.to_string()))?;

        let db = Self {
            connection: Arc::new(Mutex::new(connection)),
            config: Arc::new(config),
        };

        // Run migrations
        db.run_migrations()?;

        // Bootstrap superadmin if needed
        db.bootstrap_superadmin(password)?;

        // Sync persisted system_config with runtime configuration values
        db.sync_system_config_with_runtime()?;

        Ok(db)
    }

    /// Run database migrations
    pub fn run_migrations(&self) -> Result<(), DatabaseError> {
        info!("Running database migrations...");

        let conn = self.lock_conn()?;

        // Read and execute migration files
        let migration_001 =
            include_str!("../../migrations/001_initial_schema.sql");
        conn.execute_batch(migration_001).map_err(|e| {
            DatabaseError::MigrationError(format!(
                "Migration 001 failed: {}",
                e
            ))
        })?;

        let migration_002 =
            include_str!("../../migrations/002_role_permissions.sql");
        conn.execute_batch(migration_002).map_err(|e| {
            DatabaseError::MigrationError(format!(
                "Migration 002 failed: {}",
                e
            ))
        })?;

        info!("Database migrations completed successfully");
        Ok(())
    }

    /// Update system_config table with current runtime configuration values
    fn sync_system_config_with_runtime(&self) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;
        let cfg = self.config.clone();

        let updates: &[(&str, String, &str)] = &[
            (
                "api_key_default_ttl_seconds",
                cfg.api_key.default_ttl_seconds.to_string(),
                "Default API key TTL in seconds",
            ),
            (
                "max_login_attempts",
                cfg.lockout.max_attempts.to_string(),
                "Maximum failed login attempts before account lockout",
            ),
            (
                "lockout_duration_seconds",
                cfg.lockout.duration_seconds.to_string(),
                "Account lockout duration in seconds",
            ),
            (
                "rate_limit_window_seconds",
                cfg.rate_limit.window_seconds.to_string(),
                "Rate limit time window in seconds",
            ),
            (
                "rate_limit_max_requests",
                cfg.rate_limit.max_requests.to_string(),
                "Maximum requests per window",
            ),
        ];

        for (key, value, desc) in updates {
            conn.execute(
                "INSERT INTO system_config (key, value, description)
                 VALUES (?1, ?2, ?3)
                 ON CONFLICT(key) DO UPDATE SET value = excluded.value, description = COALESCE(system_config.description, excluded.description)",
                params![key, value, desc],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        Ok(())
    }

    /// Bootstrap superadmin account on first run
    pub fn bootstrap_superadmin(
        &self,
        password: &str,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if any users exist
        let user_count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM users WHERE is_deleted = 0",
                [],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        if user_count > 0 {
            debug!("Users already exist, skipping superadmin bootstrap");
            return Ok(());
        }

        // Get superadmin config
        let superadmin = if !self.config.superadmin.is_empty() {
            self.config.superadmin.clone()
        } else {
            "admin".to_owned()
        };

        info!("Bootstrapping superadmin account: {}", superadmin);

        // Hash password
        let password_hash = hash_password(password).map_err(|e| {
            DatabaseError::CryptoError(format!(
                "Failed to hash superadmin password: {}",
                e
            ))
        })?;

        // Create superadmin user
        conn.execute(
            "INSERT INTO users (username, password_hash, is_superadmin, is_active)
             VALUES (?1, ?2, 1, 1)",
            params![superadmin, password_hash],
        ).map_err(|e| DatabaseError::InsertError(format!("Failed to create superadmin: {}", e)))?;

        let user_id = conn.last_insert_rowid();

        // Assign superadmin role
        let superadmin_role_id: i64 = conn
            .query_row(
                "SELECT id FROM roles WHERE name = 'superadmin'",
                [],
                |row| row.get(0),
            )
            .map_err(|e| {
                DatabaseError::QueryError(format!(
                    "Failed to get superadmin role: {}",
                    e
                ))
            })?;

        conn.execute(
            "INSERT INTO user_roles (user_id, role_id) VALUES (?1, ?2)",
            params![user_id, superadmin_role_id],
        )
        .map_err(|e| {
            DatabaseError::InsertError(format!(
                "Failed to assign superadmin role: {}",
                e
            ))
        })?;

        info!("Superadmin account created successfully");
        Ok(())
    }

    /// Get the current Unix timestamp in seconds
    pub(crate) fn now() -> i64 {
        time::OffsetDateTime::now_utc().unix_timestamp()
    }

    /// Generate a UUID v4 string (for API key public IDs)
    pub(crate) fn generate_uuid() -> String {
        use rand::Rng;
        let mut rng = rand::rng();

        format!(
            "{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
            rng.random::<u32>(),
            rng.random::<u16>(),
            0x4000 | (rng.random::<u16>() & 0x0FFF), // Version 4
            0x8000 | (rng.random::<u16>() & 0x3FFF), // Variant 1
            rng.random::<u64>() & 0xFFFF_FFFF_FFFF,
        )
    }

    /// Override default API key TTL on an existing instance (used for tests/config reloads)
    #[allow(dead_code)] // primarily used in tests / config reload scenarios
    pub fn set_default_api_key_ttl(&mut self, ttl: i64) {
        Arc::make_mut(&mut self.config).api_key.default_ttl_seconds = ttl;
    }
}

// =============================================================================
// USER OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Create a new user with explicit active flag
    pub fn create_user(
        &self,
        username: &str,
        password: &str,
        is_superadmin: bool,
        role_ids: Option<Vec<i64>>,
        created_by: Option<i64>,
        must_change_password: Option<bool>,
    ) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;

        // SECURITY FIX: Validate username for CRLF and other attacks
        Self::validate_username(username)?;
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE username = ?1 AND is_deleted = 0)",
                params![username],
                |row| row.get(0),
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        if exists {
            return Err(DatabaseError::DuplicateError(format!(
                "Username '{}' already exists",
                username
            )));
        }

        // Validate password
        validate_password(password).map_err(DatabaseError::ValidationError)?;

        // Hash password
        let password_hash = hash_password(password).map_err(|e| {
            DatabaseError::CryptoError(format!(
                "Failed to hash password: {}",
                e
            ))
        })?;

        // Insert user
        let must_change = must_change_password.unwrap_or(true);
        conn.execute(
            "INSERT INTO users (username, password_hash, is_superadmin, is_active, must_change_password)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![username, password_hash, is_superadmin, true, must_change],
        ).map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        let user_id = conn.last_insert_rowid();

        // Assign roles if provided
        if let Some(roles) = role_ids {
            for role_id in roles {
                conn.execute(
                    "INSERT INTO user_roles (user_id, role_id, assigned_by) VALUES (?1, ?2, ?3)",
                    params![user_id, role_id, created_by],
                ).map_err(|e| DatabaseError::InsertError(format!("Failed to assign role: {}", e)))?;
            }
        }

        // Fetch and return the created user
        Self::get_user_by_id_internal(&conn, user_id)
    }

    /// Internal: Get user by ID without acquiring lock
    pub(crate) fn get_user_by_id_internal(
        conn: &Connection,
        user_id: i64,
    ) -> Result<User, DatabaseError> {
        conn.query_row(
            "SELECT id, username, password_hash, is_superadmin, is_active, is_deleted,
                    must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at
             FROM users
             WHERE id = ?1 AND is_deleted = 0",
            params![user_id],
            |row| {
                let user = User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_superadmin: row.get(3)?,
                    is_active: row.get(4)?,
                    is_deleted: row.get(5)?,
                    must_change_password: row.get(6)?,
                    failed_login_attempts: row.get(7)?,
                    locked_until: row.get(8)?,
                    last_login_at: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                };
                Ok(user)
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFoundError(format!("User with id {} not found", user_id)))
    }

    /// Get user by ID
    pub fn get_user_by_id(&self, user_id: i64) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_user_by_id_internal(&conn, user_id)
    }

    /// List all users
    pub fn list_users(
        &self,
        include_inactive: bool,
    ) -> Result<Vec<UserInfo>, DatabaseError> {
        let conn = self.lock_conn()?;

        let query = if include_inactive {
            "SELECT u.id, u.username, u.is_superadmin, u.is_active, u.failed_login_attempts,
                    u.locked_until, u.last_login_at, u.created_at, u.must_change_password
             FROM users u
             WHERE u.is_deleted = 0
             ORDER BY u.username"
        } else {
            "SELECT u.id, u.username, u.is_superadmin, u.is_active, u.failed_login_attempts,
                    u.locked_until, u.last_login_at, u.created_at, u.must_change_password
             FROM users u
             WHERE u.is_deleted = 0 AND u.is_active = 1
             ORDER BY u.username"
        };

        let mut stmt = conn
            .prepare(query)
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let users = stmt
            .query_map([], |row| {
                let user_id: i64 = row.get(0)?;
                Ok((
                    user_id,
                    UserInfo {
                        id: user_id,
                        username: row.get(1)?,
                        is_superadmin: row.get(2)?,
                        is_active: row.get(3)?,
                        failed_login_attempts: row.get(4)?,
                        locked_until: row.get(5)?,
                        last_login_at: row.get(6)?,
                        created_at: row.get(7)?,
                        must_change_password: row.get(8)?,
                        roles: Vec::new(), // Will be filled below
                    },
                ))
            })
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<_>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        // Get roles for each user
        let mut result = Vec::new();
        for (user_id, mut user_info) in users {
            user_info.roles = Self::get_user_roles_internal(&conn, user_id)?;
            result.push(user_info);
        }

        Ok(result)
    }

    /// Update user
    pub fn update_user(
        &self,
        user_id: i64,
        password: Option<&str>,
        is_active: Option<bool>,
    ) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;

        // Check if user exists
        let _ = Self::get_user_by_id_internal(&conn, user_id)?;

        // Update password if provided
        if let Some(pwd) = password {
            validate_password(pwd).map_err(DatabaseError::ValidationError)?;

            let password_hash = hash_password(pwd).map_err(|e| {
                DatabaseError::CryptoError(format!(
                    "Failed to hash password: {}",
                    e
                ))
            })?;

            conn.execute(
                "UPDATE users SET password_hash = ?1, must_change_password = 0, failed_login_attempts = 0, locked_until = NULL WHERE id = ?2",
                params![password_hash, user_id],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        // Update active status if provided
        if let Some(active) = is_active {
            conn.execute(
                "UPDATE users SET is_active = ?1 WHERE id = ?2",
                params![active, user_id],
            )
            .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;
        }

        Self::get_user_by_id_internal(&conn, user_id)
    }

    /// Delete user (soft delete)
    pub fn delete_user(&self, user_id: i64) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        conn.execute(
            "UPDATE users SET is_deleted = 1 WHERE id = ?1",
            params![user_id],
        )
        .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Ok(())
    }

    /// Internal: Get user roles without acquiring lock
    pub(crate) fn get_user_roles_internal(
        conn: &Connection,
        user_id: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let mut stmt = conn
            .prepare(
                "SELECT r.name
             FROM roles r
             INNER JOIN user_roles ur ON r.id = ur.role_id
             WHERE ur.user_id = ?1 AND r.is_deleted = 0
             ORDER BY r.name",
            )
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        let roles = stmt
            .query_map(params![user_id], |row| row.get(0))
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?
            .collect::<SqliteResult<Vec<String>>>()
            .map_err(|e| DatabaseError::QueryError(e.to_string()))?;

        Ok(roles)
    }

    /// Get user roles
    pub fn get_user_roles(
        &self,
        user_id: i64,
    ) -> Result<Vec<String>, DatabaseError> {
        let conn = self.lock_conn()?;
        Self::get_user_roles_internal(&conn, user_id)
    }

    /// Assign role to user
    pub fn assign_role_to_user(
        &self,
        user_id: i64,
        role_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        conn.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
             VALUES (?1, ?2, ?3)",
            params![user_id, role_id, assigned_by],
        )
        .map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        // Revoke API keys
        Self::revoke_user_api_keys_internal(
            &conn,
            user_id,
            assigned_by,
            "Role changed",
        )?;

        Ok(())
    }

    /// Remove role from user
    pub fn remove_role_from_user(
        &self,
        user_id: i64,
        role_id: i64,
    ) -> Result<(), DatabaseError> {
        let conn = self.lock_conn()?;

        conn.execute(
            "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2",
            params![user_id, role_id],
        )
        .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        // Revoke API keys
        Self::revoke_user_api_keys_internal(
            &conn,
            user_id,
            None,
            "Role changed",
        )?;
        Ok(())
    }

    /// Verify user credentials (username + password)
    ///
    /// SECURITY: This function uses constant-time comparison to prevent username enumeration
    /// via timing attacks. When a user doesn't exist, we still perform a dummy hash computation
    /// to make the response time similar to a failed login for an existing user.
    pub fn verify_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;

        // Try to find the user
        let user_result = conn.query_row(
            "SELECT id, username, password_hash, is_superadmin, is_active, is_deleted,
                    must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at
             FROM users
             WHERE username = ?1 AND is_deleted = 0",
            params![username],
            |row| {
                let user = User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_superadmin: row.get(3)?,
                    is_active: row.get(4)?,
                    is_deleted: row.get(5)?,
                    must_change_password: row.get(6)?,
                    failed_login_attempts: row.get(7)?,
                    locked_until: row.get(8)?,
                    last_login_at: row.get(9)?,
                    created_at: row.get(10)?,
                    updated_at: row.get(11)?,
                };
                Ok(user)
            },
        );

        // SECURITY: Constant-time username enumeration mitigation
        // Always perform password hash verification with equal timing
        // Use a real Argon2id hash to ensure identical parameters and computation cost
        let (user, password_valid) = match user_result {
            Ok(u) => {
                // User exists - verify with real hash
                let valid = super::crypto::verify_password(password, &u.password_hash)
                    .map_err(|e| DatabaseError::CryptoError(format!("Password verification failed: {}", e)))?;
                (Some(u), valid)
            },
            Err(_) => {
                // User doesn't exist - verify with dummy hash to match timing
                let _ = super::crypto::verify_password(password, DUMMY_PASSWORD_HASH);
                (None, false)
            }
        };

        // If user doesn't exist, return error now (after hash verification for timing)
        let user = user.ok_or_else(|| {
            DatabaseError::PermissionDenied("Invalid username or password".to_string())
        })?;

        // Active check
        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "Account is disabled".to_string(),
            ));
        }

        // Lockout check
        if let Some(locked_until) = user.locked_until
            && locked_until > Self::now()
        {
            return Err(DatabaseError::AccountLocked(format!(
                "Account is locked until timestamp {}",
                locked_until
            )));
        }

        // Password was already verified above for timing attack mitigation
        if !password_valid {
            // Increment failed login attempts
            let new_attempts = user.failed_login_attempts + 1;
            let locked_until =
                if new_attempts >= self.config.lockout.max_attempts as i32 {
                    Some(Self::now() + self.config.lockout.duration_seconds)
                } else {
                    None
                };

            conn.execute(
                "UPDATE users SET failed_login_attempts = ?1, locked_until = ?2 WHERE id = ?3",
                params![new_attempts, locked_until, user.id],
            )
            .ok();

            return Err(DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            ));
        }

        // Reset failed login attempts on successful login
        conn.execute(
            "UPDATE users SET failed_login_attempts = 0, locked_until = NULL, last_login_at = ?1 WHERE id = ?2",
            params![Self::now(), user.id],
        )
        .ok();

        if user.must_change_password {
            return Err(DatabaseError::PasswordChangeRequired(
                "Password change required".to_string(),
            ));
        }

        Ok(user)
    }

    /// Calculate all effective permissions for a user
    /// Combines role permissions and user-specific overrides
    pub fn calculate_user_permissions(
        &self,
        user_id: i64,
    ) -> Result<Vec<super::models::Permission>, DatabaseError> {
        // This method is already implemented in database_ext.rs via get_user_effective_permissions
        // We'll use that
        self.get_user_effective_permissions(user_id)
    }

    /// Change password providing current credentials (for forced reset flow)
    ///
    /// SECURITY: This function uses constant-time comparison to prevent username enumeration
    /// via timing attacks. When a user doesn't exist, we still perform a dummy hash computation
    /// to make the response time similar to a failed password change for an existing user.
    pub fn change_password_with_credentials(
        &self,
        username: &str,
        current_password: &str,
        new_password: &str,
    ) -> Result<User, DatabaseError> {
        let conn = self.lock_conn()?;

        let user_result = conn
            .query_row(
                "SELECT id, username, password_hash, is_superadmin, is_active, is_deleted,
                        must_change_password, failed_login_attempts, locked_until, last_login_at, created_at, updated_at
                 FROM users
                 WHERE username = ?1 AND is_deleted = 0",
                params![username],
                |row| {
                    let user = User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        is_superadmin: row.get(3)?,
                        is_active: row.get(4)?,
                        is_deleted: row.get(5)?,
                        must_change_password: row.get(6)?,
                        failed_login_attempts: row.get(7)?,
                        locked_until: row.get(8)?,
                        last_login_at: row.get(9)?,
                        created_at: row.get(10)?,
                        updated_at: row.get(11)?,
                    };
                    Ok(user)
                },
            )
            .optional()
            .map_err(|e| DatabaseError::QueryError(e.to_string()));

        // SECURITY: Constant-time username enumeration mitigation
        // Always perform password hash verification with equal timing
        // Use a real Argon2id hash to ensure identical parameters and computation cost
        let (mut user, password_valid) = match user_result {
            Ok(Some(u)) => {
                // User exists - verify with real hash
                let valid = super::crypto::verify_password(current_password, &u.password_hash)
                    .map_err(|e| DatabaseError::CryptoError(format!("Password verification failed: {}", e)))?;
                (Some(u), valid)
            },
            Ok(None) | Err(_) => {
                // User doesn't exist - verify with dummy hash to match timing
                let _ = super::crypto::verify_password(current_password, DUMMY_PASSWORD_HASH);
                (None, false)
            }
        };

        // If user doesn't exist, return error now (after hash verification for timing)
        let mut user = user.ok_or_else(|| {
            DatabaseError::PermissionDenied("Invalid username or password".to_string())
        })?;

        // Password was already verified above for timing attack mitigation
        if !password_valid {
            return Err(DatabaseError::PermissionDenied(
                "Invalid username or password".to_string(),
            ));
        }

        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "Account is disabled".to_string(),
            ));
        }
        if let Some(locked_until) = user.locked_until
            && locked_until > Self::now()
        {
            return Err(DatabaseError::AccountLocked(
                "Account is temporarily locked".to_string(),
            ));
        }

        // SECURITY: Only allow password change if it's required
        // This prevents users from resetting their lockout counter by changing password
        if !user.must_change_password {
            return Err(DatabaseError::PermissionDenied(
                "Password change not required. Use authenticated endpoints to change your password.".to_string(),
            ));
        }

        // Validate new password
        validate_password(new_password)
            .map_err(DatabaseError::ValidationError)?;

        // Prevent setting the same password
        if current_password == new_password {
            return Err(DatabaseError::ValidationError(
                "New password must be different from current password".to_string(),
            ));
        }

        let password_hash = hash_password(new_password).map_err(|e| {
            DatabaseError::CryptoError(format!(
                "Failed to hash password: {}",
                e
            ))
        })?;

        conn.execute(
            "UPDATE users
             SET password_hash = ?1, must_change_password = 0, failed_login_attempts = 0, locked_until = NULL, updated_at = strftime('%s','now')
             WHERE id = ?2",
            params![password_hash, user.id],
        )
        .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        // Refresh user
        user.must_change_password = false;
        user.password_hash = password_hash;
        user.failed_login_attempts = 0;
        user.locked_until = None;

        Ok(user)
    }

    /// Admin resets a user's password (forces change on next login)
    pub fn admin_reset_password(
        &self,
        user_id: i64,
        new_password: &str,
    ) -> Result<User, DatabaseError> {
        // Validate password
        validate_password(new_password)
            .map_err(DatabaseError::ValidationError)?;

        let password_hash = hash_password(new_password).map_err(|e| {
            DatabaseError::CryptoError(format!(
                "Failed to hash password: {}",
                e
            ))
        })?;

        let conn = self.lock_conn()?;

        // Ensure user exists
        let _ = Self::get_user_by_id_internal(&conn, user_id)?;

        conn.execute(
            "UPDATE users
             SET password_hash = ?1, must_change_password = 1, failed_login_attempts = 0, locked_until = NULL, updated_at = strftime('%s','now')
             WHERE id = ?2",
            params![password_hash, user_id],
        )
        .map_err(|e| DatabaseError::UpdateError(e.to_string()))?;

        Self::get_user_by_id_internal(&conn, user_id)
    }

    // =============================================================================
    // STRING VALIDATION HELPERS
    // =============================================================================

    /// Validate a username for CRLF injection and other attacks
    ///
    /// SECURITY FIX: Prevents CRLF injection, header manipulation, and log forgery
    pub(crate) fn validate_username(username: &str) -> Result<(), DatabaseError> {
        // Check length (reasonable username limit)
        if username.len() > 64 {
            return Err(DatabaseError::ValidationError(
                "Username must be 64 characters or less".to_string(),
            ));
        }

        if username.is_empty() || username.trim().is_empty() {
            return Err(DatabaseError::ValidationError(
                "Username cannot be empty".to_string(),
            ));
        }

        // SECURITY: Check for CRLF injection
        if username.contains('\r') || username.contains('\n') {
            return Err(DatabaseError::ValidationError(
                "Username contains invalid characters (CRLF)".to_string(),
            ));
        }

        // Check for null bytes
        if username.contains('\0') {
            return Err(DatabaseError::ValidationError(
                "Username contains null bytes".to_string(),
            ));
        }

        // Check for other control characters
        if username.chars().any(|c| c.is_control() && c != '\t') {
            return Err(DatabaseError::ValidationError(
                "Username contains invalid control characters".to_string(),
            ));
        }

        // Check for dangerous characters commonly used in attacks
        let dangerous = ['<', '>', '"', '\'', '`', '&', '|', ';', '$', '\\'];
        if username.chars().any(|c| dangerous.contains(&c)) {
            return Err(DatabaseError::ValidationError(
                "Username contains invalid characters. Only alphanumeric, underscore, hyphen, period, and @ allowed".to_string(),
            ));
        }

        Ok(())
    }

    /// Validate a description field for CRLF injection
    ///
    /// SECURITY FIX: Prevents CRLF injection in description fields
    pub(crate) fn validate_description(description: Option<&str>) -> Result<(), DatabaseError> {
        if let Some(desc) = description {
            // Check length
            if desc.len() > 500 {
                return Err(DatabaseError::ValidationError(
                    "Description must be 500 characters or less".to_string(),
                ));
            }

            // SECURITY: Check for CRLF injection
            if desc.contains('\r') || desc.contains('\n') {
                return Err(DatabaseError::ValidationError(
                    "Description contains invalid characters (CRLF)".to_string(),
                ));
            }

            // Check for null bytes
            if desc.contains('\0') {
                return Err(DatabaseError::ValidationError(
                    "Description contains null bytes".to_string(),
                ));
            }

            // Check for excessive control characters (allow tab)
            if desc.chars().any(|c| c.is_control() && c != '\t') {
                return Err(DatabaseError::ValidationError(
                    "Description contains invalid control characters".to_string(),
                ));
            }
        }

        Ok(())
    }
}
