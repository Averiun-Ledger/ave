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
    sync::{Arc, Mutex},
};
use thiserror::Error;
use tracing::{debug, error, info};

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
}

// =============================================================================
// DATABASE SERVICE
// =============================================================================

/// Thread-safe database service for auth operations
#[derive(Clone)]
pub struct AuthDatabase {
    pub(crate) connection: Arc<Mutex<Connection>>,
    pub(crate) config: Arc<AuthConfig>,
}

impl AuthDatabase {
    /// Create a new AuthDatabase instance
    ///
    /// This will:
    /// 1. Create the database file if it doesn't exist
    /// 2. Run migrations to set up the schema
    /// 3. Bootstrap the superadmin account if configured
    pub fn new(config: AuthConfig, password: &str) -> Result<Self, DatabaseError> {
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

        Ok(db)
    }

    /// Run database migrations
    pub fn run_migrations(&self) -> Result<(), DatabaseError> {
        info!("Running database migrations...");

        let conn = self.connection.lock().unwrap();

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

    /// Bootstrap superadmin account on first run
    pub fn bootstrap_superadmin(&self, password: &str) -> Result<(), DatabaseError> {
        let conn = self.connection.lock().unwrap();

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

        info!(
            "Bootstrapping superadmin account: {}",
            superadmin
        );

        // Hash password
        let password_hash = hash_password(&password)
            .map_err(|e| {
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
}

// =============================================================================
// USER OPERATIONS
// =============================================================================

impl AuthDatabase {
    /// Create a new user
    pub fn create_user(
        &self,
        username: &str,
        password: &str,
        is_superadmin: bool,
        role_ids: Option<Vec<i64>>,
        created_by: Option<i64>,
    ) -> Result<User, DatabaseError> {
        let conn = self.connection.lock().unwrap();

        // Check if username already exists
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
        validate_password(password, &self.config.password_policy)
            .map_err(DatabaseError::ValidationError)?;

        // Hash password
        let password_hash = hash_password(password).map_err(|e| {
            DatabaseError::CryptoError(format!(
                "Failed to hash password: {}",
                e
            ))
        })?;

        // Insert user
        conn.execute(
            "INSERT INTO users (username, password_hash, is_superadmin, is_active)
             VALUES (?1, ?2, ?3, 1)",
            params![username, password_hash, is_superadmin],
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
                    failed_login_attempts, locked_until, last_login_at, created_at, updated_at
             FROM users
             WHERE id = ?1 AND is_deleted = 0",
            params![user_id],
            |row| {
                Ok(User {
                    id: row.get(0)?,
                    username: row.get(1)?,
                    password_hash: row.get(2)?,
                    is_superadmin: row.get(3)?,
                    is_active: row.get(4)?,
                    is_deleted: row.get(5)?,
                    failed_login_attempts: row.get(6)?,
                    locked_until: row.get(7)?,
                    last_login_at: row.get(8)?,
                    created_at: row.get(9)?,
                    updated_at: row.get(10)?,
                })
            },
        )
        .optional()
        .map_err(|e| DatabaseError::QueryError(e.to_string()))?
        .ok_or_else(|| DatabaseError::NotFoundError(format!("User with id {} not found", user_id)))
    }

    /// Get user by ID
    pub fn get_user_by_id(&self, user_id: i64) -> Result<User, DatabaseError> {
        let conn = self.connection.lock().unwrap();
        Self::get_user_by_id_internal(&conn, user_id)
    }

    /// List all users
    pub fn list_users(
        &self,
        include_inactive: bool,
    ) -> Result<Vec<UserInfo>, DatabaseError> {
        let conn = self.connection.lock().unwrap();

        let query = if include_inactive {
            "SELECT u.id, u.username, u.is_superadmin, u.is_active, u.failed_login_attempts,
                    u.locked_until, u.last_login_at, u.created_at
             FROM users u
             WHERE u.is_deleted = 0
             ORDER BY u.username"
        } else {
            "SELECT u.id, u.username, u.is_superadmin, u.is_active, u.failed_login_attempts,
                    u.locked_until, u.last_login_at, u.created_at
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
        let conn = self.connection.lock().unwrap();

        // Check if user exists
        let _ = Self::get_user_by_id_internal(&conn, user_id)?;

        // Update password if provided
        if let Some(pwd) = password {
            validate_password(pwd, &self.config.password_policy)
                .map_err(DatabaseError::ValidationError)?;

            let password_hash = hash_password(pwd).map_err(|e| {
                DatabaseError::CryptoError(format!(
                    "Failed to hash password: {}",
                    e
                ))
            })?;

            conn.execute(
                "UPDATE users SET password_hash = ?1 WHERE id = ?2",
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
        let conn = self.connection.lock().unwrap();

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
        let conn = self.connection.lock().unwrap();
        Self::get_user_roles_internal(&conn, user_id)
    }

    /// Assign role to user
    pub fn assign_role_to_user(
        &self,
        user_id: i64,
        role_id: i64,
        assigned_by: Option<i64>,
    ) -> Result<(), DatabaseError> {
        let conn = self.connection.lock().unwrap();

        conn.execute(
            "INSERT OR IGNORE INTO user_roles (user_id, role_id, assigned_by)
             VALUES (?1, ?2, ?3)",
            params![user_id, role_id, assigned_by],
        )
        .map_err(|e| DatabaseError::InsertError(e.to_string()))?;

        // Revoke API keys if configured
        if self.config.api_key.revoke_on_role_change {
            Self::revoke_user_api_keys_internal(
                &conn,
                user_id,
                assigned_by,
                "Role changed",
            )?;
        }

        Ok(())
    }

    /// Remove role from user
    pub fn remove_role_from_user(
        &self,
        user_id: i64,
        role_id: i64,
    ) -> Result<(), DatabaseError> {
        let conn = self.connection.lock().unwrap();

        conn.execute(
            "DELETE FROM user_roles WHERE user_id = ?1 AND role_id = ?2",
            params![user_id, role_id],
        )
        .map_err(|e| DatabaseError::DeleteError(e.to_string()))?;

        // Revoke API keys if configured
        if self.config.api_key.revoke_on_role_change {
            Self::revoke_user_api_keys_internal(
                &conn,
                user_id,
                None,
                "Role changed",
            )?;
        }

        Ok(())
    }

    /// Verify user credentials (username + password)
    pub fn verify_credentials(
        &self,
        username: &str,
        password: &str,
    ) -> Result<User, DatabaseError> {
        let conn = self.connection.lock().unwrap();

        let user: User = conn
            .query_row(
                "SELECT id, username, password_hash, is_superadmin, is_active, is_deleted,
                        failed_login_attempts, locked_until, last_login_at, created_at, updated_at
                 FROM users
                 WHERE username = ?1 AND is_deleted = 0",
                params![username],
                |row| {
                    Ok(User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        password_hash: row.get(2)?,
                        is_superadmin: row.get(3)?,
                        is_active: row.get(4)?,
                        is_deleted: row.get(5)?,
                        failed_login_attempts: row.get(6)?,
                        locked_until: row.get(7)?,
                        last_login_at: row.get(8)?,
                        created_at: row.get(9)?,
                        updated_at: row.get(10)?,
                    })
                },
            )
            .map_err(|_| {
                DatabaseError::PermissionDenied(
                    "Invalid username or password".to_string(),
                )
            })?;

        // Active check
        if !user.is_active {
            return Err(DatabaseError::PermissionDenied(
                "Account is disabled".to_string(),
            ));
        }

        // Lockout check
        if let Some(locked_until) = user.locked_until {
            if locked_until > Self::now() {
                return Err(DatabaseError::AccountLocked(format!(
                    "Account is locked until timestamp {}",
                    locked_until
                )));
            }
        }

        // Verify password
        let password_valid =
            super::crypto::verify_password(password, &user.password_hash)
                .map_err(|e| {
                    DatabaseError::CryptoError(format!(
                        "Password verification failed: {}",
                        e
                    ))
                })?;

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
}
