-- Ave HTTP Auth System - Initial Schema Migration
--
-- This migration creates the complete auth system including:
-- - Users with password hashing
-- - Roles with permissions
-- - API keys with expiration and revocation
-- - Audit logging
-- - Rate limiting

-- =============================================================================
-- USERS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT 1,
    is_deleted BOOLEAN NOT NULL DEFAULT 0,
    must_change_password BOOLEAN NOT NULL DEFAULT 0,
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until INTEGER, -- Unix timestamp when account unlock, NULL if not locked
    last_login_at INTEGER, -- Unix timestamp
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_users_username ON users(username) WHERE is_deleted = 0;
CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active) WHERE is_deleted = 0;

-- =============================================================================
-- ROLES TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT 0, -- System roles cannot be deleted
    is_deleted BOOLEAN NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_roles_name ON roles(name) WHERE is_deleted = 0;

-- =============================================================================
-- USER_ROLES TABLE (Many-to-Many relationship)
-- =============================================================================
CREATE TABLE IF NOT EXISTS user_roles (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    role_id INTEGER NOT NULL,
    assigned_by INTEGER, -- User ID who assigned this role
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(user_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_user_roles_user ON user_roles(user_id);
CREATE INDEX IF NOT EXISTS idx_user_roles_role ON user_roles(role_id);

-- =============================================================================
-- RESOURCES TABLE
-- =============================================================================
-- Resources represent API endpoints or groups of endpoints
CREATE TABLE IF NOT EXISTS resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, -- e.g., "node_subject", "admin_system", "user"
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_resources_name ON resources(name);

-- =============================================================================
-- ACTIONS TABLE
-- =============================================================================
-- Actions represent operations on resources (aligned with HTTP verbs)
CREATE TABLE IF NOT EXISTS actions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE, -- e.g., "get", "post", "put", "patch", "delete", "all"
    description TEXT,
    is_system BOOLEAN NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_actions_name ON actions(name);

-- =============================================================================
-- ROLE_PERMISSIONS TABLE
-- =============================================================================
-- Defines what actions roles can perform on resources
CREATE TABLE IF NOT EXISTS role_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    action_id INTEGER NOT NULL,
    allowed BOOLEAN NOT NULL DEFAULT 1, -- TRUE = allow, FALSE = deny
    is_system BOOLEAN NOT NULL DEFAULT 0, -- System permissions cannot be modified/deleted
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    UNIQUE(role_id, resource_id, action_id)
);

CREATE INDEX IF NOT EXISTS idx_role_permissions_role ON role_permissions(role_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_resource ON role_permissions(resource_id);
CREATE INDEX IF NOT EXISTS idx_role_permissions_action ON role_permissions(action_id);

-- =============================================================================
-- USER_PERMISSIONS TABLE
-- =============================================================================
-- User-specific permission overrides (takes precedence over role permissions)
CREATE TABLE IF NOT EXISTS user_permissions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    resource_id INTEGER NOT NULL,
    action_id INTEGER NOT NULL,
    allowed BOOLEAN NOT NULL, -- TRUE = allow, FALSE = deny
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    granted_by INTEGER, -- User ID who granted this permission
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (resource_id) REFERENCES resources(id) ON DELETE CASCADE,
    FOREIGN KEY (action_id) REFERENCES actions(id) ON DELETE CASCADE,
    FOREIGN KEY (granted_by) REFERENCES users(id) ON DELETE SET NULL,
    UNIQUE(user_id, resource_id, action_id)
);

CREATE INDEX IF NOT EXISTS idx_user_permissions_user ON user_permissions(user_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_resource ON user_permissions(resource_id);
CREATE INDEX IF NOT EXISTS idx_user_permissions_action ON user_permissions(action_id);

-- =============================================================================
-- API_KEYS TABLE
-- =============================================================================
-- SECURITY: Using UUID as PRIMARY KEY prevents IDOR and enumeration attacks
CREATE TABLE IF NOT EXISTS api_keys (
    id TEXT PRIMARY KEY, -- UUID v4 as primary key (e.g., "550e8400-e29b-41d4-a716-446655440000")
    user_id INTEGER NOT NULL,
    key_hash TEXT NOT NULL UNIQUE, -- SHA-256 hash of the actual key
    key_prefix TEXT NOT NULL, -- First 8 chars for identification (e.g., "ave_v1_a")
    name TEXT NOT NULL, -- User-friendly name for the key (required)
    description TEXT,
    is_management BOOLEAN NOT NULL DEFAULT 0, -- 1 = login/management key, 0 = service key
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    expires_at INTEGER, -- Unix timestamp, NULL = no expiration
    revoked BOOLEAN NOT NULL DEFAULT 0,
    revoked_at INTEGER,
    revoked_by INTEGER, -- User ID who revoked the key
    revoked_reason TEXT,
    last_used_at INTEGER, -- Unix timestamp of last successful auth
    last_used_ip TEXT,
    metadata TEXT, -- JSON field for additional key metadata
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (revoked_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_user ON api_keys(user_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash) WHERE revoked = 0;
CREATE INDEX IF NOT EXISTS idx_api_keys_prefix ON api_keys(key_prefix);
CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(user_id, revoked, expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_user_name_active ON api_keys(user_id, name) WHERE revoked = 0;
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_user_management_active ON api_keys(user_id) WHERE revoked = 0 AND is_management = 1;

-- =============================================================================
-- AUDIT_LOGS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    user_id INTEGER, -- NULL for anonymous/failed auth attempts
    api_key_id TEXT, -- UUID reference to api_keys
    action_type TEXT NOT NULL, -- e.g., "login_success", "login_failed", "api_key_created"
    endpoint TEXT, -- HTTP endpoint called
    http_method TEXT, -- GET, POST, PUT, DELETE, etc.
    ip_address TEXT,
    user_agent TEXT,
    request_id TEXT, -- For correlating related log entries
    details TEXT, -- JSON field for additional context
    success BOOLEAN NOT NULL DEFAULT 1,
    error_message TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_audit_logs_timestamp ON audit_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_api_key ON audit_logs(api_key_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_action_type ON audit_logs(action_type);

-- =============================================================================
-- RATE_LIMITS TABLE
-- =============================================================================
-- Track rate limiting per API key and IP
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id TEXT, -- UUID reference to api_keys
    ip_address TEXT,
    endpoint TEXT, -- NULL = global limit
    window_start INTEGER NOT NULL, -- Unix timestamp of current window
    request_count INTEGER NOT NULL DEFAULT 1,
    last_request_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE,
    UNIQUE(api_key_id, ip_address, endpoint, window_start)
);

CREATE INDEX IF NOT EXISTS idx_rate_limits_api_key ON rate_limits(api_key_id, window_start);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip ON rate_limits(ip_address, window_start);
CREATE INDEX IF NOT EXISTS idx_rate_limits_cleanup ON rate_limits(window_start);

-- =============================================================================
-- IP_ALLOWLIST TABLE
-- =============================================================================
-- Optional IP allowlist/denylist per API key or role
-- =============================================================================
-- SYSTEM_CONFIG TABLE
-- =============================================================================
-- Global system configuration flags
CREATE TABLE IF NOT EXISTS system_config (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    description TEXT,
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_by INTEGER,
    FOREIGN KEY (updated_by) REFERENCES users(id) ON DELETE SET NULL
);

-- Insert default system config
INSERT OR IGNORE INTO system_config (key, value, description) VALUES
    ('max_login_attempts', '5', 'Maximum failed login attempts before account lockout'),
    ('lockout_duration_seconds', '900', 'Account lockout duration in seconds'),
    ('rate_limit_window_seconds', '60', 'Rate limit time window in seconds'),
    ('rate_limit_max_requests', '100', 'Maximum requests per window'),
    ('api_key_default_ttl_seconds', '2592000', 'Default API key TTL in seconds');

-- =============================================================================
-- INSERT SYSTEM RESOURCES
-- =============================================================================
INSERT OR IGNORE INTO resources (name, description, is_system) VALUES
    ('user', 'User self-service endpoints', 1),
    ('admin_system', 'Administrative system endpoints', 1),
    ('admin_api_key', 'Administrative API key endpoints', 1),
    ('admin_roles', 'Administrative role and permission endpoints', 1),
    ('admin_users', 'Administrative user management endpoints', 1),
    ('node_system', 'Node information endpoints', 1),
    ('node_subject', 'Ledger subject and governance endpoints', 1),
    ('node_request', 'Ledger request submission endpoints', 1),
    ('user_api_key', 'User self-service API key endpoints', 1);

-- =============================================================================
-- INSERT SYSTEM ACTIONS
-- =============================================================================
INSERT OR IGNORE INTO actions (name, description, is_system) VALUES
    ('get', 'Read/view resources', 1),
    ('post', 'Create resources or trigger operations', 1),
    ('put', 'Replace or update resources', 1),
    ('patch', 'Partial update or custom action', 1),
    ('delete', 'Delete resources', 1),
    ('all', 'Full access to the resource', 1);

-- =============================================================================
-- INSERT SYSTEM ROLES
-- =============================================================================
INSERT OR IGNORE INTO roles (name, description, is_system) VALUES
    ('superadmin', 'Full system access with all privileges', 1),
    ('admin', 'Administrative access to users, roles, and API keys', 1),
    ('sender', 'Limited to sending event requests', 1),
    ('manager', 'Business manager with operational control', 1),
    ('data', 'Read-only access to business data', 1);

-- Get role IDs
-- Note: We'll set up permissions programmatically in Rust to handle the dynamic IDs

-- =============================================================================
-- TRIGGERS FOR UPDATED_AT
-- =============================================================================

-- Users table trigger
CREATE TRIGGER IF NOT EXISTS update_users_timestamp
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

-- Roles table trigger
CREATE TRIGGER IF NOT EXISTS update_roles_timestamp
AFTER UPDATE ON roles
FOR EACH ROW
BEGIN
    UPDATE roles SET updated_at = strftime('%s', 'now') WHERE id = NEW.id;
END;

-- System config trigger
CREATE TRIGGER IF NOT EXISTS update_system_config_timestamp
AFTER UPDATE ON system_config
FOR EACH ROW
BEGIN
    UPDATE system_config SET updated_at = strftime('%s', 'now') WHERE key = NEW.key;
END;

-- =============================================================================
-- TRIGGERS FOR API KEY REVOCATION
-- =============================================================================

-- When user is deactivated, revoke all their API keys
CREATE TRIGGER IF NOT EXISTS revoke_keys_on_user_deactivate
AFTER UPDATE OF is_active ON users
FOR EACH ROW
WHEN NEW.is_active = 0 AND OLD.is_active = 1
BEGIN
    UPDATE api_keys
    SET revoked = 1,
        revoked_at = strftime('%s', 'now'),
        revoked_reason = 'User account deactivated'
    WHERE user_id = NEW.id AND revoked = 0;
END;

-- When user is deleted (soft delete), revoke all their API keys
CREATE TRIGGER IF NOT EXISTS revoke_keys_on_user_delete
AFTER UPDATE OF is_deleted ON users
FOR EACH ROW
WHEN NEW.is_deleted = 1 AND OLD.is_deleted = 0
BEGIN
    UPDATE api_keys
    SET revoked = 1,
        revoked_at = strftime('%s', 'now'),
        revoked_reason = 'User account deleted'
    WHERE user_id = NEW.id AND revoked = 0;
END;

-- =============================================================================
-- API KEY LIMIT ENFORCEMENT
-- =============================================================================
-- SECURITY NOTE: The max_keys_per_user limit is enforced at application level
-- (see database_apikeys.rs:85-99). A database-level trigger was considered but
-- removed because:
-- 1. It would require hardcoding the limit (20) or using a config table
-- 2. The race condition window is extremely small and difficult to exploit
-- 3. Application-level check is more flexible and respects config changes
-- 4. SQLite transactions already provide isolation for the check+insert operation
--
-- The application performs the check within a transaction, making the race
-- condition very unlikely. If stricter enforcement is needed in the future,
-- consider using:
-- - SERIALIZABLE transaction isolation mode
-- - A database-level config table with trigger reading from it
-- - Row-level locking (though SQLite uses database-level locks)

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
