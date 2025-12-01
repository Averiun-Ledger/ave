-- Ave HTTP Auth System - Role Permissions Setup
--
-- This migration sets up the initial permissions for system roles

-- =============================================================================
-- SUPERADMIN ROLE PERMISSIONS
-- =============================================================================
-- Superadmin has ALL permissions on ALL resources

INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'superadmin'),
    r.id,
    a.id,
    1
FROM resources r
CROSS JOIN actions a;

-- =============================================================================
-- ADMIN ROLE PERMISSIONS
-- =============================================================================
-- Admin can manage users, roles, permissions, and API keys
-- Admin CANNOT access ledger endpoints (subjects, events, etc.)

-- Users management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'users'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('create', 'read', 'update', 'delete', 'list', 'manage');

-- Roles management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'roles'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('create', 'read', 'update', 'delete', 'list', 'manage');

-- Permissions management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'permissions'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('create', 'read', 'update', 'delete', 'list', 'manage');

-- API keys management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'api_keys'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('create', 'read', 'update', 'delete', 'list', 'manage');

-- Audit logs (read-only)
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'audit'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('read', 'list');

-- System config (read and update)
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'system'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('read', 'update', 'list');

-- DENY admin access to ledger endpoints
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    r.id,
    a.id,
    0
FROM resources r
CROSS JOIN actions a
WHERE r.name IN ('subjects', 'events', 'governances', 'approvals', 'transfers', 'signatures', 'auth');

-- =============================================================================
-- ALL ROLE PERMISSIONS
-- =============================================================================
-- All role has full access to ledger endpoints
-- All role CANNOT manage users, roles, permissions, or API keys (except their own)

-- Ledger endpoints - full access
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'all'),
    r.id,
    a.id,
    1
FROM resources r
CROSS JOIN actions a
WHERE r.name IN ('subjects', 'events', 'governances', 'approvals', 'transfers', 'signatures', 'auth');

-- System endpoints - read only
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'all'),
    (SELECT id FROM resources WHERE name = 'system'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('read');

-- Own API keys - read and manage (will be enforced at application level)
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'all'),
    (SELECT id FROM resources WHERE name = 'api_keys'),
    a.id,
    1
FROM actions a
WHERE a.name IN ('read', 'list');

-- DENY all access to admin endpoints
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'all'),
    r.id,
    a.id,
    0
FROM resources r
CROSS JOIN actions a
WHERE r.name IN ('users', 'roles', 'permissions');

-- =============================================================================
-- READONLY ROLE PERMISSIONS
-- =============================================================================
-- Readonly has read/list access to everything except admin functions

-- Read access to ledger endpoints
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'readonly'),
    r.id,
    a.id,
    1
FROM resources r
CROSS JOIN actions a
WHERE r.name IN ('subjects', 'events', 'governances', 'approvals', 'transfers', 'signatures', 'auth', 'system', 'audit')
  AND a.name IN ('read', 'list');

-- DENY write operations
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'readonly'),
    r.id,
    a.id,
    0
FROM resources r
CROSS JOIN actions a
WHERE a.name IN ('create', 'update', 'delete', 'execute', 'manage');

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
