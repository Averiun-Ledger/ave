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
-- OWNER ROLE PERMISSIONS
-- =============================================================================
-- Full access to business endpoints (non-admin)
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'owner'),
    r.id,
    a.id,
    1
FROM resources r
CROSS JOIN actions a
WHERE r.name IN ('subjects', 'events', 'governances', 'approvals', 'transfers', 'signatures', 'auth', 'system');

-- =============================================================================
-- READ ROLE PERMISSIONS
-- =============================================================================
-- Read/list on selected endpoints; allows update/check-transfer flows
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'read'),
    r.id,
    a.id,
    1
FROM resources r
CROSS JOIN actions a
WHERE
    (
        r.name IN ('signatures', 'subjects', 'events', 'governances', 'approvals', 'auth', 'transfers', 'system')
        AND a.name IN ('read', 'list')
    )
    OR (r.name = 'subjects' AND a.name = 'update')
    OR (r.name = 'transfers' AND a.name = 'execute');

-- =============================================================================
-- WRITE ROLE PERMISSIONS
-- =============================================================================
-- Write flows over business endpoints
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'write'),
    r.id,
    a.id,
    1
FROM resources r
CROSS JOIN actions a
WHERE (r.name, a.name) IN (
    ('approvals', 'read'), ('approvals', 'execute'),
    ('events', 'create'), ('events', 'read'),
    ('transfers', 'read'), ('transfers', 'execute'),
    ('subjects', 'update'),
    ('auth', 'create'), ('auth', 'update'), ('auth', 'delete'), ('auth', 'read'), ('auth', 'list'),
    ('system', 'read')
);

-- =============================================================================
-- SENDER ROLE PERMISSIONS
-- =============================================================================
-- Only allowed to send event requests
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'sender'),
    (SELECT id FROM resources WHERE name = 'events'),
    (SELECT id FROM actions WHERE name = 'create'),
    1;
