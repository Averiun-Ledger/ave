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
    (SELECT id FROM actions WHERE name = 'all'),
    1
FROM resources r
;

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
    (SELECT id FROM actions WHERE name = 'all'),
    1;

-- Roles management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'roles'),
    (SELECT id FROM actions WHERE name = 'all'),
    1;

-- Permissions management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'permissions'),
    (SELECT id FROM actions WHERE name = 'all'),
    1;

-- API keys management
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'api_keys'),
    (SELECT id FROM actions WHERE name = 'all'),
    1;

-- Audit logs
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'audit'),
    (SELECT id FROM actions WHERE name = 'all'),
    1;

-- System config
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    (SELECT id FROM resources WHERE name = 'system'),
    (SELECT id FROM actions WHERE name = 'all'),
    1;

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
        AND a.name IN ('get')
    )
    OR (r.name = 'subjects' AND a.name = 'post')
    OR (r.name = 'transfers' AND a.name = 'post');

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
    ('approvals', 'get'), ('approvals', 'patch'),
    ('events', 'post'), ('events', 'get'),
    ('transfers', 'get'), ('transfers', 'post'),
    ('subjects', 'post'),
    ('auth', 'post'), ('auth', 'put'), ('auth', 'delete'), ('auth', 'get'),
    ('system', 'get')
);

-- =============================================================================
-- SENDER ROLE PERMISSIONS
-- =============================================================================
-- Only allowed to send event requests
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed)
SELECT
    (SELECT id FROM roles WHERE name = 'sender'),
    (SELECT id FROM resources WHERE name = 'events'),
    (SELECT id FROM actions WHERE name = 'post'),
    1;
