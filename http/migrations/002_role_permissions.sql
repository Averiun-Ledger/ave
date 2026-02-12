-- Ave HTTP Auth System - Role Permissions Setup
--
-- This migration sets up the initial permissions for system roles

-- =============================================================================
-- SUPERADMIN ROLE PERMISSIONS
-- =============================================================================
-- Superadmin has ALL permissions on ALL resources

INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'superadmin'),
    r.id,
    (SELECT id FROM actions WHERE name = 'all'),
    1,
    1
FROM resources r
;

-- =============================================================================
-- ADMIN ROLE PERMISSIONS
-- =============================================================================
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'admin'),
    r.id,
    (SELECT id FROM actions WHERE name = 'all'),
    1,
    1
FROM resources r
WHERE r.name IN (
    'admin_users',
    'admin_roles',
    'admin_system',
    'admin_api_key',
    'user',
    'user_api_key'
);

-- =============================================================================
-- SENDER ROLE PERMISSIONS
-- =============================================================================
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'sender'),
    r.id,
    a.id,
    1,
    1
FROM resources r
CROSS JOIN actions a
WHERE (r.name = 'node_request' AND a.name IN ('get', 'post'));

INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'sender'),
    r.id,
    (SELECT id FROM actions WHERE name = 'get'),
    1,
    1
FROM resources r
WHERE r.name IN ('node_subject', 'node_system');

INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'sender'),
    r.id,
    (SELECT id FROM actions WHERE name = 'all'),
    1,
    1
FROM resources r
WHERE r.name IN ('user', 'user_api_key');

-- =============================================================================
-- MANAGER ROLE PERMISSIONS
-- =============================================================================
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'manager'),
    r.id,
    (SELECT id FROM actions WHERE name = 'all'),
    1,
    1
FROM resources r
WHERE r.name IN ('node_subject', 'node_system', 'user', 'user_api_key', 'node_request');


-- =============================================================================
-- DATA ROLE PERMISSIONS
-- =============================================================================
INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'data'),
    r.id,
    (SELECT id FROM actions WHERE name = 'all'),
    1,
    1
FROM resources r
WHERE r.name IN ('user', 'user_api_key');

INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'data'),
    r.id,
    (SELECT id FROM actions WHERE name = 'get'),
    1,
    1
FROM resources r
WHERE r.name IN ('node_request', 'node_subject', 'node_system');
