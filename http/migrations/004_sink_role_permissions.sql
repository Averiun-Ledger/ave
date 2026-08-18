-- Ave HTTP Auth System - Sink Role Permissions Update
--
-- Brings the sink role in line with the common role base shared by every
-- other functional role: self-management (user, user_api_key) plus full
-- control of its domain resource (node_sink, previously read-only).
-- node_maintenance stays superadmin-only by design.

INSERT OR IGNORE INTO role_permissions (role_id, resource_id, action_id, allowed, is_system)
SELECT
    (SELECT id FROM roles WHERE name = 'sink'),
    r.id,
    (SELECT id FROM actions WHERE name = 'all'),
    1,
    1
FROM resources r
WHERE r.name IN ('node_sink', 'user', 'user_api_key')
;
