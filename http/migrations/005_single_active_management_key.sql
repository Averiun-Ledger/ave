-- Ave HTTP Auth System - Single Active Management Key Per User
--
-- Two concurrent logins could both revoke the old management key and insert
-- a new one, leaving two active management keys for the same user. Existing
-- databases may already contain such duplicates, so they are revoked first
-- (keeping the most recently inserted one) and then a partial unique index
-- makes the invariant structural.

UPDATE api_keys
SET revoked = 1,
    revoked_at = CAST(strftime('%s', 'now') AS INTEGER),
    revoked_by = user_id,
    revoked_reason = 'duplicate management key cleanup'
WHERE is_management = 1 AND revoked = 0 AND rowid NOT IN (
    SELECT MAX(rowid)
    FROM api_keys
    WHERE is_management = 1 AND revoked = 0
    GROUP BY user_id
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_keys_one_active_management_key
ON api_keys(user_id)
WHERE is_management = 1 AND revoked = 0;
