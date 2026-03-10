-- Ave HTTP Auth System - Usage Plans and Monthly Quotas
--
-- Adds optional usage plans for API keys without breaking existing keys.
-- Keys with no associated plan remain unlimited.

-- =============================================================================
-- USAGE_PLANS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS usage_plans (
    id TEXT PRIMARY KEY, -- Stable plan identifier (e.g., free, basic, pro)
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    monthly_events INTEGER NOT NULL CHECK (monthly_events >= 0),
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_usage_plans_name ON usage_plans(name);

-- =============================================================================
-- API_KEY_PLANS TABLE
-- =============================================================================
-- Optional plan assignment per API key.
-- Absence of a row means the API key has no plan and therefore no monthly quota.
CREATE TABLE IF NOT EXISTS api_key_plans (
    api_key_id TEXT PRIMARY KEY,
    plan_id TEXT NOT NULL,
    assigned_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    assigned_by INTEGER,
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (plan_id) REFERENCES usage_plans(id) ON DELETE RESTRICT,
    FOREIGN KEY (assigned_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_api_key_plans_plan ON api_key_plans(plan_id);

-- =============================================================================
-- API_KEY_USAGE TABLE
-- =============================================================================
-- Monthly usage counter by API key.
-- `usage_month` uses UTC `YYYY-MM` format.
CREATE TABLE IF NOT EXISTS api_key_usage (
    api_key_id TEXT NOT NULL,
    usage_month TEXT NOT NULL,
    used_events INTEGER NOT NULL DEFAULT 0 CHECK (used_events >= 0),
    updated_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    PRIMARY KEY (api_key_id, usage_month),
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_api_key_usage_month ON api_key_usage(usage_month);

-- =============================================================================
-- QUOTA_EXTENSIONS TABLE
-- =============================================================================
-- Extra events granted manually for a given key and month.
CREATE TABLE IF NOT EXISTS quota_extensions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    api_key_id TEXT NOT NULL,
    usage_month TEXT NOT NULL,
    extra_events INTEGER NOT NULL CHECK (extra_events > 0),
    reason TEXT,
    created_by INTEGER,
    created_at INTEGER NOT NULL DEFAULT (strftime('%s', 'now')),
    FOREIGN KEY (api_key_id) REFERENCES api_keys(id) ON DELETE CASCADE,
    FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_quota_extensions_key_month ON quota_extensions(api_key_id, usage_month);
