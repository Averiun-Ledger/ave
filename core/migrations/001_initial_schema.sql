-- =============================================================================
-- EVENTS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS events (
    subject_id TEXT NOT NULL,
    sn INTEGER NOT NULL,
    event_request_timestamp INTEGER NOT NULL,
    event_ledger_timestamp INTEGER NOT NULL,
    sink_timestamp INTEGER NOT NULL,
    event_type TEXT NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (subject_id, sn)
);

CREATE INDEX IF NOT EXISTS idx_events_subject_event_type_sn
ON events(subject_id, event_type, sn);

CREATE INDEX IF NOT EXISTS idx_events_subject_request_ts_sn
ON events(subject_id, event_request_timestamp, sn);

CREATE INDEX IF NOT EXISTS idx_events_subject_ledger_ts_sn
ON events(subject_id, event_ledger_timestamp, sn);

CREATE INDEX IF NOT EXISTS idx_events_subject_sink_ts_sn
ON events(subject_id, sink_timestamp, sn);

-- =============================================================================
-- SUBJECTS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS subjects (
    name TEXT,
    description TEXT,
    subject_id TEXT NOT NULL,
    governance_id TEXT NOT NULL,
    genesis_gov_version INTEGER NOT NULL,
    prev_ledger_event_hash TEXT,
    schema_id TEXT NOT NULL,
    namespace TEXT NOT NULL,
    sn INTEGER NOT NULL,         -- Current sequence number
    creator TEXT NOT NULL,
    owner TEXT NOT NULL,
    new_owner TEXT,              -- New owner during ownership transfer
    active INTEGER NOT NULL CHECK (active IN (0, 1)),  -- 0 = false, 1 = true
    tracker_visibility TEXT,     -- JSON serialized simplified tracker visibility state; NULL for governance subjects
    properties TEXT NOT NULL,    -- JSON serialized subject properties
    PRIMARY KEY (subject_id)
);

-- =============================================================================
-- ABORTS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS aborts (
    request_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    sn INTEGER,
    error TEXT NOT NULL,
    who TEXT NOT NULL,
    abort_type TEXT NOT NULL,
    PRIMARY KEY (request_id)
);

DROP INDEX IF EXISTS idx_aborts_subject_sn;
DROP INDEX IF EXISTS idx_aborts_subject_sn_request_id;

CREATE INDEX IF NOT EXISTS idx_aborts_subject_sn_request_id
ON aborts(subject_id, COALESCE(sn, -1), request_id);

-- =============================================================================
-- REGISTER TABLES
-- =============================================================================
CREATE TABLE IF NOT EXISTS register_govs (
    governance_id TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    name TEXT,
    description TEXT,
    PRIMARY KEY (governance_id)
);

CREATE INDEX IF NOT EXISTS idx_register_govs_active_governance_id
ON register_govs(active, governance_id);

CREATE TABLE IF NOT EXISTS register_subjects (
    governance_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),
    namespace TEXT NOT NULL,
    name TEXT,
    description TEXT,
    PRIMARY KEY (governance_id, subject_id)
);

CREATE INDEX IF NOT EXISTS idx_register_subjects_governance_active_subject
ON register_subjects(governance_id, active, subject_id);

CREATE INDEX IF NOT EXISTS idx_register_subjects_governance_schema_subject
ON register_subjects(governance_id, schema_id, subject_id);

CREATE INDEX IF NOT EXISTS idx_register_subjects_governance_active_schema_subject
ON register_subjects(governance_id, active, schema_id, subject_id);
-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
