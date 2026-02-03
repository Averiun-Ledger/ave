-- Ave Core - Initial Schema Migration
--
-- This migration creates the complete database schema for Ave ledger operations including:
-- - Event history storage
-- - Subject metadata storage

-- =============================================================================
-- EVENTS TABLE
-- =============================================================================
-- Stores the complete event history for all subjects in the ledger
-- Each event is identified by subject_id + sn (sequence number)
CREATE TABLE IF NOT EXISTS events (
    subject_id TEXT NOT NULL,
    sn INTEGER NOT NULL,
    event_request_timestamp INTEGER NOT NULL,
    event_ledger_timestamp INTEGER NOT NULL,
    sink_timestamp INTEGER NOT NULL,
    event TEXT NOT NULL,
    PRIMARY KEY (subject_id, sn)
);

-- =============================================================================
-- SUBJECTS TABLE
-- =============================================================================
-- Stores the current state and metadata for all subjects in the ledger
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
    properties TEXT NOT NULL,    -- JSON serialized subject properties
    PRIMARY KEY (subject_id)
);

-- =============================================================================
-- ABORTS TABLE
-- =============================================================================
CREATE TABLE IF NOT EXISTS aborts (
    request_id TEXT NOT NULL,
    subject_id TEXT NOT NULL,
    sn INTEGER NOT NULL,
    error TEXT NOT NULL,
    who TEXT NOT NULL,
    PRIMARY KEY (request_id)
);
-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
