-- Ave Core - Initial Schema Migration
--
-- This migration creates the complete database schema for Ave ledger operations including:
-- - Request state tracking
-- - Approval workflow management
-- - Validation tracking
-- - Event history storage
-- - Subject metadata storage
-- - Signature tracking (evaluators, approvers, validators)

-- =============================================================================
-- REQUEST TABLE
-- =============================================================================
-- Tracks the state and version of event requests as they flow through the system
CREATE TABLE IF NOT EXISTS request (
    id TEXT NOT NULL,
    state TEXT NOT NULL,
    version INTEGER NOT NULL,
    error TEXT,
    PRIMARY KEY (id)
);

-- =============================================================================
-- APPROVAL TABLE
-- =============================================================================
-- Stores approval request data and state for each subject
CREATE TABLE IF NOT EXISTS approval (
    subject_id TEXT NOT NULL,
    data TEXT NOT NULL,        -- JSON serialized ApprovalReq
    state TEXT NOT NULL,        -- Approval state
    PRIMARY KEY (subject_id)
);

-- =============================================================================
-- EVENTS TABLE
-- =============================================================================
-- Stores the complete event history for all subjects in the ledger
-- Each event is identified by subject_id + sn (sequence number)
CREATE TABLE IF NOT EXISTS events (
    subject_id TEXT NOT NULL,
    sn INTEGER NOT NULL,
    patch TEXT,                 -- JSON patch applied (if success)
    error TEXT,                 -- Error information (if failed)
    event_req TEXT NOT NULL,    -- JSON serialized event request
    succes INTEGER NOT NULL CHECK (succes IN (0, 1)),  -- 0 = false, 1 = true
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
    namespace TEXT NOT NULL,
    schema_id TEXT NOT NULL,
    owner TEXT NOT NULL,
    creator TEXT NOT NULL,
    active INTEGER NOT NULL CHECK (active IN (0, 1)),  -- 0 = false, 1 = true
    sn INTEGER NOT NULL,         -- Current sequence number
    properties TEXT NOT NULL,    -- JSON serialized subject properties
    new_owner TEXT,              -- New owner during ownership transfer
    PRIMARY KEY (subject_id)
);

-- =============================================================================
-- SIGNATURES TABLE
-- =============================================================================
-- Tracks signatures from evaluators, approvers, and validators for each event
CREATE TABLE IF NOT EXISTS signatures (
    subject_id TEXT NOT NULL,
    sn INTEGER NOT NULL,
    signatures_eval TEXT,        -- JSON serialized HashSet<ProtocolsSignatures> (optional)
    signatures_appr TEXT,        -- JSON serialized HashSet<ProtocolsSignatures> (optional)
    signatures_vali TEXT NOT NULL, -- JSON serialized HashSet<ProtocolsSignatures>
    PRIMARY KEY (subject_id)
);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_events_subject ON events(subject_id);
CREATE INDEX IF NOT EXISTS idx_events_sn ON events(sn);
CREATE INDEX IF NOT EXISTS idx_signatures_subject ON signatures(subject_id);

-- =============================================================================
-- END OF MIGRATION
-- =============================================================================
