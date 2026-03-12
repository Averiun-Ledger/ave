//! Database error types.
//!

use thiserror::Error;

/// Errors that can occur during database operations.
#[derive(Debug, Clone, Error)]
pub enum DatabaseError {
    /// Failed to acquire mutex lock on database connection.
    #[error("failed to lock database connection")]
    MutexLock,

    /// Database pool or connection coordination failed.
    #[error("database pool error: {0}")]
    Pool(String),

    /// Failed to open database connection.
    #[error("failed to open database connection: {0}")]
    ConnectionOpen(String),

    /// Database migration failed.
    #[error("migration failed: {0}")]
    Migration(String),

    /// Failed to create database directory.
    #[error("failed to create database directory: {0}")]
    DirectoryCreation(String),

    /// SQL query execution failed.
    #[error("query failed: {0}")]
    Query(String),

    /// Failed to serialize data to JSON.
    #[error("JSON serialization failed: {0}")]
    JsonSerialize(String),

    /// Failed to deserialize data from JSON.
    #[error("JSON deserialization failed: {0}")]
    JsonDeserialize(String),

    /// Integer conversion failed (e.g., u64 to i64).
    #[error("integer conversion failed: {0}")]
    IntegerConversion(String),

    /// Subject not found in database.
    #[error("subject not found: {0}")]
    SubjectNotFound(String),

    /// Governance not found in register projection.
    #[error("governance not found: {0}")]
    GovernanceNotFound(String),

    /// Event not found in database.
    #[error("event not found for subject {subject_id} at sn {sn}")]
    EventNotFound { subject_id: String, sn: u64 },

    /// No events found for subject.
    #[error("no events found for subject: {0}")]
    NoEvents(String),

    /// Failed to parse date/time string.
    #[error("date/time parse failed: {0}")]
    DateTimeParse(String),

    /// Invalid pagination cursor.
    #[error("invalid pagination cursor: {0}")]
    InvalidCursor(String),

    /// Failed to execute SQLite work in a blocking task.
    #[error("database blocking task failed: {0}")]
    BlockingTask(String),
}
