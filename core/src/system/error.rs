//! System initialization error types.
//!

use thiserror::Error;

/// Errors that can occur during system initialization.
#[derive(Debug, Clone, Error)]
pub enum SystemError {
    /// Failed to create Wasmtime engine.
    #[error("failed to create Wasmtime engine: {0}")]
    EngineCreation(String),

    /// Failed to open database.
    #[error("failed to open database: {0}")]
    DatabaseOpen(String),

    /// Failed to compute password hash.
    #[error("failed to compute password hash: {0}")]
    PasswordHash(String),

    /// Failed to convert hash to array.
    #[error("failed to convert hash to array: {0}")]
    HashArrayConversion(String),

    /// Failed to create encrypted key.
    #[error("failed to create encrypted key: {0}")]
    EncryptedKeyCreation(String),

    /// Failed to create root actor.
    #[error("failed to create root actor: {0}")]
    RootActorCreation(String),

    /// Failed to build external database.
    #[error("failed to build external database: {0}")]
    ExternalDbBuild(String),
}
