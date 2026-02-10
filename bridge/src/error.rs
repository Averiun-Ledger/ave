use thiserror::Error;

use ave_core::error::Error as CoreError;
use ave_core::helpers::sink::SinkError;

/// Bridge API errors.
///
/// These errors wrap core errors and add bridge-specific error types
/// for input validation, key management, and configuration.
#[derive(Debug, Clone, Error)]
pub enum BridgeError {
    // ========================================
    // Core Errors (propagated from Ave core)
    // ========================================
    /// An error originated in the core layer.
    #[error(transparent)]
    Core(#[from] CoreError),

    // ========================================
    // Input Validation Errors
    // ========================================
    /// The provided subject identifier is not valid.
    #[error("Invalid subject identifier: {0}")]
    InvalidSubjectId(String),

    /// The provided request identifier is not valid.
    #[error("Invalid request identifier: {0}")]
    InvalidRequestId(String),

    /// The provided public key is not valid.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// The provided signature is not valid.
    #[error("Invalid signature: {0}")]
    InvalidSignature(String),

    // ========================================
    // Key Management Errors
    // ========================================
    /// Failed to create the keys directory.
    #[error("Failed to create keys directory: {0}")]
    KeyDirectoryCreation(String),

    /// Failed to read the private key file.
    #[error("Failed to read private key: {0}")]
    KeyRead(String),

    /// Failed to decrypt the private key. Usually indicates a wrong password.
    #[error("Failed to decrypt private key: ensure your password is correct")]
    KeyDecrypt(String),

    /// Failed to create a key pair from the stored key material.
    #[error("Failed to restore key pair: {0}")]
    KeyRestore(String),

    /// Failed to generate a new key pair.
    #[error("Failed to generate key pair: {0}")]
    KeyGeneration(String),

    /// Failed to encrypt the private key for storage.
    #[error("Failed to encrypt private key: {0}")]
    KeyEncrypt(String),

    /// Failed to write the private key file.
    #[error("Failed to store private key: {0}")]
    KeyWrite(String),

    // ========================================
    // Configuration Errors
    // ========================================
    /// Failed to build the configuration from the provided sources.
    #[error("Failed to build configuration: {0}")]
    ConfigBuild(String),

    /// Failed to deserialize the configuration file.
    #[error("Invalid configuration format: {0}")]
    ConfigDeserialize(String),

    // ========================================
    // Conversion Errors
    // ========================================
    /// The event request could not be converted to the internal format.
    #[error("Invalid event request format: {0}")]
    InvalidEventRequest(String),

    // ========================================
    // Sink Authentication Errors
    // ========================================
    /// Sink authentication failed during initialization.
    #[error("Sink authentication failed: {0}")]
    SinkAuth(#[from] SinkError),
}
