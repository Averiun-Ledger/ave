//! Error types returned by `ave-identity`.
//!
//! The enum keeps parsing, serialization and cryptographic failures under a
//! single type so callers can propagate or match them without depending on the
//! implementation details of each algorithm.

use thiserror::Error;

/// Errors returned by hashing, key handling and signature operations.
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// The identifier prefix does not match any supported algorithm.
    #[error("Unknown algorithm identifier: {0}")]
    UnknownAlgorithm(String),

    /// A digest cannot be parsed or does not match the expected layout.
    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    /// A signature cannot be parsed or does not match the expected layout.
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    /// Signature verification failed.
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// A public key is malformed or has an unexpected size.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// A secret key is malformed, missing data or cannot be decrypted.
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Signing was requested from a verification-only value.
    #[error("No secret key available for signing (verification-only instance)")]
    MissingSecretKey,

    /// Base64 decoding failed.
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),

    /// The input size does not match the size required by the algorithm.
    #[error("Invalid data length: expected {expected}, got {actual}")]
    InvalidDataLength { expected: usize, actual: usize },

    /// Borsh serialization or deserialization failed.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Hash computation or hash comparison failed.
    #[error("Hash computation failed: {0}")]
    HashError(String),

    /// A signing operation could not be completed.
    #[error("Signing failed: {0}")]
    SigningError(String),

    /// The algorithm is recognized but not implemented by this crate.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// PKCS#8 DER parsing failed.
    #[error("Invalid PKCS#8 DER format: {0}")]
    InvalidDerFormat(String),
}
