//! Error types used by `ave-common`.

use thiserror::Error;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Errors returned when converting bridge payloads into internal types.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum ConversionError {
    #[error("invalid subject identifier: {0}")]
    InvalidSubjectId(String),

    #[error("invalid governance identifier: {0}")]
    InvalidGovernanceId(String),

    #[error("invalid schema identifier: {0}")]
    InvalidSchemaId(String),

    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid namespace: {0}")]
    InvalidNamespace(String),

    #[error("missing governance identifier")]
    MissingGovernanceId,

    #[error("missing namespace")]
    MissingNamespace,
}

/// Errors returned when decoding API-facing signatures.
#[derive(Debug, Clone, Error)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum SignatureError {
    #[error("invalid public key: {0}")]
    InvalidPublicKey(String),

    #[error("invalid signature value: {0}")]
    InvalidSignature(String),

    #[error("invalid content hash: {0}")]
    InvalidContentHash(String),
}

/// Top-level error type for this crate.
#[derive(Error, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum Error {
    /// Bridge error
    #[error("bridge error: {0}")]
    Bridge(String),

    /// Serialization/Deserialization error
    #[error("serde error: {0}")]
    Serde(String),

    /// Invalid identifier error
    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    /// Conversion error
    #[error("conversion error: {0}")]
    Conversion(#[from] ConversionError),

    /// Signature error
    #[error("signature error: {0}")]
    Signature(#[from] SignatureError),

    /// Generic error
    #[error("{0}")]
    Generic(String),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Self::Serde(err.to_string())
    }
}
