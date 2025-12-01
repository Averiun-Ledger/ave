//! Error types for Ave Common
//!
//! Simplified error types without heavy dependencies

use thiserror::Error;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Error, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum Error {
    /// Bridge error
    #[error("Bridge error: {0}")]
    Bridge(String),

    /// Serialization/Deserialization error
    #[error("Serde error: {0}")]
    Serde(String),

    /// Invalid identifier error
    #[error("Invalid identifier: {0}")]
    InvalidIdentifier(String),

    /// Generic error
    #[error("{0}")]
    Generic(String),
}

impl From<serde_json::Error> for Error {
    fn from(err: serde_json::Error) -> Self {
        Error::Serde(err.to_string())
    }
}
