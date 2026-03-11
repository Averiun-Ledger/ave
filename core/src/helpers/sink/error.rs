//! Sink error types.
//!

use thiserror::Error;

/// Errors that can occur during sink operations.
#[derive(Debug, Clone, Error)]
pub enum SinkError {
    /// Failed to build HTTP client.
    #[error("failed to build HTTP client: {0}")]
    ClientBuild(String),

    /// Failed to send authentication request.
    #[error("failed to send auth request: {0}")]
    AuthRequest(String),

    /// Authentication endpoint returned an error.
    #[error("auth endpoint error: {0}")]
    AuthEndpoint(String),

    /// Failed to parse OAuth 2.0 token response.
    #[error("failed to parse token response: {0}")]
    TokenParse(String),

    /// Failed to send data to sink.
    #[error("failed to send data to sink: {message}")]
    SendRequest { message: String, retryable: bool },

    /// Sink returned unauthorized (401).
    #[error("sink authentication failed")]
    Unauthorized,

    /// Sink returned unprocessable entity (422).
    #[error("sink rejected data format: {message}")]
    UnprocessableEntity { message: String },

    /// Sink returned an HTTP error.
    #[error("sink returned HTTP {status}: {message}")]
    HttpStatus {
        status: u16,
        message: String,
        retryable: bool,
    },

    /// Sink worker stopped because shutdown was requested.
    #[error("sink shutdown in progress")]
    Shutdown,
}

impl SinkError {
    pub const fn is_transient(&self) -> bool {
        match self {
            Self::SendRequest { retryable, .. }
            | Self::HttpStatus { retryable, .. } => *retryable,
            Self::ClientBuild(_)
            | Self::AuthRequest(_)
            | Self::AuthEndpoint(_)
            | Self::TokenParse(_)
            | Self::Unauthorized
            | Self::UnprocessableEntity { .. }
            | Self::Shutdown => false,
        }
    }
}
