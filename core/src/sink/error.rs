//! Sink error types.
//!

use thiserror::Error;

/// Errors that can occur during sink operations.
#[derive(Debug, Clone, Error)]
pub enum SinkError {
    /// Failed to build or configure the transport.
    #[error("failed to build sink transport: {0}")]
    ClientBuild(String),

    /// Delivery failure (network/protocol). `retryable` drives the retry loop.
    #[error("failed to deliver data to sink: {message}")]
    Delivery { message: String, retryable: bool },

    /// Authentication/authorization failed. The worker treats it as
    /// AuthFailed (subject goes to lagging, retried via catch-up).
    #[error("sink authentication failed: {message}")]
    Auth { message: String },

    /// Permanent payload rejection (e.g. 422, flapping) → sink blocked.
    #[error("sink rejected data: {message}")]
    Rejected { message: String },

    /// Sink worker stopped because shutdown was requested.
    #[error("sink shutdown in progress")]
    Shutdown,
}
