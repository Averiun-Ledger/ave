//! Core API error types.
//!
//! These errors are exposed to end users through the API and should provide
//! clear, actionable error messages.

use thiserror::Error;

/// Core API errors that may be returned to users.
#[derive(Debug, Clone, Error)]
pub enum Error {
    // ========================================
    // System Initialization Errors
    // ========================================
    /// System initialization failed.
    #[error("System initialization failed: {0}")]
    SystemInit(String),

    /// Failed to create a required actor.
    #[error("Failed to initialize {actor}: {reason}")]
    ActorCreation { actor: String, reason: String },

    /// Required helper or resource not found.
    #[error("Required resource '{name}' not found: {reason}")]
    MissingResource { name: String, reason: String },

    // ========================================
    // Network Errors
    // ========================================
    /// Network operation failed.
    #[error("Network error: {0}")]
    Network(String),

    /// Unable to retrieve network state.
    #[error("Unable to retrieve network state: {0}")]
    NetworkState(String),

    // ========================================
    // Request Handling Errors
    // ========================================
    /// Request could not be processed.
    #[error("Request processing failed: {0}")]
    RequestProcessing(String),

    /// Request signature is invalid or verification failed.
    #[error("Invalid request signature: {0}")]
    InvalidSignature(String),

    /// Node was unable to sign the request.
    #[error("Failed to sign request: {0}")]
    SigningFailed(String),

    /// Request not found in tracking system.
    #[error("Request '{0}' not found")]
    RequestNotFound(String),

    /// Request is in an invalid state for this operation.
    #[error("Request is in invalid state: {0}")]
    InvalidRequestState(String),

    // ========================================
    // Approval Errors
    // ========================================
    /// Invalid approval state transition.
    #[error("Invalid approval state: cannot set approval to '{0}'")]
    InvalidApprovalState(String),

    /// Approval not found for subject.
    #[error("No approval request found for subject '{0}'")]
    ApprovalNotFound(String),

    /// Failed to update approval state.
    #[error("Failed to update approval state: {0}")]
    ApprovalUpdateFailed(String),

    // ========================================
    // Subject & Governance Errors
    // ========================================
    /// Subject not found.
    #[error("Subject '{0}' not found")]
    SubjectNotFound(String),

    /// Subject is not active.
    #[error("Subject '{0}' is not active")]
    SubjectNotActive(String),

    /// Governance not found.
    #[error("Governance '{0}' not found")]
    GovernanceNotFound(String),

    /// Invalid subject identifier.
    #[error("Invalid subject identifier: {0}")]
    InvalidSubjectId(String),

    // ========================================
    // Authorization Errors
    // ========================================
    /// Authorization failed.
    #[error("Authorization failed: {0}")]
    Unauthorized(String),

    /// Insufficient permissions for operation.
    #[error("Insufficient permissions: {0}")]
    Forbidden(String),

    /// Authentication subject operation failed.
    #[error("Authentication operation failed: {0}")]
    AuthOperation(String),

    /// Witnesses not found for subject.
    #[error("No witnesses found for subject '{0}'")]
    WitnessesNotFound(String),

    // ========================================
    // Query Errors
    // ========================================
    /// Query execution failed.
    #[error("Query failed: {0}")]
    QueryFailed(String),

    /// No events found matching criteria.
    #[error("No events found for subject '{0}'")]
    NoEventsFound(String),

    /// Event not found at specified sequence number.
    #[error("Event not found for subject '{subject}' at sequence number {sn}")]
    EventNotFound { subject: String, sn: u64 },

    /// Invalid query parameters.
    #[error("Invalid query parameters: {0}")]
    InvalidQueryParams(String),

    /// Database query error.
    #[error("Database error: {0}")]
    DatabaseError(String),

    // ========================================
    // Validation Errors
    // ========================================
    /// Request validation failed.
    #[error("Validation failed: {0}")]
    ValidationFailed(String),

    /// Invalid event request format.
    #[error("Invalid event request: {0}")]
    InvalidEventRequest(String),

    /// Schema validation failed.
    #[error("Schema validation failed: {0}")]
    SchemaValidation(String),

    // ========================================
    // Actor Communication Errors
    // ========================================
    /// Actor communication failed.
    #[error("Internal communication error: failed to communicate with {actor}")]
    ActorCommunication { actor: String },

    /// Received unexpected response from actor.
    #[error(
        "Unexpected response from {actor}: expected {expected}, got {received}"
    )]
    UnexpectedResponse {
        actor: String,
        expected: String,
        received: String,
    },

    /// Actor returned an error.
    #[error("Operation failed: {0}")]
    ActorError(String),

    // ========================================
    // Transfer Errors
    // ========================================
    /// Subject transfer operation failed.
    #[error("Transfer operation failed: {0}")]
    TransferFailed(String),

    /// No pending transfers found.
    #[error("No pending transfers found")]
    NoPendingTransfers,

    // ========================================
    // Distribution Errors
    // ========================================
    /// Manual distribution failed.
    #[error("Manual distribution failed for subject '{0}'")]
    DistributionFailed(String),

    /// Update operation failed.
    #[error("Update failed for subject '{0}': {1}")]
    UpdateFailed(String, String),

    // ========================================
    // Generic/Fallback Errors
    // ========================================
    /// Internal server error (catch-all for unexpected errors).
    #[error("Internal error: {0}")]
    Internal(String),

    /// Operation timed out.
    #[error("Operation timed out: {0}")]
    Timeout(String),

    /// Feature not implemented.
    #[error("Feature not implemented: {0}")]
    NotImplemented(String),
}

// Conversions from subsystem errors
impl From<crate::system::SystemError> for Error {
    fn from(err: crate::system::SystemError) -> Self {
        Error::SystemInit(err.to_string())
    }
}

impl From<ave_actors::ActorError> for Error {
    fn from(err: ave_actors::ActorError) -> Self {
        match err {
            ave_actors::ActorError::NotFound { path } => {
                Error::MissingResource {
                    name: path.to_string(),
                    reason: "Actor not found".to_string(),
                }
            }
            ave_actors::ActorError::Functional { description } => {
                Error::ActorError(description)
            }
            ave_actors::ActorError::FunctionalCritical { description } => {
                Error::Internal(description)
            }
            _ => Error::Internal(err.to_string()),
        }
    }
}
