use ave_actors::ActorError;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum LedgerError {
    #[error("failed to hash ledger: {0}")]
    HashingFailed(String),

    #[error("protocols error: {0}")]
    Protocols(#[from] ProtocolsError),
}

#[derive(Debug, Error, Clone)]
pub enum ProtocolsError {
    #[error(
        "invalid evaluation: evaluation result does not match expected state"
    )]
    InvalidEvaluation,

    #[error("invalid evaluation: approval required but not provided")]
    ApprovalRequired,

    #[error("invalid actual protocols: expected {expected}, got {got}")]
    InvalidActualProtocols {
        expected: &'static str,
        got: &'static str,
    },

    #[error(
        "invalid event request type: {request_type} is not supported for is_gov={is_gov}"
    )]
    InvalidEventRequestType {
        request_type: &'static str,
        is_gov: bool,
    },

    #[error(
        "expected create event with metadata, got different protocol or validation metadata"
    )]
    NotCreateWithMetadata,

    #[error("failed to hash protocols: {0}")]
    HashingFailed(String),

    #[error("tracker fact full requires a fact event request")]
    InvalidTrackerFactFullEventRequest,
}

impl From<ProtocolsError> for ActorError {
    fn from(error: ProtocolsError) -> Self {
        Self::Functional {
            description: error.to_string(),
        }
    }
}
