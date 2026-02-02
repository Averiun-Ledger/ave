use ave_actors::ActorError;
use ave_common::identity::DigestIdentifier;
use thiserror::Error;

use crate::{governance::error::GovernanceError, model::event::ProtocolsError};

#[derive(Debug, Error, Clone)]
pub enum RequestManagerError {
    // Internal state errors
    #[error("request is not set")]
    RequestNotSet,

    #[error("helpers (hash algorithm and network sender) are not initialized")]
    HelpersNotInitialized,

    #[error("invalid request state: expected {expected}, got {got}")]
    InvalidRequestState {
        expected: &'static str,
        got: &'static str,
    },

    // Event request type errors
    #[error("only Fact, Transfer and Confirm requests can be evaluated")]
    InvalidEventRequestForEvaluation,

    #[error("Confirm events on tracker subjects cannot be evaluated")]
    ConfirmNotEvaluableForTracker,

    // Protocol participant errors
    #[error("no evaluators available for schema '{schema_id}'")]
    NoEvaluatorsAvailable { schema_id: String, governance_id: DigestIdentifier },

    #[error("no approvers available for schema '{schema_id}'")]
    NoApproversAvailable { schema_id: String, governance_id: DigestIdentifier },

    #[error("no validators available for schema '{schema_id}'")]
    NoValidatorsAvailable { schema_id: String, governance_id: DigestIdentifier },

    // Governance errors
    #[error("governance error: {0}")]
    Governance(#[from] GovernanceError),

    // Subject data errors
    #[error("subject data not found for subject '{subject_id}'")]
    SubjectDataNotFound { subject_id: String },

    #[error("last ledger event not found for subject")]
    LastLedgerEventNotFound,

    #[error("failed to compute ledger hash: {details}")]
    LedgerHashFailed { details: String },

    // Protocol build errors
    #[error("failed to build protocols: {0}")]
    ProtocolsBuild(#[from] ProtocolsError),

    // Wrapped ActorError for operations that return ActorError
    #[error("actor error: {0}")]
    ActorError(#[from] ActorError),
}

/*
Abort:
Governance

//////////////////////
reboot:
NoEvaluatorsAvailable
NoApproversAvailable
NoValidatorsAvailable
*/