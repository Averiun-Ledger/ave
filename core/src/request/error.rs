use ave_actors::ActorError;
use ave_common::identity::DigestIdentifier;
use thiserror::Error;

use crate::{
    governance::error::GovernanceError,
    model::error::{LedgerError, ProtocolsError},
};

#[derive(Debug, Error, Clone)]
pub enum RequestHandlerError {
    /// Helpers (hash algorithm, network sender) are not initialized.
    #[error("helpers are not initialized")]
    HelpersNotInitialized,

    #[error("the payload cannot be deserialized as a governance event")]
    GovFactInvalidEvent,

    #[error("governance fact events cannot define viewpoints")]
    GovFactViewpointsNotAllowed,

    #[error("invalid tracker fact viewpoints: {0}")]
    InvalidTrackerFactViewpoints(String),

    /// Attempted to mark an approval as obsolete.
    #[error("a user cannot mark a request approval as obsolete")]
    ObsoleteApproval,

    /// Approval actor not found for a subject.
    #[error(
        "no approval found for subject '{0}', node likely no longer has approver role"
    )]
    ApprovalNotFound(String),

    /// Failed to change approval state.
    #[error("failed to change approval state")]
    ApprovalChangeFailed,

    /// Failed to get approval state.
    #[error("failed to get approval state")]
    ApprovalGetFailed,

    /// Not the owner of the subject.
    #[error("not the owner of subject '{0}'")]
    NotOwner(String),

    /// There is a pending new_owner on the subject.
    #[error("subject '{0}' has a pending new owner")]
    PendingNewOwner(String),

    /// The signer is the owner but should not be (Confirm/Reject).
    #[error("signer is the owner of subject '{0}', cannot confirm/reject")]
    IsOwner(String),

    /// The signer is not the new owner (Confirm/Reject).
    #[error("signer is not the new owner of subject '{0}'")]
    NotNewOwner(String),

    /// No new owner pending (Confirm/Reject).
    #[error("no new owner pending for subject '{0}'")]
    NoNewOwnerPending(String),

    /// Subject name validation failed.
    #[error("subject name must be between 1 and 100 characters")]
    InvalidName,

    /// Subject description validation failed.
    #[error("subject description must be between 1 and 200 characters")]
    InvalidDescription,

    /// Invalid schema_id in request.
    #[error("invalid schema_id in request")]
    InvalidSchemaId,

    /// Governance creation must have empty governance_id.
    #[error("governance creation must have empty governance_id")]
    GovernanceIdMustBeEmpty,

    /// Governance creation must have empty namespace.
    #[error("governance creation must have empty namespace")]
    NamespaceMustBeEmpty,

    /// Non-governance creation must have a governance_id.
    #[error("non-governance creation must have a governance_id")]
    GovernanceIdRequired,

    /// Transfer event must have a new_owner.
    #[error("transfer event must have a non-empty new_owner")]
    TransferNewOwnerEmpty,

    /// Confirm event name_old_owner is empty.
    #[error(
        "governance confirm event name_old_owner cannot be empty if present"
    )]
    ConfirmNameOldOwnerEmpty,

    /// Confirm event for tracker should not have name_old_owner.
    #[error("tracker confirm event must not have name_old_owner")]
    ConfirmTrackerNameOldOwner,

    /// SubjectData not found.
    #[error("subject data not found for subject '{0}'")]
    SubjectDataNotFound(String),

    /// Subject is not active.
    #[error("subject '{0}' is not active")]
    SubjectNotActive(String),

    /// Creation events cannot be queued.
    #[error("creation events cannot be queued")]
    CreationNotQueued,

    /// Failed to compute request_id hash.
    #[error("failed to compute request_id: {0}")]
    RequestIdHash(String),

    /// Failed to compute subject_id hash.
    #[error("failed to compute subject_id: {0}")]
    SubjectIdHash(String),

    /// Failed to verify request signature.
    #[error("request signature verification failed: {0}")]
    SignatureVerification(String),

    /// Wrapped ActorError for actor operations.
    #[error("actor error: {0}")]
    Actor(#[from] ActorError),
}

impl From<RequestHandlerError> for ActorError {
    fn from(err: RequestHandlerError) -> Self {
        match err {
            RequestHandlerError::HelpersNotInitialized => {
                Self::FunctionalCritical {
                    description: err.to_string(),
                }
            }
            RequestHandlerError::Actor(e) => e,
            _ => Self::Functional {
                description: err.to_string(),
            },
        }
    }
}

#[derive(Debug, Error, Clone)]
pub enum RequestManagerError {
    #[error(
        "the subject could not be created; the maximum limit has been reached."
    )]
    CheckLimit,
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
    NoEvaluatorsAvailable {
        schema_id: String,
        governance_id: DigestIdentifier,
    },

    #[error("no approvers available for schema '{schema_id}'")]
    NoApproversAvailable {
        schema_id: String,
        governance_id: DigestIdentifier,
    },

    #[error("no validators available for schema '{schema_id}'")]
    NoValidatorsAvailable {
        schema_id: String,
        governance_id: DigestIdentifier,
    },

    #[error(
        "governance version changed for '{governance_id}': expected {expected}, got {current}"
    )]
    GovernanceVersionChanged {
        governance_id: DigestIdentifier,
        expected: u64,
        current: u64,
    },

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

    #[error("ledger error: {0}")]
    Ledger(#[from] LedgerError),

    // Wrapped ActorError for operations that return ActorError
    #[error("actor error: {0}")]
    ActorError(#[from] ActorError),

    #[error("Can not obtain SubjectData, is None")]
    SubjecData,

    #[error("In fact events, the signer has to be an issuer")]
    NotIssuer,
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
