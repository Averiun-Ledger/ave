use thiserror::Error;

use ave_actors::ActorError;
use ave_common::identity::DigestIdentifier;

#[derive(Debug, Error, Clone)]
pub enum DistributorError {
    #[error("governance is not authorized")]
    GovernanceNotAuthorized,

    #[error("we are not witness for this subject")]
    NotWitness,

    #[error(
        "subject not found: we do not have the subject that we have been asked for"
    )]
    SubjectNotFound,

    #[error("sender '{sender}' is not a member of governance")]
    SenderNotMember { sender: String },

    #[error("sender does not have access to the subject")]
    SenderNoAccess,

    #[error("missing governance_id for tracker subject {subject_id}")]
    MissingGovernanceId { subject_id: DigestIdentifier },

    #[error(
        "missing governance_id in create event for tracker subject {subject_id}"
    )]
    MissingGovernanceIdInCreate { subject_id: DigestIdentifier },

    #[error("updating subject, need to fetch first event")]
    UpdatingSubject,

    #[error(
        "actual_sn ({actual_sn}) is greater than or equal to witness sn ({witness_sn})"
    )]
    ActualSnBiggerThanWitness { actual_sn: u64, witness_sn: u64 },

    #[error("sender is not the expected one")]
    UnexpectedSender,

    #[error("events list is empty")]
    EmptyEvents,

    #[error("missing create event in create ledger for subject {subject_id}")]
    MissingCreateEventInCreateLedger { subject_id: DigestIdentifier },

    #[error(
        "our governance version ({our_version}) is less than theirs ({their_version})"
    )]
    GovernanceVersionMismatch {
        our_version: u64,
        their_version: u64,
    },

    #[error("failed to get governance data: {details}")]
    GetGovernanceFailed { details: String },

    #[error("failed to up tracker: {details}")]
    UpTrackerFailed { details: String },

    #[error("failed to update subject ledger: {details}")]
    UpdateLedgerFailed { details: String },
}

impl From<DistributorError> for ActorError {
    fn from(error: DistributorError) -> Self {
        match error {
            DistributorError::GovernanceNotAuthorized
            | DistributorError::NotWitness
            | DistributorError::SubjectNotFound
            | DistributorError::SenderNotMember { .. }
            | DistributorError::SenderNoAccess
            | DistributorError::UpdatingSubject
            | DistributorError::ActualSnBiggerThanWitness { .. }
            | DistributorError::UnexpectedSender
            | DistributorError::EmptyEvents
            | DistributorError::MissingCreateEventInCreateLedger { .. }
            | DistributorError::GetGovernanceFailed { .. }
            | DistributorError::GovernanceVersionMismatch { .. } => {
                Self::Functional {
                    description: error.to_string(),
                }
            }
            DistributorError::MissingGovernanceId { .. }
            | DistributorError::MissingGovernanceIdInCreate { .. }
            | DistributorError::UpTrackerFailed { .. }
            | DistributorError::UpdateLedgerFailed { .. } => {
                Self::FunctionalCritical {
                    description: error.to_string(),
                }
            }
        }
    }
}
