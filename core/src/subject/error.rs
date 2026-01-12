use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum SubjectError {
    #[error("subject is not active")]
    SubjectNotActive,

    #[error("invalid ledger signer")]
    InvalidLedgerSigner,

    #[error("invalid event signer")]
    InvalidEventSigner,

    #[error("signature verification failed [{context}]: {details}")]
    SignatureVerificationFailed {
        context: &'static str,
        details: String,
    },

    #[error("hash computation failed [{context}]: {details}")]
    HashComputationFailed {
        context: &'static str,
        details: String,
    },

    #[error("hash mismatch: {kind}")]
    HashMismatch { kind: HashMismatchKind },

    #[error("event sequence error: {kind}")]
    EventSequenceError { kind: EventSequenceKind },

    #[error("invalid event: {kind}")]
    InvalidEvent { kind: InvalidEventKind },

    #[error("create event validation: {kind}")]
    CreateEventError { kind: CreateEventErrorKind },

    #[error("patch error: {kind}")]
    PatchError { kind: PatchErrorKind },
}

#[derive(Debug, Clone)]
pub enum HashMismatchKind {
    PreviousEventHash {
        message: &'static str,
    },
    StateHashWithoutPatch {
        event_type: &'static str,
    },
    StateHashAfterPatch,
}

impl std::fmt::Display for HashMismatchKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PreviousEventHash { message } => write!(f, "{}", message),
            Self::StateHashWithoutPatch { event_type } => {
                write!(
                    f,
                    "in {} event, the hash obtained without applying any patch is different from the state hash of the event",
                    event_type
                )
            }
            Self::StateHashAfterPatch => {
                write!(
                    f,
                    "the new patch has been applied and we have obtained a different hash than the event after applying the patch"
                )
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum EventSequenceKind {
    CreateAfterCreation,
    FactAfterTransfer,
    TransferAfterTransfer,
    ConfirmWithoutTransfer,
    RejectWithoutTransfer,
    EolAfterTransfer,
    EventAfterEol,
}

impl std::fmt::Display for EventSequenceKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CreateAfterCreation => {
                write!(
                    f,
                    "a creation event is being logged when the subject has already been created previously"
                )
            }
            Self::FactAfterTransfer => {
                write!(
                    f,
                    "after a transfer event there must be a confirmation or a reject event"
                )
            }
            Self::TransferAfterTransfer => {
                write!(
                    f,
                    "after a transfer event there must be a confirmation or a reject event"
                )
            }
            Self::ConfirmWithoutTransfer => {
                write!(f, "before a confirm event there must be a transfer event")
            }
            Self::RejectWithoutTransfer => {
                write!(f, "before a reject event there must be a transfer event")
            }
            Self::EolAfterTransfer => {
                write!(
                    f,
                    "after a transfer event there must be a confirmation or a reject event"
                )
            }
            Self::EventAfterEol => {
                write!(f, "the last event was EOL, no more events can be received")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum InvalidEventKind {
    NameLength { length: usize },
    DescriptionLength { length: usize },
    InvalidSequenceNumber { expected: u64, actual: u64 },
    InvalidPreviousHash,
    InvalidSigner { context: &'static str },
    NotCreateEvent,
}

impl std::fmt::Display for InvalidEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NameLength { length } => {
                write!(
                    f,
                    "the subject name must be less than 100 characters or not be empty (got {} characters)",
                    length
                )
            }
            Self::DescriptionLength { length } => {
                write!(
                    f,
                    "the subject description must be less than 200 characters or not be empty (got {} characters)",
                    length
                )
            }
            Self::InvalidSequenceNumber { expected, actual } => {
                write!(
                    f,
                    "invalid sequence number (expected: {}, got: {})",
                    expected, actual
                )
            }
            Self::InvalidPreviousHash => {
                write!(f, "in create event, previous hash event must be empty")
            }
            Self::InvalidSigner { context } => {
                write!(f, "in create event, owner must sign request and event: {}", context)
            }
            Self::NotCreateEvent => {
                write!(f, "first event is not a create event")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum CreateEventErrorKind {
    InvalidGovernanceMetadata,
    SequenceNumberNotZero { sn: u64 },
    ValidationProtocolFailed,
}

impl std::fmt::Display for CreateEventErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidGovernanceMetadata => {
                write!(
                    f,
                    "in create event, governance_id must be empty, namespace must be empty and gov version must be 0"
                )
            }
            Self::SequenceNumberNotZero { sn } => {
                write!(f, "in create event, sn must be 0 (got: {})", sn)
            }
            Self::ValidationProtocolFailed => {
                write!(f, "create event fail in validation protocol")
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum PatchErrorKind {
    MissingPatch,
    InvalidPatchFormat { details: String },
    PatchApplicationFailed,
}

impl std::fmt::Display for PatchErrorKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingPatch => {
                write!(
                    f,
                    "the event was successful but does not have a json patch to apply"
                )
            }
            Self::InvalidPatchFormat { details } => {
                write!(f, "failed to extract event patch: {}", details)
            }
            Self::PatchApplicationFailed => {
                write!(f, "failed to apply event patch")
            }
        }
    }
}
