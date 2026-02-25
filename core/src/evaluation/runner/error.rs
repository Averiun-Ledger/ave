use crate::model::common::contract::ContractError;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum RunnerError {
    #[error("[{location}] invalid event: {kind}")]
    InvalidEvent {
        location: &'static str,
        kind: InvalidEventKind,
    },

    #[error("contract returned failure: {details}")]
    ContractFailed { details: String },

    #[error("contract not found: {name}")]
    ContractNotFound { name: String },

    #[error("missing helper: {name}")]
    MissingHelper { name: &'static str },

    #[error("wasm error [{operation}]: {details}")]
    WasmError {
        operation: &'static str,
        details: String,
    },

    #[error("serialization error [{context}]: {details}")]
    SerializationError {
        context: &'static str,
        details: String,
    },

    #[error("memory error [{operation}]: {details}")]
    MemoryError {
        operation: &'static str,
        details: String,
    },
}

#[derive(Debug, Clone)]
pub enum InvalidEventKind {
    Empty {
        what: String,
    },
    InvalidSize {
        field: String,
        actual: usize,
        max: usize,
    },
    ReservedWord {
        field: String,
        value: String,
    },
    NotFound {
        what: String,
        id: String,
    },
    Duplicate {
        what: String,
        id: String,
    },
    AlreadyExists {
        what: String,
        id: String,
    },
    CannotModify {
        what: String,
        reason: String,
    },
    CannotRemove {
        what: String,
        reason: String,
    },
    InvalidValue {
        field: String,
        reason: String,
    },
    SameValue {
        what: String,
    },
    NotMember {
        who: String,
    },
    NotSchema {
        id: String,
    },
    MissingRole {
        who: String,
        role: String,
        context: String,
    },
    InvalidQuorum {
        context: String,
        details: String,
    },
    Other {
        msg: String,
    },
}

impl std::fmt::Display for InvalidEventKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty { what } => write!(f, "{} cannot be empty", what),
            Self::InvalidSize { field, actual, max } => {
                write!(
                    f,
                    "{} size ({}) exceeds maximum ({})",
                    field, actual, max
                )
            }
            Self::ReservedWord { field, value } => {
                write!(f, "{} cannot be '{}' (reserved word)", field, value)
            }
            Self::NotFound { what, id } => {
                write!(f, "{} '{}' not found", what, id)
            }
            Self::Duplicate { what, id } => {
                write!(f, "{} '{}' already exists", what, id)
            }
            Self::AlreadyExists { what, id } => {
                write!(f, "{} '{}' already exists", what, id)
            }
            Self::CannotModify { what, reason } => {
                write!(f, "cannot modify {}: {}", what, reason)
            }
            Self::CannotRemove { what, reason } => {
                write!(f, "cannot remove {}: {}", what, reason)
            }
            Self::InvalidValue { field, reason } => {
                write!(f, "invalid value for {}: {}", field, reason)
            }
            Self::SameValue { what } => {
                write!(f, "{} is already set to this value", what)
            }
            Self::NotMember { who } => {
                write!(f, "'{}' is not a member of governance", who)
            }
            Self::NotSchema { id } => write!(f, "'{}' is not a schema", id),
            Self::MissingRole { who, role, context } => {
                write!(
                    f,
                    "'{}' does not have role '{}' for {}",
                    who, role, context
                )
            }
            Self::InvalidQuorum { context, details } => {
                write!(f, "invalid quorum for {}: {}", context, details)
            }
            Self::Other { msg } => write!(f, "{}", msg),
        }
    }
}

impl From<ContractError> for RunnerError {
    fn from(error: ContractError) -> Self {
        match error {
            ContractError::MemoryAllocationFailed { .. }
            | ContractError::InvalidPointer { .. }
            | ContractError::WriteOutOfBounds { .. }
            | ContractError::AllocationTooLarge { .. }
            | ContractError::TotalMemoryExceeded { .. }
            | ContractError::AllocationOverflow => Self::MemoryError {
                operation: "contract memory operation",
                details: error.to_string(),
            },
            ContractError::LinkerError { function, details } => {
                Self::WasmError {
                    operation: function,
                    details,
                }
            }
        }
    }
}
