use ave_common::{ValueWrapper, identity::DigestIdentifier};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::evaluation::compiler::error::CompilerError;
use crate::evaluation::runner::error::RunnerError;

/// A struct representing an evaluation response.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum EvaluationRes {
    Error {
        error: EvaluatorError,
        eval_req_hash: DigestIdentifier,
        req_subject_data_hash: DigestIdentifier,
    },
    Abort(String),
    TimeOut,
    Response {
        response: EvaluatorResponse,
        eval_req_hash: DigestIdentifier,
        req_subject_data_hash: DigestIdentifier,
    },
    Reboot,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Hash,
)]
pub enum EvaluatorError {
    InvalidEventSignature,
    InvalidEventRequest(String),
    Runner(EvalRunnerError),
    InternalError(String),
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Hash,
)]
pub enum EvalRunnerError {
    InvalidEvent(String),
    ContractFailed(String),
    ContractNotFound(String),
}

impl std::fmt::Display for EvalRunnerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvent(msg) => write!(f, "invalid event: {}", msg),
            Self::ContractFailed(msg) => write!(f, "contract failed: {}", msg),
            Self::ContractNotFound(msg) => {
                write!(f, "contract not found: {}", msg)
            }
        }
    }
}

impl std::fmt::Display for EvaluatorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEventSignature => write!(f, "invalid event signature"),
            Self::InvalidEventRequest(e) => {
                write!(f, "invalid event request {}", e)
            }
            Self::Runner(e) => write!(f, "runner error: {}", e),
            Self::InternalError(msg) => write!(f, "internal error: {}", msg),
        }
    }
}

impl From<CompilerError> for EvaluatorError {
    fn from(value: CompilerError) -> Self {
        match value {
            // Errores del usuario: el contrato enviado es inválido
            CompilerError::Base64DecodeFailed { .. } => {
                Self::InvalidEventRequest(value.to_string())
            }
            CompilerError::CompilationFailed
            | CompilerError::InvalidModule { .. }
            | CompilerError::EntryPointNotFound { .. }
            | CompilerError::ContractCheckFailed { .. }
            | CompilerError::ContractExecutionFailed { .. }
            | CompilerError::InvalidContractOutput { .. } => {
                Self::Runner(EvalRunnerError::ContractFailed(value.to_string()))
            }
            // Fallos del sistema: no deberían ocurrir en un entorno sano
            CompilerError::CargoBuildFailed { .. }
            | CompilerError::InvalidContractPath { .. }
            | CompilerError::DirectoryCreationFailed { .. }
            | CompilerError::FileWriteFailed { .. }
            | CompilerError::FileReadFailed { .. }
            | CompilerError::MetadataParseFailed { .. }
            | CompilerError::MissingHelper { .. }
            | CompilerError::FuelLimitError { .. }
            | CompilerError::WasmPrecompileFailed { .. }
            | CompilerError::WasmDeserializationFailed { .. }
            | CompilerError::InstantiationFailed { .. }
            | CompilerError::MemoryAllocationFailed { .. }
            | CompilerError::SerializationError { .. } => {
                Self::InternalError(value.to_string())
            }
        }
    }
}

impl From<RunnerError> for EvaluatorError {
    fn from(value: RunnerError) -> Self {
        match value {
            RunnerError::InvalidEvent { .. } => {
                Self::Runner(EvalRunnerError::InvalidEvent(value.to_string()))
            }
            RunnerError::ContractFailed { .. } => {
                Self::Runner(EvalRunnerError::ContractFailed(value.to_string()))
            }
            RunnerError::ContractNotFound { .. } => Self::Runner(
                EvalRunnerError::ContractNotFound(value.to_string()),
            ),
            RunnerError::MissingHelper { .. } => {
                Self::InternalError(value.to_string())
            }
            RunnerError::WasmError { .. } => {
                Self::InternalError(value.to_string())
            }
            RunnerError::SerializationError { .. } => {
                Self::InternalError(value.to_string())
            }
            RunnerError::MemoryError { .. } => {
                Self::InternalError(value.to_string())
            }
        }
    }
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Hash,
)]
pub struct EvaluatorResponse {
    /// The patch to apply to the state.
    pub patch: ValueWrapper,
    /// The hash of the state after applying the patch.
    pub properties_hash: DigestIdentifier,
    /// Whether approval is required for the evaluation to be applied to the state.
    pub appr_required: bool,
}

pub enum ResponseSummary {
    Reboot,
    Error,
    Ok,
}

impl ResponseSummary {
    pub const fn is_ok(&self) -> bool {
        match self {
            Self::Reboot => false,
            Self::Error => false,
            Self::Ok => true,
        }
    }
}
