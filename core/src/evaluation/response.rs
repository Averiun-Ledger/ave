use ave_common::identity::Signature;
use ave_common::{ValueWrapper, identity::DigestIdentifier};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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
    Response {
        result: EvaluationResult,
        result_hash: DigestIdentifier,
        result_hash_signature: Signature,
    },
    Abort(String),
    TimeOut,
    Reboot,
    /// The evaluator can not evaluate right now for reasons unrelated to
    /// the request (its local artifacts are missing, its own resources are
    /// not enough...): not a verdict. The requester drops the evaluator from
    /// the current set, pulls fresh ones from the pending pool and only
    /// reboots the request when no evaluator can answer at all.
    ///
    /// Added at the end of the enum on purpose: borsh encodes the variant
    /// ordinal, so existing variants keep their wire value. Nodes running
    /// older code can not deserialize it and treat the message as lost —
    /// the same outcome as the evaluator not answering.
    Unavailable,
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
)]
pub enum EvaluationResult {
    Ok {
        response: EvaluatorResponse,
        eval_req_hash: DigestIdentifier,
        req_subject_data_hash: DigestIdentifier,
    },
    Error {
        error: EvaluatorError,
        eval_req_hash: DigestIdentifier,
        req_subject_data_hash: DigestIdentifier,
    },
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
    /// The node cannot do the work with its own resources (memory or
    /// instantiation limits, which derive from this machine's spec):
    /// another evaluator with more capacity may succeed, so the evaluator
    /// answers `EvaluationRes::Unavailable` instead of calling the request
    /// invalid.
    ResourceUnavailable(String),
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
            Self::ResourceUnavailable(msg) => {
                write!(f, "resource unavailable: {}", msg)
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
            // Resource limits whose ceiling derives from this machine's
            // spec: cast no verdict instead of calling the request invalid.
            RunnerError::ResourceLimit { .. } => {
                Self::ResourceUnavailable(value.to_string())
            }
            RunnerError::MissingHelper { .. } => {
                Self::InternalError(value.to_string())
            }
            RunnerError::WasmError { .. } => {
                Self::InternalError(value.to_string())
            }
            RunnerError::SerializationError { .. } => {
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
