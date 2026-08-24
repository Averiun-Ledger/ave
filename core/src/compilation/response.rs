use std::collections::BTreeMap;

use ave_common::{
    SchemaType,
    identity::{DigestIdentifier, Signature},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing a compilation response.
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
pub enum CompilationRes {
    Response {
        result: CompilationResult,
        result_hash: DigestIdentifier,
        result_hash_signature: Signature,
    },
    Abort(String),
    TimeOut,
    Reboot,
    /// The compiler can not compile right now for reasons unrelated to
    /// the request (its toolchain is missing, it is shutting down...):
    /// not a verdict. The requester drops the compiler from the current
    /// set, pulls fresh ones from the pending pool and only reboots the
    /// request when no compiler can answer at all. Same semantics as
    /// `EvaluationRes::Unavailable`.
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
pub enum CompilationResult {
    Ok {
        response: CompilerResponse,
        compile_req_hash: DigestIdentifier,
        req_subject_data_hash: DigestIdentifier,
    },
    Error {
        error: CompilationError,
        compile_req_hash: DigestIdentifier,
        req_subject_data_hash: DigestIdentifier,
    },
}

/// Deterministic compilation verdicts: every honest compiler reaches the
/// same one for the same request, so they are signed and voted. Node or
/// infrastructure problems are never voted — the worker answers
/// `CompilationRes::Unavailable` instead.
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
pub enum CompilationError {
    /// The event content is invalid (the payload does not describe a
    /// compilable schema change).
    InvalidEvent(String),
    /// The contract does not compile or its init check fails.
    CompilationFailed(String),
}

impl std::fmt::Display for CompilationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidEvent(msg) => write!(f, "invalid event: {}", msg),
            Self::CompilationFailed(msg) => {
                write!(f, "compilation failed: {}", msg)
            }
        }
    }
}

/// The successful compilation payload: the resulting artifact hash of
/// every contract touched by the governance fact, in deterministic order.
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
pub struct CompilerResponse {
    pub contracts: BTreeMap<SchemaType, DigestIdentifier>,
}
