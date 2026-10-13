//! Compilation evidence data shared by the node and the off-chain
//! verification tool.

use super::compilation_response::{CompilationError, CompilerResponse};
use crate::identity::{DigestIdentifier, Signature};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum CompilationResponse {
    Ok {
        result: CompilerResponse,
        result_hash: DigestIdentifier,
        /// rustc version the quorum built with, voted inside the
        /// result hash: validators compare it against the registry
        /// entry for the pin (valid ID, wrong toolchain is
        /// rejected). Always measured, in tests as in production.
        toolchain_version: String,
    },
    Error {
        result: CompilationError,
        result_hash: DigestIdentifier,
        /// Same attestation for deterministic failures.
        toolchain_version: String,
    },
}

impl CompilationResponse {
    pub const fn is_ok(&self) -> bool {
        matches!(&self, Self::Ok { .. })
    }
}

/// Evidence of the compilation phase of a governance fact.
///
/// The owner's
/// signature over the compilation request, its hash, and one signature
/// per compiler over the agreed result. Follows the same shape as
/// `EvaluationData` / `ApprovalData` / `ValidationData`.
#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct CompilationData {
    pub compile_req_signature: Signature,
    pub compile_req_hash: DigestIdentifier,
    pub compilers_signatures: Vec<Signature>,
    pub response: CompilationResponse,
}

impl CompilationData {
    pub const fn is_ok(&self) -> bool {
        matches!(&self.response, CompilationResponse::Ok { .. })
    }
}
