//! Evaluation evidence data shared by the node and the off-chain
//! verification tool.

use super::evaluation_response::{EvaluatorError, EvaluatorResponse};
use crate::identity::{DigestIdentifier, PublicKey, Signature, TimeStamp};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum EvaluationResponse {
    Ok {
        result: EvaluatorResponse,
        result_hash: DigestIdentifier,
    },
    Error {
        result: EvaluatorError,
        result_hash: DigestIdentifier,
    },
}

impl EvaluationResponse {
    pub fn build_opaque(&self) -> EvaluationResponseOpaque {
        match self.clone() {
            Self::Ok { result_hash, .. } => {
                EvaluationResponseOpaque::Ok { result_hash }
            }
            Self::Error { result_hash, .. } => {
                EvaluationResponseOpaque::Error { result_hash }
            }
        }
    }
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum EvaluationResponseOpaque {
    Ok { result_hash: DigestIdentifier },
    Error { result_hash: DigestIdentifier },
}

impl EvaluationDataOpaque {
    pub const fn is_ok(&self) -> bool {
        matches!(&self.response, EvaluationResponseOpaque::Ok { .. })
    }
}

/// Envelope data of an opaque tracker fact: who asked, when, for
/// which subject. The viewpoints themselves never leave the
/// originator.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct OpaqueData {
    pub subject_id: DigestIdentifier,
    pub event_request_timestamp: TimeStamp,
    pub signer: PublicKey,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct EvaluationDataOpaque {
    pub eval_req_signature: Signature,
    pub eval_req_hash: DigestIdentifier,
    pub evaluators_signatures: Vec<Signature>,
    pub viewpoints: BTreeSet<String>,
    pub response: EvaluationResponseOpaque,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct EvaluationData {
    pub eval_req_signature: Signature,
    pub eval_req_hash: DigestIdentifier,
    pub evaluators_signatures: Vec<Signature>,
    pub response: EvaluationResponse,
}

impl EvaluationData {
    pub const fn is_ok(&self) -> bool {
        matches!(&self.response, EvaluationResponse::Ok { .. })
    }

    pub fn evaluator_response_ok(&self) -> Option<EvaluatorResponse> {
        match &self.response {
            EvaluationResponse::Ok { result, .. } => Some(result.clone()),
            _ => None,
        }
    }
}
