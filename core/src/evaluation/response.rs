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

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::identity::{
        DSAlgorithm, PublicKey, SignatureIdentifier, TimeStamp,
    };
    use borsh::{BorshDeserialize, to_vec};

    /// Borsh of `DigestIdentifier::default()`: algorithm tag (Blake3 = 0)
    /// plus an empty byte vector (u32 length 0).
    fn default_digest_bytes() -> Vec<u8> {
        vec![0, 0, 0, 0, 0]
    }

    /// Borsh of a `String`: u32 little-endian length plus raw bytes.
    fn string_bytes(s: &str) -> Vec<u8> {
        let mut bytes = (s.len() as u32).to_le_bytes().to_vec();
        bytes.extend_from_slice(s.as_bytes());
        bytes
    }

    fn sample_signature() -> Signature {
        Signature {
            signer: PublicKey::default(),
            timestamp: TimeStamp::from_nanos(1),
            content_hash: DigestIdentifier::default(),
            value: SignatureIdentifier::new(
                DSAlgorithm::Ed25519,
                vec![0xAB; 64],
            )
            .expect("64 bytes is a valid Ed25519 signature length"),
        }
    }

    fn sample_signature_bytes() -> Vec<u8> {
        let mut bytes = vec![0, 0, 0, 0, 0]; // signer: Ed25519 + empty key
        bytes.extend_from_slice(&1u64.to_le_bytes()); // timestamp
        bytes.extend_from_slice(&default_digest_bytes()); // content hash
        bytes.push(0); // signature algorithm: Ed25519
        bytes.extend_from_slice(&64u32.to_le_bytes());
        bytes.extend_from_slice(&[0xAB; 64]);
        bytes
    }

    fn sample_ok_result() -> EvaluationResult {
        EvaluationResult::Ok {
            response: EvaluatorResponse {
                patch: ValueWrapper(serde_json::Value::Bool(true)),
                properties_hash: DigestIdentifier::default(),
                appr_required: false,
            },
            eval_req_hash: DigestIdentifier::default(),
            req_subject_data_hash: DigestIdentifier::default(),
        }
    }

    fn sample_ok_result_bytes() -> Vec<u8> {
        let mut bytes = vec![0]; // EvaluationResult::Ok
        bytes.extend_from_slice(&[0, 1]); // patch: bool true
        bytes.extend_from_slice(&default_digest_bytes()); // properties hash
        bytes.push(0); // appr_required: false
        bytes.extend_from_slice(&default_digest_bytes()); // eval_req_hash
        bytes.extend_from_slice(&default_digest_bytes()); // req_subject_data_hash
        bytes
    }

    fn assert_wire_shape<T>(value: &T, expected: &[u8])
    where
        T: BorshSerialize + BorshDeserialize + Eq + std::fmt::Debug,
    {
        let encoded = to_vec(value).expect("serialization must succeed");
        assert_eq!(
            encoded, expected,
            "wire shape changed: this type is signed and hash-covered; \
             an enum edit (reorder, insert, remove) is a breaking protocol \
             change and must be an explicit, reviewed decision"
        );
        let decoded =
            T::try_from_slice(&encoded).expect("deserialization must succeed");
        assert_eq!(&decoded, value, "round trip must be lossless");
    }

    // Wire-shape pin: borsh encodes the variant ordinal, so these exact
    // bytes pin both the order and the field layout of the evaluation
    // protocol messages.
    #[test]
    fn evaluation_wire_shape_is_pinned() {
        // EvaluationRes::Response
        let mut expected = vec![0];
        expected.extend_from_slice(&sample_ok_result_bytes());
        expected.extend_from_slice(&default_digest_bytes());
        expected.extend_from_slice(&sample_signature_bytes());
        assert_wire_shape(
            &EvaluationRes::Response {
                result: sample_ok_result(),
                result_hash: DigestIdentifier::default(),
                result_hash_signature: sample_signature(),
            },
            &expected,
        );

        // EvaluationRes::Abort
        let mut expected = vec![1];
        expected.extend_from_slice(&string_bytes("abort"));
        assert_wire_shape(&EvaluationRes::Abort("abort".to_owned()), &expected);

        // EvaluationRes::TimeOut / Reboot / Unavailable
        assert_wire_shape(&EvaluationRes::TimeOut, &[2]);
        assert_wire_shape(&EvaluationRes::Reboot, &[3]);
        assert_wire_shape(&EvaluationRes::Unavailable, &[4]);

        // EvaluationResult::Error
        let mut expected = vec![1];
        expected.push(0); // EvaluatorError::InvalidEventSignature
        expected.extend_from_slice(&default_digest_bytes());
        expected.extend_from_slice(&default_digest_bytes());
        assert_wire_shape(
            &EvaluationResult::Error {
                error: EvaluatorError::InvalidEventSignature,
                eval_req_hash: DigestIdentifier::default(),
                req_subject_data_hash: DigestIdentifier::default(),
            },
            &expected,
        );

        // EvaluatorError variants
        assert_wire_shape(&EvaluatorError::InvalidEventSignature, &[0]);

        let mut expected = vec![1];
        expected.extend_from_slice(&string_bytes("req"));
        assert_wire_shape(
            &EvaluatorError::InvalidEventRequest("req".to_owned()),
            &expected,
        );

        let mut expected = vec![2, 1]; // Runner + ContractFailed
        expected.extend_from_slice(&string_bytes("failed"));
        assert_wire_shape(
            &EvaluatorError::Runner(EvalRunnerError::ContractFailed(
                "failed".to_owned(),
            )),
            &expected,
        );

        let mut expected = vec![3];
        expected.extend_from_slice(&string_bytes("internal"));
        assert_wire_shape(
            &EvaluatorError::InternalError("internal".to_owned()),
            &expected,
        );

        let mut expected = vec![4];
        expected.extend_from_slice(&string_bytes("resources"));
        assert_wire_shape(
            &EvaluatorError::ResourceUnavailable("resources".to_owned()),
            &expected,
        );

        // EvalRunnerError variants
        let mut expected = vec![0];
        expected.extend_from_slice(&string_bytes("event"));
        assert_wire_shape(
            &EvalRunnerError::InvalidEvent("event".to_owned()),
            &expected,
        );

        let mut expected = vec![2];
        expected.extend_from_slice(&string_bytes("missing"));
        assert_wire_shape(
            &EvalRunnerError::ContractNotFound("missing".to_owned()),
            &expected,
        );
    }
}
