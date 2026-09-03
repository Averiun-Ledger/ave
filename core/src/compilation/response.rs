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

    fn sample_ok_result() -> CompilationResult {
        CompilationResult::Ok {
            response: CompilerResponse {
                contracts: BTreeMap::from([(
                    SchemaType::Type("Foo".to_owned()),
                    DigestIdentifier::default(),
                )]),
            },
            compile_req_hash: DigestIdentifier::default(),
            req_subject_data_hash: DigestIdentifier::default(),
        }
    }

    fn sample_ok_result_bytes() -> Vec<u8> {
        let mut bytes = vec![0]; // CompilationResult::Ok
        // CompilerResponse: BTreeMap with one entry.
        bytes.extend_from_slice(&1u32.to_le_bytes()); // map length
        bytes.push(1); // SchemaType::Type
        bytes.extend_from_slice(&string_bytes("Foo")); // schema id
        bytes.extend_from_slice(&default_digest_bytes()); // wasm hash
        bytes.extend_from_slice(&default_digest_bytes()); // compile_req_hash
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
    // bytes pin both the order and the field layout of the compilation
    // protocol messages — they ARE the compile quorum evidence (signed
    // and hash-covered), so any edit is a breaking protocol change.
    #[test]
    fn compilation_wire_shape_is_pinned() {
        // CompilationRes::Response
        let mut expected = vec![0];
        expected.extend_from_slice(&sample_ok_result_bytes());
        expected.extend_from_slice(&default_digest_bytes());
        expected.extend_from_slice(&sample_signature_bytes());
        assert_wire_shape(
            &CompilationRes::Response {
                result: sample_ok_result(),
                result_hash: DigestIdentifier::default(),
                result_hash_signature: sample_signature(),
            },
            &expected,
        );

        // CompilationRes::Abort
        let mut expected = vec![1];
        expected.extend_from_slice(&string_bytes("abort"));
        assert_wire_shape(&CompilationRes::Abort("abort".to_owned()), &expected);

        // CompilationRes::TimeOut / Reboot / Unavailable
        assert_wire_shape(&CompilationRes::TimeOut, &[2]);
        assert_wire_shape(&CompilationRes::Reboot, &[3]);
        assert_wire_shape(&CompilationRes::Unavailable, &[4]);

        // CompilationResult::Ok
        assert_wire_shape(&sample_ok_result(), &sample_ok_result_bytes());

        // CompilationResult::Error
        let mut expected = vec![1];
        expected.push(1); // CompilationError::CompilationFailed
        expected.extend_from_slice(&string_bytes("failed"));
        expected.extend_from_slice(&default_digest_bytes());
        expected.extend_from_slice(&default_digest_bytes());
        assert_wire_shape(
            &CompilationResult::Error {
                error: CompilationError::CompilationFailed(
                    "failed".to_owned()
                ),
                compile_req_hash: DigestIdentifier::default(),
                req_subject_data_hash: DigestIdentifier::default(),
            },
            &expected,
        );

        // CompilationError variants
        let mut expected = vec![0];
        expected.extend_from_slice(&string_bytes("invalid"));
        assert_wire_shape(
            &CompilationError::InvalidEvent("invalid".to_owned()),
            &expected,
        );
        let mut expected = vec![1];
        expected.extend_from_slice(&string_bytes("failed"));
        assert_wire_shape(
            &CompilationError::CompilationFailed("failed".to_owned()),
            &expected,
        );

        // SchemaType variant order is part of the evidence wire shape
        // (CompilerResponse carries SchemaType keys).
        assert_wire_shape(&SchemaType::Governance, &[0]);
        let mut expected = vec![1];
        expected.extend_from_slice(&string_bytes("Foo"));
        assert_wire_shape(&SchemaType::Type("Foo".to_owned()), &expected);
        assert_wire_shape(&SchemaType::TrackerSchemas, &[2]);
    }
}
