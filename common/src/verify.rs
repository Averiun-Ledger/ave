//! Shared ledger-verification cores: quorum, request rebuilds
//! and evidence checks consumed by the node and the off-chain
//! verification tool from this single source.

pub mod approval_data;
pub mod approval_request;
pub mod approval_response;
pub mod approval_verify;
pub mod compilation_data;
pub mod compilation_request;
pub mod compilation_response;
pub mod compilation_sources;
pub mod evaluation_response;
pub mod role_data;
pub mod runner_error;
pub mod subject_metadata;
pub mod validation_checks;
pub mod validation_response;
pub mod validator_error;

pub use approval_data::ApprovalData;
pub use approval_request::ApprovalReq;
pub use approval_response::{ApprovalCollectAck, ApprovalRes};
pub use approval_verify::{
    ApprovalVerification, CLOCK_SKEW, build_canonical_tally,
    rebuild_approval_req, terminal_outcome, verify_approval_data,
};
pub use compilation_data::{CompilationData, CompilationResponse};
pub use compilation_request::{CompilationReq, effective_pin};
pub use compilation_response::{
    CompilationError, CompilationRes, CompilationResult, CompilerResponse,
};
pub use compilation_sources::payload_contract_sources;
pub use evaluation_response::{
    EvalRunnerError, EvaluationRes, EvaluationResult, EvaluatorError,
    EvaluatorResponse, ResponseSummary,
};
pub use role_data::RoleDataRegister;
pub use runner_error::{InvalidEventKind, RunnerError};
pub use subject_metadata::{Metadata, MetadataWithoutProperties};
pub use validation_checks::{
    EventAnchor, check_approval_req, check_basic_data, check_metadata,
    event_request_hash, viewpoints_hash,
};
pub use validation_response::ValidationRes;
pub use validator_error::ValidatorError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ValueWrapper,
        identity::{
            DigestIdentifier, KeyPair, Signature, TimeStamp,
            keys::Ed25519Signer,
        },
    };

    fn keys(n: usize) -> HashSet<PublicKey> {
        (0..n)
            .map(|_| {
                KeyPair::Ed25519(Ed25519Signer::generate().expect("keygen"))
                    .public_key()
            })
            .collect()
    }

    fn dummy_sig() -> Signature {
        let signer =
            KeyPair::Ed25519(Ed25519Signer::generate().expect("keygen"));
        Signature::new(&42u8, &signer).expect("sign")
    }

    #[test]
    fn quorum_table() {
        let workers = keys(3);
        let two: HashSet<PublicKey> =
            workers.iter().take(2).cloned().collect();
        assert!(check_quorum_signers(&two, &Quorum::Majority, &workers));
        assert!(check_quorum_signers(&two, &Quorum::Fixed(2), &workers));
        assert!(!check_quorum_signers(&two, &Quorum::Fixed(3), &workers));
        assert!(!check_quorum_signers(
            &HashSet::new(),
            &Quorum::Majority,
            &workers
        ));
        // Count reached but not a subset: still no quorum.
        let mut outsider = two.clone();
        outsider.insert(keys(1).into_iter().next().expect("key"));
        assert!(!check_quorum_signers(&outsider, &Quorum::Fixed(3), &workers));
    }

    fn roundtrip<T>(value: &T)
    where
        T: borsh::BorshSerialize + borsh::BorshDeserialize,
    {
        let bytes = borsh::to_vec(value).expect("encode");
        let back = T::try_from_slice(&bytes).expect("decode");
        assert_eq!(borsh::to_vec(&back).expect("re-encode"), bytes);
    }

    #[test]
    fn approval_wire_roundtrip() {
        let req = ApprovalReq {
            subject_id: DigestIdentifier::default(),
            sn: 7,
            gov_version: 3,
            patch: ValueWrapper(serde_json::json!({"one": 1})),
            signer: keys(1).into_iter().next().expect("key"),
            issued_at: TimeStamp::from_nanos(1_000),
            deadline: TimeStamp::from_nanos(200_000),
        };
        roundtrip(&req);
        roundtrip(&ApprovalRes::Response {
            approval_req_hash: DigestIdentifier::default(),
            agrees: true,
            req_subject_data_hash: DigestIdentifier::default(),
        });
        roundtrip(&ApprovalRes::TimeOut {
            approval_req_hash: DigestIdentifier::default(),
            who: keys(1).into_iter().next().expect("key"),
        });
        roundtrip(&ApprovalData {
            approval_req_signature: dummy_sig(),
            approval_req_hash: DigestIdentifier::default(),
            issued_at: TimeStamp::from_nanos(1_000),
            deadline: TimeStamp::from_nanos(200_000),
            approvers_agrees_signatures: vec![dummy_sig(), dummy_sig()],
            approvers_disagrees_signatures: vec![],
            double_votes: vec![(dummy_sig(), dummy_sig())],
            approvers_timeouts: vec![(
                keys(1).into_iter().next().expect("key"),
                vec![dummy_sig()],
            )],
            approved: true,
        });
        roundtrip(&RoleDataRegister {
            workers: keys(2),
            quorum: Quorum::Majority,
        });
    }
}

use std::collections::HashSet;

use crate::{
    governance::Quorum,
    identity::PublicKey,
};

/// Quorum over an explicit signer set: every signer must belong
/// to the worker set and the quorum rule must hold over the
/// worker-set size.
pub fn check_quorum_signers(
    signers: &HashSet<PublicKey>,
    quorum: &Quorum,
    workers: &HashSet<PublicKey>,
) -> bool {
    // Set sizes can not overflow `u32` on any real node, but never truncate
    // them with `as` in consensus code.
    let total = u32::try_from(workers.len()).unwrap_or(u32::MAX);
    let signed = u32::try_from(signers.len()).unwrap_or(u32::MAX);
    signers.is_subset(workers) && quorum.check_quorum(total, signed)
}
