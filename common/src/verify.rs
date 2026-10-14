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
pub mod compilation_sets;
pub mod compilation_sources;
pub mod decode;
pub mod evaluation_data;
pub mod evaluation_request;
pub mod evaluation_response;
pub mod governance;
pub mod role_data;
pub mod runner_error;
pub mod subject_data;
pub mod subject_metadata;
pub mod validation_checks;
pub mod validation_request;
pub mod validation_response;
pub mod validator_error;
pub mod viewpoints;

pub use viewpoints::validate_fact_viewpoints;

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
pub use compilation_sets::{
    compilation_set, needs_compilation_evidence, schemas_to_compile,
};
pub use compilation_sources::payload_contract_sources;
pub use decode::{
    ContractSourceError, MAX_CONTRACT_SOURCE_BYTES, decode_contract_source,
    hash_bytes, validate_contract_source,
};
pub use evaluation_data::{
    EvaluationData, EvaluationDataOpaque, EvaluationResponse,
    EvaluationResponseOpaque, OpaqueData,
};
pub use evaluation_request::{EvaluateData, EvaluationReq};
pub use evaluation_response::{
    EvalRunnerError, EvaluationRes, EvaluationResult, EvaluatorError,
    EvaluatorResponse, ResponseSummary,
};
pub use governance::{GovernanceData, GovernanceError};
pub use role_data::{
    RoleDataRegister, RolesAtVersion, lone_owner_roles,
};
pub use subject_data::RequestSubjectData;
pub use runner_error::{InvalidEventKind, RunnerError};
pub use subject_metadata::{Metadata, MetadataWithoutProperties};
pub use validation_checks::{
    Check, EventAnchor, approval_data_hash_of, check_approval_req,
    check_basic_data, check_compilation, check_evaluation,
    check_genesis_metadata, check_gov_fact_combination, check_metadata,
    check_opaque_evaluation, check_validation_bundle,
    check_validation_signatures, check_witness_evaluation,
    evaluated_patch, event_request_hash, gov_roles_from_pre,
    req_subject_data_hash, validation_result_from_parts,
    verify_approval_evidence, verify_compilation_evidence, viewpoints_hash,
};
pub use validation_request::{ActualProtocols, LastData, ValidationReq};
pub use validation_response::{ValidationData, ValidationMetadata, ValidationRes};
pub use validator_error::ValidatorError;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        ValueWrapper,
        identity::{
            DigestIdentifier, HashAlgorithm, KeyPair, Signature, TimeStamp,
            hash_borsh, keys::Ed25519Signer,
        },
    };
    use std::collections::{BTreeSet, HashSet};

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
    fn subject_wire_roundtrip() {
        use crate::{Namespace, SchemaType};

        let id = |b: u8| {
            hash_borsh(&*HashAlgorithm::Blake3.hasher(), &b).expect("hash")
        };
        roundtrip(&RequestSubjectData {
            subject_id: id(1),
            governance_id: id(2),
            namespace: Namespace::new(),
            schema_id: SchemaType::Type("Example".to_owned()),
            sn: 4,
            gov_version: 2,
            signer: keys(1).into_iter().next().expect("key"),
        });
        roundtrip(&OpaqueData {
            subject_id: id(1),
            event_request_timestamp: TimeStamp::from_nanos(7),
            signer: keys(1).into_iter().next().expect("key"),
        });
        roundtrip(&EvaluationDataOpaque {
            eval_req_signature: dummy_sig(),
            eval_req_hash: id(3),
            evaluators_signatures: vec![dummy_sig()],
            viewpoints: BTreeSet::from(["agua".to_owned()]),
            response: EvaluationResponseOpaque::Error {
                result_hash: id(4),
            },
        });
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
