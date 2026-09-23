use ave_actors::Message;
use ave_common::{
    SchemaType,
    identity::{DigestIdentifier, Signed},
};
use ave_network::ComunicateInfo;
use serde::{Deserialize, Serialize};

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    compilation::{request::CompilationReq, response::CompilationRes},
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    governance::witnesses_register::CurrentWitnessSubject,
    model::event::Ledger,
    update::UpdateWitnessOffer,
    validation::{request::ValidationReq, response::ValidationRes},
};

pub mod error;
pub mod intermediary;
pub mod service;
#[cfg(feature = "test")]
pub mod test_faults;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ActorMessage {
    ValidationReq {
        req: Signed<ValidationReq>,
    },
    ValidationRes {
        res: Signed<ValidationRes>,
    },
    EvaluationReq {
        req: Box<Signed<EvaluationReq>>,
    },
    EvaluationRes {
        res: EvaluationRes,
    },
    ApprovalReq {
        req: Signed<ApprovalReq>,
        /// Actor path the asking validator listens on for the vote.
        asker_actor: String,
    },
    /// The requester asks a validator to collect the approver votes for
    /// this approval request (approval phase, owner → validator).
    ApprovalCollectReq {
        req: Signed<ApprovalReq>,
    },
    /// A validator acknowledges a collection request (approval phase,
    /// validator → owner coordinator).
    ApprovalCollectAck {
        approval_req_hash: DigestIdentifier,
        ack: crate::approval::response::ApprovalCollectAck,
    },
    ApprovalRes {
        res: Box<Signed<ApprovalRes>>,
    },
    /// A validator pushes a newly observed approver vote to the
    /// requester.
    ApprovalVoteReport {
        res: Box<Signed<ApprovalRes>>,
    },
    /// The requester asks a validator for the votes observed so far
    /// (keepalive).
    ApprovalStatusReq {
        approval_req_hash: DigestIdentifier,
    },
    /// A validator answers the keepalive ask with its votes.
    ApprovalStatusRes {
        approval_req_hash: DigestIdentifier,
        votes: Vec<Signed<ApprovalRes>>,
    },
    DistributionLastEventReq {
        ledger: Box<Ledger>,
    },
    DistributionLastEventRes,
    DistributionLedgerReq {
        actual_sn: Option<u64>,
        target_sn: Option<u64>,
        subject_id: DigestIdentifier,
        already_verified_transfer_sn: Option<u64>,
    },
    DistributionLedgerRes {
        ledger: Vec<Ledger>,
        is_all: bool,
        transfer_event: Option<Box<Ledger>>,
    },
    DistributionGetLastSn {
        subject_id: DigestIdentifier,
        actual_sn: Option<u64>,
        receiver_actor: String,
    },
    UpdateNoOffer,
    UpdateOffer {
        offer: UpdateWitnessOffer,
    },
    GovernanceVersionReq {
        subject_id: DigestIdentifier,
        receiver_actor: String,
    },
    GovernanceVersionRes {
        version: u64,
    },
    TrackerSyncReq {
        subject_id: DigestIdentifier,
        request_nonce: u64,
        governance_version: u64,
        after_subject_id: Option<DigestIdentifier>,
        limit: usize,
        receiver_actor: String,
    },
    TrackerSyncRes {
        request_nonce: u64,
        governance_version: u64,
        items: Vec<CurrentWitnessSubject>,
        next_cursor: Option<DigestIdentifier>,
    },
    CompilationReq {
        req: Box<Signed<CompilationReq>>,
    },
    CompilationRes {
        res: CompilationRes,
    },
    ArtifactProbeReq {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        receiver_actor: String,
    },
    ArtifactProbeRes {
        request_nonce: u64,
        result: crate::compilation::artifact::ArtifactProbeResult,
    },
    ArtifactReq {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        receiver_actor: String,
    },
    ArtifactRes {
        request_nonce: u64,
        result: crate::compilation::artifact::ArtifactFetchResult,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMessage {
    pub info: ComunicateInfo,
    pub message: ActorMessage,
}

impl Message for NetworkMessage {}
