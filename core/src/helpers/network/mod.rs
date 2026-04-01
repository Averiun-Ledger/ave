use ave_actors::Message;
use ave_common::identity::{DigestIdentifier, Signed};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes}, evaluation::{request::EvaluationReq, response::EvaluationRes}, governance::witnesses_register::CurrentWitnessSubject, model::event::Ledger, validation::{request::ValidationReq, response::ValidationRes}
};

pub mod error;
pub mod intermediary;
pub mod service;

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
    },
    ApprovalRes {
        res: Box<Signed<ApprovalRes>>,
    },
    DistributionLastEventReq {
        ledger: Box<Ledger>,
    },
    DistributionLastEventRes,
    DistributionLedgerReq {
        actual_sn: Option<u64>,
        subject_id: DigestIdentifier,
    },
    DistributionLedgerRes {
        ledger: Vec<Ledger>,
        is_all: bool,
    },
    DistributionGetLastSn {
        subject_id: DigestIdentifier,
        receiver_actor: String,
    },
    AuthLastSn {
        sn: u64,
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMessage {
    pub info: ComunicateInfo,
    pub message: ActorMessage,
}

impl Message for NetworkMessage {}
