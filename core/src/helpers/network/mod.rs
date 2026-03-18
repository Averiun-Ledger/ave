use ave_actors::Message;
use ave_common::identity::{DigestIdentifier, Signed};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    subject::SignedLedger,
    validation::{request::ValidationReq, response::ValidationRes},
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
        res: Signed<EvaluationRes>,
    },
    ApprovalReq {
        req: Signed<ApprovalReq>,
    },
    ApprovalRes {
        res: Box<Signed<ApprovalRes>>,
    },
    DistributionLastEventReq {
        ledger: Box<SignedLedger>,
    },
    DistributionLastEventRes,
    DistributionLedgerReq {
        actual_sn: Option<u64>,
        subject_id: DigestIdentifier,
    },
    DistributionLedgerRes {
        ledger: Vec<SignedLedger>,
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
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMessage {
    pub info: ComunicateInfo,
    pub message: ActorMessage,
}

impl Message for NetworkMessage {}
