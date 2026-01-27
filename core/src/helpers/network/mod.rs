use ave_actors::Message;
use ave_common::{
    SchemaType,
    identity::{DigestIdentifier, Signed},
};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    subject::SignedLedger,
    update::TransferResponse,
    validation::{request::ValidationReq, response::ValidationRes},
};

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
        req: Signed<EvaluationReq>,
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
        gov_version: Option<u64>,
        actual_sn: Option<u64>,
        subject_id: DigestIdentifier,
    },
    DistributionLedgerRes {
        ledger: Vec<SignedLedger>,
        namespace: String,
        schema_id: SchemaType,
        governance_id: DigestIdentifier,
    },
    DistributionGetLastSn {
        subject_id: DigestIdentifier,
    },
    AuthLastSn {
        sn: u64,
    },
    Transfer {
        subject_id: DigestIdentifier,
    },
    TransferRes {
        res: TransferResponse,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMessage {
    pub info: ComunicateInfo,
    pub message: ActorMessage,
}

impl Message for NetworkMessage {}
