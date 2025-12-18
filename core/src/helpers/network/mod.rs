use ave_actors::Message;
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};

use crate::{
    Event as AveEvent,
    approval::{request::ApprovalReq, response::ApprovalRes},
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    model::event::ProtocolsSignatures,
    subject::{LastStateData, SignedLedger},
    update::TransferResponse,
    validation::{
        proof::ValidationProof, request::ValidationReq, response::ValidationRes,
    },
};

pub mod intermediary;
pub mod service;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ActorMessage {
    ValidationReq {
        req: Box<Signed<ValidationReq>>,
        schema_id: String,
    },
    ValidationRes {
        res: Signed<ValidationRes>,
    },
    EvaluationReq {
        req: Signed<EvaluationReq>,
        schema_id: String,
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
        event: Box<Signed<AveEvent>>,
        last_proof: ValidationProof,
        last_vali_res: Vec<ProtocolsSignatures>,
    },
    DistributionLastEventRes {
        signer: PublicKey,
    },
    DistributionLedgerReq {
        gov_version: Option<u64>,
        actual_sn: Option<u64>,
        subject_id: DigestIdentifier,
    },
    DistributionLedgerRes {
        ledger: Vec<SignedLedger>,
        last_state: Option<LastStateData>,
        namespace: String,
        schema_id: String,
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
