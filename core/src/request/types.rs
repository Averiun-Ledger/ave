use std::collections::HashSet;

use crate::{
    Event as AveEvent, ValidationInfo,
    evaluation::{request::EvaluationReq, response::EvalLedgerResponse},
    model::event::ProtocolsSignatures,
    subject::SignedLedger,
    validation::proof::ValidationProof,
};

use borsh::{BorshDeserialize, BorshSerialize};
use identity::Signed;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize)]
pub enum RequestManagerState {
    Reboot,
    Starting,
    Evaluation,
    Approval {
        eval_req: Box<EvaluationReq>,
        eval_res: EvalLedgerResponse,
        eval_signatures: HashSet<ProtocolsSignatures>,
    },
    Validation {
        val_info: Box<ValidationInfo>,
        last_proof: Option<ValidationProof>,
        prev_event_validation_response: Vec<ProtocolsSignatures>,
    },
    Distribution {
        event: Box<Signed<AveEvent>>,
        ledger: Box<SignedLedger>,
        last_proof: ValidationProof,
        prev_event_validation_response: Vec<ProtocolsSignatures>,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize,  BorshDeserialize, BorshSerialize)]
pub enum ReqManInitMessage {
    Evaluate,
    Validate,
}

#[derive(Default)]
pub struct ProtocolsResult {
    pub eval_success: Option<bool>,
    pub appr_required: bool,
    pub appr_success: Option<bool>,
    pub eval_signatures: Option<HashSet<ProtocolsSignatures>>,
    pub appr_signatures: Option<HashSet<ProtocolsSignatures>>,
}
