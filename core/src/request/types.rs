use std::collections::HashSet;

use crate::{
    evaluation::request::EvaluationReq,
    governance::model::Quorum,
    model::event::{EvaluationData, Ledger, ValidationData},
    validation::request::ValidationReq,
};

use ave_common::{
    ValueWrapper,
    identity::{PublicKey, Signed},
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RequestManagerState {
    Reboot,
    Starting,
    Evaluation,
    EvaluationRes {
        eval_req: EvaluationReq,
        eval_res: EvaluationData,
    },
    Validation {
        request: Signed<ValidationReq>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        signers: HashSet<PublicKey>,
    },
    ValidationRes {
        val_req: ValidationReq,
        val_res: ValidationData,
    },
    Distribution {
        ledger: Signed<Ledger>,
    },
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum ReqManInitMessage {
    Evaluate,
    Validate,
}
