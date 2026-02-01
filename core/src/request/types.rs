use std::collections::HashSet;

use crate::{
    evaluation::request::EvaluationReq,
    governance::model::Quorum,
    model::event::EvaluationData,
    subject::SignedLedger,
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
    Approval {
        eval_req: EvaluationReq,
        eval_res: EvaluationData,
    },
    Validation {
        request: Signed<ValidationReq>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        signers: HashSet<PublicKey>,
    },
    UpdateSubject {
        ledger: SignedLedger,
    },
    Distribution {
        ledger: SignedLedger,
    },
    End
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum ReqManInitMessage {
    Evaluate,
    Validate,
}
