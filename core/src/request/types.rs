use std::{collections::HashSet, fmt::Display};

use crate::{
    evaluation::request::EvaluationReq, governance::model::Quorum,
    model::event::EvaluationData, subject::SignedLedger,
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
        request: Box<Signed<ValidationReq>>,
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
    End,
}

impl Display for RequestManagerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestManagerState::Reboot => write!(f, "Reboot"),
            RequestManagerState::Starting => write!(f, "Starting"),
            RequestManagerState::Evaluation => write!(f, "Evaluation"),
            RequestManagerState::Approval { .. } => {
                write!(f, "Approval")
            }
            RequestManagerState::Validation {..} => write!(f, "Validation"),
            RequestManagerState::UpdateSubject { .. } => {
                write!(f, "UpdateSubject")
            }
            RequestManagerState::Distribution { .. } => {
                write!(f, "Distribution")
            }
            RequestManagerState::End => write!(f, "End"),
        }
    }
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum ReqManInitMessage {
    Evaluate,
    Validate,
}
