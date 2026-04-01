use std::{collections::HashSet, fmt::Display};

use crate::{
    evaluation::request::EvaluationReq,
    governance::model::Quorum,
    model::event::{EvaluationData, Ledger},
    validation::{request::ValidationReq, worker::CurrentRequestRoles},
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
        current_request_roles: CurrentRequestRoles,
        signers: HashSet<PublicKey>,
    },
    UpdateSubject {
        ledger: Ledger,
    },
    Distribution {
        ledger: Ledger,
    },
    End,
}

impl Display for RequestManagerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reboot => write!(f, "Reboot"),
            Self::Starting => write!(f, "Starting"),
            Self::Evaluation => write!(f, "Evaluation"),
            Self::Approval { .. } => {
                write!(f, "Approval")
            }
            Self::Validation { .. } => write!(f, "Validation"),
            Self::UpdateSubject { .. } => {
                write!(f, "UpdateSubject")
            }
            Self::Distribution { .. } => {
                write!(f, "Distribution")
            }
            Self::End => write!(f, "End"),
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
