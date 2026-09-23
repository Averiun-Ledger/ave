use std::{collections::HashSet, fmt::Display};

use crate::{
    approval::request::ApprovalReq,
    compilation::request::CompilationReq,
    evaluation::request::EvaluationReq,
    governance::{model::Quorum, role_register::RoleDataRegister},
    model::event::{CompilationData, EvaluationData, Ledger},
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
pub enum DistributionPlanMode {
    Clear,
    Opaque,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct DistributionPlanEntry {
    pub node: PublicKey,
    pub mode: DistributionPlanMode,
}

/// The compilation phase outcome carried across the following phases so
/// it can be embedded in the validation request (and survive a restart).
pub type CompileEvidence = (CompilationReq, CompilationData);

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RequestManagerState {
    Reboot,
    Starting,
    Compilation,
    Evaluation {
        compile: Option<Box<CompileEvidence>>,
    },
    /// The evaluation required approval: the approval phase runs with
    /// the signed approval request and the validation role set that
    /// will collect the approver votes. Everything needed to build the
    /// validation request at the close is kept here so a restart can
    /// resume the phase.
    Approval {
        signed_approval_req: Signed<ApprovalReq>,
        compile: Option<Box<CompileEvidence>>,
        eval: Box<(EvaluationReq, EvaluationData)>,
        signers: HashSet<PublicKey>,
        quorum: Quorum,
        approvers: RoleDataRegister,
    },
    Validation {
        request: Box<Signed<ValidationReq>>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        current_request_roles: CurrentRequestRoles,
        signers: HashSet<PublicKey>,
        distribution_plan: Vec<DistributionPlanEntry>,
    },
    UpdateSubject {
        ledger: Ledger,
        distribution_plan: Vec<DistributionPlanEntry>,
    },
    Distribution {
        ledger: Ledger,
        distribution_plan: Vec<DistributionPlanEntry>,
    },
    End,
}

impl Display for RequestManagerState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Reboot => write!(f, "Reboot"),
            Self::Starting => write!(f, "Starting"),
            Self::Compilation => write!(f, "Compilation"),
            Self::Evaluation { .. } => write!(f, "Evaluation"),
            Self::Approval { .. } => write!(f, "Approval"),
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
