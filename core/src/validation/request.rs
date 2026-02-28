use crate::{
    model::event::{ApprovalData, EvaluationData, ValidationData},
    subject::Metadata,
};

use ave_common::{
    Namespace, SchemaType,
    bridge::request::EventRequestType,
    identity::{DigestIdentifier, Signed},
    request::EventRequest,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing a validation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ValidationReq {
    Create {
        subject_id: DigestIdentifier,
        event_request: Signed<EventRequest>,
        gov_version: u64,
    },
    Event {
        actual_protocols: Box<ActualProtocols>,
        event_request: Signed<EventRequest>,
        ledger_hash: DigestIdentifier,
        metadata: Box<Metadata>,
        last_data: Box<LastData>,
        gov_version: u64,
        sn: u64,
    },
}

impl ValidationReq {
    pub fn get_subject_id(&self) -> DigestIdentifier {
        match self {
            Self::Create { subject_id, .. } => subject_id.clone(),
            Self::Event { metadata, .. } => metadata.subject_id.clone(),
        }
    }

    pub const fn is_valid(&self) -> bool {
        match self {
            Self::Create { event_request, .. } => {
                matches!(event_request.content(), EventRequest::Create(..))
            }
            Self::Event { event_request, .. } => {
                !matches!(event_request.content(), EventRequest::Create(..))
            }
        }
    }

    pub fn get_signed_event_request(&self) -> Signed<EventRequest> {
        match self {
            Self::Create { event_request, .. } => event_request.clone(),
            Self::Event { event_request, .. } => event_request.clone(),
        }
    }

    pub fn get_governance_id(&self) -> Result<DigestIdentifier, String> {
        match self {
            Self::Create { event_request, .. } => {
                if let EventRequest::Create(create) = &event_request.content() {
                    Ok(create.governance_id.clone())
                } else {
                    Err(format!(
                        "Invalid event request: {}",
                        EventRequestType::from(event_request.content())
                    ))
                }
            }
            Self::Event { metadata, .. } => Ok(metadata.governance_id.clone()),
        }
    }

    pub const fn get_gov_version(&self) -> u64 {
        match self {
            Self::Create { gov_version, .. } => *gov_version,
            Self::Event { gov_version, .. } => *gov_version,
        }
    }

    pub const fn get_sn(&self) -> u64 {
        match self {
            Self::Create { .. } => 0,
            Self::Event { sn, .. } => *sn,
        }
    }

    pub fn get_schema_id(&self) -> Result<SchemaType, String> {
        match self {
            Self::Create { event_request, .. } => {
                if let EventRequest::Create(create) = &event_request.content() {
                    Ok(create.schema_id.clone())
                } else {
                    Err(format!(
                        "Invalid event request: {}",
                        EventRequestType::from(event_request.content())
                    ))
                }
            }
            Self::Event { metadata, .. } => Ok(metadata.schema_id.clone()),
        }
    }

    pub fn get_namespace(&self) -> Result<Namespace, String> {
        match self {
            Self::Create { event_request, .. } => {
                if let EventRequest::Create(create) = &event_request.content() {
                    Ok(create.namespace.clone())
                } else {
                    Err(format!(
                        "Invalid event request: {}",
                        EventRequestType::from(event_request.content())
                    ))
                }
            }
            Self::Event { metadata, .. } => Ok(metadata.namespace.clone()),
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct LastData {
    pub vali_data: ValidationData,
    pub gov_version: u64,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ActualProtocols {
    None,
    Eval {
        eval_data: EvaluationData,
    },
    EvalApprove {
        eval_data: EvaluationData,
        approval_data: ApprovalData,
    },
}

impl ActualProtocols {
    pub fn is_success(&self) -> bool {
        match &self {
            Self::None => true,
            Self::Eval { eval_data } => eval_data.evaluator_res().is_some(),
            Self::EvalApprove { approval_data, .. } => approval_data.approved,
        }
    }

    pub fn check_protocols(
        &self,
        is_gov: bool,
        event_request_type: &EventRequestType,
    ) -> bool {
        match (&self, is_gov, event_request_type) {
            (Self::None, true, EventRequestType::Create)
            | (Self::None, false, EventRequestType::Create)
            | (Self::Eval { .. }, false, EventRequestType::Fact)
            | (Self::Eval { .. }, true, EventRequestType::Transfer)
            | (Self::Eval { .. }, false, EventRequestType::Transfer)
            | (Self::Eval { .. }, true, EventRequestType::Confirm)
            | (Self::None, false, EventRequestType::Confirm)
            | (Self::None, true, EventRequestType::Reject)
            | (Self::None, false, EventRequestType::Reject)
            | (Self::None, true, EventRequestType::Eol)
            | (Self::None, false, EventRequestType::Eol) => true,
            (Self::Eval { eval_data }, true, EventRequestType::Fact) => {
                eval_data.evaluator_res().is_none()
            }
            (
                Self::EvalApprove { eval_data, .. },
                true,
                EventRequestType::Fact,
            ) => eval_data.evaluator_res().is_some(),
            _ => false,
        }
    }
}
