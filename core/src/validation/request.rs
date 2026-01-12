use crate::{
    model::{
        event::{ApprovalData, EvaluationData, ValidationData},
        request::EventRequestType,
    },
    subject::Metadata,
};

use ave_common::{
    Namespace, SchemaType,
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
        event_request: Signed<EventRequest>,
        gov_version: u64,
    },
    Event {
        actual_protocols: ActualProtocols,
        event_request: Signed<EventRequest>,
        ledger_hash: DigestIdentifier,
        metadata: Metadata,
        last_data: LastData,
        gov_version: u64,
        sn: u64,
    },
}

impl ValidationReq {
    pub fn is_valid(&self) -> bool {
        match self {
            ValidationReq::Create { event_request, .. } => {
                if let EventRequest::Create(..) = event_request.content() {
                    true
                } else {
                    false
                }
            }
            ValidationReq::Event { event_request, .. } => {
                if let EventRequest::Create(..) = event_request.content() {
                    false
                } else {
                    true
                }
            },
        }
    }

    pub fn get_signed_event_request(&self) -> Signed<EventRequest> {
        match self {
            ValidationReq::Create { event_request, .. } =>event_request.clone(),
            ValidationReq::Event { event_request, .. } => event_request.clone(),
        }
    }

    pub fn get_governance_id(&self) -> Result<DigestIdentifier, String> {
        match self {
            ValidationReq::Create { event_request, .. } => {
                if let EventRequest::Create(create) = &event_request.content() {
                    Ok(create.governance_id.clone())
                } else {
                    Err(format!(
                        "Invalid event request: {}",
                        EventRequestType::from(event_request.content())
                    ))
                }
            }
            ValidationReq::Event { metadata, .. } => {
                Ok(metadata.governance_id.clone())
            }
        }
    }

    pub fn get_gov_version(&self) -> u64 {
        match self {
            ValidationReq::Create { gov_version, .. } => *gov_version,
            ValidationReq::Event { gov_version, .. } => *gov_version,
        }
    }

    pub fn get_sn(&self) -> u64 {
        match self {
            ValidationReq::Create { .. } => 0,
            ValidationReq::Event { sn, .. } => *sn,
        }
    }

    pub fn get_schema_id(&self) -> Result<SchemaType, String> {
        match self {
            ValidationReq::Create { event_request, .. } => {
                if let EventRequest::Create(create) = &event_request.content() {
                    Ok(create.schema_id.clone())
                } else {
                    Err(format!(
                        "Invalid event request: {}",
                        EventRequestType::from(event_request.content())
                    ))
                }
            }
            ValidationReq::Event { metadata, .. } => {
                Ok(metadata.schema_id.clone())
            }
        }
    }

    pub fn get_namespace(&self) -> Result<Namespace, String> {
        match self {
            ValidationReq::Create { event_request, .. } => {
                if let EventRequest::Create(create) = &event_request.content() {
                    Ok(create.namespace.clone())
                } else {
                    Err(format!(
                        "Invalid event request: {}",
                        EventRequestType::from(event_request.content())
                    ))
                }
            }
            ValidationReq::Event { metadata, .. } => {
                Ok(metadata.namespace.clone())
            }
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
            ActualProtocols::None => true,
            ActualProtocols::Eval { eval_data } => {
                eval_data.evaluator_res().is_some()
            }
            ActualProtocols::EvalApprove { approval_data, .. } => {
                approval_data.approved
            }
        }
    }

    pub fn check_protocols(
        &self,
        is_gov: bool,
        event_request_type: &EventRequestType,
    ) -> bool {
        match (&self, is_gov, event_request_type) {
            (ActualProtocols::None, true, EventRequestType::Create)
            | (ActualProtocols::None, false, EventRequestType::Create)
            | (ActualProtocols::Eval { .. }, false, EventRequestType::Fact)
            | (
                ActualProtocols::Eval { .. },
                true,
                EventRequestType::Transfer,
            )
            | (
                ActualProtocols::Eval { .. },
                false,
                EventRequestType::Transfer,
            )
            | (ActualProtocols::Eval { .. }, true, EventRequestType::Confirm)
            | (ActualProtocols::None, false, EventRequestType::Confirm)
            | (ActualProtocols::None, true, EventRequestType::Reject)
            | (ActualProtocols::None, false, EventRequestType::Reject)
            | (ActualProtocols::None, true, EventRequestType::EOL)
            | (ActualProtocols::None, false, EventRequestType::EOL) => true,
            (
                ActualProtocols::Eval { eval_data },
                true,
                EventRequestType::Fact,
            ) => eval_data.evaluator_res().is_none(),
            (
                ActualProtocols::EvalApprove { eval_data, .. },
                true,
                EventRequestType::Fact,
            ) => eval_data.evaluator_res().is_some(),
            _ => false,
        }
    }
}
