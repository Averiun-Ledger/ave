//! # Event data model.
//!

use super::network::TimeOut;

use crate::{
    evaluation::response::{EvaluatorError, EvaluatorResponse},
    subject::Metadata,
    validation::request::ActualProtocols,
};

use ave_actors::ActorError;
use ave_common::{
    bridge::request::EventRequestType, identity::{DigestIdentifier, Signature, Signed, TimeStamp}, request::EventRequest, response::{EvalResDB, LedgerDB, RequestEventDB}
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ProtocolsError {
    #[error(
        "invalid evaluation: evaluation result does not match expected state"
    )]
    InvalidEvaluation,

    #[error("invalid evaluation: approval required but not provided")]
    ApprovalRequired,

    #[error("invalid actual protocols: expected {expected}, got {got}")]
    InvalidActualProtocols {
        expected: &'static str,
        got: &'static str,
    },

    #[error(
        "invalid event request type: {request_type} is not supported for is_gov={is_gov}"
    )]
    InvalidEventRequestType {
        request_type: &'static str,
        is_gov: bool,
    },

    #[error(
        "expected create event with metadata, got different protocol or validation metadata"
    )]
    NotCreateWithMetadata,
}

impl From<ProtocolsError> for ActorError {
    fn from(error: ProtocolsError) -> Self {
        ActorError::Functional {
            description: error.to_string(),
        }
    }
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum EvaluationResponse {
    Ok(EvaluatorResponse),
    Error(EvaluatorError),
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct EvaluationData {
    pub eval_req_signature: Signature,
    pub eval_req_hash: DigestIdentifier,
    pub evaluators_signatures: Vec<Signature>,
    pub response: EvaluationResponse,
}

impl EvaluationData {
    pub fn evaluator_res(&self) -> Option<EvaluatorResponse> {
        match &self.response {
            EvaluationResponse::Ok(evaluator_response) => {
                Some(evaluator_response.clone())
            }
            _ => None,
        }
    }
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct ApprovalData {
    pub approval_req_signature: Signature,
    pub approval_req_hash: DigestIdentifier,
    pub approvers_agrees_signatures: Vec<Signature>,
    pub approvers_disagrees_signatures: Vec<Signature>,
    pub approvers_timeout: Vec<TimeOut>,
    pub approved: bool,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ValidationData {
    pub validation_req_signature: Signature,
    pub validation_req_hash: DigestIdentifier,
    pub validators_signatures: Vec<Signature>,
    pub validation_metadata: ValidationMetadata,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Eq,
    PartialEq,
    Hash,
)]
pub enum ValidationMetadata {
    ModifiedHash(DigestIdentifier),
    Metadata(Box<Metadata>),
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum Protocols {
    Create {
        validation: ValidationData,
    },
    TrackerFact {
        evaluation: EvaluationData,
        validation: ValidationData,
    },
    GovFact {
        evaluation: EvaluationData,
        approval: Option<ApprovalData>,
        validation: ValidationData,
    },
    Transfer {
        evaluation: EvaluationData,
        validation: ValidationData,
    },
    TrackerConfirm {
        validation: ValidationData,
    },
    GovConfirm {
        evaluation: EvaluationData,
        validation: ValidationData,
    },
    Reject {
        validation: ValidationData,
    },
    EOL {
        validation: ValidationData,
    },
}

impl Protocols {
    pub fn buidl_event_db(
        &self,
        event_request: &EventRequest,
    ) -> (RequestEventDB, DigestIdentifier) {
        match (self, event_request) {
            (Protocols::Create { validation }, EventRequest::Create( create)) => {
                let ValidationMetadata::Metadata(metadata) = &validation.validation_metadata else {
                    unreachable!(
                        "Unreachable combination is a create event request"
                    )
                };

                (RequestEventDB::Create {
                name: create.name.clone(),
                description: create.description.clone(),
                schema_id: create.schema_id.to_string(),
                namespace: create.namespace.to_string(),
            }, metadata.subject_id.clone())
            },
            (
                Protocols::TrackerFact { evaluation, .. },
                EventRequest::Fact(fact_request),
            ) => {
                let evaluation_response = match evaluation.response.clone() {
                    EvaluationResponse::Ok(eval_res) => EvalResDB::Patch(eval_res.patch.0.clone()),
                    EvaluationResponse::Error(e) => EvalResDB::Error(e.to_string()),
                };
                
                (RequestEventDB::TrackerFact {
                    payload: fact_request.payload.0.clone(),
                    evaluation_response,
                }, event_request.get_subject_id())
            }
            (
                Protocols::GovFact {
                    evaluation,
                    approval,
                    ..
                },
                EventRequest::Fact(fact_request),
            ) => {
                let (evaluation_response, approval_success) = match evaluation
                    .response
                    .clone()
                {
                    EvaluationResponse::Ok(eval_res) => {
                        if let Some(appr) = approval {
                            (EvalResDB::Patch(eval_res.patch.0.clone()), Some(appr.approved))
                        } else {
                            unreachable!(
                                "In a factual governance event, if the assessment is correct, there should be approval"
                            )
                        }
                    }
                    EvaluationResponse::Error(e) => (EvalResDB::Error(e.to_string()), None),
                };
                (RequestEventDB::GovernanceFact {
                    payload: fact_request.payload.0.clone(),
                    evaluation_response,
                    approval_success,
                }, event_request.get_subject_id())
            }
            (
                Protocols::Transfer { evaluation, .. },
                EventRequest::Transfer(transfer_request),
            ) => {
                let evaluation_error = match evaluation.response.clone() {
                    EvaluationResponse::Ok(_) => None,
                    EvaluationResponse::Error(e) => Some(e.to_string()),
                };
                (RequestEventDB::Transfer {
                    new_owner: transfer_request.new_owner.to_string(),
                    evaluation_error,
                }, event_request.get_subject_id())
            }
            (Protocols::TrackerConfirm { .. }, EventRequest::Confirm(..)) => {
                (RequestEventDB::TrackerConfirm, event_request.get_subject_id())
            }
            (
                Protocols::GovConfirm { evaluation, .. },
                EventRequest::Confirm(confirm_request),
            ) => {
                let evaluation_response = match evaluation.response.clone() {
                    EvaluationResponse::Ok(eval_res) => EvalResDB::Patch(eval_res.patch.0.clone()),
                    EvaluationResponse::Error(e) => EvalResDB::Error(e.to_string()),
                };
                (RequestEventDB::GovernanceConfirm {
                    name_old_owner: confirm_request.name_old_owner.clone(),
                    evaluation_response,
                }, event_request.get_subject_id())
            }
            (Protocols::Reject { .. }, EventRequest::Reject(..)) => (RequestEventDB::Reject, event_request.get_subject_id()),
            (Protocols::EOL { .. }, EventRequest::EOL(..)) => (RequestEventDB::EOL, event_request.get_subject_id()),
            _ => unreachable!(
                "Unreachable combination of protocol and event request"
            ),
        }
    }

    pub fn get_validation_data(&self) -> ValidationData {
        match self {
            Protocols::Create { validation }
            | Protocols::TrackerFact { validation, .. }
            | Protocols::GovFact { validation, .. }
            | Protocols::Transfer { validation, .. }
            | Protocols::TrackerConfirm { validation }
            | Protocols::GovConfirm { validation, .. }
            | Protocols::Reject { validation }
            | Protocols::EOL { validation } => validation.clone(),
        }
    }

    pub fn is_success(&self) -> bool {
        match self {
            Protocols::Create { .. } => true,
            Protocols::TrackerFact { evaluation, .. } => {
                evaluation.evaluator_res().is_some()
            }
            Protocols::GovFact { approval, .. } => {
                if let Some(approval) = approval {
                    approval.approved
                } else {
                    false
                }
            }
            Protocols::Transfer { evaluation, .. } => {
                evaluation.evaluator_res().is_some()
            }
            Protocols::TrackerConfirm { .. } => true,
            Protocols::GovConfirm { evaluation, .. } => {
                evaluation.evaluator_res().is_some()
            }
            Protocols::Reject { .. } => true,
            Protocols::EOL { .. } => true,
        }
    }

    pub fn build(
        is_gov: bool,
        event_request: EventRequestType,
        actual_protocols: ActualProtocols,
        validation: ValidationData,
    ) -> Result<Self, ProtocolsError> {
        match (event_request, is_gov) {
            (EventRequestType::Fact, true) => {
                let (evaluation, approval) = match actual_protocols {
                    ActualProtocols::Eval { eval_data } => {
                        if eval_data.evaluator_res().is_some() {
                            return Err(ProtocolsError::InvalidEvaluation);
                        } else {
                            (eval_data, None)
                        }
                    }
                    ActualProtocols::EvalApprove {
                        eval_data,
                        approval_data,
                    } => {
                        if let Some(eval_res) = eval_data.evaluator_res() {
                            if !eval_res.appr_required {
                                return Err(ProtocolsError::ApprovalRequired);
                            }
                        } else {
                            return Err(ProtocolsError::InvalidEvaluation);
                        };

                        (eval_data, Some(approval_data))
                    }
                    ActualProtocols::None => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval or EvalApprove",
                            got: "None",
                        });
                    }
                };

                Ok(Self::GovFact {
                    evaluation,
                    approval,
                    validation,
                })
            }
            (EventRequestType::Fact, false) => {
                let evaluation = match actual_protocols {
                    ActualProtocols::Eval { eval_data } => eval_data,
                    ActualProtocols::None => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval",
                            got: "None",
                        });
                    }
                    ActualProtocols::EvalApprove { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval",
                            got: "EvalApprove",
                        });
                    }
                };

                Ok(Self::TrackerFact {
                    evaluation,
                    validation,
                })
            }
            (EventRequestType::Transfer, true)
            | (EventRequestType::Transfer, false) => {
                let evaluation = match actual_protocols {
                    ActualProtocols::Eval { eval_data } => eval_data,
                    ActualProtocols::None => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval",
                            got: "None",
                        });
                    }
                    ActualProtocols::EvalApprove { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval",
                            got: "EvalApprove",
                        });
                    }
                };

                Ok(Self::Transfer {
                    evaluation,
                    validation,
                })
            }
            (EventRequestType::Confirm, true) => {
                let evaluation = match actual_protocols {
                    ActualProtocols::Eval { eval_data } => eval_data,
                    ActualProtocols::None => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval",
                            got: "None",
                        });
                    }
                    ActualProtocols::EvalApprove { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "Eval",
                            got: "EvalApprove",
                        });
                    }
                };
                Ok(Self::GovConfirm {
                    evaluation,
                    validation,
                })
            }
            (EventRequestType::Confirm, false) => {
                match actual_protocols {
                    ActualProtocols::Eval { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "None",
                            got: "Eval",
                        });
                    }
                    ActualProtocols::EvalApprove { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "None",
                            got: "EvalApprove",
                        });
                    }
                    ActualProtocols::None => {}
                }
                Ok(Self::TrackerConfirm { validation })
            }
            (EventRequestType::Reject, true)
            | (EventRequestType::Reject, false) => {
                match actual_protocols {
                    ActualProtocols::Eval { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "None",
                            got: "Eval",
                        });
                    }
                    ActualProtocols::EvalApprove { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "None",
                            got: "EvalApprove",
                        });
                    }
                    ActualProtocols::None => {}
                }
                Ok(Self::Reject { validation })
            }
            (EventRequestType::Eol, true) | (EventRequestType::Eol, false) => {
                match actual_protocols {
                    ActualProtocols::Eval { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "None",
                            got: "Eval",
                        });
                    }
                    ActualProtocols::EvalApprove { .. } => {
                        return Err(ProtocolsError::InvalidActualProtocols {
                            expected: "None",
                            got: "EvalApprove",
                        });
                    }
                    ActualProtocols::None => {}
                }
                Ok(Self::EOL { validation })
            }
            (EventRequestType::Create, _) => {
                Err(ProtocolsError::InvalidEventRequestType {
                    request_type: "Create",
                    is_gov,
                })
            }
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Ledger {
    pub event_request: Signed<EventRequest>,
    pub gov_version: u64,
    pub sn: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    pub protocols: Protocols,
}

impl Ledger {
    pub fn get_subject_id(&self) -> DigestIdentifier {
        if let Protocols::Create { validation } = &self.protocols && let ValidationMetadata::Metadata(metadata) = &validation.validation_metadata {
            metadata.subject_id.clone()
        } else {
            self.event_request.content().get_subject_id()
        }
    }

    pub fn build_ledger_db(&self, signature_timestamp: u64) -> LedgerDB {
        let (event, subject_id) = self.protocols.buidl_event_db(self.event_request.content());

        LedgerDB {
            subject_id: subject_id
                .to_string(),
            sn: self.sn,
            event_request_timestamp: self
                .event_request
                .signature()
                .timestamp
                .as_nanos(),
            event_ledger_timestamp: signature_timestamp,
            sink_timestamp: TimeStamp::now().as_nanos(),
            event_type: event.get_event_type(),
            event
        }
    }
    pub fn get_create_metadata(&self) -> Result<Metadata, ProtocolsError> {
        if let Protocols::Create { validation } = &self.protocols
            && let ValidationMetadata::Metadata(metadata) =
                &validation.validation_metadata
        {
            Ok(*metadata.clone())
        } else {
            Err(ProtocolsError::NotCreateWithMetadata)
        }
    }
}
