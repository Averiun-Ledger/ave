//! # Event data model.
//!

use super::network::TimeOut;

use crate::{
    evaluation::response::{EvaluatorError, EvaluatorResponse},
    model::request::EventRequestType,
    subject::Metadata,
    validation::request::ActualProtocols,
};

use ave_actors::ActorError;
use ave_common::{
    identity::{DigestIdentifier, Signature, Signed},
    request::EventRequest,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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
    Metadata(Metadata),
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
    ) -> Result<Self, ActorError> {
        match (event_request, is_gov) {
            (EventRequestType::Fact, true) => {
                let (evaluation, approval) = match actual_protocols {
                    ActualProtocols::Eval { eval_data } => {
                        if eval_data.evaluator_res().is_some() {
                            return Err(ActorError::FunctionalFail(
                                "Invalid evaluation".to_string(),
                            ));
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
                                return Err(ActorError::FunctionalFail(
                                    "Invalid evaluation".to_string(),
                                ));
                            }
                        } else {
                            return Err(ActorError::FunctionalFail(
                                "Invalid evaluation".to_string(),
                            ));
                        };

                        (eval_data, Some(approval_data))
                    }
                    ActualProtocols::None => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
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
                    ActualProtocols::None
                    | ActualProtocols::EvalApprove { .. } => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
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
                    ActualProtocols::None
                    | ActualProtocols::EvalApprove { .. } => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
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
                    ActualProtocols::None
                    | ActualProtocols::EvalApprove { .. } => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
                    }
                };
                Ok(Self::GovConfirm {
                    evaluation,
                    validation,
                })
            }
            (EventRequestType::Confirm, false) => {
                match actual_protocols {
                    ActualProtocols::Eval { .. }
                    | ActualProtocols::EvalApprove { .. } => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
                    }
                    _ => {}
                }
                Ok(Self::TrackerConfirm { validation })
            }
            (EventRequestType::Reject, true)
            | (EventRequestType::Reject, false) => {
                match actual_protocols {
                    ActualProtocols::Eval { .. }
                    | ActualProtocols::EvalApprove { .. } => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
                    }
                    _ => {}
                }
                Ok(Self::Reject { validation })
            }
            (EventRequestType::EOL, true) | (EventRequestType::EOL, false) => {
                match actual_protocols {
                    ActualProtocols::Eval { .. }
                    | ActualProtocols::EvalApprove { .. } => {
                        return Err(ActorError::FunctionalFail(
                            "Invalid actual protocols".to_string(),
                        ));
                    }
                    _ => {}
                }
                Ok(Self::EOL { validation })
            }
            _ => {
                return Err(ActorError::FunctionalFail(
                    "Invalid event request type".to_string(),
                ));
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
    pub fn get_create_metadata(&self) -> Result<Metadata, String> {
        if let Protocols::Create { validation } = &self.protocols
            && let ValidationMetadata::Metadata(metadata) =
                &validation.validation_metadata
        {
            Ok(metadata.clone())
        } else {
            todo!()
        }
    }
}
