//! # Event data model.
//!

use std::collections::BTreeSet;

use super::network::TimeOut;

use crate::{
    evaluation::response::{EvaluatorError, EvaluatorResponse},
    subject::Metadata,
    validation::request::ActualProtocols,
};

use ave_common::{
    bridge::request::EventRequestType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signature, Signed,
        TimeStamp, hash_borsh,
    },
    request::EventRequest,
    response::{EvalResDB, LedgerDB, RequestEventDB},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::error::{LedgerError, ProtocolsError};

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum EvaluationResponse {
    Ok {
        result: EvaluatorResponse,
        result_hash: DigestIdentifier,
    },
    Error {
        result: EvaluatorError,
        result_hash: DigestIdentifier,
    },
}

impl EvaluationResponse {
    pub fn build_opaque(&self) -> EvaluationResponseOpaque {
        match self.clone() {
            EvaluationResponse::Ok { result_hash, .. } => {
                EvaluationResponseOpaque::Ok { result_hash }
            }
            EvaluationResponse::Error { result_hash, .. } => {
                EvaluationResponseOpaque::Error { result_hash }
            }
        }
    }
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum EvaluationResponseOpaque {
    Ok { result_hash: DigestIdentifier },
    Error { result_hash: DigestIdentifier },
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct EvaluationDataOpaque {
    pub eval_req_signature: Signature,
    pub eval_req_hash: DigestIdentifier,
    pub evaluators_signatures: Vec<Signature>,
    pub viewpoints: BTreeSet<String>,
    pub response: EvaluationResponseOpaque,
}

impl EvaluationDataOpaque {
    pub fn is_ok(&self) -> bool {
        match &self.response {
            EvaluationResponseOpaque::Ok { .. } => true,
            _ => false,
        }
    }
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
    pub fn is_ok(&self) -> bool {
        match &self.response {
            EvaluationResponse::Ok { .. } => true,
            _ => false,
        }
    }

    pub fn evaluator_response_ok(&self) -> Option<EvaluatorResponse> {
        match &self.response {
            EvaluationResponse::Ok { result, .. } => Some(result.clone()),
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
    ModifiedHash {
        modified_metadata_without_propierties_hash: DigestIdentifier,
        propierties_hash: DigestIdentifier,
        event_request_hash: DigestIdentifier,
        viewpoints_hash: DigestIdentifier,
    },
    Metadata(Box<Metadata>),
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct OpaqueData {
    pub subject_id: DigestIdentifier,
    pub event_request_timestamp: TimeStamp,
    pub signer: PublicKey,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum Protocols {
    Create {
        event_request: Signed<EventRequest>,
        validation: ValidationData,
    },
    TrackerFactFull {
        event_request: Signed<EventRequest>,
        evaluation: EvaluationData,
        validation: ValidationData,
    },
    TrackerFactOpaque {
        event_request_hash: DigestIdentifier,
        evaluation: EvaluationDataOpaque,
        validation: ValidationData,
        data: OpaqueData,
    },
    GovFact {
        event_request: Signed<EventRequest>,
        evaluation: EvaluationData,
        approval: Option<ApprovalData>,
        validation: ValidationData,
    },
    Transfer {
        event_request: Signed<EventRequest>,
        evaluation: EvaluationData,
        validation: ValidationData,
    },
    TrackerConfirm {
        event_request: Signed<EventRequest>,
        validation: ValidationData,
    },
    GovConfirm {
        event_request: Signed<EventRequest>,
        evaluation: EvaluationData,
        validation: ValidationData,
    },
    Reject {
        event_request: Signed<EventRequest>,
        validation: ValidationData,
    },
    EOL {
        event_request: Signed<EventRequest>,
        validation: ValidationData,
    },
}

impl Protocols {
    pub fn hash_for_ledger(
        &self,
        hash: &HashAlgorithm,
    ) -> Result<DigestIdentifier, ProtocolsError> {
        match self {
            Self::TrackerFactFull {
                event_request,
                evaluation,
                validation,
            } => {
                let fact_request =
                    match event_request.content() {
                        EventRequest::Fact(fact_request) => fact_request,
                        _ => return Err(
                            ProtocolsError::InvalidTrackerFactFullEventRequest,
                        ),
                    };
                let eval_res_opaque = evaluation.response.build_opaque();

                let opaque = Self::TrackerFactOpaque {
                    data: OpaqueData {
                        subject_id: event_request.content().get_subject_id(),
                        event_request_timestamp: event_request
                            .signature()
                            .timestamp,
                        signer: event_request.signature().signer.clone(),
                    },
                    event_request_hash: hash_borsh(
                        &*hash.hasher(),
                        event_request,
                    )
                    .map_err(|e| {
                        ProtocolsError::HashingFailed(e.to_string())
                    })?,
                    evaluation: EvaluationDataOpaque {
                        eval_req_signature: evaluation
                            .eval_req_signature
                            .clone(),
                        eval_req_hash: evaluation.eval_req_hash.clone(),
                        evaluators_signatures: evaluation
                            .evaluators_signatures
                            .clone(),
                        viewpoints: fact_request.viewpoints.clone(),
                        response: eval_res_opaque,
                    },
                    validation: validation.clone(),
                };

                hash_borsh(&*hash.hasher(), &opaque)
                    .map_err(|e| ProtocolsError::HashingFailed(e.to_string()))
            }
            _ => hash_borsh(&*hash.hasher(), self)
                .map_err(|e| ProtocolsError::HashingFailed(e.to_string())),
        }
    }

    pub fn buidl_event_db(
        &self,
    ) -> (RequestEventDB, DigestIdentifier, u64) {
        match self {
            Self::Create {
                validation,
                event_request,
            } => {
                let ValidationMetadata::Metadata(metadata) =
                    &validation.validation_metadata
                else {
                    unreachable!(
                        "Unreachable combination is a create event request"
                    )
                };

                let EventRequest::Create(create) = event_request.content()
                else {
                    unreachable!(
                        "Unreachable combination is a create event request"
                    )
                };

                (
                    RequestEventDB::Create {
                        name: create.name.clone(),
                        description: create.description.clone(),
                        schema_id: create.schema_id.to_string(),
                        namespace: create.namespace.to_string(),
                    },
                    metadata.subject_id.clone(),
                    event_request.signature().timestamp.as_nanos(),
                )
            }
            Self::TrackerFactFull {
                evaluation,
                event_request,
                ..
            } => {
                let evaluation_response = match evaluation.response.clone() {
                    EvaluationResponse::Ok { result, .. } => {
                        EvalResDB::Patch(result.patch.0)
                    }
                    EvaluationResponse::Error { result, .. } => {
                        EvalResDB::Error(result.to_string())
                    }
                };

                let EventRequest::Fact(fact_request) = event_request.content()
                else {
                    unreachable!(
                        "Unreachable combination is a fact event request"
                    )
                };

                (
                    RequestEventDB::TrackerFactFull {
                        payload: fact_request.payload.0.clone(),
                        viewpoints: fact_request
                            .viewpoints
                            .iter()
                            .cloned()
                            .collect(),
                        evaluation_response,
                    },
                    event_request.content().get_subject_id(),
                    event_request.signature().timestamp.as_nanos(),
                )
            }
            Self::TrackerFactOpaque {
                evaluation,
                data,
                ..
            } => (
                RequestEventDB::TrackerFactOpaque {
                    viewpoints: evaluation.viewpoints.iter().cloned().collect(),
                    evaluation_success: evaluation.is_ok(),
                },
                data.subject_id.clone(),
                data.event_request_timestamp.as_nanos(),
            ),
            Self::GovFact {
                evaluation,
                approval,
                event_request,
                ..
            } => {
                let (evaluation_response, approval_success) = match evaluation
                    .response
                    .clone()
                {
                    EvaluationResponse::Ok { result, .. } => {
                        if let Some(appr) = approval {
                            (
                                EvalResDB::Patch(result.patch.0),
                                Some(appr.approved),
                            )
                        } else {
                            unreachable!(
                                "In a fact governance event, if the assessment is correct, there should be approval"
                            )
                        }
                    }
                    EvaluationResponse::Error { result, .. } => {
                        (EvalResDB::Error(result.to_string()), None)
                    }
                };

                let EventRequest::Fact(fact_request) = event_request.content()
                else {
                    unreachable!(
                        "Unreachable combination is a fact event request"
                    )
                };

                (
                    RequestEventDB::GovernanceFact {
                        payload: fact_request.payload.0.clone(),
                        evaluation_response,
                        approval_success,
                    },
                    event_request.content().get_subject_id(),
                    event_request.signature().timestamp.as_nanos()
                )
            }
            Self::Transfer {
                evaluation,
                event_request,
                ..
            } => {
                let EventRequest::Transfer(transfer_request) =
                    event_request.content()
                else {
                    unreachable!(
                        "Unreachable combination is a transfer event request"
                    )
                };

                let evaluation_error = match evaluation.response.clone() {
                    EvaluationResponse::Ok { .. } => None,
                    EvaluationResponse::Error { result, .. } => {
                        Some(result.to_string())
                    }
                };

                (
                    RequestEventDB::Transfer {
                        new_owner: transfer_request.new_owner.to_string(),
                        evaluation_error,
                    },
                    event_request.content().get_subject_id(),
                    event_request.signature().timestamp.as_nanos()
                )
            }
            Self::TrackerConfirm { event_request, .. } => (
                RequestEventDB::TrackerConfirm,
                event_request.content().get_subject_id(),
                event_request.signature().timestamp.as_nanos()
            ),
            Self::GovConfirm {
                evaluation,
                event_request,
                ..
            } => {
                let EventRequest::Confirm(confirm_request) =
                    event_request.content()
                else {
                    unreachable!(
                        "Unreachable combination is a confirm event request"
                    )
                };

                let evaluation_response = match evaluation.response.clone() {
                    EvaluationResponse::Ok { result, .. } => {
                        EvalResDB::Patch(result.patch.0)
                    }
                    EvaluationResponse::Error { result, .. } => {
                        EvalResDB::Error(result.to_string())
                    }
                };
                (
                    RequestEventDB::GovernanceConfirm {
                        name_old_owner: confirm_request.name_old_owner.clone(),
                        evaluation_response,
                    },
                    event_request.content().get_subject_id(),
                    event_request.signature().timestamp.as_nanos()
                )
            }
            Self::Reject { event_request, .. } => (
                RequestEventDB::Reject,
                event_request.content().get_subject_id(),
                event_request.signature().timestamp.as_nanos()
            ),
            Self::EOL { event_request, .. } => (
                RequestEventDB::EOL,
                event_request.content().get_subject_id(),
                event_request.signature().timestamp.as_nanos()
            ),
        }
    }

    pub fn get_validation_data(&self) -> ValidationData {
        match self {
            Self::Create { validation, .. }
            | Self::TrackerFactFull { validation, .. }
            | Self::TrackerFactOpaque { validation, .. }
            | Self::GovFact { validation, .. }
            | Self::Transfer { validation, .. }
            | Self::TrackerConfirm { validation, .. }
            | Self::GovConfirm { validation, .. }
            | Self::Reject { validation, .. }
            | Self::EOL { validation, .. } => validation.clone(),
        }
    }

    pub fn is_success(&self) -> bool {
        match self {
            Self::Create { .. } => true,
            Self::TrackerFactFull { evaluation, .. } => evaluation.is_ok(),
            Self::TrackerFactOpaque { evaluation, .. } => evaluation.is_ok(),
            Self::GovFact { approval, .. } => {
                approval.as_ref().is_some_and(|approval| approval.approved)
            }
            Self::Transfer { evaluation, .. } => evaluation.is_ok(),
            Self::TrackerConfirm { .. } => true,
            Self::GovConfirm { evaluation, .. } => evaluation.is_ok(),
            Self::Reject { .. } => true,
            Self::EOL { .. } => true,
        }
    }

    pub fn build(
        is_gov: bool,
        event_request: Signed<EventRequest>,
        actual_protocols: ActualProtocols,
        validation: ValidationData,
    ) -> Result<Self, ProtocolsError> {
        let event_request_type =
            EventRequestType::from(event_request.content());

        match (event_request_type, is_gov) {
            (EventRequestType::Create, _) => {
                Err(ProtocolsError::InvalidEventRequestType {
                    request_type: "Create",
                    is_gov,
                })
            }
            (EventRequestType::Fact, true) => {
                let (evaluation, approval) = match actual_protocols {
                    ActualProtocols::Eval { eval_data } => {
                        if eval_data.is_ok() {
                            return Err(ProtocolsError::InvalidEvaluation);
                        } else {
                            (eval_data, None)
                        }
                    }
                    ActualProtocols::EvalApprove {
                        eval_data,
                        approval_data,
                    } => {
                        if let EvaluationResponse::Ok { result, .. } =
                            &eval_data.response
                        {
                            if !result.appr_required {
                                return Err(ProtocolsError::ApprovalRequired);
                            }
                        } else {
                            return Err(ProtocolsError::InvalidEvaluation);
                        }

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
                    event_request,
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

                Ok(Self::TrackerFactFull {
                    event_request,
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
                    event_request,
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
                    event_request,
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
                Ok(Self::TrackerConfirm {
                    event_request,
                    validation,
                })
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
                Ok(Self::Reject {
                    event_request,
                    validation,
                })
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
                Ok(Self::EOL {
                    event_request,
                    validation,
                })
            }
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct LedgerSeal {
    pub gov_version: u64,
    pub sn: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    pub protocols_hash: DigestIdentifier,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct LedgerHash {
    pub gov_version: u64,
    pub sn: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    pub protocols_hash: DigestIdentifier,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Ledger {
    pub gov_version: u64,
    pub sn: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    pub ledger_seal_signature: Signature,
    pub protocols: Protocols,
}

impl Ledger {
    pub fn get_issuer_event_request_timestamp(&self) -> (String, u64) {
        match &self.protocols {
            Protocols::TrackerFactOpaque { data , .. } => (data.signer.to_string(), data.event_request_timestamp.as_nanos()),
            Protocols::Create { event_request, .. }
            | Protocols::TrackerFactFull { event_request, .. }
            | Protocols::GovFact { event_request, .. }
            | Protocols::Transfer { event_request, .. }
            | Protocols::TrackerConfirm { event_request, .. }
            | Protocols::GovConfirm { event_request, .. }
            | Protocols::Reject { event_request, .. }
            | Protocols::EOL { event_request, .. } => (
                event_request.signature().signer.clone().to_string(),
                event_request.signature().timestamp.clone().as_nanos(),
            ),
        }
    }

    pub fn ledger_hash(
        &self,
        hash: HashAlgorithm,
    ) -> Result<DigestIdentifier, LedgerError> {
        let protocols_hash = self.protocols.hash_for_ledger(&hash)?;

        let ledger_hash = LedgerHash {
            gov_version: self.gov_version,
            sn: self.sn,
            prev_ledger_event_hash: self.prev_ledger_event_hash.clone(),
            protocols_hash,
        };

        hash_borsh(&*hash.hasher(), &ledger_hash)
            .map_err(|e| LedgerError::HashingFailed(e.to_string()))
    }

    pub fn get_event_request_type(&self) -> EventRequestType {
        match &self.protocols {
            Protocols::Create { .. } => EventRequestType::Create,
            Protocols::TrackerFactFull { .. }
            | Protocols::TrackerFactOpaque { .. }
            | Protocols::GovFact { .. } => EventRequestType::Fact,
            Protocols::Transfer { .. } => EventRequestType::Transfer,
            Protocols::TrackerConfirm { .. } | Protocols::GovConfirm { .. } => {
                EventRequestType::Confirm
            }
            Protocols::Reject { .. } => EventRequestType::Reject,
            Protocols::EOL { .. } => EventRequestType::Eol,
        }
    }

    pub fn get_event_request(&self) -> Result<EventRequest, LedgerError> {
        match &self.protocols {
            Protocols::TrackerFactOpaque { .. } => {
                Err(LedgerError::MissingEventRequest)
            }
            Protocols::Create { event_request, .. }
            | Protocols::TrackerFactFull { event_request, .. }
            | Protocols::GovFact { event_request, .. }
            | Protocols::Transfer { event_request, .. }
            | Protocols::TrackerConfirm { event_request, .. }
            | Protocols::GovConfirm { event_request, .. }
            | Protocols::Reject { event_request, .. }
            | Protocols::EOL { event_request, .. } => {
                Ok(event_request.content().clone())
            }
        }
    }

    pub fn get_subject_id(&self) -> DigestIdentifier {
        match &self.protocols {
            Protocols::Create {
                event_request,
                validation,
            } => {
                if let ValidationMetadata::Metadata(metadata) =
                    &validation.validation_metadata
                {
                    metadata.subject_id.clone()
                } else {
                    event_request.content().get_subject_id()
                }
            }
            Protocols::TrackerFactOpaque { data, .. } => {
                data.subject_id.clone()
            }
            Protocols::TrackerFactFull { event_request, .. }
            | Protocols::GovFact { event_request, .. }
            | Protocols::Transfer { event_request, .. }
            | Protocols::TrackerConfirm { event_request, .. }
            | Protocols::GovConfirm { event_request, .. }
            | Protocols::Reject { event_request, .. }
            | Protocols::EOL { event_request, .. } => {
                event_request.content().get_subject_id()
            }
        }
    }

    pub fn build_ledger_db(&self, signature_timestamp: u64) -> LedgerDB {
        let (event, subject_id, event_request_timestamp) =
            self.protocols.buidl_event_db();

        LedgerDB {
            subject_id: subject_id.to_string(),
            sn: self.sn,
            event_request_timestamp,
            event_ledger_timestamp: signature_timestamp,
            sink_timestamp: TimeStamp::now().as_nanos(),
            event_type: event.get_event_type(),
            event,
        }
    }
    pub fn get_create_metadata(&self) -> Result<Metadata, ProtocolsError> {
        if let Protocols::Create { validation, .. } = &self.protocols
            && let ValidationMetadata::Metadata(metadata) =
                &validation.validation_metadata
        {
            Ok(*metadata.clone())
        } else {
            Err(ProtocolsError::NotCreateWithMetadata)
        }
    }
}
