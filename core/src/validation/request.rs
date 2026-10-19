use crate::model::event::{
    ApprovalData, CompilationData, EvaluationData, EvaluationResponse,
    ValidationData,
};
use crate::validation::response::ValidatorError;
use crate::subject::{Metadata, RequestSubjectData};

use anyhow::bail;
use ave_common::{
    Namespace, SchemaType,
    bridge::request::EventRequestType,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh},
    request::EventRequest,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A struct representing a validation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ValidationReq {
    Create {
        subject_id: DigestIdentifier,
        event_request: Arc<Signed<EventRequest>>,
        gov_version: u64,
    },
    Event {
        actual_protocols: Box<ActualProtocols>,
        event_request: Arc<Signed<EventRequest>>,
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

    pub fn is_valid(&self) -> bool {
        match self {
            Self::Create { event_request, .. } => {
                matches!(event_request.content(), EventRequest::Create(..))
            }
            Self::Event { event_request, .. } => {
                !matches!(event_request.content(), EventRequest::Create(..))
            }
        }
    }

    pub fn get_signed_event_request(&self) -> Arc<Signed<EventRequest>> {
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
    /// Hash of the approval tally of the previous event, present when that
    /// event went through approval.
    pub approval_data_hash: Option<DigestIdentifier>,
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
        approval_data: Box<ApprovalData>,
    },
    /// The governance fact touched contracts and the compilation phase
    /// rejected them: the event commits as failed without evaluation.
    Compile {
        compile_data: CompilationData,
    },
    /// Compilation succeeded but the evaluation failed.
    CompileEval {
        compile_data: CompilationData,
        eval_data: EvaluationData,
    },
    /// Compilation and evaluation succeeded and the approval closed.
    CompileEvalApprove {
        compile_data: CompilationData,
        eval_data: EvaluationData,
        approval_data: Box<ApprovalData>,
    },
}

impl ActualProtocols {
    /// `approved` is the outcome of the approval collection, only consulted
    /// for the approve variants: at request time it is unknown and the
    /// caller must not rely on this method for them.
    pub const fn is_success(&self, approved: bool) -> bool {
        match &self {
            Self::None => true,
            Self::Eval { eval_data } => eval_data.is_ok(),
            Self::EvalApprove { .. } => approved,
            Self::Compile { .. } | Self::CompileEval { .. } => false,
            Self::CompileEvalApprove { .. } => approved,
        }
    }

    pub const fn needs_approval(&self) -> bool {
        matches!(
            self,
            Self::EvalApprove { .. } | Self::CompileEvalApprove { .. }
        )
    }

    pub const fn check_protocols(
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
                !eval_data.is_ok()
            }
            (
                Self::EvalApprove { eval_data, .. },
                true,
                EventRequestType::Fact,
            ) => eval_data.is_ok(),
            (Self::Compile { compile_data }, true, EventRequestType::Fact) => {
                !compile_data.is_ok()
            }
            (
                Self::CompileEval {
                    compile_data,
                    eval_data,
                },
                true,
                EventRequestType::Fact,
            ) => compile_data.is_ok() && !eval_data.is_ok(),
            (
                Self::CompileEvalApprove {
                    compile_data,
                    eval_data,
                    ..
                },
                true,
                EventRequestType::Fact,
            ) => compile_data.is_ok() && eval_data.is_ok(),
            _ => false,
        }
    }
}

impl ActualProtocols {
    /// Rebuilds the protocol combination from committed phase
    /// evidence, mirroring the request manager: same match, same
    /// shapes. A compilation with approval but without evaluation
    /// can never commit honestly.
    pub fn build_actual_protocols(
        compilation: Option<&CompilationData>,
        evaluation: Option<&EvaluationData>,
        approval: Option<&ApprovalData>,
    ) -> Result<Self, ValidatorError> {
        match (
            compilation.is_some(),
            evaluation.is_some(),
            approval.is_some(),
        ) {
            (true, true, true) => Ok(Self::CompileEvalApprove {
                compile_data: compilation.expect("matched present").clone(),
                eval_data: evaluation.expect("matched present").clone(),
                approval_data: Box::new(
                    approval.expect("matched present").clone(),
                ),
            }),
            (true, true, false) => Ok(Self::CompileEval {
                compile_data: compilation.expect("matched present").clone(),
                eval_data: evaluation.expect("matched present").clone(),
            }),
            (true, false, false) => Ok(Self::Compile {
                compile_data: compilation.expect("matched present").clone(),
            }),
            (false, true, true) => Ok(Self::EvalApprove {
                eval_data: evaluation.expect("matched present").clone(),
                approval_data: Box::new(
                    approval.expect("matched present").clone(),
                ),
            }),
            (false, true, false) => Ok(Self::Eval {
                eval_data: evaluation.expect("matched present").clone(),
            }),
            (false, false, _) => Ok(Self::None),
            (true, false, true) => Err(ValidatorError::InvalidData {
                value: "protocols combination",
            }),
        }
    }

    /// Rebuilds a validation request from anchored data: phases,
    /// envelope, chain linkage, pre-event metadata and the previous
    /// event. Same atoms the request manager assembles live.
    pub fn rebuild_validation_req(
        actual_protocols: Self,
        event_request: &Arc<Signed<EventRequest>>,
        ledger_hash: DigestIdentifier,
        metadata: &Metadata,
        last_data: LastData,
        gov_version: u64,
        sn: u64,
    ) -> ValidationReq {
        ValidationReq::Event {
            actual_protocols: Box::new(actual_protocols),
            event_request: event_request.clone(),
            ledger_hash,
            metadata: Box::new(metadata.clone()),
            last_data: Box::new(last_data),
            gov_version,
            sn,
        }
    }
}

/// Request-subject hash anchoring requests to their position,
/// exactly like validators compute it.
pub fn req_subject_data_hash(
    hash: &HashAlgorithm,
    metadata: &Metadata,
    sn: u64,
    gov_version: u64,
    signer: &PublicKey,
) -> anyhow::Result<DigestIdentifier> {
    hash_borsh(
        &*hash.hasher(),
        &RequestSubjectData {
            subject_id: metadata.subject_id.clone(),
            governance_id: metadata.governance_id.clone(),
            namespace: metadata.namespace.clone(),
            schema_id: metadata.schema_id.clone(),
            sn,
            gov_version,
            signer: signer.clone(),
        },
    )
    .map_err(|e| anyhow::anyhow!("subject hash: {e}"))
}

/// Phase combination rules of a governance fact.
///
/// Mirrors the node constructors: a failed compilation carries
/// neither evaluation nor approval (nothing to evaluate);
/// otherwise an evaluation is mandatory, a successful one always
/// travels with its approval and a failed one never does.
pub fn check_gov_fact_combination(
    compilation: &Option<Box<CompilationData>>,
    evaluation: &Option<EvaluationData>,
    approval: &Option<ApprovalData>,
) -> anyhow::Result<()> {
    if let Some(compilation) = compilation
        && !compilation.is_ok()
    {
        if evaluation.is_some() || approval.is_some() {
            bail!(
                "failed compilation carries no evaluation or approval"
            );
        }
        return Ok(());
    }
    match (evaluation, approval) {
        (None, _) => bail!("governance fact without evaluation"),
        (Some(evaluation), None) => {
            if evaluation.is_ok() {
                bail!("evaluation succeeded without approval");
            }
            Ok(())
        }
        (Some(evaluation), Some(_)) => {
            match &evaluation.response {
                EvaluationResponse::Ok {
                    result,
                    ..
                } => {
                    if !result.appr_required {
                        bail!("approval without required evaluation");
                    }
                    Ok(())
                }
                _ => bail!("approval over failed evaluation"),
            }
        }
    }
}
