use crate::{
    evaluation::{response::EvaluatorError, runner::types::EvaluateInfo},
    governance::data::GovernanceData,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed},
    request::EventRequest,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing an evaluation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct EvaluationReq {
    /// The signed event request.
    pub event_request: Signed<EventRequest>,

    pub governance_id: DigestIdentifier,

    pub data: EvaluateData,

    pub sn: u64,

    pub gov_version: u64,

    pub namespace: Namespace,

    pub schema_id: SchemaType,

    pub signer: PublicKey,

    pub signer_is_owner: bool,
}

impl EvaluationReq {
    pub fn build_evaluate_info(
        &self,
        init_state: &Option<ValueWrapper>,
    ) -> Result<EvaluateInfo, EvaluatorError> {
        match (self.event_request.content(), &self.data) {
            (
                EventRequest::Fact(fact_request),
                EvaluateData::GovFact { state },
            ) => Ok(EvaluateInfo::GovFact {
                payload: fact_request.payload.clone(),
                state: state.clone(),
            }),
            (
                EventRequest::Fact(fact_request),
                EvaluateData::TrackerSchemasFact { contract, state },
            ) => init_state.as_ref().map_or_else(
                || {
                    Err(EvaluatorError::InternalError(
                        "Init state must be some".to_owned(),
                    ))
                },
                |init_state| {
                    Ok(EvaluateInfo::TrackerSchemasFact {
                        contract: contract.clone(),
                        init_state: init_state.clone(),
                        state: state.clone(),
                        payload: fact_request.payload.clone(),
                    })
                },
            ),
            (
                EventRequest::Transfer(transfer_request),
                EvaluateData::GovTransfer { state },
            ) => Ok(EvaluateInfo::GovTransfer {
                new_owner: transfer_request.new_owner.clone(),
                state: state.clone(),
            }),
            (
                EventRequest::Transfer(transfer_request),
                EvaluateData::TrackerSchemasTransfer {
                    governance_data,
                    namespace,
                    schema_id,
                    ..
                },
            ) => Ok(EvaluateInfo::TrackerSchemasTransfer {
                governance_data: governance_data.clone(),
                new_owner: transfer_request.new_owner.clone(),
                old_owner: self.event_request.signature().signer.clone(),
                namespace: namespace.clone(),
                schema_id: schema_id.clone(),
            }),
            (
                EventRequest::Confirm(confirm_request),
                EvaluateData::GovConfirm { state },
            ) => Ok(EvaluateInfo::GovConfirm {
                new_owner: self.event_request.signature().signer.clone(),
                old_owner_name: confirm_request.name_old_owner.clone(),
                state: state.clone(),
            }),
            _ => Err(EvaluatorError::InvalidEventRequest(
                "Evaluate data does not correspond to the type of request"
                    .to_string(),
            )),
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum EvaluateData {
    GovFact {
        state: GovernanceData,
    },
    GovTransfer {
        state: GovernanceData,
    },
    GovConfirm {
        state: GovernanceData,
    },
    TrackerSchemasFact {
        contract: String,
        state: ValueWrapper,
    },
    TrackerSchemasTransfer {
        state: ValueWrapper,
        governance_data: GovernanceData,
        namespace: Namespace,
        schema_id: SchemaType,
    },
}

impl EvaluateData {
    pub const fn is_gov_event(&self) -> bool {
        match self {
            Self::GovFact { .. }
            | Self::GovTransfer { .. }
            | Self::GovConfirm { .. } => true,
            Self::TrackerSchemasFact { .. }
            | Self::TrackerSchemasTransfer { .. } => false,
        }
    }
}

/// A struct representing the context in which the evaluation is being performed.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SubjectContext {
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub schema_id: SchemaType,
    pub is_owner: bool,
    pub namespace: Namespace,
}
