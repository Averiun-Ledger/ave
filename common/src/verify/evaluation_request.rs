//! Evaluation request shared by the node and the off-chain
//! verification tool. Context assembly from live actors stays in
//! core.

use super::{
    evaluation_response::EvaluatorError,
    governance::GovernanceData,
    viewpoints::validate_fact_viewpoints,
};
use crate::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed},
    request::EventRequest,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, sync::Arc};

/// A struct representing an evaluation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct EvaluationReq {
    /// The signed event request.
    pub event_request: Arc<Signed<EventRequest>>,

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
    pub fn validate_fact_viewpoints(
        fact_viewpoints: &BTreeSet<String>,
        schema_id: &SchemaType,
        schema_viewpoints: Option<&BTreeSet<String>>,
    ) -> Result<(), EvaluatorError> {
        validate_fact_viewpoints(fact_viewpoints, schema_id, schema_viewpoints)
            .map_err(EvaluatorError::InvalidEventRequest)
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum EvaluateData {
    GovFact { state: GovernanceData },
    GovTransfer { state: GovernanceData },
    GovConfirm { state: GovernanceData },
    TrackerSchemasFact { state: ValueWrapper },
    TrackerSchemasTransfer { state: ValueWrapper },
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
