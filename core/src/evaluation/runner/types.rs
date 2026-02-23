use ave_common::{Namespace, SchemaType, ValueWrapper, identity::PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::governance::data::GovernanceData;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone,
)]
pub struct ContractResult {
    pub final_state: ValueWrapper,
    pub success: bool,
    pub error: String,
}

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone,
)]
pub struct RunnerResult {
    pub final_state: ValueWrapper,
    pub approval_required: bool,
}

#[derive(Debug, Clone)]
pub enum EvaluateInfo {
    GovFact {
        payload: ValueWrapper,
        state: GovernanceData,
    },
    GovTransfer {
        new_owner: PublicKey,
        state: GovernanceData,
    },
    GovConfirm {
        new_owner: PublicKey,
        old_owner_name: Option<String>,
        state: GovernanceData,
    },
    TrackerSchemasFact {
        contract: String,
        init_state: ValueWrapper,
        state: ValueWrapper,
        payload: ValueWrapper,
    },
    TrackerSchemasTransfer {
        governance_data: GovernanceData,
        new_owner: PublicKey,
        old_owner: PublicKey,
        namespace: Namespace,
        schema_id: SchemaType,
    },
}
