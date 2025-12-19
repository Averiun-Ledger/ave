use ave_common::{ValueWrapper, identity::PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::model::{Namespace, request::SchemaType};

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
pub enum EvaluateType {
    AllSchemasFact {
        contract: String,
        init_state: ValueWrapper,
        payload: ValueWrapper,
    },
    GovFact {
        payload: ValueWrapper,
    },
    GovTransfer {
        new_owner: PublicKey,
    },
    AllSchemasTransfer {
        new_owner: PublicKey,
        old_owner: PublicKey,
        namespace: Namespace,
        schema_id: SchemaType,
    },
    GovConfirm {
        new_owner: PublicKey,
        old_owner_name: Option<String>,
    },
}
