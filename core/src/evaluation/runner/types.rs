use borsh::{BorshDeserialize, BorshSerialize};
use identity::PublicKey;
use serde::{Deserialize, Serialize};

use crate::{ValueWrapper, model::Namespace};

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
        contract: Vec<u8>,
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
        schema_id: String,
    },
    GovConfirm {
        new_owner: PublicKey,
        old_owner_name: Option<String>,
    },
}
