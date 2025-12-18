use super::proof::ValidationProof;

use crate::model::event::ProtocolsSignatures;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing a validation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ValidationReq {
    // La generamos nosotros
    pub proof: ValidationProof,
    // Hay que sacarlo de la base de datos,
    pub previous_proof: Option<ValidationProof>,
    // Hay que sacarlo de la base de datos,
    pub last_vali_res: Vec<ProtocolsSignatures>,
}
