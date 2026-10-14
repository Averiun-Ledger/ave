//! Subject-level request data shared by the node and the
//! off-chain verification tool.

use crate::{
    Namespace, SchemaType,
    identity::{DigestIdentifier, PublicKey},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct RequestSubjectData {
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub namespace: Namespace,
    pub schema_id: SchemaType,
    pub sn: u64,
    pub gov_version: u64,
    pub signer: PublicKey,
}
