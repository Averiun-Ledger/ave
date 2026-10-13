//! Subject metadata shared by the node and the off-chain
//! verification tool. State conversions from live actors stay in
//! core.

use crate::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, PublicKey},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// Subject metadata.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct Metadata {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The identifier of the subject of the event.
    pub subject_id: DigestIdentifier,
    /// The identifier of the governance contract.
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    /// The identifier of the schema_id used to validate the event.
    pub schema_id: SchemaType,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The current sequence number of the subject.
    pub sn: u64,
    /// The identifier of the public key of the creator owner.
    pub creator: PublicKey,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct MetadataWithoutProperties {
    pub name: Option<String>,
    pub description: Option<String>,
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    pub schema_id: SchemaType,
    pub namespace: Namespace,
    pub sn: u64,
    pub creator: PublicKey,
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    pub active: bool,
}

impl From<Metadata> for MetadataWithoutProperties {
    fn from(value: Metadata) -> Self {
        Self {
            name: value.name,
            description: value.description,
            subject_id: value.subject_id,
            governance_id: value.governance_id,
            genesis_gov_version: value.genesis_gov_version,
            prev_ledger_event_hash: value.prev_ledger_event_hash,
            schema_id: value.schema_id,
            namespace: value.namespace,
            sn: value.sn,
            creator: value.creator,
            owner: value.owner,
            new_owner: value.new_owner,
            active: value.active,
        }
    }
}
