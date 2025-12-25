//! # Request data model.
//!

use std::{
    collections::HashSet,
    fmt::Display,
};

use super::Namespace;

use crate::{
    Error,
    governance::{data::GovernanceData, model::SignersType},
    subject::Metadata,
};

use ave_common::{
    ValueWrapper,
    identity::{
        DSAlgorithm, DigestIdentifier, PublicKey, Signature,
        SignatureIdentifier, Signed, TimeStamp,
    },
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

#[derive(
    Default,
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum SchemaType {
    #[default]
    Governance,
    Type(String),
    AllSchemas,
}

impl std::str::FromStr for SchemaType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Special case: empty string deserializes to default (empty) digest
        if s.is_empty() {
            return Err("Schema_id can not be empty".to_string());
        }

        match s {
            "governance" => Ok(SchemaType::Governance),
            "all_schemas" => Ok(SchemaType::AllSchemas),
            _ => Ok(SchemaType::Type(s.to_string())),
        }
    }
}

impl SchemaType {
    pub fn len(&self) -> usize {
        match self {
            SchemaType::Governance => "governance".len(),
            SchemaType::Type(schema_id) => schema_id.len(),
            SchemaType::AllSchemas => "all_schemas".len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            SchemaType::Governance => false,
            SchemaType::Type(schschema_id) => schschema_id.is_empty(),
            SchemaType::AllSchemas => false,
        } 
    }

    pub fn is_valid(&self) -> bool {
        match self {
            SchemaType::Governance => true,
            SchemaType::AllSchemas => true,
            SchemaType::Type(schema_id) => {
                !schema_id.is_empty()
                    && schema_id != "governance"
                    && schema_id != "all_schemas"
                    && schema_id.trim().len() == schema_id.len()
            }
        }
    }
}

impl Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaType::AllSchemas => write!(f, "all_schemas"),
            SchemaType::Governance => write!(f, "governance"),
            SchemaType::Type(schema_id) => write!(f, "{}", schema_id),
        }
    }
}

impl SchemaType {
    pub fn is_gov(&self) -> bool {
        matches!(self, SchemaType::Governance)
    }
}

impl<'de> Deserialize<'de> for SchemaType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom(
                "Schema can not be empty".to_string(),
            ));
        }

        Ok(match s.as_str() {
            "governance" => SchemaType::Governance,
            "all_schemas" => SchemaType::AllSchemas,
            _ => SchemaType::Type(s),
        })
    }
}

impl Serialize for SchemaType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SchemaType::AllSchemas => serializer.serialize_str("all_schemas"),
            SchemaType::Governance => serializer.serialize_str("governance"),
            SchemaType::Type(schema) => serializer.serialize_str(schema),
        }
    }
}

pub enum EventRequestType {
    Create,
    Fact,
    Transfer,
    Confirm,
    Reject,
    EOL,
}

pub enum SignerTypes {
    One(PublicKey),
    List(HashSet<PublicKey>, bool),
}

impl From<&EventRequest> for EventRequestType {
    fn from(value: &EventRequest) -> Self {
        match value {
            EventRequest::Create(_start_request) => Self::Create,
            EventRequest::Fact(_fact_request) => Self::Fact,
            EventRequest::Transfer(_transfer_request) => Self::Transfer,
            EventRequest::Confirm(_confirm_request) => Self::Confirm,
            EventRequest::EOL(_eolrequest) => Self::EOL,
            EventRequest::Reject(_reject_request) => Self::Reject,
        }
    }
}

pub fn empty_request() -> Signed<EventRequest> {
    Signed {
        content: EventRequest::EOL(EOLRequest {
            subject_id: DigestIdentifier::default(),
        }),
        signature: Signature {
            signer: PublicKey::default(),
            timestamp: TimeStamp::from_nanos(0),
            content_hash: DigestIdentifier::default(),
            value: SignatureIdentifier::new(
                DSAlgorithm::Ed25519,
                vec![0u8; 32],
            )
            .expect("64 bytes, can not fail"),
        },
    }
}

/// An enum representing a Ave Ledger event request.
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
pub enum EventRequest {
    /// A request to create a new subject.
    Create(CreateRequest),
    /// A request to add a fact to a subject.
    Fact(FactRequest),
    /// A request to transfer ownership of a subject.
    Transfer(TransferRequest),

    Confirm(ConfirmRequest),

    Reject(RejectRequest),
    /// A request to mark a subject as end-of-life.
    EOL(EOLRequest),
}

impl EventRequest {
    pub fn check_ledger_signature(
        &self,
        signer: &PublicKey,
        owner: &PublicKey,
        new_owner: &Option<PublicKey>,
    ) -> Result<bool, Error> {
        match self {
            EventRequest::Create(..)
            | EventRequest::Transfer(..)
            | EventRequest::EOL(..) => Ok(signer == owner),
            EventRequest::Confirm(..) | EventRequest::Reject(..) => {
                let Some(new_owner) = new_owner else {
                    return Err(Error::Subject(
                        "new_owner can not be None in Confirm or Reject event"
                            .to_owned(),
                    ));
                };
                Ok(new_owner == signer)
            }
            EventRequest::Fact(..) => Ok(true),
        }
    }

    pub fn check_event_signature(
        &self,
        signer: &PublicKey,
        owner: &PublicKey,
        new_owner: &Option<PublicKey>,
    ) -> Result<bool, Error> {
        match self {
            EventRequest::Create(..)
            | EventRequest::Transfer(..)
            | EventRequest::EOL(..) => Ok(signer == owner),
            EventRequest::Confirm(..) | EventRequest::Reject(..) => {
                let Some(new_owner) = new_owner else {
                    return Err(Error::Subject(
                        "new_owner can not be None in Confirm or Reject event"
                            .to_owned(),
                    ));
                };
                Ok(new_owner == signer)
            }
            EventRequest::Fact(..) => Ok(true),
        }
    }

    pub fn is_create_event(&self) -> bool {
        matches!(self, EventRequest::Create(_create_request))
    }
    pub fn is_fact_event(&self) -> bool {
        matches!(self, EventRequest::Fact(_fact_request))
    }
    pub fn check_signers(
        &self,
        signer: &PublicKey,
        metadata: &Metadata,
        gov: &GovernanceData,
    ) -> bool {
        match self {
            EventRequest::Create(_)
            | EventRequest::EOL(_)
            | EventRequest::Transfer(_) => {
                return metadata.owner == *signer;
            }
            EventRequest::Fact(_) => {
                let (set, any) = gov.get_signers(
                    SignersType::Issuer,
                    &metadata.schema_id,
                    metadata.namespace.clone(),
                );

                if any {
                    return true;
                }

                return set.iter().any(|x| x == signer);
            }
            EventRequest::Confirm(_) | EventRequest::Reject(_) => {
                if let Some(new_owner) = metadata.new_owner.clone() {
                    return new_owner == *signer;
                }
            }
        }
        false
    }

    pub fn get_subject_id(&self) -> DigestIdentifier {
        match self {
            EventRequest::Create(_create_request) => {
                DigestIdentifier::default()
            }
            EventRequest::Fact(fact_request) => fact_request.subject_id.clone(),
            EventRequest::Transfer(transfer_request) => {
                transfer_request.subject_id.clone()
            }
            EventRequest::Confirm(confirm_request) => {
                confirm_request.subject_id.clone()
            }
            EventRequest::Reject(reject_request) => {
                reject_request.subject_id.clone()
            }
            EventRequest::EOL(eolrequest) => eolrequest.subject_id.clone(),
        }
    }
}

/// A struct representing a request to create a new subject.
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
pub struct CreateRequest {
    /// The name of subject.
    pub name: Option<String>,
    /// The description of subject.
    pub description: Option<String>,
    /// The identifier of the governance contract.
    pub governance_id: DigestIdentifier,
    /// The identifier of the schema used to validate the event.
    pub schema_id: SchemaType,
    /// The namespace of the subject.
    pub namespace: Namespace,
}

/// A struct representing a request to add a fact to a subject.
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
pub struct FactRequest {
    /// The identifier of the subject to which the fact will be added.
    pub subject_id: DigestIdentifier,
    /// The payload of the fact to be added.
    pub payload: ValueWrapper,
}

/// A struct representing a request to transfer ownership of a subject.
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
pub struct TransferRequest {
    /// The identifier of the subject to transfer ownership of.
    pub subject_id: DigestIdentifier,
    /// The identifier of the public key of the new owner.
    pub new_owner: PublicKey,
}

/// A struct representing a request to transfer ownership of a subject.
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
pub struct ConfirmRequest {
    pub subject_id: DigestIdentifier,
    /// The new name of old owner, only for governance confirm, if is None in governance confirm, old owner will not add to members
    pub name_old_owner: Option<String>,
}

/// A struct representing a request to mark a subject as end-of-life.
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
pub struct EOLRequest {
    /// The identifier of the subject to mark as end-of-life.
    pub subject_id: DigestIdentifier,
}

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
pub struct RejectRequest {
    pub subject_id: DigestIdentifier,
}


#[cfg(test)]
pub mod tests {

    use super::*;

    use ave_common::identity::{Signature, Signed, keys::KeyPair};

    // Mocks

    // Create governance request mock.
    pub fn create_start_request_mock(
        _issuer: &str,
        keys: KeyPair,
    ) -> Signed<EventRequest> {
        let req = CreateRequest {
            name: None,
            description: None,
            governance_id: DigestIdentifier::default(),
            schema_id: SchemaType::Governance,
            namespace: Namespace::from("namespace"),
        };
        let content = EventRequest::Create(req);
        let signature = Signature::new(&content, &keys).unwrap();
        Signed { content, signature }
    }
}
