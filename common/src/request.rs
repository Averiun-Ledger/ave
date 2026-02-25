use ave_identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{Namespace, SchemaType, ValueWrapper};

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
    pub fn check_request_signature(
        &self,
        signer: &PublicKey,
        owner: &PublicKey,
        new_owner: &Option<PublicKey>,
    ) -> bool {
        match self {
            Self::Create(..)
            | Self::Transfer(..)
            | Self::EOL(..) => signer == owner,
            Self::Confirm(..) | Self::Reject(..) => {
                if let Some(new_owner) = new_owner {
                    new_owner == signer
                } else {
                    false
                }
            }
            Self::Fact(..) => true,
        }
    }

    pub const fn is_create_event(&self) -> bool {
        matches!(self, Self::Create(_create_request))
    }
    pub const fn is_fact_event(&self) -> bool {
        matches!(self, Self::Fact(_fact_request))
    }

    pub fn get_subject_id(&self) -> DigestIdentifier {
        match self {
            Self::Create(_create_request) => {
                DigestIdentifier::default()
            }
            Self::Fact(fact_request) => fact_request.subject_id.clone(),
            Self::Transfer(transfer_request) => {
                transfer_request.subject_id.clone()
            }
            Self::Confirm(confirm_request) => {
                confirm_request.subject_id.clone()
            }
            Self::Reject(reject_request) => {
                reject_request.subject_id.clone()
            }
            Self::EOL(eolrequest) => eolrequest.subject_id.clone(),
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
