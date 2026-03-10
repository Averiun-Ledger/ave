//! Ledger event request types.
//!
//! These structures describe the input accepted by the core ledger flow before
//! it is wrapped in transport-specific formats.

use ave_identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use crate::{Namespace, SchemaType, ValueWrapper};

/// Event request accepted by the ledger.
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
    /// Creates a new subject.
    Create(CreateRequest),
    /// Appends a fact to an existing subject.
    Fact(FactRequest),
    /// Transfers subject ownership.
    Transfer(TransferRequest),
    /// Confirms a transfer.
    Confirm(ConfirmRequest),
    /// Rejects a transfer.
    Reject(RejectRequest),
    /// Marks a subject as end-of-life.
    EOL(EOLRequest),
}

impl EventRequest {
    /// Returns `true` when `signer` is allowed to sign this request.
    pub fn check_request_signature(
        &self,
        signer: &PublicKey,
        owner: &PublicKey,
        new_owner: &Option<PublicKey>,
    ) -> bool {
        match self {
            Self::Create(..) | Self::Transfer(..) | Self::EOL(..) => {
                signer == owner
            }
            Self::Confirm(..) | Self::Reject(..) => {
                new_owner.as_ref() == Some(signer)
            }
            Self::Fact(..) => true,
        }
    }

    /// Returns `true` when the request is a `Create`.
    pub const fn is_create_event(&self) -> bool {
        matches!(self, Self::Create(_create_request))
    }

    /// Returns `true` when the request is a `Fact`.
    pub const fn is_fact_event(&self) -> bool {
        matches!(self, Self::Fact(_fact_request))
    }

    /// Returns the subject identifier affected by the request.
    ///
    /// `Create` requests do not have a subject id yet, so they return the empty
    /// digest placeholder used by the rest of the workspace.
    pub fn get_subject_id(&self) -> DigestIdentifier {
        match self {
            Self::Create(_create_request) => DigestIdentifier::default(),
            Self::Fact(fact_request) => fact_request.subject_id.clone(),
            Self::Transfer(transfer_request) => {
                transfer_request.subject_id.clone()
            }
            Self::Confirm(confirm_request) => {
                confirm_request.subject_id.clone()
            }
            Self::Reject(reject_request) => reject_request.subject_id.clone(),
            Self::EOL(eolrequest) => eolrequest.subject_id.clone(),
        }
    }
}

/// Payload for a `Create` event.
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
    /// Optional subject name.
    pub name: Option<String>,
    /// Optional subject description.
    pub description: Option<String>,
    /// Governance identifier.
    pub governance_id: DigestIdentifier,
    /// Schema used to validate the initial state.
    pub schema_id: SchemaType,
    /// Subject namespace.
    pub namespace: Namespace,
}

/// Payload for a `Fact` event.
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
    /// Subject identifier.
    pub subject_id: DigestIdentifier,
    /// JSON payload to append to the subject state.
    pub payload: ValueWrapper,
}

/// Payload for a `Transfer` event.
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
    /// Subject identifier.
    pub subject_id: DigestIdentifier,
    /// Public key of the new owner.
    pub new_owner: PublicKey,
}

/// Payload for a `Confirm` event.
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
    /// Optional name for the previous owner in governance updates.
    pub name_old_owner: Option<String>,
}

/// Payload for an `EOL` event.
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
    /// Subject identifier.
    pub subject_id: DigestIdentifier,
}

/// Payload for a `Reject` event.
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
