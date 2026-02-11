//! Request types for Ave API
//!
//! These types are used for communication with the Ave HTTP API


use std::fmt::Display;

use crate::signature::BridgeSignature;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum ApprovalStateRes {
    /// Request for approval which is in responded status and accepted
    RespondedAccepted,
    /// Request for approval which is in responded status and rejected
    RespondedRejected,
    /// The approval entity is obsolete.
    Obsolete,
}

impl Display for ApprovalStateRes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            ApprovalStateRes::RespondedAccepted => {
                "RespondedAccepted".to_owned()
            }
            ApprovalStateRes::RespondedRejected => {
                "RespondedRejected".to_owned()
            }
            ApprovalStateRes::Obsolete => "Obsolete".to_owned(),
        };
        write!(f, "{}", string,)
    }
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BorshDeserialize,
    BorshSerialize,
)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum ApprovalState {
    /// The approval entity is pending a response.
    #[default]
    Pending,
    /// Request for approval which is in responded status and accepted
    RespondedAccepted,
    /// Request for approval which is in responded status and rejected
    RespondedRejected,
    /// The approval entity is obsolete.
    Obsolete,
}

impl Display for ApprovalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            ApprovalState::RespondedAccepted => "RespondedAccepted".to_owned(),
            ApprovalState::RespondedRejected => "RespondedRejected".to_owned(),
            ApprovalState::Obsolete => "Obsolete".to_owned(),
            ApprovalState::Pending => "Pending".to_owned(),
        };
        write!(f, "{}", string,)
    }
}

/// Signed event request
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeSignedEventRequest {
    /// Event request
    pub request: BridgeEventRequest,
    /// Signature
    pub signature: Option<BridgeSignature>,
}

/// Event request
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum BridgeEventRequest {
    Create(BridgeCreateRequest),
    Fact(BridgeFactRequest),
    Transfer(BridgeTransferRequest),
    EOL(BridgeEOLRequest),
    Confirm(BridgeConfirmRequest),
    Reject(BridgeRejectRequest),
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeRejectRequest {
    /// Subject identifier
    pub subject_id: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeCreateRequest {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The identifier of the governance contract
    pub governance_id: Option<String>,
    /// The identifier of the schema used to validate the event
    pub schema_id: String,
    /// The namespace of the subject
    pub namespace: Option<String>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeFactRequest {
    /// Subject identifier
    pub subject_id: String,
    /// Changes to be applied to the subject
    pub payload: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeTransferRequest {
    /// Subject identifier
    pub subject_id: String,
    /// Public key of the new owner
    pub new_owner: String,
}

/// EOL request
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeEOLRequest {
    /// Subject identifier
    pub subject_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeConfirmRequest {
    /// Subject identifier
    pub subject_id: String,
    pub name_old_owner: Option<String>,
}
