//! Request types for Ave API
//!
//! These types are used for communication with the Ave HTTP API

use std::fmt::Display;

use crate::{
    request::EventRequest, response::TimeRange, signature::BridgeSignature,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};
#[cfg(feature = "typescript")]
use ts_rs::TS;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SubjectQuery {
    pub active: Option<bool>,
    pub schema_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovQuery {
    pub active: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct ApprovalQuery {
    pub state: Option<ApprovalState>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct EventsQuery {
    pub quantity: Option<u64>,
    pub page: Option<u64>,
    pub reverse: Option<bool>,
    #[cfg_attr(feature = "openapi", param(style = DeepObject, explode))]
    pub event_request_ts: Option<TimeRange>,
    #[cfg_attr(feature = "openapi", param(style = DeepObject, explode))]
    pub event_ledger_ts: Option<TimeRange>,
    #[cfg_attr(feature = "openapi", param(style = DeepObject, explode))]
    pub sink_ts: Option<TimeRange>,
    pub event_type: Option<EventRequestType>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct AbortsQuery {
    pub request_id: Option<String>,
    pub sn: Option<u64>,
    pub quantity: Option<u64>,
    pub page: Option<u64>,
    pub reverse: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct FirstEndEvents {
    pub quantity: Option<u64>,
    pub reverse: Option<bool>,
    pub event_type: Option<EventRequestType>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum EventRequestType {
    Create,
    Fact,
    Transfer,
    Confirm,
    Reject,
    Eol,
}

impl From<&EventRequest> for EventRequestType {
    fn from(value: &EventRequest) -> Self {
        match value {
            EventRequest::Create(..) => Self::Create,
            EventRequest::Fact(..) => Self::Fact,
            EventRequest::Transfer(..) => Self::Transfer,
            EventRequest::Confirm(..) => Self::Confirm,
            EventRequest::EOL(..) => Self::Eol,
            EventRequest::Reject(..) => Self::Reject,
        }
    }
}

impl Display for EventRequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventRequestType::Create => write!(f, "create"),
            EventRequestType::Fact => write!(f, "fact"),
            EventRequestType::Transfer => write!(f, "transfer"),
            EventRequestType::Confirm => write!(f, "confirm"),
            EventRequestType::Reject => write!(f, "reject"),
            EventRequestType::Eol => write!(f, "eol"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum ApprovalStateRes {
    /// Request for approval which is in responded status and accepted
    Accepted,
    /// Request for approval which is in responded status and rejected
    Rejected,
    /// The approval entity is obsolete.
    Obsolete,
}

impl Display for ApprovalStateRes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            ApprovalStateRes::Accepted => "accepted".to_owned(),
            ApprovalStateRes::Rejected => "rejected".to_owned(),
            ApprovalStateRes::Obsolete => "obsolete".to_owned(),
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
#[serde(rename_all = "snake_case")]
pub enum ApprovalState {
    /// The approval entity is pending a response.
    #[default]
    Pending,
    /// Request for approval which is in responded status and accepted
    Accepted,
    /// Request for approval which is in responded status and rejected
    Rejected,
    /// The approval entity is obsolete.
    Obsolete,
}

impl Display for ApprovalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            ApprovalState::Accepted => "accepted".to_owned(),
            ApprovalState::Rejected => "rejected".to_owned(),
            ApprovalState::Obsolete => "obsolete".to_owned(),
            ApprovalState::Pending => "pending".to_owned(),
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
    Eol(BridgeEOLRequest),
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
