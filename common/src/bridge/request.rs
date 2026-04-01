//! Request and query types exposed by the Ave API.

use std::fmt::Display;

use crate::{
    request::EventRequest, response::TimeRange, signature::BridgeSignature,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "typescript")]
use ts_rs::TS;
#[cfg(feature = "openapi")]
use utoipa::{IntoParams, ToSchema};

/// Filters subjects by activity and schema.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SubjectQuery {
    pub active: Option<bool>,
    pub schema_id: Option<String>,
}

/// Filters governances by activity.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovQuery {
    pub active: Option<bool>,
}

/// Filters approvals by state.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct ApprovalQuery {
    pub state: Option<ApprovalState>,
}

/// Pagination and time filters for event queries.
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

/// Range query for replaying sink-formatted events.
#[derive(Debug, Clone, Deserialize, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema, IntoParams))]
#[cfg_attr(feature = "openapi", into_params(parameter_in = Query))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkEventsQuery {
    pub from_sn: Option<u64>,
    pub to_sn: Option<u64>,
    pub limit: Option<u64>,
}

/// Pagination filters for abort queries.
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

/// Query for retrieving the first or last events of a subject.
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

/// Event request type used by API filters and responses.
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

impl EventRequestType {
    pub fn is_create_event(&self) -> bool {
        if let EventRequestType::Create = self {
            true
        } else {
            false
        }
    }
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
            Self::Create => write!(f, "create"),
            Self::Fact => write!(f, "fact"),
            Self::Transfer => write!(f, "transfer"),
            Self::Confirm => write!(f, "confirm"),
            Self::Reject => write!(f, "reject"),
            Self::Eol => write!(f, "eol"),
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
            Self::Accepted => "accepted".to_owned(),
            Self::Rejected => "rejected".to_owned(),
            Self::Obsolete => "obsolete".to_owned(),
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
            Self::Accepted => "accepted".to_owned(),
            Self::Rejected => "rejected".to_owned(),
            Self::Obsolete => "obsolete".to_owned(),
            Self::Pending => "pending".to_owned(),
        };
        write!(f, "{}", string,)
    }
}

/// API event request plus optional signature metadata.
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

/// Event request payload received or returned by the API.
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
    /// Viewpoints targeted by this fact.
    pub viewpoints: Vec<String>,
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
