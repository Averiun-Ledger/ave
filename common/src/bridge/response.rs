//! Response payloads returned by the Ave API.

use crate::{
    DataToSink, SchemaType,
    bridge::request::{ApprovalState, EventRequestType},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashMap, fmt::Display};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Approval entry with request data and current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct ApprovalEntry {
    /// The approval request details
    pub request: ApprovalReq,
    /// Current state of the approval
    pub state: ApprovalState,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd,
)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SubjsData {
    pub subject_id: String,
    pub schema_id: SchemaType,
    pub active: bool,
    pub namespace: String,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovsData {
    pub governance_id: String,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TransferSubject {
    pub name: Option<String>,
    pub subject_id: String,
    pub new_owner: String,
    pub actual_owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct ApprovalReq {
    /// The signed event request.
    pub subject_id: String,
    /// The sequence number of the event.
    pub sn: u64,
    /// The version of the governance contract.
    pub gov_version: u64,
    /// The patch to apply to the state.
    pub patch: Value,

    pub signer: String,
}

/// Network status exposed by monitoring endpoints.
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum MonitorNetworkState {
    /// Connecting to others network nodes
    #[default]
    Connecting,
    /// Connected to others netowrk nodes
    Running,
    /// Can not connect to others network nodes
    Down,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct LedgerDB {
    pub subject_id: String,
    pub sn: u64,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
    pub sink_timestamp: u64,
    pub event: RequestEventDB,
    pub event_type: EventRequestType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestsInManager {
    pub handling: HashMap<String, String>,
    pub in_queue: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestsInManagerSubject {
    pub handling: Option<String>,
    pub in_queue: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct AbortDB {
    pub request_id: String,
    pub subject_id: String,
    pub sn: Option<u64>,
    pub error: String,
    pub who: String,
    pub abort_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum RequestEventDB {
    Create {
        name: Option<String>,
        description: Option<String>,
        schema_id: String,
        namespace: String,
    },
    TrackerFact {
        payload: Value,
        evaluation_response: EvalResDB,
    },
    GovernanceFact {
        payload: Value,
        evaluation_response: EvalResDB,
        approval_success: Option<bool>,
    },
    Transfer {
        evaluation_error: Option<String>,
        new_owner: String,
    },
    TrackerConfirm,
    GovernanceConfirm {
        name_old_owner: Option<String>,
        evaluation_response: EvalResDB,
    },
    Reject,
    EOL,
}

impl RequestEventDB {
    pub const fn get_event_type(&self) -> EventRequestType {
        match self {
            Self::Create { .. } => EventRequestType::Create,
            Self::TrackerFact { .. } | Self::GovernanceFact { .. } => {
                EventRequestType::Fact
            }
            Self::Transfer { .. } => EventRequestType::Transfer,
            Self::TrackerConfirm | Self::GovernanceConfirm { .. } => {
                EventRequestType::Confirm
            }
            Self::Reject => EventRequestType::Reject,
            Self::EOL => EventRequestType::Eol,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum EvalResDB {
    Patch(Value),
    Error(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SubjectDB {
    pub name: Option<String>,
    pub description: Option<String>,
    pub subject_id: String,
    pub governance_id: String,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: Option<String>,
    pub schema_id: String,
    pub namespace: String,
    pub sn: u64,
    pub creator: String,
    pub owner: String,
    pub new_owner: Option<String>,
    pub active: bool,
    pub properties: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct PaginatorEvents {
    pub paginator: Paginator,
    pub events: Vec<LedgerDB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkEventsPage {
    pub from_sn: u64,
    pub to_sn: Option<u64>,
    pub limit: u64,
    pub next_sn: Option<u64>,
    pub has_more: bool,
    pub events: Vec<DataToSink>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct PaginatorAborts {
    pub paginator: Paginator,
    pub events: Vec<AbortDB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct Paginator {
    pub pages: u64,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestInfo {
    pub state: RequestState,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestInfoExtend {
    pub request_id: String,
    pub state: RequestState,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum RequestState {
    // Handler
    InQueue,
    Handling,
    Invalid {
        subject_id: String,
        who: String,
        sn: Option<u64>,
        error: String,
    },
    // Manager
    Abort {
        subject_id: String,
        who: String,
        sn: Option<u64>,
        error: String,
    },
    Reboot,
    RebootDiff {
        seconds: u64,
        count: u64,
    },
    RebootTimeOut {
        seconds: u64,
        count: u64,
    },
    Evaluation,
    Approval,
    Validation,
    Distribution,
    Finish,
}

impl Display for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handling => write!(f, "Handling"),
            Self::Abort {
                subject_id,
                who,
                sn,
                error,
            } => {
                let sn_text = sn
                    .as_ref()
                    .map_or_else(|| "None".to_string(), |sn| format!("{sn}"));

                write!(
                    f,
                    "Abort, subject_id: {}, who: {}, sn: {}, error: {}",
                    subject_id, who, sn_text, error
                )
            }
            Self::InQueue => write!(f, "In Queue"),
            Self::Invalid {
                subject_id,
                who,
                sn,
                error,
            } => {
                let sn_text = sn
                    .as_ref()
                    .map_or_else(|| "None".to_string(), |sn| format!("{sn}"));

                write!(
                    f,
                    "Abort, subject_id: {}, who: {}, sn: {}, error: {}",
                    subject_id, who, sn_text, error
                )
            }
            Self::Finish => write!(f, "Finish"),
            Self::Reboot => write!(f, "Reboot"),
            Self::RebootDiff { seconds, count } => {
                write!(f, "Reboot diff, try: {}, seconds: {}", count, seconds)
            }
            Self::RebootTimeOut { seconds, count } => write!(
                f,
                "Reboot timeout, try: {}, seconds: {}",
                count, seconds
            ),
            Self::Evaluation => write!(f, "Evaluation"),
            Self::Approval => write!(f, "Approval"),
            Self::Validation => write!(f, "Validation"),
            Self::Distribution => write!(f, "Distribution"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestData {
    pub request_id: String,
    pub subject_id: String,
}

/// Time range filter for querying events by timestamp.
/// Both `from` and `to` are optional and should be ISO 8601 strings (e.g., "2024-01-15T14:30:00Z").
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TimeRange {
    /// Start of the range (inclusive). ISO 8601 format.
    pub from: Option<String>,
    /// End of the range (inclusive). ISO 8601 format.
    pub to: Option<String>,
}
