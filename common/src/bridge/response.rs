//! Response types from Ave API

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::fmt::Display;

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct LedgerDB {
    pub subject_id: String,
    pub sn: u64,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
    pub sink_timestamp: u64,
    pub event: RequestEventDB,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct AbortDB {
    pub request_id: String,
    pub subject_id: String,
    pub sn: u64,
    pub error: String,
    pub who: String,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum RequestEventDB {
    Create,
    TrackerFact {
        payload: Value,
        evaluation_error: Option<String>,
    },
    GovernanceFact {
        payload: Value,
        evaluation_error: Option<String>,
        approval_success: Option<bool>,
    },
    Transfer {
        evaluation_error: Option<String>,
        new_owner: String,
    },
    TrackerConfirm,
    GovernanceConfirm {
        name_old_owner: Option<String>,
        evaluation_error: Option<String>,
    },
    Reject,
    EOL,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
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
pub struct PaginatorEvents {
    pub paginator: Paginator,
    pub events: Vec<LedgerDB>,
}


#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct PaginatorAborts {
    pub paginator: Paginator,
    pub events: Vec<AbortDB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Paginator {
    pub pages: u64,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RequestInfo {
    pub state: RequestState,
    pub version: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum RequestState {
    // Handler
    InQueue,
    Invalid,
    // Manager
    Abort,
    Reboot,
    RebootDiff { seconds: u64, count: u64 },
    RebootTimeOut { seconds: u64, count: u64 },
    Evaluation,
    Approval,
    Validation,
    Distribution,
    Finish,
}

impl Display for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestState::Abort => write!(f, "Abort"),
            RequestState::InQueue => write!(f, "In Queue"),
            RequestState::Invalid => write!(f, "Invalid"),
            RequestState::Finish => write!(f, "Finish"),
            RequestState::Reboot => write!(f, "Reboot"),
            RequestState::RebootDiff { seconds, count } => {
                write!(f, "Reboot diff, try: {}, seconds: {}", count, seconds)
            }
            RequestState::RebootTimeOut { seconds, count } => write!(
                f,
                "Reboot timeout, try: {}, seconds: {}",
                count, seconds
            ),
            RequestState::Evaluation => write!(f, "Evaluation"),
            RequestState::Approval => write!(f, "Approval"),
            RequestState::Validation => write!(f, "Validation"),
            RequestState::Distribution => write!(f, "Distribution"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RequestData {
    pub request_id: String,
    pub subject_id: String,
}

/// Time range filter for querying events by timestamp.
/// Both `from` and `to` are optional and should be ISO 8601 strings (e.g., "2024-01-15T14:30:00Z").
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct TimeRange {
    /// Start of the range (inclusive). ISO 8601 format.
    pub from: Option<String>,
    /// End of the range (inclusive). ISO 8601 format.
    pub to: Option<String>,
}
