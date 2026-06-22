//! Sink payloads exported from ledger events.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::SchemaType;

#[cfg(feature = "typescript")]
use ts_rs::TS;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Event data sent to external sink consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct DataToSink {
    pub payload: DataToSinkEvent,
    pub public_key: String,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
    pub sink_timestamp: u64,
}

/// Flattened ledger event stored or emitted by sink integrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum DataToSinkEvent {
    Create {
        governance_id: Option<String>,
        subject_id: String,
        owner: String,
        schema_id: SchemaType,
        namespace: String,
        sn: u64,
        gov_version: u64,
        state: Value,
    },
    FactFull {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        viewpoints: Vec<String>,
        issuer: String,
        owner: String,
        payload: Option<Value>,
        patch: Option<Value>,
        success: bool,
        error: Option<String>,
        sn: u64,
        gov_version: u64,
    },
    FactOpaque {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        viewpoints: Vec<String>,
        owner: String,
        success: bool,
        sn: u64,
        gov_version: u64,
    },
    Transfer {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        owner: String,
        new_owner: String,
        success: bool,
        error: Option<String>,
        sn: u64,
        gov_version: u64,
    },
    Confirm {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        patch: Option<Value>,
        success: bool,
        error: Option<String>,
        gov_version: u64,
        name_old_owner: Option<String>,
    },
    Reject {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        gov_version: u64,
    },
    Eol {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        gov_version: u64,
    },
}

impl DataToSinkEvent {
    /// Returns `(subject_id, schema_id)` for the event.
    pub fn get_subject_schema(&self) -> (String, String) {
        match self {
            Self::Create {
                subject_id,
                schema_id,
                ..
            }
            | Self::FactFull {
                subject_id,
                schema_id,
                ..
            }
            | Self::FactOpaque {
                subject_id,
                schema_id,
                ..
            }
            | Self::Transfer {
                subject_id,
                schema_id,
                ..
            }
            | Self::Confirm {
                subject_id,
                schema_id,
                ..
            }
            | Self::Reject {
                subject_id,
                schema_id,
                ..
            }
            | Self::Eol {
                subject_id,
                schema_id,
                ..
            } => (subject_id.clone(), schema_id.to_string()),
        }
    }
}

/// Categorisation of sink event types used for routing/filtering.
#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SinkTypes {
    Create,
    Fact,
    Transfer,
    Confirm,
    Reject,
    EOL,
    All,
}

impl std::fmt::Display for SinkTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "Create"),
            Self::Fact => write!(f, "Fact"),
            Self::Transfer => write!(f, "Transfer"),
            Self::Confirm => write!(f, "Confirm"),
            Self::Reject => write!(f, "Reject"),
            Self::EOL => write!(f, "EOL"),
            Self::All => write!(f, "All"),
        }
    }
}

impl From<&DataToSink> for SinkTypes {
    fn from(value: &DataToSink) -> Self {
        match value.payload {
            DataToSinkEvent::Create { .. } => Self::Create,
            DataToSinkEvent::FactFull { .. }
            | DataToSinkEvent::FactOpaque { .. } => Self::Fact,
            DataToSinkEvent::Transfer { .. } => Self::Transfer,
            DataToSinkEvent::Confirm { .. } => Self::Confirm,
            DataToSinkEvent::Reject { .. } => Self::Reject,
            DataToSinkEvent::Eol { .. } => Self::EOL,
        }
    }
}

impl From<String> for SinkTypes {
    fn from(value: String) -> Self {
        match value.trim() {
            "Create" => Self::Create,
            "Fact" => Self::Fact,
            "Transfer" => Self::Transfer,
            "Confirm" => Self::Confirm,
            "Reject" => Self::Reject,
            "EOL" => Self::EOL,
            _ => Self::All,
        }
    }
}

/// Lightweight event payload sent to sinks when the event type does not match
/// the sink's full-payload filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct LightEvent {
    pub subject_id: String,
    pub schema_id: String,
    pub governance_id: Option<String>,
    pub sn: u64,
    pub event_type: SinkTypes,
    pub success: bool,
}

/// Event received by an external HTTP sink.
///
/// A sink may be configured to receive full [`DataToSink`] payloads or
/// lightweight [`LightEvent`] payloads depending on its `events` filter. This
/// untagged enum allows a generic sink endpoint to accept either format without
/// knowing the filter in advance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(untagged)]
pub enum IncomingSinkEvent {
    Full(DataToSink),
    Light(LightEvent),
}

impl IncomingSinkEvent {
    /// Returns the subject identifier for the event.
    pub fn subject_id(&self) -> &str {
        match self {
            Self::Full(d) => match &d.payload {
                DataToSinkEvent::Create { subject_id, .. }
                | DataToSinkEvent::FactFull { subject_id, .. }
                | DataToSinkEvent::FactOpaque { subject_id, .. }
                | DataToSinkEvent::Transfer { subject_id, .. }
                | DataToSinkEvent::Confirm { subject_id, .. }
                | DataToSinkEvent::Reject { subject_id, .. }
                | DataToSinkEvent::Eol { subject_id, .. } => subject_id,
            },
            Self::Light(l) => &l.subject_id,
        }
    }

    /// Returns the sequence number for the event.
    pub fn sn(&self) -> u64 {
        match self {
            Self::Full(d) => match &d.payload {
                DataToSinkEvent::Create { sn, .. }
                | DataToSinkEvent::FactFull { sn, .. }
                | DataToSinkEvent::FactOpaque { sn, .. }
                | DataToSinkEvent::Transfer { sn, .. }
                | DataToSinkEvent::Confirm { sn, .. }
                | DataToSinkEvent::Reject { sn, .. }
                | DataToSinkEvent::Eol { sn, .. } => *sn,
            },
            Self::Light(l) => l.sn,
        }
    }

    /// Returns the sink event type category.
    pub fn event_type(&self) -> SinkTypes {
        match self {
            Self::Full(d) => SinkTypes::from(d),
            Self::Light(l) => l.event_type.clone(),
        }
    }
}

impl From<&DataToSink> for LightEvent {
    fn from(data: &DataToSink) -> Self {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let (governance_id, sn, event_type, success) = match &data.payload {
            DataToSinkEvent::Create {
                governance_id, sn, ..
            } => (governance_id.clone(), *sn, SinkTypes::Create, true),
            DataToSinkEvent::FactFull {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Fact, *success),
            DataToSinkEvent::FactOpaque {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Fact, *success),
            DataToSinkEvent::Transfer {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Transfer, *success),
            DataToSinkEvent::Confirm {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Confirm, *success),
            DataToSinkEvent::Reject {
                governance_id, sn, ..
            } => (governance_id.clone(), *sn, SinkTypes::Reject, true),
            DataToSinkEvent::Eol {
                governance_id, sn, ..
            } => (governance_id.clone(), *sn, SinkTypes::EOL, true),
        };

        Self {
            subject_id,
            schema_id,
            governance_id,
            sn,
            event_type,
            success,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sink_types_serde_lowercase() {
        let json = serde_json::to_string(&SinkTypes::Fact).unwrap();
        assert_eq!(json, "\"fact\"");
    }

    #[test]
    fn test_get_subject_schema_with_custom_type() {
        // Ensure get_subject_schema correctly serializes SchemaType::Type, not just reserved words.
        let event = DataToSinkEvent::FactFull {
            governance_id: None,
            subject_id: "sub_custom".to_string(),
            schema_id: SchemaType::Type("my_custom_schema".to_string()),
            viewpoints: vec![],
            issuer: "iss".to_string(),
            owner: "owner".to_string(),
            payload: None,
            patch: None,
            success: true,
            error: None,
            sn: 1,
            gov_version: 1,
        };
        assert_eq!(
            event.get_subject_schema(),
            ("sub_custom".to_string(), "my_custom_schema".to_string())
        );
    }

    #[test]
    fn test_data_to_sink_event_serde_with_custom_schema() {
        let event = DataToSinkEvent::FactFull {
            governance_id: None,
            subject_id: "sub2".to_string(),
            schema_id: SchemaType::Type("custom".to_string()),
            viewpoints: vec!["vp1".to_string()],
            issuer: "iss".to_string(),
            owner: "owner2".to_string(),
            payload: Some(json!({"k": "v"})),
            patch: None,
            success: true,
            error: None,
            sn: 1,
            gov_version: 1,
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: DataToSinkEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            DataToSinkEvent::FactFull { schema_id, .. } => {
                assert_eq!(schema_id, SchemaType::Type("custom".to_string()));
            }
            other => panic!("expected FactFull, got {:?}", other),
        }
    }

    #[test]
    fn test_data_to_sink_serde_rejects_missing_payload() {
        let json = r#"{
            "public_key": "pk",
            "event_request_timestamp": 100,
            "event_ledger_timestamp": 200,
            "sink_timestamp": 300
        }"#;
        assert!(serde_json::from_str::<DataToSink>(json).is_err());
    }
}

/// Per-sink authentication configuration.
/// When present, the sink requires authentication for delivery and health-check.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SinkAuthConfig {
    /// OAuth2 / token endpoint URL.
    pub auth_url: String,
    /// Username for the token endpoint.
    pub username: String,
    /// API key for Api-Key header authentication (alternative to OAuth2).
    #[serde(default)]
    pub api_key: String,
}

/// Target of a sink configuration entry.
///
/// Every sink targets a schema. The special schema `"governance"` means the
/// sink receives governance-level events and is handled by the node-level
/// `NodeSinkManager`; in that case `governance_id` must be `None`. For any
/// other schema `governance_id` is mandatory and identifies the governance
/// whose trackers will feed the sink.
#[derive(
    Debug, Clone, Deserialize, Serialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTarget {
    Schema {
        schema_id: String,
        /// Governance to which this sink applies. Must be `None` when
        /// `schema_id` is `"governance"`; mandatory otherwise.
        #[serde(default)]
        governance_id: Option<String>,
    },
}

/// Configuration for a single sink server endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(default)]
pub struct SinkServer {
    pub server: String,
    pub events: BTreeSet<SinkTypes>,
    pub url: String,
    /// Per-sink authentication. When `Some`, the worker will load the
    /// password from the environment variable `AVE_SINK_PASSWORD_{{SERVER}}`
    /// (where `{{SERVER}}` is the sink name upper-cased with non-alphanumeric
    /// characters replaced by `_`).
    pub auth: Option<SinkAuthConfig>,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub max_retries: usize,
    pub batch_size: usize,
    pub sink_worker_idle_timeout_ms: u64,
    pub healthcheck_intervals_secs: Vec<u64>,
    pub max_catch_up_concurrency: usize,
    pub retry_base_delay_ms: u64,
    /// Optional dedicated health-check URL.
    pub health_check_url: Option<String>,
    pub sink_subject_worker_idle_timeout_ms: u64,
    pub token_refresh_margin_secs: u64,
    /// Maximum number of recoveries after failure before a sink is considered
    /// "flapping".
    pub max_recoveries_after_failure: u32,
    /// Delay in seconds before the first healthcheck is scheduled after startup.
    pub startup_healthcheck_delay_secs: u64,
}

impl Default for SinkServer {
    fn default() -> Self {
        Self {
            server: String::new(),
            events: BTreeSet::new(),
            url: String::new(),
            auth: None,
            connect_timeout_ms: 2_000,
            request_timeout_ms: 5_000,
            max_retries: 2,
            batch_size: 100,
            sink_worker_idle_timeout_ms: 10_000,
            healthcheck_intervals_secs: vec![30, 60, 120, 300, 600],
            max_catch_up_concurrency: 2,
            retry_base_delay_ms: 500,
            health_check_url: None,
            sink_subject_worker_idle_timeout_ms: 2_000,
            token_refresh_margin_secs: 30,
            max_recoveries_after_failure: 5,
            startup_healthcheck_delay_secs: 1,
        }
    }
}

/// A single sink configuration entry: a target plus the list of servers that
/// serve events for that target.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SinkConfigEntry {
    pub target: SinkTarget,
    pub servers: Vec<SinkServer>,
}

pub const fn default_sink_worker_idle_timeout_ms() -> u64 {
    10_000
}

pub fn default_sink_healthcheck_intervals_secs() -> Vec<u64> {
    vec![30, 60, 120, 300, 600]
}
