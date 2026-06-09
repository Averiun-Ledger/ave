//! Sink payloads exported from ledger events.

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

impl From<&DataToSink> for LightEvent {
    fn from(data: &DataToSink) -> Self {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let (governance_id, sn, event_type, success) = match &data.payload {
            DataToSinkEvent::Create { governance_id, sn, .. } => {
                (governance_id.clone(), *sn, SinkTypes::Create, true)
            }
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
            DataToSinkEvent::Reject { governance_id, sn, .. } => {
                (governance_id.clone(), *sn, SinkTypes::Reject, true)
            }
            DataToSinkEvent::Eol { governance_id, sn, .. } => {
                (governance_id.clone(), *sn, SinkTypes::EOL, true)
            }
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
        assert_eq!(event.get_subject_schema(), ("sub_custom".to_string(), "my_custom_schema".to_string()));
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
