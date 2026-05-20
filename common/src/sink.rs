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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn make_event(variant: &str) -> DataToSinkEvent {
        match variant {
            "create" => DataToSinkEvent::Create {
                governance_id: None,
                subject_id: "sub1".to_string(),
                owner: "owner1".to_string(),
                schema_id: SchemaType::Governance,
                namespace: "ns".to_string(),
                sn: 0,
                gov_version: 1,
                state: json!({}),
            },
            "fact_full" => DataToSinkEvent::FactFull {
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
            },
            "fact_opaque" => DataToSinkEvent::FactOpaque {
                governance_id: None,
                subject_id: "sub3".to_string(),
                schema_id: SchemaType::TrackerSchemas,
                viewpoints: vec![],
                owner: "owner3".to_string(),
                success: true,
                sn: 2,
                gov_version: 1,
            },
            "transfer" => DataToSinkEvent::Transfer {
                governance_id: None,
                subject_id: "sub4".to_string(),
                schema_id: SchemaType::Governance,
                owner: "old".to_string(),
                new_owner: "new".to_string(),
                success: true,
                error: None,
                sn: 3,
                gov_version: 1,
            },
            "confirm" => DataToSinkEvent::Confirm {
                governance_id: None,
                subject_id: "sub5".to_string(),
                schema_id: SchemaType::Governance,
                sn: 4,
                patch: None,
                success: true,
                error: None,
                gov_version: 1,
                name_old_owner: None,
            },
            "reject" => DataToSinkEvent::Reject {
                governance_id: None,
                subject_id: "sub6".to_string(),
                schema_id: SchemaType::Governance,
                sn: 5,
                gov_version: 1,
            },
            "eol" => DataToSinkEvent::Eol {
                governance_id: None,
                subject_id: "sub7".to_string(),
                schema_id: SchemaType::Governance,
                sn: 6,
                gov_version: 1,
            },
            _ => panic!("unknown variant"),
        }
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
