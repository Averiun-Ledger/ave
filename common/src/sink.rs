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
    pub event: DataToSinkEvent,
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
    Fact {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        issuer: String,
        owner: String,
        payload: Value,
        patch: Value,
        sn: u64,
        gov_version: u64,
    },
    Transfer {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        owner: String,
        new_owner: String,
        sn: u64,
        gov_version: u64,
    },
    Confirm {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        patch: Option<Value>,
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
    Abort {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
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
            | Self::Fact {
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
            }
            | Self::Abort {
                subject_id,
                schema_id,
                ..
            } => (subject_id.clone(), schema_id.to_string()),
        }
    }
}
