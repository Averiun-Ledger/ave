//! Schema identifiers used by Ave subjects and governance rules.

use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Schema identifier.
///
/// Reserved values are represented as dedicated variants and custom schema ids
/// are stored in [`SchemaType::Type`].
#[derive(
    Default,
    Debug,
    Clone,
    Hash,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    BorshSerialize,
    BorshDeserialize,
)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
/// Reserved words used by the schema system.
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export, type = "string"))]
pub enum SchemaType {
    #[default]
    Governance,
    Type(String),
    TrackerSchemas,
}

#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum ReservedWords {
    TrackerSchemas,
    Governance,
    Any,
    Witnesses,
    Owner,
}

impl Display for ReservedWords {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrackerSchemas => write!(f, "tracker_schemas"),
            Self::Governance => write!(f, "governance"),
            Self::Any => write!(f, "Any"),
            Self::Witnesses => write!(f, "Witnesses"),
            Self::Owner => write!(f, "Owner"),
        }
    }
}

impl std::str::FromStr for SchemaType {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Special case: empty string deserializes to default (empty) digest
        if s.is_empty() {
            return Err("Schema_id can not be empty".to_string());
        }

        match s {
            "governance" => Ok(Self::Governance),
            "tracker_schemas" => Ok(Self::TrackerSchemas),
            _ => Ok(Self::Type(s.to_string())),
        }
    }
}

impl SchemaType {
    /// Returns the serialized string length of the schema identifier.
    pub const fn len(&self) -> usize {
        match self {
            Self::Governance => "governance".len(),
            Self::Type(schema_id) => schema_id.len(),
            Self::TrackerSchemas => "tracker_schemas".len(),
        }
    }

    /// Returns `true` when the custom schema identifier is empty.
    pub const fn is_empty(&self) -> bool {
        match self {
            Self::Governance => false,
            Self::Type(schschema_id) => schschema_id.is_empty(),
            Self::TrackerSchemas => false,
        }
    }

    /// Returns `true` when the schema identifier is valid in stored state.
    pub fn is_valid(&self) -> bool {
        match self {
            Self::Governance => true,
            Self::TrackerSchemas => true,
            Self::Type(schema_id) => {
                !schema_id.is_empty()
                    && schema_id != &ReservedWords::Governance.to_string()
                    && schema_id != &ReservedWords::TrackerSchemas.to_string()
                    && schema_id.trim().len() == schema_id.len()
            }
        }
    }

    /// Returns `true` when the schema identifier is valid in incoming requests.
    pub fn is_valid_in_request(&self) -> bool {
        match self {
            Self::Governance => true,
            Self::TrackerSchemas => false,
            Self::Type(schema_id) => {
                !schema_id.is_empty()
                    && schema_id != &ReservedWords::Governance.to_string()
                    && schema_id != &ReservedWords::TrackerSchemas.to_string()
                    && schema_id.trim().len() == schema_id.len()
            }
        }
    }
}

impl Display for SchemaType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::TrackerSchemas => write!(f, "tracker_schemas"),
            Self::Governance => write!(f, "governance"),
            Self::Type(schema_id) => write!(f, "{}", schema_id),
        }
    }
}

impl SchemaType {
    /// Returns `true` when the schema is the governance schema.
    pub const fn is_gov(&self) -> bool {
        matches!(self, Self::Governance)
    }
}

impl<'de> Deserialize<'de> for SchemaType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = <String as serde::Deserialize>::deserialize(deserializer)?;
        if s.is_empty() {
            return Err(serde::de::Error::custom(
                "Schema can not be empty".to_string(),
            ));
        }

        Ok(match s.as_str() {
            "governance" => Self::Governance,
            "tracker_schemas" => Self::TrackerSchemas,
            _ => Self::Type(s),
        })
    }
}

impl Serialize for SchemaType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::TrackerSchemas => serializer.serialize_str("tracker_schemas"),
            Self::Governance => serializer.serialize_str("governance"),
            Self::Type(schema) => serializer.serialize_str(schema),
        }
    }
}
