use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

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
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
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
            ReservedWords::TrackerSchemas => write!(f, "tracker_schemas"),
            ReservedWords::Governance => write!(f, "governance"),
            ReservedWords::Any => write!(f, "Any"),
            ReservedWords::Witnesses => write!(f, "Witnesses"),
            ReservedWords::Owner => write!(f, "Owner"),
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
            "governance" => Ok(SchemaType::Governance),
            "tracker_schemas" => Ok(SchemaType::TrackerSchemas),
            _ => Ok(SchemaType::Type(s.to_string())),
        }
    }
}

impl SchemaType {
    pub fn len(&self) -> usize {
        match self {
            SchemaType::Governance => "governance".len(),
            SchemaType::Type(schema_id) => schema_id.len(),
            SchemaType::TrackerSchemas => "tracker_schemas".len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            SchemaType::Governance => false,
            SchemaType::Type(schschema_id) => schschema_id.is_empty(),
            SchemaType::TrackerSchemas => false,
        }
    }

    pub fn is_valid(&self) -> bool {
        match self {
            SchemaType::Governance => true,
            SchemaType::TrackerSchemas => true,
            SchemaType::Type(schema_id) => {
                !schema_id.is_empty()
                    && schema_id != &ReservedWords::Governance.to_string()
                    && schema_id != &ReservedWords::TrackerSchemas.to_string()
                    && schema_id.trim().len() == schema_id.len()
            }
        }
    }

    pub fn is_valid_in_request(&self) -> bool {
        match self {
            SchemaType::Governance => true,
            SchemaType::TrackerSchemas => false,
            SchemaType::Type(schema_id) => {
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
            SchemaType::TrackerSchemas => write!(f, "tracker_schemas"),
            SchemaType::Governance => write!(f, "governance"),
            SchemaType::Type(schema_id) => write!(f, "{}", schema_id),
        }
    }
}

impl SchemaType {
    pub fn is_gov(&self) -> bool {
        matches!(self, SchemaType::Governance)
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
            "governance" => SchemaType::Governance,
            "tracker_schemas" => SchemaType::TrackerSchemas,
            _ => SchemaType::Type(s),
        })
    }
}

impl Serialize for SchemaType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            SchemaType::TrackerSchemas => serializer.serialize_str("tracker_schemas"),
            SchemaType::Governance => serializer.serialize_str("governance"),
            SchemaType::Type(schema) => serializer.serialize_str(schema),
        }
    }
}
