//! Governance update payloads.
//!
//! These types model member, role, schema and policy changes applied to a
//! governance subject. They are plain serializable data structures and are
//! shared by the API layer, the core ledger and TypeScript exports.

use std::{
    collections::{BTreeSet, HashSet},
    hash::Hash,
};

use serde::{Deserialize, Serialize, Serializer};
use serde_json::Value;

#[cfg(feature = "typescript")]
use ts_rs::TS;

use crate::identity::PublicKey;
use crate::{Namespace, SchemaType};

fn default_witnesses_creator() -> BTreeSet<String> {
    BTreeSet::from(["Witnesses".to_owned()])
}

pub type MemberName = String;

/// Governance change set grouped by concern.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovernanceEvent {
    pub members: Option<MemberEvent>,
    pub roles: Option<RolesEvent>,
    pub schemas: Option<SchemasEvent>,
    pub policies: Option<PoliciesEvent>,
}

///// Members /////
/// Member additions and removals.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct MemberEvent {
    pub add: Option<HashSet<NewMember>>,
    pub remove: Option<HashSet<MemberName>>,
}

/// New member entry used in governance updates.
#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct NewMember {
    pub name: MemberName,
    #[cfg_attr(feature = "typescript", ts(type = "string"))]
    pub key: PublicKey,
}

///// Roles /////
/// Role updates grouped by role family.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RolesEvent {
    pub governance: Option<GovRoleEvent>,
    pub tracker_schemas: Option<TrackerSchemasRoleEvent>,
    pub schema: Option<HashSet<SchemaIdRole>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovRoleEvent {
    pub add: Option<GovRolesEvent>,
    pub remove: Option<GovRolesEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaIdRole {
    pub schema_id: SchemaType,
    pub add: Option<SchemaRolesAddEvent>,
    pub remove: Option<SchemaRolesRemoveEvent>,
    pub change: Option<SchemaRolesChangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerSchemasRoleEvent {
    pub add: Option<TrackerSchemasRolesAddEvent>,
    pub remove: Option<TrackerSchemasRolesRemoveEvent>,
    pub change: Option<TrackerSchemasRolesChangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovRolesEvent {
    pub approver: Option<BTreeSet<MemberName>>,
    pub evaluator: Option<BTreeSet<MemberName>>,
    pub validator: Option<BTreeSet<MemberName>>,
    pub witness: Option<BTreeSet<MemberName>>,
    pub issuer: Option<BTreeSet<MemberName>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerSchemasRolesAddEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub issuer: Option<BTreeSet<Role>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaRolesAddEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub creator: Option<BTreeSet<RoleCreator>>,
    pub issuer: Option<BTreeSet<Role>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerSchemasRolesRemoveEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub issuer: Option<BTreeSet<Role>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaRolesRemoveEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub creator: Option<BTreeSet<Role>>,
    pub issuer: Option<BTreeSet<Role>>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerSchemasRolesChangeEvent {
    pub evaluator: Option<BTreeSet<RoleChange>>,
    pub validator: Option<BTreeSet<RoleChange>>,
    pub witness: Option<BTreeSet<RoleChange>>,
    pub issuer: Option<BTreeSet<RoleChange>>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaRolesChangeEvent {
    pub evaluator: Option<BTreeSet<RoleChange>>,
    pub validator: Option<BTreeSet<RoleChange>>,
    pub witness: Option<BTreeSet<RoleChange>>,
    pub creator: Option<BTreeSet<RoleCreatorChange>>,
    pub issuer: Option<BTreeSet<RoleChange>>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RoleCreatorChange {
    pub actual_name: MemberName,
    pub actual_namespace: Namespace,
    pub new_namespace: Option<Namespace>,
    pub new_witnesses: Option<BTreeSet<String>>,
    pub new_quantity: Option<CreatorQuantity>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RoleChange {
    pub actual_name: MemberName,
    pub actual_namespace: Namespace,
    pub new_namespace: Namespace,
}

///// Schemas /////
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemasEvent {
    pub add: Option<HashSet<SchemaAdd>>,
    pub remove: Option<HashSet<SchemaType>>,
    pub change: Option<HashSet<SchemaChange>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaAdd {
    pub id: SchemaType,
    pub contract: String,
    pub initial_value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaChange {
    pub actual_id: SchemaType,
    pub new_contract: Option<String>,
    pub new_initial_value: Option<Value>,
}

///// Policies /////
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct PoliciesEvent {
    pub governance: Option<GovPolicieEvent>,
    pub schema: Option<HashSet<SchemaIdPolicie>>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaIdPolicie {
    pub schema_id: SchemaType,
    pub change: SchemaPolicieChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovPolicieEvent {
    pub change: GovPolicieChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovPolicieChange {
    pub approve: Option<Quorum>,
    pub evaluate: Option<Quorum>,
    pub validate: Option<Quorum>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaPolicieChange {
    pub evaluate: Option<Quorum>,
    pub validate: Option<Quorum>,
}

/// Governance-wide quorum policy.
/// Governance quorum.
#[derive(
    Debug, Clone, Default, Serialize, Deserialize, PartialEq, Hash, Eq,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(rename_all = "lowercase")]
pub enum Quorum {
    #[default]
    Majority,
    Fixed(u32),
    Percentage(u8),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export, type = "number | \"infinity\""))]
pub enum CreatorQuantity {
    Quantity(u32),
    Infinity,
}

impl<'de> Deserialize<'de> for CreatorQuantity {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        match value {
            serde_json::Value::String(s) if s == "infinity" => {
                Ok(Self::Infinity)
            }
            serde_json::Value::Number(n) if n.is_u64() => {
                Ok(Self::Quantity(n.as_u64().ok_or_else(|| {
                    serde::de::Error::custom(
                        "Quantity must be a number or 'infinity'",
                    )
                })? as u32))
            }
            _ => Err(serde::de::Error::custom(
                "Quantity must be a number or 'infinity'",
            )),
        }
    }
}

impl Serialize for CreatorQuantity {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Quantity(n) => serializer.serialize_u32(*n),
            Self::Infinity => serializer.serialize_str("infinity"),
        }
    }
}

#[derive(
    Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, PartialOrd, Ord,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct Role {
    pub name: String,
    pub namespace: Namespace,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RoleCreator {
    pub name: String,
    pub namespace: Namespace,
    #[serde(default = "default_witnesses_creator")]
    pub witnesses: BTreeSet<String>,
    pub quantity: CreatorQuantity,
}

impl Hash for RoleCreator {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.name.hash(state);
        self.namespace.hash(state);
    }
}

impl PartialOrd for RoleCreator {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RoleCreator {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.name.clone(), self.namespace.clone())
            .cmp(&(other.name.clone(), other.namespace.clone()))
    }
}

impl PartialEq for RoleCreator {
    fn eq(&self, other: &Self) -> bool {
        self.name == other.name && self.namespace == other.namespace
    }
}

impl Eq for RoleCreator {}
