//! Governance update payloads.
//!
//! These types model member, role, schema and policy changes applied to a
//! governance subject. They are plain serializable data structures and are
//! shared by the API layer, the core ledger and TypeScript exports.

use std::{
    collections::{BTreeSet, HashSet},
    fmt,
    hash::Hash,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

#[cfg(feature = "typescript")]
use ts_rs::TS;

use crate::identity::PublicKey;
use crate::{Namespace, SchemaType};

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
    pub new_witnesses: Option<BTreeSet<CreatorWitness>>,
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
    #[serde(default)]
    pub viewpoints: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SchemaChange {
    pub actual_id: SchemaType,
    pub new_contract: Option<String>,
    pub new_initial_value: Option<Value>,
    #[serde(default)]
    pub new_viewpoints: Option<Vec<String>>,
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
    Debug,
    Clone,
    Default,
    Serialize,
    Deserialize,
    PartialEq,
    Hash,
    Eq,
    BorshDeserialize,
    BorshSerialize,
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

#[derive(
    Debug,
    Clone,
    Eq,
    PartialEq,
    Hash,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
)]
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

impl CreatorQuantity {
    pub const fn check(&self) -> bool {
        match self {
            Self::Quantity(quantity) => *quantity != 0,
            Self::Infinity => true,
        }
    }
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Hash,
    Eq,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct Role {
    pub name: String,
    pub namespace: Namespace,
}

#[derive(
    Debug,
    Serialize,
    Clone,
    PartialEq,
    Hash,
    Eq,
    PartialOrd,
    Ord,
    BorshDeserialize,
    BorshSerialize,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct CreatorWitness {
    pub name: String,
    #[cfg_attr(feature = "typescript", ts(type = "string[] | undefined"))]
    pub viewpoints: BTreeSet<String>,
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct UniqueViewpoints(BTreeSet<String>);

impl From<UniqueViewpoints> for BTreeSet<String> {
    fn from(value: UniqueViewpoints) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for UniqueViewpoints {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let viewpoints =
            <Vec<String> as serde::Deserialize>::deserialize(deserializer)?;
        let mut unique = BTreeSet::new();

        for viewpoint in viewpoints {
            if !unique.insert(viewpoint.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicated viewpoint '{viewpoint}'"
                )));
            }
        }

        Ok(Self(unique))
    }
}

#[derive(Deserialize)]
struct CreatorWitnessDef {
    name: String,
    #[serde(default)]
    viewpoints: UniqueViewpoints,
}

impl<'de> Deserialize<'de> for CreatorWitness {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let CreatorWitnessDef { name, viewpoints } =
            CreatorWitnessDef::deserialize(deserializer)?;

        Ok(Self {
            name,
            viewpoints: viewpoints.into(),
        })
    }
}

fn default_creator_witnesses() -> BTreeSet<CreatorWitness> {
    BTreeSet::from([CreatorWitness {
        name: "Witnesses".to_owned(),
        viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
    }])
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CreatorWitnessInput {
    Name(String),
    Detailed(CreatorWitness),
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CreatorWitnesses(BTreeSet<CreatorWitness>);

impl From<CreatorWitnesses> for BTreeSet<CreatorWitness> {
    fn from(value: CreatorWitnesses) -> Self {
        value.0
    }
}

impl<'de> Deserialize<'de> for CreatorWitnesses {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values =
            <Vec<CreatorWitnessInput> as serde::Deserialize>::deserialize(
                deserializer,
            )?;
        let mut by_name = HashSet::new();
        let mut out = BTreeSet::new();

        for value in values {
            let witness = match value {
                CreatorWitnessInput::Name(name) => CreatorWitness {
                    name,
                    viewpoints: BTreeSet::new(),
                },
                CreatorWitnessInput::Detailed(witness) => witness,
            };

            if !by_name.insert(witness.name.clone()) {
                return Err(serde::de::Error::custom(format!(
                    "duplicated creator witness '{}'",
                    witness.name
                )));
            }

            out.insert(witness);
        }

        Ok(Self(out))
    }
}

#[derive(Debug, Serialize, Clone, BorshDeserialize, BorshSerialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RoleCreator {
    pub name: String,
    pub namespace: Namespace,
    #[cfg_attr(
        feature = "typescript",
        ts(type = "(string | CreatorWitness)[] | undefined")
    )]
    pub witnesses: BTreeSet<CreatorWitness>,
    pub quantity: CreatorQuantity,
}

#[derive(Deserialize)]
struct RoleCreatorDef {
    name: String,
    pub namespace: Namespace,
    #[serde(default)]
    witnesses: Option<CreatorWitnesses>,
    pub quantity: CreatorQuantity,
}

impl<'de> Deserialize<'de> for RoleCreator {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let RoleCreatorDef {
            name,
            namespace,
            witnesses,
            quantity,
        } = RoleCreatorDef::deserialize(deserializer)?;

        let witnesses = witnesses
            .map_or_else(default_creator_witnesses, |values| values.into());

        Ok(Self {
            name,
            namespace,
            witnesses,
            quantity,
        })
    }
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

impl RoleCreator {
    pub fn create(name: &str, namespace: Namespace) -> Self {
        Self {
            name: name.to_owned(),
            namespace,
            witnesses: default_creator_witnesses(),
            quantity: CreatorQuantity::Infinity,
        }
    }
}

impl Quorum {
    pub fn check_values(&self) -> Result<(), String> {
        if let Self::Percentage(percentage) = self
            && (*percentage == 0_u8 || *percentage > 100_u8)
        {
            return Err("the percentage must be between 1 and 100".to_owned());
        }

        Ok(())
    }

    pub fn get_signers(&self, total_members: u32, pending: u32) -> u32 {
        let signers = match self {
            Self::Fixed(fixed) => {
                let min = std::cmp::min(fixed, &total_members);
                *min
            }
            Self::Majority => total_members / 2 + 1,
            Self::Percentage(percentage) => {
                total_members * (percentage / 100) as u32
            }
        };

        std::cmp::min(signers, pending)
    }

    pub fn check_quorum(&self, total_members: u32, signers: u32) -> bool {
        match self {
            Self::Fixed(fixed) => {
                let min = std::cmp::min(fixed, &total_members);
                signers >= *min
            }
            Self::Majority => signers > total_members / 2,
            Self::Percentage(percentage) => {
                signers >= (total_members * (percentage / 100) as u32)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{CreatorWitness, RoleCreator, SchemaAdd, SchemaChange};
    use serde_json::json;
    use std::collections::BTreeSet;

    #[test]
    fn test_schema_add_allows_duplicated_viewpoints_deserialization() {
        let schema = serde_json::from_value::<SchemaAdd>(json!({
            "id": "Example",
            "contract": "contract",
            "initial_value": {},
            "viewpoints": ["agua", "agua"]
        }))
        .unwrap();

        assert_eq!(
            schema.viewpoints,
            vec!["agua".to_owned(), "agua".to_owned()]
        );
    }

    #[test]
    fn test_schema_change_allows_duplicated_viewpoints_deserialization() {
        let change = serde_json::from_value::<SchemaChange>(json!({
            "actual_id": "Example",
            "new_viewpoints": ["agua", "agua"]
        }))
        .unwrap();

        assert_eq!(
            change.new_viewpoints,
            Some(vec!["agua".to_owned(), "agua".to_owned()])
        );
    }

    #[test]
    fn test_creator_witness_rejects_duplicated_viewpoints() {
        let error = serde_json::from_value::<CreatorWitness>(json!({
            "name": "pepito",
            "viewpoints": ["agua", "agua"]
        }))
        .unwrap_err();

        assert!(error.to_string().contains("duplicated viewpoint"));
    }

    #[test]
    fn test_role_creator_defaults_to_generic_all_viewpoints() {
        let creator = serde_json::from_value::<RoleCreator>(json!({
            "name": "Owner",
            "namespace": [],
            "quantity": 1
        }))
        .unwrap();

        assert_eq!(
            creator.witnesses,
            BTreeSet::from([CreatorWitness {
                name: "Witnesses".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            }])
        );
    }

    #[test]
    fn test_role_creator_allows_legacy_string_witnesses() {
        let creator = serde_json::from_value::<RoleCreator>(json!({
            "name": "Owner",
            "namespace": [],
            "witnesses": ["Alice"],
            "quantity": 1
        }))
        .unwrap();

        assert_eq!(
            creator.witnesses,
            BTreeSet::from([CreatorWitness {
                name: "Alice".to_owned(),
                viewpoints: BTreeSet::new(),
            }])
        );
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct Member {
    #[cfg_attr(feature = "typescript", ts(type = "string"))]
    pub id: PublicKey,
    pub name: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum ProtocolTypes {
    Approval,
    Evaluation,
    Validation,
}

impl fmt::Display for ProtocolTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Approval => write!(f, "Approval"),
            Self::Evaluation => write!(f, "Evaluation"),
            Self::Validation => write!(f, "Validation"),
        }
    }
}
