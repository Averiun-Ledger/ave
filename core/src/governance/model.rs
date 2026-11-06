//! # Governance model.
//!

use ave_common::{
    Namespace, SchemaType, ValueWrapper, identity::PublicKey,
    schematype::ReservedWords,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use std::{collections::BTreeSet, vec};

pub type MemberName = String;

pub use ave_common::governance::{
    CreatorQuantity, CreatorWitness, Member, ProtocolTypes, Quorum, Role,
    RoleCreator,
};

/// Governance schema.
#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    Hash,
    PartialEq,
    Eq,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Schema {
    pub initial_value: ValueWrapper,
    pub contract: String,
    pub viewpoints: BTreeSet<String>,
}

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RolesGov {
    pub approver: BTreeSet<MemberName>,
    pub evaluator: BTreeSet<MemberName>,
    pub validator: BTreeSet<MemberName>,
    pub witness: BTreeSet<MemberName>,
    pub issuer: RoleGovIssuer,
    pub compiler: BTreeSet<MemberName>,
}

impl RolesGov {
    pub fn check_basic_gov(&self) -> bool {
        self.approver.contains(&ReservedWords::Owner.to_string())
            && self.evaluator.contains(&ReservedWords::Owner.to_string())
            && self.validator.contains(&ReservedWords::Owner.to_string())
            && self.witness.contains(&ReservedWords::Owner.to_string())
            && self
                .issuer
                .signers
                .contains(&ReservedWords::Owner.to_string())
            && self.compiler.contains(&ReservedWords::Owner.to_string())
    }

    pub fn remove_member_role(&mut self, remove_members: &Vec<String>) {
        for remove in remove_members {
            self.approver.remove(remove);
            self.evaluator.remove(remove);
            self.validator.remove(remove);
            self.witness.remove(remove);
            self.issuer.signers.remove(remove);
            self.compiler.remove(remove);
        }
    }

    pub fn hash_this_rol(&self, role: RoleTypes, name: &str) -> bool {
        match role {
            RoleTypes::Approver => self.approver.contains(name),
            RoleTypes::Evaluator => self.evaluator.contains(name),
            RoleTypes::Validator => self.validator.contains(name),
            RoleTypes::Issuer => {
                self.issuer.signers.contains(name) || self.issuer.any
            }
            RoleTypes::Creator => false,
            RoleTypes::Witness => self.witness.contains(name),
            RoleTypes::Compiler => self.compiler.contains(name),
        }
    }

    pub fn get_signers(&self, role: RoleTypes) -> (Vec<String>, bool) {
        match role {
            RoleTypes::Evaluator => (
                self.evaluator.iter().cloned().collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Validator => (
                self.validator.iter().cloned().collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Approver => (
                self.approver.iter().cloned().collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Issuer => (
                self.issuer.signers.iter().cloned().collect::<Vec<String>>(),
                self.issuer.any,
            ),
            RoleTypes::Witness => {
                (self.witness.iter().cloned().collect::<Vec<String>>(), false)
            }
            RoleTypes::Creator => (vec![], false),
            RoleTypes::Compiler => (
                self.compiler.iter().cloned().collect::<Vec<String>>(),
                false,
            ),
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RolesTrackerSchemas {
    pub evaluator: BTreeSet<Role>,
    pub validator: BTreeSet<Role>,
    pub witness: BTreeSet<Role>,
    pub issuer: RoleSchemaIssuer,
}

impl From<RolesTrackerSchemas> for RolesSchema {
    fn from(value: RolesTrackerSchemas) -> Self {
        Self {
            evaluator: value.evaluator,
            validator: value.validator,
            witness: value.witness,
            creator: BTreeSet::new(),
            issuer: value.issuer,
        }
    }
}

impl From<RolesSchema> for RolesTrackerSchemas {
    fn from(value: RolesSchema) -> Self {
        Self {
            evaluator: value.evaluator,
            validator: value.validator,
            witness: value.witness,
            issuer: value.issuer,
        }
    }
}

impl RolesTrackerSchemas {
    pub fn role_namespace(
        &self,
        role: ProtocolTypes,
        name: &str,
    ) -> Vec<Namespace> {
        let role = RoleTypes::from(role);
        match role {
            RoleTypes::Evaluator => self
                .evaluator
                .iter()
                .filter(|x| x.name == name)
                .map(|x| x.namespace.clone())
                .collect(),
            RoleTypes::Validator => self
                .validator
                .iter()
                .filter(|x| x.name == name)
                .map(|x| x.namespace.clone())
                .collect(),
            // Approver, compiler and future roles hold no schema
            // namespaces; `Compilation` reaches here today.
            _ => {
                vec![]
            }
        }
    }

    pub fn hash_this_rol_not_namespace(
        &self,
        role: ProtocolTypes,
        name: &str,
    ) -> bool {
        let role = RoleTypes::from(role);
        match role {
            RoleTypes::Evaluator => {
                self.evaluator.iter().any(|x| x.name == name)
            }
            RoleTypes::Validator => {
                self.validator.iter().any(|x| x.name == name)
            }
            // Approver, compiler and future roles never match here.
            _ => false,
        }
    }

    pub fn remove_member_role(&mut self, remove_members: &Vec<String>) {
        for remove in remove_members {
            self.evaluator.retain(|x| x.name != *remove);
            self.validator.retain(|x| x.name != *remove);
            self.witness.retain(|x| x.name != *remove);
            self.issuer.signers.retain(|x| x.name != *remove);
        }
    }

    pub const fn issuer_any(&self) -> bool {
        self.issuer.any
    }

    pub fn hash_this_rol(
        &self,
        role: RoleTypes,
        namespace: Namespace,
        name: &str,
    ) -> bool {
        match role {
            RoleTypes::Evaluator => self.evaluator.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Validator => self.validator.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Witness => self.witness.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Issuer => {
                self.issuer.signers.iter().any(|x| {
                    let namespace_role = x.namespace.clone();
                    namespace_role.is_ancestor_or_equal_of(&namespace)
                        && x.name == name
                }) || self.issuer.any
            }
            RoleTypes::Approver | RoleTypes::Creator | RoleTypes::Compiler => {
                false
            }
        }
    }

    pub fn get_signers(
        &self,
        role: RoleTypes,
        namespace: Namespace,
    ) -> (Vec<String>, bool) {
        match role {
            RoleTypes::Evaluator => (
                self.evaluator
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Validator => (
                self.validator
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Witness => (
                self.witness
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Issuer => (
                self.issuer
                    .signers
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                self.issuer.any,
            ),
            RoleTypes::Approver | RoleTypes::Creator | RoleTypes::Compiler => {
                (vec![], false)
            }
        }
    }
}

#[derive(
    Serialize,
    Deserialize,
    Clone,
    Debug,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RolesSchema {
    pub evaluator: BTreeSet<Role>,
    pub validator: BTreeSet<Role>,
    pub witness: BTreeSet<Role>,
    pub creator: BTreeSet<RoleCreator>,
    pub issuer: RoleSchemaIssuer,
}

impl RolesSchema {
    pub fn creator_witnesses(
        &self,
        name: &str,
        namespace: Namespace,
    ) -> BTreeSet<String> {
        self.creator
            .get(&RoleCreator::create(name, namespace))
            .map(|x| {
                x.witnesses
                    .iter()
                    .map(|witness| witness.name.clone())
                    .collect()
            })
            .unwrap_or_default()
    }

    pub fn remove_member_role(&mut self, remove_members: &Vec<String>) {
        for remove in remove_members {
            self.evaluator.retain(|x| x.name != *remove);
            self.validator.retain(|x| x.name != *remove);
            self.witness.retain(|x| x.name != *remove);
            self.issuer.signers.retain(|x| x.name != *remove);
            self.creator = std::mem::take(&mut self.creator)
                .into_iter()
                .filter(|x| x.name != *remove)
                .map(|mut c| {
                    c.witnesses.retain(|x| x.name != *remove);
                    c
                })
                .collect();
        }
    }

    pub const fn issuer_any(&self) -> bool {
        self.issuer.any
    }

    pub fn hash_this_rol(
        &self,
        role: RoleTypes,
        namespace: Namespace,
        name: &str,
    ) -> bool {
        match role {
            RoleTypes::Evaluator => self.evaluator.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Validator => self.validator.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Witness => self.witness.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Creator => self.creator.iter().any(|x| {
                let namespace_role = x.namespace.clone();
                namespace_role.is_ancestor_or_equal_of(&namespace)
                    && x.name == name
            }),
            RoleTypes::Issuer => {
                self.issuer.signers.iter().any(|x| {
                    let namespace_role = x.namespace.clone();
                    namespace_role.is_ancestor_or_equal_of(&namespace)
                        && x.name == name
                }) || self.issuer.any
            }
            RoleTypes::Approver | RoleTypes::Compiler => false,
        }
    }

    pub fn role_namespace(
        &self,
        role: ProtocolTypes,
        name: &str,
    ) -> Vec<Namespace> {
        let role = RoleTypes::from(role);
        match role {
            RoleTypes::Evaluator => self
                .evaluator
                .iter()
                .filter(|x| x.name == name)
                .map(|x| x.namespace.clone())
                .collect(),
            RoleTypes::Validator => self
                .validator
                .iter()
                .filter(|x| x.name == name)
                .map(|x| x.namespace.clone())
                .collect(),
            // Approver, compiler and future roles hold no schema
            // namespaces; `Compilation` reaches here today.
            _ => {
                vec![]
            }
        }
    }

    pub fn hash_this_rol_not_namespace(
        &self,
        role: ProtocolTypes,
        name: &str,
    ) -> bool {
        let role = RoleTypes::from(role);
        match role {
            RoleTypes::Evaluator => {
                self.evaluator.iter().any(|x| x.name == name)
            }
            RoleTypes::Validator => {
                self.validator.iter().any(|x| x.name == name)
            }
            // Approver, compiler and future roles never match here.
            _ => false,
        }
    }

    pub fn get_signers(
        &self,
        role: RoleTypes,
        namespace: Namespace,
    ) -> (Vec<String>, bool) {
        match role {
            RoleTypes::Evaluator => (
                self.evaluator
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Validator => (
                self.validator
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Witness => (
                self.witness
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Creator => (
                self.creator
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                false,
            ),
            RoleTypes::Issuer => (
                self.issuer
                    .signers
                    .iter()
                    .filter(|x| {
                        let namespace_role = x.namespace.clone();
                        namespace_role.is_ancestor_or_equal_of(&namespace)
                    })
                    .map(|x| x.name.clone())
                    .collect::<Vec<String>>(),
                self.issuer.any,
            ),
            RoleTypes::Approver | RoleTypes::Compiler => (vec![], false),
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum RoleTypes {
    Approver,
    Evaluator,
    Validator,
    Witness,
    Creator,
    Issuer,
    Compiler,
}

impl From<ProtocolTypes> for RoleTypes {
    fn from(value: ProtocolTypes) -> Self {
        match value {
            ProtocolTypes::Approval => Self::Approver,
            ProtocolTypes::Evaluation => Self::Evaluator,
            ProtocolTypes::Validation => Self::Validator,
            ProtocolTypes::Compilation => Self::Compiler,
        }
    }
}

#[derive(Debug, Clone)]
pub enum WitnessesData {
    Gov,
    Schema {
        creator: PublicKey,
        schema_id: SchemaType,
        namespace: Namespace,
    },
}

#[derive(Debug, Clone)]
pub enum HashThisRole {
    Gov {
        who: PublicKey,
        role: RoleTypes,
    },
    Schema {
        who: PublicKey,
        role: RoleTypes,
        schema_id: SchemaType,
        namespace: Namespace,
    },
    SchemaWitness {
        who: PublicKey,
        creator: PublicKey,
        schema_id: SchemaType,
        namespace: Namespace,
    },
}

impl HashThisRole {
    pub fn get_who(&self) -> PublicKey {
        match self {
            Self::Gov { who, .. } => who.clone(),
            Self::Schema { who, .. } => who.clone(),
            Self::SchemaWitness { who, .. } => who.clone(),
        }
    }
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RoleGovIssuer {
    pub signers: BTreeSet<MemberName>,
    pub any: bool,
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RoleSchemaIssuer {
    pub signers: BTreeSet<Role>,
    pub any: bool,
}

/// Governance policy.
#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct PolicyGov {
    /// Approve quorum
    pub approve: Quorum,
    /// Evaluate quorum
    pub evaluate: Quorum,
    /// Validate quorum
    pub validate: Quorum,
    /// Compile quorum
    pub compile: Quorum,
}

impl PolicyGov {
    pub fn get_quorum(&self, role: ProtocolTypes) -> Option<Quorum> {
        match role {
            ProtocolTypes::Approval => Some(self.approve.clone()),
            ProtocolTypes::Evaluation => Some(self.evaluate.clone()),
            ProtocolTypes::Validation => Some(self.validate.clone()),
            ProtocolTypes::Compilation => Some(self.compile.clone()),
        }
    }
}

#[derive(
    Debug,
    Serialize,
    Deserialize,
    Clone,
    Hash,
    PartialEq,
    Eq,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct PolicySchema {
    /// Evaluate quorum
    pub evaluate: Quorum,
    /// Validate quorum
    pub validate: Quorum,
}

impl PolicySchema {
    pub fn get_quorum(&self, role: ProtocolTypes) -> Option<Quorum> {
        match role {
            ProtocolTypes::Approval => None,
            ProtocolTypes::Evaluation => Some(self.evaluate.clone()),
            ProtocolTypes::Validation => Some(self.validate.clone()),
            ProtocolTypes::Compilation => None,
        }
    }
}
