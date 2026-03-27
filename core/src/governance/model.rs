//! # Governance model.
//!

use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::PublicKey,
    schematype::ReservedWords,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use std::{
    collections::{BTreeSet, HashSet},
    vec,
};

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

pub struct NameCreators {
    pub validation: Option<HashSet<String>>,
    pub evaluation: Option<HashSet<String>>,
}

impl NameCreators {
    pub const fn is_empty(&self) -> bool {
        self.validation.is_none() && self.evaluation.is_none()
    }
}

pub struct SchemaKeyCreators {
    pub schema_id: SchemaType,
    pub validation: Option<HashSet<PublicKey>>,
    pub evaluation: Option<HashSet<PublicKey>>,
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
    }

    pub fn remove_member_role(&mut self, remove_members: &Vec<String>) {
        for remove in remove_members {
            self.approver.remove(remove);
            self.evaluator.remove(remove);
            self.validator.remove(remove);
            self.witness.remove(remove);
            self.issuer.signers.remove(remove);
        }
    }

    pub fn change_name_role(
        &mut self,
        chang_name_members: &Vec<(String, String)>,
    ) {
        for (old_name, new_name) in chang_name_members {
            if self.approver.remove(old_name) {
                self.approver.insert(new_name.clone());
            };
            if self.evaluator.remove(old_name) {
                self.evaluator.insert(new_name.clone());
            };
            if self.validator.remove(old_name) {
                self.validator.insert(new_name.clone());
            };
            if self.witness.remove(old_name) {
                self.witness.insert(new_name.clone());
            };
            if self.issuer.signers.remove(old_name) {
                self.issuer.signers.insert(new_name.clone());
            };
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
            RoleTypes::Approver => {
                vec![]
            }
            _ => unreachable!("The role is obtained from ProtocolTypes"),
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
            RoleTypes::Approver => false,
            _ => unreachable!("The role is obtained from ProtocolTypes"),
        }
    }

    pub fn roles_namespace(
        &self,
        name: &str,
    ) -> (Option<Vec<Namespace>>, Option<Vec<Namespace>>) {
        let val_namespace = self
            .validator
            .iter()
            .filter(|x| x.name == name)
            .map(|x| x.namespace.clone())
            .collect::<Vec<Namespace>>();
        let eval_namespace = self
            .evaluator
            .iter()
            .filter(|x| x.name == name)
            .map(|x| x.namespace.clone())
            .collect::<Vec<Namespace>>();

        let val_namespace = if val_namespace.is_empty() {
            None
        } else {
            Some(val_namespace)
        };

        let eval_namespace = if eval_namespace.is_empty() {
            None
        } else {
            Some(eval_namespace)
        };

        (val_namespace, eval_namespace)
    }

    pub fn remove_member_role(&mut self, remove_members: &Vec<String>) {
        for remove in remove_members {
            self.evaluator.retain(|x| x.name != *remove);
            self.validator.retain(|x| x.name != *remove);
            self.witness.retain(|x| x.name != *remove);
            self.issuer.signers.retain(|x| x.name != *remove);
        }
    }

    pub fn change_name_role(
        &mut self,
        chang_name_members: &Vec<(String, String)>,
    ) {
        for (old_name, new_name) in chang_name_members {
            self.evaluator = self
                .evaluator
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();

            self.validator = self
                .validator
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();

            self.witness = self
                .witness
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();

            self.issuer.signers = self
                .issuer
                .signers
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
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
            RoleTypes::Issuer => {
                self.issuer.signers.iter().any(|x| {
                    let namespace_role = x.namespace.clone();
                    namespace_role.is_ancestor_or_equal_of(&namespace)
                        && x.name == name
                }) || self.issuer.any
            }
            RoleTypes::Approver | RoleTypes::Creator => false,
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
            RoleTypes::Approver | RoleTypes::Creator => (vec![], false),
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
            .map(|x| x.witnesses.clone())
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
                    c.witnesses.remove(remove);
                    c.witness_viewpoints.retain(|x| x.name != *remove);
                    c
                })
                .collect();
        }
    }

    pub fn change_name_role(
        &mut self,
        chang_name_members: &Vec<(String, String)>,
    ) {
        for (old_name, new_name) in chang_name_members {
            self.evaluator = self
                .evaluator
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();

            self.validator = self
                .validator
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();

            self.witness = self
                .witness
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();

            self.creator = self
                .creator
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        RoleCreator {
                            quantity: x.quantity.clone(),
                            name: new_name.clone(),
                            witnesses: x.witnesses.clone(),
                            witness_viewpoints: x
                                .witness_viewpoints
                                .iter()
                                .map(|w| {
                                    if w.name == *old_name {
                                        CreatorWitness {
                                            name: new_name.clone(),
                                            viewpoints: w.viewpoints.clone(),
                                        }
                                    } else {
                                        w.clone()
                                    }
                                })
                                .collect(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        let mut role = x.clone();
                        if role.witnesses.remove(old_name) {
                            role.witnesses.insert(new_name.clone());
                        }
                        role.witness_viewpoints = role
                            .witness_viewpoints
                            .iter()
                            .map(|w| {
                                if w.name == *old_name {
                                    CreatorWitness {
                                        name: new_name.clone(),
                                        viewpoints: w.viewpoints.clone(),
                                    }
                                } else {
                                    w.clone()
                                }
                            })
                            .collect();
                        role
                    }
                })
                .collect();

            self.issuer.signers = self
                .issuer
                .signers
                .iter()
                .map(|x| {
                    if x.name == *old_name {
                        Role {
                            name: new_name.clone(),
                            namespace: x.namespace.clone(),
                        }
                    } else {
                        x.clone()
                    }
                })
                .collect();
        }
    }

    pub fn roles_creators(
        &self,
        name: &str,
        not_gov_val: Option<Vec<Namespace>>,
        not_gov_eval: Option<Vec<Namespace>>,
    ) -> NameCreators {
        let mut val_namespace = self
            .validator
            .iter()
            .filter(|x| x.name == name)
            .map(|x| x.namespace.clone())
            .collect::<Vec<Namespace>>();
        if let Some(mut not_gov_val) = not_gov_val {
            val_namespace.append(&mut not_gov_val);
        }

        let mut eval_namespace = self
            .evaluator
            .iter()
            .filter(|x| x.name == name)
            .map(|x| x.namespace.clone())
            .collect::<Vec<Namespace>>();
        if let Some(mut not_gov_eval) = not_gov_eval {
            eval_namespace.append(&mut not_gov_eval);
        }

        let mut creators_val: Vec<String> = vec![];
        for namespace in val_namespace.clone() {
            let mut creators = self
                .creator
                .iter()
                .filter(|x| {
                    let namespace_role = x.namespace.clone();
                    namespace.is_ancestor_or_equal_of(&namespace_role)
                })
                .map(|x| x.name.clone())
                .collect::<Vec<String>>();

            creators_val.append(&mut creators);
        }

        let mut creators_eval: Vec<String> = vec![];
        for namespace in eval_namespace.clone() {
            let mut creators = self
                .creator
                .iter()
                .filter(|x| {
                    let namespace_role = x.namespace.clone();
                    namespace.is_ancestor_or_equal_of(&namespace_role)
                })
                .map(|x| x.name.clone())
                .collect::<Vec<String>>();

            creators_eval.append(&mut creators);
        }

        let hash_val: Option<HashSet<String>> = if val_namespace.is_empty() {
            None
        } else {
            Some(HashSet::from_iter(creators_val.iter().cloned()))
        };

        let hash_eval: Option<HashSet<String>> = if eval_namespace.is_empty() {
            None
        } else {
            Some(HashSet::from_iter(creators_eval.iter().cloned()))
        };

        NameCreators {
            validation: hash_val,
            evaluation: hash_eval,
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
            RoleTypes::Approver => false,
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
            RoleTypes::Approver => {
                vec![]
            }
            _ => unreachable!("The role is obtained from ProtocolTypes"),
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
            RoleTypes::Approver => false,
            _ => unreachable!("The role is obtained from ProtocolTypes"),
        }
    }

    pub fn max_creations(
        &self,
        namespace: Namespace,
        name: &str,
    ) -> Option<CreatorQuantity> {
        self.creator
            .get(&RoleCreator {
                name: name.to_string(),
                namespace,
                witnesses: BTreeSet::default(),
                witness_viewpoints: BTreeSet::default(),
                quantity: CreatorQuantity::Infinity,
            })
            .map(|x| x.quantity.clone())
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
            RoleTypes::Approver => (vec![], false),
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
}

impl From<ProtocolTypes> for RoleTypes {
    fn from(value: ProtocolTypes) -> Self {
        match value {
            ProtocolTypes::Approval => Self::Approver,
            ProtocolTypes::Evaluation => Self::Evaluator,
            ProtocolTypes::Validation => Self::Validator,
        }
    }
}

pub enum WitnessesData {
    Gov,
    Schema {
        creator: PublicKey,
        schema_id: SchemaType,
        namespace: Namespace,
    },
}

impl WitnessesData {
    pub fn build(
        schema_id: SchemaType,
        namespace: Namespace,
        creator: PublicKey,
    ) -> Self {
        if schema_id.is_gov() {
            Self::Gov
        } else {
            Self::Schema {
                creator,
                schema_id,
                namespace,
            }
        }
    }
}

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
}

impl PolicyGov {
    pub fn get_quorum(&self, role: ProtocolTypes) -> Option<Quorum> {
        match role {
            ProtocolTypes::Approval => Some(self.approve.clone()),
            ProtocolTypes::Evaluation => Some(self.evaluate.clone()),
            ProtocolTypes::Validation => Some(self.validate.clone()),
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
        }
    }
}
