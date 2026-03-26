//! # GovernanceData module.
//!

use crate::governance::{
    RolesUpdateConfirm, RolesUpdateRemove,
    error::GovernanceError,
    model::{
        HashThisRole, PolicyGov, PolicySchema, ProtocolTypes, Quorum,
        RoleGovIssuer, RoleSchemaIssuer, RoleTypes, RolesGov, RolesSchema,
        RolesTrackerSchemas, Schema, WitnessesData,
    },
};

use ave_common::{
    Namespace, SchemaType, ValueWrapper, identity::PublicKey,
    schematype::ReservedWords,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

pub type MemberName = String;

#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct GovernanceData {
    pub version: u64,
    pub members: BTreeMap<MemberName, PublicKey>,
    pub roles_gov: RolesGov,
    pub policies_gov: PolicyGov,
    pub schemas: BTreeMap<SchemaType, Schema>,
    pub roles_schema: BTreeMap<SchemaType, RolesSchema>,
    pub roles_tracker_schemas: RolesTrackerSchemas,
    pub policies_schema: BTreeMap<SchemaType, PolicySchema>,
}

impl GovernanceData {
    pub fn new(owner_key: PublicKey) -> Self {
        let policies_gov = PolicyGov {
            approve: Quorum::Majority,
            evaluate: Quorum::Majority,
            validate: Quorum::Majority,
        };

        let owner_signers_gov: BTreeSet<MemberName> =
            BTreeSet::from([ReservedWords::Owner.to_string()]);

        let roles_gov = RolesGov {
            approver: owner_signers_gov.clone(),
            evaluator: owner_signers_gov.clone(),
            validator: owner_signers_gov.clone(),
            witness: owner_signers_gov.clone(),
            issuer: RoleGovIssuer {
                any: false,
                signers: owner_signers_gov,
            },
        };

        let not_gov_role = RolesTrackerSchemas {
            evaluator: BTreeSet::new(),
            validator: BTreeSet::new(),
            witness: BTreeSet::new(),
            issuer: RoleSchemaIssuer {
                signers: BTreeSet::new(),
                any: false,
            },
        };

        Self {
            version: 0,
            members: BTreeMap::from([(
                ReservedWords::Owner.to_string(),
                owner_key,
            )]),
            roles_gov,
            policies_gov,
            schemas: BTreeMap::new(),
            roles_schema: BTreeMap::new(),
            roles_tracker_schemas: not_gov_role,
            policies_schema: BTreeMap::new(),
        }
    }

    pub fn roles_update_remove_confirm(
        &self,
        old_owner_key: &PublicKey,
        new_owner_key: &PublicKey,
    ) -> RolesUpdateConfirm {
        let mut remove_creator: HashSet<(SchemaType, String, PublicKey)> =
            HashSet::new();

        let mut new_approver = None;
        let mut new_evaluator = None;
        let mut new_validator = None;

        let mut remove_witnesses: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let remove_approver: PublicKey = old_owner_key.clone();
        let mut remove_evaluators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();
        let mut remove_validators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let old_name = self
            .members
            .iter()
            .find(|x| x.1 == new_owner_key)
            .map(|x| x.0)
            .cloned();

        // gov
        if let Some(old_name) = old_name {
            if !self.roles_gov.approver.contains(&old_name) {
                new_approver = Some(new_owner_key.clone());
            }

            if !self.roles_gov.evaluator.contains(&old_name) {
                new_evaluator = Some(new_owner_key.clone());
            }
            remove_evaluators
                .entry((SchemaType::Governance, old_owner_key.clone()))
                .or_default()
                .push(Namespace::new());
            if !self.roles_gov.validator.contains(&old_name) {
                new_validator = Some(new_owner_key.clone());
            }

            remove_validators
                .entry((SchemaType::Governance, old_owner_key.clone()))
                .or_default()
                .push(Namespace::new());

            // schema
            for (schema_id, roles_schema) in self.roles_schema.iter() {
                for evaluators in roles_schema.evaluator.iter() {
                    if evaluators.name == ReservedWords::Owner.to_string() {
                        remove_evaluators
                            .entry((schema_id.clone(), old_owner_key.clone()))
                            .or_default()
                            .push(evaluators.namespace.clone());
                    } else if evaluators.name == old_name {
                        remove_evaluators
                            .entry((schema_id.clone(), new_owner_key.clone()))
                            .or_default()
                            .push(evaluators.namespace.clone());
                    }
                }

                for validators in roles_schema.validator.iter() {
                    if validators.name == ReservedWords::Owner.to_string() {
                        remove_validators
                            .entry((schema_id.clone(), old_owner_key.clone()))
                            .or_default()
                            .push(validators.namespace.clone());
                    } else if validators.name == old_name {
                        remove_validators
                            .entry((schema_id.clone(), new_owner_key.clone()))
                            .or_default()
                            .push(validators.namespace.clone());
                    }
                }

                for creators in roles_schema.creator.iter() {
                    if creators.name == ReservedWords::Owner.to_string() {
                        remove_creator.insert((
                            schema_id.clone(),
                            creators.namespace.to_string(),
                            old_owner_key.clone(),
                        ));
                    } else if creators.name == old_name {
                        remove_creator.insert((
                            schema_id.clone(),
                            creators.namespace.to_string(),
                            new_owner_key.clone(),
                        ));
                    }
                }
                for witness in roles_schema.witness.iter() {
                    if witness.name == ReservedWords::Owner.to_string() {
                        remove_witnesses
                            .entry((schema_id.clone(), old_owner_key.clone()))
                            .or_default()
                            .push(witness.namespace.clone());
                    } else if witness.name == old_name {
                        remove_witnesses
                            .entry((schema_id.clone(), new_owner_key.clone()))
                            .or_default()
                            .push(witness.namespace.clone());
                    }
                }
            }

            for evaluators in self.roles_tracker_schemas.evaluator.iter() {
                if evaluators.name == ReservedWords::Owner.to_string() {
                    remove_evaluators
                        .entry((
                            SchemaType::TrackerSchemas,
                            old_owner_key.clone(),
                        ))
                        .or_default()
                        .push(evaluators.namespace.clone());
                } else if evaluators.name == old_name {
                    remove_evaluators
                        .entry((
                            SchemaType::TrackerSchemas,
                            new_owner_key.clone(),
                        ))
                        .or_default()
                        .push(evaluators.namespace.clone());
                }
            }
            for validators in self.roles_tracker_schemas.validator.iter() {
                if validators.name == ReservedWords::Owner.to_string() {
                    remove_validators
                        .entry((
                            SchemaType::TrackerSchemas,
                            old_owner_key.clone(),
                        ))
                        .or_default()
                        .push(validators.namespace.clone());
                } else if validators.name == old_name {
                    remove_validators
                        .entry((
                            SchemaType::TrackerSchemas,
                            new_owner_key.clone(),
                        ))
                        .or_default()
                        .push(validators.namespace.clone());
                }
            }
            for witness in self.roles_tracker_schemas.witness.iter() {
                if witness.name == ReservedWords::Owner.to_string() {
                    remove_witnesses
                        .entry((
                            SchemaType::TrackerSchemas,
                            old_owner_key.clone(),
                        ))
                        .or_default()
                        .push(witness.namespace.clone());
                } else if witness.name == old_name {
                    remove_witnesses
                        .entry((
                            SchemaType::TrackerSchemas,
                            new_owner_key.clone(),
                        ))
                        .or_default()
                        .push(witness.namespace.clone());
                }
            }
        }

        RolesUpdateConfirm {
            new_approver,
            new_evaluator,
            new_validator,
            remove_approver,
            remove_creator,
            remove_evaluators,
            remove_validators,
            remove_witnesses,
        }
    }

    pub fn roles_update_remove_fact(
        &self,
        remove_members: Option<HashSet<String>>,
        remove_schemas: Option<HashSet<SchemaType>>,
    ) -> RolesUpdateRemove {
        let mut remove_creator: HashSet<(SchemaType, String, PublicKey)> =
            HashSet::new();

        let mut remove_witnesses: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let mut remove_approvers: Vec<PublicKey> = vec![];
        let mut remove_evaluators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();
        let mut remove_validators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let remove_schemas = remove_schemas.unwrap_or_default();

        for schema_id in remove_schemas.iter() {
            if let Some(roles_schema) = self.roles_schema.get(schema_id) {
                for evaluators in roles_schema.evaluator.iter() {
                    if let Some(user) = self.members.get(&evaluators.name) {
                        remove_evaluators
                            .entry((schema_id.clone(), user.clone()))
                            .or_default()
                            .push(evaluators.namespace.clone());
                    }
                }

                for validators in roles_schema.validator.iter() {
                    if let Some(user) = self.members.get(&validators.name) {
                        remove_validators
                            .entry((schema_id.clone(), user.clone()))
                            .or_default()
                            .push(validators.namespace.clone());
                    }
                }

                for creators in roles_schema.creator.iter() {
                    if let Some(user) = self.members.get(&creators.name) {
                        remove_creator.insert((
                            schema_id.clone(),
                            creators.namespace.to_string(),
                            user.clone(),
                        ));
                    }
                }
                for witness in roles_schema.witness.iter() {
                    if let Some(user) = self.members.get(&witness.name) {
                        remove_witnesses
                            .entry((schema_id.clone(), user.clone()))
                            .or_default()
                            .push(witness.namespace.clone());
                    }
                }
            }
        }

        if let Some(remove_members) = remove_members {
            // gov
            for user in remove_members.iter() {
                if let Some(user_key) = self.members.get(user) {
                    if self.roles_gov.approver.contains(user) {
                        remove_approvers.push(user_key.clone());
                    }
                    if self.roles_gov.evaluator.contains(user) {
                        remove_evaluators
                            .entry((SchemaType::Governance, user_key.clone()))
                            .or_default()
                            .push(Namespace::new());
                    }
                    if self.roles_gov.validator.contains(user) {
                        remove_validators
                            .entry((SchemaType::Governance, user_key.clone()))
                            .or_default()
                            .push(Namespace::new());
                    }
                }
            }

            // schema
            for (schema_id, roles_schema) in self.roles_schema.iter() {
                if !remove_schemas.contains(schema_id) {
                    for evaluators in roles_schema.evaluator.iter() {
                        if remove_members.contains(&evaluators.name)
                            && let Some(user) =
                                self.members.get(&evaluators.name)
                        {
                            remove_evaluators
                                .entry((schema_id.clone(), user.clone()))
                                .or_default()
                                .push(evaluators.namespace.clone());
                        }
                    }

                    for validators in roles_schema.validator.iter() {
                        if remove_members.contains(&validators.name)
                            && let Some(user) =
                                self.members.get(&validators.name)
                        {
                            remove_validators
                                .entry((schema_id.clone(), user.clone()))
                                .or_default()
                                .push(validators.namespace.clone());
                        }
                    }

                    for creators in roles_schema.creator.iter() {
                        if remove_members.contains(&creators.name)
                            && let Some(user) = self.members.get(&creators.name)
                        {
                            remove_creator.insert((
                                schema_id.clone(),
                                creators.namespace.to_string(),
                                user.clone(),
                            ));
                        }
                    }
                    for witness in roles_schema.witness.iter() {
                        if remove_members.contains(&witness.name)
                            && let Some(user) = self.members.get(&witness.name)
                        {
                            remove_witnesses
                                .entry((schema_id.clone(), user.clone()))
                                .or_default()
                                .push(witness.namespace.clone());
                        }
                    }
                }
            }

            // tracker_schemas
            for evaluators in self.roles_tracker_schemas.evaluator.iter() {
                if remove_members.contains(&evaluators.name)
                    && let Some(user) = self.members.get(&evaluators.name)
                {
                    remove_evaluators
                        .entry((SchemaType::TrackerSchemas, user.clone()))
                        .or_default()
                        .push(evaluators.namespace.clone());
                }
            }
            for validators in self.roles_tracker_schemas.validator.iter() {
                if remove_members.contains(&validators.name)
                    && let Some(user) = self.members.get(&validators.name)
                {
                    remove_validators
                        .entry((SchemaType::TrackerSchemas, user.clone()))
                        .or_default()
                        .push(validators.namespace.clone());
                }
            }
            for witness in self.roles_tracker_schemas.witness.iter() {
                if remove_members.contains(&witness.name)
                    && let Some(user) = self.members.get(&witness.name)
                {
                    remove_witnesses
                        .entry((SchemaType::TrackerSchemas, user.clone()))
                        .or_default()
                        .push(witness.namespace.clone());
                }
            }
        }

        RolesUpdateRemove {
            witnesses: remove_witnesses,
            creator: remove_creator,
            approvers: remove_approvers,
            evaluators: remove_evaluators,
            validators: remove_validators,
        }
    }

    pub fn remove_schema(&mut self, remove_schemas: HashSet<SchemaType>) {
        for schema_id in remove_schemas {
            self.roles_schema.remove(&schema_id);
            self.policies_schema.remove(&schema_id);
        }
    }

    pub fn add_schema(&mut self, add_schema: HashSet<SchemaType>) {
        for schema_id in add_schema {
            self.roles_schema
                .insert(schema_id.clone(), RolesSchema::default());
            self.policies_schema
                .insert(schema_id, PolicySchema::default());
        }
    }

    pub fn remove_member_role(&mut self, remove_members: &Vec<MemberName>) {
        self.roles_gov.remove_member_role(remove_members);
        self.roles_tracker_schemas
            .remove_member_role(remove_members);

        for (_, roles) in self.roles_schema.iter_mut() {
            roles.remove_member_role(remove_members);
        }
    }

    pub fn update_name_role(&mut self, old_name: String) {
        let old_name = vec![old_name];
        let owner_name = vec![ReservedWords::Owner.to_string()];
        self.roles_gov.remove_member_role(&old_name);

        self.roles_tracker_schemas.remove_member_role(&old_name);
        self.roles_tracker_schemas.remove_member_role(&owner_name);

        for (_, roles) in self.roles_schema.iter_mut() {
            roles.remove_member_role(&old_name);
            roles.remove_member_role(&owner_name);
        }
    }

    pub fn to_value_wrapper(&self) -> ValueWrapper {
        ValueWrapper(serde_json::to_value(self).expect("It cannot fail; it does not contain a map with keys other than strings"))
    }

    pub fn check_basic_gov(&self) -> bool {
        self.roles_gov.check_basic_gov()
    }

    /// Get the initial state for GovernanceData model
    ///  # Arguments
    ///  * `schema_id` - The identifier of the [`Schema`].
    /// # Returns
    /// * [`ValueWrapper`] - The initial state.
    /// # Errors
    /// * `GovernanceError` - If the schema is not found.
    pub fn get_init_state(
        &self,
        schema_id: &SchemaType,
    ) -> Result<ValueWrapper, GovernanceError> {
        let Some(schema) = self.schemas.get(schema_id) else {
            return Err(GovernanceError::SchemaDoesNotExist {
                schema_id: schema_id.to_string(),
            });
        };

        Ok(schema.initial_value.clone())
    }

    /// Check if the user has a role.
    /// # Arguments
    /// * `user` - The user id.
    /// * [`Roles`] - The role.
    /// * `schema` - The schema id from [`Schema`].
    /// * [`Namespace`] - The namespace.
    pub fn has_this_role(&self, data: HashThisRole) -> bool {
        let who = data.get_who();

        let Some(name) = self
            .members
            .iter()
            .find(|x| *x.1 == who)
            .map(|x| x.0)
            .cloned()
        else {
            if let HashThisRole::Schema {
                role: RoleTypes::Issuer,
                schema_id,
                ..
            } = data
            {
                if self.roles_tracker_schemas.issuer_any() {
                    return true;
                }

                let Some(roles) = self.roles_schema.get(&schema_id) else {
                    return false;
                };

                return roles.issuer_any();
            } else {
                return false;
            }
        };

        match data {
            HashThisRole::Gov { role, .. } => {
                if matches!(role, RoleTypes::Witness) {
                    return true;
                }

                self.roles_gov.hash_this_rol(role, &name)
            }
            HashThisRole::Schema {
                role,
                schema_id,
                namespace,
                ..
            } => {
                if self.roles_tracker_schemas.hash_this_rol(
                    role.clone(),
                    namespace.clone(),
                    &name,
                ) {
                    return true;
                }

                let Some(roles) = self.roles_schema.get(&schema_id) else {
                    return false;
                };

                roles.hash_this_rol(role, namespace, &name)
            }
            HashThisRole::SchemaWitness {
                creator,
                schema_id,
                namespace,
                ..
            } => {
                let Some(creator_name) = self
                    .members
                    .iter()
                    .find(|x| *x.1 == creator)
                    .map(|x| x.0)
                    .cloned()
                else {
                    return false;
                };

                let Some(roles_schema) = self.roles_schema.get(&schema_id)
                else {
                    return false;
                };

                let witnesses_creator = roles_schema
                    .creator_witnesses(&creator_name, namespace.clone());

                if witnesses_creator.contains(&name) {
                    return true;
                }

                if witnesses_creator
                    .contains(&ReservedWords::Witnesses.to_string())
                {
                    let not_gov_witnesses = self
                        .roles_tracker_schemas
                        .get_signers(RoleTypes::Witness, namespace.clone())
                        .0;

                    if not_gov_witnesses.contains(&name) {
                        return true;
                    }

                    let schema_witnesses = roles_schema
                        .get_signers(RoleTypes::Witness, namespace)
                        .0;

                    if schema_witnesses.contains(&name) {
                        return true;
                    }
                }

                false
            }
        }
    }

    /// Gets the signers for the request stage.
    /// # Arguments
    /// * [`Roles`] - The role.
    /// * `schema_id` - The schema id from [`Schema`].
    /// * [`Namespace`] - The namespace.
    /// # Returns
    /// * (HashSet<[`PublicKey`]>, bool) - The set of key identifiers and a flag indicating if the user is not a member.
    pub fn get_signers(
        &self,
        role: RoleTypes,
        schema_id: &SchemaType,
        namespace: Namespace,
    ) -> (HashSet<PublicKey>, bool) {
        let (names, any) = if schema_id.is_gov() {
            self.roles_gov.get_signers(role)
        } else {
            let (mut not_gov_signers, not_gov_any) = self
                .roles_tracker_schemas
                .get_signers(role.clone(), namespace.clone());
            let (mut schema_signers, schema_any) =
                self.roles_schema.get(schema_id).map_or_else(
                    || (vec![], false),
                    |roles| roles.get_signers(role, namespace),
                );

            not_gov_signers.append(&mut schema_signers);

            (not_gov_signers, not_gov_any || schema_any)
        };

        let mut signers = HashSet::new();
        for name in names {
            if let Some(key) = self.members.get(&name) {
                signers.insert(key.clone());
            }
        }

        (signers, any)
    }

    pub fn get_witnesses(
        &self,
        data: WitnessesData,
    ) -> Result<HashSet<PublicKey>, GovernanceError> {
        let names = match data {
            WitnessesData::Gov => {
                self.roles_gov.get_signers(RoleTypes::Witness).0
            }
            WitnessesData::Schema {
                creator,
                schema_id,
                namespace,
            } => {
                let Some(creator) = self
                    .members
                    .iter()
                    .find(|x| *x.1 == creator)
                    .map(|x| x.0)
                    .cloned()
                else {
                    return Err(GovernanceError::CreatorNotMember);
                };

                let Some(roles_schema) = self.roles_schema.get(&schema_id)
                else {
                    return Err(GovernanceError::WitnessesForNonexistentSchema);
                };
                let witnesses_creator =
                    roles_schema.creator_witnesses(&creator, namespace.clone());

                let mut names = vec![];
                for witness in witnesses_creator {
                    if witness == ReservedWords::Witnesses.to_string() {
                        let mut not_gov_witnesses = self
                            .roles_tracker_schemas
                            .get_signers(RoleTypes::Witness, namespace.clone())
                            .0;
                        let mut schema_witnesses = roles_schema
                            .get_signers(RoleTypes::Witness, namespace.clone())
                            .0;

                        names.append(&mut not_gov_witnesses);
                        names.append(&mut schema_witnesses);
                    } else {
                        names.push(witness);
                    }
                }

                names
            }
        };

        let mut signers = HashSet::new();
        for name in names {
            if let Some(key) = self.members.get(&name) {
                signers.insert(key.clone());
            }
        }

        Ok(signers)
    }

    /// Get the quorum for the role and schema.
    /// # Arguments
    /// * [`Roles`] - The role.
    /// * `schema_id` - The schema id from [`Schema`].
    /// # Returns
    /// * Option<[`Quorum`]> - The quorum.
    fn get_quorum(
        &self,
        role: ProtocolTypes,
        schema_id: &SchemaType,
    ) -> Option<Quorum> {
        if schema_id.is_gov() {
            self.policies_gov.get_quorum(role)
        } else {
            let policie = self.policies_schema.get(schema_id)?;

            policie.get_quorum(role)
        }
    }

    /// Get the quorum and signers for the role and schema.
    /// # Arguments
    /// * [`Roles`] - The role.
    /// * `schema_id` - The schema id from [`Schema`].
    /// * [`Namespace`] - The namespace.
    /// # Returns
    /// * (HashSet<[`PublicKey`]>, [`Quorum`]) - The set of key identifiers and the quorum.
    pub fn get_quorum_and_signers(
        &self,
        role: ProtocolTypes,
        schema_id: &SchemaType,
        namespace: Namespace,
    ) -> Result<(HashSet<PublicKey>, Quorum), GovernanceError> {
        let (signers, _not_members) = self.get_signers(
            RoleTypes::from(role.clone()),
            schema_id,
            namespace,
        );

        let Some(quorum) = self.get_quorum(role.clone(), schema_id) else {
            return Err(GovernanceError::QuorumNotFound {
                role: role.to_string(),
                schema_id: schema_id.to_string(),
            });
        };

        Ok((signers, quorum))
    }

    pub fn schemas_name(
        &self,
        role: ProtocolTypes,
        key: &PublicKey,
    ) -> BTreeSet<SchemaType> {
        let Some(name) = self
            .members
            .iter()
            .find(|x| x.1 == key)
            .map(|x| x.0)
            .cloned()
        else {
            return BTreeSet::new();
        };

        if self
            .roles_tracker_schemas
            .hash_this_rol_not_namespace(role.clone(), &name)
        {
            return self.schemas.keys().cloned().collect();
        }

        let mut schemas: BTreeSet<SchemaType> = BTreeSet::new();

        for (schema_id, roles) in self.roles_schema.iter() {
            if roles.hash_this_rol_not_namespace(role.clone(), &name) {
                schemas.insert(schema_id.clone());
            }
        }

        schemas
    }

    pub fn schemas_namespace(
        &self,
        role: ProtocolTypes,
        key: &PublicKey,
    ) -> BTreeMap<SchemaType, Vec<Namespace>> {
        let mut map = BTreeMap::new();

        let Some(name) = self
            .members
            .iter()
            .find(|x| x.1 == key)
            .map(|x| x.0)
            .cloned()
        else {
            return map;
        };

        let vec = self
            .roles_tracker_schemas
            .role_namespace(role.clone(), &name);

        if !vec.is_empty() {
            map.insert(SchemaType::TrackerSchemas, vec);
        }

        for (schema_id, roles) in self.roles_schema.iter() {
            let vec = roles.role_namespace(role.clone(), &name);
            if !vec.is_empty() {
                map.insert(schema_id.clone(), vec);
            }
        }
        map
    }

    pub fn schema_creators_namespace(
        &self,
        schema_namespaces: BTreeMap<SchemaType, Vec<Namespace>>,
    ) -> BTreeMap<SchemaType, BTreeMap<PublicKey, BTreeSet<Namespace>>> {
        let mut map: BTreeMap<
            SchemaType,
            BTreeMap<PublicKey, BTreeSet<Namespace>>,
        > = BTreeMap::new();

        for (schema_id, namespace) in schema_namespaces {
            if schema_id == SchemaType::TrackerSchemas {
                for (schema_id, roles) in self.roles_schema.iter() {
                    let schema_entry =
                        map.entry(schema_id.clone()).or_default();
                    for ns in namespace.iter() {
                        for user in roles.creator.iter() {
                            if ns.is_ancestor_or_equal_of(&user.namespace)
                                && let Some(pub_key) =
                                    self.members.get(&user.name)
                            {
                                schema_entry
                                    .entry(pub_key.clone())
                                    .or_default()
                                    .insert(user.namespace.clone());
                            }
                        }
                    }
                }
            } else if let Some(roles) = self.roles_schema.get(&schema_id) {
                let schema_entry = map.entry(schema_id).or_default();
                for ns in namespace.iter() {
                    for user in roles.creator.iter() {
                        if ns.is_ancestor_or_equal_of(&user.namespace)
                            && let Some(pub_key) = self.members.get(&user.name)
                        {
                            schema_entry
                                .entry(pub_key.clone())
                                .or_default()
                                .insert(user.namespace.clone());
                        }
                    }
                }
            }
        }

        map
    }

    pub fn schemas(
        &self,
        role: ProtocolTypes,
        key: &PublicKey,
    ) -> BTreeMap<SchemaType, Schema> {
        let Some(name) = self
            .members
            .iter()
            .find(|x| x.1 == key)
            .map(|x| x.0)
            .cloned()
        else {
            return BTreeMap::new();
        };

        if self
            .roles_tracker_schemas
            .hash_this_rol_not_namespace(role.clone(), &name)
        {
            return self.schemas.clone();
        }

        let mut not_schemas: Vec<SchemaType> = vec![];

        for (schema_id, roles) in self.roles_schema.iter() {
            if !roles.hash_this_rol_not_namespace(role.clone(), &name) {
                not_schemas.push(schema_id.clone());
            }
        }

        let mut copy_schemas = self.schemas.clone();
        for schema_id in not_schemas {
            copy_schemas.remove(&schema_id);
        }

        copy_schemas
    }

    pub fn schemas_init_value(
        &self,
        role: ProtocolTypes,
        key: &PublicKey,
    ) -> BTreeMap<SchemaType, ValueWrapper> {
        let Some(name) = self
            .members
            .iter()
            .find(|x| x.1 == key)
            .map(|x| x.0)
            .cloned()
        else {
            return BTreeMap::new();
        };

        if self
            .roles_tracker_schemas
            .hash_this_rol_not_namespace(role.clone(), &name)
        {
            return self
                .schemas
                .iter()
                .map(|x| (x.0.clone(), x.1.initial_value.clone()))
                .collect();
        }

        let mut not_schemas: Vec<SchemaType> = vec![];

        for (schema_id, roles) in self.roles_schema.iter() {
            if !roles.hash_this_rol_not_namespace(role.clone(), &name) {
                not_schemas.push(schema_id.clone());
            }
        }

        let mut copy_schemas = self.schemas.clone();
        for schema_id in not_schemas {
            copy_schemas.remove(&schema_id);
        }

        copy_schemas
            .iter()
            .map(|x| (x.0.clone(), x.1.initial_value.clone()))
            .collect()
    }

    /// Check if the key is a member.
    pub fn is_member(&self, key: &PublicKey) -> bool {
        self.members.iter().any(|x| x.1 == key)
    }
}

impl TryFrom<ValueWrapper> for GovernanceData {
    type Error = GovernanceError;

    fn try_from(value: ValueWrapper) -> Result<Self, Self::Error> {
        let governance: Self =
            serde_json::from_value(value.0).map_err(|e| {
                GovernanceError::ConversionFailed {
                    details: e.to_string(),
                }
            })?;
        Ok(governance)
    }
}
