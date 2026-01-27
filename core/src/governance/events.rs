use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ave_common::{
    Namespace, SchemaType, identity::PublicKey, schematype::ReservedWords,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    evaluation::runner::error::{self, RunnerError},
    governance::{
        CreatorRoleUpdate, RolesUpdate, RolesUpdateRemove,
        data::GovernanceData,
        model::{Quorum, Role},
        witnesses_register::WitnessesType,
    },
};

use super::model::{
    CreatorQuantity, RoleCreator, RolesAllSchemas, RolesGov, RolesSchema,
};

pub type MemberName = String;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovernanceEvent {
    pub members: Option<MemberEvent>,
    pub roles: Option<RolesEvent>,
    pub schemas: Option<SchemasEvent>,
    pub policies: Option<PoliciesEvent>,
}

impl GovernanceEvent {
    pub fn update_creator_change(
        &self,
        members: &BTreeMap<MemberName, PublicKey>,
        roles_schema: &BTreeMap<SchemaType, RolesSchema>,
    ) -> CreatorRoleUpdate {
        let mut new_creator: HashMap<
            (SchemaType, String, PublicKey),
            (CreatorQuantity, BTreeSet<String>),
        > = HashMap::new();

        let mut update_creator_quantity: HashSet<(
            SchemaType,
            String,
            PublicKey,
            CreatorQuantity,
        )> = HashSet::new();

        let mut update_creator_witnesses: HashSet<(
            SchemaType,
            String,
            PublicKey,
            BTreeSet<String>,
        )> = HashSet::new();

        let mut remove_creator: HashSet<(SchemaType, String, PublicKey)> =
            HashSet::new();

        if let Some(roles) = &self.roles {
            if let Some(schemas) = &roles.schema {
                for schema in schemas {
                    if let Some(change) = &schema.change {
                        if let Some(creator) = &change.creator {
                            if let Some(roles) =
                                roles_schema.get(&schema.schema_id)
                            {
                                creator.iter().for_each(|x| {
                                    if let Some(user) = members.get(&x.actual_name) {
                                        if let Some(new_namespace) = &x.new_namespace {
                                            remove_creator.insert((
                                                schema.schema_id.clone(),
                                                x.actual_namespace.to_string(),
                                                user.clone(),
                                            ));

                                            match (&x.new_witnesses, &x.new_quantity) {
                                                (None, None) => {
                                                    if let Some(creator) =
                                                        roles.creator.get(&RoleCreator {
                                                            name: x.actual_name.clone(),
                                                            namespace: x.actual_namespace.clone(),
                                                            witnesses: BTreeSet::new(),
                                                            quantity: CreatorQuantity::Infinity,
                                                        })
                                                    {
                                                        if let Some(user) = members.get(&creator.name) {
                                                            new_creator.insert(
                                                                (
                                                                    schema.schema_id.clone(),
                                                                    new_namespace.to_string(),
                                                                    user.clone(),
                                                                ),
                                                                (
                                                                    creator.quantity.clone(),
                                                                    creator.witnesses.clone(),
                                                                ),
                                                            );
                                                        }
                                                    }
                                                }
                                                (None, Some(q)) => {
                                                    if let Some(creator) =
                                                        roles.creator.get(&RoleCreator {
                                                            name: x.actual_name.clone(),
                                                            namespace: x.actual_namespace.clone(),
                                                            witnesses: BTreeSet::new(),
                                                            quantity: CreatorQuantity::Infinity,
                                                        })
                                                    {
                                                        if let Some(user) = members.get(&creator.name) {
                                                            new_creator.insert(
                                                                (
                                                                    schema.schema_id.clone(),
                                                                    new_namespace.to_string(),
                                                                    user.clone(),
                                                                ),
                                                                (q.clone(), creator.witnesses.clone()),
                                                            );
                                                        }
                                                    }
                                                }
                                                (Some(w), None) => {
                                                    if let Some(creator) =
                                                        roles.creator.get(&RoleCreator {
                                                            name: x.actual_name.clone(),
                                                            namespace: x.actual_namespace.clone(),
                                                            witnesses: BTreeSet::new(),
                                                            quantity: CreatorQuantity::Infinity,
                                                        })
                                                    {
                                                        if let Some(user) = members.get(&creator.name) {
                                                            new_creator.insert(
                                                                (
                                                                    schema.schema_id.clone(),
                                                                    new_namespace.to_string(),
                                                                    user.clone(),
                                                                ),
                                                                (creator.quantity.clone(), w.clone()),
                                                            );
                                                        }
                                                    }
                                                }
                                                (Some(w), Some(q)) => {
                                                    new_creator.insert(
                                                        (
                                                            schema.schema_id.clone(),
                                                            new_namespace.to_string(),
                                                            user.clone(),
                                                        ),
                                                        (q.clone(), w.clone()),
                                                    );
                                                }
                                            }
                                        } else {
                                            if let Some(q) = &x.new_quantity {
                                                update_creator_quantity.insert((
                                                    schema.schema_id.clone(),
                                                    x.actual_namespace.to_string(),
                                                    user.clone(),
                                                    q.clone(),
                                                ));
                                            }

                                            if let Some(w) = &x.new_witnesses {
                                                update_creator_witnesses.insert((
                                                    schema.schema_id.clone(),
                                                    x.actual_namespace.to_string(),
                                                    user.clone(),
                                                    w.clone(),
                                                ));
                                            }
                                        }
                                    }
                                });
                            }
                        }
                    }
                }
            }
        }

        CreatorRoleUpdate {
            new_creator,
            update_creator_quantity,
            update_creator_witnesses,
            remove_creator,
        }
    }

    pub fn roles_update(
        &self,
        members: &BTreeMap<MemberName, PublicKey>,
        rm_roles: Option<RolesUpdateRemove>,
    ) -> RolesUpdate {
        let mut appr_quorum: Option<Quorum> = None;
        let mut eval_quorum: HashMap<SchemaType, Quorum> = HashMap::new();
        let mut vali_quorum: HashMap<SchemaType, Quorum> = HashMap::new();

        let mut new_approvers: Vec<PublicKey> = vec![];
        let mut remove_approvers: Vec<PublicKey> = vec![];

        let mut new_evaluators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let mut remove_evaluators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let mut new_validators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let mut remove_validators: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let mut new_creator: HashMap<
            (SchemaType, String, PublicKey),
            (CreatorQuantity, Vec<WitnessesType>),
        > = HashMap::new();

        let mut remove_creator: HashSet<(SchemaType, String, PublicKey)> =
            HashSet::new();

        let mut new_witnesses: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        let mut remove_witnesses: HashMap<
            (SchemaType, PublicKey),
            Vec<Namespace>,
        > = HashMap::new();

        if let Some(schema) = &self.schemas
            && let Some(schema_add) = &schema.add
        {
            for schema_data in schema_add {
                eval_quorum.insert(schema_data.id.clone(), Quorum::Majority);
                vali_quorum.insert(schema_data.id.clone(), Quorum::Majority);
            }
        }

        if let Some(roles) = &self.roles {
            // Gov
            if let Some(governance) = &roles.governance {
                if let Some(add) = &governance.add {
                    if let Some(approvers) = &add.approver {
                        approvers.iter().for_each(|x| {
                            if let Some(user) = members.get(x) {
                                new_approvers.push(user.clone());
                            }
                        });
                    }

                    if let Some(evaluators) = &add.evaluator {
                        evaluators.iter().for_each(|x| {
                            if let Some(user) = members.get(x) {
                                new_evaluators
                                    .entry((
                                        SchemaType::Governance,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(Namespace::new());
                            }
                        });
                    }

                    if let Some(validators) = &add.validator {
                        validators.iter().for_each(|x| {
                            if let Some(user) = members.get(x) {
                                new_validators
                                    .entry((
                                        SchemaType::Governance,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(Namespace::new());
                            }
                        });
                    }
                }
                if let Some(remove) = &governance.remove {
                    if let Some(approvers) = &remove.approver {
                        approvers.iter().for_each(|x| {
                            if let Some(user) = members.get(x) {
                                remove_approvers.push(user.clone());
                            }
                        });
                    }

                    if let Some(evaluators) = &remove.evaluator {
                        evaluators.iter().for_each(|x| {
                            if let Some(user) = members.get(x) {
                                remove_evaluators
                                    .entry((
                                        SchemaType::Governance,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(Namespace::new());
                            }
                        });
                    }

                    if let Some(validators) = &remove.validator {
                        validators.iter().for_each(|x| {
                            if let Some(user) = members.get(x) {
                                remove_validators
                                    .entry((
                                        SchemaType::Governance,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(Namespace::new());
                            }
                        });
                    }
                }
            }

            // all schemas
            if let Some(all_schemas) = &roles.all_schemas {
                if let Some(add) = &all_schemas.add {
                    if let Some(evaluators) = &add.evaluator {
                        evaluators.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.name) {
                                new_evaluators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.namespace.clone());
                            }
                        });
                    }

                    if let Some(validators) = &add.validator {
                        validators.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.name) {
                                new_validators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.namespace.clone());
                            }
                        });
                    }

                    if let Some(witnesses) = &add.witness {
                        witnesses.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.name) {
                                new_witnesses
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.namespace.clone());
                            }
                        });
                    }
                }
                if let Some(remove) = &all_schemas.remove {
                    if let Some(evaluators) = &remove.evaluator {
                        evaluators.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.name) {
                                remove_evaluators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.namespace.clone());
                            }
                        });
                    }

                    if let Some(validators) = &remove.validator {
                        validators.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.name) {
                                remove_validators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.namespace.clone());
                            }
                        });
                    }

                    if let Some(witnesses) = &remove.witness {
                        witnesses.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.name) {
                                remove_witnesses
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.namespace.clone());
                            }
                        });
                    }
                }
                if let Some(change) = &all_schemas.change {
                    if let Some(evaluators) = &change.evaluator {
                        evaluators.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.actual_name) {
                                remove_evaluators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.actual_namespace.clone());

                                new_evaluators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.new_namespace.clone());
                            }
                        });
                    }

                    if let Some(validators) = &change.validator {
                        validators.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.actual_name) {
                                remove_validators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.actual_namespace.clone());

                                new_validators
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.new_namespace.clone());
                            }
                        });
                    }

                    if let Some(witnesses) = &change.witness {
                        witnesses.iter().for_each(|x| {
                            if let Some(user) = members.get(&x.actual_name) {
                                remove_witnesses
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.actual_namespace.clone());

                                new_witnesses
                                    .entry((
                                        SchemaType::AllSchemas,
                                        user.clone(),
                                    ))
                                    .or_default()
                                    .push(x.new_namespace.clone());
                            }
                        });
                    }
                }
            }

            // schema
            if let Some(schemas) = &roles.schema {
                for schema in schemas {
                    if let Some(add) = &schema.add {
                        if let Some(evaluators) = &add.evaluator {
                            evaluators.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    new_evaluators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.namespace.clone());
                                }
                            });
                        }
                        if let Some(validators) = &add.validator {
                            validators.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    new_validators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.namespace.clone());
                                }
                            });
                        }
                        if let Some(creator) = &add.creator {
                            creator.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    let mut witnesses = vec![];
                                    for witness in x.witnesses.iter() {
                                        if witness
                                            == &ReservedWords::Witnesses
                                                .to_string()
                                        {
                                            witnesses
                                                .push(WitnessesType::Witnesses);
                                        } else {
                                            if let Some(w) =
                                                members.get(witness)
                                            {
                                                witnesses.push(
                                                    WitnessesType::User(
                                                        w.clone(),
                                                    ),
                                                );
                                            }
                                        }
                                    }

                                    new_creator.insert(
                                        (
                                            schema.schema_id.clone(),
                                            x.namespace.to_string(),
                                            user.clone(),
                                        ),
                                        (x.quantity.clone(), witnesses),
                                    );
                                }
                            });
                        }

                        if let Some(witnesses) = &add.witness {
                            witnesses.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    new_witnesses
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.namespace.clone());
                                }
                            });
                        }
                    }

                    if let Some(remove) = &schema.remove {
                        if let Some(evaluators) = &remove.evaluator {
                            evaluators.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    remove_evaluators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.namespace.clone());
                                }
                            });
                        }
                        if let Some(validators) = &remove.validator {
                            validators.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    remove_validators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.namespace.clone());
                                }
                            });
                        }
                        if let Some(creator) = &remove.creator {
                            creator.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    remove_creator.insert((
                                        schema.schema_id.clone(),
                                        x.namespace.to_string(),
                                        user.clone(),
                                    ));
                                }
                            });
                        }
                        if let Some(witnesses) = &remove.witness {
                            witnesses.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.name) {
                                    remove_witnesses
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.namespace.clone());
                                }
                            });
                        }
                    }
                    if let Some(change) = &schema.change {
                        if let Some(evaluators) = &change.evaluator {
                            evaluators.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.actual_name)
                                {
                                    remove_evaluators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.actual_namespace.clone());

                                    new_evaluators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.new_namespace.clone());
                                }
                            });
                        }

                        if let Some(validators) = &change.validator {
                            validators.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.actual_name)
                                {
                                    remove_validators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.actual_namespace.clone());

                                    new_validators
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.new_namespace.clone());
                                }
                            });
                        }

                        if let Some(witnesses) = &change.witness {
                            witnesses.iter().for_each(|x| {
                                if let Some(user) = members.get(&x.actual_name)
                                {
                                    remove_witnesses
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.actual_namespace.clone());

                                    new_witnesses
                                        .entry((
                                            schema.schema_id.clone(),
                                            user.clone(),
                                        ))
                                        .or_default()
                                        .push(x.new_namespace.clone());
                                }
                            });
                        }
                    }
                }
            }
        }

        if let Some(policies) = &self.policies {
            // gov
            if let Some(governance) = &policies.governance {
                appr_quorum = governance.change.approve.clone();

                if let Some(quorum) = &governance.change.evaluate {
                    eval_quorum.insert(SchemaType::Governance, quorum.clone());
                }
                if let Some(quorum) = &governance.change.validate {
                    vali_quorum.insert(SchemaType::Governance, quorum.clone());
                }
            }

            // schemas
            if let Some(schemas) = &policies.schema {
                for schema in schemas {
                    if let Some(quorum) = &schema.change.evaluate {
                        eval_quorum
                            .insert(schema.schema_id.clone(), quorum.clone());
                    }
                    if let Some(quorum) = &schema.change.validate {
                        vali_quorum
                            .insert(schema.schema_id.clone(), quorum.clone());
                    }
                }
            }
        }

        if let Some(rm) = rm_roles {
            remove_witnesses.extend(rm.witnesses);
            remove_creator.extend(rm.creator);
            remove_approvers.extend(rm.approvers);
            remove_evaluators.extend(rm.evaluators);
            remove_validators.extend(rm.validators);
        }

        RolesUpdate {
            appr_quorum,
            new_evaluators,
            new_validators,
            eval_quorum,
            new_approvers,
            remove_approvers,
            vali_quorum,
            remove_evaluators,
            remove_validators,
            new_creator,
            remove_creator,
            new_witnesses,
            remove_witnesses,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.members.is_none()
            && self.roles.is_none()
            && self.schemas.is_none()
            && self.policies.is_none()
    }
}

///// Members /////
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberEvent {
    pub add: Option<HashSet<NewMember>>,
    pub remove: Option<HashSet<MemberName>>,
}

impl MemberEvent {
    pub fn is_empty(&self) -> bool {
        self.add.is_none() && self.remove.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct NewMember {
    pub name: MemberName,
    pub key: PublicKey,
}

///// Roles /////
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RolesEvent {
    pub governance: Option<GovRoleEvent>,
    pub all_schemas: Option<AllSchemasRoleEvent>,
    pub schema: Option<HashSet<SchemaIdRole>>,
}

impl RolesEvent {
    pub fn is_empty(&self) -> bool {
        self.governance.is_none()
            && self.schema.is_none()
            && self.all_schemas.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct GovRoleEvent {
    pub add: Option<GovRolesEvent>,
    pub remove: Option<GovRolesEvent>,
}

impl GovRoleEvent {
    pub fn is_empty(&self) -> bool {
        self.add.is_none() && self.remove.is_none()
    }

    pub fn check_data(
        &self,
        governance: &GovernanceData,
        new_roles: &mut RolesGov,
    ) -> Result<(), RunnerError> {
        // Validar que cada (role_type, name) solo aparezca una vez
        let mut seen_roles: HashSet<(String, String)> = HashSet::new();

        // Helper para registrar un rol y detectar duplicados
        let mut check_and_register = |role_type: &str,
                                      name: &str|
         -> Result<(), RunnerError> {
            let key = (role_type.to_string(), name.to_string());
            if !seen_roles.insert(key) {
                return Err(RunnerError::InvalidEvent {
                    location: "GovRoleEvent::check_data",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: format!("{} role operation", role_type),
                        reason: format!(
                            "Role {} appears multiple times in the same event. Only one operation per role is allowed.",
                            name
                        ),
                    },
                });
            }
            Ok(())
        };

        // Validar add operations
        if let Some(ref add) = self.add {
            if let Some(ref approvers) = add.approver {
                for approver in approvers {
                    check_and_register("approver", approver)?;
                }
            }
            if let Some(ref evaluators) = add.evaluator {
                for evaluator in evaluators {
                    check_and_register("evaluator", evaluator)?;
                }
            }
            if let Some(ref validators) = add.validator {
                for validator in validators {
                    check_and_register("validator", validator)?;
                }
            }
            if let Some(ref witnesses) = add.witness {
                for witness in witnesses {
                    check_and_register("witness", witness)?;
                }
            }
            if let Some(ref issuers) = add.issuer {
                for issuer in issuers {
                    check_and_register("issuer", issuer)?;
                }
            }
        }

        // Validar remove operations
        if let Some(ref remove) = self.remove {
            if let Some(ref approvers) = remove.approver {
                for approver in approvers {
                    check_and_register("approver", approver)?;
                }
            }
            if let Some(ref evaluators) = remove.evaluator {
                for evaluator in evaluators {
                    check_and_register("evaluator", evaluator)?;
                }
            }
            if let Some(ref validators) = remove.validator {
                for validator in validators {
                    check_and_register("validator", validator)?;
                }
            }
            if let Some(ref witnesses) = remove.witness {
                for witness in witnesses {
                    check_and_register("witness", witness)?;
                }
            }
            if let Some(ref issuers) = remove.issuer {
                for issuer in issuers {
                    check_and_register("issuer", issuer)?;
                }
            }
        }

        if let Some(add) = self.add.clone() {
            if add.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "GovRoleEvent::check_data",
                    kind: error::InvalidEventKind::Empty {
                        what: "GovRoleEvent add".to_owned(),
                    },
                });
            }

            let members: HashSet<String> =
                governance.members.keys().cloned().collect();

            // Approvers
            if let Some(approvers) = add.approver {
                if approvers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "approvers vec".to_owned(),
                        },
                    });
                }

                for mut approver in approvers {
                    approver = approver.trim().to_owned();

                    if approver.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: "approver name".to_owned(),
                            },
                        });
                    }

                    if approver.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: "approver name".to_owned(),
                                actual: approver.len(),
                                max: 100,
                            },
                        });
                    }

                    if !members.contains(&approver) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: approver.clone(),
                            },
                        });
                    }

                    if !new_roles.approver.insert(approver.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "governance approver".to_owned(),
                                id: approver,
                            },
                        });
                    };
                }
            }

            // Evaluators
            if let Some(evaluators) = add.evaluator {
                if evaluators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "evaluators vec in governance roles add"
                                .to_owned(),
                        },
                    });
                }

                for mut evaluator in evaluators {
                    evaluator = evaluator.trim().to_owned();

                    if evaluator.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: "evaluator name".to_owned(),
                            },
                        });
                    }

                    if evaluator.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: "evaluator name".to_owned(),
                                actual: evaluator.len(),
                                max: 100,
                            },
                        });
                    }

                    if !members.contains(&evaluator) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: evaluator.clone(),
                            },
                        });
                    }

                    if !new_roles.evaluator.insert(evaluator.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "governance evaluator".to_owned(),
                                id: evaluator,
                            },
                        });
                    };
                }
            }

            // Validators
            if let Some(validators) = add.validator {
                if validators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "validators vec in governance roles add"
                                .to_owned(),
                        },
                    });
                }

                for mut validator in validators {
                    validator = validator.trim().to_owned();

                    if validator.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: "validator name".to_owned(),
                            },
                        });
                    }

                    if validator.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: "validator name".to_owned(),
                                actual: validator.len(),
                                max: 100,
                            },
                        });
                    }

                    if !members.contains(&validator) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: validator.clone(),
                            },
                        });
                    }

                    if !new_roles.validator.insert(validator.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "governance validator".to_owned(),
                                id: validator,
                            },
                        });
                    };
                }
            }

            // Witnesses
            if let Some(witnesses) = add.witness {
                if witnesses.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "witnesses vec in governance roles add"
                                .to_owned(),
                        },
                    });
                }

                for mut witness in witnesses {
                    witness = witness.trim().to_owned();

                    if witness.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: "witness name".to_owned(),
                            },
                        });
                    }

                    if witness.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: "witness name".to_owned(),
                                actual: witness.len(),
                                max: 100,
                            },
                        });
                    }

                    if !members.contains(&witness) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: witness.clone(),
                            },
                        });
                    }

                    if !new_roles.witness.insert(witness.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "governance witness".to_owned(),
                                id: witness,
                            },
                        });
                    };
                }
            }

            // Issuers
            if let Some(issuers) = add.issuer {
                if issuers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "issuers vec in governance roles add"
                                .to_owned(),
                        },
                    });
                }

                for mut issuer in issuers {
                    issuer = issuer.trim().to_owned();

                    if issuer.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: "issuer name".to_owned(),
                            },
                        });
                    }

                    if issuer.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: "issuer name".to_owned(),
                                actual: issuer.len(),
                                max: 100,
                            },
                        });
                    }

                    if issuer != ReservedWords::Any.to_string() {
                        if !members.contains(&issuer) {
                            return Err(RunnerError::InvalidEvent {
                                location: "GovRoleEvent::check_data",
                                kind: error::InvalidEventKind::NotMember {
                                    who: issuer.clone(),
                                },
                            });
                        }

                        if !new_roles.issuer.users.insert(issuer.clone()) {
                            return Err(RunnerError::InvalidEvent {
                                location: "GovRoleEvent::check_data",
                                kind: error::InvalidEventKind::AlreadyExists {
                                    what: "governance issuer".to_owned(),
                                    id: issuer,
                                },
                            });
                        };
                    } else {
                        new_roles.issuer.any = true;
                    }
                }
            }
        }

        if let Some(remove) = self.remove.clone() {
            if remove.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "GovRoleEvent::check_data",
                    kind: error::InvalidEventKind::Empty {
                        what: "GovRoleEvent remove".to_owned(),
                    },
                });
            }

            // Approvers
            if let Some(approvers) = remove.approver {
                if approvers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "approvers vec in governance roles remove"
                                .to_owned(),
                        },
                    });
                }

                for approver in approvers {
                    if !new_roles.approver.remove(&approver) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: format!("approver {}", approver),
                                reason: "does not have this role".to_owned(),
                            },
                        });
                    }
                }
            }

            // Evaluators
            if let Some(evaluators) = remove.evaluator {
                if evaluators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "evaluators vec in governance roles remove"
                                .to_owned(),
                        },
                    });
                }

                for evaluator in evaluators {
                    if !new_roles.evaluator.remove(&evaluator) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: format!("evaluator {}", evaluator),
                                reason: "does not have this role".to_owned(),
                            },
                        });
                    }
                }
            }

            // Validators
            if let Some(validators) = remove.validator {
                if validators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "validators vec in governance roles remove"
                                .to_owned(),
                        },
                    });
                }
                for validator in validators {
                    if !new_roles.validator.remove(&validator) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: format!("validator {}", validator),
                                reason: "does not have this role".to_owned(),
                            },
                        });
                    }
                }
            }

            // Witnesses
            if let Some(witnesses) = remove.witness {
                if witnesses.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "witnesses vec in governance roles remove"
                                .to_owned(),
                        },
                    });
                }
                for witness in witnesses {
                    if !new_roles.witness.remove(&witness) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: format!("witness {}", witness),
                                reason: "does not have this role".to_owned(),
                            },
                        });
                    };
                }
            }

            // Issuers
            if let Some(issuers) = remove.issuer {
                if issuers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "issuers vec in governance roles remove"
                                .to_owned(),
                        },
                    });
                }
                for issuer in issuers {
                    if issuer != ReservedWords::Any.to_string() {
                        if !new_roles.issuer.users.remove(&issuer) {
                            return Err(RunnerError::InvalidEvent {
                                location: "GovRoleEvent::check_data",
                                kind: error::InvalidEventKind::CannotRemove {
                                    what: format!("issuer {}", issuer),
                                    reason: "does not have this role"
                                        .to_owned(),
                                },
                            });
                        };
                    } else {
                        new_roles.issuer.any = false;
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SchemaIdRole {
    pub schema_id: SchemaType,
    pub add: Option<SchemaRolesAddEvent>,
    pub remove: Option<SchemaRolesRemoveEvent>,
    pub change: Option<SchemaRolesChangeEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct AllSchemasRoleEvent {
    pub add: Option<AllSchemasRolesAddEvent>,
    pub remove: Option<AllSchemasRolesRemoveEvent>,
    pub change: Option<AllSchemasRolesChangeEvent>,
}

impl AllSchemasRoleEvent {
    pub fn check_data(
        &self,
        governance: &GovernanceData,
        roles_not_gov: RolesAllSchemas,
        schema_id: &SchemaType,
    ) -> Result<RolesAllSchemas, RunnerError> {
        let schema_role = SchemaIdRole::from(self.clone());

        let mut roles_schema = RolesSchema::from(roles_not_gov);
        schema_role.check_data(governance, &mut roles_schema, schema_id)?;
        let roles_not_gov = RolesAllSchemas::from(roles_schema.clone());
        Ok(roles_not_gov)
    }
}

impl From<AllSchemasRoleEvent> for SchemaIdRole {
    fn from(value: AllSchemasRoleEvent) -> Self {
        Self {
            schema_id: SchemaType::AllSchemas,
            add: value.add.map(SchemaRolesAddEvent::from),
            remove: value.remove.map(SchemaRolesRemoveEvent::from),
            change: value.change.map(SchemaRolesChangeEvent::from),
        }
    }
}

impl SchemaIdRole {
    pub fn is_empty(&self) -> bool {
        !self.schema_id.is_valid()
            || self.add.is_none()
                && self.change.is_none()
                && self.remove.is_none()
    }

    pub fn check_data(
        &self,
        governance: &GovernanceData,
        roles_schema: &mut RolesSchema,
        schema_id: &SchemaType,
    ) -> Result<(), RunnerError> {
        // Validar que cada (role_type, name, namespace) solo aparezca una vez
        let mut seen_roles: HashSet<(String, String, String)> = HashSet::new();

        // Helper para registrar un rol y detectar duplicados
        let mut check_and_register = |role_type: &str,
                                      name: &str,
                                      namespace: &Namespace|
         -> Result<(), RunnerError> {
            let key = (
                role_type.to_string(),
                name.to_string(),
                namespace.to_string(),
            );
            if !seen_roles.insert(key) {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: format!("{} role operation", role_type),
                        reason: format!(
                            "Role ({}, {}) appears multiple times in the same event. Only one operation per role is allowed.",
                            name, namespace
                        ),
                    },
                });
            }
            Ok(())
        };

        // Validar add operations
        if let Some(ref add) = self.add {
            if let Some(ref evaluators) = add.evaluator {
                for eval in evaluators {
                    check_and_register(
                        "evaluator",
                        &eval.name,
                        &eval.namespace,
                    )?;
                }
            }
            if let Some(ref validators) = add.validator {
                for val in validators {
                    check_and_register("validator", &val.name, &val.namespace)?;
                }
            }
            if let Some(ref witnesses) = add.witness {
                for wit in witnesses {
                    check_and_register("witness", &wit.name, &wit.namespace)?;
                }
            }
            if let Some(ref creators) = add.creator {
                for creator in creators {
                    check_and_register(
                        "creator",
                        &creator.name,
                        &creator.namespace,
                    )?;
                }
            }
            if let Some(ref issuers) = add.issuer {
                for issuer in issuers {
                    check_and_register(
                        "issuer",
                        &issuer.name,
                        &issuer.namespace,
                    )?;
                }
            }
        }

        // Validar change operations
        if let Some(ref change) = self.change {
            if let Some(ref evaluators) = change.evaluator {
                for eval in evaluators {
                    check_and_register(
                        "evaluator",
                        &eval.actual_name,
                        &eval.actual_namespace,
                    )?;
                }
            }
            if let Some(ref validators) = change.validator {
                for val in validators {
                    check_and_register(
                        "validator",
                        &val.actual_name,
                        &val.actual_namespace,
                    )?;
                }
            }
            if let Some(ref witnesses) = change.witness {
                for wit in witnesses {
                    check_and_register(
                        "witness",
                        &wit.actual_name,
                        &wit.actual_namespace,
                    )?;
                }
            }
            if let Some(ref creators) = change.creator {
                for creator in creators {
                    check_and_register(
                        "creator",
                        &creator.actual_name,
                        &creator.actual_namespace,
                    )?;
                }
            }
            if let Some(ref issuers) = change.issuer {
                for issuer in issuers {
                    check_and_register(
                        "issuer",
                        &issuer.actual_name,
                        &issuer.actual_namespace,
                    )?;
                }
            }
        }

        // Validar remove operations
        if let Some(ref remove) = self.remove {
            if let Some(ref evaluators) = remove.evaluator {
                for eval in evaluators {
                    check_and_register(
                        "evaluator",
                        &eval.name,
                        &eval.namespace,
                    )?;
                }
            }
            if let Some(ref validators) = remove.validator {
                for val in validators {
                    check_and_register("validator", &val.name, &val.namespace)?;
                }
            }
            if let Some(ref witnesses) = remove.witness {
                for wit in witnesses {
                    check_and_register("witness", &wit.name, &wit.namespace)?;
                }
            }
            if let Some(ref creators) = remove.creator {
                for creator in creators {
                    check_and_register(
                        "creator",
                        &creator.name,
                        &creator.namespace,
                    )?;
                }
            }
            if let Some(ref issuers) = remove.issuer {
                for issuer in issuers {
                    check_and_register(
                        "issuer",
                        &issuer.name,
                        &issuer.namespace,
                    )?;
                }
            }
        }

        let members: HashSet<String> =
            governance.members.keys().cloned().collect();

        if let Some(add) = self.add.clone() {
            if add.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaRolesEvent add".to_owned(),
                    },
                });
            }

            if let Some(evaluators) = add.evaluator {
                if evaluators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "evaluators vec in schema roles add"
                                .to_owned(),
                        },
                    });
                }

                for mut evaluator in evaluators {
                    evaluator.name = evaluator.name.trim().to_owned();

                    if evaluator.name.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: format!(
                                    "evaluator name in schema {}",
                                    schema_id
                                ),
                            },
                        });
                    }

                    if evaluator.name.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: format!(
                                    "evaluator name in schema {}",
                                    schema_id
                                ),
                                actual: evaluator.name.len(),
                                max: 100,
                            },
                        });
                    }

                    if !evaluator.namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "evaluator namespace in schema {}",
                                    schema_id
                                ),
                                reason: "namespace is invalid".to_owned(),
                            },
                        });
                    }

                    if !members.contains(&evaluator.name) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: evaluator.name.clone(),
                            },
                        });
                    }

                    if !roles_schema.evaluator.insert(evaluator.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: format!("schema {} evaluator", schema_id),
                                id: evaluator.name,
                            },
                        });
                    };
                }
            }

            if let Some(validators) = add.validator {
                if validators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "validators vec".to_owned(),
                        },
                    });
                }

                for mut validator in validators {
                    validator.name = validator.name.trim().to_owned();

                    if validator.name.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: format!(
                                    "validator name in schema {}",
                                    schema_id
                                ),
                            },
                        });
                    }

                    if validator.name.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: format!(
                                    "validator name in schema {}",
                                    schema_id
                                ),
                                actual: validator.name.len(),
                                max: 100,
                            },
                        });
                    }

                    if !validator.namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "validator namespace in schema {}",
                                    schema_id
                                ),
                                reason: "invalid namespace".to_owned(),
                            },
                        });
                    }

                    if !members.contains(&validator.name) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: validator.name.clone(),
                            },
                        });
                    }

                    if !roles_schema.validator.insert(validator.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "validator".to_owned(),
                                id: validator.name.clone(),
                            },
                        });
                    };
                }
            }

            if let Some(witnesses) = add.witness {
                if witnesses.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "witnesses vec".to_owned(),
                        },
                    });
                }

                for mut witness in witnesses {
                    witness.name = witness.name.trim().to_owned();

                    if witness.name.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: format!(
                                    "witness name in schema {}",
                                    schema_id
                                ),
                            },
                        });
                    }

                    if witness.name.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: format!(
                                    "witness name in schema {}",
                                    schema_id
                                ),
                                actual: witness.name.len(),
                                max: 100,
                            },
                        });
                    }

                    if !witness.namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "witness namespace in schema {}",
                                    schema_id
                                ),
                                reason: "invalid namespace".to_owned(),
                            },
                        });
                    }

                    if !members.contains(&witness.name) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: witness.name.clone(),
                            },
                        });
                    }

                    if !roles_schema.witness.insert(witness.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "witness".to_owned(),
                                id: witness.name.clone(),
                            },
                        });
                    };
                }
            }

            if let Some(creators) = add.creator {
                if creators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "creators vec".to_owned(),
                        },
                    });
                }

                for mut creator in creators {
                    creator.name = creator.name.trim().to_owned();

                    if creator.name.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: format!(
                                    "creator name in schema {}",
                                    schema_id
                                ),
                            },
                        });
                    }

                    if creator.name.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: format!(
                                    "creator name in schema {}",
                                    schema_id
                                ),
                                actual: creator.name.len(),
                                max: 100,
                            },
                        });
                    }

                    if !creator.quantity.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: "creator quantity".to_owned(),
                                reason: "cannot be 0".to_owned(),
                            },
                        });
                    }

                    if !creator.namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "creator namespace in schema {}",
                                    schema_id
                                ),
                                reason: "invalid namespace".to_owned(),
                            },
                        });
                    }

                    if !members.contains(&creator.name) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::NotMember {
                                who: creator.name.clone(),
                            },
                        });
                    }

                    for witness in creator.witnesses.iter() {
                        if witness != &ReservedWords::Witnesses.to_string()
                            && !members.contains(witness)
                        {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::NotMember {
                                    who: witness.clone(),
                                },
                            });
                        }
                    }

                    if !roles_schema.creator.insert(creator.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "creator".to_owned(),
                                id: creator.name.clone(),
                            },
                        });
                    };
                }
            }

            if let Some(issuers) = add.issuer {
                if issuers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "issuers vec".to_owned(),
                        },
                    });
                }

                for mut issuer in issuers {
                    issuer.name = issuer.name.trim().to_owned();

                    if issuer.name.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::Empty {
                                what: format!(
                                    "issuer name in schema {}",
                                    schema_id
                                ),
                            },
                        });
                    }

                    if issuer.name.len() > 100 {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidSize {
                                field: format!(
                                    "issuer name in schema {}",
                                    schema_id
                                ),
                                actual: issuer.name.len(),
                                max: 100,
                            },
                        });
                    }

                    if issuer.name != ReservedWords::Any.to_string() {
                        if !issuer.namespace.check() {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::InvalidValue {
                                    field: format!(
                                        "issuer namespace in schema {}",
                                        schema_id
                                    ),
                                    reason: "invalid namespace".to_owned(),
                                },
                            });
                        }

                        if !members.contains(&issuer.name) {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::NotMember {
                                    who: issuer.name.clone(),
                                },
                            });
                        }

                        if !roles_schema.issuer.users.insert(issuer.clone()) {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::AlreadyExists {
                                    what: "issuer".to_owned(),
                                    id: issuer.name.clone(),
                                },
                            });
                        };
                    } else {
                        if !issuer.namespace.is_empty() {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::InvalidValue {
                                    field: format!("issuer 'Any' namespace in schema {}", schema_id),
                                    reason: "namespace must be empty for 'Any' issuer".to_owned(),
                                },
                            });
                        }

                        roles_schema.issuer.any = true;
                    }
                }
            }
        }

        if let Some(remove) = self.remove.clone() {
            if remove.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaRolesEvent remove".to_owned(),
                    },
                });
            }

            if let Some(evaluators) = remove.evaluator {
                if evaluators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "evaluators vec in remove".to_owned(),
                        },
                    });
                }

                for evaluator in evaluators {
                    if !roles_schema.evaluator.remove(&evaluator) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "evaluator".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    evaluator.name,
                                    evaluator.namespace,
                                    schema_id
                                ),
                            },
                        });
                    };
                }
            }

            if let Some(validators) = remove.validator {
                if validators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "validators vec in remove".to_owned(),
                        },
                    });
                }

                for validator in validators {
                    if !roles_schema.validator.remove(&validator) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "validator".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    validator.name,
                                    validator.namespace,
                                    schema_id
                                ),
                            },
                        });
                    };
                }
            }

            if let Some(witnesses) = remove.witness {
                if witnesses.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "witnesses vec in remove".to_owned(),
                        },
                    });
                }

                for witness in witnesses {
                    if !roles_schema.witness.remove(&witness) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "witness".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    witness.name, witness.namespace, schema_id
                                ),
                            },
                        });
                    };
                }
            }

            if let Some(creators) = remove.creator {
                if creators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "creators vec in remove".to_owned(),
                        },
                    });
                }

                for creator in creators {
                    if !roles_schema.creator.remove(&RoleCreator::create(
                        &creator.name,
                        creator.namespace.clone(),
                    )) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "creator".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    creator.name, creator.namespace, schema_id
                                ),
                            },
                        });
                    }
                }
            }

            if let Some(issuers) = remove.issuer {
                if issuers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "issuers vec in remove".to_owned(),
                        },
                    });
                }

                for issuer in issuers {
                    if issuer.name != ReservedWords::Any.to_string() {
                        if !roles_schema.issuer.users.remove(&issuer) {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::CannotRemove {
                                    what: "issuer".to_owned(),
                                    reason: format!(
                                        "{} {} does not have this role in schema {}",
                                        issuer.name,
                                        issuer.namespace,
                                        schema_id
                                    ),
                                },
                            });
                        }
                    } else {
                        if !issuer.namespace.is_empty() {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::InvalidValue {
                                    field: "issuer 'Any' namespace in remove".to_owned(),
                                    reason: "namespace must be empty for 'Any' issuer".to_owned(),
                                },
                            });
                        }
                        roles_schema.issuer.any = false;
                    }
                }
            }
        }

        if let Some(change) = self.change.clone() {
            if change.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaRolesEvent change".to_owned(),
                    },
                });
            }

            if let Some(evaluators) = change.evaluator {
                if evaluators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "evaluators vec in change".to_owned(),
                        },
                    });
                }

                for evaluator in evaluators {
                    if !evaluator.new_namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "evaluator {} {} new namespace in schema {}",
                                    evaluator.actual_name,
                                    evaluator.actual_namespace,
                                    schema_id
                                ),
                                reason: "invalid new namespace".to_owned(),
                            },
                        });
                    }

                    if !roles_schema.evaluator.remove(&Role {
                        name: evaluator.actual_name.clone(),
                        namespace: evaluator.actual_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotModify {
                                what: "evaluator".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    evaluator.actual_name,
                                    evaluator.actual_namespace,
                                    schema_id
                                ),
                            },
                        });
                    };

                    if !roles_schema.evaluator.insert(Role {
                        name: evaluator.actual_name.clone(),
                        namespace: evaluator.new_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "evaluator with new namespace".to_owned(),
                                id: format!(
                                    "{} {} in schema {}",
                                    evaluator.actual_name,
                                    evaluator.new_namespace,
                                    schema_id
                                ),
                            },
                        });
                    }
                }
            }

            if let Some(validators) = change.validator {
                if validators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "validators vec in change".to_owned(),
                        },
                    });
                }

                for validator in validators {
                    if !validator.new_namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "validator {} {} new namespace in schema {}",
                                    validator.actual_name,
                                    validator.actual_namespace,
                                    schema_id
                                ),
                                reason: "invalid new namespace".to_owned(),
                            },
                        });
                    }

                    if !roles_schema.validator.remove(&Role {
                        name: validator.actual_name.clone(),
                        namespace: validator.actual_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotModify {
                                what: "validator".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    validator.actual_name,
                                    validator.actual_namespace,
                                    schema_id
                                ),
                            },
                        });
                    };

                    if !roles_schema.validator.insert(Role {
                        name: validator.actual_name.clone(),
                        namespace: validator.new_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "validator with new namespace".to_owned(),
                                id: format!(
                                    "{} {} in schema {}",
                                    validator.actual_name,
                                    validator.new_namespace,
                                    schema_id
                                ),
                            },
                        });
                    }
                }
            }

            if let Some(witnesses) = change.witness {
                if witnesses.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "witnesses vec in change".to_owned(),
                        },
                    });
                }

                for witness in witnesses {
                    if !witness.new_namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "witness {} {} new namespace in schema {}",
                                    witness.actual_name,
                                    witness.actual_namespace,
                                    schema_id
                                ),
                                reason: "invalid new namespace".to_owned(),
                            },
                        });
                    }

                    if !roles_schema.witness.remove(&Role {
                        name: witness.actual_name.clone(),
                        namespace: witness.actual_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotModify {
                                what: "witness".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    witness.actual_name,
                                    witness.actual_namespace,
                                    schema_id
                                ),
                            },
                        });
                    };

                    if !roles_schema.witness.insert(Role {
                        name: witness.actual_name.clone(),
                        namespace: witness.new_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "witness with new namespace".to_owned(),
                                id: format!(
                                    "{} {} in schema {}",
                                    witness.actual_name,
                                    witness.new_namespace,
                                    schema_id
                                ),
                            },
                        });
                    }
                }
            }

            if let Some(creators) = change.creator {
                if creators.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "creators vec in change".to_owned(),
                        },
                    });
                }

                for creator in creators {
                    if creator.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!("creator {} {} change in schema {}", creator.actual_name, creator.actual_namespace, schema_id),
                                reason: "must specify at least one of: new namespace, new quantity, or new witnesses".to_owned(),
                            },
                        });
                    }

                    let Some(old_creator) =
                        roles_schema.creator.take(&RoleCreator::create(
                            &creator.actual_name,
                            creator.actual_namespace.clone(),
                        ))
                    else {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotModify {
                                what: "creator".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    creator.actual_name,
                                    creator.actual_namespace,
                                    schema_id
                                ),
                            },
                        });
                    };

                    let new_namespace = if let Some(new_namespace) =
                        creator.new_namespace
                    {
                        if !new_namespace.check() {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::InvalidValue {
                                    field: format!(
                                        "creator {} {} new namespace in schema {}",
                                        creator.actual_name,
                                        creator.actual_namespace,
                                        schema_id
                                    ),
                                    reason: "invalid new namespace".to_owned(),
                                },
                            });
                        }
                        new_namespace
                    } else {
                        old_creator.namespace
                    };

                    let new_quantity = if let Some(quantity) =
                        creator.new_quantity
                    {
                        if !quantity.check() {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::InvalidValue {
                                    field: "creator quantity".to_owned(),
                                    reason: "cannot be 0".to_owned(),
                                },
                            });
                        }
                        quantity
                    } else {
                        old_creator.quantity
                    };

                    let new_witnesses = if let Some(witnesses) =
                        creator.new_witnesses
                    {
                        let mut witnesses = witnesses.clone();

                        if witnesses.is_empty() {
                            witnesses
                                .insert(ReservedWords::Witnesses.to_string());
                        }

                        for witness in witnesses.iter() {
                            if witness != &ReservedWords::Witnesses.to_string()
                                && !members.contains(witness)
                            {
                                return Err(RunnerError::InvalidEvent {
                                    location: "SchemaIdRole::check_data",
                                    kind: error::InvalidEventKind::NotMember {
                                        who: witness.clone(),
                                    },
                                });
                            }
                        }

                        witnesses
                    } else {
                        old_creator.witnesses
                    };

                    if !roles_schema.creator.insert(RoleCreator {
                        name: creator.actual_name.clone(),
                        namespace: new_namespace.clone(),
                        quantity: new_quantity,
                        witnesses: new_witnesses,
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "creator with new namespace".to_owned(),
                                id: format!(
                                    "{} {} in schema {}",
                                    creator.actual_name,
                                    new_namespace,
                                    schema_id
                                ),
                            },
                        });
                    }
                }
            }

            if let Some(issuers) = change.issuer {
                if issuers.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::Empty {
                            what: "issuers vec in change".to_owned(),
                        },
                    });
                }

                for issuer in issuers {
                    if issuer.actual_name != ReservedWords::Any.to_string() {
                        if !issuer.new_namespace.check() {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::InvalidValue {
                                    field: format!(
                                        "issuer {} {} new namespace in schema {}",
                                        issuer.actual_name,
                                        issuer.actual_namespace,
                                        schema_id
                                    ),
                                    reason: "invalid new namespace".to_owned(),
                                },
                            });
                        }

                        if !roles_schema.issuer.users.remove(&Role {
                            name: issuer.actual_name.clone(),
                            namespace: issuer.actual_namespace.clone(),
                        }) {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::CannotModify {
                                    what: "issuer".to_owned(),
                                    reason: format!(
                                        "{} {} does not have this role in schema {}",
                                        issuer.actual_name,
                                        issuer.actual_namespace,
                                        schema_id
                                    ),
                                },
                            });
                        };

                        if !roles_schema.issuer.users.insert(Role {
                            name: issuer.actual_name.clone(),
                            namespace: issuer.new_namespace.clone(),
                        }) {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::AlreadyExists {
                                    what: "issuer with new namespace"
                                        .to_owned(),
                                    id: format!(
                                        "{} {} in schema {}",
                                        issuer.actual_name,
                                        issuer.new_namespace,
                                        schema_id
                                    ),
                                },
                            });
                        }
                    } else {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotModify {
                                what: "issuer 'Any'".to_owned(),
                                reason: "cannot change issuer 'Any'".to_owned(),
                            },
                        });
                    }
                }
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct GovRolesEvent {
    pub approver: Option<BTreeSet<MemberName>>,
    pub evaluator: Option<BTreeSet<MemberName>>,
    pub validator: Option<BTreeSet<MemberName>>,
    pub witness: Option<BTreeSet<MemberName>>,
    pub issuer: Option<BTreeSet<MemberName>>,
}

impl GovRolesEvent {
    pub fn is_empty(&self) -> bool {
        self.approver.is_none()
            && self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AllSchemasRolesAddEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub issuer: Option<BTreeSet<Role>>,
}

impl AllSchemasRolesAddEvent {
    pub fn is_empty(&self) -> bool {
        self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

impl From<AllSchemasRolesAddEvent> for SchemaRolesAddEvent {
    fn from(value: AllSchemasRolesAddEvent) -> Self {
        Self {
            evaluator: value.evaluator,
            validator: value.validator,
            witness: value.witness,
            creator: None,
            issuer: value.issuer,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SchemaRolesAddEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub creator: Option<BTreeSet<RoleCreator>>,
    pub issuer: Option<BTreeSet<Role>>,
}

impl SchemaRolesAddEvent {
    pub fn is_empty(&self) -> bool {
        self.creator.is_none()
            && self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct AllSchemasRolesRemoveEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub issuer: Option<BTreeSet<Role>>,
}

impl AllSchemasRolesRemoveEvent {
    pub fn is_empty(&self) -> bool {
        self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

impl From<AllSchemasRolesRemoveEvent> for SchemaRolesRemoveEvent {
    fn from(value: AllSchemasRolesRemoveEvent) -> Self {
        Self {
            evaluator: value.evaluator,
            validator: value.validator,
            witness: value.witness,
            creator: None,
            issuer: value.issuer,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SchemaRolesRemoveEvent {
    pub evaluator: Option<BTreeSet<Role>>,
    pub validator: Option<BTreeSet<Role>>,
    pub witness: Option<BTreeSet<Role>>,
    pub creator: Option<BTreeSet<Role>>,
    pub issuer: Option<BTreeSet<Role>>,
}

impl SchemaRolesRemoveEvent {
    pub fn is_empty(&self) -> bool {
        self.creator.is_none()
            && self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct AllSchemasRolesChangeEvent {
    pub evaluator: Option<BTreeSet<RoleChange>>,
    pub validator: Option<BTreeSet<RoleChange>>,
    pub witness: Option<BTreeSet<RoleChange>>,
    pub issuer: Option<BTreeSet<RoleChange>>,
}

impl AllSchemasRolesChangeEvent {
    pub fn is_empty(&self) -> bool {
        self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

impl From<AllSchemasRolesChangeEvent> for SchemaRolesChangeEvent {
    fn from(value: AllSchemasRolesChangeEvent) -> Self {
        Self {
            evaluator: value.evaluator,
            validator: value.validator,
            witness: value.witness,
            creator: None,
            issuer: value.issuer,
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct SchemaRolesChangeEvent {
    pub evaluator: Option<BTreeSet<RoleChange>>,
    pub validator: Option<BTreeSet<RoleChange>>,
    pub witness: Option<BTreeSet<RoleChange>>,
    pub creator: Option<BTreeSet<RoleCreatorChange>>,
    pub issuer: Option<BTreeSet<RoleChange>>,
}

impl SchemaRolesChangeEvent {
    pub fn is_empty(&self) -> bool {
        self.creator.is_none()
            && self.evaluator.is_none()
            && self.validator.is_none()
            && self.witness.is_none()
            && self.issuer.is_none()
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct RoleCreatorChange {
    pub actual_name: MemberName,
    pub actual_namespace: Namespace,
    pub new_namespace: Option<Namespace>,
    pub new_witnesses: Option<BTreeSet<String>>,
    pub new_quantity: Option<CreatorQuantity>,
}

impl RoleCreatorChange {
    pub fn is_empty(&self) -> bool {
        self.new_namespace.is_none()
            && self.new_quantity.is_none()
            && self.new_witnesses.is_none()
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq, PartialOrd, Ord,
)]
pub struct RoleChange {
    pub actual_name: MemberName,
    pub actual_namespace: Namespace,
    pub new_namespace: Namespace,
}

///// Schemas /////
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemasEvent {
    pub add: Option<HashSet<SchemaAdd>>,
    pub remove: Option<HashSet<SchemaType>>,
    pub change: Option<HashSet<SchemaChange>>,
}

impl SchemasEvent {
    pub fn is_empty(&self) -> bool {
        self.add.is_none() && self.remove.is_none() && self.change.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct SchemaAdd {
    pub id: SchemaType,
    pub contract: String,
    pub initial_value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct SchemaChange {
    pub actual_id: SchemaType,
    pub new_contract: Option<String>,
    pub new_initial_value: Option<Value>,
}

impl SchemaChange {
    pub fn is_empty(&self) -> bool {
        !self.actual_id.is_valid()
            || self.new_contract.is_none() && self.new_initial_value.is_none()
    }
}

///// Policies /////
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoliciesEvent {
    pub governance: Option<GovPolicieEvent>,
    pub schema: Option<HashSet<SchemaIdPolicie>>,
}

impl PoliciesEvent {
    pub fn is_empty(&self) -> bool {
        self.governance.is_none() && self.schema.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct SchemaIdPolicie {
    pub schema_id: SchemaType,
    pub change: SchemaPolicieChange,
}

impl SchemaIdPolicie {
    pub fn is_empty(&self) -> bool {
        !self.schema_id.is_valid() || self.change.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovPolicieEvent {
    pub change: GovPolicieChange,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GovPolicieChange {
    pub approve: Option<Quorum>,
    pub evaluate: Option<Quorum>,
    pub validate: Option<Quorum>,
}

impl GovPolicieChange {
    pub fn is_empty(&self) -> bool {
        self.approve.is_none()
            && self.evaluate.is_none()
            && self.validate.is_none()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Hash, PartialEq, Eq)]
pub struct SchemaPolicieChange {
    pub evaluate: Option<Quorum>,
    pub validate: Option<Quorum>,
}

impl SchemaPolicieChange {
    pub fn is_empty(&self) -> bool {
        self.evaluate.is_none() && self.validate.is_none()
    }
}
