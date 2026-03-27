use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use ave_common::{
    Namespace, SchemaType, identity::PublicKey, schematype::ReservedWords,
};

use crate::{
    evaluation::runner::error::{self, RunnerError},
    governance::{
        CreatorRoleUpdate, RolesUpdate, RolesUpdateRemove,
        data::GovernanceData,
        witnesses_register::WitnessesType,
    },
};

use super::model::{
    CreatorWitness,
    RolesGov, RolesSchema, RolesTrackerSchemas,
};

pub use ave_common::governance::{
    CreatorQuantity as EventCreatorQuantity,
    CreatorWitness as EventCreatorWitness, GovPolicieChange, GovPolicieEvent,
    GovRoleEvent, GovRolesEvent, GovernanceEvent, MemberEvent, MemberName,
    NewMember, PoliciesEvent, Quorum as EventQuorum, Role as EventRole,
    RoleChange, RoleCreator as EventRoleCreator, RoleCreatorChange, RolesEvent,
    SchemaAdd, SchemaChange, SchemaIdPolicie, SchemaIdRole,
    SchemaPolicieChange, SchemaRolesAddEvent, SchemaRolesChangeEvent,
    SchemaRolesRemoveEvent, SchemasEvent, TrackerSchemasRoleEvent,
    TrackerSchemasRolesAddEvent, TrackerSchemasRolesChangeEvent,
    TrackerSchemasRolesRemoveEvent,
};

pub(crate) const fn creator_quantity_is_valid(
    quantity: &EventCreatorQuantity,
) -> bool {
    quantity.check()
}

fn validate_viewpoint_names(
    schema_id: &SchemaType,
    viewpoints: &BTreeSet<String>,
    field: &str,
) -> Result<BTreeSet<String>, RunnerError> {
    let mut unique = BTreeSet::new();

    for viewpoint in viewpoints {
        if viewpoint != viewpoint.trim() {
            return Err(RunnerError::InvalidEvent {
                location: "viewpoints::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!("{field} in schema {schema_id}"),
                    reason: "cannot have leading or trailing whitespace"
                        .to_owned(),
                },
            });
        }

        if viewpoint.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "viewpoints::check_data",
                kind: error::InvalidEventKind::Empty {
                    what: format!("{field} in schema {schema_id}"),
                },
            });
        }

        if viewpoint.len() > 100 {
            return Err(RunnerError::InvalidEvent {
                location: "viewpoints::check_data",
                kind: error::InvalidEventKind::InvalidSize {
                    field: format!("{field} in schema {schema_id}"),
                    actual: viewpoint.len(),
                    max: 100,
                },
            });
        }

        if !unique.insert(viewpoint.clone()) {
            return Err(RunnerError::InvalidEvent {
                location: "viewpoints::check_data",
                kind: error::InvalidEventKind::Duplicate {
                    what: field.to_owned(),
                    id: viewpoint.clone(),
                },
            });
        }
    }

    Ok(unique)
}

fn validate_creator_witness_viewpoints(
    creator_name: &str,
    schema_id: &SchemaType,
    schema_viewpoints: &BTreeSet<String>,
    creator_witnesses: &BTreeSet<String>,
    witness_viewpoints: &BTreeSet<EventCreatorWitness>,
) -> Result<BTreeSet<CreatorWitness>, RunnerError> {
    let mut unique_names = HashSet::new();
    let mut out = BTreeSet::new();

    for witness in witness_viewpoints {
        if witness.name != witness.name.trim() {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!(
                        "creator witness viewpoints name in schema {}",
                        schema_id
                    ),
                    reason: "cannot have leading or trailing whitespace"
                        .to_owned(),
                },
            });
        }

        if witness.name == creator_name {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!(
                        "creator {} witness viewpoints in schema {}",
                        creator_name, schema_id
                    ),
                    reason: "a creator cannot be listed as their own witness"
                        .to_owned(),
                },
            });
        }

        if witness.name == ReservedWords::Witnesses.to_string() {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!(
                        "creator {} witness viewpoints in schema {}",
                        creator_name, schema_id
                    ),
                    reason:
                        "generic Witnesses cannot carry explicit viewpoints"
                            .to_owned(),
                },
            });
        }

        if !creator_witnesses.contains(&witness.name) {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!(
                        "creator {} witness viewpoints in schema {}",
                        creator_name, schema_id
                    ),
                    reason: format!(
                        "witness {} must exist in creator witnesses",
                        witness.name
                    ),
                },
            });
        }

        if !unique_names.insert(witness.name.clone()) {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::Duplicate {
                    what: format!(
                        "creator {} witness viewpoints in schema {}",
                        creator_name, schema_id
                    ),
                    id: witness.name.clone(),
                },
            });
        }

        if witness.viewpoints.is_empty() {
            out.insert(CreatorWitness {
                name: witness.name.clone(),
                viewpoints: BTreeSet::from([ReservedWords::AllViewpoints
                    .to_string()]),
            });
            continue;
        }

        if witness
            .viewpoints
            .contains(&ReservedWords::AllViewpoints.to_string())
        {
            if witness.viewpoints.len() != 1 {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: format!(
                            "creator witness {} viewpoints in schema {}",
                            witness.name, schema_id
                        ),
                        reason: "AllViewpoints cannot be combined with other viewpoints"
                            .to_owned(),
                    },
                });
            }

            out.insert(CreatorWitness {
                name: witness.name.clone(),
                viewpoints: BTreeSet::from([ReservedWords::AllViewpoints
                    .to_string()]),
            });
            continue;
        }

        if witness
            .viewpoints
            .contains(&ReservedWords::NoViewpoints.to_string())
        {
            if witness.viewpoints.len() != 1 {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: format!(
                            "creator witness {} viewpoints in schema {}",
                            witness.name, schema_id
                        ),
                        reason: "NoViewpoints cannot be combined with other viewpoints"
                            .to_owned(),
                    },
                });
            }

            out.insert(CreatorWitness {
                name: witness.name.clone(),
                viewpoints: BTreeSet::from([ReservedWords::NoViewpoints
                    .to_string()]),
            });
            continue;
        }

        let validated = validate_viewpoint_names(
            schema_id,
            &witness.viewpoints,
            &format!("creator witness {} viewpoints", witness.name),
        )?;

        for viewpoint in &validated {
            if !schema_viewpoints.contains(viewpoint) {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: format!(
                            "creator witness {} viewpoints in schema {}",
                            witness.name, schema_id
                        ),
                        reason: format!(
                            "viewpoint {} does not exist in schema",
                            viewpoint
                        ),
                    },
                });
            }
        }

        out.insert(CreatorWitness {
            name: witness.name.clone(),
            viewpoints: validated,
        });
    }

    Ok(out)
}

fn normalize_creator_witness_viewpoints(
    creator_witnesses: &BTreeSet<String>,
    mut witness_viewpoints: BTreeSet<CreatorWitness>,
) -> BTreeSet<CreatorWitness> {
    for witness in creator_witnesses {
        if !witness_viewpoints.iter().any(|x| x.name == *witness) {
            witness_viewpoints.insert(CreatorWitness {
                name: witness.clone(),
                viewpoints: BTreeSet::from([ReservedWords::AllViewpoints
                    .to_string()]),
            });
        }
    }

    witness_viewpoints
}

fn validate_creator_witnesses(
    creator_name: &str,
    schema_id: &SchemaType,
    schema_viewpoints: &BTreeSet<String>,
    members: &HashSet<String>,
    witnesses: &BTreeSet<EventCreatorWitness>,
) -> Result<(BTreeSet<String>, BTreeSet<CreatorWitness>), RunnerError> {
    if witnesses.is_empty() {
        return Ok((
            BTreeSet::from([ReservedWords::Witnesses.to_string()]),
            BTreeSet::new(),
        ));
    }

    let mut names = BTreeSet::new();
    let mut explicit = BTreeSet::new();

    for witness in witnesses {
        if witness.name != witness.name.trim() {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!(
                        "creator witness name in schema {}",
                        schema_id
                    ),
                    reason: "cannot have leading or trailing whitespace"
                        .to_owned(),
                },
            });
        }

        if witness.name == creator_name {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!(
                        "creator {} witnesses in schema {}",
                        creator_name, schema_id
                    ),
                    reason: "a creator cannot be listed as their own witness"
                        .to_owned(),
                },
            });
        }

        if !names.insert(witness.name.clone()) {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::Duplicate {
                    what: format!(
                        "creator {} witnesses in schema {}",
                        creator_name, schema_id
                    ),
                    id: witness.name.clone(),
                },
            });
        }

        if witness.name == ReservedWords::Witnesses.to_string() {
            if witness.viewpoints.len() != 1
                || !witness
                    .viewpoints
                    .contains(&ReservedWords::AllViewpoints.to_string())
            {
                return Err(RunnerError::InvalidEvent {
                    location: "SchemaIdRole::check_data",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: format!(
                            "creator {} witnesses in schema {}",
                            creator_name, schema_id
                        ),
                        reason:
                            "generic Witnesses must use exactly AllViewpoints"
                                .to_owned(),
                    },
                });
            }

            continue;
        }

        if !members.contains(&witness.name) {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::NotMember {
                    who: witness.name.clone(),
                },
            });
        }

        explicit.insert(witness.clone());
    }

    let validated = validate_creator_witness_viewpoints(
        creator_name,
        schema_id,
        schema_viewpoints,
        &names,
        &explicit,
    )?;

    let normalized = normalize_creator_witness_viewpoints(&names, validated);
    Ok((names, normalized))
}

fn tracker_schemas_role_event_to_schema_id_role(
    event: &TrackerSchemasRoleEvent,
) -> SchemaIdRole {
    SchemaIdRole {
        schema_id: SchemaType::TrackerSchemas,
        add: event
            .add
            .clone()
            .map(tracker_schemas_roles_add_event_to_schema_roles_add_event),
        remove: event.remove.clone().map(
            tracker_schemas_roles_remove_event_to_schema_roles_remove_event,
        ),
        change: event.change.clone().map(
            tracker_schemas_roles_change_event_to_schema_roles_change_event,
        ),
    }
}

fn tracker_schemas_roles_add_event_to_schema_roles_add_event(
    value: TrackerSchemasRolesAddEvent,
) -> SchemaRolesAddEvent {
    SchemaRolesAddEvent {
        evaluator: value.evaluator,
        validator: value.validator,
        witness: value.witness,
        creator: None,
        issuer: value.issuer,
    }
}

fn tracker_schemas_roles_remove_event_to_schema_roles_remove_event(
    value: TrackerSchemasRolesRemoveEvent,
) -> SchemaRolesRemoveEvent {
    SchemaRolesRemoveEvent {
        evaluator: value.evaluator,
        validator: value.validator,
        witness: value.witness,
        creator: None,
        issuer: value.issuer,
    }
}

fn tracker_schemas_roles_change_event_to_schema_roles_change_event(
    value: TrackerSchemasRolesChangeEvent,
) -> SchemaRolesChangeEvent {
    SchemaRolesChangeEvent {
        evaluator: value.evaluator,
        validator: value.validator,
        witness: value.witness,
        creator: None,
        issuer: value.issuer,
    }
}

pub fn governance_event_update_creator_change(
    event: &GovernanceEvent,
    members: &BTreeMap<MemberName, PublicKey>,
    roles_schema: &BTreeMap<SchemaType, RolesSchema>,
) -> CreatorRoleUpdate {
    let mut new_creator: HashMap<
        (SchemaType, String, PublicKey),
        (EventCreatorQuantity, BTreeSet<String>),
    > = HashMap::new();

    let mut update_creator_quantity: HashSet<(
        SchemaType,
        String,
        PublicKey,
        EventCreatorQuantity,
    )> = HashSet::new();

    let mut update_creator_witnesses: HashSet<(
        SchemaType,
        String,
        PublicKey,
        BTreeSet<String>,
    )> = HashSet::new();

    let mut remove_creator: HashSet<(SchemaType, String, PublicKey)> =
        HashSet::new();

    if let Some(roles) = &event.roles
        && let Some(schemas) = &roles.schema
    {
        for schema in schemas {
            if let Some(change) = &schema.change
                && let Some(creator) = &change.creator
                && let Some(roles) = roles_schema.get(&schema.schema_id)
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
                                        roles.creator.get(&EventRoleCreator {
                                            name: x.actual_name.clone(),
                                            namespace: x
                                                .actual_namespace
                                                .clone(),
                                            witnesses: BTreeSet::new(),
                                            witness_viewpoints:
                                                BTreeSet::new(),
                                            quantity:
                                                EventCreatorQuantity::Infinity,
                                        })
                                        && let Some(user) =
                                            members.get(&creator.name)
                                    {
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
                                (None, Some(q)) => {
                                    if let Some(creator) =
                                        roles.creator.get(&EventRoleCreator {
                                            name: x.actual_name.clone(),
                                            namespace: x
                                                .actual_namespace
                                                .clone(),
                                            witnesses: BTreeSet::new(),
                                            witness_viewpoints:
                                                BTreeSet::new(),
                                            quantity:
                                                EventCreatorQuantity::Infinity,
                                        })
                                        && let Some(user) =
                                            members.get(&creator.name)
                                    {
                                        new_creator.insert(
                                            (
                                                schema.schema_id.clone(),
                                                new_namespace.to_string(),
                                                user.clone(),
                                            ),
                                            (
                                                q.clone(),
                                                creator.witnesses.clone(),
                                            ),
                                        );
                                    }
                                }
                                (Some(w), None) => {
                                    if let Some(creator) =
                                        roles.creator.get(&EventRoleCreator {
                                            name: x.actual_name.clone(),
                                            namespace: x
                                                .actual_namespace
                                                .clone(),
                                            witnesses: BTreeSet::new(),
                                            witness_viewpoints:
                                                BTreeSet::new(),
                                            quantity:
                                                EventCreatorQuantity::Infinity,
                                        })
                                        && let Some(user) =
                                            members.get(&creator.name)
                                    {
                                        new_creator.insert(
                                            (
                                                schema.schema_id.clone(),
                                                new_namespace.to_string(),
                                                user.clone(),
                                            ),
                                            (
                                                creator.quantity.clone(),
                                                w.iter()
                                                    .map(|x| x.name.clone())
                                                    .collect(),
                                            ),
                                        );
                                    }
                                }
                                (Some(w), Some(q)) => {
                                    new_creator.insert(
                                        (
                                            schema.schema_id.clone(),
                                            new_namespace.to_string(),
                                            user.clone(),
                                        ),
                                        (
                                            q.clone(),
                                            w.iter()
                                                .map(|x| x.name.clone())
                                                .collect(),
                                        ),
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
                                    w.iter()
                                        .map(|x| x.name.clone())
                                        .collect(),
                                ));
                            }
                        }
                    }
                });
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

pub fn governance_event_roles_update_fact(
    event: &GovernanceEvent,
    members: &BTreeMap<MemberName, PublicKey>,
    rm_roles: Option<RolesUpdateRemove>,
) -> RolesUpdate {
    let mut appr_quorum: Option<EventQuorum> = None;
    let mut eval_quorum: HashMap<SchemaType, EventQuorum> = HashMap::new();
    let mut vali_quorum: HashMap<SchemaType, EventQuorum> = HashMap::new();

    let mut new_approvers: Vec<PublicKey> = vec![];
    let mut remove_approvers: Vec<PublicKey> = vec![];

    let mut new_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>> =
        HashMap::new();

    let mut remove_evaluators: HashMap<
        (SchemaType, PublicKey),
        Vec<Namespace>,
    > = HashMap::new();

    let mut new_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>> =
        HashMap::new();

    let mut remove_validators: HashMap<
        (SchemaType, PublicKey),
        Vec<Namespace>,
    > = HashMap::new();

    let mut new_creator: HashMap<
        (SchemaType, String, PublicKey),
        (EventCreatorQuantity, Vec<WitnessesType>),
    > = HashMap::new();

    let mut remove_creator: HashSet<(SchemaType, String, PublicKey)> =
        HashSet::new();

    let mut new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>> =
        HashMap::new();

    let mut remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>> =
        HashMap::new();

    if let Some(schema) = &event.schemas
        && let Some(schema_add) = &schema.add
    {
        for schema_data in schema_add {
            eval_quorum.insert(schema_data.id.clone(), EventQuorum::Majority);
            vali_quorum.insert(schema_data.id.clone(), EventQuorum::Majority);
        }
    }

    if let Some(roles) = &event.roles {
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
                                .entry((SchemaType::Governance, user.clone()))
                                .or_default()
                                .push(Namespace::new());
                        }
                    });
                }

                if let Some(validators) = &add.validator {
                    validators.iter().for_each(|x| {
                        if let Some(user) = members.get(x) {
                            new_validators
                                .entry((SchemaType::Governance, user.clone()))
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
                                .entry((SchemaType::Governance, user.clone()))
                                .or_default()
                                .push(Namespace::new());
                        }
                    });
                }

                if let Some(validators) = &remove.validator {
                    validators.iter().for_each(|x| {
                        if let Some(user) = members.get(x) {
                            remove_validators
                                .entry((SchemaType::Governance, user.clone()))
                                .or_default()
                                .push(Namespace::new());
                        }
                    });
                }
            }
        }

        // all schemas
        if let Some(tracker_schemas) = &roles.tracker_schemas {
            if let Some(add) = &tracker_schemas.add {
                if let Some(evaluators) = &add.evaluator {
                    evaluators.iter().for_each(|x| {
                        if let Some(user) = members.get(&x.name) {
                            new_evaluators
                                .entry((
                                    SchemaType::TrackerSchemas,
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
                                    SchemaType::TrackerSchemas,
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
                                    SchemaType::TrackerSchemas,
                                    user.clone(),
                                ))
                                .or_default()
                                .push(x.namespace.clone());
                        }
                    });
                }
            }
            if let Some(remove) = &tracker_schemas.remove {
                if let Some(evaluators) = &remove.evaluator {
                    evaluators.iter().for_each(|x| {
                        if let Some(user) = members.get(&x.name) {
                            remove_evaluators
                                .entry((
                                    SchemaType::TrackerSchemas,
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
                                    SchemaType::TrackerSchemas,
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
                                    SchemaType::TrackerSchemas,
                                    user.clone(),
                                ))
                                .or_default()
                                .push(x.namespace.clone());
                        }
                    });
                }
            }
            if let Some(change) = &tracker_schemas.change {
                if let Some(evaluators) = &change.evaluator {
                    evaluators.iter().for_each(|x| {
                        if let Some(user) = members.get(&x.actual_name) {
                            remove_evaluators
                                .entry((
                                    SchemaType::TrackerSchemas,
                                    user.clone(),
                                ))
                                .or_default()
                                .push(x.actual_namespace.clone());

                            new_evaluators
                                .entry((
                                    SchemaType::TrackerSchemas,
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
                                    SchemaType::TrackerSchemas,
                                    user.clone(),
                                ))
                                .or_default()
                                .push(x.actual_namespace.clone());

                            new_validators
                                .entry((
                                    SchemaType::TrackerSchemas,
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
                                    SchemaType::TrackerSchemas,
                                    user.clone(),
                                ))
                                .or_default()
                                .push(x.actual_namespace.clone());

                            new_witnesses
                                .entry((
                                    SchemaType::TrackerSchemas,
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
                                        == &ReservedWords::Witnesses.to_string()
                                    {
                                        witnesses
                                            .push(WitnessesType::Witnesses);
                                    } else if let Some(w) = members.get(witness)
                                    {
                                        witnesses.push(WitnessesType::User(
                                            w.clone(),
                                        ));
                                    }
                                }

                                new_creator.insert(
                                    (
                                        schema.schema_id.clone(),
                                        x.namespace.to_string(),
                                        user.clone(),
                                    ),
                                    (
                                        x.quantity.clone(),
                                        witnesses,
                                    ),
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
                            if let Some(user) = members.get(&x.actual_name) {
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
                            if let Some(user) = members.get(&x.actual_name) {
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
                            if let Some(user) = members.get(&x.actual_name) {
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

    if let Some(policies) = &event.policies {
        // gov
        if let Some(governance) = &policies.governance {
            appr_quorum = governance.change.approve.clone();

            if let Some(quorum) = &governance.change.evaluate {
                eval_quorum
                    .insert(SchemaType::Governance, quorum.clone());
            }
            if let Some(quorum) = &governance.change.validate {
                vali_quorum
                    .insert(SchemaType::Governance, quorum.clone());
            }
        }

        // schemas
        if let Some(schemas) = &policies.schema {
            for schema in schemas {
                if let Some(quorum) = &schema.change.evaluate {
                    eval_quorum.insert(
                        schema.schema_id.clone(),
                        quorum.clone(),
                    );
                }
                if let Some(quorum) = &schema.change.validate {
                    vali_quorum.insert(
                        schema.schema_id.clone(),
                        quorum.clone(),
                    );
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

pub const fn governance_event_is_empty(event: &GovernanceEvent) -> bool {
    event.members.is_none()
        && event.roles.is_none()
        && event.schemas.is_none()
        && event.policies.is_none()
}

///// Members /////
pub const fn member_event_is_empty(event: &MemberEvent) -> bool {
    event.add.is_none() && event.remove.is_none()
}

///// Roles /////
pub const fn roles_event_is_empty(event: &RolesEvent) -> bool {
    event.governance.is_none()
        && event.schema.is_none()
        && event.tracker_schemas.is_none()
}

pub const fn gov_role_event_is_empty(event: &GovRoleEvent) -> bool {
    event.add.is_none() && event.remove.is_none()
}

pub fn gov_role_event_check_data(
    event: &GovRoleEvent,
    governance: &GovernanceData,
    new_roles: &mut RolesGov,
) -> Result<(), RunnerError> {
    // Validar que cada (role_type, name) solo aparezca una vez
    let mut seen_roles: HashSet<(String, String)> = HashSet::new();

    // Helper para registrar un rol y detectar duplicados
    let mut check_and_register = |role_type: &str,
                                  name: &str|
     -> Result<(), RunnerError> {
        let key = (role_type.to_string(), name.trim().to_string());
        if !seen_roles.insert(key) {
            return Err(RunnerError::InvalidEvent {
                location: "GovRoleEvent::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!("{} role operation", role_type),
                    reason: format!(
                        "Role {} appears multiple times in the same event. Only one operation per role is allowed",
                        name.trim()
                    ),
                },
            });
        }
        Ok(())
    };

    // Validar add operations
    if let Some(ref add) = event.add {
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
    if let Some(ref remove) = event.remove {
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

    if let Some(add) = event.add.clone() {
        if gov_roles_event_is_empty(&add) {
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

            for approver in approvers {
                if approver != approver.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "approver name".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: approver,
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

            for evaluator in evaluators {
                if evaluator != evaluator.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "evaluator name".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: evaluator,
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

            for validator in validators {
                if validator != validator.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "validator name".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: validator,
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

            for witness in witnesses {
                if witness != witness.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "witness name".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: witness,
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
                        what: "issuers vec in governance roles add".to_owned(),
                    },
                });
            }

            for issuer in issuers {
                if issuer != issuer.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "issuer name".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                                who: issuer,
                            },
                        });
                    }

                    if !new_roles.issuer.signers.insert(issuer.clone()) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "governance issuer".to_owned(),
                                id: issuer,
                            },
                        });
                    };
                } else {
                    if new_roles.issuer.any {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "governance issuer 'Any'".to_owned(),
                                id: ReservedWords::Any.to_string(),
                            },
                        });
                    }
                    new_roles.issuer.any = true;
                }
            }
        }
    }

    if let Some(remove) = event.remove.clone() {
        if gov_roles_event_is_empty(&remove) {
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
                if approver != approver.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "approver name to remove".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
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
                if evaluator != evaluator.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "evaluator name to remove".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
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
                if validator != validator.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "validator name to remove".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
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
                if witness != witness.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "witness name to remove".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
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
                if issuer != issuer.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "GovRoleEvent::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "issuer name to remove".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if issuer != ReservedWords::Any.to_string() {
                    if !new_roles.issuer.signers.remove(&issuer) {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: format!("issuer {}", issuer),
                                reason: "does not have this role".to_owned(),
                            },
                        });
                    };
                } else {
                    if !new_roles.issuer.any {
                        return Err(RunnerError::InvalidEvent {
                            location: "GovRoleEvent::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "governance issuer 'Any'".to_owned(),
                                reason: "issuer 'Any' is not set".to_owned(),
                            },
                        });
                    }
                    new_roles.issuer.any = false;
                }
            }
        }
    }

    Ok(())
}

pub const fn tracker_schemas_role_event_is_empty(
    event: &TrackerSchemasRoleEvent,
) -> bool {
    event.add.is_none() && event.remove.is_none() && event.change.is_none()
}

pub fn tracker_schemas_role_event_check_data(
    event: &TrackerSchemasRoleEvent,
    governance: &GovernanceData,
    roles_not_gov: RolesTrackerSchemas,
    schema_id: &SchemaType,
) -> Result<RolesTrackerSchemas, RunnerError> {
    let schema_role = tracker_schemas_role_event_to_schema_id_role(event);

    let mut roles_schema = RolesSchema::from(roles_not_gov);
    schema_id_role_check_data(
        &schema_role,
        governance,
        &mut roles_schema,
        schema_id,
    )?;
    Ok(RolesTrackerSchemas::from(roles_schema))
}

pub fn schema_id_role_is_empty(event: &SchemaIdRole) -> bool {
    !event.schema_id.is_valid()
        || event.add.is_none()
            && event.change.is_none()
            && event.remove.is_none()
}

pub fn schema_id_role_check_data(
    event: &SchemaIdRole,
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
            name.trim().to_string(),
            namespace.to_string(),
        );
        if !seen_roles.insert(key) {
            return Err(RunnerError::InvalidEvent {
                location: "SchemaIdRole::check_data",
                kind: error::InvalidEventKind::InvalidValue {
                    field: format!("{} role operation", role_type),
                    reason: format!(
                        "Role ({}, {}) appears multiple times in the same event. Only one operation per role is allowed",
                        name.trim(),
                        namespace
                    ),
                },
            });
        }
        Ok(())
    };

    // Validar add operations
    if let Some(ref add) = event.add {
        if let Some(ref evaluators) = add.evaluator {
            for eval in evaluators {
                check_and_register("evaluator", &eval.name, &eval.namespace)?;
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
                check_and_register("issuer", &issuer.name, &issuer.namespace)?;
            }
        }
    }

    // Validar change operations
    if let Some(ref change) = event.change {
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
    if let Some(ref remove) = event.remove {
        if let Some(ref evaluators) = remove.evaluator {
            for eval in evaluators {
                check_and_register("evaluator", &eval.name, &eval.namespace)?;
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
                check_and_register("issuer", &issuer.name, &issuer.namespace)?;
            }
        }
    }

    let members: HashSet<String> = governance.members.keys().cloned().collect();

    if let Some(add) = event.add.clone() {
        if schema_roles_add_event_is_empty(&add) {
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
                        what: "evaluators vec in schema roles add".to_owned(),
                    },
                });
            }

            for evaluator in evaluators {
                if evaluator.name != evaluator.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "evaluator name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: evaluator.name,
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

            for validator in validators {
                if validator.name != validator.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "validator name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: validator.name,
                        },
                    });
                }

                if !roles_schema.validator.insert(validator.clone()) {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::AlreadyExists {
                            what: "validator".to_owned(),
                            id: validator.name,
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

            for witness in witnesses {
                if witness.name != witness.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "witness name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                            who: witness.name,
                        },
                    });
                }

                if !roles_schema.witness.insert(witness.clone()) {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::AlreadyExists {
                            what: "witness".to_owned(),
                            id: witness.name,
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

            for creator in creators {
                if creator.name != creator.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "creator name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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

                if !creator_quantity_is_valid(&creator.quantity) {
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
                            who: creator.name,
                        },
                    });
                }

                let schema_viewpoints = governance
                    .schemas
                    .get(schema_id)
                    .map(|x| &x.viewpoints)
                    .ok_or_else(|| RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::NotSchema {
                            id: schema_id.to_string(),
                        },
                    })?;

                for witness in creator.witnesses.iter() {
                    if witness != &ReservedWords::Witnesses.to_string() {
                        if witness != witness.trim() {
                            return Err(RunnerError::InvalidEvent {
                                    location: "SchemaIdRole::check_data",
                                    kind: error::InvalidEventKind::InvalidValue {
                                        field: format!("creator witness name in schema {}", schema_id),
                                        reason: "cannot have leading or trailing whitespace".to_owned(),
                                    },
                                });
                        }
                        if witness == &creator.name {
                            return Err(RunnerError::InvalidEvent {
                                    location: "SchemaIdRole::check_data",
                                    kind: error::InvalidEventKind::InvalidValue {
                                        field: format!("creator {} witnesses in schema {}", creator.name, schema_id),
                                        reason: "a creator cannot be listed as their own witness".to_owned(),
                                    },
                                });
                        }
                        if !members.contains(witness) {
                            return Err(RunnerError::InvalidEvent {
                                location: "SchemaIdRole::check_data",
                                kind: error::InvalidEventKind::NotMember {
                                    who: witness.clone(),
                                },
                            });
                        }
                    }
                }

                let witness_viewpoints = normalize_creator_witness_viewpoints(
                    &creator.witnesses,
                    validate_creator_witness_viewpoints(
                    &creator.name,
                    schema_id,
                    schema_viewpoints,
                    &creator.witnesses,
                    &creator.witness_viewpoints,
                )?,
                );

                if !roles_schema.creator.insert(EventRoleCreator {
                    witness_viewpoints,
                    ..creator.clone()
                })
                {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::AlreadyExists {
                            what: "creator".to_owned(),
                            id: creator.name,
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

            for issuer in issuers {
                if issuer.name != issuer.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "issuer name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

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
                                who: issuer.name,
                            },
                        });
                    }

                    if !roles_schema
                        .issuer
                        .signers
                        .insert(issuer.clone())
                    {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "issuer".to_owned(),
                                id: issuer.name,
                            },
                        });
                    };
                } else {
                    if !issuer.namespace.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "issuer 'Any' namespace in schema {}",
                                    schema_id
                                ),
                                reason:
                                    "namespace must be empty for 'Any' issuer"
                                        .to_owned(),
                            },
                        });
                    }

                    if roles_schema.issuer.any {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: format!(
                                    "issuer 'Any' in schema {}",
                                    schema_id
                                ),
                                id: ReservedWords::Any.to_string(),
                            },
                        });
                    }

                    roles_schema.issuer.any = true;
                }
            }
        }
    }

    if let Some(remove) = event.remove.clone() {
        if schema_roles_remove_event_is_empty(&remove) {
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
                if evaluator.name != evaluator.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "evaluator name to remove in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !evaluator.namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "evaluator namespace to remove in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
                if !roles_schema.evaluator.remove(&evaluator) {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::CannotRemove {
                            what: "evaluator".to_owned(),
                            reason: format!(
                                "{} {} does not have this role in schema {}",
                                evaluator.name, evaluator.namespace, schema_id
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
                if validator.name != validator.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "validator name to remove in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !validator.namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "validator namespace to remove in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
                if !roles_schema.validator.remove(&validator) {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::CannotRemove {
                            what: "validator".to_owned(),
                            reason: format!(
                                "{} {} does not have this role in schema {}",
                                validator.name, validator.namespace, schema_id
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
                if witness.name != witness.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "witness name to remove in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !witness.namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "witness namespace to remove in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
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
                if creator.name != creator.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "creator name to remove in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !creator.namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "creator namespace to remove in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
                if !roles_schema.creator.remove(&EventRoleCreator::create(
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
                if issuer.name != issuer.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "issuer name to remove in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if issuer.name != ReservedWords::Any.to_string() {
                    if !issuer.namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "issuer namespace to remove in schema {}",
                                    schema_id
                                ),
                                reason: "invalid namespace".to_owned(),
                            },
                        });
                    }
                    if !roles_schema
                        .issuer
                        .signers
                        .remove(&issuer)
                    {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "issuer".to_owned(),
                                reason: format!(
                                    "{} {} does not have this role in schema {}",
                                    issuer.name, issuer.namespace, schema_id
                                ),
                            },
                        });
                    }
                } else {
                    if !issuer.namespace.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: "issuer 'Any' namespace in remove"
                                    .to_owned(),
                                reason:
                                    "namespace must be empty for 'Any' issuer"
                                        .to_owned(),
                            },
                        });
                    }
                    if !roles_schema.issuer.any {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::CannotRemove {
                                what: "issuer 'Any'".to_owned(),
                                reason: "issuer 'Any' is not set".to_owned(),
                            },
                        });
                    }
                    roles_schema.issuer.any = false;
                }
            }
        }
    }

    if let Some(change) = event.change.clone() {
        if schema_roles_change_event_is_empty(&change) {
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
                if evaluator.actual_name != evaluator.actual_name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "evaluator actual name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !evaluator.actual_namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "evaluator actual namespace in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
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

                if evaluator.new_namespace == evaluator.actual_namespace {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::SameValue {
                            what: format!(
                                "evaluator {} namespace in schema {}",
                                evaluator.actual_name, schema_id
                            ),
                        },
                    });
                }

                if !roles_schema.evaluator.remove(&EventRole {
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

                if !roles_schema.evaluator.insert(EventRole {
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
                if validator.actual_name != validator.actual_name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "validator actual name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !validator.actual_namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "validator actual namespace in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
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

                if validator.new_namespace == validator.actual_namespace {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::SameValue {
                            what: format!(
                                "validator {} namespace in schema {}",
                                validator.actual_name, schema_id
                            ),
                        },
                    });
                }

                if !roles_schema.validator.remove(&EventRole {
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

                if !roles_schema.validator.insert(EventRole {
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
                if witness.actual_name != witness.actual_name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "witness actual name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !witness.actual_namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "witness actual namespace in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
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

                if witness.new_namespace == witness.actual_namespace {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::SameValue {
                            what: format!(
                                "witness {} namespace in schema {}",
                                witness.actual_name, schema_id
                            ),
                        },
                    });
                }

                if !roles_schema.witness.remove(&EventRole {
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

                if !roles_schema.witness.insert(EventRole {
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
                if creator.actual_name != creator.actual_name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "creator actual name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if !creator.actual_namespace.check() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "creator actual namespace in schema {}",
                                schema_id
                            ),
                            reason: "invalid namespace".to_owned(),
                        },
                    });
                }
                if role_creator_change_is_empty(&creator) {
                    return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!("creator {} {} change in schema {}", creator.actual_name, creator.actual_namespace, schema_id),
                                reason: "must specify at least one of: new namespace, new quantity, or new witnesses".to_owned(),
                            },
                        });
                }

                let Some(old_creator) =
                    roles_schema.creator.take(&EventRoleCreator::create(
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
                    if new_namespace == creator.actual_namespace {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "creator {} namespace in schema {}",
                                    creator.actual_name, schema_id
                                ),
                            },
                        });
                    }
                    new_namespace
                } else {
                    old_creator.namespace
                };

                let new_quantity = if let Some(quantity) = creator.new_quantity
                {
                    if !creator_quantity_is_valid(&quantity) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: "creator quantity".to_owned(),
                                reason: "cannot be 0".to_owned(),
                            },
                        });
                    }
                    let quantity = quantity.clone();

                    if quantity == old_creator.quantity {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "creator {} quantity in schema {}",
                                    creator.actual_name, schema_id
                                ),
                            },
                        });
                    }
                    quantity
                } else {
                    old_creator.quantity
                };

                let schema_viewpoints = governance
                    .schemas
                    .get(schema_id)
                    .map(|x| &x.viewpoints)
                    .ok_or_else(|| RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::NotSchema {
                            id: schema_id.to_string(),
                        },
                    })?;

                let (new_witnesses, base_witness_viewpoints, witness_names_changed) =
                    if let Some(witnesses) = creator.new_witnesses.as_ref() {
                        let (witnesses, witness_viewpoints) =
                            validate_creator_witnesses(
                                &creator.actual_name,
                                schema_id,
                                schema_viewpoints,
                                &members,
                                &witnesses,
                            )?;

                        (
                            witnesses.clone(),
                            witness_viewpoints,
                            witnesses != old_creator.witnesses,
                        )
                    } else {
                        (
                            old_creator.witnesses.clone(),
                            normalize_creator_witness_viewpoints(
                                &old_creator.witnesses,
                                old_creator.witness_viewpoints.clone(),
                            ),
                            false,
                        )
                    };

                let effective_old_witness_viewpoints =
                    normalize_creator_witness_viewpoints(
                        &new_witnesses,
                        old_creator
                            .witness_viewpoints
                            .iter()
                            .filter(|x| new_witnesses.contains(&x.name))
                            .cloned()
                            .collect(),
                    );

                if creator.new_witnesses.is_some()
                    && !witness_names_changed
                    && base_witness_viewpoints == effective_old_witness_viewpoints
                {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::SameValue {
                            what: format!(
                                "creator {} witnesses in schema {}",
                                creator.actual_name, schema_id
                            ),
                        },
                    });
                }

                let new_witness_viewpoints = if creator.new_witnesses.is_some() {
                    base_witness_viewpoints
                } else {
                    effective_old_witness_viewpoints
                };

                if !roles_schema.creator.insert(EventRoleCreator {
                    name: creator.actual_name.clone(),
                    namespace: new_namespace.clone(),
                    quantity: new_quantity,
                    witnesses: new_witnesses,
                    witness_viewpoints: new_witness_viewpoints,
                }) {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::AlreadyExists {
                            what: "creator with new namespace".to_owned(),
                            id: format!(
                                "{} {} in schema {}",
                                creator.actual_name, new_namespace, schema_id
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
                if issuer.actual_name != issuer.actual_name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "SchemaIdRole::check_data",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "issuer actual name in schema {}",
                                schema_id
                            ),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }
                if issuer.actual_name != ReservedWords::Any.to_string() {
                    if !issuer.actual_namespace.check() {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "issuer actual namespace in schema {}",
                                    schema_id
                                ),
                                reason: "invalid namespace".to_owned(),
                            },
                        });
                    }
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

                    if issuer.new_namespace == issuer.actual_namespace {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "issuer {} namespace in schema {}",
                                    issuer.actual_name, schema_id
                                ),
                            },
                        });
                    }

                    if !roles_schema.issuer.signers.remove(&EventRole {
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

                    if !roles_schema.issuer.signers.insert(EventRole {
                        name: issuer.actual_name.clone(),
                        namespace: issuer.new_namespace.clone(),
                    }) {
                        return Err(RunnerError::InvalidEvent {
                            location: "SchemaIdRole::check_data",
                            kind: error::InvalidEventKind::AlreadyExists {
                                what: "issuer with new namespace".to_owned(),
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

pub const fn gov_roles_event_is_empty(event: &GovRolesEvent) -> bool {
    event.approver.is_none()
        && event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn tracker_schemas_roles_add_event_is_empty(
    event: &TrackerSchemasRolesAddEvent,
) -> bool {
    event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn schema_roles_add_event_is_empty(
    event: &SchemaRolesAddEvent,
) -> bool {
    event.creator.is_none()
        && event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn tracker_schemas_roles_remove_event_is_empty(
    event: &TrackerSchemasRolesRemoveEvent,
) -> bool {
    event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn schema_roles_remove_event_is_empty(
    event: &SchemaRolesRemoveEvent,
) -> bool {
    event.creator.is_none()
        && event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn tracker_schemas_roles_change_event_is_empty(
    event: &TrackerSchemasRolesChangeEvent,
) -> bool {
    event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn schema_roles_change_event_is_empty(
    event: &SchemaRolesChangeEvent,
) -> bool {
    event.creator.is_none()
        && event.evaluator.is_none()
        && event.validator.is_none()
        && event.witness.is_none()
        && event.issuer.is_none()
}

pub const fn role_creator_change_is_empty(event: &RoleCreatorChange) -> bool {
    event.new_namespace.is_none()
        && event.new_quantity.is_none()
        && event.new_witnesses.is_none()
}

///// Schemas /////
pub const fn schemas_event_is_empty(event: &SchemasEvent) -> bool {
    event.add.is_none() && event.remove.is_none() && event.change.is_none()
}

pub fn schema_change_is_empty(event: &SchemaChange) -> bool {
    !event.actual_id.is_valid()
        || event.new_contract.is_none()
            && event.new_initial_value.is_none()
            && event.new_viewpoints.is_none()
}

///// Policies /////
pub const fn policies_event_is_empty(event: &PoliciesEvent) -> bool {
    event.governance.is_none() && event.schema.is_none()
}

pub fn schema_id_policie_is_empty(event: &SchemaIdPolicie) -> bool {
    !event.schema_id.is_valid() || schema_policie_change_is_empty(&event.change)
}

pub const fn gov_policie_change_is_empty(event: &GovPolicieChange) -> bool {
    event.approve.is_none()
        && event.evaluate.is_none()
        && event.validate.is_none()
}

pub const fn schema_policie_change_is_empty(
    event: &SchemaPolicieChange,
) -> bool {
    event.evaluate.is_none() && event.validate.is_none()
}
