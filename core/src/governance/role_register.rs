use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::{
    governance::model::Quorum,
    model::common::{
        CeilingMap, Interval, IntervalSet, crash_system, purge_storage,
    },
};
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler,
    LightPersistence, Message, PersistentActor, Response,
};

use ave_common::{Namespace, SchemaType, identity::PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::db::Storable;

#[derive(Debug, Clone, Serialize, Deserialize, Hash, Eq, PartialEq)]
pub struct SearchRole {
    pub schema_id: SchemaType,
    pub namespace: Namespace,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Hash,
    Eq,
    PartialEq,
    Ord,
    PartialOrd,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RoleData {
    pub key: PublicKey,
    pub namespace: Namespace,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Default,
)]
pub struct RoleRegister {
    version: u64,

    appr_quorum: Quorum,
    approvers: HashSet<PublicKey>,

    comp_quorum: Quorum,
    compilers: HashSet<PublicKey>,

    eval_quorum: HashMap<SchemaType, Quorum>,
    evaluators: HashMap<SchemaType, HashSet<(PublicKey, Namespace)>>,

    vali_quorum: HashMap<SchemaType, CeilingMap<Quorum>>,
    validators:
        HashMap<SchemaType, HashMap<(PublicKey, Namespace), IntervalData>>,
}

type IntervalData = (IntervalSet, Option<u64>);

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RoleDataRegister {
    pub workers: HashSet<PublicKey>,
    pub quorum: Quorum,
}

#[derive(Debug, Clone)]
pub struct CurrentSchemaRoles {
    pub evaluation: HashSet<RoleData>,
    pub evaluation_quorum: Quorum,
    pub validation: HashSet<RoleData>,
    pub validation_quorum: Quorum,
}

#[derive(Debug, Clone)]
pub struct CurrentValidationRoles {
    pub approval: RoleDataRegister,
    pub compilation: RoleDataRegister,
    pub schema: CurrentSchemaRoles,
}

#[derive(Debug, Clone)]
pub enum RoleRegisterMessage {
    PurgeStorage,
    GetCurrentValidationRoles {
        schema_id: SchemaType,
    },
    SearchActualRoles {
        version: u64,
        evaluation: SearchRole,
        approval: bool,
        compilation: bool,
    },
    SearchValidators {
        search: SearchRole,
        version: u64,
    },
    UpdateVersion {
        version: u64,
    },
    UpdateFact {
        version: u64,

        appr_quorum: Option<Quorum>,
        comp_quorum: Option<Quorum>,
        eval_quorum: HashMap<SchemaType, Quorum>,
        vali_quorum: HashMap<SchemaType, Quorum>,

        new_approvers: Vec<PublicKey>,
        remove_approvers: Vec<PublicKey>,

        new_compilers: Vec<PublicKey>,
        remove_compilers: Vec<PublicKey>,

        new_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

        new_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
    UpdateConfirm {
        version: u64,

        new_approver: Option<PublicKey>,
        remove_approver: PublicKey,

        new_compiler: Option<PublicKey>,
        remove_compiler: PublicKey,

        new_evaluator: Option<PublicKey>,
        remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

        new_validator: Option<PublicKey>,
        remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
}
impl Message for RoleRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::PurgeStorage
                | Self::UpdateVersion { .. }
                | Self::UpdateFact { .. }
                | Self::UpdateConfirm { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub enum RoleRegisterResponse {
    CurrentValidationRoles(CurrentValidationRoles),
    ActualRoles {
        evaluation: RoleDataRegister,
        approval: Option<RoleDataRegister>,
        compilation: Option<RoleDataRegister>,
    },
    Validation(RoleDataRegister),
    MissingData,
    OutOfVersion,
    Ok,
}

impl Response for RoleRegisterResponse {}

#[derive(
    Debug, Clone, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub enum RoleRegisterEvent {
    UpdateVersion {
        version: u64,
    },
    UpdateFact {
        version: u64,

        appr_quorum: Option<Quorum>,
        comp_quorum: Option<Quorum>,
        eval_quorum: HashMap<SchemaType, Quorum>,
        vali_quorum: HashMap<SchemaType, Quorum>,

        new_approvers: Vec<PublicKey>,
        remove_approvers: Vec<PublicKey>,

        new_compilers: Vec<PublicKey>,
        remove_compilers: Vec<PublicKey>,

        new_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

        new_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
    UpdateConfirm {
        version: u64,

        new_approver: Option<PublicKey>,
        remove_approver: PublicKey,

        new_compiler: Option<PublicKey>,
        remove_compiler: PublicKey,

        new_evaluator: Option<PublicKey>,
        remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

        new_validator: Option<PublicKey>,
        remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
}

impl Event for RoleRegisterEvent {}

#[async_trait]
impl Actor for RoleRegister {
    type Event = RoleRegisterEvent;
    type Message = RoleRegisterMessage;
    type Response = RoleRegisterResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("RoleRegister"),
            |parent_span| info_span!(parent: parent_span, "RoleRegister"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self
            .init_store(
                "role_register",
                Some(ctx.path().parent().key().to_owned()),
                true,
                ctx,
            )
            .await
        {
            error!(
                error = %e,
                "Failed to initialize role_register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for RoleRegister {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: RoleRegisterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<RoleRegisterResponse, ActorError> {
        match msg {
            RoleRegisterMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    "Role register storage purged"
                );

                Ok(RoleRegisterResponse::Ok)
            }
            RoleRegisterMessage::GetCurrentValidationRoles { schema_id } => {
                let approval = RoleDataRegister {
                    workers: self.approvers.clone(),
                    quorum: self.appr_quorum.clone(),
                };

                let compilation = RoleDataRegister {
                    workers: self.compilers.clone(),
                    quorum: self.comp_quorum.clone(),
                };

                let Some(evaluation_quorum) =
                    self.eval_quorum.get(&schema_id).cloned()
                else {
                    return Ok(RoleRegisterResponse::MissingData);
                };

                let Some(validation_quorum) = self
                    .vali_quorum
                    .get(&schema_id)
                    .and_then(|quorum| quorum.get_prev_or_equal(self.version))
                else {
                    return Ok(RoleRegisterResponse::MissingData);
                };

                let mut evaluation = HashSet::new();
                if !schema_id.is_gov()
                    && let Some(evaluators) =
                        self.evaluators.get(&SchemaType::TrackerSchemas)
                {
                    for (key, namespace) in evaluators {
                        evaluation.insert(RoleData {
                            key: key.clone(),
                            namespace: namespace.clone(),
                        });
                    }
                }

                if let Some(evaluators) = self.evaluators.get(&schema_id) {
                    for (key, namespace) in evaluators {
                        evaluation.insert(RoleData {
                            key: key.clone(),
                            namespace: namespace.clone(),
                        });
                    }
                }

                let mut validation = HashSet::new();
                if !schema_id.is_gov()
                    && let Some(validators) =
                        self.validators.get(&SchemaType::TrackerSchemas)
                {
                    for ((key, namespace), (_, last)) in validators {
                        if let Some(last) = last
                            && *last <= self.version
                        {
                            validation.insert(RoleData {
                                key: key.clone(),
                                namespace: namespace.clone(),
                            });
                        }
                    }
                }

                if let Some(validators) = self.validators.get(&schema_id) {
                    for ((key, namespace), (_, last)) in validators {
                        if let Some(last) = last
                            && *last <= self.version
                        {
                            validation.insert(RoleData {
                                key: key.clone(),
                                namespace: namespace.clone(),
                            });
                        }
                    }
                }

                Ok(RoleRegisterResponse::CurrentValidationRoles(
                    CurrentValidationRoles {
                        approval,
                        compilation,
                        schema: CurrentSchemaRoles {
                            evaluation,
                            evaluation_quorum,
                            validation,
                            validation_quorum,
                        },
                    },
                ))
            }
            RoleRegisterMessage::SearchActualRoles {
                version,
                evaluation,
                approval,
                compilation,
            } => {
                if version != self.version {
                    debug!(
                        msg_type = "SearchActualRoles",
                        version = version,
                        current_version = self.version,
                        schema_id = %evaluation.schema_id,
                        namespace = %evaluation.namespace,
                        "Request version exceeds current version"
                    );
                    return Ok(RoleRegisterResponse::OutOfVersion);
                }

                'data: {
                    let approvers = if approval {
                        if self.approvers.is_empty() {
                            break 'data;
                        } else {
                            Some(RoleDataRegister {
                                workers: self.approvers.clone(),
                                quorum: self.appr_quorum.clone(),
                            })
                        }
                    } else {
                        None
                    };

                    let compilers = if compilation {
                        if self.compilers.is_empty() {
                            break 'data;
                        } else {
                            Some(RoleDataRegister {
                                workers: self.compilers.clone(),
                                quorum: self.comp_quorum.clone(),
                            })
                        }
                    } else {
                        None
                    };

                    let mut all_eval = if !evaluation.schema_id.is_gov()
                        && let Some(evaluators) =
                            self.evaluators.get(&SchemaType::TrackerSchemas)
                    {
                        let mut schema_eval = vec![];
                        for (key, namespace) in evaluators {
                            if namespace
                                .is_ancestor_or_equal_of(&evaluation.namespace)
                            {
                                schema_eval.push(key.clone());
                            }
                        }

                        schema_eval
                    } else {
                        vec![]
                    };

                    let mut schema_eval = if let Some(evaluators) =
                        self.evaluators.get(&evaluation.schema_id)
                    {
                        let mut schema_eval = vec![];
                        for (key, namespace) in evaluators {
                            if namespace
                                .is_ancestor_or_equal_of(&evaluation.namespace)
                            {
                                schema_eval.push(key.clone());
                            }
                        }

                        schema_eval
                    } else {
                        vec![]
                    };

                    let quorum = if let Some(quorum_schema) =
                        self.eval_quorum.get(&evaluation.schema_id)
                    {
                        quorum_schema.clone()
                    } else {
                        break 'data;
                    };

                    if schema_eval.is_empty() && all_eval.is_empty() {
                        break 'data;
                    }

                    let mut evaluators = vec![];
                    evaluators.append(&mut schema_eval);
                    evaluators.append(&mut all_eval);

                    debug!(
                        msg_type = "SearchActualRoles",
                        version = version,
                        schema_id = %evaluation.schema_id,
                        namespace = %evaluation.namespace,
                        evaluators_count = evaluators.len(),
                        has_approvers = approvers.is_some(),
                        "Found actual roles successfully"
                    );

                    return Ok(RoleRegisterResponse::ActualRoles {
                        evaluation: RoleDataRegister {
                            workers: evaluators.iter().cloned().collect(),
                            quorum,
                        },
                        approval: approvers,
                        compilation: compilers,
                    });
                }

                debug!(
                    msg_type = "SearchActualRoles",
                    version = version,
                    schema_id = %evaluation.schema_id,
                    namespace = %evaluation.namespace,
                    "Missing role data for version"
                );
                Ok(RoleRegisterResponse::MissingData)
            }
            RoleRegisterMessage::SearchValidators { search, version } => {
                if version > self.version {
                    debug!(
                        msg_type = "SearchValidators",
                        version = version,
                        current_version = self.version,
                        schema_id = %search.schema_id,
                        namespace = %search.namespace,
                        "Request version exceeds current version"
                    );
                    return Ok(RoleRegisterResponse::OutOfVersion);
                }

                let mut all_val = if !search.schema_id.is_gov()
                    && let Some(validators) =
                        self.validators.get(&SchemaType::TrackerSchemas)
                {
                    // PublicKey, Namespace), (IntervalSet, Option<u64>
                    let mut schema_val = vec![];
                    for ((key, namespace), (interval, last)) in validators {
                        if namespace.is_ancestor_or_equal_of(&search.namespace)
                        {
                            if let Some(last) = last
                                && last <= &version
                            {
                                schema_val.push(key.clone());
                            } else if interval.contains(version) {
                                schema_val.push(key.clone());
                            }
                        }
                    }

                    schema_val
                } else {
                    vec![]
                };

                let mut schema_val = if let Some(validators) =
                    self.validators.get(&search.schema_id)
                {
                    let mut schema_val = vec![];
                    for ((key, namespace), (interval, last)) in validators {
                        if namespace.is_ancestor_or_equal_of(&search.namespace)
                        {
                            if let Some(last) = last
                                && last <= &version
                            {
                                schema_val.push(key.clone());
                            } else if interval.contains(version) {
                                schema_val.push(key.clone());
                            }
                        }
                    }

                    schema_val
                } else {
                    vec![]
                };

                'data: {
                    let quorum = if let Some(quorum_schema) =
                        self.vali_quorum.get(&search.schema_id)
                    {
                        let Some(quorum) =
                            quorum_schema.get_prev_or_equal(version)
                        else {
                            break 'data;
                        };

                        quorum
                    } else {
                        break 'data;
                    };

                    if schema_val.is_empty() && all_val.is_empty() {
                        break 'data;
                    }

                    let mut validators = vec![];
                    validators.append(&mut schema_val);
                    validators.append(&mut all_val);

                    debug!(
                        msg_type = "SearchValidators",
                        version = version,
                        schema_id = %search.schema_id,
                        namespace = %search.namespace,
                        validators_count = validators.len(),
                        "Found validators successfully"
                    );

                    return Ok(RoleRegisterResponse::Validation(
                        RoleDataRegister {
                            workers: validators.iter().cloned().collect(),
                            quorum,
                        },
                    ));
                }

                debug!(
                    msg_type = "SearchValidators",
                    version = version,
                    schema_id = %search.schema_id,
                    namespace = %search.namespace,
                    "Missing validator data for version"
                );
                Ok(RoleRegisterResponse::MissingData)
            }
            RoleRegisterMessage::UpdateVersion { version } => {
                if version > self.version || self.version == 0 {
                    self.on_event(
                        RoleRegisterEvent::UpdateVersion { version },
                        ctx,
                    )
                    .await;

                    debug!(
                        msg_type = "UpdateVersion",
                        version = version,
                        "Roles register updated successfully"
                    );
                } else {
                    debug!(
                        msg_type = "UpdateVersion",
                        version = version,
                        current_version = self.version,
                        "Update skipped, version not greater than current"
                    );
                }

                Ok(RoleRegisterResponse::Ok)
            }
            RoleRegisterMessage::UpdateConfirm {
                version,
                new_approver,
                remove_approver,
                new_compiler,
                remove_compiler,
                new_evaluator,
                remove_evaluators,
                new_validator,
                remove_validators,
            } => {
                if version > self.version || self.version == 0 {
                    self.on_event(
                        RoleRegisterEvent::UpdateConfirm {
                            version,
                            new_approver,
                            remove_approver,
                            new_compiler,
                            remove_compiler,
                            new_evaluator,
                            remove_evaluators,
                            new_validator,
                            remove_validators,
                        },
                        ctx,
                    )
                    .await;

                    debug!(
                        msg_type = "UpdateConfirm",
                        version = version,
                        "Roles register updated successfully"
                    );
                } else {
                    debug!(
                        msg_type = "UpdateConfirm",
                        version = version,
                        current_version = self.version,
                        "Update skipped, version not greater than current"
                    );
                }

                Ok(RoleRegisterResponse::Ok)
            }
            RoleRegisterMessage::UpdateFact {
                version,
                appr_quorum,
                comp_quorum,
                eval_quorum,
                vali_quorum,
                new_approvers,
                remove_approvers,
                new_compilers,
                remove_compilers,
                new_evaluators,
                remove_evaluators,
                new_validators,
                remove_validators,
            } => {
                if version > self.version || self.version == 0 {
                    self.on_event(
                        RoleRegisterEvent::UpdateFact {
                            version,
                            appr_quorum,
                            comp_quorum,
                            eval_quorum,
                            vali_quorum,
                            new_approvers,
                            remove_approvers,
                            new_compilers,
                            remove_compilers,
                            new_evaluators,
                            remove_evaluators,
                            new_validators,
                            remove_validators,
                        },
                        ctx,
                    )
                    .await;

                    debug!(
                        msg_type = "UpdateFact",
                        version = version,
                        "Roles register updated successfully"
                    );
                } else {
                    debug!(
                        msg_type = "UpdateFact",
                        version = version,
                        current_version = self.version,
                        "Update skipped, version not greater than current"
                    );
                }

                Ok(RoleRegisterResponse::Ok)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: RoleRegisterEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        let version = match &event {
            RoleRegisterEvent::UpdateFact { version, .. } => *version,
            RoleRegisterEvent::UpdateVersion { version } => *version,
            RoleRegisterEvent::UpdateConfirm { version, .. } => *version,
        };
        if let Err(e) = self.persist(event, ctx).await {
            error!(
                version = version,
                error = %e,
                "Failed to persist role register event"
            );
            crash_system(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for RoleRegister {
    type Persistence = LightPersistence;
    type InitParams = ();
    type State = Self;

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            RoleRegisterEvent::UpdateVersion { version } => {
                inner.version = *version;
            }
            RoleRegisterEvent::UpdateConfirm {
                version,
                new_approver,
                remove_approver,
                new_compiler,
                remove_compiler,
                new_evaluator,
                remove_evaluators,
                new_validator,
                remove_validators,
            } => {
                inner.version = *version;
                if let Some(approver) = new_approver {
                    inner.approvers.insert(approver.clone());
                }

                if let Some(compiler) = new_compiler {
                    inner.compilers.insert(compiler.clone());
                }

                if let Some(evaluator) = new_evaluator {
                    inner
                        .evaluators
                        .entry(SchemaType::Governance)
                        .or_default()
                        .insert((evaluator.clone(), Namespace::new()));
                }

                if let Some(validator) = new_validator {
                    inner
                        .validators
                        .entry(SchemaType::Governance)
                        .or_default()
                        .entry((validator.clone(), Namespace::new()))
                        .or_default()
                        .1 = Some(*version);
                }

                inner.approvers.remove(remove_approver);

                inner.compilers.remove(remove_compiler);

                for ((schema_id, evaluator), namespaces) in
                    remove_evaluators.iter()
                {
                    for ns in namespaces.iter() {
                        inner
                            .evaluators
                            .entry(schema_id.clone())
                            .or_default()
                            .remove(&(evaluator.clone(), ns.clone()));
                    }
                }

                for ((schema_id, validator), namespaces) in
                    remove_validators.iter()
                {
                    for ns in namespaces.iter() {
                        let (interval, last) = inner
                            .validators
                            .entry(schema_id.clone())
                            .or_default()
                            .entry((validator.clone(), ns.clone()))
                            .or_default();
                        if let Some(last) = last.take() {
                            interval.insert(Interval {
                                lo: last,
                                hi: *version - 1,
                            });
                        }
                    }
                }

                debug!(
                    event_type = "UpdateFact",
                    version = version,
                    new_approver = new_approver.is_some(),
                    remove_approvers_count = 1,
                    new_evaluator = new_evaluator.is_some(),
                    remove_evaluators_count = remove_evaluators.len(),
                    new_validator = new_validator.is_some(),
                    remove_validators_count = remove_validators.len(),
                    "Role register state updated"
                );
            }
            RoleRegisterEvent::UpdateFact {
                version,
                appr_quorum,
                comp_quorum,
                eval_quorum,
                vali_quorum,
                new_approvers,
                remove_approvers,
                new_compilers,
                remove_compilers,
                new_evaluators,
                remove_evaluators,
                new_validators,
                remove_validators,
            } => {
                inner.version = *version;

                if let Some(appr_quorum) = appr_quorum {
                    inner.appr_quorum = appr_quorum.clone();
                }

                if let Some(comp_quorum) = comp_quorum {
                    inner.comp_quorum = comp_quorum.clone();
                }

                for (schema_id, quorum) in vali_quorum.iter() {
                    inner
                        .vali_quorum
                        .entry(schema_id.clone())
                        .or_default()
                        .insert(*version, quorum.clone());
                }

                for (schema_id, quorum) in eval_quorum.iter() {
                    inner.eval_quorum.insert(schema_id.clone(), quorum.clone());
                }

                for approver in new_approvers.iter() {
                    inner.approvers.insert(approver.clone());
                }

                for approver in remove_approvers.iter() {
                    inner.approvers.remove(approver);
                }

                for compiler in new_compilers.iter() {
                    inner.compilers.insert(compiler.clone());
                }

                for compiler in remove_compilers.iter() {
                    inner.compilers.remove(compiler);
                }

                for ((schema_id, evaluator), namespaces) in
                    new_evaluators.iter()
                {
                    for ns in namespaces.iter() {
                        inner
                            .evaluators
                            .entry(schema_id.clone())
                            .or_default()
                            .insert((evaluator.clone(), ns.clone()));
                    }
                }

                for ((schema_id, evaluator), namespaces) in
                    remove_evaluators.iter()
                {
                    for ns in namespaces.iter() {
                        inner
                            .evaluators
                            .entry(schema_id.clone())
                            .or_default()
                            .remove(&(evaluator.clone(), ns.clone()));
                    }
                }

                for ((schema_id, validator), namespaces) in
                    new_validators.iter()
                {
                    for ns in namespaces.iter() {
                        inner
                            .validators
                            .entry(schema_id.clone())
                            .or_default()
                            .entry((validator.clone(), ns.clone()))
                            .or_default()
                            .1 = Some(*version);
                    }
                }

                for ((schema_id, validator), namespaces) in
                    remove_validators.iter()
                {
                    for ns in namespaces.iter() {
                        let (interval, last) = inner
                            .validators
                            .entry(schema_id.clone())
                            .or_default()
                            .entry((validator.clone(), ns.clone()))
                            .or_default();
                        if let Some(last) = last.take() {
                            interval.insert(Interval {
                                lo: last,
                                hi: *version - 1,
                            });
                        }
                    }
                }

                debug!(
                    event_type = "UpdateFact",
                    version = version,
                    new_approvers_count = new_approvers.len(),
                    remove_approvers_count = remove_approvers.len(),
                    new_evaluators_count = new_evaluators.len(),
                    remove_evaluators_count = remove_evaluators.len(),
                    new_validators_count = new_validators.len(),
                    remove_validators_count = remove_validators.len(),
                    "Role register state updated"
                );
            }
        }
        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        Arc::new(self.clone())
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        *self = (*state).clone();
    }
}

impl Storable for RoleRegister {}
