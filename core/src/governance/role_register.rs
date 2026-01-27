use std::collections::{HashMap, HashSet};

use crate::{
    governance::model::Quorum,
    model::common::{CeilingMap, Interval, IntervalSet, emit_fail},
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

    eval_quorum: HashMap<SchemaType, Quorum>,
    evaluators: HashMap<SchemaType, HashSet<(PublicKey, Namespace)>>,

    vali_quorum: HashMap<SchemaType, CeilingMap<Quorum>>,
    validators: HashMap<
        SchemaType,
        HashMap<(PublicKey, Namespace), (IntervalSet, Option<u64>)>,
    >,
}

impl RoleRegister {
    pub fn new() -> Self {
        Self {
            version: 0,
            appr_quorum: Quorum::Majority,
            eval_quorum: HashMap::new(),
            vali_quorum: HashMap::new(),
            evaluators: HashMap::new(),
            validators: HashMap::new(),
            approvers: HashSet::new(),
        }
    }
}

#[derive(
    Debug, Clone, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct UpdateRole {
    pub schema_id: SchemaType,
    pub role: HashSet<RoleData>,
}

#[derive(
    Debug, Clone, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub struct UpdateQuorum {
    pub schema_id: SchemaType,
    pub quorum: Quorum,
}

#[derive(Debug, Clone)]
pub struct RoleDataRegister {
    pub workers: HashSet<PublicKey>,
    pub quorum: Quorum,
}

#[derive(Debug, Clone)]
pub enum RoleRegisterMessage {
    SearchActualRoles {
        version: u64,
        evaluation: SearchRole,
        approval: bool,
    },
    SearchValidators {
        search: SearchRole,
        version: u64,
    },
    Update {
        version: u64,

        appr_quorum: Option<Quorum>,
        eval_quorum: HashMap<SchemaType, Quorum>,
        vali_quorum: HashMap<SchemaType, Quorum>,

        new_approvers: Vec<PublicKey>,
        remove_approvers: Vec<PublicKey>,

        new_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

        new_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
}
impl Message for RoleRegisterMessage {}

#[derive(Debug, Clone)]
pub enum RoleRegisterResponse {
    ActualRoles {
        evaluation: RoleDataRegister,
        approval: Option<RoleDataRegister>,
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
    Update {
        version: u64,

        appr_quorum: Option<Quorum>,
        eval_quorum: HashMap<SchemaType, Quorum>,
        vali_quorum: HashMap<SchemaType, Quorum>,

        new_approvers: Vec<PublicKey>,
        remove_approvers: Vec<PublicKey>,

        new_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

        new_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
}

impl Event for RoleRegisterEvent {}

#[async_trait]
impl Actor for RoleRegister {
    type Event = RoleRegisterEvent;
    type Message = RoleRegisterMessage;
    type Response = RoleRegisterResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RoleRegister", id = id)
        } else {
            info_span!("RoleRegister", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        self.init_store("role_register", Some(prefix), true, ctx)
            .await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<RoleRegister> for RoleRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RoleRegisterMessage,
        ctx: &mut ActorContext<RoleRegister>,
    ) -> Result<RoleRegisterResponse, ActorError> {
        match msg {
            RoleRegisterMessage::SearchActualRoles {
                version,
                evaluation,
                approval,
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

                    let mut all_eval = if !evaluation.schema_id.is_gov()
                        && let Some(evaluators) =
                            self.evaluators.get(&SchemaType::AllSchemas)
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
                        self.validators.get(&SchemaType::AllSchemas)
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
            RoleRegisterMessage::Update {
                version,
                appr_quorum,
                eval_quorum,
                vali_quorum,
                new_approvers,
                remove_approvers,
                new_evaluators,
                remove_evaluators,
                new_validators,
                remove_validators,
            } => {
                if version > self.version {
                    ctx.publish_event(RoleRegisterEvent::Update {
                        version,
                        appr_quorum,
                        eval_quorum,
                        vali_quorum,
                        new_approvers,
                        remove_approvers,
                        new_evaluators,
                        remove_evaluators,
                        new_validators,
                        remove_validators,
                    })
                    .await?;

                    debug!(
                        msg_type = "Update",
                        version = version,
                        "Roles register updated successfully"
                    );
                } else {
                    debug!(
                        msg_type = "Update",
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
        ctx: &mut ActorContext<RoleRegister>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                error = %e,
                "Failed to persist roles register event"
            );
            emit_fail(ctx, e).await;
        } else {
            debug!("Roles register event persisted successfully");
        }
    }
}

#[async_trait]
impl PersistentActor for RoleRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RoleRegisterEvent::Update {
                version,
                appr_quorum,
                eval_quorum,
                vali_quorum,
                new_approvers,
                remove_approvers,
                new_evaluators,
                remove_evaluators,
                new_validators,
                remove_validators,
            } => {
                self.version = *version;

                if let Some(appr_quorum) = appr_quorum {
                    self.appr_quorum = appr_quorum.clone();
                }

                for (schema_id, quorum) in vali_quorum.iter() {
                    self.vali_quorum
                        .entry(schema_id.clone())
                        .or_default()
                        .insert(*version, quorum.clone());
                }

                for (schema_id, quorum) in eval_quorum.iter() {
                    self.eval_quorum.insert(schema_id.clone(), quorum.clone());
                }

                for approver in new_approvers.iter() {
                    self.approvers.insert(approver.clone());
                }

                for approver in remove_approvers.iter() {
                    self.approvers.remove(approver);
                }

                for ((schema_id, evaluator), namespaces) in
                    new_evaluators.iter()
                {
                    for ns in namespaces.iter() {
                        self.evaluators
                            .entry(schema_id.clone())
                            .or_default()
                            .insert((evaluator.clone(), ns.clone()));
                    }
                }

                for ((schema_id, evaluator), namespaces) in
                    remove_evaluators.iter()
                {
                    for ns in namespaces.iter() {
                        self.evaluators
                            .entry(schema_id.clone())
                            .or_default()
                            .remove(&(evaluator.clone(), ns.clone()));
                    }
                }

                for ((schema_id, validator), namespaces) in
                    new_validators.iter()
                {
                    for ns in namespaces.iter() {
                        self.validators
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
                        let (interval, last) = self
                            .validators
                            .entry(schema_id.clone())
                            .or_default()
                            .entry((validator.clone(), ns.clone()))
                            .or_default();
                        if let Some(last) = last.take() {
                            interval.insert(Interval {
                                lo: last,
                                hi: *version,
                            });
                        }
                    }
                }
            }
        }
        Ok(())
    }
}

impl Storable for RoleRegister {}
