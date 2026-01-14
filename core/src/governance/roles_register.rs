// Copyright 2025 Kore Ledger, SL
// SPDX-License-Identifier: AGPL-3.0-or-later

use std::collections::{HashMap, HashSet};

use crate::{
    governance::model::Quorum,
    model::{
        common::{CeilingMap, emit_fail},
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
pub struct RolesRegister {
    version: u64,

    appr_quorum: CeilingMap<Quorum>,
    approvers: CeilingMap<HashSet<PublicKey>>,

    eval_quorum: HashMap<SchemaType, CeilingMap<Quorum>>,
    evaluators: HashMap<SchemaType, CeilingMap<HashSet<RoleData>>>,

    vali_quorum: HashMap<SchemaType, CeilingMap<Quorum>>,
    validators: HashMap<SchemaType, CeilingMap<HashSet<RoleData>>>,
}

pub struct RolesRegisterUpdate {
    pub appr_quorum: bool,
    pub approvers: bool,

    pub eval_quorum: Option<Vec<SchemaType>>,
    pub evaluators: Option<Vec<SchemaType>>,

    pub vali_quorum: Option<Vec<SchemaType>>,
    pub validators: Option<Vec<SchemaType>>,
}

impl RolesRegister {
    pub fn new() -> Self {
        Self {
            version: 0,
            appr_quorum: CeilingMap::new(),
            eval_quorum: HashMap::new(),
            vali_quorum: HashMap::new(),
            evaluators: HashMap::new(),
            validators: HashMap::new(),
            approvers: CeilingMap::new(),
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
pub enum RolesRegisterMessage {
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
        eval_quorum: Option<Vec<UpdateQuorum>>,
        vali_quorum: Option<Vec<UpdateQuorum>>,
        validators: Option<Vec<UpdateRole>>,
        evaluators: Option<Vec<UpdateRole>>,
        approvers: Option<HashSet<PublicKey>>,
    },
}
impl Message for RolesRegisterMessage {}

#[derive(Debug, Clone)]
pub enum RolesRegisterResponse {
    ActualRoles {
        evaluation: RoleDataRegister,
        approval: Option<RoleDataRegister>,
    },
    Validation(RoleDataRegister),
    MissingData,
    OutOfVersion,
    Ok,
}

impl Response for RolesRegisterResponse {}

#[derive(
    Debug, Clone, Deserialize, Serialize, BorshDeserialize, BorshSerialize,
)]
pub enum RolesRegisterEvent {
    Update {
        version: u64,
        appr_quorum: Option<Quorum>,
        eval_quorum: Option<Vec<UpdateQuorum>>,
        vali_quorum: Option<Vec<UpdateQuorum>>,
        validators: Option<Vec<UpdateRole>>,
        evaluators: Option<Vec<UpdateRole>>,
        approvers: Option<HashSet<PublicKey>>,
    },
}

impl Event for RolesRegisterEvent {}

#[async_trait]
impl Actor for RolesRegister {
    type Event = RolesRegisterEvent;
    type Message = RolesRegisterMessage;
    type Response = RolesRegisterResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RolesRegister", id = id)
        } else {
            info_span!("RolesRegister", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        self.init_store("roles_register", Some(prefix), true, ctx)
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
impl Handler<RolesRegister> for RolesRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RolesRegisterMessage,
        ctx: &mut ActorContext<RolesRegister>,
    ) -> Result<RolesRegisterResponse, ActorError> {
        match msg {
            RolesRegisterMessage::SearchActualRoles {
                version,
                evaluation,
                approval,
            } => {
                if version > self.version {
                    debug!(
                        msg_type = "SearchActualRoles",
                        version = version,
                        current_version = self.version,
                        schema_id = %evaluation.schema_id,
                        namespace = %evaluation.namespace,
                        "Request version exceeds current version"
                    );
                    return Ok(RolesRegisterResponse::OutOfVersion);
                }

                'data: {
                    let approvers = if approval {
                        let gov_approvers = if let Some(approvers) =
                            self.approvers.get_prev_or_equal(version)
                        {
                            approvers
                        } else {
                            break 'data;
                        };

                        let Some(quorum) =
                            self.appr_quorum.get_prev_or_equal(version)
                        else {
                            break 'data;
                        };

                        if gov_approvers.is_empty() {
                            break 'data;
                        } else {
                            Some(RoleDataRegister {
                                workers: gov_approvers,
                                quorum,
                            })
                        }
                    } else {
                        None
                    };

                    let mut all_eval = if let Some(evaluators) =
                        self.evaluators.get(&SchemaType::AllSchemas)
                    {
                        if let Some(evaluators) =
                            evaluators.get_prev_or_equal(version)
                        {
                            let mut schema_eval = vec![];

                            for witness in evaluators {
                                if witness
                                    .namespace
                                    .is_ancestor_or_equal_of(&evaluation.namespace)
                                {
                                    schema_eval.push(witness.key);
                                }
                            }

                            schema_eval
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };

                    let mut schema_eval = if let Some(evaluators) =
                        self.evaluators.get(&evaluation.schema_id)
                    {
                        if let Some(evaluators) =
                            evaluators.get_prev_or_equal(version)
                        {
                            let mut schema_eval = vec![];

                            for witness in evaluators {
                                if witness
                                    .namespace
                                    .is_ancestor_or_equal_of(&evaluation.namespace)
                                {
                                    schema_eval.push(witness.key);
                                }
                            }

                            schema_eval
                        } else {
                            vec![]
                        }
                    } else {
                        vec![]
                    };

                    let quorum = if let Some(quorum_schema) =
                        self.eval_quorum.get(&evaluation.schema_id)
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

                    return Ok(RolesRegisterResponse::ActualRoles { evaluation: RoleDataRegister { workers: evaluators.iter().cloned().collect(), quorum }, approval: approvers } );
                }

                debug!(
                    msg_type = "SearchActualRoles",
                    version = version,
                    schema_id = %evaluation.schema_id,
                    namespace = %evaluation.namespace,
                    "Missing role data for version"
                );
                Ok(RolesRegisterResponse::MissingData)
            }
            RolesRegisterMessage::SearchValidators { search, version } => {
                if version > self.version {
                    debug!(
                        msg_type = "SearchValidators",
                        version = version,
                        current_version = self.version,
                        schema_id = %search.schema_id,
                        namespace = %search.namespace,
                        "Request version exceeds current version"
                    );
                    return Ok(RolesRegisterResponse::OutOfVersion);
                }

                let mut all_val = if let Some(validators) =
                    self.validators.get(&SchemaType::AllSchemas)
                {
                    if let Some(validators) =
                        validators.get_prev_or_equal(version)
                    {
                        let mut schema_val = vec![];

                        for witness in validators {
                            if witness
                                .namespace
                                .is_ancestor_or_equal_of(&search.namespace)
                            {
                                schema_val.push(witness.key);
                            }
                        }

                        schema_val
                    } else {
                        vec![]
                    }
                } else {
                    vec![]
                };

                let mut schema_val = if let Some(validators) =
                    self.validators.get(&search.schema_id)
                {
                    if let Some(validators) =
                        validators.get_prev_or_equal(version)
                    {
                        let mut schema_val = vec![];

                        for witness in validators {
                            if witness
                                .namespace
                                .is_ancestor_or_equal_of(&search.namespace)
                            {
                                schema_val.push(witness.key);
                            }
                        }

                        schema_val
                    } else {
                        vec![]
                    }
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

                    return Ok(RolesRegisterResponse::Validation(RoleDataRegister {
                        workers: validators.iter().cloned().collect(),
                        quorum
                    }));
                }

                debug!(
                    msg_type = "SearchValidators",
                    version = version,
                    schema_id = %search.schema_id,
                    namespace = %search.namespace,
                    "Missing validator data for version"
                );
                Ok(RolesRegisterResponse::MissingData)
            }
            RolesRegisterMessage::Update {
                version,
                eval_quorum,
                appr_quorum,
                vali_quorum,
                validators,
                evaluators,
                approvers,
            } => {
                if version > self.version {
                    ctx.publish_event(RolesRegisterEvent::Update {
                        version,
                        eval_quorum,
                        appr_quorum,
                        vali_quorum,
                        validators,
                        evaluators,
                        approvers,
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

                Ok(RolesRegisterResponse::Ok)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: RolesRegisterEvent,
        ctx: &mut ActorContext<RolesRegister>,
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
impl PersistentActor for RolesRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RolesRegisterEvent::Update {
                version,
                validators,
                evaluators,
                approvers,
                eval_quorum,
                appr_quorum,
                vali_quorum,
            } => {
                self.version = *version;

                if let Some(vali_quorum) = vali_quorum {
                    for quorum in vali_quorum.clone() {
                        self.vali_quorum
                            .entry(quorum.schema_id)
                            .or_default()
                            .insert(*version, quorum.quorum);
                    }
                    debug!(
                        event_type = "Update",
                        version = version,
                        quorum_count = vali_quorum.len(),
                        "Applied validator quorum update"
                    );
                }

                if let Some(eval_quorum) = eval_quorum {
                    for quorum in eval_quorum.clone() {
                        self.eval_quorum
                            .entry(quorum.schema_id)
                            .or_default()
                            .insert(*version, quorum.quorum);
                    }
                    debug!(
                        event_type = "Update",
                        version = version,
                        quorum_count = eval_quorum.len(),
                        "Applied evaluator quorum update"
                    );
                }

                if let Some(appr_quorum) = appr_quorum {
                    self.appr_quorum.insert(*version, appr_quorum.clone());
                    debug!(
                        event_type = "Update",
                        version = version,
                        "Applied approver quorum update"
                    );
                }

                if let Some(validators) = validators {
                    for role in validators.clone() {
                        self.validators
                            .entry(role.schema_id)
                            .or_default()
                            .insert(*version, role.role);
                    }
                    debug!(
                        event_type = "Update",
                        version = version,
                        role_count = validators.len(),
                        "Applied validator roles update"
                    );
                }

                if let Some(evaluators) = evaluators {
                    for role in evaluators.clone() {
                        self.evaluators
                            .entry(role.schema_id)
                            .or_default()
                            .insert(*version, role.role);
                    }
                    debug!(
                        event_type = "Update",
                        version = version,
                        role_count = evaluators.len(),
                        "Applied evaluator roles update"
                    );
                }

                if let Some(approvers) = approvers
                    && !approvers.is_empty()
                {
                    self.approvers.insert(*version, approvers.clone());
                    debug!(
                        event_type = "Update",
                        version = version,
                        approver_count = approvers.len(),
                        "Applied approver roles update"
                    );
                }

                debug!(
                    event_type = "Update",
                    version = version,
                    "Roles register update applied successfully"
                );
            }
        }
        Ok(())
    }
}

impl Storable for RolesRegister {}
