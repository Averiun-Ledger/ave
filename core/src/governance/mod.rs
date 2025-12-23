//! # Governance module.
//!

use crate::{
    Error, EventRequestType,
    approval::{
        Approval,
        approver::{Approver, InitApprover, VotationType},
    },
    auth::WitnessesAuth,
    db::Storable,
    distribution::{Distribution, DistributionType},
    evaluation::{
        Evaluation,
        compiler::{Compiler, CompilerMessage},
        evaluator::Evaluator,
        schema::{EvaluationSchema, EvaluationSchemaMessage},
    },
    governance::{
        data::GovernanceData,
        events::GovernanceEvent,
        model::{HashThisRole, ProtocolTypes, RoleTypes, Schema},
        relationship::RelationShip,
        roles_register::{
            RoleData, RolesRegister, RolesRegisterMessage, RolesRegisterUpdate,
            UpdateQuorum, UpdateRole,
        },
    },
    helpers::{db::ExternalDB, sink::AveSink},
    model::{
        common::{
            emit_fail, get_last_event, get_n_events, get_node_key,
            node::{UpdateData, try_to_update},
            purge_storage,
            subject::get_last_state,
        },
        event::{Ledger, LedgerValue},
        request::{EventRequest, SchemaType},
    },
    node::register::RegisterMessage,
    subject::{
        CreateSubjectData, DataForSink, LastStateData, Metadata, SignedLedger,
        Subject, SubjectMetadata, VerifyData,
        laststate::LastState,
        sinkdata::{SinkData, SinkDataMessage},
    },
    system::ConfigHelper,
    update::{self, TransferResponse},
    validation::{
        Validation,
        schema::{ValidationSchema, ValidationSchemaMessage},
        validator::Validator,
    },
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, Response, Sink,
};
use ave_common::{
    Namespace,
    identity::{DigestIdentifier, PublicKey, Signed, hash_borsh},
};

use async_trait::async_trait;
use ave_actors::{FullPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use std::collections::{BTreeMap, HashMap, HashSet};

pub mod data;
pub mod events;
pub mod model;
pub mod relationship;
pub mod roles_register;

const TARGET_GOVERNANCE: &str = "Ave-Governance";

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Clone,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Governance {
    pub subject_metadata: SubjectMetadata,
    /// The current status of the subject.
    pub properties: GovernanceData,
}

impl From<CreateSubjectData> for Governance {
    fn from(value: CreateSubjectData) -> Self {
        Governance {
            subject_metadata: SubjectMetadata::new(&value),
            properties: serde_json::from_value::<GovernanceData>(value.value.0)
                .expect("schema_id is governance"),
        }
    }
}

#[async_trait]
impl Subject for Governance {
    async fn delete_subject(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        Self::delet_node_subject(
            ctx,
            &self.subject_metadata.subject_id.to_string(),
        )
        .await?;

        purge_storage(ctx).await?;

        ctx.stop(None).await;

        Ok(())
    }

    async fn get_ledger_data(
        &self,
        ctx: &mut ActorContext<Self>,
        last_sn: u64,
    ) -> Result<(Vec<SignedLedger>, Option<LastStateData>), ActorError> {
        let ledger = get_n_events(ctx, last_sn, 100).await?;

        if ledger.len() < 100 {
            match get_last_state(
                ctx,
                &self.subject_metadata.subject_id.to_string(),
            )
            .await
            {
                Ok((event, proof, vali_res)) => Ok((
                    ledger,
                    Some(LastStateData {
                        event,
                        proof,
                        vali_res,
                    }),
                )),
                Err(e) => {
                    if let ActorError::Functional(_) = e {
                        Ok((ledger, None))
                    } else {
                        error!(
                            TARGET_GOVERNANCE,
                            "GetLedger, can not get last event: {}", e
                        );
                        Err(e)
                    }
                }
            }
        } else {
            Ok((ledger, None))
        }
    }

    fn apply_patch(&mut self, value: LedgerValue) -> Result<(), ActorError> {
        let json_patch = match value {
            LedgerValue::Patch(value_wrapper) => value_wrapper,
            LedgerValue::Error(e) => {
                let error = format!(
                    "Apply, event value can not be an error if protocols was successful: {:?}",
                    e
                );
                error!(TARGET_GOVERNANCE, error);
                return Err(ActorError::Functional(error));
            }
        };

        let patch_json = match serde_json::from_value::<Patch>(json_patch.0) {
            Ok(patch) => patch,
            Err(e) => {
                let error = format!("Apply, can not obtain json patch: {}", e);
                error!(TARGET_GOVERNANCE, error);
                return Err(ActorError::Functional(error));
            }
        };
        let mut properties = self.properties.to_value_wrapper();

        if let Err(e) = patch(&mut properties.0, &patch_json) {
            let error = format!("Apply, can not apply json patch: {}", e);
            error!(TARGET_GOVERNANCE, error);
            return Err(ActorError::Functional(error));
        };

        self.properties = serde_json::from_value::<GovernanceData>(
            properties.0,
        )
        .map_err(|e| {
            let error =
                format!("Can not convert value into GovernanceData: {}", e);
            error!(TARGET_GOVERNANCE, error);
            ActorError::Functional(error)
        })?;

        Ok(())
    }

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let our_key = get_node_key(ctx).await?;
        let current_sn = self.subject_metadata.sn;
        let current_new_owner_some = self.subject_metadata.new_owner.is_some();
        let i_current_new_owner =
            self.subject_metadata.new_owner.clone() == Some(our_key.clone());
        let current_owner = self.subject_metadata.owner.clone();

        let current_properties = self.properties.clone();

        if let Err(e) = self.verify_new_ledger_events(ctx, events).await {
            if let ActorError::Functional(error) = e.clone() {
                warn!(
                    TARGET_GOVERNANCE,
                    "Error verifying new events: {}", error
                );

                // Falló en la creación
                if self.subject_metadata.sn == 0 {
                    return Err(e);
                }
            } else {
                error!(TARGET_GOVERNANCE, "Error verifying new events {}", e);
                return Err(e);
            }
        };

        if current_sn < self.subject_metadata.sn {
            let old_gov = GovernanceData::try_from(current_properties)
                .map_err(|e| ActorError::FunctionalFail(e.to_string()))?;
            if !self.subject_metadata.active {
                if current_owner == our_key {
                    Self::down_owner(ctx).await?;
                } else {
                    Self::down_not_owner(ctx, old_gov.clone(), our_key.clone())
                        .await?;
                }

                let old_schemas_eval = old_gov
                    .schemas(ProtocolTypes::Evaluation, &our_key)
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<SchemaType>>();
                Self::down_compilers_schemas(ctx, old_schemas_eval.clone())
                    .await?;

                let old_schemas_val = old_gov
                    .schemas(ProtocolTypes::Validation, &our_key)
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<SchemaType>>();

                Self::down_schemas(ctx, old_schemas_eval, old_schemas_val)
                    .await?;
            } else {
                let new_gov = GovernanceData::try_from(self.properties.clone())
                    .map_err(|e| ActorError::FunctionalFail(e.to_string()))?;

                let Some(ext_db): Option<ExternalDB> =
                    ctx.system().get_helper("ext_db").await
                else {
                    return Err(ActorError::NotHelper("config".to_owned()));
                };

                let new_owner_some = self.subject_metadata.new_owner.is_some();
                let i_new_owner = self.subject_metadata.new_owner.clone()
                    == Some(our_key.clone());
                let mut up_not_owner: bool = false;
                let mut up_owner: bool = false;

                if current_owner == our_key {
                    // Eramos dueños
                    if current_owner != self.subject_metadata.owner {
                        // Ya no somos dueño
                        if !current_new_owner_some && !i_new_owner {
                            // Si antes new owner false
                            up_not_owner = true;
                        } else if current_new_owner_some && i_new_owner {
                            up_owner = true;
                        }
                    } else {
                        // Seguimos siendo dueños
                        if current_new_owner_some && !new_owner_some {
                            up_owner = true;
                        } else if !current_new_owner_some && new_owner_some {
                            up_not_owner = true;
                        }
                    }
                } else {
                    // No eramos dueño
                    if current_owner != self.subject_metadata.owner
                        && self.subject_metadata.owner == our_key
                    {
                        // Ahora Somos dueños
                        if !new_owner_some && !i_current_new_owner {
                            // new owner false
                            up_owner = true;
                        } else if new_owner_some && i_current_new_owner {
                            up_not_owner = true;
                        }
                    } else if i_current_new_owner && !i_new_owner {
                        up_not_owner = true;
                    } else if !i_current_new_owner && i_new_owner {
                        up_owner = true;
                    }
                }

                if up_not_owner {
                    Self::down_owner(ctx).await?;
                    Self::up_not_owner(
                        ctx,
                        new_gov.clone(),
                        our_key.clone(),
                        ext_db.clone(),
                        self.subject_metadata.subject_id.clone(),
                    )
                    .await?;
                } else if up_owner {
                    Self::down_not_owner(ctx, old_gov.clone(), our_key.clone())
                        .await?;
                    Self::up_owner(
                        ctx,
                        our_key.clone(),
                        self.subject_metadata.subject_id.clone(),
                        ext_db.clone(),
                    )
                    .await?;
                }

                // Seguimos sin ser owner ni new owner,
                // pero tenemos que ver si tenemos un rol nuevo.
                if !up_not_owner
                    && !up_owner
                    && our_key != self.subject_metadata.owner
                {
                    Self::up_down_not_owner(
                        ctx,
                        new_gov.clone(),
                        old_gov.clone(),
                        our_key.clone(),
                        ext_db.clone(),
                        self.subject_metadata.subject_id.clone(),
                    )
                    .await?;
                }

                let old_schemas_eval =
                    old_gov.schemas(ProtocolTypes::Evaluation, &our_key);
                let new_schemas_eval =
                    new_gov.schemas(ProtocolTypes::Evaluation, &our_key);

                // Bajamos los compilers que ya no soy evaluador
                let down = old_schemas_eval
                    .clone()
                    .iter()
                    .filter(|x| !new_schemas_eval.contains_key(x.0))
                    .map(|x| x.0.clone())
                    .collect();
                Self::down_compilers_schemas(ctx, down).await?;

                // Subimos los compilers que soy nuevo evaluador
                let up = new_schemas_eval
                    .clone()
                    .iter()
                    .filter(|x| !old_schemas_eval.contains_key(x.0))
                    .map(|x| (x.0.clone(), x.1.clone()))
                    .collect();
                Self::up_compilers_schemas(
                    ctx,
                    up,
                    self.subject_metadata.subject_id.clone(),
                )
                .await?;

                // Compilo los nuevos contratos en el caso de que hayan sido modificados, sino no afecta.
                let current = new_schemas_eval
                    .clone()
                    .iter()
                    .filter(|x| old_schemas_eval.contains_key(x.0))
                    .map(|x| (x.0.clone(), x.1.clone()))
                    .collect();
                Self::compile_schemas(
                    ctx,
                    current,
                    self.subject_metadata.subject_id.clone(),
                )
                .await?;

                let mut old_schemas_eval = old_schemas_eval
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<SchemaType>>();
                let mut old_schemas_val = old_gov
                    .schemas(ProtocolTypes::Validation, &our_key)
                    .iter()
                    .map(|x| x.0.clone())
                    .collect::<Vec<SchemaType>>();

                let new_creators =
                    new_gov.subjects_schemas_rol_namespace(&our_key);

                for creators in new_creators {
                    if let Some(eval_users) = creators.evaluation {
                        let pos = old_schemas_eval
                            .iter()
                            .position(|x| *x == creators.schema_id);

                        if let Some(pos) = pos {
                            old_schemas_eval.remove(pos);
                            let actor: Option<ActorRef<EvaluationSchema>> = ctx
                                .get_child(&format!(
                                    "{}_evaluation",
                                    creators.schema_id
                                ))
                                .await;
                            if let Some(actor) = actor {
                                if let Err(e) = actor.tell(EvaluationSchemaMessage::UpdateEvaluators(eval_users, new_gov.version)).await {
                                        return Err(emit_fail(ctx, e).await);
                                    }
                            } else {
                                let e = ActorError::NotFound(ActorPath::from(
                                    format!(
                                        "{}/{}_evaluation",
                                        ctx.path(),
                                        creators.schema_id
                                    ),
                                ));
                                return Err(emit_fail(ctx, e).await);
                            }
                        } else {
                            let eval_actor = EvaluationSchema::new(
                                eval_users,
                                new_gov.version,
                            );
                            ctx.create_child(
                                &format!("{}_evaluation", creators.schema_id),
                                eval_actor,
                            )
                            .await?;
                        }
                    }

                    if let Some(val_user) = creators.validation {
                        let pos = old_schemas_val
                            .iter()
                            .position(|x| *x == creators.schema_id);
                        if let Some(pos) = pos {
                            old_schemas_val.remove(pos);
                            let actor: Option<ActorRef<ValidationSchema>> = ctx
                                .get_child(&format!(
                                    "{}_validation",
                                    creators.schema_id
                                ))
                                .await;
                            if let Some(actor) = actor {
                                if let Err(e) = actor.tell(ValidationSchemaMessage::UpdateValidators(val_user, new_gov.version)).await {
                                        return Err(emit_fail(ctx, e).await);
                                    }
                            } else {
                                let e = ActorError::NotFound(ActorPath::from(
                                    format!(
                                        "{}/{}_validation",
                                        ctx.path(),
                                        creators.schema_id
                                    ),
                                ));
                                return Err(emit_fail(ctx, e).await);
                            }
                        } else {
                            let actor = ValidationSchema::new(
                                val_user,
                                new_gov.version,
                            );
                            ctx.create_child(
                                &format!("{}_validation", creators.schema_id),
                                actor,
                            )
                            .await?;
                        }
                    }
                }

                Self::down_schemas(ctx, old_schemas_eval, old_schemas_val)
                    .await?;
            }
        }

        if current_sn < self.subject_metadata.sn || current_sn == 0 {
            Self::publish_sink(
                ctx,
                SinkDataMessage::UpdateState(Box::new(Metadata::from(
                    self.clone(),
                ))),
            )
            .await?;

            Self::update_subject_node(
                ctx,
                &self.subject_metadata.subject_id.to_string(),
                self.subject_metadata.sn,
            )
            .await?;
        }

        Ok(())
    }
}

impl Governance {
    pub fn from_create_event(ledger: &Signed<Ledger>) -> Result<Self, Error> {
        if let EventRequest::Create(request) =
            &ledger.content.event_request.content
        {
            Ok(Governance {
                subject_metadata: SubjectMetadata::from_create_request(
                    ledger.content.subject_id.clone(),
                    request,
                    ledger.content.event_request.signature.signer.clone(),
                    DigestIdentifier::default(),
                ),
                properties: GovernanceData::new(
                    ledger.content.event_request.signature.signer.clone(),
                ),
            })
        } else {
            Err(Error::Governance(
                "Invalid create event request".to_string(),
            ))
        }
    }

    async fn build_childs(
        &self,
        ctx: &mut ActorContext<Governance>,
        our_key: PublicKey,
        ext_db: ExternalDB,
    ) -> Result<(), ActorError> {
        // If subject is a governance
        let gov = GovernanceData::try_from(self.properties.clone())
            .map_err(|e| ActorError::FunctionalFail(e.to_string()))?;

        let owner = our_key == self.subject_metadata.owner;
        let new_owner = self.subject_metadata.new_owner.is_some();
        let i_new_owner =
            self.subject_metadata.new_owner == Some(our_key.clone());

        if new_owner {
            if i_new_owner {
                Self::up_owner(
                    ctx,
                    our_key.clone(),
                    self.subject_metadata.subject_id.clone(),
                    ext_db,
                )
                .await?;
            } else {
                Self::up_not_owner(
                    ctx,
                    gov.clone(),
                    our_key.clone(),
                    ext_db,
                    self.subject_metadata.subject_id.clone(),
                )
                .await?;
            }
        } else if owner {
            Self::up_owner(
                ctx,
                our_key.clone(),
                self.subject_metadata.subject_id.clone(),
                ext_db,
            )
            .await?;
        } else {
            Self::up_not_owner(
                ctx,
                gov.clone(),
                our_key.clone(),
                ext_db,
                self.subject_metadata.subject_id.clone(),
            )
            .await?;
        }

        let schemas = gov.schemas(ProtocolTypes::Evaluation, &our_key);
        Self::up_compilers_schemas(
            ctx,
            schemas,
            self.subject_metadata.subject_id.clone(),
        )
        .await?;

        let new_creators = gov.subjects_schemas_rol_namespace(&our_key);

        for creators in new_creators {
            if let Some(eval_user) = creators.evaluation {
                let eval_actor = EvaluationSchema::new(eval_user, gov.version);
                ctx.create_child(
                    &format!("{}_evaluation", creators.schema_id),
                    eval_actor,
                )
                .await?;
            }

            if let Some(val_user) = creators.validation {
                let actor = ValidationSchema::new(val_user, gov.version);
                ctx.create_child(
                    &format!("{}_validation", creators.schema_id),
                    actor,
                )
                .await?;
            }
        }

        Ok(())
    }

    async fn up_not_owner(
        ctx: &mut ActorContext<Self>,
        gov: GovernanceData,
        our_key: PublicKey,
        ext_db: ExternalDB,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Validator,
        }) {
            // If we are a validator
            let validator = Validator::default();
            ctx.create_child("validator", validator).await?;
        }

        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Evaluator,
        }) {
            // If we are a evaluator
            let evaluator = Evaluator::default();
            ctx.create_child("evaluator", evaluator).await?;
        }

        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Approver,
        }) {
            let always_accept = if let Some(config) =
                ctx.system().get_helper::<ConfigHelper>("config").await
            {
                config.always_accept
            } else {
                return Err(ActorError::NotHelper("config".to_owned()));
            };

            let init_approver = InitApprover {
                request_id: String::default(),
                version: 0,
                node: our_key.clone(),
                subject_id: subject_id.to_string(),
                pass_votation: VotationType::from(always_accept),
            };

            let approver_actor = ctx
                .create_child("approver", Approver::initial(init_approver))
                .await?;

            let sink =
                Sink::new(approver_actor.subscribe(), ext_db.get_approver());
            ctx.system().run_sink(sink).await;
        }

        Ok(())
    }

    async fn up_down_not_owner(
        ctx: &mut ActorContext<Self>,
        new_gov: GovernanceData,
        old_gov: GovernanceData,
        our_key: PublicKey,
        ext_db: ExternalDB,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let old_val = old_gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Validator,
        });

        let new_val = new_gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Validator,
        });

        match (old_val, new_val) {
            (true, false) => {
                let actor: Option<ActorRef<Validator>> =
                    ctx.get_child("validator").await;
                if let Some(actor) = actor {
                    actor.ask_stop().await?;
                } else {
                    return Err(ActorError::NotFound(ActorPath::from(
                        format!("{}/validator", ctx.path()),
                    )));
                }
            }
            (false, true) => {
                let validator = Validator::default();
                ctx.create_child("validator", validator).await?;
            }
            _ => {}
        };

        let old_eval = old_gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Evaluator,
        });

        let new_eval = new_gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Evaluator,
        });

        match (old_eval, new_eval) {
            (true, false) => {
                let actor: Option<ActorRef<Evaluator>> =
                    ctx.get_child("evaluator").await;
                if let Some(actor) = actor {
                    actor.ask_stop().await?;
                } else {
                    return Err(ActorError::NotFound(ActorPath::from(
                        format!("{}/evaluator", ctx.path()),
                    )));
                }
            }
            (false, true) => {
                let evaluator = Evaluator::default();
                ctx.create_child("evaluator", evaluator).await?;
            }
            _ => {}
        };

        let old_appr = old_gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Approver,
        });

        let new_appr = new_gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Approver,
        });

        match (old_appr, new_appr) {
            (true, false) => {
                let actor: Option<ActorRef<Approver>> =
                    ctx.get_child("approver").await;
                if let Some(actor) = actor {
                    actor.ask_stop().await?;
                } else {
                    return Err(ActorError::NotFound(ActorPath::from(
                        format!("{}/approver", ctx.path()),
                    )));
                }
            }
            (false, true) => {
                let always_accept = if let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config").await
                {
                    config.always_accept
                } else {
                    return Err(ActorError::NotHelper("config".to_owned()));
                };

                let init_approver = InitApprover {
                    request_id: String::default(),
                    version: 0,
                    node: our_key.clone(),
                    subject_id: subject_id.to_string(),
                    pass_votation: VotationType::from(always_accept),
                };

                let approver_actor = ctx
                    .create_child("approver", Approver::initial(init_approver))
                    .await?;

                let sink = Sink::new(
                    approver_actor.subscribe(),
                    ext_db.get_approver(),
                );
                ctx.system().run_sink(sink).await;
            }
            _ => {}
        };

        Ok(())
    }

    async fn down_not_owner(
        ctx: &mut ActorContext<Self>,
        gov: GovernanceData,
        our_key: PublicKey,
    ) -> Result<(), ActorError> {
        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Validator,
        }) {
            let actor: Option<ActorRef<Validator>> =
                ctx.get_child("validator").await;
            if let Some(actor) = actor {
                actor.ask_stop().await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/validator",
                    ctx.path()
                ))));
            }
        }

        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Evaluator,
        }) {
            let actor: Option<ActorRef<Evaluator>> =
                ctx.get_child("evaluator").await;
            if let Some(actor) = actor {
                actor.ask_stop().await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/evaluator",
                    ctx.path()
                ))));
            }
        }

        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Approver,
        }) {
            let actor: Option<ActorRef<Approver>> =
                ctx.get_child("approver").await;
            if let Some(actor) = actor {
                actor.ask_stop().await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/approver",
                    ctx.path()
                ))));
            }
        }

        Ok(())
    }

    async fn up_owner(
        ctx: &mut ActorContext<Self>,
        our_key: PublicKey,
        subject_id: DigestIdentifier,
        ext_db: ExternalDB,
    ) -> Result<(), ActorError> {
        let always_accept = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.always_accept
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        let validation = Validation::new(our_key.clone());
        ctx.create_child("validation", validation).await?;

        let evaluation = Evaluation::new(our_key.clone());
        ctx.create_child("evaluation", evaluation).await?;

        ctx.create_child("approval", Approval::initial(our_key.clone()))
            .await?;

        let init_approver = InitApprover {
            request_id: String::default(),
            version: 0,
            node: our_key.clone(),
            subject_id: subject_id.to_string(),
            pass_votation: VotationType::from(always_accept),
        };

        let approver_actor = ctx
            .create_child("approver", Approver::initial(init_approver))
            .await?;

        let sink = Sink::new(approver_actor.subscribe(), ext_db.get_approver());
        ctx.system().run_sink(sink).await;

        let distribution =
            Distribution::new(our_key.clone(), DistributionType::Subject);
        ctx.create_child("distribution", distribution).await?;

        Ok(())
    }

    async fn down_owner(
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor: Option<ActorRef<Validation>> =
            ctx.get_child("validation").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            let e = ActorError::NotFound(ActorPath::from(format!(
                "{}/validation",
                ctx.path()
            )));
            return Err(emit_fail(ctx, e).await);
        }

        let actor: Option<ActorRef<Evaluation>> =
            ctx.get_child("evaluation").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            let e = ActorError::NotFound(ActorPath::from(format!(
                "{}/evaluation",
                ctx.path()
            )));
            return Err(emit_fail(ctx, e).await);
        }

        let actor: Option<ActorRef<Approval>> = ctx.get_child("approval").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            let e = ActorError::NotFound(ActorPath::from(format!(
                "{}/approval",
                ctx.path()
            )));
            return Err(emit_fail(ctx, e).await);
        }

        let actor: Option<ActorRef<Approver>> = ctx.get_child("approver").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            let e = ActorError::NotFound(ActorPath::from(format!(
                "{}/approver",
                ctx.path()
            )));
            return Err(emit_fail(ctx, e).await);
        }

        let actor: Option<ActorRef<Distribution>> =
            ctx.get_child("distribution").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            let e = ActorError::NotFound(ActorPath::from(format!(
                "{}/distribution",
                ctx.path()
            )));
            return Err(emit_fail(ctx, e).await);
        }

        Ok(())
    }

    async fn up_compilers_schemas(
        ctx: &mut ActorContext<Self>,
        schemas: BTreeMap<SchemaType, Schema>,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let contracts_path = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.contracts_path
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        for (id, schema) in schemas {
            let actor_name = format!("{}_compiler", id);

            let compiler =
                if let Some(compiler) = ctx.get_child(&actor_name).await {
                    compiler
                } else {
                    ctx.create_child(&actor_name, Compiler::default()).await?
                };

            let Schema {
                contract,
                initial_value,
            } = schema;

            compiler
                .tell(CompilerMessage::Compile {
                    contract_name: format!("{}_{}", subject_id, id),
                    contract,
                    initial_value: initial_value.0,
                    contract_path: contracts_path
                        .join("contracts")
                        .join(format!("{}_{}", subject_id, id)),
                })
                .await?;
        }

        Ok(())
    }

    async fn down_compilers_schemas(
        ctx: &mut ActorContext<Self>,
        schemas: Vec<SchemaType>,
    ) -> Result<(), ActorError> {
        for schema in schemas {
            let actor: Option<ActorRef<Compiler>> =
                ctx.get_child(&format!("{}_compiler", schema)).await;
            if let Some(actor) = actor {
                actor.ask_stop().await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/{}_compiler",
                    ctx.path(),
                    schema
                ))));
            }
        }

        Ok(())
    }

    async fn down_schemas(
        ctx: &mut ActorContext<Self>,
        old_schemas_eval: Vec<SchemaType>,
        old_schemas_val: Vec<SchemaType>,
    ) -> Result<(), ActorError> {
        for schema in old_schemas_eval {
            let actor: Option<ActorRef<EvaluationSchema>> =
                ctx.get_child(&format!("{}_evaluation", schema)).await;
            if let Some(actor) = actor {
                actor.ask_stop().await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/{}_evaluation",
                    ctx.path(),
                    schema
                ))));
            }
        }

        for schema_id in old_schemas_val {
            let actor: Option<ActorRef<ValidationSchema>> =
                ctx.get_child(&format!("{}_validation", schema_id)).await;
            if let Some(actor) = actor {
                actor.ask_stop().await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/{}_validation",
                    ctx.path(),
                    schema_id
                ))));
            }
        }

        Ok(())
    }

    async fn compile_schemas(
        ctx: &mut ActorContext<Self>,
        schemas: HashMap<SchemaType, Schema>,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let contracts_path = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.contracts_path
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        for (id, schema) in schemas {
            let actor: Option<ActorRef<Compiler>> =
                ctx.get_child(&format!("{}_compiler", id)).await;
            if let Some(actor) = actor {
                actor
                    .tell(CompilerMessage::Compile {
                        contract_name: format!("{}_{}", subject_id, id),
                        contract: schema.contract.clone(),
                        initial_value: schema.initial_value.0.clone(),
                        contract_path: contracts_path
                            .join("contracts")
                            .join(format!("{}_{}", subject_id, id)),
                    })
                    .await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/{}_compiler",
                    ctx.path(),
                    id
                ))));
            }
        }

        Ok(())
    }

    fn create_roles_register_message(
        &self,
        update: &RolesRegisterUpdate,
    ) -> Result<RolesRegisterMessage, ActorError> {
        let appr_quorum = (update.appr_quorum)
            .then(|| self.properties.policies_gov.approve.clone());

        let approvers = if update.approvers {
            let mut approvers_set = HashSet::new();
            for approver in &self.properties.roles_gov.approver {
                let Some(approver_key) = self.properties.members.get(approver)
                else {
                    return Err(ActorError::FunctionalFail(format!(
                        "Approver {} is not a member",
                        approver
                    )));
                };

                approvers_set.insert(approver_key.clone());
            }

            Some(approvers_set)
        } else {
            None
        };

        let eval_quorum = if let Some(eval_quorum) = &update.eval_quorum {
            let mut eval_vec: Vec<UpdateQuorum> = vec![];

            for schema_id in eval_quorum {
                let quorum = match schema_id {
                    SchemaType::Governance => {
                        self.properties.policies_gov.evaluate.clone()
                    }
                    _ => {
                        let Some(policies) =
                            self.properties.policies_schema.get(schema_id)
                        else {
                            return Err(ActorError::FunctionalFail(format!(
                                "Schema {} has no policies",
                                schema_id
                            )));
                        };

                        policies.evaluate.clone()
                    }
                };
                eval_vec.push(UpdateQuorum {
                    schema_id: schema_id.clone(),
                    quorum,
                });
            }

            Some(eval_vec)
        } else {
            None
        };

        let evaluators = if let Some(evaluators) = &update.evaluators {
            let mut eval_vec: Vec<UpdateRole> = vec![];

            for schema_id in evaluators {
                let mut evaluators: HashSet<RoleData> = HashSet::new();
                match schema_id {
                    SchemaType::Governance => {
                        for name in &self.properties.roles_gov.evaluator {
                            let Some(key) = self.properties.members.get(name)
                            else {
                                return Err(ActorError::FunctionalFail(
                                    format!(
                                        "Evaluator {} is not a member",
                                        name
                                    ),
                                ));
                            };

                            evaluators.insert(RoleData {
                                key: key.clone(),
                                namespace: Namespace::new(),
                            });
                        }
                    }
                    SchemaType::AllSchemas => {
                        for role in &self.properties.roles_all_schemas.evaluator
                        {
                            let Some(key) =
                                self.properties.members.get(&role.name)
                            else {
                                return Err(ActorError::FunctionalFail(
                                    format!(
                                        "Evaluator {} is not a member",
                                        role.name
                                    ),
                                ));
                            };
                            evaluators.insert(RoleData {
                                key: key.clone(),
                                namespace: role.namespace.clone(),
                            });
                        }
                    }
                    _ => {
                        let Some(schema) =
                            self.properties.roles_schema.get(schema_id)
                        else {
                            return Err(ActorError::FunctionalFail(format!(
                                "Schema {} is not a schema",
                                schema_id
                            )));
                        };

                        for role in &schema.evaluator {
                            let Some(key) =
                                self.properties.members.get(&role.name)
                            else {
                                return Err(ActorError::FunctionalFail(
                                    format!(
                                        "Evaluator {} is not a member",
                                        role.name
                                    ),
                                ));
                            };
                            evaluators.insert(RoleData {
                                key: key.clone(),
                                namespace: role.namespace.clone(),
                            });
                        }
                    }
                };

                eval_vec.push(UpdateRole {
                    schema_id: schema_id.clone(),
                    role: evaluators,
                });
            }

            Some(eval_vec)
        } else {
            None
        };

        let vali_quorum = if let Some(vali_quorum) = &update.vali_quorum {
            let mut vali_vec: Vec<UpdateQuorum> = vec![];

            for schema_id in vali_quorum {
                let quorum = match schema_id {
                    SchemaType::Governance => {
                        self.properties.policies_gov.validate.clone()
                    }
                    _ => {
                        let Some(policies) =
                            self.properties.policies_schema.get(schema_id)
                        else {
                            return Err(ActorError::FunctionalFail(format!(
                                "Schema {} have not got a policies",
                                schema_id
                            )));
                        };

                        policies.validate.clone()
                    }
                };
                vali_vec.push(UpdateQuorum {
                    schema_id: schema_id.clone(),
                    quorum,
                });
            }

            Some(vali_vec)
        } else {
            None
        };

        let validators = if let Some(validators) = &update.validators {
            let mut vali_vec: Vec<UpdateRole> = vec![];

            for schema_id in validators {
                let mut validators: HashSet<RoleData> = HashSet::new();
                match schema_id {
                    SchemaType::Governance => {
                        for name in &self.properties.roles_gov.validator {
                            let Some(key) = self.properties.members.get(name)
                            else {
                                return Err(ActorError::FunctionalFail(
                                    format!(
                                        "Validator {} is not a member",
                                        name
                                    ),
                                ));
                            };

                            validators.insert(RoleData {
                                key: key.clone(),
                                namespace: Namespace::new(),
                            });
                        }
                    }
                    SchemaType::AllSchemas => {
                        for role in &self.properties.roles_all_schemas.validator
                        {
                            let Some(key) =
                                self.properties.members.get(&role.name)
                            else {
                                return Err(ActorError::FunctionalFail(
                                    format!(
                                        "Validator {} is not a member",
                                        role.name
                                    ),
                                ));
                            };
                            validators.insert(RoleData {
                                key: key.clone(),
                                namespace: role.namespace.clone(),
                            });
                        }
                    }
                    _ => {
                        let Some(schema) =
                            self.properties.roles_schema.get(schema_id)
                        else {
                            return Err(ActorError::FunctionalFail(format!(
                                "Schema {} is not a schema",
                                schema_id
                            )));
                        };

                        for role in &schema.validator {
                            let Some(key) =
                                self.properties.members.get(&role.name)
                            else {
                                return Err(ActorError::FunctionalFail(
                                    format!(
                                        "Validator {} is not a member",
                                        role.name
                                    ),
                                ));
                            };
                            validators.insert(RoleData {
                                key: key.clone(),
                                namespace: role.namespace.clone(),
                            });
                        }
                    }
                };

                vali_vec.push(UpdateRole {
                    schema_id: schema_id.clone(),
                    role: validators,
                });
            }

            Some(vali_vec)
        } else {
            None
        };

        Ok(RolesRegisterMessage::Update {
            version: self.properties.version,
            appr_quorum,
            eval_quorum,
            vali_quorum,
            validators,
            evaluators,
            approvers,
        })
    }

    async fn update_roles_register(
        &self,
        ctx: &mut ActorContext<Self>,
        update: &RolesRegisterUpdate,
    ) -> Result<(), ActorError> {
        let actor: Option<ActorRef<RolesRegister>> =
            ctx.get_child("roles_register").await;

        let message = self.create_roles_register_message(update)?;

        if let Some(actor) = actor {
            actor.tell(message).await
        } else {
            Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/{}",
                ctx.path(),
                "roles_register"
            ))))
        }
    }

    async fn verify_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let mut iter = events.into_iter();
        let last_ledger = get_last_event(ctx).await?;

        let mut last_ledger = if let Some(last_ledger) = last_ledger {
            last_ledger
        } else {
            let Some(first) = iter.next() else {
                return Ok(());
            };
            if let Err(e) = Self::verify_first_ledger_event(
                self.subject_metadata.owner.clone(),
                &first,
            )
            .await
            {
                self.delete_subject(ctx).await?;
                return Err(ActorError::Functional(e.to_string()));
            }

            self.on_event(first.clone(), ctx).await;
            Self::register(
                ctx,
                RegisterMessage::RegisterGov {
                    gov_id: self.subject_metadata.subject_id.to_string(),
                    name: self.subject_metadata.name.clone(),
                    description: self.subject_metadata.description.clone(),
                },
            )
            .await?;

            self.update_roles_register(
                ctx,
                &RolesRegisterUpdate {
                    appr_quorum: true,
                    approvers: true,
                    eval_quorum: Some(vec![SchemaType::Governance]),
                    evaluators: Some(vec![SchemaType::Governance]),
                    vali_quorum: Some(vec![SchemaType::Governance]),
                    validators: Some(vec![SchemaType::Governance]),
                },
            )
            .await?;

            Self::event_to_sink(
                ctx,
                DataForSink {
                    gov_id: None,
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    sn: self.subject_metadata.sn,
                    owner: self.subject_metadata.owner.to_string(),
                    namespace: String::default(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    issuer: first
                        .content
                        .event_request
                        .signature
                        .signer
                        .to_string(),
                },
                &first.content.event_request.content,
            )
            .await?;

            first
        };

        for event in iter {
            let last_event_is_ok = match Self::verify_new_ledger_event(
                VerifyData {
                    active: self.subject_metadata.active,
                    owner: self.subject_metadata.owner.clone(),
                    new_owner: self.subject_metadata.new_owner.clone(),
                    is_gov: self.subject_metadata.schema_id.is_gov(),
                    properties: self.properties.to_value_wrapper(),
                },
                &last_ledger,
                &event,
            )
            .await
            {
                Ok(last_event_is_ok) => last_event_is_ok,
                Err(e) => {
                    if let Error::Sn = e {
                        // El evento que estamos aplicando no es el siguiente.
                        continue;
                    } else {
                        return Err(ActorError::Functional(e.to_string()));
                    }
                }
            };
            let roles_update = if last_event_is_ok {
                let update = match event.content.event_request.content.clone() {
                    EventRequest::Transfer(transfer_request) => {
                        Governance::new_transfer_subject(
                            ctx,
                            self.subject_metadata.name.clone(),
                            &transfer_request.subject_id.to_string(),
                            &transfer_request.new_owner.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;

                        None
                    }
                    EventRequest::Reject(reject_request) => {
                        Governance::reject_transfer_subject(
                            ctx,
                            &reject_request.subject_id.to_string(),
                        )
                        .await?;

                        None
                    }
                    EventRequest::Confirm(confirm_request) => {
                        Governance::change_node_subject(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                            &event.signature.signer.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;

                        None
                    }
                    EventRequest::EOL(_eolrequest) => {
                        Self::register(
                            ctx,
                            RegisterMessage::EOLGov {
                                gov_id: self
                                    .subject_metadata
                                    .subject_id
                                    .to_string(),
                            },
                        )
                        .await?;

                        None
                    }
                    EventRequest::Fact(fact_request) => {
                        let governance_event = serde_json::from_value::<GovernanceEvent>(fact_request.payload.0).map_err(|e| {
                            ActorError::FunctionalFail(format!("Can not convert payload into governance event in governance fact event: {}", e))
                        })?;

                        governance_event.roles_update()
                    }
                    _ => None,
                };

                Self::event_to_sink(
                    ctx,
                    DataForSink {
                        gov_id: None,
                        subject_id: self
                            .subject_metadata
                            .subject_id
                            .to_string(),
                        sn: self.subject_metadata.sn,
                        owner: self.subject_metadata.owner.to_string(),
                        namespace: String::default(),
                        schema_id: self.subject_metadata.schema_id.clone(),
                        issuer: event
                            .content
                            .event_request
                            .signature
                            .signer
                            .to_string(),
                    },
                    &event.content.event_request.content,
                )
                .await?;

                update
            } else {
                None
            };

            // Aplicar evento.
            self.on_event(event.clone(), ctx).await;

            if let Some(update) = roles_update {
                self.update_roles_register(ctx, &update).await?;
            }

            // Acutalizar último evento.
            last_ledger = event.clone();
        }

        Ok(())
    }

    async fn create_compilers(
        ctx: &mut ActorContext<Self>,
        compilers: &[SchemaType],
    ) -> Result<Vec<SchemaType>, ActorError> {
        let mut new_compilers = vec![];

        for compiler in compilers {
            let child: Option<ActorRef<Compiler>> =
                ctx.get_child(&format!("{}_compiler", compiler)).await;
            if child.is_none() {
                new_compilers.push(compiler.clone());

                ctx.create_child(
                    &format!("{}_compiler", compiler),
                    Compiler::default(),
                )
                .await?;
            }
        }

        Ok(new_compilers)
    }
}

/// Governance command.
#[derive(Debug, Clone)]
pub enum GovernanceMessage {
    UpdateTransfer(TransferResponse),
    CreateCompilers(Vec<SchemaType>),
    /// Get the subject metadata.
    GetMetadata,
    GetLedger {
        last_sn: u64,
    },
    GetLastLedger,
    UpdateLedger {
        events: Vec<SignedLedger>,
    },
    GetGovernance,
    GetOwner,
    DeleteGovernance,
}

impl Message for GovernanceMessage {}

#[derive(Debug, Clone)]
pub enum GovernanceResponse {
    /// The subject metadata.
    Metadata(Box<Metadata>),
    UpdateResult(u64, PublicKey, Option<PublicKey>),
    Ledger {
        ledger: Vec<SignedLedger>,
        last_state: Option<LastStateData>,
    },
    Governance(Box<GovernanceData>),
    Owner(PublicKey),
    NewCompilers(Vec<SchemaType>),
    Ok,
}
impl Response for GovernanceResponse {}

#[async_trait]
impl Actor for Governance {
    type Event = SignedLedger;
    type Message = GovernanceMessage;
    type Response = GovernanceResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("governance", None, true, ctx).await?;

        let our_key = get_node_key(ctx).await?;

        let Some(ext_db): Option<ExternalDB> =
            ctx.system().get_helper("ext_db").await
        else {
            return Err(ActorError::NotHelper("ext_db".to_owned()));
        };

        let Some(ave_sink): Option<AveSink> =
            ctx.system().get_helper("sink").await
        else {
            return Err(ActorError::NotHelper("sink".to_owned()));
        };

        let last_state_actor = ctx
            .create_child("last_state", LastState::initial(()))
            .await?;

        let sink =
            Sink::new(last_state_actor.subscribe(), ext_db.get_last_state());
        ctx.system().run_sink(sink).await;

        if self.subject_metadata.active {
            self.build_childs(ctx, our_key.clone(), ext_db.clone())
                .await?;
        }

        ctx.create_child("relation_ship", RelationShip::initial(()))
            .await?;

        let sink_actor = ctx
            .create_child(
                "sink_data",
                SinkData {
                    controller_id: our_key.to_string(),
                },
            )
            .await?;
        let sink = Sink::new(sink_actor.subscribe(), ext_db.get_sink_data());
        ctx.system().run_sink(sink).await;

        let sink = Sink::new(sink_actor.subscribe(), ave_sink.clone());
        ctx.system().run_sink(sink).await;

        ctx.create_child("roles_register", RolesRegister::initial(()))
            .await?;

        Ok(())
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<Governance> for Governance {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: GovernanceMessage,
        ctx: &mut ActorContext<Governance>,
    ) -> Result<GovernanceResponse, ActorError> {
        match msg {
            GovernanceMessage::UpdateTransfer(res) => {
                match res {
                    TransferResponse::Confirm => {
                        let Some(new_owner) =
                            self.subject_metadata.new_owner.clone()
                        else {
                            let e = "Can not obtain new_owner";
                            error!(TARGET_GOVERNANCE, "Confirm, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        };

                        Governance::change_node_subject(
                            ctx,
                            &self.subject_metadata.subject_id.to_string(),
                            &new_owner.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;
                    }
                    TransferResponse::Reject => {
                        Governance::reject_transfer_subject(
                            ctx,
                            &self.subject_metadata.subject_id.to_string(),
                        )
                        .await?;
                        try_to_update(
                            ctx,
                            self.subject_metadata.subject_id.clone(),
                            WitnessesAuth::None,
                        )
                        .await?;
                    }
                }

                Ok(GovernanceResponse::Ok)
            }
            GovernanceMessage::DeleteGovernance => {
                self.delete_subject(ctx).await?;

                Ok(GovernanceResponse::Ok)
            }
            GovernanceMessage::CreateCompilers(compilers) => {
                let new_compilers =
                    match Self::create_compilers(ctx, &compilers).await {
                        Ok(new_compilers) => new_compilers,
                        Err(e) => {
                            warn!(
                                TARGET_GOVERNANCE,
                                "CreateCompilers, can not create compilers: {}",
                                e
                            );
                            return Err(e);
                        }
                    };
                Ok(GovernanceResponse::NewCompilers(new_compilers))
            }
            GovernanceMessage::GetLedger { last_sn } => {
                let (ledger, last_state) =
                    self.get_ledger_data(ctx, last_sn).await?;
                Ok(GovernanceResponse::Ledger { ledger, last_state })
            }
            GovernanceMessage::GetLastLedger => {
                let (ledger, last_state) =
                    self.get_ledger_data(ctx, self.subject_metadata.sn).await?;
                Ok(GovernanceResponse::Ledger { ledger, last_state })
            }
            GovernanceMessage::GetOwner => Ok(GovernanceResponse::Owner(
                self.subject_metadata.owner.clone(),
            )),
            GovernanceMessage::GetMetadata => Ok(GovernanceResponse::Metadata(
                Box::new(Metadata::from(self.clone())),
            )),
            GovernanceMessage::UpdateLedger { events } => {
                if let Err(e) =
                    self.manager_new_ledger_events(ctx, events).await
                {
                    warn!(
                        TARGET_GOVERNANCE,
                        "UpdateLedger, can not verify new events: {}", e
                    );
                    return Err(e);
                };
                Ok(GovernanceResponse::UpdateResult(
                    self.subject_metadata.sn,
                    self.subject_metadata.owner.clone(),
                    self.subject_metadata.new_owner.clone(),
                ))
            }
            GovernanceMessage::GetGovernance => {
                Ok(GovernanceResponse::Governance(Box::new(
                    self.properties.clone(),
                )))
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SignedLedger,
        ctx: &mut ActorContext<Governance>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_GOVERNANCE,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event).await {
            error!(
                TARGET_GOVERNANCE,
                "PublishEvent, can not publish event: {}", e
            );
            emit_fail(ctx, e).await;
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Governance>,
    ) -> ChildAction {
        error!(TARGET_GOVERNANCE, "OnChildFault, {}", error);
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for Governance {
    type Persistence = FullPersistence;
    type InitParams = Option<Self>;

    fn create_initial(params: Self::InitParams) -> Self {
        params.unwrap_or_default()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        let valid_event = match Self::verify_protocols_state(
            EventRequestType::from(&event.content.event_request.content),
            event.content.eval_success,
            event.content.appr_success,
            event.content.appr_required,
            event.content.vali_success,
            true,
        ) {
            Ok(is_ok) => is_ok,
            Err(e) => {
                let error =
                    format!("Apply, can not verify protocols state: {}", e);
                error!(TARGET_GOVERNANCE, error);
                return Err(ActorError::Functional(error));
            }
        };

        if valid_event {
            match &event.content.event_request.content {
                EventRequest::Create(create_event) => {
                    let last_event_hash = hash_borsh(
                        &*event.signature.content_hash.algorithm().hasher(),
                        &event,
                    )
                    .map_err(|e| {
                        let error = format!(
                            "Apply, can not obtain last event hash: {}",
                            e
                        );
                        error!(TARGET_GOVERNANCE, error);
                        ActorError::Functional(error)
                    })?;

                    self.subject_metadata =
                        SubjectMetadata::from_create_request(
                            event.content.subject_id.clone(),
                            create_event,
                            event
                                .content
                                .event_request
                                .signature
                                .signer
                                .clone(),
                            last_event_hash,
                        );
                    self.properties = GovernanceData::new(
                        event.content.event_request.signature.signer.clone(),
                    );

                    return Ok(());
                }
                EventRequest::Fact(_fact_request) => {
                    self.apply_patch(event.content.value.clone())?;
                }
                EventRequest::Transfer(transfer_request) => {
                    self.subject_metadata.new_owner =
                        Some(transfer_request.new_owner.clone());
                }
                EventRequest::Confirm(_confirm_request) => {
                    self.apply_patch(event.content.value.clone())?;

                    let Some(new_owner) =
                        self.subject_metadata.new_owner.clone()
                    else {
                        let error = "In confirm event was succefully but new owner is empty:";
                        error!(TARGET_GOVERNANCE, error);
                        return Err(ActorError::Functional(error.to_owned()));
                    };

                    self.subject_metadata.owner = new_owner;
                    self.subject_metadata.new_owner = None;
                }
                EventRequest::Reject(_reject_request) => {
                    self.subject_metadata.new_owner = None;
                }
                EventRequest::EOL(_eolrequest) => {
                    self.subject_metadata.active = false
                }
            }

            self.properties.version += 1;
        }

        let last_event_hash = hash_borsh(
            &*event.signature.content_hash.algorithm().hasher(),
            &event,
        )
        .map_err(|e| {
            let error = format!("Apply, can not obtain last event hash: {}", e);
            error!(TARGET_GOVERNANCE, error);
            ActorError::Functional(error)
        })?;

        self.subject_metadata.last_event_hash = last_event_hash;
        self.subject_metadata.sn += 1;

        Ok(())
    }
}

impl Storable for Governance {}
