//! # Governance module.
//!

use crate::{
    Error,
    approval::{
        persist::{ApprPersist, InitApprPersist},
        types::VotationType,
    },
    auth::WitnessesAuth,
    db::Storable,
    evaluation::{
        compiler::{Compiler, CompilerMessage},
        worker::EvalWorker,
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
    helpers::{db::ExternalDB, network::service::NetworkSender, sink::AveSink},
    model::{
        common::{
            emit_fail, get_last_event, get_n_events, node::try_to_update,
            purge_storage,
        },
        event::{Protocols, ValidationMetadata},
    },
    node::register::RegisterMessage,
    subject::{
        DataForSink, Metadata, SignedLedger, Subject, SubjectMetadata,
        sinkdata::{SinkData, SinkDataMessage},
    },
    system::ConfigHelper,
    update::TransferResponse,
    validation::{
        request::LastData,
        schema::{ValidationSchema, ValidationSchemaMessage},
        worker::ValiWorker,
    },
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, Response, Sink,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey, hash_borsh},
    request::EventRequest,
};

use async_trait::async_trait;
use ave_actors::{FullPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
};

pub mod data;
pub mod events;
pub mod model;
pub mod relationship;
pub mod roles_register;

const TARGET_GOVERNANCE: &str = "Ave-Governance";

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct Governance {
    #[serde(skip)]
    pub our_key: Arc<PublicKey>,

    pub subject_metadata: SubjectMetadata,
    /// The current status of the subject.
    pub properties: GovernanceData,
}

impl BorshSerialize for Governance {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the fields we want to persist, skipping 'owner'
        BorshSerialize::serialize(&self.subject_metadata, writer)?;
        BorshSerialize::serialize(&self.properties, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for Governance {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let subject_metadata = SubjectMetadata::deserialize_reader(reader)?;
        let properties = GovernanceData::deserialize_reader(reader)?;

        // Create a default/placeholder KeyPair for 'owner'
        // This will be replaced by the actual owner during actor initialization
        let our_key = Arc::new(PublicKey::default());

        Ok(Self {
            our_key,
            subject_metadata,
            properties,
        })
    }
}

#[async_trait]
impl Subject for Governance {
    async fn get_last_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Option<SignedLedger>, ActorError> {
        get_last_event(ctx).await
    }

    async fn get_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
        last_sn: u64,
    ) -> Result<Vec<SignedLedger>, ActorError> {
        get_n_events(ctx, last_sn, 100).await
    }

    fn apply_patch(
        &mut self,
        json_patch: ValueWrapper,
    ) -> Result<(), ActorError> {
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
        let Some(network) = ctx
            .system()
            .get_helper::<Arc<NetworkSender>>("network")
            .await
        else {
            return Err(ActorError::NotHelper("network".to_owned()));
        };

        let hash = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.hash_algorithm
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        let current_sn = self.subject_metadata.sn;
        let current_new_owner_some = self.subject_metadata.new_owner.is_some();
        let i_current_new_owner = self.subject_metadata.new_owner.clone()
            == Some((*self.our_key).clone());
        let current_owner = self.subject_metadata.owner.clone();

        let current_properties = self.properties.clone();

        if let Err(e) = self.verify_new_ledger_events(ctx, events, &hash).await
        {
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
            let old_gov = current_properties;
            if !self.subject_metadata.active {
                if current_owner == *self.our_key {
                    Self::down_owner(ctx).await?;
                } else {
                    Self::down_not_owner(
                        ctx,
                        &old_gov,
                        self.our_key.clone(),
                    )
                    .await?;
                }

                let old_schemas_eval = old_gov
                    .schemas_name(ProtocolTypes::Evaluation, &self.our_key);

                Self::down_compilers_schemas(ctx, &old_schemas_eval).await?;

                let old_schemas_val = old_gov
                    .schemas_name(ProtocolTypes::Validation, &self.our_key);

                Self::down_schemas(ctx, &old_schemas_eval, &old_schemas_val)
                    .await?;
            } else {
                let new_owner_some = self.subject_metadata.new_owner.is_some();
                let i_new_owner = self.subject_metadata.new_owner.clone()
                    == Some((*self.our_key).clone());
                let mut up_not_owner: bool = false;
                let mut up_owner: bool = false;

                if current_owner == *self.our_key {
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
                        && self.subject_metadata.owner == *self.our_key
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
                    self.up_not_owner(ctx, &hash, &network).await?;
                } else if up_owner {
                    Self::down_not_owner(
                        ctx,
                        &old_gov,
                        self.our_key.clone(),
                    )
                    .await?;
                    self.up_not_owner(ctx, &hash, &network).await?;
                }

                // Seguimos sin ser owner ni new owner,
                // pero tenemos que ver si tenemos un rol nuevo.
                if !up_not_owner
                    && !up_owner
                    && *self.our_key != self.subject_metadata.owner
                {
                    self.up_down_not_owner(ctx, &old_gov, &hash, &network)
                        .await?;
                }

                self.manager_schemas_compilers(ctx, &old_gov).await?;
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
    async fn update_schemas(
        &self,
        ctx: &mut ActorContext<Self>,
        schema_creators_eval: &BTreeMap<
            SchemaType,
            BTreeMap<PublicKey, BTreeSet<Namespace>>,
        >,
        schema_creators_vali: &BTreeMap<
            SchemaType,
            BTreeMap<PublicKey, BTreeSet<Namespace>>,
        >,
        update_eval: &BTreeMap<SchemaType, ValueWrapper>,
        update_vali: &BTreeMap<SchemaType, ValueWrapper>,
    ) -> Result<(), ActorError> {
        for (schema_id, init_state) in update_eval.iter() {
            let actor: Option<ActorRef<EvaluationSchema>> =
                ctx.get_child(&format!("{}_evaluation", schema_id)).await;

            if let Some(actor) = actor {
                actor
                    .tell(EvaluationSchemaMessage::Update {
                        creators: schema_creators_eval
                            .get(schema_id)
                            .cloned()
                            .unwrap_or_default(),
                        sn: self.subject_metadata.sn,
                        gov_version: self.properties.version,
                        init_state: init_state.clone(),
                    })
                    .await?;
            } else {
                return Err(ActorError::NotFound(ActorPath::from(format!(
                    "{}/{}_evaluation",
                    ctx.path(),
                    schema_id
                ))));
            }
        }

        for (schema_id, init_state) in update_vali.iter() {
            let actor: Option<ActorRef<ValidationSchema>> =
                ctx.get_child(&format!("{}_validation", schema_id)).await;

            if let Some(actor) = actor {
                actor
                    .tell(ValidationSchemaMessage::Update {
                        creators: schema_creators_vali
                            .get(schema_id)
                            .cloned()
                            .unwrap_or_default(),
                        sn: self.subject_metadata.sn,
                        gov_version: self.properties.version,
                        init_state: init_state.clone(),
                    })
                    .await?;
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

    async fn down_schemas(
        ctx: &mut ActorContext<Self>,
        old_schemas_eval: &BTreeSet<SchemaType>,
        old_schemas_val: &BTreeSet<SchemaType>,
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

    async fn up_schemas(
        &self,
        ctx: &mut ActorContext<Self>,
        schema_creators_eval: &BTreeMap<
            SchemaType,
            BTreeMap<PublicKey, BTreeSet<Namespace>>,
        >,
        schema_creators_vali: &BTreeMap<
            SchemaType,
            BTreeMap<PublicKey, BTreeSet<Namespace>>,
        >,
        up_eval: &BTreeMap<SchemaType, ValueWrapper>,
        up_vali: &BTreeMap<SchemaType, ValueWrapper>,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        for (schema_id, init_state) in up_eval.iter() {
            let eval_actor = EvaluationSchema {
                our_key: self.our_key.clone(),
                governance_id: self.subject_metadata.subject_id.clone(),
                gov_version: self.properties.version,
                sn: self.subject_metadata.sn,
                creators: schema_creators_eval
                    .get(schema_id)
                    .cloned()
                    .unwrap_or_default(),
                schema_id: schema_id.clone(),
                init_state: init_state.clone(),
                hash: hash.clone(),
                network: network.clone(),
            };

            ctx.create_child(&format!("{}_evaluation", schema_id), eval_actor)
                .await?;
        }

        for (schema_id, init_state) in up_vali.iter() {
            let vali_actor = ValidationSchema {
                our_key: self.our_key.clone(),
                governance_id: self.subject_metadata.subject_id.clone(),
                gov_version: self.properties.version,
                sn: self.subject_metadata.sn,
                creators: schema_creators_vali
                    .get(schema_id)
                    .cloned()
                    .unwrap_or_default(),
                schema_id: schema_id.clone(),
                init_state: init_state.clone(),
                hash: hash.clone(),
                network: network.clone(),
            };

            ctx.create_child(&format!("{}_validation", schema_id), vali_actor)
                .await?;
        }

        Ok(())
    }

    async fn manager_schemas_compilers(
        &self,
        ctx: &mut ActorContext<Self>,
        old_gov: &GovernanceData,
    ) -> Result<(), ActorError> {
        let Some(network) = ctx
            .system()
            .get_helper::<Arc<NetworkSender>>("network")
            .await
        else {
            return Err(ActorError::NotHelper("network".to_owned()));
        };
        let hash = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.hash_algorithm
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        let (old_schemas_eval, new_schemas_eval) = {
            let old_schemas_eval =
                old_gov.schemas_name(ProtocolTypes::Evaluation, &self.our_key);

            let new_schemas_eval = self
                .properties
                .schemas(ProtocolTypes::Evaluation, &self.our_key);

            // Compilers
            // Bajamos los compilers que ya no soy evaluador
            let down = old_schemas_eval
                .clone()
                .iter()
                .filter(|x| !new_schemas_eval.contains_key(x))
                .map(|x| x.clone())
                .collect();
            Self::down_compilers_schemas(ctx, &down).await?;

            // Subimos los compilers que soy nuevo evaluador
            let up = new_schemas_eval
                .clone()
                .iter()
                .filter(|x| !old_schemas_eval.contains(x.0))
                .map(|x| (x.0.clone(), x.1.clone()))
                .collect();

            Self::up_compilers_schemas(
                ctx,
                &up,
                self.subject_metadata.subject_id.clone(),
            )
            .await?;

            // Compilo los nuevos contratos en el caso de que hayan sido modificados, sino no afecta.
            let current = new_schemas_eval
                .clone()
                .iter()
                .filter(|x| old_schemas_eval.contains(x.0))
                .map(|x| (x.0.clone(), x.1.clone()))
                .collect();

            Self::compile_schemas(
                ctx,
                current,
                self.subject_metadata.subject_id.clone(),
            )
            .await?;

            (
                old_schemas_eval,
                new_schemas_eval
                    .iter()
                    .map(|x| (x.0.clone(), x.1.initial_value.clone()))
                    .collect::<BTreeMap<SchemaType, ValueWrapper>>(),
            )
        };
        let old_schemas_vali =
            old_gov.schemas_name(ProtocolTypes::Validation, &self.our_key);

        let new_schemas_vali = self
            .properties
            .schemas_init_value(ProtocolTypes::Validation, &self.our_key);

        // Bajar schemas
        let down_eval = old_schemas_eval
            .clone()
            .iter()
            .filter(|x| !new_schemas_eval.contains_key(x))
            .map(|x| x.clone())
            .collect();

        let down_vali = old_schemas_vali
            .clone()
            .iter()
            .filter(|x| !new_schemas_vali.contains_key(x))
            .map(|x| x.clone())
            .collect();

        Self::down_schemas(ctx, &down_eval, &down_vali).await?;

        // Subir los nuevos schemas
        let schemas_namespace_eval = self
            .properties
            .schemas_namespace(ProtocolTypes::Evaluation, &self.our_key);

        let schema_creators_eval = self
            .properties
            .schema_creators_namespace(schemas_namespace_eval);

        let up_eval = new_schemas_eval
            .clone()
            .iter()
            .filter(|x| !old_schemas_eval.contains(x.0))
            .map(|x| (x.0.clone(), x.1.clone()))
            .collect::<BTreeMap<SchemaType, ValueWrapper>>();

        let schemas_namespace_vali = self
            .properties
            .schemas_namespace(ProtocolTypes::Validation, &self.our_key);

        let schema_creators_vali = self
            .properties
            .schema_creators_namespace(schemas_namespace_vali);

        let up_vali = new_schemas_vali
            .clone()
            .iter()
            .filter(|x| !old_schemas_vali.contains(x.0))
            .map(|x| (x.0.clone(), x.1.clone()))
            .collect::<BTreeMap<SchemaType, ValueWrapper>>();
        // Up
        self.up_schemas(
            ctx,
            &schema_creators_eval,
            &schema_creators_vali,
            &up_eval,
            &up_vali,
            &hash,
            &network,
        )
        .await?;

        // Update
        let update_eval = new_schemas_eval
            .clone()
            .iter()
            .filter(|x| old_schemas_eval.contains(x.0))
            .map(|x| (x.0.clone(), x.1.clone()))
            .collect::<BTreeMap<SchemaType, ValueWrapper>>();

        let update_vali = new_schemas_vali
            .clone()
            .iter()
            .filter(|x| old_schemas_vali.contains(x.0))
            .map(|x| (x.0.clone(), x.1.clone()))
            .collect::<BTreeMap<SchemaType, ValueWrapper>>();

        self.update_schemas(
            ctx,
            &schema_creators_eval,
            &schema_creators_vali,
            &update_eval,
            &update_vali,
        )
        .await
    }

    async fn build_childs(
        &self,
        ctx: &mut ActorContext<Governance>,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        // If subject is a governance
        let owner = *self.our_key == self.subject_metadata.owner;
        let new_owner = self.subject_metadata.new_owner.is_some();
        let i_new_owner =
            self.subject_metadata.new_owner == Some((*self.our_key).clone());

        if new_owner {
            if i_new_owner {
                self.up_owner(ctx, hash, network).await?;
            } else {
                self.up_not_owner(ctx, hash, network).await?;
            }
        } else if owner {
            self.up_owner(ctx, hash, network).await?;
        } else {
            self.up_not_owner(ctx, hash, network).await?;
        }

        let new_schemas_eval = {
            let schemas =
                self.properties.schemas(ProtocolTypes::Evaluation, &self.our_key);
            Self::up_compilers_schemas(
                ctx,
                &schemas,
                self.subject_metadata.subject_id.clone(),
            )
            .await?;

            schemas
                .iter()
                .map(|x| (x.0.clone(), x.1.initial_value.clone()))
                .collect::<BTreeMap<SchemaType, ValueWrapper>>()
        };

        let schemas_namespace_eval = self
            .properties
            .schemas_namespace(ProtocolTypes::Evaluation, &self.our_key);

        let schema_creators_eval = self
            .properties
            .schema_creators_namespace(schemas_namespace_eval);

        let schemas_namespace_vali = self
            .properties
            .schemas_namespace(ProtocolTypes::Validation, &self.our_key);

        let schema_creators_vali = self
            .properties
            .schema_creators_namespace(schemas_namespace_vali);

        let new_schemas_vali = self
            .properties
            .schemas_init_value(ProtocolTypes::Validation, &self.our_key);

        self.up_schemas(
            ctx,
            &schema_creators_eval,
            &schema_creators_vali,
            &new_schemas_eval,
            &new_schemas_vali,
            hash,
            network,
        )
        .await
    }

    async fn up_not_owner(
        &self,
        ctx: &mut ActorContext<Self>,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        let node_key = if let Some(new_owner) = &self.subject_metadata.new_owner
        {
            new_owner.clone()
        } else {
            self.subject_metadata.owner.clone()
        };

        if self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Validator,
        }) {
            // If we are a validator
            let validator = ValiWorker {
                node_key: node_key.clone(),
                our_key: self.our_key.clone(),
                init_state: None,
                governance_id: self.subject_metadata.subject_id.clone(),
                gov_version: self.properties.version,
                sn: self.subject_metadata.sn,
                hash: *hash,
                network: network.clone(),
            };
            ctx.create_child("validator", validator).await?;
        }

        if self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Evaluator,
        }) {
            // If we are a evaluator
            let evaluator = EvalWorker {
                node_key: node_key.clone(),
                our_key: self.our_key.clone(),
                governance_id: self.subject_metadata.subject_id.clone(),
                gov_version: self.properties.version,
                sn: self.subject_metadata.sn,
                init_state: None,
                hash: *hash,
                network: network.clone(),
            };
            ctx.create_child("evaluator", evaluator).await?;
        }

        if self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Approver,
        }) {
            let always_accept = if let Some(config) =
                ctx.system().get_helper::<ConfigHelper>("config").await
            {
                config.always_accept
            } else {
                return Err(ActorError::NotHelper("config".to_owned()));
            };

            let pass_votation = if always_accept {
                VotationType::AlwaysAccept
            } else {
                VotationType::Manual
            };

            let init_approver = InitApprPersist {
                our_key: self.our_key.clone(),
                node_key: node_key.clone(),
                subject_id: self.subject_metadata.subject_id.clone(),
                pass_votation,
                helpers: (hash.clone(), network.clone()),
            };

            ctx.create_child(
                "approver",
                ApprPersist::initial(init_approver),
            )
            .await?;
        }

        Ok(())
    }

    async fn up_down_not_owner(
        &self,
        ctx: &mut ActorContext<Self>,
        old_gov: &GovernanceData,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        let node_key = if let Some(new_owner) = &self.subject_metadata.new_owner
        {
            new_owner.clone()
        } else {
            self.subject_metadata.owner.clone()
        };

        let old_val = old_gov.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Validator,
        });

        let new_val = self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Validator,
        });

        match (old_val, new_val) {
            (true, false) => {
                let actor: Option<ActorRef<ValiWorker>> =
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
                // If we are a validator
                let validator = ValiWorker {
                    node_key: node_key.clone(),
                    our_key: self.our_key.clone(),
                    init_state: None,
                    governance_id: self.subject_metadata.subject_id.clone(),
                    gov_version: self.properties.version,
                    sn: self.subject_metadata.sn,
                    hash: *hash,
                    network: network.clone(),
                };
                ctx.create_child("validator", validator).await?;
            }
            _ => {}
        };

        let old_eval = old_gov.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Evaluator,
        });

        let new_eval = self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Evaluator,
        });

        match (old_eval, new_eval) {
            (true, false) => {
                let actor: Option<ActorRef<EvalWorker>> =
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
                let evaluator = EvalWorker {
                    node_key: node_key.clone(),
                    our_key: self.our_key.clone(),
                    governance_id: self.subject_metadata.subject_id.clone(),
                    gov_version: self.properties.version,
                    sn: self.subject_metadata.sn,
                    init_state: None,
                    hash: *hash,
                    network: network.clone(),
                };
                ctx.create_child("evaluator", evaluator).await?;
            }
            _ => {}
        };

        let old_appr = old_gov.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Approver,
        });

        let new_appr = self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Approver,
        });

        match (old_appr, new_appr) {
            (true, false) => {
                let actor: Option<ActorRef<ApprPersist>> =
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

                let pass_votation = if always_accept {
                    VotationType::AlwaysAccept
                } else {
                    VotationType::Manual
                };

                let init_approver = InitApprPersist {
                    our_key: self.our_key.clone(),
                    node_key: node_key.clone(),
                    subject_id: self.subject_metadata.subject_id.clone(),
                    pass_votation,
                    helpers: (hash.clone(), network.clone()),
                };

                ctx.create_child(
                    "approver",
                    ApprPersist::initial(init_approver),
                )
                .await?;
            }
            _ => {}
        };

        Ok(())
    }

    async fn down_not_owner(
        ctx: &mut ActorContext<Self>,
        gov: &GovernanceData,
        our_key: PublicKey,
    ) -> Result<(), ActorError> {
        if gov.has_this_role(HashThisRole::Gov {
            who: our_key.clone(),
            role: RoleTypes::Validator,
        }) {
            let actor: Option<ActorRef<ValiWorker>> =
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
            let actor: Option<ActorRef<ValiWorker>> =
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
            let actor: Option<ActorRef<ApprPersist>> =
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
        &self,
        ctx: &mut ActorContext<Self>,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        let always_accept = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.always_accept
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };
        let pass_votation = if always_accept {
            VotationType::AlwaysAccept
        } else {
            VotationType::Manual
        };

        let init_approver = InitApprPersist {
            our_key: self.our_key.clone(),
            node_key: (*self.our_key).clone(),
            subject_id: self.subject_metadata.subject_id.clone(),
            pass_votation,
            helpers: (hash.clone(), network.clone()),
        };

        ctx.create_child("approver", ApprPersist::initial(init_approver))
            .await?;

        Ok(())
    }

    async fn down_owner(
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor: Option<ActorRef<ApprPersist>> =
            ctx.get_child("approver").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            let e = ActorError::NotFound(ActorPath::from(format!(
                "{}/approver",
                ctx.path()
            )));
            return Err(emit_fail(ctx, e).await);
        }

        Ok(())
    }

    async fn up_compilers_schemas(
        ctx: &mut ActorContext<Self>,
        schemas: &BTreeMap<SchemaType, Schema>,
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
                    contract: contract.clone(),
                    initial_value: initial_value.0.clone(),
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
        schemas: &BTreeSet<SchemaType>,
    ) -> Result<(), ActorError> {
        for schema in schemas.iter() {
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
        hash: &HashAlgorithm,
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
                ctx,
                &first,
                hash,
                Metadata::from(self.clone()),
            )
            .await
            {
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
                        .content()
                        .event_request
                        .signature()
                        .signer
                        .to_string(),
                },
                &first.content().event_request.content(),
            )
            .await?;

            first
        };

        for event in iter {
            let actual_ledger_hash = hash_borsh(&*hash.hasher(), &last_ledger.0)
                .map_err(|e| todo!())?;
            let last_data = LastData {
                gov_version: last_ledger.content().gov_version,
                vali_data: last_ledger
                    .content()
                    .protocols
                    .get_validation_data(),
            };

            let last_event_is_ok = match Self::verify_new_ledger_event(
                ctx,
                event,
                Metadata::from(self.clone()),
                actual_ledger_hash,
                last_data,
                hash,
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
                let update = match event
                    .content()
                    .event_request
                    .content()
                    .clone()
                {
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
                            &event.signature().signer.to_string(),
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
                            .content()
                            .event_request
                            .signature()
                            .signer
                            .to_string(),
                    },
                    &event.content().event_request.content(),
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
    GetLastSn,
    GetGovernance,
}

impl Message for GovernanceMessage {}

#[derive(Debug, Clone)]
pub enum GovernanceResponse {
    /// The subject metadata.
    Metadata(Box<Metadata>),
    UpdateResult(u64, PublicKey, Option<PublicKey>),
    Ledger {
        ledger: Vec<SignedLedger>,
    },
    LastLedger {
        ledger_event: Option<SignedLedger>,
    },
    Governance(Box<GovernanceData>),
    NewCompilers(Vec<SchemaType>),
    Sn(u64),
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

        let Some(network) = ctx
            .system()
            .get_helper::<Arc<NetworkSender>>("network")
            .await
        else {
            return Err(ActorError::NotHelper("network".to_owned()));
        };

        let hash = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.hash_algorithm
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        if self.subject_metadata.active {
            self.build_childs(ctx, &hash, &network)
                .await?;

            let sink_actor = ctx
                .create_child(
                    "sink_data",
                    SinkData {
                        controller_id: self.our_key.to_string(),
                    },
                )
                .await?;
            let sink =
                Sink::new(sink_actor.subscribe(), ext_db.get_sink_data());
            ctx.system().run_sink(sink).await;

            let sink = Sink::new(sink_actor.subscribe(), ave_sink.clone());
            ctx.system().run_sink(sink).await;
        }

        ctx.create_child("relation_ship", RelationShip::initial(()))
            .await?;

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
            GovernanceMessage::GetLastSn => {
                Ok(GovernanceResponse::Sn(self.subject_metadata.sn))
            },
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
                let ledger = self.get_ledger(ctx, last_sn).await?;
                Ok(GovernanceResponse::Ledger { ledger })
            }
            GovernanceMessage::GetLastLedger => {
                let ledger_event = self.get_last_ledger(ctx).await?;
                Ok(GovernanceResponse::LastLedger { ledger_event })
            }
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
    type InitParams =
        (Option<(SubjectMetadata, GovernanceData)>, Arc<PublicKey>);

    fn update(&mut self, state: Self) {
        self.properties = state.properties;
        self.subject_metadata = state.subject_metadata;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        let (subject_metadata, properties) =
            if let Some((subject_metadata, properties)) = params.0 {
                (subject_metadata, properties)
            } else {
                Default::default()
            };
        Self {
            our_key: params.1,
            subject_metadata,
            properties,
        }
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match (
            event.content().event_request.content(),
            &event.content().protocols,
        ) {
            (EventRequest::Create(..), Protocols::Create { validation }) => {
                if let ValidationMetadata::Metadata(metadata) =
                    &validation.validation_metadata
                {
                    self.subject_metadata = SubjectMetadata::new(metadata);
                    self.properties = serde_json::from_value::<GovernanceData>(
                        metadata.properties.0.clone(),
                    )
                    .map_err(|e| todo!())?;
                } else {
                    todo!()
                }

                return Ok(());
            }
            (
                EventRequest::Fact(..),
                Protocols::GovFact {
                    evaluation,
                    approval,
                    ..
                },
            ) => {
                if let Some(eval_res) = evaluation.evaluator_res() {
                    if let Some(appr_res) = approval {
                        if appr_res.approved {
                            self.apply_patch(eval_res.patch)?;
                        }
                    } else {
                        todo!()
                    }
                }
            }
            (
                EventRequest::Transfer(transfer_request),
                Protocols::Transfer { evaluation, .. },
            ) => {
                if evaluation.evaluator_res().is_some() {
                    self.subject_metadata.new_owner =
                        Some(transfer_request.new_owner.clone());
                }
            }
            (
                EventRequest::Confirm(..),
                Protocols::GovConfirm { evaluation, .. },
            ) => {
                if let Some(eval_res) = evaluation.evaluator_res() {
                    if let Some(new_owner) =
                        self.subject_metadata.new_owner.take()
                    {
                        self.subject_metadata.owner = new_owner;
                    } else {
                        todo!()
                    }

                    self.apply_patch(eval_res.patch)?;
                }
            }
            (EventRequest::Reject(..), Protocols::Reject { .. }) => {
                self.subject_metadata.new_owner = None;
            }
            (EventRequest::EOL(..), Protocols::EOL { .. }) => {
                self.subject_metadata.active = false
            }
            _ => todo!("Tackers events es una gov esto"),
        }

        if event.content().protocols.is_success() {
            self.properties.version += 1;
        }

        self.subject_metadata.sn += 1;
        self.subject_metadata.prev_ledger_event_hash =
            event.content().prev_ledger_event_hash.clone();

        Ok(())
    }
}

impl Storable for Governance {}
