//! # Governance module.
//!

use crate::{
    approval::{
        persist::{ApprPersist, InitApprPersist},
        types::VotationType,
    },
    db::Storable,
    evaluation::{
        compiler::{
            CompilerResponse, ContractCompiler, ContractCompilerMessage,
        },
        schema::{EvaluationSchema, EvaluationSchemaMessage},
        worker::{EvalWorker, EvalWorkerMessage},
    },
    governance::{
        contract_register::{
            ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
        },
        data::GovernanceData,
        events::{
            GovernanceEvent, governance_event_roles_update_fact,
            governance_event_update_creator_change,
        },
        model::{
            CreatorQuantity, HashThisRole, ProtocolTypes, Quorum, RoleTypes,
            Schema, WitnessesData,
        },
        role_register::{
            CurrentValidationRoles, RoleRegister, RoleRegisterMessage,
            RoleRegisterResponse,
        },
        sn_register::{SnRegister, SnRegisterMessage, SnRegisterResponse},
        subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        },
        tracker_sync::{TrackerSync, TrackerSyncConfig},
        version_sync::{GovernanceVersionSync, GovernanceVersionSyncMessage},
        witnesses_register::{
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse, WitnessesType,
        },
    },
    helpers::{db::ExternalDB, network::service::NetworkSender, sink::AveSink},
    model::{
        common::{
            emit_fail, get_last_event, purge_storage, subject::make_obsolete,
        },
        event::{Ledger, Protocols, ValidationMetadata},
    },
    node::{Node, NodeMessage, TransferSubject, register::RegisterMessage},
    subject::{
        DataForSink, EventLedgerDataForSink, Metadata, Subject,
        SubjectMetadata,
        error::SubjectError,
        sinkdata::{SinkData, SinkDataMessage},
    },
    system::ConfigHelper,
    validation::{
        request::LastData,
        schema::{ValidationSchema, ValidationSchemaMessage},
        worker::{ValiWorker, ValiWorkerMessage},
    },
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, Response, Sink,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey},
    request::EventRequest,
    schematype::ReservedWords,
};

use async_trait::async_trait;
use ave_actors::{FullPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    sync::Arc,
    time::Duration,
};
use tokio::{fs, sync::RwLock};
use wasmtime::Module;

pub mod contract_register;
pub mod data;
pub mod error;
pub mod events;
pub mod model;
pub mod role_register;
pub mod sn_register;
pub mod subject_register;
pub mod tracker_sync;
pub mod version_sync;
pub mod witnesses_register;

pub struct RolesUpdate {
    pub appr_quorum: Option<Quorum>,
    pub new_approvers: Vec<PublicKey>,
    pub remove_approvers: Vec<PublicKey>,

    pub eval_quorum: HashMap<SchemaType, Quorum>,
    pub new_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

    pub vali_quorum: HashMap<SchemaType, Quorum>,
    pub new_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

    pub new_creator: HashMap<
        (SchemaType, String, PublicKey),
        (CreatorQuantity, Vec<WitnessesType>),
    >,
    pub remove_creator: HashSet<(SchemaType, String, PublicKey)>,

    pub new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
}

pub struct RolesUpdateConfirm {
    pub new_approver: Option<PublicKey>,
    pub remove_approver: PublicKey,

    pub new_evaluator: Option<PublicKey>,
    pub remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

    pub new_validator: Option<PublicKey>,
    pub remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

    pub remove_creator: HashSet<(SchemaType, String, PublicKey)>,
    pub remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
}

pub struct RolesUpdateRemove {
    pub witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub creator: HashSet<(SchemaType, String, PublicKey)>,
    pub approvers: Vec<PublicKey>,
    pub evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
}

pub struct CreatorRoleUpdate {
    pub new_creator: HashMap<
        (SchemaType, String, PublicKey),
        (CreatorQuantity, BTreeSet<String>),
    >,

    pub update_creator_quantity:
        HashSet<(SchemaType, String, PublicKey, CreatorQuantity)>,

    pub update_creator_witnesses:
        HashSet<(SchemaType, String, PublicKey, BTreeSet<String>)>,

    pub remove_creator: HashSet<(SchemaType, String, PublicKey)>,
}

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct Governance {
    #[serde(skip)]
    pub our_key: Arc<PublicKey>,
    #[serde(skip)]
    pub service: bool,
    #[serde(skip)]
    pub hash: Option<HashAlgorithm>,
    pub subject_metadata: SubjectMetadata,
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
        let hash = None;

        Ok(Self {
            hash,
            our_key,
            service: false,
            subject_metadata,
            properties,
        })
    }
}

#[async_trait]
impl Subject for Governance {
    async fn update_sn(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let witnesses_register = ctx
            .get_child::<WitnessesRegister>("witnesses_register")
            .await?;

        witnesses_register
            .tell(WitnessesRegisterMessage::UpdateSnGov {
                sn: self.subject_metadata.sn,
            })
            .await
    }

    async fn eol(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::EOLSubject {
            subject_id: self.subject_metadata.subject_id.clone(),
            i_owner: *self.our_key == self.subject_metadata.owner,
        })
        .await
    }

    async fn reject(
        &self,
        ctx: &mut ActorContext<Self>,
        _gov_version: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::RejectTransfer(
            self.subject_metadata.subject_id.clone(),
        ))
        .await
    }

    async fn confirm(
        &self,
        ctx: &mut ActorContext<Self>,
        _new_owner: PublicKey,
        _gov_version: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::ConfirmTransfer(
            self.subject_metadata.subject_id.clone(),
        ))
        .await
    }

    async fn transfer(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        _gov_version: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::TransferSubject(TransferSubject {
            name: self.subject_metadata.name.clone(),
            subject_id: self.subject_metadata.subject_id.clone(),
            new_owner: new_owner.clone(),
            actual_owner: self.subject_metadata.owner.clone(),
        }))
        .await
    }

    async fn get_last_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Option<Ledger>, ActorError> {
        get_last_event(ctx).await
    }

    fn apply_patch(
        &mut self,
        json_patch: ValueWrapper,
    ) -> Result<(), ActorError> {
        let patch_json = serde_json::from_value::<Patch>(json_patch.0)
            .map_err(|e| {
                let error = SubjectError::PatchConversionFailed {
                    details: e.to_string(),
                };
                error!(
                    error = %e,
                    subject_id = %self.subject_metadata.subject_id,
                    "Failed to convert patch from JSON"
                );
                ActorError::Functional {
                    description: error.to_string(),
                }
            })?;

        let mut properties = self.properties.to_value_wrapper();

        patch(&mut properties.0, &patch_json).map_err(|e| {
            let error = SubjectError::PatchApplicationFailed {
                details: e.to_string(),
            };
            error!(
                error = %e,
                subject_id = %self.subject_metadata.subject_id,
                "Failed to apply patch to properties"
            );
            ActorError::Functional {
                description: error.to_string(),
            }
        })?;

        self.properties = serde_json::from_value::<GovernanceData>(
            properties.0,
        )
        .map_err(|e| {
            let error = SubjectError::GovernanceDataConversionFailed {
                details: e.to_string(),
            };
            error!(
                error = %e,
                subject_id = %self.subject_metadata.subject_id,
                "Failed to convert properties to GovernanceData"
            );
            ActorError::Functional {
                description: error.to_string(),
            }
        })?;

        debug!(
            subject_id = %self.subject_metadata.subject_id,
            "Patch applied successfully"
        );

        Ok(())
    }

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<Ledger>,
    ) -> Result<(), ActorError> {
        let Some(network) = ctx
            .system()
            .get_helper::<Arc<NetworkSender>>("network")
            .await
        else {
            return Err(ActorError::Helper {
                name: "network".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let Some(hash) = self.hash else {
            return Err(ActorError::FunctionalCritical {
                description: "Hash algorithm is None".to_string(),
            });
        };

        let current_sn = self.subject_metadata.sn;
        let current_new_owner_some = self.subject_metadata.new_owner.is_some();
        let i_current_new_owner = self.subject_metadata.new_owner.clone()
            == Some((*self.our_key).clone());
        let current_owner = self.subject_metadata.owner.clone();

        let current_properties = self.properties.clone();

        if let Err(e) = self.verify_new_ledger_events(ctx, events, &hash).await
        {
            if let ActorError::Functional { description } = e.clone() {
                warn!(
                    error = %description,
                    subject_id = %self.subject_metadata.subject_id,
                    sn = self.subject_metadata.sn,
                    "Error verifying new ledger events"
                );

                // Falló en la creación
                if self.subject_metadata.sn == 0 {
                    return Err(e);
                }
            } else {
                error!(
                    error = %e,
                    subject_id = %self.subject_metadata.subject_id,
                    sn = self.subject_metadata.sn,
                    "Critical error verifying new ledger events"
                );
                return Err(e);
            }
        };

        if current_sn < self.subject_metadata.sn {
            let old_gov = current_properties;
            if !self.subject_metadata.active {
                if current_owner == *self.our_key {
                    Self::down_owner(ctx).await?;
                } else {
                    Self::down_not_owner(ctx, &old_gov, self.our_key.clone())
                        .await?;
                }

                let old_schemas_eval = old_gov
                    .schemas_name(ProtocolTypes::Evaluation, &self.our_key);

                Self::down_compilers_schemas(
                    ctx,
                    &old_schemas_eval,
                    &self.subject_metadata.subject_id,
                )
                .await?;

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
                    Self::down_not_owner(ctx, &old_gov, self.our_key.clone())
                        .await?;
                    self.up_owner(ctx, &hash, &network).await?;
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
                self.update_childs(ctx).await?;
            }

            let _ = make_obsolete(ctx, &self.subject_metadata.subject_id).await;
        }

        if current_sn < self.subject_metadata.sn || current_sn == 0 {
            Self::publish_sink(
                ctx,
                SinkDataMessage::UpdateState(Box::new(Metadata::from(
                    self.clone(),
                ))),
            )
            .await?;

            self.update_sn(ctx).await?;
            self.refresh_version_sync(ctx).await?;
        }

        Ok(())
    }
}

impl Governance {
    async fn up_approver_only(
        &self,
        ctx: &mut ActorContext<Self>,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        if !self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Approver,
        }) {
            return Ok(());
        }

        let always_accept = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.always_accept
        } else {
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let pass_votation = if always_accept {
            VotationType::AlwaysAccept
        } else {
            VotationType::Manual
        };

        let owner = *self.our_key == self.subject_metadata.owner;
        let i_new_owner =
            self.subject_metadata.new_owner == Some((*self.our_key).clone());

        let node_key = if (owner && self.subject_metadata.new_owner.is_none())
            || i_new_owner
        {
            (*self.our_key).clone()
        } else {
            self.subject_metadata
                .new_owner
                .clone()
                .unwrap_or_else(|| self.subject_metadata.owner.clone())
        };

        let init_approver = InitApprPersist {
            our_key: self.our_key.clone(),
            node_key,
            subject_id: self.subject_metadata.subject_id.clone(),
            pass_votation,
            helpers: (*hash, network.clone()),
        };

        ctx.create_child("approver", ApprPersist::initial(init_approver))
            .await?;

        Ok(())
    }

    async fn current_validation_roles(
        &self,
        ctx: &ActorContext<Self>,
        schema_id: SchemaType,
    ) -> Result<CurrentValidationRoles, ActorError> {
        let actor = ctx.get_child::<RoleRegister>("role_register").await?;
        let response = actor
            .ask(RoleRegisterMessage::GetCurrentValidationRoles { schema_id })
            .await?;

        match response {
            RoleRegisterResponse::CurrentValidationRoles(roles) => Ok(roles),
            _ => Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}/role_register",
                    self.subject_metadata.subject_id
                )),
                expected: "RoleRegisterResponse::CurrentValidationRoles"
                    .to_owned(),
            }),
        }
    }

    async fn refresh_version_sync(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if !self.service {
            return Ok(());
        }

        let version_sync = ctx
            .get_child::<GovernanceVersionSync>("version_sync")
            .await?;
        let governance_peers = self
            .properties
            .get_witnesses(WitnessesData::Gov)
            .map_err(|e| ActorError::Functional {
                description: e.to_string(),
            })?;

        let _ = version_sync
            .ask(GovernanceVersionSyncMessage::RefreshGovernance {
                version: self.properties.version,
                governance_peers,
            })
            .await?;

        Ok(())
    }

    async fn update_schemas(
        &self,
        ctx: &ActorContext<Self>,
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
            let actor = ctx
                .get_child::<EvaluationSchema>(&format!(
                    "{}_evaluation",
                    schema_id
                ))
                .await?;

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
        }

        for (schema_id, init_state) in update_vali.iter() {
            let current_roles = self
                .current_validation_roles(ctx, schema_id.clone())
                .await?;
            let actor = ctx
                .get_child::<ValidationSchema>(&format!(
                    "{}_validation",
                    schema_id
                ))
                .await?;

            actor
                .tell(ValidationSchemaMessage::Update {
                    creators: schema_creators_vali
                        .get(schema_id)
                        .cloned()
                        .unwrap_or_default(),
                    sn: self.subject_metadata.sn,
                    gov_version: self.properties.version,
                    init_state: init_state.clone(),
                    current_roles: current_roles.schema,
                })
                .await?;
        }

        Ok(())
    }

    async fn down_schemas(
        ctx: &ActorContext<Self>,
        old_schemas_eval: &BTreeSet<SchemaType>,
        old_schemas_val: &BTreeSet<SchemaType>,
    ) -> Result<(), ActorError> {
        for schema_id in old_schemas_eval {
            let actor = ctx
                .get_child::<EvaluationSchema>(&format!(
                    "{}_evaluation",
                    schema_id
                ))
                .await?;
            actor.ask_stop().await?;
        }

        for schema_id in old_schemas_val {
            let actor = ctx
                .get_child::<ValidationSchema>(&format!(
                    "{}_validation",
                    schema_id
                ))
                .await?;
            actor.ask_stop().await?;
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
        hash_network: (&HashAlgorithm, &Arc<NetworkSender>),
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
                hash: *hash_network.0,
                network: hash_network.1.clone(),
            };

            ctx.create_child(&format!("{}_evaluation", schema_id), eval_actor)
                .await?;
        }

        for (schema_id, init_state) in up_vali.iter() {
            let current_roles = self
                .current_validation_roles(ctx, schema_id.clone())
                .await?;
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
                current_roles: current_roles.schema,
                hash: *hash_network.0,
                network: hash_network.1.clone(),
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
            return Err(ActorError::Helper {
                name: "network".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let Some(hash) = self.hash else {
            return Err(ActorError::FunctionalCritical {
                description: "Hash algorithm is None".to_string(),
            });
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
                .cloned()
                .collect();
            Self::down_compilers_schemas(
                ctx,
                &down,
                &self.subject_metadata.subject_id,
            )
            .await?;

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
                &hash,
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
            .cloned()
            .collect();

        let down_vali = old_schemas_vali
            .clone()
            .iter()
            .filter(|x| !new_schemas_vali.contains_key(x))
            .cloned()
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
            (&hash, &network),
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

    async fn update_childs(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Ok(evaluator) = ctx.get_child::<EvalWorker>("evaluator").await {
            evaluator
                .tell(EvalWorkerMessage::UpdateGovVersion {
                    gov_version: self.properties.version,
                })
                .await?;
        }

        if let Ok(validator) = ctx.get_child::<ValiWorker>("validator").await {
            let current_roles = self
                .current_validation_roles(ctx, SchemaType::Governance)
                .await?;
            validator
                .tell(ValiWorkerMessage::UpdateCurrentRoles {
                    gov_version: self.properties.version,
                    current_roles: crate::validation::worker::CurrentWorkerRoles {
                        approval: current_roles.approval,
                        evaluation: crate::governance::role_register::RoleDataRegister {
                            workers: current_roles
                                .schema
                                .evaluation
                                .iter()
                                .map(|role| role.key.clone())
                                .collect(),
                            quorum: current_roles.schema.evaluation_quorum,
                        },
                    },
                })
                .await?;
        }

        Ok(())
    }

    async fn sweep_contract_artifacts(
        &self,
        ctx: &ActorContext<Self>,
        schemas: &BTreeMap<SchemaType, Schema>,
    ) -> Result<(), ActorError> {
        let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        else {
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let Some(contracts) = ctx
            .system()
            .get_helper::<Arc<RwLock<HashMap<String, Arc<Module>>>>>(
                "contracts",
            )
            .await
        else {
            return Err(ActorError::Helper {
                name: "contracts".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let contract_register = ctx
            .get_child::<ContractRegister>("contract_register")
            .await?;

        let prefix = format!("{}_", self.subject_metadata.subject_id);
        let mut allowed: HashSet<String> = schemas
            .keys()
            .map(|schema_id| {
                format!("{}_{}", self.subject_metadata.subject_id, schema_id)
            })
            .collect();

        let registered: Vec<String> = match contract_register
            .ask(ContractRegisterMessage::ListContracts)
            .await?
        {
            ContractRegisterResponse::Contracts(contracts) => contracts,
            _ => Vec::new(),
        };

        for contract_name in registered {
            if contract_name.starts_with(&prefix)
                && !allowed.contains(&contract_name)
            {
                contract_register
                    .tell(ContractRegisterMessage::DeleteMetadata {
                        contract_name: contract_name.clone(),
                    })
                    .await?;
                let mut contracts = contracts.write().await;
                contracts.remove(&contract_name);
            }
        }

        let contracts_dir = config.contracts_path.join("contracts");
        if !contracts_dir.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(&contracts_dir).await.map_err(|e| {
            ActorError::Functional {
                description: format!(
                    "Can not read contracts directory {}: {}",
                    contracts_dir.display(),
                    e
                ),
            }
        })?;

        while let Some(entry) =
            entries
                .next_entry()
                .await
                .map_err(|e| ActorError::Functional {
                    description: format!(
                        "Can not iterate contracts directory {}: {}",
                        contracts_dir.display(),
                        e
                    ),
                })?
        {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if !file_name.starts_with(&prefix) {
                continue;
            }

            let is_temp = file_name.starts_with(&format!(
                "{}_temp_",
                self.subject_metadata.subject_id
            ));
            if is_temp || !allowed.contains(&file_name) {
                let path = entry.path();
                let _ = fs::remove_dir_all(path).await;
                if !is_temp {
                    allowed.remove(&file_name);
                }
            }
        }

        Ok(())
    }

    async fn delete_all_contract_artifacts(
        &self,
        ctx: &ActorContext<Self>,
        contract_register: &ActorRef<ContractRegister>,
    ) -> Result<(), ActorError> {
        let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        else {
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let Some(contracts) = ctx
            .system()
            .get_helper::<Arc<RwLock<HashMap<String, Arc<Module>>>>>(
                "contracts",
            )
            .await
        else {
            return Err(ActorError::Helper {
                name: "contracts".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let prefix = format!("{}_", self.subject_metadata.subject_id);

        let registered: Vec<String> = match contract_register
            .ask(ContractRegisterMessage::ListContracts)
            .await?
        {
            ContractRegisterResponse::Contracts(contracts) => contracts,
            _ => Vec::new(),
        };

        for contract_name in registered {
            if contract_name.starts_with(&prefix) {
                contract_register
                    .ask(ContractRegisterMessage::DeleteMetadata {
                        contract_name: contract_name.clone(),
                    })
                    .await?;
                let mut contracts = contracts.write().await;
                contracts.remove(&contract_name);
            }
        }

        let contracts_dir = config.contracts_path.join("contracts");
        if !contracts_dir.exists() {
            return Ok(());
        }

        let mut entries = fs::read_dir(&contracts_dir).await.map_err(|e| {
            ActorError::Functional {
                description: format!(
                    "Can not read contracts directory {}: {}",
                    contracts_dir.display(),
                    e
                ),
            }
        })?;

        while let Some(entry) =
            entries
                .next_entry()
                .await
                .map_err(|e| ActorError::Functional {
                    description: format!(
                        "Can not iterate contracts directory {}: {}",
                        contracts_dir.display(),
                        e
                    ),
                })?
        {
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with(&prefix) {
                let path = entry.path();
                fs::remove_dir_all(&path).await.map_err(|e| {
                    ActorError::Functional {
                        description: format!(
                            "Can not remove contract directory {}: {}",
                            path.display(),
                            e
                        ),
                    }
                })?;
            }
        }

        Ok(())
    }

    async fn build_childs(
        &self,
        ctx: &mut ActorContext<Self>,
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
            let schemas = self
                .properties
                .schemas(ProtocolTypes::Evaluation, &self.our_key);
            self.sweep_contract_artifacts(ctx, &schemas).await?;
            Self::up_compilers_schemas(
                ctx,
                &schemas,
                self.subject_metadata.subject_id.clone(),
                hash,
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
            (hash, network),
        )
        .await
    }

    async fn up_not_owner(
        &self,
        ctx: &mut ActorContext<Self>,
        hash: &HashAlgorithm,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        let node_key = self.subject_metadata.new_owner.as_ref().map_or_else(
            || self.subject_metadata.owner.clone(),
            |new_owner| new_owner.clone(),
        );

        if self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Validator,
        }) {
            let current_roles = self
                .current_validation_roles(ctx, SchemaType::Governance)
                .await?;
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
                current_roles: crate::validation::worker::CurrentWorkerRoles {
                    approval: current_roles.approval,
                    evaluation:
                        crate::governance::role_register::RoleDataRegister {
                            workers: current_roles
                                .schema
                                .evaluation
                                .iter()
                                .map(|role| role.key.clone())
                                .collect(),
                            quorum: current_roles.schema.evaluation_quorum,
                        },
                },
                stop: false,
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
                stop: false,
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
                return Err(ActorError::Helper {
                    name: "config".to_owned(),
                    reason: "Not found".to_owned(),
                });
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
                helpers: (*hash, network.clone()),
            };

            ctx.create_child("approver", ApprPersist::initial(init_approver))
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
        let node_key = self.subject_metadata.new_owner.as_ref().map_or_else(
            || self.subject_metadata.owner.clone(),
            |new_owner| new_owner.clone(),
        );

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
                let actor = ctx.get_child::<ValiWorker>("validator").await?;
                actor.ask_stop().await?;
            }
            (false, true) => {
                let current_roles = self
                    .current_validation_roles(ctx, SchemaType::Governance)
                    .await?;
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
                    current_roles: crate::validation::worker::CurrentWorkerRoles {
                        approval: current_roles.approval,
                        evaluation: crate::governance::role_register::RoleDataRegister {
                            workers: current_roles
                                .schema
                                .evaluation
                                .iter()
                                .map(|role| role.key.clone())
                                .collect(),
                            quorum: current_roles.schema.evaluation_quorum,
                        },
                    },
                    stop: false,
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
                let actor = ctx.get_child::<EvalWorker>("evaluator").await?;

                actor.ask_stop().await?;
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
                    stop: false,
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
                let actor = ctx.get_child::<ApprPersist>("approver").await?;

                actor.ask_stop().await?;
            }
            (false, true) => {
                let always_accept = if let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config").await
                {
                    config.always_accept
                } else {
                    return Err(ActorError::Helper {
                        name: "config".to_owned(),
                        reason: "Not found".to_owned(),
                    });
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
                    helpers: (*hash, network.clone()),
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
        ctx: &ActorContext<Self>,
        gov: &GovernanceData,
        our_key: Arc<PublicKey>,
    ) -> Result<(), ActorError> {
        if gov.has_this_role(HashThisRole::Gov {
            who: (*our_key).clone(),
            role: RoleTypes::Validator,
        }) {
            let actor = ctx.get_child::<ValiWorker>("validator").await?;

            actor.ask_stop().await?;
        }

        if gov.has_this_role(HashThisRole::Gov {
            who: (*our_key).clone(),
            role: RoleTypes::Evaluator,
        }) {
            let actor = ctx.get_child::<EvalWorker>("evaluator").await?;

            actor.ask_stop().await?;
        }

        if gov.has_this_role(HashThisRole::Gov {
            who: (*our_key).clone(),
            role: RoleTypes::Approver,
        }) {
            let actor = ctx.get_child::<ApprPersist>("approver").await?;

            actor.ask_stop().await?;
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
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not Found".to_string(),
            });
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
            helpers: (*hash, network.clone()),
        };

        ctx.create_child("approver", ApprPersist::initial(init_approver))
            .await?;

        Ok(())
    }

    async fn down_owner(ctx: &ActorContext<Self>) -> Result<(), ActorError> {
        let actor = ctx.get_child::<ApprPersist>("approver").await?;
        actor.ask_stop().await?;

        Ok(())
    }

    async fn up_compilers_schemas(
        ctx: &mut ActorContext<Self>,
        schemas: &BTreeMap<SchemaType, Schema>,
        subject_id: DigestIdentifier,
        hash: &HashAlgorithm,
    ) -> Result<(), ActorError> {
        let contracts_path = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.contracts_path
        } else {
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        for (id, schema) in schemas {
            let actor_name = format!("{}_contract_compiler", id);

            let compiler = ctx
                .create_child(&actor_name, ContractCompiler::new(*hash))
                .await?;

            let Schema {
                contract,
                initial_value,
                viewpoints: _,
            } = schema;

            let response = compiler
                .ask(ContractCompilerMessage::Compile {
                    contract_name: format!("{}_{}", subject_id, id),
                    contract: contract.clone(),
                    initial_value: initial_value.0.clone(),
                    contract_path: contracts_path
                        .join("contracts")
                        .join(format!("{}_{}", subject_id, id)),
                })
                .await?;

            if let CompilerResponse::Error(error) = response {
                return Err(ActorError::Functional {
                    description: format!(
                        "Can not compile schema contract {}: {}",
                        id, error
                    ),
                });
            }
        }

        Ok(())
    }

    async fn down_compilers_schemas(
        ctx: &ActorContext<Self>,
        schemas: &BTreeSet<SchemaType>,
        subject_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        else {
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let Some(contracts) = ctx
            .system()
            .get_helper::<Arc<RwLock<HashMap<String, Arc<Module>>>>>(
                "contracts",
            )
            .await
        else {
            return Err(ActorError::Helper {
                name: "contracts".to_string(),
                reason: "Not Found".to_string(),
            });
        };

        let contract_register = ctx
            .get_child::<ContractRegister>("contract_register")
            .await?;

        for schema_id in schemas.iter() {
            let actor = ctx
                .get_child::<ContractCompiler>(&format!(
                    "{}_contract_compiler",
                    schema_id
                ))
                .await?;

            actor.ask_stop().await?;

            let contract_name = format!("{}_{}", subject_id, schema_id);
            contract_register
                .tell(ContractRegisterMessage::DeleteMetadata {
                    contract_name: contract_name.clone(),
                })
                .await?;

            {
                let mut contracts = contracts.write().await;
                contracts.remove(&contract_name);
            }

            let contract_path =
                config.contracts_path.join("contracts").join(&contract_name);
            let _ = fs::remove_dir_all(contract_path).await;
        }

        Ok(())
    }

    async fn compile_schemas(
        ctx: &ActorContext<Self>,
        schemas: HashMap<SchemaType, Schema>,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let contracts_path = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.contracts_path
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        for (id, schema) in schemas {
            let actor = ctx
                .get_child::<ContractCompiler>(&format!(
                    "{}_contract_compiler",
                    id
                ))
                .await?;

            let response = actor
                .ask(ContractCompilerMessage::Compile {
                    contract_name: format!("{}_{}", subject_id, id),
                    contract: schema.contract.clone(),
                    initial_value: schema.initial_value.0.clone(),
                    contract_path: contracts_path
                        .join("contracts")
                        .join(format!("{}_{}", subject_id, id)),
                })
                .await?;

            if let CompilerResponse::Error(error) = response {
                return Err(ActorError::Functional {
                    description: format!(
                        "Can not refresh schema contract {}: {}",
                        id, error
                    ),
                });
            }
        }

        Ok(())
    }

    fn build_creators_register_fact(
        &self,
        new_creator: HashMap<
            (SchemaType, String, PublicKey),
            (CreatorQuantity, Vec<WitnessesType>),
        >,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        creator_update: CreatorRoleUpdate,
        new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    ) -> (SubjectRegisterMessage, WitnessesRegisterMessage) {
        let mut data: Vec<(PublicKey, SchemaType, String, CreatorQuantity)> =
            vec![];

        let mut new_creator_data: HashMap<
            (SchemaType, String, PublicKey),
            Vec<WitnessesType>,
        > = HashMap::new();

        let mut update_creator_witnesses_data: HashSet<(
            SchemaType,
            String,
            PublicKey,
            Vec<WitnessesType>,
        )> = HashSet::new();

        for ((schema_id, ns, creator), (quantity, witnesses)) in
            new_creator.iter()
        {
            data.push((
                creator.clone(),
                schema_id.clone(),
                ns.clone(),
                quantity.clone(),
            ));

            new_creator_data.insert(
                (schema_id.clone(), ns.clone(), creator.clone()),
                witnesses.clone(),
            );
        }

        for (schema_id, ns, creator) in remove_creator.iter() {
            data.push((
                creator.clone(),
                schema_id.clone(),
                ns.clone(),
                CreatorQuantity::Quantity(0),
            ));
        }

        for ((schema_id, ns, creator), (quantity, creator_witnesses)) in
            creator_update.new_creator.iter()
        {
            data.push((
                creator.clone(),
                schema_id.clone(),
                ns.clone(),
                quantity.clone(),
            ));

            let mut witnesses = vec![];
            for witness in creator_witnesses.iter() {
                if witness == &ReservedWords::Witnesses.to_string() {
                    witnesses.push(WitnessesType::Witnesses);
                } else if let Some(w) = self.properties.members.get(witness) {
                    witnesses.push(WitnessesType::User(w.clone()));
                }
            }

            new_creator_data.insert(
                (schema_id.clone(), ns.clone(), creator.clone()),
                witnesses,
            );
        }

        for (schema_id, ns, creator, quantity) in
            creator_update.update_creator_quantity.iter()
        {
            data.push((
                creator.clone(),
                schema_id.clone(),
                ns.clone(),
                quantity.clone(),
            ));
        }

        for (schema_id, ns, creator, creator_witnesses) in
            creator_update.update_creator_witnesses.iter()
        {
            let mut witnesses = vec![];
            for witness in creator_witnesses.iter() {
                if witness == &ReservedWords::Witnesses.to_string() {
                    witnesses.push(WitnessesType::Witnesses);
                } else if let Some(w) = self.properties.members.get(witness) {
                    witnesses.push(WitnessesType::User(w.clone()));
                }
            }

            update_creator_witnesses_data.insert((
                schema_id.clone(),
                ns.clone(),
                creator.clone(),
                witnesses,
            ));
        }

        for (schema_id, ns, creator) in creator_update.remove_creator.iter() {
            data.push((
                creator.clone(),
                schema_id.clone(),
                ns.clone(),
                CreatorQuantity::Quantity(0),
            ));
        }

        (
            SubjectRegisterMessage::RegisterData {
                gov_version: self.properties.version,
                data,
            },
            WitnessesRegisterMessage::UpdateCreatorsWitnessesFact {
                version: self.properties.version,
                new_creator: new_creator_data,
                remove_creator,
                update_creator_witnesses: update_creator_witnesses_data,
                new_witnesses,
                remove_witnesses,
            },
        )
    }

    fn build_creators_register_confirm(
        &self,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    ) -> (SubjectRegisterMessage, WitnessesRegisterMessage) {
        let data: Vec<(PublicKey, SchemaType, String, CreatorQuantity)> =
            remove_creator
                .iter()
                .map(|x| {
                    (
                        x.2.clone(),
                        x.0.clone(),
                        x.1.clone(),
                        CreatorQuantity::Quantity(0),
                    )
                })
                .collect();
        (
            SubjectRegisterMessage::RegisterData {
                gov_version: self.properties.version,
                data,
            },
            WitnessesRegisterMessage::UpdateCreatorsWitnessesConfirm {
                version: self.properties.version,
                remove_creator,
                remove_witnesses,
            },
        )
    }

    async fn first_role_register(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor = ctx.get_child::<RoleRegister>("role_register").await?;

        actor
            .tell(RoleRegisterMessage::UpdateFact {
                version: 0,
                appr_quorum: Some(Quorum::Majority),
                eval_quorum: HashMap::from([(
                    SchemaType::Governance,
                    Quorum::Majority,
                )]),
                new_approvers: vec![self.subject_metadata.owner.clone()],
                new_evaluators: HashMap::from([(
                    (
                        SchemaType::Governance,
                        self.subject_metadata.owner.clone(),
                    ),
                    vec![Namespace::new()],
                )]),
                new_validators: HashMap::from([(
                    (
                        SchemaType::Governance,
                        self.subject_metadata.owner.clone(),
                    ),
                    vec![Namespace::new()],
                )]),
                remove_approvers: vec![],
                remove_evaluators: HashMap::new(),
                remove_validators: HashMap::new(),
                vali_quorum: HashMap::from([(
                    SchemaType::Governance,
                    Quorum::Majority,
                )]),
            })
            .await
    }

    async fn update_gov_version(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor = ctx.get_child::<RoleRegister>("role_register").await?;

        actor
            .tell(RoleRegisterMessage::UpdateVersion {
                version: self.properties.version + 1,
            })
            .await
    }

    async fn update_registers_fact(
        &self,
        ctx: &ActorContext<Self>,
        update: RolesUpdate,
        creator_update: CreatorRoleUpdate,
    ) -> Result<(), ActorError> {
        let RolesUpdate {
            appr_quorum,
            new_approvers,
            remove_approvers,
            eval_quorum,
            new_evaluators,
            remove_evaluators,
            vali_quorum,
            new_validators,
            remove_validators,
            new_creator,
            remove_creator,
            new_witnesses,
            remove_witnesses,
        } = update;

        let actor = ctx.get_child::<RoleRegister>("role_register").await?;
        actor
            .tell(RoleRegisterMessage::UpdateFact {
                version: self.properties.version,
                appr_quorum,
                eval_quorum,
                new_approvers,
                new_evaluators,
                new_validators,
                remove_approvers,
                remove_evaluators,
                remove_validators,
                vali_quorum,
            })
            .await?;

        let (subj_msg, wit_msg) = self.build_creators_register_fact(
            new_creator,
            remove_creator,
            creator_update,
            new_witnesses,
            remove_witnesses,
        );

        let actor =
            ctx.get_child::<SubjectRegister>("subject_register").await?;

        actor.tell(subj_msg).await?;

        let actor = ctx
            .get_child::<WitnessesRegister>("witnesses_register")
            .await?;

        actor.tell(wit_msg).await
    }

    async fn update_registers_confirm(
        &self,
        ctx: &ActorContext<Self>,
        update: RolesUpdateConfirm,
    ) -> Result<(), ActorError> {
        let RolesUpdateConfirm {
            new_approver,
            remove_approver,
            new_evaluator,
            remove_evaluators,
            new_validator,
            remove_validators,
            remove_creator,
            remove_witnesses,
        } = update;

        let actor = ctx.get_child::<RoleRegister>("role_register").await?;
        actor
            .tell(RoleRegisterMessage::UpdateConfirm {
                version: self.properties.version,
                new_approver,
                remove_approver,
                new_evaluator,
                remove_evaluators,
                new_validator,
                remove_validators,
            })
            .await?;

        let (subj_msg, wit_msg) = self
            .build_creators_register_confirm(remove_creator, remove_witnesses);

        let actor =
            ctx.get_child::<SubjectRegister>("subject_register").await?;

        actor.tell(subj_msg).await?;

        let actor = ctx
            .get_child::<WitnessesRegister>("witnesses_register")
            .await?;

        actor.tell(wit_msg).await
    }

    async fn verify_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<Ledger>,
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
                return Err(ActorError::Functional {
                    description: e.to_string(),
                });
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

            self.first_role_register(ctx).await?;

            let (issuer, event_request_timestamp) =
                first.get_issuer_event_request_timestamp();
            let event_request = first.get_event_request();

            Self::event_to_sink(
                ctx,
                DataForSink {
                    gov_id: None,
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    sn: self.subject_metadata.sn,
                    owner: self.subject_metadata.owner.to_string(),
                    namespace: String::default(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    issuer,
                    event_ledger_timestamp: first
                        .ledger_seal_signature
                        .timestamp
                        .as_nanos(),
                    event_request_timestamp,
                    gov_version: first.gov_version,
                    event_data_ledger: EventLedgerDataForSink::build(
                        &first.protocols,
                        &self.properties.to_value_wrapper().0,
                    ),
                },
                event_request,
            )
            .await?;

            first
        };

        for event in iter {
            let actual_ledger_hash =
                last_ledger.ledger_hash(*hash).map_err(|e| {
                    ActorError::FunctionalCritical {
                        description: format!(
                            "Can not creacte actual ledger event hash: {}",
                            e
                        ),
                    }
                })?;

            let last_data = LastData {
                gov_version: last_ledger.gov_version,
                vali_data: last_ledger.protocols.get_validation_data(),
            };

            let last_event_is_ok = match Self::verify_new_ledger_event(
                ctx,
                &event,
                Metadata::from(self.clone()),
                actual_ledger_hash,
                last_data,
                hash,
                true,
                false
            )
            .await
            {
                Ok(last_event_is_ok) => last_event_is_ok,
                Err(e) => {
                    // Check if it's a sequence number error
                    if matches!(e, SubjectError::InvalidSequenceNumber { .. }) {
                        // El evento que estamos aplicando no es el siguiente.
                        continue;
                    } else {
                        return Err(ActorError::Functional {
                            description: e.to_string(),
                        });
                    }
                }
            };

            let event_request = event.get_event_request().expect("It has been previously verified that all events have the event_request set to clear.");

            let (update_fact, update_confirm) = if last_event_is_ok {
                match &event_request {
                    EventRequest::Transfer(transfer_request) => {
                        self.transfer(
                            ctx,
                            transfer_request.new_owner.clone(),
                            0,
                        )
                        .await?;

                        self.update_gov_version(ctx).await?;
                    }
                    EventRequest::Reject(..) => {
                        self.reject(ctx, 0).await?;

                        self.update_gov_version(ctx).await?;
                    }
                    EventRequest::EOL(..) => {
                        self.eol(ctx).await?;

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

                        self.update_gov_version(ctx).await?;
                    }
                    _ => {}
                };

                let update_confirm =
                    if let EventRequest::Confirm(..) = &event_request {
                        self.confirm(
                            ctx,
                            event.ledger_seal_signature.signer.clone(),
                            0,
                        )
                        .await?;

                        if let Some(new_owner_key) =
                            &self.subject_metadata.new_owner
                        {
                            Some(self.properties.roles_update_remove_confirm(
                                &self.subject_metadata.owner,
                                new_owner_key,
                            ))
                        } else {
                            None
                        }
                    } else {
                        None
                    };

                let update_fact = if let EventRequest::Fact(fact_request) =
                    &event_request
                {
                    let governance_event = serde_json::from_value::<GovernanceEvent>(fact_request.payload.0.clone()).map_err(|e| {
                            ActorError::FunctionalCritical{description: format!("Can not convert payload into governance event in governance fact event: {}", e)}
                        })?;

                    let rm_members = governance_event
                        .members
                        .as_ref()
                        .map_or_else(|| None, |members| members.remove.clone());

                    let rm_schemas = governance_event
                        .schemas
                        .as_ref()
                        .map_or_else(|| None, |schemas| schemas.remove.clone());

                    let rm_roles =
                        if rm_members.is_some() || rm_schemas.is_some() {
                            Some(self.properties.roles_update_remove_fact(
                                rm_members, rm_schemas,
                            ))
                        } else {
                            None
                        };

                    let creator_update = governance_event_update_creator_change(
                        &governance_event,
                        &self.properties.members,
                        &self.properties.roles_schema,
                    );

                    Some((governance_event, creator_update, rm_roles))
                } else {
                    None
                };
                (update_fact, update_confirm)
            } else {
                (None, None)
            };

            // Aplicar evento.
            self.on_event(event.clone(), ctx).await;

            let (issuer, event_request_timestamp) =
                event.get_issuer_event_request_timestamp();
            Self::event_to_sink(
                ctx,
                DataForSink {
                    gov_id: None,
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    sn: self.subject_metadata.sn,
                    owner: self.subject_metadata.owner.to_string(),
                    namespace: String::default(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    issuer,
                    event_ledger_timestamp: event
                        .ledger_seal_signature
                        .timestamp
                        .as_nanos(),
                    event_request_timestamp,
                    gov_version: event.gov_version,
                    event_data_ledger: EventLedgerDataForSink::build(
                        &event.protocols,
                        &self.properties.to_value_wrapper().0,
                    ),
                },
                Some(event_request.clone()),
            )
            .await?;

            if let Some((event, creator_update, rm_roles)) = update_fact {
                let update = governance_event_roles_update_fact(
                    &event,
                    &self.properties.members,
                    rm_roles,
                );

                self.update_registers_fact(ctx, update, creator_update)
                    .await?;
            }

            if let Some(update_confirm) = update_confirm {
                self.update_registers_confirm(ctx, update_confirm).await?;
            }

            // Acutalizar último evento.
            last_ledger = event.clone();
        }

        Ok(())
    }

    async fn delete_tracker_references(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let mut cleanup_errors = Vec::new();

        let subject_register = match ctx
            .create_child("subject_register", SubjectRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<SubjectRegister>("subject_register").await
                {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("subject_register lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("subject_register: {error}"));
                None
            }
        };

        if let Some(subject_register) = subject_register {
            match subject_register
                .ask(SubjectRegisterMessage::DeleteSubject {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(SubjectRegisterResponse::Ok) => {}
                Ok(other) => cleanup_errors.push(format!(
                    "subject_register: unexpected response {other:?}"
                )),
                Err(error) => {
                    cleanup_errors.push(format!("subject_register: {error}"))
                }
            }

            if let Err(error) = subject_register.ask_stop().await {
                cleanup_errors.push(format!("subject_register stop: {error}"));
            }
        }

        let sn_register = match ctx
            .create_child("sn_register", SnRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<SnRegister>("sn_register").await {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("sn_register lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("sn_register: {error}"));
                None
            }
        };

        if let Some(sn_register) = sn_register {
            match sn_register
                .ask(SnRegisterMessage::DeleteSubject {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(SnRegisterResponse::Ok) => {}
                Ok(other) => cleanup_errors.push(format!(
                    "sn_register: unexpected response {other:?}"
                )),
                Err(error) => {
                    cleanup_errors.push(format!("sn_register: {error}"))
                }
            }

            if let Err(error) = sn_register.ask_stop().await {
                cleanup_errors.push(format!("sn_register stop: {error}"));
            }
        }

        let witnesses_register = match ctx
            .create_child("witnesses_register", WitnessesRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx
                    .get_child::<WitnessesRegister>("witnesses_register")
                    .await
                {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors.push(format!(
                            "witnesses_register lookup: {error}"
                        ));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("witnesses_register: {error}"));
                None
            }
        };

        if let Some(witnesses_register) = witnesses_register {
            match witnesses_register
                .ask(WitnessesRegisterMessage::DeleteSubject {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(WitnessesRegisterResponse::Ok) => {}
                Ok(_) => cleanup_errors
                    .push("witnesses_register: unexpected response".to_owned()),
                Err(error) => {
                    cleanup_errors.push(format!("witnesses_register: {error}"))
                }
            }

            if let Err(error) = witnesses_register.ask_stop().await {
                cleanup_errors
                    .push(format!("witnesses_register stop: {error}"));
            }
        }

        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(ActorError::Functional {
                description: cleanup_errors.join("; "),
            })
        }
    }

    async fn delete_governance_storage(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let mut cleanup_errors = Vec::new();

        if self.properties.has_this_role(HashThisRole::Gov {
            who: (*self.our_key).clone(),
            role: RoleTypes::Approver,
        }) {
            let hash = self.hash.map_or_else(
                || {
                    cleanup_errors
                        .push("approver init: missing hash".to_owned());
                    None
                },
                Some,
            );

            let network = ctx
                .system()
                .get_helper::<Arc<NetworkSender>>("network")
                .await
                .map_or_else(
                    || {
                        cleanup_errors.push(
                            "approver init: missing network helper".to_owned(),
                        );
                        None
                    },
                    Some,
                );

            if let (Some(hash), Some(network)) = (hash, network) {
                let approver = match ctx
                    .get_child::<ApprPersist>("approver")
                    .await
                {
                    Ok(actor) => Some(actor),
                    Err(_) => match self
                        .up_approver_only(ctx, &hash, &network)
                        .await
                    {
                        Ok(()) => match ctx
                            .get_child::<ApprPersist>("approver")
                            .await
                        {
                            Ok(actor) => Some(actor),
                            Err(error) => {
                                cleanup_errors
                                    .push(format!("approver lookup: {error}"));
                                None
                            }
                        },
                        Err(error) => {
                            cleanup_errors.push(format!("approver: {error}"));
                            None
                        }
                    },
                };

                if let Some(approver) = approver {
                    match approver
                        .ask(crate::approval::persist::ApprPersistMessage::PurgeStorage)
                        .await
                    {
                        Ok(crate::approval::persist::ApprPersistResponse::Ok) => {}
                        Ok(_) => cleanup_errors
                            .push("approver: unexpected response".to_owned()),
                        Err(error) => {
                            cleanup_errors.push(format!("approver: {error}"))
                        }
                    }

                    if let Err(error) = approver.ask_stop().await {
                        cleanup_errors.push(format!("approver stop: {error}"));
                    }
                }
            }
        }

        let contract_register = match ctx
            .create_child("contract_register", ContractRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx
                    .get_child::<ContractRegister>("contract_register")
                    .await
                {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("contract_register lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("contract_register: {error}"));
                None
            }
        };

        if let Some(contract_register) = contract_register {
            if let Err(error) = self
                .delete_all_contract_artifacts(ctx, &contract_register)
                .await
            {
                cleanup_errors.push(format!("contract_artifacts: {error}"));
            }

            match contract_register
                .ask(ContractRegisterMessage::PurgeStorage)
                .await
            {
                Ok(ContractRegisterResponse::Ok) => {}
                Ok(other) => cleanup_errors.push(format!(
                    "contract_register: unexpected response {other:?}"
                )),
                Err(error) => {
                    cleanup_errors.push(format!("contract_register: {error}"))
                }
            }

            if let Err(error) = contract_register.ask_stop().await {
                cleanup_errors.push(format!("contract_register stop: {error}"));
            }
        }

        let role_register = match ctx
            .create_child("role_register", RoleRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<RoleRegister>("role_register").await {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("role_register lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("role_register: {error}"));
                None
            }
        };

        if let Some(role_register) = role_register {
            match role_register.ask(RoleRegisterMessage::PurgeStorage).await {
                Ok(RoleRegisterResponse::Ok) => {}
                Ok(other) => cleanup_errors.push(format!(
                    "role_register: unexpected response {other:?}"
                )),
                Err(error) => {
                    cleanup_errors.push(format!("role_register: {error}"))
                }
            }

            if let Err(error) = role_register.ask_stop().await {
                cleanup_errors.push(format!("role_register stop: {error}"));
            }
        }

        let subject_register = match ctx
            .create_child("subject_register", SubjectRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<SubjectRegister>("subject_register").await
                {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("subject_register lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("subject_register: {error}"));
                None
            }
        };

        if let Some(subject_register) = subject_register {
            match subject_register
                .ask(SubjectRegisterMessage::PurgeStorage)
                .await
            {
                Ok(SubjectRegisterResponse::Ok) => {}
                Ok(other) => cleanup_errors.push(format!(
                    "subject_register: unexpected response {other:?}"
                )),
                Err(error) => {
                    cleanup_errors.push(format!("subject_register: {error}"))
                }
            }

            if let Err(error) = subject_register.ask_stop().await {
                cleanup_errors.push(format!("subject_register stop: {error}"));
            }
        }

        let sn_register = match ctx
            .create_child("sn_register", SnRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<SnRegister>("sn_register").await {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("sn_register lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("sn_register: {error}"));
                None
            }
        };

        if let Some(sn_register) = sn_register {
            match sn_register.ask(SnRegisterMessage::PurgeStorage).await {
                Ok(SnRegisterResponse::Ok) => {}
                Ok(other) => cleanup_errors.push(format!(
                    "sn_register: unexpected response {other:?}"
                )),
                Err(error) => {
                    cleanup_errors.push(format!("sn_register: {error}"))
                }
            }

            if let Err(error) = sn_register.ask_stop().await {
                cleanup_errors.push(format!("sn_register stop: {error}"));
            }
        }

        let witnesses_register = match ctx
            .create_child("witnesses_register", WitnessesRegister::initial(()))
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx
                    .get_child::<WitnessesRegister>("witnesses_register")
                    .await
                {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors.push(format!(
                            "witnesses_register lookup: {error}"
                        ));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("witnesses_register: {error}"));
                None
            }
        };

        if let Some(witnesses_register) = witnesses_register {
            match witnesses_register
                .ask(WitnessesRegisterMessage::PurgeStorage)
                .await
            {
                Ok(WitnessesRegisterResponse::Ok) => {}
                Ok(_) => cleanup_errors
                    .push("witnesses_register: unexpected response".to_owned()),
                Err(error) => {
                    cleanup_errors.push(format!("witnesses_register: {error}"))
                }
            }

            if let Err(error) = witnesses_register.ask_stop().await {
                cleanup_errors
                    .push(format!("witnesses_register stop: {error}"));
            }
        }

        if let Err(error) = purge_storage(ctx).await {
            cleanup_errors.push(format!("governance: {error}"));
        }

        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(ActorError::Functional {
                description: cleanup_errors.join("; "),
            })
        }
    }
}

/// Governance command.
#[derive(Debug, Clone)]
pub enum GovernanceMessage {
    GetMetadata,
    GetLedger { lo_sn: Option<u64>, hi_sn: u64 },
    GetLastLedger,
    DeleteTrackerReferences { subject_id: DigestIdentifier },
    DeleteGovernanceStorage,
    UpdateLedger { events: Vec<Ledger> },
    GetGovernance,
    GetVersion,
}

impl Message for GovernanceMessage {}

#[derive(Debug, Clone)]
pub enum GovernanceResponse {
    /// The subject metadata.
    Metadata(Box<Metadata>),
    UpdateResult(u64, PublicKey, Option<PublicKey>),
    Ledger {
        ledger: Vec<Ledger>,
        is_all: bool,
    },
    LastLedger {
        ledger_event: Box<Option<Ledger>>,
    },
    Governance(Box<GovernanceData>),
    NewCompilers(Vec<SchemaType>),
    Sn(u64),
    Version(u64),
    Ok,
}
impl Response for GovernanceResponse {}

#[async_trait]
impl Actor for Governance {
    type Event = Ledger;
    type Message = GovernanceMessage;
    type Response = GovernanceResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Governance", id),
            |parent_span| info_span!(parent: parent_span, "Governance", id),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.init_store("governance", None, true, ctx).await {
            error!(
                error = %e,
                "Failed to initialize governance store"
            );
            return Err(e);
        }

        let safe_mode = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if safe_mode {
            let Some(hash) = self.hash else {
                error!("Hash algorithm not found");
                return Err(ActorError::FunctionalCritical {
                    description: "Hash algorithm is None".to_string(),
                });
            };

            let Some(network) = ctx
                .system()
                .get_helper::<Arc<NetworkSender>>("network")
                .await
            else {
                error!("Network helper not found");
                return Err(ActorError::Helper {
                    name: "network".to_owned(),
                    reason: "Not found".to_owned(),
                });
            };

            self.up_approver_only(ctx, &hash, &network).await?;
            return Ok(());
        }

        let Some(hash) = self.hash else {
            error!("Hash algorithm not found");
            return Err(ActorError::FunctionalCritical {
                description: "Hash algorithm is None".to_string(),
            });
        };

        let Some(ext_db): Option<Arc<ExternalDB>> =
            ctx.system().get_helper("ext_db").await
        else {
            error!("External database helper not found");
            return Err(ActorError::Helper {
                name: "ext_db".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let Some(ave_sink): Option<AveSink> =
            ctx.system().get_helper("sink").await
        else {
            error!("Sink helper not found");
            return Err(ActorError::Helper {
                name: "sink".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let Some(network) = ctx
            .system()
            .get_helper::<Arc<NetworkSender>>("network")
            .await
        else {
            error!("Network helper not found");
            return Err(ActorError::Helper {
                name: "network".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if let Err(e) = ctx
            .create_child("role_register", RoleRegister::initial(()))
            .await
        {
            error!(
                error = %e,
                "Failed to create role_register child"
            );
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child("subject_register", SubjectRegister::initial(()))
            .await
        {
            error!(
                error = %e,
                "Failed to create subject_register child"
            );
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child("sn_register", SnRegister::initial(()))
            .await
        {
            error!(
                error = %e,
                "Failed to create sn_register child"
            );
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child("witnesses_register", WitnessesRegister::initial(()))
            .await
        {
            error!(
                error = %e,
                "Failed to create witnesses_register child"
            );
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child("contract_register", ContractRegister::initial(()))
            .await
        {
            error!(
                error = %e,
                "Failed to create contract_register child"
            );
            return Err(e);
        }

        if self.subject_metadata.active {
            if let Err(e) = self.build_childs(ctx, &hash, &network).await {
                error!(
                    error = %e,
                    "Failed to build governance child actors"
                );
                return Err(e);
            }

            let sink_actor = match ctx
                .create_child(
                    "sink_data",
                    SinkData {
                        public_key: self.our_key.to_string(),
                    },
                )
                .await
            {
                Ok(actor) => actor,
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to create sink_data child"
                    );
                    return Err(e);
                }
            };
            let sink =
                Sink::new(sink_actor.subscribe(), ext_db.get_sink_data());
            ctx.system().run_sink(sink).await;

            let sink = Sink::new(sink_actor.subscribe(), ave_sink.clone());
            ctx.system().run_sink(sink).await;
        }

        if self.service {
            let Some(config): Option<ConfigHelper> =
                ctx.system().get_helper("config").await
            else {
                error!("Config helper not found");
                return Err(ActorError::Helper {
                    name: "config".to_owned(),
                    reason: "Not found".to_owned(),
                });
            };

            let version_sync_tick_interval = Duration::from_secs(
                config.sync_governance.interval_secs.max(1),
            );
            let version_sync_response_timeout = Duration::from_secs(
                config.sync_governance.response_timeout_secs.max(1),
            );
            let tracker_sync_tick_interval =
                Duration::from_secs(config.sync_tracker.interval_secs.max(1));
            let tracker_sync_response_timeout = Duration::from_secs(
                config.sync_tracker.response_timeout_secs.max(1),
            );
            let tracker_sync_update_timeout = Duration::from_secs(
                config.sync_tracker.update_timeout_secs.max(1),
            );

            if let Err(e) = ctx
                .create_child(
                    "tracker_sync",
                    TrackerSync::new(
                        self.subject_metadata.subject_id.clone(),
                        self.our_key.clone(),
                        network.clone(),
                        TrackerSyncConfig {
                            service: self.service,
                            tick_interval: tracker_sync_tick_interval,
                            response_timeout: tracker_sync_response_timeout,
                            page_size: config.sync_tracker.page_size,
                            update_batch_size: config
                                .sync_tracker
                                .update_batch_size,
                            update_timeout: tracker_sync_update_timeout,
                        },
                    ),
                )
                .await
            {
                error!(
                    error = %e,
                    subject_id = %self.subject_metadata.subject_id,
                    "Failed to create tracker_sync child"
                );
                return Err(e);
            }

            let version_sync = ctx
                .create_child(
                    "version_sync",
                    GovernanceVersionSync::new(
                        self.subject_metadata.subject_id.clone(),
                        self.our_key.clone(),
                        network.clone(),
                        self.properties.version,
                        config.sync_governance.sample_size,
                        version_sync_tick_interval,
                        version_sync_response_timeout,
                    ),
                )
                .await?;

            let governance_peers = self
                .properties
                .get_witnesses(WitnessesData::Gov)
                .map_err(|e| ActorError::Functional {
                    description: e.to_string(),
                })?;

            let _ = version_sync
                .ask(GovernanceVersionSyncMessage::RefreshGovernance {
                    version: self.properties.version,
                    governance_peers,
                })
                .await?;
        }

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for Governance {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: GovernanceMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<GovernanceResponse, ActorError> {
        match msg {
            GovernanceMessage::GetVersion => {
                Ok(GovernanceResponse::Version(self.properties.version))
            }
            GovernanceMessage::GetLedger { lo_sn, hi_sn } => {
                let (ledger, is_all) =
                    self.get_ledger(ctx, lo_sn, hi_sn).await?;
                Ok(GovernanceResponse::Ledger { ledger, is_all })
            }
            GovernanceMessage::GetLastLedger => {
                let ledger_event = self.get_last_ledger(ctx).await?;
                Ok(GovernanceResponse::LastLedger {
                    ledger_event: Box::new(ledger_event),
                })
            }
            GovernanceMessage::GetMetadata => Ok(GovernanceResponse::Metadata(
                Box::new(Metadata::from(self.clone())),
            )),
            GovernanceMessage::DeleteTrackerReferences { subject_id } => {
                self.delete_tracker_references(ctx, subject_id.clone())
                    .await?;

                debug!(
                    msg_type = "DeleteTrackerReferences",
                    subject_id = %subject_id,
                    governance_id = %self.subject_metadata.subject_id,
                    "Tracker references deleted from governance"
                );

                Ok(GovernanceResponse::Ok)
            }
            GovernanceMessage::DeleteGovernanceStorage => {
                self.delete_governance_storage(ctx).await?;

                debug!(
                    msg_type = "DeleteGovernanceStorage",
                    governance_id = %self.subject_metadata.subject_id,
                    "Governance storage deleted"
                );

                Ok(GovernanceResponse::Ok)
            }
            GovernanceMessage::UpdateLedger { events } => {
                let events_count = events.len();
                if let Err(e) =
                    self.manager_new_ledger_events(ctx, events).await
                {
                    warn!(
                        msg_type = "UpdateLedger",
                        error = %e,
                        subject_id = %self.subject_metadata.subject_id,
                        events_count = events_count,
                        "Failed to verify new ledger events"
                    );
                    return Err(e);
                };

                debug!(
                    msg_type = "UpdateLedger",
                    subject_id = %self.subject_metadata.subject_id,
                    sn = self.subject_metadata.sn,
                    events_count = events_count,
                    "Ledger updated successfully"
                );

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

    async fn on_event(&mut self, event: Ledger, ctx: &mut ActorContext<Self>) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                error = %e,
                subject_id = %self.subject_metadata.subject_id,
                sn = self.subject_metadata.sn,
                "Failed to persist event"
            );
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event).await {
            error!(
                error = %e,
                subject_id = %self.subject_metadata.subject_id,
                sn = self.subject_metadata.sn,
                "Failed to publish event"
            );
            emit_fail(ctx, e).await;
        } else {
            debug!(
                subject_id = %self.subject_metadata.subject_id,
                sn = self.subject_metadata.sn,
                "Event persisted and published successfully"
            );
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            error = %error,
            subject_id = %self.subject_metadata.subject_id,
            "Child fault occurred"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for Governance {
    type Persistence = FullPersistence;
    type InitParams = (
        Option<(SubjectMetadata, GovernanceData)>,
        Arc<PublicKey>,
        HashAlgorithm,
        bool,
    );

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
            hash: Some(params.2),
            our_key: params.1,
            service: params.3,
            subject_metadata,
            properties,
        }
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match &event.protocols {
            Protocols::Create { validation, event_request } => {
                if let EventRequest::Create(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Create",
                        subject_id = %self.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for governance create apply"
                    );
                    return Err(ActorError::Functional {
                        description: "In create event, event request must be Create"
                            .to_owned(),
                    });
                };

                if let ValidationMetadata::Metadata(metadata) =
                    &validation.validation_metadata
                {
                    self.subject_metadata = SubjectMetadata::new(metadata);
                    self.properties = serde_json::from_value::<GovernanceData>(
                        metadata.properties.0.clone(),
                    )
                    .map_err(|e| {
                        error!(
                            event_type = "Create",
                            subject_id = %self.subject_metadata.subject_id,
                            error = %e,
                            "Failed to convert properties into GovernanceData"
                        );
                        ActorError::Functional { description: format!("In create event, can not convert properties into GovernanceData: {e}")}
                    })?;

                    debug!(
                        event_type = "Create",
                        subject_id = %self.subject_metadata.subject_id,
                        sn = self.subject_metadata.sn,
                        "Applied create event"
                    );
                } else {
                    error!(
                        event_type = "Create",
                        "Validation metadata must be Metadata type"
                    );
                    return Err(ActorError::Functional { description: "In create event, validation metadata must be a Metadata".to_owned() });
                }

                return Ok(());
            }
                Protocols::GovFact {
                    evaluation,
                    approval,
                    event_request,
                    ..
                }
             => {
                if let EventRequest::Fact(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Fact",
                        subject_id = %self.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for governance fact apply"
                    );
                    return Err(ActorError::Functional {
                        description: "In fact event, event request must be Fact"
                            .to_owned(),
                    });
                };

                if let Some(eval_res) = evaluation.evaluator_response_ok() {
                    if let Some(appr_res) = approval {
                        if appr_res.approved {
                            self.apply_patch(eval_res.patch)?;
                            debug!(
                                event_type = "Fact",
                                subject_id = %self.subject_metadata.subject_id,
                                approved = true,
                                "Applied fact event with patch"
                            );
                        } else {
                            debug!(
                                event_type = "Fact",
                                subject_id = %self.subject_metadata.subject_id,
                                approved = false,
                                "Fact event not approved, patch not applied"
                            );
                        }
                    } else {
                        error!(
                            event_type = "Fact",
                            subject_id = %self.subject_metadata.subject_id,
                            "Evaluation successful but no approval present"
                        );
                        return Err(ActorError::Functional { description: "The evaluation event was successful, but there is no approval".to_owned() });
                    }
                }
            }
            
                Protocols::Transfer { evaluation, event_request, .. }
             => {
                let EventRequest::Transfer(transfer_request) = event_request.content() else {
                    error!(
                        event_type = "Transfer",
                        subject_id = %self.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for governance transfer apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In transfer event, event request must be Transfer"
                                .to_owned(),
                    });
                };

                if evaluation.evaluator_response_ok().is_some() {
                    self.subject_metadata.new_owner =
                        Some(transfer_request.new_owner.clone());
                    debug!(
                        event_type = "Transfer",
                        subject_id = %self.subject_metadata.subject_id,
                        new_owner = %transfer_request.new_owner,
                        "Applied transfer event"
                    );
                }
            }
            
                Protocols::GovConfirm { evaluation, event_request, .. }
             => {
                if let EventRequest::Confirm(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Confirm",
                        subject_id = %self.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for governance confirm apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In confirm event, event request must be Confirm"
                                .to_owned(),
                    });
                };

                if let Some(eval_res) = evaluation.evaluator_response_ok() {
                    if let Some(new_owner) =
                        self.subject_metadata.new_owner.take()
                    {
                        self.subject_metadata.owner = new_owner.clone();
                        self.apply_patch(eval_res.patch)?;
                        debug!(
                            event_type = "Confirm",
                            subject_id = %self.subject_metadata.subject_id,
                            new_owner = %new_owner,
                            "Applied confirm event with patch"
                        );
                    } else {
                        error!(
                            event_type = "Confirm",
                            subject_id = %self.subject_metadata.subject_id,
                            "New owner is None in confirm event"
                        );
                        return Err(ActorError::Functional {
                            description: "In confirm event, new owner is None"
                                .to_owned(),
                        });
                    }
                }
            }
            Protocols::Reject { event_request, .. } => {
                if let EventRequest::Reject(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Reject",
                        subject_id = %self.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for governance reject apply"
                    );
                    return Err(ActorError::Functional {
                        description: "In reject event, event request must be Reject"
                            .to_owned(),
                    });
                };

                self.subject_metadata.new_owner = None;
                debug!(
                    event_type = "Reject",
                    subject_id = %self.subject_metadata.subject_id,
                    "Applied reject event"
                );
            }
            Protocols::EOL { event_request, .. } => {
                if let EventRequest::EOL(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "EOL",
                        subject_id = %self.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for governance eol apply"
                    );
                    return Err(ActorError::Functional {
                        description: "In EOL event, event request must be EOL"
                            .to_owned(),
                    });
                };

                self.subject_metadata.active = false;
                debug!(
                    event_type = "EOL",
                    subject_id = %self.subject_metadata.subject_id,
                    "Applied EOL event"
                );
            }
            _ => {
                error!(
                    subject_id = %self.subject_metadata.subject_id,
                    "Invalid protocol data for Governance"
                );
                return Err(ActorError::Functional {
                    description: "Invalid protocol data for Governance"
                        .to_owned(),
                });
            }
        }

        if event.protocols.is_success() {
            self.properties.version += 1;
        }

        self.subject_metadata.sn += 1;
        self.subject_metadata.prev_ledger_event_hash =
            event.prev_ledger_event_hash.clone();

        Ok(())
    }
}

impl Storable for Governance {}
