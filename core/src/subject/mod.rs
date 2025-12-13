//! # Subject module.
//!

use crate::{
    CreateRequest, Error, EventRequestType, Governance, Node,
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
        Schema,
        model::{CreatorQuantity, HashThisRole, ProtocolTypes, RoleTypes},
    },
    helpers::{db::ExternalDB, sink::AveSink},
    model::{
        Namespace,
        common::{
            delete_relation, emit_fail, get_gov, get_last_event, get_vali_data,
            register_relation, try_to_update, verify_protocols_state,
        },
        event::{Event as AveEvent, Ledger, LedgerValue, ProtocolsSignatures},
        request::EventRequest,
    },
    node::{
        NodeMessage, TransferSubject,
        nodekey::{NodeKey, NodeKeyMessage, NodeKeyResponse},
        register::{
            Register, RegisterDataGov, RegisterDataSubj, RegisterMessage,
        },
        transfer,
    },
    system::ConfigHelper,
    update::TransferResponse,
    validation::{
        Validation,
        proof::ValidationProof,
        schema::{ValidationSchema, ValidationSchemaMessage},
        validator::Validator,
    },
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Event,
    Handler, Message, Response, Sink,
};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed, hash_borsh},
};
use event::LedgerEvent;

use std::ops::Deref;

use async_trait::async_trait;
use ave_actors::{
    FullPersistence, PersistentActor, Store, StoreCommand, StoreResponse,
};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use serde_json::to_value;
use sinkdata::{SinkData, SinkDataMessage};
use tracing::{error, warn};
use transfer::{TransferRegister, TransferRegisterMessage};
use validata::ValiData;

use std::collections::{BTreeMap, HashMap};

pub mod event;
pub mod sinkdata;
pub mod validata;

const TARGET_SUBJECT: &str = "Ave-Subject";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateSubjectData {
    pub create_req: CreateRequest,
    pub subject_id: DigestIdentifier,
    pub creator: PublicKey,
    pub genesis_gov_version: u64,
    pub value: ValueWrapper,
}

impl From<CreateSubjectData> for Subject {
    fn from(value: CreateSubjectData) -> Self {
        Subject {
            name: value.create_req.name,
            description: value.create_req.description,
            subject_id: value.subject_id,
            governance_id: value.create_req.governance_id,
            genesis_gov_version: value.genesis_gov_version,
            namespace: value.create_req.namespace,
            schema_id: value.create_req.schema_id,
            owner: value.creator.clone(),
            new_owner: None,
            creator: value.creator,
            last_event_hash: DigestIdentifier::default(),
            active: true,
            sn: 0,
            properties: value.value,
        }
    }
}

/// Subject metadata.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Metadata {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The identifier of the subject of the event.
    pub subject_id: DigestIdentifier,
    /// The identifier of the governance contract.
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub last_event_hash: DigestIdentifier,
    /// The identifier of the schema_id used to validate the event.
    pub schema_id: String,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The current sequence number of the subject.
    pub sn: u64,
    /// The identifier of the public key of the creator owner.
    pub creator: PublicKey,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

/// Suject header
#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Clone,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Subject {
    /// The name of the subject.
    pub name: Option<String>,
    /// The description of the subject.
    pub description: Option<String>,
    /// The identifier of the subject.
    pub subject_id: DigestIdentifier,
    /// The identifier of the governance that drives this subject.
    pub governance_id: DigestIdentifier,
    /// The version of the governance contract that created the subject.
    pub genesis_gov_version: u64,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The identifier of the schema_id used to validate the subject.
    pub schema_id: String,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    /// The identifier of the public key of the new subject owner.
    pub new_owner: Option<PublicKey>,

    pub last_event_hash: DigestIdentifier,
    /// The identifier of the public key of the subject creator.
    pub creator: PublicKey,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current sequence number of the subject.
    pub sn: u64,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

impl Subject {
    /// Creates a new `Subject` from an create event.
    ///
    /// # Arguments
    ///
    /// * `event` - The event.
    /// * `derivator` - The key derivator.
    ///
    /// # Returns
    ///
    /// A `Result` containing the `Subject` or an `Error`.
    ///
    /// # Errors
    ///
    /// An error is returned if the event is invalid.
    ///
    pub fn from_event(
        ledger: &Signed<Ledger>,
        properties: ValueWrapper,
    ) -> Result<Self, Error> {
        if let EventRequest::Create(request) =
            &ledger.content.event_request.content
        {
            let subject = Subject {
                name: request.name.clone(),
                description: request.description.clone(),
                subject_id: ledger.content.subject_id.clone(),
                governance_id: request.governance_id.clone(),
                genesis_gov_version: ledger.content.gov_version,
                namespace: request.namespace.clone(),
                schema_id: request.schema_id.clone(),
                last_event_hash: DigestIdentifier::default(),
                owner: ledger.content.event_request.signature.signer.clone(),
                new_owner: None,
                creator: ledger.content.event_request.signature.signer.clone(),
                active: true,
                sn: 0,
                properties,
            };
            Ok(subject)
        } else {
            Err(Error::Subject("Invalid create event request".to_string()))
        }
    }
    async fn get_node_key(
        &self,
        ctx: &mut ActorContext<Subject>,
    ) -> Result<PublicKey, ActorError> {
        // Node path.
        let node_key_path = ActorPath::from("/user/node/key");
        // Node actor.
        let node_key_actor: Option<ActorRef<NodeKey>> =
            ctx.system().get_actor(&node_key_path).await;

        // We obtain the actor node
        let response = if let Some(node_key_actor) = node_key_actor {
            node_key_actor.ask(NodeKeyMessage::GetPublicKey).await?
        } else {
            return Err(ActorError::NotFound(node_key_path));
        };

        // We handle the possible responses of node
        match response {
            NodeKeyResponse::PublicKey(key) => Ok(key),
        }
    }

    /// Returns subject metadata.
    ///
    /// # Returns
    ///
    /// The subject metadata.
    ///
    fn get_metadata(&self) -> Metadata {
        Metadata {
            description: self.description.clone(),
            name: self.name.clone(),
            creator: self.creator.clone(),
            genesis_gov_version: self.genesis_gov_version,
            last_event_hash: self.last_event_hash.clone(),
            subject_id: self.subject_id.clone(),
            governance_id: self.governance_id.clone(),
            schema_id: self.schema_id.clone(),
            namespace: self.namespace.clone(),
            properties: self.properties.clone(),
            owner: self.owner.clone(),
            new_owner: self.new_owner.clone(),
            active: self.active,
            sn: self.sn,
        }
    }

    async fn build_childs_all_schemas(
        &self,
        ctx: &mut ActorContext<Subject>,
        our_key: PublicKey,
    ) -> Result<(), ActorError> {
        let owner = our_key == self.owner;
        let new_owner = self.new_owner.is_some();
        let i_new_owner = self.new_owner == Some(our_key.clone());

        if new_owner {
            if i_new_owner {
                Self::up_owner_not_gov(ctx, &our_key).await?;
            }
        } else if owner {
            Self::up_owner_not_gov(ctx, &our_key).await?;
        }

        Ok(())
    }

    async fn up_owner_not_gov(
        ctx: &mut ActorContext<Subject>,
        our_key: &PublicKey,
    ) -> Result<(), ActorError> {
        let validation = Validation::new(our_key.clone());
        ctx.create_child("validation", validation).await?;

        let evaluation = Evaluation::new(our_key.clone());
        ctx.create_child("evaluation", evaluation).await?;

        let distribution =
            Distribution::new(our_key.clone(), DistributionType::Subject);
        ctx.create_child("distribution", distribution).await?;

        Ok(())
    }

    async fn down_owner_not_gov(
        ctx: &mut ActorContext<Subject>,
    ) -> Result<(), ActorError> {
        let actor: Option<ActorRef<Validation>> =
            ctx.get_child("validation").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            return Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/validation",
                ctx.path()
            ))));
        }

        let actor: Option<ActorRef<Evaluation>> =
            ctx.get_child("evaluation").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            return Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/evaluation",
                ctx.path()
            ))));
        }

        let actor: Option<ActorRef<Distribution>> =
            ctx.get_child("distribution").await;
        if let Some(actor) = actor {
            actor.ask_stop().await?;
        } else {
            return Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/distribution",
                ctx.path()
            ))));
        }

        Ok(())
    }

    async fn build_childs_governance(
        &self,
        ctx: &mut ActorContext<Subject>,
        our_key: PublicKey,
        ext_db: ExternalDB,
    ) -> Result<(), ActorError> {
        // If subject is a governance
        let gov = Governance::try_from(self.properties.clone())
            .map_err(|e| ActorError::FunctionalFail(e.to_string()))?;

        let owner = our_key == self.owner;
        let new_owner = self.new_owner.is_some();
        let i_new_owner = self.new_owner == Some(our_key.clone());

        if new_owner {
            if i_new_owner {
                Self::up_owner(
                    ctx,
                    our_key.clone(),
                    self.subject_id.clone(),
                    ext_db,
                )
                .await?;
            } else {
                Self::up_not_owner(
                    ctx,
                    gov.clone(),
                    our_key.clone(),
                    ext_db,
                    self.subject_id.clone(),
                )
                .await?;
            }
        } else if owner {
            Self::up_owner(
                ctx,
                our_key.clone(),
                self.subject_id.clone(),
                ext_db,
            )
            .await?;
        } else {
            Self::up_not_owner(
                ctx,
                gov.clone(),
                our_key.clone(),
                ext_db,
                self.subject_id.clone(),
            )
            .await?;
        }

        let schemas = gov.schemas(ProtocolTypes::Evaluation, &our_key);
        Self::up_compilers_schemas(ctx, schemas, self.subject_id.clone())
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
        ctx: &mut ActorContext<Subject>,
        gov: Governance,
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
        ctx: &mut ActorContext<Subject>,
        new_gov: Governance,
        old_gov: Governance,
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
        ctx: &mut ActorContext<Subject>,
        gov: Governance,
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
        ctx: &mut ActorContext<Subject>,
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
        ctx: &mut ActorContext<Subject>,
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
        ctx: &mut ActorContext<Subject>,
        schemas: BTreeMap<String, Schema>,
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

            let Schema { contract, initial_value } = schema;

            compiler
                .tell(CompilerMessage::Compile {
                    contract_name: format!("{}_{}", subject_id, id),
                    contract,
                    initial_value,
                    contract_path: contracts_path
                        .join("contracts")
                        .join(format!("{}_{}", subject_id, id)),
                })
                .await?;
        }

        Ok(())
    }

    async fn down_compilers_schemas(
        ctx: &mut ActorContext<Subject>,
        schemas: Vec<String>,
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
        ctx: &mut ActorContext<Subject>,
        old_schemas_eval: Vec<String>,
        old_schemas_val: Vec<String>,
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
        ctx: &mut ActorContext<Subject>,
        schemas: HashMap<String, Schema>,
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
                        initial_value: schema.initial_value.clone(),
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

    async fn get_governance_from_other_subject(
        &self,
        ctx: &mut ActorContext<Subject>,
    ) -> Result<Governance, ActorError> {
        let governance_path =
            ActorPath::from(format!("/user/node/{}", self.governance_id));

        let governance_actor: Option<ActorRef<Subject>> =
            ctx.system().get_actor(&governance_path).await;

        let response = if let Some(governance_actor) = governance_actor {
            governance_actor.ask(SubjectMessage::GetGovernance).await?
        } else {
            return Err(ActorError::NotFound(governance_path));
        };

        match response {
            SubjectResponse::Governance(gov) => Ok(*gov),
            _ => Err(ActorError::UnexpectedResponse(
                governance_path,
                "SubjectResponse::Governance".to_owned(),
            )),
        }
    }

    async fn get_last_ledger_state(
        &self,
        ctx: &mut ActorContext<Subject>,
    ) -> Result<Option<SignedLedger>, ActorError> {
        let path = ActorPath::from(&format!("{}/store", ctx.path()));
        let store: Option<ActorRef<Store<Subject>>> =
            ctx.get_child("store").await;
        let response = if let Some(store) = store {
            store.ask(StoreCommand::LastEvent).await?
        } else {
            return Err(ActorError::NotFound(path));
        };

        match response {
            StoreResponse::LastEvent(event) => Ok(event),
            StoreResponse::Error(e) => {
                Err(ActorError::FunctionalFail(e.to_string()))
            }
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "StoreResponse::LastEvent".to_string(),
            )),
        }
    }

    async fn change_node_subject(
        ctx: &mut ActorContext<Subject>,
        subject_id: &str,
        new_owner: &str,
        old_owner: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .ask(NodeMessage::ChangeSubjectOwner {
                    new_owner: new_owner.to_owned(),
                    old_owner: old_owner.to_owned(),
                    subject_id: subject_id.to_owned(),
                })
                .await?;
        } else {
            return Err(ActorError::NotFound(node_path));
        }

        Ok(())
    }

    async fn new_transfer_subject(
        ctx: &mut ActorContext<Subject>,
        name: Option<String>,
        subject_id: &str,
        new_owner: &str,
        actual_owner: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .tell(NodeMessage::TransferSubject(TransferSubject {
                    name: name.unwrap_or_default(),
                    subject_id: subject_id.to_owned(),
                    new_owner: new_owner.to_owned(),
                    actual_owner: actual_owner.to_owned(),
                }))
                .await?;
        } else {
            return Err(ActorError::NotFound(node_path));
        }
        Ok(())
    }

    async fn reject_transfer_subject(
        ctx: &mut ActorContext<Subject>,
        subject_id: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .tell(NodeMessage::RejectTransfer(subject_id.to_owned()))
                .await?;
        } else {
            return Err(ActorError::NotFound(node_path));
        }
        Ok(())
    }

    async fn verify_new_ledger_event(
        &self,
        last_ledger: &Signed<Ledger>,
        new_ledger: &Signed<Ledger>,
    ) -> Result<bool, Error> {
        // Si no sigue activo
        if !self.active {
            return Err(Error::Subject("Subject is not active".to_owned()));
        }

        if !new_ledger
            .content
            .event_request
            .content
            .check_ledger_signature(
                &new_ledger.signature.signer,
                &self.owner,
                &self.new_owner,
            )?
        {
            return Err(Error::Subject("Invalid ledger signer".to_owned()));
        }

        if !new_ledger
            .content
            .event_request
            .content
            .check_ledger_signature(
                &new_ledger.content.event_request.signature.signer,
                &self.owner,
                &self.new_owner,
            )?
        {
            return Err(Error::Subject("Invalid event signer".to_owned()));
        }

        if let Err(e) = new_ledger.verify() {
            return Err(Error::Subject(format!(
                "In new event, event signature: {}",
                e
            )));
        }

        if let Err(e) = new_ledger.content.event_request.verify() {
            return Err(Error::Subject(format!(
                "In new event request, request signature: {}",
                e
            )));
        }

        // Mirar que sea el siguiente sn
        if last_ledger.content.sn + 1 != new_ledger.content.sn {
            return Err(Error::Sn);
        }

        //Comprobar que el hash del actual event sea el mismo que el pre_event_hash,
        let last_ledger_hash = hash_borsh(
            &*new_ledger.content.hash_prev_event.algorithm().hasher(),
            last_ledger,
        )
        .map_err(|e| {
            Error::Subject(format!(
                "Can not obtain previous event hash : {}",
                e
            ))
        })?;

        if last_ledger_hash != new_ledger.content.hash_prev_event {
            return Err(Error::Subject("Last event hash is not the same that previous event hash in new event".to_owned()));
        }

        let valid_last_event = verify_protocols_state(
            EventRequestType::from(
                &last_ledger.content.event_request.content,
            ),
            last_ledger.content.eval_success,
            last_ledger.content.appr_success,
            last_ledger.content.appr_required,
            last_ledger.content.vali_success,
            self.governance_id.is_empty(),
        )?;

        if valid_last_event
            && let EventRequest::EOL(..) =
                last_ledger.content.event_request.content.clone()
        {
            return Err(Error::Subject(
                "The last event was EOL, no more events can be received"
                    .to_owned(),
            ));
        }

        let valid_new_event = verify_protocols_state(
            EventRequestType::from(
                &new_ledger.content.event_request.content,
            ),
            new_ledger.content.eval_success,
            new_ledger.content.appr_success,
            new_ledger.content.appr_required,
            new_ledger.content.vali_success,
            self.governance_id.is_empty(),
        )?;

        // Si el nuevo evento a registrar fue correcto.
        if valid_new_event {
            match &new_ledger.content.event_request.content {
                EventRequest::Create(_start_request) => {
                    return Err(Error::Subject("A creation event is being logged when the subject has already been created previously".to_owned()));
                }
                EventRequest::Fact(_fact_request) => {
                    if self.new_owner.is_some() {
                        return Err(Error::Subject("After a transfer event there must be a confirmation or a reject event.".to_owned()));
                    }

                    self.check_patch(
                        &new_ledger.content.value,
                        &new_ledger.content.state_hash,
                    )?;
                }
                EventRequest::Transfer(..) => {
                    if self.new_owner.is_some() {
                        return Err(Error::Subject("After a transfer event there must be a confirmation or a reject event.".to_owned()));
                    }
                    let hash_without_patch = hash_borsh(
                        &*new_ledger.content.state_hash.algorithm().hasher(),
                        &self.properties,
                    )
                    .map_err(|e| {
                        Error::Subject(format!(
                            "Can not obtain state hash : {}",
                            e
                        ))
                    })?;

                    if hash_without_patch != new_ledger.content.state_hash {
                        return Err(Error::Subject("In Transfer event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                    }
                }
                EventRequest::Confirm(..) => {
                    if self.new_owner.is_none() {
                        return Err(Error::Subject("Before a confirm event there must be a transfer event.".to_owned()));
                    }

                    if self.governance_id.is_empty() {
                        self.check_patch(
                            &new_ledger.content.value,
                            &new_ledger.content.state_hash,
                        )?;
                    } else {
                        let hash_without_patch = hash_borsh(
                            &*new_ledger
                                .content
                                .state_hash
                                .algorithm()
                                .hasher(),
                            &self.properties,
                        )
                        .map_err(|e| {
                            Error::Subject(format!(
                                "Can not obtain state hash : {}",
                                e
                            ))
                        })?;

                        if hash_without_patch != new_ledger.content.state_hash {
                            return Err(Error::Subject("In Confirm event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                        }
                    }
                }
                EventRequest::Reject(..) => {
                    if self.new_owner.is_none() {
                        return Err(Error::Subject("Before a reject event there must be a transfer event.".to_owned()));
                    }

                    let hash_without_patch = hash_borsh(
                        &*new_ledger.content.state_hash.algorithm().hasher(),
                        &self.properties,
                    )
                    .map_err(|e| {
                        Error::Subject(format!(
                            "Can not obtain state hash : {}",
                            e
                        ))
                    })?;

                    if hash_without_patch != new_ledger.content.state_hash {
                        return Err(Error::Subject("In Reject event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                    }
                }
                EventRequest::EOL(..) => {
                    if self.new_owner.is_some() {
                        return Err(Error::Subject("After a transfer event there must be a confirmation or a reject event.".to_owned()));
                    }

                    let hash_without_patch = hash_borsh(
                        &*new_ledger.content.state_hash.algorithm().hasher(),
                        &self.properties,
                    )
                    .map_err(|e| {
                        Error::Subject(format!(
                            "Can not obtain state hash : {}",
                            e
                        ))
                    })?;

                    if hash_without_patch != new_ledger.content.state_hash {
                        return Err(Error::Subject("In EOL event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                    }
                }
            };
        } else {
            let hash_without_patch = hash_borsh(
                &*new_ledger.content.state_hash.algorithm().hasher(),
                &self.properties,
            )
            .map_err(|e| {
                Error::Subject(format!("Can not obtain state hash : {}", e))
            })?;

            if hash_without_patch != new_ledger.content.state_hash {
                return Err(Error::Subject("The hash obtained without applying any patch is different from the state hash of the event".to_owned()));
            }
        }
        Ok(valid_new_event)
    }

    async fn verify_first_ledger_event(
        &self,
        event: &SignedLedger,
    ) -> Result<(), Error> {
        let is_gov = if let EventRequest::Create(event_req) =
            event.content.event_request.content.clone()
        {
            if let Some(name) = event_req.name
                && (name.is_empty() || name.len() > 100)
            {
                return Err(Error::Subject("The subject name must be less than 100 characters or not be empty.".to_owned()));
            }

            if let Some(description) = event_req.description
                && (description.is_empty() || description.len() > 200)
            {
                return Err(Error::Subject("The subject description must be less than 200 characters or not be empty.".to_owned()));
            }

            if event_req.schema_id == "governance"
                && (!event_req.governance_id.is_empty()
                    || !event_req.namespace.is_empty()
                        && event.content.gov_version != 0)
            {
                return Err(Error::Subject("In create event, governance_id must be empty, namespace must be empty and gov version must be 0".to_owned()));
            }

            event_req.schema_id == "governance"
        } else {
            return Err(Error::Subject(
                "First event is not a create event".to_owned(),
            ));
        };

        if event.signature.signer != self.owner
            || event.content.event_request.signature.signer != self.owner
        {
            return Err(Error::Subject(
                "In create event, owner must sign request and event."
                    .to_owned(),
            ));
        }

        if let Err(e) = event.verify() {
            return Err(Error::Subject(format!(
                "In create event, event signature: {}",
                e
            )));
        }

        if let Err(e) = event.content.event_request.verify() {
            return Err(Error::Subject(format!(
                "In create event, request signature: {}",
                e
            )));
        }

        if event.content.sn != 0 {
            return Err(Error::Subject(
                "In create event, sn must be 0.".to_owned(),
            ));
        }

        if !event.content.hash_prev_event.is_empty() {
            return Err(Error::Subject(
                "In create event, previous hash event must be empty."
                    .to_owned(),
            ));
        }

        if verify_protocols_state(
            EventRequestType::Create,
            event.content.eval_success,
            event.content.appr_success,
            event.content.appr_required,
            event.content.vali_success,
            is_gov,
        )? {
            Ok(())
        } else {
            Err(Error::Subject(
                "Create event fail in validation protocol".to_owned(),
            ))
        }
    }

    async fn register(
        &self,
        ctx: &mut ActorContext<Subject>,
        active: bool,
    ) -> Result<(), ActorError> {
        let register_path = ActorPath::from("/user/node/register");
        let register: Option<ActorRef<Register>> =
            ctx.system().get_actor(&register_path).await;
        if let Some(register) = register {
            let message = if self.governance_id.is_empty() {
                RegisterMessage::RegisterGov {
                    gov_id: self.subject_id.to_string(),
                    data: RegisterDataGov {
                        active,
                        name: self.name.clone(),
                        description: self.description.clone(),
                    },
                }
            } else {
                RegisterMessage::RegisterSubj {
                    gov_id: self.governance_id.to_string(),
                    data: RegisterDataSubj {
                        subject_id: self.subject_id.to_string(),
                        schema_id: self.schema_id.clone(),
                        active,
                        name: self.name.clone(),
                        description: self.description.clone(),
                    },
                }
            };

            register.tell(message).await?;
        } else {
            return Err(ActorError::NotFound(register_path));
        }

        Ok(())
    }

    async fn event_to_sink(
        &self,
        ctx: &mut ActorContext<Subject>,
        event: &EventRequest,
        issuer: &str,
    ) -> Result<(), ActorError> {
        let gov_id = if self.governance_id.is_empty() {
            None
        } else {
            Some(self.governance_id.to_string())
        };
        let sub_id = self.subject_id.to_string();
        let owner = self.owner.to_string();
        let schema_id = self.schema_id.clone();

        let event_to_sink = match event {
            EventRequest::Create(..) => SinkDataMessage::Create {
                governance_id: gov_id,
                subject_id: sub_id,
                owner,
                schema_id,
                namespace: self.namespace.to_string(),
                sn: self.sn,
            },
            EventRequest::Fact(fact_request) => SinkDataMessage::Fact {
                governance_id: gov_id,
                subject_id: sub_id,
                issuer: issuer.to_string(),
                owner,
                payload: fact_request.payload.0.clone(),
                schema_id,
                sn: self.sn,
            },
            EventRequest::Transfer(transfer_request) => {
                SinkDataMessage::Transfer {
                    governance_id: gov_id,
                    subject_id: sub_id,
                    owner,
                    new_owner: transfer_request.new_owner.to_string(),
                    schema_id,
                    sn: self.sn,
                }
            }
            EventRequest::Confirm(..) => SinkDataMessage::Confirm {
                governance_id: gov_id,
                subject_id: sub_id,
                schema_id,
                sn: self.sn,
            },
            EventRequest::Reject(..) => SinkDataMessage::Reject {
                governance_id: gov_id,
                subject_id: sub_id,
                schema_id,
                sn: self.sn,
            },
            EventRequest::EOL(..) => SinkDataMessage::EOL {
                governance_id: gov_id,
                subject_id: sub_id,
                schema_id,
                sn: self.sn,
            },
        };

        Self::publish_sink(ctx, event_to_sink).await
    }

    async fn verify_new_ledger_events_gov(
        &mut self,
        ctx: &mut ActorContext<Subject>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let mut iter = events.into_iter();
        let last_ledger = self.get_last_ledger_state(ctx).await?;

        let mut last_ledger = if let Some(last_ledger) = last_ledger {
            last_ledger
        } else {
            let Some(first) = iter.next() else { return Ok(()); };
            if let Err(e) =
                self.verify_first_ledger_event(&first).await
            {
                self.delete_subject(ctx).await?;
                return Err(ActorError::Functional(e.to_string()));
            }

            self.on_event(first.clone(), ctx).await;
            self.register(ctx, true).await?;

            first
        };

        for event in iter {
            let last_event_is_ok = match self
                .verify_new_ledger_event(&last_ledger, &event)
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
            if last_event_is_ok {
                match event.content.event_request.content.clone() {
                    EventRequest::Transfer(transfer_request) => {
                        Subject::new_transfer_subject(
                            ctx,
                            self.name.clone(),
                            &transfer_request.subject_id.to_string(),
                            &transfer_request.new_owner.to_string(),
                            &self.owner.to_string(),
                        )
                        .await?
                    }
                    EventRequest::Reject(reject_request) => {
                        Subject::reject_transfer_subject(
                            ctx,
                            &reject_request.subject_id.to_string(),
                        )
                        .await?;
                    }
                    EventRequest::Confirm(confirm_request) => {
                        Subject::change_node_subject(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                            &event.signature.signer.to_string(),
                            &self.owner.to_string(),
                        )
                        .await?;
                    }
                    EventRequest::EOL(_eolrequest) => {
                        self.register(ctx, false).await?
                    }
                    _ => {}
                };

                self.event_to_sink(
                    ctx,
                    &event.content.event_request.content,
                    &event.content.event_request.signature.signer.to_string(),
                )
                .await?;
            }

            // Aplicar evento.
            self.on_event(event.clone(), ctx).await;

            // Acutalizar último evento.
            last_ledger = event.clone();
        }

        Ok(())
    }

    async fn register_relation(
        &self,
        ctx: &mut ActorContext<Subject>,
        signer: String,
        max_quantity: CreatorQuantity,
    ) -> Result<(), ActorError> {
        register_relation(
            ctx,
            self.governance_id.to_string(),
            self.schema_id.clone(),
            signer,
            self.subject_id.to_string(),
            self.namespace.to_string(),
            max_quantity,
        )
        .await
    }

    async fn purge_storage(
        ctx: &mut ActorContext<Subject>,
    ) -> Result<(), ActorError> {
        let store: Option<ActorRef<Store<Subject>>> =
            ctx.get_child("store").await;
        let response = if let Some(store) = store {
            store.ask(StoreCommand::Purge).await?
        } else {
            return Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/store",
                ctx.path()
            ))));
        };

        if let StoreResponse::Error(e) = response {
            return Err(ActorError::Store(format!(
                "Can not purge request: {}",
                e
            )));
        };

        Ok(())
    }

    pub async fn delet_node_subject(
        ctx: &mut ActorContext<Subject>,
        subject_id: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        // We obtain the validator
        let Some(node_actor) = node_actor else {
            return Err(ActorError::NotFound(node_path));
        };
        node_actor
            .tell(NodeMessage::DeleteSubject(subject_id.to_owned()))
            .await
    }

    async fn delete_subject(
        &self,
        ctx: &mut ActorContext<Subject>,
    ) -> Result<(), ActorError> {
        if self.schema_id != "governance" {
            delete_relation(
                ctx,
                self.governance_id.to_string(),
                self.schema_id.clone(),
                self.owner.to_string(),
                self.subject_id.to_string(),
                self.namespace.to_string(),
            )
            .await?;
        }

        Self::delet_node_subject(ctx, &self.subject_id.to_string()).await?;

        Self::purge_storage(ctx).await?;

        ctx.stop(None).await;

        Ok(())
    }

    async fn verify_new_ledger_events_not_gov(
        &mut self,
        ctx: &mut ActorContext<Subject>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let mut iter = events.into_iter();
        let last_ledger = self.get_last_ledger_state(ctx).await?;

        let gov = get_gov(ctx, &self.governance_id.to_string()).await?;

        let Some(first) = iter.next() else { return Ok(()); };

        let Some(max_quantity) = gov.max_creations(
            &first.signature.signer,
            &self.schema_id,
            self.namespace.clone(),
        ) else {
            return Err(ActorError::Functional(
                "The number of subjects that can be created has not been found"
                    .to_owned(),
            ));
        };

        let mut pending = Vec::new();

        let mut last_ledger = if let Some(last_ledger) = last_ledger {
            pending.push(first);
            last_ledger
        } else {
            self.register_relation(
                ctx,
                self.owner.to_string(),
                max_quantity.clone(),
            )
            .await?;

            if let Err(e) =
                self.verify_first_ledger_event(&first).await
            {
                self.delete_subject(ctx).await?;
                return Err(ActorError::Functional(e.to_string()));
            }

            self.on_event(first.clone(), ctx).await;
            self.register(ctx, true).await?;

            first
        };

        pending.extend(iter);

        for event in pending {
            let last_event_is_ok = match self
                .verify_new_ledger_event(&last_ledger, &event)
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

            if last_event_is_ok {
                match event.content.event_request.content.clone() {
                    EventRequest::Transfer(transfer_request) => {
                        Subject::new_transfer_subject(
                            ctx,
                            self.name.clone(),
                            &transfer_request.subject_id.to_string(),
                            &transfer_request.new_owner.to_string(),
                            &self.owner.to_string(),
                        )
                        .await?;
                    }
                    EventRequest::Reject(reject_request) => {
                        Subject::reject_transfer_subject(
                            ctx,
                            &reject_request.subject_id.to_string(),
                        )
                        .await?;
                    }
                    EventRequest::Confirm(confirm_request) => {
                        self.register_relation(
                            ctx,
                            event.signature.signer.to_string(),
                            max_quantity.clone(),
                        )
                        .await?;

                        Subject::change_node_subject(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                            &event.signature.signer.to_string(),
                            &self.owner.to_string(),
                        )
                        .await?;

                        delete_relation(
                            ctx,
                            self.governance_id.to_string(),
                            self.schema_id.clone(),
                            self.owner.to_string(),
                            self.subject_id.to_string(),
                            self.namespace.to_string(),
                        )
                        .await?;

                        Subject::transfer_register(
                            ctx,
                            &self.subject_id.to_string(),
                            event.signature.signer.clone(),
                            self.owner.clone(),
                        )
                        .await?;
                    }
                    EventRequest::EOL(_eolrequest) => {
                        self.register(ctx, false).await?
                    }
                    _ => {}
                };

                self.event_to_sink(
                    ctx,
                    &event.content.event_request.content,
                    &event.content.event_request.signature.signer.to_string(),
                )
                .await?;
            }

            // Aplicar evento.
            self.on_event(event.clone(), ctx).await;

            // Acutalizar último evento.
            last_ledger = event.clone();
        }

        Ok(())
    }

    async fn transfer_register(
        ctx: &mut ActorContext<Subject>,
        subject_id: &str,
        new: PublicKey,
        old: PublicKey,
    ) -> Result<(), ActorError> {
        let tranfer_register_path =
            ActorPath::from("/user/node/transfer_register");
        let transfer_register_actor: Option<
            ave_actors::ActorRef<TransferRegister>,
        > = ctx.system().get_actor(&tranfer_register_path).await;

        let Some(transfer_register_actor) = transfer_register_actor else {
            return Err(ActorError::NotFound(tranfer_register_path));
        };

        transfer_register_actor
            .tell(TransferRegisterMessage::RegisterNewOldOwner {
                old,
                new,
                subject_id: subject_id.to_owned(),
            })
            .await?;

        Ok(())
    }

    async fn verify_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Subject>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let our_key = self.get_node_key(ctx).await?;
        let current_sn = self.sn;
        let current_new_owner_some = self.new_owner.is_some();
        let i_current_new_owner =
            self.new_owner.clone() == Some(our_key.clone());
        let current_owner = self.owner.clone();

        if self.governance_id.is_empty() {
            let current_properties = self.properties.clone();

            if let Err(e) = self.verify_new_ledger_events_gov(ctx, events).await
            {
                if let ActorError::Functional(error) = e.clone() {
                    warn!(
                        TARGET_SUBJECT,
                        "Error verifying new events: {}", error
                    );

                    // Falló en la creación
                    if self.sn == 0 {
                        return Err(e);
                    }
                    // TODO falló pero pudo aplicar algún evento entonces seguimos.
                } else {
                    error!(TARGET_SUBJECT, "Error verifying new events {}", e);
                    return Err(e);
                }
            };

            if current_sn < self.sn {
                let old_gov = Governance::try_from(current_properties)
                    .map_err(|e| ActorError::FunctionalFail(e.to_string()))?;
                if !self.active {
                    if current_owner == our_key {
                        Self::down_owner(ctx).await?;
                    } else {
                        Self::down_not_owner(
                            ctx,
                            old_gov.clone(),
                            our_key.clone(),
                        )
                        .await?;
                    }

                    let old_schemas_eval = old_gov
                        .schemas(ProtocolTypes::Evaluation, &our_key)
                        .iter()
                        .map(|x| x.0.clone())
                        .collect::<Vec<String>>();
                    Self::down_compilers_schemas(ctx, old_schemas_eval.clone())
                        .await?;

                    let old_schemas_val = old_gov
                        .schemas(ProtocolTypes::Validation, &our_key)
                        .iter()
                        .map(|x| x.0.clone())
                        .collect::<Vec<String>>();

                    Self::down_schemas(ctx, old_schemas_eval, old_schemas_val)
                        .await?;
                } else {
                    let new_gov = Governance::try_from(self.properties.clone())
                        .map_err(|e| {
                            ActorError::FunctionalFail(e.to_string())
                        })?;

                    let Some(ext_db): Option<ExternalDB> =
                        ctx.system().get_helper("ext_db").await
                    else {
                        return Err(ActorError::NotHelper("config".to_owned()));
                    };

                    let new_owner_some = self.new_owner.is_some();
                    let i_new_owner =
                        self.new_owner.clone() == Some(our_key.clone());
                    let mut up_not_owner: bool = false;
                    let mut up_owner: bool = false;

                    if current_owner == our_key {
                        // Eramos dueños
                        if current_owner != self.owner {
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
                            } else if !current_new_owner_some && new_owner_some
                            {
                                up_not_owner = true;
                            }
                        }
                    } else {
                        // No eramos dueño
                        if current_owner != self.owner && self.owner == our_key
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
                            self.subject_id.clone(),
                        )
                        .await?;
                    } else if up_owner {
                        Self::down_not_owner(
                            ctx,
                            old_gov.clone(),
                            our_key.clone(),
                        )
                        .await?;
                        Self::up_owner(
                            ctx,
                            our_key.clone(),
                            self.subject_id.clone(),
                            ext_db.clone(),
                        )
                        .await?;
                    }

                    // Seguimos sin ser owner ni new owner,
                    // pero tenemos que ver si tenemos un rol nuevo.
                    if !up_not_owner && !up_owner && our_key != self.owner {
                        Self::up_down_not_owner(
                            ctx,
                            new_gov.clone(),
                            old_gov.clone(),
                            our_key.clone(),
                            ext_db.clone(),
                            self.subject_id.clone(),
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
                        self.subject_id.clone(),
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
                        self.subject_id.clone(),
                    )
                    .await?;

                    let mut old_schemas_eval = old_schemas_eval
                        .iter()
                        .map(|x| x.0.clone())
                        .collect::<Vec<String>>();
                    let mut old_schemas_val = old_gov
                        .schemas(ProtocolTypes::Validation, &our_key)
                        .iter()
                        .map(|x| x.0.clone())
                        .collect::<Vec<String>>();

                    let new_creators =
                        new_gov.subjects_schemas_rol_namespace(&our_key);

                    for creators in new_creators {
                        if let Some(eval_users) = creators.evaluation {
                            let pos = old_schemas_eval
                                .iter()
                                .position(|x| *x == creators.schema_id);

                            if let Some(pos) = pos {
                                old_schemas_eval.remove(pos);
                                let actor: Option<ActorRef<EvaluationSchema>> =
                                    ctx.get_child(&format!(
                                        "{}_evaluation",
                                        creators.schema_id
                                    ))
                                    .await;
                                if let Some(actor) = actor {
                                    if let Err(e) = actor.tell(EvaluationSchemaMessage::UpdateEvaluators(eval_users, new_gov.version)).await {
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                } else {
                                    let e = ActorError::NotFound(
                                        ActorPath::from(format!(
                                            "{}/{}_evaluation",
                                            ctx.path(),
                                            creators.schema_id
                                        )),
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            } else {
                                let eval_actor = EvaluationSchema::new(
                                    eval_users,
                                    new_gov.version,
                                );
                                ctx.create_child(
                                    &format!(
                                        "{}_evaluation",
                                        creators.schema_id
                                    ),
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
                                let actor: Option<ActorRef<ValidationSchema>> =
                                    ctx.get_child(&format!(
                                        "{}_validation",
                                        creators.schema_id
                                    ))
                                    .await;
                                if let Some(actor) = actor {
                                    if let Err(e) = actor.tell(ValidationSchemaMessage::UpdateValidators(val_user, new_gov.version)).await {
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                } else {
                                    let e = ActorError::NotFound(
                                        ActorPath::from(format!(
                                            "{}/{}_validation",
                                            ctx.path(),
                                            creators.schema_id
                                        )),
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            } else {
                                let actor = ValidationSchema::new(
                                    val_user,
                                    new_gov.version,
                                );
                                ctx.create_child(
                                    &format!(
                                        "{}_validation",
                                        creators.schema_id
                                    ),
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
        } else {
            if let Err(e) =
                self.verify_new_ledger_events_not_gov(ctx, events).await
            {
                if let ActorError::Functional(error) = e.clone() {
                    warn!(
                        TARGET_SUBJECT,
                        "Error verifying new events: {}", error
                    );

                    // Falló en la creación
                    if self.sn == 0 {
                        return Err(e);
                    }
                } else {
                    error!(TARGET_SUBJECT, "Error verifying new events {}", e);
                    return Err(e);
                }
            };

            if current_sn < self.sn {
                if !self.active && current_owner == our_key {
                    Self::down_owner_not_gov(ctx).await?;
                }

                let i_new_owner =
                    self.new_owner.clone() == Some(our_key.clone());

                // Si antes no eramos el new owner y ahora somos el new owner.
                if !i_current_new_owner
                    && i_new_owner
                    && current_owner != our_key
                {
                    Self::up_owner_not_gov(ctx, &our_key).await?;
                }

                // Si cambió el dueño
                if current_owner != self.owner {
                    // Si ahora somos el dueño pero no eramos new owner.
                    if self.owner == our_key && !i_current_new_owner {
                        Self::up_owner_not_gov(ctx, &our_key).await?;
                    } else if current_owner == our_key && !i_new_owner {
                        Self::down_owner_not_gov(ctx).await?;
                    }
                } else if i_current_new_owner && !i_new_owner {
                    Self::down_owner_not_gov(ctx).await?;
                }
            }
        }

        if current_sn < self.sn || current_sn == 0 {
            Self::publish_sink(
                ctx,
                SinkDataMessage::UpdateState(Box::new(self.get_metadata())),
            )
            .await?;

            Self::update_subject_node(
                ctx,
                &self.subject_id.to_string(),
                self.sn,
            )
            .await?;
        }

        Ok(())
    }

    async fn publish_sink(
        ctx: &mut ActorContext<Subject>,
        message: SinkDataMessage,
    ) -> Result<(), ActorError> {
        let sink_data: Option<ActorRef<SinkData>> =
            ctx.get_child("sink_data").await;
        if let Some(sink_data) = sink_data {
            sink_data.tell(message).await
        } else {
            Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/sink_data",
                ctx.path()
            ))))
        }
    }

    async fn update_subject_node(
        ctx: &mut ActorContext<Subject>,
        subject_id: &str,
        sn: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .tell(NodeMessage::UpdateSubject {
                    subject_id: subject_id.to_owned(),
                    sn,
                })
                .await
        } else {
            Err(ActorError::NotFound(node_path))
        }
    }

    async fn get_ledger(
        &self,
        ctx: &mut ActorContext<Subject>,
        last_sn: u64,
    ) -> Result<Vec<<Subject as Actor>::Event>, ActorError> {
        let store: Option<ActorRef<Store<Subject>>> =
            ctx.get_child("store").await;
        let response = if let Some(store) = store {
            store
                .ask(StoreCommand::GetEvents {
                    from: last_sn,
                    to: last_sn + 100,
                })
                .await?
        } else {
            return Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/store",
                ctx.path()
            ))));
        };

        match response {
            StoreResponse::Events(events) => Ok(events),
            _ => Err(ActorError::UnexpectedResponse(
                ActorPath::from(format!("{}/store", ctx.path())),
                "StoreResponse::Events".to_owned(),
            )),
        }
    }

    async fn create_compilers(
        ctx: &mut ActorContext<Subject>,
        compilers: &[String],
    ) -> Result<Vec<String>, ActorError> {
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

    async fn get_ledger_data(
        &self,
        ctx: &mut ActorContext<Subject>,
        last_sn: u64,
    ) -> Result<SubjectResponse, ActorError> {
        let ledger = self.get_ledger(ctx, last_sn).await?;

        if ledger.len() < 100 {
            let last_event = get_last_event(ctx, &self.subject_id.to_string())
                .await
                .map_err(|e| {
                    error!(
                        TARGET_SUBJECT,
                        "GetLedger, can not get last event: {}", e
                    );
                    e
                })?;

            let (last_proof, prev_event_validation_response) =
                get_vali_data(ctx, &self.subject_id.to_string())
                    .await
                    .map_err(|e| {
                        error!(
                            TARGET_SUBJECT,
                            "GetLedger, can not get last vali data: {}", e
                        );
                        e
                    })?;

            Ok(SubjectResponse::Ledger {
                ledger,
                last_event: Box::new(Some(last_event)),
                last_proof: Box::new(last_proof),
                prev_event_validation_response: Some(
                    prev_event_validation_response,
                ),
            })
        } else {
            Ok(SubjectResponse::Ledger {
                ledger,
                last_event: Box::new(None),
                last_proof: Box::new(None),
                prev_event_validation_response: None,
            })
        }
    }

    fn check_patch(
        &self,
        value: &LedgerValue,
        state_hash: &DigestIdentifier,
    ) -> Result<(), Error> {
        let LedgerValue::Patch(json_patch) = value else {
            return Err(Error::Subject("The event was successful but does not have a json patch to apply".to_owned()));
        };

        let patch_json = serde_json::from_value::<Patch>(json_patch.0.clone())
            .map_err(|e| {
                Error::Subject(format!("Failed to extract event patch: {}", e))
            })?;
        let mut properties = self.properties.0.clone();
        let Ok(()) = patch(&mut properties, &patch_json) else {
            return Err(Error::Subject(
                "Failed to apply event patch".to_owned(),
            ));
        };

        let hash_state_after_patch = hash_borsh(
            &*state_hash.algorithm().hasher(),
            &ValueWrapper(properties),
        )
        .map_err(|e| {
            Error::Subject(format!(
                "Can not obtain previous event hash : {}",
                e
            ))
        })?;

        if hash_state_after_patch != *state_hash {
            return Err(Error::Subject("The new patch has been applied and we have obtained a different hash than the event after applying the patch".to_owned()));
        }
        Ok(())
    }

    fn apply_patch(&mut self, value: LedgerValue) -> Result<(), ActorError> {
        let json_patch = match value {
            LedgerValue::Patch(value_wrapper) => value_wrapper,
            LedgerValue::Error(e) => {
                let error = format!(
                    "Apply, event value can not be an error if protocols was successful: {:?}",
                    e
                );
                error!(TARGET_SUBJECT, error);
                return Err(ActorError::Functional(error));
            }
        };

        let patch_json = match serde_json::from_value::<Patch>(json_patch.0) {
            Ok(patch) => patch,
            Err(e) => {
                let error = format!("Apply, can not obtain json patch: {}", e);
                error!(TARGET_SUBJECT, error);
                return Err(ActorError::Functional(error));
            }
        };

        if let Err(e) = patch(&mut self.properties.0, &patch_json) {
            let error = format!("Apply, can not apply json patch: {}", e);
            error!(TARGET_SUBJECT, error);
            return Err(ActorError::Functional(error));
        };

        Ok(())
    }
}

/// Subject command.
#[derive(Debug, Clone)]
pub enum SubjectMessage {
    UpdateTransfer(TransferResponse),
    CreateCompilers(Vec<String>),
    /// Get the subject metadata.
    GetMetadata,
    GetLedger {
        last_sn: u64,
    },
    GetLastLedger,
    UpdateLedger {
        events: Vec<SignedLedger>,
    },
    /// Get governance if subject is a governance
    GetGovernance,
    GetOwner,
    DeleteSubject,
}

impl Message for SubjectMessage {}

/// Subject response.
#[derive(Debug, Clone)]
pub enum SubjectResponse {
    /// The subject metadata.
    Metadata(Box<Metadata>),
    UpdateResult(u64, PublicKey, Option<PublicKey>),
    Ledger {
        ledger: Vec<SignedLedger>,
        last_event: Box<Option<Signed<AveEvent>>>,
        last_proof: Box<Option<ValidationProof>>,
        prev_event_validation_response: Option<Vec<ProtocolsSignatures>>,
    },
    Governance(Box<Governance>),
    Owner(PublicKey),
    NewCompilers(Vec<String>),
    Ok,
}

impl Response for SubjectResponse {}

/// Newtype wrapper for Signed<Ledger> to allow implementing the Event trait.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SignedLedger(pub Signed<Ledger>);

impl Deref for SignedLedger {
    type Target = Signed<Ledger>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Event for SignedLedger {}

/// Actor implementation for `Subject`.
#[async_trait]
impl Actor for Subject {
    type Event = SignedLedger;
    type Message = SubjectMessage;
    type Response = SubjectResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("subject", None, true, ctx).await?;

        let our_key = self.get_node_key(ctx).await?;

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

        let ledger_event_actor = ctx
            .create_child(
                "ledger_event",
                LedgerEvent::initial(self.governance_id.is_empty()),
            )
            .await?;

        let sink = Sink::new(
            ledger_event_actor.subscribe(),
            ext_db.get_ledger_event(),
        );
        ctx.system().run_sink(sink).await;

        let vali_data_actor =
            ctx.create_child("vali_data", ValiData::initial(())).await?;
        let sink =
            Sink::new(vali_data_actor.subscribe(), ext_db.get_vali_data());
        ctx.system().run_sink(sink).await;

        if self.active {
            if self.governance_id.is_empty() {
                self.build_childs_governance(
                    ctx,
                    our_key.clone(),
                    ext_db.clone(),
                )
                .await?;
            } else {
                self.build_childs_all_schemas(ctx, our_key.clone()).await?;
            }
        }

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
impl Handler<Subject> for Subject {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SubjectMessage,
        ctx: &mut ActorContext<Subject>,
    ) -> Result<SubjectResponse, ActorError> {
        match msg {
            SubjectMessage::UpdateTransfer(res) => {
                match res {
                    TransferResponse::Confirm => {
                        let Some(new_owner) = self.new_owner.clone() else {
                            let e = "Can not obtain new_owner";
                            error!(TARGET_SUBJECT, "Confirm, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        };

                        Subject::change_node_subject(
                            ctx,
                            &self.subject_id.to_string(),
                            &new_owner.to_string(),
                            &self.owner.to_string(),
                        )
                        .await?;

                        delete_relation(
                            ctx,
                            self.governance_id.to_string(),
                            self.schema_id.clone(),
                            self.owner.to_string(),
                            self.subject_id.to_string(),
                            self.namespace.to_string(),
                        )
                        .await?;
                    }
                    TransferResponse::Reject => {
                        Subject::reject_transfer_subject(
                            ctx,
                            &self.subject_id.to_string(),
                        )
                        .await?;
                        try_to_update(
                            ctx,
                            self.subject_id.clone(),
                            WitnessesAuth::None,
                        )
                        .await?;
                    }
                }

                Ok(SubjectResponse::Ok)
            }
            SubjectMessage::DeleteSubject => {
                self.delete_subject(ctx).await?;
                Ok(SubjectResponse::Ok)
            }
            SubjectMessage::CreateCompilers(compilers) => {
                let new_compilers =
                    match Self::create_compilers(ctx, &compilers).await {
                        Ok(new_compilers) => new_compilers,
                        Err(e) => {
                            warn!(
                                TARGET_SUBJECT,
                                "CreateCompilers, can not create compilers: {}",
                                e
                            );
                            return Err(e);
                        }
                    };
                Ok(SubjectResponse::NewCompilers(new_compilers))
            }
            SubjectMessage::GetLedger { last_sn } => {
                self.get_ledger_data(ctx, last_sn).await
            }
            SubjectMessage::GetLastLedger => {
                self.get_ledger_data(ctx, self.sn).await
            }
            SubjectMessage::GetOwner => {
                Ok(SubjectResponse::Owner(self.owner.clone()))
            }
            SubjectMessage::GetMetadata => {
                Ok(SubjectResponse::Metadata(Box::new(self.get_metadata())))
            }
            SubjectMessage::UpdateLedger { events } => {
                if let Err(e) =
                    self.verify_new_ledger_events(ctx, events).await
                {
                    warn!(
                        TARGET_SUBJECT,
                        "UpdateLedger, can not verify new events: {}", e
                    );
                    return Err(e);
                };
                Ok(SubjectResponse::UpdateResult(
                    self.sn,
                    self.owner.clone(),
                    self.new_owner.clone(),
                ))
            }
            SubjectMessage::GetGovernance => {
                // If is a governance
                if self.governance_id.is_empty() {
                    match Governance::try_from(self.properties.clone()) {
                        Ok(gov) => {
                            return Ok(SubjectResponse::Governance(Box::new(
                                gov,
                            )));
                        }
                        Err(e) => {
                            error!(
                                TARGET_SUBJECT,
                                "GetGovernance, can not convert governance from properties: {}",
                                e
                            );
                            return Err(ActorError::FunctionalFail(
                                e.to_string(),
                            ));
                        }
                    }
                }
                // If is not a governance
                return Ok(SubjectResponse::Governance(Box::new(
                    self.get_governance_from_other_subject(ctx).await?,
                )));
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SignedLedger,
        ctx: &mut ActorContext<Subject>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_SUBJECT,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event).await {
            error!(
                TARGET_SUBJECT,
                "PublishEvent, can not publish event: {}", e
            );
            emit_fail(ctx, e).await;
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Subject>,
    ) -> ChildAction {
        error!(TARGET_SUBJECT, "OnChildFault, {}", error);
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for Subject {
    type Persistence = FullPersistence;
    type InitParams = Option<Self>;

    fn create_initial(params: Self::InitParams) -> Self {
        params.unwrap_or_default()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        let is_gov = {
            match &event.content.event_request.content {
                EventRequest::Create(create_event) => {
                    create_event.governance_id.is_empty()
                }
                _ => self.governance_id.is_empty(),
            }
        };

        let valid_event = match verify_protocols_state(
            EventRequestType::from(&event.content.event_request.content),
            event.content.eval_success,
            event.content.appr_success,
            event.content.appr_required,
            event.content.vali_success,
            is_gov,
        ) {
            Ok(is_ok) => is_ok,
            Err(e) => {
                let error =
                    format!("Apply, can not verify protocols state: {}", e);
                error!(TARGET_SUBJECT, error);
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
                        error!(TARGET_SUBJECT, error);
                        ActorError::Functional(error)
                    })?;

                    let properties = if create_event.schema_id == "governance" {
                        let gov = Governance::new(
                            event
                                .content
                                .event_request
                                .signature
                                .signer
                                .clone(),
                        );
                        gov.to_value_wrapper().map_err(|e| {
                            ActorError::Functional(e.to_string())
                        })?
                    } else if let LedgerValue::Patch(init_state) =
                        event.content.value.clone()
                    {
                        init_state
                    } else {
                        let e = "Can not create subject, ledgerValue is not a patch";
                        return Err(ActorError::Functional(e.to_string()));
                    };

                    self.name = create_event.name.clone();
                    self.description = create_event.description.clone();
                    self.subject_id = event.content.subject_id.clone();
                    self.governance_id = create_event.governance_id.clone();
                    self.genesis_gov_version = event.content.gov_version;
                    self.namespace = create_event.namespace.clone();
                    self.schema_id = create_event.schema_id.clone();
                    self.last_event_hash = last_event_hash;
                    self.owner =
                        event.content.event_request.signature.signer.clone();
                    self.creator =
                        event.content.event_request.signature.signer.clone();
                    self.new_owner = None;
                    self.sn = 0;
                    self.active = true;
                    self.properties = properties;

                    return Ok(());
                }
                EventRequest::Fact(_fact_request) => {
                    self.apply_patch(event.content.value.clone())?;
                }
                EventRequest::Transfer(transfer_request) => {
                    self.new_owner = Some(transfer_request.new_owner.clone());
                }
                EventRequest::Confirm(_confirm_request) => {
                    if self.governance_id.is_empty() {
                        self.apply_patch(event.content.value.clone())?;
                    }

                    let Some(new_owner) = self.new_owner.clone() else {
                        let error = "In confirm event was succefully but new owner is empty:";
                        error!(TARGET_SUBJECT, error);
                        return Err(ActorError::Functional(error.to_owned()));
                    };

                    self.owner = new_owner;
                    self.new_owner = None;
                }
                EventRequest::Reject(_reject_request) => {
                    self.new_owner = None;
                }
                EventRequest::EOL(_eolrequest) => self.active = false,
            }

            if self.governance_id.is_empty() {
                let mut gov = match Governance::try_from(
                    self.properties.clone(),
                ) {
                    Ok(gov) => gov,
                    Err(e) => {
                        let error = format!(
                            "Apply, Governance_id is empty but can not convert properties in governance data: {}",
                            e
                        );
                        error!(TARGET_SUBJECT, error);
                        return Err(ActorError::Functional(error));
                    }
                };

                gov.version += 1;
                let gov_value = match to_value(gov) {
                    Ok(value) => value,
                    Err(e) => {
                        let error = format!(
                            "Apply, can not convert governance data into Value: {}",
                            e
                        );
                        error!(TARGET_SUBJECT, error);
                        return Err(ActorError::Functional(error));
                    }
                };

                self.properties.0 = gov_value;
            }
        }

        let last_event_hash = hash_borsh(
            &*event.signature.content_hash.algorithm().hasher(),
            &event,
        )
        .map_err(|e| {
            let error = format!("Apply, can not obtain last event hash: {}", e);
            error!(TARGET_SUBJECT, error);
            ActorError::Functional(error)
        })?;

        self.last_event_hash = last_event_hash;
        self.sn += 1;

        Ok(())
    }
}

impl Storable for Subject {}

#[cfg(test)]
mod tests {

    use std::{collections::HashSet, time::Instant};

    use super::*;

    use crate::{
        FactRequest,
        model::{
            event::Event as AveEvent, request::tests::create_start_request_mock,
        },
        node::NodeResponse,
        system::tests::create_system,
    };

    async fn create_subject_and_ledger_event(
        system: SystemRef,
        node_keys: KeyPair,
    ) -> (ActorRef<Subject>, ActorRef<LedgerEvent>, Signed<Ledger>) {
        let node_actor = system
            .create_root_actor("node", Node::initial(node_keys.clone()))
            .await
            .unwrap();
        let request = create_start_request_mock("issuer", node_keys.clone());
        let event = AveEvent::from_create_request(
            &request,
            0,
            &Governance::new(node_keys.public_key())
                .to_value_wrapper()
                .unwrap(),
        )
        .unwrap();
        let ledger = Ledger::from(event.clone());
        let signature_ledger =
            Signature::new(&ledger, &node_keys.clone()).unwrap();
        let signed_ledger = Signed {
            content: ledger,
            signature: signature_ledger,
        };

        let signature_event = Signature::new(&event, &node_keys).unwrap();

        let signed_event = Signed {
            content: event,
            signature: signature_event,
        };

        let response = node_actor
            .ask(NodeMessage::CreateNewSubjectLedger(SignedLedger(
                signed_ledger.clone(),
            )))
            .await
            .unwrap();

        let NodeResponse::SonWasCreated = response else {
            panic!("Invalid response");
        };

        let subject_actor = system
            .get_actor(&ActorPath::from(format!(
                "user/node/{}",
                signed_ledger.content.subject_id
            )))
            .await
            .unwrap();

        let ledger_event_actor: Option<ActorRef<LedgerEvent>> = system
            .get_actor(&ActorPath::from(format!(
                "user/node/{}/ledger_event",
                signed_ledger.content.subject_id
            )))
            .await;

        let ledger_event_actor = if let Some(actor) = ledger_event_actor {
            actor
        } else {
            panic!("Actor must be in system actor");
        };

        ledger_event_actor
            .ask(LedgerEventMessage::UpdateLastEvent {
                event: Box::new(signed_event),
            })
            .await
            .unwrap();

        let response = subject_actor
            .ask(SubjectMessage::UpdateLedger {
                events: vec![SignedLedger(signed_ledger.clone())],
            })
            .await
            .unwrap();

        if let SubjectResponse::UpdateResult(last_sn, _, _) = response {
            assert_eq!(last_sn, 0);
        } else {
            panic!("Invalid response");
        }

        (subject_actor, ledger_event_actor, signed_ledger)
    }

    fn create_n_fact_events(
        mut hash_prev_event: DigestIdentifier,
        n: u64,
        keys: KeyPair,
        subject_id: DigestIdentifier,
        mut subject_properties: Value,
    ) -> Vec<SignedLedger> {
        let mut vec = vec![];

        for i in 0..n {
            let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                .public_key()
                .to_string();
            let patch_event_req = json!(
                    [{"op":"add","path": format!("/members/AveNode{}", i),"value": key},
                    {
                        "op": "add",
                        "path": "/version",
                        "value": i
                    }]
            );

            let event_req = EventRequest::Fact(FactRequest {
                subject_id: subject_id.clone(),
                payload: ValueWrapper(patch_event_req.clone()),
            });

            let signature_event_req =
                Signature::new(&event_req, &keys).unwrap();

            let signed_event_req = Signed {
                content: event_req,
                signature: signature_event_req,
            };

            let patch_json =
                serde_json::from_value::<Patch>(patch_event_req.clone())
                    .unwrap();
            patch(&mut subject_properties, &patch_json).unwrap();

            let state_hash = hash_borsh(
                &Blake3Hasher,
                &ValueWrapper(subject_properties.clone()),
            )
            .unwrap();

            let ledger = Ledger {
                subject_id: subject_id.clone(),
                event_request: signed_event_req,
                sn: i + 1,
                gov_version: i,
                value: LedgerValue::Patch(ValueWrapper(patch_event_req)),
                state_hash,
                eval_success: Some(true),
                appr_required: true,
                appr_success: Some(true),
                vali_success: true,
                hash_prev_event: hash_prev_event.clone(),
            };

            let signature_ledger = Signature::new(&ledger, &keys).unwrap();

            let signed_ledger = Signed {
                content: ledger,
                signature: signature_ledger,
            };

            hash_prev_event =
                hash_borsh(&Blake3Hasher, &signed_ledger).unwrap();
            vec.push(SignedLedger(signed_ledger));
        }

        vec
    }

    impl AveEvent {
        pub fn from_create_request(
            request: &Signed<EventRequest>,
            governance_version: u64,
            init_state: &ValueWrapper,
        ) -> Result<Self, Error> {
            let EventRequest::Create(_start_request) = &request.content else {
                panic!("Invalid Event Request")
            };

            let state_hash = hash_borsh(&Blake3Hasher, init_state).unwrap();
            let subject_id = hash_borsh(&Blake3Hasher, request).unwrap();

            Ok(AveEvent {
                subject_id,
                event_request: request.clone(),
                sn: 0,
                gov_version: governance_version,
                value: LedgerValue::Patch(init_state.clone()),
                state_hash,
                eval_success: None,
                appr_required: false,
                hash_prev_event: DigestIdentifier::default(),
                evaluators: None,
                approvers: None,
                appr_success: None,
                vali_success: true,
                validators: HashSet::new(),
            })
        }
    }

    use ave_actors::SystemRef;
    use ave_common::identity::{
        Blake3Hasher, KeyPair, KeyPairAlgorithm, Signature, keys::Ed25519Signer,
    };
    use event::LedgerEventMessage;
    use serde_json::{Value, json};
    use test_log::test;

    #[test]
    fn test_serialize_deserialize() {
        let node_keys = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

        let value = Governance::new(node_keys.public_key())
            .to_value_wrapper()
            .unwrap();

        let request = create_start_request_mock("issuer", node_keys.clone());
        let event = AveEvent::from_create_request(&request, 0, &value).unwrap();

        let ledger = Ledger::from(event);

        let signature = Signature::new(&ledger, &node_keys).unwrap();
        let signed_ledger = Signed {
            content: ledger,
            signature,
        };

        let subject_a = Subject::from_event(
            &signed_ledger,
            Governance::new(signed_ledger.signature.signer.clone())
                .to_value_wrapper()
                .unwrap(),
        )
        .unwrap();

        let bytes = borsh::to_vec(&subject_a).unwrap();
        let subject_b: Subject = borsh::from_slice(&bytes).unwrap();
        assert_eq!(subject_a.subject_id, subject_b.subject_id);
    }

    #[test(tokio::test)]
    async fn test_get_events() {
        let (system, ..) = create_system().await;
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

        let (subject_actor, _ledger_event_actor, _signed_ledger) =
            create_subject_and_ledger_event(system, node_keys.clone()).await;

        let response = subject_actor
            .ask(SubjectMessage::GetLedger { last_sn: 0 })
            .await
            .unwrap();
        if let SubjectResponse::Ledger {
            ledger, last_event, ..
        } = response
        {
            assert!(ledger.len() == 1);
            last_event.unwrap();
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(SubjectMessage::GetMetadata)
            .await
            .unwrap();

        if let SubjectResponse::Metadata(metadata) = response {
            assert_eq!(metadata.sn, 0);
        } else {
            panic!("Invalid response");
        }
    }

    #[test(tokio::test)]
    async fn test_1000_events() {
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let (system, ..) = create_system().await;

        let (subject_actor, _ledger_event_actor, signed_ledger) =
            create_subject_and_ledger_event(system, node_keys.clone()).await;

        let res = subject_actor
            .ask(SubjectMessage::GetMetadata)
            .await
            .unwrap();
        let SubjectResponse::Metadata(metadata) = res else {
            panic!("Invalid response")
        };

        let hash_pre_event = hash_borsh(&Blake3Hasher, &signed_ledger).unwrap();

        let inicio = Instant::now();
        let response = subject_actor
            .ask(SubjectMessage::UpdateLedger {
                events: create_n_fact_events(
                    hash_pre_event,
                    1000,
                    node_keys,
                    metadata.subject_id,
                    metadata.properties.0,
                ),
            })
            .await
            .unwrap();
        let duracion = inicio.elapsed();
        println!("El método tardó: {:.2?}", duracion);

        if let SubjectResponse::UpdateResult(last_sn, _, _) = response {
            assert_eq!(last_sn, 1000);
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(SubjectMessage::GetMetadata)
            .await
            .unwrap();

        if let SubjectResponse::Metadata(metadata) = response {
            assert_eq!(metadata.sn, 1000);
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(SubjectMessage::GetGovernance)
            .await
            .unwrap();

        if let SubjectResponse::Governance(gov) = response {
            assert_eq!(gov.version, 1000);
        } else {
            panic!("Invalid response");
        }
    }
}
