use std::sync::Arc;

use crate::{
    Error, EventRequestType,
    auth::WitnessesAuth,
    db::Storable,
    distribution::{Distribution, DistributionType},
    evaluation::Evaluation,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData,
        model::CreatorQuantity,
        relationship::{
            OwnerSchema, RelationShip, RelationShipMessage,
            RelationShipResponse,
        },
    },
    helpers::{db::ExternalDB, sink::AveSink},
    model::{
        common::{
            emit_fail, get_last_event, get_n_events, node::try_to_update,
            purge_storage, subject::get_gov,
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
    validation::request::LastData,
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, Response, Sink,
};
use ave_common::{
    Namespace, ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey, hash_borsh},
    request::EventRequest,
};

use async_trait::async_trait;
use ave_actors::{FullPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

const TARGET_TRACKER: &str = "Ave-Tracker";

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct Tracker {
    #[serde(skip)]
    pub our_key: Arc<PublicKey>,

    pub subject_metadata: SubjectMetadata,
    pub governance_id: DigestIdentifier,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The version of the governance contract that created the subject.
    pub genesis_gov_version: u64,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

#[derive(Default)]
pub struct TrackerInit {
    pub subject_metadata: SubjectMetadata,
    pub governance_id: DigestIdentifier,
    pub namespace: Namespace,
    pub genesis_gov_version: u64,
    pub properties: ValueWrapper,
}

impl BorshSerialize for Tracker {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the fields we want to persist, skipping 'owner'
        BorshSerialize::serialize(&self.subject_metadata, writer)?;
        BorshSerialize::serialize(&self.governance_id, writer)?;
        BorshSerialize::serialize(&self.namespace, writer)?;
        BorshSerialize::serialize(&self.genesis_gov_version, writer)?;
        BorshSerialize::serialize(&self.properties, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for Tracker {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let subject_metadata = SubjectMetadata::deserialize_reader(reader)?;
        let governance_id = DigestIdentifier::deserialize_reader(reader)?;
        let namespace = Namespace::deserialize_reader(reader)?;
        let genesis_gov_version = u64::deserialize_reader(reader)?;
        let properties = ValueWrapper::deserialize_reader(reader)?;

        // Create a default/placeholder KeyPair for 'owner'
        // This will be replaced by the actual owner during actor initialization
        let our_key = Arc::new(PublicKey::default());

        Ok(Self {
            our_key,
            subject_metadata,
            governance_id,
            namespace,
            genesis_gov_version,
            properties,
        })
    }
}

#[async_trait]
impl Subject for Tracker {
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
                error!(TARGET_TRACKER, error);
                return Err(ActorError::Functional(error));
            }
        };

        if let Err(e) = patch(&mut self.properties.0, &patch_json) {
            let error = format!("Apply, can not apply json patch: {}", e);
            error!(TARGET_TRACKER, error);
            return Err(ActorError::Functional(error));
        };

        Ok(())
    }

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let hash = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.hash_algorithm
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        let current_sn = self.subject_metadata.sn;

        if let Err(e) = self.verify_new_ledger_events(ctx, events, &hash).await
        {
            if let ActorError::Functional(error) = e.clone() {
                warn!(TARGET_TRACKER, "Error verifying new events: {}", error);

                // Falló en la creación
                if self.subject_metadata.sn == 0 {
                    return Err(e);
                }
            } else {
                error!(TARGET_TRACKER, "Error verifying new events {}", e);
                return Err(e);
            }
        };

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

impl Tracker {
    async fn get_governance(
        &self,
        ctx: &mut ActorContext<Tracker>,
    ) -> Result<GovernanceData, ActorError> {
        let governance_path =
            ActorPath::from(format!("/user/node/{}", self.governance_id));

        let governance_actor: Option<ActorRef<Governance>> =
            ctx.system().get_actor(&governance_path).await;

        let response = if let Some(governance_actor) = governance_actor {
            governance_actor
                .ask(GovernanceMessage::GetGovernance)
                .await?
        } else {
            return Err(ActorError::NotFound(governance_path));
        };

        match response {
            GovernanceResponse::Governance(gov) => Ok(*gov),
            _ => Err(ActorError::UnexpectedResponse(
                governance_path,
                "TrackerResponse::Governance".to_owned(),
            )),
        }
    }

    async fn verify_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Tracker>,
        events: Vec<SignedLedger>,
        hash: &HashAlgorithm,
    ) -> Result<(), ActorError> {
        let mut iter = events.into_iter();
        let last_ledger = get_last_event(ctx).await?;

        let gov = get_gov(ctx, &self.governance_id.to_string()).await?;

        let Some(first) = iter.next() else {
            return Ok(());
        };

        let Some(max_quantity) = gov.max_creations(
            &first.signature().signer,
            self.subject_metadata.schema_id.clone(),
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
                self.subject_metadata.owner.to_string(),
                max_quantity.clone(),
            )
            .await?;

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
                RegisterMessage::RegisterSubj {
                    gov_id: self.governance_id.to_string(),
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    name: self.subject_metadata.name.clone(),
                    description: self.subject_metadata.description.clone(),
                },
            )
            .await?;

            Self::event_to_sink(
                ctx,
                DataForSink {
                    gov_id: Some(self.governance_id.to_string()),
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    sn: self.subject_metadata.sn,
                    owner: self.subject_metadata.owner.to_string(),
                    namespace: self.namespace.to_string(),
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

        pending.extend(iter);

        for event in pending {
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

            if last_event_is_ok {
                match event.content().event_request.content().clone() {
                    EventRequest::Transfer(transfer_request) => {
                        Tracker::new_transfer_subject(
                            ctx,
                            self.subject_metadata.name.clone(),
                            &transfer_request.subject_id.to_string(),
                            &transfer_request.new_owner.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;
                    }
                    EventRequest::Reject(reject_request) => {
                        Tracker::reject_transfer_subject(
                            ctx,
                            &reject_request.subject_id.to_string(),
                        )
                        .await?;
                    }
                    EventRequest::Confirm(confirm_request) => {
                        self.register_relation(
                            ctx,
                            event.signature().signer.to_string(),
                            max_quantity.clone(),
                        )
                        .await?;

                        Tracker::change_node_subject(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                            &event.signature().signer.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;

                        self.delete_relation(ctx).await?;

                        Tracker::transfer_register(
                            ctx,
                            &self.subject_metadata.subject_id.to_string(),
                            event.signature().signer.clone(),
                            self.subject_metadata.owner.clone(),
                        )
                        .await?;
                    }
                    EventRequest::EOL(_eolrequest) => {
                        Self::register(
                            ctx,
                            RegisterMessage::EOLSubj {
                                gov_id: self.governance_id.to_string(),
                                subj_id: self
                                    .subject_metadata
                                    .subject_id
                                    .to_string(),
                            },
                        )
                        .await?
                    }
                    _ => {}
                };

                Self::event_to_sink(
                    ctx,
                    DataForSink {
                        gov_id: Some(self.governance_id.to_string()),
                        subject_id: self
                            .subject_metadata
                            .subject_id
                            .to_string(),
                        sn: self.subject_metadata.sn,
                        owner: self.subject_metadata.owner.to_string(),
                        namespace: self.namespace.to_string(),
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
        ctx: &mut ActorContext<Self>,
        owner: String,
        max_quantity: CreatorQuantity,
    ) -> Result<(), ActorError> {
        let relation_path = ActorPath::from(&format!(
            "/user/node/{}/relation_ship",
            self.governance_id
        ));
        let relation_actor: Option<ActorRef<RelationShip>> =
            ctx.system().get_actor(&relation_path).await;

        let response = if let Some(relation_actor) = relation_actor {
            relation_actor
                .ask(RelationShipMessage::RegisterNewSubject {
                    data: OwnerSchema {
                        owner,
                        schema_id: self.subject_metadata.schema_id.clone(),
                        namespace: self.namespace.to_string(),
                    },
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    max_quantity,
                })
                .await?
        } else {
            return Err(ActorError::NotFound(relation_path));
        };

        match response {
            RelationShipResponse::None => Ok(()),
            _ => Err(ActorError::UnexpectedResponse(
                relation_path,
                "RelationShipResponse::None".to_owned(),
            )),
        }
    }

    pub async fn delete_relation(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let relation_path = ActorPath::from(&format!(
            "/user/node/{}/relation_ship",
            self.governance_id
        ));
        let relation_actor: Option<ActorRef<RelationShip>> =
            ctx.system().get_actor(&relation_path).await;

        let response = if let Some(relation_actor) = relation_actor {
            relation_actor
                .ask(RelationShipMessage::DeleteSubject {
                    data: OwnerSchema {
                        owner: self.subject_metadata.owner.to_string(),
                        schema_id: self.subject_metadata.schema_id.clone(),
                        namespace: self.namespace.to_string(),
                    },
                    subject_id: self.subject_metadata.subject_id.to_string(),
                })
                .await?
        } else {
            return Err(ActorError::NotFound(relation_path));
        };

        if let RelationShipResponse::None = response {
            Ok(())
        } else {
            Err(ActorError::UnexpectedResponse(
                relation_path,
                "RelationShipResponse::None".to_owned(),
            ))
        }
    }
}

#[derive(Debug, Clone)]
pub enum TrackerMessage {
    UpdateTransfer(TransferResponse),
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

impl Message for TrackerMessage {}

#[derive(Debug, Clone)]
pub enum TrackerResponse {
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
    Sn(u64),
    Ok,
}
impl Response for TrackerResponse {}

#[async_trait]
impl Actor for Tracker {
    type Event = SignedLedger;
    type Message = TrackerMessage;
    type Response = TrackerResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("tracker", None, true, ctx).await?;

        let our_key = self.our_key.clone();

        if self.subject_metadata.active {
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

            let sink_actor = ctx
                .create_child(
                    "sink_data",
                    SinkData {
                        controller_id: our_key.to_string(),
                    },
                )
                .await?;
            let sink =
                Sink::new(sink_actor.subscribe(), ext_db.get_sink_data());
            ctx.system().run_sink(sink).await;

            let sink = Sink::new(sink_actor.subscribe(), ave_sink.clone());
            ctx.system().run_sink(sink).await;
        }

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
impl Handler<Tracker> for Tracker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TrackerMessage,
        ctx: &mut ActorContext<Tracker>,
    ) -> Result<TrackerResponse, ActorError> {
        match msg {
            TrackerMessage::GetLastSn => {
                Ok(TrackerResponse::Sn(self.subject_metadata.sn))
            }
            TrackerMessage::UpdateTransfer(res) => {
                match res {
                    TransferResponse::Confirm => {
                        let Some(new_owner) =
                            self.subject_metadata.new_owner.clone()
                        else {
                            let e = "Can not obtain new_owner";
                            error!(TARGET_TRACKER, "Confirm, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        };

                        Tracker::change_node_subject(
                            ctx,
                            &self.subject_metadata.subject_id.to_string(),
                            &new_owner.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;

                        self.delete_relation(ctx).await?;
                    }
                    TransferResponse::Reject => {
                        Tracker::reject_transfer_subject(
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

                Ok(TrackerResponse::Ok)
            }
            TrackerMessage::GetLedger { last_sn } => {
                let ledger = self.get_ledger(ctx, last_sn).await?;
                Ok(TrackerResponse::Ledger { ledger })
            }
            TrackerMessage::GetLastLedger => {
                let ledger_event = self.get_last_ledger(ctx).await?;
                Ok(TrackerResponse::LastLedger { ledger_event })
            }
            TrackerMessage::GetMetadata => Ok(TrackerResponse::Metadata(
                Box::new(Metadata::from(self.clone())),
            )),
            TrackerMessage::UpdateLedger { events } => {
                if let Err(e) =
                    self.manager_new_ledger_events(ctx, events).await
                {
                    warn!(
                        TARGET_TRACKER,
                        "UpdateLedger, can not verify new events: {}", e
                    );
                    return Err(e);
                };
                Ok(TrackerResponse::UpdateResult(
                    self.subject_metadata.sn,
                    self.subject_metadata.owner.clone(),
                    self.subject_metadata.new_owner.clone(),
                ))
            }
            TrackerMessage::GetGovernance => {
                return Ok(TrackerResponse::Governance(Box::new(
                    self.get_governance(ctx).await?,
                )));
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SignedLedger,
        ctx: &mut ActorContext<Tracker>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_TRACKER,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event).await {
            error!(
                TARGET_TRACKER,
                "PublishEvent, can not publish event: {}", e
            );
            emit_fail(ctx, e).await;
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Tracker>,
    ) -> ChildAction {
        error!(TARGET_TRACKER, "OnChildFault, {}", error);
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for Tracker {
    type Persistence = FullPersistence;
    type InitParams = (Option<TrackerInit>, PublicKey);

    fn update(&mut self, state: Self) {
        self.properties = state.properties;
        self.governance_id = state.governance_id;
        self.namespace = state.namespace;
        self.genesis_gov_version = state.genesis_gov_version;
        self.subject_metadata = state.subject_metadata;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        let init = params.0.unwrap_or_default();

        Self {
            our_key: params.1,
            subject_metadata: init.subject_metadata,
            properties: init.properties,
            genesis_gov_version: init.genesis_gov_version,
            governance_id: init.governance_id,
            namespace: init.namespace,
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
                    self.properties = metadata.properties.clone();
                } else {
                    todo!()
                }

                return Ok(());
            }
            (
                EventRequest::Fact(..),
                Protocols::TrackerFact { evaluation, .. },
            ) => {
                if let Some(eval_res) = evaluation.evaluator_res() {
                    self.apply_patch(eval_res.patch)?;
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
            (EventRequest::Confirm(..), Protocols::TrackerConfirm { .. }) => {
                if let Some(new_owner) = self.subject_metadata.new_owner.take()
                {
                    self.subject_metadata.owner = new_owner;
                } else {
                    todo!()
                }
            }
            (EventRequest::Reject(..), Protocols::Reject { .. }) => {
                self.subject_metadata.new_owner = None;
            }
            (EventRequest::EOL(..), Protocols::EOL { .. }) => {
                self.subject_metadata.active = false
            }
            _ => todo!("gov events es un tracker esto"),
        }

        self.subject_metadata.sn += 1;
        self.subject_metadata.prev_ledger_event_hash =
            event.content().prev_ledger_event_hash.clone();

        Ok(())
    }
}

impl Storable for Tracker {}
