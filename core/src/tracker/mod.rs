use crate::{
    Error, EventRequestType,
    auth::WitnessesAuth,
    db::Storable,
    distribution::{Distribution, DistributionType},
    evaluation::Evaluation,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData,
        model::CreatorQuantity, relationship::{OwnerSchema, RelationShip, RelationShipMessage, RelationShipResponse},
    },
    helpers::{db::ExternalDB, sink::AveSink},
    model::{
        Namespace,
        common::{
            emit_fail, get_last_event, get_n_events, get_node_key, node::try_to_update, purge_storage, subject::{get_gov, get_last_state}
        },
        event::{Ledger, LedgerValue},
        request::EventRequest,
    },
    node::register::RegisterMessage,
    subject::{
        CreateSubjectData, DataForSink, LastStateData,
        Metadata, SignedLedger, Subject, SubjectMetadata, VerifyData,
        laststate::LastState, sinkdata::{SinkData, SinkDataMessage},
    },
    update::TransferResponse,
    validation::Validation,
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction,
    Handler, Message, Response, Sink,
};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed, hash_borsh},
};

use async_trait::async_trait;
use ave_actors::{
    FullPersistence, PersistentActor,
};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

const TARGET_TRACKER: &str = "Ave-Tracker";

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Clone,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Tracker {
    pub subject_metadata: SubjectMetadata,
    pub governance_id: DigestIdentifier,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The version of the governance contract that created the subject.
    pub genesis_gov_version: u64,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

impl From<CreateSubjectData> for Tracker {
    fn from(value: CreateSubjectData) -> Self {
        Tracker {
            subject_metadata: SubjectMetadata::new(&value),
            governance_id: value.create_req.governance_id,
            genesis_gov_version: value.genesis_gov_version,
            namespace: value.create_req.namespace,
            properties: value.value,
        }
    }
}

#[async_trait]
impl Subject for Tracker {
        async fn delete_subject(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        
        self.delete_relation(ctx).await?;
        Self::delet_node_subject(ctx, &self.subject_metadata.subject_id.to_string()).await?;

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
                            TARGET_TRACKER,
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
                error!(TARGET_TRACKER, error);
                return Err(ActorError::Functional(error));
            }
        };

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
        let our_key = get_node_key(ctx).await?;
        let current_sn = self.subject_metadata.sn;

        let i_current_new_owner =
            self.subject_metadata.new_owner.clone() == Some(our_key.clone());
        let current_owner = self.subject_metadata.owner.clone();

        if let Err(e) = self.verify_new_ledger_events_not_gov(ctx, events).await
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

        if current_sn < self.subject_metadata.sn {
            if !self.subject_metadata.active && current_owner == our_key {
                Self::down_owner_not_gov(ctx).await?;
            }

            let i_new_owner = self.subject_metadata.new_owner.clone()
                == Some(our_key.clone());

            // Si antes no eramos el new owner y ahora somos el new owner.
            if !i_current_new_owner && i_new_owner && current_owner != our_key {
                Self::up_owner_not_gov(ctx, &our_key).await?;
            }

            // Si cambió el dueño
            if current_owner != self.subject_metadata.owner {
                // Si ahora somos el dueño pero no eramos new owner.
                if self.subject_metadata.owner == our_key
                    && !i_current_new_owner
                {
                    Self::up_owner_not_gov(ctx, &our_key).await?;
                } else if current_owner == our_key && !i_new_owner {
                    Self::down_owner_not_gov(ctx).await?;
                }
            } else if i_current_new_owner && !i_new_owner {
                Self::down_owner_not_gov(ctx).await?;
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

impl Tracker {
    pub fn from_create_event(
        ledger: &Signed<Ledger>,
        properties: ValueWrapper,
    ) -> Result<Self, Error> {
        if let EventRequest::Create(request) =
            &ledger.content.event_request.content
        {
            Ok(Tracker {
                subject_metadata: SubjectMetadata::from_create_request(
                    ledger.content.subject_id.clone(),
                    request,
                    ledger.content.event_request.signature.signer.clone(),
                    DigestIdentifier::default(),
                ),
                governance_id: request.governance_id.clone(),
                namespace: request.namespace.clone(),
                genesis_gov_version: ledger.content.gov_version,
                properties,
            })
        } else {
            Err(Error::Tracker("Invalid create event request".to_string()))
        }
    }

    async fn build_childs_all_schemas(
        &self,
        ctx: &mut ActorContext<Tracker>,
        our_key: PublicKey,
    ) -> Result<(), ActorError> {
        let owner = our_key == self.subject_metadata.owner;
        let new_owner = self.subject_metadata.new_owner.is_some();
        let i_new_owner =
            self.subject_metadata.new_owner == Some(our_key.clone());

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
        ctx: &mut ActorContext<Self>,
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
        ctx: &mut ActorContext<Tracker>,
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

    async fn verify_new_ledger_events_not_gov(
        &mut self,
        ctx: &mut ActorContext<Tracker>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let mut iter = events.into_iter();
        let last_ledger = get_last_event(ctx).await?;

        let gov = get_gov(ctx, &self.governance_id.to_string()).await?;

        let Some(first) = iter.next() else {
            return Ok(());
        };

        let Some(max_quantity) = gov.max_creations(
            &first.signature.signer,
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
                self.subject_metadata.owner.clone(),
                &first,
            )
            .await
            {
                self.delete_subject(ctx,).await?;

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

        pending.extend(iter);

        for event in pending {
            let last_event_is_ok = match Self::verify_new_ledger_event(
                VerifyData {
                    active: self.subject_metadata.active,
                    owner: self.subject_metadata.owner.clone(),
                    new_owner: self.subject_metadata.new_owner.clone(),
                    is_gov: self.subject_metadata.schema_id.is_gov(),
                    properties: self.properties.clone(),
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

            if last_event_is_ok {
                match event.content.event_request.content.clone() {
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
                            event.signature.signer.to_string(),
                            max_quantity.clone(),
                        )
                        .await?;

                        Tracker::change_node_subject(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                            &event.signature.signer.to_string(),
                            &self.subject_metadata.owner.to_string(),
                        )
                        .await?;

                        self.delete_relation(ctx).await?;

                        Tracker::transfer_register(
                            ctx,
                            &self.subject_metadata.subject_id.to_string(),
                            event.signature.signer.clone(),
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
                            .content
                            .event_request
                            .signature
                            .signer
                            .to_string(),
                    },
                    &event.content.event_request.content,
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
            self.governance_id.to_string()
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
            self.governance_id.to_string()
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
    GetGovernance,
    GetOwner,
    DeleteTracker,
}

impl Message for TrackerMessage {}

#[derive(Debug, Clone)]
pub enum TrackerResponse {
    /// The subject metadata.
    Metadata(Box<Metadata>),
    UpdateResult(u64, PublicKey, Option<PublicKey>),
    Ledger {
        ledger: Vec<SignedLedger>,
        last_state: Option<LastStateData>,
    },
    Governance(Box<GovernanceData>),
    Owner(PublicKey),
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
            self.build_childs_all_schemas(ctx, our_key.clone()).await?;
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
impl Handler<Tracker> for Tracker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TrackerMessage,
        ctx: &mut ActorContext<Tracker>,
    ) -> Result<TrackerResponse, ActorError> {
        match msg {
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
            TrackerMessage::DeleteTracker => {
                self.delete_subject(ctx).await?;
                Ok(TrackerResponse::Ok)
            }
            TrackerMessage::GetLedger { last_sn } => {
                let (ledger, last_state) =
                    self.get_ledger_data(ctx, last_sn).await?;
                Ok(TrackerResponse::Ledger { ledger, last_state })
            }
            TrackerMessage::GetLastLedger => {
                let (ledger, last_state) =
                    self.get_ledger_data(ctx, self.subject_metadata.sn).await?;
                Ok(TrackerResponse::Ledger { ledger, last_state })
            }
            TrackerMessage::GetOwner => {
                Ok(TrackerResponse::Owner(self.subject_metadata.owner.clone()))
            }
            TrackerMessage::GetMetadata => {
                Ok(TrackerResponse::Metadata(Box::new(Metadata::from(self.clone()))))
            }
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
            false,
        ) {
            Ok(is_ok) => is_ok,
            Err(e) => {
                let error =
                    format!("Apply, can not verify protocols state: {}", e);
                error!(TARGET_TRACKER, error);
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
                        error!(TARGET_TRACKER, error);
                        ActorError::Functional(error)
                    })?;

                    let properties = if let LedgerValue::Patch(init_state) =
                        event.content.value.clone()
                    {
                        init_state
                    } else {
                        let e = "Can not create subject, ledgerValue is not a patch";
                        return Err(ActorError::Functional(e.to_string()));
                    };

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
                    self.genesis_gov_version = event.content.gov_version;
                    self.namespace = create_event.namespace.clone();
                    self.governance_id = create_event.governance_id.clone();
                    self.properties = properties;

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
                    let Some(new_owner) =
                        self.subject_metadata.new_owner.clone()
                    else {
                        let error = "In confirm event was succefully but new owner is empty:";
                        error!(TARGET_TRACKER, error);
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
        }

        let last_event_hash = hash_borsh(
            &*event.signature.content_hash.algorithm().hasher(),
            &event,
        )
        .map_err(|e| {
            let error = format!("Apply, can not obtain last event hash: {}", e);
            error!(TARGET_TRACKER, error);
            ActorError::Functional(error)
        })?;

        self.subject_metadata.last_event_hash = last_event_hash;
        self.subject_metadata.sn += 1;

        Ok(())
    }
}

impl Storable for Tracker {}
