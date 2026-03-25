use std::sync::Arc;

use crate::{
    db::Storable,
    governance::{
        sn_register::{SnRegister, SnRegisterMessage},
        subject_register::{SubjectRegister, SubjectRegisterMessage},
        witnesses_register::{WitnessesRegister, WitnessesRegisterMessage},
    },
    helpers::{db::ExternalDB, sink::AveSink},
    model::{
        common::{emit_fail, get_last_event, purge_storage},
        event::{Protocols, ValidationMetadata},
    },
    node::{Node, NodeMessage, TransferSubject, register::RegisterMessage},
    subject::{
        DataForSink, EventLedgerDataForSink, Metadata, SignedLedger, Subject,
        SubjectMetadata,
        error::SubjectError,
        sinkdata::{SinkData, SinkDataMessage},
    },
    validation::request::LastData,
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    Response, Sink,
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
use tracing::{Span, debug, error, info_span, warn};

#[derive(Default, Debug, Serialize, Deserialize, Clone)]
pub struct Tracker {
    #[serde(skip)]
    pub our_key: Arc<PublicKey>,
    #[serde(skip)]
    pub service: bool,
    #[serde(skip)]
    pub hash: Option<HashAlgorithm>,

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

impl From<&Metadata> for TrackerInit {
    fn from(value: &Metadata) -> Self {
        Self {
            subject_metadata: SubjectMetadata::new(value),
            governance_id: value.governance_id.clone(),
            namespace: value.namespace.clone(),
            genesis_gov_version: value.genesis_gov_version,
            properties: value.properties.clone(),
        }
    }
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
        let hash = None;

        Ok(Self {
            service: false,
            hash,
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
    async fn update_sn(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        witnesses_register
            .tell(WitnessesRegisterMessage::UpdateSn {
                subject_id: self.subject_metadata.subject_id.clone(),
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
        gov_version: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::RejectTransfer(
            self.subject_metadata.subject_id.clone(),
        ))
        .await?;

        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        witnesses_register
            .tell(WitnessesRegisterMessage::Reject {
                subject_id: self.subject_metadata.subject_id.clone(),
                sn: self.subject_metadata.sn + 1,
                gov_version,
            })
            .await
    }

    async fn confirm(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::ConfirmTransfer(
            self.subject_metadata.subject_id.clone(),
        ))
        .await?;

        if self.service || *self.our_key == self.subject_metadata.owner {
            let subject_register = ctx
                .system()
                .get_actor::<SubjectRegister>(&ActorPath::from(&format!(
                    "/user/node/subject_manager/{}/subject_register",
                    self.governance_id
                )))
                .await?;

            let _response = subject_register
                .ask(SubjectRegisterMessage::UpdateSubject {
                    new_owner,
                    old_owner: self.subject_metadata.owner.clone(),
                    subject_id: self.subject_metadata.subject_id.clone(),
                    namespace: self.namespace.to_string(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    gov_version,
                })
                .await?;
        }

        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        witnesses_register
            .tell(WitnessesRegisterMessage::Confirm {
                subject_id: self.subject_metadata.subject_id.clone(),
                sn: self.subject_metadata.sn + 1,
                gov_version,
            })
            .await
    }

    async fn transfer(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        node.tell(NodeMessage::TransferSubject(TransferSubject {
            name: self.subject_metadata.name.clone(),
            subject_id: self.subject_metadata.subject_id.clone(),
            new_owner: new_owner.clone(),
            actual_owner: self.subject_metadata.owner.clone(),
        }))
        .await?;

        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        witnesses_register
            .tell(WitnessesRegisterMessage::Transfer {
                subject_id: self.subject_metadata.subject_id.clone(),
                new_owner,
                gov_version,
            })
            .await
    }

    async fn get_last_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Option<SignedLedger>, ActorError> {
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

        patch(&mut self.properties.0, &patch_json).map_err(|e| {
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

        debug!(
            subject_id = %self.subject_metadata.subject_id,
            "Patch applied successfully"
        );

        Ok(())
    }

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError> {
        let Some(hash) = self.hash else {
            return Err(ActorError::FunctionalCritical {
                description: "Can not obtain Hash".to_string(),
            });
        };

        let current_sn = self.subject_metadata.sn;

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

        if current_sn < self.subject_metadata.sn || current_sn == 0 {
            Self::publish_sink(
                ctx,
                SinkDataMessage::UpdateState(Box::new(Metadata::from(
                    self.clone(),
                ))),
            )
            .await?;

            self.update_sn(ctx).await?;
        }

        Ok(())
    }
}

impl Tracker {
    async fn create(
        &self,
        ctx: &ActorContext<Self>,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        let sn_register = ctx
            .system()
            .get_actor::<SnRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/sn_register",
                self.governance_id
            )))
            .await?;

        sn_register
            .tell(SnRegisterMessage::RegisterSn {
                subject_id: self.subject_metadata.subject_id.clone(),
                gov_version,
                sn: 0,
            })
            .await?;

        if self.service || *self.our_key == self.subject_metadata.owner {
            let subject_register = ctx
                .system()
                .get_actor::<SubjectRegister>(&ActorPath::from(&format!(
                    "/user/node/subject_manager/{}/subject_register",
                    self.governance_id
                )))
                .await?;

            let _response = subject_register
                .ask(SubjectRegisterMessage::CreateSubject {
                    creator: self.subject_metadata.owner.clone(),
                    subject_id: self.subject_metadata.subject_id.clone(),
                    namespace: self.namespace.to_string(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    gov_version,
                })
                .await?;
        }

        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;

        witnesses_register
            .tell(WitnessesRegisterMessage::Create {
                subject_id: self.subject_metadata.subject_id.clone(),
                gov_version,
                owner: self.subject_metadata.owner.clone(),
            })
            .await
    }

    async fn register_gov_version_sn(
        &self,
        ctx: &ActorContext<Self>,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        let sn_register = ctx
            .system()
            .get_actor::<SnRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/sn_register",
                self.governance_id
            )))
            .await?;

        sn_register
            .tell(SnRegisterMessage::RegisterSn {
                subject_id: self.subject_metadata.subject_id.clone(),
                gov_version,
                sn: self.subject_metadata.sn,
            })
            .await
    }

    async fn verify_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
        hash: &HashAlgorithm,
    ) -> Result<(), ActorError> {
        let mut iter = events.into_iter();
        let last_ledger = get_last_event(ctx).await?;

        let Some(first) = iter.next() else {
            return Ok(());
        };

        let mut pending = Vec::new();

        let mut last_ledger = if let Some(last_ledger) = last_ledger {
            pending.push(first);
            last_ledger
        } else {
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

            self.create(ctx, first.content().gov_version).await?;

            self.on_event(first.clone(), ctx).await;

            Self::register(
                ctx,
                RegisterMessage::RegisterSubj {
                    gov_id: self.governance_id.to_string(),
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    namespace: self.namespace.to_string(),
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
                    event_ledger_timestamp: first
                        .signature()
                        .timestamp
                        .as_nanos(),
                    event_request_timestamp: first
                        .content()
                        .event_request
                        .signature()
                        .timestamp
                        .as_nanos(),
                    gov_version: first.content().gov_version,
                    event_data_ledger: EventLedgerDataForSink::build(
                        &first.content().protocols,
                        &self.properties.0,
                    ),
                },
                first.content().event_request.content(),
            )
            .await?;

            first
        };

        pending.extend(iter);

        for event in pending {
            let actual_ledger_hash =
                hash_borsh(&*hash.hasher(), &last_ledger.0).map_err(|e| {
                    ActorError::FunctionalCritical {
                        description: format!(
                            "Can not creacte actual ledger event hash: {}",
                            e
                        ),
                    }
                })?;
            let last_data = LastData {
                gov_version: last_ledger.content().gov_version,
                vali_data: last_ledger
                    .content()
                    .protocols
                    .get_validation_data(),
            };

            let last_gov_version = last_data.gov_version;

            let last_event_is_ok = match Self::verify_new_ledger_event(
                ctx,
                &event,
                Metadata::from(self.clone()),
                actual_ledger_hash,
                last_data,
                hash,
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

            let event_gov_version = event.content().gov_version;

            if last_event_is_ok {
                if last_gov_version != event_gov_version {
                    self.register_gov_version_sn(ctx, last_gov_version).await?;
                }

                match event.content().event_request.content().clone() {
                    EventRequest::Transfer(transfer_request) => {
                        self.transfer(
                            ctx,
                            transfer_request.new_owner,
                            event.content().gov_version,
                        )
                        .await?;
                    }
                    EventRequest::Reject(..) => {
                        self.reject(ctx, event.content().gov_version).await?;
                    }
                    EventRequest::Confirm(..) => {
                        self.confirm(
                            ctx,
                            event.signature().signer.clone(),
                            event.content().gov_version,
                        )
                        .await?;
                    }
                    EventRequest::EOL(..) => {
                        self.eol(ctx).await?;

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
                        event_ledger_timestamp: event
                            .signature()
                            .timestamp
                            .as_nanos(),
                        event_request_timestamp: event
                            .content()
                            .event_request
                            .signature()
                            .timestamp
                            .as_nanos(),
                        gov_version: event.content().gov_version,
                        event_data_ledger: EventLedgerDataForSink::build(
                            &event.content().protocols,
                            &self.properties.0,
                        ),
                    },
                    event.content().event_request.content(),
                )
                .await?;
            }

            // Aplicar evento.
            self.on_event(event.clone(), ctx).await;

            // Registrar la gov_version del evento con el sn ya actualizado.
            // Necesario cuando varios eventos comparten la misma gov_version:
            // la transición (línea anterior) solo captura el sn antes del primer
            // evento del nuevo gov_version, pero no el sn final de ese tramo.
            self.register_gov_version_sn(ctx, event_gov_version).await?;

            // Actualizar último evento.
            last_ledger = event.clone();
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum TrackerMessage {
    GetMetadata,
    GetLedger { lo_sn: Option<u64>, hi_sn: u64 },
    GetLastLedger,
    PurgeStorage,
    UpdateLedger { events: Vec<SignedLedger> },
}

impl Message for TrackerMessage {}

#[derive(Debug, Clone)]
pub enum TrackerResponse {
    /// The subject metadata.
    Metadata(Box<Metadata>),
    UpdateResult(u64, PublicKey, Option<PublicKey>),
    Ledger {
        ledger: Vec<SignedLedger>,
        is_all: bool,
    },
    LastLedger {
        ledger_event: Box<Option<SignedLedger>>,
    },
    Sn(u64),
    Ok,
}
impl Response for TrackerResponse {}

#[async_trait]
impl Actor for Tracker {
    type Event = SignedLedger;
    type Message = TrackerMessage;
    type Response = TrackerResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Tracker", id),
            |parent_span| info_span!(parent: parent_span, "Tracker", id),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.init_store("tracker", None, true, ctx).await {
            error!(
                error = %e,
                "Failed to initialize tracker store"
            );
            return Err(e);
        }

        let Some(config): Option<crate::system::ConfigHelper> =
            ctx.system().get_helper("config").await
        else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if config.safe_mode {
            return Ok(());
        }

        let our_key = self.our_key.clone();

        if self.subject_metadata.active {
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

            let sink_actor = match ctx
                .create_child(
                    "sink_data",
                    SinkData {
                        public_key: our_key.to_string(),
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

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for Tracker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TrackerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<TrackerResponse, ActorError> {
        match msg {
            TrackerMessage::GetLedger { lo_sn, hi_sn } => {
                let (ledger, is_all) =
                    self.get_ledger(ctx, lo_sn, hi_sn).await?;
                Ok(TrackerResponse::Ledger { ledger, is_all })
            }
            TrackerMessage::GetLastLedger => {
                let ledger_event = self.get_last_ledger(ctx).await?;
                Ok(TrackerResponse::LastLedger {
                    ledger_event: Box::new(ledger_event),
                })
            }
            TrackerMessage::GetMetadata => Ok(TrackerResponse::Metadata(
                Box::new(Metadata::from(self.clone())),
            )),
            TrackerMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    subject_id = %self.subject_metadata.subject_id,
                    "Tracker storage purged"
                );

                Ok(TrackerResponse::Ok)
            }
            TrackerMessage::UpdateLedger { events } => {
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

                Ok(TrackerResponse::UpdateResult(
                    self.subject_metadata.sn,
                    self.subject_metadata.owner.clone(),
                    self.subject_metadata.new_owner.clone(),
                ))
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SignedLedger,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                error = %e,
                subject_id = %self.subject_metadata.subject_id,
                sn = self.subject_metadata.sn,
                "Failed to persist event"
            );
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event.clone()).await {
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
            subject_id = %self.subject_metadata.subject_id,
            sn = self.subject_metadata.sn,
            error = %error,
            "Child fault in tracker"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

pub struct InitParamsTracker {
    pub data: Option<TrackerInit>,
    pub public_key: Arc<PublicKey>,
    pub hash: HashAlgorithm,
    pub is_service: bool,
}

#[async_trait]
impl PersistentActor for Tracker {
    type Persistence = FullPersistence;
    type InitParams = InitParamsTracker;

    fn update(&mut self, state: Self) {
        self.properties = state.properties;
        self.governance_id = state.governance_id;
        self.namespace = state.namespace;
        self.genesis_gov_version = state.genesis_gov_version;
        self.subject_metadata = state.subject_metadata;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        let init = params.data.unwrap_or_default();

        Self {
            service: params.is_service,
            hash: Some(params.hash),
            our_key: params.public_key,
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
            (
                EventRequest::Fact(..),
                Protocols::TrackerFact { evaluation, .. },
            ) => {
                if let Some(eval_res) = evaluation.evaluator_res() {
                    self.apply_patch(eval_res.patch)?;
                    debug!(
                        event_type = "Fact",
                        subject_id = %self.subject_metadata.subject_id,
                        "Applied fact event with patch"
                    );
                }
            }
            (
                EventRequest::Transfer(transfer_request),
                Protocols::Transfer { evaluation, .. },
            ) => {
                if evaluation.evaluator_res().is_some() {
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
            (EventRequest::Confirm(..), Protocols::TrackerConfirm { .. }) => {
                if let Some(new_owner) = self.subject_metadata.new_owner.take()
                {
                    self.subject_metadata.owner = new_owner.clone();
                    debug!(
                        event_type = "Confirm",
                        subject_id = %self.subject_metadata.subject_id,
                        new_owner = %new_owner,
                        "Applied confirm event"
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
            (EventRequest::Reject(..), Protocols::Reject { .. }) => {
                self.subject_metadata.new_owner = None;
                debug!(
                    event_type = "Reject",
                    subject_id = %self.subject_metadata.subject_id,
                    "Applied reject event"
                );
            }
            (EventRequest::EOL(..), Protocols::EOL { .. }) => {
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
                    "Invalid protocol data for Tracker"
                );
                return Err(ActorError::Functional {
                    description:
                        "Protocols data is for Governance and this is a Tracker"
                            .to_owned(),
                });
            }
        }

        self.subject_metadata.sn += 1;
        self.subject_metadata.prev_ledger_event_hash =
            event.content().prev_ledger_event_hash.clone();

        Ok(())
    }
}

impl Storable for Tracker {}
