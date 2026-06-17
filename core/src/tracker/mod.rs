use std::{collections::BTreeSet, sync::Arc};

use crate::{
    db::Storable,
    governance::{
        sn_register::{SnRegister, SnRegisterMessage},
        subject_register::{SubjectRegister, SubjectRegisterMessage},

        witnesses_register::{
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        },
    },

    model::{
        common::{
            TrackerEventVisibility, TrackerStoredVisibility,
            TrackerVisibilityMode, TrackerVisibilityState, crash_system,
            get_last_event, purge_storage, remove_verified_transfer,
        },
        event::{Ledger, Protocols, ValidationMetadata},
    },
    node::{Node, NodeMessage, TransferSubject, register::RegisterMessage},
    sink::{SinkManager, SinkManagerMessage},
    subject::{
        DataForSink, EventLedgerDataForSink, Metadata, Subject,
        SubjectMetadata,
        error::SubjectError,
    },
    model::sink::{SinkDataEvent, SubjectSinkEvent},
    validation::request::LastData,
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    Response,
};
use ave_common::{
    DataToSink, Namespace, ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey},
    request::EventRequest,
    response::SubjectDB,
};

use async_trait::async_trait;
use ave_actors::{FullPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

#[derive(Debug, Serialize, Deserialize, Clone, BorshSerialize, BorshDeserialize)]
pub struct TrackerState {
    pub subject_metadata: SubjectMetadata,
    pub governance_id: DigestIdentifier,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The version of the governance contract that created the subject.
    pub genesis_gov_version: u64,
    pub visibility_mode: TrackerVisibilityMode,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

#[derive(Debug)]
pub struct Tracker {
    pub our_key: Arc<PublicKey>,
    pub service: bool,
    pub only_clear_events: bool,
    pub hash: Option<HashAlgorithm>,
    pub state: Arc<TrackerState>,
}

impl Clone for Tracker {
    fn clone(&self) -> Self {
        Self {
            our_key: self.our_key.clone(),
            service: self.service,
            only_clear_events: self.only_clear_events,
            hash: self.hash,
            state: self.state.clone(),
        }
    }
}

impl std::ops::Deref for Tracker {
    type Target = TrackerState;
    fn deref(&self) -> &TrackerState {
        &self.state
    }
}

impl std::ops::DerefMut for Tracker {
    fn deref_mut(&mut self) -> &mut TrackerState {
        Arc::make_mut(&mut self.state)
    }
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
            .await?;

        Ok(())
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

            let _ = subject_register
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
    ) -> Result<Option<Ledger>, ActorError> {
        get_last_event(ctx).await
    }

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<Ledger>,
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
            let subject_db = self.build_subject_db(ctx).await?;
            ctx.publish_all(SubjectSinkEvent::SinkData(SinkDataEvent::State(Box::new(subject_db))));

            self.update_sn(ctx).await?;
        }

        Ok(())
    }

    fn our_key(&self) -> std::sync::Arc<ave_common::identity::PublicKey> {
        self.our_key.clone()
    }

    async fn notify_reliable_sinks(
        &self,
        ctx: &mut ActorContext<Self>,
        data: DataToSink,
    ) -> Result<(), ActorError> {
        let gov_id = self.governance_id.to_string();
        let manager_path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/sink_manager",
            gov_id
        ));
        match ctx.system().get_actor::<SinkManager>(&manager_path).await {
            Ok(manager) => {
                if let Err(e) = manager
                    .tell(SinkManagerMessage::NotifyNewEvent(Arc::new(data)))
                    .await
                {
                    error!(error = %e, "Failed to notify SinkManager");
                }
            }
            Err(e) => {
                debug!(error = %e, path = %manager_path, "SinkManager not found");
            }
        }
        Ok(())
    }
}

impl TrackerState {
    const fn is_full(&self) -> bool {
        matches!(self.visibility_mode, TrackerVisibilityMode::Full)
    }

    fn apply_patch_inner(
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
}

impl Tracker {
    const fn public_visibilities()
    -> (TrackerStoredVisibility, TrackerEventVisibility) {
        (
            TrackerStoredVisibility::Full,
            TrackerEventVisibility::NonFact,
        )
    }

    fn fact_visibilities(
        viewpoints: &BTreeSet<String>,
        opaque: bool,
    ) -> (TrackerStoredVisibility, TrackerEventVisibility) {
        let event_visibility = TrackerEventVisibility::Fact(viewpoints.clone());

        let stored_visibility = if opaque {
            TrackerStoredVisibility::None
        } else if viewpoints.is_empty() {
            TrackerStoredVisibility::Full
        } else {
            TrackerStoredVisibility::Only(viewpoints.clone())
        };

        (stored_visibility, event_visibility)
    }

    async fn record_visibility_event(
        &self,
        ctx: &ActorContext<Self>,
        event: &Ledger,
    ) -> Result<(), ActorError> {
        let (stored_visibility, event_visibility, mode) = match &event.protocols
        {
            Protocols::Create { .. } => {
                let (stored_visibility, event_visibility) =
                    Self::public_visibilities();
                (
                    stored_visibility,
                    event_visibility,
                    TrackerVisibilityMode::Full,
                )
            }
            Protocols::TrackerFactFull { event_request, .. } => {
                let EventRequest::Fact(fact_request) = event_request.content()
                else {
                    return Err(ActorError::Functional {
                        description:
                            "In fact event, event request must be Fact"
                                .to_owned(),
                    });
                };
                let (stored_visibility, event_visibility) =
                    Self::fact_visibilities(&fact_request.viewpoints, false);
                (stored_visibility, event_visibility, self.visibility_mode)
            }
            Protocols::TrackerFactOpaque { evaluation, .. } => {
                let (stored_visibility, event_visibility) =
                    Self::fact_visibilities(&evaluation.viewpoints, true);
                let mode = if evaluation.is_ok() {
                    TrackerVisibilityMode::Opaque
                } else {
                    self.visibility_mode
                };
                (stored_visibility, event_visibility, mode)
            }
            Protocols::Transfer { .. }
            | Protocols::TrackerConfirm { .. }
            | Protocols::Reject { .. }
            | Protocols::EOL { .. } => {
                let (stored_visibility, event_visibility) =
                    Self::public_visibilities();
                (stored_visibility, event_visibility, self.visibility_mode)
            }
            _ => {
                return Err(ActorError::Functional {
                    description: "Invalid protocol data for tracker visibility"
                        .to_owned(),
                });
            }
        };

        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;

        witnesses_register
            .tell(WitnessesRegisterMessage::UpdateTrackerVisibility {
                subject_id: self.subject_metadata.subject_id.clone(),
                sn: event.sn,
                mode,
                stored_visibility,
                event_visibility,
            })
            .await
    }

    async fn get_tracker_visibility_state(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<TrackerVisibilityState, ActorError> {
        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;

        let response = witnesses_register
            .ask(WitnessesRegisterMessage::GetTrackerVisibilityState {
                subject_id: self.subject_metadata.subject_id.clone(),
            })
            .await?;

        match response {
            WitnessesRegisterResponse::TrackerVisibilityState { state } => {
                Ok(state)
            }
            _ => Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}/witnesses_register",
                    self.governance_id
                )),
                expected: "WitnessesRegisterResponse::TrackerVisibilityState"
                    .to_owned(),
            }),
        }
    }

    async fn build_subject_db(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<SubjectDB, ActorError> {
        let visibility_state = self.get_tracker_visibility_state(ctx).await?;

        Ok(SubjectDB {
            name: self.subject_metadata.name.clone(),
            description: self.subject_metadata.description.clone(),
            subject_id: self.subject_metadata.subject_id.to_string(),
            governance_id: self.governance_id.to_string(),
            genesis_gov_version: self.genesis_gov_version,
            prev_ledger_event_hash: if self
                .subject_metadata
                .prev_ledger_event_hash
                .is_empty()
            {
                None
            } else {
                Some(self.subject_metadata.prev_ledger_event_hash.to_string())
            },
            schema_id: self.subject_metadata.schema_id.to_string(),
            namespace: self.namespace.to_string(),
            sn: self.subject_metadata.sn,
            creator: self.subject_metadata.creator.to_string(),
            owner: self.subject_metadata.owner.to_string(),
            new_owner: self
                .subject_metadata
                .new_owner
                .clone()
                .map(|owner| owner.to_string()),
            active: self.subject_metadata.active,
            tracker_visibility: Some(visibility_state.into()),
            properties: self.properties.0.clone(),
        })
    }

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

            let _ = subject_register
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
        events: Vec<Ledger>,
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
                Metadata::from(&*self),
            )
            .await
            {
                return Err(ActorError::Functional {
                    description: e.to_string(),
                });
            }

            self.create(ctx, first.gov_version).await?;

            self.on_event(first.clone(), ctx).await;
            self.record_visibility_event(ctx, &first).await?;

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

            let (issuer, event_request_timestamp) =
                first.get_issuer_event_request_timestamp();
            let event_request = first.get_event_request();

            self.event_to_sink(
                ctx,
                DataForSink {
                    gov_id: Some(self.governance_id.to_string()),
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    sn: self.subject_metadata.sn,
                    owner: self.subject_metadata.owner.to_string(),
                    namespace: self.namespace.to_string(),
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
                        &self.properties.0,
                    ),
                    public_key: self.our_key.to_string(),
                },
                event_request,
            )
            .await?;

            first
        };

        pending.extend(iter);

        for event in pending {
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

            let last_gov_version = last_data.gov_version;

            let last_event_is_ok = match Self::verify_new_ledger_event(
                ctx,
                Self::verify_new_ledger_event_args(
                    &event,
                    Metadata::from(&*self),
                    actual_ledger_hash,
                    last_data,
                    hash,
                    self.is_full(),
                    self.only_clear_events,
                ),
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

            let event_gov_version = event.gov_version;

            let event_request = event.get_event_request();

            if last_event_is_ok {
                if last_gov_version != event_gov_version {
                    self.register_gov_version_sn(ctx, last_gov_version).await?;
                }
                if let Some(event_request) = &event_request {
                    match event_request {
                        EventRequest::Transfer(transfer_request) => {
                            self.transfer(
                                ctx,
                                transfer_request.new_owner.clone(),
                                event.gov_version,
                            )
                            .await?;
                            remove_verified_transfer(
                                ctx,
                                &self.governance_id,
                                &self.subject_metadata.subject_id,
                            )
                            .await?;
                        }
                        EventRequest::Reject(..) => {
                            self.reject(ctx, event.gov_version).await?;
                        }
                        EventRequest::Confirm(..) => {
                            self.confirm(
                                ctx,
                                event.ledger_seal_signature.signer.clone(),
                                event.gov_version,
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
                }
            }

            // Aplicar evento.
            self.on_event(event.clone(), ctx).await;
            self.record_visibility_event(ctx, &event).await?;

            let (issuer, event_request_timestamp) =
                event.get_issuer_event_request_timestamp();
            self.event_to_sink(
                ctx,
                DataForSink {
                    gov_id: Some(self.governance_id.to_string()),
                    subject_id: self.subject_metadata.subject_id.to_string(),
                    sn: self.subject_metadata.sn,
                    owner: self.subject_metadata.owner.to_string(),
                    namespace: self.namespace.to_string(),
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
                        &self.properties.0,
                    ),
                    public_key: self.our_key.to_string(),
                },
                event_request,
            )
            .await?;

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
    UpdateLedger { events: Vec<Ledger> },
    GetSinkEvents {
        from_sn: u64,
        batch_size: usize,
    },
}

impl Message for TrackerMessage {}

#[derive(Debug, Clone)]
pub enum TrackerResponse {
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
    SinkEvents(Vec<DataToSink>),
    Ok,
}
impl Response for TrackerResponse {}

#[async_trait]
impl Actor for Tracker {
    type Event = Ledger;
    type Message = TrackerMessage;
    type Response = TrackerResponse;
    type SinkEvent = SubjectSinkEvent;
        type ChildError = ActorError;
    type ChildFault = ActorError;

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

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for Tracker {
    async fn handle_message(
        &mut self,
        _: ActorPath,
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
                Box::new(Metadata::from(&*self)),
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
            TrackerMessage::GetSinkEvents {
                from_sn,
                batch_size,
            } => {
                let events = self.get_sink_events(ctx, from_sn, batch_size).await?;
                Ok(TrackerResponse::SinkEvents(events))
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

    async fn on_event(&mut self, event: Ledger, ctx: &mut ActorContext<Self>) {
        let event_for_publish = event.clone();
        if let Err(e) = self.persist(event, ctx).await {
            error!(
                error = %e,
                subject_id = %self.subject_metadata.subject_id,
                sn = self.subject_metadata.sn,
                "Failed to persist event"
            );
            crash_system(ctx, e).await;
        };

        ctx.publish_all(SubjectSinkEvent::Ledger(Box::new(event_for_publish)));
        debug!(
            subject_id = %self.subject_metadata.subject_id,
            sn = self.subject_metadata.sn,
            "Event persisted and published successfully"
        );
    }
}

pub struct InitParamsTracker {
    pub data: Option<TrackerInit>,
    pub public_key: Arc<PublicKey>,
    pub hash: HashAlgorithm,
    pub is_service: bool,
    pub only_clear_events: bool,
}

#[async_trait]
impl PersistentActor for Tracker {
    type Persistence = FullPersistence;
    type InitParams = InitParamsTracker;
    type State = TrackerState;

    fn create_initial(params: Self::InitParams) -> Self {
        let init = params.data.unwrap_or_default();

        Self {
            service: params.is_service,
            only_clear_events: params.only_clear_events,
            hash: Some(params.hash),
            our_key: params.public_key,
            state: Arc::new(TrackerState {
                subject_metadata: init.subject_metadata,
                properties: init.properties,
                genesis_gov_version: init.genesis_gov_version,
                governance_id: init.governance_id,
                namespace: init.namespace,
                visibility_mode: TrackerVisibilityMode::Full,
            }),
        }
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match &event.protocols {
            Protocols::Create {
                validation,
                event_request,
            } => {
                if let EventRequest::Create(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Create",
                        subject_id = %inner.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for tracker create apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In create event, event request must be Create"
                                .to_owned(),
                    });
                }

                if let ValidationMetadata::Metadata(metadata) =
                    &validation.validation_metadata
                {
                    inner.subject_metadata = SubjectMetadata::new(metadata);
                    inner.properties = metadata.properties.clone();
                    inner.visibility_mode = TrackerVisibilityMode::Full;

                    debug!(
                        event_type = "Create",
                        subject_id = %inner.subject_metadata.subject_id,
                        sn = inner.subject_metadata.sn,
                        "Applied create event"
                    );
                } else {
                    error!(
                        event_type = "Create",
                        "Validation metadata must be Metadata type"
                    );
                    return Err(ActorError::Functional { description: "In create event, validation metadata must be a Metadata".to_owned() });
                }

                return Ok(state);
            }
            Protocols::TrackerFactFull {
                evaluation,
                event_request,
                ..
            } => {
                let EventRequest::Fact(_fact_request) = event_request.content()
                else {
                    error!(
                        event_type = "Fact",
                        subject_id = %inner.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for tracker fact apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In fact event, event request must be Fact"
                                .to_owned(),
                    });
                };

                if let Some(eval_res) = evaluation.evaluator_response_ok() {
                    if inner.is_full() {
                        inner.apply_patch_inner(eval_res.patch)?;
                        debug!(
                            event_type = "Fact",
                            subject_id = %inner.subject_metadata.subject_id,
                            "Applied fact event with patch"
                        );
                    } else {
                        debug!(
                            event_type = "Fact",
                            subject_id = %inner.subject_metadata.subject_id,
                            "Tracker is not in full mode, fact patch not applied"
                        );
                    }
                }
            }
            Protocols::TrackerFactOpaque { evaluation, .. } => {
                if evaluation.is_ok() {
                    inner.visibility_mode = TrackerVisibilityMode::Opaque;
                }
                debug!(
                    event_type = "FactOpaque",
                    subject_id = %inner.subject_metadata.subject_id,
                    "Applied tracker opaque fact event"
                );
            }
            Protocols::Transfer {
                evaluation,
                event_request,
                ..
            } => {
                let EventRequest::Transfer(transfer_request) =
                    event_request.content()
                else {
                    error!(
                        event_type = "Transfer",
                        subject_id = %inner.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for tracker transfer apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In transfer event, event request must be Transfer"
                                .to_owned(),
                    });
                };

                if evaluation.evaluator_response_ok().is_some() {
                    if inner.is_full()
                        && let Some(eval_res) =
                            evaluation.evaluator_response_ok()
                    {
                        inner.apply_patch_inner(eval_res.patch)?;
                    } else if !inner.is_full() {
                        debug!(
                            event_type = "Transfer",
                            subject_id = %inner.subject_metadata.subject_id,
                            "Tracker is not in full mode, transfer patch not applied"
                        );
                    }
                    inner.subject_metadata.new_owner =
                        Some(transfer_request.new_owner.clone());
                    debug!(
                        event_type = "Transfer",
                        subject_id = %inner.subject_metadata.subject_id,
                        new_owner = %transfer_request.new_owner,
                        "Applied transfer event"
                    );
                }
            }
            Protocols::TrackerConfirm { event_request, .. } => {
                if let EventRequest::Confirm(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Confirm",
                        subject_id = %inner.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for tracker confirm apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In confirm event, event request must be Confirm"
                                .to_owned(),
                    });
                }

                if let Some(new_owner) = inner.subject_metadata.new_owner.take()
                {
                    inner.subject_metadata.owner = new_owner.clone();
                    debug!(
                        event_type = "Confirm",
                        subject_id = %inner.subject_metadata.subject_id,
                        new_owner = %new_owner,
                        "Applied confirm event"
                    );
                } else {
                    error!(
                        event_type = "Confirm",
                        subject_id = %inner.subject_metadata.subject_id,
                        "New owner is None in confirm event"
                    );
                    return Err(ActorError::Functional {
                        description: "In confirm event, new owner is None"
                            .to_owned(),
                    });
                }
            }
            Protocols::Reject { event_request, .. } => {
                if let EventRequest::Reject(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "Reject",
                        subject_id = %inner.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for tracker reject apply"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "In reject event, event request must be Reject"
                                .to_owned(),
                    });
                }

                inner.subject_metadata.new_owner = None;
                debug!(
                    event_type = "Reject",
                    subject_id = %inner.subject_metadata.subject_id,
                    "Applied reject event"
                );
            }
            Protocols::EOL { event_request, .. } => {
                if let EventRequest::EOL(..) = event_request.content() {
                } else {
                    error!(
                        event_type = "EOL",
                        subject_id = %inner.subject_metadata.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type for tracker eol apply"
                    );
                    return Err(ActorError::Functional {
                        description: "In EOL event, event request must be EOL"
                            .to_owned(),
                    });
                }

                inner.subject_metadata.active = false;
                debug!(
                    event_type = "EOL",
                    subject_id = %inner.subject_metadata.subject_id,
                    "Applied EOL event"
                );
            }
            _ => {
                error!(
                    subject_id = %inner.subject_metadata.subject_id,
                    "Invalid protocol data for Tracker"
                );
                return Err(ActorError::Functional {
                    description:
                        "Protocols data is for Governance and this is a Tracker"
                            .to_owned(),
                });
            }
        }

        inner.subject_metadata.sn += 1;
        inner.subject_metadata.prev_ledger_event_hash =
            event.prev_ledger_event_hash.clone();

        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        self.state.clone()
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        self.state = state;
    }
}

impl Storable for Tracker {}
