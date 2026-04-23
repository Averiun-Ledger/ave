use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler, Message,
    NotPersistentActor, PersistentActor, Response, Sink,
};
use ave_common::identity::{DigestIdentifier, HashAlgorithm, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::{
    governance::{
        Governance, GovernanceMessage, GovernanceResponse, data::GovernanceData,
    },
    helpers::db::ExternalDB,
    model::event::{Ledger, Protocols, ValidationMetadata},
    node::{Node, NodeMessage, NodeResponse, SubjectData},
    subject::SubjectMetadata,
    tracker::{
        InitParamsTracker, Tracker, TrackerInit, TrackerMessage,
        TrackerResponse,
    },
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubjectManagerMessage {
    UpGovernances {
        governance_ids: Vec<DigestIdentifier>,
    },
    Up {
        subject_id: DigestIdentifier,
        requester: String,
        create_ledger: Option<Box<Ledger>>,
    },
    Finish {
        subject_id: DigestIdentifier,
        requester: String,
    },
    DeleteTracker {
        subject_id: DigestIdentifier,
    },
    DeleteGovernance {
        subject_id: DigestIdentifier,
    },
}

impl Message for SubjectManagerMessage {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubjectManagerResponse {
    Up,
    Finish,
    DeleteTracker,
    DeleteGovernance,
}

impl Response for SubjectManagerResponse {}

#[derive(Debug, Default, Clone)]
struct SubjectEntry {
    requesters: HashSet<String>,
}

pub struct SubjectManager {
    our_key: Arc<PublicKey>,
    hash: HashAlgorithm,
    is_service: bool,
    only_clear_events: bool,
    subjects: HashMap<DigestIdentifier, SubjectEntry>,
}

impl SubjectManager {
    pub fn new(
        our_key: Arc<PublicKey>,
        hash: HashAlgorithm,
        is_service: bool,
        only_clear_events: bool,
    ) -> Self {
        Self {
            our_key,
            hash,
            is_service,
            only_clear_events,
            subjects: HashMap::new(),
        }
    }

    async fn up_governances(
        &self,
        ctx: &mut ActorContext<Self>,
        governance_ids: Vec<DigestIdentifier>,
    ) -> Result<(), ActorError> {
        let safe_mode = if let Some(config) = ctx
            .system()
            .get_helper::<crate::system::ConfigHelper>("config")
            .await
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        for governance_id in governance_ids {
            let actor: ActorRef<Governance> = ctx
                .create_child(
                    &governance_id.to_string(),
                    Governance::initial((
                        None,
                        self.our_key.clone(),
                        self.hash,
                        self.is_service,
                    )),
                )
                .await?;

            if !safe_mode {
                let Some(ext_db): Option<Arc<ExternalDB>> =
                    ctx.system().get_helper("ext_db").await
                else {
                    return Err(ActorError::Helper {
                        name: "ext_db".to_owned(),
                        reason: "Not found".to_owned(),
                    });
                };

                let sink = Sink::new(actor.subscribe(), ext_db.get_subject());
                ctx.system().run_sink(sink).await;
            }
        }

        Ok(())
    }

    async fn up(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
        requester: String,
        create_ledger: Option<Box<Ledger>>,
    ) -> Result<(), ActorError> {
        if let Some(entry) = self.subjects.get_mut(&subject_id) {
            entry.requesters.insert(requester);
            return Ok(());
        }

        if let Some(ledger) = create_ledger {
            let ledger = *ledger;
            let metadata = Self::metadata_from_create_ledger(&ledger)?;

            if metadata.schema_id.is_gov() {
                self.create_governance(ctx, &subject_id, metadata, ledger)
                    .await?;
                return Ok(());
            }

            self.create_tracker(ctx, &subject_id, metadata, ledger)
                .await?;
        } else {
            self.load_tracker(ctx, &subject_id).await?;
        }

        let entry = self.subjects.entry(subject_id).or_default();
        entry.requesters.insert(requester);

        Ok(())
    }

    async fn finish(
        &mut self,
        ctx: &ActorContext<Self>,
        subject_id: DigestIdentifier,
        requester: String,
    ) -> Result<(), ActorError> {
        let Some(entry) = self.subjects.get_mut(&subject_id) else {
            return Ok(());
        };

        entry.requesters.remove(&requester);

        if !entry.requesters.is_empty() {
            return Ok(());
        }

        let tracker = ctx.get_child::<Tracker>(&subject_id.to_string()).await?;
        tracker.ask_stop().await?;
        self.subjects.remove(&subject_id);

        Ok(())
    }

    async fn delete_tracker(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let mut cleanup_errors = Vec::new();

        let tracker = match ctx
            .create_child(
                &subject_id.to_string(),
                Tracker::initial(InitParamsTracker {
                    data: None,
                    hash: self.hash,
                    is_service: self.is_service,
                    only_clear_events: self.only_clear_events,
                    public_key: self.our_key.clone(),
                }),
            )
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<Tracker>(&subject_id.to_string()).await {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors.push(format!("tracker lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("tracker: {error}"));
                None
            }
        };

        if let Some(tracker) = tracker {
            match tracker.ask(TrackerMessage::PurgeStorage).await {
                Ok(TrackerResponse::Ok) => {}
                Ok(other) => cleanup_errors
                    .push(format!("tracker: unexpected response {other:?}")),
                Err(error) => cleanup_errors.push(format!("tracker: {error}")),
            }

            if let Err(error) = tracker.ask_stop().await {
                cleanup_errors.push(format!("tracker stop: {error}"));
            }
        }

        self.subjects.remove(&subject_id);

        let governance_id = match ctx.get_parent::<Node>().await {
            Ok(node) => match node
                .ask(NodeMessage::GetSubjectData(subject_id.clone()))
                .await
            {
                Ok(NodeResponse::SubjectData(Some(SubjectData::Tracker {
                    governance_id,
                    ..
                }))) => Some(governance_id),
                Ok(NodeResponse::SubjectData(Some(
                    SubjectData::Governance { .. },
                ))) => {
                    cleanup_errors.push(format!(
                        "subject '{}' is governance, not tracker",
                        subject_id
                    ));
                    None
                }
                Ok(NodeResponse::SubjectData(None)) => {
                    cleanup_errors.push(format!(
                        "subject '{}' not found in node",
                        subject_id
                    ));
                    None
                }
                Ok(other) => {
                    cleanup_errors
                        .push(format!("node: unexpected response {other:?}"));
                    None
                }
                Err(error) => {
                    cleanup_errors.push(format!("node: {error}"));
                    None
                }
            },
            Err(error) => {
                cleanup_errors.push(format!("node parent: {error}"));
                None
            }
        };

        if let Some(governance_id) = governance_id {
            match ctx
                .get_child::<Governance>(&governance_id.to_string())
                .await
            {
                Ok(governance) => {
                    match governance
                        .ask(GovernanceMessage::DeleteTrackerReferences {
                            subject_id: subject_id.clone(),
                        })
                        .await
                    {
                        Ok(GovernanceResponse::Ok) => {}
                        Ok(other) => cleanup_errors.push(format!(
                            "governance: unexpected response {other:?}"
                        )),
                        Err(error) => {
                            cleanup_errors.push(format!("governance: {error}"))
                        }
                    }
                }
                Err(error) => {
                    cleanup_errors.push(format!("governance lookup: {error}"));
                }
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

    async fn delete_governance(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let mut cleanup_errors = Vec::new();

        let governance = match ctx
            .create_child(
                &subject_id.to_string(),
                Governance::initial((
                    None,
                    self.our_key.clone(),
                    self.hash,
                    self.is_service,
                )),
            )
            .await
        {
            Ok(actor) => Some(actor),
            Err(ActorError::Exists { .. }) => {
                match ctx.get_child::<Governance>(&subject_id.to_string()).await
                {
                    Ok(actor) => Some(actor),
                    Err(error) => {
                        cleanup_errors
                            .push(format!("governance lookup: {error}"));
                        None
                    }
                }
            }
            Err(error) => {
                cleanup_errors.push(format!("governance: {error}"));
                None
            }
        };

        if let Some(governance) = governance {
            match governance
                .ask(GovernanceMessage::DeleteGovernanceStorage)
                .await
            {
                Ok(GovernanceResponse::Ok) => {}
                Ok(other) => cleanup_errors
                    .push(format!("governance: unexpected response {other:?}")),
                Err(error) => {
                    cleanup_errors.push(format!("governance: {error}"))
                }
            }

            if let Err(error) = governance.ask_stop().await {
                cleanup_errors.push(format!("governance stop: {error}"));
            }
        }

        self.subjects.remove(&subject_id);

        if cleanup_errors.is_empty() {
            Ok(())
        } else {
            Err(ActorError::Functional {
                description: cleanup_errors.join("; "),
            })
        }
    }

    async fn load_tracker(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let tracker_actor: ActorRef<Tracker> = ctx
            .create_child(
                &subject_id.to_string(),
                Tracker::initial(InitParamsTracker {
                    data: None,
                    hash: self.hash,
                    is_service: self.is_service,
                    only_clear_events: self.only_clear_events,
                    public_key: self.our_key.clone(),
                }),
            )
            .await?;

        self.run_tracker_sink(ctx, tracker_actor).await
    }

    async fn create_tracker(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        metadata: crate::subject::Metadata,
        ledger: Ledger,
    ) -> Result<(), ActorError> {
        let tracker_actor: ActorRef<Tracker> = ctx
            .create_child(
                &subject_id.to_string(),
                Tracker::initial(InitParamsTracker {
                    data: Some(TrackerInit::from(&metadata)),
                    hash: self.hash,
                    is_service: self.is_service,
                    only_clear_events: self.only_clear_events,
                    public_key: self.our_key.clone(),
                }),
            )
            .await?;

        self.run_tracker_sink(ctx, tracker_actor.clone()).await?;

        if let Err(error) = tracker_actor
            .ask(TrackerMessage::UpdateLedger {
                events: vec![ledger],
            })
            .await
        {
            tracker_actor.tell_stop().await;
            return Err(error);
        }

        self.register_subject_in_node(
            ctx,
            metadata.owner.clone(),
            metadata.subject_id.clone(),
            SubjectData::Tracker {
                governance_id: metadata.governance_id.clone(),
                schema_id: metadata.schema_id.clone(),
                namespace: metadata.namespace.to_string(),
                active: true,
            },
        )
        .await?;

        Ok(())
    }

    async fn create_governance(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        metadata: crate::subject::Metadata,
        ledger: Ledger,
    ) -> Result<(), ActorError> {
        let governance_data = serde_json::from_value::<GovernanceData>(
            metadata.properties.0.clone(),
        )
        .map_err(|e| ActorError::Functional {
            description: format!(
                "Governance properties must be GovernanceData: {e}"
            ),
        })?;

        if ctx
            .get_child::<Governance>(&subject_id.to_string())
            .await
            .is_ok()
        {
            return Ok(());
        }

        let governance_actor: ActorRef<Governance> = ctx
            .create_child(
                &subject_id.to_string(),
                Governance::initial((
                    Some((SubjectMetadata::new(&metadata), governance_data)),
                    self.our_key.clone(),
                    self.hash,
                    self.is_service,
                )),
            )
            .await?;

        self.run_governance_sink(ctx, governance_actor.clone())
            .await?;

        if let Err(error) = governance_actor
            .ask(GovernanceMessage::UpdateLedger {
                events: vec![ledger],
            })
            .await
        {
            governance_actor.tell_stop().await;
            return Err(error);
        }

        self.register_subject_in_node(
            ctx,
            metadata.owner.clone(),
            metadata.subject_id.clone(),
            SubjectData::Governance { active: true },
        )
        .await?;

        Ok(())
    }

    fn metadata_from_create_ledger(
        ledger: &Ledger,
    ) -> Result<crate::subject::Metadata, ActorError> {
        match &ledger.protocols {
            Protocols::Create { validation, .. } => {
                if let ValidationMetadata::Metadata(metadata) =
                    &validation.validation_metadata
                {
                    Ok(*metadata.clone())
                } else {
                    Err(ActorError::Functional {
                        description:
                            "Create validation metadata must be Metadata"
                                .to_owned(),
                    })
                }
            }
            _ => Err(ActorError::Functional {
                description:
                    "SubjectManager create flow requires a create ledger"
                        .to_owned(),
            }),
        }
    }

    async fn run_tracker_sink(
        &self,
        ctx: &ActorContext<Self>,
        actor: ActorRef<Tracker>,
    ) -> Result<(), ActorError> {
        let safe_mode = if let Some(config) = ctx
            .system()
            .get_helper::<crate::system::ConfigHelper>("config")
            .await
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if safe_mode {
            return Ok(());
        }

        let Some(ext_db): Option<Arc<ExternalDB>> =
            ctx.system().get_helper("ext_db").await
        else {
            return Err(ActorError::Helper {
                name: "ext_db".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let sink = Sink::new(actor.subscribe(), ext_db.get_subject());
        ctx.system().run_sink(sink).await;
        Ok(())
    }

    async fn run_governance_sink(
        &self,
        ctx: &ActorContext<Self>,
        actor: ActorRef<Governance>,
    ) -> Result<(), ActorError> {
        let safe_mode = if let Some(config) = ctx
            .system()
            .get_helper::<crate::system::ConfigHelper>("config")
            .await
        {
            config.safe_mode
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        if safe_mode {
            return Ok(());
        }

        let Some(ext_db): Option<Arc<ExternalDB>> =
            ctx.system().get_helper("ext_db").await
        else {
            return Err(ActorError::Helper {
                name: "ext_db".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let sink = Sink::new(actor.subscribe(), ext_db.get_subject());
        ctx.system().run_sink(sink).await;
        Ok(())
    }

    async fn register_subject_in_node(
        &self,
        ctx: &ActorContext<Self>,
        owner: PublicKey,
        subject_id: DigestIdentifier,
        data: SubjectData,
    ) -> Result<(), ActorError> {
        let node = ctx.get_parent::<Node>().await?;
        let response = node
            .ask(NodeMessage::RegisterSubject {
                owner,
                subject_id,
                data,
            })
            .await?;

        match response {
            NodeResponse::Ok => Ok(()),
            _ => Err(ActorError::UnexpectedResponse {
                path: ctx.path().parent(),
                expected: "NodeResponse::Ok".to_owned(),
            }),
        }
    }
}

#[async_trait]
impl Actor for SubjectManager {
    type Event = ();
    type Message = SubjectManagerMessage;
    type Response = SubjectManagerResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("SubjectManager"),
            |parent_span| info_span!(parent: parent_span, "SubjectManager"),
        )
    }
}

impl NotPersistentActor for SubjectManager {}

#[async_trait]
impl Handler<Self> for SubjectManager {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SubjectManagerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<SubjectManagerResponse, ActorError> {
        match msg {
            SubjectManagerMessage::UpGovernances { governance_ids } => {
                debug!(
                    governance_count = governance_ids.len(),
                    "Governance bootstrap requested"
                );
                self.up_governances(ctx, governance_ids).await?;
                Ok(SubjectManagerResponse::Up)
            }
            SubjectManagerMessage::Up {
                subject_id,
                requester,
                create_ledger,
            } => {
                debug!(
                    subject_id = %subject_id,
                    requester = %requester,
                    "Subject up requested"
                );
                self.up(ctx, subject_id, requester, create_ledger).await?;
                Ok(SubjectManagerResponse::Up)
            }
            SubjectManagerMessage::Finish {
                subject_id,
                requester,
            } => {
                debug!(
                    subject_id = %subject_id,
                    requester = %requester,
                    "Subject finish requested"
                );
                self.finish(ctx, subject_id, requester).await?;
                Ok(SubjectManagerResponse::Finish)
            }
            SubjectManagerMessage::DeleteTracker { subject_id } => {
                debug!(
                    subject_id = %subject_id,
                    "Tracker delete requested"
                );
                self.delete_tracker(ctx, subject_id).await?;
                Ok(SubjectManagerResponse::DeleteTracker)
            }
            SubjectManagerMessage::DeleteGovernance { subject_id } => {
                debug!(
                    subject_id = %subject_id,
                    "Governance delete requested"
                );
                self.delete_governance(ctx, subject_id).await?;
                Ok(SubjectManagerResponse::DeleteGovernance)
            }
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ave_actors::ChildAction {
        error!(error = %error, "Child fault in subject manager");
        ctx.system().crash_system();
        ave_actors::ChildAction::Stop
    }
}
