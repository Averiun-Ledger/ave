//! Node module
//!

use std::{
    collections::{HashMap, HashSet},
    path::Path,
    sync::Arc,
};

use borsh::{BorshDeserialize, BorshSerialize};
use register::Register;
use tokio::fs;
use tracing::{Span, debug, error, info_span};

use crate::{
    auth::{Auth, AuthInitParams, AuthMessage, AuthResponse},
    db::Storable,
    distribution::worker::DistriWorker,
    governance::{Governance, GovernanceMessage, GovernanceResponse},
    helpers::{db::ExternalDB, network::service::NetworkSender},
    manual_distribution::ManualDistribution,
    model::{common::node::SignTypesNode, event::Ledger},
    node::subject_manager::{SubjectManager, SubjectManagerMessage},
    subject::replay_sink_events as replay_ledgers_to_sink_events,
    system::ConfigHelper,
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};

use ave_common::{
    SchemaType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signature, keys::KeyPair,
    },
    response::SinkEventsPage,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message, Response, Sink,
};
use ave_actors::{LightPersistence, PersistentActor};
use serde::{Deserialize, Serialize};

pub mod register;
pub mod subject_manager;

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TransferSubject {
    pub name: Option<String>,
    pub subject_id: DigestIdentifier,
    pub new_owner: PublicKey,
    pub actual_owner: PublicKey,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct TransferData {
    pub name: Option<String>,
    pub new_owner: PublicKey,
    pub actual_owner: PublicKey,
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    Eq,
    PartialEq,
)]
pub enum SubjectData {
    Tracker {
        governance_id: DigestIdentifier,
        schema_id: SchemaType,
        namespace: String,
        active: bool,
    },
    Governance {
        active: bool,
    },
}

impl SubjectData {
    pub fn get_schema_id(&self) -> SchemaType {
        match self {
            Self::Tracker { schema_id, .. } => schema_id.clone(),
            Self::Governance { .. } => SchemaType::Governance,
        }
    }

    pub fn get_governance_id(&self) -> Option<DigestIdentifier> {
        match self {
            Self::Tracker { governance_id, .. } => Some(governance_id.clone()),
            Self::Governance { .. } => None,
        }
    }

    pub fn get_namespace(&self) -> String {
        match self {
            Self::Tracker { namespace, .. } => namespace.clone(),
            Self::Governance { .. } => String::default(),
        }
    }

    pub const fn get_active(&self) -> bool {
        match self {
            Self::Tracker { active, .. } => *active,
            Self::Governance { active } => *active,
        }
    }

    pub const fn eol(&mut self) {
        match self {
            Self::Tracker { active, .. } => *active = false,
            Self::Governance { active } => *active = false,
        };
    }
}

/// Node struct.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Node {
    /// Owner of the node.
    #[serde(skip)]
    owner: KeyPair,
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    #[serde(skip)]
    hash: Option<HashAlgorithm>,
    #[serde(skip)]
    is_service: bool,
    #[serde(skip)]
    ledger_batch_size: u64,
    /// The node's owned subjects.
    owned_subjects: HashMap<DigestIdentifier, SubjectData>,
    /// The node's known subjects.
    known_subjects: HashMap<DigestIdentifier, SubjectData>,

    transfer_subjects: HashMap<DigestIdentifier, TransferData>,

    reject_subjects: HashSet<DigestIdentifier>,
}

// Manual Borsh implementation to skip the 'owner' field
impl BorshSerialize for Node {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the fields we want to persist, skipping 'owner'
        BorshSerialize::serialize(&self.owned_subjects, writer)?;
        BorshSerialize::serialize(&self.known_subjects, writer)?;
        BorshSerialize::serialize(&self.transfer_subjects, writer)?;
        BorshSerialize::serialize(&self.reject_subjects, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for Node {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let owned_subjects =
            HashMap::<DigestIdentifier, SubjectData>::deserialize_reader(
                reader,
            )?;
        let known_subjects =
            HashMap::<DigestIdentifier, SubjectData>::deserialize_reader(
                reader,
            )?;
        let transfer_subjects =
            HashMap::<DigestIdentifier, TransferData>::deserialize_reader(
                reader,
            )?;
        let reject_subjects =
            HashSet::<DigestIdentifier>::deserialize_reader(reader)?;

        // Create a default/placeholder KeyPair for 'owner'
        // This will be replaced by the actual owner during actor initialization
        let owner = KeyPair::default();
        let our_key = Arc::new(PublicKey::default());
        let hash = None;

        Ok(Self {
            hash,
            our_key,
            owner,
            ledger_batch_size: 100,
            owned_subjects,
            known_subjects,
            transfer_subjects,
            reject_subjects,
            is_service: false,
        })
    }
}

impl Node {
    fn get_subject_data(
        &self,
        subject_id: &DigestIdentifier,
    ) -> Option<SubjectData> {
        self.owned_subjects
            .get(subject_id)
            .or_else(|| self.known_subjects.get(subject_id))
            .cloned()
    }

    /// Adds a subject to the node's owned subjects.
    pub fn transfer_subject(&mut self, data: TransferSubject) {
        if data.new_owner == *self.our_key {
            self.reject_subjects.remove(&data.subject_id);
        }

        self.transfer_subjects.insert(
            data.subject_id,
            TransferData {
                name: data.name,
                new_owner: data.new_owner,
                actual_owner: data.actual_owner,
            },
        );
    }

    pub fn delete_transfer(&mut self, subject_id: &DigestIdentifier) {
        if let Some(data) = self.transfer_subjects.remove(subject_id)
            && data.actual_owner == *self.our_key
        {
            self.reject_subjects.insert(subject_id.clone());
        }
    }

    pub fn confirm_transfer(&mut self, subject_id: DigestIdentifier) {
        self.our_key.to_string();

        if let Some(data) = self.transfer_subjects.remove(&subject_id) {
            if data.actual_owner == *self.our_key {
                if let Some(data) = self.owned_subjects.remove(&subject_id) {
                    self.known_subjects.insert(subject_id, data);
                }
            } else if data.new_owner == *self.our_key
                && let Some(data) = self.known_subjects.remove(&subject_id)
            {
                self.owned_subjects.insert(subject_id, data);
            };
        };
    }

    pub fn eol(&mut self, subject_id: DigestIdentifier, i_owner: bool) {
        if i_owner {
            if let Some(data) = self.owned_subjects.get_mut(&subject_id) {
                data.eol();
            }
        } else if let Some(data) = self.known_subjects.get_mut(&subject_id) {
            data.eol();
        }
    }

    pub fn register_subject(
        &mut self,
        subject_id: DigestIdentifier,
        owner: PublicKey,
        data: SubjectData,
    ) {
        if *self.our_key == owner {
            self.owned_subjects.insert(subject_id, data);
        } else {
            self.known_subjects.insert(subject_id, data);
        }
    }

    pub fn delete_subject(&mut self, subject_id: &DigestIdentifier) {
        self.owned_subjects
            .remove(subject_id)
            .or_else(|| self.known_subjects.remove(subject_id));

        self.transfer_subjects.remove(subject_id);
        self.reject_subjects.remove(subject_id);
    }

    fn governance_trackers(
        &self,
        governance_id: &DigestIdentifier,
    ) -> Vec<DigestIdentifier> {
        self.owned_subjects
            .iter()
            .chain(self.known_subjects.iter())
            .filter_map(|(subject_id, data)| match data {
                SubjectData::Tracker {
                    governance_id: tracker_governance_id,
                    ..
                } if tracker_governance_id == governance_id => {
                    Some(subject_id.clone())
                }
                _ => None,
            })
            .collect()
    }

    fn sign<T: BorshSerialize>(
        &self,
        content: &T,
    ) -> Result<Signature, ActorError> {
        Signature::new(content, &self.owner).map_err(|e| {
            ActorError::Functional {
                description: format!("{}", e),
            }
        })
    }

    async fn build_compilation_dir(
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let contracts_path = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.contracts_path
        } else {
            error!("Config helper not found");
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_string(),
            });
        };

        let dir = contracts_path.join("contracts");

        if !Path::new(&dir).exists() {
            fs::create_dir_all(&dir).await.map_err(|e| {
                error!(
                    error = %e,
                    path = ?dir,
                    "Failed to create contracts directory"
                );
                ActorError::FunctionalCritical {
                    description: format!("Can not create contracts dir: {}", e),
                }
            })?;
        }
        Ok(())
    }

    async fn create_distributors(
        &self,
        ctx: &mut ActorContext<Self>,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        for subject in self.owned_subjects.keys() {
            let distributor_name = format!("distributor_{}", subject);
            if ctx
                .get_child::<DistriWorker>(&distributor_name)
                .await
                .is_err()
            {
                ctx.create_child(
                    &distributor_name,
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network: network.clone(),
                        ledger_batch_size: self.ledger_batch_size,
                    },
                )
                .await?;
            }
        }

        for subject in self.known_subjects.keys() {
            let distributor_name = format!("distributor_{}", subject);
            if ctx
                .get_child::<DistriWorker>(&distributor_name)
                .await
                .is_err()
            {
                ctx.create_child(
                    &distributor_name,
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network: network.clone(),
                        ledger_batch_size: self.ledger_batch_size,
                    },
                )
                .await?;
            }
        }

        Ok(())
    }

    fn governance_ids(&self) -> Vec<DigestIdentifier> {
        let mut governance_ids = self
            .owned_subjects
            .iter()
            .filter(|(_, data)| matches!(data, SubjectData::Governance { .. }))
            .map(|(subject_id, _)| subject_id.clone())
            .collect::<HashSet<_>>();

        governance_ids.extend(
            self.known_subjects
                .iter()
                .filter(|(_, data)| {
                    matches!(data, SubjectData::Governance { .. })
                })
                .map(|(subject_id, _)| subject_id.clone()),
        );

        governance_ids.into_iter().collect()
    }

    async fn get_tracker_ledger_batch(
        ctx: &ActorContext<Self>,
        actor: &ave_actors::ActorRef<Tracker>,
        lo_sn: Option<u64>,
        hi_sn: u64,
    ) -> Result<(Vec<Ledger>, bool), ActorError> {
        let response = actor
            .ask(TrackerMessage::GetLedger { lo_sn, hi_sn })
            .await?;

        match response {
            TrackerResponse::Ledger { ledger, is_all } => Ok((ledger, is_all)),
            _ => Err(ActorError::UnexpectedResponse {
                path: ctx.path().clone() / "subject_manager",
                expected: "TrackerResponse::Ledger".to_owned(),
            }),
        }
    }

    async fn get_governance_ledger_batch(
        ctx: &ActorContext<Self>,
        actor: &ave_actors::ActorRef<Governance>,
        lo_sn: Option<u64>,
        hi_sn: u64,
    ) -> Result<(Vec<Ledger>, bool), ActorError> {
        let response = actor
            .ask(GovernanceMessage::GetLedger { lo_sn, hi_sn })
            .await?;

        match response {
            GovernanceResponse::Ledger { ledger, is_all } => {
                Ok((ledger, is_all))
            }
            _ => Err(ActorError::UnexpectedResponse {
                path: ctx.path().clone() / "subject_manager",
                expected: "GovernanceResponse::Ledger".to_owned(),
            }),
        }
    }

    async fn collect_tracker_ledger(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        hi_sn: u64,
    ) -> Result<Vec<Ledger>, ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            subject_id
        ));
        let tracker = ctx.system().get_actor::<Tracker>(&path).await?;
        let mut ledger = Vec::new();
        let mut lo_sn = None;
        let ledger_batch_size = self.ledger_batch_size;

        loop {
            let from_sn =
                lo_sn.map_or(0_u64, |sn: u64| sn.saturating_add(1));
            let batch_hi_sn = from_sn
                .saturating_add(ledger_batch_size)
                .saturating_sub(1)
                .min(hi_sn);
            let (mut batch, is_all) =
                Self::get_tracker_ledger_batch(
                    ctx,
                    &tracker,
                    lo_sn,
                    batch_hi_sn,
                )
                .await?;
            if batch.is_empty() {
                break;
            }
            lo_sn = batch.last().map(|event| event.sn);
            ledger.append(&mut batch);
            if is_all {
                break;
            }
        }

        Ok(ledger)
    }

    async fn collect_governance_ledger(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        hi_sn: u64,
    ) -> Result<Vec<Ledger>, ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            subject_id
        ));
        let governance = ctx.system().get_actor::<Governance>(&path).await?;
        let mut ledger = Vec::new();
        let mut lo_sn = None;
        let ledger_batch_size = self.ledger_batch_size;

        loop {
            let from_sn =
                lo_sn.map_or(0_u64, |sn: u64| sn.saturating_add(1));
            let batch_hi_sn = from_sn
                .saturating_add(ledger_batch_size)
                .saturating_sub(1)
                .min(hi_sn);
            let (mut batch, is_all) = Self::get_governance_ledger_batch(
                ctx,
                &governance,
                lo_sn,
                batch_hi_sn,
            )
            .await?;
            if batch.is_empty() {
                break;
            }
            lo_sn = batch.last().map(|event| event.sn);
            ledger.append(&mut batch);
            if is_all {
                break;
            }
        }

        Ok(ledger)
    }

    async fn replay_sink_events(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: DigestIdentifier,
        from_sn: u64,
        to_sn: Option<u64>,
        limit: u64,
    ) -> Result<SinkEventsPage, ActorError> {
        if limit == 0 {
            return Err(ActorError::Functional {
                description: "Replay limit must be greater than zero"
                    .to_owned(),
            });
        }
        if let Some(to_sn) = to_sn
            && from_sn > to_sn
        {
            return Err(ActorError::Functional {
                description: "Replay range requires from_sn <= to_sn"
                    .to_owned(),
            });
        }

        let Some(subject_data) = self
            .owned_subjects
            .get(&subject_id)
            .cloned()
            .or_else(|| self.known_subjects.get(&subject_id).cloned())
        else {
            return Err(ActorError::NotFound {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}",
                    subject_id
                )),
            });
        };

        let sink_timestamp = ave_common::identity::TimeStamp::now().as_nanos();
        let public_key = self.our_key.to_string();

        match subject_data {
            SubjectData::Governance { .. } => {
                let path = ActorPath::from(format!(
                    "/user/node/subject_manager/{}",
                    subject_id
                ));
                let governance =
                    ctx.system().get_actor::<Governance>(&path).await?;
                let response =
                    governance.ask(GovernanceMessage::GetMetadata).await?;
                let GovernanceResponse::Metadata(metadata) = response else {
                    return Err(ActorError::UnexpectedResponse {
                        path,
                        expected: "GovernanceResponse::Metadata".to_owned(),
                    });
                };
                let hi_sn = to_sn
                    .map(|to_sn| to_sn.min(metadata.sn))
                    .unwrap_or(metadata.sn);
                let ledger =
                    self.collect_governance_ledger(ctx, &subject_id, hi_sn)
                        .await?;
                replay_ledgers_to_sink_events(
                    &ledger,
                    &public_key,
                    from_sn,
                    to_sn,
                    limit,
                    sink_timestamp,
                )
            }
            SubjectData::Tracker { .. } => {
                let subject_manager =
                    ctx.get_child::<SubjectManager>("subject_manager").await?;
                let requester = format!(
                    "node_replay_sink_events:{}:{}:{}",
                    subject_id, from_sn, limit
                );
                subject_manager
                    .ask(SubjectManagerMessage::Up {
                        subject_id: subject_id.clone(),
                        requester: requester.clone(),
                        create_ledger: None,
                    })
                    .await?;

                let result = async {
                    let path = ActorPath::from(format!(
                        "/user/node/subject_manager/{}",
                        subject_id
                    ));
                    let tracker =
                        ctx.system().get_actor::<Tracker>(&path).await?;
                    let response =
                        tracker.ask(TrackerMessage::GetMetadata).await?;
                    let TrackerResponse::Metadata(metadata) = response else {
                        return Err(ActorError::UnexpectedResponse {
                            path,
                            expected: "TrackerResponse::Metadata".to_owned(),
                        });
                    };
                    let hi_sn = to_sn
                        .map(|to_sn| to_sn.min(metadata.sn))
                        .unwrap_or(metadata.sn);
                    let ledger =
                        self.collect_tracker_ledger(ctx, &subject_id, hi_sn)
                            .await?;
                    replay_ledgers_to_sink_events(
                        &ledger,
                        &public_key,
                        from_sn,
                        to_sn,
                        limit,
                        sink_timestamp,
                    )
                }
                .await;

                let _ = subject_manager
                    .ask(SubjectManagerMessage::Finish {
                        subject_id,
                        requester,
                    })
                    .await;

                result
            }
        }
    }
}

/// Node message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeMessage {
    GetGovernances,
    GetSinkEvents {
        subject_id: DigestIdentifier,
        from_sn: u64,
        to_sn: Option<u64>,
        limit: u64,
    },
    SignRequest(Box<SignTypesNode>),
    PendingTransfers,
    RegisterSubject {
        owner: PublicKey,
        subject_id: DigestIdentifier,
        data: SubjectData,
    },
    GetSubjectData(DigestIdentifier),
    GovernanceTrackers(DigestIdentifier),
    DeleteSubject(DigestIdentifier),
    IOwnerNewOwnerSubject(DigestIdentifier),
    ICanSendLastLedger(DigestIdentifier),
    AuthData(DigestIdentifier),
    TransferSubject(TransferSubject),
    RejectTransfer(DigestIdentifier),
    ConfirmTransfer(DigestIdentifier),
    EOLSubject {
        subject_id: DigestIdentifier,
        i_owner: bool,
    },
}

impl Message for NodeMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::TransferSubject(..)
                | Self::DeleteSubject(..)
                | Self::RejectTransfer(..)
                | Self::ConfirmTransfer(..)
                | Self::EOLSubject { .. }
        )
    }
}

/// Node response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeResponse {
    Governances(Vec<DigestIdentifier>),
    SinkEvents(SinkEventsPage),
    SubjectData(Option<SubjectData>),
    GovernanceTrackers(Vec<DigestIdentifier>),
    PendingTransfers(Vec<TransferSubject>),
    SignRequest(Signature),
    IOwnerNewOwner {
        i_owner: bool,
        i_new_owner: Option<bool>,
    },
    AuthData {
        auth: bool,
        subject_data: Option<SubjectData>,
    },
    Ok,
}

impl Response for NodeResponse {}

/// Node event.
#[derive(
    Clone, Debug, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum NodeEvent {
    RegisterSubject {
        owner: PublicKey,
        subject_id: DigestIdentifier,
        data: SubjectData,
    },
    DeleteSubject(DigestIdentifier),
    TransferSubject(TransferSubject),
    RejectTransfer(DigestIdentifier),
    ConfirmTransfer(DigestIdentifier),
    EOLSubject {
        subject_id: DigestIdentifier,
        i_owner: bool,
    },
}

impl Event for NodeEvent {}

#[async_trait]
impl Actor for Node {
    type Event = NodeEvent;
    type Message = NodeMessage;
    type Response = NodeResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Node"),
            |parent_span| info_span!(parent: parent_span, "Node"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = Self::build_compilation_dir(ctx).await {
            error!(
                error = %e,
                "Failed to build compilation directory"
            );
            return Err(e);
        }

        // Start store
        if let Err(e) = self.init_store("node", None, true, ctx).await {
            error!(
                error = %e,
                "Failed to initialize node store"
            );
            return Err(e);
        }

        let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        else {
            error!("Config helper not found");
            return Err(ActorError::Helper {
                name: "config".to_string(),
                reason: "Not found".to_string(),
            });
        };
        let safe_mode = config.safe_mode;
        let Some(network): Option<Arc<NetworkSender>> =
            ctx.system().get_helper("network").await
        else {
            error!("Network helper not found");
            return Err(ActorError::Helper {
                name: "network".to_string(),
                reason: "Not found".to_string(),
            });
        };

        if !safe_mode {
            let register_actor =
                match ctx.create_child("register", Register).await {
                    Ok(actor) => actor,
                    Err(e) => {
                        error!(error = %e, "Failed to create register child");
                        return Err(e);
                    }
                };

            let Some(ext_db): Option<Arc<ExternalDB>> =
                ctx.system().get_helper("ext_db").await
            else {
                error!("External DB helper not found");
                return Err(ActorError::Helper {
                    name: "ext_db".to_string(),
                    reason: "Not found".to_string(),
                });
            };

            let sink =
                Sink::new(register_actor.subscribe(), ext_db.get_register());
            ctx.system().run_sink(sink).await;

            if let Err(e) = ctx
                .create_child(
                    "manual_distribution",
                    ManualDistribution::new(self.our_key.clone()),
                )
                .await
            {
                error!(
                    error = %e,
                    "Failed to create manual_distribution child"
                );
                return Err(e);
            }

            if let Err(e) = self.create_distributors(ctx, &network).await {
                error!(
                    error = %e,
                    "Failed to create distributors"
                );
                return Err(e);
            }
        }

        let Some(hash) = self.hash else {
            error!("Hash is None during subject manager startup");
            return Err(ActorError::FunctionalCritical {
                description: "Hash is None".to_string(),
            });
        };

        let subject_manager = match ctx
            .create_child(
                "subject_manager",
                SubjectManager::new(
                    self.our_key.clone(),
                    hash,
                    self.is_service,
                ),
            )
            .await
        {
            Ok(actor) => actor,
            Err(e) => {
                error!(error = %e, "Failed to create subject_manager child");
                return Err(e);
            }
        };

        if let Err(e) = subject_manager
            .ask(SubjectManagerMessage::UpGovernances {
                governance_ids: self.governance_ids(),
            })
            .await
        {
            error!(error = %e, "Failed to bootstrap governances");
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child(
                "auth",
                Auth::initial(AuthInitParams {
                    network: network.clone(),
                    our_key: self.our_key.clone(),
                    round_retry_interval_secs: config
                        .sync_update
                        .round_retry_interval_secs,
                    max_round_retries: config.sync_update.max_round_retries,
                    witness_retry_count: config
                        .sync_update
                        .witness_retry_count,
                    witness_retry_interval_secs: config
                        .sync_update
                        .witness_retry_interval_secs,
                }),
            )
            .await
        {
            error!(
                error = %e,
                "Failed to create auth child"
            );
            return Err(e);
        }

        if !safe_mode
            && let Err(e) = ctx
                .create_child(
                    "distributor",
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network,
                        ledger_batch_size: self.ledger_batch_size,
                    },
                )
                .await
        {
            error!(
                error = %e,
                "Failed to create distributor child"
            );
            return Err(e);
        }

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for Node {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: NodeMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<NodeResponse, ActorError> {
        match msg {
            NodeMessage::GetSinkEvents {
                subject_id,
                from_sn,
                to_sn,
                limit,
            } => Ok(NodeResponse::SinkEvents(
                self.replay_sink_events(ctx, subject_id, from_sn, to_sn, limit)
                    .await?,
            )),
            NodeMessage::RegisterSubject {
                owner,
                subject_id,
                data,
            } => {
                let Some(network): Option<Arc<NetworkSender>> =
                    ctx.system().get_helper("network").await
                else {
                    error!(
                        msg_type = "RegisterSubject",
                        subject_id = %subject_id,
                        "Network helper not found"
                    );
                    return Err(ActorError::Helper {
                        name: "network".to_string(),
                        reason: "Not found".to_string(),
                    });
                };

                self.on_event(
                    NodeEvent::RegisterSubject {
                        owner,
                        subject_id: subject_id.clone(),
                        data,
                    },
                    ctx,
                )
                .await;

                let distributor_name = format!("distributor_{}", subject_id);
                if ctx
                    .get_child::<DistriWorker>(&distributor_name)
                    .await
                    .is_err()
                {
                    ctx.create_child(
                        &distributor_name,
                        DistriWorker {
                            our_key: self.our_key.clone(),
                            network,
                            ledger_batch_size: self.ledger_batch_size,
                        },
                    )
                    .await?;
                }

                Ok(NodeResponse::Ok)
            }
            NodeMessage::EOLSubject {
                subject_id,
                i_owner,
            } => {
                self.on_event(
                    NodeEvent::EOLSubject {
                        subject_id: subject_id.clone(),
                        i_owner,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "EOLSubject",
                    subject_id = %subject_id,
                    i_owner = %i_owner,
                    "EOL confirmed"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::GetGovernances => {
                let mut gov_know = self
                    .known_subjects
                    .iter()
                    .filter(|x| matches!(x.1, SubjectData::Governance { .. }))
                    .map(|x| x.0.clone())
                    .collect::<Vec<DigestIdentifier>>();
                let mut gov_owned = self
                    .owned_subjects
                    .iter()
                    .filter(|x| matches!(x.1, SubjectData::Governance { .. }))
                    .map(|x| x.0.clone())
                    .collect::<Vec<DigestIdentifier>>();
                gov_know.append(&mut gov_owned);

                return Ok(NodeResponse::Governances(gov_know));
            }
            NodeMessage::ICanSendLastLedger(subject_id) => {
                let subject_data = if self.reject_subjects.contains(&subject_id)
                {
                    self.known_subjects.get(&subject_id).cloned()
                } else {
                    self.owned_subjects.get(&subject_id).cloned()
                };

                Ok(NodeResponse::SubjectData(subject_data))
            }
            NodeMessage::GetSubjectData(subject_id) => {
                let data = self.get_subject_data(&subject_id);
                if data.is_none() {
                    debug!(
                        msg_type = "GetSubjectData",
                        subject_id = %subject_id,
                        "Subject not found"
                    );
                } else {
                    debug!(
                        msg_type = "GetSubjectData",
                        subject_id = %subject_id,
                        "Subject data retrieved successfully"
                    );
                }

                Ok(NodeResponse::SubjectData(data))
            }
            NodeMessage::GovernanceTrackers(governance_id) => {
                let trackers = self.governance_trackers(&governance_id);

                debug!(
                    msg_type = "GovernanceTrackers",
                    governance_id = %governance_id,
                    count = trackers.len(),
                    "Governance tracker association check completed"
                );

                Ok(NodeResponse::GovernanceTrackers(trackers))
            }
            NodeMessage::DeleteSubject(subject_id) => {
                self.on_event(
                    NodeEvent::DeleteSubject(subject_id.clone()),
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Subject deleted from node state"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::PendingTransfers => {
                let transfers: Vec<TransferSubject> = self
                    .transfer_subjects
                    .iter()
                    .map(|x| TransferSubject {
                        name: x.1.name.clone(),
                        subject_id: x.0.clone(),
                        new_owner: x.1.new_owner.clone(),
                        actual_owner: x.1.actual_owner.clone(),
                    })
                    .collect();

                debug!(
                    msg_type = "PendingTransfers",
                    count = transfers.len(),
                    "Retrieved pending transfers"
                );

                Ok(NodeResponse::PendingTransfers(transfers))
            }
            NodeMessage::RejectTransfer(subject_id) => {
                self.on_event(
                    NodeEvent::RejectTransfer(subject_id.clone()),
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "RejectTransfer",
                    subject_id = %subject_id,
                    "Transfer rejected successfully"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::TransferSubject(data) => {
                let subject_id = data.subject_id.clone();
                self.on_event(NodeEvent::TransferSubject(data), ctx).await;

                debug!(
                    msg_type = "TransferSubject",
                    subject_id = %subject_id,
                    "Subject transfer registered successfully"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::ConfirmTransfer(subject_id) => {
                self.on_event(
                    NodeEvent::ConfirmTransfer(subject_id.clone()),
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "ConfirmTransfer",
                    subject_id = %subject_id,
                    "Transfer confirmed between other parties"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::SignRequest(content) => {
                let content = *content;
                let content_type = match &content {
                    SignTypesNode::EventRequest(_) => "EventRequest",
                    SignTypesNode::ValidationReq(_) => "ValidationReq",
                    SignTypesNode::ValidationRes(_) => "ValidationRes",
                    SignTypesNode::EvaluationReq(_) => "EvaluationReq",
                    SignTypesNode::EvaluationSignature(_) => "EvaluationRes",
                    SignTypesNode::ApprovalReq(_) => "ApprovalReq",
                    SignTypesNode::ApprovalRes(_) => "ApprovalRes",
                    SignTypesNode::LedgerSeal(_) => "LedgerSeal",
                };

                let sign = match content {
                    SignTypesNode::EventRequest(event_req) => {
                        self.sign(&event_req)
                    }
                    SignTypesNode::ValidationReq(validation_req) => {
                        self.sign(&*validation_req)
                    }
                    SignTypesNode::ValidationRes(validation_res) => {
                        self.sign(&validation_res)
                    }
                    SignTypesNode::EvaluationReq(evaluation_req) => {
                        self.sign(&evaluation_req)
                    }
                    SignTypesNode::EvaluationSignature(evaluation_res) => {
                        self.sign(&evaluation_res)
                    }
                    SignTypesNode::ApprovalReq(approval_req) => {
                        self.sign(&approval_req)
                    }
                    SignTypesNode::ApprovalRes(approval_res) => {
                        self.sign(&*approval_res)
                    }
                    SignTypesNode::LedgerSeal(ledger) => self.sign(&ledger),
                }
                .map_err(|e| {
                    error!(
                        msg_type = "SignRequest",
                        content_type = content_type,
                        error = %e,
                        "Failed to sign content"
                    );
                    ActorError::FunctionalCritical {
                        description: format!("Can not sign event: {}", e),
                    }
                })?;

                debug!(
                    msg_type = "SignRequest",
                    content_type = content_type,
                    "Content signed successfully"
                );

                Ok(NodeResponse::SignRequest(sign))
            }
            NodeMessage::IOwnerNewOwnerSubject(subject_id) => {
                let i_owner =
                    self.owned_subjects.keys().any(|x| *x == subject_id);

                let i_new_owner = if let Some(data) =
                    self.transfer_subjects.get(&subject_id)
                {
                    Some(data.new_owner == *self.our_key)
                } else {
                    None
                };

                debug!(
                    msg_type = "OwnerPendingSubject",
                    subject_id = %subject_id,
                    i_owner = i_owner,
                    i_new_owner = i_new_owner,
                    "Checked owner/pending status"
                );

                Ok(NodeResponse::IOwnerNewOwner {
                    i_owner,
                    i_new_owner,
                })
            }
            NodeMessage::AuthData(subject_id) => {
                let authorized_subjects = match ctx
                    .get_child::<Auth>("auth")
                    .await
                {
                    Ok(auth) => {
                        let res = match auth.ask(AuthMessage::GetAuths).await {
                            Ok(res) => res,
                            Err(e) => {
                                error!(
                                    msg_type = "AuthData",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to get authorizations from auth actor"
                                );
                                ctx.system().crash_system();
                                return Err(e);
                            }
                        };
                        let AuthResponse::Auths { subjects } = res else {
                            error!(
                                msg_type = "AuthData",
                                subject_id = %subject_id,
                                "Unexpected response from auth actor"
                            );
                            ctx.system().crash_system();
                            return Err(ActorError::UnexpectedResponse {
                                expected: "AuthResponse::Auths".to_owned(),
                                path: ctx.path().clone() / "auth",
                            });
                        };
                        subjects
                    }
                    Err(e) => {
                        error!(
                            msg_type = "AuthData",
                            subject_id = %subject_id,
                            error = %e,
                            "Auth actor not found"
                        );
                        ctx.system().crash_system();
                        return Err(e);
                    }
                };

                let auth_subj =
                    authorized_subjects.iter().any(|x| x.clone() == subject_id);

                let subj_data = self
                    .known_subjects
                    .get(&subject_id)
                    .or_else(|| self.owned_subjects.get(&subject_id))
                    .cloned();

                debug!(
                    msg_type = "AuthData",
                    subject_id = %subject_id,
                    authorized = auth_subj,
                    subject_data = ?subj_data,
                    "Checked subject authorization status"
                );

                Ok(NodeResponse::AuthData {
                    auth: auth_subj,
                    subject_data: subj_data,
                })
            }
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child actor fault, stopping system"
        );
        ctx.system().crash_system();
        ChildAction::Stop
    }

    async fn on_event(
        &mut self,
        event: NodeEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist node event"
            );
            ctx.system().crash_system();
        }
    }
}

pub struct InitParamsNode {
    pub key_pair: KeyPair,
    pub public_key: Arc<PublicKey>,
    pub hash: HashAlgorithm,
    pub is_service: bool,
    pub ledger_batch_size: u64,
}

#[async_trait]
impl PersistentActor for Node {
    type Persistence = LightPersistence;
    type InitParams = InitParamsNode;

    fn update(&mut self, state: Self) {
        self.owned_subjects = state.owned_subjects;
        self.known_subjects = state.known_subjects;
        self.transfer_subjects = state.transfer_subjects;
        self.reject_subjects = state.reject_subjects
    }

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            hash: Some(params.hash),
            owner: params.key_pair,
            our_key: params.public_key,
            is_service: params.is_service,
            ledger_batch_size: params.ledger_batch_size,
            owned_subjects: HashMap::new(),
            known_subjects: HashMap::new(),
            transfer_subjects: HashMap::new(),
            reject_subjects: HashSet::new(),
        }
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            NodeEvent::EOLSubject {
                subject_id,
                i_owner,
            } => {
                self.eol(subject_id.clone(), *i_owner);
                debug!(
                    event_type = "EOLSubject",
                    subject_id = %subject_id,
                    i_owner = &i_owner,
                    "Applied eol"
                );
            }
            NodeEvent::ConfirmTransfer(subject_id) => {
                self.confirm_transfer(subject_id.clone());
                debug!(
                    event_type = "ConfirmTransfer",
                    subject_id = %subject_id,
                    "Applied transfer confirmation"
                );
            }
            NodeEvent::RegisterSubject {
                subject_id,
                data,
                owner,
            } => {
                self.register_subject(
                    subject_id.clone(),
                    owner.clone(),
                    data.clone(),
                );
                debug!(
                    event_type = "RegisterSubject",
                    subject_id = %subject_id,
                    owner = %owner,
                    "Applied subject registration"
                );
            }
            NodeEvent::DeleteSubject(subject_id) => {
                self.delete_subject(subject_id);
                debug!(
                    event_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Applied subject deletion"
                );
            }
            NodeEvent::RejectTransfer(subject_id) => {
                self.delete_transfer(subject_id);
                debug!(
                    event_type = "RejectTransfer",
                    subject_id = %subject_id,
                    "Applied transfer rejection"
                );
            }
            NodeEvent::TransferSubject(transfer) => {
                self.transfer_subject(transfer.clone());
                debug!(
                    event_type = "TransferSubject",
                    subject_id = %transfer.subject_id,
                    new_owner = %transfer.new_owner,
                    "Applied subject transfer"
                );
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for Node {}
