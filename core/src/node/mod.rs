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
    auth::{Auth, AuthMessage, AuthResponse},
    db::Storable,
    distribution::worker::DistriWorker,
    governance::{Governance, GovernanceMessage, data::GovernanceData},
    helpers::{db::ExternalDB, network::service::NetworkSender},
    manual_distribution::ManualDistribution,
    model::{
        common::node::SignTypesNode,
        event::{Protocols, ValidationMetadata},
    },
    subject::{SignedLedger, SubjectMetadata},
    system::ConfigHelper,
    tracker::{InitParamsTracker, Tracker, TrackerInit, TrackerMessage},
};

use ave_common::{
    SchemaType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signature, keys::KeyPair,
    },
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message, Response, Sink,
};
use ave_actors::{LightPersistence, PersistentActor};
use serde::{Deserialize, Serialize};

pub mod register;

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
            SubjectData::Tracker { schema_id, .. } => schema_id.clone(),
            SubjectData::Governance { .. } => SchemaType::Governance,
        }
    }

    pub fn get_governance_id(&self) -> Option<DigestIdentifier> {
        match self {
            SubjectData::Tracker { governance_id, .. } => {
                Some(governance_id.clone())
            }
            SubjectData::Governance { .. } => None,
        }
    }

    pub fn get_namespace(&self) -> String {
        match self {
            SubjectData::Tracker { namespace, .. } => namespace.clone(),
            SubjectData::Governance { .. } => String::default(),
        }
    }

    pub fn get_active(&self) -> bool {
        match self {
            SubjectData::Tracker { active, .. } => *active,
            SubjectData::Governance { active } => *active,
        }
    }

    pub fn eol(&mut self) {
        match self {
            SubjectData::Tracker { active, .. } => *active = false,
            SubjectData::Governance { active } => *active = false,
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
            owned_subjects,
            known_subjects,
            transfer_subjects,
            reject_subjects,
            is_service: false
        })
    }
}

impl Node {
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
            } else if data.new_owner == *self.our_key {
                if let Some(data) = self.known_subjects.remove(&subject_id) {
                    self.owned_subjects.insert(subject_id, data);
                };
            }
        };
    }

    pub fn eol(&mut self, subject_id: DigestIdentifier, i_owner: bool) {
        if i_owner {
            if let Some(data) = self.owned_subjects.get_mut(&subject_id) {
                data.eol();
            }
        } else {
            if let Some(data) = self.known_subjects.get_mut(&subject_id) {
                data.eol();
            }
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

    fn sign<T: BorshSerialize>(&self, content: &T) -> Result<Signature, ActorError> {
        Signature::new(content, &self.owner)
            .map_err(|e| ActorError::Functional { description: format!("{}", e) })
    }

    async fn build_compilation_dir(
        ctx: &mut ActorContext<Self>,
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

    async fn create_subjects(
        &self,
        ctx: &mut ActorContext<Self>,
        network: &Arc<NetworkSender>,
    ) -> Result<(), ActorError> {
        let Some(ext_db): Option<Arc<ExternalDB>> =
            ctx.system().get_helper("ext_db").await
        else {
            error!("External database helper not found");
            return Err(ActorError::Helper {
                name: "ext_db".to_string(),
                reason: "Not found".to_string(),
            });
        };

        let Some(hash) = self.hash else {
            error!("Hash is None during subject creation");
            return Err(ActorError::FunctionalCritical {
                description: "Hash is None".to_string(),
            });
        };

        for (subject, data) in self.owned_subjects.clone() {
            if let SubjectData::Governance { .. } = data {
                let governance_actor = ctx
                    .create_child(
                        &subject.to_string(),
                        Governance::initial((None, self.our_key.clone(), hash)),
                    )
                    .await?;

                let sink = Sink::new(
                    governance_actor.subscribe(),
                    ext_db.get_subject(),
                );

                ctx.system().run_sink(sink).await;

                ctx.create_child(
                    &format!("distributor_{}", subject),
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network: network.clone(),
                    },
                )
                .await?;
            } else {
                let tracker_actor = ctx
                    .create_child(
                        &subject.to_string(),
                        Tracker::initial(InitParamsTracker {
                            data: None,
                            hash,
                            is_service: self.is_service,
                            public_key: self.our_key.clone()
                        }),
                    )
                    .await?;

                let sink =
                    Sink::new(tracker_actor.subscribe(), ext_db.get_subject());

                ctx.system().run_sink(sink).await;

                ctx.create_child(
                    &format!("distributor_{}", subject),
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network: network.clone(),
                    },
                )
                .await?;
            }
        }

        for (subject, data) in self.known_subjects.clone() {
            let i_new_owner =
                if let Some(transfer) = self.transfer_subjects.get(&subject) {
                    transfer.new_owner == *self.our_key
                } else {
                    false
                };

            if let SubjectData::Governance { .. } = data {
                let governance_actor = ctx
                    .create_child(
                        &subject.to_string(),
                        Governance::initial((None, self.our_key.clone(), hash)),
                    )
                    .await?;

                let sink = Sink::new(
                    governance_actor.subscribe(),
                    ext_db.get_subject(),
                );

                ctx.system().run_sink(sink).await;

                ctx.create_child(
                    &format!("distributor_{}", subject),
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network: network.clone(),
                    },
                )
                .await?;
            } else if i_new_owner {
                let tracker_actor = ctx
                    .create_child(
                        &subject.to_string(),
                        Tracker::initial(InitParamsTracker {
                            data: None,
                            hash,
                            is_service: self.is_service,
                            public_key: self.our_key.clone()
                        }),
                    )
                    .await?;

                let sink =
                    Sink::new(tracker_actor.subscribe(), ext_db.get_subject());

                ctx.system().run_sink(sink).await;

                ctx.create_child(
                    &format!("distributor_{}", subject),
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network: network.clone(),
                    },
                )
                .await?;
            }
        }

        Ok(())
    }
}

/// Node message.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeMessage {
    GetGovernances,
    SignRequest(SignTypesNode),
    PendingTransfers,
    UpSubject {
        subject_id: DigestIdentifier,
        light: bool,
    },
    GetSubjectData(DigestIdentifier),
    CreateNewSubject(SignedLedger),
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

impl Message for NodeMessage {}

/// Node response.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeResponse {
    Governances(Vec<DigestIdentifier>),
    SubjectData(Option<SubjectData>),
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
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Node")
        } else {
            info_span!("Node")
        }
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

        let Some(network): Option<Arc<NetworkSender>> =
            ctx.system().get_helper("network").await
        else {
            error!("Network helper not found");
            return Err(ActorError::Helper {
                name: "network".to_string(),
                reason: "Not found".to_string(),
            });
        };

        if let Err(e) =
            ctx.create_child("register", Register::initial(())).await
        {
            error!(
                error = %e,
                "Failed to create register child"
            );
            return Err(e);
        }

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

        if let Err(e) = self.create_subjects(ctx, &network).await {
            error!(
                error = %e,
                "Failed to create subjects"
            );
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child(
                "auth",
                Auth::initial(network.clone()),
            )
            .await
        {
            error!(
                error = %e,
                "Failed to create auth child"
            );
            return Err(e);
        }

        if let Err(e) = ctx
            .create_child(
                "distributor",
                DistriWorker {
                    our_key: self.our_key.clone(),
                    network,
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

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.stop_store(ctx).await {
            error!(
                error = %e,
                "Failed to stop node store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Node> for Node {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: NodeMessage,
        ctx: &mut ave_actors::ActorContext<Node>,
    ) -> Result<NodeResponse, ActorError> {
        match msg {
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
                    .filter(|x| {
                        if let SubjectData::Governance { .. } = x.1 {
                            true
                        } else {
                            false
                        }
                    })
                    .map(|x| x.0.clone())
                    .collect::<Vec<DigestIdentifier>>();
                let mut gov_owned = self
                    .owned_subjects
                    .iter()
                    .filter(|x| {
                        if let SubjectData::Governance { .. } = x.1 {
                            true
                        } else {
                            false
                        }
                    })
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
            NodeMessage::UpSubject { subject_id, light } => {
                let Some(ext_db): Option<Arc<ExternalDB>> =
                    ctx.system().get_helper("ext_db").await
                else {
                    error!(
                        msg_type = "UpSubject",
                        subject_id = %subject_id,
                        "External database helper not found"
                    );
                    return Err(ActorError::Helper {
                        name: "ext_db".to_string(),
                        reason: "Not found".to_string(),
                    });
                };

                let Some(hash) = self.hash else {
                    error!(
                        msg_type = "UpSubject",
                        subject_id = %subject_id,
                        "Hash is None"
                    );
                    return Err(ActorError::FunctionalCritical {
                        description: "Hash is None".to_string(),
                    });
                };

                let tracker_actor = ctx
                    .create_child(
                        &subject_id.to_string(),
                        Tracker::initial(InitParamsTracker {
                            data: None,
                            hash,
                            is_service: self.is_service,
                            public_key: self.our_key.clone()
                        }),
                    )
                    .await?;
                if !light {
                    let sink = Sink::new(
                        tracker_actor.subscribe(),
                        ext_db.get_subject(),
                    );
                    ctx.system().run_sink(sink).await;
                }

                debug!(
                    msg_type = "UpSubject",
                    subject_id = %subject_id,
                    light = light,
                    "Subject brought up successfully"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::GetSubjectData(subject_id) => {
                let data = if let Some(data) =
                    self.owned_subjects.get(&subject_id)
                {
                    Some(data.clone())
                } else if let Some(data) = self.known_subjects.get(&subject_id)
                {
                    Some(data.clone())
                } else {
                    debug!(
                        msg_type = "GetSubjectData",
                        subject_id = %subject_id,
                        "Subject not found"
                    );

                    None
                };

                debug!(
                    msg_type = "GetSubjectData",
                    subject_id = %subject_id,
                    "Subject data retrieved successfully"
                );

                Ok(NodeResponse::SubjectData(data))
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
            NodeMessage::CreateNewSubject(ledger) => {
                let Some(ext_db): Option<Arc<ExternalDB>> =
                    ctx.system().get_helper("ext_db").await
                else {
                    error!(
                        msg_type = "CreateNewSubject",
                        "External database helper not found"
                    );
                    return Err(ActorError::Helper {
                        name: "ext_db".to_string(),
                        reason: "Not found".to_string(),
                    });
                };

                let Some(network): Option<Arc<NetworkSender>> =
                    ctx.system().get_helper("network").await
                else {
                    error!(
                        msg_type = "CreateNewSubject",
                        "Network helper not found"
                    );
                    return Err(ActorError::Helper {
                        name: "network".to_string(),
                        reason: "Not found".to_string(),
                    });
                };

                let Some(hash) = self.hash else {
                    error!(msg_type = "CreateNewSubject", "Hash is None");
                    return Err(ActorError::FunctionalCritical {
                        description: "Hash is None".to_string(),
                    });
                };

                let metadata = match &ledger.content().protocols {
                    Protocols::Create { validation } => {
                        if let ValidationMetadata::Metadata(metadata) =
                            &validation.validation_metadata
                        {
                            metadata.clone()
                        } else {
                            error!(
                                msg_type = "CreateNewSubject",
                                "ValidationMetadata must be Metadata in Create event"
                            );
                            return Err(ActorError::Functional { description: "In Create event ValidationMetadata must be Metadata".to_string() });
                        }
                    }
                    _ => {
                        error!(
                            msg_type = "CreateNewSubject",
                            "Event must be a Create event"
                        );
                        return Err(ActorError::Functional {
                            description: "Event must be a Create event"
                                .to_string(),
                        });
                    }
                };

                let subject_id = metadata.subject_id.to_string();

                let subject_data = if metadata.schema_id.is_gov() {
                    let subject_metadata = SubjectMetadata::new(&metadata);
                    let governance_data =
                        serde_json::from_value::<GovernanceData>(
                            metadata.properties.0,
                        )
                        .map_err(|e| {
                            error!(
                                msg_type = "CreateNewSubject",
                                subject_id = %subject_id,
                                error = %e,
                                "Governance properties must be GovernanceData"
                            );
                            ActorError::Functional { description: format!("In governance properties must be a GovernanceData: {e}")}
                        })?;

                    let governance = Governance::initial((
                        Some((subject_metadata, governance_data)),
                        self.our_key.clone(),
                        hash,
                    ));

                    let governance_actor =
                        ctx.create_child(&subject_id, governance).await?;

                    let sink = Sink::new(
                        governance_actor.subscribe(),
                        ext_db.get_subject(),
                    );
                    ctx.system().run_sink(sink).await;

                    if let Err(e) = governance_actor
                        .ask(GovernanceMessage::UpdateLedger {
                            events: vec![ledger.clone()],
                        })
                        .await
                    {
                        error!(
                            msg_type = "CreateNewSubject",
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to update governance ledger"
                        );
                        governance_actor.tell_stop().await;
                        return Err(e);
                    };

                    debug!(
                        msg_type = "CreateNewSubject",
                        subject_id = %subject_id,
                        "Governance subject created successfully"
                    );

                    SubjectData::Governance { active: true }
                } else {
                    let tracker_init = TrackerInit::from(&metadata);

                    let tracker = Tracker::initial(
                        InitParamsTracker {
                            data: Some(tracker_init),
                            hash,
                            is_service: self.is_service,
                            public_key: self.our_key.clone()
                        });

                    let tracker_actor =
                        ctx.create_child(&subject_id, tracker).await?;

                    let sink = Sink::new(
                        tracker_actor.subscribe(),
                        ext_db.get_subject(),
                    );
                    ctx.system().run_sink(sink).await;

                    if let Err(e) = tracker_actor
                        .ask(TrackerMessage::UpdateLedger {
                            events: vec![ledger.clone()],
                        })
                        .await
                    {
                        error!(
                            msg_type = "CreateNewSubject",
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to update tracker ledger"
                        );
                        tracker_actor.tell_stop().await;
                        return Err(e);
                    };

                    debug!(
                        msg_type = "CreateNewSubject",
                        subject_id = %subject_id,
                        governance_id = %metadata.governance_id,
                        "Tracker subject created successfully"
                    );

                    SubjectData::Tracker {
                        governance_id: metadata.governance_id.clone(),
                        schema_id: metadata.schema_id.clone(),
                        namespace: metadata.namespace.to_string(),
                        active: true,
                    }
                };

                self.on_event(
                    NodeEvent::RegisterSubject {
                        subject_id: metadata.subject_id.clone(),
                        owner: metadata.owner.clone(),
                        data: subject_data,
                    },
                    ctx,
                )
                .await;

                ctx.create_child(
                    &format!("distributor_{}", subject_id),
                    DistriWorker {
                        our_key: self.our_key.clone(),
                        network,
                    },
                )
                .await?;

                debug!(
                    msg_type = "CreateNewSubject",
                    subject_id = %subject_id,
                    "New subject and distributor created successfully"
                );

                Ok(NodeResponse::Ok)
            }
            NodeMessage::SignRequest(content) => {
                let content_type = match &content {
                    SignTypesNode::EventRequest(_) => "EventRequest",
                    SignTypesNode::ValidationReq(_) => "ValidationReq",
                    SignTypesNode::ValidationRes(_) => "ValidationRes",
                    SignTypesNode::EvaluationReq(_) => "EvaluationReq",
                    SignTypesNode::EvaluationRes(_) => "EvaluationRes",
                    SignTypesNode::ApprovalReq(_) => "ApprovalReq",
                    SignTypesNode::ApprovalRes(_) => "ApprovalRes",
                    SignTypesNode::Ledger(_) => "Ledger",
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
                    SignTypesNode::EvaluationRes(evaluation_res) => {
                        self.sign(&evaluation_res)
                    }
                    SignTypesNode::ApprovalReq(approval_req) => {
                        self.sign(&approval_req)
                    }
                    SignTypesNode::ApprovalRes(approval_res) => {
                        self.sign(&*approval_res)
                    }
                    SignTypesNode::Ledger(ledger) => self.sign(&ledger),
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
                                ctx.system().stop_system();
                                return Err(e);
                            }
                        };
                        let AuthResponse::Auths { subjects } = res else {
                            error!(
                                msg_type = "AuthData",
                                subject_id = %subject_id,
                                "Unexpected response from auth actor"
                            );
                            ctx.system().stop_system();
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
                            "Auth actor not found"
                        );
                        ctx.system().stop_system();
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
        ctx: &mut ActorContext<Node>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child actor fault, stopping system"
        );
        ctx.system().stop_system();
        ChildAction::Stop
    }

    async fn on_event(
        &mut self,
        event: NodeEvent,
        ctx: &mut ActorContext<Node>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist node event"
            );
            ctx.system().stop_system();
        }
    }
}

pub struct InitParamsNode {
    pub key_pair: KeyPair,
    pub public_key: Arc<PublicKey>,
    pub hash: HashAlgorithm,
    pub is_service: bool
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

#[cfg(test)]
pub mod tests {}
