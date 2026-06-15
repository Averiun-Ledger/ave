use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message, Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::Namespace;
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{Span, debug, error, info, info_span, warn};

use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::get_subject_data;
use crate::model::common::subject::{
    get_gov_sn, get_tracker_sn_owner, get_witnesses,
};
use crate::node::SubjectData;
use crate::update::UpdateType;
use crate::{
    db::Storable,

    governance::model::WitnessesData,
    model::common::crash_system,
    update::{Update, UpdateMessage, UpdateNew, UpdateSubjectKind},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubjectAccess {
    #[serde(skip)]
    network: Option<Arc<NetworkSender>>,

    #[serde(skip)]
    our_key: Arc<PublicKey>,

    #[serde(skip)]
    round_retry_interval_secs: u64,

    #[serde(skip)]
    max_round_retries: usize,

    #[serde(skip)]
    witness_retry_count: usize,

    #[serde(skip)]
    witness_retry_interval_secs: u64,

    gov_allowlist: HashSet<DigestIdentifier>,
    tracker_banlist: HashSet<DigestIdentifier>,
    sync_peers: HashMap<DigestIdentifier, HashSet<PublicKey>>,
}

#[derive(Clone, Debug)]
pub struct SubjectAccessInitParams {
    pub network: Arc<NetworkSender>,
    pub our_key: Arc<PublicKey>,
    pub round_retry_interval_secs: u64,
    pub max_round_retries: usize,
    pub witness_retry_count: usize,
    pub witness_retry_interval_secs: u64,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum AuthWitness {
    One(PublicKey),
    Many(Vec<PublicKey>),
    None,
}

impl BorshSerialize for SubjectAccess {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.gov_allowlist, writer)?;
        BorshSerialize::serialize(&self.tracker_banlist, writer)?;
        BorshSerialize::serialize(&self.sync_peers, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for SubjectAccess {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        let gov_allowlist = HashSet::<DigestIdentifier>::deserialize_reader(reader)?;
        let tracker_banlist = HashSet::<DigestIdentifier>::deserialize_reader(reader)?;
        let sync_peers = HashMap::<DigestIdentifier, HashSet<PublicKey>>::deserialize_reader(reader)?;
        let network = None;
        let our_key = Arc::new(PublicKey::default());

        Ok(Self {
            network,
            gov_allowlist,
            tracker_banlist,
            sync_peers,
            our_key,
            round_retry_interval_secs: 10,
            max_round_retries: 3,
            witness_retry_count: 3,
            witness_retry_interval_secs: 10,
        })
    }
}

impl SubjectAccess {
    fn witness_to_set(witness: &AuthWitness) -> HashSet<PublicKey> {
        match witness {
            AuthWitness::One(public_key) => HashSet::from([public_key.clone()]),
            AuthWitness::Many(items) => items.iter().cloned().collect(),
            AuthWitness::None => HashSet::default(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum SubjectAccessMessage {
    // GovAllowlist
    AuthorizeGov {
        subject_id: DigestIdentifier,
        witnesses: AuthWitness,
    },
    DisauthorizeGov {
        subject_id: DigestIdentifier,
    },
    IsGovAuthorized {
        subject_id: DigestIdentifier,
    },
    GetAuthorizedGovs,

    // TrackerBanlist
    BanTracker {
        subject_id: DigestIdentifier,
    },
    UnbanTracker {
        subject_id: DigestIdentifier,
    },
    IsTrackerBanned {
        subject_id: DigestIdentifier,
    },
    GetBannedTrackers,

    // SyncPeers
    AddSyncPeers {
        subject_id: DigestIdentifier,
        peers: Vec<PublicKey>,
    },
    RemoveSyncPeers {
        subject_id: DigestIdentifier,
        peers: Vec<PublicKey>,
    },
    GetSyncPeers {
        subject_id: DigestIdentifier,
    },
    GetSubjectsWithSyncPeers,

    // Access info
    GetAccessInfo {
        subject_id: DigestIdentifier,
    },

    // Cleanup
    ClearSubject {
        subject_id: DigestIdentifier,
    },

    // Update
    Update {
        subject_id: DigestIdentifier,
        objective: Option<PublicKey>,
        strict: bool,
    },
}

impl Message for SubjectAccessMessage {}

#[derive(Debug, Clone)]
pub enum SubjectAccessResponse {
    Bool(bool),
    Subjects(Vec<DigestIdentifier>),
    Peers(HashSet<PublicKey>),
    AccessInfo {
        is_gov_authorized: bool,
        is_tracker_banned: bool,
    },
    None,
}

impl Response for SubjectAccessResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum SubjectAccessEvent {
    GovAuthorized {
        subject_id: DigestIdentifier,
        witnesses: AuthWitness,
    },
    GovDisauthorized {
        subject_id: DigestIdentifier,
    },
    TrackerBanned {
        subject_id: DigestIdentifier,
    },
    TrackerUnbanned {
        subject_id: DigestIdentifier,
    },
    SyncPeersAdded {
        subject_id: DigestIdentifier,
        peers: Vec<PublicKey>,
    },
    SyncPeersRemoved {
        subject_id: DigestIdentifier,
        peers: Vec<PublicKey>,
    },
    SubjectCleared {
        subject_id: DigestIdentifier,
    },
}

impl Event for SubjectAccessEvent {}

#[async_trait]
impl Actor for SubjectAccess {
    type Event = SubjectAccessEvent;
    type Message = SubjectAccessMessage;
    type Response = SubjectAccessResponse;
    type SinkEvent = ();
        type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("SubjectAccess"),
            |parent_span| info_span!(parent: parent_span, "SubjectAccess"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.init_store("auth", None, false, ctx).await {
            error!(
                error = %e,
                "Failed to initialize subject_access store"
            );
            return Err(e);
        }

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for SubjectAccess {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: SubjectAccessMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<SubjectAccessResponse, ActorError> {
        match msg {
            // GovAllowlist
            SubjectAccessMessage::AuthorizeGov {
                subject_id,
                witnesses,
            } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::GovAuthorized {
                        subject_id: subject_id.clone(),
                        witnesses,
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "AuthorizeGov",
                    subject_id = %subject_id,
                    "Governance authorized"
                );
            }
            SubjectAccessMessage::DisauthorizeGov { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::GovDisauthorized {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "DisauthorizeGov",
                    subject_id = %subject_id,
                    "Governance disauthorized"
                );
            }
            SubjectAccessMessage::IsGovAuthorized { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                let authorized = self.gov_allowlist.contains(&subject_id);
                return Ok(SubjectAccessResponse::Bool(authorized));
            }
            SubjectAccessMessage::GetAuthorizedGovs => {
                let subjects: Vec<DigestIdentifier> =
                    self.gov_allowlist.iter().cloned().collect();
                return Ok(SubjectAccessResponse::Subjects(subjects));
            }

            // TrackerBanlist
            SubjectAccessMessage::BanTracker { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::TrackerBanned {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "BanTracker",
                    subject_id = %subject_id,
                    "Tracker banned"
                );
            }
            SubjectAccessMessage::UnbanTracker { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::TrackerUnbanned {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "UnbanTracker",
                    subject_id = %subject_id,
                    "Tracker unbanned"
                );
            }
            SubjectAccessMessage::IsTrackerBanned { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                let banned = self.tracker_banlist.contains(&subject_id);
                return Ok(SubjectAccessResponse::Bool(banned));
            }
            SubjectAccessMessage::GetBannedTrackers => {
                let subjects: Vec<DigestIdentifier> =
                    self.tracker_banlist.iter().cloned().collect();
                return Ok(SubjectAccessResponse::Subjects(subjects));
            }

            // SyncPeers
            SubjectAccessMessage::AddSyncPeers { subject_id, peers } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                if peers.is_empty() {
                    return Err(ActorError::Functional {
                        description: "peers cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::SyncPeersAdded {
                        subject_id: subject_id.clone(),
                        peers: peers.clone(),
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "AddSyncPeers",
                    subject_id = %subject_id,
                    count = peers.len(),
                    "Sync peers added"
                );
            }
            SubjectAccessMessage::RemoveSyncPeers { subject_id, peers } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                if peers.is_empty() {
                    return Err(ActorError::Functional {
                        description: "peers cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::SyncPeersRemoved {
                        subject_id: subject_id.clone(),
                        peers: peers.clone(),
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "RemoveSyncPeers",
                    subject_id = %subject_id,
                    count = peers.len(),
                    "Sync peers removed"
                );
            }
            SubjectAccessMessage::GetSyncPeers { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                let peers = self
                    .sync_peers
                    .get(&subject_id)
                    .cloned()
                    .unwrap_or_default();
                return Ok(SubjectAccessResponse::Peers(peers));
            }
            SubjectAccessMessage::GetSubjectsWithSyncPeers => {
                let subjects: Vec<DigestIdentifier> =
                    self.sync_peers.keys().cloned().collect();
                return Ok(SubjectAccessResponse::Subjects(subjects));
            }

            // Access info
            SubjectAccessMessage::GetAccessInfo { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                let is_gov_authorized = self.gov_allowlist.contains(&subject_id);
                let is_tracker_banned = self.tracker_banlist.contains(&subject_id);
                return Ok(SubjectAccessResponse::AccessInfo {
                    is_gov_authorized,
                    is_tracker_banned,
                });
            }

            // Cleanup
            SubjectAccessMessage::ClearSubject { subject_id } => {
                if subject_id.is_empty() {
                    return Err(ActorError::Functional {
                        description: "subject_id cannot be empty".to_owned(),
                    });
                }
                self.on_event(
                    SubjectAccessEvent::SubjectCleared {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;
                debug!(
                    msg_type = "ClearSubject",
                    subject_id = %subject_id,
                    "Cleared subject access state"
                );
            }

            // Update
            SubjectAccessMessage::Update {
                subject_id,
                objective,
                strict,
            } => {
                if self.tracker_banlist.contains(&subject_id) {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Refusing update for banned tracker"
                    );
                    return Err(ActorError::Functional {
                        description: "Tracker is banned".to_owned(),
                    });
                }

                let data = get_subject_data(ctx, &subject_id).await?;
                let is_gov = matches!(data, Some(SubjectData::Governance { .. }));

                if is_gov && !self.gov_allowlist.contains(&subject_id) {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Refusing update for unauthorized governance"
                    );
                    return Err(ActorError::Functional {
                        description: "Governance is not authorized".to_owned(),
                    });
                }

                let Some(network) = self.network.clone() else {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Network is none"
                    );
                    return Err(ActorError::FunctionalCritical {
                        description: "network is none".to_string(),
                    });
                };

                let (witnesses, actual_sn, subject_kind_hint) = {
                    let sync_witnesses =
                        self.sync_peers.get(&subject_id).cloned().unwrap_or_default();
                    let (mut witnesses, actual_sn, subject_kind_hint) =
                        if strict {
                            let actual_sn = if let Some(SubjectData::Tracker { governance_id, .. }) = &data {
                                get_tracker_sn_owner(ctx, governance_id, &subject_id)
                                    .await?
                                    .map(|(_, sn)| sn)
                            } else if data.is_some() {
                                Some(get_gov_sn(ctx, &subject_id).await?)
                            } else {
                                None
                            };
                            let kind = if is_gov {
                                Some(UpdateSubjectKind::Governance)
                            } else {
                                Some(UpdateSubjectKind::Tracker)
                            };
                            (sync_witnesses, actual_sn, kind)
                        } else {
                            let (gov_witnesses, actual_sn, subject_kind_hint) =
                                if let Some(ref d) = data {
                                    match d {
                                        SubjectData::Tracker {
                                            governance_id,
                                            schema_id,
                                            namespace,
                                            ..
                                        } => {
                                            if let Some((owner, actual_sn)) =
                                                get_tracker_sn_owner(ctx, governance_id, &subject_id)
                                                    .await?
                                            {
                                                let w = get_witnesses(
                                                    ctx,
                                                    governance_id,
                                                    WitnessesData::Schema {
                                                        creator: owner,
                                                        schema_id: schema_id.clone(),
                                                        namespace: Namespace::from(
                                                            namespace.to_owned(),
                                                        ),
                                                    },
                                                )
                                                .await
                                                .map_err(|e| {
                                                    error!(
                                                        subject_id = %subject_id,
                                                        governance_id = %governance_id,
                                                        error = %e,
                                                        "Failed to get witnesses for tracker schema"
                                                    );
                                                    ActorError::Functional {
                                                        description: e.to_string(),
                                                    }
                                                })?;
                                                (w, Some(actual_sn), Some(UpdateSubjectKind::Tracker))
                                            } else {
                                                (HashSet::default(), None, Some(UpdateSubjectKind::Tracker))
                                            }
                                        }
                                        SubjectData::Governance { .. } => {
                                            let w = get_witnesses(ctx, &subject_id, WitnessesData::Gov)
                                                .await
                                                .map_err(|e| {
                                                    warn!(
                                                        subject_id = %subject_id,
                                                        error = %e,
                                                        "Failed to get witnesses for governance"
                                                    );
                                                    ActorError::Functional {
                                                        description: e.to_string(),
                                                    }
                                                })?;
                                            let sn = get_gov_sn(ctx, &subject_id).await?;
                                            (w, Some(sn), Some(UpdateSubjectKind::Governance))
                                        }
                                    }
                                } else {
                                    (HashSet::default(), None, None)
                                };

                            let mut all_witnesses = gov_witnesses;
                            if let Some(witness) = objective {
                                all_witnesses.insert(witness);
                            }

                            (
                                all_witnesses
                                    .union(&sync_witnesses)
                                    .cloned()
                                    .collect::<HashSet<PublicKey>>(),
                                actual_sn,
                                subject_kind_hint,
                            )
                        };
                    witnesses.remove(&self.our_key);

                    (witnesses, actual_sn, subject_kind_hint)
                };

                if witnesses.is_empty() {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Subject has no witnesses to ask for update"
                    );
                    return Err(ActorError::Functional {
                        description: "The subject has no witnesses to try to ask for an update".to_owned(),
                    });
                } else {
                    let data = UpdateNew {
                        network,
                        subject_id: subject_id.clone(),
                        our_sn: actual_sn,
                        witnesses,
                        update_type: UpdateType::Auth,
                        subject_kind_hint,
                        round_retry_interval_secs: self
                            .round_retry_interval_secs,
                        max_round_retries: self.max_round_retries,
                        witness_retry_count: self.witness_retry_count,
                        witness_retry_interval_secs: self
                            .witness_retry_interval_secs,
                    };

                    let updater = Update::new(data);
                    if let Ok(child) =
                        ctx.create_child(&subject_id.to_string(), updater).await
                    {
                        if let Err(e) = child.tell(UpdateMessage::Run).await {
                            error!(
                                msg_type = "Update",
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to send Run message to update actor"
                            );
                            return Err(crash_system(ctx, e).await);
                        }

                        debug!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            "Update process initiated with multiple witnesses"
                        );
                    } else {
                        info!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            "An update is already in progress."
                        );
                    };
                }
            }
        };

        Ok(SubjectAccessResponse::None)
    }

    async fn on_event(
        &mut self,
        event: SubjectAccessEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(event, ctx).await {
            error!(
                error = %e,
                "Failed to persist subject_access event"
            );
            crash_system(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for SubjectAccess {
    type Persistence = LightPersistence;
    type InitParams = SubjectAccessInitParams;
    type State = Self;

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            network: Some(params.network),
            gov_allowlist: HashSet::new(),
            tracker_banlist: HashSet::new(),
            sync_peers: HashMap::new(),
            our_key: params.our_key,
            round_retry_interval_secs: params.round_retry_interval_secs,
            max_round_retries: params.max_round_retries,
            witness_retry_count: params.witness_retry_count,
            witness_retry_interval_secs: params.witness_retry_interval_secs,
        }
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            SubjectAccessEvent::GovAuthorized {
                subject_id,
                witnesses,
            } => {
                inner.gov_allowlist.insert(subject_id.clone());
                let peers = Self::witness_to_set(witnesses);
                if !peers.is_empty() {
                    inner.sync_peers.insert(subject_id.clone(), peers);
                }
                debug!(
                    event_type = "GovAuthorized",
                    subject_id = %subject_id,
                    "Applied gov authorization"
                );
            }
            SubjectAccessEvent::GovDisauthorized { subject_id } => {
                inner.gov_allowlist.remove(subject_id);
                inner.sync_peers.remove(subject_id);
                debug!(
                    event_type = "GovDisauthorized",
                    subject_id = %subject_id,
                    "Applied gov disauthorization"
                );
            }
            SubjectAccessEvent::TrackerBanned { subject_id } => {
                inner.tracker_banlist.insert(subject_id.clone());
                inner.sync_peers.remove(subject_id);
                debug!(
                    event_type = "TrackerBanned",
                    subject_id = %subject_id,
                    "Applied tracker ban"
                );
            }
            SubjectAccessEvent::TrackerUnbanned { subject_id } => {
                inner.tracker_banlist.remove(subject_id);
                debug!(
                    event_type = "TrackerUnbanned",
                    subject_id = %subject_id,
                    "Applied tracker unban"
                );
            }
            SubjectAccessEvent::SyncPeersAdded { subject_id, peers } => {
                inner.sync_peers
                    .entry(subject_id.clone())
                    .or_default()
                    .extend(peers.iter().cloned());
                debug!(
                    event_type = "SyncPeersAdded",
                    subject_id = %subject_id,
                    "Applied sync peers addition"
                );
            }
            SubjectAccessEvent::SyncPeersRemoved { subject_id, peers } => {
                if let Some(set) = inner.sync_peers.get_mut(subject_id) {
                    for p in peers {
                        set.remove(p);
                    }
                    if set.is_empty() {
                        inner.sync_peers.remove(subject_id);
                    }
                }
                debug!(
                    event_type = "SyncPeersRemoved",
                    subject_id = %subject_id,
                    "Applied sync peers removal"
                );
            }
            SubjectAccessEvent::SubjectCleared { subject_id } => {
                inner.gov_allowlist.remove(subject_id);
                inner.tracker_banlist.remove(subject_id);
                inner.sync_peers.remove(subject_id);
                debug!(
                    event_type = "SubjectCleared",
                    subject_id = %subject_id,
                    "Applied subject clearance"
                );
            }
        };

        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        Arc::new(self.clone())
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        let state = &*state;
        self.gov_allowlist.clone_from(&state.gov_allowlist);
        self.tracker_banlist.clone_from(&state.tracker_banlist);
        self.sync_peers.clone_from(&state.sync_peers);
    }
}

#[async_trait]
impl Storable for SubjectAccess {}
