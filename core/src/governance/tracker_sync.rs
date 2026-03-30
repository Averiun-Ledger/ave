use std::{
    collections::{HashSet, VecDeque},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use network::ComunicateInfo;
use rand::seq::IteratorRandom;
use tracing::{Span, debug, info_span, warn};

use crate::auth::{Auth, AuthMessage, AuthResponse};
use crate::governance::witnesses_register::{
    CurrentWitnessSubject, WitnessesRegister, WitnessesRegisterMessage,
    WitnessesRegisterResponse,
};
use crate::governance::{
    Governance, GovernanceMessage, GovernanceResponse, model::WitnessesData,
};
use crate::helpers::network::{
    ActorMessage, NetworkMessage, service::NetworkSender,
};
use crate::metrics::try_core_metrics;
use crate::model::common::node::get_subject_data;
use crate::model::common::subject::acquire_subject;
use crate::node::SubjectData;
use crate::tracker::{Tracker, TrackerMessage, TrackerResponse};

#[derive(Debug, Clone)]
pub enum TrackerSyncMessage {
    Tick,
    FetchTimeout { request_nonce: u64 },
    UpdateTimeout { batch_nonce: u64 },
    NetworkRequest(TrackerSyncNetworkRequest),
    NetworkResponse(TrackerSyncNetworkResponse),
}

impl Message for TrackerSyncMessage {}

#[derive(Debug, Clone)]
pub enum TrackerSyncResponse {
    None,
}

impl Response for TrackerSyncResponse {}

#[derive(Debug, Clone)]
struct FetchState {
    peer: PublicKey,
    governance_version: u64,
    request_nonce: u64,
}

#[derive(Debug, Clone)]
struct UpdateState {
    peer: PublicKey,
    governance_version: u64,
    pending_items: VecDeque<CurrentWitnessSubject>,
    next_cursor: Option<DigestIdentifier>,
    active_batch: Vec<ActiveUpdate>,
    batch_nonce: u64,
}

#[derive(Debug, Clone)]
struct ActiveUpdate {
    item: CurrentWitnessSubject,
    last_seen_sn: Option<u64>,
    stalled_checks: u8,
}

#[derive(Debug, Clone, Default)]
enum SyncState {
    #[default]
    Idle,
    Fetching(FetchState),
    Updating(UpdateState),
}

#[derive(Debug, Clone)]
pub struct TrackerSyncConfig {
    pub service: bool,
    pub tick_interval: Duration,
    pub response_timeout: Duration,
    pub page_size: usize,
    pub update_batch_size: usize,
    pub update_timeout: Duration,
}

#[derive(Debug, Clone)]
pub struct TrackerSyncNetworkRequest {
    pub request_nonce: u64,
    pub governance_version: u64,
    pub after_subject_id: Option<DigestIdentifier>,
    pub limit: usize,
    pub info: ComunicateInfo,
    pub sender: PublicKey,
    pub receiver_actor: String,
}

#[derive(Debug, Clone)]
pub struct TrackerSyncNetworkResponse {
    pub peer: PublicKey,
    pub request_nonce: u64,
    pub governance_version: u64,
    pub items: Vec<CurrentWitnessSubject>,
    pub next_cursor: Option<DigestIdentifier>,
}

pub struct TrackerSync {
    governance_id: DigestIdentifier,
    our_key: Arc<PublicKey>,
    network: Arc<NetworkSender>,
    service: bool,
    tick_interval: Duration,
    response_timeout: Duration,
    page_size: usize,
    update_batch_size: usize,
    update_timeout: Duration,
    next_nonce: u64,
    state: SyncState,
}

const MAX_STALLED_UPDATE_CHECKS: u8 = 3;

impl TrackerSync {
    fn observe_round(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_tracker_sync_round(result);
        }
    }

    fn observe_update(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_tracker_sync_update(result);
        }
    }

    pub fn new(
        governance_id: DigestIdentifier,
        our_key: Arc<PublicKey>,
        network: Arc<NetworkSender>,
        config: TrackerSyncConfig,
    ) -> Self {
        Self {
            governance_id,
            our_key,
            network,
            service: config.service,
            tick_interval: config.tick_interval,
            response_timeout: config.response_timeout,
            page_size: config.page_size.max(1),
            update_batch_size: config.update_batch_size.max(1),
            update_timeout: config.update_timeout,
            next_nonce: 0,
            state: SyncState::Idle,
        }
    }

    const fn allocate_nonce(&mut self) -> u64 {
        self.next_nonce += 1;
        self.next_nonce
    }

    async fn schedule_tick(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if !self.service {
            return Ok(());
        }

        let actor = ctx.reference().await?;
        let delay = self.tick_interval;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = actor.tell(TrackerSyncMessage::Tick).await;
        });
        Ok(())
    }

    async fn schedule_fetch_timeout(
        &self,
        ctx: &ActorContext<Self>,
        request_nonce: u64,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let delay = self.response_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = actor
                .tell(TrackerSyncMessage::FetchTimeout { request_nonce })
                .await;
        });
        Ok(())
    }

    async fn schedule_update_timeout(
        &self,
        ctx: &ActorContext<Self>,
        batch_nonce: u64,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let delay = self.update_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = actor
                .tell(TrackerSyncMessage::UpdateTimeout { batch_nonce })
                .await;
        });
        Ok(())
    }

    async fn get_governance_version(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<u64, ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            self.governance_id
        ));
        let actor = ctx.system().get_actor::<Governance>(&path).await?;
        let response = actor.ask(GovernanceMessage::GetVersion).await?;

        match response {
            GovernanceResponse::Version(version) => Ok(version),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "GovernanceResponse::Version".to_owned(),
            }),
        }
    }

    async fn get_governance_peers(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<HashSet<PublicKey>, ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            self.governance_id
        ));
        let actor = ctx.system().get_actor::<Governance>(&path).await?;
        let response = actor.ask(GovernanceMessage::GetGovernance).await?;

        let GovernanceResponse::Governance(governance) = response else {
            return Err(ActorError::UnexpectedResponse {
                path,
                expected: "GovernanceResponse::Governance".to_owned(),
            });
        };

        governance.get_witnesses(WitnessesData::Gov).map_err(|e| {
            ActorError::Functional {
                description: e.to_string(),
            }
        })
    }

    async fn get_auth_peers(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<HashSet<PublicKey>, ActorError> {
        let auth_path = ActorPath::from("/user/node/auth");
        let auth = ctx.system().get_actor::<Auth>(&auth_path).await?;
        match auth
            .ask(AuthMessage::GetAuth {
                subject_id: self.governance_id.clone(),
            })
            .await
        {
            Ok(AuthResponse::Witnesses(mut witnesses)) => {
                witnesses.remove(&*self.our_key);
                Ok(witnesses)
            }
            Ok(_) => Ok(HashSet::new()),
            Err(ActorError::Functional { .. }) => Ok(HashSet::new()),
            Err(error) => Err(error),
        }
    }

    async fn select_peer(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<Option<PublicKey>, ActorError> {
        let mut peers = self.get_governance_peers(ctx).await?;
        peers.extend(self.get_auth_peers(ctx).await?);
        peers.remove(&*self.our_key);

        let mut rng = rand::rng();
        Ok(peers.into_iter().choose(&mut rng))
    }

    async fn start_fetch(
        &mut self,
        ctx: &ActorContext<Self>,
        peer: PublicKey,
        governance_version: u64,
        after_subject_id: Option<DigestIdentifier>,
    ) -> Result<(), ActorError> {
        let request_nonce = self.allocate_nonce();

        self.network
            .send_command(network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info: ComunicateInfo {
                        receiver: peer.clone(),
                        request_id: String::default(),
                        version: 0,
                        receiver_actor: format!(
                            "/user/node/subject_manager/{}/tracker_sync",
                            self.governance_id
                        ),
                    },
                    message: ActorMessage::TrackerSyncReq {
                        subject_id: self.governance_id.clone(),
                        request_nonce,
                        governance_version,
                        after_subject_id,
                        limit: self.page_size,
                        receiver_actor: ctx.path().to_string(),
                    },
                },
            })
            .await?;

        self.state = SyncState::Fetching(FetchState {
            peer,
            governance_version,
            request_nonce,
        });
        self.schedule_fetch_timeout(ctx, request_nonce).await
    }

    async fn get_local_tracker_sn(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<Option<u64>, ActorError> {
        let Some(data) = get_subject_data(ctx, subject_id).await? else {
            return Ok(None);
        };

        if !matches!(data, SubjectData::Tracker { .. }) {
            return Ok(None);
        }

        let requester = format!("tracker_sync_local:{}", subject_id);
        let lease =
            acquire_subject(ctx, subject_id, requester, None, true).await?;
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            subject_id
        ));
        let tracker = ctx.system().get_actor::<Tracker>(&path).await?;
        let response = tracker.ask(TrackerMessage::GetMetadata).await;
        lease.finish(ctx).await?;
        let response = response?;

        match response {
            TrackerResponse::Metadata(metadata) => Ok(Some(metadata.sn)),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "TrackerResponse::Metadata".to_owned(),
            }),
        }
    }

    async fn request_tracker_update(
        &self,
        peer: &PublicKey,
        subject_id: &DigestIdentifier,
        actual_sn: Option<u64>,
    ) -> Result<(), ActorError> {
        self.network
            .send_command(network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info: ComunicateInfo {
                        receiver: peer.clone(),
                        request_id: String::default(),
                        version: 0,
                        receiver_actor: format!(
                            "/user/node/distributor_{}",
                            subject_id
                        ),
                    },
                    message: ActorMessage::DistributionLedgerReq {
                        actual_sn,
                        subject_id: subject_id.clone(),
                    },
                },
            })
            .await
    }

    async fn build_pending_updates(
        &self,
        ctx: &mut ActorContext<Self>,
        items: Vec<CurrentWitnessSubject>,
    ) -> Result<VecDeque<CurrentWitnessSubject>, ActorError> {
        let mut pending_items = VecDeque::new();

        for item in items {
            let local_sn =
                self.get_local_tracker_sn(ctx, &item.subject_id).await?;
            if local_sn.is_none_or(|local_sn| local_sn < item.target_sn) {
                pending_items.push_back(item);
            }
        }

        Ok(pending_items)
    }

    async fn start_update_phase(
        &mut self,
        ctx: &mut ActorContext<Self>,
        peer: PublicKey,
        governance_version: u64,
        pending_items: VecDeque<CurrentWitnessSubject>,
        next_cursor: Option<DigestIdentifier>,
    ) -> Result<(), ActorError> {
        self.state = SyncState::Updating(UpdateState {
            peer,
            governance_version,
            pending_items,
            next_cursor,
            active_batch: Vec::new(),
            batch_nonce: 0,
        });

        self.advance_update_phase(ctx).await
    }

    async fn advance_update_phase(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let current_local_version = self.get_governance_version(ctx).await?;
        let SyncState::Updating(mut state) = std::mem::take(&mut self.state)
        else {
            return Ok(());
        };

        if current_local_version != state.governance_version {
            return self
                .start_fetch(ctx, state.peer, current_local_version, None)
                .await;
        }

        if !state.active_batch.is_empty() {
            let mut still_running =
                Vec::with_capacity(state.active_batch.len());
            for mut active_update in state.active_batch {
                let current_sn = self
                    .get_local_tracker_sn(ctx, &active_update.item.subject_id)
                    .await?;

                if current_sn.is_some_and(|current_sn| {
                    current_sn >= active_update.item.target_sn
                }) {
                    Self::observe_update("completed");
                    continue;
                }

                if current_sn != active_update.last_seen_sn {
                    active_update.last_seen_sn = current_sn;
                    active_update.stalled_checks = 0;
                    still_running.push(active_update);
                    continue;
                }

                active_update.stalled_checks += 1;
                if active_update.stalled_checks < MAX_STALLED_UPDATE_CHECKS {
                    still_running.push(active_update);
                } else {
                    Self::observe_update("stalled");
                    warn!(
                        governance_id = %self.governance_id,
                        subject_id = %active_update.item.subject_id,
                        target_sn = active_update.item.target_sn,
                        current_sn = ?current_sn,
                        "Tracker sync update stalled, skipping subject"
                    );
                }
            }

            state.active_batch = still_running;
            if !state.active_batch.is_empty() {
                let batch_nonce = self.allocate_nonce();
                state.batch_nonce = batch_nonce;
                self.state = SyncState::Updating(state);
                return self.schedule_update_timeout(ctx, batch_nonce).await;
            }
        }

        if state.pending_items.is_empty() {
            if let Some(after_subject_id) = state.next_cursor {
                return self
                    .start_fetch(
                        ctx,
                        state.peer,
                        state.governance_version,
                        Some(after_subject_id),
                    )
                    .await;
            }

            Self::observe_round("completed");
            return self.finish_cycle(ctx).await;
        }

        let batch_nonce = self.allocate_nonce();
        let peer = state.peer.clone();
        let mut active_batch = Vec::with_capacity(self.update_batch_size);
        for _ in 0..self.update_batch_size {
            let Some(item) = state.pending_items.pop_front() else {
                break;
            };
            let last_seen_sn =
                self.get_local_tracker_sn(ctx, &item.subject_id).await?;
            self.request_tracker_update(&peer, &item.subject_id, last_seen_sn)
                .await?;
            Self::observe_update("launched");
            active_batch.push(ActiveUpdate {
                item,
                last_seen_sn,
                stalled_checks: 0,
            });
        }

        state.active_batch = active_batch;
        state.batch_nonce = batch_nonce;
        self.state = SyncState::Updating(state);

        self.schedule_update_timeout(ctx, batch_nonce).await
    }

    async fn handle_tick(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if !self.service || !matches!(self.state, SyncState::Idle) {
            return Ok(());
        }

        let Some(peer) = self.select_peer(ctx).await? else {
            Self::observe_round("no_peer");
            self.schedule_tick(ctx).await?;
            return Ok(());
        };

        let governance_version = self.get_governance_version(ctx).await?;
        Self::observe_round("started");
        self.start_fetch(ctx, peer, governance_version, None).await
    }

    async fn handle_network_request(
        &self,
        ctx: &ActorContext<Self>,
        request: TrackerSyncNetworkRequest,
    ) -> Result<(), ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/witnesses_register",
            self.governance_id
        ));
        let actor = ctx.system().get_actor::<WitnessesRegister>(&path).await?;
        let response = actor
            .ask(WitnessesRegisterMessage::ListCurrentWitnessSubjects {
                node: request.sender.clone(),
                governance_version: request.governance_version,
                after_subject_id: request.after_subject_id,
                limit: request.limit,
            })
            .await?;

        let WitnessesRegisterResponse::CurrentWitnessSubjects {
            governance_version,
            items,
            next_cursor,
        } = response
        else {
            return Err(ActorError::UnexpectedResponse {
                path,
                expected: "WitnessesRegisterResponse::CurrentWitnessSubjects"
                    .to_owned(),
            });
        };

        self.network
            .send_command(network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info: ComunicateInfo {
                        receiver: request.sender,
                        request_id: request.info.request_id,
                        version: request.info.version,
                        receiver_actor: request.receiver_actor,
                    },
                    message: ActorMessage::TrackerSyncRes {
                        request_nonce: request.request_nonce,
                        governance_version,
                        items,
                        next_cursor,
                    },
                },
            })
            .await
    }

    async fn finish_cycle(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.state = SyncState::Idle;
        self.schedule_tick(ctx).await
    }
}

#[async_trait]
impl Actor for TrackerSync {
    type Event = ();
    type Message = TrackerSyncMessage;
    type Response = TrackerSyncResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("TrackerSync"),
            |parent| info_span!(parent: parent, "TrackerSync"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.schedule_tick(ctx).await
    }
}

impl NotPersistentActor for TrackerSync {}

#[async_trait]
impl Handler<Self> for TrackerSync {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TrackerSyncMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<TrackerSyncResponse, ActorError> {
        match msg {
            TrackerSyncMessage::Tick => {
                if let Err(error) = self.handle_tick(ctx).await {
                    Self::observe_round("error");
                    warn!(
                        governance_id = %self.governance_id,
                        error = %error,
                        "Tracker sync tick failed"
                    );
                    self.finish_cycle(ctx).await?;
                }
            }
            TrackerSyncMessage::FetchTimeout { request_nonce } => {
                let timed_out = matches!(
                    &self.state,
                    SyncState::Fetching(state)
                        if state.request_nonce == request_nonce
                );

                if timed_out {
                    Self::observe_round("timeout");
                    debug!(
                        governance_id = %self.governance_id,
                        request_nonce = request_nonce,
                        "Tracker sync fetch timed out"
                    );
                    self.finish_cycle(ctx).await?;
                }
            }
            TrackerSyncMessage::UpdateTimeout { batch_nonce } => {
                let timed_out = matches!(
                    &self.state,
                    SyncState::Updating(state)
                        if state.batch_nonce == batch_nonce
                );

                if timed_out {
                    self.advance_update_phase(ctx).await?;
                }
            }
            TrackerSyncMessage::NetworkRequest(request) => {
                self.handle_network_request(ctx, request).await?;
            }
            TrackerSyncMessage::NetworkResponse(
                TrackerSyncNetworkResponse {
                    peer,
                    request_nonce,
                    governance_version,
                    items,
                    next_cursor,
                },
            ) => {
                let (active_peer, active_governance_version) = match &self.state
                {
                    SyncState::Fetching(state)
                        if state.peer == peer
                            && state.request_nonce == request_nonce =>
                    {
                        (state.peer.clone(), state.governance_version)
                    }
                    _ => return Ok(TrackerSyncResponse::None),
                };

                debug!(
                    governance_id = %self.governance_id,
                    peer = %peer,
                    request_nonce = request_nonce,
                    governance_version = governance_version,
                    item_count = items.len(),
                    has_next = next_cursor.is_some(),
                    "Received tracker sync page"
                );

                let local_governance_version =
                    self.get_governance_version(ctx).await?;
                let effective_governance_version =
                    local_governance_version.max(governance_version);

                if effective_governance_version != active_governance_version {
                    Self::observe_round("gov_changed");
                    self.start_fetch(
                        ctx,
                        active_peer,
                        effective_governance_version,
                        None,
                    )
                    .await?;
                    return Ok(TrackerSyncResponse::None);
                }

                let pending_items =
                    self.build_pending_updates(ctx, items).await?;
                if pending_items.is_empty() {
                    if let Some(after_subject_id) = next_cursor {
                        self.start_fetch(
                            ctx,
                            active_peer,
                            governance_version,
                            Some(after_subject_id),
                        )
                        .await?;
                    } else {
                        Self::observe_round("completed");
                        self.finish_cycle(ctx).await?;
                    }
                    return Ok(TrackerSyncResponse::None);
                }

                self.start_update_phase(
                    ctx,
                    active_peer,
                    governance_version,
                    pending_items,
                    next_cursor,
                )
                .await?;
            }
        }

        Ok(TrackerSyncResponse::None)
    }
}
