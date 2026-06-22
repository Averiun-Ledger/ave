use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response, TimerKey,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use rand::seq::IteratorRandom;
use tracing::{Span, debug, info_span, warn};

use crate::auth::{SubjectAccess, SubjectAccessMessage, SubjectAccessResponse};
use crate::helpers::network::{
    ActorMessage, NetworkMessage, service::NetworkSender,
};
use ave_network::ComunicateInfo;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpdateTarget {
    pub peer: PublicKey,
    pub version: u64,
}

#[derive(Debug, Clone)]
pub enum GovernanceVersionSyncMessage {
    RefreshGovernance {
        version: u64,
        governance_peers: HashSet<PublicKey>,
    },
    Tick,
    RoundTimeout,
    PeerVersion {
        peer: PublicKey,
        version: u64,
    },
}

impl Message for GovernanceVersionSyncMessage {}

#[derive(Debug, Clone)]
pub enum GovernanceVersionSyncResponse {
    None,
}

impl Response for GovernanceVersionSyncResponse {}

pub struct GovernanceVersionSync {
    governance_id: DigestIdentifier,
    our_key: Arc<PublicKey>,
    network: Arc<NetworkSender>,
    local_version: u64,
    sample_size: usize,
    tick_interval: Duration,
    response_timeout: Duration,
    governance_peers: HashSet<PublicKey>,
    pending_peers: HashSet<PublicKey>,
    update_target: Option<UpdateTarget>,
    round_open: bool,
    pending_timeout: Option<TimerKey>,
}

impl GovernanceVersionSync {
    pub fn new(
        governance_id: DigestIdentifier,
        our_key: Arc<PublicKey>,
        network: Arc<NetworkSender>,
        local_version: u64,
        sample_size: usize,
        tick_interval: Duration,
        response_timeout: Duration,
    ) -> Self {
        Self {
            governance_id,
            our_key,
            network,
            local_version,
            sample_size: sample_size.max(1),
            tick_interval,
            response_timeout,
            governance_peers: HashSet::new(),
            pending_peers: HashSet::new(),
            update_target: None,
            round_open: false,
            pending_timeout: None,
        }
    }

    fn schedule_tick(&self, ctx: &ActorContext<Self>) {
        ctx.schedule_once(
            self.tick_interval,
            GovernanceVersionSyncMessage::Tick,
        );
    }

    fn schedule_timeout(&mut self, ctx: &ActorContext<Self>) {
        if let Some(key) = self.pending_timeout.take() {
            ctx.cancel_timer(key);
        }
        let key = ctx.schedule_once(
            self.response_timeout,
            GovernanceVersionSyncMessage::RoundTimeout,
        );
        self.pending_timeout = Some(key);
    }

    fn cancel_timeout(&mut self, ctx: &ActorContext<Self>) {
        if let Some(key) = self.pending_timeout.take() {
            ctx.cancel_timer(key);
        }
    }

    fn refresh_governance(
        &mut self,
        version: u64,
        mut governance_peers: HashSet<PublicKey>,
    ) {
        governance_peers.remove(&*self.our_key);
        self.local_version = version;
        self.governance_peers = governance_peers;

        if self
            .update_target
            .as_ref()
            .is_some_and(|target| target.version <= version)
        {
            self.update_target = None;
        }
    }

    async fn trigger_update_if_needed(&self) -> Result<(), ActorError> {
        let Some(UpdateTarget { peer, .. }) = self.update_target.clone() else {
            return Ok(());
        };

        let info = ComunicateInfo {
            receiver: peer,
            request_id: String::default(),
            version: 0,
            receiver_actor: format!(
                "/user/node/distributor_{}",
                self.governance_id
            ),
        };

        self.network
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info,
                    message: ActorMessage::DistributionLedgerReq {
                        actual_sn: Some(self.local_version),
                        target_sn: None,
                        subject_id: self.governance_id.clone(),
                        already_verified_transfer_sn: None,
                    },
                },
            })
            .await
    }

    async fn get_sync_peers(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<HashSet<PublicKey>, ActorError> {
        let access_path = ActorPath::from("/user/node/auth");
        let access = ctx
            .system()
            .get_actor::<SubjectAccess>(&access_path)
            .await?;
        match access
            .ask(SubjectAccessMessage::GetSyncPeers {
                subject_id: self.governance_id.clone(),
            })
            .await
        {
            Ok(SubjectAccessResponse::Peers(mut peers)) => {
                peers.remove(&*self.our_key);
                Ok(peers)
            }
            Ok(_) => Ok(HashSet::new()),
            Err(ActorError::Functional { .. }) => Ok(HashSet::new()),
            Err(error) => Err(error),
        }
    }

    fn select_peers(&self, sync_peers: HashSet<PublicKey>) -> Vec<PublicKey> {
        let mut peers = self.governance_peers.clone();
        peers.extend(sync_peers);
        peers.remove(&*self.our_key);

        if peers.is_empty() {
            return Vec::new();
        }

        let mut rng = rand::rng();
        peers
            .iter()
            .cloned()
            .sample(&mut rng, self.sample_size.min(peers.len()))
    }

    fn peer_version(&mut self, peer: PublicKey, version: u64) -> bool {
        if !self.round_open || !self.pending_peers.remove(&peer) {
            return false;
        }

        if version <= self.local_version {
            return self.pending_peers.is_empty();
        }

        let should_replace = self
            .update_target
            .as_ref()
            .is_none_or(|target| version > target.version);
        if should_replace {
            self.update_target = Some(UpdateTarget { peer, version });
        }

        self.pending_peers.is_empty()
    }

    async fn handle_tick(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.update_target.is_some() {
            self.schedule_tick(ctx);
            return Ok(());
        }

        let sync_peers = self.get_sync_peers(ctx).await?;
        let peers = self.select_peers(sync_peers);

        if peers.is_empty() {
            self.schedule_tick(ctx);
            return Ok(());
        }

        self.pending_peers = peers.into_iter().collect();
        self.round_open = !self.pending_peers.is_empty();

        for peer in self.pending_peers.clone() {
            let message = NetworkMessage {
                info: ComunicateInfo {
                    receiver: peer.clone(),
                    request_id: String::default(),
                    version: 0,
                    receiver_actor: format!(
                        "/user/node/distributor_{}",
                        self.governance_id
                    ),
                },
                message: ActorMessage::GovernanceVersionReq {
                    subject_id: self.governance_id.clone(),
                    receiver_actor: ctx.path().to_string(),
                },
            };

            if let Err(error) = self
                .network
                .send_command(ave_network::CommandHelper::SendMessage {
                    message,
                })
                .await
            {
                warn!(
                    governance_id = %self.governance_id,
                    peer = %peer,
                    error = %error,
                    "Failed to send governance version request"
                );
                self.pending_peers.remove(&peer);
            }
        }

        debug!(
            governance_id = %self.governance_id,
            local_version = self.local_version,
            selected_peers = self.pending_peers.len(),
            "Governance version sync tick"
        );

        // The actual network request/response path is integrated later.
        self.schedule_timeout(ctx);
        self.schedule_tick(ctx);

        Ok(())
    }
}

#[async_trait]
impl Actor for GovernanceVersionSync {
    type Event = ();
    type Message = GovernanceVersionSyncMessage;
    type Response = GovernanceVersionSyncResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("GovernanceVersionSync"),
            |parent| info_span!(parent: parent, "GovernanceVersionSync"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.schedule_tick(ctx);
        Ok(())
    }
}

impl NotPersistentActor for GovernanceVersionSync {}

#[async_trait]
impl Handler<Self> for GovernanceVersionSync {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: GovernanceVersionSyncMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<GovernanceVersionSyncResponse, ActorError> {
        match msg {
            GovernanceVersionSyncMessage::RefreshGovernance {
                version,
                governance_peers,
            } => {
                self.refresh_governance(version, governance_peers);
            }
            GovernanceVersionSyncMessage::Tick => {
                if let Err(error) = self.handle_tick(ctx).await {
                    warn!(
                        governance_id = %self.governance_id,
                        error = %error,
                        "Governance version sync tick failed"
                    );
                }
            }
            GovernanceVersionSyncMessage::RoundTimeout => {
                self.cancel_timeout(ctx);
                if self.round_open {
                    self.round_open = false;
                    self.pending_peers.clear();
                    if let Err(error) = self.trigger_update_if_needed().await {
                        warn!(
                            governance_id = %self.governance_id,
                            error = %error,
                            "Failed to trigger governance update after round timeout"
                        );
                    }
                }
            }
            GovernanceVersionSyncMessage::PeerVersion { peer, version } => {
                if self.peer_version(peer, version) {
                    self.cancel_timeout(ctx);
                    self.round_open = false;
                    if let Err(error) = self.trigger_update_if_needed().await {
                        warn!(
                            governance_id = %self.governance_id,
                            error = %error,
                            "Failed to trigger governance update after round completion"
                        );
                    }
                }
            }
        }

        Ok(GovernanceVersionSyncResponse::None)
    }
}
