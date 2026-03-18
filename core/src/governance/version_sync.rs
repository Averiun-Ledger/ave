use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use rand::seq::IteratorRandom;
use tracing::{Span, debug, info_span, warn};

use crate::auth::{Auth, AuthMessage, AuthResponse};

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
    local_version: u64,
    sample_size: usize,
    tick_interval: Duration,
    response_timeout: Duration,
    governance_peers: HashSet<PublicKey>,
    pending_peers: HashSet<PublicKey>,
    update_target: Option<UpdateTarget>,
}

impl GovernanceVersionSync {
    pub fn new(
        governance_id: DigestIdentifier,
        our_key: Arc<PublicKey>,
        local_version: u64,
        sample_size: usize,
        tick_interval: Duration,
        response_timeout: Duration,
    ) -> Self {
        Self {
            governance_id,
            our_key,
            local_version,
            sample_size: sample_size.max(1),
            tick_interval,
            response_timeout,
            governance_peers: HashSet::new(),
            pending_peers: HashSet::new(),
            update_target: None,
        }
    }

    async fn schedule_tick(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let delay = self.tick_interval;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = actor.tell(GovernanceVersionSyncMessage::Tick).await;
        });
        Ok(())
    }

    async fn schedule_timeout(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let delay = self.response_timeout;
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let _ = actor
                .tell(GovernanceVersionSyncMessage::RoundTimeout)
                .await;
        });
        Ok(())
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

    fn select_peers(
        &self,
        auth_peers: HashSet<PublicKey>,
    ) -> Vec<PublicKey> {
        let mut peers = self.governance_peers.clone();
        peers.extend(auth_peers);
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

    fn peer_version(
        &mut self,
        peer: PublicKey,
        version: u64,
    ) {
        self.pending_peers.remove(&peer);

        if version <= self.local_version {
            return;
        }

        let should_replace = self
            .update_target
            .as_ref()
            .is_none_or(|target| version > target.version);
        if should_replace {
            self.update_target = Some(UpdateTarget { peer, version });
        }
    }

    async fn handle_tick(
        &mut self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.update_target.is_some() {
            self.schedule_tick(ctx).await?;
            return Ok(());
        }

        let auth_peers = self.get_auth_peers(ctx).await?;
        let peers = self.select_peers(auth_peers);

        if peers.is_empty() {
            self.schedule_tick(ctx).await?;
            return Ok(());
        }

        self.pending_peers = peers.into_iter().collect();

        debug!(
            governance_id = %self.governance_id,
            local_version = self.local_version,
            selected_peers = self.pending_peers.len(),
            "Governance version sync tick"
        );

        // The actual network request/response path is integrated later.
        self.schedule_timeout(ctx).await?;
        self.schedule_tick(ctx).await?;

        Ok(())
    }
}

#[async_trait]
impl Actor for GovernanceVersionSync {
    type Event = ();
    type Message = GovernanceVersionSyncMessage;
    type Response = GovernanceVersionSyncResponse;

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
        self.schedule_tick(ctx).await
    }
}

impl NotPersistentActor for GovernanceVersionSync {}

#[async_trait]
impl Handler<Self> for GovernanceVersionSync {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
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
                self.pending_peers.clear();
            }
            GovernanceVersionSyncMessage::PeerVersion { peer, version } => {
                self.peer_version(peer, version);
            }
        }

        Ok(GovernanceVersionSyncResponse::None)
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;

    fn pk(value: &str) -> PublicKey {
        PublicKey::from_str(value).unwrap()
    }

    fn gov_id() -> DigestIdentifier {
        DigestIdentifier::from_str(
            "B3B7tbY0OWp5jVq3OKYwYGQnM2zJ5V8i3G5znQJg4s8A",
        )
        .unwrap()
    }

    fn actor() -> GovernanceVersionSync {
        GovernanceVersionSync::new(
            gov_id(),
            Arc::new(pk("EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbD")),
            5,
            3,
            Duration::from_secs(30),
            Duration::from_secs(5),
        )
    }

    #[test]
    fn refresh_updates_version_and_governance_peers() {
        let mut actor = actor();
        let peer = pk("EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE");

        actor.refresh_governance(
            6,
            HashSet::from([peer.clone(), (*actor.our_key).clone()]),
        );

        assert_eq!(actor.local_version, 6);
        assert_eq!(actor.governance_peers, HashSet::from([peer]));
    }

    #[test]
    fn select_peers_uses_governance_plus_auth() {
        let mut actor = actor();
        let peer_a = pk("EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE");
        let peer_b = pk("EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbF");

        actor.refresh_governance(5, HashSet::from([peer_a.clone()]));
        let peers = actor.select_peers(HashSet::from([
            peer_b.clone(),
            (*actor.our_key).clone(),
        ]));
        let peers: HashSet<_> = peers.into_iter().collect();

        assert_eq!(peers, HashSet::from([peer_a, peer_b]));
    }

    #[test]
    fn peer_version_sets_update_target() {
        let mut actor = actor();
        let peer = pk("EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE");
        actor.pending_peers.insert(peer.clone());

        actor.peer_version(peer.clone(), 6);

        assert!(actor.pending_peers.is_empty());
        assert_eq!(
            actor.update_target,
            Some(UpdateTarget { peer, version: 6 })
        );
    }

    #[test]
    fn refresh_clears_update_target_when_version_is_reached() {
        let mut actor = actor();
        let peer = pk("EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE");
        actor.update_target = Some(UpdateTarget { peer, version: 7 });

        actor.refresh_governance(6, HashSet::new());
        assert!(actor.update_target.is_some());

        actor.refresh_governance(7, HashSet::new());
        assert!(actor.update_target.is_none());
    }
}
