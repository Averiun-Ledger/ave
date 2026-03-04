//! # Network worker.
//!

use crate::{
    Command, CommandHelper, Config, Error, Event as NetworkEvent, MachineSpec,
    Monitor, MonitorMessage, NodeType, ResolvedSpec,
    behaviour::{Behaviour, Event as BehaviourEvent, ReqResMessage},
    resolve_spec,
    service::NetworkService,
    transport::build_transport,
    utils::{
        Action, Due, IDENTIFY_PROTOCOL, LimitsConfig, MessagesHelper,
        NetworkState, REQRES_PROTOCOL, RetryKind, RetryState, ScheduleType,
        convert_addresses, convert_boot_nodes, is_ephemeral_agent_version,
        peer_id_to_ed25519_pubkey_bytes,
    },
};

use std::{
    collections::{BinaryHeap, HashSet},
    fmt::Debug,
    num::{NonZeroU8, NonZeroUsize},
    pin::Pin,
    time::Duration,
};

use ave_actors::ActorRef;
use ave_common::identity::KeyPair;

use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm,
    identity::{Keypair, ed25519},
    request_response::{self, ResponseChannel},
    swarm::{self, DialError, SwarmEvent, dial_opts::DialOpts},
};

use futures::StreamExt;
use serde::Serialize;
use tokio::{
    sync::mpsc,
    time::{Instant, Sleep, sleep, sleep_until},
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

use bytes::Bytes;
use std::collections::{HashMap, VecDeque};

const TARGET: &str = "ave::network::worker";

/// Maximum number of outbound messages queued per peer while disconnected.
/// When this limit is reached the oldest message is evicted to make room.
const MAX_PENDING_MESSAGES_PER_PEER: usize = 100;

/// Bounded queue of outbound messages for a single peer.
///
/// Keeps the 100 most recent messages; when full the oldest is evicted.
#[derive(Default)]
struct PendingQueue {
    messages: VecDeque<Bytes>,
}

impl PendingQueue {
    /// Enqueue a message. Duplicates (byte-identical messages already in the
    /// queue) are silently dropped. If the count limit is reached the oldest
    /// is evicted and `true` is returned; otherwise `false`.
    fn push(&mut self, message: Bytes) -> bool {
        if self.messages.contains(&message) {
            return false;
        }
        let evicted = if self.messages.len() >= MAX_PENDING_MESSAGES_PER_PEER {
            self.messages.pop_front();
            true
        } else {
            false
        };
        self.messages.push_back(message);
        evicted
    }

    fn drain(&mut self) -> impl Iterator<Item = Bytes> + '_ {
        self.messages.drain(..)
    }

    fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }
}

/// Main network worker. Must be polled in order for the network to advance.
///
/// The worker is responsible for handling the network events and commands.
///
pub struct NetworkWorker<T>
where
    T: Debug + Serialize,
{
    /// Local Peer ID.
    local_peer_id: PeerId,

    /// Network service.
    service: NetworkService,

    /// The libp2p swarm.
    swarm: Swarm<Behaviour>,

    /// The network state.
    state: NetworkState,

    /// The command receiver.
    command_receiver: mpsc::Receiver<Command>,

    /// The command sender to Helper Intermediary.
    helper_sender: Option<mpsc::Sender<CommandHelper<T>>>,

    /// Monitor actor.
    monitor: Option<ActorRef<Monitor>>,

    /// The cancellation token.
    cancel: CancellationToken,

    /// Node type.
    node_type: NodeType,

    /// List of boot noodes.
    boot_nodes: HashMap<PeerId, Vec<Multiaddr>>,

    /// nodes with which it has not been possible to establish a connection by keepAliveTimeout in pre-routing.
    retry_boot_nodes: HashMap<PeerId, Vec<Multiaddr>>,

    /// Pending outbound messages to the peer (bounded by count and bytes).
    pending_outbound_messages: HashMap<PeerId, PendingQueue>,

    pending_inbound_messages: HashMap<PeerId, PendingQueue>,

    /// Ephemeral responses.
    response_channels:
        HashMap<PeerId, VecDeque<ResponseChannel<ReqResMessage>>>,

    /// Successful dials
    successful_dials: u64,

    peer_identify: HashSet<PeerId>,

    retry_by_peer: HashMap<PeerId, RetryState>,

    retry_queue: BinaryHeap<Due>,

    retry_timer: Option<Pin<Box<Sleep>>>,

    peer_action: HashMap<PeerId, Action>,

    reported_network_busy: bool,
    reported_network_busy_causes: Vec<String>,
}

impl<T: Debug + Serialize> NetworkWorker<T> {
    /// Create a new `NetworkWorker`.
    pub fn new(
        keys: &KeyPair,
        config: Config,
        monitor: Option<ActorRef<Monitor>>,
        cancel: CancellationToken,
        machine_spec: Option<MachineSpec>,
    ) -> Result<Self, Error> {
        // Create channels to communicate commands
        info!(target: TARGET, "network initialising");
        let (command_sender, command_receiver) = mpsc::channel(512);

        let key = match keys {
            KeyPair::Ed25519(ed25519_signer) => {
                let sk_bytes = ed25519_signer
                    .secret_key_bytes()
                    .map_err(|e| Error::KeyExtraction(e.to_string()))?;

                let sk = ed25519::SecretKey::try_from_bytes(sk_bytes)
                    .map_err(|e| Error::KeyExtraction(e.to_string()))?;

                let kp = ed25519::Keypair::from(sk);
                Keypair::from(kp)
            }
        };

        // Generate the `PeerId` from the public key.
        let local_peer_id = key.public().to_peer_id();

        let boot_nodes = convert_boot_nodes(&config.boot_nodes);

        // Create the listen addressess.
        let addresses = convert_addresses(&config.listen_addresses)?;

        // Create the listen addressess.
        let external_addresses = convert_addresses(&config.external_addresses)?;

        let node_type = config.node_type.clone();

        // Resolve machine sizing from the declared spec, or auto-detect from host.
        let ResolvedSpec { ram_mb, cpu_cores } = resolve_spec(machine_spec);

        let limits = LimitsConfig::build(ram_mb, cpu_cores);

        // Build transport.
        let transport = build_transport(&key, limits.clone())?;

        let behaviour =
            Behaviour::new(&key.public(), config, cancel.clone(), limits);

        // Create the swarm.
        let mut swarm = Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            swarm::Config::with_tokio_executor()
                .with_idle_connection_timeout(Duration::from_secs(90))
                .with_max_negotiating_inbound_streams(32)
                .with_notify_handler_buffer_size(
                    NonZeroUsize::new(32).expect("32 > 0"),
                )
                .with_per_connection_event_buffer_size(16)
                .with_dial_concurrency_factor(
                    NonZeroU8::new(2).expect("2 > 0"),
                ),
        );

        let service = NetworkService::new(command_sender);

        if addresses.is_empty() {
            // Listen on all tcp addresses.
            swarm
                .listen_on(
                    "/ip4/0.0.0.0/tcp/0"
                        .parse::<Multiaddr>()
                        .map_err(|e| Error::InvalidAddress(e.to_string()))?,
                )
                .map_err(|e| Error::Listen(format!("0.0.0.0:0: {e}")))?;
            info!(target: TARGET, "listening on all interfaces");
        } else {
            // Listen on the external addresses.
            for addr in addresses.iter() {
                info!(target: TARGET, addr = %addr, "listening on address");
                swarm
                    .listen_on(addr.clone())
                    .map_err(|e| Error::Listen(format!("{addr}: {e}")))?;
            }
        }

        if !external_addresses.is_empty() {
            for addr in external_addresses.iter() {
                debug!(target: TARGET, addr = %addr, "external address registered");
                swarm.add_external_address(addr.clone());
            }
        }

        info!(target: TARGET, peer_id = %local_peer_id, "local peer id");

        Ok(Self {
            local_peer_id,
            service,
            swarm,
            state: NetworkState::Start,
            command_receiver,
            helper_sender: None,
            monitor,
            cancel,
            node_type,
            boot_nodes,
            retry_boot_nodes: HashMap::new(),
            pending_outbound_messages: HashMap::default(),
            pending_inbound_messages: HashMap::default(),
            response_channels: HashMap::default(),
            successful_dials: 0,
            peer_identify: HashSet::new(),
            retry_by_peer: HashMap::new(),
            retry_queue: BinaryHeap::new(),
            retry_timer: None,
            peer_action: HashMap::new(),
            reported_network_busy: false,
            reported_network_busy_causes: Vec::new(),
        })
    }

    fn schedule_retry(&mut self, peer: PeerId, schedule_type: ScheduleType) {
        if self.peer_action.contains_key(&peer) {
            return;
        }

        let (kind, addrs) = match schedule_type {
            ScheduleType::Discover => (RetryKind::Discover, vec![]),
            ScheduleType::Dial(multiaddrs) => (RetryKind::Dial, multiaddrs),
        };

        let now = Instant::now();
        let base = Duration::from_millis(250);
        let cap = Duration::from_secs(30);

        let entry = self.retry_by_peer.entry(peer).or_insert(RetryState {
            attempts: 0,
            when: now,
            kind,
            addrs: vec![],
        });

        let when = if matches!(
            (entry.kind, kind),
            (RetryKind::Discover, RetryKind::Dial)
        ) {
            now
        } else {
            if entry.attempts >= 8 {
                self.clear_pending_messages(&peer);
                return;
            }

            // Exponential backoff: 250ms * 2^attempt, capped at 30s
            // attempts 0-7 → ~250ms, 500ms, 1s, 2s, 4s, 8s, 16s, 30s
            let exp = 1u32 << entry.attempts.min(7);
            let mut delay = base * exp;
            if delay > cap {
                delay = cap;
            }

            // jitter 80–120% determinista por peer (sin RNG externo)
            // Fold all bytes to avoid the fixed multihash prefix dominating.
            let hash = peer
                .to_bytes()
                .iter()
                .fold(0u32, |acc, &b| acc.wrapping_add(b as u32));
            let j = 80 + (hash % 41);
            delay = delay * j / 100;

            now + delay
        };

        entry.when = when;
        entry.kind = kind;
        entry.addrs = addrs;

        self.peer_action.insert(peer, Action::from(kind));

        self.retry_queue.push(Due(peer, entry.when));
        self.arm_retry_timer();
    }

    fn arm_retry_timer(&mut self) {
        if let Some(next) = self.retry_queue.peek() {
            match &mut self.retry_timer {
                Some(timer) => timer.as_mut().reset(next.1),
                None => self.retry_timer = Some(Box::pin(sleep_until(next.1))),
            }
        }
    }

    fn drain_due_retries(
        &mut self,
    ) -> Vec<(PeerId, RetryKind, Vec<Multiaddr>)> {
        let now = Instant::now();
        let mut out = Vec::new();
        while let Some(Due(peer, when)) = self.retry_queue.peek().cloned() {
            if when > now {
                break;
            }

            self.retry_queue.pop();
            // Match the exact instant to reject stale Due entries. Multiple Due
            // entries for the same peer can accumulate (e.g. Discover → Dial
            // transition pushes a second entry without removing the first).
            // Comparing `when` (from the popped Due) against `retry_by_peer[peer].when`
            // ensures only the current scheduling cycle fires.
            if let Some(retry) = self.retry_by_peer.get(&peer).cloned()
                && retry.when == when
            {
                self.retry_by_peer
                    .entry(peer)
                    .and_modify(|x| x.attempts += 1);
                out.push((peer, retry.kind, retry.addrs));
            }
        }

        if self.retry_queue.is_empty() {
            self.retry_timer = None;
        } else {
            self.arm_retry_timer();
        }
        out
    }

    /// Add sender helper
    pub fn add_helper_sender(
        &mut self,
        helper_sender: mpsc::Sender<CommandHelper<T>>,
    ) {
        self.helper_sender = Some(helper_sender);
    }

    /// Get the local peer ID.
    pub const fn local_peer_id(&self) -> PeerId {
        self.local_peer_id
    }

    /// Send message to a peer.
    fn send_message(
        &mut self,
        peer: PeerId,
        message: Bytes,
    ) -> Result<(), Error> {
        if let Some(mut responses) = self.response_channels.remove(&peer) {
            while let Some(response_channel) = responses.pop_front() {
                match self
                    .swarm
                    .behaviour_mut()
                    .send_response(response_channel, message.clone())
                {
                    Ok(()) => {
                        if !responses.is_empty() {
                            self.response_channels.insert(peer, responses);
                        }
                        return Ok(());
                    }
                    Err(e) => {
                        debug!(target: TARGET, peer_id = %peer, error = %e, "failed to send response: channel may already be consumed");
                    }
                }
            }
        }

        self.add_pending_outbound_message(peer, message);

        if self.swarm.behaviour_mut().is_known_peer(&peer) {
            if let Some(Action::Identified(..)) = self.peer_action.get(&peer) {
                self.send_pending_outbound_messages(peer);
            } else {
                self.schedule_retry(peer, ScheduleType::Dial(vec![]));
            }
        } else {
            self.schedule_retry(peer, ScheduleType::Discover);
        }

        Ok(())
    }

    /// Add pending message to peer.
    ///
    /// If the count limit is reached the oldest message is evicted to make room.
    fn add_pending_outbound_message(&mut self, peer: PeerId, message: Bytes) {
        let queue = self.pending_outbound_messages.entry(peer).or_default();
        if queue.push(message) {
            warn!(
                target: TARGET,
                peer_id = %peer,
                max_messages = MAX_PENDING_MESSAGES_PER_PEER,
                "outbound queue count limit reached; oldest message evicted",
            );
        }
    }

    /// Add ephemeral response.
    fn add_ephemeral_response(
        &mut self,
        peer: PeerId,
        response_channel: ResponseChannel<ReqResMessage>,
    ) {
        self.response_channels
            .entry(peer)
            .or_default()
            .push_back(response_channel);
    }

    /// Send pending messages to peer.
    fn send_pending_outbound_messages(&mut self, peer: PeerId) {
        if let Some(mut queue) = self.pending_outbound_messages.remove(&peer) {
            for message in queue.drain() {
                self.swarm.behaviour_mut().send_message(&peer, message);
            }
        }

        self.retry_by_peer.remove(&peer);
    }

    /// Get the network service.
    pub fn service(&self) -> NetworkService {
        self.service.clone()
    }

    /// Change the network state.
    async fn change_state(&mut self, state: NetworkState) {
        trace!(target: TARGET, state = ?state, "state changed");
        self.state = state.clone();
        self.send_event(NetworkEvent::StateChanged(state)).await;
        self.emit_network_busy_if_changed().await;
    }

    /// Send event
    #[allow(clippy::needless_pass_by_ref_mut)]
    async fn send_event(&mut self, event: NetworkEvent) {
        if let Some(monitor) = self.monitor.clone()
            && let Err(e) = monitor.tell(MonitorMessage::Network(event)).await
        {
            error!(target: TARGET, error = %e, "failed to forward event to monitor");
            self.cancel.cancel();
        }
    }

    fn network_busy_causes(&self) -> Vec<String> {
        let mut causes = Vec::new();

        if matches!(self.state, NetworkState::Dial | NetworkState::Dialing) {
            causes.push("bootstrap_dialing".to_owned());
        }
        if !self.boot_nodes.is_empty() {
            causes.push("bootstrap_candidates_pending".to_owned());
        }
        if !self.retry_boot_nodes.is_empty() {
            causes.push("bootstrap_retry_pending".to_owned());
        }
        if !self.pending_outbound_messages.is_empty() {
            causes.push("pending_outbound_messages".to_owned());
        }
        if !self.pending_inbound_messages.is_empty() {
            causes.push("pending_inbound_messages".to_owned());
        }
        if !self.response_channels.is_empty() {
            causes.push("pending_response_channels".to_owned());
        }
        if !self.retry_by_peer.is_empty() {
            causes.push("peer_retry_state".to_owned());
        }
        if !self.retry_queue.is_empty() {
            causes.push("retry_queue".to_owned());
        }
        if self.retry_timer.is_some() {
            causes.push("retry_timer_armed".to_owned());
        }
        if self
            .peer_action
            .values()
            .any(|action| matches!(action, Action::Dial | Action::Discover))
        {
            causes.push("peer_actions_pending".to_owned());
        }

        causes
    }

    async fn emit_network_busy_if_changed(&mut self) {
        let causes = self.network_busy_causes();
        let busy = !causes.is_empty();

        if busy != self.reported_network_busy {
            self.reported_network_busy = busy;
            self.send_event(NetworkEvent::BusyChanged(busy)).await;
        }

        if causes != self.reported_network_busy_causes {
            self.reported_network_busy_causes = causes.clone();
            self.send_event(NetworkEvent::BusyCausesChanged(causes)).await;
        }
    }

    /// Run the network worker.
    pub async fn run(&mut self) {
        // Run connection to bootstrap node.
        if let Err(error) = self.run_connection().await {
            error!(target: TARGET, error = %error, "bootstrap connection failed");
            self.send_event(NetworkEvent::Error(error)).await;
            // Irrecoverable error. Cancel the node.
            self.cancel.cancel();
            return;
        }

        self.change_state(NetworkState::Running).await;

        // Finish pre routing state, activating random walk (if node is a bootstrap).
        self.swarm.behaviour_mut().finish_prerouting_state();
        // Run main loop.
        self.run_main().await;
    }

    /// Run connection to bootstrap node.
    pub async fn run_connection(&mut self) -> Result<(), Error> {
        // If is the first node of ave network.
        if self.node_type == NodeType::Bootstrap && self.boot_nodes.is_empty() {
            self.change_state(NetworkState::Running).await;
            Ok(())
        } else {
            self.change_state(NetworkState::Dial).await;

            let mut retrys: u8 = 0;

            // Per-round deadline: if any boot node's TCP connects but Identify never
            // completes (NAT half-open, overloaded peer, protocol stall…), this timer
            // moves the remaining nodes to retry_boot_nodes so the retry logic handles
            // them instead of waiting up to idle_connection_timeout (90 s) per round.
            let dialing_round_timeout = sleep(Duration::from_secs(0));
            tokio::pin!(dialing_round_timeout);
            let mut dialing_timeout_active = false;

            loop {
                match self.state {
                    NetworkState::Dial => {
                        // Dial to boot node.
                        if self.boot_nodes.is_empty() {
                            error!(target: TARGET, "no bootstrap nodes available");
                            self.send_event(NetworkEvent::Error(
                                Error::NoBootstrapNode,
                            ))
                            .await;
                            self.change_state(NetworkState::Disconnected).await;
                        } else {
                            let copy_boot_nodes = self.boot_nodes.clone();

                            for (peer, addresses) in copy_boot_nodes {
                                if let Err(e) = self.swarm.dial(
                                    DialOpts::peer_id(peer)
                                        .addresses(addresses.clone())
                                        .build(),
                                ) {
                                    let (add_to_retry, new_addresses) =
                                        Self::init_dial_error_manager(e, peer);
                                    self.boot_nodes.remove(&peer);
                                    if add_to_retry {
                                        if new_addresses.is_empty() {
                                            self.retry_boot_nodes
                                                .insert(peer, addresses);
                                        } else {
                                            self.retry_boot_nodes
                                                .insert(peer, new_addresses);
                                        }
                                    }
                                }
                            }
                            if !self.boot_nodes.is_empty() {
                                self.change_state(NetworkState::Dialing).await;
                                dialing_round_timeout.as_mut().reset(
                                    Instant::now() + Duration::from_secs(15),
                                );
                                dialing_timeout_active = true;
                            } else {
                                warn!(target: TARGET, "all bootstrap dials failed");
                                self.change_state(NetworkState::Disconnected)
                                    .await;
                            }
                        }
                    }
                    NetworkState::Dialing => {
                        // No more bootnodes to send dial, none was successful nut one or more Dial fail by keepalivetimeout
                        if self.boot_nodes.is_empty()
                            && self.successful_dials == 0
                            && !self.retry_boot_nodes.is_empty()
                            && retrys < 3
                        {
                            retrys += 1;
                            let wait = Duration::from_secs(1u64 << retrys); // retrys=1→2s, retrys=2→4s
                            debug!(target: TARGET, attempt = retrys, wait_secs = wait.as_secs(), "retrying bootstrap dials");

                            let backoff = sleep(wait);
                            tokio::pin!(backoff);
                            loop {
                                tokio::select! {
                                    _ = &mut backoff => break,
                                    event = self.swarm.select_next_some() => {
                                        self.handle_connection_events(event).await;
                                    }
                                    _ = self.cancel.cancelled() => {
                                        return Err(Error::Cancelled);
                                    }
                                }
                            }

                            dialing_timeout_active = false;
                            self.boot_nodes.clone_from(&self.retry_boot_nodes);
                            self.retry_boot_nodes.clear();
                            self.change_state(NetworkState::Dial).await;
                        }
                        // No more bootnodes to send dial and none was successful
                        else if self.boot_nodes.is_empty()
                            && self.successful_dials == 0
                        {
                            self.change_state(NetworkState::Disconnected).await;
                        // No more bootnodes to send dial and one or more was successful
                        } else if self.boot_nodes.is_empty() {
                            return Ok(());
                        }
                    }
                    NetworkState::Running => {
                        return Ok(());
                    }
                    NetworkState::Disconnected => {
                        return Err(Error::NoBootstrapNode);
                    }
                    _ => {}
                }
                if self.state != NetworkState::Disconnected {
                    tokio::select! {
                        event = self.swarm.select_next_some() => {
                            self.handle_connection_events(event).await;
                        }
                        _ = self.cancel.cancelled() => {
                            return Err(Error::Cancelled);
                        }
                        _ = &mut dialing_round_timeout, if dialing_timeout_active => {
                            warn!(
                                target: TARGET,
                                remaining = self.boot_nodes.len(),
                                "bootstrap round timed out waiting for Identify; \
                                 moving remaining peers to retry queue"
                            );
                            for (peer, addrs) in self.boot_nodes.drain() {
                                self.retry_boot_nodes.insert(peer, addrs);
                            }
                            dialing_timeout_active = false;
                        }
                    }
                }
            }
        }
    }

    fn init_dial_error_manager(
        e: DialError,
        peer: PeerId,
    ) -> (bool, Vec<Multiaddr>) {
        match e {
            DialError::LocalPeerId { .. } => {
                warn!(target: TARGET, peer_id = %peer, "dial rejected: connected peer-id matches local peer");
            }
            DialError::NoAddresses => {
                debug!(target: TARGET, peer_id = %peer, "dial skipped: no addresses");
            }
            DialError::DialPeerConditionFalse(_) => {
                debug!(target: TARGET, peer_id = %peer, "dial skipped: peer condition not met");
            }
            DialError::Denied { cause } => {
                debug!(target: TARGET, peer_id = %peer, cause = %cause, "dial denied by behaviour");
            }
            DialError::Aborted => {
                debug!(target: TARGET, peer_id = %peer, "dial aborted, will retry");
                return (true, vec![]);
            }
            DialError::WrongPeerId { obtained, .. } => {
                warn!(target: TARGET, expected = %peer, obtained = %obtained, "dial failed: peer identity mismatch");
            }
            DialError::Transport(items) => {
                debug!(target: TARGET, peer_id = %peer, "transport dial failed");

                let mut new_addresses = vec![];

                for (address, error) in items {
                    trace!(target: TARGET, addr = %address, err = ?error, "address unreachable");

                    if let libp2p::TransportError::Other(e) = error {
                        match e.kind() {
                            std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::NotConnected
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::HostUnreachable
                            | std::io::ErrorKind::NetworkUnreachable => {
                                new_addresses.push(address);
                            }
                            _ => {}
                        }
                    };
                }
                if !new_addresses.is_empty() {
                    return (true, new_addresses);
                }
            }
        }

        (false, vec![])
    }

    fn dial_error_manager(
        &mut self,
        e: DialError,
        peer_id: &PeerId,
    ) -> Option<(bool, Vec<Multiaddr>)> {
        match e {
            DialError::LocalPeerId { .. } | DialError::WrongPeerId { .. } => {
                self.retry_by_peer.remove(peer_id);
                self.clear_pending_messages(peer_id);
                self.swarm
                    .behaviour_mut()
                    .clean_hard_peer_to_remove(peer_id);
                return None;
            }
            DialError::NoAddresses => {}
            DialError::DialPeerConditionFalse(..) => {
                return None;
            }
            DialError::Denied { .. } => {}
            DialError::Aborted => {
                return Some((true, vec![]));
            }
            DialError::Transport(items) => {
                let mut new_addresses = vec![];

                for (address, error) in items {
                    if let libp2p::TransportError::Other(e) = error {
                        match e.kind() {
                            std::io::ErrorKind::ConnectionRefused
                            | std::io::ErrorKind::TimedOut
                            | std::io::ErrorKind::UnexpectedEof
                            | std::io::ErrorKind::ConnectionReset
                            | std::io::ErrorKind::ConnectionAborted
                            | std::io::ErrorKind::NotConnected
                            | std::io::ErrorKind::BrokenPipe
                            | std::io::ErrorKind::Interrupted
                            | std::io::ErrorKind::HostUnreachable
                            | std::io::ErrorKind::NetworkUnreachable => {
                                new_addresses.push(address);
                            }
                            _ => {}
                        }
                    };
                }
                if !new_addresses.is_empty() {
                    return Some((true, new_addresses));
                }
            }
        }

        Some((false, vec![]))
    }

    /// Handle connection events.
    async fn handle_connection_events(
        &mut self,
        event: SwarmEvent<BehaviourEvent>,
    ) {
        match event {
            SwarmEvent::ConnectionClosed { peer_id, .. } => {
                self.boot_nodes.remove(&peer_id);
            }
            SwarmEvent::OutgoingConnectionError {
                peer_id: Some(peer_id),
                error,
                ..
            } => {
                let (add_to_retry, new_addresses) =
                    Self::init_dial_error_manager(error, peer_id);

                if let Some(addresses) = self.boot_nodes.remove(&peer_id)
                    && add_to_retry
                {
                    if new_addresses.is_empty() {
                        self.retry_boot_nodes.insert(peer_id, addresses);
                    } else {
                        self.retry_boot_nodes.insert(peer_id, new_addresses);
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::Identified {
                peer_id,
                info,
                connection_id,
            }) => {
                if !self
                    .check_protocols(&info.protocol_version, &info.protocols)
                {
                    warn!(target: TARGET, peer_id = %peer_id, protocol_version = %info.protocol_version, "peer uses incompatible protocols; closing connection");

                    self.swarm
                        .behaviour_mut()
                        .close_connections(&peer_id, Some(connection_id));
                } else {
                    let peer_is_ephemeral =
                        is_ephemeral_agent_version(&info.agent_version);
                    self.peer_action
                        .insert(peer_id, Action::Identified(connection_id));

                    let mut any_address_is_valid = false;
                    for addr in info.listen_addrs {
                        if self
                            .swarm
                            .behaviour_mut()
                            .add_self_reported_address(&peer_id, &addr)
                        {
                            any_address_is_valid = true;
                        }
                    }

                    if any_address_is_valid {
                        if self.boot_nodes.remove(&peer_id).is_some() {
                            self.successful_dials += 1;
                        }
                        self.peer_identify.insert(peer_id);

                        if peer_is_ephemeral {
                            self.swarm
                                .behaviour_mut()
                                .mark_peer_non_dialable(&peer_id);
                        } else {
                            self.swarm
                                .behaviour_mut()
                                .mark_peer_dialable(&peer_id);
                        }
                    } else {
                        warn!(target: TARGET, peer_id = %peer_id, "bootstrap peer has no valid addresses");
                        if peer_is_ephemeral {
                            self.swarm
                                .behaviour_mut()
                                .mark_peer_non_dialable(&peer_id);
                        }

                        self.swarm
                            .behaviour_mut()
                            .close_connections(&peer_id, Some(connection_id));
                    }
                }
            }
            SwarmEvent::Behaviour(BehaviourEvent::IdentifyError {
                peer_id,
                error,
            }) => {
                match error {
                    swarm::StreamUpgradeError::Timeout => {
                        // Recoverable: wait for ConnectionClosed to remove from boot_nodes.
                    }
                    _ => {
                        // Hard failure: Identify will never complete; move to retry immediately
                        // instead of waiting for the per-round timeout.
                        debug!(target: TARGET, peer_id = %peer_id, error = %error, "identify hard failure during bootstrap; queuing for retry");
                        if let Some(addrs) = self.boot_nodes.remove(&peer_id) {
                            self.retry_boot_nodes.insert(peer_id, addrs);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn clear_pending_messages(&mut self, peer_id: &PeerId) {
        warn!(target: TARGET, peer_id = %peer_id, "max dial attempts reached; dropping pending messages");

        self.pending_outbound_messages.remove(peer_id);
        self.peer_action.remove(peer_id);
        self.retry_by_peer.remove(peer_id);
    }

    fn check_protocols(
        &self,
        protocol_version: &str,
        protocols: &[StreamProtocol],
    ) -> bool {
        let supp_protocols: HashSet<StreamProtocol> = protocols
            .iter()
            .cloned()
            .collect::<HashSet<StreamProtocol>>();

        protocol_version == IDENTIFY_PROTOCOL
            && supp_protocols.contains(&StreamProtocol::new(REQRES_PROTOCOL))
    }

    /// Run network worker.
    pub async fn run_main(&mut self) {
        info!(target: TARGET, "network worker started");

        loop {
            tokio::select! {
                command = self.command_receiver.recv() => {
                    match command {
                        Some(command) => {
                            self.handle_command(command).await;
                            self.emit_network_busy_if_changed().await;
                        }
                        None => break,
                    }
                }
                event = self.swarm.select_next_some() => {
                    // Handle events.
                    self.handle_event(event).await;
                    self.emit_network_busy_if_changed().await;
                }
                _ = async {
                    if let Some(t) = &mut self.retry_timer {
                        t.as_mut().await;
                    }
                }, if self.retry_timer.is_some() => {
                    for (peer, kind, addrs) in self.drain_due_retries() {
                        if let Some(action) = self.peer_action.get(&peer) {
                            match (action, kind) {
                                (Action::Discover, RetryKind::Discover) => {
                                    self.swarm.behaviour_mut().discover(&peer);
                                },
                                (Action::Dial, RetryKind::Dial) => {
                                    let has_pending_messages = self
                                        .pending_outbound_messages
                                        .get(&peer)
                                        .is_some_and(|q| !q.is_empty());

                                    if has_pending_messages {
                                        // Message-driven dial: allow one explicit outbound attempt
                                        // even if the peer is marked non-dialable (ephemeral).
                                        self.swarm
                                            .behaviour_mut()
                                            .allow_next_outbound_dial(&peer);
                                    }

                                    let retry_addrs = addrs.clone();

                                    if let Err(error) = self.swarm.dial(
                                        DialOpts::peer_id(peer)
                                            .addresses(addrs)
                                            .extend_addresses_through_behaviour()
                                            .build()
                                    ) && let Some((retry, new_address)) =
                                        self.dial_error_manager(error, &peer) {

                                        self.peer_action.remove(&peer);
                                        if retry {
                                            let addr = new_address
                                                    .iter()
                                                    .filter(|x| {
                                                        !self
                                                        .swarm
                                                        .behaviour()
                                                        .is_invalid_address(x)
                                                    })
                                                    .cloned()
                                                    .collect::<Vec<Multiaddr>>();

                                                if addr.is_empty() {
                                                    if has_pending_messages {
                                                        self.schedule_retry(
                                                            peer,
                                                            ScheduleType::Dial(retry_addrs),
                                                        );
                                                    } else {
                                                        self.schedule_retry(
                                                            peer,
                                                            ScheduleType::Discover,
                                                        );
                                                    }
                                                } else {
                                                    self.schedule_retry(
                                                        peer,
                                                        ScheduleType::Dial(addr),
                                                    );
                                                }
                                        } else if has_pending_messages {
                                            self.schedule_retry(
                                                peer,
                                                ScheduleType::Dial(retry_addrs),
                                            );
                                        } else {
                                            self.schedule_retry(
                                                peer,
                                                ScheduleType::Discover,
                                            );
                                        }
                                };
                                },
                                _ => {}
                            }
                        };
                    }
                    self.emit_network_busy_if_changed().await;
                },
                _ = self.cancel.cancelled() => {
                    break;
                }
            }
        }
    }

    async fn handle_command(&mut self, command: Command) {
        match command {
            Command::SendMessage { peer, message } => {
                if let Err(error) = self.send_message(peer, message) {
                    error!(target: TARGET, error = %error, "failed to deliver message");
                    self.send_event(NetworkEvent::Error(error)).await;
                }
            }
        }
    }

    #[allow(clippy::needless_pass_by_ref_mut)]
    async fn message_to_helper(
        &mut self,
        message: MessagesHelper,
        peer_id: &PeerId,
    ) {
        let sender = match peer_id_to_ed25519_pubkey_bytes(peer_id) {
            Ok(public_key) => public_key,
            Err(e) => {
                warn!(target: TARGET, error = %e, "cannot resolve public key from peer id");
                return;
            }
        };

        'Send: {
            if let Some(helper_sender) = self.helper_sender.as_ref() {
                match message {
                    MessagesHelper::Single(items) => {
                        if helper_sender
                            .send(CommandHelper::ReceivedMessage {
                                sender,
                                message: items,
                            })
                            .await
                            .is_err()
                        {
                            break 'Send;
                        }
                    }
                    MessagesHelper::Vec(items) => {
                        for item in items {
                            if helper_sender
                                .send(CommandHelper::ReceivedMessage {
                                    sender,
                                    message: item,
                                })
                                .await
                                .is_err()
                            {
                                break 'Send;
                            }
                        }
                    }
                }

                return;
            }
        }

        error!(target: TARGET, "helper channel closed; shutting down");
        self.cancel.cancel();
    }

    async fn handle_event(&mut self, event: SwarmEvent<BehaviourEvent>) {
        match event {
            SwarmEvent::Behaviour(event) => {
                match event {
                    BehaviourEvent::Identified {
                        peer_id,
                        info,
                        connection_id,
                    } => {
                        if !self.check_protocols(
                            &info.protocol_version,
                            &info.protocols,
                        ) {
                            warn!(
                                target: TARGET,
                                peer_id = %peer_id,
                                protocol_version = %info.protocol_version,
                                protocols = ?info.protocols,
                                "peer uses incompatible protocols; closing connection"
                            );

                            self.clear_pending_messages(&peer_id);

                            self.swarm
                                .behaviour_mut()
                                .clean_hard_peer_to_remove(&peer_id);

                            self.swarm.behaviour_mut().close_connections(
                                &peer_id,
                                Some(connection_id),
                            );
                        } else {
                            let peer_is_ephemeral =
                                is_ephemeral_agent_version(&info.agent_version);

                            self.peer_action.insert(
                                peer_id,
                                Action::Identified(connection_id),
                            );

                            self.swarm
                                .behaviour_mut()
                                .clean_peer_to_remove(&peer_id);
                            if peer_is_ephemeral {
                                self.swarm
                                    .behaviour_mut()
                                    .mark_peer_non_dialable(&peer_id);
                            } else {
                                self.swarm
                                    .behaviour_mut()
                                    .mark_peer_dialable(&peer_id);
                            }
                            for addr in info.listen_addrs {
                                self.swarm
                                    .behaviour_mut()
                                    .add_self_reported_address(&peer_id, &addr);
                            }

                            self.peer_identify.insert(peer_id);

                            if let Some(mut queue) =
                                self.pending_inbound_messages.remove(&peer_id)
                            {
                                self.message_to_helper(
                                    MessagesHelper::Vec(
                                        queue.drain().collect(),
                                    ),
                                    &peer_id,
                                )
                                .await;
                            };

                            self.send_pending_outbound_messages(peer_id);
                        }
                    }
                    BehaviourEvent::IdentifyError { peer_id, error } => {
                        debug!(target: TARGET, peer_id = %peer_id, error = %error, "identify error");

                        match error {
                            swarm::StreamUpgradeError::Timeout => {
                                // We do not clean since we will try to open the connection when it is
                                // confirmed that it has been closed in SwarmEvent::ConnectionClosed
                            }
                            swarm::StreamUpgradeError::Apply(..)
                            | swarm::StreamUpgradeError::NegotiationFailed
                            | swarm::StreamUpgradeError::Io(..) => {
                                // Do not call clear_pending_messages here — it removes
                                // peer_action, which ConnectionClosed needs to trigger
                                // its cleanup path. Clean only the state that
                                // ConnectionClosed won't reach.
                                self.pending_outbound_messages.remove(&peer_id);
                                self.retry_by_peer.remove(&peer_id);
                                self.response_channels.remove(&peer_id);
                                self.pending_inbound_messages.remove(&peer_id);
                            }
                        }

                        self.swarm
                            .behaviour_mut()
                            .close_connections(&peer_id, None);
                    }
                    BehaviourEvent::ReqresMessage { peer_id, message } => {
                        let message_data = match message {
                            request_response::Message::Request {
                                request,
                                channel,
                                ..
                            } => {
                                trace!(target: TARGET, peer_id = %peer_id, "request received");
                                self.add_ephemeral_response(peer_id, channel);
                                request.0
                            }
                            request_response::Message::Response {
                                response,
                                ..
                            } => {
                                trace!(target: TARGET, peer_id = %peer_id, "response received");
                                response.0
                            }
                        };

                        if self.peer_identify.contains(&peer_id) {
                            self.message_to_helper(
                                MessagesHelper::Single(message_data),
                                &peer_id,
                            )
                            .await;
                        } else {
                            let queue = self
                                .pending_inbound_messages
                                .entry(peer_id)
                                .or_default();
                            if queue.push(message_data) {
                                warn!(
                                    target: TARGET,
                                    peer_id = %peer_id,
                                    max_messages = MAX_PENDING_MESSAGES_PER_PEER,
                                    "inbound queue count limit reached; oldest message evicted",
                                );
                            }
                        }
                    }
                    BehaviourEvent::ClosestPeer { peer_id, info } => {
                        if matches!(
                            self.peer_action.get(&peer_id),
                            Some(Action::Discover)
                        ) {
                            self.peer_action.remove(&peer_id);
                            if let Some(info) = info {
                                let addr = info
                                    .addrs
                                    .iter()
                                    .filter(|x| {
                                        !self
                                            .swarm
                                            .behaviour()
                                            .is_invalid_address(x)
                                    })
                                    .cloned()
                                    .collect::<Vec<Multiaddr>>();

                                if addr.is_empty() {
                                    self.schedule_retry(
                                        peer_id,
                                        ScheduleType::Discover,
                                    );
                                } else {
                                    self.schedule_retry(
                                        peer_id,
                                        ScheduleType::Dial(addr),
                                    );
                                }
                            } else {
                                self.schedule_retry(
                                    peer_id,
                                    ScheduleType::Discover,
                                );
                            };
                        }
                    }
                    BehaviourEvent::Dummy => {
                        // For contron_list, ReqRes events
                    }
                }
            }
            SwarmEvent::OutgoingConnectionError {
                error,
                peer_id: Some(peer_id),
                ..
            } => {
                if matches!(self.peer_action.get(&peer_id), Some(Action::Dial))
                {
                    self.peer_action.remove(&peer_id);

                    let has_pending_messages = self
                        .pending_outbound_messages
                        .get(&peer_id)
                        .is_some_and(|q| !q.is_empty());

                    if let Some((retry, new_address)) =
                        self.dial_error_manager(error, &peer_id)
                    {
                        if retry {
                            let addr = new_address
                                .iter()
                                .filter(|x| {
                                    !self
                                        .swarm
                                        .behaviour()
                                        .is_invalid_address(x)
                                })
                                .cloned()
                                .collect::<Vec<Multiaddr>>();

                            if addr.is_empty() {
                                if has_pending_messages {
                                    self.schedule_retry(
                                        peer_id,
                                        ScheduleType::Dial(vec![]),
                                    );
                                } else {
                                    self.schedule_retry(
                                        peer_id,
                                        ScheduleType::Discover,
                                    );
                                }
                            } else {
                                self.schedule_retry(
                                    peer_id,
                                    ScheduleType::Dial(addr),
                                );
                            }
                        } else if has_pending_messages {
                            self.schedule_retry(
                                peer_id,
                                ScheduleType::Dial(vec![]),
                            );
                        } else {
                            self.schedule_retry(
                                peer_id,
                                ScheduleType::Discover,
                            );
                        }
                    };
                }
            }
            SwarmEvent::ConnectionClosed {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                if num_established == 0 {
                    if let Some(Action::Identified(id)) =
                        self.peer_action.get(&peer_id)
                        && connection_id == *id
                    {
                        self.peer_action.remove(&peer_id);

                        self.peer_identify.remove(&peer_id);
                        self.pending_inbound_messages.remove(&peer_id);
                        self.response_channels.remove(&peer_id);

                        self.retry_by_peer.remove(&peer_id);

                        if self
                            .pending_outbound_messages
                            .get(&peer_id)
                            .is_some_and(|q| !q.is_empty())
                        {
                            self.schedule_retry(
                                peer_id,
                                ScheduleType::Dial(vec![]),
                            );
                        }
                    } else if let Some(Action::Dial | Action::Discover) =
                        self.peer_action.get(&peer_id)
                    {
                        self.peer_action.remove(&peer_id);
                        self.retry_by_peer.remove(&peer_id);
                        self.pending_inbound_messages.remove(&peer_id);
                        self.response_channels.remove(&peer_id);
                        self.peer_identify.remove(&peer_id);

                        if self
                            .pending_outbound_messages
                            .get(&peer_id)
                            .is_some_and(|q| !q.is_empty())
                        {
                            self.schedule_retry(
                                peer_id,
                                ScheduleType::Discover,
                            );
                        }
                    }
                }
            }
            SwarmEvent::IncomingConnectionError { .. } => {
                // We are not interested in this event at the moment.
                // The logs generate many false positives and cannot be associated with a
                // node since I do not have the peer-id. The best solution to avoid
                // confusion for the user is not to filter these errors.
            }
            SwarmEvent::ExpiredListenAddr { address, .. } => {
                warn!(target: TARGET, addr = %address, "listen address expired");
            }
            SwarmEvent::ListenerError { error, .. } => {
                error!(target: TARGET, error = %error, "listener error");
            }
            SwarmEvent::ConnectionEstablished {
                peer_id,
                connection_id,
                num_established,
                ..
            } => {
                if num_established.get() > 1 {
                    debug!(target: TARGET, peer_id = %peer_id, "duplicate connection detected; closing excess");
                    self.swarm
                        .behaviour_mut()
                        .close_connections(&peer_id, Some(connection_id));
                }
            }
            SwarmEvent::IncomingConnection { .. }
            | SwarmEvent::ListenerClosed { .. }
            | SwarmEvent::Dialing { .. }
            | SwarmEvent::NewExternalAddrCandidate { .. }
            | SwarmEvent::ExternalAddrConfirmed { .. }
            | SwarmEvent::ExternalAddrExpired { .. }
            | SwarmEvent::NewExternalAddrOfPeer { .. }
            | SwarmEvent::NewListenAddr { .. } => {
                // We are not interested in this event at the moment.
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {

    use crate::routing::RoutingNode;

    use super::*;
    use serde::Deserialize;
    use test_log::test;

    use ave_common::identity::{KeyPair, keys::Ed25519Signer};

    use serial_test::serial;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Dummy;

    // Build a relay server.
    fn build_worker(
        boot_nodes: Vec<RoutingNode>,
        random_walk: bool,
        node_type: NodeType,
        token: CancellationToken,
        memory_addr: String,
    ) -> NetworkWorker<Dummy> {
        let config = create_config(
            boot_nodes,
            random_walk,
            node_type,
            vec![memory_addr],
        );
        let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

        NetworkWorker::new(&keys, config, None, token, None).unwrap()
    }

    // Create a config
    fn create_config(
        boot_nodes: Vec<RoutingNode>,
        random_walk: bool,
        node_type: NodeType,
        listen_addresses: Vec<String>,
    ) -> Config {
        let config = crate::routing::Config::default()
            .with_discovery_limit(50)
            .with_dht_random_walk(random_walk);

        Config {
            boot_nodes,
            node_type,
            routing: config,
            external_addresses: vec![],
            listen_addresses,
            ..Default::default()
        }
    }

    #[test(tokio::test)]
    #[serial]
    async fn test_no_boot_nodes() {
        let boot_nodes = vec![];
        let token = CancellationToken::new();

        // Build a node.
        let node_addr = "/memory/3000";
        let mut node = build_worker(
            boot_nodes.clone(),
            false,
            NodeType::Addressable,
            token.clone(),
            node_addr.to_owned(),
        );
        if let Err(e) = node.run_connection().await {
            assert_eq!(
                e.to_string(),
                "cannot connect to the ave network: no reachable bootstrap node"
            );
        };

        assert_eq!(node.state, NetworkState::Disconnected);
    }

    #[test(tokio::test)]
    #[serial]
    async fn test_fake_boot_node() {
        let mut boot_nodes = vec![];
        let token = CancellationToken::new();

        // Build a fake bootstrap node.
        let fake_boot_peer = PeerId::random();
        let fake_boot_addr = "/memory/3001";
        let fake_node = RoutingNode {
            peer_id: fake_boot_peer.to_string(),
            address: vec![fake_boot_addr.to_owned()],
        };
        boot_nodes.push(fake_node);

        // Build a node.
        let node_addr = "/memory/3002";
        let mut node = build_worker(
            boot_nodes.clone(),
            false,
            NodeType::Addressable,
            token.clone(),
            node_addr.to_owned(),
        );

        if let Err(e) = node.run_connection().await {
            assert_eq!(
                e.to_string(),
                "cannot connect to the ave network: no reachable bootstrap node"
            );
        };

        assert_eq!(node.state, NetworkState::Disconnected);
    }

    #[test(tokio::test)]
    #[serial]
    async fn test_connect() {
        let mut boot_nodes = vec![];

        let token = CancellationToken::new();

        // Build a bootstrap node.
        let boot_addr = "/memory/3003";
        let mut boot = build_worker(
            boot_nodes.clone(),
            false,
            NodeType::Bootstrap,
            token.clone(),
            boot_addr.to_owned(),
        );

        let boot_node = RoutingNode {
            peer_id: boot.local_peer_id().to_string(),
            address: vec![boot_addr.to_owned()],
        };

        boot_nodes.push(boot_node);

        // Build a node.
        let node_addr = "/memory/3004";
        let mut node = build_worker(
            boot_nodes,
            false,
            NodeType::Ephemeral,
            token.clone(),
            node_addr.to_owned(),
        );

        // Spawn the boot node
        tokio::spawn(async move {
            boot.run_main().await;
        });

        // Wait for connection.
        node.run_connection().await.unwrap();
    }
}
