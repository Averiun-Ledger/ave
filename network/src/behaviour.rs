//! # Network composed behaviour.
//!

use crate::{
    Config, Error, MemoryLimit, NodeType,
    control_list::{self, build_control_lists_updaters},
    routing::{self},
    utils::{
        IDENTIFY_PROTOCOL, LimitsConfig, REQRES_PROTOCOL, ROUTING_PROTOCOL,
        TELL_PROTOCOL, USER_AGENT,
    },
};

use libp2p::{
    Multiaddr, PeerId, StreamProtocol,
    connection_limits::{self, ConnectionLimits},
    identify::{self, Info as IdentifyInfo, UpgradeError},
    identity::PublicKey,
    kad::PeerInfo,
    memory_connection_limits,
    request_response::{
        self, Config as ReqResConfig, ProtocolSupport, ResponseChannel,
    },
    swarm::{
        ConnectionId, NetworkBehaviour, StreamUpgradeError,
        behaviour::toggle::Toggle,
    },
};
use tell::{
    Event as TellEvent, ProtocolSupport as TellProtocol, binary as TellBinary,
};

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tracing::warn;
use std::{convert::Infallible, iter, time::Duration};
use tokio_util::sync::CancellationToken;

/// The network composed behaviour.
#[derive(NetworkBehaviour)]
#[behaviour(out_event = "Event")]
pub struct Behaviour {
    /// The `control-list` behaviour.
    control_list: control_list::Behaviour,

    /// The `request-response` behaviour.
    req_res: request_response::cbor::Behaviour<ReqResMessage, ReqResMessage>,

    /// The `tell` behaviour.
    tell: TellBinary::Behaviour,

    /// The `routing` behaviour.
    routing: routing::Behaviour,

    /// The `identify` behaviour.
    identify: identify::Behaviour,

    mem_limits: Toggle<memory_connection_limits::Behaviour>,

    conn_limits: connection_limits::Behaviour,
}

impl Behaviour {
    /// Create a new `Behaviour`.
    pub fn new(
        public_key: &PublicKey,
        config: Config,
        token: CancellationToken,
        limits: LimitsConfig,
        memory_limit: Option<MemoryLimit>,
    ) -> Self {
        let stream_tell = StreamProtocol::new(TELL_PROTOCOL);
        let stream_reqres = StreamProtocol::new(REQRES_PROTOCOL);
        let stream_routing = StreamProtocol::new(ROUTING_PROTOCOL);

        // TELL
        let tell_protocol = if config.node_type == NodeType::Ephemeral {
            TellProtocol::Inbound
        } else {
            TellProtocol::Full
        };

        let config_tell = tell::Config::default()
            .with_max_concurrent_streams(limits.tell_max_concurrent_streams)
            .with_request_timeout(Duration::from_secs(
                limits.tell_request_timeout,
            ));

        let tell = TellBinary::Behaviour::new(
            iter::once((stream_tell, tell_protocol)),
            config_tell,
        );

        // REQRES
        let reqres_protocol = if config.node_type == NodeType::Ephemeral {
            ProtocolSupport::Outbound
        } else {
            ProtocolSupport::Inbound
        };

        let config_req_res = ReqResConfig::default()
            .with_max_concurrent_streams(limits.reqres_max_concurrent_streams)
            .with_request_timeout(Duration::from_secs(
                limits.reqres_request_timeout,
            ));

        let req_res = request_response::cbor::Behaviour::new(
            iter::once((stream_reqres, reqres_protocol)),
            config_req_res,
        );

        let boot_nodes = config.boot_nodes;

        let control_list_receiver =
            build_control_lists_updaters(&config.control_list, token);

        let conn_limmits = ConnectionLimits::default()
            .with_max_established(limits.conn_limmits_max_established_total)
            .with_max_established_incoming(
                limits.conn_limmits_max_established_incoming,
            )
            .with_max_established_outgoing(
                limits.conn_limmits_max_established_outgoing,
            )
            .with_max_pending_incoming(limits.conn_limmits_max_pending_incoming)
            .with_max_pending_outgoing(limits.conn_limmits_max_pending_outgoing)
            .with_max_established_per_peer(
                limits.conn_limmits_max_established_per_peer,
            );

        let mem_limits = if let Some(memory_limit) = memory_limit {
            match memory_limit {
                MemoryLimit::Percentage(percentage) => {
                    let clamped = percentage.clamp(0.01, 1.0);
                    if clamped != percentage {
                        warn!(
                            "MemoryLimit::Percentage value {} is out of range (0.01, 1.0], clamped to {}",
                            percentage, clamped
                        );
                    }
                    Toggle::from(Some(
                        memory_connection_limits::Behaviour::with_max_percentage(
                            clamped,
                        ),
                    ))
                }
                MemoryLimit::Bytes(bytes) => Toggle::from(Some(
                    memory_connection_limits::Behaviour::with_max_bytes(bytes),
                )),
            }
        } else {
            Toggle::from(None)
        };

        Self {
            control_list: control_list::Behaviour::new(
                config.control_list,
                &boot_nodes,
                control_list_receiver,
            ),
            identify: identify::Behaviour::new(
                identify::Config::new(
                    IDENTIFY_PROTOCOL.to_owned(),
                    public_key.clone(),
                )
                .with_agent_version(USER_AGENT.to_string())
                .with_cache_size(limits.identify_cache),
            ),
            routing: routing::Behaviour::new(
                PeerId::from_public_key(public_key),
                config.routing,
                stream_routing,
                config.node_type,
                limits,
            ),
            tell,
            req_res,
            mem_limits,
            conn_limits: connection_limits::Behaviour::new(conn_limmits),
        }
    }

    pub fn clean_peer_to_remove(&mut self, peer_id: &PeerId) {
        self.routing.clean_peer_to_remove(peer_id);
    }

    pub fn clean_hard_peer_to_remove(&mut self, peer_id: &PeerId) {
        self.routing.clean_peer_to_remove(peer_id);
        self.routing.remove_node(peer_id);
    }

    pub fn add_peer_to_remove(&mut self, peer_id: &PeerId) {
        self.routing.add_peer_to_remove(peer_id);
    }

    /// Discover closets peers.
    pub fn discover(&mut self, peer_id: &PeerId) {
        self.routing.discover(peer_id);
    }

    pub fn add_self_reported_address(
        &mut self,
        peer_id: &PeerId,
        addr: &Multiaddr,
    ) -> bool {
        self.routing.add_self_reported_address(peer_id, addr)
    }

    /// Returns true if the given `PeerId` is known.
    pub fn is_known_peer(&mut self, peer_id: &PeerId) -> bool {
        self.routing.is_known_peer(peer_id)
    }

    /// Returns true if the given `PeerId` is known.
    pub fn is_invalid_address(&self, addr: &Multiaddr) -> bool {
        self.routing.is_invalid_address(addr)
    }

    pub fn close_connections(
        &mut self,
        peer_id: &PeerId,
        connection_id: Option<ConnectionId>,
    ) {
        self.routing.new_close_connections(*peer_id, connection_id);
    }

    /// Finish the prerouting state.
    pub fn finish_prerouting_state(&mut self) {
        self.routing.finish_prerouting_state();
    }

    /// Send request messasge to peer.
    pub fn send_message(
        &mut self,
        peer_id: &PeerId,
        message: Bytes,
        node_type: &NodeType,
    ) {
        if node_type == &NodeType::Ephemeral {
            self.req_res.send_request(peer_id, ReqResMessage(message));
        } else {
            self.tell.send_message(peer_id, message);
        }
    }

    /// Send response message to peer.
    pub fn send_response(
        &mut self,
        channel: ResponseChannel<ReqResMessage>,
        message: Bytes,
    ) -> Result<(), Error> {
        self.req_res
            .send_response(channel, ReqResMessage(message))
            .map_err(|_| Error::Behaviour("Cannot send response".to_owned()))
    }
}

/// Network event.
#[derive(Debug)]
pub enum Event {
    /// We have obtained identity information from a peer, including the addresses it is listening
    /// on.
    Identified {
        connection_id: ConnectionId,
        /// Id of the peer that has been identified.
        peer_id: PeerId,
        /// Information about the peer.
        info: Box<IdentifyInfo>,
    },

    /// Identify error.
    IdentifyError {
        peer_id: PeerId,
        error: StreamUpgradeError<UpgradeError>,
    },

    /// Request - Response message received from a peer.
    ReqresMessage {
        peer_id: PeerId,
        message: request_response::Message<ReqResMessage, ReqResMessage>,
    },

    /// Tell message recieved from a peer.
    TellMessage {
        peer_id: PeerId,
        message: tell::TellMessage<Bytes>,
    },

    /// Closets peers founded.
    ClosestPeer {
        peer_id: PeerId,
        info: Option<PeerInfo>,
    },

    /// Dummy Event for control_list, ReqRes and Tell
    Dummy,
}

impl From<Infallible> for Event {
    fn from(v: Infallible) -> Self {
        match v {}
    }
}

impl From<control_list::Event> for Event {
    fn from(_event: control_list::Event) -> Self {
        Event::Dummy
    }
}

impl From<routing::Event> for Event {
    fn from(event: routing::Event) -> Self {
        match event {
            routing::Event::ClosestPeer { peer_id, info } => {
                Event::ClosestPeer { peer_id, info }
            }
        }
    }
}

impl From<identify::Event> for Event {
    fn from(event: identify::Event) -> Self {
        match event {
            identify::Event::Received {
                peer_id,
                info,
                connection_id,
            } => Event::Identified {
                connection_id,
                peer_id,
                info: Box::new(info),
            },
            identify::Event::Error { peer_id, error, .. } => {
                Event::IdentifyError { peer_id, error }
            }
            identify::Event::Sent { .. } | identify::Event::Pushed { .. } => {
                Event::Dummy
            }
        }
    }
}

impl From<TellEvent<Bytes>> for Event {
    fn from(event: TellEvent<Bytes>) -> Self {
        match event {
            TellEvent::Message { peer_id, message } => {
                Event::TellMessage { peer_id, message }
            }
            TellEvent::MessageProcessed { .. }
            | TellEvent::MessageSent { .. }
            | TellEvent::InboundFailure { .. }
            | TellEvent::OutboundFailure { .. } => Event::Dummy,
        }
    }
}

impl From<request_response::Event<ReqResMessage, ReqResMessage>> for Event {
    fn from(
        event: request_response::Event<ReqResMessage, ReqResMessage>,
    ) -> Self {
        match event {
            request_response::Event::Message { peer, message, .. } => {
                Event::ReqresMessage {
                    peer_id: peer,
                    message,
                }
            }
            request_response::Event::ResponseSent { .. }
            | request_response::Event::InboundFailure { .. }
            | request_response::Event::OutboundFailure { .. } => Event::Dummy,
        }
    }
}

/// Wrapper for request-response message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReqResMessage(pub Bytes);

#[cfg(test)]
mod tests {
    use super::*;
    use test_log::test;

    use crate::{Config, NodeType, RoutingNode};

    use futures::prelude::*;
    use libp2p::{
        Multiaddr, Swarm,
        core::transport::{Transport, memory, upgrade::Version},
        identity, plaintext,
        swarm::{self, SwarmEvent},
        yamux,
    };

    use request_response::Message;
    use serial_test::serial;

    use std::vec;

    #[test(tokio::test)]
    #[serial]
    async fn test_reqres() {
        let boot_nodes = vec![];

        // Build node a.
        let config_a =
            create_config(boot_nodes.clone(), false, NodeType::Ephemeral);
        let mut node_a = build_node(config_a);
        node_a.behaviour_mut().finish_prerouting_state();
        let node_a_addr: Multiaddr = "/memory/1000".parse().unwrap();
        let _ = node_a.listen_on(node_a_addr.clone());

        // Build node b.
        let config_b =
            create_config(boot_nodes.clone(), true, NodeType::Addressable);
        let mut node_b = build_node(config_b);
        node_b.behaviour_mut().finish_prerouting_state();
        let node_b_addr: Multiaddr = "/memory/1001".parse().unwrap();
        let _ = node_b.listen_on(node_b_addr.clone());
        node_b.add_external_address(node_b_addr.clone());

        let _ = node_a.dial(node_b_addr.clone());

        let peer_b = async move {
            loop {
                match node_b.select_next_some().await {
                    SwarmEvent::Behaviour(Event::ReqresMessage {
                        message,
                        ..
                    }) => {
                        match message {
                            Message::Request {
                                channel, request, ..
                            } => {
                                assert_eq!(request.0, b"Hello Node B".to_vec());
                                // Send response to node a.
                                let _ = node_b.behaviour_mut().send_response(
                                    channel,
                                    Bytes::from("Hello Node A"),
                                );
                            }
                            Message::Response { .. } => {}
                        }
                    }
                    _ => {}
                }
            }
        };

        let peer_a = async move {
            let mut counter = 0;
            loop {
                match node_a.select_next_some().await {
                    SwarmEvent::Behaviour(Event::Identified {
                        peer_id,
                        ..
                    }) => {
                        for _ in 0..100 {
                            node_a.behaviour_mut().send_message(
                                &peer_id,
                                Bytes::from("Hello Node B"),
                                &NodeType::Ephemeral,
                            );
                        }
                    }
                    SwarmEvent::Behaviour(Event::ReqresMessage {
                        message,
                        ..
                    }) => match message {
                        Message::Request { .. } => {}
                        Message::Response { response, .. } => {
                            assert_eq!(response.0, b"Hello Node A".to_vec());
                            counter += 1;

                            if counter == 100 {
                                break;
                            }
                        }
                    },
                    _ => {}
                }
            }
        };

        tokio::task::spawn(Box::pin(peer_b));
        peer_a.await;
    }

    #[test(tokio::test)]
    #[serial]
    async fn test_tell() {
        let boot_nodes = vec![];

        // Build node a.
        let config =
            create_config(boot_nodes.clone(), false, NodeType::Addressable);
        let mut node_a = build_node(config);
        let node_a_addr: Multiaddr = "/memory/1003".parse().unwrap();
        let _ = node_a.listen_on(node_a_addr.clone());
        node_a.add_external_address(node_a_addr.clone());
        node_a.behaviour_mut().finish_prerouting_state();

        // Build node b.
        let config =
            create_config(boot_nodes.clone(), true, NodeType::Addressable);
        let mut node_b = build_node(config);
        let node_b_addr: Multiaddr = "/memory/1004".parse().unwrap();
        let _ = node_b.listen_on(node_b_addr.clone());
        node_b.add_external_address(node_b_addr.clone());
        node_b.behaviour_mut().finish_prerouting_state();

        let _ = node_a.dial(node_b_addr.clone());

        let peer_b = async move {
            loop {
                match node_b.select_next_some().await {
                    SwarmEvent::Behaviour(Event::TellMessage {
                        peer_id,
                        message,
                    }) => {
                        // Message received from node a.
                        assert_eq!(message.message, b"Hello Node B".to_vec());
                        // Send response to node a.
                        let _ = node_b.behaviour_mut().send_message(
                            &peer_id,
                            Bytes::from("Hello Node A"),
                            &NodeType::Addressable,
                        );
                    }
                    _ => {}
                }
            }
        };

        let peer_a = async move {
            let mut counter = 0;
            loop {
                match node_a.select_next_some().await {
                    SwarmEvent::Behaviour(Event::Identified {
                        peer_id,
                        ..
                    }) => {
                        //node_a.behaviour_mut().add_identified_peer(peer_id, *info);
                        node_a.behaviour_mut().send_message(
                            &peer_id,
                            Bytes::from("Hello Node B"),
                            &NodeType::Addressable,
                        );
                    }
                    SwarmEvent::Behaviour(Event::TellMessage {
                        peer_id,
                        message,
                    }) => {
                        assert_eq!(message.message, b"Hello Node A".to_vec());
                        counter += 1;
                        if counter == 100 {
                            break;
                        } else {
                            node_a.behaviour_mut().send_message(
                                &peer_id,
                                Bytes::from("Hello Node B"),
                                &NodeType::Addressable,
                            );
                        }
                    }
                    _ => {}
                }
            }
        };

        tokio::task::spawn(Box::pin(peer_b));
        peer_a.await;
    }

    #[test(tokio::test)]
    #[serial]
    async fn test_behaviour() {
        let boot_nodes = vec![];

        // Build bootstrap node.
        let config =
            create_config(boot_nodes.clone(), true, NodeType::Bootstrap);
        let mut boot_node = build_node(config);
        boot_node.behaviour_mut().finish_prerouting_state();
        let boot_node_addr: Multiaddr = "/memory/1005".parse().unwrap();
        let _ = boot_node.listen_on(boot_node_addr.clone());
        boot_node.add_external_address(boot_node_addr.clone());

        // Build node a.
        let config =
            create_config(boot_nodes.clone(), false, NodeType::Ephemeral);
        let mut node_a = build_node(config);
        node_a.behaviour_mut().finish_prerouting_state();
        let node_a_addr: Multiaddr = "/memory/1006".parse().unwrap();
        let _ = node_a.listen_on(node_a_addr.clone());
        node_a.add_external_address(node_a_addr.clone());

        // Build node b.
        let config =
            create_config(boot_nodes.clone(), true, NodeType::Addressable);
        let mut node_b = build_node(config);
        node_b.behaviour_mut().finish_prerouting_state();
        let node_b_addr: Multiaddr = "/memory/1007".parse().unwrap();
        let _ = node_b.listen_on(node_b_addr.clone());
        node_b.add_external_address(node_b_addr.clone());
        let node_b_peer_id = *node_b.local_peer_id();

        node_a.dial(boot_node_addr.clone()).unwrap();
        node_b.dial(boot_node_addr).unwrap();

        let boot_peer = async move {
            loop {
                match boot_node.select_next_some().await {
                    SwarmEvent::Behaviour(Event::Identified {
                        peer_id,
                        info,
                        ..
                    }) => {
                        for addr in info.listen_addrs {
                            boot_node
                                .behaviour_mut()
                                .add_self_reported_address(&peer_id, &addr);
                        }
                    }
                    _ => {}
                }
            }
        };

        let peer_b = async move {
            loop {
                match node_b.select_next_some().await {
                    SwarmEvent::Behaviour(Event::Identified {
                        peer_id,
                        info,
                        ..
                    }) => {
                        // Peer identified.
                        for addr in info.listen_addrs {
                            node_b
                                .behaviour_mut()
                                .add_self_reported_address(&peer_id, &addr);
                        }
                    }
                    SwarmEvent::Behaviour(Event::ReqresMessage {
                        message,
                        ..
                    }) => {
                        match message {
                            Message::Request {
                                channel, request, ..
                            } => {
                                assert_eq!(request.0, b"Hello Node B".to_vec());
                                // Send response to node a.
                                let _ = node_b.behaviour_mut().send_response(
                                    channel,
                                    Bytes::from("Hello Node A"),
                                );
                            }
                            Message::Response { .. } => {}
                        }
                    }
                    _ => {}
                }
            }
        };

        let peer_a = async move {
            loop {
                match node_a.select_next_some().await {
                    SwarmEvent::Behaviour(Event::Identified {
                        peer_id,
                        info,
                        ..
                    }) => {
                        for addr in info.listen_addrs {
                            node_a
                                .behaviour_mut()
                                .add_self_reported_address(&peer_id, &addr);
                        }

                        if peer_id == node_b_peer_id {
                            node_a.behaviour_mut().send_message(
                                &peer_id,
                                Bytes::from("Hello Node B"),
                                &NodeType::Ephemeral,
                            );
                        } else {
                            node_a.behaviour_mut().discover(&node_b_peer_id);
                        }
                    }
                    SwarmEvent::Behaviour(Event::ReqresMessage {
                        message,
                        ..
                    }) => match message {
                        Message::Request { .. } => {}
                        Message::Response { response, .. } => {
                            assert_eq!(response.0, b"Hello Node A".to_vec());
                            break;
                        }
                    },
                    _ => {}
                }
            }
        };

        tokio::task::spawn(Box::pin(boot_peer));
        tokio::task::spawn(Box::pin(peer_b));
        peer_a.await;
    }

    // Build node.
    fn build_node(config: Config) -> Swarm<Behaviour> {
        let local_key = identity::Keypair::generate_ed25519();
        let local_peer_id = local_key.public().to_peer_id();

        let transport = memory::MemoryTransport::default();

        let transport = transport
            .upgrade(Version::V1)
            .authenticate(plaintext::Config::new(&local_key))
            .multiplex(yamux::Config::default())
            .boxed();

        let limits = LimitsConfig::build(&config.node_type);

        let behaviour = Behaviour::new(
            &local_key.public(),
            config,
            CancellationToken::new(),
            limits,
            None,
        );
        Swarm::new(
            transport,
            behaviour,
            local_peer_id,
            swarm::Config::with_tokio_executor().with_idle_connection_timeout(
                std::time::Duration::from_secs(5),
            ),
        )
    }

    // Create a config
    fn create_config(
        boot_nodes: Vec<RoutingNode>,
        random_walk: bool,
        node_type: NodeType,
    ) -> Config {
        let config = crate::routing::Config::default()
            .with_discovery_limit(50)
            .with_dht_random_walk(random_walk);

        Config {
            boot_nodes,
            node_type,
            routing: config,
            external_addresses: vec![],
            listen_addresses: vec![],
            ..Default::default()
        }
    }
}
