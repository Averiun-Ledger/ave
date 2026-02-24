//! # Network package.

#![warn(missing_docs)]

mod behaviour;
mod control_list;
pub mod error;
//mod node;
mod monitor;
mod routing;
mod service;
mod transport;
mod utils;
mod worker;

use std::fmt::{self, Debug};

use ave_common::identity::PublicKey;
use borsh::{BorshDeserialize, BorshSerialize};
pub use control_list::Config as ControlListConfig;
pub use error::Error;
pub use libp2p::{
    PeerId,
    identity::{
        PublicKey as PublicKeyLibP2P, ed25519::PublicKey as PublicKeyEd25519,
    },
};
pub use monitor::*;
pub use routing::{Config as RoutingConfig, RoutingNode};
pub use service::NetworkService;
pub use utils::NetworkState;
pub use worker::NetworkWorker;

use bytes::Bytes;
use serde::{Deserialize, Serialize};

pub use crate::utils::ReqResConfig;

#[cfg(all(feature = "test", not(test), not(debug_assertions)))]
compile_error!(
    "The 'test' feature should only be used during development/testing"
);

/// The network configuration.
#[derive(Debug, Clone, Deserialize, Default, Serialize)]
#[serde(default)]
pub struct Config {
    /// The node type.
    pub node_type: NodeType,

    /// Listen addresses.
    pub listen_addresses: Vec<String>,

    /// External addresses.
    pub external_addresses: Vec<String>,

    /// Bootnodes to connect to.
    pub boot_nodes: Vec<RoutingNode>,

    /// Routing configuration.
    pub routing: routing::Config,

    /// Control List configuration.
    pub control_list: control_list::Config,

    /// Ram Limits.
    pub memory_limit: Option<MemoryLimit>,
}

/// Ram Limits.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub enum MemoryLimit {
    /// Ram in percentage.
    Percentage(f64),
    /// Ram in bytes.
    Bytes(usize),
}

impl Config {
    /// Create a new configuration.
    pub fn new(
        node_type: NodeType,
        listen_addresses: Vec<String>,
        external_addresses: Vec<String>,
        boot_nodes: Vec<RoutingNode>,
        memory_limit: Option<MemoryLimit>,
    ) -> Self {
        Self {
            boot_nodes,
            node_type,
            listen_addresses,
            external_addresses,
            memory_limit,
            routing: routing::Config::default(),
            control_list: control_list::Config::default(),
        }
    }
}

/// Type of a node.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Serialize)]
pub enum NodeType {
    /// Bootstrap node.
    #[default]
    Bootstrap,
    /// Addressable node.
    Addressable,
    /// Ephemeral node.
    Ephemeral,
}

impl fmt::Display for NodeType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NodeType::Bootstrap => write!(f, "Bootstrap"),
            NodeType::Addressable => write!(f, "Addressable"),
            NodeType::Ephemeral => write!(f, "Ephemeral"),
        }
    }
}

/// Command enumeration for the network service.
#[derive(Debug)]
pub enum Command {
    /// Send a message to the given peer.
    SendMessage {
        /// The peer to send the message to.
        peer: PeerId,
        /// The message to send.
        message: Bytes,
    },
}

/// Event enumeration for the network service.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum Event {
    /// Network state changed.
    StateChanged(utils::NetworkState),

    /// Network error.
    Error(Error),
}

/// Command enumeration for the Helper service.
#[derive(Debug, Serialize, Deserialize)]
pub enum CommandHelper<T>
where
    T: Debug + Serialize,
{
    /// Send a message to the given peer.
    SendMessage {
        /// The message to send.
        message: T,
    },
    /// Received a message.
    ReceivedMessage {
        /// Sender public key
        sender: [u8; 32],
        /// The message received.
        message: Bytes,
    },
}

/// Event enumeration for the Helper service.
#[derive(
    Debug, Serialize, Deserialize, Clone, BorshDeserialize, BorshSerialize,
)]
pub struct ComunicateInfo {
    /// The request id.
    pub request_id: String,
    /// The request version.
    pub version: u64,
    /// The receiver key identifier.
    pub receiver: PublicKey,
    /// The receiver actor.
    pub receiver_actor: String,
}
