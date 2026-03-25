//! # Network package.

#![warn(missing_docs)]

mod behaviour;
mod control_list;
pub mod error;
//mod node;
pub mod metrics;
mod monitor;
mod routing;
mod service;
mod transport;
mod utils;
mod worker;

use std::fmt::{self, Debug, Display};

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

/// How to size the network backend.
///
/// - `Profile` — use a predefined instance type: implies fixed vCPU and RAM.
/// - `Custom`  — supply exact RAM (MB) and vCPU count manually.
/// - Absent (`None` in `Config`) — auto-detect from the running host.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[serde(rename_all = "snake_case")]
pub enum MachineSpec {
    /// Use a predefined profile.
    Profile(MachineProfile),
    /// Supply exact machine dimensions.
    Custom {
        /// Total RAM in megabytes.
        ram_mb: u64,
        /// Available CPU cores.
        cpu_cores: usize,
    },
}

/// Predefined instance profiles with fixed vCPU and RAM.
/// They only exist to provide convenient default values — the actual
/// network tuning is derived from the resolved `ram_mb` and `cpu_cores`.
///
/// | Profile  | vCPU | RAM    |
/// |----------|------|--------|
/// | Nano     | 2    | 512 MB |
/// | Micro    | 2    | 1 GB   |
/// | Small    | 2    | 2 GB   |
/// | Medium   | 2    | 4 GB   |
/// | Large    | 2    | 8 GB   |
/// | XLarge   | 4    | 16 GB  |
/// | XXLarge  | 8    | 32 GB  |
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum MachineProfile {
    /// 2 vCPU, 512 MB RAM.
    Nano,
    /// 2 vCPU, 1 GB RAM.
    Micro,
    /// 2 vCPU, 2 GB RAM.
    Small,
    /// 2 vCPU, 4 GB RAM.
    Medium,
    /// 2 vCPU, 8 GB RAM.
    Large,
    /// 4 vCPU, 16 GB RAM.
    XLarge,
    /// 8 vCPU, 32 GB RAM.
    #[serde(rename = "2xlarge")]
    XXLarge,
}

impl MachineProfile {
    /// Canonical RAM for this profile in megabytes.
    pub const fn ram_mb(self) -> u64 {
        match self {
            Self::Nano => 512,
            Self::Micro => 1_024,
            Self::Small => 2_048,
            Self::Medium => 4_096,
            Self::Large => 8_192,
            Self::XLarge => 16_384,
            Self::XXLarge => 32_768,
        }
    }

    /// vCPU count for this profile.
    pub const fn cpu_cores(self) -> usize {
        match self {
            Self::Nano => 2,
            Self::Micro => 2,
            Self::Small => 2,
            Self::Medium => 2,
            Self::Large => 2,
            Self::XLarge => 4,
            Self::XXLarge => 8,
        }
    }
}

impl Display for MachineProfile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Nano => write!(f, "nano"),
            Self::Micro => write!(f, "micro"),
            Self::Small => write!(f, "small"),
            Self::Medium => write!(f, "medium"),
            Self::Large => write!(f, "large"),
            Self::XLarge => write!(f, "xlarge"),
            Self::XXLarge => write!(f, "2xlarge"),
        }
    }
}

/// Resolved machine parameters ready to be consumed by the network backend.
/// Network tuning is computed directly from these two values.
pub struct ResolvedSpec {
    /// Total RAM in megabytes.
    pub ram_mb: u64,
    /// Available CPU cores.
    pub cpu_cores: usize,
}

/// Resolve the final network sizing parameters from a [`MachineSpec`]:
///
/// - `Profile(p)` → use the profile's canonical RAM and vCPU.
/// - `Custom { ram_mb, cpu_cores }` → use the supplied values directly.
/// - `None` → auto-detect total RAM and available CPU cores from the host.
pub fn resolve_spec(spec: Option<MachineSpec>) -> ResolvedSpec {
    match spec {
        Some(MachineSpec::Profile(p)) => ResolvedSpec {
            ram_mb: p.ram_mb(),
            cpu_cores: p.cpu_cores(),
        },
        Some(MachineSpec::Custom { ram_mb, cpu_cores }) => {
            ResolvedSpec { ram_mb, cpu_cores }
        }
        None => ResolvedSpec {
            ram_mb: detect_ram_mb(),
            cpu_cores: detect_cpu_cores(),
        },
    }
}

/// Detect total system RAM from `/proc/meminfo` (Linux). Falls back to 4 096 MB.
pub(crate) fn detect_ram_mb() -> u64 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if let Some(rest) = line.strip_prefix("MemTotal:")
                    && let Some(kb_str) = rest.split_whitespace().next()
                    && let Ok(kb) = kb_str.parse::<u64>()
                {
                    return kb / 1024;
                }
            }
        }
    }
    4_096
}

/// Detect available CPU parallelism. Falls back to 2.
pub(crate) fn detect_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

/// The network configuration.
/// Memory-based connection limit policy.
///
/// Controls when libp2p should stop accepting new connections based on
/// process memory usage. The default is `Disabled`.
///
/// # Config examples
/// ```toml
/// # Reject new connections when process RAM exceeds 80% of system RAM (value must be 0.0–1.0)
/// [network.memory_limits]
/// type = "percentage"
/// value = 0.8
///
/// # Reject new connections when process RAM exceeds 512 MB
/// [network.memory_limits]
/// type = "mb"
/// value = 512
///
/// # No memory-based limit (default — omit the section or set type = "disabled")
/// ```
#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Default)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MemoryLimitsConfig {
    /// No memory-based connection limit (default).
    #[default]
    Disabled,
    /// Reject new connections when process memory exceeds `value` fraction of total RAM.
    /// Must be in the range 0.0–1.0 (e.g. `0.8` means 80% of system RAM).
    Percentage {
        /// Range into 0.0–1.0
        value: f64,
    },
    /// Reject new connections when process memory exceeds `value` megabytes.
    Mb {
        /// `value` in megabytes
        value: usize,
    },
}

impl MemoryLimitsConfig {
    /// Returns an error string if the configuration values are out of range.
    pub fn validate(&self) -> Result<(), String> {
        if let Self::Percentage { value } = self
            && (*value <= 0.0 || *value > 1.0)
        {
            return Err(format!(
                "network.memory_limits percentage must be in range (0.0, 1.0], got {}",
                value
            ));
        }

        Ok(())
    }
}

impl Display for MemoryLimitsConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => write!(f, "disabled"),
            Self::Percentage { value } => {
                write!(f, "{:.0}% of system RAM", value * 100.0)
            }
            Self::Mb { value } => write!(f, "{} MB", value),
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
/// Network config
pub struct Config {
    /// Safe mode keeps the network worker alive but isolated from peers.
    #[serde(default)]
    pub safe_mode: bool,

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

    /// Memory-based connection limit policy.
    pub memory_limits: MemoryLimitsConfig,

    /// Maximum accepted application message payload in bytes.
    #[serde(default = "default_max_app_message_bytes")]
    pub max_app_message_bytes: usize,

    /// Maximum buffered outbound bytes per peer while disconnected.
    /// `0` disables the per-peer bytes limit.
    #[serde(default = "default_max_pending_outbound_bytes_per_peer")]
    pub max_pending_outbound_bytes_per_peer: usize,

    /// Maximum buffered inbound bytes per peer before helper delivery.
    /// `0` disables the per-peer bytes limit.
    #[serde(default = "default_max_pending_inbound_bytes_per_peer")]
    pub max_pending_inbound_bytes_per_peer: usize,

    /// Maximum total buffered outbound bytes across all peers while disconnected.
    /// `0` disables the global bytes limit.
    #[serde(default = "default_max_pending_outbound_bytes_total")]
    pub max_pending_outbound_bytes_total: usize,

    /// Maximum total buffered inbound bytes across all peers before helper delivery.
    /// `0` disables the global bytes limit.
    #[serde(default = "default_max_pending_inbound_bytes_total")]
    pub max_pending_inbound_bytes_total: usize,
}

impl Config {
    /// Create a new configuration.
    pub fn new(
        node_type: NodeType,
        listen_addresses: Vec<String>,
        external_addresses: Vec<String>,
        boot_nodes: Vec<RoutingNode>,
    ) -> Self {
        Self {
            safe_mode: false,
            boot_nodes,
            node_type,
            listen_addresses,
            external_addresses,
            routing: routing::Config::default(),
            control_list: control_list::Config::default(),
            memory_limits: MemoryLimitsConfig::default(),
            max_app_message_bytes: default_max_app_message_bytes(),
            max_pending_outbound_bytes_per_peer:
                default_max_pending_outbound_bytes_per_peer(),
            max_pending_inbound_bytes_per_peer:
                default_max_pending_inbound_bytes_per_peer(),
            max_pending_outbound_bytes_total:
                default_max_pending_outbound_bytes_total(),
            max_pending_inbound_bytes_total:
                default_max_pending_inbound_bytes_total(),
        }
    }
}

const fn default_max_app_message_bytes() -> usize {
    crate::utils::MAX_APP_MESSAGE_BYTES
}

const fn default_max_pending_outbound_bytes_per_peer() -> usize {
    crate::utils::DEFAULT_MAX_PENDING_OUTBOUND_BYTES_PER_PEER
}

const fn default_max_pending_inbound_bytes_per_peer() -> usize {
    crate::utils::DEFAULT_MAX_PENDING_INBOUND_BYTES_PER_PEER
}

const fn default_max_pending_outbound_bytes_total() -> usize {
    crate::utils::DEFAULT_MAX_PENDING_OUTBOUND_BYTES_TOTAL
}

const fn default_max_pending_inbound_bytes_total() -> usize {
    crate::utils::DEFAULT_MAX_PENDING_INBOUND_BYTES_TOTAL
}

impl Default for Config {
    fn default() -> Self {
        Self {
            safe_mode: false,
            node_type: NodeType::default(),
            listen_addresses: Vec::default(),
            external_addresses: Vec::default(),
            boot_nodes: Vec::default(),
            routing: routing::Config::default(),
            control_list: control_list::Config::default(),
            memory_limits: MemoryLimitsConfig::default(),
            max_app_message_bytes: default_max_app_message_bytes(),
            max_pending_outbound_bytes_per_peer:
                default_max_pending_outbound_bytes_per_peer(),
            max_pending_inbound_bytes_per_peer:
                default_max_pending_inbound_bytes_per_peer(),
            max_pending_outbound_bytes_total:
                default_max_pending_outbound_bytes_total(),
            max_pending_inbound_bytes_total:
                default_max_pending_inbound_bytes_total(),
        }
    }
}

/// Type of a node.
#[derive(Debug, Clone, Deserialize, Default, PartialEq, Eq, Serialize)]
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
            Self::Bootstrap => write!(f, "Bootstrap"),
            Self::Addressable => write!(f, "Addressable"),
            Self::Ephemeral => write!(f, "Ephemeral"),
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
