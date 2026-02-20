use crate::{Error, NodeType, routing::RoutingNode};
use bytes::Bytes;
use ip_network::IpNetwork;
use libp2p::{
    Multiaddr, PeerId,
    identity::{self},
    multiaddr::Protocol,
    multihash::Multihash,
    swarm::ConnectionId,
};
use serde::{Deserialize, Deserializer, Serialize};
use tokio::time::Instant;
use tracing::error;

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque},
    str::FromStr,
    time::Duration,
};

const TARGET_UTILS: &str = "AveNetwork-Utils";
pub const NOISE_PROTOCOL: &str = "ave-p2p-v1";
pub const TELL_PROTOCOL: &str = "/ave/tell/1.0.0";
pub const REQRES_PROTOCOL: &str = "/ave/reqres/1.0.0";
pub const ROUTING_PROTOCOL: &str = "/ave/routing/1.0.0";
pub const IDENTIFY_PROTOCOL: &str = "/ave/1.0.0";
pub const USER_AGENT: &str = "ave/0.8.0";

#[derive(Debug, thiserror::Error)]
pub enum PeerIdToEd25519Error {
    #[error(
        "peer id is not an identity multihash (public key is not recoverable)"
    )]
    NotIdentityMultihash,
    #[error("multihash digest is empty or invalid")]
    InvalidDigest,
    #[error("failed to decode protobuf-encoded public key: {0}")]
    Protobuf(#[from] identity::DecodingError),
    #[error("public key is not ed25519: {0}")]
    NotEd25519(#[from] identity::OtherVariantError),
}

pub fn peer_id_to_ed25519_pubkey_bytes(
    peer_id: &PeerId,
) -> Result<[u8; 32], PeerIdToEd25519Error> {
    // PeerId: AsRef<Multihash<64>>
    let mh: &Multihash<64> = peer_id.as_ref();

    // multihash identity = 0x00
    if mh.code() != 0x00 {
        return Err(PeerIdToEd25519Error::NotIdentityMultihash);
    }

    let digest = mh.digest();
    if digest.is_empty() {
        return Err(PeerIdToEd25519Error::InvalidDigest);
    }

    // digest == protobuf-encoded public key
    let pk = identity::PublicKey::try_decode_protobuf(digest)?;
    let ed_pk = pk.try_into_ed25519()?;
    Ok(ed_pk.to_bytes())
}

#[derive(Clone)]
pub struct LimitsConfig {
    pub yamux_max_num_streams: usize,
    pub tcp_listen_backlog: u32,
    pub tcp_nodelay: bool,
    pub reqres_max_concurrent_streams: usize,
    pub reqres_request_timeout: u64,
    pub tell_max_concurrent_streams: usize,
    pub tell_request_timeout: u64,
    pub identify_interval: u64,
    // TODO mirar en un futuro.
    pub identify_cache: usize,
    pub kademlia_query_timeout: u64,
    pub conn_limmits_max_pending_incoming: Option<u32>,
    pub conn_limmits_max_pending_outgoing: Option<u32>,
    pub conn_limmits_max_established_incoming: Option<u32>,
    pub conn_limmits_max_established_outgoing: Option<u32>,
    pub conn_limmits_max_established_per_peer: Option<u32>,
    pub conn_limmits_max_established_total: Option<u32>,
}

impl LimitsConfig {
    pub fn build(node_type: &NodeType) -> Self {
        match node_type {
            NodeType::Bootstrap | NodeType::Addressable => Self {
                yamux_max_num_streams: 512,
                tcp_listen_backlog: 8192,
                tcp_nodelay: true,
                reqres_max_concurrent_streams: 2048,
                reqres_request_timeout: 15,
                tell_max_concurrent_streams: 2048,
                tell_request_timeout: 15,
                identify_interval: 60 * 15,
                identify_cache: 1024,
                kademlia_query_timeout: 25,
                conn_limmits_max_pending_incoming: Some(512),
                conn_limmits_max_pending_outgoing: Some(128),
                conn_limmits_max_established_incoming: Some(8000),
                conn_limmits_max_established_outgoing: Some(1000),
                conn_limmits_max_established_per_peer: Some(2),
                conn_limmits_max_established_total: Some(9000),
            },
            NodeType::Ephemeral => Self {
                yamux_max_num_streams: 128,
                tcp_listen_backlog: 512,
                tcp_nodelay: true,
                reqres_max_concurrent_streams: 128,
                reqres_request_timeout: 10,
                tell_max_concurrent_streams: 128,
                tell_request_timeout: 10,
                identify_interval: 60 * 60,
                identify_cache: 0,
                kademlia_query_timeout: 15,
                conn_limmits_max_pending_incoming: Some(50),
                conn_limmits_max_pending_outgoing: Some(100),
                conn_limmits_max_established_incoming: Some(100),
                conn_limmits_max_established_outgoing: Some(200),
                conn_limmits_max_established_per_peer: Some(2),
                conn_limmits_max_established_total: Some(300),
            },
        }
    }
}

pub enum ScheduleType {
    Discover,
    Dial(Vec<Multiaddr>),
}

#[derive(Copy, Clone, Debug)]
pub enum Action {
    Discover,
    Dial,
    Identified(ConnectionId),
}

impl From<RetryKind> for Action {
    fn from(value: RetryKind) -> Self {
        match value {
            RetryKind::Discover => Action::Discover,
            RetryKind::Dial => Action::Dial,
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub enum RetryKind {
    Discover,
    Dial,
}

#[derive(Clone, Debug)]
pub struct RetryState {
    pub attempts: u8,
    pub when: Instant,
    pub kind: RetryKind,
    pub addrs: Vec<Multiaddr>,
}

#[derive(Eq, Clone, Debug)]
pub struct Due(pub PeerId, pub Instant);
impl PartialEq for Due {
    fn eq(&self, o: &Self) -> bool {
        self.1.eq(&o.1)
    }
}
impl Ord for Due {
    fn cmp(&self, o: &Self) -> Ordering {
        o.1.cmp(&self.1)
    }
}
impl PartialOrd for Due {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}

/// Network state.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NetworkState {
    /// Start.
    Start,
    /// Dial.
    Dial,
    /// Dialing boot node.
    Dialing,
    /// Running.
    Running,
    /// Disconnected.
    Disconnected,
}

pub enum MessagesHelper {
    Single(Bytes),
    Vec(VecDeque<Bytes>),
}

/// Method that update allow and block lists
pub async fn request_update_lists(
    service_allow: &[String],
    service_block: &[String],
) -> ((Vec<String>, Vec<String>), (u16, u16)) {
    let mut vec_allow_peers: Vec<String> = vec![];
    let mut vec_block_peers: Vec<String> = vec![];
    let mut successful_allow: u16 = 0;
    let mut successful_block: u16 = 0;
    let client = reqwest::Client::new();

    for service in service_allow {
        match client.get(service).send().await {
            Ok(res) => {
                let fail = !res.status().is_success();
                if !fail {
                    match res.json().await {
                        Ok(peers) => {
                            let peers: Vec<String> = peers;
                            vec_allow_peers.append(&mut peers.clone());
                            successful_allow += 1;
                        }
                        Err(e) => {
                            error!(
                                TARGET_UTILS,
                                "Error performing Get {}, The server did not return what was expected: {}",
                                service,
                                e
                            );
                        }
                    }
                } else {
                    error!(
                        TARGET_UTILS,
                        "Error performing Get {}, The server did not return a correct code: {}",
                        service,
                        res.status()
                    );
                }
            }
            Err(e) => {
                error!(TARGET_UTILS, "Error performing Get {}: {}", service, e);
            }
        }
    }

    for service in service_block {
        match client.get(service).send().await {
            Ok(res) => {
                let fail = !res.status().is_success();
                if !fail {
                    match res.json().await {
                        Ok(peers) => {
                            let peers: Vec<String> = peers;
                            vec_block_peers.append(&mut peers.clone());
                            successful_block += 1;
                        }
                        Err(e) => {
                            error!(
                                TARGET_UTILS,
                                "Error performing Get {}, The server did not return what was expected: {}",
                                service,
                                e
                            );
                        }
                    }
                } else {
                    error!(
                        TARGET_UTILS,
                        "Error performing Get {}, The server did not return a correct code: {}",
                        service,
                        res.status()
                    );
                }
            }
            Err(e) => {
                error!(TARGET_UTILS, "Error performing Get {}: {}", service, e);
            }
        }
    }

    (
        (vec_allow_peers, vec_block_peers),
        (successful_allow, successful_block),
    )
}

/// Convert boot nodes to `PeerId` and `Multiaddr`.
pub fn convert_boot_nodes(
    boot_nodes: &[RoutingNode],
) -> HashMap<PeerId, Vec<Multiaddr>> {
    let mut boot_nodes_aux = HashMap::new();

    for node in boot_nodes {
        let Ok(peer) = bs58::decode(node.peer_id.clone()).into_vec() else {
            continue;
        };

        let Ok(peer) = PeerId::from_bytes(peer.as_slice()) else {
            continue;
        };

        let mut aux_addrs = vec![];
        for addr in node.address.iter() {
            let Ok(addr) = Multiaddr::from_str(addr) else {
                continue;
            };

            aux_addrs.push(addr);
        }

        if !aux_addrs.is_empty() {
            boot_nodes_aux.insert(peer, aux_addrs);
        }
    }

    boot_nodes_aux
}

/// Gets the list of external (public) addresses for the node from string array.
pub fn convert_addresses(
    addresses: &[String],
) -> Result<HashSet<Multiaddr>, Error> {
    let mut addrs = HashSet::new();
    for address in addresses {
        if let Some(value) = multiaddr(address) {
            addrs.insert(value);
        } else {
            return Err(Error::Address(format!(
                "Invalid MultiAddress conversion in External Address: {}",
                address
            )));
        }
    }
    Ok(addrs)
}

/// Parses a string into a `Multiaddr` if possible.
fn multiaddr(addr: &str) -> Option<Multiaddr> {
    addr.parse::<Multiaddr>().ok()
}

/// Check if the given `Multiaddr` is reachable.
///
/// This test is successful only for global IP addresses and DNS names.
// NB: Currently all DNS names are allowed and no check for TLD suffixes is done
// because the set of valid domains is highly dynamic and would require frequent
// updates, for example by utilising publicsuffix.org or IANA.
pub fn is_global(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => IpNetwork::from(ip).is_global(),
        Protocol::Ip6(ip) => IpNetwork::from(ip).is_global(),
        _ => false,
    })
}

pub fn is_private(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_private(),
        Protocol::Ip6(ip) => ip.is_unique_local(),
        _ => false,
    })
}

pub fn is_loop_back(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

pub fn is_dns(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| {
        matches!(p, Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_))
    })
}

/// Chech if the given `Multiaddr` is a memory address.
pub fn is_tcp(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| matches!(p, Protocol::Tcp(_)))
}

/// The configuration for a `Behaviour` protocol.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ReqResConfig {
    /// message timeout
    #[serde(deserialize_with = "deserialize_duration_secs")]
    pub message_timeout: Duration,
    /// max concurrent streams
    pub max_concurrent_streams: usize,
}

fn deserialize_duration_secs<'de, D>(
    deserializer: D,
) -> Result<Duration, D::Error>
where
    D: Deserializer<'de>,
{
    let u: u64 = u64::deserialize(deserializer)?;
    Ok(Duration::from_secs(u))
}

impl ReqResConfig {
    /// Create a ReqRes Confing
    pub fn new(
        message_timeout: Duration,
        max_concurrent_streams: usize,
    ) -> Self {
        Self {
            message_timeout,
            max_concurrent_streams,
        }
    }
}

impl Default for ReqResConfig {
    fn default() -> Self {
        Self {
            message_timeout: Duration::from_secs(10),
            max_concurrent_streams: 100,
        }
    }
}

impl ReqResConfig {
    /// Sets the timeout for inbound and outbound requests.
    pub fn with_message_timeout(mut self, timeout: Duration) -> Self {
        self.message_timeout = timeout;
        self
    }

    /// Sets the upper bound for the number of concurrent inbound + outbound streams.
    pub fn with_max_concurrent_streams(mut self, num_streams: usize) -> Self {
        self.max_concurrent_streams = num_streams;
        self
    }

    /// Get message timeout
    pub fn get_message_timeout(&self) -> Duration {
        self.message_timeout
    }

    /// Get max concurrent streams
    pub fn get_max_concurrent_streams(&self) -> usize {
        self.max_concurrent_streams
    }
}
