use crate::{Error, routing::RoutingNode};
use bytes::Bytes;
use futures::{StreamExt, stream};
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
use tokio_util::sync::CancellationToken;
use tracing::warn;

use std::{
    cmp::Ordering,
    collections::{HashMap, HashSet, VecDeque},
    str::FromStr,
    time::Duration,
};

const TARGET: &str = "ave::network::utils";
pub const NOISE_PROTOCOL: &str = "ave-p2p-v1";
pub const REQRES_PROTOCOL: &str = "/ave/reqres/1.0.0";
pub const ROUTING_PROTOCOL: &str = "/ave/routing/1.0.0";
pub const IDENTIFY_PROTOCOL: &str = "/ave/1.0.0";
pub const USER_AGENT: &str = "ave/0.8.0";
pub const MAX_APP_MESSAGE_BYTES: usize = 1024 * 1024; // 1 MiB
pub const DEFAULT_MAX_PENDING_OUTBOUND_BYTES_PER_PEER: usize = 8 * 1024 * 1024; // 8 MiB
pub const DEFAULT_MAX_PENDING_INBOUND_BYTES_PER_PEER: usize = 8 * 1024 * 1024; // 8 MiB
pub const DEFAULT_MAX_PENDING_OUTBOUND_BYTES_TOTAL: usize = 0; // disabled
pub const DEFAULT_MAX_PENDING_INBOUND_BYTES_TOTAL: usize = 0; // disabled

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
    /// Build network limits from the total machine RAM and CPU count.
    ///
    /// `ram_mb` and `cpu_cores` are **total machine specs** shared by all components
    /// (DB backends, actor runtime, libp2p, OS).
    ///
    /// ## Resource split
    ///
    /// - **RAM-driven**: connection counts. Each established connection ≈ 50 KB
    ///   (TCP state ~20 KB + yamux ~4 KB + Noise ~3 KB + bookkeeping ~3 KB).
    ///   Budget: 10 % of total RAM. Split: 80 % inbound / 20 % outbound.
    ///
    /// - **CPU-driven**: stream concurrency and pending handshakes.
    ///   Noise handshakes (pending connections) are asymmetric-crypto intensive.
    ///   ReqRes concurrent streams are tokio tasks — more cores = more parallelism.
    pub fn build(ram_mb: u64, cpu_cores: usize) -> Self {
        let cores = cpu_cores.max(1);

        // ── Connection limits (RAM) ──────────────────────────────────────────────
        let budget_bytes = ram_mb * 1024 * 1024 * 10 / 100;
        let bytes_per_conn: u64 = 50 * 1024; // ~50 KB per established connection

        // Total connections: floor 50, cap 9 000 (file-descriptor & kernel limits)
        let max_total =
            ((budget_bytes / bytes_per_conn) as u32).clamp(50, 9_000);

        // 80 % incoming (nodes are mostly servers), 20 % outgoing
        let max_incoming = (max_total * 80 / 100).clamp(30, 8_000);
        let max_outgoing = (max_total * 20 / 100).clamp(20, 1_000);

        // ── Pending connections (CPU) ────────────────────────────────────────────
        // Each pending connection performs a Noise handshake (X25519 + ChaCha20).
        // ~64 parallel handshakes per core is a practical bound.
        let pending_incoming = (max_incoming / 10)
            .max(10)
            .min((cores as u32) * 64)
            .min(512);
        let pending_outgoing = (max_outgoing / 4).clamp(20, 128);

        // ── Stream concurrency (CPU) ─────────────────────────────────────────────
        // Each concurrent ReqRes stream is a tokio task. More cores → more tasks
        // that run in true parallel. ~512 concurrent tasks per core is sensible.
        let reqres_streams = (cores * 512).clamp(64, 4_096);

        // Yamux per-connection stream limit: must cover the worst case where a
        // single peer saturates the full ReqRes budget, plus routing/kad overhead.
        let yamux_streams = (reqres_streams + 64).clamp(256, 8_192);

        // ── TCP listen backlog (kernel-managed) ──────────────────────────────────
        // Sized for SYN bursts: 1/8 of max_incoming, floor 128, cap 8 192.
        let tcp_backlog = (max_incoming / 8).clamp(128, 8_192);

        // ── Identify cache (RAM) ─────────────────────────────────────────────────
        // Metadata for frequently-contacted peers: 1/4 of total, cap 1 024.
        let identify_cache = ((max_total / 4) as usize).min(1_024);

        Self {
            yamux_max_num_streams: yamux_streams,
            tcp_listen_backlog: tcp_backlog,
            tcp_nodelay: true,
            reqres_max_concurrent_streams: reqres_streams,
            reqres_request_timeout: 30,
            identify_cache,
            kademlia_query_timeout: 25,
            conn_limmits_max_pending_incoming: Some(pending_incoming),
            conn_limmits_max_pending_outgoing: Some(pending_outgoing),
            conn_limmits_max_established_incoming: Some(max_incoming),
            conn_limmits_max_established_outgoing: Some(max_outgoing),
            conn_limmits_max_established_per_peer: Some(2),
            conn_limmits_max_established_total: Some(max_total),
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
            RetryKind::Discover => Self::Discover,
            RetryKind::Dial => Self::Dial,
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
async fn request_peer_list(
    client: reqwest::Client,
    service: String,
    request_timeout: Duration,
    token: CancellationToken,
    list_kind: &'static str,
) -> Option<Vec<String>> {
    let response = tokio::select! {
        _ = token.clone().cancelled_owned() => return None,
        response = client.get(&service).timeout(request_timeout).send() => response,
    };

    match response {
        Ok(res) => {
            if !res.status().is_success() {
                warn!(
                    target: TARGET,
                    list_kind = list_kind,
                    url = service,
                    status = %res.status(),
                    "control-list service returned error status"
                );
                return None;
            }

            let peers = tokio::select! {
                _ = token.clone().cancelled_owned() => return None,
                peers = res.json::<Vec<String>>() => peers,
            };

            match peers {
                Ok(peers) => Some(peers),
                Err(e) => {
                    warn!(
                        target: TARGET,
                        list_kind = list_kind,
                        url = service,
                        error = %e,
                        "control-list service returned unexpected body"
                    );
                    None
                }
            }
        }
        Err(e) => {
            if e.is_timeout() {
                warn!(
                    target: TARGET,
                    list_kind = list_kind,
                    url = service,
                    timeout_secs = request_timeout.as_secs_f64(),
                    "control-list service timed out"
                );
            } else {
                warn!(
                    target: TARGET,
                    list_kind = list_kind,
                    url = service,
                    error = %e,
                    "control-list service unreachable"
                );
            }
            None
        }
    }
}

async fn request_peer_lists(
    client: reqwest::Client,
    services: Vec<String>,
    request_timeout: Duration,
    max_concurrent_requests: usize,
    token: CancellationToken,
    list_kind: &'static str,
) -> (Vec<String>, u16) {
    if services.is_empty() || token.is_cancelled() {
        return (vec![], 0);
    }

    let responses = stream::iter(services.into_iter().map(|service| {
        let client = client.clone();
        let token = token.clone();
        async move {
            request_peer_list(
                client,
                service,
                request_timeout,
                token,
                list_kind,
            )
            .await
        }
    }))
    .buffer_unordered(max_concurrent_requests.max(1))
    .collect::<Vec<Option<Vec<String>>>>()
    .await;

    let mut peers = Vec::new();
    let mut successful = 0u16;

    for item in responses.into_iter().flatten() {
        peers.extend(item);
        successful = successful.saturating_add(1);
    }

    (peers, successful)
}

pub async fn request_update_lists(
    client: reqwest::Client,
    service_allow: Vec<String>,
    service_block: Vec<String>,
    request_timeout: Duration,
    max_concurrent_requests: usize,
    token: CancellationToken,
) -> ((Vec<String>, Vec<String>), (u16, u16)) {
    let (
        (vec_allow_peers, successful_allow),
        (vec_block_peers, successful_block),
    ) = tokio::join!(
        request_peer_lists(
            client.clone(),
            service_allow,
            request_timeout,
            max_concurrent_requests,
            token.clone(),
            "allow"
        ),
        request_peer_lists(
            client,
            service_block,
            request_timeout,
            max_concurrent_requests,
            token,
            "block"
        )
    );

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
            return Err(Error::InvalidAddress(address.clone()));
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
#[cfg(not(feature = "test"))]
pub fn is_global(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => IpNetwork::from(ip).is_global(),
        Protocol::Ip6(ip) => IpNetwork::from(ip).is_global(),
        _ => false,
    })
}

#[cfg(not(feature = "test"))]
pub fn is_private(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_private(),
        Protocol::Ip6(ip) => ip.is_unique_local(),
        _ => false,
    })
}

#[cfg(not(feature = "test"))]
pub fn is_loop_back(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| match p {
        Protocol::Ip4(ip) => ip.is_loopback(),
        Protocol::Ip6(ip) => ip.is_loopback(),
        _ => false,
    })
}

#[cfg(not(feature = "test"))]
pub fn is_dns(addr: &Multiaddr) -> bool {
    addr.iter().any(|p| {
        matches!(p, Protocol::Dns(_) | Protocol::Dns4(_) | Protocol::Dns6(_))
    })
}

/// Chech if the given `Multiaddr` is a memory address.
#[cfg(not(feature = "test"))]
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
    pub const fn new(
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
    pub const fn with_message_timeout(mut self, timeout: Duration) -> Self {
        self.message_timeout = timeout;
        self
    }

    /// Sets the upper bound for the number of concurrent inbound + outbound streams.
    pub const fn with_max_concurrent_streams(
        mut self,
        num_streams: usize,
    ) -> Self {
        self.max_concurrent_streams = num_streams;
        self
    }

    /// Get message timeout
    pub const fn get_message_timeout(&self) -> Duration {
        self.message_timeout
    }

    /// Get max concurrent streams
    pub const fn get_max_concurrent_streams(&self) -> usize {
        self.max_concurrent_streams
    }
}
