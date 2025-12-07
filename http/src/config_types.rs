//! Configuration wrapper types for OpenAPI documentation
//!
//! These types wrap the core configuration types to provide Serialize and ToSchema support

use ave_bridge::{
    HttpConfig,
    auth::{
        ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig,
    },
};
use serde::Serialize;
use std::collections::BTreeMap;
use utoipa::ToSchema;

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct ConfigHttp {
    /// Core AVE configuration
    pub node: AveConfigHttp,
    /// Path to cryptographic keys
    pub keys_path: String,
    /// Prometheus metrics endpoint
    pub prometheus: String,
    /// Logging configuration
    pub logging: LoggingHttp,
    /// Event sink configuration
    pub sink: SinkConfigHttp,
    pub auth: AuthConfigHttp,
    pub http: HttpConfigHttp,
}

impl From<ave_bridge::config::Config> for ConfigHttp {
    fn from(value: ave_bridge::config::Config) -> Self {
        Self {
            node: AveConfigHttp::from(value.node),
            keys_path: value.keys_path.to_string_lossy().to_string(),
            prometheus: value.prometheus,
            logging: LoggingHttp::from(value.logging),
            sink: SinkConfigHttp::from(value.sink),
            auth: AuthConfigHttp::from(value.auth),
            http: HttpConfigHttp::from(value.http)
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct AuthConfigHttp {
    pub enable: bool,
    pub database_path: String,
    pub superadmin: String,
    pub api_key: ApiKeyConfigHttp,
    pub lockout: LockoutConfigHttp,
    pub rate_limit: RateLimitConfigHttp,
    pub session: SessionConfigHttp,
}

impl From<AuthConfig> for AuthConfigHttp {
    fn from(value: AuthConfig) -> Self {
        Self {
            enable: value.enable,
            database_path: value.database_path.to_string_lossy().to_string(),
            superadmin: value.superadmin,
            api_key: ApiKeyConfigHttp::from(value.api_key),
            lockout: LockoutConfigHttp::from(value.lockout),
            rate_limit: RateLimitConfigHttp::from(value.rate_limit),
            session: SessionConfigHttp::from(value.session),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct ApiKeyConfigHttp {
    pub default_ttl_seconds: i64,
    pub max_keys_per_user: u32,
}

impl From<ApiKeyConfig> for ApiKeyConfigHttp {
    fn from(value: ApiKeyConfig) -> Self {
        Self {
            default_ttl_seconds: value.default_ttl_seconds,
            max_keys_per_user: value.max_keys_per_user,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct LockoutConfigHttp {
    pub max_attempts: u32,
    pub duration_seconds: i64,
}

impl From<LockoutConfig> for LockoutConfigHttp {
    fn from(value: LockoutConfig) -> Self {
        Self {
            max_attempts: value.max_attempts,
            duration_seconds: value.duration_seconds,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct RateLimitConfigHttp {
    pub enable: bool,
    pub window_seconds: i64,
    pub max_requests: u32,
    pub limit_by_key: bool,
    pub limit_by_ip: bool,
    pub cleanup_interval_seconds: i64,
}

impl From<RateLimitConfig> for RateLimitConfigHttp {
    fn from(value: RateLimitConfig) -> Self {
        Self {
            enable: value.enable,
            window_seconds: value.window_seconds,
            max_requests: value.max_requests,
            limit_by_key: value.limit_by_key,
            limit_by_ip: value.limit_by_ip,
            cleanup_interval_seconds: value.cleanup_interval_seconds,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct SessionConfigHttp {
    pub audit_enable: bool,
    pub audit_retention_days: u32,
    pub log_all_requests: bool,
}

impl From<SessionConfig> for SessionConfigHttp {
    fn from(value: SessionConfig) -> Self {
        Self {
            audit_enable: value.audit_enable,
            audit_retention_days: value.audit_retention_days,
            log_all_requests: value.log_all_requests,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct HttpConfigHttp {
    pub http_address: String,
    pub https_address: Option<String>,
    pub https_cert_path: Option<String>,
    pub https_private_key_path: Option<String>,
    pub enable_doc: bool,
}

impl From<HttpConfig> for HttpConfigHttp {
    fn from(value: HttpConfig) -> Self {
        Self {
            http_address: value.http_address,
            https_address: value.https_address,
            https_cert_path: value
                .https_cert_path
                .map(|x| x.to_string_lossy().to_string()),
            https_private_key_path: value
                .https_private_key_path
                .map(|x| x.to_string_lossy().to_string()),
            enable_doc: value.enable_doc,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct AveConfigHttp {
    /// Keypair algorithm
    pub keypair_algorithm: String,
    /// Hash algorithm
    pub hash_algorithm: String,
    /// AVE database path
    pub ave_db: String,
    /// External database path
    pub external_db: String,
    /// Network configuration
    pub network: NetworkConfigHttp,
    /// Directory for smart contracts
    pub contracts_path: String,
    /// Whether to automatically accept all events (development mode)
    pub always_accept: bool,
    /// Garbage collector interval in seconds
    pub garbage_collector: u64,
}

impl From<ave_bridge::AveConfig> for AveConfigHttp {
    fn from(value: ave_bridge::AveConfig) -> Self {
        Self {
            keypair_algorithm: format!("{:?}", value.keypair_algorithm),
            hash_algorithm: format!("{:?}", value.hash_algorithm),
            ave_db: value.ave_db.to_string(),
            external_db: value.external_db.to_string(),
            network: NetworkConfigHttp::from(value.network),
            contracts_path: value.contracts_path.to_string_lossy().to_string(),
            always_accept: value.always_accept,
            garbage_collector: value.garbage_collector.as_secs(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct NetworkConfigHttp {
    /// The node type (Bootstrap, Addressable, Ephemeral)
    pub node_type: String,
    /// Listen addresses for the network
    pub listen_addresses: Vec<String>,
    /// External addresses advertised to the network
    pub external_addresses: Vec<String>,
    /// Bootstrap nodes to connect to
    pub boot_nodes: Vec<RoutingNodeHttp>,
    /// Tell protocol configuration
    pub tell: TellConfigHttp,
    /// Request-Response protocol configuration
    pub req_res: ReqResConfigHttp,
    /// Routing configuration (DHT and discovery settings)
    pub routing: RoutingConfigHttp,
    /// Control list configuration (allow/deny lists)
    pub control_list: ControlListConfigHttp,
}

impl From<ave_bridge::NetworkConfig> for NetworkConfigHttp {
    fn from(value: ave_bridge::NetworkConfig) -> Self {
        Self {
            node_type: format!("{:?}", value.node_type),
            listen_addresses: value.listen_addresses,
            external_addresses: value.external_addresses,
            boot_nodes: value
                .boot_nodes
                .into_iter()
                .map(RoutingNodeHttp::from)
                .collect(),
            tell: TellConfigHttp::from(value.tell),
            req_res: ReqResConfigHttp::from(value.req_res),
            routing: RoutingConfigHttp::from(value.routing),
            control_list: ControlListConfigHttp::from(value.control_list),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct TellConfigHttp {
    /// Tell protocol message timeout in seconds
    pub message_timeout_secs: u64,
    /// Maximum concurrent streams for Tell protocol
    pub max_concurrent_streams: usize,
}

impl From<ave_bridge::TellConfig> for TellConfigHttp {
    fn from(value: ave_bridge::TellConfig) -> Self {
        Self {
            message_timeout_secs: value.message_timeout.as_secs(),
            max_concurrent_streams: value.max_concurrent_streams,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct ReqResConfigHttp {
    /// Request-Response message timeout in seconds
    pub message_timeout_secs: u64,
    /// Maximum concurrent streams
    pub max_concurrent_streams: usize,
}

impl From<ave_bridge::ReqResConfig> for ReqResConfigHttp {
    fn from(value: ave_bridge::ReqResConfig) -> Self {
        Self {
            message_timeout_secs: value.message_timeout.as_secs(),
            max_concurrent_streams: value.max_concurrent_streams,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct RoutingConfigHttp {
    /// Whether to enable random walks in the Kademlia DHT
    pub dht_random_walk: bool,
    /// Number of active connections over which we interrupt the discovery process
    pub discovery_only_if_under_num: u64,
    /// Allow private addresses in DHT
    pub allow_private_address_in_dht: bool,
    /// Allow DNS addresses in DHT
    pub allow_dns_address_in_dht: bool,
    /// Allow loopback addresses in DHT
    pub allow_loop_back_address_in_dht: bool,
    /// Use disjoint query paths in Kademlia
    pub kademlia_disjoint_query_paths: bool,
}

impl From<ave_bridge::RoutingConfig> for RoutingConfigHttp {
    fn from(value: ave_bridge::RoutingConfig) -> Self {
        Self {
            dht_random_walk: value.get_dht_random_walk(),
            discovery_only_if_under_num: value.get_discovery_limit(),
            allow_private_address_in_dht: value
                .get_allow_private_address_in_dht(),
            allow_dns_address_in_dht: value.get_allow_dns_address_in_dht(),
            allow_loop_back_address_in_dht: value
                .get_allow_loop_back_address_in_dht(),
            kademlia_disjoint_query_paths: value
                .get_kademlia_disjoint_query_paths(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct ControlListConfigHttp {
    /// Enable control lists (allow/block)
    pub enable: bool,
    /// Nodes allowed to make and receive connections
    pub allow_list: Vec<String>,
    /// Nodes that are not allowed to make and receive connections
    pub block_list: Vec<String>,
    /// Services where the node will query the list of allowed nodes
    pub service_allow_list: Vec<String>,
    /// Services where the node will query the list of blocked nodes
    pub service_block_list: Vec<String>,
    /// Time interval in seconds for updating the lists
    pub interval_request_secs: u64,
}

impl From<ave_bridge::ControlListConfig> for ControlListConfigHttp {
    fn from(value: ave_bridge::ControlListConfig) -> Self {
        Self {
            enable: value.get_enable(),
            allow_list: value.get_allow_list(),
            block_list: value.get_block_list(),
            service_allow_list: value.get_service_allow_list(),
            service_block_list: value.get_service_block_list(),
            interval_request_secs: value.get_interval_request().as_secs(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct RoutingNodeHttp {
    /// Peer ID of the routing node
    pub peer_id: String,
    /// Addresses to connect to this node
    pub address: Vec<String>,
}

impl From<ave_bridge::RoutingNode> for RoutingNodeHttp {
    fn from(value: ave_bridge::RoutingNode) -> Self {
        Self {
            peer_id: value.peer_id.to_string(),
            address: value.address.iter().map(|a| a.to_string()).collect(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct LoggingHttp {
    /// Logging output configuration
    pub output: LoggingOutputHttp,
    /// API URL for remote logging (optional)
    pub api_url: Option<String>,
    /// Path to the log file
    pub file_path: String,
    /// Log rotation policy (Size, Hourly, Daily, Weekly, Monthly, Yearly, Never)
    pub rotation: String,
    /// Maximum size of the log file in bytes
    pub max_size: usize,
    /// Maximum number of log files to keep
    pub max_files: usize,
}

impl From<ave_bridge::LoggingConfig> for LoggingHttp {
    fn from(value: ave_bridge::LoggingConfig) -> Self {
        Self {
            output: LoggingOutputHttp::from(value.output),
            api_url: value.api_url,
            file_path: value.file_path.to_string_lossy().to_string(),
            rotation: format!("{:?}", value.rotation),
            max_size: value.max_size,
            max_files: value.max_files,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct LoggingOutputHttp {
    /// Enable logging to stdout
    pub stdout: bool,
    /// Enable logging to file
    pub file: bool,
    /// Enable logging to remote API
    pub api: bool,
}

impl From<ave_bridge::LoggingOutput> for LoggingOutputHttp {
    fn from(value: ave_bridge::LoggingOutput) -> Self {
        Self {
            stdout: value.stdout,
            file: value.file,
            api: value.api,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct SinkConfigHttp {
    /// Map of sink configurations by name
    pub sinks: BTreeMap<String, Vec<SinkServerHttp>>,
    /// Authentication method for sinks
    pub auth: String,
    /// Username for sink authentication
    pub username: String,
}

impl From<ave_bridge::SinkConfig> for SinkConfigHttp {
    fn from(value: ave_bridge::SinkConfig) -> Self {
        Self {
            sinks: value
                .sinks
                .into_iter()
                .map(|(k, v)| {
                    (k, v.into_iter().map(SinkServerHttp::from).collect())
                })
                .collect(),
            auth: value.auth,
            username: value.username,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct SinkServerHttp {
    /// Server identifier
    pub server: String,
    /// Event types to send to this sink (Create, Fact, Transfer, Confirm, Reject, EOL, All)
    pub events: Vec<String>,
    /// URL endpoint for the sink
    pub url: String,
    /// Whether authentication is required for this sink
    pub auth: bool,
}

impl From<ave_bridge::SinkServer> for SinkServerHttp {
    fn from(value: ave_bridge::SinkServer) -> Self {
        Self {
            server: value.server,
            events: value.events.into_iter().map(|e| e.to_string()).collect(),
            url: value.url,
            auth: value.auth,
        }
    }
}
