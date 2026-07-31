//! Configuration wrapper types for OpenAPI documentation
//!
//! These types wrap the core configuration types to provide Serialize and ToSchema support

use ave_bridge::{
    AveExternalDBConfig, AveInternalDBConfig, HttpConfig, ProxyConfig,
    SelfSignedCertConfig, SinkConfigEntry, SinkTarget,
    auth::{
        ApiKeyConfig, AuthConfig, EndpointRateLimit, LockoutConfig,
        RateLimitConfig, SessionConfig,
    },
};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct ConfigHttp {
    /// Core AVE configuration
    pub node: AveConfigHttp,
    /// Path to cryptographic keys
    pub keys_path: String,
    /// Logging configuration
    pub logging: LoggingHttp,
    /// Event sink configuration
    pub sink: SinkConfigHttp,
    pub auth: AuthConfigHttp,
    pub http: HttpConfigHttp,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub enum MachineSpecHttp {
    /// Use a predefined profile.
    Profile(String),
    /// Supply exact machine dimensions.
    Custom {
        /// Total RAM in megabytes.
        ram_mb: u64,
        /// Available CPU cores.
        cpu_cores: usize,
    },
}

impl From<ave_bridge::MachineSpec> for MachineSpecHttp {
    fn from(value: ave_bridge::MachineSpec) -> Self {
        match value {
            ave_bridge::MachineSpec::Profile(machine_profile) => {
                Self::Profile(machine_profile.to_string())
            }
            ave_bridge::MachineSpec::Custom { ram_mb, cpu_cores } => {
                Self::Custom { ram_mb, cpu_cores }
            }
        }
    }
}

impl From<ave_bridge::config::Config> for ConfigHttp {
    fn from(value: ave_bridge::config::Config) -> Self {
        let sinks = SinkConfigHttp {
            sinks: value
                .sinks
                .into_iter()
                .map(SinkConfigEntryHttp::from)
                .collect(),
        };
        Self {
            node: AveConfigHttp::from(value.node),
            keys_path: value.keys_path.to_string_lossy().to_string(),
            logging: LoggingHttp::from(value.logging),
            sink: sinks,
            auth: AuthConfigHttp::from(value.auth),
            http: HttpConfigHttp::from(value.http),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct AuthConfigHttp {
    pub enable: bool,
    pub durability: bool,
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
            durability: value.durability,
            api_key: ApiKeyConfigHttp::from(value.api_key),
            lockout: LockoutConfigHttp::from(value.lockout),
            rate_limit: RateLimitConfigHttp::from(value.rate_limit),
            session: SessionConfigHttp::from(value.session),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct ApiKeyConfigHttp {
    pub default_ttl_seconds: i64,
    pub max_keys_per_user: u32,
    pub prefix: String,
}

impl From<ApiKeyConfig> for ApiKeyConfigHttp {
    fn from(value: ApiKeyConfig) -> Self {
        Self {
            default_ttl_seconds: value.default_ttl_seconds,
            max_keys_per_user: value.max_keys_per_user,
            prefix: value.prefix,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct RateLimitConfigHttp {
    pub enable: bool,
    pub window_seconds: i64,
    pub max_requests: u32,
    pub limit_by_key: bool,
    pub limit_by_ip: bool,
    pub cleanup_interval_seconds: i64,
    pub sensitive_endpoints: Vec<EndpointRateLimitHttp>,
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
            sensitive_endpoints: value
                .sensitive_endpoints
                .into_iter()
                .map(EndpointRateLimitHttp::from)
                .collect(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct EndpointRateLimitHttp {
    pub endpoint: String,
    pub max_requests: u32,
    pub window_seconds: Option<i64>,
}

impl From<EndpointRateLimit> for EndpointRateLimitHttp {
    fn from(value: EndpointRateLimit) -> Self {
        Self {
            endpoint: value.endpoint,
            max_requests: value.max_requests,
            window_seconds: value.window_seconds,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SessionConfigHttp {
    pub audit_enable: bool,
    pub audit_retention_days: u32,
    pub audit_max_entries: u32,
}

impl From<SessionConfig> for SessionConfigHttp {
    fn from(value: SessionConfig) -> Self {
        Self {
            audit_enable: value.audit_enable,
            audit_retention_days: value.audit_retention_days,
            audit_max_entries: value.audit_max_entries,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct HttpConfigHttp {
    pub http_address: String,
    pub https_address: Option<String>,
    pub https_cert_path: Option<String>,
    pub https_private_key_path: Option<String>,
    pub enable_doc: bool,
    pub proxy: ProxyConfigHttp,
    pub cors: CorsConfigHttp,
    pub self_signed_cert: SelfSignedCertConfigHttp,
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
            proxy: ProxyConfigHttp::from(value.proxy),
            cors: CorsConfigHttp::from(value.cors),
            self_signed_cert: SelfSignedCertConfigHttp::from(
                value.self_signed_cert,
            ),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct ProxyConfigHttp {
    pub trusted_proxies: Vec<String>,
    pub trust_x_forwarded_for: bool,
    pub trust_x_real_ip: bool,
}

impl From<ProxyConfig> for ProxyConfigHttp {
    fn from(value: ProxyConfig) -> Self {
        Self {
            trusted_proxies: value.trusted_proxies,
            trust_x_forwarded_for: value.trust_x_forwarded_for,
            trust_x_real_ip: value.trust_x_real_ip,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SelfSignedCertConfigHttp {
    /// Enable automatic self-signed certificate generation
    pub enabled: bool,
    /// Common Name for the certificate (e.g., "localhost")
    pub common_name: String,
    /// Subject Alternative Names (additional hostnames/IPs)
    pub san: Vec<String>,
    /// Certificate validity in days
    pub validity_days: u32,
    /// Days before expiration to trigger renewal
    pub renew_before_days: u32,
    /// Check interval in seconds for certificate expiration
    pub check_interval_secs: u64,
}

impl From<SelfSignedCertConfig> for SelfSignedCertConfigHttp {
    fn from(value: SelfSignedCertConfig) -> Self {
        Self {
            enabled: value.enabled,
            common_name: value.common_name,
            san: value.san,
            validity_days: value.validity_days,
            renew_before_days: value.renew_before_days,
            check_interval_secs: value.check_interval_secs,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct CorsConfigHttp {
    pub enabled: bool,
    pub allow_any_origin: bool,
    pub allowed_origins: Vec<String>,
    pub allow_credentials: bool,
}

impl From<ave_bridge::CorsConfig> for CorsConfigHttp {
    fn from(value: ave_bridge::CorsConfig) -> Self {
        Self {
            enabled: value.enabled,
            allow_any_origin: value.allow_any_origin,
            allowed_origins: value.allowed_origins,
            allow_credentials: value.allow_credentials,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
pub enum KeyPairAlgorithmHttp {
    /// Ed25519 elliptic curve signature scheme.
    Ed25519,
}

impl From<ave_bridge::ave_common::identity::KeyPairAlgorithm>
    for KeyPairAlgorithmHttp
{
    fn from(value: ave_bridge::ave_common::identity::KeyPairAlgorithm) -> Self {
        match value {
            ave_bridge::ave_common::identity::KeyPairAlgorithm::Ed25519 => {
                Self::Ed25519
            }
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
pub enum HashAlgorithmHttp {
    /// Blake3 hash algorithm.
    Blake3,
}

impl From<ave_bridge::ave_common::identity::HashAlgorithm>
    for HashAlgorithmHttp
{
    fn from(value: ave_bridge::ave_common::identity::HashAlgorithm) -> Self {
        match value {
            ave_bridge::ave_common::identity::HashAlgorithm::Blake3 => {
                Self::Blake3
            }
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct AveConfigHttp {
    /// Keypair algorithm
    pub keypair_algorithm: KeyPairAlgorithmHttp,
    /// Hash algorithm
    pub hash_algorithm: HashAlgorithmHttp,
    /// AVE database path
    pub internal_db: AveStoreConfigHttp,
    /// External database path
    pub external_db: AveStoreConfigHttp,
    /// Network configuration
    pub network: NetworkConfigHttp,
    /// Directory for smart contracts
    pub contracts_path: String,
    /// Whether to automatically accept all events (development mode)
    pub always_accept: bool,
    /// Whether the node is running in safe mode
    pub safe_mode: bool,
    /// Garbage collector interval in seconds
    pub tracking_size: usize,
    /// Is a service node
    pub is_service: bool,
    /// Whether the node rejects tracker opaque events
    pub only_clear_events: bool,
    /// Sync protocol configuration
    pub sync: SyncConfigHttp,

    pub spec: Option<MachineSpecHttp>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SyncConfigHttp {
    pub ledger_batch_size: usize,
    pub governance: GovernanceSyncConfigHttp,
    pub tracker: TrackerSyncConfigHttp,
    pub update: UpdateSyncConfigHttp,
    pub reboot: RebootSyncConfigHttp,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct GovernanceSyncConfigHttp {
    pub interval_secs: u64,
    pub sample_size: usize,
    pub response_timeout_secs: u64,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct TrackerSyncConfigHttp {
    pub interval_secs: u64,
    pub page_size: usize,
    pub response_timeout_secs: u64,
    pub update_batch_size: usize,
    pub update_timeout_secs: u64,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct UpdateSyncConfigHttp {
    pub round_retry_interval_secs: u64,
    pub max_round_retries: usize,
    pub witness_retry_count: usize,
    pub witness_retry_interval_secs: u64,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct RebootSyncConfigHttp {
    pub stability_check_interval_secs: u64,
    pub stability_check_max_retries: u64,
    pub diff_retry_schedule_secs: Vec<u64>,
    pub timeout_retry_schedule_secs: Vec<u64>,
}

impl From<ave_bridge::AveConfig> for AveConfigHttp {
    fn from(value: ave_bridge::AveConfig) -> Self {
        Self {
            keypair_algorithm: value.keypair_algorithm.into(),
            hash_algorithm: value.hash_algorithm.into(),
            internal_db: AveStoreConfigHttp::from(value.internal_db),
            external_db: AveStoreConfigHttp::from(value.external_db),
            network: NetworkConfigHttp::from(value.network),
            contracts_path: value.contracts_path.to_string_lossy().to_string(),
            always_accept: value.always_accept,
            safe_mode: value.safe_mode,
            tracking_size: value.tracking_size,
            is_service: value.is_service,
            only_clear_events: value.only_clear_events,
            sync: SyncConfigHttp {
                ledger_batch_size: value.sync.ledger_batch_size,
                governance: GovernanceSyncConfigHttp {
                    interval_secs: value.sync.governance.interval_secs,
                    sample_size: value.sync.governance.sample_size,
                    response_timeout_secs: value
                        .sync
                        .governance
                        .response_timeout_secs,
                },
                tracker: TrackerSyncConfigHttp {
                    interval_secs: value.sync.tracker.interval_secs,
                    page_size: value.sync.tracker.page_size,
                    response_timeout_secs: value
                        .sync
                        .tracker
                        .response_timeout_secs,
                    update_batch_size: value.sync.tracker.update_batch_size,
                    update_timeout_secs: value.sync.tracker.update_timeout_secs,
                },
                update: UpdateSyncConfigHttp {
                    round_retry_interval_secs: value
                        .sync
                        .update
                        .round_retry_interval_secs,
                    max_round_retries: value.sync.update.max_round_retries,
                    witness_retry_count: value.sync.update.witness_retry_count,
                    witness_retry_interval_secs: value
                        .sync
                        .update
                        .witness_retry_interval_secs,
                },
                reboot: RebootSyncConfigHttp {
                    stability_check_interval_secs: value
                        .sync
                        .reboot
                        .stability_check_interval_secs,
                    stability_check_max_retries: value
                        .sync
                        .reboot
                        .stability_check_max_retries,
                    diff_retry_schedule_secs: value
                        .sync
                        .reboot
                        .diff_retry_schedule_secs,
                    timeout_retry_schedule_secs: value
                        .sync
                        .reboot
                        .timeout_retry_schedule_secs,
                },
            },
            spec: value.spec.map(MachineSpecHttp::from),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct AveStoreConfigHttp {
    pub db: String,
    pub durability: bool,
}

impl From<AveInternalDBConfig> for AveStoreConfigHttp {
    fn from(value: AveInternalDBConfig) -> Self {
        Self {
            db: value.db.to_string(),
            durability: value.durability,
        }
    }
}

impl From<AveExternalDBConfig> for AveStoreConfigHttp {
    fn from(value: AveExternalDBConfig) -> Self {
        Self {
            db: value.db.to_string(),
            durability: value.durability,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
pub enum NodeTypeHttp {
    /// Bootstrap node.
    Bootstrap,
    /// Addressable node.
    Addressable,
    /// Ephemeral node.
    Ephemeral,
}

impl From<ave_bridge::NodeType> for NodeTypeHttp {
    fn from(value: ave_bridge::NodeType) -> Self {
        match value {
            ave_bridge::NodeType::Bootstrap => Self::Bootstrap,
            ave_bridge::NodeType::Addressable => Self::Addressable,
            ave_bridge::NodeType::Ephemeral => Self::Ephemeral,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum MemoryLimitsConfigHttp {
    /// No memory-based connection limit.
    Disabled,
    /// Reject new connections when process memory exceeds `value` fraction
    /// of total RAM (range 0.0–1.0, e.g. `0.8` means 80% of system RAM).
    Percentage {
        /// Fraction of total system RAM, in the range 0.0–1.0.
        value: f64,
    },
    /// Reject new connections when process memory exceeds `value` megabytes.
    Mb {
        /// Limit in megabytes.
        value: usize,
    },
}

impl From<ave_bridge::MemoryLimitsConfig> for MemoryLimitsConfigHttp {
    fn from(value: ave_bridge::MemoryLimitsConfig) -> Self {
        match value {
            ave_bridge::MemoryLimitsConfig::Disabled => Self::Disabled,
            ave_bridge::MemoryLimitsConfig::Percentage { value } => {
                Self::Percentage { value }
            }
            ave_bridge::MemoryLimitsConfig::Mb { value } => Self::Mb { value },
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct NetworkConfigHttp {
    /// The node type (Bootstrap, Addressable, Ephemeral)
    pub node_type: NodeTypeHttp,
    /// Listen addresses for the network
    pub listen_addresses: Vec<String>,
    /// External addresses advertised to the network
    pub external_addresses: Vec<String>,
    /// Bootstrap nodes to connect to
    pub boot_nodes: Vec<RoutingNodeHttp>,
    /// Routing configuration (DHT and discovery settings)
    pub routing: RoutingConfigHttp,
    /// Control list configuration (allow/deny lists)
    pub control_list: ControlListConfigHttp,
    /// Memory-based connection limit policy
    pub memory_limits: MemoryLimitsConfigHttp,
    /// Maximum accepted application message payload in bytes.
    pub max_app_message_bytes: usize,
    /// Maximum buffered inbound bytes per peer while waiting for helper delivery.
    pub max_pending_inbound_bytes_per_peer: usize,
    /// Maximum buffered outbound bytes per peer while disconnected.
    pub max_pending_outbound_bytes_per_peer: usize,
    /// Maximum total buffered inbound bytes across all peers while waiting for helper delivery.
    /// `0` means no global limit.
    pub max_pending_inbound_bytes_total: usize,
    /// Maximum total buffered outbound bytes across all peers while disconnected.
    /// `0` means no global limit.
    pub max_pending_outbound_bytes_total: usize,
}

impl From<ave_bridge::NetworkConfig> for NetworkConfigHttp {
    fn from(value: ave_bridge::NetworkConfig) -> Self {
        Self {
            node_type: value.node_type.into(),
            listen_addresses: value.listen_addresses,
            external_addresses: value.external_addresses,
            boot_nodes: value
                .boot_nodes
                .into_iter()
                .map(RoutingNodeHttp::from)
                .collect(),
            routing: RoutingConfigHttp::from(value.routing),
            control_list: ControlListConfigHttp::from(value.control_list),
            memory_limits: value.memory_limits.into(),
            max_app_message_bytes: value.max_app_message_bytes,
            max_pending_outbound_bytes_per_peer: value
                .max_pending_outbound_bytes_per_peer,
            max_pending_inbound_bytes_per_peer: value
                .max_pending_inbound_bytes_per_peer,
            max_pending_outbound_bytes_total: value
                .max_pending_outbound_bytes_total,
            max_pending_inbound_bytes_total: value
                .max_pending_inbound_bytes_total,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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
    /// Timeout in seconds for each control-list HTTP request
    pub request_timeout_secs: u64,
    /// Maximum number of concurrent HTTP requests while refreshing lists
    pub max_concurrent_requests: usize,
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
            request_timeout_secs: value.get_request_timeout().as_secs(),
            max_concurrent_requests: value.get_max_concurrent_requests(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LoggingRotationHttp {
    /// Rotate when the log file reaches `max_size` bytes.
    Size,
    /// Rotate every hour.
    Hourly,
    /// Rotate every day.
    Daily,
    /// Rotate every week.
    Weekly,
    /// Rotate every month.
    Monthly,
    /// Rotate every year.
    Yearly,
    /// Never rotate.
    Never,
}

impl From<ave_bridge::LoggingRotation> for LoggingRotationHttp {
    fn from(value: ave_bridge::LoggingRotation) -> Self {
        match value {
            ave_bridge::LoggingRotation::Size => Self::Size,
            ave_bridge::LoggingRotation::Hourly => Self::Hourly,
            ave_bridge::LoggingRotation::Daily => Self::Daily,
            ave_bridge::LoggingRotation::Weekly => Self::Weekly,
            ave_bridge::LoggingRotation::Monthly => Self::Monthly,
            ave_bridge::LoggingRotation::Yearly => Self::Yearly,
            ave_bridge::LoggingRotation::Never => Self::Never,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct LoggingHttp {
    /// Logging output configuration
    pub output: LoggingOutputHttp,
    /// API URL for remote logging (optional)
    pub api_url: Option<String>,
    /// Path to the log file
    pub file_path: String,
    /// Log rotation policy (size, hourly, daily, weekly, monthly, yearly, never)
    pub rotation: LoggingRotationHttp,
    /// Maximum size of the log file in bytes
    pub max_size: usize,
    /// Maximum number of log files to keep
    pub max_files: usize,
    /// Log level filter (e.g. "info", "debug", "info,ave=debug")
    pub level: String,
}

impl From<ave_bridge::LoggingConfig> for LoggingHttp {
    fn from(value: ave_bridge::LoggingConfig) -> Self {
        Self {
            output: LoggingOutputHttp::from(value.output),
            api_url: value.api_url,
            file_path: value.file_path.to_string_lossy().to_string(),
            rotation: value.rotation.into(),
            max_size: value.max_size,
            max_files: value.max_files,
            level: value.level,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SinkConfigHttp {
    /// List of sink configuration entries. Each entry pairs a target with the
    /// servers that deliver events for that target.
    pub sinks: Vec<SinkConfigEntryHttp>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTargetHttp {
    /// Every sink targets a schema. Use `"governance"` as `schema_id` for
    /// node-level governance sinks; in that case `governance_id` must be
    /// `None`.
    Schema {
        schema_id: String,
        /// Governance to which this sink applies. Must be `None` when
        /// `schema_id` is `"governance"`; mandatory otherwise.
        governance_id: Option<String>,
    },
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SinkConfigEntryHttp {
    pub target: SinkTargetHttp,
    pub servers: Vec<SinkServerHttp>,
}

impl From<SinkTarget> for SinkTargetHttp {
    fn from(value: SinkTarget) -> Self {
        let SinkTarget::Schema {
            schema_id,
            governance_id,
        } = value;
        Self::Schema {
            schema_id,
            governance_id,
        }
    }
}

impl From<SinkConfigEntry> for SinkConfigEntryHttp {
    fn from(value: SinkConfigEntry) -> Self {
        Self {
            target: value.target.into(),
            servers: value
                .servers
                .into_iter()
                .map(SinkServerHttp::from)
                .collect(),
        }
    }
}

#[derive(
    Debug, Default, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq,
)]
#[serde(rename_all = "snake_case")]
pub enum OAuth2GrantTypeHttp {
    /// Resource Owner Password Credentials grant.
    #[default]
    Password,
    /// Client Credentials grant (machine-to-machine / enterprise IdP).
    ClientCredentials,
}

impl From<ave_bridge::ave_common::sink::OAuth2GrantType>
    for OAuth2GrantTypeHttp
{
    fn from(value: ave_bridge::ave_common::sink::OAuth2GrantType) -> Self {
        match value {
            ave_bridge::ave_common::sink::OAuth2GrantType::Password => {
                Self::Password
            }
            ave_bridge::ave_common::sink::OAuth2GrantType::ClientCredentials => {
                Self::ClientCredentials
            }
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SinkAuthConfigHttp {
    /// OAuth2 / token endpoint URL
    pub auth_url: String,
    /// Username for the token endpoint
    pub username: String,
    /// API key for Api-Key header authentication. Always redacted (`"***"`)
    /// in API responses; the real value never leaves the node.
    pub api_key: String,
    /// OAuth2 grant type. Defaults to `password` for backwards compatibility.
    #[serde(default)]
    pub grant_type: OAuth2GrantTypeHttp,
    /// Client identifier for the `client_credentials` grant
    #[serde(default)]
    pub client_id: String,
    /// Optional OAuth2 scope(s) requested when obtaining a token
    #[serde(default)]
    pub scope: String,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
pub enum HttpTlsVersionHttp {
    /// TLS 1.2.
    #[serde(rename = "1.2")]
    Tls12,
    /// TLS 1.3.
    #[serde(rename = "1.3")]
    Tls13,
}

impl From<ave_bridge::ave_common::sink::HttpTlsVersion> for HttpTlsVersionHttp {
    fn from(value: ave_bridge::ave_common::sink::HttpTlsVersion) -> Self {
        match value {
            ave_bridge::ave_common::sink::HttpTlsVersion::Tls12 => Self::Tls12,
            ave_bridge::ave_common::sink::HttpTlsVersion::Tls13 => Self::Tls13,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Default)]
#[serde(default)]
pub struct HttpTlsConfigHttp {
    /// Path to an additional PEM-encoded root CA certificate to trust.
    pub ca_certificate: String,
    /// Path to the PEM-encoded client certificate chain used for mTLS.
    pub client_certificate: String,
    /// Path to the PEM-encoded PKCS#8 client private key used for mTLS.
    pub client_key: String,
    /// Path to a PEM-encoded server certificate to pin.
    pub pinned_certificate: String,
    /// Minimum TLS version accepted (`"1.2"` or `"1.3"`); absent uses the
    /// TLS library default.
    pub min_tls_version: Option<HttpTlsVersionHttp>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Default)]
#[serde(default)]
pub struct HttpProxyConfigHttp {
    /// Proxy URL (`http://` or `https://`), without embedded credentials.
    pub url: String,
    /// Proxy username; the password is read from the
    /// `AVE_SINK_PROXY_PASSWORD_{{SERVER}}` environment variable.
    pub username: String,
    /// Hosts that bypass the proxy.
    pub no_proxy: Vec<String>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum HttpCompressionHttp {
    /// No compression.
    None,
    /// gzip compression (`Content-Encoding: gzip`).
    Gzip,
}

impl From<ave_bridge::ave_common::sink::HttpCompression>
    for HttpCompressionHttp
{
    fn from(value: ave_bridge::ave_common::sink::HttpCompression) -> Self {
        match value {
            ave_bridge::ave_common::sink::HttpCompression::None => Self::None,
            ave_bridge::ave_common::sink::HttpCompression::Gzip => Self::Gzip,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(default)]
pub struct HttpSinkConfigHttp {
    /// URL endpoint template; supports the `{{schema-id}}`, `{{subject-id}}`
    /// and `{{event-type}}` placeholders.
    pub url: String,
    /// Per-sink authentication configuration
    pub auth: Option<SinkAuthConfigHttp>,
    /// TCP connect timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
    /// Maximum transient retries per delivery
    pub max_retries: usize,
    /// Base delay between delivery retries, in milliseconds
    pub retry_base_delay_ms: u64,
    /// TLS customization: additional root CA, mTLS identity, minimum version
    pub tls: Option<HttpTlsConfigHttp>,
    /// Whether deliveries are signed with the node identity
    pub signature: bool,
    /// Signature protocol version (`1` = body only, `2` = canonical headers + body)
    pub signature_version: u8,
    /// Outbound proxy for this sink's requests
    pub proxy: Option<HttpProxyConfigHttp>,
    /// Upper bound for any delivery retry delay, in milliseconds
    pub retry_max_delay_ms: u64,
    /// Whether events are delivered in batches (single POST with a JSON array)
    pub batch_delivery: bool,
    /// Maximum time a live event waits for a batch to fill, in milliseconds
    pub batch_max_delay_ms: u64,
    /// Body compression for deliveries: `none` or `"gzip"`
    pub compression: HttpCompressionHttp,
    /// Custom health-check URL; when absent the delivery URL is used
    pub health_check_url: Option<String>,
    /// Margin in seconds before token expiry to trigger a refresh
    pub token_refresh_margin_secs: u64,
    /// Maximum number of bytes to read from an error response body
    pub max_error_body_bytes: usize,
    /// TCP keepalive interval in seconds; `None` disables keepalive
    pub tcp_keepalive_secs: Option<u64>,
    /// Maximum time a pooled idle connection remains open, in seconds
    pub pool_idle_timeout_secs: u64,
    /// Maximum number of idle connections to keep open per host
    pub pool_max_idle_per_host: usize,
    /// Maximum number of HTTP redirects the sink client will follow. `0`
    /// disables redirects (recommended for webhooks).
    pub max_redirects: usize,
    /// Custom static headers added to every delivery and health-check request.
    /// Internal sink headers (Authorization, X-Ave-*, etc.) take precedence.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
}

impl Default for HttpSinkConfigHttp {
    fn default() -> Self {
        Self {
            url: String::new(),
            auth: None,
            connect_timeout_ms: 2_000,
            request_timeout_ms: 5_000,
            max_retries: 2,
            retry_base_delay_ms: 500,
            tls: None,
            signature: false,
            signature_version: 1,
            proxy: None,
            retry_max_delay_ms: 30_000,
            batch_delivery: false,
            batch_max_delay_ms: 100,
            compression: HttpCompressionHttp::None,
            health_check_url: None,
            token_refresh_margin_secs: 30,
            max_error_body_bytes: 4_096,
            tcp_keepalive_secs: Some(60),
            pool_idle_timeout_secs: 90,
            pool_max_idle_per_host: 4,
            max_redirects: 0,
            headers: std::collections::HashMap::new(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
pub enum KafkaSaslMechanismHttp {
    /// PLAIN username/password authentication.
    #[serde(rename = "PLAIN")]
    Plain,
    /// SCRAM challenge-response with SHA-256.
    #[serde(rename = "SCRAM-SHA-256")]
    ScramSha256,
    /// SCRAM challenge-response with SHA-512.
    #[serde(rename = "SCRAM-SHA-512")]
    ScramSha512,
    /// OIDC bearer tokens (`client_credentials` grant against
    /// `oauth_token_url`).
    #[serde(rename = "OAUTHBEARER")]
    OAuthBearer,
    /// Kerberos/GSSAPI authentication.
    #[serde(rename = "GSSAPI")]
    Gssapi,
}

impl From<ave_bridge::ave_common::sink::KafkaSaslMechanism>
    for KafkaSaslMechanismHttp
{
    fn from(value: ave_bridge::ave_common::sink::KafkaSaslMechanism) -> Self {
        match value {
            ave_bridge::ave_common::sink::KafkaSaslMechanism::Plain => {
                Self::Plain
            }
            ave_bridge::ave_common::sink::KafkaSaslMechanism::ScramSha256 => {
                Self::ScramSha256
            }
            ave_bridge::ave_common::sink::KafkaSaslMechanism::ScramSha512 => {
                Self::ScramSha512
            }
            ave_bridge::ave_common::sink::KafkaSaslMechanism::OAuthBearer => {
                Self::OAuthBearer
            }
            ave_bridge::ave_common::sink::KafkaSaslMechanism::Gssapi => {
                Self::Gssapi
            }
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Default)]
#[serde(default)]
pub struct KafkaKerberosConfigHttp {
    /// Kerberos service name of the Kafka brokers (usually `kafka`).
    pub service_name: String,
    /// Client principal used to authenticate.
    pub principal: String,
    /// Path to the client's keytab file.
    pub keytab: String,
}

impl From<ave_bridge::ave_common::sink::KafkaKerberosConfig>
    for KafkaKerberosConfigHttp
{
    fn from(value: ave_bridge::ave_common::sink::KafkaKerberosConfig) -> Self {
        Self {
            service_name: value.service_name,
            principal: value.principal,
            keytab: value.keytab,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum KafkaSecurityConfigHttp {
    /// No encryption, no authentication.
    Plaintext,
    /// TLS encryption without authentication.
    Ssl,
    /// SASL authentication over a plaintext connection.
    SaslPlaintext {
        /// SASL mechanism.
        mechanism: KafkaSaslMechanismHttp,
        /// SASL username.
        username: String,
    },
    /// SASL authentication over a TLS connection.
    SaslSsl {
        /// SASL mechanism.
        mechanism: KafkaSaslMechanismHttp,
        /// SASL username.
        username: String,
    },
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
pub enum KafkaAcksHttp {
    /// No acknowledgement is required (fire and forget).
    #[serde(rename = "0")]
    Zero,
    /// Only the leader broker acknowledges the write.
    #[serde(rename = "1")]
    One,
    /// All in-sync replicas acknowledge the write.
    #[serde(rename = "all")]
    All,
}

impl From<ave_bridge::ave_common::sink::KafkaAcks> for KafkaAcksHttp {
    fn from(value: ave_bridge::ave_common::sink::KafkaAcks) -> Self {
        match value {
            ave_bridge::ave_common::sink::KafkaAcks::Zero => Self::Zero,
            ave_bridge::ave_common::sink::KafkaAcks::One => Self::One,
            ave_bridge::ave_common::sink::KafkaAcks::All => Self::All,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum KafkaCompressionHttp {
    /// No compression.
    None,
    /// gzip compression.
    Gzip,
    /// Snappy compression.
    Snappy,
    /// LZ4 compression.
    Lz4,
    /// Zstandard compression.
    Zstd,
}

impl From<ave_bridge::ave_common::sink::KafkaCompression>
    for KafkaCompressionHttp
{
    fn from(value: ave_bridge::ave_common::sink::KafkaCompression) -> Self {
        match value {
            ave_bridge::ave_common::sink::KafkaCompression::None => Self::None,
            ave_bridge::ave_common::sink::KafkaCompression::Gzip => Self::Gzip,
            ave_bridge::ave_common::sink::KafkaCompression::Snappy => {
                Self::Snappy
            }
            ave_bridge::ave_common::sink::KafkaCompression::Lz4 => Self::Lz4,
            ave_bridge::ave_common::sink::KafkaCompression::Zstd => Self::Zstd,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum KafkaKeyStrategyHttp {
    /// Use the event's subject id as the key.
    SubjectId,
    /// Send messages without a key (round-robin partition).
    None,
    /// Use a fixed literal key for every delivery.
    Static(String),
    /// Render the key from `{{subject-id}}` and `{{schema-id}}` placeholders.
    Template(String),
}

impl From<ave_bridge::ave_common::sink::KafkaKeyStrategy>
    for KafkaKeyStrategyHttp
{
    fn from(value: ave_bridge::ave_common::sink::KafkaKeyStrategy) -> Self {
        use ave_bridge::ave_common::sink::KafkaKeyStrategy;
        match value {
            KafkaKeyStrategy::SubjectId => Self::SubjectId,
            KafkaKeyStrategy::None => Self::None,
            KafkaKeyStrategy::Static(v) => Self::Static(v),
            KafkaKeyStrategy::Template(v) => Self::Template(v),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize, Default)]
#[serde(default)]
pub struct KafkaTlsConfigHttp {
    /// Path to an additional PEM-encoded root CA certificate to trust.
    pub ca_certificate: String,
    /// Path to the PEM-encoded client certificate chain used for mTLS.
    pub client_certificate: String,
    /// Path to the PEM-encoded PKCS#8 client private key used for mTLS.
    pub client_key: String,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct KafkaSinkConfigHttp {
    /// Comma-separated list of `host:port` bootstrap brokers.
    pub bootstrap_servers: String,
    /// Topic template; supports `{{schema-id}}` and `{{subject-id}}`.
    pub topic: String,
    /// Producer client id.
    pub client_id: String,
    /// Security configuration for the brokers.
    pub security: KafkaSecurityConfigHttp,
    /// TLS customization: additional root CA, mTLS identity, minimum version.
    pub tls: Option<KafkaTlsConfigHttp>,
    /// Whether deliveries are signed with the node identity
    pub signature: bool,
    /// Signature protocol version (`1` = body only, `2` = canonical headers + body)
    pub signature_version: u8,
    /// Required acknowledgements.
    pub acks: KafkaAcksHttp,
    /// Compression codec.
    pub compression: KafkaCompressionHttp,
    /// Per-message produce timeout in milliseconds.
    pub request_timeout_ms: u64,
    /// Whether events are delivered in batches (single message with a JSON array)
    /// instead of one message per event.
    pub batch_delivery: bool,
    /// Maximum time a live event waits for a batch to fill before it is
    /// flushed. Only used when `batch_delivery` is enabled.
    pub batch_max_delay_ms: u64,
    /// Maximum transient retries per delivery.
    pub max_retries: usize,
    /// Base delay between delivery retries, in milliseconds.
    pub retry_base_delay_ms: u64,
    /// Upper bound for any delivery retry delay, in milliseconds.
    pub retry_max_delay_ms: u64,
    /// Default timeout for network requests, in milliseconds.
    pub socket_timeout_ms: u64,
    /// Enable TCP keep-alives on broker sockets.
    pub socket_keepalive: bool,
    /// Close broker connections after this inactivity, in milliseconds.
    pub connections_max_idle_ms: u64,
    /// Metadata cache max age, in milliseconds.
    pub metadata_max_age_ms: u64,
    /// Strategy used to derive the Kafka message key for each delivery.
    pub key_strategy: KafkaKeyStrategyHttp,
    /// Use Kafka transactions for exactly-once semantics on the producer side.
    pub transactional: bool,
    /// Transactional id used by Kafka to fence zombies.
    pub transactional_id: Option<String>,
    /// Producer linger in milliseconds.
    pub linger_ms: u64,
    /// Producer batch size in bytes.
    pub batch_size_bytes: usize,
    /// Producer queue capacity in number of messages.
    pub queue_buffering_max_messages: usize,
    /// Interval in milliseconds between librdkafka producer statistics
    /// reports, used to expose producer metrics. `0` disables them.
    pub statistics_interval_ms: u64,
    /// Custom static headers added to every delivered message.
    /// Internal sink headers (`x-ave-*`, `idempotency-key`) take precedence.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// librdkafka partitioner; `None` keeps the librdkafka default.
    #[serde(default)]
    pub partitioner: Option<String>,
    /// OIDC token endpoint used with the `OAUTHBEARER` SASL mechanism.
    #[serde(default)]
    pub oauth_token_url: Option<String>,
    /// Optional OAuth2 scope requested at the OIDC token endpoint.
    #[serde(default)]
    pub oauth_scope: Option<String>,
    /// Kerberos configuration used with the `GSSAPI` SASL mechanism.
    #[serde(default)]
    pub kerberos: Option<KafkaKerberosConfigHttp>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum GrpcAuthConfigHttp {
    /// `authorization: Bearer <token>` metadata on every RPC.
    BearerToken,
    /// `x-api-key: <key>` metadata on every RPC.
    ApiKey,
    /// `authorization: Basic base64(username:password)` metadata on every RPC.
    Basic {
        /// Username of the basic credentials.
        username: String,
    },
    /// OAuth2 with token cache and refresh on UNAUTHENTICATED.
    OAuth2(SinkAuthConfigHttp),
}

#[derive(Debug, Default, Serialize, Clone, ToSchema, Deserialize)]
pub struct GrpcTlsConfigHttp {
    /// Path to an additional PEM-encoded root CA certificate to trust.
    pub ca_certificate: String,
    /// Path to the PEM-encoded client certificate chain used for mTLS.
    pub client_certificate: String,
    /// Path to the PEM-encoded PKCS#8 client private key used for mTLS.
    pub client_key: String,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct GrpcSinkConfigHttp {
    /// Server endpoint (`http://host:port`, `https://host:port` or `dns:///host:port`).
    pub endpoint: String,
    /// Per-RPC authentication.
    pub auth: Option<GrpcAuthConfigHttp>,
    /// TLS customization: additional root CA and mTLS identity.
    pub tls: Option<GrpcTlsConfigHttp>,
    /// Whether deliveries are signed with the node identity (canonical v2).
    pub signature: bool,
    /// Seconds before token expiry at which an OAuth2 token is refreshed.
    pub token_refresh_margin_secs: u64,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    /// Maximum transient retries per delivery.
    pub max_retries: usize,
    /// Base delay between delivery retries, in milliseconds.
    pub retry_base_delay_ms: u64,
    /// Upper bound for any delivery retry delay, in milliseconds.
    pub retry_max_delay_ms: u64,
    /// Whether events are delivered in batches (single request with a JSON array)
    /// instead of one request per event.
    pub batch_delivery: bool,
    /// Maximum time a live event waits for a batch to fill before it is
    /// flushed. Only used when `batch_delivery` is enabled.
    pub batch_max_delay_ms: u64,
    /// Message compression for deliveries: `none` (default) or `gzip`.
    pub compression: HttpCompressionHttp,
    /// Custom static metadata added to every RPC.
    /// Internal sink metadata (`authorization`, `x-api-key`, `x-ave-*`, `grpc-*`)
    /// takes precedence.
    #[serde(default)]
    pub headers: std::collections::HashMap<String, String>,
    /// Maximum size of an inbound gRPC message.
    pub max_decoding_message_bytes: usize,
    /// Maximum size of an outbound gRPC message (one batch).
    pub max_encoding_message_bytes: usize,
    /// Maximum number of unacknowledged deliveries in flight on the delivery
    /// stream (backpressure window).
    pub max_in_flight_batches: usize,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTransportConfigHttp {
    Http(Box<HttpSinkConfigHttp>),
    Kafka(Box<KafkaSinkConfigHttp>),
    Grpc(Box<GrpcSinkConfigHttp>),
}

impl Default for SinkTransportConfigHttp {
    fn default() -> Self {
        Self::Http(Box::default())
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(default)]
pub struct SinkServerHttp {
    /// Server identifier
    pub server: String,
    /// Event types to send to this sink (Create, Fact, Transfer, Confirm, Reject, EOL, All)
    pub events: Vec<String>,
    /// Delivery transport and its specific configuration
    pub transport: SinkTransportConfigHttp,
    /// Number of events read from the ledger per catch-up batch.
    pub catch_up_batch_size: usize,
    /// Maximum number of live events to buffer before flushing a batch delivery.
    pub batch_delivery_size: usize,
    /// Time a sink worker can be idle before the manager shuts it down
    pub sink_worker_idle_timeout_ms: u64,
    /// Backoff schedule for periodic healthchecks when the sink has lagging subjects
    pub healthcheck_intervals_secs: Vec<u64>,
    /// Maximum concurrent catch-up streams per sink worker
    pub max_catch_up_concurrency: usize,
    /// Time a per-subject worker can be idle before it is stopped
    pub sink_subject_worker_idle_timeout_ms: u64,
    /// Maximum recoveries after failure before the sink is considered flapping
    pub max_recoveries_after_failure: u32,
    /// Consecutive failed healthchecks required before the sink is declared unhealthy
    pub healthcheck_max_failures: u32,
    /// Delay before the first healthcheck after worker startup
    pub startup_healthcheck_delay_secs: u64,
}

impl Default for SinkServerHttp {
    fn default() -> Self {
        Self {
            server: String::new(),
            events: Vec::new(),
            transport: SinkTransportConfigHttp::default(),
            catch_up_batch_size: 100,
            batch_delivery_size: 100,
            sink_worker_idle_timeout_ms: 10_000,
            healthcheck_intervals_secs: vec![30, 60, 120, 300, 600],
            max_catch_up_concurrency: 2,
            sink_subject_worker_idle_timeout_ms: 2_000,
            max_recoveries_after_failure: 5,
            healthcheck_max_failures: 3,
            startup_healthcheck_delay_secs: 1,
        }
    }
}

impl From<ave_bridge::SinkServer> for SinkServerHttp {
    fn from(value: ave_bridge::SinkServer) -> Self {
        let transport = match value.transport {
            ave_bridge::SinkTransportConfig::Http(http) => {
                SinkTransportConfigHttp::Http(Box::new(HttpSinkConfigHttp {
                    url: http.url,
                    auth: http.auth.map(sink_auth_to_http),
                    connect_timeout_ms: http.connect_timeout_ms,
                    request_timeout_ms: http.request_timeout_ms,
                    max_retries: http.max_retries,
                    retry_base_delay_ms: http.retry_base_delay_ms,
                    tls: http.tls.map(|t| HttpTlsConfigHttp {
                        ca_certificate: t.ca_certificate,
                        client_certificate: t.client_certificate,
                        client_key: t.client_key,
                        pinned_certificate: t.pinned_certificate,
                        min_tls_version: t.min_tls_version.map(Into::into),
                    }),
                    signature: http.signature,
                    signature_version: http.signature_version,
                    proxy: http.proxy.map(|p| HttpProxyConfigHttp {
                        url: p.url,
                        username: p.username,
                        no_proxy: p.no_proxy,
                    }),
                    retry_max_delay_ms: http.retry_max_delay_ms,
                    batch_delivery: http.batch_delivery,
                    batch_max_delay_ms: http.batch_max_delay_ms,
                    compression: http.compression.into(),
                    health_check_url: http.health_check_url,
                    token_refresh_margin_secs: http.token_refresh_margin_secs,
                    max_error_body_bytes: http.max_error_body_bytes,
                    tcp_keepalive_secs: http.tcp_keepalive_secs,
                    pool_idle_timeout_secs: http.pool_idle_timeout_secs,
                    pool_max_idle_per_host: http.pool_max_idle_per_host,
                    max_redirects: http.max_redirects,
                    headers: http.headers,
                }))
            }
            ave_bridge::SinkTransportConfig::Kafka(kafka) => {
                SinkTransportConfigHttp::Kafka(Box::new(KafkaSinkConfigHttp {
                    bootstrap_servers: kafka.bootstrap_servers,
                    topic: kafka.topic,
                    client_id: kafka.client_id,
                    security: kafka_security_to_http(kafka.security),
                    tls: kafka.tls.map(|t| KafkaTlsConfigHttp {
                        ca_certificate: t.ca_certificate,
                        client_certificate: t.client_certificate,
                        client_key: t.client_key,
                    }),
                    signature: kafka.signature,
                    signature_version: kafka.signature_version,
                    acks: kafka.acks.into(),
                    compression: kafka.compression.into(),
                    request_timeout_ms: kafka.request_timeout_ms,
                    batch_delivery: kafka.batch_delivery,
                    batch_max_delay_ms: kafka.batch_max_delay_ms,
                    max_retries: kafka.max_retries,
                    retry_base_delay_ms: kafka.retry_base_delay_ms,
                    retry_max_delay_ms: kafka.retry_max_delay_ms,
                    socket_timeout_ms: kafka.socket_timeout_ms,
                    socket_keepalive: kafka.socket_keepalive,
                    connections_max_idle_ms: kafka.connections_max_idle_ms,
                    metadata_max_age_ms: kafka.metadata_max_age_ms,
                    key_strategy: kafka.key_strategy.into(),
                    transactional: kafka.transactional,
                    transactional_id: kafka.transactional_id,
                    linger_ms: kafka.linger_ms,
                    batch_size_bytes: kafka.batch_size_bytes,
                    queue_buffering_max_messages: kafka
                        .queue_buffering_max_messages,
                    statistics_interval_ms: kafka.statistics_interval_ms,
                    headers: kafka.headers,
                    partitioner: kafka.partitioner,
                    oauth_token_url: kafka.oauth_token_url,
                    oauth_scope: kafka.oauth_scope,
                    kerberos: kafka.kerberos.map(Into::into),
                }))
            }
            ave_bridge::SinkTransportConfig::Grpc(grpc) => {
                SinkTransportConfigHttp::Grpc(Box::new(GrpcSinkConfigHttp {
                    endpoint: grpc.endpoint,
                    auth: grpc.auth.map(|a| match a {
                        ave_bridge::ave_common::sink::GrpcAuthConfig::BearerToken => {
                            GrpcAuthConfigHttp::BearerToken
                        }
                        ave_bridge::ave_common::sink::GrpcAuthConfig::ApiKey => {
                            GrpcAuthConfigHttp::ApiKey
                        }
                        ave_bridge::ave_common::sink::GrpcAuthConfig::Basic {
                            username,
                        } => GrpcAuthConfigHttp::Basic { username },
                        ave_bridge::ave_common::sink::GrpcAuthConfig::OAuth2(
                            auth,
                        ) => {
                            GrpcAuthConfigHttp::OAuth2(sink_auth_to_http(auth))
                        }
                    }),
                    tls: grpc.tls.map(|t| GrpcTlsConfigHttp {
                        ca_certificate: t.ca_certificate,
                        client_certificate: t.client_certificate,
                        client_key: t.client_key,
                    }),
                    signature: grpc.signature,
                    token_refresh_margin_secs: grpc.token_refresh_margin_secs,
                    connect_timeout_ms: grpc.connect_timeout_ms,
                    request_timeout_ms: grpc.request_timeout_ms,
                    max_retries: grpc.max_retries,
                    retry_base_delay_ms: grpc.retry_base_delay_ms,
                    retry_max_delay_ms: grpc.retry_max_delay_ms,
                    batch_delivery: grpc.batch_delivery,
                    batch_max_delay_ms: grpc.batch_max_delay_ms,
                    compression: grpc.compression.into(),
                    headers: grpc.headers,
                    max_decoding_message_bytes: grpc
                        .max_decoding_message_bytes,
                    max_encoding_message_bytes: grpc
                        .max_encoding_message_bytes,
                    max_in_flight_batches: grpc.max_in_flight_batches,
                }))
            }
        };
        Self {
            server: value.server,
            events: value.events.into_iter().map(|e| e.to_string()).collect(),
            transport,
            catch_up_batch_size: value.catch_up_batch_size,
            batch_delivery_size: value.batch_delivery_size,
            sink_worker_idle_timeout_ms: value.sink_worker_idle_timeout_ms,
            healthcheck_intervals_secs: value.healthcheck_intervals_secs,
            max_catch_up_concurrency: value.max_catch_up_concurrency,
            sink_subject_worker_idle_timeout_ms: value
                .sink_subject_worker_idle_timeout_ms,
            max_recoveries_after_failure: value.max_recoveries_after_failure,
            healthcheck_max_failures: value.healthcheck_max_failures,
            startup_healthcheck_delay_secs: value
                .startup_healthcheck_delay_secs,
        }
    }
}

fn sink_auth_to_http(
    value: ave_bridge::ave_common::sink::SinkAuthConfig,
) -> SinkAuthConfigHttp {
    SinkAuthConfigHttp {
        auth_url: value.auth_url,
        username: value.username,
        // Never expose the configured API key through the API.
        api_key: if value.api_key.is_empty() {
            String::new()
        } else {
            "***".to_owned()
        },
        grant_type: value.grant_type.into(),
        client_id: value.client_id,
        scope: value.scope,
    }
}

fn kafka_security_to_http(
    value: ave_bridge::KafkaSecurityConfig,
) -> KafkaSecurityConfigHttp {
    match value {
        ave_bridge::KafkaSecurityConfig::Plaintext => {
            KafkaSecurityConfigHttp::Plaintext
        }
        ave_bridge::KafkaSecurityConfig::Ssl => KafkaSecurityConfigHttp::Ssl,
        ave_bridge::KafkaSecurityConfig::SaslPlaintext {
            mechanism,
            username,
        } => KafkaSecurityConfigHttp::SaslPlaintext {
            mechanism: mechanism.into(),
            username,
        },
        ave_bridge::KafkaSecurityConfig::SaslSsl {
            mechanism,
            username,
        } => KafkaSecurityConfigHttp::SaslSsl {
            mechanism: mechanism.into(),
            username,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The API key configured for a sink must never appear in the HTTP
    /// representation exposed through the API: it is redacted to `"***"`.
    /// TLS and signature settings must survive the conversion.
    #[test]
    fn sink_server_http_redacts_api_key() {
        let server: ave_bridge::SinkServer = serde_json::from_value(json!({
            "server": "secure-sink",
            "transport": {
                "type": "http",
                "url": "https://sink.example.com/events",
                "auth": { "auth_url": "", "username": "", "api_key": "real-secret-key" },
                "tls": { "ca_certificate": "/etc/ave/ca.pem" },
                "signature": true
            }
        }))
        .expect("sink server should deserialize");

        let json = serde_json::to_string(&SinkServerHttp::from(server))
            .expect("sink server should serialize");

        assert!(
            !json.contains("real-secret-key"),
            "the API key must never be exposed: {json}"
        );
        assert!(json.contains("***"), "the API key must be redacted: {json}");
        assert!(json.contains("/etc/ave/ca.pem"));
        assert!(json.contains("\"signature\":true"));
    }

    /// An empty API key stays empty instead of being redacted, so the
    /// response does not suggest a key is configured when it is not.
    #[test]
    fn sink_server_http_keeps_empty_api_key_empty() {
        let server: ave_bridge::SinkServer = serde_json::from_value(json!({
            "server": "plain-sink",
            "transport": {
                "type": "http",
                "url": "http://sink.example.com/events",
                "auth": { "auth_url": "", "username": "", "api_key": "" }
            }
        }))
        .expect("sink server should deserialize");

        let SinkTransportConfigHttp::Http(http) =
            SinkServerHttp::from(server).transport
        else {
            panic!("expected HTTP transport");
        };
        let auth = http.auth.expect("auth config should be present");
        assert!(auth.api_key.is_empty());
    }

    /// The HTTP mirror must expose every effective knob of the sink config:
    /// `retry_base_delay_ms`, `health_check_url` and
    /// `token_refresh_margin_secs` are carried over from the bridge config.
    #[test]
    fn sink_server_http_maps_http_tuning_fields() {
        let server: ave_bridge::SinkServer = serde_json::from_value(json!({
            "server": "tuning-sink",
            "transport": {
                "type": "http",
                "url": "https://sink.example.com/events",
                "retry_base_delay_ms": 250,
                "health_check_url": "https://sink.example.com/health",
                "token_refresh_margin_secs": 10
            }
        }))
        .expect("sink server should deserialize");

        let SinkTransportConfigHttp::Http(http) =
            SinkServerHttp::from(server).transport
        else {
            panic!("expected HTTP transport");
        };
        assert_eq!(http.retry_base_delay_ms, 250);
        assert_eq!(
            http.health_check_url.as_deref(),
            Some("https://sink.example.com/health")
        );
        assert_eq!(http.token_refresh_margin_secs, 10);
    }

    /// Nested mirror structs must accept partial JSON: any subset of fields
    /// deserializes and the rest fall back to their defaults, matching the
    /// behavior of the bridge config types.
    #[test]
    fn nested_mirror_structs_deserialize_partial_json() {
        let tls: HttpTlsConfigHttp = serde_json::from_value(json!({
            "ca_certificate": "/etc/ave/ca.pem"
        }))
        .expect("tls config should deserialize");
        assert_eq!(tls.ca_certificate, "/etc/ave/ca.pem");
        assert!(tls.client_certificate.is_empty());
        assert!(tls.client_key.is_empty());
        assert!(tls.min_tls_version.is_none());

        let proxy: HttpProxyConfigHttp = serde_json::from_value(json!({
            "url": "http://proxy.example.com:8080"
        }))
        .expect("proxy config should deserialize");
        assert_eq!(proxy.url, "http://proxy.example.com:8080");
        assert!(proxy.username.is_empty());
        assert!(proxy.no_proxy.is_empty());
    }

    /// The Kafka mirror must expose the operator-configured custom static
    /// headers, carried over from the bridge config like any other tuning
    /// knob. A missing `headers` key falls back to an empty map.
    #[test]
    fn sink_server_kafka_maps_custom_headers() {
        let server: ave_bridge::SinkServer = serde_json::from_value(json!({
            "server": "kafka-headers-sink",
            "transport": {
                "type": "kafka",
                "bootstrap_servers": "broker:9092",
                "topic": "ave-events",
                "headers": { "x-custom-tenant": "tenant-1" }
            }
        }))
        .expect("sink server should deserialize");

        let SinkTransportConfigHttp::Kafka(kafka) =
            SinkServerHttp::from(server).transport
        else {
            panic!("expected Kafka transport");
        };
        assert_eq!(
            kafka.headers.get("x-custom-tenant").map(String::as_str),
            Some("tenant-1")
        );

        let server: ave_bridge::SinkServer = serde_json::from_value(json!({
            "server": "kafka-no-headers-sink",
            "transport": {
                "type": "kafka",
                "bootstrap_servers": "broker:9092",
                "topic": "ave-events"
            }
        }))
        .expect("sink server without headers should deserialize");

        let SinkTransportConfigHttp::Kafka(kafka) =
            SinkServerHttp::from(server).transport
        else {
            panic!("expected Kafka transport");
        };
        assert!(kafka.headers.is_empty());
    }
}
