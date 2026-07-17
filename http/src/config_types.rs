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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SinkAuthConfigHttp {
    /// OAuth2 / token endpoint URL
    pub auth_url: String,
    /// Username for the token endpoint
    pub username: String,
    /// API key for Api-Key header authentication. Always redacted (`"***"`)
    /// in API responses; the real value never leaves the node.
    pub api_key: String,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct HttpTlsConfigHttp {
    /// Path to an additional PEM-encoded root CA certificate to trust.
    pub ca_certificate: String,
    /// Path to the PEM-encoded client certificate chain used for mTLS.
    pub client_certificate: String,
    /// Path to the PEM-encoded PKCS#8 client private key used for mTLS.
    pub client_key: String,
    /// Minimum TLS version accepted (`"1.2"` or `"1.3"`); absent uses the
    /// TLS library default.
    pub min_tls_version: Option<HttpTlsVersionHttp>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct HttpProxyConfigHttp {
    /// Proxy URL (`http://` or `https://`), without embedded credentials.
    pub url: String,
    /// Proxy username; the password is read from the
    /// `AVE_SINK_PROXY_PASSWORD_{{SERVER}}` environment variable.
    pub username: String,
    /// Hosts that bypass the proxy.
    pub no_proxy: Vec<String>,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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
    /// URL endpoint for the sink
    pub url: String,
    /// Per-sink authentication configuration
    pub auth: Option<SinkAuthConfigHttp>,
    /// TCP connect timeout in milliseconds
    pub connect_timeout_ms: u64,
    /// Request timeout in milliseconds
    pub request_timeout_ms: u64,
    /// Maximum transient retries per delivery
    pub max_retries: usize,
    /// TLS customization: additional root CA, mTLS identity, minimum version
    pub tls: Option<HttpTlsConfigHttp>,
    /// Whether deliveries are signed with the node identity
    pub signature: bool,
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
}

impl Default for HttpSinkConfigHttp {
    fn default() -> Self {
        Self {
            url: String::new(),
            auth: None,
            connect_timeout_ms: 2_000,
            request_timeout_ms: 5_000,
            max_retries: 2,
            tls: None,
            signature: false,
            proxy: None,
            retry_max_delay_ms: 30_000,
            batch_delivery: false,
            batch_max_delay_ms: 100,
            compression: HttpCompressionHttp::None,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
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
    /// Required acknowledgements.
    pub acks: KafkaAcksHttp,
    /// Compression codec.
    pub compression: KafkaCompressionHttp,
    /// Per-message produce timeout in milliseconds.
    pub request_timeout_ms: u64,
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTransportConfigHttp {
    Http(HttpSinkConfigHttp),
    Kafka(KafkaSinkConfigHttp),
}

#[derive(Debug, Serialize, Clone, ToSchema, Deserialize)]
pub struct SinkServerHttp {
    /// Server identifier
    pub server: String,
    /// Event types to send to this sink (Create, Fact, Transfer, Confirm, Reject, EOL, All)
    pub events: Vec<String>,
    /// Delivery transport and its specific configuration
    pub transport: SinkTransportConfigHttp,
}

impl From<ave_bridge::SinkServer> for SinkServerHttp {
    fn from(value: ave_bridge::SinkServer) -> Self {
        let transport = match value.transport {
            ave_bridge::SinkTransportConfig::Http(http) => {
                SinkTransportConfigHttp::Http(HttpSinkConfigHttp {
                    url: http.url,
                    auth: http.auth.map(|a| SinkAuthConfigHttp {
                        auth_url: a.auth_url,
                        username: a.username,
                        // Never expose the configured API key through the API.
                        api_key: if a.api_key.is_empty() {
                            String::new()
                        } else {
                            "***".to_owned()
                        },
                    }),
                    connect_timeout_ms: http.connect_timeout_ms,
                    request_timeout_ms: http.request_timeout_ms,
                    max_retries: http.max_retries,
                    tls: http.tls.map(|t| HttpTlsConfigHttp {
                        ca_certificate: t.ca_certificate,
                        client_certificate: t.client_certificate,
                        client_key: t.client_key,
                        min_tls_version: t.min_tls_version.map(Into::into),
                    }),
                    signature: http.signature,
                    proxy: http.proxy.map(|p| HttpProxyConfigHttp {
                        url: p.url,
                        username: p.username,
                        no_proxy: p.no_proxy,
                    }),
                    retry_max_delay_ms: http.retry_max_delay_ms,
                    batch_delivery: http.batch_delivery,
                    batch_max_delay_ms: http.batch_max_delay_ms,
                    compression: http.compression.into(),
                })
            }
            ave_bridge::SinkTransportConfig::Kafka(kafka) => {
                SinkTransportConfigHttp::Kafka(KafkaSinkConfigHttp {
                    bootstrap_servers: kafka.bootstrap_servers,
                    topic: kafka.topic,
                    client_id: kafka.client_id,
                    security: kafka_security_to_http(kafka.security),
                    acks: kafka.acks.into(),
                    compression: kafka.compression.into(),
                    request_timeout_ms: kafka.request_timeout_ms,
                })
            }
        };
        Self {
            server: value.server,
            events: value.events.into_iter().map(|e| e.to_string()).collect(),
            transport,
        }
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
}
