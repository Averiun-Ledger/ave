//! # Configuration module

use std::{
    fmt::{self, Display},
    path::PathBuf,
    time::Instant,
};

use ave_common::Error;
use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};

pub use ave_common::sink::{
    HttpCompression, HttpSinkConfig, HttpTlsVersion, KafkaAcks,
    KafkaCompression, KafkaSaslMechanism, KafkaSecurityConfig, KafkaSinkConfig,
    SinkConfigEntry, SinkServer, SinkTarget, SinkTransportConfig,
};
use ave_network::Config as NetworkConfig;
use serde::{Deserialize, Deserializer, Serialize};

#[derive(Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
    #[serde(skip, default)]
    pub obtained_at: Option<Instant>,
}

impl TokenResponse {
    pub fn is_expired_or_expiring_soon(&self, margin_secs: u64) -> bool {
        self.obtained_at.is_none_or(|t| {
            let elapsed = t.elapsed().as_secs();
            self.expires_in > 0
                && elapsed + margin_secs >= self.expires_in as u64
        })
    }
}

/// Node configuration.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
pub struct Config {
    /// Key derivator.
    pub keypair_algorithm: KeyPairAlgorithm,
    /// Digest derivator.
    pub hash_algorithm: HashAlgorithm,
    /// Database configuration.
    pub internal_db: AveInternalDBConfig,
    /// External database configuration.
    pub external_db: AveExternalDBConfig,
    /// Network configuration.
    pub network: NetworkConfig,
    /// Contract dir.
    pub contracts_path: PathBuf,
    /// Approval mode.
    pub always_accept: bool,
    /// Safe mode disables mutating operations while allowing queries.
    pub safe_mode: bool,
    /// Tracking lru cache size
    pub tracking_size: usize,
    /// Is a service node
    pub is_service: bool,
    /// Reject tracker opaque events and only commit clear tracker events.
    pub only_clear_events: bool,
    /// Sync protocol configuration.
    pub sync: SyncConfig,
    /// Wasmtime execution environment sizing.
    /// `None` machine spec → auto-detect RAM and CPU from the host.
    pub spec: Option<MachineSpec>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keypair_algorithm: KeyPairAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Blake3,
            internal_db: Default::default(),
            external_db: Default::default(),
            network: Default::default(),
            contracts_path: PathBuf::from("contracts"),
            always_accept: Default::default(),
            safe_mode: false,
            tracking_size: 100,
            is_service: false,
            only_clear_events: false,
            sync: Default::default(),
            spec: None,
        }
    }
}

impl Config {
    /// Validates the node configuration, returning an error describing the
    /// first invalid value found.
    pub fn validate(&self) -> Result<(), Error> {
        if self.contracts_path.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "node.contracts_path".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if self.tracking_size == 0 {
            return Err(Error::InvalidConfiguration {
                component: "node.tracking_size".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }

        self.internal_db.validate().map_err(|e| {
            Error::InvalidConfiguration {
                component: "node.internal_db".to_string(),
                reason: e.to_string(),
            }
        })?;
        self.external_db.validate().map_err(|e| {
            Error::InvalidConfiguration {
                component: "node.external_db".to_string(),
                reason: e.to_string(),
            }
        })?;
        self.sync
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "node.sync".to_string(),
                reason: e.to_string(),
            })?;

        if let Some(spec) = &self.spec {
            spec.validate().map_err(|e| Error::InvalidConfiguration {
                component: "node.spec".to_string(),
                reason: e.to_string(),
            })?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
pub struct SyncConfig {
    pub ledger_batch_size: usize,
    pub governance: GovernanceSyncConfig,
    pub tracker: TrackerSyncConfig,
    pub update: UpdateSyncConfig,
    pub reboot: RebootSyncConfig,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            ledger_batch_size: 100,
            governance: GovernanceSyncConfig::default(),
            tracker: TrackerSyncConfig::default(),
            update: UpdateSyncConfig::default(),
            reboot: RebootSyncConfig::default(),
        }
    }
}

impl SyncConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.ledger_batch_size == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.ledger_batch_size".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }

        self.governance.validate().map_err(|e| {
            Error::InvalidConfiguration {
                component: "sync.governance".to_string(),
                reason: e.to_string(),
            }
        })?;
        self.tracker
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "sync.tracker".to_string(),
                reason: e.to_string(),
            })?;
        self.update
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "sync.update".to_string(),
                reason: e.to_string(),
            })?;
        self.reboot
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "sync.reboot".to_string(),
                reason: e.to_string(),
            })?;

        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
pub struct UpdateSyncConfig {
    /// Seconds between update round retries for tracker updates.
    pub round_retry_interval_secs: u64,
    /// Maximum number of tracker round retries without local progress.
    pub max_round_retries: usize,
    /// Retry attempts for each witness `GetLastSn` request.
    pub witness_retry_count: usize,
    /// Seconds between witness `GetLastSn` retry attempts.
    pub witness_retry_interval_secs: u64,
}

impl Default for UpdateSyncConfig {
    fn default() -> Self {
        Self {
            round_retry_interval_secs: 8,
            max_round_retries: 3,
            witness_retry_count: 1,
            witness_retry_interval_secs: 5,
        }
    }
}

impl UpdateSyncConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.round_retry_interval_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.update.round_retry_interval_secs".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.witness_retry_count == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.update.witness_retry_count".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.witness_retry_interval_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.update.witness_retry_interval_secs"
                    .to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
pub struct RebootSyncConfig {
    /// Seconds between governance stability checks while waiting in reboot.
    pub stability_check_interval_secs: u64,
    /// Number of unchanged checks before finishing reboot wait.
    pub stability_check_max_retries: u64,
    /// Backoff schedule, in seconds, for diff reboot retries.
    pub diff_retry_schedule_secs: Vec<u64>,
    /// Backoff schedule, in seconds, for timeout reboot retries.
    pub timeout_retry_schedule_secs: Vec<u64>,
}

impl Default for RebootSyncConfig {
    fn default() -> Self {
        Self {
            stability_check_interval_secs: 5,
            stability_check_max_retries: 3,
            diff_retry_schedule_secs: vec![10, 20, 30, 60],
            timeout_retry_schedule_secs:
                default_reboot_timeout_retry_schedule_secs(),
        }
    }
}

impl RebootSyncConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.stability_check_interval_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.reboot.stability_check_interval_secs"
                    .to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.stability_check_max_retries == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.reboot.stability_check_max_retries"
                    .to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        validate_positive_vec(
            "sync.reboot.diff_retry_schedule_secs",
            &self.diff_retry_schedule_secs,
        )?;
        validate_positive_vec(
            "sync.reboot.timeout_retry_schedule_secs",
            &self.timeout_retry_schedule_secs,
        )?;
        Ok(())
    }
}

#[cfg(any(test, feature = "test"))]
fn default_reboot_timeout_retry_schedule_secs() -> Vec<u64> {
    vec![5, 5, 5, 5]
}

#[cfg(not(any(test, feature = "test")))]
fn default_reboot_timeout_retry_schedule_secs() -> Vec<u64> {
    vec![30, 60, 120, 300]
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
pub struct GovernanceSyncConfig {
    /// Seconds between version sync rounds for governance service nodes.
    pub interval_secs: u64,
    /// Number of peers sampled on each version sync round.
    pub sample_size: usize,
    /// Seconds to wait for responses during a version sync round.
    pub response_timeout_secs: u64,
}

impl Default for GovernanceSyncConfig {
    fn default() -> Self {
        Self {
            interval_secs: 60,
            sample_size: 3,
            response_timeout_secs: 10,
        }
    }
}

impl GovernanceSyncConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.interval_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.governance.interval_secs".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.sample_size == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.governance.sample_size".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.response_timeout_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.governance.response_timeout_secs".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
#[serde(rename_all = "snake_case")]
pub struct TrackerSyncConfig {
    /// Seconds between tracker sync rounds for service nodes.
    pub interval_secs: u64,
    /// Number of tracker subjects returned per remote page.
    pub page_size: usize,
    /// Seconds to wait for a tracker sync page response.
    pub response_timeout_secs: u64,
    /// Number of tracker updates launched per local batch.
    pub update_batch_size: usize,
    /// Seconds between tracker update progress checks.
    pub update_timeout_secs: u64,
}

impl Default for TrackerSyncConfig {
    fn default() -> Self {
        Self {
            interval_secs: 30,
            page_size: 50,
            response_timeout_secs: 10,
            update_batch_size: 2,
            update_timeout_secs: 10,
        }
    }
}

impl TrackerSyncConfig {
    pub fn validate(&self) -> Result<(), Error> {
        if self.interval_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.tracker.interval_secs".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.page_size == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.tracker.page_size".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.response_timeout_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.tracker.response_timeout_secs".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.update_batch_size == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.tracker.update_batch_size".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        if self.update_timeout_secs == 0 {
            return Err(Error::InvalidConfiguration {
                component: "sync.tracker.update_timeout_secs".to_string(),
                reason: "must be greater than zero".to_string(),
            });
        }
        Ok(())
    }
}

// ── Machine specification ─────────────────────────────────────────────────────

/// How to size the contract execution environment.
///
/// - `Profile` — use a predefined instance type.
/// - `Custom`  — supply exact RAM (MB) and vCPU count manually.
/// - Absent (`None` in `WasmConfig`) — auto-detect from the running host.
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
/// wasmtime tuning is derived from the resolved `ram_mb` and `cpu_cores`.
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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

impl MachineSpec {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Profile(_) => Ok(()),
            Self::Custom { ram_mb, cpu_cores } => {
                if *ram_mb == 0 {
                    return Err(Error::InvalidConfiguration {
                        component: "MachineSpec.custom.ram_mb".to_string(),
                        reason: "must be greater than zero".to_string(),
                    });
                }
                if *cpu_cores == 0 {
                    return Err(Error::InvalidConfiguration {
                        component: "MachineSpec.custom.cpu_cores".to_string(),
                        reason: "must be greater than zero".to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

// ── Spec resolution ───────────────────────────────────────────────────────────

/// Resolved machine parameters ready to be consumed by any tuned subsystem.
pub struct ResolvedSpec {
    /// Total RAM in megabytes.
    pub ram_mb: u64,
    /// Available CPU cores.
    pub cpu_cores: usize,
}

/// Resolve the final sizing parameters from a [`MachineSpec`]:
///
/// - `Profile(p)` → use the profile's canonical RAM and vCPU.
/// - `Custom { ram_mb, cpu_cores }` → use the supplied values directly.
/// - `None` → auto-detect total RAM and available CPU cores from the host.
pub fn resolve_spec(spec: Option<&MachineSpec>) -> ResolvedSpec {
    match spec {
        Some(MachineSpec::Profile(p)) => ResolvedSpec {
            ram_mb: p.ram_mb(),
            cpu_cores: p.cpu_cores(),
        },
        Some(MachineSpec::Custom { ram_mb, cpu_cores }) => ResolvedSpec {
            ram_mb: *ram_mb,
            cpu_cores: *cpu_cores,
        },
        None => ResolvedSpec {
            ram_mb: detect_ram_mb(),
            cpu_cores: detect_cpu_cores(),
        },
    }
}

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

pub(crate) fn detect_cpu_cores() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(2)
}

// ── Conversions to peer-crate MachineSpec types ───────────────────────────────

impl From<MachineProfile> for ave_network::MachineProfile {
    fn from(p: MachineProfile) -> Self {
        match p {
            MachineProfile::Nano => Self::Nano,
            MachineProfile::Micro => Self::Micro,
            MachineProfile::Small => Self::Small,
            MachineProfile::Medium => Self::Medium,
            MachineProfile::Large => Self::Large,
            MachineProfile::XLarge => Self::XLarge,
            MachineProfile::XXLarge => Self::XXLarge,
        }
    }
}

impl From<MachineSpec> for ave_network::MachineSpec {
    fn from(spec: MachineSpec) -> Self {
        match spec {
            MachineSpec::Profile(p) => Self::Profile(p.into()),
            MachineSpec::Custom { ram_mb, cpu_cores } => {
                Self::Custom { ram_mb, cpu_cores }
            }
        }
    }
}

impl From<MachineProfile> for ave_actors::MachineProfile {
    fn from(p: MachineProfile) -> Self {
        match p {
            MachineProfile::Nano => Self::Nano,
            MachineProfile::Micro => Self::Micro,
            MachineProfile::Small => Self::Small,
            MachineProfile::Medium => Self::Medium,
            MachineProfile::Large => Self::Large,
            MachineProfile::XLarge => Self::XLarge,
            MachineProfile::XXLarge => Self::XXLarge,
        }
    }
}

impl From<MachineSpec> for ave_actors::MachineSpec {
    fn from(spec: MachineSpec) -> Self {
        match spec {
            MachineSpec::Profile(p) => Self::Profile(p.into()),
            MachineSpec::Custom { ram_mb, cpu_cores } => {
                Self::Custom { ram_mb, cpu_cores }
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AveInternalDBConfig {
    #[serde(deserialize_with = "AveInternalDBFeatureConfig::deserialize_db")]
    pub db: AveInternalDBFeatureConfig,
    pub durability: bool,
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub enum AveInternalDBFeatureConfig {
    /// Rocksdb database.
    #[cfg(feature = "rocksdb")]
    Rocksdb {
        /// Path to the database.
        path: PathBuf,
    },
    /// Sqlite database.
    #[cfg(feature = "sqlite")]
    Sqlite {
        /// Path to the database.
        path: PathBuf,
    },
}

impl Default for AveInternalDBFeatureConfig {
    fn default() -> Self {
        #[cfg(feature = "rocksdb")]
        return AveInternalDBFeatureConfig::Rocksdb {
            path: PathBuf::from("db").join("local").join("rocksdb"),
        };
        #[cfg(feature = "sqlite")]
        return Self::Sqlite {
            path: PathBuf::from("db").join("local").join("sqlite"),
        };
    }
}

impl AveInternalDBFeatureConfig {
    pub fn build(path: &PathBuf) -> Self {
        #[cfg(feature = "rocksdb")]
        return AveInternalDBFeatureConfig::Rocksdb {
            path: path.to_owned(),
        };
        #[cfg(feature = "sqlite")]
        return Self::Sqlite {
            path: path.to_owned(),
        };
    }

    pub fn deserialize_db<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path: String = String::deserialize(deserializer)?;
        #[cfg(feature = "rocksdb")]
        return Ok(AveInternalDBFeatureConfig::Rocksdb {
            path: PathBuf::from(path),
        });
        #[cfg(feature = "sqlite")]
        return Ok(Self::Sqlite {
            path: PathBuf::from(path),
        });
    }
}

impl fmt::Display for AveInternalDBFeatureConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "rocksdb")]
            AveInternalDBFeatureConfig::Rocksdb { .. } => write!(f, "Rocksdb"),
            #[cfg(feature = "sqlite")]
            Self::Sqlite { .. } => write!(f, "Sqlite"),
        }
    }
}

impl AveInternalDBConfig {
    pub fn validate(&self) -> Result<(), Error> {
        match &self.db {
            #[cfg(feature = "rocksdb")]
            AveInternalDBFeatureConfig::Rocksdb { path } => {
                if path.as_os_str().is_empty() {
                    return Err(Error::InvalidConfiguration {
                        component: "internal_db.db.path".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            }
            #[cfg(feature = "sqlite")]
            AveInternalDBFeatureConfig::Sqlite { path } => {
                if path.as_os_str().is_empty() {
                    return Err(Error::InvalidConfiguration {
                        component: "internal_db.db.path".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Deserialize, Serialize, Default)]
#[serde(default)]
pub struct AveExternalDBConfig {
    #[serde(deserialize_with = "AveExternalDBFeatureConfig::deserialize_db")]
    pub db: AveExternalDBFeatureConfig,
    pub durability: bool,
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Eq, Serialize)]
pub enum AveExternalDBFeatureConfig {
    /// Sqlite database.
    #[cfg(feature = "ext-sqlite")]
    Sqlite {
        /// Path to the database.
        path: PathBuf,
    },
}

impl Default for AveExternalDBFeatureConfig {
    fn default() -> Self {
        #[cfg(feature = "ext-sqlite")]
        return Self::Sqlite {
            path: PathBuf::from("db").join("ext").join("sqlite"),
        };
    }
}

impl AveExternalDBFeatureConfig {
    pub fn build(path: &PathBuf) -> Self {
        #[cfg(feature = "ext-sqlite")]
        return Self::Sqlite {
            path: path.to_owned(),
        };
    }

    pub fn deserialize_db<'de, D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path: String = String::deserialize(deserializer)?;
        #[cfg(feature = "ext-sqlite")]
        return Ok(Self::Sqlite {
            path: PathBuf::from(path),
        });
    }
}

impl fmt::Display for AveExternalDBFeatureConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sqlite")
    }
}

impl AveExternalDBConfig {
    pub fn validate(&self) -> Result<(), Error> {
        match &self.db {
            #[cfg(feature = "ext-sqlite")]
            AveExternalDBFeatureConfig::Sqlite { path } => {
                if path.as_os_str().is_empty() {
                    return Err(Error::InvalidConfiguration {
                        component: "external_db.db.path".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct LoggingOutput {
    pub stdout: bool,
    pub file: bool,
    pub api: bool,
}

impl Default for LoggingOutput {
    fn default() -> Self {
        Self {
            stdout: true,
            file: Default::default(),
            api: Default::default(),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Default, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingRotation {
    #[default]
    Size,
    Hourly,
    Daily,
    Weekly,
    Monthly,
    Yearly,
    Never,
}

impl Display for LoggingRotation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Size => write!(f, "size"),
            Self::Hourly => write!(f, "hourly"),
            Self::Daily => write!(f, "daily"),
            Self::Weekly => write!(f, "weekly"),
            Self::Monthly => write!(f, "monthly"),
            Self::Yearly => write!(f, "yearly"),
            Self::Never => write!(f, "never"),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default)]
pub struct LoggingConfig {
    pub output: LoggingOutput,
    pub api_url: Option<String>,
    pub file_path: PathBuf, // ruta base de logs
    pub rotation: LoggingRotation,
    pub max_size: usize,  // bytes
    pub max_files: usize, // copias a conservar
    /// Log level filter. Accepts tracing/RUST_LOG syntax: "info", "debug",
    /// "warn", "error", "trace", or per-crate directives like "info,ave=debug".
    /// The RUST_LOG environment variable takes priority over this field.
    pub level: String,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            output: LoggingOutput::default(),
            api_url: None,
            file_path: PathBuf::from("logs"),
            rotation: LoggingRotation::default(),
            max_size: 100 * 1024 * 1024,
            max_files: 3,
            level: "info".to_string(),
        }
    }
}

impl LoggingConfig {
    pub const fn logs(&self) -> bool {
        self.output.api || self.output.file || self.output.stdout
    }

    pub fn validate(&self) -> Result<(), Error> {
        if self.output.api {
            let url = self.api_url.as_deref().unwrap_or("");
            if url.is_empty() {
                return Err(Error::InvalidConfiguration {
                    component: "logging.api_url".to_string(),
                    reason: "must be set when output.api is true".to_string(),
                });
            }
            if !url.starts_with("http://") && !url.starts_with("https://") {
                return Err(Error::InvalidConfiguration {
                    component: "logging.api_url".to_string(),
                    reason: format!("must be an http/https URL, got {url}"),
                });
            }
        }

        if self.output.file {
            if self.file_path.as_os_str().is_empty() {
                return Err(Error::InvalidConfiguration {
                    component: "logging.file_path".to_string(),
                    reason: "must be set when output.file is true".to_string(),
                });
            }
            if self.max_files == 0 {
                return Err(Error::InvalidConfiguration {
                    component: "logging.max_files".to_string(),
                    reason:
                        "must be greater than zero when output.file is true"
                            .to_string(),
                });
            }
        }

        if self.rotation == LoggingRotation::Size && self.max_size == 0 {
            return Err(Error::InvalidConfiguration {
                component: "logging.max_size".to_string(),
                reason: "must be greater than zero when rotation is Size"
                    .to_string(),
            });
        }

        if self.level.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "logging.level".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        Ok(())
    }
}

fn validate_positive_vec(component: &str, values: &[u64]) -> Result<(), Error> {
    if values.is_empty() {
        return Err(Error::InvalidConfiguration {
            component: component.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    for (i, value) in values.iter().enumerate() {
        if *value == 0 {
            return Err(Error::InvalidConfiguration {
                component: format!("{component}[{i}]"),
                reason: "must be greater than zero, got 0".to_string(),
            });
        }
    }
    Ok(())
}
