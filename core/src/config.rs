//! # Configuration module

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Display},
    path::PathBuf,
};

use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
use network::Config as NetworkConfig;
use serde::{Deserialize, Deserializer, Serialize};

use crate::{helpers::sink::TokenResponse, subject::sinkdata::SinkTypes};

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
    /// Tracking lru cache size
    pub tracking_size: usize,
    /// Is a service node
    pub is_service: bool,
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
            contracts_path: PathBuf::new(),
            always_accept: Default::default(),
            tracking_size: 100,
            is_service: false,
            spec: None,
        }
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

impl From<MachineProfile> for network::MachineProfile {
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

impl From<MachineSpec> for network::MachineSpec {
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
}

#[derive(Clone, Debug, Deserialize, Default, Eq, PartialEq, Serialize)]
#[serde(default)]
pub struct SinkServer {
    pub server: String,
    pub events: BTreeSet<SinkTypes>,
    pub url: String,
    pub auth: bool,
    #[serde(default = "default_sink_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_sink_queue_capacity")]
    pub queue_capacity: usize,
    #[serde(default)]
    pub queue_policy: SinkQueuePolicy,
    #[serde(default)]
    pub routing_strategy: SinkRoutingStrategy,
    #[serde(default = "default_sink_connect_timeout_ms")]
    pub connect_timeout_ms: u64,
    #[serde(default = "default_sink_request_timeout_ms")]
    pub request_timeout_ms: u64,
    #[serde(default = "default_sink_max_retries")]
    pub max_retries: usize,
}

#[derive(Default)]
pub struct SinkAuth {
    pub sink: SinkConfig,
    pub token: Option<TokenResponse>,
    pub password: String,
    pub api_key: String,
}

#[derive(Clone, Debug, Deserialize, Default, Serialize)]
#[serde(default)]
pub struct SinkConfig {
    pub sinks: BTreeMap<String, Vec<SinkServer>>,
    pub auth: String,
    pub username: String,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkQueuePolicy {
    DropOldest,
    #[default]
    DropNewest,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SinkRoutingStrategy {
    #[default]
    OrderedBySubject,
    UnorderedRoundRobin,
}

const fn default_sink_concurrency() -> usize {
    2
}

const fn default_sink_queue_capacity() -> usize {
    1024
}

const fn default_sink_connect_timeout_ms() -> u64 {
    2_000
}

const fn default_sink_request_timeout_ms() -> u64 {
    5_000
}

const fn default_sink_max_retries() -> usize {
    2
}
