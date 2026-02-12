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
pub struct Config {
    /// Key derivator.
    pub keypair_algorithm: KeyPairAlgorithm,
    /// Digest derivator.
    pub hash_algorithm: HashAlgorithm,
    /// Database configuration.
    #[serde(deserialize_with = "AveDbConfig::deserialize_db")]
    pub ave_db: AveDbConfig,
    /// External database configuration.
    #[serde(deserialize_with = "ExternalDbConfig::deserialize_db")]
    pub external_db: ExternalDbConfig,
    /// Network configuration.
    pub network: NetworkConfig,
    /// Contract dir.
    pub contracts_path: PathBuf,
    /// Approval mode.
    pub always_accept: bool,
    /// Tracking lru cache size
    pub tracking_size: usize,
    /// Is a service node
    pub is_service: bool
}

impl Default for Config {
    fn default() -> Self {
        Self {
            keypair_algorithm: KeyPairAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Blake3,
            ave_db: Default::default(),
            external_db: Default::default(),
            network: Default::default(),
            contracts_path: PathBuf::new(),
            always_accept: Default::default(),
            tracking_size: 100,
            is_service: false
        }
    }
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub enum AveDbConfig {
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

impl Default for AveDbConfig {
    fn default() -> Self {
        #[cfg(feature = "rocksdb")]
        return AveDbConfig::Rocksdb {
            path: PathBuf::from("db").join("local").join("rocksdb"),
        };
        #[cfg(feature = "sqlite")]
        return AveDbConfig::Sqlite {
            path: PathBuf::from("db").join("local").join("sqlite"),
        };
    }
}

impl AveDbConfig {
    pub fn build(path: &PathBuf) -> Self {
        #[cfg(feature = "rocksdb")]
        return AveDbConfig::Rocksdb {
            path: path.to_owned(),
        };
        #[cfg(feature = "sqlite")]
        return AveDbConfig::Sqlite {
            path: path.to_owned(),
        };
    }

    pub fn deserialize_db<'de, D>(
        deserializer: D,
    ) -> Result<AveDbConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path: String = String::deserialize(deserializer)?;
        #[cfg(feature = "rocksdb")]
        return Ok(AveDbConfig::Rocksdb {
            path: PathBuf::from(path),
        });
        #[cfg(feature = "sqlite")]
        return Ok(AveDbConfig::Sqlite {
            path: PathBuf::from(path),
        });
    }
}

impl fmt::Display for AveDbConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            #[cfg(feature = "rocksdb")]
            AveDbConfig::Rocksdb { .. } => write!(f, "Rocksdb"),
            #[cfg(feature = "sqlite")]
            AveDbConfig::Sqlite { .. } => write!(f, "Sqlite"),
        }
    }
}

/// Database configuration.
#[derive(Debug, Clone, Deserialize, PartialEq, Serialize)]
pub enum ExternalDbConfig {
    /// Sqlite database.
    #[cfg(feature = "ext-sqlite")]
    Sqlite {
        /// Path to the database.
        path: PathBuf,
    },
}

impl Default for ExternalDbConfig {
    fn default() -> Self {
        #[cfg(feature = "ext-sqlite")]
        return ExternalDbConfig::Sqlite {
            path: PathBuf::from("db").join("ext").join("sqlite"),
        };
    }
}

impl ExternalDbConfig {
    pub fn build(path: &PathBuf) -> Self {
        #[cfg(feature = "ext-sqlite")]
        return ExternalDbConfig::Sqlite {
            path: path.to_owned(),
        };
    }

    pub fn deserialize_db<'de, D>(
        deserializer: D,
    ) -> Result<ExternalDbConfig, D::Error>
    where
        D: Deserializer<'de>,
    {
        let path: String = String::deserialize(deserializer)?;
        #[cfg(feature = "ext-sqlite")]
        return Ok(ExternalDbConfig::Sqlite {
            path: PathBuf::from(path),
        });
    }
}

impl fmt::Display for ExternalDbConfig {
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
            LoggingRotation::Size => write!(f, "size"),
            LoggingRotation::Hourly => write!(f, "hourly"),
            LoggingRotation::Daily => write!(f, "daily"),
            LoggingRotation::Weekly => write!(f, "weekly"),
            LoggingRotation::Monthly => write!(f, "monthly"),
            LoggingRotation::Yearly => write!(f, "yearly"),
            LoggingRotation::Never => write!(f, "never"),
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
        }
    }
}

impl LoggingConfig {
    pub fn logs(&self) -> bool {
        self.output.api || self.output.file || self.output.stdout
    }
}

#[derive(Clone, Debug, Deserialize, Default, Eq, PartialEq, Serialize)]
pub struct SinkServer {
    pub server: String,
    pub events: BTreeSet<SinkTypes>,
    pub url: String,
    pub auth: bool,
}

#[derive(Default)]
pub struct SinkAuth {
    pub sink: SinkConfig,
    pub token: Option<TokenResponse>,
    pub password: String,
}

#[derive(Clone, Debug, Deserialize, Default, Serialize)]
#[serde(default)]
pub struct SinkConfig {
    pub sinks: BTreeMap<String, Vec<SinkServer>>,
    pub auth: String,
    pub username: String,
}
