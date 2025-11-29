//! Configuration wrapper types for OpenAPI documentation
//!
//! These types wrap the core configuration types to provide Serialize and ToSchema support

use serde::Serialize;
use utoipa::ToSchema;
use std::collections::BTreeMap;

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct ConfigHttp {
    pub ave_config: AveConfigHttp,
    pub keys_path: String,
    pub prometheus: String,
    pub logging: LoggingHttp,
    pub sink: SinkConfigHttp,
}

impl From<bridge::config::Config> for ConfigHttp {
    fn from(value: bridge::config::Config) -> Self {
        Self {
            ave_config: AveConfigHttp::from(value.ave_config),
            keys_path: value.keys_path,
            prometheus: value.prometheus,
            logging: LoggingHttp::from(value.logging),
            sink: SinkConfigHttp::from(value.sink),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct AveConfigHttp {
    pub keypair_algorithm: String,
    pub hash_algorithm: String,
    pub ave_db: String,
    pub external_db: String,
    pub network: NetworkConfigHttp,
    pub contracts_dir: String,
    pub always_accept: bool,
    pub garbage_collector: u64,
}

impl From<bridge::AveConfig> for AveConfigHttp {
    fn from(value: bridge::AveConfig) -> Self {
        Self {
            keypair_algorithm: format!("{:?}", value.keypair_algorithm),
            hash_algorithm: format!("{:?}", value.hash_algorithm),
            ave_db: value.ave_db.to_string(),
            external_db: value.external_db.to_string(),
            network: NetworkConfigHttp::from(value.network),
            contracts_dir: value.contracts_dir,
            always_accept: value.always_accept,
            garbage_collector: value.garbage_collector.as_secs(),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct NetworkConfigHttp {
    /// Debug representation of network configuration
    pub config: String,
}

impl From<bridge::NetworkConfig> for NetworkConfigHttp {
    fn from(value: bridge::NetworkConfig) -> Self {
        Self {
            config: format!("{:?}", value),
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct LoggingHttp {
    pub output: LoggingOutputHttp,
    pub api_url: Option<String>,
    pub file_path: String,
    pub rotation: String,
    pub max_size: usize,
    pub max_files: usize,
}

impl From<bridge::Logging> for LoggingHttp {
    fn from(value: bridge::Logging) -> Self {
        Self {
            output: LoggingOutputHttp::from(value.output),
            api_url: value.api_url,
            file_path: value.file_path,
            rotation: format!("{:?}", value.rotation),
            max_size: value.max_size,
            max_files: value.max_files,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct LoggingOutputHttp {
    pub stdout: bool,
    pub file: bool,
    pub api: bool,
}

impl From<bridge::LoggingOutput> for LoggingOutputHttp {
    fn from(value: bridge::LoggingOutput) -> Self {
        Self {
            stdout: value.stdout,
            file: value.file,
            api: value.api,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct SinkConfigHttp {
    pub sinks: BTreeMap<String, Vec<SinkServerHttp>>,
    pub auth: String,
    pub username: String,
}

impl From<bridge::SinkConfig> for SinkConfigHttp {
    fn from(value: bridge::SinkConfig) -> Self {
        Self {
            sinks: value.sinks.into_iter()
                .map(|(k, v)| (k, v.into_iter().map(SinkServerHttp::from).collect()))
                .collect(),
            auth: value.auth,
            username: value.username,
        }
    }
}

#[derive(Debug, Serialize, Clone, ToSchema)]
pub struct SinkServerHttp {
    pub server: String,
    pub events: Vec<String>,
    pub url: String,
    pub auth: bool,
}

impl From<bridge::SinkServer> for SinkServerHttp {
    fn from(value: bridge::SinkServer) -> Self {
        Self {
            server: value.server,
            events: value.events.into_iter().map(|e| format!("{:?}", e)).collect(),
            url: value.url,
            auth: value.auth,
        }
    }
}
