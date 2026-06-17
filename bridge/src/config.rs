use ave_core::config::{Config as AveConfig, LoggingConfig, SinkConfigEntry};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

use crate::{auth::AuthConfig, http::HttpConfig};

#[derive(Deserialize, Serialize, Debug, Clone)]
#[serde(default)]
pub struct Config {
    /// Settings from Ave Base.
    pub node: AveConfig,
    /// Path for encrypted keys.
    pub keys_path: PathBuf,
    /// Logging parameters.
    pub logging: LoggingConfig,
    /// Sink configuration entries: each entry pairs a target (governance or a
    /// schema, optionally scoped to a governance) with the servers that
    /// deliver events for that target.
    pub sinks: Vec<SinkConfigEntry>,
    /// Authentication configuration.
    pub auth: AuthConfig,
    /// HTTP server configuration.
    pub http: HttpConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            node: Default::default(),
            keys_path: PathBuf::from("keys"),
            logging: Default::default(),
            sinks: Vec::new(),
            auth: Default::default(),
            http: Default::default(),
        }
    }
}
