use ave_core::config::{Config as AveConfig, LoggingConfig, SinkConfig};
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
    /// Sink parameters.
    pub sink: SinkConfig,
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
            sink: Default::default(),
            auth: Default::default(),
            http: Default::default(),
        }
    }
}
