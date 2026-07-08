use ave_common::Error;
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

impl Config {
    pub fn validate(&self) -> Result<(), Error> {
        if self.keys_path.as_os_str().is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "keys_path".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        self.logging.validate().map_err(|e| Error::InvalidConfiguration {
            component: "logging".to_string(),
            reason: e.to_string(),
        })?;
        self.auth.validate().map_err(|e| Error::InvalidConfiguration {
            component: "auth".to_string(),
            reason: e.to_string(),
        })?;
        self.http.validate().map_err(|e| Error::InvalidConfiguration {
            component: "http".to_string(),
            reason: e.to_string(),
        })?;

        for (i, sink) in self.sinks.iter().enumerate() {
            sink.validate().map_err(|e| Error::InvalidConfiguration {
                component: format!("sinks[{i}]"),
                reason: e.to_string(),
            })?;
        }

        Ok(())
    }
}
