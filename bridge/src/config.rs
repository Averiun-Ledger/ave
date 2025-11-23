use core::config::{Config as AveConfig, Logging, SinkConfig};
use serde::Deserialize;

#[derive(Deserialize, Debug, Clone)]
pub struct Config {
    /// Settings from Ave Base.
    pub ave_config: AveConfig,
    /// Path for encryptep keys.
    pub keys_path: String,
    /// TcpListener from prometheus axum server.
    pub prometheus: String,
    /// Logging parameters.
    pub logging: Logging,
    /// Sink parameters.
    pub sink: SinkConfig,
}

impl Config {
    pub fn add_path(&mut self, path: &str) {
        self.keys_path = format!("{}/{}", path, self.keys_path);
        self.ave_config.add_path(path);
    }
}
