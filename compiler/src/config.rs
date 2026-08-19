//! Compiler service configuration (file-based, `config` crate + serde).

use std::path::PathBuf;

use serde::Deserialize;

use crate::service::ServiceError;

/// Default listen address of the compiler gRPC service.
fn default_listen_addr() -> String {
    "127.0.0.1:50051".to_owned()
}

/// Default maximum source payload accepted per compile request (1 MiB).
fn default_max_source_bytes() -> usize {
    1024 * 1024
}

/// Default artifact store size cap (1 GiB).
fn default_max_store_bytes() -> u64 {
    1024 * 1024 * 1024
}

/// Default bound for builds waiting on a semaphore slot.
fn default_max_queued_builds() -> usize {
    64
}

fn default_artifacts_dir() -> PathBuf {
    PathBuf::from("compiler-artifacts")
}

fn default_work_dir() -> PathBuf {
    PathBuf::from("compiler-work")
}

fn default_key_path() -> PathBuf {
    PathBuf::from("compiler-key.der")
}

/// TLS material of the compiler service. When absent the service listens
/// in plain HTTP/2 (acceptable on trusted local networks; API key auth is
/// always required regardless).
#[derive(Debug, Clone, Deserialize)]
pub struct TlsConfig {
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
}

/// Configuration of the compiler service.
#[derive(Debug, Clone, Deserialize)]
#[serde(default)]
pub struct ServiceConfig {
    /// Address the gRPC server binds to (host:port).
    pub listen_addr: String,
    /// Optional TLS; plain HTTP/2 when absent.
    pub tls: Option<TlsConfig>,
    /// Accepted API keys (request metadata `x-api-key`). Never empty in a
    /// valid configuration; several keys allow rotation without downtime.
    pub api_keys: Vec<String>,
    /// Maximum concurrent cargo builds. Defaults to available parallelism.
    pub max_concurrent_builds: Option<usize>,
    /// Maximum accepted `source_b64` length in bytes.
    pub max_source_bytes: usize,
    /// Directory of the content-addressed wasm artifact store.
    pub artifacts_dir: PathBuf,
    /// Total size cap of the artifact store; least recently used entries
    /// are collected after each insert.
    pub max_store_bytes: u64,
    /// Scratch directory for builds (`<work_dir>/contracts/<key>`; a
    /// `<work_dir>/vendor` directory, when present, enables offline builds
    /// against vendored sources).
    pub work_dir: PathBuf,
    /// Ed25519 identity (PKCS#8 DER) used to sign attestations; generated
    /// and persisted on first start.
    pub key_path: PathBuf,
    /// Maximum builds waiting for a build slot before the service applies
    /// backpressure with RESOURCE_EXHAUSTED.
    pub max_queued_builds: usize,
}

impl Default for ServiceConfig {
    fn default() -> Self {
        Self {
            listen_addr: default_listen_addr(),
            tls: None,
            api_keys: Vec::new(),
            max_concurrent_builds: None,
            max_source_bytes: default_max_source_bytes(),
            artifacts_dir: default_artifacts_dir(),
            max_store_bytes: default_max_store_bytes(),
            work_dir: default_work_dir(),
            key_path: default_key_path(),
            max_queued_builds: default_max_queued_builds(),
        }
    }
}

impl ServiceConfig {
    /// Loads the service configuration from a file (json, yaml or toml,
    /// detected by extension), falling back to defaults for absent keys.
    pub fn load(file: &str) -> Result<Self, ServiceError> {
        let config = config::Config::builder()
            .add_source(config::File::with_name(file))
            .build()
            .map_err(|e| {
                ServiceError::Config(format!(
                    "failed to build configuration from '{file}': {e}"
                ))
            })?;

        config.try_deserialize().map_err(|e| {
            ServiceError::Config(format!(
                "failed to deserialize configuration from '{file}': {e}"
            ))
        })
    }

    /// Validates the configuration: API keys are mandatory and limits must
    /// be non-zero.
    pub fn validate(&self) -> Result<(), ServiceError> {
        if self.api_keys.is_empty() {
            return Err(ServiceError::Config(
                "at least one API key is required".to_owned(),
            ));
        }
        if self.api_keys.iter().any(|key| key.is_empty()) {
            return Err(ServiceError::Config(
                "API keys must not be empty".to_owned(),
            ));
        }
        if self.max_concurrent_builds == Some(0) {
            return Err(ServiceError::Config(
                "max_concurrent_builds must be greater than zero".to_owned(),
            ));
        }
        if self.max_source_bytes == 0 {
            return Err(ServiceError::Config(
                "max_source_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_store_bytes == 0 {
            return Err(ServiceError::Config(
                "max_store_bytes must be greater than zero".to_owned(),
            ));
        }
        if self.max_queued_builds == 0 {
            return Err(ServiceError::Config(
                "max_queued_builds must be greater than zero".to_owned(),
            ));
        }
        Ok(())
    }

    /// Effective number of concurrent builds: the configured value or the
    /// available parallelism of the machine.
    pub fn concurrent_builds(&self) -> usize {
        self.max_concurrent_builds.unwrap_or_else(|| {
            std::thread::available_parallelism()
                .map(std::num::NonZero::get)
                .unwrap_or(1)
        })
    }
}
