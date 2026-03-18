pub use error::SystemError;
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{
    config::{Config, SinkAuth},
    db::Database,
    external_db::DBManager,
    helpers::{db::ExternalDB, sink::AveSink},
    model::common::contract::WasmRuntime,
};
use ave_actors::{
    ActorSystem, DbManager, EncryptedKey, MachineSpec, SystemRef,
};
use ave_common::identity::hash_borsh;
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::error;

pub mod error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigHelper {
    pub contracts_path: PathBuf,
    pub always_accept: bool,
    pub tracking_size: usize,
    pub version_sync_interval_secs: u64,
    pub version_sync_sample_size: usize,
}

impl From<Config> for ConfigHelper {
    fn from(value: Config) -> Self {
        Self {
            contracts_path: value.contracts_path,
            always_accept: value.always_accept,
            tracking_size: value.tracking_size,
            version_sync_interval_secs: value.version_sync_interval_secs,
            version_sync_sample_size: value.version_sync_sample_size,
        }
    }
}

pub async fn system(
    config: Config,
    sink_auth: SinkAuth,
    password: &str,
    graceful_token: CancellationToken,
    crash_token: CancellationToken,
) -> Result<(SystemRef, JoinHandle<()>), SystemError> {
    // Create de actor system.
    let (system, mut runner) =
        ActorSystem::create(graceful_token.clone(), crash_token.clone());

    system
        .add_helper("config", ConfigHelper::from(config.clone()))
        .await;

    // Build engine + limits together; actors fetch both via a single helper access.
    let wasm_runtime = WasmRuntime::new(config.spec.clone())
        .map_err(|e| SystemError::EngineCreation(e.to_string()))?;
    system
        .add_helper("wasm_runtime", Arc::new(wasm_runtime))
        .await;

    let contracts: HashMap<String, Vec<u8>> = HashMap::new();
    system
        .add_helper("contracts", Arc::new(RwLock::new(contracts)))
        .await;

    let actor_spec = config.spec.clone().map(MachineSpec::from);

    // Build database manager.
    let mut db = Database::open(&config.internal_db, actor_spec)
        .map_err(|e| SystemError::DatabaseOpen(e.to_string()))?;
    system.add_helper("store", db.clone()).await;

    // Build sink manager.
    let api_key = if sink_auth.api_key.is_empty() {
        None
    } else {
        Some(sink_auth.api_key.clone())
    };
    let ave_sink = AveSink::new(
        sink_auth.sink.sinks,
        sink_auth.token,
        &sink_auth.sink.auth,
        &sink_auth.sink.username,
        &sink_auth.password,
        api_key,
    );
    system.add_helper("sink", ave_sink).await;

    let pass_hash =
        hash_borsh(&*config.hash_algorithm.hasher(), &password.to_string())
            .map_err(|e| SystemError::PasswordHash(e.to_string()))?;

    let array_hash: [u8; 32] = pass_hash
        .hash_array()
        .map_err(|e| SystemError::HashArrayConversion(e.to_string()))?;

    // Helper memory encryption for passwords to be used in secure stores.
    let encrypted_key = EncryptedKey::new(&array_hash)
        .map_err(|e| SystemError::EncryptedKeyCreation(e.to_string()))?;

    system.add_helper("encrypted_key", encrypted_key).await;

    let db_manager_actor = system
        .create_root_actor("db_manager", DBManager)
        .await
        .map_err(|e| SystemError::RootActorCreation(e.to_string()))?;

    let ext_db = Arc::new(
        ExternalDB::build(
        config.external_db.db,
        config.external_db.durability,
        db_manager_actor,
        config.spec.clone(),
    )
    .await
    .map_err(|e| SystemError::ExternalDbBuild(e.to_string()))?,
    );

    system.add_helper("ext_db", Arc::clone(&ext_db)).await;

    let runner = tokio::spawn(async move {
        runner.run().await;
        if let Err(e) = ext_db.shutdown().await {
            error!(error = %e, "Failed to stop external db");
        };
        if let Err(e) = db.stop() {
            error!(error = %e, "Failed to stop db");
        };
    });

    Ok((system, runner))
}

#[cfg(test)]
pub mod tests {

    use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
    use network::Config as NetworkConfig;
    use tempfile::TempDir;
    use test_log::test;

    use crate::config::{
        AveExternalDBConfig, AveExternalDBFeatureConfig, AveInternalDBConfig,
        AveInternalDBFeatureConfig,
    };

    use super::*;

    #[derive(Debug, Clone)]
    pub struct Dummy;

    #[test(tokio::test)]
    async fn test_system() {
        let (system, _runner, _dirs) = create_system().await;
        let db: Option<Database> = system.get_helper("store").await;
        assert!(db.is_some());
        let ep: Option<EncryptedKey> = system.get_helper("encrypted_key").await;
        assert!(ep.is_some());
        let any: Option<Dummy> = system.get_helper("dummy").await;
        assert!(any.is_none());
    }

    pub async fn create_system() -> (SystemRef, JoinHandle<()>, Vec<TempDir>) {
        let mut vec_dirs = vec![];

        let dir_ave_db =
            tempfile::tempdir().expect("Can not create temporal directory");
        let ave_path = dir_ave_db.path().to_path_buf();
        vec_dirs.push(dir_ave_db);

        let dir_ext_db =
            tempfile::tempdir().expect("Can not create temporal directory");
        let ext_path = dir_ext_db.path().to_path_buf();
        vec_dirs.push(dir_ext_db);

        let dir_contracts =
            tempfile::tempdir().expect("Can not create temporal directory");
        let contracts_path = dir_contracts.path().to_path_buf();
        vec_dirs.push(dir_contracts);

        let newtork_config = NetworkConfig::new(
            network::NodeType::Bootstrap,
            vec![],
            vec![],
            vec![],
        );
        let config = Config {
            keypair_algorithm: KeyPairAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Blake3,
            internal_db: AveInternalDBConfig {
                db: AveInternalDBFeatureConfig::build(&ave_path),
                ..Default::default()
            },
            external_db: AveExternalDBConfig {
                db: AveExternalDBFeatureConfig::build(&ext_path),
                ..Default::default()
            },
            network: newtork_config,
            contracts_path: contracts_path,
            always_accept: false,
            tracking_size: 100,
            is_service: true,
            version_sync_interval_secs: 60,
            version_sync_sample_size: 3,
            spec: None,
        };

        let (sys, handlers) = system(
            config.clone(),
            SinkAuth::default(),
            "password",
            CancellationToken::new(),
            CancellationToken::new(),
        )
        .await
        .unwrap();

        (sys, handlers, vec_dirs)
    }
}
