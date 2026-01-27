use std::{collections::HashMap, path::PathBuf, sync::Arc};

use ave_actors::{ActorSystem, EncryptedKey, SystemRef};
use ave_common::identity::{HashAlgorithm, hash_borsh};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use wasmtime::Engine;

use crate::{
    Error,
    config::{Config, SinkAuth},
    db::Database,
    external_db::DBManager,
    helpers::{db::ExternalDB, sink::AveSink},
    model::common::contract::create_secure_wasmtime_config,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigHelper {
    pub contracts_path: PathBuf,
    pub always_accept: bool,
    pub hash_algorithm: HashAlgorithm,
    pub tracking_size: usize,
}

impl From<Config> for ConfigHelper {
    fn from(value: Config) -> Self {
        Self {
            contracts_path: value.contracts_path,
            always_accept: value.always_accept,
            hash_algorithm: value.hash_algorithm,
            tracking_size: value.tracking_size,
        }
    }
}

pub async fn system(
    config: Config,
    sink_auth: SinkAuth,
    password: &str,
    token: CancellationToken,
) -> Result<(SystemRef, JoinHandle<()>), Error> {
    // Create de actor system.
    let (system, mut runner) = ActorSystem::create(token);

    system
        .add_helper("config", ConfigHelper::from(config.clone()))
        .await;

    // Create secure Wasmtime configuration with resource limits
    let engine =
        Engine::new(&create_secure_wasmtime_config()).map_err(|e| {
            Error::System(format!("Error creating the engine: {}", e))
        })?;

    system.add_helper("engine", Arc::new(engine)).await;

    let contracts: HashMap<String, Vec<u8>> = HashMap::new();
    system
        .add_helper("contracts", Arc::new(RwLock::new(contracts)))
        .await;

    // Build database manager.
    let db = Database::open(&config.ave_db)
        .map_err(|e| Error::System(format!("Can not open DB: {}", e)))?;
    system.add_helper("store", db).await;

    // Build sink manager.
    let ave_sink = AveSink::new(
        sink_auth.sink.sinks,
        sink_auth.token,
        &sink_auth.sink.auth,
        &sink_auth.sink.username,
        &sink_auth.password,
    );
    system.add_helper("sink", ave_sink).await;

    let pass_hash =
        hash_borsh(&*config.hash_algorithm.hasher(), &password.to_string())
            .map_err(|e| {
                Error::System(format!("Can not obtain password hash: {}", e))
            })?;

    let array_hash: [u8; 32] = pass_hash.hash_array().map_err(|e| {
        Error::System(format!("Can not obtain password hash as array: {}", e))
    })?;

    // Helper memory encryption for passwords to be used in secure stores.
    let encrypted_key = EncryptedKey::new(&array_hash).map_err(|e| {
        Error::System(format!("Can not create EncryptedKey: {}", e))
    })?;

    system.add_helper("encrypted_key", encrypted_key).await;

    let db_manager_actor = system
        .create_root_actor("db_manager", DBManager)
        .await
        .map_err(|e| Error::System(e.to_string()))?;

    let ext_db =
        ExternalDB::build(config.external_db, db_manager_actor).await?;

    system.add_helper("ext_db", ext_db).await;

    let runner = tokio::spawn(async move {
        runner.run().await;
    });

    Ok((system, runner))
}

#[cfg(test)]
pub mod tests {

    use crate::config::{AveDbConfig, ExternalDbConfig};
    use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
    use network::Config as NetworkConfig;
    use tempfile::TempDir;
    use test_log::test;

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
            tempfile::tempdir().expect("Can not create temporal directory.");
        let ave_path = dir_ave_db.path().to_path_buf();
        vec_dirs.push(dir_ave_db);

        let dir_ext_db =
            tempfile::tempdir().expect("Can not create temporal directory.");
        let ext_path = dir_ext_db.path().to_path_buf();
        vec_dirs.push(dir_ext_db);

        let dir_contracts =
            tempfile::tempdir().expect("Can not create temporal directory.");
        let contracts_path = dir_contracts.path().to_path_buf();
        vec_dirs.push(dir_contracts);

        let newtork_config = NetworkConfig::new(
            network::NodeType::Bootstrap,
            vec![],
            vec![],
            vec![],
            None,
        );
        let config = Config {
            keypair_algorithm: KeyPairAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Blake3,
            ave_db: AveDbConfig::build(&ave_path),
            external_db: ExternalDbConfig::build(&ext_path),
            network: newtork_config,
            contracts_path: contracts_path,
            always_accept: false,
            tracking_size: 100,
        };

        let (sys, handlers) = system(
            config.clone(),
            SinkAuth::default(),
            "password",
            CancellationToken::new(),
        )
        .await
        .unwrap();

        (sys, handlers, vec_dirs)
    }
}
