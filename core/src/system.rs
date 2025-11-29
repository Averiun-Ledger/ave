use ave_common::identity::hash_borsh;
use ave_actors::{ActorSystem, EncryptedKey, PersistentActor, SystemRef};
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::{
    Error, HASH_ALGORITHM, AveBaseConfig,
    config::SinkAuth,
    db::Database,
    external_db::DBManager,
    helpers::{db::ExternalDB, sink::AveSink},
};

pub async fn system(
    config: AveBaseConfig,
    sink_auth: SinkAuth,
    password: &str,
    token: CancellationToken,
) -> Result<(SystemRef, JoinHandle<()>), Error> {
    // Update statics.
    if let Ok(mut derivator) = HASH_ALGORITHM.lock() {
        *derivator = config.hash_algorithm;
    }

    // Create de actor system.
    let (system, mut runner) = ActorSystem::create(token);

    system.add_helper("config", config.clone()).await;

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

    let pass_hash = hash_borsh(&*config.hash_algorithm.hasher(), &password.to_string()).map_err(|e| {
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
        .create_root_actor("db_manager", DBManager::initial(config.garbage_collector))
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

    use crate::config::{ExternalDbConfig, AveDbConfig};
    use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
    use network::Config as NetworkConfig;
    use std::{fs, time::Duration};
    use test_log::test;

    use super::*;

    #[derive(Debug, Clone)]
    pub struct Dummy;

    #[test(tokio::test)]
    async fn test_system() {
        let (system, _runner) = create_system().await;
        let db: Option<Database> = system.get_helper("store").await;
        assert!(db.is_some());
        let ep: Option<EncryptedKey> =
            system.get_helper("encrypted_key").await;
        assert!(ep.is_some());
        let any: Option<Dummy> = system.get_helper("dummy").await;
        assert!(any.is_none());
    }

    pub fn create_temp_dir() -> String {
        let path = temp_dir();

        if fs::metadata(&path).is_err() {
            fs::create_dir_all(&path).unwrap();
        }
        path
    }

    fn temp_dir() -> String {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory.");
        dir.path().to_str().unwrap().to_owned()
    }

    pub async fn create_system() -> (SystemRef, JoinHandle<()>) {
        let dir =
            tempfile::tempdir().expect("Can not create temporal directory.");
        let path = dir.path().to_str().unwrap();

        let newtork_config = NetworkConfig::new(
            network::NodeType::Bootstrap,
            vec![],
            vec![],
            vec![],
        );
        let config = AveBaseConfig {
            keypair_algorithm: KeyPairAlgorithm::Ed25519,
            hash_algorithm: HashAlgorithm::Blake3,
            ave_db: AveDbConfig::build(path),
            external_db: ExternalDbConfig::build(&create_temp_dir()),
            network: newtork_config,
            contracts_dir: create_temp_dir(),
            always_accept: false,
            garbage_collector: Duration::from_secs(500),
        };

        let sys = system(
            config.clone(),
            SinkAuth::default(),
            "password",
            CancellationToken::new(),
        )
        .await
        .unwrap();
        sys
    }
}
