pub use error::SystemError;
#[cfg(feature = "test")]
use std::time::Duration;
use std::{collections::HashMap, path::PathBuf, sync::Arc};

use crate::{
    config::{
        Config, GovernanceSyncConfig, RebootSyncConfig, SinkConfigEntry,
        TrackerSyncConfig, UpdateSyncConfig,
    },
    db::Database,
    external_db::DBManager,
    helpers::db::ExternalDB,
};
use ave_actors::{
    ActorSystem, DbManager, EncryptedKey, MachineSpec, SystemRef,
};
use ave_common::identity::hash_borsh;
#[cfg(feature = "prometheus")]
use ave_contract_sdk::runtime::ContractMetrics;
use ave_contract_sdk::runtime::{CompiledModule, ContractRuntime};
use serde::{Deserialize, Serialize};
use tokio::{sync::RwLock, task::JoinHandle};
use tokio_util::sync::CancellationToken;
use tracing::error;

#[cfg(feature = "prometheus")]
use prometheus_client::registry::Registry;

pub mod error;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConfigHelper {
    pub contracts_path: PathBuf,
    pub always_accept: bool,
    pub safe_mode: bool,
    pub tracking_size: usize,
    pub only_clear_events: bool,
    pub ledger_batch_size: usize,
    pub sync_governance: GovernanceSyncConfig,
    pub sync_tracker: TrackerSyncConfig,
    pub sync_update: UpdateSyncConfig,
    pub sync_reboot: RebootSyncConfig,
    /// Sink configuration entries read from the bridge configuration. Each
    /// entry pairs a [`SinkTarget`] with the list of servers that deliver
    /// events for that target.
    pub sinks: Vec<SinkConfigEntry>,
}

impl ConfigHelper {
    pub fn from_config(config: Config, sinks: Vec<SinkConfigEntry>) -> Self {
        Self {
            contracts_path: config.contracts_path,
            always_accept: config.always_accept,
            safe_mode: config.safe_mode,
            tracking_size: config.tracking_size,
            only_clear_events: config.only_clear_events,
            ledger_batch_size: config.sync.ledger_batch_size,
            sync_governance: config.sync.governance,
            sync_tracker: config.sync.tracker,
            sync_update: config.sync.update,
            sync_reboot: config.sync.reboot,
            sinks,
        }
    }
}

pub async fn system(
    config: Config,
    sinks: Vec<SinkConfigEntry>,
    password: &str,
    graceful_token: CancellationToken,
    crash_token: CancellationToken,
    #[cfg(feature = "prometheus")] mut registry: Option<&mut Registry>,
) -> Result<(SystemRef, JoinHandle<()>), SystemError> {
    // Test builds get the embedded test compiler automatically when no
    // compiler pool is configured, so any crate driving core with the
    // `test` feature compiles contracts without extra wiring. An
    // explicitly configured pool always wins: failure-path tests point
    // at dead endpoints on purpose.
    #[cfg(feature = "test")]
    let config = if config.compiler.endpoints.is_empty() {
        Config {
            compiler: crate::test_compiler::test_compiler_config().await,
            ..config
        }
    } else {
        config
    };

    // Create de actor system.
    // `system` is only mutated when the prometheus or test features add
    // helpers to it, hence the conditional allow.
    #[cfg_attr(
        not(any(feature = "test", feature = "prometheus")),
        allow(unused_mut)
    )]
    let (mut system, mut runner) =
        ActorSystem::create(graceful_token.clone(), crash_token.clone());

    #[cfg(feature = "prometheus")]
    if let Some(registry) = registry.as_mut() {
        ave_actors::prometheus::register(registry, &mut system);
    }

    let config_helper = ConfigHelper::from_config(config.clone(), sinks);
    system.add_helper("config", config_helper);

    #[cfg(feature = "prometheus")]
    let contract_metrics = registry.map(|registry| {
        let metrics = Arc::new(ContractMetrics::new());
        metrics.register_into(registry);
        metrics
    });

    // Build engine + limits together via the SDK runtime.
    let resolved = crate::config::resolve_spec(config.spec.as_ref());
    let contract_runtime = ContractRuntime::with_metrics(
        Some(ave_contract_sdk::runtime::ResolvedMachineSpec {
            ram_mb: resolved.ram_mb,
            cpu_cores: resolved.cpu_cores,
        }),
        #[cfg(feature = "prometheus")]
        contract_metrics,
        #[cfg(not(feature = "prometheus"))]
        None,
    )
    .map_err(|e| SystemError::EngineCreation(e.to_string()))?;
    system.add_helper("contract_runtime", Arc::new(contract_runtime));

    let contracts: HashMap<String, Arc<CompiledModule>> = HashMap::new();
    system.add_helper("contracts", Arc::new(RwLock::new(contracts)));

    // The node never compiles contracts remotely in production: the
    // gRPC compiler client is a TEST-BUILD helper (embedded pool or
    // explicit endpoints, e.g. dead ones for failure-path tests).
    // Production nodes compile in-process (`toolchain` feature); a
    // node built without it answers `CompilersUnavailable`.
    #[cfg(feature = "test")]
    if !config.compiler.endpoints.is_empty() {
        let expected_toolchain = config
            .compiler
            .expected_toolchain
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| {
                SystemError::CompilerConfig(format!(
                    "invalid expected_toolchain: {e}"
                ))
            })?;
        let compiler_public_key = config
            .compiler
            .compiler_public_key
            .as_deref()
            .map(str::parse)
            .transpose()
            .map_err(|e| {
                SystemError::CompilerConfig(format!(
                    "invalid compiler_public_key: {e}"
                ))
            })?;
        let compiler_client =
            crate::compilation::client::CompilerClient::new(
                config.compiler.endpoints.clone(),
                config.compiler.api_key.clone().unwrap_or_default(),
                expected_toolchain,
                compiler_public_key,
                Some(Duration::from_secs(
                    config.compiler.request_timeout_secs,
                )),
                config.compiler.pinned_cert_pem.clone(),
            );
        system.add_helper("compiler_client", Arc::new(compiler_client));
    }

    let actor_spec = config.spec.clone().map(MachineSpec::from);

    // Build database manager.
    let db = Arc::new(
        Database::open(&config.internal_db, actor_spec)
            .map_err(|e| SystemError::DatabaseOpen(e.to_string()))?,
    );
    system.add_helper("store", db.clone());

    let pass_hash =
        hash_borsh(&*config.hash_algorithm.hasher(), &password.to_string())
            .map_err(|e| SystemError::PasswordHash(e.to_string()))?;

    let array_hash: [u8; 32] = pass_hash
        .hash_array()
        .map_err(|e| SystemError::HashArrayConversion(e.to_string()))?;

    // Helper memory encryption for passwords to be used in secure stores.
    let encrypted_key = EncryptedKey::new(&array_hash)
        .map_err(|e| SystemError::EncryptedKeyCreation(e.to_string()))?;

    system.add_helper("encrypted_key", encrypted_key);

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

    system.add_helper("ext_db", Arc::clone(&ext_db));

    let system_shutdown = system.clone();
    let runner = tokio::spawn(async move {
        runner.run().await;
        if let Err(e) = ext_db.shutdown().await {
            error!(error = %e, "Failed to stop external db");
        };

        // Remove the helper so the shared Arc<Database> reference is dropped
        // before we try to take ownership of the local one.
        if let Some(helper) =
            system_shutdown.remove_helper::<Arc<Database>>("store")
        {
            drop(helper);
        }

        match Arc::try_unwrap(db) {
            Ok(db) => {
                if let Err(e) = db.stop() {
                    error!(error = %e, "Failed to stop db");
                }
            }
            Err(_) => {
                error!(
                    "Database still referenced at shutdown; file lock may persist"
                );
            }
        }
    });

    Ok((system, runner))
}

#[cfg(test)]
pub mod tests {

    use std::{
        env, process,
        sync::atomic::{AtomicU64, Ordering},
    };

    use ave_common::identity::{HashAlgorithm, KeyPairAlgorithm};
    use ave_network::Config as NetworkConfig;
    use tempfile::TempDir;
    use test_log::test;

    use crate::config::{
        AveExternalDBConfig, AveExternalDBFeatureConfig, AveInternalDBConfig,
        AveInternalDBFeatureConfig, SyncConfig,
    };

    use super::*;

    static CONTRACTS_COUNTER: AtomicU64 = AtomicU64::new(0);

    fn create_contracts_temp_dir() -> TempDir {
        tempfile::Builder::new()
            .prefix(&format!(
                "ave-test-contracts-{}-{}-",
                process::id(),
                CONTRACTS_COUNTER.fetch_add(1, Ordering::SeqCst)
            ))
            .tempdir_in(env::temp_dir())
            .expect("Can not create temporal directory")
    }

    #[derive(Debug, Clone)]
    pub struct Dummy;

    #[test(tokio::test)]
    async fn test_system() {
        let (system, _runner, _dirs) = create_system().await;
        let db: Option<Arc<Database>> = system.get_helper("store");
        assert!(db.is_some());
        let ep: Option<EncryptedKey> = system.get_helper("encrypted_key");
        assert!(ep.is_some());
        let any: Option<Dummy> = system.get_helper("dummy");
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

        let dir_contracts = create_contracts_temp_dir();
        let contracts_path = dir_contracts.path().to_path_buf();
        vec_dirs.push(dir_contracts);

        let newtork_config = NetworkConfig::new(
            ave_network::NodeType::Bootstrap,
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
            contracts_path,
            always_accept: false,
            tracking_size: 100,
            safe_mode: false,
            is_service: true,
            only_clear_events: false,
            sync: SyncConfig {
                governance: GovernanceSyncConfig {
                    interval_secs: 60,
                    sample_size: 3,
                    response_timeout_secs: 30,
                },
                tracker: TrackerSyncConfig {
                    interval_secs: 60,
                    page_size: 200,
                    response_timeout_secs: 10,
                    update_batch_size: 2,
                    update_timeout_secs: 10,
                },
                update: UpdateSyncConfig::default(),
                reboot: RebootSyncConfig::default(),
                ledger_batch_size: 100,
            },
            spec: None,
            #[cfg(feature = "test")]
            compiler: Default::default(),
        };

        #[cfg(feature = "prometheus")]
        let mut registry = Registry::default();

        let (sys, handlers) = system(
            config.clone(),
            Vec::new(),
            "password",
            CancellationToken::new(),
            CancellationToken::new(),
            #[cfg(feature = "prometheus")]
            Some(&mut registry),
        )
        .await
        .unwrap();

        (sys, handlers, vec_dirs)
    }
}
