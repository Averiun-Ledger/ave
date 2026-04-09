use std::{
    collections::{HashMap, HashSet},
    hash::{DefaultHasher, Hash as StdHash, Hasher},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Instant,
};
#[cfg(feature = "test")]
use std::env;
#[cfg(feature = "test")]
use std::io::ErrorKind;

use ave_actors::{Actor, ActorContext, ActorError, ActorPath, Response};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{fs, process::Command, sync::RwLock};
#[cfg(feature = "test")]
use tokio::time::{Duration, sleep};
use tracing::debug;
use wasmtime::{ExternType, Module, Store};

use crate::model::common::contract::{
    MAX_FUEL_COMPILATION, MemoryManager, WasmLimits, WasmRuntime,
    generate_linker,
};
use crate::{
    governance::contract_register::{
        ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
    },
    metrics::try_core_metrics,
};

pub mod contract_compiler;
pub mod error;
pub mod temp_compiler;

pub use contract_compiler::{ContractCompiler, ContractCompilerMessage};
pub use temp_compiler::{TempCompiler, TempCompilerMessage};

use error::*;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone,
)]
pub struct ContractResult {
    pub success: bool,
    pub error: String,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct ContractArtifactRecord {
    pub contract_hash: DigestIdentifier,
    pub manifest_hash: DigestIdentifier,
    pub wasm_hash: DigestIdentifier,
    pub cwasm_hash: DigestIdentifier,
    pub engine_fingerprint: DigestIdentifier,
    pub toolchain_fingerprint: DigestIdentifier,
}

#[derive(Debug, Clone)]
pub enum CompilerResponse {
    Ok,
    Error(CompilerError),
}

impl Response for CompilerResponse {}

struct CompilerSupport;

impl CompilerSupport {
    const SHARED_TARGET_DIR: &'static str = "target";
    const VENDOR_DIR: &'static str = "vendor";
    const ARTIFACT_WASM: &'static str = "contract.wasm";
    const ARTIFACT_PRECOMPILED: &'static str = "contract.cwasm";
    const LEGACY_ARTIFACT_METADATA: &'static str = "contract.json";
    #[cfg(feature = "test")]
    const GLOBAL_CACHE_DIR: &'static str = "ave-contract-artifacts";
    #[cfg(feature = "test")]
    const GLOBAL_CACHE_METADATA: &'static str = "metadata.borsh";

    fn observe_contract_prepare(
        kind: &'static str,
        result: &'static str,
        started_at: Instant,
    ) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_contract_prepare(
                kind,
                result,
                started_at.elapsed(),
            );
        }
    }

    fn compilation_toml() -> String {
        include_str!("contract_Cargo.toml").to_owned()
    }

    fn contracts_root(contract_path: &Path) -> Result<PathBuf, CompilerError> {
        contract_path
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .ok_or_else(|| CompilerError::InvalidContractPath {
                path: contract_path.to_string_lossy().to_string(),
                details:
                    "expected contract path under <contracts_path>/contracts/<name>"
                        .to_owned(),
            })
    }

    #[cfg(feature = "test")]
    fn artifact_wasm_path_in(base_path: &Path) -> PathBuf {
        base_path.join(Self::ARTIFACT_WASM)
    }

    fn artifact_wasm_path(contract_path: &Path) -> PathBuf {
        contract_path.join(Self::ARTIFACT_WASM)
    }

    #[cfg(feature = "test")]
    fn artifact_precompiled_path_in(base_path: &Path) -> PathBuf {
        base_path.join(Self::ARTIFACT_PRECOMPILED)
    }

    fn artifact_precompiled_path(contract_path: &Path) -> PathBuf {
        contract_path.join(Self::ARTIFACT_PRECOMPILED)
    }

    fn legacy_artifact_metadata_path(contract_path: &Path) -> PathBuf {
        contract_path.join(Self::LEGACY_ARTIFACT_METADATA)
    }

    #[cfg(feature = "test")]
    fn global_cache_root() -> PathBuf {
        env::temp_dir().join(Self::GLOBAL_CACHE_DIR)
    }

    #[cfg(feature = "test")]
    fn global_cache_entry_dir(
        contract_hash: &DigestIdentifier,
        manifest_hash: &DigestIdentifier,
        engine_fingerprint: &DigestIdentifier,
        toolchain_fingerprint: &DigestIdentifier,
    ) -> PathBuf {
        Self::global_cache_root().join(format!(
            "{contract_hash}_{manifest_hash}_{engine_fingerprint}_{toolchain_fingerprint}"
        ))
    }

    #[cfg(feature = "test")]
    fn global_cache_metadata_path(cache_dir: &Path) -> PathBuf {
        cache_dir.join(Self::GLOBAL_CACHE_METADATA)
    }

    #[cfg(feature = "test")]
    fn global_cache_lock_path(cache_dir: &Path) -> PathBuf {
        cache_dir.with_extension("lock")
    }

    fn cargo_config_path(contract_path: &Path) -> PathBuf {
        contract_path.join(".cargo").join("config.toml")
    }

    fn build_output_wasm_path(contracts_root: &Path) -> PathBuf {
        contracts_root
            .join(Self::SHARED_TARGET_DIR)
            .join("wasm32-unknown-unknown")
            .join("release")
            .join(Self::ARTIFACT_WASM)
    }

    fn cargo_config(
        shared_target_dir: &Path,
        vendor_dir: Option<&Path>,
    ) -> String {
        let mut config = format!(
            "[build]\ntarget-dir = \"{}\"\n",
            shared_target_dir.to_string_lossy()
        );

        if let Some(vendor_dir) = vendor_dir {
            config.push_str(&format!(
                "\n[net]\noffline = true\n\n[source.crates-io]\nreplace-with = \"vendored-sources\"\n\n[source.vendored-sources]\ndirectory = \"{}\"\n",
                vendor_dir.to_string_lossy()
            ));
        }

        config
    }

    async fn build_contract(
        contract_path: &Path,
        offline: bool,
    ) -> Result<(), CompilerError> {
        let cargo = contract_path.join("Cargo.toml");
        let cargo_config = Self::cargo_config_path(contract_path);
        let mut command = Command::new("cargo");
        command
            .arg("build")
            .arg(format!("--manifest-path={}", cargo.to_string_lossy()))
            .arg("--target")
            .arg("wasm32-unknown-unknown")
            .arg("--release")
            .env("CARGO_HOME", contract_path.join(".cargo"))
            .env("CARGO_CONFIG", &cargo_config)
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        if offline {
            command.arg("--offline");
        }

        let status = command.status().await.map_err(|e| {
            CompilerError::CargoBuildFailed {
                details: e.to_string(),
            }
        })?;

        if !status.success() {
            return Err(CompilerError::CompilationFailed);
        }

        Ok(())
    }

    async fn prepare_contract_project(
        contract: &str,
        contract_path: &Path,
    ) -> Result<(), CompilerError> {
        let decode_base64 = BASE64_STANDARD.decode(contract).map_err(|e| {
            CompilerError::Base64DecodeFailed {
                details: format!(
                    "{} (path: {})",
                    e,
                    contract_path.to_string_lossy()
                ),
            }
        })?;

        let contracts_root = Self::contracts_root(contract_path)?;
        let dir = contract_path.join("src");
        if !Path::new(&dir).exists() {
            fs::create_dir_all(&dir).await.map_err(|e| {
                CompilerError::DirectoryCreationFailed {
                    path: dir.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;
        }

        let cargo_config_dir = contract_path.join(".cargo");
        if !Path::new(&cargo_config_dir).exists() {
            fs::create_dir_all(&cargo_config_dir).await.map_err(|e| {
                CompilerError::DirectoryCreationFailed {
                    path: cargo_config_dir.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;
        }

        let toml = Self::compilation_toml();
        let cargo = contract_path.join("Cargo.toml");
        fs::write(&cargo, toml).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: cargo.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let lib_rs = contract_path.join("src").join("lib.rs");
        fs::write(&lib_rs, decode_base64).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: lib_rs.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let vendor_dir = contracts_root.join(Self::VENDOR_DIR);
        let cargo_config = Self::cargo_config(
            &contracts_root.join(Self::SHARED_TARGET_DIR),
            vendor_dir.exists().then_some(vendor_dir.as_path()),
        );
        let cargo_config_path = Self::cargo_config_path(contract_path);
        fs::write(&cargo_config_path, cargo_config)
            .await
            .map_err(|e| CompilerError::FileWriteFailed {
                path: cargo_config_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })?;

        Ok(())
    }

    async fn load_artifact_wasm(
        contract_path: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let wasm_path = Self::artifact_wasm_path(contract_path);
        fs::read(&wasm_path)
            .await
            .map_err(|e| CompilerError::FileReadFailed {
                path: wasm_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })
    }

    #[cfg(feature = "test")]
    async fn load_artifact_wasm_from(
        base_path: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let wasm_path = Self::artifact_wasm_path_in(base_path);
        fs::read(&wasm_path)
            .await
            .map_err(|e| CompilerError::FileReadFailed {
                path: wasm_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })
    }

    async fn load_artifact_precompiled(
        contract_path: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let precompiled_path = Self::artifact_precompiled_path(contract_path);
        fs::read(&precompiled_path).await.map_err(|e| {
            CompilerError::FileReadFailed {
                path: precompiled_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })
    }

    #[cfg(feature = "test")]
    async fn load_artifact_precompiled_from(
        base_path: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let precompiled_path = Self::artifact_precompiled_path_in(base_path);
        fs::read(&precompiled_path).await.map_err(|e| {
            CompilerError::FileReadFailed {
                path: precompiled_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })
    }

    async fn load_compiled_wasm(
        contracts_root: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let wasm_path = Self::build_output_wasm_path(contracts_root);
        fs::read(&wasm_path)
            .await
            .map_err(|e| CompilerError::FileReadFailed {
                path: wasm_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })
    }

    async fn persist_artifact(
        contract_path: &Path,
        wasm_bytes: &[u8],
        precompiled_bytes: &[u8],
    ) -> Result<(), CompilerError> {
        let artifact_path = Self::artifact_wasm_path(contract_path);
        fs::write(&artifact_path, wasm_bytes).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: artifact_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let precompiled_path = Self::artifact_precompiled_path(contract_path);
        fs::write(&precompiled_path, precompiled_bytes)
            .await
            .map_err(|e| CompilerError::FileWriteFailed {
                path: precompiled_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })?;

        let legacy_metadata_path =
            Self::legacy_artifact_metadata_path(contract_path);
        let _ = fs::remove_file(&legacy_metadata_path).await;

        Ok(())
    }

    #[cfg(feature = "test")]
    async fn persist_global_cache_artifact(
        cache_dir: &Path,
        metadata: &ContractArtifactRecord,
        wasm_bytes: &[u8],
        precompiled_bytes: &[u8],
    ) -> Result<(), CompilerError> {
        fs::create_dir_all(cache_dir).await.map_err(|e| {
            CompilerError::DirectoryCreationFailed {
                path: cache_dir.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let artifact_path = Self::artifact_wasm_path_in(cache_dir);
        fs::write(&artifact_path, wasm_bytes).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: artifact_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let precompiled_path = Self::artifact_precompiled_path_in(cache_dir);
        fs::write(&precompiled_path, precompiled_bytes)
            .await
            .map_err(|e| CompilerError::FileWriteFailed {
                path: precompiled_path.to_string_lossy().to_string(),
                details: e.to_string(),
            })?;

        let metadata_path = Self::global_cache_metadata_path(cache_dir);
        fs::write(&metadata_path, to_vec(metadata).map_err(|e| {
            CompilerError::SerializationError {
                context: "global cache metadata",
                details: e.to_string(),
            }
        })?)
        .await
        .map_err(|e| CompilerError::FileWriteFailed {
            path: metadata_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

        Ok(())
    }

    #[cfg(feature = "test")]
    async fn try_acquire_global_cache_lock(
        cache_dir: &Path,
    ) -> Result<Option<GlobalCacheLock>, CompilerError> {
        fs::create_dir_all(Self::global_cache_root())
            .await
            .map_err(|e| CompilerError::DirectoryCreationFailed {
                path: Self::global_cache_root().to_string_lossy().to_string(),
                details: e.to_string(),
            })?;

        let lock_path = Self::global_cache_lock_path(cache_dir);
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
            .await
        {
            Ok(_) => Ok(Some(GlobalCacheLock { path: lock_path })),
            Err(error) if error.kind() == ErrorKind::AlreadyExists => Ok(None),
            Err(error) => Err(CompilerError::FileWriteFailed {
                path: lock_path.to_string_lossy().to_string(),
                details: error.to_string(),
            }),
        }
    }

    #[cfg(feature = "test")]
    async fn wait_for_global_cache<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        initial_value: Value,
        contract_hash: &DigestIdentifier,
        manifest_hash: &DigestIdentifier,
        engine_fingerprint: &DigestIdentifier,
        toolchain_fingerprint: &DigestIdentifier,
    ) -> Result<
        Option<(
            Arc<Module>,
            ContractArtifactRecord,
            &'static str,
            Vec<u8>,
            Vec<u8>,
        )>,
        CompilerError,
    > {
        let cache_dir = Self::global_cache_entry_dir(
            contract_hash,
            manifest_hash,
            engine_fingerprint,
            toolchain_fingerprint,
        );
        let lock_path = Self::global_cache_lock_path(&cache_dir);

        loop {
            if let Some(hit) = Self::try_load_global_cache(
                hash,
                ctx,
                initial_value.clone(),
                contract_hash,
                manifest_hash,
                engine_fingerprint,
                toolchain_fingerprint,
            )
            .await?
            {
                return Ok(Some(hit));
            }

            if fs::metadata(&lock_path).await.is_err() {
                return Ok(None);
            }

            sleep(Duration::from_millis(50)).await;
        }
    }

    #[cfg(feature = "test")]
    async fn load_global_cache_metadata(
        cache_dir: &Path,
    ) -> Result<ContractArtifactRecord, CompilerError> {
        let metadata_path = Self::global_cache_metadata_path(cache_dir);
        let metadata_bytes =
            fs::read(&metadata_path).await.map_err(|e| {
                CompilerError::FileReadFailed {
                    path: metadata_path.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;

        ContractArtifactRecord::try_from_slice(&metadata_bytes).map_err(|e| {
            CompilerError::SerializationError {
                context: "global cache metadata",
                details: e.to_string(),
            }
        })
    }

    fn deserialize_precompiled(
        wasm_runtime: &WasmRuntime,
        precompiled_bytes: &[u8],
    ) -> Result<Module, CompilerError> {
        unsafe {
            Module::deserialize(&wasm_runtime.engine, precompiled_bytes)
                .map_err(|e| CompilerError::WasmDeserializationFailed {
                    details: e.to_string(),
                })
        }
    }

    fn precompile_module(
        wasm_runtime: &WasmRuntime,
        wasm_bytes: &[u8],
    ) -> Result<(Vec<u8>, Module), CompilerError> {
        let precompiled_bytes = wasm_runtime
            .engine
            .precompile_module(wasm_bytes)
            .map_err(|e| CompilerError::WasmPrecompileFailed {
                details: e.to_string(),
            })?;

        let module =
            Self::deserialize_precompiled(wasm_runtime, &precompiled_bytes)?;

        Ok((precompiled_bytes, module))
    }

    async fn validate_module<A: Actor>(
        ctx: &ActorContext<A>,
        module: &Module,
        state: ValueWrapper,
    ) -> Result<(), CompilerError> {
        let wasm_runtime = Self::wasm_runtime(ctx).await?;

        let imports = module.imports();
        let mut pending_sdk = Self::get_sdk_functions_identifier();

        for import in imports {
            match import.ty() {
                ExternType::Func(_) => {
                    if !pending_sdk.remove(import.name()) {
                        return Err(CompilerError::InvalidModule {
                            kind: InvalidModuleKind::UnknownImportFunction {
                                name: import.name().to_string(),
                            },
                        });
                    }
                }
                extern_type => {
                    return Err(CompilerError::InvalidModule {
                        kind: InvalidModuleKind::NonFunctionImport {
                            import_type: format!("{:?}", extern_type),
                        },
                    });
                }
            }
        }
        if !pending_sdk.is_empty() {
            return Err(CompilerError::InvalidModule {
                kind: InvalidModuleKind::MissingImports {
                    missing: pending_sdk
                        .into_iter()
                        .map(|s| s.to_string())
                        .collect(),
                },
            });
        }

        let (context, state_ptr) =
            Self::generate_context(state, &wasm_runtime.limits)?;
        let mut store = Store::new(&wasm_runtime.engine, context);

        store.limiter(|data| &mut data.store_limits);
        store.set_fuel(MAX_FUEL_COMPILATION).map_err(|e| {
            CompilerError::FuelLimitError {
                details: e.to_string(),
            }
        })?;

        let linker = generate_linker(&wasm_runtime.engine)?;
        let instance = linker.instantiate(&mut store, module).map_err(|e| {
            CompilerError::InstantiationFailed {
                details: e.to_string(),
            }
        })?;

        let _main_contract_entrypoint = instance
            .get_typed_func::<(u32, u32, u32, u32), u32>(
                &mut store,
                "main_function",
            )
            .map_err(|_e| CompilerError::EntryPointNotFound {
                function: "main_function",
            })?;

        let init_contract_entrypoint = instance
            .get_typed_func::<u32, u32>(&mut store, "init_check_function")
            .map_err(|_e| CompilerError::EntryPointNotFound {
                function: "init_check_function",
            })?;

        let result_ptr =
            init_contract_entrypoint
                .call(&mut store, state_ptr)
                .map_err(|e| CompilerError::ContractExecutionFailed {
                    details: e.to_string(),
                })?;

        Self::check_result(&store, result_ptr)?;

        Ok(())
    }

    async fn wasm_runtime<A: Actor>(
        ctx: &ActorContext<A>,
    ) -> Result<Arc<WasmRuntime>, CompilerError> {
        ctx.system()
            .get_helper::<Arc<WasmRuntime>>("wasm_runtime")
            .await
            .ok_or(CompilerError::MissingHelper {
                name: "wasm_runtime",
            })
    }

    async fn contracts_helper<A: Actor>(
        ctx: &ActorContext<A>,
    ) -> Result<Arc<RwLock<HashMap<String, Arc<Module>>>>, ActorError> {
        ctx.system()
            .get_helper::<Arc<RwLock<HashMap<String, Arc<Module>>>>>(
                "contracts",
            )
            .await
            .ok_or_else(|| ActorError::Helper {
                name: "contracts".to_owned(),
                reason: "Not found".to_owned(),
            })
    }

    fn build_contract_record(
        hash: HashAlgorithm,
        contract_hash: DigestIdentifier,
        manifest_hash: DigestIdentifier,
        wasm_bytes: &[u8],
        precompiled_bytes: &[u8],
        engine_fingerprint: DigestIdentifier,
        toolchain_fingerprint: DigestIdentifier,
    ) -> Result<ContractArtifactRecord, CompilerError> {
        let wasm_hash = Self::hash_bytes(hash, wasm_bytes, "wasm artifact")?;
        let cwasm_hash =
            Self::hash_bytes(hash, precompiled_bytes, "cwasm artifact")?;

        Ok(ContractArtifactRecord {
            contract_hash,
            manifest_hash,
            wasm_hash,
            cwasm_hash,
            engine_fingerprint,
            toolchain_fingerprint,
        })
    }

    fn hash_bytes(
        hash: HashAlgorithm,
        bytes: &[u8],
        context: &'static str,
    ) -> Result<DigestIdentifier, CompilerError> {
        hash_borsh(&*hash.hasher(), &bytes.to_vec()).map_err(|e| {
            CompilerError::SerializationError {
                context,
                details: e.to_string(),
            }
        })
    }

    fn engine_fingerprint(
        hash: HashAlgorithm,
        wasm_runtime: &WasmRuntime,
    ) -> Result<DigestIdentifier, CompilerError> {
        let mut hasher = DefaultHasher::new();
        wasm_runtime
            .engine
            .precompile_compatibility_hash()
            .hash(&mut hasher);
        hash_borsh(&*hash.hasher(), &hasher.finish()).map_err(|e| {
            CompilerError::SerializationError {
                context: "engine fingerprint",
                details: e.to_string(),
            }
        })
    }

    async fn toolchain_fingerprint(
        hash: HashAlgorithm,
    ) -> Result<DigestIdentifier, CompilerError> {
        let output = Command::new("rustc")
            .arg("--version")
            .arg("--verbose")
            .output()
            .await
            .map_err(|e| CompilerError::ToolchainFingerprintFailed {
                details: e.to_string(),
            })?;

        if !output.status.success() {
            return Err(CompilerError::ToolchainFingerprintFailed {
                details: String::from_utf8_lossy(&output.stderr).to_string(),
            });
        }

        let fingerprint_input =
            String::from_utf8_lossy(&output.stdout).to_string();
        hash_borsh(&*hash.hasher(), &fingerprint_input).map_err(|e| {
            CompilerError::SerializationError {
                context: "toolchain fingerprint",
                details: e.to_string(),
            }
        })
    }

    async fn contract_environment(
        hash: HashAlgorithm,
        wasm_runtime: &Arc<WasmRuntime>,
    ) -> Result<(DigestIdentifier, DigestIdentifier), CompilerError> {
        let engine_fingerprint = Self::engine_fingerprint(hash, wasm_runtime)?;
        let toolchain_fingerprint = Self::toolchain_fingerprint(hash).await?;
        Ok((engine_fingerprint, toolchain_fingerprint))
    }

    fn metadata_matches(
        persisted: &ContractArtifactRecord,
        expected_contract_hash: &DigestIdentifier,
        expected_manifest_hash: &DigestIdentifier,
        expected_engine_fingerprint: &DigestIdentifier,
        expected_toolchain_fingerprint: &DigestIdentifier,
    ) -> bool {
        persisted.contract_hash == *expected_contract_hash
            && persisted.manifest_hash == *expected_manifest_hash
            && persisted.engine_fingerprint == *expected_engine_fingerprint
            && persisted.toolchain_fingerprint
                == *expected_toolchain_fingerprint
    }

    async fn compile_fresh<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
    ) -> Result<(Arc<Module>, ContractArtifactRecord), CompilerError> {
        let contract_hash =
            hash_borsh(&*hash.hasher(), &contract).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract hash",
                    details: e.to_string(),
                }
            })?;
        let manifest = Self::compilation_toml();
        let manifest_hash =
            hash_borsh(&*hash.hasher(), &manifest).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract manifest hash",
                    details: e.to_string(),
                }
            })?;

        Self::prepare_contract_project(contract, contract_path).await?;

        let wasm_runtime = Self::wasm_runtime(ctx).await?;
        let (engine_fingerprint, toolchain_fingerprint) =
            Self::contract_environment(hash, &wasm_runtime).await?;

        let contracts_root = Self::contracts_root(contract_path)?;
        Self::build_contract(
            contract_path,
            contracts_root.join(Self::VENDOR_DIR).exists(),
        )
        .await?;

        let wasm_bytes = Self::load_compiled_wasm(&contracts_root).await?;
        let (precompiled_bytes, module) =
            Self::precompile_module(&wasm_runtime, &wasm_bytes)?;
        Self::validate_module(ctx, &module, ValueWrapper(initial_value))
            .await?;
        Self::persist_artifact(contract_path, &wasm_bytes, &precompiled_bytes)
            .await?;

        let metadata = Self::build_contract_record(
            hash,
            contract_hash,
            manifest_hash,
            &wasm_bytes,
            &precompiled_bytes,
            engine_fingerprint,
            toolchain_fingerprint,
        )?;

        #[cfg(feature = "test")]
        {
            let global_cache_dir = Self::global_cache_entry_dir(
                &metadata.contract_hash,
                &metadata.manifest_hash,
                &metadata.engine_fingerprint,
                &metadata.toolchain_fingerprint,
            );
            if let Err(error) = Self::persist_global_cache_artifact(
                &global_cache_dir,
                &metadata,
                &wasm_bytes,
                &precompiled_bytes,
            )
            .await
            {
                debug!(
                    error = %error,
                    path = %global_cache_dir.display(),
                    "Failed to persist global contract cache artifact"
                );
            }
        }

        Ok((Arc::new(module), metadata))
    }

    #[cfg(feature = "test")]
    async fn try_load_global_cache<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        initial_value: Value,
        contract_hash: &DigestIdentifier,
        manifest_hash: &DigestIdentifier,
        engine_fingerprint: &DigestIdentifier,
        toolchain_fingerprint: &DigestIdentifier,
    ) -> Result<
        Option<(
            Arc<Module>,
            ContractArtifactRecord,
            &'static str,
            Vec<u8>,
            Vec<u8>,
        )>,
        CompilerError,
    > {
        let cache_dir = Self::global_cache_entry_dir(
            contract_hash,
            manifest_hash,
            engine_fingerprint,
            toolchain_fingerprint,
        );

        let persisted = match Self::load_global_cache_metadata(&cache_dir).await {
            Ok(metadata) => metadata,
            Err(error) => {
                debug!(
                    error = %error,
                    path = %cache_dir.display(),
                    "Global contract cache metadata unavailable"
                );
                return Ok(None);
            }
        };

        if !Self::metadata_matches(
            &persisted,
            contract_hash,
            manifest_hash,
            engine_fingerprint,
            toolchain_fingerprint,
        ) {
            return Ok(None);
        }

        let wasm_runtime = Self::wasm_runtime(ctx).await?;
        let wasm_bytes = match Self::load_artifact_wasm_from(&cache_dir).await {
            Ok(bytes) => bytes,
            Err(error) => {
                debug!(
                    error = %error,
                    path = %cache_dir.display(),
                    "Global contract cache wasm artifact unavailable"
                );
                return Ok(None);
            }
        };

        let wasm_hash =
            Self::hash_bytes(hash, &wasm_bytes, "global cache wasm artifact")?;
        if wasm_hash != persisted.wasm_hash {
            debug!(
                expected = %persisted.wasm_hash,
                actual = %wasm_hash,
                path = %cache_dir.display(),
                "Global cache wasm artifact hash mismatch"
            );
            return Ok(None);
        }

        if let Ok(precompiled_bytes) =
            Self::load_artifact_precompiled_from(&cache_dir).await
        {
            let precompiled_hash = Self::hash_bytes(
                hash,
                &precompiled_bytes,
                "global cache cwasm artifact",
            )?;
            if precompiled_hash == persisted.cwasm_hash
                && let Ok(module) = Self::deserialize_precompiled(
                    &wasm_runtime,
                    &precompiled_bytes,
                )
                && Self::validate_module(
                    ctx,
                    &module,
                    ValueWrapper(initial_value.clone()),
                )
                .await
                .is_ok()
            {
                return Ok(Some((
                    Arc::new(module),
                    persisted,
                    "global_cwasm_hit",
                    wasm_bytes,
                    precompiled_bytes,
                )));
            }
        }

        if let Ok((precompiled_bytes, module)) =
            Self::precompile_module(&wasm_runtime, &wasm_bytes)
            && Self::validate_module(
                ctx,
                &module,
                ValueWrapper(initial_value),
            )
            .await
            .is_ok()
        {
            let refreshed_record = Self::build_contract_record(
                hash,
                contract_hash.clone(),
                manifest_hash.clone(),
                &wasm_bytes,
                &precompiled_bytes,
                engine_fingerprint.clone(),
                toolchain_fingerprint.clone(),
            )?;

            if let Err(error) = Self::persist_global_cache_artifact(
                &cache_dir,
                &refreshed_record,
                &wasm_bytes,
                &precompiled_bytes,
            )
            .await
            {
                debug!(
                    error = %error,
                    path = %cache_dir.display(),
                    "Failed to refresh global contract cache artifact"
                );
            }

            return Ok(Some((
                Arc::new(module),
                refreshed_record,
                "global_wasm_hit",
                wasm_bytes,
                precompiled_bytes,
            )));
        }

        Ok(None)
    }

    async fn compile_or_load_registered<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
    ) -> Result<(Arc<Module>, ContractArtifactRecord), CompilerError> {
        let started_at = Instant::now();
        let result = async {
            let contract_hash =
                hash_borsh(&*hash.hasher(), &contract).map_err(|e| {
                    CompilerError::SerializationError {
                        context: "contract hash",
                        details: e.to_string(),
                    }
                })?;
            let manifest = Self::compilation_toml();
            let manifest_hash =
                hash_borsh(&*hash.hasher(), &manifest).map_err(|e| {
                    CompilerError::SerializationError {
                        context: "contract manifest hash",
                        details: e.to_string(),
                    }
                })?;

            Self::prepare_contract_project(contract, contract_path).await?;

            let wasm_runtime = Self::wasm_runtime(ctx).await?;
            let (engine_fingerprint, toolchain_fingerprint) =
                Self::contract_environment(hash, &wasm_runtime).await?;

            let parent_path = ctx.path().parent();
            let register_path =
                ActorPath::from(format!("{}/contract_register", parent_path));
            let register = ctx
                .system()
                .get_actor::<ContractRegister>(&register_path)
                .await
                .map_err(|e| CompilerError::ContractRegisterFailed {
                    details: e.to_string(),
                })?;

            let persisted = match register
                .ask(ContractRegisterMessage::GetMetadata {
                    contract_name: contract_name.to_owned(),
                })
                .await
            {
                Ok(ContractRegisterResponse::Metadata(metadata)) => metadata,
                Ok(ContractRegisterResponse::Contracts(_)) => None,
                Ok(ContractRegisterResponse::Ok) => None,
                Err(e) => {
                    return Err(CompilerError::ContractRegisterFailed {
                        details: e.to_string(),
                    });
                }
            };

            if let Some(persisted) = persisted
                && Self::metadata_matches(
                    &persisted,
                    &contract_hash,
                    &manifest_hash,
                    &engine_fingerprint,
                    &toolchain_fingerprint,
                )
            {
                match Self::load_artifact_precompiled(contract_path).await {
                    Ok(precompiled_bytes) => {
                        let precompiled_hash = Self::hash_bytes(
                            hash,
                            &precompiled_bytes,
                            "persisted cwasm artifact",
                        )?;
                        if precompiled_hash == persisted.cwasm_hash {
                            match Self::deserialize_precompiled(
                                &wasm_runtime,
                                &precompiled_bytes,
                            ) {
                                Ok(module) => {
                                    match Self::validate_module(
                                        ctx,
                                        &module,
                                        ValueWrapper(initial_value.clone()),
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            return Ok((
                                                Arc::new(module),
                                                persisted,
                                                "cwasm_hit",
                                            ));
                                        }
                                        Err(error) => {
                                            debug!(
                                                error = %error,
                                                path = %contract_path.display(),
                                                "Persisted precompiled contract is invalid, retrying from wasm artifact"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    debug!(
                                        error = %error,
                                        path = %contract_path.display(),
                                        "Persisted precompiled contract can not be deserialized, retrying from wasm artifact"
                                    );
                                }
                            }
                        } else {
                            debug!(
                                expected = %persisted.cwasm_hash,
                                actual = %precompiled_hash,
                                path = %contract_path.display(),
                                "Persisted precompiled artifact hash mismatch, retrying from wasm artifact"
                            );
                        }
                    }
                    Err(error) => {
                        debug!(
                            error = %error,
                            path = %contract_path.display(),
                            "Persisted precompiled artifact can not be read, retrying from wasm artifact"
                        );
                    }
                }

                match Self::load_artifact_wasm(contract_path).await {
                    Ok(wasm_bytes) => {
                        let wasm_hash = Self::hash_bytes(
                            hash,
                            &wasm_bytes,
                            "persisted wasm artifact",
                        )?;
                        if wasm_hash == persisted.wasm_hash {
                            match Self::precompile_module(
                                &wasm_runtime,
                                &wasm_bytes,
                            ) {
                                Ok((precompiled_bytes, module)) => {
                                    match Self::validate_module(
                                        ctx,
                                        &module,
                                        ValueWrapper(initial_value.clone()),
                                    )
                                    .await
                                    {
                                        Ok(()) => {
                                            Self::persist_artifact(
                                                contract_path,
                                                &wasm_bytes,
                                                &precompiled_bytes,
                                            )
                                            .await?;
                                            let refreshed_record =
                                                Self::build_contract_record(
                                                    hash,
                                                    contract_hash.clone(),
                                                    manifest_hash.clone(),
                                                    &wasm_bytes,
                                                    &precompiled_bytes,
                                                    engine_fingerprint.clone(),
                                                    toolchain_fingerprint
                                                        .clone(),
                                                )?;

                                            register
                                                .tell(
                                                    ContractRegisterMessage::SetMetadata {
                                                        contract_name: contract_name
                                                            .to_owned(),
                                                        metadata: refreshed_record
                                                            .clone(),
                                                    },
                                                )
                                                .await
                                                .map_err(|e| {
                                                    CompilerError::ContractRegisterFailed {
                                                        details: e.to_string(),
                                                    }
                                                })?;

                                            return Ok((
                                                Arc::new(module),
                                                refreshed_record,
                                                "wasm_hit",
                                            ));
                                        }
                                        Err(error) => {
                                            debug!(
                                                error = %error,
                                                path = %contract_path.display(),
                                                "Persisted wasm artifact is invalid, recompiling"
                                            );
                                        }
                                    }
                                }
                                Err(error) => {
                                    debug!(
                                        error = %error,
                                        path = %contract_path.display(),
                                        "Persisted wasm artifact can not be precompiled, recompiling"
                                    );
                                }
                            }
                        } else {
                            debug!(
                                expected = %persisted.wasm_hash,
                                actual = %wasm_hash,
                                path = %contract_path.display(),
                                "Persisted wasm artifact hash mismatch, recompiling"
                            );
                        }
                    }
                    Err(error) => {
                        debug!(
                            error = %error,
                            path = %contract_path.display(),
                            "Persisted contract artifact can not be read, recompiling"
                        );
                    }
                }
            }

            #[cfg(feature = "test")]
            let cache_dir = Self::global_cache_entry_dir(
                &contract_hash,
                &manifest_hash,
                &engine_fingerprint,
                &toolchain_fingerprint,
            );

            #[cfg(feature = "test")]
            if let Some((
                module,
                metadata,
                prepare_result,
                wasm_bytes,
                precompiled_bytes,
            )) = Self::try_load_global_cache(
                hash,
                ctx,
                initial_value.clone(),
                &contract_hash,
                &manifest_hash,
                &engine_fingerprint,
                &toolchain_fingerprint,
            )
            .await?
            {
                Self::persist_artifact(
                    contract_path,
                    &wasm_bytes,
                    &precompiled_bytes,
                )
                .await?;

                register
                    .tell(ContractRegisterMessage::SetMetadata {
                        contract_name: contract_name.to_owned(),
                        metadata: metadata.clone(),
                    })
                    .await
                    .map_err(|e| CompilerError::ContractRegisterFailed {
                        details: e.to_string(),
                    })?;

                return Ok((module, metadata, prepare_result));
            }

            #[cfg(feature = "test")]
            let global_cache_lock =
                match Self::try_acquire_global_cache_lock(&cache_dir).await? {
                    Some(lock) => Some(lock),
                    None => {
                        if let Some((
                            module,
                            metadata,
                            prepare_result,
                            wasm_bytes,
                            precompiled_bytes,
                        )) = Self::wait_for_global_cache(
                            hash,
                            ctx,
                            initial_value.clone(),
                            &contract_hash,
                            &manifest_hash,
                            &engine_fingerprint,
                            &toolchain_fingerprint,
                        )
                        .await?
                        {
                            Self::persist_artifact(
                                contract_path,
                                &wasm_bytes,
                                &precompiled_bytes,
                            )
                            .await?;

                            register
                                .tell(ContractRegisterMessage::SetMetadata {
                                    contract_name: contract_name.to_owned(),
                                    metadata: metadata.clone(),
                                })
                                .await
                                .map_err(|e| {
                                    CompilerError::ContractRegisterFailed {
                                        details: e.to_string(),
                                    }
                                })?;

                            return Ok((module, metadata, prepare_result));
                        }

                        Self::try_acquire_global_cache_lock(&cache_dir).await?
                    }
                };

            let (module, metadata) = Self::compile_fresh(
                hash,
                ctx,
                contract,
                contract_path,
                initial_value,
            )
            .await?;

            #[cfg(feature = "test")]
            drop(global_cache_lock);

            register
                .tell(ContractRegisterMessage::SetMetadata {
                    contract_name: contract_name.to_owned(),
                    metadata: metadata.clone(),
                })
                .await
                .map_err(|e| CompilerError::ContractRegisterFailed {
                    details: e.to_string(),
                })?;

            Ok((module, metadata, "recompiled"))
        }
        .await;

        match result {
            Ok((module, metadata, prepare_result)) => {
                Self::observe_contract_prepare(
                    "registered",
                    prepare_result,
                    started_at,
                );
                Ok((module, metadata))
            }
            Err(error) => {
                Self::observe_contract_prepare(
                    "registered",
                    "error",
                    started_at,
                );
                Err(error)
            }
        }
    }

    fn check_result(
        store: &Store<MemoryManager>,
        pointer: u32,
    ) -> Result<(), CompilerError> {
        let bytes = store.data().read_data(pointer as usize)?;
        let contract_result: ContractResult =
            BorshDeserialize::try_from_slice(bytes).map_err(|e| {
                CompilerError::InvalidContractOutput {
                    details: e.to_string(),
                }
            })?;

        if contract_result.success {
            Ok(())
        } else {
            Err(CompilerError::ContractCheckFailed {
                error: contract_result.error,
            })
        }
    }

    fn generate_context(
        state: ValueWrapper,
        limits: &WasmLimits,
    ) -> Result<(MemoryManager, u32), CompilerError> {
        let mut context = MemoryManager::from_limits(limits);
        let state_bytes =
            to_vec(&state).map_err(|e| CompilerError::SerializationError {
                context: "state serialization",
                details: e.to_string(),
            })?;
        let state_ptr = context.add_data_raw(&state_bytes)?;
        Ok((context, state_ptr as u32))
    }

    fn get_sdk_functions_identifier() -> HashSet<&'static str> {
        ["alloc", "write_byte", "pointer_len", "read_byte"]
            .into_iter()
            .collect()
    }
}

#[cfg(feature = "test")]
struct GlobalCacheLock {
    path: PathBuf,
}

#[cfg(feature = "test")]
impl Drop for GlobalCacheLock {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}
