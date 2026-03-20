use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{fs, process::Command, sync::RwLock};

use tracing::{Span, debug, error, info_span};
use wasmtime::{ExternType, Module, Store};

use crate::model::common::contract::{
    MAX_FUEL_COMPILATION, MemoryManager, WasmLimits, WasmRuntime,
    generate_linker,
};

pub mod error;
use error::*;

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone,
)]
pub struct ContractResult {
    pub success: bool,
    pub error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ContractArtifactMetadata {
    contract_hash: DigestIdentifier,
    manifest_hash: DigestIdentifier,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Compiler {
    contract: DigestIdentifier,
    hash: HashAlgorithm,
}

impl Compiler {
    const SHARED_TARGET_DIR: &'static str = "target";
    const VENDOR_DIR: &'static str = "vendor";
    const ARTIFACT_WASM: &'static str = "contract.wasm";
    const ARTIFACT_PRECOMPILED: &'static str = "contract.cwasm";
    const ARTIFACT_METADATA: &'static str = "contract.json";

    pub fn new(hash: HashAlgorithm) -> Self {
        Self {
            contract: DigestIdentifier::default(),
            hash,
        }
    }

    fn compilation_toml() -> String {
        include_str!("contract_Cargo.toml").to_owned()
    }

    fn contracts_root(
        contract_path: &Path,
    ) -> Result<PathBuf, CompilerError> {
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

    fn artifact_wasm_path(contract_path: &Path) -> PathBuf {
        contract_path.join(Self::ARTIFACT_WASM)
    }

    fn artifact_metadata_path(contract_path: &Path) -> PathBuf {
        contract_path.join(Self::ARTIFACT_METADATA)
    }

    fn artifact_precompiled_path(contract_path: &Path) -> PathBuf {
        contract_path.join(Self::ARTIFACT_PRECOMPILED)
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

        let status = command
            .status()
            .await
            .map_err(|e| CompilerError::CargoBuildFailed {
                details: e.to_string(),
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

        let toml: String = Self::compilation_toml();
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
        fs::write(&cargo_config_path, cargo_config).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: cargo_config_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn load_artifact_metadata(
        contract_path: &Path,
    ) -> Result<Option<ContractArtifactMetadata>, CompilerError> {
        let metadata_path = Self::artifact_metadata_path(contract_path);
        if !metadata_path.exists() {
            return Ok(None);
        }

        let metadata =
            fs::read_to_string(&metadata_path).await.map_err(|e| {
                CompilerError::FileReadFailed {
                    path: metadata_path.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;

        let metadata = serde_json::from_str::<ContractArtifactMetadata>(
            &metadata,
        )
        .map_err(|e| CompilerError::MetadataParseFailed {
            path: metadata_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

        Ok(Some(metadata))
    }

    async fn persist_artifact(
        contract_path: &Path,
        wasm_bytes: &[u8],
        precompiled_bytes: &[u8],
        metadata: &ContractArtifactMetadata,
    ) -> Result<(), CompilerError> {
        let artifact_path = Self::artifact_wasm_path(contract_path);
        fs::write(&artifact_path, wasm_bytes).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: artifact_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let precompiled_path = Self::artifact_precompiled_path(contract_path);
        fs::write(&precompiled_path, precompiled_bytes).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: precompiled_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        let metadata_path = Self::artifact_metadata_path(contract_path);
        let metadata_json = serde_json::to_vec(metadata).map_err(|e| {
            CompilerError::SerializationError {
                context: "contract artifact metadata",
                details: e.to_string(),
            }
        })?;
        fs::write(&metadata_path, metadata_json).await.map_err(|e| {
            CompilerError::FileWriteFailed {
                path: metadata_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn load_artifact_wasm(
        contract_path: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let wasm_path = Self::artifact_wasm_path(contract_path);
        fs::read(&wasm_path).await.map_err(|e| CompilerError::FileReadFailed {
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

    async fn load_compiled_wasm(
        contracts_root: &Path,
    ) -> Result<Vec<u8>, CompilerError> {
        let wasm_path = Self::build_output_wasm_path(contracts_root);
        fs::read(&wasm_path).await.map_err(|e| CompilerError::FileReadFailed {
            path: wasm_path.to_string_lossy().to_string(),
            details: e.to_string(),
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

    async fn validate_module(
        ctx: &ActorContext<Self>,
        module: &Module,
        state: ValueWrapper,
    ) -> Result<(), CompilerError> {
        let Some(wasm_runtime) = ctx
            .system()
            .get_helper::<Arc<WasmRuntime>>("wasm_runtime")
            .await
        else {
            return Err(CompilerError::MissingHelper {
                name: "wasm_runtime",
            });
        };

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
        let instance =
            linker.instantiate(&mut store, module).map_err(|e| {
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

    async fn compile_or_load(
        &self,
        ctx: &ActorContext<Self>,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
    ) -> Result<(Arc<Module>, DigestIdentifier), CompilerError> {
        let contract_hash =
            hash_borsh(&*self.hash.hasher(), &contract).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract hash",
                    details: e.to_string(),
                }
            })?;
        let manifest = Self::compilation_toml();
        let manifest_hash =
            hash_borsh(&*self.hash.hasher(), &manifest).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract manifest hash",
                    details: e.to_string(),
                }
            })?;

        Self::prepare_contract_project(contract, contract_path).await?;

        let Some(wasm_runtime) = ctx
            .system()
            .get_helper::<Arc<WasmRuntime>>("wasm_runtime")
            .await
        else {
            return Err(CompilerError::MissingHelper {
                name: "wasm_runtime",
            });
        };

        let expected_metadata = ContractArtifactMetadata {
            contract_hash: contract_hash.clone(),
            manifest_hash,
        };

        if let Some(current_metadata) =
            Self::load_artifact_metadata(contract_path).await?
            && current_metadata.contract_hash == expected_metadata.contract_hash
            && current_metadata.manifest_hash == expected_metadata.manifest_hash
        {
            match Self::load_artifact_precompiled(contract_path).await {
                Ok(precompiled_bytes) => {
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
                                        contract_hash,
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
                                        &expected_metadata,
                                    )
                                    .await?;
                                    return Ok((
                                        Arc::new(module),
                                        contract_hash,
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
        Self::persist_artifact(
            contract_path,
            &wasm_bytes,
            &precompiled_bytes,
            &expected_metadata,
        )
        .await?;

        Ok((Arc::new(module), contract_hash))
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

#[derive(Debug, Clone)]
pub enum CompilerMessage {
    TemporalCompile {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
    },
    Compile {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
    },
}

impl Message for CompilerMessage {}

#[derive(Debug, Clone)]
pub enum CompilerResponse {
    Ok,
    Error(CompilerError),
}

impl Response for CompilerResponse {}

impl NotPersistentActor for Compiler {}

#[async_trait]
impl Actor for Compiler {
    type Event = ();
    type Message = CompilerMessage;
    type Response = CompilerResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Compiler", id),
            |parent_span| info_span!(parent: parent_span, "Compiler", id),
        )
    }
}

#[async_trait]
impl Handler<Self> for Compiler {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: CompilerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<CompilerResponse, ActorError> {
        match msg {
            CompilerMessage::TemporalCompile {
                contract,
                contract_name,
                contract_path,
                initial_value,
            } => {
                if let Err(e) = self
                    .compile_or_load(
                        ctx,
                        &contract,
                        &contract_path,
                        initial_value,
                    )
                    .await
                {
                    error!(
                        msg_type = "TemporalCompile",
                        error = %e,
                        contract_name = %contract_name,
                        path = %contract_path.display(),
                        "Contract compilation or validation failed"
                    );
                    let _ = fs::remove_dir_all(&contract_path).await;
                    return Ok(CompilerResponse::Error(e));
                };

                if let Err(e) = fs::remove_dir_all(&contract_path).await {
                    error!(
                        msg_type = "TemporalCompile",
                        error = %e,
                        path = %contract_path.display(),
                        "Failed to remove temporal contract directory"
                    );
                }

                Ok(CompilerResponse::Ok)
            }
            CompilerMessage::Compile {
                contract,
                contract_name,
                contract_path,
                initial_value,
            } => {
                let contract_hash =
                    match hash_borsh(&*self.hash.hasher(), &contract) {
                        Ok(hash) => hash,
                        Err(e) => {
                            error!(
                                msg_type = "Compile",
                                error = %e,
                                "Failed to hash contract"
                            );
                            return Err(ActorError::FunctionalCritical {
                                description: format!(
                                    "Can not hash contract: {}",
                                    e
                                ),
                            });
                        }
                    };

                if contract_hash != self.contract {
                    let (contract, contract_hash) = match self
                        .compile_or_load(
                            ctx,
                            &contract,
                            &contract_path,
                            initial_value,
                        )
                        .await
                    {
                        Ok(result) => result,
                        Err(e) => {
                            error!(
                                msg_type = "Compile",
                                error = %e,
                                contract_name = %contract_name,
                                path = %contract_path.display(),
                                "Contract compilation or validation failed"
                            );
                            return Ok(CompilerResponse::Error(e));
                        }
                    };

                    {
                        let Some(contracts) = ctx.system().get_helper::<Arc<RwLock<HashMap<String, Arc<Module>>>>>("contracts").await else {
                            error!(
                                msg_type = "Compile",
                                "Contracts helper not found"
                            );
                            return Err(ActorError::Helper { name: "contracts".to_string(), reason: "Not found".to_string() });
                        };

                        let mut contracts = contracts.write().await;
                        contracts.insert(contract_name.clone(), contract);
                    }

                    self.contract = contract_hash.clone();

                    debug!(
                        msg_type = "Compile",
                        contract_name = %contract_name,
                        contract_hash = %contract_hash,
                        "Contract compiled and validated successfully"
                    );
                } else {
                    debug!(
                        msg_type = "Compile",
                        contract_name = %contract_name,
                        "Contract already compiled, skipping"
                    );
                }

                Ok(CompilerResponse::Ok)
            }
        }
    }
}
