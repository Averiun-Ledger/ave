use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::Arc,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{fs, sync::RwLock};

use tracing::{Span, debug, error, info_span};
use wasmtime::{Engine, ExternType, Module, Store};

use crate::model::common::contract::{
    MAX_FUEL_COMPILATION, MemoryManager, generate_linker,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Compiler {
    contract: DigestIdentifier,
    hash: HashAlgorithm,
}

impl Compiler {
    pub fn new(hash: HashAlgorithm) -> Self {
        Self {
            contract: DigestIdentifier::default(),
            hash,
        }
    }

    fn compilation_toml() -> String {
        r#"
    [package]
    name = "contract"
    version = "0.1.0"
    edition = "2024"

    [dependencies]
    serde = { version = "1.0.219", features = ["derive"] }
    serde_json = "1.0.140"
    ave-contract-sdk = "0.6.0"

    [profile.release]
    strip = "debuginfo"
    lto = true

    [lib]
    crate-type = ["cdylib"]

    [workspace]
      "#
        .into()
    }

    async fn compile_contract(
        contract: &str,
        contract_path: &Path,
    ) -> Result<(), CompilerError> {
        // Write contract.
        let decode_base64 = BASE64_STANDARD.decode(contract).map_err(|e| {
            CompilerError::Base64DecodeFailed {
                details: format!(
                    "{} (path: {})",
                    e,
                    contract_path.to_string_lossy()
                ),
            }
        })?;

        let dir = contract_path.join("src");
        if !Path::new(&dir).exists() {
            fs::create_dir_all(&dir).await.map_err(|e| {
                CompilerError::DirectoryCreationFailed {
                    path: dir.to_string_lossy().to_string(),
                    details: e.to_string(),
                }
            })?;
        }

        let toml: String = Self::compilation_toml();
        let cargo = contract_path.join("Cargo.toml");
        // We write cargo.toml
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

        // Compiling contract
        let status = Command::new("cargo")
            .arg("build")
            .arg(format!("--manifest-path={}", cargo.to_string_lossy()))
            .arg("--target")
            .arg("wasm32-unknown-unknown")
            .arg("--release")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| CompilerError::CargoBuildFailed {
                details: e.to_string(),
            })?;

        // Is success
        if !status.success() {
            return Err(CompilerError::CompilationFailed);
        }

        Ok(())
    }

    async fn check_wasm(
        ctx: &mut ActorContext<Compiler>,
        contract_path: &Path,
        state: ValueWrapper,
    ) -> Result<Vec<u8>, CompilerError> {
        // Use the same secure configuration as the runner to ensure consistency
        let Some(engine) =
            ctx.system().get_helper::<Arc<Engine>>("engine").await
        else {
            return Err(CompilerError::MissingHelper { name: "engine" });
        };
        // Read compile contract
        let wasm_path = contract_path
            .join("target")
            .join("wasm32-unknown-unknown")
            .join("release")
            .join("contract.wasm");
        let file = fs::read(&wasm_path).await.map_err(|e| {
            CompilerError::FileReadFailed {
                path: wasm_path.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;

        // Precompilation
        let contract_bytes = engine.precompile_module(&file).map_err(|e| {
            CompilerError::WasmPrecompileFailed {
                details: e.to_string(),
            }
        })?;

        drop(file);

        // Module represents a precompiled WebAssembly program that is ready to be instantiated and executed.
        // This function receives the previous input from Engine::precompile_module, that is why this function can be considered safe.
        let module = unsafe {
            Module::deserialize(&engine, &contract_bytes).map_err(|e| {
                CompilerError::WasmDeserializationFailed {
                    details: e.to_string(),
                }
            })?
        };

        // Obtain imports
        let imports = module.imports();
        // get functions of sdk
        let mut pending_sdk = Self::get_sdk_functions_identifier();

        for import in imports {
            // import must be a function
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

        // We create a context from the state and the event.
        let (context, state_ptr) = Self::generate_context(state)?;

        // Container to store and manage the global state of a WebAssembly instance during its execution.
        let mut store = Store::new(&engine, context);

        // Set fuel limit for compilation/validation (more generous than production)
        store.set_fuel(MAX_FUEL_COMPILATION).map_err(|e| {
            CompilerError::FuelLimitError {
                details: e.to_string(),
            }
        })?;

        // Responsible for combining several object files into a single WebAssembly executable file (.wasm).
        let linker = generate_linker(&engine)?;

        // Contract instance.
        let instance =
            linker.instantiate(&mut store, &module).map_err(|e| {
                CompilerError::InstantiationFailed {
                    details: e.to_string(),
                }
            })?;

        // Get access to contract, only to check if main_function exist.
        let _main_contract_entrypoint = instance
            .get_typed_func::<(u32, u32, u32, u32), u32>(
                &mut store,
                "main_function",
            )
            .map_err(|_e| CompilerError::EntryPointNotFound {
                function: "main_function",
            })?;

        // Get access to contract
        let init_contract_entrypoint = instance
            .get_typed_func::<u32, u32>(&mut store, "init_check_function")
            .map_err(|_e| CompilerError::EntryPointNotFound {
                function: "init_check_function",
            })?;

        // Contract execution
        let result_ptr =
            init_contract_entrypoint
                .call(&mut store, state_ptr)
                .map_err(|e| CompilerError::ContractExecutionFailed {
                    details: e.to_string(),
                })?;

        Self::check_result(&store, result_ptr)?;

        Ok(contract_bytes)
    }

    fn check_result(
        store: &Store<MemoryManager>,
        pointer: u32,
    ) -> Result<(), CompilerError> {
        let bytes = store.data().read_data(pointer as usize)?;
        let contract_result: ContractResult =
            BorshDeserialize::try_from_slice(bytes).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract result deserialization",
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
    ) -> Result<(MemoryManager, u32), CompilerError> {
        let mut context = MemoryManager::default();
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
    Compile {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
    },
}

impl Message for CompilerMessage {}

impl NotPersistentActor for Compiler {}

#[async_trait]
impl Actor for Compiler {
    type Event = ();
    type Message = CompilerMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Compiler", id)
        } else {
            info_span!("Compiler", id)
        }
    }
}

#[async_trait]
impl Handler<Compiler> for Compiler {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: CompilerMessage,
        ctx: &mut ActorContext<Compiler>,
    ) -> Result<(), ActorError> {
        match msg {
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
                    if let Err(e) =
                        Self::compile_contract(&contract, &contract_path).await
                    {
                        error!(
                            msg_type = "Compile",
                            error = %e,
                            contract_name = %contract_name,
                            path = %contract_path.display(),
                            "Contract compilation failed"
                        );
                        return Err(ActorError::FunctionalCritical {
                            description: e.to_string(),
                        });
                    };

                    let contract = match Self::check_wasm(
                        ctx,
                        &contract_path,
                        ValueWrapper(initial_value),
                    )
                    .await
                    {
                        Ok(contract) => contract,
                        Err(e) => {
                            error!(
                                msg_type = "Compile",
                                error = %e,
                                contract_name = %contract_name,
                                "WASM validation failed"
                            );
                            return Err(ActorError::FunctionalCritical {
                                description: e.to_string(),
                            });
                        }
                    };

                    {
                        let Some(contracts) = ctx.system().get_helper::<Arc<RwLock<HashMap<String, Vec<u8>>>>>("contracts").await else {
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

                Ok(())
            }
        }
    }
}
