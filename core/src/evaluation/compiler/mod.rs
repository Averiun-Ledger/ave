use std::{
    collections::{HashMap, HashSet},
    path::{Path, PathBuf},
    process::Command, sync::Arc,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, hash_borsh},
};
use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
use borsh::{BorshDeserialize, BorshSerialize, to_vec};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::{fs, sync::RwLock};

use tracing::error;
use wasmtime::{Engine, ExternType, Module, Store};

use crate::{
    Error, model::common::{
        MAX_FUEL_COMPILATION, MemoryManager,
        generate_linker,
    }, system::ConfigHelper
};

const TARGET_COMPILER: &str = "Ave-Evaluation-Compiler";

#[derive(
    Serialize, Deserialize, BorshSerialize, BorshDeserialize, Debug, Clone,
)]
pub struct ContractResult {
    pub success: bool,
    pub error: String,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct Compiler {
    pub contract: DigestIdentifier,
}

impl Compiler {
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
    ) -> Result<(), Error> {
        // Write contract.
        let Ok(decode_base64) = BASE64_STANDARD.decode(contract) else {
            return Err(Error::Compiler(format!(
                "Failed to decode base64 {}",
                contract_path.to_string_lossy()
            )));
        };

        let dir = contract_path.join("src");
        if !Path::new(&dir).exists() {
            fs::create_dir_all(&dir).await.map_err(|e| {
                Error::Node(format!("Can not create src dir: {}", e))
            })?;
        }

        let toml: String = Self::compilation_toml();
        let cargo = contract_path.join("Cargo.toml");
        // We write cargo.toml
        fs::write(&cargo, toml).await.map_err(|e| {
            Error::Node(format!("Can not create Cargo.toml file: {}", e))
        })?;

        fs::write(contract_path.join("src").join("lib.rs"), decode_base64)
            .await
            .map_err(|e| {
                Error::Compiler(format!("Can not create lib.rs file: {}", e))
            })?;

        // Compiling contract
        let status = Command::new("cargo")
            .arg("build")
            .arg(format!("--manifest-path={}", cargo.to_string_lossy()))
            .arg("--target")
            .arg("wasm32-unknown-unknown")
            .arg("--release")
            .status()
            // Does not show stdout. Generates child process and waits
            .map_err(|e| {
                Error::Compiler(format!("Can not compile contract: {}", e))
            })?;

        // Is success
        if !status.success() {
            return Err(Error::Compiler(
                "Can not compile contract".to_string(),
            ));
        }

        Ok(())
    }

    async fn check_wasm(
        ctx: &mut ActorContext<Compiler>,
        contract_path: &Path,
        state: ValueWrapper,
    ) -> Result<Vec<u8>, Error> {
        // Use the same secure configuration as the runner to ensure consistency
        let Some(engine) = ctx.system().get_helper::<Arc<Engine>>("engine").await
        else {
            return Err(Error::Compiler("Can not get engine from helper".to_owned()));
        };
        // Read compile contract
        let file = fs::read(
            contract_path
                .join("target")
                .join("wasm32-unknown-unknown")
                .join("release")
                .join("contract.wasm"),
        )
        .await
        .map_err(|e| {
            Error::Compiler(format!("Can not read contract.wasm: {}", e))
        })?;

        // Precompilation
        let contract_bytes = engine.precompile_module(&file).map_err(|e| {
            Error::Compiler(format!(
                "Can not precompile module with wasmtime engine: {}",
                e
            ))
        })?;

        drop(file);

        // Module represents a precompiled WebAssembly program that is ready to be instantiated and executed.
        // This function receives the previous input from Engine::precompile_module, that is why this function can be considered safe.
        let module = unsafe {
            Module::deserialize(&engine, &contract_bytes).map_err(|e| {
                Error::Compiler(format!(
                    "Error deserializing the contract in wastime: {}",
                    e
                ))
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
                        return Err(Error::Compiler("Module has a function that is not contemplated in the sdk".to_owned()));
                    }
                }
                _ => {
                    return Err(Error::Compiler(
                        "Module has a import that is not function".to_owned(),
                    ));
                }
            }
        }
        if !pending_sdk.is_empty() {
            return Err(Error::Compiler(
                "Module has not all imports of sdk".to_owned(),
            ));
        }

        // We create a context from the state and the event.
        let (context, state_ptr) = Self::generate_context(state)?;

        // Container to store and manage the global state of a WebAssembly instance during its execution.
        let mut store = Store::new(&engine, context);

        // Set fuel limit for compilation/validation (more generous than production)
        store.set_fuel(MAX_FUEL_COMPILATION).map_err(|e| {
            Error::Compiler(format!("Error setting fuel limit: {}", e))
        })?;

        // Responsible for combining several object files into a single WebAssembly executable file (.wasm).
        let linker = generate_linker(&engine)?;

        // Contract instance.
        let instance =
            linker.instantiate(&mut store, &module).map_err(|e| {
                Error::Compiler(format!(
                    "Error when creating a contract instance: {}",
                    e
                ))
            })?;

        // Get access to contract, only to check if main_function exist.
        let _main_contract_entrypoint = instance
            .get_typed_func::<(u32, u32, u32, u32), u32>(
                &mut store,
                "main_function",
            )
            .map_err(|e| {
                Error::Compiler(format!(
                    "Contract entry point not found: {}",
                    e
                ))
            })?;

        // Get access to contract
        let init_contract_entrypoint = instance
            .get_typed_func::<u32, u32>(&mut store, "init_check_function")
            .map_err(|e| {
                Error::Compiler(format!(
                    "Contract entry point not found: {}",
                    e
                ))
            })?;

        // Contract execution
        let result_ptr = init_contract_entrypoint
            .call(&mut store, state_ptr)
            .map_err(|e| {
            Error::Compiler(format!("Contract execution failed: {}", e))
        })?;

        Self::check_result(&store, result_ptr)?;

        Ok(contract_bytes)
    }

    fn check_result(
        store: &Store<MemoryManager>,
        pointer: u32,
    ) -> Result<(), Error> {
        let bytes = store.data().read_data(pointer as usize)?;
        let contract_result: ContractResult =
            BorshDeserialize::try_from_slice(bytes).map_err(|e| {
                Error::Compiler(format!(
                    "Can not generate wasm contract result: {}",
                    e
                ))
            })?;

        if contract_result.success {
            Ok(())
        } else {
            Err(Error::Compiler(format!(
                "Contract execution in compilation was not successful: {}",
                contract_result.error
            )))
        }
    }

    fn generate_context(
        state: ValueWrapper,
    ) -> Result<(MemoryManager, u32), Error> {
        let mut context = MemoryManager::default();
        let state_bytes = to_vec(&state).map_err(|e| {
            Error::Compiler(format!(
                "Error when serializing the state using borsh: {}",
                e
            ))
        })?;
        let state_ptr = context.add_data_raw(&state_bytes).map_err(|e| {
            Error::Compiler(format!("Error allocating state in memory: {}", e))
        })?;
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
                let hash = if let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config").await {
                        config.hash_algorithm
                }
                else {
                    return Err(ActorError::NotHelper("config".to_owned()));
                };

                let contract_hash = match hash_borsh(&*hash.hasher(), &contract)
                {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!(
                            TARGET_COMPILER,
                            "Compile, Can not hash contract: {}", e
                        );
                        return Err(ActorError::Functional(format!(
                            "Can not hash contract: {}",
                            e
                        )));
                    }
                };

                if contract_hash != self.contract {
                    if let Err(e) =
                        Self::compile_contract(&contract, &contract_path).await
                    {
                        error!(
                            TARGET_COMPILER,
                            "Compile, Can not compile: {}", e
                        );
                        return Err(ActorError::Functional(e.to_string()));
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
                                TARGET_COMPILER,
                                "Compile, Can check wasm: {}", e
                            );
                            return Err(ActorError::Functional(e.to_string()));
                        }
                    };

                    {
                        let Some(contracts) = ctx.system().get_helper::<Arc<RwLock<HashMap<String, Vec<u8>>>>>("contracts").await else {
                            return Err(ActorError::FunctionalFail("Can not obtain contracts helper".to_owned()));
                        };
                        
                        let mut contracts = contracts.write().await;
                        contracts.insert(contract_name, contract);
                    }

                    self.contract = contract_hash;
                }

                Ok(())
            }
        }
    }
}
