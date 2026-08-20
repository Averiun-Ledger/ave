#[cfg(feature = "test")]
use std::env;
use std::time::Duration;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};

use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use ave_contract_sdk::runtime::{
    CompiledModule, ContractRuntime, RuntimeError,
};
use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
#[cfg(feature = "test")]
use borsh::to_vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
#[cfg(feature = "test")]
use serde_json::Value;
use tokio::time::timeout;
use tokio::{fs, process::Command};
use tracing::debug;

use crate::error::CompilerError;

/// Maximum time allowed for a single contract build.
const BUILD_TIMEOUT: Duration = Duration::from_secs(600);

const BUILD_TARGET_DIR: &str = ".build-target";
const SHARED_CARGO_HOME_DIR: &str = ".cargo-home";
const VENDOR_DIR: &str = "vendor";
const ARTIFACT_WASM: &str = "contract.wasm";
const ARTIFACT_PRECOMPILED: &str = "contract.cwasm";
const LEGACY_ARTIFACT_METADATA: &str = "contract.json";
#[cfg(feature = "test")]
const GLOBAL_CACHE_DIR: &str = "ave-contract-artifacts";
#[cfg(feature = "test")]
const GLOBAL_CACHE_METADATA: &str = "metadata.borsh";

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

pub fn compilation_toml() -> String {
    ave_contract_sdk::runtime::CONTRACT_CARGO_TOML.to_owned()
}

/// Validates that `contract` is well-formed base64 (standard alphabet).
///
/// The node runs this cheap local check before delegating a build to the
/// compiler service: a malformed payload is a request error
/// ([`CompilerError::Base64DecodeFailed`]), not a build error, and must
/// not be conflated with "the contract does not compile".
pub fn validate_source_base64(contract: &str) -> Result<(), CompilerError> {
    BASE64_STANDARD.decode(contract).map_err(|e| {
        CompilerError::Base64DecodeFailed {
            details: e.to_string(),
        }
    })?;
    Ok(())
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
    base_path.join(ARTIFACT_WASM)
}

fn artifact_wasm_path(contract_path: &Path) -> PathBuf {
    contract_path.join(ARTIFACT_WASM)
}

#[cfg(feature = "test")]
fn artifact_precompiled_path_in(base_path: &Path) -> PathBuf {
    base_path.join(ARTIFACT_PRECOMPILED)
}

fn artifact_precompiled_path(contract_path: &Path) -> PathBuf {
    contract_path.join(ARTIFACT_PRECOMPILED)
}

fn legacy_artifact_metadata_path(contract_path: &Path) -> PathBuf {
    contract_path.join(LEGACY_ARTIFACT_METADATA)
}

#[cfg(feature = "test")]
fn global_cache_root() -> PathBuf {
    env::temp_dir().join(GLOBAL_CACHE_DIR)
}

#[cfg(feature = "test")]
pub fn global_cache_entry_dir(
    contract_hash: &DigestIdentifier,
    manifest_hash: &DigestIdentifier,
    engine_fingerprint: &DigestIdentifier,
    toolchain_fingerprint: &DigestIdentifier,
) -> PathBuf {
    global_cache_root().join(format!(
        "{contract_hash}_{manifest_hash}_{engine_fingerprint}_{toolchain_fingerprint}"
    ))
}

#[cfg(feature = "test")]
fn global_cache_metadata_path(cache_dir: &Path) -> PathBuf {
    cache_dir.join(GLOBAL_CACHE_METADATA)
}

fn cargo_config_path(contract_path: &Path) -> PathBuf {
    contract_path.join(".cargo").join("config.toml")
}

fn vendor_dir_for_contract() -> PathBuf {
    PathBuf::from(".")
        .join("..")
        .join("..")
        .join(VENDOR_DIR)
}

fn build_output_wasm_path(contract_path: &Path) -> PathBuf {
    contract_path
        .join(BUILD_TARGET_DIR)
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(ARTIFACT_WASM)
}

fn cargo_config(target_dir: &Path, vendor_dir: Option<&Path>) -> String {
    let mut config =
        ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG.to_owned();
    config =
        config.replace("{target_dir}", &target_dir.to_string_lossy());

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
    let cargo_home = contracts_root(contract_path)?.join(SHARED_CARGO_HOME_DIR);
    let mut command = Command::new("cargo");
    command
        .arg("build")
        .arg(format!("--manifest-path={}", cargo.to_string_lossy()))
        .arg("--target")
        .arg("wasm32-unknown-unknown")
        .arg("--release")
        .current_dir(contract_path)
        .env("CARGO_HOME", cargo_home)
        .stdout(Stdio::null())
        .stderr(Stdio::null());

    if offline {
        command.arg("--offline");
    }

    let mut child = command.spawn().map_err(|e| {
        CompilerError::CargoBuildFailed {
            details: e.to_string(),
        }
    })?;

    let status = match timeout(BUILD_TIMEOUT, child.wait()).await {
        Ok(result) => result.map_err(|e| CompilerError::CargoBuildFailed {
            details: e.to_string(),
        })?,
        Err(_) => {
            if let Err(error) = child.kill().await {
                debug!(
                    error = %error,
                    "Failed to kill cargo build process after timeout"
                );
            }
            return Err(CompilerError::BuildTimeout {
                secs: BUILD_TIMEOUT.as_secs(),
            });
        }
    };

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

    let contracts_root = contracts_root(contract_path)?;
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

    let toml = compilation_toml();
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

    let vendor_dir = contracts_root.join(VENDOR_DIR);
    let cargo_config = cargo_config(
        Path::new(BUILD_TARGET_DIR),
        vendor_dir
            .exists()
            .then(vendor_dir_for_contract)
            .as_deref(),
    );
    let cargo_config_path = cargo_config_path(contract_path);
    fs::write(&cargo_config_path, cargo_config)
        .await
        .map_err(|e| CompilerError::FileWriteFailed {
            path: cargo_config_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

    Ok(())
}

pub async fn load_artifact_wasm(
    contract_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let wasm_path = artifact_wasm_path(contract_path);
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
    let wasm_path = artifact_wasm_path_in(base_path);
    fs::read(&wasm_path)
        .await
        .map_err(|e| CompilerError::FileReadFailed {
            path: wasm_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })
}

pub async fn load_artifact_precompiled(
    contract_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let precompiled_path = artifact_precompiled_path(contract_path);
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
    let precompiled_path = artifact_precompiled_path_in(base_path);
    fs::read(&precompiled_path).await.map_err(|e| {
        CompilerError::FileReadFailed {
            path: precompiled_path.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })
}

async fn load_compiled_wasm(
    contract_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let wasm_path = build_output_wasm_path(contract_path);
    fs::read(&wasm_path)
        .await
        .map_err(|e| CompilerError::FileReadFailed {
            path: wasm_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })
}

/// Builds a base64-encoded contract source into raw wasm bytes.
///
/// Prepares the contract project under `contract_path`, runs the cargo
/// build and returns the compiled artifact. It does not validate the
/// module (`init_check`) nor persist artifacts: both are the node's
/// responsibility. Used by the compiler service; the node never compiles.
pub async fn build_wasm(
    contract: &str,
    contract_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    prepare_contract_project(contract, contract_path).await?;

    let contracts_root = contracts_root(contract_path)?;
    build_contract(
        contract_path,
        contracts_root.join(VENDOR_DIR).exists(),
    )
    .await?;

    load_compiled_wasm(contract_path).await
}

pub async fn persist_artifact(
    contract_path: &Path,
    wasm_bytes: &[u8],
    precompiled_bytes: &[u8],
) -> Result<(), CompilerError> {
    fs::create_dir_all(contract_path).await.map_err(|e| {
        CompilerError::DirectoryCreationFailed {
            path: contract_path.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })?;

    let artifact_path = artifact_wasm_path(contract_path);
    fs::write(&artifact_path, wasm_bytes).await.map_err(|e| {
        CompilerError::FileWriteFailed {
            path: artifact_path.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })?;

    let precompiled_path = artifact_precompiled_path(contract_path);
    fs::write(&precompiled_path, precompiled_bytes)
        .await
        .map_err(|e| CompilerError::FileWriteFailed {
            path: precompiled_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

    let legacy_metadata_path =
        legacy_artifact_metadata_path(contract_path);
    let _ = fs::remove_file(&legacy_metadata_path).await;

    Ok(())
}

#[cfg(feature = "test")]
pub async fn persist_global_cache_artifact(
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

    let artifact_path = artifact_wasm_path_in(cache_dir);
    fs::write(&artifact_path, wasm_bytes).await.map_err(|e| {
        CompilerError::FileWriteFailed {
            path: artifact_path.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })?;

    let precompiled_path = artifact_precompiled_path_in(cache_dir);
    fs::write(&precompiled_path, precompiled_bytes)
        .await
        .map_err(|e| CompilerError::FileWriteFailed {
            path: precompiled_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

    let metadata_path = global_cache_metadata_path(cache_dir);
    fs::write(
        &metadata_path,
        to_vec(metadata).map_err(|e| {
            CompilerError::SerializationError {
                context: "global cache metadata",
                details: e.to_string(),
            }
        })?,
    )
    .await
    .map_err(|e| CompilerError::FileWriteFailed {
        path: metadata_path.to_string_lossy().to_string(),
        details: e.to_string(),
    })?;

    Ok(())
}

#[cfg(feature = "test")]
async fn load_global_cache_metadata(
    cache_dir: &Path,
) -> Result<ContractArtifactRecord, CompilerError> {
    let metadata_path = global_cache_metadata_path(cache_dir);
    let metadata_bytes = fs::read(&metadata_path).await.map_err(|e| {
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

pub fn precompile_module(
    contract_runtime: &ContractRuntime,
    wasm_bytes: &[u8],
) -> Result<(Vec<u8>, Arc<CompiledModule>), CompilerError> {
    let module = contract_runtime
        .compile(wasm_bytes)
        .map_err(map_runtime_error_to_compiler_error)?;

    let precompiled_bytes = module.precompiled_bytes().to_vec();
    let module = Arc::new(module);

    Ok((precompiled_bytes, module))
}

pub fn validate_module(
    contract_runtime: &ContractRuntime,
    module: &CompiledModule,
    state: ValueWrapper,
) -> Result<(), CompilerError> {
    contract_runtime
        .validate(module, &state)
        .map_err(map_runtime_error_to_compiler_error)
}

pub fn build_contract_record(
    hash: HashAlgorithm,
    contract_hash: DigestIdentifier,
    manifest_hash: DigestIdentifier,
    wasm_bytes: &[u8],
    precompiled_bytes: &[u8],
    engine_fingerprint: DigestIdentifier,
    toolchain_fingerprint: DigestIdentifier,
) -> Result<ContractArtifactRecord, CompilerError> {
    let wasm_hash = hash_bytes(hash, wasm_bytes, "wasm artifact")?;
    let cwasm_hash =
        hash_bytes(hash, precompiled_bytes, "cwasm artifact")?;

    Ok(ContractArtifactRecord {
        contract_hash,
        manifest_hash,
        wasm_hash,
        cwasm_hash,
        engine_fingerprint,
        toolchain_fingerprint,
    })
}

pub fn hash_bytes(
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

pub async fn toolchain_fingerprint(
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

pub fn metadata_matches(
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

#[cfg(feature = "test")]
pub async fn try_load_global_cache(
    hash: HashAlgorithm,
    contract_runtime: &Arc<ContractRuntime>,
    initial_value: Value,
    contract_hash: &DigestIdentifier,
    manifest_hash: &DigestIdentifier,
    engine_fingerprint: &DigestIdentifier,
    toolchain_fingerprint: &DigestIdentifier,
) -> Result<
    Option<(
        Arc<CompiledModule>,
        ContractArtifactRecord,
        &'static str,
        Vec<u8>,
        Vec<u8>,
    )>,
    CompilerError,
> {
    let cache_dir = global_cache_entry_dir(
        contract_hash,
        manifest_hash,
        engine_fingerprint,
        toolchain_fingerprint,
    );

    let persisted = match load_global_cache_metadata(&cache_dir).await
    {
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

    if !metadata_matches(
        &persisted,
        contract_hash,
        manifest_hash,
        engine_fingerprint,
        toolchain_fingerprint,
    ) {
        return Ok(None);
    }

    let wasm_bytes = match load_artifact_wasm_from(&cache_dir).await {
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
        hash_bytes(hash, &wasm_bytes, "global cache wasm artifact")?;
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
        load_artifact_precompiled_from(&cache_dir).await
    {
        let precompiled_hash = hash_bytes(
            hash,
            &precompiled_bytes,
            "global cache cwasm artifact",
        )?;
        if precompiled_hash == persisted.cwasm_hash
            && let Ok((_, module)) =
                precompile_module(contract_runtime, &wasm_bytes)
            && validate_module(
                contract_runtime,
                &module,
                ValueWrapper(initial_value.clone()),
            )
            .is_ok()
        {
            return Ok(Some((
                module,
                persisted,
                "global_cwasm_hit",
                wasm_bytes,
                precompiled_bytes,
            )));
        }
    }

    if let Ok((precompiled_bytes, module)) =
        precompile_module(contract_runtime, &wasm_bytes)
        && validate_module(
            contract_runtime,
            &module,
            ValueWrapper(initial_value),
        )
        .is_ok()
    {
        let refreshed_record = build_contract_record(
            hash,
            contract_hash.clone(),
            manifest_hash.clone(),
            &wasm_bytes,
            &precompiled_bytes,
            engine_fingerprint.clone(),
            toolchain_fingerprint.clone(),
        )?;

        if let Err(error) = persist_global_cache_artifact(
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
            module,
            refreshed_record,
            "global_wasm_hit",
            wasm_bytes,
            precompiled_bytes,
        )));
    }

    Ok(None)
}

pub fn map_runtime_error_to_compiler_error(
    error: RuntimeError,
) -> CompilerError {
    match error {
        // The wasmtime engine cannot be built: the host is broken, not the
        // contract — must never be reported as a contract failure.
        RuntimeError::EngineCreation(details) => {
            CompilerError::EngineCreation { details }
        }
        RuntimeError::PrecompileFailed(details) => {
            CompilerError::WasmPrecompileFailed { details }
        }
        RuntimeError::DeserializationFailed(details) => {
            CompilerError::WasmDeserializationFailed { details }
        }
        RuntimeError::InvalidModule(kind) => {
            CompilerError::InvalidModule { kind }
        }
        RuntimeError::EntryPointNotFound { function } => {
            CompilerError::EntryPointNotFound { function }
        }
        RuntimeError::ContractExecutionFailed(details) => {
            CompilerError::ContractExecutionFailed { details }
        }
        RuntimeError::FuelLimitError(details) => {
            CompilerError::FuelLimitError { details }
        }
        RuntimeError::InstantiationFailed(details) => {
            CompilerError::InstantiationFailed { details }
        }
        RuntimeError::MemoryAllocationFailed(details) => {
            CompilerError::MemoryAllocationFailed { details }
        }
        // These contexts deserialize bytes produced by the contract (its
        // result buffers and final state): garbage there is a deterministic
        // contract failure, not a host serialization problem.
        RuntimeError::SerializationError { context, details }
            if matches!(
                context,
                "execution result" | "final state json" | "init check result"
            ) =>
        {
            CompilerError::ContractExecutionFailed {
                details: format!(
                    "invalid contract output [{context}]: {details}"
                ),
            }
        }
        RuntimeError::SerializationError { context, details } => {
            CompilerError::SerializationError { context, details }
        }
    }
}
