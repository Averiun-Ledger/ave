#[cfg(feature = "test")]
use std::env;
use std::time::Duration;
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    sync::atomic::{AtomicU64, Ordering},
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
use tokio::io::AsyncWriteExt;
use tokio::time::timeout;
use tokio::{fs, process::Command};
use tracing::debug;

use super::error::CompilerError;

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

/// Largest contract source accepted once decoded and, when it carries the
/// zstd magic number, decompressed. Bounds memory against zip-bomb
/// payloads; production minified sources are a few KiB.
pub const MAX_CONTRACT_SOURCE_BYTES: usize = 1024 * 1024;

/// zstd frame magic number (little-endian 0xFD2FB528). A base64-decoded
/// contract payload starting with these bytes is a compressed source;
/// anything else is a plain UTF-8 source — a Rust source can never begin
/// with this non-UTF-8 prefix, so the formats are unambiguous and both
/// stay accepted (plain payloads in already-committed events keep
/// replaying).
const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Decodes a governance-event contract payload into source bytes.
///
/// Base64, then bounded zstd decompression when the decoded payload
/// carries the
/// zstd magic number. Deterministic and identical on every node.
pub fn decode_contract_source(
    contract: &str,
) -> Result<Vec<u8>, CompilerError> {
    let decoded = BASE64_STANDARD.decode(contract).map_err(|e| {
        CompilerError::Base64DecodeFailed {
            details: e.to_string(),
        }
    })?;
    if decoded.starts_with(&ZSTD_MAGIC) {
        return zstd::bulk::decompress(&decoded, MAX_CONTRACT_SOURCE_BYTES)
            .map_err(|e| CompilerError::SourceDecompressionFailed {
                details: e.to_string(),
            });
    }
    if decoded.len() > MAX_CONTRACT_SOURCE_BYTES {
        return Err(CompilerError::ContractSourceTooLarge {
            size: decoded.len(),
            max: MAX_CONTRACT_SOURCE_BYTES,
        });
    }
    Ok(decoded)
}

/// Validates that `contract` is a well-formed contract payload: base64
/// carrying a plain or zstd-compressed source within
/// [`MAX_CONTRACT_SOURCE_BYTES`].
///
/// The node runs this cheap local check before delegating a build to the
/// compiler: a malformed payload is a request error
/// ([`CompilerError::Base64DecodeFailed`] and friends), not a build
/// error, and must not be conflated with "the contract does not compile".
pub fn validate_contract_source(contract: &str) -> Result<(), CompilerError> {
    decode_contract_source(contract).map(|_| ())
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
    PathBuf::from(".").join("..").join("..").join(VENDOR_DIR)
}

/// Kills a timed-out cargo build with its whole process tree: on Unix
/// the build runs in its own process group, so one signal reaps cargo
/// and every rustc/linker child instead of orphaning them.
async fn kill_build_tree(child: &mut tokio::process::Child) {
    #[cfg(unix)]
    if let Some(pid) = child.id() {
        // SAFETY: `killpg` with `SIGKILL` touches only the build group
        // derived from our own child pid.
        let group_killed =
            unsafe { libc::killpg(pid as libc::pid_t, libc::SIGKILL) == 0 };
        if group_killed {
            return;
        }
    }
    if let Err(error) = child.kill().await {
        debug!(
            error = %error,
            "Failed to kill cargo build process after timeout"
        );
    }
}

fn build_output_wasm_path(contract_path: &Path) -> PathBuf {
    contract_path
        .join(BUILD_TARGET_DIR)
        .join("wasm32-unknown-unknown")
        .join("release")
        .join(ARTIFACT_WASM)
}

fn cargo_config(
    target_dir: &Path,
    vendor_dir: Option<&Path>,
    cargo_home: &Path,
    rust_src: &Path,
    rustc_commit: &str,
) -> String {
    let mut config =
        ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG.to_owned();
    // Template placeholders are built programmatically: a `{...}`
    // literal here would trip the formatting-args lint while being
    // exactly what the template needs.
    fn pattern(name: &str) -> String {
        format!("{{{name}}}")
    }
    // The placeholders sit inside quoted TOML strings: escape values
    // so adversarial paths can not break the manifest syntax (or, when
    // paths differ per machine, break determinism across compilers).
    fn escape_toml(value: &str) -> String {
        value.replace('\\', "\\\\").replace('"', "\\\"")
    }
    config = config
        .replace(&pattern("target_dir"), &escape_toml(&target_dir.to_string_lossy()))
        .replace(&pattern("cargo_home"), &escape_toml(&cargo_home.to_string_lossy()))
        .replace(&pattern("rust_src"), &escape_toml(&rust_src.to_string_lossy()))
        .replace(&pattern("rustc_commit"), &escape_toml(rustc_commit));

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

    // Own process group: a timeout kills cargo and every rustc/linker
    // child with it, instead of orphaning them over a build dir that
    // is removed right after.
    #[cfg(unix)]
    {
        command.process_group(0);
    }
    let mut child =
        command
            .spawn()
            .map_err(|e| CompilerError::CargoBuildFailed {
                details: e.to_string(),
            })?;

    let status = match timeout(BUILD_TIMEOUT, child.wait()).await {
        Ok(result) => result.map_err(|e| CompilerError::CargoBuildFailed {
            details: e.to_string(),
        })?,
        Err(_) => {
            kill_build_tree(&mut child).await;
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
    let source = decode_contract_source(contract)?;

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
    fs::write(&lib_rs, source).await.map_err(|e| {
        CompilerError::FileWriteFailed {
            path: lib_rs.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })?;

    let (rust_src, rustc_commit) = rustc_sysroot_rust_src().await?;
    let vendor_dir = contracts_root.join(VENDOR_DIR);
    let cargo_config = cargo_config(
        Path::new(BUILD_TARGET_DIR),
        vendor_dir.exists().then(vendor_dir_for_contract).as_deref(),
        &contracts_root.join(SHARED_CARGO_HOME_DIR),
        &rust_src,
        &rustc_commit,
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
        .map_err(|e| CompilerError::file_read(wasm_path.to_string_lossy(), e))
}

#[cfg(feature = "test")]
async fn load_artifact_wasm_from(
    base_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let wasm_path = artifact_wasm_path_in(base_path);
    fs::read(&wasm_path)
        .await
        .map_err(|e| CompilerError::file_read(wasm_path.to_string_lossy(), e))
}

pub async fn load_artifact_precompiled(
    contract_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let precompiled_path = artifact_precompiled_path(contract_path);
    fs::read(&precompiled_path).await.map_err(|e| {
        CompilerError::file_read(precompiled_path.to_string_lossy(), e)
    })
}

#[cfg(feature = "test")]
async fn load_artifact_precompiled_from(
    base_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let precompiled_path = artifact_precompiled_path_in(base_path);
    fs::read(&precompiled_path).await.map_err(|e| {
        CompilerError::file_read(precompiled_path.to_string_lossy(), e)
    })
}

async fn load_compiled_wasm(
    contract_path: &Path,
) -> Result<Vec<u8>, CompilerError> {
    let wasm_path = build_output_wasm_path(contract_path);
    fs::read(&wasm_path)
        .await
        .map_err(|e| CompilerError::file_read(wasm_path.to_string_lossy(), e))
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
    build_contract(contract_path, contracts_root.join(VENDOR_DIR).exists())
        .await?;

    load_compiled_wasm(contract_path).await
}

/// Unique suffix per atomic write: two writers can persist the same
/// artifact concurrently (two compile children building the same source
/// into the same staging directory). A fixed `.tmp` sibling makes one
/// writer's rename steal the other's temp file, and the loser's ENOENT
/// is a spurious local-fatal write error that crashes the node. The
/// content is identical either way — same source, same toolchain — so
/// the last rename simply wins.
static ATOMIC_WRITE_COUNTER: AtomicU64 = AtomicU64::new(0);

/// Atomic file write: write to a temp sibling, fsync it, rename over
/// the target and fsync the directory. A crash or power cut leaves
/// either the old bytes or the new ones, never a truncated file.
async fn write_file_atomic(
    dir: &Path,
    file_name: &str,
    bytes: &[u8],
) -> Result<(), CompilerError> {
    let target = dir.join(file_name);
    let tmp = dir.join(format!(
        "{file_name}.tmp.{}.{}",
        std::process::id(),
        ATOMIC_WRITE_COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    let result = async {
        let mut file = fs::File::create(&tmp).await?;
        file.write_all(bytes).await?;
        file.sync_all().await?;
        drop(file);
        fs::rename(&tmp, &target).await?;
        fs::File::open(dir).await?.sync_all().await?;
        Ok::<(), std::io::Error>(())
    }
    .await;
    if result.is_err() {
        let _ = fs::remove_file(&tmp).await;
    }
    result.map_err(|e| CompilerError::FileWriteFailed {
        path: target.to_string_lossy().to_string(),
        details: e.to_string(),
    })
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
    // A new directory entry lives in its parent: fsync the parent so a
    // crash can not lose the whole entry (only a recompile, never
    // corruption — but avoid even that). Best-effort: persistence of
    // the files themselves is already fsynced below.
    if let Some(parent) = contract_path.parent()
        && let Ok(dir) = fs::File::open(parent).await
        && let Err(e) = dir.sync_all().await
    {
        debug!(
            error = %e,
            path = %parent.display(),
            "Failed to fsync artifact parent directory"
        );
    }

    // wasm first, precompiled second: the precompiled file marks a
    // complete artifact (readers require it before trusting the wasm).
    write_file_atomic(contract_path, ARTIFACT_WASM, wasm_bytes).await?;
    write_file_atomic(contract_path, ARTIFACT_PRECOMPILED, precompiled_bytes)
        .await?;

    let legacy_metadata_path = legacy_artifact_metadata_path(contract_path);
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
        to_vec(metadata).map_err(|e| CompilerError::SerializationError {
            context: "global cache metadata",
            details: e.to_string(),
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
        CompilerError::file_read(metadata_path.to_string_lossy(), e)
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
    let cwasm_hash = hash_bytes(hash, precompiled_bytes, "cwasm artifact")?;

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
    // Slices serialize exactly like `Vec` in Borsh (length prefix plus raw
    // bytes), so hashing the slice directly keeps every digest identical
    // while sparing a multi-megabyte clone on hot paths.
    hash_borsh(&*hash.hasher(), &bytes).map_err(|e| {
        CompilerError::SerializationError {
            context,
            details: e.to_string(),
        }
    })
}

/// Sysroot rust-src path and commit hash of the active rustc. With the
/// rust-src component installed, panic locations in std/core/alloc embed
/// the absolute sysroot path instead of the canonical /rustc/<commit>
/// one, breaking byte-reproducibility across machines; the generated
/// build config remaps it back to the canonical form.
async fn rustc_sysroot_rust_src() -> Result<(PathBuf, String), CompilerError> {
    let output = Command::new("rustc")
        .arg("--print")
        .arg("sysroot")
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
    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_owned();

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
    let stdout = String::from_utf8_lossy(&output.stdout);
    let commit = stdout
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .map(str::to_owned)
        .ok_or_else(|| CompilerError::ToolchainFingerprintFailed {
            details: "rustc -vV output has no commit-hash".to_owned(),
        })?;

    Ok((
        PathBuf::from(sysroot)
            .join("lib")
            .join("rustlib")
            .join("src")
            .join("rust"),
        commit,
    ))
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

    // The build configuration (rustflags and friends) shapes the artifact
    // bytes as much as the rustc version itself, so the raw template is
    // part of the fingerprint: a flag change is a toolchain change.
    let fingerprint_input = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        ave_contract_sdk::runtime::CONTRACT_CARGO_CONFIG
    );
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
        && persisted.toolchain_fingerprint == *expected_toolchain_fingerprint
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

    let persisted = match load_global_cache_metadata(&cache_dir).await {
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

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;

    /// Distinct fingerprints per case so parallel tests never share a
    /// global cache entry.
    fn test_fingerprints(
        tag: &str,
    ) -> (
        DigestIdentifier,
        DigestIdentifier,
        DigestIdentifier,
        DigestIdentifier,
    ) {
        let hash = HashAlgorithm::Blake3;
        let digest = |label: &str| {
            hash_borsh(
                &*hash.hasher(),
                &format!("global-cache-test-{tag}-{label}"),
            )
            .expect("hashing a static label must succeed")
        };
        (
            digest("contract"),
            digest("manifest"),
            digest("engine"),
            digest("toolchain"),
        )
    }

    /// Corrupt or missing global cache entries must be a clean miss
    /// (`None` → fall through to the compiler pool), never a bad module:
    /// a poisoned shared cache would silently corrupt the whole suite.
    #[tokio::test]
    async fn global_cache_integrity_guards() {
        let runtime = Arc::new(
            ContractRuntime::new(None).expect("runtime must be created"),
        );

        // Case 1: corrupt metadata.borsh (invalid borsh) → miss.
        let (contract, manifest, engine, toolchain) = test_fingerprints("meta");
        let cache_dir =
            global_cache_entry_dir(&contract, &manifest, &engine, &toolchain);
        fs::create_dir_all(&cache_dir)
            .await
            .expect("cache dir must be created");
        fs::write(global_cache_metadata_path(&cache_dir), b"not borsh")
            .await
            .expect("metadata must be written");
        let result = try_load_global_cache(
            HashAlgorithm::Blake3,
            &runtime,
            Value::Null,
            &contract,
            &manifest,
            &engine,
            &toolchain,
        )
        .await
        .expect("corrupt metadata must be a miss, not an error");
        assert!(result.is_none(), "corrupt metadata must not be served");
        let _ = fs::remove_dir_all(&cache_dir).await;

        // Case 2: valid metadata, but the wasm bytes do not match the
        // recorded hash → miss.
        let (contract, manifest, engine, toolchain) = test_fingerprints("wasm");
        let cache_dir =
            global_cache_entry_dir(&contract, &manifest, &engine, &toolchain);
        let wasm_bytes = b"fake wasm".to_vec();
        let precompiled_bytes = b"fake cwasm".to_vec();
        let mut record = build_contract_record(
            HashAlgorithm::Blake3,
            contract.clone(),
            manifest.clone(),
            &wasm_bytes,
            &precompiled_bytes,
            engine.clone(),
            toolchain.clone(),
        )
        .expect("record must be built");
        // Poison the record: the hash no longer describes the bytes.
        record.wasm_hash = hash_bytes(
            HashAlgorithm::Blake3,
            b"different bytes",
            "poisoned wasm hash",
        )
        .expect("hash must be computed");
        persist_global_cache_artifact(
            &cache_dir,
            &record,
            &wasm_bytes,
            &precompiled_bytes,
        )
        .await
        .expect("artifact must be persisted");
        let result = try_load_global_cache(
            HashAlgorithm::Blake3,
            &runtime,
            Value::Null,
            &contract,
            &manifest,
            &engine,
            &toolchain,
        )
        .await
        .expect("corrupt wasm must be a miss, not an error");
        assert!(result.is_none(), "corrupt wasm must not be served");
        let _ = fs::remove_dir_all(&cache_dir).await;

        // Case 3: lookup under a toolchain key with no entry → miss.
        let (contract, manifest, engine, _) = test_fingerprints("toolchain");
        let (_, _, _, absent_toolchain) = test_fingerprints("absent");
        let result = try_load_global_cache(
            HashAlgorithm::Blake3,
            &runtime,
            Value::Null,
            &contract,
            &manifest,
            &engine,
            &absent_toolchain,
        )
        .await
        .expect("absent entry must be a miss, not an error");
        assert!(result.is_none(), "unknown toolchain key must be a miss");
    }

    /// Pins for the contract payload wire format: base64 carrying a plain
    /// or zstd-compressed source, sniffed by magic number and bounded at
    /// [`MAX_CONTRACT_SOURCE_BYTES`] once decoded. The sniffing and the
    /// bound are consensus determinism — any drift between nodes breaks
    /// the compilation quorum.
    #[test]
    fn decode_contract_source_format_and_bounds() {
        // Plain roundtrip.
        let plain = b"fn contract() { /* logic */ }".to_vec();
        let encoded = BASE64_STANDARD.encode(&plain);
        let decoded =
            decode_contract_source(&encoded).expect("plain source must decode");
        assert_eq!(decoded, plain);

        // zstd roundtrip: the magic number selects decompression.
        let compressed =
            zstd::bulk::compress(&plain, 3).expect("compression must succeed");
        let encoded = BASE64_STANDARD.encode(&compressed);
        let decoded =
            decode_contract_source(&encoded).expect("zstd source must decode");
        assert_eq!(decoded, plain);

        // Truncated base64 is a payload error, never a build error.
        let truncated = &encoded[..encoded.len() - 1];
        let err = decode_contract_source(truncated)
            .expect_err("truncated base64 must fail");
        assert!(
            matches!(err, CompilerError::Base64DecodeFailed { .. }),
            "truncated base64 must fail with Base64DecodeFailed, got {err}"
        );

        // zstd magic followed by a corrupt payload is a decompression
        // failure, not a base64 one.
        let mut corrupt = ZSTD_MAGIC.to_vec();
        corrupt.extend_from_slice(&[0u8; 16]);
        let encoded = BASE64_STANDARD.encode(&corrupt);
        let err = decode_contract_source(&encoded)
            .expect_err("corrupt zstd payload must fail");
        assert!(
            matches!(err, CompilerError::SourceDecompressionFailed { .. }),
            "corrupt zstd payload must fail with SourceDecompressionFailed, \
             got {err}"
        );

        // Zip-bomb: compresses far under the limit but expands past it;
        // the bounded decompressor must refuse it.
        let bomb = vec![b'x'; MAX_CONTRACT_SOURCE_BYTES + 1];
        let compressed =
            zstd::bulk::compress(&bomb, 3).expect("compression must succeed");
        assert!(
            compressed.len() <= MAX_CONTRACT_SOURCE_BYTES,
            "test premise: the bomb must compress under the limit"
        );
        let encoded = BASE64_STANDARD.encode(&compressed);
        let err =
            decode_contract_source(&encoded).expect_err("zip-bomb must fail");
        assert!(
            matches!(err, CompilerError::SourceDecompressionFailed { .. }),
            "zip-bomb must fail with SourceDecompressionFailed, got {err}"
        );

        // A plain source past the limit is rejected by size.
        let oversized = vec![b'x'; MAX_CONTRACT_SOURCE_BYTES + 1];
        let encoded = BASE64_STANDARD.encode(&oversized);
        let err = decode_contract_source(&encoded)
            .expect_err("oversized plain source must fail");
        assert!(
            matches!(
                err,
                CompilerError::ContractSourceTooLarge { size, max }
                if size == MAX_CONTRACT_SOURCE_BYTES + 1
                    && max == MAX_CONTRACT_SOURCE_BYTES
            ),
            "oversized plain source must fail with ContractSourceTooLarge, \
             got {err}"
        );
    }
}
