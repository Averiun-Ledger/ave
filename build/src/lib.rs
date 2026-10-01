//! Deterministic contract compilation shared by the node
//! (`ave-core`) and the off-chain pin tooling.
//!
//! Single source of truth for: materializing a contract build
//! project (manifest, source, frozen lockfile, cargo config),
//! running the cargo build with the selected toolchain, and
//! attesting which toolchain produced the bytes. Callers own
//! everything else (staging, anchors, quorum, CLI, pins).
//!
//! Rules shared with `ave_common::build` (target, epoch, frozen
//! inputs): same inputs in, byte-identical config and procedure
//! out, on any machine with the pinned toolchain.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use ave_common::{
    build as rules,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use thiserror::Error;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;
use tokio::{fs, process::Command};

/// Compiled contract artifact file name, shared by every layout
/// (staging, official, scratch, off-chain builds).
pub const ARTIFACT_WASM: &str = "contract.wasm";

/// Failures of the contract build procedure. Callers map these to
/// their own taxonomy (deterministic contract errors vs local
/// infrastructure); nothing here decides that.
#[derive(Debug, Error)]
pub enum BuildError {
    #[error("cannot create directory {path}: {details}")]
    DirectoryCreationFailed { path: String, details: String },
    #[error("cannot write file {path}: {details}")]
    FileWriteFailed { path: String, details: String },
    #[error("cannot read file {path}: {details}")]
    FileReadFailed {
        path: String,
        details: String,
        kind: std::io::ErrorKind,
    },
    #[error("cargo build failed to spawn: {details}")]
    CargoSpawnFailed { details: String },
    #[error("cargo build failed")]
    CompilationFailed { stderr: String },
    #[error("contract build timed out after {secs}s")]
    BuildTimeout { secs: u64 },
    #[error("toolchain probe failed: {details}")]
    ToolchainProbeFailed { details: String },
    #[error("serialization failed in {context}: {details}")]
    SerializationError { context: &'static str, details: String },
}

/// Which cargo binary runs the build. `System` is the ambient cargo
/// (pre-pins behavior); `Rustup` runs isolated via `rustup run`
/// (concurrent builds with different toolchains can not interfere);
/// `Pinned` runs an explicit binary (the reproducible toolchain)
/// with `RUSTC` resolved to the selected toolchain.
pub enum CargoProgram<'a> {
    System,
    Rustup(&'a str),
    Pinned(&'a Path),
}

/// Everything a contract build needs, with paths exactly as the
/// caller lays them out (relative or absolute — always resolved
/// against the build directory, never derived by depth).
pub struct BuildRequest<'a> {
    /// Decoded contract source bytes (base64/zstd handled by callers).
    pub source: &'a [u8],
    /// Contract manifest template.
    pub manifest_toml: &'a str,
    /// Cargo config template (placeholders per `ave_common::build`).
    pub config_template: &'a str,
    /// Frozen dependency set, written next to the manifest so the
    /// build below can run `--locked`. `None` resolves fresh.
    pub lockfile: Option<&'a str>,
    /// Cargo target directory, as given.
    pub target_dir: PathBuf,
    /// Vendored sources directory, as given. Enables `--offline`.
    pub vendor_dir: Option<PathBuf>,
    /// Cargo home for the build (remapped, never leaks to artifacts).
    pub cargo_home: PathBuf,
    /// Resolved rustup toolchain selector (`""` = system cargo).
    pub toolchain: &'a str,
    /// Cargo binary selection.
    pub cargo: CargoProgram<'a>,
    /// Sysroot rust-src directory (remapped, never leaks).
    pub rust_src: PathBuf,
    /// rustc commit hash (remapped path root).
    pub rustc_commit: String,
    /// Pass `--offline` (requires vendored sources).
    pub offline: bool,
    /// Pass `--locked` (requires a frozen lockfile).
    pub locked: bool,
    /// Kill the build after this long. `None` waits indefinitely.
    pub timeout: Option<Duration>,
    /// On Unix, run in its own process group so a timeout reaps the
    /// whole build tree (cargo + rustc + linker) instead of
    /// orphaning it over a directory that is removed right after.
    pub kill_process_group: bool,
}

/// Sysroot rust-src path and commit hash of the SELECTED toolchain.
/// With the rust-src component installed, panic locations in
/// std/core/alloc embed the absolute sysroot path instead of the
/// canonical /rustc/<commit> one, breaking byte-reproducibility
/// across machines; the generated build config remaps it back to
/// the canonical form.
pub async fn query_sysroot(
    toolchain: &str,
) -> Result<(PathBuf, String), BuildError> {
    // Query the SELECTED toolchain, never the ambient one: remapping
    // the wrong sysroot leaks absolute paths into the artifact.
    let mut sysroot_cmd = if toolchain.is_empty() {
        Command::new("rustc")
    } else {
        let mut command = Command::new("rustup");
        command.arg("run").arg(toolchain).arg("rustc");
        command
    };
    let output = sysroot_cmd
        .arg("--print")
        .arg("sysroot")
        .output()
        .await
        .map_err(|e| BuildError::ToolchainProbeFailed {
            details: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(BuildError::ToolchainProbeFailed {
            details: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    let sysroot = String::from_utf8_lossy(&output.stdout).trim().to_owned();

    let mut version_cmd = if toolchain.is_empty() {
        Command::new("rustc")
    } else {
        let mut command = Command::new("rustup");
        command.arg("run").arg(toolchain).arg("rustc");
        command
    };
    let output = version_cmd
        .arg("--version")
        .arg("--verbose")
        .output()
        .await
        .map_err(|e| BuildError::ToolchainProbeFailed {
            details: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(BuildError::ToolchainProbeFailed {
            details: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    let commit = stdout
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .map(str::to_owned)
        .ok_or_else(|| BuildError::ToolchainProbeFailed {
            details: "rustc -vV output has no commit-hash".to_owned(),
        })?;

    Ok((rules::rust_src_dir(Path::new(&sysroot)), commit))
}

/// `rustc 1.95.0 (hash date)` → `1.95.0`: normalized, no host triple.
/// What compilers attest in their votes and validators compare
/// against the registry entry. Empty selects the system rustc.
pub async fn rustc_version(
    toolchain: &str,
) -> Result<String, BuildError> {
    let mut command = if toolchain.is_empty() {
        Command::new("rustc")
    } else {
        let mut command = Command::new("rustup");
        command.arg("run").arg(toolchain).arg("rustc");
        command
    };
    let output = command
        .arg("--version")
        .output()
        .await
        .map_err(|e| BuildError::ToolchainProbeFailed {
            details: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(BuildError::ToolchainProbeFailed {
            details: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    // `rustc 1.98.1 (hash date)`: the version token, normalized.
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .nth(1)
        .map(str::to_owned)
        .ok_or_else(|| BuildError::ToolchainProbeFailed {
            details: "unexpected rustc version output".to_owned(),
        })
}

/// Attests what built the bytes: `rustc -vV` plus the raw config
/// template (rustflags shape artifacts as much as the version, so a
/// flag change is a toolchain change). The caller passes its own
/// template (node and tool share the SDK one). Used for cache keys
/// and artifact records — never voted, never compared across nodes.
pub async fn toolchain_fingerprint(
    hash: HashAlgorithm,
    toolchain: &str,
    config_template: &str,
) -> Result<DigestIdentifier, BuildError> {
    // Fingerprint the SELECTED toolchain, never the ambient one: the
    // record must attest what built the bytes. Empty selects the
    // system rustc.
    let mut command = if toolchain.is_empty() {
        Command::new("rustc")
    } else {
        let mut command = Command::new("rustup");
        command.arg("run").arg(toolchain).arg("rustc");
        command
    };
    let output = command
        .arg("--version")
        .arg("--verbose")
        .output()
        .await
        .map_err(|e| BuildError::ToolchainProbeFailed {
            details: e.to_string(),
        })?;

    if !output.status.success() {
        return Err(BuildError::ToolchainProbeFailed {
            details: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }

    // The build configuration (rustflags and friends) shapes the artifact
    // bytes as much as the rustc version itself, so the raw template is
    // part of the fingerprint: a flag change is a toolchain change.
    let fingerprint_input = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        config_template
    );
    hash_borsh(&*hash.hasher(), &fingerprint_input).map_err(|e| {
        BuildError::SerializationError {
            context: "toolchain fingerprint",
            details: e.to_string(),
        }
    })
}

/// Materializes a contract build project: source, manifest, frozen
/// lockfile (when given) and rendered cargo config. Reads nothing
/// outside the given paths.
pub async fn prepare_project(
    contract_path: &Path,
    request: &BuildRequest<'_>,
) -> Result<(), BuildError> {
    let dir = contract_path.join("src");
    if !Path::new(&dir).exists() {
        fs::create_dir_all(&dir).await.map_err(|e| {
            BuildError::DirectoryCreationFailed {
                path: dir.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;
    }

    let cargo_config_dir = contract_path.join(".cargo");
    if !Path::new(&cargo_config_dir).exists() {
        fs::create_dir_all(&cargo_config_dir).await.map_err(|e| {
            BuildError::DirectoryCreationFailed {
                path: cargo_config_dir.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;
    }

    let cargo = contract_path.join("Cargo.toml");
    fs::write(&cargo, request.manifest_toml).await.map_err(|e| {
        BuildError::FileWriteFailed {
            path: cargo.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })?;

    let lib_rs = contract_path.join("src").join("lib.rs");
    fs::write(&lib_rs, request.source).await.map_err(|e| {
        BuildError::FileWriteFailed {
            path: lib_rs.to_string_lossy().to_string(),
            details: e.to_string(),
        }
    })?;

    // Frozen dependency set, when the caller provides one: written
    // next to the manifest so `--locked` below freezes versions
    // across machines and time.
    if let Some(lockfile) = request.lockfile {
        let lock = contract_path.join("Cargo.lock");
        fs::write(&lock, lockfile).await.map_err(|e| {
            BuildError::FileWriteFailed {
                path: lock.to_string_lossy().to_string(),
                details: e.to_string(),
            }
        })?;
    }

    let cargo_config = rules::render_contract_cargo_config(
        request.config_template,
        &request.target_dir,
        request.vendor_dir.as_deref(),
        &request.cargo_home,
        &request.rust_src,
        &request.rustc_commit,
    );
    let cargo_config_path = cargo_config_path(contract_path);
    fs::write(&cargo_config_path, cargo_config)
        .await
        .map_err(|e| BuildError::FileWriteFailed {
            path: cargo_config_path.to_string_lossy().to_string(),
            details: e.to_string(),
        })?;

    Ok(())
}

/// Runs the cargo build for a prepared project and returns the raw
/// wasm bytes. Stderr is collected in the background: on failure its
/// full text travels in the error (callers decide how much to log),
/// on timeout the reader is dropped with the killed tree.
pub async fn run_cargo_build(
    contract_path: &Path,
    request: &BuildRequest<'_>,
) -> Result<(), BuildError> {
    let cargo = contract_path.join("Cargo.toml");
    // A named rustup toolchain runs isolated (`rustup run`), never
    // through process-global env: concurrent builds with different
    // toolchains can not interfere. Empty selects the system cargo.
    let mut command = match &request.cargo {
        CargoProgram::System => Command::new("cargo"),
        CargoProgram::Rustup(name) if name.is_empty() => {
            Command::new("cargo")
        }
        CargoProgram::Rustup(name) => {
            let mut command = Command::new("rustup");
            command.arg("run").arg(name).arg("cargo");
            command
        }
        CargoProgram::Pinned(binary) => {
            let mut command = Command::new(binary);
            if !request.toolchain.is_empty() {
                // Pin rustc to the selected toolchain: resolve its
                // binary path through rustup (empty = system rustc
                // from PATH, as before).
                let rustc = rustc_binary(request.toolchain).await?;
                command.env("RUSTC", rustc);
            }
            command
        }
    };
    command
        .arg("build")
        .arg(format!("--manifest-path={}", cargo.to_string_lossy()))
        .arg("--target")
        .arg(rules::WASM_TARGET)
        .arg("--release")
        .current_dir(contract_path)
        .env("CARGO_HOME", &request.cargo_home)
        // Single source of truth (`ave_common::build`): no wall-clock
        // input may shape artifacts.
        .env("SOURCE_DATE_EPOCH", rules::SOURCE_DATE_EPOCH)
        .stdout(Stdio::null())
        .stderr(Stdio::piped());

    if request.offline {
        command.arg("--offline");
    }
    if request.locked {
        command.arg("--locked");
    }

    #[cfg(unix)]
    if request.kill_process_group {
        // Own process group: a timeout kills cargo and every
        // rustc/linker child with it, instead of orphaning them over
        // a build dir that is removed right after.
        command.process_group(0);
    }
    let mut child =
        command
            .spawn()
            .map_err(|e| BuildError::CargoSpawnFailed {
                details: e.to_string(),
            })?;

    let stderr = child.stderr.take();
    let reader = tokio::spawn(async move {
        let mut buf = Vec::new();
        if let Some(mut stderr) = stderr {
            let _ = stderr.read_to_end(&mut buf).await;
        }
        buf
    });

    let status = match request.timeout {
        Some(limit) => match timeout(limit, child.wait()).await {
            Ok(result) => result.map_err(|e| {
                BuildError::CargoSpawnFailed {
                    details: e.to_string(),
                }
            })?,
            Err(_) => {
                kill_build_tree(&mut child).await;
                reader.abort();
                return Err(BuildError::BuildTimeout {
                    secs: limit.as_secs(),
                });
            }
        },
        None => child.wait().await.map_err(|e| {
            BuildError::CargoSpawnFailed {
                details: e.to_string(),
            }
        })?,
    };

    if !status.success() {
        // The vote carries no details (stable wire taxonomy); the log
        // does, or failed builds are undebuggable in production.
        let stderr = reader.await.unwrap_or_default();
        return Err(BuildError::CompilationFailed {
            stderr: String::from_utf8_lossy(&stderr).to_string(),
        });
    }

    Ok(())
}

/// Builds contract source bytes into raw wasm: query sysroot,
/// prepare, build, load. One call for the common case.
pub async fn build_contract_wasm(
    contract_path: &Path,
    request: &BuildRequest<'_>,
) -> Result<Vec<u8>, BuildError> {
    prepare_project(contract_path, request).await?;
    run_cargo_build(contract_path, request).await?;
    load_compiled_wasm(contract_path, &request.target_dir).await
}

/// Output wasm of a finished build.
pub fn build_output_wasm_path(
    contract_path: &Path,
    target_dir: &Path,
) -> PathBuf {
    contract_path
        .join(target_dir)
        .join(rules::WASM_TARGET)
        .join("release")
        .join(ARTIFACT_WASM)
}

async fn load_compiled_wasm(
    contract_path: &Path,
    target_dir: &Path,
) -> Result<Vec<u8>, BuildError> {
    let wasm_path = build_output_wasm_path(contract_path, target_dir);
    fs::read(&wasm_path).await.map_err(|e| BuildError::FileReadFailed {
        path: wasm_path.to_string_lossy().to_string(),
        details: e.to_string(),
        kind: e.kind(),
    })
}

fn cargo_config_path(contract_path: &Path) -> PathBuf {
    contract_path.join(".cargo").join("config.toml")
}

/// Resolves the rustc binary of a named rustup toolchain
/// (`rustup which`), for pinning `RUSTC` under an explicit cargo.
async fn rustc_binary(toolchain: &str) -> Result<String, BuildError> {
    let output = Command::new("rustup")
        .arg("which")
        .arg("--toolchain")
        .arg(toolchain)
        .arg("rustc")
        .output()
        .await
        .map_err(|e| BuildError::ToolchainProbeFailed {
            details: e.to_string(),
        })?;
    if !output.status.success() {
        return Err(BuildError::ToolchainProbeFailed {
            details: String::from_utf8_lossy(&output.stderr).to_string(),
        });
    }
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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
        let _ = error;
    }
}

