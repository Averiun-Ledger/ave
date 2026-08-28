use std::time::{Duration, Instant};
use std::{collections::HashMap, path::Path, sync::Arc};

use ave_actors::{Actor, ActorContext, ActorError, ActorPath, Response};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use ave_compiler::CompilerClient;
use ave_contract_sdk::runtime::{CompiledModule, ContractRuntime};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::debug;

use crate::compilation::artifact::ArtifactData;
use crate::governance::contract_register::{
    ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
};
use crate::metrics::try_core_metrics;
use crate::system::ConfigHelper;

pub mod contract_compiler;
pub mod error;
pub mod temp_compiler;

pub use ave_compiler::ContractArtifactRecord;
pub use contract_compiler::{ContractCompiler, ContractCompilerMessage};
pub use temp_compiler::{TempCompiler, TempCompilerMessage};

use error::CompilerError;

#[derive(Debug, Clone)]
pub enum CompilerResponse {
    Ok,
    Error(CompilerError),
}

impl Response for CompilerResponse {}

/// Whether a compiler error is an infrastructure failure (compilers
/// unreachable, toolchain drift, attestation problems) rather than a
/// contract failure. Infrastructure errors retry; contract errors do not.
pub(crate) fn is_compiler_infra_error(error: &CompilerError) -> bool {
    matches!(
        error,
        CompilerError::CompilersUnavailable { .. }
            | CompilerError::ToolchainMismatch { .. }
            | CompilerError::InvalidAttestationSignature
            | CompilerError::AttestationMismatch { .. }
    )
}

/// Whether a compiler error is a fatal LOCAL problem (disk, artifact
/// register, missing helpers, engine, local serialization): the node is
/// broken and these must stay fatal — they never degrade. This is the
/// same family that maps to `EvaluatorError::InternalError` in
/// `evaluation/response.rs`; keep both in sync.
pub(crate) fn is_local_fatal_compiler_error(error: &CompilerError) -> bool {
    matches!(
        error,
        CompilerError::InvalidContractPath { .. }
            | CompilerError::DirectoryCreationFailed { .. }
            | CompilerError::FileWriteFailed { .. }
            | CompilerError::FileReadFailed { .. }
            | CompilerError::MissingHelper { .. }
            | CompilerError::ContractRegisterFailed { .. }
            | CompilerError::ToolchainFingerprintFailed { .. }
            | CompilerError::EngineCreation { .. }
            | CompilerError::SerializationError { .. }
    )
}

pub(crate) struct CompilerSupport;

/// TTL of a serving cache entry: after a contract change every evaluator
/// fetches the artifact at once (thundering herd), so the serving node
/// keeps the bytes in memory for a short window instead of re-reading
/// them from disk per request. Contract changes are rare, so the cache
/// must not live forever — the entry expires and the RAM is freed.
pub(crate) const SERVING_CACHE_TTL: Duration = Duration::from_secs(300);

/// An official artifact kept in memory for serving, with the instant it
/// was filled: drives the expiry and guards the eviction against late
/// timer messages of an already replaced entry.
#[derive(Debug, Clone)]
pub struct ServingCacheEntry {
    pub artifact: ArtifactData,
    pub filled_at: Instant,
}

impl CompilerSupport {
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

    async fn contract_runtime<A: Actor>(
        ctx: &ActorContext<A>,
    ) -> Result<Arc<ContractRuntime>, CompilerError> {
        ctx.system()
            .get_helper::<Arc<ContractRuntime>>("contract_runtime")
            .ok_or(CompilerError::MissingHelper {
                name: "contract_runtime",
            })
    }

    async fn compiler_client<A: Actor>(
        ctx: &ActorContext<A>,
    ) -> Result<Arc<CompilerClient>, CompilerError> {
        ctx.system()
            .get_helper::<Arc<CompilerClient>>("compiler_client")
            .ok_or(CompilerError::CompilersUnavailable {
                details: "no compiler endpoints configured".to_owned(),
            })
    }

    async fn contracts_helper<A: Actor>(
        ctx: &ActorContext<A>,
    ) -> Result<Arc<RwLock<HashMap<String, Arc<CompiledModule>>>>, ActorError>
    {
        ctx.system()
            .get_helper::<Arc<RwLock<HashMap<String, Arc<CompiledModule>>>>>(
                "contracts",
            )
            .ok_or_else(|| ActorError::Helper {
                name: "contracts".to_owned(),
                reason: "Not found".to_owned(),
            })
    }

    pub(crate) async fn compile_or_load_registered<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
        register_path: &ActorPath,
    ) -> Result<(Arc<CompiledModule>, ContractArtifactRecord), CompilerError>
    {
        let started_at = Instant::now();
        let result = async {
            let contract_hash = hash_borsh(&*hash.hasher(), &contract)
                .map_err(|e| CompilerError::SerializationError {
                    context: "contract hash",
                    details: e.to_string(),
                })?;
            let manifest = ave_compiler::compilation_toml();
            let manifest_hash = hash_borsh(&*hash.hasher(), &manifest)
                .map_err(|e| CompilerError::SerializationError {
                    context: "contract manifest hash",
                    details: e.to_string(),
                })?;

            // Payload format check (same position as the old
            // `prepare_contract_project`): a malformed payload is a
            // request error, not a build error.
            ave_compiler::validate_source_base64(contract)?;

            // The node has no toolchain: the engine fingerprint is local
            // (wasmtime), the toolchain fingerprint comes from the
            // compiler service.
            let contract_runtime = Self::contract_runtime(ctx).await?;
            let engine_fingerprint = contract_runtime
                .engine_fingerprint(hash)
                .map_err(ave_compiler::map_runtime_error_to_compiler_error)?;
            let client = Self::compiler_client(ctx).await?;

            if let Some((module, record, prepare_result)) =
                Self::load_registered_artifact(
                    hash,
                    ctx,
                    contract_name,
                    contract_path,
                    &initial_value,
                    register_path,
                    &contract_hash,
                    &manifest_hash,
                    &engine_fingerprint,
                    client.expected_toolchain(),
                )
                .await?
            {
                return Ok((module, record, prepare_result));
            }

            // Global test cache: only usable once the toolchain fingerprint
            // of the pool is known (after the first remote compile).
            #[cfg(feature = "test")]
            if let Some(toolchain_fingerprint) = client.last_toolchain().await
                && let Some((
                    module,
                    metadata,
                    prepare_result,
                    wasm_bytes,
                    precompiled_bytes,
                )) = ave_compiler::try_load_global_cache(
                    hash,
                    &contract_runtime,
                    initial_value.clone(),
                    &contract_hash,
                    &manifest_hash,
                    &engine_fingerprint,
                    &toolchain_fingerprint,
                )
                .await?
            {
                ave_compiler::persist_artifact(
                    contract_path,
                    &wasm_bytes,
                    &precompiled_bytes,
                )
                .await?;

                let register = ctx
                    .system()
                    .get_actor::<ContractRegister>(register_path)
                    .await
                    .map_err(|e| CompilerError::ContractRegisterFailed {
                        details: e.to_string(),
                    })?;
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

            // The node never compiles locally: the wasm comes from the
            // compiler pool (already verified by the client), is
            // precompiled and validated locally, and persisted.
            let outcome = client.compile(contract).await?;
            let (precompiled_bytes, module) = ave_compiler::precompile_module(
                &contract_runtime,
                &outcome.wasm,
            )?;
            ave_compiler::validate_module(
                &contract_runtime,
                &module,
                ValueWrapper(initial_value),
            )?;
            ave_compiler::persist_artifact(
                contract_path,
                &outcome.wasm,
                &precompiled_bytes,
            )
            .await?;

            let metadata = ave_compiler::build_contract_record(
                hash,
                contract_hash,
                manifest_hash,
                &outcome.wasm,
                &precompiled_bytes,
                engine_fingerprint,
                outcome.toolchain_fingerprint,
            )?;

            #[cfg(feature = "test")]
            {
                let global_cache_dir = ave_compiler::global_cache_entry_dir(
                    &metadata.contract_hash,
                    &metadata.manifest_hash,
                    &metadata.engine_fingerprint,
                    &metadata.toolchain_fingerprint,
                );
                if let Err(error) = ave_compiler::persist_global_cache_artifact(
                    &global_cache_dir,
                    &metadata,
                    &outcome.wasm,
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

            let register = ctx
                .system()
                .get_actor::<ContractRegister>(register_path)
                .await
                .map_err(|e| CompilerError::ContractRegisterFailed {
                    details: e.to_string(),
                })?;
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

    /// Loads the persisted artifact registered for `contract_name`,
    /// following the cwasm → wasm fallback chain and refreshing the
    /// artifact when only the wasm survived. Returns `Ok(None)` when
    /// there is no usable persisted artifact: the caller falls through
    /// to its own source of bytes (compiler pool or network fetch).
    /// `expected_toolchain`: `Some` pins the check to that toolchain;
    /// `None` is a deliberate no-op against the persisted record itself
    /// (level 1 of trust).
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn load_registered_artifact<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract_path: &Path,
        initial_value: &Value,
        register_path: &ActorPath,
        contract_hash: &DigestIdentifier,
        manifest_hash: &DigestIdentifier,
        engine_fingerprint: &DigestIdentifier,
        expected_toolchain: Option<DigestIdentifier>,
    ) -> Result<
        Option<(Arc<CompiledModule>, ContractArtifactRecord, &'static str)>,
        CompilerError,
    > {
        let register = ctx
            .system()
            .get_actor::<ContractRegister>(register_path)
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
            Ok(ContractRegisterResponse::Anchor(_)) => None,
            Ok(ContractRegisterResponse::Contracts(_)) => None,
            Ok(ContractRegisterResponse::Ok) => None,
            Err(e) => {
                return Err(CompilerError::ContractRegisterFailed {
                    details: e.to_string(),
                });
            }
        };

        let Some(persisted) = persisted else {
            return Ok(None);
        };

        let expected_toolchain = expected_toolchain
            .unwrap_or_else(|| persisted.toolchain_fingerprint.clone());
        if !ave_compiler::metadata_matches(
            &persisted,
            contract_hash,
            manifest_hash,
            engine_fingerprint,
            &expected_toolchain,
        ) {
            // Contract, engine or toolchain drift: the persisted bytes
            // are simply not the ones needed — not a manipulation, they
            // are left alone and the caller replaces them.
            return Ok(None);
        }

        let contract_runtime = Self::contract_runtime(ctx).await?;

        match ave_compiler::load_artifact_precompiled(contract_path).await {
            Ok(precompiled_bytes) => {
                let precompiled_hash = ave_compiler::hash_bytes(
                    hash,
                    &precompiled_bytes,
                    "persisted cwasm artifact",
                )?;
                if precompiled_hash == persisted.cwasm_hash {
                    match contract_runtime.load_precompiled(&precompiled_bytes)
                    {
                        Ok(module) => {
                            match ave_compiler::validate_module(
                                &contract_runtime,
                                &module,
                                ValueWrapper(initial_value.clone()),
                            ) {
                                Ok(()) => {
                                    return Ok(Some((
                                        Arc::new(module),
                                        persisted,
                                        "cwasm_hit",
                                    )));
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

        match ave_compiler::load_artifact_wasm(contract_path).await {
            Ok(wasm_bytes) => {
                let wasm_hash = ave_compiler::hash_bytes(
                    hash,
                    &wasm_bytes,
                    "persisted wasm artifact",
                )?;
                if wasm_hash == persisted.wasm_hash {
                    match ave_compiler::precompile_module(
                        &contract_runtime,
                        &wasm_bytes,
                    ) {
                        Ok((precompiled_bytes, module)) => {
                            match ave_compiler::validate_module(
                                &contract_runtime,
                                &module,
                                ValueWrapper(initial_value.clone()),
                            ) {
                                Ok(()) => {
                                    ave_compiler::persist_artifact(
                                        contract_path,
                                        &wasm_bytes,
                                        &precompiled_bytes,
                                    )
                                    .await?;
                                    let refreshed_record =
                                        ave_compiler::build_contract_record(
                                            hash,
                                            contract_hash.clone(),
                                            manifest_hash.clone(),
                                            &wasm_bytes,
                                            &precompiled_bytes,
                                            engine_fingerprint.clone(),
                                            persisted
                                                .toolchain_fingerprint
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

                                    return Ok(Some((
                                        module,
                                        refreshed_record,
                                        "wasm_hit",
                                    )));
                                }
                                Err(error) => {
                                    // The artifact is intact
                                    // (hash matched) and
                                    // precompiles: the value
                                    // is what fails. That is
                                    // a deterministic verdict
                                    // — recompiling the same
                                    // source fails the same
                                    // way, so do not waste a
                                    // build.
                                    debug!(
                                        error = %error,
                                        path = %contract_path.display(),
                                        "Persisted wasm artifact rejects the value"
                                    );
                                    return Err(error);
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

        // The persisted artifact could not be verified (unreadable,
        // hash mismatch or unusable bytes): presume it was or could have
        // been manipulated — discard it, so the caller rebuilds it from
        // its own source (compiler pool or network fetch).
        Self::discard_persisted_artifact(
            ctx,
            contract_name,
            contract_path,
            &register,
        )
        .await?;

        Ok(None)
    }

    /// Discards a persisted artifact whose verification failed:
    /// unreadable, hash mismatch or unusable bytes mean it was or could
    /// have been manipulated, so it must not survive. The ledger anchor
    /// is kept — it is a projection of the applied events, not of the
    /// bytes on disk.
    async fn discard_persisted_artifact<A: Actor>(
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract_path: &Path,
        register: &ave_actors::ActorRef<ContractRegister>,
    ) -> Result<(), CompilerError> {
        if let Err(error) = tokio::fs::remove_dir_all(contract_path).await
            && error.kind() != std::io::ErrorKind::NotFound
        {
            return Err(CompilerError::FileWriteFailed {
                path: contract_path.display().to_string(),
                details: error.to_string(),
            });
        }

        register
            .tell(ContractRegisterMessage::DeleteArtifact {
                contract_name: contract_name.to_owned(),
            })
            .await
            .map_err(|e| CompilerError::ContractRegisterFailed {
                details: e.to_string(),
            })?;

        // Best-effort: the in-memory module, if any, is stale the same
        // way the bytes were.
        if let Ok(contracts) = Self::contracts_helper(ctx).await {
            contracts.write().await.remove(contract_name);
        }

        Ok(())
    }

    /// Whether the official artifact of a contract is registered — the
    /// light check that answers an availability probe. The register is
    /// the authoritative source: the metadata only exists when the
    /// artifact was compiled, promoted or fetched and verified.
    pub(crate) async fn has_official_artifact<A: Actor>(
        ctx: &ActorContext<A>,
        contract_name: &str,
        register_path: &ActorPath,
    ) -> bool {
        let Ok(register) = ctx
            .system()
            .get_actor::<ContractRegister>(register_path)
            .await
        else {
            return false;
        };
        matches!(
            register
                .ask(ContractRegisterMessage::GetMetadata {
                    contract_name: contract_name.to_owned(),
                })
                .await,
            Ok(ContractRegisterResponse::Metadata(Some(_)))
        )
    }

    /// Serves the official artifact of a contract to another node. The
    /// governance version was already negotiated by the caller, so the
    /// official store holds exactly what the requester needs. The staged
    /// area is never served — until the event commits, the good contract
    /// is the previous one. Returns `None` when the artifact is missing
    /// or unreadable.
    pub(crate) async fn serve_official_artifact<A: Actor>(
        ctx: &ActorContext<A>,
        contract_name: &str,
        register_path: &ActorPath,
    ) -> Option<ArtifactData> {
        let config = ctx.system().get_helper::<ConfigHelper>("config")?;
        let contract_path =
            config.contracts_path.join("contracts").join(contract_name);

        let wasm_bytes =
            match ave_compiler::load_artifact_wasm(&contract_path).await {
                Ok(wasm_bytes) => wasm_bytes,
                Err(error) => {
                    debug!(
                        error = %error,
                        contract_name = %contract_name,
                        "Can not read official artifact to serve it"
                    );
                    return None;
                }
            };

        // Cache-hygiene metadata of the build, when registered.
        let toolchain_fingerprint = match ctx
            .system()
            .get_actor::<ContractRegister>(register_path)
            .await
        {
            Ok(register) => match register
                .ask(ContractRegisterMessage::GetMetadata {
                    contract_name: contract_name.to_owned(),
                })
                .await
            {
                Ok(ContractRegisterResponse::Metadata(Some(record))) => {
                    Some(record.toolchain_fingerprint)
                }
                _ => None,
            },
            Err(_) => None,
        };

        match ArtifactData::from_wasm(&wasm_bytes, toolchain_fingerprint) {
            Ok(artifact) => Some(artifact),
            Err(error) => {
                debug!(
                    error = %error,
                    contract_name = %contract_name,
                    "Can not prepare official artifact for network serving"
                );
                None
            }
        }
    }

    /// Registers an artifact fetched from the network: the wasm hash is
    /// recomputed and checked against the ledger anchor BEFORE anything
    /// is persisted, then the precompiled artifact is generated locally
    /// (wasmtime, no toolchain), the init check runs and the module is
    /// inserted into the in-memory cache — the same end state as a local
    /// compile.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn register_fetched_artifact<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
        register_path: &ActorPath,
        expected_wasm_hash: &DigestIdentifier,
        artifact: ArtifactData,
    ) -> Result<(Arc<CompiledModule>, ContractArtifactRecord), CompilerError>
    {
        let wasm = artifact.decompress().map_err(|error| {
            CompilerError::FetchedArtifactDecompressionFailed {
                details: error.to_string(),
            }
        })?;
        let wasm_hash = ave_compiler::hash_bytes(
            hash,
            &wasm,
            "fetched wasm artifact",
        )?;
        if &wasm_hash != expected_wasm_hash {
            return Err(CompilerError::FetchedArtifactMismatch {
                expected: expected_wasm_hash.to_string(),
                actual: wasm_hash.to_string(),
            });
        }

        let contract_hash =
            hash_borsh(&*hash.hasher(), &contract).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract hash",
                    details: e.to_string(),
                }
            })?;
        let manifest = ave_compiler::compilation_toml();
        let manifest_hash =
            hash_borsh(&*hash.hasher(), &manifest).map_err(|e| {
                CompilerError::SerializationError {
                    context: "contract manifest hash",
                    details: e.to_string(),
                }
            })?;

        let contract_runtime = Self::contract_runtime(ctx).await?;
        let engine_fingerprint = contract_runtime
            .engine_fingerprint(hash)
            .map_err(ave_compiler::map_runtime_error_to_compiler_error)?;

        let (precompiled_bytes, module) =
            ave_compiler::precompile_module(&contract_runtime, &wasm)?;
        ave_compiler::validate_module(
            &contract_runtime,
            &module,
            ValueWrapper(initial_value),
        )?;
        ave_compiler::persist_artifact(
            contract_path,
            &wasm,
            &precompiled_bytes,
        )
        .await?;

        // The build toolchain fingerprint comes from the serving node;
        // unknown (default) forces a recompile if this node ever becomes
        // a compiler with a pinned toolchain.
        let metadata = ave_compiler::build_contract_record(
            hash,
            contract_hash,
            manifest_hash,
            &wasm,
            &precompiled_bytes,
            engine_fingerprint,
            artifact.toolchain_fingerprint.unwrap_or_default(),
        )?;

        let register = ctx
            .system()
            .get_actor::<ContractRegister>(register_path)
            .await
            .map_err(|e| CompilerError::ContractRegisterFailed {
                details: e.to_string(),
            })?;
        register
            .tell(ContractRegisterMessage::SetMetadata {
                contract_name: contract_name.to_owned(),
                metadata: metadata.clone(),
            })
            .await
            .map_err(|e| CompilerError::ContractRegisterFailed {
                details: e.to_string(),
            })?;

        Ok((module, metadata))
    }
}
