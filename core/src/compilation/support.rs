use std::time::{Duration, Instant};
use std::{collections::HashMap, path::Path, sync::Arc};

use ave_actors::{Actor, ActorContext, ActorError, ActorPath, Response};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, hash_borsh},
};
use ave_contract_sdk::runtime::{CompiledModule, ContractRuntime};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::{debug, warn};

use super::client::CompilerClient;
use super::error::CompilerError;
use super::pipeline;
use crate::compilation::artifact::ArtifactData;
use crate::governance::contract_register::{
    ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
};
use crate::metrics::try_core_metrics;
use crate::system::ConfigHelper;

pub use super::pipeline::ContractArtifactRecord;

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
            | CompilerError::MissingArtifactAnchor { .. }
            | CompilerError::ArtifactAnchorMismatch { .. }
    )
}

/// Whether recovery may retry this local failure. `NotFound` is deliberately
/// absent: a missing artifact is rebuilt immediately, not retried as I/O.
pub(crate) fn is_retryable_compiler_recovery_error(
    error: &CompilerError,
) -> bool {
    matches!(
        error,
        CompilerError::CompilersUnavailable { .. }
            | CompilerError::FileReadFailed {
                kind:
                    std::io::ErrorKind::Interrupted
                    | std::io::ErrorKind::WouldBlock
                    | std::io::ErrorKind::TimedOut,
                ..
            }
    )
}

pub(crate) struct CompilerSupport;

/// TTL of a serving cache entry: after a contract change every evaluator
/// fetches the artifact at once (thundering herd), so the serving node
/// keeps the bytes in memory for a short window instead of re-reading
/// them from disk per request. Contract changes are rare, so the cache
/// must not live forever — the entry expires and the RAM is freed.
pub(crate) const SERVING_CACHE_TTL: Duration = Duration::from_secs(300);

/// Backoff between artifact healing attempts: a healed artifact is
/// needed for sure, so healing never gives up on transient failures —
/// the backoff is what keeps the retry cheap. Same policy as the fetch
/// cycle timeoff.
#[cfg(any(test, feature = "test"))]
pub(crate) const HEAL_RETRY_BASE_MS: u64 = 1_000;
/// Backoff between artifact healing attempts: a healed artifact is
/// needed for sure, so healing never gives up on transient failures —
/// the backoff is what keeps the retry cheap. Same policy as the fetch
/// cycle timeoff.
#[cfg(not(any(test, feature = "test")))]
pub(crate) const HEAL_RETRY_BASE_MS: u64 = 5_000;

#[cfg(any(test, feature = "test"))]
pub(crate) const HEAL_RETRY_MAX_MS: u64 = 5_000;
#[cfg(not(any(test, feature = "test")))]
pub(crate) const HEAL_RETRY_MAX_MS: u64 = 60_000;

/// Outcome of serving an official artifact: the bytes were verified
/// against the registered metadata, there is nothing to serve (the
/// requester fails over to another peer), or the persisted bytes failed
/// verification and were discarded — the caller re-obtains the artifact
/// (a compiler recompiles against the ledger anchor, an evaluator
/// fetches from the network again).
#[derive(Debug)]
pub(crate) enum ServedArtifact {
    Verified(ArtifactData),
    Missing,
    Corrupt,
}

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

    pub(crate) async fn contract_runtime<A: Actor>(
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

    pub(crate) async fn contracts_helper<A: Actor>(
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
        expected_wasm_hash: Option<&DigestIdentifier>,
    ) -> Result<(Arc<CompiledModule>, ContractArtifactRecord), CompilerError>
    {
        let started_at = Instant::now();
        let result = async {
            let contract_hash = hash_borsh(&*hash.hasher(), &contract)
                .map_err(|e| CompilerError::SerializationError {
                    context: "contract hash",
                    details: e.to_string(),
                })?;
            let manifest = pipeline::compilation_toml();
            let manifest_hash = hash_borsh(&*hash.hasher(), &manifest)
                .map_err(|e| CompilerError::SerializationError {
                    context: "contract manifest hash",
                    details: e.to_string(),
                })?;

            // Payload format check (same position as the old
            // `prepare_contract_project`): a malformed payload is a
            // request error, not a build error.
            pipeline::validate_source_base64(contract)?;

            // The engine fingerprint is local. A valid persisted artifact
            // does not need the compiler pool, so defer its lookup until a
            // rebuild is actually required.
            let contract_runtime = Self::contract_runtime(ctx).await?;
            let engine_fingerprint = contract_runtime
                .engine_fingerprint(hash)
                .map_err(pipeline::map_runtime_error_to_compiler_error)?;

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
                    None,
                    expected_wasm_hash,
                )
                .await?
            {
                return Ok((module, record, prepare_result));
            }

            let client = Self::compiler_client(ctx).await?;

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
                )) = pipeline::try_load_global_cache(
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
                if let Some(expected) = expected_wasm_hash
                    && metadata.wasm_hash != *expected
                {
                    return Err(CompilerError::ArtifactAnchorMismatch {
                        expected: expected.to_string(),
                        actual: metadata.wasm_hash.to_string(),
                    });
                }
                pipeline::persist_artifact(
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
            let wasm_hash = pipeline::hash_bytes(
                hash,
                &outcome.wasm,
                "compiler pool wasm artifact",
            )?;
            if let Some(expected) = expected_wasm_hash
                && wasm_hash != *expected
            {
                return Err(CompilerError::ArtifactAnchorMismatch {
                    expected: expected.to_string(),
                    actual: wasm_hash.to_string(),
                });
            }
            let (precompiled_bytes, module) = pipeline::precompile_module(
                &contract_runtime,
                &outcome.wasm,
            )?;
            pipeline::validate_module(
                &contract_runtime,
                &module,
                ValueWrapper(initial_value),
            )?;
            pipeline::persist_artifact(
                contract_path,
                &outcome.wasm,
                &precompiled_bytes,
            )
            .await?;

            let metadata = pipeline::build_contract_record(
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
                let global_cache_dir = pipeline::global_cache_entry_dir(
                    &metadata.contract_hash,
                    &metadata.manifest_hash,
                    &metadata.engine_fingerprint,
                    &metadata.toolchain_fingerprint,
                );
                if let Err(error) = pipeline::persist_global_cache_artifact(
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
        expected_wasm_hash: Option<&DigestIdentifier>,
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

        // An anchor authorizes raw wasm even when local metadata was lost.
        // Metadata only gates a fast cwasm hit and carries cache hygiene.
        if persisted.is_none() && expected_wasm_hash.is_none() {
            return Ok(None);
        }

        let metadata_matches = persisted.as_ref().is_some_and(|persisted| {
            let expected_toolchain = expected_toolchain
                .clone()
                .unwrap_or_else(|| persisted.toolchain_fingerprint.clone());
            pipeline::metadata_matches(
                persisted,
                contract_hash,
                manifest_hash,
                engine_fingerprint,
                &expected_toolchain,
            )
        });
        let persisted_matches_anchor = persisted.as_ref().is_none_or(|persisted| {
            expected_wasm_hash
                .is_none_or(|expected_wasm_hash| persisted.wasm_hash == *expected_wasm_hash)
        });

        // Without a ledger anchor, metadata still decides whether these
        // bytes belong to the source requested by a regular compilation.
        if !metadata_matches && expected_wasm_hash.is_none() {
            return Ok(None);
        }

        let contract_runtime = Self::contract_runtime(ctx).await?;

        if metadata_matches && persisted_matches_anchor {
            let persisted = persisted.as_ref().ok_or_else(|| {
                CompilerError::SerializationError {
                    context: "persisted contract metadata",
                    details: "metadata unexpectedly missing".to_owned(),
                }
            })?;
            match pipeline::load_artifact_precompiled(contract_path).await {
            Ok(precompiled_bytes) => {
                let precompiled_hash = pipeline::hash_bytes(
                    hash,
                    &precompiled_bytes,
                    "persisted cwasm artifact",
                )?;
                if precompiled_hash == persisted.cwasm_hash {
                    match contract_runtime.load_precompiled(&precompiled_bytes)
                    {
                        Ok(module) => {
                            match pipeline::validate_module(
                                &contract_runtime,
                                &module,
                                ValueWrapper(initial_value.clone()),
                            ) {
                                Ok(()) => {
                                    return Ok(Some((
                                        Arc::new(module),
                                        persisted.clone(),
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
        }

        match pipeline::load_artifact_wasm(contract_path).await {
            Ok(wasm_bytes) => {
                let wasm_hash = pipeline::hash_bytes(
                    hash,
                    &wasm_bytes,
                    "persisted wasm artifact",
                )?;
                if persisted.as_ref().is_none_or(|persisted| {
                    wasm_hash == persisted.wasm_hash
                })
                    && expected_wasm_hash
                        .is_none_or(|expected_wasm_hash| wasm_hash == *expected_wasm_hash)
                {
                    match pipeline::precompile_module(
                        &contract_runtime,
                        &wasm_bytes,
                    ) {
                        Ok((precompiled_bytes, module)) => {
                            match pipeline::validate_module(
                                &contract_runtime,
                                &module,
                                ValueWrapper(initial_value.clone()),
                            ) {
                                Ok(()) => {
                                    pipeline::persist_artifact(
                                        contract_path,
                                        &wasm_bytes,
                                        &precompiled_bytes,
                                    )
                                    .await?;
                                    let refreshed_record =
                                        pipeline::build_contract_record(
                                            hash,
                                            contract_hash.clone(),
                                            manifest_hash.clone(),
                                            &wasm_bytes,
                                            &precompiled_bytes,
                                            engine_fingerprint.clone(),
                                            persisted
                                                .as_ref()
                                                .map_or_else(
                                                    DigestIdentifier::default,
                                                    |persisted| {
                                                        persisted
                                                            .toolchain_fingerprint
                                                            .clone()
                                                    },
                                                ),
                                        )?;

                                    register
                                        .tell(
                                            ContractRegisterMessage::SetMetadata {
                                                contract_name: contract_name
                                                    .to_owned(),
                                                metadata: refreshed_record.clone(),
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
                        expected = ?persisted.as_ref().map(|persisted| &persisted.wasm_hash),
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
        // its own source (compiler pool or network fetch). The
        // in-memory module goes with it: it was never verified.
        Self::discard_persisted_artifact(
            ctx,
            contract_name,
            contract_path,
            &register,
            true,
        )
        .await?;

        Ok(None)
    }

    /// Recovers an official compiler artifact from local storage or the
    /// compiler pool. The ledger anchor is the only authority accepted for
    /// the wasm bytes; cache metadata merely avoids unnecessary work.
    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn recover_official_artifact<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
        register_path: &ActorPath,
    ) -> Result<Arc<CompiledModule>, CompilerError>
    {
        let register = ctx
            .system()
            .get_actor::<ContractRegister>(register_path)
            .await
            .map_err(|e| CompilerError::ContractRegisterFailed {
                details: e.to_string(),
            })?;
        let anchor = match register
            .ask(ContractRegisterMessage::GetAnchor {
                contract_name: contract_name.to_owned(),
            })
            .await
        {
            Ok(ContractRegisterResponse::Anchor(Some(anchor))) => anchor,
            Ok(_) => {
                return Err(CompilerError::MissingArtifactAnchor {
                    contract_name: contract_name.to_owned(),
                });
            }
            Err(error) => {
                return Err(CompilerError::ContractRegisterFailed {
                    details: error.to_string(),
                });
            }
        };

        // A valid cached wasm cannot make a malformed committed source
        // acceptable: the next recovery would be unable to reproduce it.
        pipeline::validate_source_base64(contract)?;

        let contract_hash = hash_borsh(&*hash.hasher(), &contract).map_err(|e| {
            CompilerError::SerializationError {
                context: "contract hash",
                details: e.to_string(),
            }
        })?;
        let manifest = pipeline::compilation_toml();
        let manifest_hash = hash_borsh(&*hash.hasher(), &manifest).map_err(|e| {
            CompilerError::SerializationError {
                context: "contract manifest hash",
                details: e.to_string(),
            }
        })?;
        let contract_runtime = Self::contract_runtime(ctx).await?;
        let engine_fingerprint = contract_runtime
            .engine_fingerprint(hash)
            .map_err(pipeline::map_runtime_error_to_compiler_error)?;
        if let Some((module, _, _)) = Self::load_registered_artifact(
            hash,
            ctx,
            contract_name,
            contract_path,
            &initial_value,
            register_path,
            &contract_hash,
            &manifest_hash,
            &engine_fingerprint,
            None,
            Some(&anchor),
        )
        .await?
        {
            return Ok(module);
        }

        let (module, _) = Self::compile_or_load_registered(
            hash,
            ctx,
            contract_name,
            contract,
            contract_path,
            initial_value,
            register_path,
            Some(&anchor),
        )
        .await?;
        Ok(module)
    }

    /// Discards a persisted artifact whose verification failed:
    /// unreadable, hash mismatch or unusable bytes mean it was or could
    /// have been manipulated, so it must not survive. The ledger anchor
    /// is kept — it is a projection of the applied events, not of the
    /// bytes on disk. `evict_module` drops the in-memory module too: the
    /// load path does (its module was never verified), the serving path
    /// does not (its module came from a verified load and keeps
    /// evaluating while the artifact is re-obtained).
    async fn discard_persisted_artifact<A: Actor>(
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract_path: &Path,
        register: &ave_actors::ActorRef<ContractRegister>,
        evict_module: bool,
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

        // Best-effort eviction, only when the in-memory module is stale
        // the same way the bytes were.
        if evict_module
            && let Ok(contracts) = Self::contracts_helper(ctx).await
        {
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
    /// is the previous one.
    ///
    /// The bytes are verified against the registered metadata before
    /// serving: a node must never hand out an artifact it cannot prove
    /// correct. A mismatch discards the persisted artifact (the anchor
    /// is kept) and reports `Corrupt`, so the caller re-obtains the
    /// artifact. Without metadata there is nothing to verify against —
    /// nothing is served and nothing is discarded.
    pub(crate) async fn serve_official_artifact<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        register_path: &ActorPath,
    ) -> Result<ServedArtifact, CompilerError> {
        let Some(config) = ctx.system().get_helper::<ConfigHelper>("config")
        else {
            return Ok(ServedArtifact::Missing);
        };
        let contract_path =
            config.contracts_path.join("contracts").join(contract_name);

        let register = ctx
            .system()
            .get_actor::<ContractRegister>(register_path)
            .await
            .map_err(|e| CompilerError::ContractRegisterFailed {
                details: e.to_string(),
            })?;
        let record = match register
            .ask(ContractRegisterMessage::GetMetadata {
                contract_name: contract_name.to_owned(),
            })
            .await
        {
            Ok(ContractRegisterResponse::Metadata(record)) => record,
            Ok(_) => None,
            Err(error) => {
                return Err(CompilerError::ContractRegisterFailed {
                    details: error.to_string(),
                });
            }
        };
        let Some(record) = record else {
            return Ok(ServedArtifact::Missing);
        };

        let wasm_bytes =
            match pipeline::load_artifact_wasm(&contract_path).await {
                Ok(wasm_bytes) => wasm_bytes,
                Err(error) => {
                    debug!(
                        error = %error,
                        contract_name = %contract_name,
                        "Can not read official artifact to serve it"
                    );
                    return Ok(ServedArtifact::Missing);
                }
            };

        let wasm_hash =
            pipeline::hash_bytes(hash, &wasm_bytes, "served wasm artifact")?;
        if wasm_hash != record.wasm_hash {
            warn!(
                expected = %record.wasm_hash,
                actual = %wasm_hash,
                contract_name = %contract_name,
                "Persisted official artifact failed verification before serving, discarding it"
            );
            Self::discard_persisted_artifact(
                ctx,
                contract_name,
                &contract_path,
                &register,
                false,
            )
            .await?;
            return Ok(ServedArtifact::Corrupt);
        }

        match ArtifactData::from_wasm(
            &wasm_bytes,
            Some(record.toolchain_fingerprint),
        ) {
            Ok(artifact) => Ok(ServedArtifact::Verified(artifact)),
            Err(error) => {
                debug!(
                    error = %error,
                    contract_name = %contract_name,
                    "Can not prepare official artifact for network serving"
                );
                Ok(ServedArtifact::Missing)
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
        let wasm_hash = pipeline::hash_bytes(
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
        let manifest = pipeline::compilation_toml();
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
            .map_err(pipeline::map_runtime_error_to_compiler_error)?;

        let (precompiled_bytes, module) =
            pipeline::precompile_module(&contract_runtime, &wasm)?;
        pipeline::validate_module(
            &contract_runtime,
            &module,
            ValueWrapper(initial_value),
        )?;
        pipeline::persist_artifact(
            contract_path,
            &wasm,
            &precompiled_bytes,
        )
        .await?;

        // The build toolchain fingerprint comes from the serving node;
        // unknown (default) forces a recompile if this node ever becomes
        // a compiler with a pinned toolchain.
        let metadata = pipeline::build_contract_record(
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

#[cfg(test)]
mod tests {
    use super::super::error::InvalidModuleKind;
    use super::*;

    fn sample_errors() -> Vec<CompilerError> {
        vec![
            CompilerError::InvalidContractPath {
                path: "p".to_owned(),
                details: "d".to_owned(),
            },
            CompilerError::Base64DecodeFailed {
                details: "d".to_owned(),
            },
            CompilerError::DirectoryCreationFailed {
                path: "p".to_owned(),
                details: "d".to_owned(),
            },
            CompilerError::FileWriteFailed {
                path: "p".to_owned(),
                details: "d".to_owned(),
            },
            CompilerError::FileReadFailed {
                path: "p".to_owned(),
                kind: std::io::ErrorKind::NotFound,
                details: "d".to_owned(),
            },
            CompilerError::FileReadFailed {
                path: "p".to_owned(),
                kind: std::io::ErrorKind::Interrupted,
                details: "d".to_owned(),
            },
            CompilerError::FileReadFailed {
                path: "p".to_owned(),
                kind: std::io::ErrorKind::WouldBlock,
                details: "d".to_owned(),
            },
            CompilerError::FileReadFailed {
                path: "p".to_owned(),
                kind: std::io::ErrorKind::TimedOut,
                details: "d".to_owned(),
            },
            CompilerError::CargoBuildFailed {
                details: "d".to_owned(),
            },
            CompilerError::BuildTimeout { secs: 1 },
            CompilerError::CompilationFailed,
            CompilerError::CompilersUnavailable {
                details: "d".to_owned(),
            },
            CompilerError::ToolchainMismatch {
                expected: "e".to_owned(),
                actual: "a".to_owned(),
            },
            CompilerError::InvalidAttestationSignature,
            CompilerError::AttestationMismatch {
                expected: "e".to_owned(),
                actual: "a".to_owned(),
            },
            CompilerError::MissingHelper { name: "h" },
            CompilerError::ContractRegisterFailed {
                details: "d".to_owned(),
            },
            CompilerError::ToolchainFingerprintFailed {
                details: "d".to_owned(),
            },
            CompilerError::WasmPrecompileFailed {
                details: "d".to_owned(),
            },
            CompilerError::WasmDeserializationFailed {
                details: "d".to_owned(),
            },
            CompilerError::InvalidModule {
                kind: InvalidModuleKind::MissingImports { missing: vec![] },
            },
            CompilerError::FuelLimitError {
                details: "d".to_owned(),
            },
            CompilerError::InstantiationFailed {
                details: "d".to_owned(),
            },
            CompilerError::EntryPointNotFound { function: "f" },
            CompilerError::ContractExecutionFailed {
                details: "d".to_owned(),
            },
            CompilerError::SerializationError {
                context: "c",
                details: "d".to_owned(),
            },
            CompilerError::InvalidContractOutput {
                details: "d".to_owned(),
            },
            CompilerError::MemoryAllocationFailed {
                details: "d".to_owned(),
            },
            CompilerError::ContractCheckFailed {
                error: "e".to_owned(),
            },
            CompilerError::EngineCreation {
                details: "d".to_owned(),
            },
            CompilerError::FetchedArtifactMismatch {
                expected: "e".to_owned(),
                actual: "a".to_owned(),
            },
            CompilerError::FetchedArtifactDecompressionFailed {
                details: "d".to_owned(),
            },
            CompilerError::MissingArtifactAnchor {
                contract_name: "c".to_owned(),
            },
            CompilerError::ArtifactAnchorMismatch {
                expected: "e".to_owned(),
                actual: "a".to_owned(),
            },
        ]
    }

    /// Expected classification of every `CompilerError` variant:
    /// (infrastructure, local fatal, retryable recovery). The match is
    /// exhaustive on purpose: adding a variant fails compilation here,
    /// forcing an explicit classification decision instead of silently
    /// falling into a `matches!` default.
    fn expected_classification(error: &CompilerError) -> (bool, bool, bool) {
        match error {
            CompilerError::CompilersUnavailable { .. } => (true, false, true),
            CompilerError::ToolchainMismatch { .. }
            | CompilerError::InvalidAttestationSignature
            | CompilerError::AttestationMismatch { .. } => (true, false, false),
            CompilerError::FileReadFailed { kind, .. } => (
                false,
                true,
                matches!(
                    kind,
                    std::io::ErrorKind::Interrupted
                        | std::io::ErrorKind::WouldBlock
                        | std::io::ErrorKind::TimedOut
                ),
            ),
            CompilerError::InvalidContractPath { .. }
            | CompilerError::DirectoryCreationFailed { .. }
            | CompilerError::FileWriteFailed { .. }
            | CompilerError::MissingHelper { .. }
            | CompilerError::ContractRegisterFailed { .. }
            | CompilerError::ToolchainFingerprintFailed { .. }
            | CompilerError::EngineCreation { .. }
            | CompilerError::SerializationError { .. }
            | CompilerError::MissingArtifactAnchor { .. }
            | CompilerError::ArtifactAnchorMismatch { .. } => {
                (false, true, false)
            }
            CompilerError::Base64DecodeFailed { .. }
            | CompilerError::CargoBuildFailed { .. }
            | CompilerError::BuildTimeout { .. }
            | CompilerError::CompilationFailed
            | CompilerError::WasmPrecompileFailed { .. }
            | CompilerError::WasmDeserializationFailed { .. }
            | CompilerError::InvalidModule { .. }
            | CompilerError::FuelLimitError { .. }
            | CompilerError::InstantiationFailed { .. }
            | CompilerError::EntryPointNotFound { .. }
            | CompilerError::ContractExecutionFailed { .. }
            | CompilerError::InvalidContractOutput { .. }
            | CompilerError::MemoryAllocationFailed { .. }
            | CompilerError::ContractCheckFailed { .. }
            | CompilerError::FetchedArtifactMismatch { .. }
            | CompilerError::FetchedArtifactDecompressionFailed { .. } => {
                (false, false, false)
            }
        }
    }

    #[test]
    fn compiler_error_taxonomy_matches_classification() {
        for error in sample_errors() {
            let expected = expected_classification(&error);
            let actual = (
                is_compiler_infra_error(&error),
                is_local_fatal_compiler_error(&error),
                is_retryable_compiler_recovery_error(&error),
            );
            assert_eq!(
                actual, expected,
                "unexpected classification for {error}"
            );
        }
    }
}
