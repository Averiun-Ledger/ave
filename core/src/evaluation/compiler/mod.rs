use std::time::Instant;
use std::{collections::HashMap, path::Path, sync::Arc};

use ave_actors::{Actor, ActorContext, ActorError, ActorPath, Response};
use ave_common::{
    ValueWrapper,
    identity::{HashAlgorithm, hash_borsh},
};
use ave_compiler::CompilerClient;
use ave_contract_sdk::runtime::{CompiledModule, ContractRuntime};
use serde_json::Value;
use tokio::sync::RwLock;
use tracing::debug;

use crate::governance::contract_register::{
    ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
};
use crate::metrics::try_core_metrics;

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

struct CompilerSupport;

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

    async fn compile_or_load_registered<A: Actor>(
        hash: HashAlgorithm,
        ctx: &ActorContext<A>,
        contract_name: &str,
        contract: &str,
        contract_path: &Path,
        initial_value: Value,
    ) -> Result<(Arc<CompiledModule>, ContractArtifactRecord), CompilerError>
    {
        let started_at = Instant::now();
        let result = async {
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

            if let Some(persisted) = persisted {
                // With a pinned toolchain the check is against the pin;
                // without one it is a deliberate no-op against the
                // persisted record itself (level 1 of trust).
                let expected_toolchain = client
                    .expected_toolchain()
                    .unwrap_or_else(|| persisted.toolchain_fingerprint.clone());
                if ave_compiler::metadata_matches(
                    &persisted,
                    &contract_hash,
                    &manifest_hash,
                    &engine_fingerprint,
                    &expected_toolchain,
                ) {
                    match ave_compiler::load_artifact_precompiled(contract_path)
                        .await
                    {
                        Ok(precompiled_bytes) => {
                            let precompiled_hash = ave_compiler::hash_bytes(
                                hash,
                                &precompiled_bytes,
                                "persisted cwasm artifact",
                            )?;
                            if precompiled_hash == persisted.cwasm_hash {
                                match contract_runtime
                                    .load_precompiled(&precompiled_bytes)
                                {
                                    Ok(module) => {
                                        match ave_compiler::validate_module(
                                            &contract_runtime,
                                            &module,
                                            ValueWrapper(initial_value.clone()),
                                        ) {
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

                    match ave_compiler::load_artifact_wasm(contract_path).await
                    {
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

                                                return Ok((
                                                    module,
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
            let (precompiled_bytes, module) =
                ave_compiler::precompile_module(&contract_runtime, &outcome.wasm)?;
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
}
