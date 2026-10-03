use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::{Duration, Instant},
};

use crate::{
    compilation::{
        CompileTarget,
        artifact::{
            ArtifactData, ArtifactFetchResult, ArtifactProbeResult,
            ArtifactTransferError,
        },
        error::CompilerError,
        pipeline,
        request::CompilationReq,
        resolve_compile_targets,
        support::{
            CompilerSupport, ContractSourceInput, HEAL_RETRY_BASE_MS,
            HEAL_RETRY_MAX_MS, SERVING_CACHE_TTL, ServedArtifact,
            ServingCacheEntry, is_compiler_infra_error,
            is_local_fatal_compiler_error, is_retryable_compiler_recovery_error,
        },
    },
    governance::{
        contract_register::{
            ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
        },
        model::Schema,
    },
    helpers::network::{NetworkMessage, delivery_of, service::NetworkSender},
    metrics::try_core_metrics,
    model::common::{
        GovVersionSync, crash_system, gov_version_sync,
        node::{SignTypesNode, get_sign},
    },
    sink::retry_delay_ms,
    subject::RequestSubjectData,
    system::ConfigHelper,
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::{
    Namespace, SchemaType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
    request::EventRequest,
};

use ave_network::ComunicateInfo;
use futures::StreamExt;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};

use tracing::{Span, debug, error, info, info_span, warn};

use super::{
    Compilation, CompilationMessage,
    response::{
        CompilationError, CompilationRes, CompilationResult, CompilerResponse,
    },
};

/// A struct representing a CompileWorker actor.
#[derive(Clone, Debug)]
pub struct CompileWorker {
    pub node_key: PublicKey,
    pub our_key: Arc<PublicKey>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub issuers: BTreeSet<PublicKey>,
    pub issuer_any: bool,
    /// Committed governance schemas: the local state compile targets
    /// resolve against. Kept up to date by the governance actor — same
    /// governance version as the request means the same schemas, so
    /// nothing contract-related travels in the request itself.
    pub schemas: BTreeMap<SchemaType, Schema>,
    /// Whitelist of legitimate artifact requesters: the evaluators of
    /// each schema (schema-level and tracker-schemas roles). Compilers
    /// are never requesters — they compile their artifacts locally — so
    /// even a compiler is rejected here. Kept up to date by the
    /// governance actor via `Update` — in memory, no per-request lookups
    /// against the governance actor.
    pub evaluators: BTreeMap<SchemaType, BTreeSet<PublicKey>>,
    /// Governance toolchain pin, kept up to date via `Update`: heal
    /// rebuilds and request builds compile under this pin, never under
    /// a stale one.
    pub toolchain_pin: String,
    /// While the governance applies an update (promoting and refreshing
    /// artifacts) nothing is served: between versions there is no good
    /// answer.
    pub serving_blocked: bool,
    /// Official artifacts recently served, per contract: the fetch burst
    /// after a contract change re-reads nothing from disk. Entries expire
    /// (`SERVING_CACHE_TTL`) — contract changes are rare, the RAM must
    /// not be held forever — and the cache is cleared when an update
    /// blocks serving (the artifacts may change under it).
    pub serving_cache: HashMap<String, ServingCacheEntry>,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
    pub stop: bool,
    /// In-flight network compilation request, if any (see `pre_stop`).
    /// Only ever set on the ephemeral build children: the standing
    /// worker answers gates and serves artifacts, it never compiles.
    pub pending: Option<PendingCompilation>,
    /// Live ephemeral build children by request id. Killed when the
    /// pin changes underneath them (their votes would be rejected at
    /// validation anyway); pruned of finished children on `Update`.
    pub build_children: BTreeSet<String>,
    /// Committed governance pin at the worker's version. Ephemeral
    /// children carry the REQUEST pin in `toolchain_pin` (what they
    /// build under); this one tells recompile-all apart from
    /// same-pin work when resolving targets.
    pub committed_pin: String,
}

/// A network compilation request being processed.
///
/// `pre_stop` uses it to
/// notify the requester that this compiler is going down mid-compilation
/// (`CompilationRes::Unavailable`) instead of letting it burn the
/// coordinator retries on a dead node.
#[derive(Clone, Debug)]
pub struct PendingCompilation {
    /// Requester node key (response receiver).
    pub sender: PublicKey,
    /// Request identifier of the in-flight compilation.
    pub request_id: String,
    /// Compilation request version.
    pub version: u64,
    /// Subject the compilation belongs to (response actor path).
    pub subject_id: DigestIdentifier,
}

/// Outcome of compiling the target contracts of a request.
enum ContractCompilation {
    /// Every contract compiled and passed its init check: artifact hash
    /// per schema.
    Compiled(BTreeMap<SchemaType, DigestIdentifier>),
    /// Deterministic failure (contract rejected or init check failed):
    /// every honest compiler votes the same.
    Failed(CompilationError),
    /// A contract payload does not even decode: the request is
    /// malformed, there is nothing to vote. Aborted, same as the
    /// evaluation's `InvalidEventRequest`.
    Abort(String),
    /// This node can not compile right now for infrastructure reasons.
    Unavailable,
}

/// Gate of an incoming artifact probe/request (see
/// `CompileWorker::artifact_gate`).
enum ArtifactGate {
    /// Whitelist and version negotiation passed: the request can be
    /// served.
    Allowed,
    /// Answer `NotServed`: this node is itself behind — the requester
    /// tries another peer.
    NotServed,
    /// Answer `Busy`: this node is applying an update — the requester
    /// waits and retries us, every compiler is busy at once.
    Busy,
    /// Answer `Outdated`: the requester is behind and must sync.
    Outdated,
    /// Silent reject (bad governance or non-whitelisted sender), like
    /// the `EvaluationSchema` rejects.
    Reject,
}

/// Outcome of one schema of a multi-schema compile: success carries
/// its artifact hash, a verdict short-circuits the whole request and
/// a fatal error crashes the node. Aggregation in schema order keeps
/// votes deterministic no matter in which order builds finish.
#[allow(clippy::large_enum_variant)]
enum SchemaOutcome {
    Compiled(SchemaType, DigestIdentifier),
    Verdict(ContractCompilation),
    Fatal(ActorError),
}

impl CompileWorker {
    /// Best-effort `Unavailable` notification for the in-flight network
    /// compilation request: the node is going down before answering, so
    /// the requester can replace it immediately instead of waiting for
    /// the coordinator retries and timeout. Errors are logged and
    /// swallowed — the coordinator timeout is the fallback.
    async fn notify_unavailable(&self) {
        let Some(pending) = &self.pending else {
            return;
        };

        let info = ComunicateInfo {
            receiver: pending.sender.clone(),
            request_id: pending.request_id.clone(),
            version: pending.version,
            receiver_actor: format!(
                "/user/request/{}/compilation/{}",
                pending.subject_id, self.our_key
            ),
        };

        let message = ActorMessage::CompilationRes {
            res: CompilationRes::Unavailable,
        };
        if let Err(error) = self
            .network
            .send_command(ave_network::CommandHelper::SendMessage {
                delivery: delivery_of(&message),
                message: NetworkMessage::new(info, message),
            })
            .await
        {
            debug!(
                error = %error,
                request_id = %pending.request_id,
                "Could not notify compiler unavailability while stopping"
            );
        }
    }

    /// Serves the official artifact of a contract, from the serving
    /// cache while the entry is fresh and from disk otherwise — filling
    /// the cache and scheduling its expiry on a miss. The cache exists
    /// for the fetch burst after a contract change (every evaluator
    /// fetches at once); outside that window reading the artifact from
    /// disk is cheap enough. Persisted bytes that fail verification are
    /// discarded by the support layer: nothing is served and healing is
    /// scheduled at once — a compiler recompiles against the anchor.
    async fn serve_artifact(
        &mut self,
        ctx: &mut ActorContext<Self>,
        schema_id: &SchemaType,
        contract_name: &str,
    ) -> Result<Option<ArtifactData>, ActorError> {
        if let Some(entry) = self.serving_cache.get(contract_name)
            && entry.filled_at.elapsed() < SERVING_CACHE_TTL
        {
            return Ok(Some(entry.artifact.clone()));
        }

        let artifact = match CompilerSupport::serve_official_artifact(
            self.hash,
            ctx,
            contract_name,
            &self.register_path(),
        )
        .await
        {
            Ok(ServedArtifact::Verified(artifact)) => artifact,
            Ok(ServedArtifact::Missing) => return Ok(None),
            Ok(ServedArtifact::Corrupt) => {
                // Serving nothing until the artifact is healed:
                // recompile it against the ledger anchor right away.
                if let Err(e) = ctx.schedule_once(
                    Duration::ZERO,
                    CompileWorkerMessage::HealArtifact {
                        schema_id: schema_id.clone(),
                        attempts: 1,
                    },
                ) {
                    return Err(crash_system(ctx, e).await);
                }
                return Ok(None);
            }
            Err(error) => {
                return Err(crash_system(
                    ctx,
                    ActorError::FunctionalCritical {
                        description: format!(
                            "Can not serve official artifact {contract_name}: {error}"
                        ),
                    },
                )
                .await);
            }
        };

        let filled_at = Instant::now();
        // The expiry is scheduled before filling: a scheduling failure
        // leaves no entry behind, so the RAM is never held forever.
        ctx.schedule_once(
            SERVING_CACHE_TTL,
            CompileWorkerMessage::EvictServingCache {
                contract_name: contract_name.to_owned(),
                filled_at,
            },
        )?;

        self.serving_cache.insert(
            contract_name.to_owned(),
            ServingCacheEntry {
                artifact: artifact.clone(),
                filled_at,
            },
        );

        Ok(Some(artifact))
    }

    fn register_path(&self) -> ActorPath {
        ActorPath::from(format!(
            "/user/node/subject_manager/{}/contract_register",
            self.governance_id
        ))
    }

    /// Whitelist and version negotiation of an incoming artifact
    /// probe/request, in the `EvaluationSchema` order: legitimate
    /// requester first (silent reject otherwise), then the blocked
    /// update window, then the governance version.
    fn artifact_gate(
        &self,
        msg_type: &'static str,
        subject_id: &DigestIdentifier,
        schema_id: &SchemaType,
        gov_version: u64,
        sender: &PublicKey,
    ) -> ArtifactGate {
        if subject_id != &self.governance_id {
            warn!(
                msg_type,
                sender = %sender,
                expected_governance_id = %self.governance_id,
                received_governance_id = %subject_id,
                "Invalid governance_id in artifact request"
            );
            return ArtifactGate::Reject;
        }

        // Only evaluators of the schema may request artifacts:
        // compilers compile locally and never fetch — even a compiler
        // is rejected.
        let whitelisted = self
            .evaluators
            .get(schema_id)
            .is_some_and(|evaluators| evaluators.contains(sender));
        if !whitelisted {
            warn!(
                msg_type,
                sender = %sender,
                schema_id = ?schema_id,
                "Artifact request from a node that is not an evaluator of the schema"
            );
            return ArtifactGate::Reject;
        }

        // Updating our own artifacts: after a contract change every
        // compiler is busy at once — tell the requester to wait for us
        // instead of pointlessly moving to another compiler.
        if self.serving_blocked {
            return ArtifactGate::Busy;
        }

        match gov_version_sync(self.gov_version, gov_version) {
            // This node is behind the request's governance version and
            // can not have the artifact: try another peer.
            GovVersionSync::NodeBehind => ArtifactGate::NotServed,
            // The requester is behind: it must sync and retry.
            GovVersionSync::RequesterBehind => ArtifactGate::Outdated,
            GovVersionSync::Current => ArtifactGate::Allowed,
        }
    }

    async fn send_artifact_message(
        &self,
        ctx: &mut ActorContext<Self>,
        msg_type: &'static str,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
        message: ActorMessage,
    ) -> Result<(), ActorError> {
        let new_info = ComunicateInfo {
            receiver: sender,
            request_id: info.request_id.clone(),
            version: info.version,
            receiver_actor,
        };

        let delivery = delivery_of(&message);
        if let Err(e) = self
            .network
            .send_command(ave_network::CommandHelper::SendMessage {
                delivery,
                message: NetworkMessage::new(new_info, message),
            })
            .await
        {
            error!(
                msg_type,
                error = %e,
                "Failed to send artifact response to network"
            );
            return Err(crash_system(ctx, e).await);
        }

        Ok(())
    }

    fn build_request_hashes(
        &self,
        compilation_req: &Signed<CompilationReq>,
    ) -> Result<(DigestIdentifier, DigestIdentifier), ActorError> {
        let compile_req_hash =
            hash_borsh(&*self.hash.hasher(), compilation_req).map_err(|e| {
                ActorError::Functional {
                    description: format!(
                        "Can not create compilation request hash: {}",
                        e
                    ),
                }
            })?;

        let req_subject_data_hash = hash_borsh(
            &*self.hash.hasher(),
            &RequestSubjectData {
                namespace: Namespace::new(),
                schema_id: SchemaType::Governance,
                subject_id: compilation_req
                    .content()
                    .event_request
                    .content()
                    .get_subject_id(),
                governance_id: compilation_req.content().governance_id.clone(),
                sn: compilation_req.content().sn,
                gov_version: compilation_req.content().gov_version,
                signer: compilation_req
                    .content()
                    .event_request
                    .signature()
                    .signer
                    .clone(),
            },
        )
        .map_err(|e| ActorError::Functional {
            description: format!(
                "Can not create request subject data hash: {}",
                e
            ),
        })?;

        Ok((compile_req_hash, req_subject_data_hash))
    }

    async fn create_res(
        &self,
        ctx: &mut ActorContext<Self>,
        compilation_req: &Signed<CompilationReq>,
    ) -> Result<CompilationRes, ActorError> {
        let (compile_req_hash, req_subject_data_hash) =
            self.build_request_hashes(compilation_req)?;

        let EventRequest::Fact(fact_request) =
            compilation_req.content().event_request.content()
        else {
            return Ok(CompilationRes::Abort(
                "Compilation requests only accept governance fact events"
                    .to_owned(),
            ));
        };

        // The request carries its effective build pin: without a local
        // toolchain for it this compiler stands down (same outcome as
        // `Unavailable`, attributed to the pin for logs and metrics).
        let pin = compilation_req.content().pin.clone();
        let toolchains = match CompilerSupport::toolchains_helper(ctx) {
            Ok(toolchains) => toolchains,
            Err(e) => return Err(crash_system(ctx, e).await),
        };
        // The build resolves the pin again internally: this gate is
        // only the early stand-down, before any work starts. An empty
        // pin predates pins (legacy request): system cargo, as before.
        if !pin.is_empty() && toolchains.resolve(&pin).is_none() {
            if let Some(metrics) = try_core_metrics() {
                metrics.observe_compiler_build(&pin, "stood_down");
            }
            return Ok(CompilationRes::NoToolchain { pin });
        }

        // The vote attests the toolchain that built it: validators
        // compare this version against the registry entry for the pin
        // (valid ID, wrong toolchain is rejected there). Measured once
        // per request from the SELECTED toolchain — the gate above
        // already proved it resolves. Unmeasurable means the toolchain
        // is broken: stand down, the build would fail the same way.
        // The test-only pool votes empty (unattested): only test pool
        // builds can produce those, never production ones.
        let toolchain_name = if pin.is_empty() {
            String::new()
        } else {
            match toolchains.resolve(&pin) {
                Some(name) => name,
                None => return Ok(CompilationRes::NoToolchain { pin }),
            }
        };
        // The test-only pool votes empty (unattested): only test pool
        // builds can produce those, never production ones. An empty
        // toolchain name selects the system cargo (legacy request):
        // production measures it (validators judge whatever it
        // attests); tests vote empty.
        #[cfg(feature = "test")]
        let empty_version = String::new();
        #[cfg(not(feature = "test"))]
        let empty_version =
            match Self::measure_toolchain_version("", &pin).await {
                Ok(version) => version,
                Err(response) => return Ok(response),
            };
        let toolchain_version = if toolchain_name.is_empty() {
            empty_version
        } else {
            match Self::measure_toolchain_version(&toolchain_name, &pin)
                .await
            {
                Ok(version) => version,
                Err(response) => return Ok(response),
            }
        };

        let result =
            match resolve_compile_targets(
                &fact_request.payload,
                &self.schemas,
                &self.committed_pin,
            )
            {
                Ok(targets) => {
                    if targets.is_empty() {
                        // No schemas in the payload yet compilation was
                        // requested: bare pin switch (the manager only
                        // asks then). Capacity attestation, no builds —
                        // the gate above already proved this pin
                        // resolves locally, so voting empty is exact.
                        let carries_pin = serde_json::from_value::<
                            ave_common::governance::GovernanceEvent,
                        >(fact_request.payload.0.clone())
                        .ok()
                        .and_then(|event| event.toolchain)
                        .is_some();
                        if carries_pin {
                            CompilationResult::Ok {
                                response: CompilerResponse {
                                    contracts: BTreeMap::new(),
                                },
                                compile_req_hash,
                                req_subject_data_hash,
                                pin: pin.clone(),
                                toolchain_version: toolchain_version.clone(),
                            }
                        } else {
                            CompilationResult::Error {
                                error: CompilationError::InvalidEvent(
                                    "The event does not add or change any contract"
                                        .to_owned(),
                                ),
                                compile_req_hash,
                                req_subject_data_hash,
                                pin: pin.clone(),
                                toolchain_version: toolchain_version.clone(),
                            }
                        }
                    } else {
                        match self
                            .compile_targets(ctx, compilation_req, targets)
                            .await
                        {
                            Ok(ContractCompilation::Compiled(contracts)) => {
                                CompilationResult::Ok {
                                    response: CompilerResponse { contracts },
                                    compile_req_hash,
                                    req_subject_data_hash,
                                    pin: pin.clone(),
                                    toolchain_version: toolchain_version.clone(),
                                }
                            }
                            Ok(ContractCompilation::Failed(error)) => {
                                CompilationResult::Error {
                                    error,
                                    compile_req_hash,
                                    req_subject_data_hash,
                                    pin: pin.clone(),
                                    toolchain_version: toolchain_version.clone(),
                                }
                            }
                            Ok(ContractCompilation::Abort(reason)) => {
                                return Ok(CompilationRes::Abort(reason));
                            }
                            Ok(ContractCompilation::Unavailable) => {
                                // This node can not compile right now for
                                // infrastructure reasons: not a verdict,
                                // the requester replaces this compiler.
                                return Ok(CompilationRes::Unavailable);
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
                Err(error) => CompilationResult::Error {
                    error,
                    compile_req_hash,
                    req_subject_data_hash,
                    pin: pin.clone(),
                    toolchain_version: toolchain_version.clone(),
                },
            };

        let result_hash =
            hash_borsh(&*self.hash.hasher(), &result).map_err(|e| {
                ActorError::Functional {
                    description: format!(
                        "Can not create compilation result hash: {}",
                        e
                    ),
                }
            })?;

        let result_hash_signature = get_sign(
            ctx,
            SignTypesNode::CompilationSignature(result_hash.clone()),
        )
        .await?;

        Ok(CompilationRes::Response {
            result,
            result_hash,
            result_hash_signature,
        })
    }

    /// Measures the selected toolchain for the vote. Unmeasurable
    /// means a broken toolchain: stand down exactly like an
    /// unresolvable pin (same metric, same response) — the build
    /// would fail the same way.
    async fn measure_toolchain_version(
        toolchain_name: &str,
        pin: &str,
    ) -> Result<String, CompilationRes> {
        match ave_build::rustc_version(toolchain_name).await {
            Ok(version) => Ok(version),
            Err(_) => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_compiler_build(pin, "stood_down");
                }
                Err(CompilationRes::NoToolchain {
                    pin: pin.to_owned(),
                })
            }
        }
    }

    /// Compiles every target contract with its init check and returns
    /// the artifact hash of each one. Changed contracts are staged under
    /// a temporary name — promoted to the official artifact if the event
    /// commits, swept otherwise — while unchanged ones reuse the
    /// official artifact and only run the init check with the new
    /// initial value.
    ///
    /// Schemas build concurrently (bounded by CPU count): every staging
    /// directory is unique per schema, so builds never touch each
    /// other, and outcomes fold back in schema order.
    async fn compile_targets(
        &self,
        ctx: &mut ActorContext<Self>,
        compilation_req: &Signed<CompilationReq>,
        targets: BTreeMap<SchemaType, CompileTarget>,
    ) -> Result<ContractCompilation, ActorError> {
        let subject_id = compilation_req
            .content()
            .event_request
            .content()
            .get_subject_id();
        let register_path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/contract_register",
            self.governance_id
        ));

        // Schemas build concurrently, bounded by CPU count: every
        // staging directory is unique per schema, so builds never touch
        // each other. The fold restores schema order and keeps the exact
        // first-failure semantics of the old sequential loop (a task can
        // not observe another task's outcome).
        let jobs: Vec<(usize, SchemaType, CompileTarget)> = targets
            .into_iter()
            .enumerate()
            .map(|(index, (schema_id, target))| (index, schema_id, target))
            .collect();
        let limit = std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(2)
            .max(1);
        let mut outcomes: Vec<(usize, SchemaOutcome)> =
            futures::stream::iter(jobs.into_iter().map(
                |(index, schema_id, target)| {
                    self.compile_one(
                        ctx,
                        compilation_req,
                        &subject_id,
                        &register_path,
                        index,
                        schema_id,
                        target,
                    )
                },
            ))
            .buffer_unordered(limit)
            .collect()
            .await;
        outcomes.sort_by_key(|(index, _)| *index);

        let mut contracts = BTreeMap::new();
        for (_, outcome) in outcomes {
            match outcome {
                SchemaOutcome::Compiled(schema_id, wasm_hash) => {
                    contracts.insert(schema_id, wasm_hash);
                }
                SchemaOutcome::Verdict(verdict) => return Ok(verdict),
                SchemaOutcome::Fatal(error) => {
                    return Err(crash_system(ctx, error).await);
                }
            }
        }

        Ok(ContractCompilation::Compiled(contracts))
    }

    /// Compiles one schema without touching shared mutable state: safe
    /// to run concurrently with other schemas of the same request. Fatal
    /// problems travel as data (`SchemaOutcome::Fatal`); the fold above
    /// crashes the node for them with `&mut` access.
    async fn compile_one(
        &self,
        ctx: &ActorContext<Self>,
        compilation_req: &Signed<CompilationReq>,
        subject_id: &DigestIdentifier,
        register_path: &ActorPath,
        index: usize,
        schema_id: SchemaType,
        target: CompileTarget,
    ) -> (usize, SchemaOutcome) {
        let Some(config) = ctx.system().get_helper::<ConfigHelper>("config")
        else {
            return (
                index,
                SchemaOutcome::Verdict(ContractCompilation::Unavailable),
            );
        };
            let (contract_name, contract_path) = if target.contract_changed
                || target.force_rebuild
            {
                let contract_hash = match hash_borsh(
                    &*self.hash.hasher(),
                    &target.source,
                ) {
                    Ok(contract_hash) => contract_hash,
                    Err(e) => {
                        return (
                            index,
                            SchemaOutcome::Fatal(ActorError::Functional {
                                description: format!(
                                    "Can not hash contract source: {}",
                                    e
                                ),
                            }),
                        );
                    }
                };
                let staging_name = format!(
                    "{}_temp_staging_{}_{}",
                    subject_id, schema_id, contract_hash
                );
                let staging_path = config.contracts_path.join(&staging_name);
                (staging_name, staging_path)
            } else {
                let official_name = format!("{}_{}", subject_id, schema_id);
                let official_path = config
                    .contracts_path
                    .join("contracts")
                    .join(&official_name);
                (official_name, official_path)
            };

            // Unchanged contract: the init check re-runs against the
            // official artifact, and the recompile fallback (missing or
            // corrupt local artifact) must reproduce the ledger-anchored
            // bytes exactly — compilation is deterministic with the same
            // toolchain, so a mismatch is a local integrity failure,
            // never a divergent vote or an anchor drift.
            let expected_wasm_hash = if target.contract_changed
                || target.force_rebuild
            {
                None
            } else {
                let register = match ctx
                    .system()
                    .get_actor::<ContractRegister>(&register_path)
                    .await
                {
                    Ok(register) => register,
                    Err(error) => {
                        return (
                            index,
                            SchemaOutcome::Fatal(
                                ActorError::FunctionalCritical {
                                    description: format!(
                                        "Can not access contract register for anchor: {}",
                                        error
                                    ),
                                },
                            ),
                        );
                    }
                };
                match register
                    .ask(ContractRegisterMessage::GetAnchor {
                        contract_name: contract_name.clone(),
                    })
                    .await
                {
                    Ok(ContractRegisterResponse::Anchor(Some(anchor))) => {
                        Some(anchor)
                    }
                    Ok(ContractRegisterResponse::Anchor(None)) => {
                        return (
                            index,
                            SchemaOutcome::Fatal(
                                ActorError::FunctionalCritical {
                                    description: format!(
                                        "No ledger anchor for committed contract {}",
                                        contract_name
                                    ),
                                },
                            ),
                        );
                    }
                    Ok(_) => {
                        return (
                            index,
                            SchemaOutcome::Fatal(
                                ActorError::UnexpectedResponse {
                                    path: register_path.clone(),
                                    expected:
                                        "ContractRegisterResponse::Anchor"
                                            .to_owned(),
                                },
                            ),
                        );
                    }
                    Err(error) => {
                        return (
                            index,
                            SchemaOutcome::Fatal(
                                ActorError::FunctionalCritical {
                                    description: format!(
                                        "Can not read contract anchor: {}",
                                        error
                                    ),
                                },
                            ),
                        );
                    }
                }
            };

            match CompilerSupport::compile_or_load_registered(
                self.hash,
                ctx,
                ContractSourceInput {
                    contract_name: &contract_name,
                    contract: &target.source,
                    contract_path: &contract_path,
                    initial_value: target.initial_value,
                },
                &register_path,
                expected_wasm_hash.as_ref(),
                // The request already carries the effective pin
                // (event pin or committed pin, computed by the
                // requester): building under it is exact.
                &compilation_req.content().pin,
                target.force_rebuild,
            )
            .await
            {
                Ok((_module, record)) => {
                    let wasm = match pipeline::load_artifact_wasm(
                        &contract_path,
                    )
                    .await
                    {
                        Ok(wasm) => wasm,
                        Err(error) => {
                            return (
                                index,
                                SchemaOutcome::Fatal(
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Can not read compiled contract {}: {}",
                                            schema_id, error
                                        ),
                                    },
                                ),
                            );
                        }
                    };
                    match ArtifactData::from_wasm(&wasm, None) {
                        Ok(_) => {}
                        Err(
                            ArtifactTransferError::TooLarge { size, max }
                            | ArtifactTransferError::UncompressedTooLarge {
                                size,
                                max,
                            },
                        ) => {
                            return (
                                index,
                                SchemaOutcome::Verdict(
                                    ContractCompilation::Failed(
                                        CompilationError::CompilationFailed(
                                            format!(
                                                "{}: artifact is too large for network transport: {} bytes (max {})",
                                                schema_id, size, max
                                            ),
                                        ),
                                    ),
                                ),
                            );
                        }
                        Err(error) => {
                            warn!(
                                governance_id = %self.governance_id,
                                schema_id = %schema_id,
                                error = %error,
                                "Could not prepare artifact for network transport"
                            );
                            return (
                                index,
                                SchemaOutcome::Verdict(
                                    ContractCompilation::Unavailable,
                                ),
                            );
                        }
                    }
                    return (
                        index,
                        SchemaOutcome::Compiled(schema_id, record.wasm_hash),
                    );
                }
                Err(error) => {
                    if matches!(error, CompilerError::Base64DecodeFailed { .. })
                    {
                        // A contract payload that does not even decode
                        // is a malformed request: nothing to vote, it
                        // is aborted (same as the evaluation's
                        // `InvalidEventRequest`).
                        if target.contract_changed {
                            return (
                                index,
                                SchemaOutcome::Verdict(
                                    ContractCompilation::Abort(format!(
                                        "{}: {}",
                                        schema_id, error
                                    )),
                                ),
                            );
                        }
                        // The undecodable contract comes from the
                        // committed local state: it is corrupt, fail
                        // loud.
                        return (
                            index,
                            SchemaOutcome::Fatal(
                                ActorError::FunctionalCritical {
                                    description: format!(
                                        "Committed contract {} does not decode: {}",
                                        schema_id, error
                                    ),
                                },
                            ),
                        );
                    }
                    // Infrastructure problems of this node are not a
                    // verdict: answer Unavailable so the requester
                    // replaces this compiler.
                    if is_compiler_infra_error(&error) {
                        warn!(
                            governance_id = %self.governance_id,
                            schema_id = %schema_id,
                            error = %error,
                            "Compiler infrastructure unavailable"
                        );
                        return (
                            index,
                            SchemaOutcome::Verdict(
                                ContractCompilation::Unavailable,
                            ),
                        );
                    }
                    // Fatal local problems (disk, register, helpers,
                    // engine): the node is broken, fail loud.
                    if is_local_fatal_compiler_error(&error) {
                        return (
                            index,
                            SchemaOutcome::Fatal(
                                ActorError::FunctionalCritical {
                                    description: format!(
                                        "Can not compile contract {}: {}",
                                        schema_id, error
                                    ),
                                },
                            ),
                        );
                    }
                    // Anything else is a contract problem: every honest
                    // compiler reaches the same verdict, so it is voted.
                    return (
                        index,
                        SchemaOutcome::Verdict(ContractCompilation::Failed(
                            CompilationError::CompilationFailed(format!(
                                "{}: {}",
                                schema_id, error
                            )),
                        )),
                    );
                }
            }
    }

    /// Request-level checks. Every failure is an abort: the requester is
    /// misbehaving or misinformed, there is nothing to vote.
    fn check_data(
        &self,
        compilation_req: &Signed<CompilationReq>,
    ) -> Result<(), String> {
        if compilation_req.content().governance_id != self.governance_id {
            return Err(format!(
                "Compiler governance_id {} and compilation request governance_id {} are different",
                self.governance_id,
                compilation_req.content().governance_id
            ));
        }

        if compilation_req.verify().is_err() {
            return Err("Invalid compilation request signature".to_owned());
        }

        if compilation_req.content().event_request.verify().is_err() {
            return Err("Invalid event request signature".to_owned());
        }

        if !compilation_req
            .content()
            .event_request
            .content()
            .is_fact_event()
        {
            return Err(
                "Compilation requests only accept governance fact events"
                    .to_owned(),
            );
        }

        if self.gov_version == compilation_req.content().gov_version {
            let signer = compilation_req
                .content()
                .event_request
                .signature()
                .signer
                .clone();

            if !self.issuer_any && !self.issuers.contains(&signer) {
                return Err(
                    "In fact events, the signer has to be an issuer".to_owned()
                );
            }
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum CompileWorkerMessage {
    Update {
        gov_version: u64,
        node_key: PublicKey,
        issuers: BTreeSet<PublicKey>,
        issuer_any: bool,
        schemas: BTreeMap<SchemaType, Schema>,
        evaluators: BTreeMap<SchemaType, BTreeSet<PublicKey>>,
        toolchain_pin: String,
    },
    /// The governance is applying an update (promoting and refreshing
    /// artifacts): serving is blocked until it finishes — between
    /// versions there is no good answer.
    ServingBlocked { blocked: bool },
    /// Expiry of a serving cache entry. Guarded by `filled_at`: a late
    /// eviction of an entry that was already refilled is moot.
    EvictServingCache {
        contract_name: String,
        filled_at: Instant,
    },
    LocalCompilation {
        compilation_req: Signed<CompilationReq>,
    },
    NetworkRequest {
        compilation_req: Signed<CompilationReq>,
        sender: PublicKey,
        info: ComunicateInfo,
    },
    /// Accepted remote compilation, offloaded to an ephemeral child of
    /// the standing worker: the build takes far longer than any gate or
    /// serving answer, and running it inline would mute the standing
    /// worker (probes, fetches and gate updates of the whole governance
    /// would queue behind the build).
    NetworkCompilation {
        compilation_req: Signed<CompilationReq>,
        sender: PublicKey,
        info: ComunicateInfo,
    },
    /// Light availability probe from another node: can this worker
    /// serve the official artifact of the schema at that governance
    /// version?
    ArtifactProbeRequest {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    },
    /// Another node asks for the official artifact of a schema. The
    /// governance version is negotiated first; the requester verifies
    /// the bytes against the compilation evidence of its own ledger.
    ArtifactRequest {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    },
    /// Re-obtains the official artifact of a schema after the serving
    /// path found the persisted bytes corrupt and discarded them:
    /// recompile against the ledger anchor. Transient failures retry
    /// with backoff — the artifact is needed for sure, healing never
    /// gives up.
    HealArtifact {
        schema_id: SchemaType,
        attempts: usize,
    },
}

impl Message for CompileWorkerMessage {}

#[async_trait]
impl Actor for CompileWorker {
    type Event = ();
    type Message = CompileWorkerMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("CompileWorker", id),
            |parent_span| info_span!(parent: parent_span, "CompileWorker", id),
        )
    }

    /// On any stop (graceful shutdown, controlled crash or fault) with a
    /// network compilation still in flight, tell the requester this
    /// compiler is unavailable so it can replace it without waiting for
    /// the coordinator retries.
    async fn pre_stop(
        &mut self,
        _ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.notify_unavailable().await;
        Ok(())
    }
}

impl NotPersistentActor for CompileWorker {}

#[async_trait]
impl Handler<Self> for CompileWorker {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: CompileWorkerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            CompileWorkerMessage::Update {
                gov_version,
                node_key,
                issuers,
                issuer_any,
                schemas,
                evaluators,
                toolchain_pin,
            } => {
                self.gov_version = gov_version;
                self.node_key = node_key;
                self.issuers = issuers;
                self.issuer_any = issuer_any;
                self.schemas = schemas;
                self.evaluators = evaluators;
                // A pin switch orphans in-flight builds: they compile
                // under the stale pin and their votes would be rejected
                // at validation anyway, so stop them instead of burning
                // builds. Finished children are simply pruned.
                let pin_changed = self.toolchain_pin != toolchain_pin;
                let mut live = BTreeSet::new();
                for child_name in std::mem::take(&mut self.build_children) {
                    match ctx.get_child::<Self>(&child_name).await {
                        Ok(child) => {
                            if pin_changed {
                                child.tell_stop().await;
                            } else {
                                live.insert(child_name);
                            }
                        }
                        Err(_) => {}
                    }
                }
                if pin_changed {
                    debug!(
                        toolchain_pin = %toolchain_pin,
                        "Pin switch applied, stale build children stopped"
                    );
                }
                self.build_children = live;
                self.toolchain_pin = toolchain_pin.clone();
                self.committed_pin = toolchain_pin;
            }
            CompileWorkerMessage::ServingBlocked { blocked } => {
                self.serving_blocked = blocked;
                if blocked {
                    // The artifacts may change under the blocked window
                    // (promotion, schema deletion): nothing cached may
                    // survive it.
                    self.serving_cache.clear();
                }
            }
            CompileWorkerMessage::EvictServingCache {
                contract_name,
                filled_at,
            } => {
                // Guarded: a late eviction must not drop an entry that
                // was already refilled.
                if self
                    .serving_cache
                    .get(&contract_name)
                    .is_some_and(|entry| entry.filled_at == filled_at)
                {
                    self.serving_cache.remove(&contract_name);
                }
            }
            CompileWorkerMessage::LocalCompilation { compilation_req } => {
                let compilation =
                    match self.create_res(ctx, &compilation_req).await {
                        Ok(compilation) => compilation,
                        Err(e) => {
                            error!(
                                msg_type = "LocalCompilation",
                                error = %e,
                                "Failed to create compilation response"
                            );
                            return Err(crash_system(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: e.to_string(),
                                },
                            )
                            .await);
                        }
                    };

                match ctx.get_parent::<Compilation>().await {
                    Ok(compilation_actor) => {
                        if let Err(e) = compilation_actor
                            .tell(CompilationMessage::Response {
                                compilation_res: compilation,
                                sender: (*self.our_key).clone(),
                            })
                            .await
                        {
                            // The phase was torn down (abort, reboot or
                            // quorum already closed) while this response
                            // was in flight: it is moot, drop it.
                            debug!(
                                msg_type = "LocalCompilation",
                                error = %e,
                                "Compilation actor gone, dropping response"
                            );
                        } else {
                            debug!(
                                msg_type = "LocalCompilation",
                                "Local compilation completed successfully"
                            );
                        }
                    }
                    Err(e) => {
                        // Same teardown race: the phase actor is gone.
                        debug!(
                            msg_type = "LocalCompilation",
                            path = %ctx.path().parent(),
                            error = %e,
                            "Compilation actor not found, dropping response"
                        );
                    }
                }

                ctx.stop(None).await;
            }
            CompileWorkerMessage::NetworkRequest {
                compilation_req,
                info,
                sender,
            } => {
                if sender != compilation_req.signature().signer
                    || sender != self.node_key
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_sender = %self.node_key,
                        received_sender = %sender,
                        signer = %compilation_req.signature().signer,
                        "Unexpected sender"
                    );
                    if self.stop {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    request_id: info.request_id.clone(),
                    version: info.version,
                    receiver_actor: format!(
                        "/user/request/{}/compilation/{}",
                        compilation_req
                            .content()
                            .event_request
                            .content()
                            .get_subject_id(),
                        self.our_key.clone()
                    ),
                };

                // Cheap gates answer in place; only an accepted request
                // spawns compilation work.
                let gate = if let Err(error) = self.check_data(&compilation_req)
                {
                    Some(CompilationRes::Abort(error))
                } else {
                    match gov_version_sync(
                        self.gov_version,
                        compilation_req.content().gov_version,
                    ) {
                        // This node is behind the request's governance
                        // version and can not compile it: say so instead
                        // of staying silent — the requester replaces this
                        // compiler from its pending pool.
                        GovVersionSync::NodeBehind => {
                            warn!(
                                msg_type = "NetworkRequest",
                                local_gov_version = self.gov_version,
                                request_gov_version = compilation_req.content().gov_version,
                                governance_id = %self.governance_id,
                                sender = %self.node_key,
                                "Request governance version is higher than local; answering unavailable"
                            );
                            Some(CompilationRes::Unavailable)
                        }
                        // The requester is behind on a governance
                        // request: it must abort (not reboot-retry) so
                        // no stale governance intent commits or loops.
                        // Compilation requests are always governance
                        // scoped, so this arm is the governance rule.
                        GovVersionSync::RequesterBehind => {
                            Some(CompilationRes::Abort(format!(
                                "requester governance is behind: local={}, request={}",
                                self.gov_version,
                                compilation_req.content().gov_version
                            )))
                        }
                        GovVersionSync::Current => None,
                    }
                };

                if let Some(gate_res) = gate {
                    let message =
                        ActorMessage::CompilationRes { res: gate_res };
                    if let Err(e) = self
                        .network
                        .send_command(ave_network::CommandHelper::SendMessage {
                            delivery: delivery_of(&message),
                            message: NetworkMessage::new(
                                new_info,
                                message,
                            ),
                        })
                        .await
                    {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to send response to network"
                        );
                        return Err(crash_system(ctx, e).await);
                    };

                    if self.stop {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                // Accepted: the build runs in an ephemeral child named
                // after the request, so this standing worker keeps
                // answering probes, fetches and gate updates while
                // compiling. A retry of the same request (its ACK is
                // still in flight or was lost) finds the child already
                // working: re-ACK instead of duplicating the build.
                let child_name = info.request_id.to_string();
                if ctx.get_child::<Self>(&child_name).await.is_ok() {
                    let message = ActorMessage::CompilationRes {
                        res: CompilationRes::Working,
                    };
                    if let Err(e) = self
                        .network
                        .send_command(ave_network::CommandHelper::SendMessage {
                            delivery: delivery_of(&message),
                            message: NetworkMessage::new(
                                new_info,
                                message,
                            ),
                        })
                        .await
                    {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to re-send working ACK to network"
                        );
                        return Err(crash_system(ctx, e).await);
                    };

                    if self.stop {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                let child = ctx
                    .create_child(
                        &child_name,
                        Self {
                            node_key: self.node_key.clone(),
                            our_key: self.our_key.clone(),
                            governance_id: self.governance_id.clone(),
                            gov_version: self.gov_version,
                            issuers: self.issuers.clone(),
                            issuer_any: self.issuer_any,
                            schemas: self.schemas.clone(),
                            // Ephemeral build workers never serve
                            // artifacts (they live outside the well-known
                            // serving path): empty whitelist rejects
                            // every probe.
                            evaluators: BTreeMap::new(),
                            toolchain_pin: compilation_req
                                .content()
                                .pin
                                .clone(),
                            committed_pin: self.committed_pin.clone(),
                            serving_blocked: false,
                            serving_cache: HashMap::new(),
                            hash: self.hash,
                            network: self.network.clone(),
                            stop: true,
                            pending: None,
                            build_children: BTreeSet::new(),
                        },
                    )
                    .await?;

                if let Err(e) = child
                    .tell(CompileWorkerMessage::NetworkCompilation {
                        compilation_req,
                        sender: sender.clone(),
                        info: info.clone(),
                    })
                    .await
                {
                    // The child would stay idle forever under the
                    // request name, blocking retries on the "already
                    // working" branch: stop it before propagating.
                    warn!(
                        msg_type = "NetworkRequest",
                        request_id = %info.request_id,
                        error = %e,
                        "Failed to dispatch to ephemeral worker, stopping orphan"
                    );
                    if let Err(stop_err) = child.ask_stop().await {
                        warn!(
                            msg_type = "NetworkRequest",
                            request_id = %info.request_id,
                            error = %stop_err,
                            "Failed to stop orphan ephemeral worker"
                        );
                    }
                    return Err(e);
                }

                debug!(
                    msg_type = "NetworkRequest",
                    request_id = %info.request_id,
                    version = info.version,
                    sender = %sender,
                    "Network compilation request accepted, build offloaded to ephemeral worker"
                );
                self.build_children.insert(child_name);

                if self.stop {
                    ctx.stop(None).await;
                }
            }
            CompileWorkerMessage::NetworkCompilation {
                compilation_req,
                info,
                sender,
            } => {
                self.pending = Some(PendingCompilation {
                    sender: sender.clone(),
                    request_id: info.request_id.clone(),
                    version: info.version,
                    subject_id: compilation_req
                        .content()
                        .event_request
                        .content()
                        .get_subject_id(),
                });

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    request_id: info.request_id.clone(),
                    version: info.version,
                    receiver_actor: format!(
                        "/user/request/{}/compilation/{}",
                        compilation_req
                            .content()
                            .event_request
                            .content()
                            .get_subject_id(),
                        self.our_key.clone()
                    ),
                };

                // ACK before compiling: the requester stops resending
                // the request and awaits the final result under a
                // longer result deadline. A large contract legitimately
                // takes longer to compile than the ACK retry budget —
                // without the ACK this node would be dropped as a
                // timeout while compiling correctly.
                let message = ActorMessage::CompilationRes {
                    res: CompilationRes::Working,
                };
                if let Err(e) = self
                    .network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        delivery: delivery_of(&message),
                        message: NetworkMessage::new(
                            new_info.clone(),
                            message,
                        ),
                    })
                    .await
                {
                    error!(
                        msg_type = "NetworkCompilation",
                        error = %e,
                        "Failed to send working ACK to network"
                    );
                    return Err(crash_system(ctx, e).await);
                };

                let compilation =
                    match self.create_res(ctx, &compilation_req).await {
                        Ok(compilation) => compilation,
                        Err(e) => {
                            error!(
                                msg_type = "NetworkCompilation",
                                error = %e,
                                "Internal error during compilation"
                            );
                            return Err(crash_system(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: e.to_string(),
                                },
                            )
                            .await);
                        }
                    };

                let message = ActorMessage::CompilationRes { res: compilation };
                if let Err(e) = self
                    .network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        delivery: delivery_of(&message),
                        message: NetworkMessage::new(new_info, message),
                    })
                    .await
                {
                    error!(
                        msg_type = "NetworkCompilation",
                        error = %e,
                        "Failed to send response to network"
                    );
                    return Err(crash_system(ctx, e).await);
                };

                self.pending = None;

                debug!(
                    msg_type = "NetworkCompilation",
                    request_id = %info.request_id,
                    version = info.version,
                    sender = %sender,
                    "Network compilation request processed successfully"
                );

                // Ephemeral build worker: the work is done.
                ctx.stop(None).await;
            }
            CompileWorkerMessage::ArtifactProbeRequest {
                subject_id,
                schema_id,
                gov_version,
                request_nonce,
                info,
                sender,
                receiver_actor,
            } => {
                let result = match self.artifact_gate(
                    "ArtifactProbeRequest",
                    &subject_id,
                    &schema_id,
                    gov_version,
                    &sender,
                ) {
                    ArtifactGate::Reject => {
                        if self.stop {
                            ctx.stop(None).await;
                        }
                        return Ok(());
                    }
                    ArtifactGate::NotServed => ArtifactProbeResult::NotServed,
                    ArtifactGate::Busy => ArtifactProbeResult::Busy,
                    ArtifactGate::Outdated => ArtifactProbeResult::Outdated {
                        gov_version: self.gov_version,
                    },
                    ArtifactGate::Allowed => {
                        let contract_name =
                            format!("{}_{}", subject_id, schema_id);
                        if CompilerSupport::has_official_artifact(
                            ctx,
                            &contract_name,
                            &self.register_path(),
                        )
                        .await
                        {
                            ArtifactProbeResult::CanServe
                        } else {
                            ArtifactProbeResult::NotServed
                        }
                    }
                };

                self.send_artifact_message(
                    ctx,
                    "ArtifactProbeRequest",
                    info,
                    sender,
                    receiver_actor,
                    ActorMessage::ArtifactProbeRes {
                        request_nonce,
                        result,
                    },
                )
                .await?;

                if self.stop {
                    ctx.stop(None).await;
                }
            }
            CompileWorkerMessage::ArtifactRequest {
                subject_id,
                schema_id,
                gov_version,
                request_nonce,
                info,
                sender,
                receiver_actor,
            } => {
                let result = match self.artifact_gate(
                    "ArtifactRequest",
                    &subject_id,
                    &schema_id,
                    gov_version,
                    &sender,
                ) {
                    ArtifactGate::Reject => {
                        if self.stop {
                            ctx.stop(None).await;
                        }
                        return Ok(());
                    }
                    ArtifactGate::NotServed => ArtifactFetchResult::NotServed,
                    ArtifactGate::Busy => ArtifactFetchResult::Busy,
                    ArtifactGate::Outdated => ArtifactFetchResult::Outdated {
                        gov_version: self.gov_version,
                    },
                    ArtifactGate::Allowed => {
                        let contract_name =
                            format!("{}_{}", subject_id, schema_id);
                        self.serve_artifact(ctx, &schema_id, &contract_name)
                            .await?
                            .map_or(
                                ArtifactFetchResult::NotServed,
                                ArtifactFetchResult::Artifact,
                            )
                    }
                };

                self.send_artifact_message(
                    ctx,
                    "ArtifactRequest",
                    info,
                    sender,
                    receiver_actor,
                    ActorMessage::ArtifactRes {
                        request_nonce,
                        result,
                    },
                )
                .await?;

                debug!(
                    msg_type = "ArtifactRequest",
                    schema_id = ?schema_id,
                    "Artifact request processed"
                );

                if self.stop {
                    ctx.stop(None).await;
                }
            }
            CompileWorkerMessage::HealArtifact {
                schema_id,
                attempts,
            } => {
                let Some(schema) = self.schemas.get(&schema_id).cloned() else {
                    // The schema left the governance meanwhile: nothing
                    // to heal.
                    return Ok(());
                };
                let contract_name =
                    format!("{}_{}", self.governance_id, schema_id);
                // A governance apply may have re-obtained the artifact
                // first.
                if CompilerSupport::has_official_artifact(
                    ctx,
                    &contract_name,
                    &self.register_path(),
                )
                .await
                {
                    return Ok(());
                }

                let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config")
                else {
                    return Err(crash_system(
                        ctx,
                        ActorError::Helper {
                            name: "config".to_owned(),
                            reason: "Not found".to_owned(),
                        },
                    )
                    .await);
                };
                let contract_path = config
                    .contracts_path
                    .join("contracts")
                    .join(&contract_name);

                match CompilerSupport::recover_official_artifact(
                    self.hash,
                    ctx,
                    ContractSourceInput {
                        contract_name: &contract_name,
                        contract: &schema.contract,
                        contract_path: &contract_path,
                        initial_value: schema.initial_value.0.clone(),
                    },
                    &self.register_path(),
                    &self.toolchain_pin,
                )
                .await
                {
                    Ok(module) => {
                        // Module residency follows the evaluator role:
                        // a compiler that does not evaluate this schema
                        // only needed the module for the recovery init
                        // check — it serves raw bytes from disk.
                        if self.evaluators.get(&schema_id).is_some_and(
                            |evaluators| evaluators.contains(&*self.our_key),
                        ) {
                            let contracts =
                                CompilerSupport::contracts_helper(ctx).await?;
                            contracts
                                .write()
                                .await
                                .insert(contract_name, module);
                        }
                        info!(
                            msg_type = "HealArtifact",
                            schema_id = ?schema_id,
                            "Official artifact healed: recompiled against the ledger anchor"
                        );
                    }
                    Err(error)
                        if is_compiler_infra_error(&error)
                            || is_retryable_compiler_recovery_error(&error) =>
                    {
                        let delay = retry_delay_ms(
                            HEAL_RETRY_BASE_MS,
                            HEAL_RETRY_MAX_MS,
                            attempts,
                            None,
                        );
                        warn!(
                            msg_type = "HealArtifact",
                            schema_id = ?schema_id,
                            error = %error,
                            delay_ms = delay,
                            "Artifact healing failed transiently, retrying"
                        );
                        if let Err(e) = ctx.schedule_once(
                            Duration::from_millis(delay),
                            CompileWorkerMessage::HealArtifact {
                                schema_id: schema_id.clone(),
                                attempts: attempts + 1,
                            },
                        ) {
                            return Err(crash_system(ctx, e).await);
                        }
                    }
                    Err(CompilerError::UnknownToolchainPin { pin }) => {
                        // No local toolchain for the committed pin: stay
                        // dormant (keep serving retained bytes), never
                        // crash-loop. The next `Update`/`Reconcile` with
                        // a resolvable pin resumes healing.
                        warn!(
                            msg_type = "HealArtifact",
                            schema_id = ?schema_id,
                            pin = %pin,
                            "No local toolchain for pin, healing stays dormant"
                        );
                    }
                    Err(error) => {
                        // The committed, quorum-anchored contract can
                        // not be reproduced locally: this node can not
                        // fulfill its compiler role — same fatal policy
                        // as boot recovery.
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Can not heal official artifact of {schema_id}: {error}"
                                ),
                            },
                        )
                        .await);
                    }
                }

                if self.stop {
                    ctx.stop(None).await;
                }
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;

    use crate::{
        Node, helpers::network::test_faults::TestFaultRegistry,
        node::InitParamsNode, system::tests::create_system,
    };

    use ave_common::{
        ValueWrapper,
        identity::{KeyPair, keys::Ed25519Signer},
        request::FactRequest,
    };

    use ave_network::CommandHelper;

    use ave_actors::PersistentActor;

    use std::sync::Mutex;

    use test_log::test;
    use tokio::{sync::mpsc, time::timeout};

    /// The working ACK (`CompilationRes::Working`) is sent to the
    /// requester BEFORE the final result, both addressed to the
    /// requester's compilation coordinator.
    #[test(tokio::test)]
    async fn working_ack_precedes_final_result() {
        let (system, _runner, _dirs) = create_system().await;

        let (command_sender, mut command_receiver) = mpsc::channel(16);
        let network = Arc::new(NetworkSender::new(
            command_sender.clone(),
            Arc::new(Mutex::new(TestFaultRegistry::new(command_sender))),
        ));
        system.add_helper("network", network.clone());

        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let our_key = Arc::new(node_keys.public_key());
        system
            .create_root_actor(
                "node",
                Node::initial(InitParamsNode {
                    key_pair: node_keys,
                    public_key: our_key.clone(),
                    hash: HashAlgorithm::Blake3,
                    is_service: true,
                    only_clear_events: false,
                    ledger_batch_size: 100,
                }),
            )
            .await
            .unwrap();

        let requester_keys =
            KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let requester_key = requester_keys.public_key();
        let governance_id = DigestIdentifier::default();

        // A fact event that adds or changes no contract: the request is
        // accepted and answered with a signed invalid-event result —
        // enough to pin the ACK/result message order.
        let event_request = EventRequest::Fact(FactRequest {
            subject_id: governance_id.clone(),
            payload: ValueWrapper(serde_json::json!({})),
            viewpoints: BTreeSet::new(),
        });
        let signed_event = Signed::new(event_request, &requester_keys).unwrap();
        let compilation_req = Signed::new(
            CompilationReq {
                event_request: signed_event,
                governance_id: governance_id.clone(),
                sn: 0,
                gov_version: 0,
                pin: ave_common::governance::DEFAULT_PIN.to_owned(),
            },
            &requester_keys,
        )
        .unwrap();

        let worker = CompileWorker {
            node_key: requester_key.clone(),
            our_key: our_key.clone(),
            governance_id: governance_id.clone(),
            gov_version: 0,
            issuers: BTreeSet::new(),
            issuer_any: true,
            schemas: BTreeMap::new(),
            evaluators: BTreeMap::new(),
            toolchain_pin: ave_common::governance::DEFAULT_PIN.to_owned(),
            committed_pin: ave_common::governance::DEFAULT_PIN.to_owned(),
            serving_blocked: false,
            serving_cache: HashMap::new(),
            hash: HashAlgorithm::Blake3,
            network,
            stop: true,
            pending: None,
            build_children: BTreeSet::new(),
        };
        let worker_ref =
            system.create_root_actor("worker", worker).await.unwrap();

        worker_ref
            .tell(CompileWorkerMessage::NetworkCompilation {
                compilation_req,
                sender: requester_key.clone(),
                info: ComunicateInfo {
                    request_id: "test-request".to_owned(),
                    version: 3,
                    receiver: requester_key.clone(),
                    receiver_actor: String::new(),
                },
            })
            .await
            .unwrap();

        let expected_receiver_actor =
            format!("/user/request/{}/compilation/{}", governance_id, our_key);

        // First message: the working ACK, sent before compiling.
        let command = timeout(Duration::from_secs(5), command_receiver.recv())
            .await
            .expect("no working ACK received")
            .expect("network channel closed");
        let CommandHelper::SendMessage { message: ack, .. } = command else {
            panic!("expected an outbound send command");
        };
        assert!(
            matches!(
                ack.message,
                ActorMessage::CompilationRes {
                    res: CompilationRes::Working
                }
            ),
            "the first message to the requester must be the working ACK"
        );
        assert_eq!(ack.info.request_id, "test-request");
        assert_eq!(ack.info.version, 3);
        assert_eq!(ack.info.receiver, requester_key);
        assert_eq!(ack.info.receiver_actor, expected_receiver_actor);

        // Second message: the final, signed result.
        let command = timeout(Duration::from_secs(5), command_receiver.recv())
            .await
            .expect("no final result received after the working ACK")
            .expect("network channel closed");
        let CommandHelper::SendMessage {
            message: result_message,
            ..
        } = command
        else {
            panic!("expected an outbound send command");
        };
        let ActorMessage::CompilationRes {
            res:
                CompilationRes::Response {
                    result,
                    result_hash,
                    result_hash_signature,
                },
        } = result_message.message
        else {
            panic!("the second message must be the final signed result");
        };
        assert!(
            matches!(
                result,
                CompilationResult::Error {
                    error: CompilationError::InvalidEvent(_),
                    ..
                }
            ),
            "a fact without contracts is a signed invalid-event result"
        );
        assert_eq!(result_hash_signature.signer, *our_key);
        result_hash_signature.verify(&result_hash).unwrap();
        let recomputed =
            hash_borsh(&*HashAlgorithm::Blake3.hasher(), &result).unwrap();
        assert_eq!(recomputed, result_hash);
        assert_eq!(result_message.info.request_id, "test-request");
        assert_eq!(result_message.info.receiver_actor, expected_receiver_actor);

        // The ephemeral build worker is done: it stops and sends nothing
        // else (no unavailability notice: `pending` was cleared).
        timeout(Duration::from_secs(5), worker_ref.closed())
            .await
            .expect("the ephemeral worker did not stop after the result");
        assert!(command_receiver.try_recv().is_err());
    }
}
