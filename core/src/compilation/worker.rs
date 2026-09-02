use std::{
    collections::{BTreeMap, BTreeSet, HashMap},
    sync::Arc,
    time::Instant,
};

use crate::{
    compilation::{
        CompileTarget,
        artifact::{
            ArtifactData, ArtifactFetchResult, ArtifactProbeResult,
            ArtifactTransferError,
        },
        request::CompilationReq,
        resolve_compile_targets,
        error::CompilerError,
        pipeline,
        support::{
            CompilerSupport, SERVING_CACHE_TTL, ServingCacheEntry,
            is_compiler_infra_error, is_local_fatal_compiler_error,
        },
    },
    governance::{
        contract_register::{
            ContractRegister, ContractRegisterMessage,
            ContractRegisterResponse,
        },
        model::Schema,
    },
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::common::{
        GovVersionSync, crash_system, gov_version_sync,
        node::{SignTypesNode, get_sign},
    },
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

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};

use tracing::{Span, debug, error, info_span, warn};

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
    pub pending: Option<PendingCompilation>,
}

/// A network compilation request being processed. `pre_stop` uses it to
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

        if let Err(error) = self
            .network
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info,
                    message: ActorMessage::CompilationRes {
                        res: CompilationRes::Unavailable,
                    },
                },
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
    /// disk is cheap enough.
    async fn serve_artifact(
        &mut self,
        ctx: &mut ActorContext<Self>,
        contract_name: &str,
    ) -> Result<Option<ArtifactData>, ActorError> {
        if let Some(entry) = self.serving_cache.get(contract_name)
            && entry.filled_at.elapsed() < SERVING_CACHE_TTL
        {
            return Ok(Some(entry.artifact.clone()));
        }

        let Some(artifact) = CompilerSupport::serve_official_artifact(
            ctx,
            contract_name,
            &self.register_path(),
        )
        .await
        else {
            return Ok(None);
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

        if let Err(e) = self
            .network
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info: new_info,
                    message,
                },
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

        let result =
            match resolve_compile_targets(&fact_request.payload, &self.schemas)
            {
                Ok(targets) => {
                    if targets.is_empty() {
                        CompilationResult::Error {
                            error: CompilationError::InvalidEvent(
                                "The event does not add or change any contract"
                                    .to_owned(),
                            ),
                            compile_req_hash,
                            req_subject_data_hash,
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
                                }
                            }
                            Ok(ContractCompilation::Failed(error)) => {
                                CompilationResult::Error {
                                    error,
                                    compile_req_hash,
                                    req_subject_data_hash,
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

    /// Compiles every target contract with its init check and returns
    /// the artifact hash of each one. Changed contracts are staged under
    /// a temporary name — promoted to the official artifact if the event
    /// commits, swept otherwise — while unchanged ones reuse the
    /// official artifact and only run the init check with the new
    /// initial value.
    async fn compile_targets(
        &self,
        ctx: &mut ActorContext<Self>,
        compilation_req: &Signed<CompilationReq>,
        targets: BTreeMap<SchemaType, CompileTarget>,
    ) -> Result<ContractCompilation, ActorError> {
        let Some(config) = ctx.system().get_helper::<ConfigHelper>("config")
        else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        let subject_id = compilation_req
            .content()
            .event_request
            .content()
            .get_subject_id();
        let register_path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/contract_register",
            self.governance_id
        ));

        let mut contracts = BTreeMap::new();
        for (schema_id, target) in targets {
            let (contract_name, contract_path) = if target.contract_changed {
                let contract_hash = hash_borsh(
                    &*self.hash.hasher(),
                    &target.source,
                )
                .map_err(|e| ActorError::Functional {
                    description: format!("Can not hash contract source: {}", e),
                })?;
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
            let expected_wasm_hash = if target.contract_changed {
                None
            } else {
                let register = match ctx
                    .system()
                    .get_actor::<ContractRegister>(&register_path)
                    .await
                {
                    Ok(register) => register,
                    Err(error) => {
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Can not access contract register for anchor: {}",
                                    error
                                ),
                            },
                        )
                        .await);
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
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "No ledger anchor for committed contract {}",
                                    contract_name
                                ),
                            },
                        )
                        .await);
                    }
                    Ok(_) => {
                        return Err(crash_system(
                            ctx,
                            ActorError::UnexpectedResponse {
                                path: register_path.clone(),
                                expected: "ContractRegisterResponse::Anchor"
                                    .to_owned(),
                            },
                        )
                        .await);
                    }
                    Err(error) => {
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Can not read contract anchor: {}",
                                    error
                                ),
                            },
                        )
                        .await);
                    }
                }
            };

            match CompilerSupport::compile_or_load_registered(
                self.hash,
                ctx,
                &contract_name,
                &target.source,
                &contract_path,
                target.initial_value,
                &register_path,
                expected_wasm_hash.as_ref(),
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
                            return Err(crash_system(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: format!(
                                        "Can not read compiled contract {}: {}",
                                        schema_id, error
                                    ),
                                },
                            )
                            .await);
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
                            return Ok(ContractCompilation::Failed(
                                CompilationError::CompilationFailed(format!(
                                    "{}: artifact is too large for network transport: {} bytes (max {})",
                                    schema_id, size, max
                                )),
                            ));
                        }
                        Err(error) => {
                            warn!(
                                governance_id = %self.governance_id,
                                schema_id = %schema_id,
                                error = %error,
                                "Could not prepare artifact for network transport"
                            );
                            return Ok(ContractCompilation::Unavailable);
                        }
                    }
                    contracts.insert(schema_id, record.wasm_hash);
                }
                Err(error) => {
                    if matches!(error, CompilerError::Base64DecodeFailed { .. })
                    {
                        // A contract payload that does not even decode
                        // is a malformed request: nothing to vote, it
                        // is aborted (same as the evaluation's
                        // `InvalidEventRequest`).
                        if target.contract_changed {
                            return Ok(ContractCompilation::Abort(
                                error.to_string(),
                            ));
                        }
                        // The undecodable contract comes from the
                        // committed local state: it is corrupt, fail
                        // loud.
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Committed contract {} does not decode: {}",
                                    schema_id, error
                                ),
                            },
                        )
                        .await);
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
                        return Ok(ContractCompilation::Unavailable);
                    }
                    // Fatal local problems (disk, register, helpers,
                    // engine): the node is broken, fail loud.
                    if is_local_fatal_compiler_error(&error) {
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Can not compile contract {}: {}",
                                    schema_id, error
                                ),
                            },
                        )
                        .await);
                    }
                    // Anything else is a contract problem: every honest
                    // compiler reaches the same verdict, so it is voted.
                    return Ok(ContractCompilation::Failed(
                        CompilationError::CompilationFailed(format!(
                            "{}: {}",
                            schema_id, error
                        )),
                    ));
                }
            }
        }

        Ok(ContractCompilation::Compiled(contracts))
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
        issuers: BTreeSet<PublicKey>,
        issuer_any: bool,
        schemas: BTreeMap<SchemaType, Schema>,
        evaluators: BTreeMap<SchemaType, BTreeSet<PublicKey>>,
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
                issuers,
                issuer_any,
                schemas,
                evaluators,
            } => {
                self.gov_version = gov_version;
                self.issuers = issuers;
                self.issuer_any = issuer_any;
                self.schemas = schemas;
                self.evaluators = evaluators;
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

                let compilation = if let Err(error) =
                    self.check_data(&compilation_req)
                {
                    CompilationRes::Abort(error)
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
                            CompilationRes::Unavailable
                        }
                        // The requester is behind: it must sync its
                        // governance and retry the request.
                        GovVersionSync::RequesterBehind => {
                            CompilationRes::Reboot
                        }
                        GovVersionSync::Current => {
                            match self.create_res(ctx, &compilation_req).await {
                                Ok(compilation) => compilation,
                                Err(e) => {
                                    error!(
                                        msg_type = "NetworkRequest",
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
                            }
                        }
                    }
                };

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

                if let Err(e) = self
                    .network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::CompilationRes {
                                res: compilation,
                            },
                        },
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

                self.pending = None;

                debug!(
                    msg_type = "NetworkRequest",
                    request_id = %info.request_id,
                    version = info.version,
                    sender = %sender,
                    "Network compilation request processed successfully"
                );

                if self.stop {
                    ctx.stop(None).await;
                }
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
                        match self.serve_artifact(ctx, &contract_name).await?
                        {
                            Some(artifact) => {
                                ArtifactFetchResult::Artifact(artifact)
                            }
                            None => ArtifactFetchResult::NotServed,
                        }
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
        }

        Ok(())
    }
}
