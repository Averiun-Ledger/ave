//! # Compilation module.
//! This module contains the compilation phase logic for the Ave protocol.
//! Only governance fact events that add a schema or change a contract (or
//! its initial value) go through this phase, and only the governance
//! owner coordinates it — the same shape as the governance evaluation.
//!
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::sync::Arc;

use crate::{
    compilation::{
        coordinator::{CompileCoordinator, CompileCoordinatorMessage},
        worker::{CompileWorker, CompileWorkerMessage},
    },
    evaluation::response::ResponseSummary,
    governance::{
        data::GovernanceData,
        model::{Quorum, Schema},
    },
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::{
        common::{
            abort_req, crash_system, send_reboot_to_req, take_random_signers,
        },
        event::{CompilationData, CompilationResponse},
    },
    request::manager::{RebootType, RequestManager, RequestManagerMessage},
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::{
    SchemaType, ValueWrapper,
    governance::GovernanceEvent,
    identity::{
        CryptoError, DigestIdentifier, HashAlgorithm, PublicKey, Signature,
        Signed, hash_borsh,
    },
};
use serde_json::Value;

use request::CompilationReq;
use response::{CompilationError, CompilationRes, CompilerResponse};

use tracing::{Span, debug, error, info_span, warn};

pub mod artifact;
/// gRPC client of the embedded compiler pool — test builds only
/// (production nodes compile in-process, see `support`).
#[cfg(feature = "test")]
pub mod client;
pub mod contract_compiler;
pub mod coordinator;
pub mod error;
pub mod pipeline;
pub mod request;
pub mod response;
#[cfg(feature = "compiler-service")]
pub mod service;
#[cfg(feature = "compiler-service")]
pub mod service_config;
pub mod support;
pub mod worker;

/// Schemas whose contract must go through the compilation phase for this
/// governance fact payload.
///
/// Every added schema plus every change with a
/// new contract or a new initial value. `None` when the payload is not a
/// valid governance event — evaluation will fail the event instead.
pub fn schemas_to_compile(
    payload: &ValueWrapper,
) -> Option<BTreeSet<SchemaType>> {
    let event: GovernanceEvent =
        serde_json::from_value(payload.0.clone()).ok()?;

    let mut schemas = BTreeSet::new();
    if let Some(schemas_event) = &event.schemas {
        if let Some(add) = &schemas_event.add {
            schemas.extend(add.iter().map(|schema| schema.id.clone()));
        }
        if let Some(change) = &schemas_event.change {
            schemas.extend(
                change
                    .iter()
                    .filter(|schema| {
                        schema.new_contract.is_some()
                            || schema.new_initial_value.is_some()
                    })
                    .map(|schema| schema.actual_id.clone()),
            );
        }
    }

    Some(schemas)
}

/// Full compilation set for a governance fact against the committed
/// governance state: the payload set above, plus — when the event
/// changes the toolchain pin — every existing schema, recompiled under
/// the new pin with fresh evidence (a pin switch never reuses old-pin's
/// builds). `None` exactly when `schemas_to_compile` is `None`.
///
/// An unknown pin short-circuits to the empty set: no node can build
/// it, so compiling would reboot forever without ever reaching the
/// evaluation that deterministically rejects it. The registry is
/// global, hence manager and validators take the identical decision
/// here, by construction.
pub fn compilation_set(
    payload: &ValueWrapper,
    pre: &crate::governance::data::GovernanceData,
) -> Option<BTreeSet<SchemaType>> {
    let mut schemas = schemas_to_compile(payload)?;
    let event: GovernanceEvent =
        serde_json::from_value(payload.0.clone()).ok()?;
    if let Some(new_pin) = event.toolchain.as_ref()
        && ave_common::governance::toolchain_info(new_pin).is_none()
    {
        return Some(BTreeSet::new());
    }
    if event
        .toolchain
        .as_ref()
        .is_some_and(|new_pin| *new_pin != pre.toolchain)
    {
        schemas.extend(pre.schemas.keys().cloned());
        // Removed schemas leave with the event: building them would
        // waste work and anchor bytes nobody can ever serve.
        if let Some(remove) = event
            .schemas
            .as_ref()
            .and_then(|schemas| schemas.remove.as_ref())
        {
            for removed in remove {
                schemas.remove(removed);
            }
        }
    }
    Some(schemas)
}

/// Contract sources coming in a governance fact payload, paired with
/// their schema id.
///
/// Every added schema plus every change with a new
/// contract. These are the only contracts the compilation phase stages —
/// unchanged contracts reuse the official artifact. Returns an empty vec
/// when the payload is not a valid governance event.
pub fn payload_contract_sources(
    payload: &ValueWrapper,
) -> Vec<(SchemaType, String)> {
    let mut sources = Vec::new();
    let Ok(event) =
        serde_json::from_value::<GovernanceEvent>(payload.0.clone())
    else {
        return sources;
    };

    if let Some(schemas_event) = event.schemas {
        if let Some(add) = schemas_event.add {
            sources.extend(
                add.into_iter().map(|schema| (schema.id, schema.contract)),
            );
        }
        if let Some(change) = schemas_event.change {
            sources.extend(change.into_iter().filter_map(|schema| {
                schema
                    .new_contract
                    .map(|contract| (schema.actual_id, contract))
            }));
        }
    }

    sources
}

/// Everything the compilation phase needs for one schema: the effective
/// contract source and initial value, and whether the contract itself
/// changes.
///
/// Added or changed contracts come from the event; the source
/// (and initial value) of an unchanged one comes from the committed
/// governance schemas.
#[derive(Debug, Clone)]
pub struct CompileTarget {
    pub source: String,
    pub initial_value: Value,
    pub contract_changed: bool,
    /// Pin-switch rebuild: the source comes from the committed state
    /// (like an unchanged contract) but must be BUILT FRESH under the
    /// new pin into staging — never reloaded. Reloading would vote the
    /// old-pin's bytes (and anchor) under the new pin, defeating the
    /// switch and breaking every later heal against the new anchor.
    pub force_rebuild: bool,
}

/// Effective compile target of every schema to compile, resolving
/// changes against the committed governance schemas.
///
/// What the event does
/// not provide comes from the committed state, which is identical at the
/// same governance version — including a pin switch with no schema
/// changes, which recompiles every committed schema (see below).
pub fn resolve_compile_targets(
    payload: &ValueWrapper,
    schemas: &BTreeMap<SchemaType, Schema>,
    committed_pin: &str,
) -> Result<BTreeMap<SchemaType, CompileTarget>, CompilationError> {
    let event: GovernanceEvent = serde_json::from_value(payload.0.clone())
        .map_err(|e| CompilationError::InvalidEvent(e.to_string()))?;

    let mut targets = BTreeMap::new();
    if let Some(schemas_event) = &event.schemas {
        if let Some(add) = &schemas_event.add {
            for schema in add {
                targets.insert(
                    schema.id.clone(),
                    CompileTarget {
                        source: schema.contract.clone(),
                        initial_value: schema.initial_value.clone(),
                        contract_changed: true,
                        force_rebuild: false,
                    },
                );
            }
        }
        if let Some(change) = &schemas_event.change {
            for schema in change {
                if schema.new_contract.is_none()
                    && schema.new_initial_value.is_none()
                {
                    continue;
                }

                // A change references an existing schema: its committed
                // data completes whatever the event does not change.
                let Some(current) = schemas.get(&schema.actual_id) else {
                    return Err(CompilationError::InvalidEvent(format!(
                        "Schema {} does not exist",
                        schema.actual_id
                    )));
                };

                let contract_changed = schema.new_contract.is_some();
                targets.insert(
                    schema.actual_id.clone(),
                    CompileTarget {
                        source: schema
                            .new_contract
                            .clone()
                            .unwrap_or_else(|| current.contract.clone()),
                        initial_value: schema
                            .new_initial_value
                            .clone()
                            .unwrap_or_else(|| current.initial_value.0.clone()),
                        contract_changed,
                        force_rebuild: false,
                    },
                );
            }
        }
    }

    // Pin switch: every committed schema recompiles under the new pin
    // on top of whatever the payload carries — the manager decides
    // with `compilation_set`, which extends identically, so worker,
    // manager and validators can never disagree on the set (a missing
    // schema would fail coverage, an extra one would overwrite an
    // anchor the event did not touch). Payload schemas keep their own
    // targets; committed-only ones rebuild fresh (`force_rebuild`).
    // On a switch EVERYTHING rebuilds, including payload schemas and
    // init-only changes: their load path would otherwise vote old
    // pin's bytes (init values do not shape builds, toolchains do).
    // Removed schemas are excluded on both sides: they leave with the
    // event, building them would anchor bytes nobody can serve.
    if let Some(new_pin) = &event.toolchain
        && new_pin != committed_pin
    {
        // Everything the switch touches rebuilds: payload targets
        // included (their load path would vote old pin's bytes).
        for target in targets.values_mut() {
            target.force_rebuild = true;
        }
        let removed = event
            .schemas
            .as_ref()
            .and_then(|schemas| schemas.remove.as_ref());
        for (schema_id, schema) in schemas {
            if removed.is_some_and(|remove| remove.contains(schema_id)) {
                continue;
            }
            targets.entry(schema_id.clone()).or_insert(CompileTarget {
                source: schema.contract.clone(),
                initial_value: schema.initial_value.0.clone(),
                contract_changed: false,
                force_rebuild: true,
            });
        }
    }

    Ok(targets)
}

/// Whether a governance fact enters the compilation phase: the schema
/// set above is non-empty, or it is a bare switch to a KNOWN pin with
/// nothing to build. The bare switch is a capacity vote — compilers
/// attest by voting, not by building — so a pin can never commit
/// without a builder quorum behind it. Unknown pins return false here
/// (evaluation rejects them); same-pin no-ops too (rejected as
/// no-ops). Manager and validators share this decision, so they can
/// never disagree on whether evidence must exist.
pub fn needs_compilation_evidence(
    payload: &ValueWrapper,
    pre: &crate::governance::data::GovernanceData,
) -> bool {
    if compilation_set(payload, pre).is_some_and(|schemas| !schemas.is_empty())
    {
        return true;
    }
    serde_json::from_value::<GovernanceEvent>(payload.0.clone())
        .ok()
        .and_then(|event| event.toolchain)
        .is_some_and(|new_pin| {
            new_pin != pre.toolchain
                && ave_common::governance::toolchain_info(&new_pin).is_some()
        })
}

/// A struct representing a Compilation actor.
pub struct Compilation {
    our_key: Arc<PublicKey>,
    // Quorum
    quorum: Quorum,
    // Actual responses
    compilers_response: Vec<(CompilerResponse, DigestIdentifier)>,
    // Compilers quantity
    compilers_quantity: u32,

    compilers_signatures: Vec<Signature>,

    request: Signed<CompilationReq>,

    /// The governance state before the event, owner-side only: it feeds
    /// the local compiler worker (schemas and issuers). It never travels
    /// in the network request — remote compilers resolve against their
    /// own committed state, identical at the same governance version.
    state: GovernanceData,

    hash: HashAlgorithm,

    network: Arc<NetworkSender>,

    request_id: DigestIdentifier,

    version: u64,

    errors: Vec<(CompilationError, DigestIdentifier)>,

    compilation_request_hash: DigestIdentifier,

    /// The round is closed (result, reboot or abort already sent): late
    /// responses are ignored. Responses only matter until the quorum
    /// closes or the compiler list runs out.
    closed: bool,

    current_compilers: HashSet<PublicKey>,

    pending_compilers: HashSet<PublicKey>,
}

impl Compilation {
    fn observe_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("compilation", result);
        }
    }

    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<CompilationReq>,
        quorum: Quorum,
        state: GovernanceData,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
            our_key,
            hash,
            network,
            request,
            quorum,
            state,
            current_compilers: HashSet::new(),
            errors: vec![],
            compilation_request_hash: DigestIdentifier::default(),
            compilers_quantity: 0,
            compilers_response: vec![],
            compilers_signatures: vec![],
            pending_compilers: HashSet::new(),
            closed: false,
            request_id: DigestIdentifier::default(),
            version: 0,
        }
    }

    fn check_compiler(&mut self, compiler: PublicKey) -> bool {
        self.current_compilers.remove(&compiler)
    }

    async fn create_compilers(
        &self,
        ctx: &mut ActorContext<Self>,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        if signer != *self.our_key {
            let child = ctx
                .create_child(
                    &format!("{}", signer),
                    CompileCoordinator::new(
                        signer.clone(),
                        self.request_id.to_string(),
                        self.version,
                        self.network.clone(),
                        self.hash,
                    ),
                )
                .await?;

            child
                .tell(CompileCoordinatorMessage::NetworkCompilation {
                    compilation_req: Box::new(self.request.clone()),
                    node_key: signer,
                })
                .await?
        } else {
            let (issuers, issuer_any) = self.state.governance_issuers();
            let child = ctx
                .create_child(
                    &format!("{}", signer),
                    CompileWorker {
                        node_key: (*self.our_key).clone(),
                        our_key: self.our_key.clone(),
                        governance_id: self
                            .request
                            .content()
                            .governance_id
                            .clone(),
                        gov_version: self.request.content().gov_version,
                        issuers,
                        issuer_any,
                        schemas: self.state.schemas.clone(),
                        // Ephemeral request workers never serve artifacts
                        // (they live outside the well-known serving
                        // path): empty whitelist rejects every probe.
                        evaluators: BTreeMap::new(),
                        toolchain_pin: self
                            .request
                            .content()
                            .pin
                            .clone(),
                        committed_pin: self.state.toolchain.clone(),
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

            child
                .tell(CompileWorkerMessage::LocalCompilation {
                    compilation_req: self.request.clone(),
                })
                .await?
        }

        Ok(())
    }

    fn check_responses(&self) -> ResponseSummary {
        let res_set: HashSet<(CompilerResponse, DigestIdentifier)> =
            HashSet::from_iter(self.compilers_response.iter().cloned());
        let error_set: HashSet<(CompilationError, DigestIdentifier)> =
            HashSet::from_iter(self.errors.iter().cloned());

        if res_set.len() == 1 && error_set.is_empty() {
            ResponseSummary::Ok
        } else if error_set.len() == 1 && res_set.is_empty() {
            ResponseSummary::Error
        } else {
            ResponseSummary::Reboot
        }
    }

    fn build_compilation_data(
        &self,
        is_ok: bool,
    ) -> Result<CompilationData, ActorError> {
        if is_ok {
            Ok(CompilationData {
                compile_req_signature: self.request.signature().clone(),
                compile_req_hash: self.compilation_request_hash.clone(),
                compilers_signatures: self.compilers_signatures.clone(),
                response: CompilationResponse::Ok {
                    result: self.compilers_response[0].0.clone(),
                    result_hash: self.compilers_response[0].1.clone(),
                },
            })
        } else {
            Ok(CompilationData {
                compile_req_signature: self.request.signature().clone(),
                compile_req_hash: self.compilation_request_hash.clone(),
                compilers_signatures: self.compilers_signatures.clone(),
                response: CompilationResponse::Error {
                    result: self.errors[0].0.clone(),
                    result_hash: self.errors[0].1.clone(),
                },
            })
        }
    }

    async fn send_compilation_to_req(
        &self,
        ctx: &ActorContext<Self>,
        response: CompilationData,
    ) -> Result<(), ActorError> {
        let req_actor = ctx.get_parent::<RequestManager>().await?;

        req_actor
            .tell(RequestManagerMessage::CompilationRes {
                request_id: self.request_id.clone(),
                compile_req: Box::new(self.request.content().clone()),
                compile_res: response,
            })
            .await
    }

    fn create_compile_req_hash(&self) -> Result<DigestIdentifier, CryptoError> {
        hash_borsh(&*self.hash.hasher(), &self.request)
    }

    /// Stores a compiler response. A response that does not bind to
    /// this request (request-hash mismatch) is dropped: the responder
    /// was already removed from the current set, and the
    /// round-exhaustion logic replaces it or reboots the request.
    fn store_response_result(
        &mut self,
        result: response::CompilationResult,
        result_hash: DigestIdentifier,
        result_hash_signature: Signature,
    ) {
        let compile_req_hash = match &result {
            response::CompilationResult::Ok {
                compile_req_hash, ..
            }
            | response::CompilationResult::Error {
                compile_req_hash, ..
            } => compile_req_hash,
        };
        if *compile_req_hash != self.compilation_request_hash {
            error!(
                msg_type = "Response",
                expected_hash = %self.compilation_request_hash,
                received_hash = %compile_req_hash,
                "Invalid compilation request hash"
            );
            return;
        }

        match result {
            response::CompilationResult::Ok { response, .. } => {
                self.compilers_response.push((response, result_hash));
            }
            response::CompilationResult::Error { error, .. } => {
                self.errors.push((error, result_hash));
            }
        }

        self.compilers_signatures.push(result_hash_signature);
    }
}

#[derive(Debug, Clone)]
pub enum CompilationMessage {
    Create {
        request_id: DigestIdentifier,
        version: u64,
        signers: HashSet<PublicKey>,
    },
    Response {
        compilation_res: CompilationRes,
        sender: PublicKey,
    },
}

impl Message for CompilationMessage {}

impl NotPersistentActor for Compilation {}

#[async_trait]
impl Actor for Compilation {
    type Event = ();
    type Message = CompilationMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Compilation"),
            |parent_span| info_span!(parent: parent_span, "Compilation"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Compilation {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: CompilationMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            CompilationMessage::Create {
                request_id,
                version,
                signers,
            } => {
                let compile_req_hash = match self.create_compile_req_hash() {
                    Ok(digest) => digest,
                    Err(e) => {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to create compilation request hash"
                        );
                        return Err(crash_system(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Cannot create compilation request hash: {}",
                                    e
                                ),
                            },
                        )
                        .await);
                    }
                };

                self.compilation_request_hash = compile_req_hash;
                self.compilers_quantity = signers.len() as u32;
                self.request_id = request_id.clone();
                self.version = version;

                let compilers_quantity = self
                    .quorum
                    .get_signers(self.compilers_quantity, signers.len() as u32);

                let (current_comp, pending_comp) =
                    take_random_signers(signers, compilers_quantity as usize);
                self.current_compilers.clone_from(&current_comp);
                self.pending_compilers.clone_from(&pending_comp);

                for signer in current_comp.clone() {
                    if let Err(e) =
                        self.create_compilers(ctx, signer.clone()).await
                    {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            signer = %signer,
                            "Failed to create compiler"
                        );
                        // Drop the failed signer so the round can
                        // exhaust itself instead of hanging forever
                        // waiting for a response that will never come.
                        self.current_compilers.remove(&signer);
                    }
                }

                if self.current_compilers.is_empty() {
                    if let Err(e) = send_reboot_to_req(
                        ctx,
                        request_id.clone(),
                        self.request.content().governance_id.clone(),
                        RebootType::TimeOut,
                    )
                    .await
                    {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to send reboot to request actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                    Self::observe_event("reboot");
                    self.closed = true;
                    return Ok(());
                }

                debug!(
                    msg_type = "Create",
                    request_id = %request_id,
                    version = version,
                    compilers_count = current_comp.len(),
                    "Compilation created and compilers initialized"
                );
            }
            CompilationMessage::Response {
                compilation_res,
                sender,
            } => {
                if !self.closed {
                    // If node is in compiler list
                    if self.check_compiler(sender.clone()) {
                        // Check type of compilation
                        match compilation_res {
                            CompilationRes::Response {
                                result,
                                result_hash,
                                result_hash_signature,
                            } => {
                                self.store_response_result(
                                    result,
                                    result_hash,
                                    result_hash_signature,
                                );
                            }
                            CompilationRes::TimeOut => {
                                Self::observe_event("timeout");
                            }
                            // Same handling as a timeout — the compiler is
                            // dropped from the current set and replaced
                            // from the pending pool — but explicit and
                            // immediate: no coordinator timeout wait.
                            CompilationRes::Unavailable => {
                                Self::observe_event("unavailable");
                            }
                            // Same as unavailable (drop + replace), but
                            // pin-scoped: the compiler can not build under
                            // this request's pin, now or ever — the retry
                            // only helps if another compiler covers it.
                            CompilationRes::NoToolchain { .. } => {
                                Self::observe_event("no_toolchain");
                            }
                            CompilationRes::Abort(error) => {
                                Self::observe_event("abort");
                                if let Err(e) = abort_req(
                                    ctx,
                                    self.request_id.clone(),
                                    sender.clone(),
                                    error.clone(),
                                    self.request.content().sn,
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        request_id = %self.request_id,
                                        sender = %sender,
                                        abort_reason = %error,
                                        error = %e,
                                        "Failed to abort request"
                                    );
                                    return Err(crash_system(ctx, e).await);
                                };

                                debug!(
                                    msg_type = "Response",
                                    request_id = %self.request_id,
                                    sender = %sender,
                                    abort_reason = %error,
                                    "Compilation aborted"
                                );

                                self.closed = true;

                                return Ok(());
                            }
                            CompilationRes::Reboot => {
                                Self::observe_event("reboot");
                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content()
                                        .governance_id
                                        .clone(),
                                    RebootType::Normal,
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(crash_system(ctx, e).await);
                                }

                                self.closed = true;

                                return Ok(());
                            }
                            // Consumed by the coordinator (it cancels
                            // the request retry and arms the result
                            // deadline there): it is never forwarded to
                            // this actor. Defensive arm only.
                            CompilationRes::Working => {}
                        };

                        if self.quorum.check_quorum(
                            self.compilers_quantity,
                            (self.compilers_response.len() + self.errors.len())
                                as u32,
                        ) {
                            let summary = self.check_responses();
                            if matches!(summary, ResponseSummary::Reboot)
                                && let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content()
                                        .governance_id
                                        .clone(),
                                    RebootType::Diff,
                                )
                                .await
                            {
                                error!(
                                    msg_type = "Response",
                                    error = %e,
                                    "Failed to send reboot to request actor"
                                );
                                return Err(crash_system(ctx, e).await);
                            }
                            if matches!(summary, ResponseSummary::Reboot) {
                                Self::observe_event("reboot");
                                self.closed = true;
                                return Ok(());
                            }

                            let response = match self
                                .build_compilation_data(summary.is_ok())
                            {
                                Ok(response) => response,
                                Err(e) => {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to create compilation response"
                                    );
                                    return Err(crash_system(ctx, e).await);
                                }
                            };

                            if let Err(e) = self
                                .send_compilation_to_req(ctx, response.clone())
                                .await
                            {
                                error!(
                                    msg_type = "Response",
                                    error = %e,
                                    "Failed to send compilation to request actor"
                                );
                                return Err(crash_system(ctx, e).await);
                            };

                            self.closed = true;

                            // The `Reboot` summary returned above, so only
                            // terminal success/error observations remain.
                            Self::observe_event(if summary.is_ok() {
                                "success"
                            } else {
                                "error"
                            });

                            debug!(
                                msg_type = "Response",
                                request_id = %self.request_id,
                                version = self.version,
                                is_ok = summary.is_ok(),
                                "Compilation completed and sent to request"
                            );
                        } else if self.current_compilers.is_empty()
                            && !self.pending_compilers.is_empty()
                        {
                            let compilers_quantity = self.quorum.get_signers(
                                self.compilers_quantity,
                                self.pending_compilers.len() as u32,
                            );

                            let (current_comp, pending_comp) =
                                take_random_signers(
                                    self.pending_compilers.clone(),
                                    compilers_quantity as usize,
                                );
                            self.current_compilers.clone_from(&current_comp);
                            self.pending_compilers.clone_from(&pending_comp);

                            for signer in current_comp.clone() {
                                if let Err(e) = self
                                    .create_compilers(ctx, signer.clone())
                                    .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        signer = %signer,
                                        "Failed to create compiler from pending pool"
                                    );
                                    // Drop the failed signer so the
                                    // round can exhaust itself instead
                                    // of hanging forever.
                                    self.current_compilers.remove(&signer);
                                }
                            }

                            if self.current_compilers.is_empty() {
                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content()
                                        .governance_id
                                        .clone(),
                                    RebootType::TimeOut,
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(crash_system(ctx, e).await);
                                }
                                Self::observe_event("reboot");
                                self.closed = true;
                            }

                            debug!(
                                msg_type = "Response",
                                new_compilers = current_comp.len(),
                                "Created additional compilers from pending pool"
                            );
                        } else if self.current_compilers.is_empty()
                            && let Err(e) = send_reboot_to_req(
                                ctx,
                                self.request_id.clone(),
                                self.request.content().governance_id.clone(),
                                RebootType::TimeOut,
                            )
                            .await
                        {
                            error!(
                                msg_type = "Response",
                                error = %e,
                                "Failed to send reboot to request actor"
                            );
                            return Err(crash_system(ctx, e).await);
                        } else if self.current_compilers.is_empty() {
                            Self::observe_event("reboot");
                            self.closed = true;
                        }
                    } else {
                        warn!(
                            msg_type = "Response",
                            sender = %sender,
                            "Response from unexpected sender"
                        );
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ave_common::{SchemaType, ValueWrapper};

    use super::resolve_compile_targets;
    use crate::governance::model::Schema;

    fn committed_schemas() -> BTreeMap<SchemaType, Schema> {
        BTreeMap::from([(
            SchemaType::Type("Example".to_owned()),
            Schema {
                contract: "contract source".to_owned(),
                initial_value: ValueWrapper(serde_json::json!({
                    "one": 0
                })),
                viewpoints: Default::default(),
            },
        )])
    }

    #[test]
    fn pin_switch_recompiles_force_rebuild_into_staging() {
        // Pin switch with no payload schemas: every committed schema
        // becomes a target with committed source but forced fresh
        // build — reloading would vote the old pin's bytes (and
        // anchor) under the new pin.
        let targets = resolve_compile_targets(
            &ValueWrapper(serde_json::json!({ "toolchain": "rust-1.98.1_sdk-0.8.0_wasm32" })),
            &committed_schemas(),
            "rust-1.95.0_sdk-0.8.0_wasm32",
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        let target = targets
            .get(&SchemaType::Type("Example".to_owned()))
            .unwrap();
        assert_eq!(target.source, "contract source");
        assert!(!target.contract_changed);
        assert!(target.force_rebuild);
    }

    #[test]
    fn no_switch_no_force_rebuild() {
        // Same pin and no schemas: nothing to compile at all (the
        // manager never asks; the worker would reject as invalid).
        let targets = resolve_compile_targets(
            &ValueWrapper(serde_json::json!({ "toolchain": "rust-1.95.0_sdk-0.8.0_wasm32" })),
            &committed_schemas(),
            "rust-1.95.0_sdk-0.8.0_wasm32",
        )
        .unwrap();
        assert!(targets.is_empty());
    }

    #[test]
    fn pin_switch_unions_payload_and_committed() {
        // Switch plus one add: the add keeps its changed target and
        // every OTHER committed schema joins as force-rebuild — the
        // exact union the manager and validators decide.
        let targets = resolve_compile_targets(
            &ValueWrapper(serde_json::json!({
                "schemas": {
                    "add": [
                        {
                            "id": "Beta",
                            "contract": "new source",
                            "initial_value": { "one": 1 }
                        }
                    ]
                },
                "toolchain": "rust-1.98.1_sdk-0.8.0_wasm32"
            })),
            &committed_schemas(),
            "rust-1.95.0_sdk-0.8.0_wasm32",
        )
        .unwrap();
        assert_eq!(targets.len(), 2);
        let beta = targets
            .get(&SchemaType::Type("Beta".to_owned()))
            .unwrap();
        assert!(beta.contract_changed);
        assert!(beta.force_rebuild);
        let example = targets
            .get(&SchemaType::Type("Example".to_owned()))
            .unwrap();
        assert!(!example.contract_changed);
        assert!(example.force_rebuild);
    }

    #[test]
    fn same_pin_never_force_rebuilds() {        // Same pin plus an add: the add builds normally, nothing else
        // is touched — force_rebuild is switch-only.
        let targets = resolve_compile_targets(
            &ValueWrapper(serde_json::json!({
                "schemas": {
                    "add": [
                        {
                            "id": "Beta",
                            "contract": "new source",
                            "initial_value": { "one": 1 }
                        }
                    ]
                },
                "toolchain": "rust-1.95.0_sdk-0.8.0_wasm32"
            })),
            &committed_schemas(),
            "rust-1.95.0_sdk-0.8.0_wasm32",
        )
        .unwrap();
        assert_eq!(targets.len(), 1);
        let beta = targets
            .get(&SchemaType::Type("Beta".to_owned()))
            .unwrap();
        assert!(beta.contract_changed);
        assert!(!beta.force_rebuild);
    }

    #[test]
    fn switch_skips_removed_schemas() {
        // Switch plus remove: the removed schema is excluded on both
        // sides — building it would anchor bytes nobody can serve.
        let targets = resolve_compile_targets(
            &ValueWrapper(serde_json::json!({
                "schemas": {
                    "remove": ["Example"]
                },
                "toolchain": "rust-1.98.1_sdk-0.8.0_wasm32"
            })),
            &committed_schemas(),
            "rust-1.95.0_sdk-0.8.0_wasm32",
        )
        .unwrap();
        assert!(targets.is_empty());
    }
}
