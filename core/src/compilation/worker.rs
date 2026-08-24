use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use crate::{
    compilation::{request::CompilationReq, resolve_compile_targets},
    governance::model::Schema,
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::common::{
        GovVersionSync, crash_system, gov_version_sync,
        node::{SignTypesNode, get_sign},
    },
    subject::RequestSubjectData,
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

impl CompileWorker {
    /// Best-effort `Unavailable` notification for the in-flight network
    /// compilation request: the node is going down before answering, so
    /// the requester can replace this compiler immediately instead of
    /// waiting for the coordinator retries and timeout. Errors are
    /// logged and swallowed — the coordinator timeout is the fallback.
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
                        let mut contracts = BTreeMap::new();
                        for (schema_id, contract) in targets {
                            // Placeholder: the source hash stands in for the
                            // artifact hash until the real compilation lands.
                            let wasm_hash =
                                hash_borsh(&*self.hash.hasher(), &contract)
                                    .map_err(|e| ActorError::Functional {
                                        description: format!(
                                            "Can not hash contract source: {}",
                                            e
                                        ),
                                    })?;
                            contracts.insert(schema_id, wasm_hash);
                        }

                        CompilationResult::Ok {
                            response: CompilerResponse { contracts },
                            compile_req_hash,
                            req_subject_data_hash,
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
    },
    LocalCompilation {
        compilation_req: Signed<CompilationReq>,
    },
    NetworkRequest {
        compilation_req: Signed<CompilationReq>,
        sender: PublicKey,
        info: ComunicateInfo,
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
            } => {
                self.gov_version = gov_version;
                self.issuers = issuers;
                self.issuer_any = issuer_any;
                self.schemas = schemas;
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
                            error!(
                                msg_type = "LocalCompilation",
                                error = %e,
                                "Failed to send response to compilation actor"
                            );
                            return Err(crash_system(ctx, e).await);
                        }

                        debug!(
                            msg_type = "LocalCompilation",
                            "Local compilation completed successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            msg_type = "LocalCompilation",
                            path = %ctx.path().parent(),
                            "Compilation actor not found"
                        );
                        return Err(e);
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
        }

        Ok(())
    }
}
