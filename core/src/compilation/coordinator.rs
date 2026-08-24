use std::{sync::Arc, time::Duration};

use crate::{
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{common::crash_system, network::RetryNetwork},
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::identity::{HashAlgorithm, PublicKey, Signed, hash_borsh};

use ave_network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, IntervalStrategy,
    Message, NotPersistentActor, RetryActor, RetryMessage, Strategy,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Compilation, CompilationMessage, request::CompilationReq,
    response::CompilationRes,
};

/// A struct representing a CompileCoordinator actor.
#[derive(Clone, Debug)]
pub struct CompileCoordinator {
    node_key: PublicKey,
    request_id: String,
    version: u64,
    network: Arc<NetworkSender>,
    hash: HashAlgorithm,
}

impl CompileCoordinator {
    pub const fn new(
        node_key: PublicKey,
        request_id: String,
        version: u64,
        network: Arc<NetworkSender>,
        hash: HashAlgorithm,
    ) -> Self {
        Self {
            node_key,
            request_id,
            version,
            network,
            hash,
        }
    }

    fn verify_result_response(
        &self,
        result: &super::response::CompilationResult,
        result_hash: &ave_common::identity::DigestIdentifier,
        result_hash_signature: &ave_common::identity::Signature,
    ) -> Result<(), ActorError> {
        let hash = hash_borsh(&*self.hash.hasher(), result).map_err(|e| {
            error!(
                msg_type = "NetworkResponse",
                error = %e,
                "Failed to create compilation result hash"
            );

            ActorError::Functional {
                description: format!("Can not verify signature: {}", e),
            }
        })?;

        if &hash != result_hash {
            error!(
                msg_type = "NetworkResponse",
                result_hash = %result_hash,
                generated_hash = %hash,
                "Result hash is invalid"
            );

            return Err(ActorError::Functional {
                description: "Result hash is invalid".to_string(),
            });
        }

        result_hash_signature.verify(result_hash).map_err(|e| {
            error!(
                msg_type = "NetworkResponse",
                error = %e,
                "Failed to verify compilation result hash signature"
            );

            ActorError::Functional {
                description: format!("Can not verify signature: {}", e),
            }
        })?;

        if result_hash_signature.signer != self.node_key {
            error!(
                msg_type = "NetworkResponse",
                expected_signer = %self.node_key,
                actual_signer = %result_hash_signature.signer,
                "Compilation result hash signature signer mismatch"
            );

            return Err(ActorError::Functional {
                description:
                    "Compilation result hash signature signer mismatch"
                        .to_string(),
            });
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum CompileCoordinatorMessage {
    EndRetry,
    NetworkCompilation {
        compilation_req: Box<Signed<CompilationReq>>,
        node_key: PublicKey,
    },
    NetworkResponse {
        compilation_res: Box<CompilationRes>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
}

impl Message for CompileCoordinatorMessage {}

#[async_trait]
impl Actor for CompileCoordinator {
    type Event = ();
    type Message = CompileCoordinatorMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("CompileCoordinator", id),
            |parent_span| info_span!(parent: parent_span, "CompileCoordinator", id),
        )
    }
}

impl NotPersistentActor for CompileCoordinator {}

#[async_trait]
impl Handler<Self> for CompileCoordinator {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: CompileCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            CompileCoordinatorMessage::EndRetry => {
                warn!(
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Retry exhausted, notifying parent and stopping"
                );

                match ctx.get_parent::<Compilation>().await {
                    Ok(compilation_actor) => {
                        if let Err(e) = compilation_actor
                            .tell(CompilationMessage::Response {
                                compilation_res: CompilationRes::TimeOut,
                                sender: self.node_key.clone(),
                            })
                            .await
                        {
                            error!(
                                error = %e,
                                "Failed to send timeout response to compilation actor"
                            );
                            crash_system(ctx, e).await;
                        } else {
                            debug!(
                                request_id = %self.request_id,
                                version = self.version,
                                "Timeout response sent to compilation actor"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            path = %ctx.path().parent(),
                            "Compilation actor not found"
                        );
                        crash_system(ctx, e).await;
                    }
                }

                ctx.stop(None).await;
            }
            CompileCoordinatorMessage::NetworkCompilation {
                compilation_req,
                node_key,
            } => {
                // The compilation phase only exists for governance facts.
                let receiver_actor = format!(
                    "/user/node/subject_manager/{}/compiler",
                    compilation_req.content().governance_id
                );

                // Fire the event that starts the retries.
                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: self.request_id.clone(),
                        version: self.version,
                        receiver: node_key.clone(),
                        receiver_actor,
                    },
                    message: ActorMessage::CompilationReq {
                        req: compilation_req,
                    },
                };

                let target = RetryNetwork::new(self.network.clone());

                #[cfg(any(test, feature = "test"))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    1,
                    Duration::from_secs(20),
                ));
                #[cfg(not(any(test, feature = "test")))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    3,
                    Duration::from_secs(60),
                ));

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    CompileCoordinatorMessage::EndRetry,
                );

                let retry = match ctx
                    .create_child::<RetryActor<RetryNetwork>, _>(
                        "retry",
                        retry_actor,
                    )
                    .await
                {
                    Ok(retry) => retry,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkCompilation",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkCompilation",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(crash_system(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkCompilation",
                    request_id = %self.request_id,
                    version = self.version,
                    node_key = %node_key,
                    "Compilation request sent to network with retry"
                );
            }
            CompileCoordinatorMessage::NetworkResponse {
                compilation_res,
                request_id,
                version,
                sender,
            } => {
                if request_id == self.request_id && version == self.version {
                    if self.node_key != sender {
                        error!(
                            msg_type = "NetworkResponse",
                            expected_node = %self.node_key,
                            network_sender = %sender,
                            "Compilation response sender mismatch"
                        );
                        return Err(ActorError::Functional {
                            description:
                                "We received a compilation response from an unexpected sender"
                                    .to_string(),
                        });
                    }

                    if let CompilationRes::Response {
                        result,
                        result_hash,
                        result_hash_signature,
                    } = &*compilation_res
                    {
                        self.verify_result_response(
                            result,
                            result_hash,
                            result_hash_signature,
                        )?;
                    }

                    // Compilation actor.
                    match ctx.get_parent::<Compilation>().await {
                        Ok(compilation_actor) => {
                            if let Err(e) = compilation_actor
                                .tell(CompilationMessage::Response {
                                    compilation_res: *compilation_res,
                                    sender: self.node_key.clone(),
                                })
                                .await
                            {
                                error!(
                                    msg_type = "NetworkResponse",
                                    error = %e,
                                    "Failed to send response to compilation actor"
                                );
                                return Err(crash_system(ctx, e).await);
                            }
                        }
                        Err(e) => {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                path = %ctx.path().parent(),
                                "Compilation actor not found"
                            );

                            return Err(crash_system(ctx, e).await);
                        }
                    }

                    'retry: {
                        let Ok(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            debug!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                "Retry actor not found while closing compilation coordinator"
                            );
                            // It does not matter here: stopping this
                            // actor stops the child.
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            warn!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to end retry actor"
                            );
                            // It does not matter here: stopping this
                            // actor stops the child.
                            break 'retry;
                        };
                    }

                    debug!(
                        msg_type = "NetworkResponse",
                        request_id = %self.request_id,
                        version = self.version,
                        sender = %sender,
                        "Compilation response processed successfully"
                    );

                    ctx.stop(None).await;
                } else {
                    warn!(
                        msg_type = "NetworkResponse",
                        expected_request_id = %self.request_id,
                        expected_version = self.version,
                        received_request_id = %request_id,
                        received_version = version,
                        "Response with mismatched request id or version"
                    );
                }
            }
        }

        Ok(())
    }
}
