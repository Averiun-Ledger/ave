use std::{sync::Arc, time::Duration};

use crate::{
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{common::emit_fail, network::RetryNetwork},
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::identity::{PublicKey, Signed};

use network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction,
    FixedIntervalStrategy, Handler, Message, NotPersistentActor, RetryActor,
    RetryMessage, Strategy,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Evaluation, EvaluationMessage, request::EvaluationReq,
    response::EvaluationRes,
};

/// A struct representing a EvalCoordinator actor.
#[derive(Clone, Debug)]
pub struct EvalCoordinator {
    node_key: PublicKey,
    request_id: String,
    version: u64,
    network: Arc<NetworkSender>,
}

impl EvalCoordinator {
    pub const fn new(
        node_key: PublicKey,
        request_id: String,
        version: u64,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
            node_key,
            request_id,
            version,
            network,
        }
    }
}

#[derive(Debug, Clone)]
pub enum EvalCoordinatorMessage {
    NetworkEvaluation {
        evaluation_req: Box<Signed<EvaluationReq>>,
        node_key: PublicKey,
    },
    NetworkResponse {
        evaluation_res: Box<Signed<EvaluationRes>>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
}

impl Message for EvalCoordinatorMessage {}

#[async_trait]
impl Actor for EvalCoordinator {
    type Event = ();
    type Message = EvalCoordinatorMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("EvalCoordinator", id),
            |parent_span| info_span!(parent: parent_span, "EvalCoordinator", id),
        )
    }
}

impl NotPersistentActor for EvalCoordinator {}

#[async_trait]
impl Handler<Self> for EvalCoordinator {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: EvalCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            EvalCoordinatorMessage::NetworkEvaluation {
                evaluation_req,
                node_key,
            } => {
                let receiver_actor =
                    if evaluation_req.content().schema_id.is_gov() {
                        format!(
                            "/user/node/{}/evaluator",
                            evaluation_req.content().governance_id
                        )
                    } else {
                        format!(
                            "/user/node/{}/{}_evaluation",
                            evaluation_req.content().governance_id,
                            evaluation_req.content().schema_id
                        )
                    };

                // Lanzar evento donde lanzar los retrys
                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: self.request_id.clone(),
                        version: self.version,
                        receiver: node_key.clone(),
                        receiver_actor,
                    },
                    message: ActorMessage::EvaluationReq {
                        req: evaluation_req,
                    },
                };

                let target = RetryNetwork::new(self.network.clone());

                // TODO, la evaluación, si hay compilación podría tardar más
                #[cfg(feature = "test")]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(1, Duration::from_secs(20)),
                );
                #[cfg(not(feature = "test"))]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(3, Duration::from_secs(60)),
                );

                let retry_actor = RetryActor::new(target, message, strategy);

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
                            msg_type = "NetworkEvaluation",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkEvaluation",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkEvaluation",
                    request_id = %self.request_id,
                    version = self.version,
                    node_key = %node_key,
                    "Evaluation request sent to network with retry"
                );
            }
            EvalCoordinatorMessage::NetworkResponse {
                evaluation_res,
                request_id,
                version,
                sender,
            } => {
                if request_id == self.request_id && version == self.version {
                    if self.node_key != sender
                        || sender != evaluation_res.signature().signer
                    {
                        error!(
                            msg_type = "NetworkResponse",
                            expected_node = %self.node_key,
                            sender = %sender,
                            signer = %evaluation_res.signature().signer,
                            "Evaluation response sender mismatch"
                        );
                        return Err(ActorError::Functional {
                            description: "We received an evaluation where the request indicates one subject but the info indicates another".to_string()
                        });
                    }

                    if let Err(e) = evaluation_res.verify() {
                        error!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Failed to verify evaluation response signature"
                        );
                        return Err(ActorError::Functional {
                            description: format!(
                                "Can not verify signature: {}",
                                e
                            ),
                        });
                    }

                    // Evaluation actor.
                    match ctx.get_parent::<Evaluation>().await {
                        Ok(evaluation_actor) => {
                            if let Err(e) = evaluation_actor
                                .tell(EvaluationMessage::Response {
                                    evaluation_res: evaluation_res
                                        .content()
                                        .clone(),
                                    sender: self.node_key.clone(),
                                    signature: Some(
                                        evaluation_res.signature().clone(),
                                    ),
                                })
                                .await
                            {
                                error!(
                                    msg_type = "NetworkResponse",
                                    error = %e,
                                    "Failed to send response to evaluation actor"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                        Err(e) => {
                            error!(
                                msg_type = "NetworkResponse",
                                path = %ctx.path().parent(),
                                "Evaluation actor not found"
                            );

                            return Err(emit_fail(ctx, e).await);
                        }
                    }

                    'retry: {
                        let Ok(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to end retry actor"
                            );
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };
                    }

                    debug!(
                        msg_type = "NetworkResponse",
                        request_id = %self.request_id,
                        version = self.version,
                        sender = %sender,
                        "Evaluation response processed successfully"
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

    async fn on_child_error(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) {
        match error {
            ActorError::Retry => {
                match ctx.get_parent::<Evaluation>().await {
                    Ok(evaluation_actor) => {
                        if let Err(e) = evaluation_actor
                            .tell(EvaluationMessage::Response {
                                evaluation_res: EvaluationRes::TimeOut,
                                signature: None,
                                sender: self.node_key.clone(),
                            })
                            .await
                        {
                            error!(
                                error = %e,
                                "Failed to send timeout response to evaluation actor"
                            );
                            emit_fail(ctx, e).await;
                        } else {
                            debug!(
                                request_id = %self.request_id,
                                version = self.version,
                                "Timeout response sent to evaluation actor"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            path = %ctx.path().parent(),
                            "Evaluation actor not found"
                        );
                        emit_fail(ctx, e).await;
                    }
                }

                ctx.stop(None).await;
            }
            _ => {
                error!(error = %error, "Unexpected child error");
            }
        };
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            request_id = %self.request_id,
            version = self.version,
            node_key = %self.node_key,
            error = %error,
            "Child fault in evaluation coordinator"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
