use std::{sync::Arc, time::Duration};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction,
    FixedIntervalStrategy, Handler, Message, NotPersistentActor, RetryActor,
    RetryMessage, Strategy,
};
use ave_common::identity::PublicKey;
use network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage,
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::{common::emit_fail, event::Ledger, network::RetryNetwork},
};

use tracing::{Span, debug, error, info_span, warn};

use super::{Distribution, DistributionMessage, error::DistributorError};

pub struct DistriCoordinator {
    pub node_key: PublicKey,
    pub network: Arc<NetworkSender>,
}

#[async_trait]
impl Actor for DistriCoordinator {
    type Event = ();
    type Message = DistriCoordinatorMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("DistriCoordinator", id),
            |parent_span| info_span!(parent: parent_span, "DistriCoordinator", id),
        )
    }
}

#[derive(Debug, Clone)]
pub enum DistriCoordinatorMessage {
    EndRetry,
    // Enviar a un nodo la replicación.
    NetworkDistribution {
        request_id: String,
        ledger: Box<Ledger>,
    },
    // El nodo al que le enviamos la replica la recivió, parar los reintentos.
    NetworkResponse {
        sender: PublicKey,
    },
}

impl Message for DistriCoordinatorMessage {}

impl NotPersistentActor for DistriCoordinator {}

#[async_trait]
impl Handler<Self> for DistriCoordinator {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: DistriCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            DistriCoordinatorMessage::EndRetry => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_protocol_event(
                        "distribution",
                        "witness_timeout",
                    );
                }
                debug!(
                    node_key = %self.node_key,
                    "Retry exhausted, notifying parent and stopping"
                );

                match ctx.get_parent::<Distribution>().await {
                    Ok(distribution_actor) => {
                        if let Err(e) = distribution_actor
                            .tell(DistributionMessage::Response {
                                sender: self.node_key.clone(),
                            })
                            .await
                        {
                            error!(
                                node_key = %self.node_key,
                                error = %e,
                                "Failed to notify parent distribution actor after retry exhausted"
                            );
                            emit_fail(ctx, e).await;
                        } else {
                            debug!(
                                node_key = %self.node_key,
                                "Parent distribution actor notified of retry exhaustion"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            node_key = %self.node_key,
                            error = %e,
                            "Failed to get parent distribution actor after retry exhausted"
                        );
                        emit_fail(ctx, e).await;
                    }
                }

                ctx.stop(None).await;
            }
            DistriCoordinatorMessage::NetworkDistribution {
                request_id,
                ledger,
            } => {
                let subject_id = ledger.content().get_subject_id();
                let sn = ledger.content().sn;

                let receiver_actor =
                    format!("/user/node/distributor_{}", subject_id);

                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: request_id.to_string(),
                        version: 0,
                        receiver: self.node_key.clone(),
                        receiver_actor,
                    },
                    message: ActorMessage::DistributionLastEventReq { ledger },
                };

                let target = RetryNetwork::new(self.network.clone());

                #[cfg(any(test, feature = "test"))]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(2, Duration::from_secs(2)),
                );
                #[cfg(not(any(test, feature = "test")))]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(3, Duration::from_secs(30)),
                );

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    DistriCoordinatorMessage::EndRetry,
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
                            msg_type = "NetworkDistribution",
                            subject_id = %subject_id,
                            sn = sn,
                            node_key = %self.node_key,
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkDistribution",
                        subject_id = %subject_id,
                        sn = sn,
                        node_key = %self.node_key,
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkDistribution",
                    subject_id = %subject_id,
                    sn = sn,
                    node_key = %self.node_key,
                    request_id = %request_id,
                    "Distribution retry initiated"
                );
            }
            DistriCoordinatorMessage::NetworkResponse { sender } => {
                if sender != self.node_key {
                    error!(
                        msg_type = "NetworkResponse",
                        sender = %sender,
                        expected = %self.node_key,
                        "Unexpected sender in network response"
                    );
                    return Err(DistributorError::UnexpectedSender.into());
                }

                match ctx.get_parent::<Distribution>().await {
                    Ok(distribution_actor) => {
                        if let Err(e) = distribution_actor
                            .tell(DistributionMessage::Response {
                                sender: sender.clone(),
                            })
                            .await
                        {
                            error!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                error = %e,
                                "Failed to notify parent distribution actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                    Err(e) => {
                        error!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Failed to get parent distribution actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                }

                'retry: {
                    let Ok(retry) = ctx
                        .get_child::<RetryActor<RetryNetwork>>("retry")
                        .await
                    else {
                        break 'retry;
                    };

                    if let Err(e) = retry.tell(RetryMessage::End).await {
                        warn!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Failed to end retry actor, stopping anyway"
                        );
                        break 'retry;
                    };
                }

                debug!(
                    msg_type = "NetworkResponse",
                    sender = %sender,
                    "Distribution acknowledged, stopping distributor"
                );

                ctx.stop(None).await;
            }
        };

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            node_key = %self.node_key,
            error = %error,
            "Child actor fault in distributor coordinator"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
