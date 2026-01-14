use std::{sync::Arc, time::Duration};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction,
    FixedIntervalStrategy, Handler, Message, NotPersistentActor, RetryActor,
    RetryMessage, Strategy,
};

use async_trait::async_trait;
use ave_common::identity::{DigestIdentifier, PublicKey};
use network::ComunicateInfo;
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    ActorMessage,
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{common::emit_fail, network::RetryNetwork},
};

use super::{TransferResponse, Update, UpdateMessage};

#[derive(Clone, Debug)]
pub struct Updater {
    network: Arc<NetworkSender>,
    node: PublicKey,
}

impl Updater {
    pub fn new(node: PublicKey, network: Arc<NetworkSender>) -> Self {
        Self { node, network }
    }
}

#[derive(Debug, Clone)]
pub enum UpdaterMessage {
    Transfer {
        subject_id: DigestIdentifier,
        node_key: PublicKey,
    },
    TransferResponse {
        res: TransferResponse,
        sender: PublicKey,
    },
    NetworkLastSn {
        subject_id: DigestIdentifier,
        node_key: PublicKey,
    },
    NetworkResponse {
        sn: u64,
        sender: PublicKey,
    },
}

impl Message for UpdaterMessage {}

impl NotPersistentActor for Updater {}

#[async_trait]
impl Actor for Updater {
    type Event = ();
    type Message = UpdaterMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Updater", id = id)
        } else {
            info_span!("Updater", id = id)
        }
    }
}

#[async_trait]
impl Handler<Updater> for Updater {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: UpdaterMessage,
        ctx: &mut ActorContext<Updater>,
    ) -> Result<(), ActorError> {
        match msg {
            UpdaterMessage::TransferResponse { res, sender } => {
                if sender == self.node {
                    let update_path = ctx.path().parent();
                    let update_actor: Option<ActorRef<Update>> =
                        ctx.system().get_actor(&update_path).await;

                    if let Some(update_actor) = update_actor {
                        if let Err(e) = update_actor
                            .tell(UpdateMessage::TransferRes {
                                sender: self.node.clone(),
                                res,
                            })
                            .await
                        {
                            error!(
                                msg_type = "TransferResponse",
                                error = %e,
                                "Failed to send response to update actor"
                            );
                            return Err(e);
                        }
                    } else {
                        let e = ActorError::NotFound { path: update_path.clone() };
                        error!(
                            msg_type = "TransferResponse",
                            path = %update_path,
                            "Update actor not found"
                        );
                        return Err(e);
                    }

                    'retry: {
                        let Some(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            warn!(
                                msg_type = "TransferResponse",
                                error = %e,
                                "Failed to end retry actor"
                            );
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };
                    }

                    debug!(
                        msg_type = "TransferResponse",
                        sender = %sender,
                        "Transfer response processed successfully"
                    );

                    ctx.stop(None).await;
                } else {
                    warn!(
                        msg_type = "TransferResponse",
                        expected_sender = %self.node,
                        received_sender = %sender,
                        "Invalid sender"
                    );
                }
            }
            UpdaterMessage::Transfer {
                subject_id,
                node_key,
            } => {
                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: String::default(),
                        version: 0,
                        receiver: node_key.clone(),
                        receiver_actor: "/user/node/distributor".to_string(),
                    },
                    message: ActorMessage::Transfer { subject_id: subject_id.clone() },
                };

                let target = RetryNetwork::new(self.network.clone());

                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(1, Duration::from_secs(5)),
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
                            msg_type = "Transfer",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "Transfer",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(emit_fail(ctx, e).await);
                } else {
                    debug!(
                        msg_type = "Transfer",
                        subject_id = %subject_id,
                        node_key = %node_key,
                        "Transfer request sent to network with retry"
                    );
                };
            }
            UpdaterMessage::NetworkLastSn {
                subject_id,
                node_key,
            } => {
                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: String::default(),
                        version: 0,
                        receiver: node_key.clone(),
                        receiver_actor: "/user/node/distributor".to_string(),
                    },
                    message: ActorMessage::DistributionGetLastSn { subject_id: subject_id.clone() },
                };

                let target = RetryNetwork::new(self.network.clone());

                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(1, Duration::from_secs(5)),
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
                            msg_type = "NetworkLastSn",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkLastSn",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(emit_fail(ctx, e).await);
                } else {
                    debug!(
                        msg_type = "NetworkLastSn",
                        subject_id = %subject_id,
                        node_key = %node_key,
                        "Last SN request sent to network with retry"
                    );
                };
            }
            UpdaterMessage::NetworkResponse { sn, sender } => {
                if sender == self.node {
                    let update_path = ctx.path().parent();
                    let update_actor: Option<ActorRef<Update>> =
                        ctx.system().get_actor(&update_path).await;

                    if let Some(update_actor) = update_actor {
                        if let Err(e) = update_actor
                            .tell(UpdateMessage::Response {
                                sender: self.node.clone(),
                                sn,
                            })
                            .await
                        {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to send response to update actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    } else {
                        let e = ActorError::NotFound { path: update_path.clone() };
                        error!(
                            msg_type = "NetworkResponse",
                            path = %update_path,
                            "Update actor not found"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }

                    'retry: {
                        let Some(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            // Aquí me da igual, porque al parar este actor para el hijo
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            warn!(
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
                        sn = sn,
                        sender = %sender,
                        "Network response processed successfully"
                    );

                    ctx.stop(None).await;
                }
            }
        };

        Ok(())
    }


    // TODO ver si en los child_error quitamos el emit_fail
    async fn on_child_error(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Updater>,
    ) {
        match error {
            ActorError::Retry => {
                let update_path = ctx.path().parent();

                // Evaluation actor.
                let update_actor: Option<ActorRef<Update>> =
                    ctx.system().get_actor(&update_path).await;

                if let Some(update_actor) = update_actor {
                    if let Err(e) = update_actor
                        .tell(UpdateMessage::Response {
                            sender: self.node.clone(),
                            sn: 0,
                        })
                        .await
                    {
                        error!(
                            error = %e,
                            "Failed to send timeout response to update actor"
                        );
                        emit_fail(ctx, e).await;
                    } else {
                        debug!(
                            node = %self.node,
                            "Timeout response sent to update actor"
                        );
                    }
                } else {
                    let e = ActorError::NotFound { path: update_path.clone() };
                    error!(
                        path = %update_path,
                        "Update actor not found"
                    );
                    emit_fail(ctx, e).await;
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
        ctx: &mut ActorContext<Updater>,
    ) -> ChildAction {
        error!(error = %error, "Child fault occurred");
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
