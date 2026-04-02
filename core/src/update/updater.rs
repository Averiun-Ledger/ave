use std::{sync::Arc, time::Duration};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction,
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

use super::{Update, UpdateMessage};

#[derive(Clone, Debug)]
pub struct Updater {
    network: Arc<NetworkSender>,
    node_key: PublicKey,
}

impl Updater {
    pub const fn new(node_key: PublicKey, network: Arc<NetworkSender>) -> Self {
        Self { node_key, network }
    }
}

#[derive(Debug, Clone)]
pub enum UpdaterMessage {
    EndRetry,
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
        parent_span.map_or_else(
            || info_span!("Updater", id),
            |parent_span| info_span!(parent: parent_span, "Updater", id),
        )
    }
}

#[async_trait]
impl Handler<Self> for Updater {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: UpdaterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            UpdaterMessage::EndRetry => {
                warn!(
                    node_key = %self.node_key,
                    "Retry exhausted, notifying parent and stopping"
                );

                match ctx.get_parent::<Update>().await {
                    Ok(update_actor) => {
                        if let Err(e) = update_actor
                            .tell(UpdateMessage::Response {
                                sender: self.node_key.clone(),
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
                                node = %self.node_key,
                                "Timeout response sent to update actor"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            path = %ctx.path().parent(),
                            "Update actor not found"
                        );
                        emit_fail(ctx, e).await;
                    }
                };

                ctx.stop(None).await;
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
                        receiver_actor: format!(
                            "/user/node/distributor_{}",
                            subject_id
                        ),
                    },
                    message: ActorMessage::DistributionGetLastSn {
                        subject_id: subject_id.clone(),
                        receiver_actor: ctx.path().to_string(),
                    },
                };

                let target = RetryNetwork::new(self.network.clone());

                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(1, Duration::from_secs(10)),
                );

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    UpdaterMessage::EndRetry,
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
                if sender != self.node_key {
                    warn!(
                        msg_type = "NetworkResponse",
                        expected_node = %self.node_key,
                        sender = %sender,
                        "Ignoring update response from unexpected sender"
                    );
                    return Ok(());
                }

                match ctx.get_parent::<Update>().await {
                    Ok(update_actor) => {
                        if let Err(e) = update_actor
                            .tell(UpdateMessage::Response {
                                sender: self.node_key.clone(),
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
                    }
                    Err(e) => {
                        error!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            path = %ctx.path().parent(),
                            "Update actor not found"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                'retry: {
                    let Ok(retry) = ctx
                        .get_child::<RetryActor<RetryNetwork>>("retry")
                        .await
                    else {
                        debug!(
                            msg_type = "NetworkResponse",
                            sender = %sender,
                            "Retry actor not found while closing updater"
                        );
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
        };

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            node = %self.node_key,
            error = %error,
            "Child fault in updater actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
