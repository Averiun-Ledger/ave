use std::{sync::Arc, time::Duration};

use crate::{
    approval::{
        Approval, ApprovalMessage, request::ApprovalReq,
        response::ApprovalCollectAck,
    },
    helpers::network::{ActorMessage, NetworkMessage, service::NetworkSender},
    model::{common::crash_system, network::RetryNetwork},
};

use async_trait::async_trait;
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};

use ave_network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, IntervalStrategy,
    Message, NotPersistentActor, RetryActor, RetryMessage, Strategy,
};

use tracing::{Span, debug, error, info_span, warn};

/// Requester-side coordinator of one approval validator: delivers the
/// approval request with retry until the validator acknowledges it.
#[derive(Clone, Debug)]
pub struct ApprCoordinator {
    node_key: PublicKey,
    governance_id: DigestIdentifier,
    request_id: String,
    version: u64,
    /// Hash of the approval request this coordinator delivers: acks for
    /// any other request are ignored.
    approval_req_hash: DigestIdentifier,
    network: Arc<NetworkSender>,
    /// The validator acknowledged the collection request: the request
    /// retry is cancelled.
    acked: bool,
}

impl ApprCoordinator {
    pub const fn new(
        node_key: PublicKey,
        governance_id: DigestIdentifier,
        request_id: String,
        version: u64,
        approval_req_hash: DigestIdentifier,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
            node_key,
            governance_id,
            request_id,
            version,
            approval_req_hash,
            network,
            acked: false,
        }
    }

    fn validator_actor_path(&self) -> String {
        format!(
            "/user/node/subject_manager/{}/validator",
            self.governance_id
        )
    }

    /// Notifies the parent that this validator can not serve the request
    /// and stops the coordinator.
    async fn unavailable_and_stop(
        &self,
        ctx: &mut ActorContext<Self>,
        msg_type: &'static str,
    ) {
        match ctx.get_parent::<Approval>().await {
            Ok(approval_actor) => {
                if let Err(e) = approval_actor
                    .tell(ApprovalMessage::Unavailable {
                        sender: self.node_key.clone(),
                    })
                    .await
                {
                    // The phase was torn down while this notification
                    // was in flight: it is moot, drop it.
                    debug!(
                        msg_type = msg_type,
                        error = %e,
                        "Approval actor gone, dropping unavailable notice"
                    );
                }
            }
            Err(e) => {
                debug!(
                    msg_type = msg_type,
                    error = %e,
                    path = %ctx.path().parent(),
                    "Approval actor not found, dropping unavailable notice"
                );
            }
        }

        ctx.stop(None).await;
    }

    /// Stops a retry child; a missing child is fine (it stops with its
    /// parent anyway).
    async fn end_retry(&self, ctx: &mut ActorContext<Self>, name: &str) {
        if let Ok(retry) = ctx
            .get_child::<RetryActor<RetryNetwork>>(name)
            .await
            && let Err(e) = retry.tell(RetryMessage::End).await
        {
            warn!(
                error = %e,
                retry = name,
                "Failed to end retry actor"
            );
        }
    }
}

#[derive(Debug, Clone)]
pub enum ApprCoordinatorMessage {
    NetworkApproval {
        approval_req: Box<Signed<ApprovalReq>>,
        node_key: PublicKey,
    },
    /// A validator answered the collection request.
    NetworkAck {
        approval_req_hash: DigestIdentifier,
        ack: ApprovalCollectAck,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
    EndRetry,
}

impl Message for ApprCoordinatorMessage {}

#[async_trait]
impl Actor for ApprCoordinator {
    type Event = ();
    type Message = ApprCoordinatorMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ApprCoordinator", id),
            |parent_span| {
                info_span!(parent: parent_span, "ApprCoordinator", id)
            },
        )
    }
}

impl NotPersistentActor for ApprCoordinator {}

#[async_trait]
impl Handler<Self> for ApprCoordinator {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: ApprCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ApprCoordinatorMessage::NetworkApproval {
                approval_req,
                node_key,
            } => {
                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: self.request_id.clone(),
                        version: self.version,
                        receiver: node_key.clone(),
                        receiver_actor: self.validator_actor_path(),
                    },
                    message: ActorMessage::ApprovalCollectReq {
                        req: *approval_req,
                    },
                };

                let target = RetryNetwork::new(self.network.clone());

                #[cfg(any(test, feature = "test"))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    1,
                    Duration::from_secs(10),
                ));
                #[cfg(not(any(test, feature = "test")))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    3,
                    Duration::from_secs(30),
                ));

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    ApprCoordinatorMessage::EndRetry,
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
                            msg_type = "NetworkApproval",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkApproval",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(crash_system(ctx, e).await);
                }

                debug!(
                    msg_type = "NetworkApproval",
                    request_id = %self.request_id,
                    version = self.version,
                    node_key = %node_key,
                    "Approval request sent to validator with retry"
                );
            }
            ApprCoordinatorMessage::NetworkAck {
                approval_req_hash,
                ack,
                request_id,
                version,
                sender,
            } => {
                if request_id != self.request_id || version != self.version {
                    warn!(
                        msg_type = "NetworkAck",
                        expected_request_id = %self.request_id,
                        expected_version = self.version,
                        received_request_id = %request_id,
                        received_version = version,
                        "Approval ack with mismatched request id or version"
                    );
                    return Ok(());
                }

                // An ack for a different approval request (e.g. a stale
                // collection request rejected by the validator) does not
                // concern this delivery: the retry schedule continues
                // and the validator is eventually replaced if it never
                // acknowledges this request.
                if approval_req_hash != self.approval_req_hash {
                    warn!(
                        msg_type = "NetworkAck",
                        expected_hash = %self.approval_req_hash,
                        received_hash = %approval_req_hash,
                        "Approval ack for a different approval request"
                    );
                    return Ok(());
                }

                if sender != self.node_key {
                    warn!(
                        msg_type = "NetworkAck",
                        expected_node = %self.node_key,
                        sender = %sender,
                        "Approval ack from an unexpected sender"
                    );
                    return Ok(());
                }

                self.end_retry(ctx, "retry").await;

                match ack {
                    ApprovalCollectAck::Accepted => {
                        if self.acked {
                            // A request retry was already in flight when
                            // the first ack arrived: harmless duplicate.
                            debug!(
                                msg_type = "NetworkAck",
                                sender = %sender,
                                "Duplicate approval ack ignored"
                            );
                            return Ok(());
                        }
                        self.acked = true;

                        match ctx.get_parent::<Approval>().await {
                            Ok(approval_actor) => {
                                if let Err(e) = approval_actor
                                    .tell(ApprovalMessage::Working {
                                        sender: self.node_key.clone(),
                                    })
                                    .await
                                {
                                    debug!(
                                        msg_type = "NetworkAck",
                                        error = %e,
                                        "Approval actor gone, dropping ack"
                                    );
                                }
                            }
                            Err(e) => {
                                debug!(
                                    msg_type = "NetworkAck",
                                    error = %e,
                                    path = %ctx.path().parent(),
                                    "Approval actor not found, dropping ack"
                                );
                            }
                        }

                        debug!(
                            msg_type = "NetworkAck",
                            request_id = %self.request_id,
                            version = self.version,
                            sender = %sender,
                            "Approval ack processed, request delivered"
                        );

                        // The request is delivered and acknowledged:
                        // this coordinator has nothing left to do.
                        ctx.stop(None).await;
                    }
                    ApprovalCollectAck::Unavailable => {
                        self.unavailable_and_stop(ctx, "NetworkAck").await;
                    }
                    ApprovalCollectAck::Reboot => {
                        match ctx.get_parent::<Approval>().await {
                            Ok(approval_actor) => {
                                if let Err(e) = approval_actor
                                    .tell(ApprovalMessage::Reboot {
                                        sender: self.node_key.clone(),
                                    })
                                    .await
                                {
                                    debug!(
                                        msg_type = "NetworkAck",
                                        error = %e,
                                        "Approval actor gone, dropping reboot"
                                    );
                                }
                            }
                            Err(e) => {
                                debug!(
                                    msg_type = "NetworkAck",
                                    error = %e,
                                    path = %ctx.path().parent(),
                                    "Approval actor not found, dropping reboot"
                                );
                            }
                        }

                        ctx.stop(None).await;
                    }
                }
            }
            ApprCoordinatorMessage::EndRetry => {
                // The retry actor reports cycle completion also on an
                // explicit `End` — which is exactly how the ack cancels
                // it. That notification is expected.
                if self.acked {
                    debug!(
                        msg_type = "EndRetry",
                        node_key = %self.node_key,
                        request_id = %self.request_id,
                        version = self.version,
                        "Retry ended after approval ack, ignoring"
                    );
                    return Ok(());
                }

                warn!(
                    msg_type = "EndRetry",
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Retry exhausted, notifying parent and stopping"
                );

                self.unavailable_and_stop(ctx, "EndRetry").await;
            }
        }

        Ok(())
    }
}
