use std::{sync::Arc, time::Duration};

use crate::{
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{common::emit_fail, network::RetryNetwork},
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::identity::{PublicKey, Signed};

use ave_network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction,
    FixedIntervalStrategy, Handler, Message, NotPersistentActor, RetryActor,
    RetryMessage, Strategy,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Validation, ValidationMessage, request::ValidationReq,
    response::ValidationRes,
};

/// A struct representing a ValiCoordinator actor.
#[derive(Clone, Debug)]
pub struct ValiCoordinator {
    node_key: PublicKey,
    request_id: String,
    version: u64,
    network: Arc<NetworkSender>,
}

impl ValiCoordinator {
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
pub enum ValiCoordinatorMessage {
    NetworkValidation {
        validation_req: Box<Signed<ValidationReq>>,
        node_key: PublicKey,
    },
    NetworkResponse {
        validation_res: Box<Signed<ValidationRes>>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
    EndRetry,
}

impl Message for ValiCoordinatorMessage {}

#[async_trait]
impl Actor for ValiCoordinator {
    type Event = ();
    type Message = ValiCoordinatorMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ValiCoordinator", id),
            |parent_span| info_span!(parent: parent_span, "ValiCoordinator", id),
        )
    }
}

impl NotPersistentActor for ValiCoordinator {}

#[async_trait]
impl Handler<Self> for ValiCoordinator {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ValiCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ValiCoordinatorMessage::EndRetry => {
                warn!(
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Retry exhausted, notifying parent and stopping"
                );

                match ctx.get_parent::<Validation>().await {
                    Ok(validation_actor) => {
                        if let Err(e) = validation_actor
                            .tell(ValidationMessage::Response {
                                validation_res: Box::new(
                                    ValidationRes::TimeOut,
                                ),
                                signature: None,
                                sender: self.node_key.clone(),
                            })
                            .await
                        {
                            error!(
                                error = %e,
                                "Failed to send timeout response to validation actor"
                            );
                            emit_fail(ctx, e).await;
                        } else {
                            debug!(
                                request_id = %self.request_id,
                                version = self.version,
                                "Timeout response sent to validation actor"
                            );
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            path = %ctx.path().parent(),
                            "Validation actor not found"
                        );
                        emit_fail(ctx, e).await;
                    }
                }

                ctx.stop(None).await;
            }
            ValiCoordinatorMessage::NetworkValidation {
                validation_req,
                node_key,
            } => {
                let schema_id = validation_req.content().get_schema_id().expect("The build process verified that the event request is valid");
                let governance_id = validation_req.content().get_governance_id().expect("The build process verified that the event request is valid");

                let receiver_actor = if schema_id.is_gov() {
                    format!(
                        "/user/node/subject_manager/{}/validator",
                        governance_id
                    )
                } else {
                    format!(
                        "/user/node/subject_manager/{}/{}_validation",
                        governance_id, schema_id
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
                    message: ActorMessage::ValidationReq {
                        req: *validation_req,
                    },
                };

                let target = RetryNetwork::new(self.network.clone());

                #[cfg(any(test, feature = "test"))]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(1, Duration::from_secs(10)),
                );
                #[cfg(not(any(test, feature = "test")))]
                let strategy = Strategy::FixedInterval(
                    FixedIntervalStrategy::new(3, Duration::from_secs(30)),
                );

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    ValiCoordinatorMessage::EndRetry,
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
                            msg_type = "NetworkValidation",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkValidation",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(emit_fail(ctx, e).await);
                } else {
                    debug!(
                        msg_type = "NetworkValidation",
                        request_id = %self.request_id,
                        version = self.version,
                        node_key = %node_key,
                        "Validation request sent to network with retry"
                    );
                };
            }
            ValiCoordinatorMessage::NetworkResponse {
                validation_res,
                request_id,
                version,
                sender,
            } => {
                if request_id == self.request_id && version == self.version {
                    if self.node_key != sender
                        || sender != validation_res.signature().signer
                    {
                        error!(
                            msg_type = "NetworkResponse",
                            expected_node = %self.node_key,
                            sender = %sender,
                            signer = %validation_res.signature().signer,
                            "Validation response sender mismatch"
                        );
                        return Err(ActorError::Functional {
                            description:
                                "We received a validation response from an unexpected sender"
                                    .to_string(),
                        });
                    }

                    if let Err(e) = validation_res.verify() {
                        error!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Failed to verify validation response signature"
                        );
                        return Err(ActorError::Functional {
                            description: format!(
                                "Can not verify signature: {}",
                                e
                            ),
                        });
                    }

                    match ctx.get_parent::<Validation>().await {
                        Ok(validation_actor) => {
                            if let Err(e) = validation_actor
                                .tell(ValidationMessage::Response {
                                    validation_res: Box::new(
                                        validation_res.content().clone(),
                                    ),
                                    sender: self.node_key.clone(),
                                    signature: Some(
                                        validation_res.signature().clone(),
                                    ),
                                })
                                .await
                            {
                                error!(
                                    msg_type = "NetworkResponse",
                                    error = %e,
                                    "Failed to send response to validation actor"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                        Err(e) => {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                path = %ctx.path().parent(),
                                "Validation actor not found"
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
                                "Retry actor not found while closing validation coordinator"
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
                        request_id = %self.request_id,
                        version = self.version,
                        sender = %sender,
                        "Validation response processed successfully"
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

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            node_key = %self.node_key,
            request_id = %self.request_id,
            version = self.version,
            error = %error,
            "Child fault in validation coordinator"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
