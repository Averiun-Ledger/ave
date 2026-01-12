use std::{collections::VecDeque, sync::Arc, time::Duration};

use crate::{
    ActorMessage, NetworkMessage,
    approval::types::VotationType,
    helpers::network::service::NetworkSender,
    model::{
        common::emit_fail,
        network::{RetryNetwork, TimeOut},
    },
};
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction,
    CustomIntervalStrategy, Handler, Message, NotPersistentActor, RetryActor,
    RetryMessage, Strategy,
};
use ave_common::{
    identity::{HashAlgorithm, PublicKey, Signed, TimeStamp},
    request::EventRequest,
};
use network::ComunicateInfo;
use tracing::{Span, debug, error, info_span, warn};

use super::{
    Approval, ApprovalMessage, request::ApprovalReq, response::ApprovalRes,
};

#[derive(Clone, Debug)]
pub struct ApprLight {
    network: Arc<NetworkSender>,
    our_key: Arc<PublicKey>,
    node_key: PublicKey,
    request_id: String,
    version: u64,
}

impl ApprLight {
    pub fn new(
        network: Arc<NetworkSender>,
        our_key: Arc<PublicKey>,
        node_key: PublicKey,
        request_id: String,
        version: u64,
    ) -> Self {
        Self {
            network,
            our_key,
            node_key,
            request_id,
            version,
        }
    }
}

pub struct InitApprLight {
    pub request_id: String,
    pub version: u64,
    pub our_key: Arc<PublicKey>,
    pub node_key: PublicKey,
    pub subject_id: String,
    pub pass_votation: VotationType,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
}

#[derive(Debug, Clone)]
pub enum ApprLightMessage {
    // Lanza los retries y envía la petición a la network(exponencial)
    NetworkApproval {
        approval_req: Signed<ApprovalReq>,
    },
    // Finaliza los retries y recibe la respuesta de la network
    NetworkResponse {
        approval_res: Signed<ApprovalRes>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
}

impl Message for ApprLightMessage {}

#[async_trait]
impl Actor for ApprLight {
    type Event = ();
    type Message = ApprLightMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "ApprLight", id = id)
        } else {
            info_span!("ApprLight", id = id)
        }
    }
}

#[async_trait]
impl Handler<ApprLight> for ApprLight {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ApprLightMessage,
        ctx: &mut ActorContext<ApprLight>,
    ) -> Result<(), ActorError> {
        match msg {
            ApprLightMessage::NetworkApproval { approval_req } => {
                // Solo admitimos eventos FACT
                let subject_id = if let EventRequest::Fact(event) =
                    approval_req.content().event_request.content().clone()
                {
                    event.subject_id
                } else {
                    error!(
                        msg_type = "NetworkApproval",
                        "Event is not fact type"
                    );
                    let e = ActorError::FunctionalCritical { description: "An attempt is being made to approve an event that is not fact.".to_owned()};
                    return Err(emit_fail(ctx, e).await);
                };

                let receiver_actor =
                    format!("/user/node/{}/approver", subject_id);

                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: self.request_id.clone(),
                        version: self.version,
                        receiver: self.node_key.clone(),
                        receiver_actor,
                    },
                    message: ActorMessage::ApprovalReq { req: approval_req },
                };

                let target = RetryNetwork::new(self.network.clone());

                let strategy = Strategy::CustomIntervalStrategy(
                    CustomIntervalStrategy::new(VecDeque::from([
                        Duration::from_secs(14400),
                        Duration::from_secs(28800),
                        Duration::from_secs(57600),
                    ])),
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
                            msg_type = "NetworkApproval",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkApproval",
                        error = %e,
                        "Failed to send retry message"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkApproval",
                    request_id = %self.request_id,
                    version = self.version,
                    "Retry actor created and started"
                );
            }
            // Finaliza los retries
            ApprLightMessage::NetworkResponse {
                approval_res,
                request_id,
                version,
                sender,
            } => {
                if request_id == self.request_id && version == self.version {
                    if self.node_key != sender
                        || sender != approval_res.signature().signer
                    {
                        error!(
                            msg_type = "NetworkResponse",
                            expected_node = %self.node_key,
                            received_sender = %sender,
                            "Unexpected approval sender"
                        );
                        return Ok(());
                    }

                    if let Err(e) = approval_res.verify() {
                        error!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            "Invalid approval signature"
                        );
                        return Ok(());
                    }

                    let approval_path = ctx.path().parent();
                    let approval_actor: Option<ActorRef<Approval>> =
                        ctx.system().get_actor(&approval_path).await;

                    if let Some(approval_actor) = approval_actor {
                        if let Err(e) = approval_actor
                            .tell(ApprovalMessage::Response {
                                approval_res: approval_res.content().clone(),
                                sender: self.node_key.clone(),
                                signature: Some(
                                    approval_res.signature().clone(),
                                ),
                            })
                            .await
                        {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to send response to approval actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    } else {
                        error!(
                            msg_type = "NetworkResponse",
                            path = %approval_path,
                            "Approval actor not found"
                        );
                        let e = ActorError::NotFound {
                            path: approval_path,
                        };
                        return Err(emit_fail(ctx, e).await);
                    }

                    'retry: {
                        let Some(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to send end message to retry actor"
                            );
                            break 'retry;
                        };
                    }

                    debug!(
                        msg_type = "NetworkResponse",
                        request_id = %request_id,
                        version = version,
                        "Approval response processed successfully"
                    );

                    ctx.stop(None).await;
                } else {
                    warn!(
                        msg_type = "NetworkResponse",
                        expected_request_id = %self.request_id,
                        received_request_id = %request_id,
                        expected_version = self.version,
                        received_version = version,
                        "Mismatched request id or version"
                    );
                }
            }
        }
        Ok(())
    }

    async fn on_child_error(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<ApprLight>,
    ) {
        match error {
            ActorError::Retry => {
                let approval_path = ctx.path().parent();

                let approval_actor: Option<ActorRef<Approval>> =
                    ctx.system().get_actor(&approval_path).await;

                if let Some(approval_actor) = approval_actor {
                    if let Err(e) = approval_actor
                        .tell(ApprovalMessage::Response {
                            approval_res: ApprovalRes::TimeOut(TimeOut {
                                re_trys: 3,
                                timestamp: TimeStamp::now(),
                                who: self.node_key.clone(),
                            }),
                            sender: self.node_key.clone(),
                            signature: None,
                        })
                        .await
                    {
                        error!(
                            error = %e,
                            "Failed to send timeout response to approval actor"
                        );
                        emit_fail(ctx, e).await;
                    }

                    debug!("Timeout response sent to approval actor");
                } else {
                    let e = ActorError::NotFound {
                        path: approval_path.clone(),
                    };
                    error!(
                        error = %e,
                        path = %approval_path,
                        "Approval actor not found"
                    );
                    emit_fail(ctx, e).await;
                }
                ctx.stop(None).await;
            }
            _ => {
                error!(error = ?error, "Unexpected child error");
            }
        };
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<ApprLight>,
    ) -> ChildAction {
        error!(error = %error, "Child fault occurred");
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

impl NotPersistentActor for ApprLight {}
