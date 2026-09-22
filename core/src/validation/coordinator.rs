use std::{sync::Arc, time::Duration};

use crate::{
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{common::crash_system, network::RetryNetwork},
    system::ConfigHelper,
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::identity::{PublicKey, Signed, TimeStamp};

use ave_network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, IntervalStrategy,
    Message, NotPersistentActor, RetryActor, RetryMessage, Strategy,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Validation, ValidationMessage,
    request::{ActualProtocols, ValidationReq},
    response::ValidationRes,
};

/// A struct representing a ValiCoordinator actor.
#[derive(Clone, Debug)]
pub struct ValiCoordinator {
    node_key: PublicKey,
    request_id: String,
    version: u64,
    network: Arc<NetworkSender>,
    /// The validator ACKed the request (`ValidationRes::Working`): the
    /// request retry is cancelled and the final response is awaited until
    /// the approval deadline.
    acked: bool,
    /// Approval deadline of the request, when it carries an approval
    /// requirement: the final response is awaited until then (plus the
    /// configured epsilon) instead of the plain retry budget.
    approval_deadline: Option<TimeStamp>,
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
            acked: false,
            approval_deadline: None,
        }
    }

    /// Notifies the parent that this validator timed out and stops the
    /// coordinator.
    async fn timeout_and_stop(
        &self,
        ctx: &mut ActorContext<Self>,
        msg_type: &'static str,
    ) {
        match ctx.get_parent::<Validation>().await {
            Ok(validation_actor) => {
                if let Err(e) = validation_actor
                    .tell(ValidationMessage::Response {
                        validation_res: Box::new(ValidationRes::TimeOut),
                        signature: None,
                        sender: self.node_key.clone(),
                    })
                    .await
                {
                    // The phase was torn down while this timeout
                    // was in flight: it is moot, drop it.
                    debug!(
                        msg_type = msg_type,
                        error = %e,
                        "Validation actor gone, dropping timeout response"
                    );
                } else {
                    debug!(
                        msg_type = msg_type,
                        request_id = %self.request_id,
                        version = self.version,
                        "Timeout response sent to validation actor"
                    );
                }
            }
            Err(e) => {
                // Same teardown race: the phase actor is gone.
                debug!(
                    msg_type = msg_type,
                    error = %e,
                    path = %ctx.path().parent(),
                    "Validation actor not found, dropping timeout response"
                );
            }
        }

        ctx.stop(None).await;
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
    /// The approval deadline (plus epsilon) passed without a final
    /// response from an acknowledged validator.
    DeadlineExceeded,
}

impl Message for ValiCoordinatorMessage {}

#[async_trait]
impl Actor for ValiCoordinator {
    type Event = ();
    type Message = ValiCoordinatorMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

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
        _: ActorPath,
        msg: ValiCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ValiCoordinatorMessage::EndRetry => {
                // The retry actor reports cycle completion also on an
                // explicit `End` — which is exactly how the `Working`
                // ACK cancels it. That notification is expected: the
                // approval deadline governs the wait from now on.
                if self.acked {
                    debug!(
                        node_key = %self.node_key,
                        request_id = %self.request_id,
                        version = self.version,
                        "Retry ended after working ACK, ignoring"
                    );
                    return Ok(());
                }

                warn!(
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Retry exhausted, notifying parent and stopping"
                );

                self.timeout_and_stop(ctx, "EndRetry").await;
            }
            ValiCoordinatorMessage::DeadlineExceeded => {
                warn!(
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Approval deadline exceeded, notifying parent and stopping"
                );

                self.timeout_and_stop(ctx, "DeadlineExceeded").await;
            }
            ValiCoordinatorMessage::NetworkValidation {
                validation_req,
                node_key,
            } => {
                let schema_id = validation_req.content().get_schema_id().expect("The build process verified that the event request is valid");
                let governance_id = validation_req.content().get_governance_id().expect("The build process verified that the event request is valid");

                // Requests with an approval requirement carry the
                // approval deadline: once the validator ACKs, its final
                // response is awaited until that instant.
                if let ValidationReq::Event {
                    actual_protocols, ..
                } = validation_req.content()
                {
                    self.approval_deadline = match actual_protocols.as_ref()
                    {
                        ActualProtocols::EvalApprove {
                            approval_req,
                            ..
                        }
                        | ActualProtocols::CompileEvalApprove {
                            approval_req,
                            ..
                        } => Some(approval_req.content().deadline),
                        _ => None,
                    };
                }

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
                        return Err(crash_system(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkValidation",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(crash_system(ctx, e).await);
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

                    // The acknowledgement only cancels the request retry
                    // and arms the approval deadline — it carries no
                    // verdict, so it is never forwarded as a response.
                    if matches!(
                        validation_res.content(),
                        ValidationRes::Working
                    ) {
                        // A validator only acknowledges requests with an
                        // approval requirement, which always carry the
                        // deadline. A Working for any other request is
                        // misbehaviour: drop the validator like a timeout
                        // instead of cancelling the retry, which would
                        // leave the slot without any recovery path.
                        let Some(deadline) = self.approval_deadline else {
                            warn!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                "Working ACK without approval deadline"
                            );
                            self.timeout_and_stop(ctx, "Working").await;
                            return Ok(());
                        };

                        if self.acked {
                            // A duplicate ACK (a request retry was
                            // already in flight when the first one
                            // arrived): harmless, ignore it.
                            debug!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                "Duplicate working ACK ignored"
                            );
                            return Ok(());
                        }
                        self.acked = true;

                        if let Ok(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                            && let Err(e) = retry.tell(RetryMessage::End).await
                        {
                            warn!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to end retry actor after working ACK"
                            );
                        }

                        match ctx.get_parent::<Validation>().await {
                            Ok(validation_actor) => {
                                if let Err(e) = validation_actor
                                    .tell(ValidationMessage::Working {
                                        sender: self.node_key.clone(),
                                    })
                                    .await
                                {
                                    // The phase was torn down while this
                                    // acknowledgement was in flight.
                                    debug!(
                                        msg_type = "NetworkResponse",
                                        error = %e,
                                        "Validation actor gone, dropping working ACK"
                                    );
                                }
                            }
                            Err(e) => {
                                debug!(
                                    msg_type = "NetworkResponse",
                                    error = %e,
                                    path = %ctx.path().parent(),
                                    "Validation actor not found, dropping working ACK"
                                );
                            }
                        }

                        let epsilon_secs = ctx
                            .system()
                            .get_helper::<ConfigHelper>("config")
                            .map(|config| config.approval.tally_epsilon_secs)
                            .ok_or_else(|| ActorError::Helper {
                                name: "config".to_owned(),
                                reason: "Not found".to_owned(),
                            })?;

                        let wait = Duration::from_nanos(
                            deadline.as_nanos().saturating_sub(
                                TimeStamp::now().as_nanos(),
                            ),
                        ) + Duration::from_secs(epsilon_secs);

                        if let Err(e) = ctx.schedule_once(
                            wait,
                            ValiCoordinatorMessage::DeadlineExceeded,
                        ) {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to schedule approval deadline"
                            );
                            return Err(crash_system(ctx, e).await);
                        }

                        debug!(
                            msg_type = "NetworkResponse",
                            request_id = %self.request_id,
                            version = self.version,
                            sender = %sender,
                            "Working ACK processed, awaiting final response"
                        );

                        return Ok(());
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
                                // The phase was torn down while this
                                // response was in flight: it is moot,
                                // drop it.
                                debug!(
                                    msg_type = "NetworkResponse",
                                    error = %e,
                                    "Validation actor gone, dropping response"
                                );
                            }
                        }
                        Err(e) => {
                            // Same teardown race: the phase actor is gone.
                            debug!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                path = %ctx.path().parent(),
                                "Validation actor not found, dropping response"
                            );
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
}
