use std::{collections::HashSet, sync::Arc};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler,
    Message, NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::identity::{DigestIdentifier, PublicKey};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};
use updater::{Updater, UpdaterMessage};

use crate::{
    ActorMessage, NetworkMessage,
    governance::{Governance, GovernanceMessage},
    helpers::network::service::NetworkSender,
    model::common::emit_fail,
    request::manager::{RequestManager, RequestManagerMessage},
    tracker::{Tracker, TrackerMessage},
};

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum TransferResponse {
    Confirm,
    Reject,
}

pub mod updater;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpdateType {
    Auth,
    Request { id: String },
    Transfer,
}

pub struct UpdateNew {
    pub subject_id: DigestIdentifier,
    pub our_key: Arc<PublicKey>,
    pub response: Option<UpdateRes>,
    pub witnesses: HashSet<PublicKey>,
    pub request: Option<ActorMessage>,
    pub update_type: UpdateType,
    pub network: Arc<NetworkSender>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpdateRes {
    Sn(u64),
    Transfer(TransferResponse),
}

#[derive(Clone, Debug)]
pub struct Update {
    subject_id: DigestIdentifier,
    our_key: Arc<PublicKey>,
    response: Option<UpdateRes>,
    witnesses: HashSet<PublicKey>,
    better: Option<PublicKey>,
    request: Option<ActorMessage>,
    update_type: UpdateType,
    network: Arc<NetworkSender>,
}

impl Update {
    pub fn new(data: UpdateNew) -> Self {
        Self {
            network: data.network,
            subject_id: data.subject_id,
            our_key: data.our_key,
            response: data.response,
            witnesses: data.witnesses,
            better: None,
            request: data.request,
            update_type: data.update_type,
        }
    }

    pub async fn update_subject(
        ctx: &mut ActorContext<Update>,
        subject_id: &str,
        res: TransferResponse,
    ) -> Result<(), ActorError> {
        let path = ActorPath::from(format!("/user/node/{}", subject_id));

        if let Ok(governance_actor) =
            ctx.system().get_actor::<Governance>(&path).await
        {
            governance_actor
                .tell(GovernanceMessage::UpdateTransfer(res))
                .await
        } else if let Ok(tracker_actor) =
            ctx.system().get_actor::<Tracker>(&path).await
        {
            tracker_actor
                .tell(TrackerMessage::UpdateTransfer(res))
                .await
        } else {
            Err(ActorError::NotFound { path })
        }
    }

    pub fn update_response(
        &mut self,
        update: UpdateRes,
        sender: PublicKey,
    ) -> Result<(), ActorError> {
        match self.update_type {
            UpdateType::Request { .. } | UpdateType::Auth => {
                if let UpdateRes::Sn(update_sn) = update {
                    match self.response.clone() {
                        Some(UpdateRes::Sn(sn)) if update_sn > sn => {
                            self.response = Some(update);
                            self.better = Some(sender);
                        }
                        Some(UpdateRes::Sn(_)) => {} // No actualizar si update_sn <= sn
                        Some(_) => {
                            return Err(ActorError::Functional {
                                description:
                                    "self response must be UpdateRes::Sn"
                                        .to_owned(),
                            });
                        }
                        None => {
                            self.response = Some(update);
                            self.better = Some(sender);
                        }
                    }
                } else {
                    return Err(ActorError::Functional {
                        description: "update must be UpdateRes::Sn".to_owned(),
                    });
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn check_witness(&mut self, witness: PublicKey) -> bool {
        self.witnesses.remove(&witness)
    }

    async fn create_updates(
        &self,
        ctx: &mut ActorContext<Update>,
    ) -> Result<(), ActorError> {
        for witness in self.witnesses.clone() {
            let updater = Updater::new(witness.clone(), self.network.clone());
            let child = ctx.create_child(&witness.to_string(), updater).await?;
            let message = match self.update_type {
                UpdateType::Auth | UpdateType::Request { .. } => {
                    UpdaterMessage::NetworkLastSn {
                        subject_id: self.subject_id.clone(),
                        node_key: witness,
                    }
                }
                UpdateType::Transfer => UpdaterMessage::Transfer {
                    subject_id: self.subject_id.clone(),
                    node_key: witness,
                },
            };

            child.tell(message).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum UpdateMessage {
    Run,
    TransferRes {
        sender: PublicKey,
        res: TransferResponse,
    },
    Response {
        sender: PublicKey,
        sn: u64,
    },
}

impl Message for UpdateMessage {}

#[async_trait]
impl Actor for Update {
    type Event = ();
    type Message = UpdateMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Update", id = id)
        } else {
            info_span!("Update", id = id)
        }
    }
}

impl NotPersistentActor for Update {}

#[async_trait]
impl Handler<Update> for Update {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: UpdateMessage,
        ctx: &mut ActorContext<Update>,
    ) -> Result<(), ActorError> {
        match msg {
            UpdateMessage::Run => {
                if let Err(e) = self.create_updates(ctx).await {
                    error!(
                        msg_type = "Run",
                        error = %e,
                        "Failed to create updates"
                    );
                    return Err(emit_fail(ctx, e).await);
                } else {
                    debug!(
                        msg_type = "Run",
                        witnesses_count = self.witnesses.len(),
                        "Updates created successfully"
                    );
                }
            }
            UpdateMessage::TransferRes { sender, res } => {
                if self.check_witness(sender.clone()) && self.response.is_none()
                {
                    self.response = Some(UpdateRes::Transfer(res.clone()));

                    if let Err(e) = Update::update_subject(
                        ctx,
                        &self.subject_id.to_string(),
                        res.clone(),
                    )
                    .await
                    {
                        error!(
                            msg_type = "TransferRes",
                            error = %e,
                            subject_id = %self.subject_id,
                            "Failed to update subject"
                        );
                    } else {
                        debug!(
                            msg_type = "TransferRes",
                            subject_id = %self.subject_id,
                            sender = %sender,
                            response = ?res,
                            "Transfer response processed successfully"
                        );
                    }

                    ctx.stop(None).await;
                }
            }
            UpdateMessage::Response { sender, sn } => {
                if self.check_witness(sender.clone()) {
                    if let Err(e) =
                        self.update_response(UpdateRes::Sn(sn), sender.clone())
                    {
                        error!(
                            msg_type = "Response",
                            error = %e,
                            sender = %sender,
                            sn = sn,
                            "Failed to update response"
                        );
                    }

                    if self.witnesses.is_empty() {
                        if let Some(node) = self.better.clone() {
                            let info = ComunicateInfo {
                                receiver: node.clone(),
                                request_id: String::default(),
                                version: 0,
                                receiver_actor: format!(
                                    "/user/node/distributor_{}",
                                    self.subject_id
                                ),
                            };

                            if let Some(request) = self.request.clone() {
                                if let Err(e) = self
                                    .network
                                    .send_command(
                                        network::CommandHelper::SendMessage {
                                            message: NetworkMessage {
                                                info: info.clone(),
                                                message: request,
                                            },
                                        },
                                    )
                                    .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        node = %node,
                                        "Failed to send request to network"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                } else {
                                    debug!(
                                        msg_type = "Response",
                                        node = %info.receiver,
                                        subject_id = %self.subject_id,
                                        "Request sent to better node"
                                    );
                                }
                            } else {
                                error!(
                                    msg_type = "Response",
                                    "Request cannot be None"
                                );
                            }
                        }

                        if let UpdateType::Request { id } = &self.update_type {
                            let request_path = ActorPath::from(format!(
                                "/user/request/{}",
                                id
                            ));
                            match ctx
                                .system()
                                .get_actor::<RequestManager>(&request_path)
                                .await
                            {
                                Ok(request_actor) => {
                                    let request = if self.better.is_none() {
                                        RequestManagerMessage::FinishReboot
                                    } else {
                                        RequestManagerMessage::Reboot {
                                            governance_id: self
                                                .subject_id
                                                .clone(),
                                        }
                                    };

                                    if let Err(e) =
                                        request_actor.tell(request).await
                                    {
                                        error!(
                                            msg_type = "Response",
                                            error = %e,
                                            request_id = %id,
                                            "Failed to send response to request actor"
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        msg_type = "Response",
                                        path = %request_path,
                                        request_id = %id,
                                        "Request actor not found"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };
                        };

                        debug!(
                            msg_type = "Response",
                            subject_id = %self.subject_id,
                            has_better = self.better.is_some(),
                            "All witnesses responded, update complete"
                        );

                        ctx.stop(None).await;
                    }
                }
            }
        };

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Update>,
    ) -> ChildAction {
        error!(error = %error, "Child fault occurred");
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
