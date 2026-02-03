use std::{collections::HashSet, sync::Arc};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::identity::{DigestIdentifier, PublicKey};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};
use updater::{Updater, UpdaterMessage};

use crate::{
    NetworkMessage,
    helpers::network::{ActorMessage, service::NetworkSender},
    model::common::emit_fail,
    request::manager::{RequestManager, RequestManagerMessage},
};

pub mod updater;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpdateType {
    Auth,
    Request { id: DigestIdentifier },
}

pub struct UpdateNew {
    pub subject_id: DigestIdentifier,
    pub witnesses: HashSet<PublicKey>,
    pub update_type: UpdateType,
    pub network: Arc<NetworkSender>,
    pub our_sn: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Update {
    subject_id: DigestIdentifier,
    witnesses: HashSet<PublicKey>,
    better: Option<(u64, PublicKey)>,
    our_sn: Option<u64>,
    update_type: UpdateType,
    network: Arc<NetworkSender>,
}

impl Update {
    pub fn new(data: UpdateNew) -> Self {
        Self {
            network: data.network,
            subject_id: data.subject_id,
            witnesses: data.witnesses,
            update_type: data.update_type,
            our_sn: data.our_sn,
            better: None,
        }
    }

    pub fn update_better(&mut self, sn: u64, sender: PublicKey) {
        match self.better {
            Some((better_sn, ..)) => {
                if sn > better_sn {
                    self.better = Some((sn, sender))
                }
            }
            None => {
                if let Some(our_sn) = self.our_sn
                    && sn > our_sn
                {
                    self.better = Some((sn, sender))
                } else {
                    self.better = Some((sn, sender))
                }
            }
        }
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
            let message = UpdaterMessage::NetworkLastSn {
                subject_id: self.subject_id.clone(),
                node_key: witness,
            };

            child.tell(message).await?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum UpdateMessage {
    Run,
    Response { sender: PublicKey, sn: u64 },
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
            UpdateMessage::Response { sender, sn } => {
                if self.check_witness(sender.clone()) {
                    self.update_better(sn, sender);

                    if self.witnesses.is_empty() {
                        if let Some((.., better_node)) = self.better.clone() {
                            let info = ComunicateInfo {
                                receiver: better_node.clone(),
                                request_id: String::default(),
                                version: 0,
                                receiver_actor: format!(
                                    "/user/node/distributor_{}",
                                    self.subject_id
                                ),
                            };

                            if let Err(e) = self
                                    .network
                                    .send_command(
                                        network::CommandHelper::SendMessage {
                                            message: NetworkMessage {
                                                info: info.clone(),
                                                message: ActorMessage::DistributionLedgerReq {
                                                    actual_sn: self.our_sn,
                                                    subject_id: self.subject_id.clone(),
                                                },
                                            },
                                        },
                                    )
                                    .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        node = %better_node,
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
                        }

                        if let UpdateType::Request { id } = &self.update_type {
                            let request_path = ActorPath::from(format!(
                                "/user/request/{}",
                                self.subject_id
                            ));
                            match ctx
                                .system()
                                .get_actor::<RequestManager>(&request_path)
                                .await
                            {
                                Ok(request_actor) => {
                                    let request = if self.better.is_none() {
                                        RequestManagerMessage::FinishReboot {
                                            request_id: id.clone(),
                                        }
                                    } else {
                                        RequestManagerMessage::RebootWait {
                                            request_id: id.clone(),
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
                                            subject_id = %self.subject_id,
                                            "Failed to send response to request actor"
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        msg_type = "Response",
                                        path = %request_path,
                                        subject_id = %self.subject_id,
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
        error!(
            subject_id = %self.subject_id,
            update_type = ?self.update_type,
            error = %error,
            "Child fault in update actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
