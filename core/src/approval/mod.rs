use std::collections::HashSet;
use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::ActorPath;
use ave_actors::{
    Actor, ActorContext, ActorError, ChildAction, Handler, Message,
    NotPersistentActor,
};

use ave_common::identity::{
    CryptoError, DigestIdentifier, HashAlgorithm, PublicKey, Signature, Signed,
    hash_borsh,
};

use request::ApprovalReq;
use response::ApprovalRes;

use tracing::{Span, debug, error, info_span, warn};

use crate::approval::light::{ApprLight, ApprLightMessage};
use crate::approval::persist::{ApprPersist, ApprPersistMessage};
use crate::governance::model::Quorum;
use crate::helpers::network::service::NetworkSender;
use crate::model::common::emit_fail;

use crate::model::event::ApprovalData;
use crate::model::network::TimeOut;

use crate::request::manager::{RequestManager, RequestManagerMessage};

pub mod light;
pub mod persist;
pub mod request;
pub mod response;
pub mod types;

#[derive(Clone, Debug)]
pub struct Approval {
    hash: HashAlgorithm,
    network: Arc<NetworkSender>,
    our_key: Arc<PublicKey>,
    quorum: Quorum,
    request_id: DigestIdentifier,
    version: u64,
    request: Signed<ApprovalReq>,
    approvers: HashSet<PublicKey>,
    approvers_timeout: Vec<TimeOut>,
    approvers_agrees: Vec<Signature>,
    approvers_disagrees: Vec<Signature>,
    approval_req_hash: DigestIdentifier,
    approvers_quantity: u32,
}

impl Approval {
    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<ApprovalReq>,
        quorum: Quorum,
        approvers: HashSet<PublicKey>,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
            hash,
            network,
            our_key,
            quorum,
            request,
            approvers_quantity: approvers.len() as u32,
            approvers,
            request_id: DigestIdentifier::default(),
            version: 0,
            approvers_timeout: vec![],
            approvers_agrees: vec![],
            approvers_disagrees: vec![],
            approval_req_hash: DigestIdentifier::default(),
        }
    }

    async fn create_approvers(
        &self,
        ctx: &mut ActorContext<Self>,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        let subject_id = self.request.content().subject_id.to_string();

        if signer == *self.our_key {
            let approver_path =
                ActorPath::from(format!("/user/node/{}/approver", subject_id));
            let approver_actor = ctx
                .system()
                .get_actor::<ApprPersist>(&approver_path)
                .await?;
            approver_actor
                .tell(ApprPersistMessage::LocalApproval {
                    request_id: self.request_id.clone(),
                    version: self.version,
                    approval_req: self.request.clone(),
                })
                .await?
        } else {
            // Create Approvers child
            let child = ctx
                .create_child(
                    &signer.to_string(),
                    ApprLight::new(
                        self.network.clone(),
                        signer.clone(),
                        self.request_id.clone(),
                        self.version,
                    ),
                )
                .await?;

            child
                .tell(ApprLightMessage::NetworkApproval {
                    approval_req: self.request.clone(),
                })
                .await?;
        }

        Ok(())
    }
    fn check_approval(&mut self, approver: PublicKey) -> bool {
        self.approvers.remove(&approver)
    }

    async fn send_approval_to_req(
        &self,
        ctx: &ActorContext<Self>,
        response: bool,
    ) -> Result<(), ActorError> {
        let req_actor = ctx.get_parent::<RequestManager>().await?;

        req_actor
            .tell(RequestManagerMessage::ApprovalRes {
                request_id: self.request_id.clone(),
                appro_res: ApprovalData {
                    approval_req_signature: self.request.signature().clone(),
                    approval_req_hash: self.approval_req_hash.clone(),
                    approvers_agrees_signatures: self.approvers_agrees.clone(),
                    approvers_disagrees_signatures: self
                        .approvers_disagrees
                        .clone(),
                    approvers_timeout: self.approvers_timeout.clone(),
                    approved: response,
                },
            })
            .await
    }

    fn create_appro_req_hash(&self) -> Result<DigestIdentifier, CryptoError> {
        hash_borsh(&*self.hash.hasher(), &self.request)
    }
}

#[derive(Debug, Clone)]
pub enum ApprovalMessage {
    Create {
        request_id: DigestIdentifier,
        version: u64,
    },
    Response {
        approval_res: ApprovalRes,
        sender: PublicKey,
        signature: Option<Signature>,
    },
}

impl Message for ApprovalMessage {}

#[async_trait]
impl Actor for Approval {
    type Event = ();
    type Message = ApprovalMessage;
    type Response = ();

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Approval"),
            |parent_span| info_span!(parent: parent_span, "Approval"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Approval {
    async fn handle_message(
        &mut self,
        __sender: ActorPath,
        msg: ApprovalMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ApprovalMessage::Create {
                request_id,
                version,
            } => {
                let approval_req_hash = match self.create_appro_req_hash() {
                    Ok(digest) => digest,
                    Err(e) => {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to create approval request hash"
                        );
                        return Err(emit_fail(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Cannot create approval request hash: {}",
                                    e
                                ),
                            },
                        )
                        .await);
                    }
                };

                self.approval_req_hash = approval_req_hash;
                self.request_id = request_id.clone();
                self.version = version;

                for signer in self.approvers.clone() {
                    if let Err(e) =
                        self.create_approvers(ctx, signer.clone()).await
                    {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            signer = %signer,
                            "Failed to create approver actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                }

                debug!(
                    msg_type = "Create",
                    request_id = %request_id,
                    version = version,
                    approvers_count = self.approvers_quantity,
                    "Approval created and approvers initialized"
                );
            }
            ApprovalMessage::Response {
                approval_res,
                sender,
                signature,
            } => {
                if self.check_approval(sender.clone()) {
                    match approval_res.clone() {
                        ApprovalRes::Response {
                            approval_req_hash,
                            agrees,
                            ..
                        } => {
                            if approval_req_hash != self.approval_req_hash {
                                error!(
                                    msg_type = "Response",
                                    expected_hash = %self.approval_req_hash,
                                    received_hash = %approval_req_hash,
                                    "Invalid approval request hash"
                                );
                                return Err(ActorError::Functional {
                                    description: "Approval Response, Invalid approval request hash".to_owned(),
                                });
                            }

                            let Some(signature) = signature else {
                                error!(
                                    msg_type = "Response",
                                    sender = %sender,
                                    "Approval response without signature"
                                );
                                return Err(ActorError::Functional {
                                    description: "Approval Response solver without signature".to_owned(),
                                });
                            };

                            if agrees {
                                self.approvers_agrees.push(signature);
                            } else {
                                self.approvers_disagrees.push(signature);
                            }
                        }
                        ApprovalRes::TimeOut(approval_time_out) => {
                            self.approvers_timeout.push(approval_time_out);
                        }
                    };

                    // si hemos llegado al quorum y hay suficientes aprobaciones aprobamos...
                    if self.quorum.check_quorum(
                        self.approvers_quantity,
                        self.approvers_agrees.len() as u32
                            + self.approvers_timeout.len() as u32,
                    ) {
                        if let Err(e) =
                            self.send_approval_to_req(ctx, true).await
                        {
                            error!(
                                msg_type = "Response",
                                error = %e,
                                "Failed to send approval response to request actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        };

                        debug!(
                            msg_type = "Response",
                            agrees = self.approvers_agrees.len(),
                            disagrees = self.approvers_disagrees.len(),
                            timeouts = self.approvers_timeout.len(),
                            "Quorum reached, approval accepted"
                        );
                    } else if self.approvers.is_empty()
                        && let Err(e) =
                            self.send_approval_to_req(ctx, false).await
                    {
                        error!(
                            msg_type = "Response",
                            error = %e,
                            "Failed to send approval response to request actor"
                        );
                        return Err(emit_fail(ctx, e).await);
                    } else if self.approvers.is_empty() {
                        debug!(
                            msg_type = "Response",
                            agrees = self.approvers_agrees.len(),
                            disagrees = self.approvers_disagrees.len(),
                            timeouts = self.approvers_timeout.len(),
                            "All approvers responded, approval rejected"
                        );
                    }
                } else {
                    warn!(
                        msg_type = "Response",
                        sender = %sender,
                        "Response from unexpected sender"
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
            request_id = %self.request_id,
            version = self.version,
            error = %error,
            "Child fault in approval actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

impl NotPersistentActor for Approval {}
