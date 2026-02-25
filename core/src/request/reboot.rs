use std::time::Duration;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message, NotPersistentActor,
};
use ave_common::identity::DigestIdentifier;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::model::common::{emit_fail, subject::get_gov_sn};

use super::manager::{RequestManager, RequestManagerMessage};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reboot {
    request_id: DigestIdentifier,
    governance_id: DigestIdentifier,
    actual_sn: u64,
    count: u64,
}

impl Reboot {
    pub const fn new(
        governance_id: DigestIdentifier,
        request_id: DigestIdentifier,
    ) -> Self {
        Self {
            request_id,
            governance_id,
            actual_sn: 0,
            count: 0,
        }
    }

    async fn sleep(
        &self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let request = RebootMessage::Update;
        let request_id = self.request_id.clone();
        let governance_id = self.governance_id.clone();
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = actor.tell(request).await {
                error!(
                    request_id = %request_id,
                    governance_id = %governance_id,
                    error = %e,
                    "Failed to send Update message to Reboot actor"
                );
            }
        });

        Ok(())
    }

    async fn finish(
        &self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        debug!(
            request_id = %self.request_id,
            governance_id = %self.governance_id,
            count = self.count,
            "Finishing reboot, notifying parent"
        );

        let request_actor = match ctx.get_parent::<RequestManager>().await {
            Ok(actor) => actor,
            Err(e) => {
                error!(
                    request_id = %self.request_id,
                    governance_id = %self.governance_id,
                    error = %e,
                    "Failed to get parent RequestManager"
                );
                return Err(e);
            }
        };

        if let Err(e) = request_actor
            .tell(RequestManagerMessage::FinishReboot {
                request_id: self.request_id.clone(),
            })
            .await
        {
            error!(
                request_id = %self.request_id,
                governance_id = %self.governance_id,
                error = %e,
                "Failed to send FinishReboot message to parent"
            );
            return Err(e);
        }

        ctx.stop(None).await;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RebootMessage {
    Init,
    Update,
}

impl Message for RebootMessage {}

impl NotPersistentActor for Reboot {}

#[async_trait]
impl Actor for Reboot {
    type Message = RebootMessage;
    type Event = ();
    type Response = ();

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Reboot")
        } else {
            info_span!("Reboot")
        }
    }
}

#[async_trait]
impl Handler<Self> for Reboot {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RebootMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            RebootMessage::Init => {
                match get_gov_sn(ctx, &self.governance_id).await {
                    Ok(sn) => {
                        self.actual_sn = sn;
                        debug!(
                            msg_type = "Init",
                            request_id = %self.request_id,
                            governance_id = %self.governance_id,
                            sn = sn,
                            "Reboot initialized with governance sn"
                        );
                    }
                    Err(e) => {
                        error!(
                            msg_type = "Init",
                            request_id = %self.request_id,
                            governance_id = %self.governance_id,
                            error = %e,
                            "Failed to get governance sn"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = self.sleep(ctx).await {
                    error!(
                        msg_type = "Init",
                        request_id = %self.request_id,
                        governance_id = %self.governance_id,
                        error = %e,
                        "Failed to schedule sleep"
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
            RebootMessage::Update => {
                let actual_sn = self.actual_sn;

                match get_gov_sn(ctx, &self.governance_id).await {
                    Ok(sn) => {
                        self.actual_sn = sn;
                        debug!(
                            msg_type = "Update",
                            request_id = %self.request_id,
                            governance_id = %self.governance_id,
                            old_sn = actual_sn,
                            new_sn = sn,
                            "Governance sn retrieved"
                        );
                    }
                    Err(e) => {
                        error!(
                            msg_type = "Update",
                            request_id = %self.request_id,
                            governance_id = %self.governance_id,
                            error = %e,
                            "Failed to get governance sn"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if actual_sn == self.actual_sn {
                    self.count += 1;
                    debug!(
                        msg_type = "Update",
                        request_id = %self.request_id,
                        governance_id = %self.governance_id,
                        sn = actual_sn,
                        count = self.count,
                        "Governance sn unchanged, incrementing counter"
                    );
                } else {
                    debug!(
                        msg_type = "Update",
                        request_id = %self.request_id,
                        governance_id = %self.governance_id,
                        old_sn = actual_sn,
                        new_sn = self.actual_sn,
                        count = self.count,
                        "Governance sn changed"
                    );
                }

                if self.count >= 3 {
                    debug!(
                        msg_type = "Update",
                        request_id = %self.request_id,
                        governance_id = %self.governance_id,
                        count = self.count,
                        "Max retry count reached, finishing reboot"
                    );
                    if let Err(e) = self.finish(ctx).await {
                        error!(
                            msg_type = "Update",
                            request_id = %self.request_id,
                            governance_id = %self.governance_id,
                            error = %e,
                            "Failed to finish reboot"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                } else if let Err(e) = self.sleep(ctx).await {
                    error!(
                        msg_type = "Update",
                        request_id = %self.request_id,
                        governance_id = %self.governance_id,
                        count = self.count,
                        error = %e,
                        "Failed to schedule sleep"
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
        };

        Ok(())
    }
}
