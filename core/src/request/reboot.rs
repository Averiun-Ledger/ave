use std::time::Duration;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::model::common::{emit_fail, subject::get_last_sn};

use super::manager::{RequestManager, RequestManagerMessage};

const TARGET_REBOOT: &str = "Ave-Request-Reboot";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reboot {
    governance_id: String,
    actual_sn: u64,
    count: u64,
}

impl Reboot {
    pub fn new(governance_id: String) -> Self {
        Self {
            governance_id,
            actual_sn: 0,
            count: 0,
        }
    }

    async fn sleep(
        &self,
        ctx: &mut ave_actors::ActorContext<Reboot>,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await;
        if let Some(actor) = actor {
            let request = RebootMessage::Update;
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(5)).await;
                if let Err(e) = actor.tell(request).await {
                    error!(
                        TARGET_REBOOT,
                        "Sleep, can not send Update message to Reboot actor: {}",
                        e
                    );
                }
            });
        } else {
            let path = ctx.path().clone();
            return Err(ActorError::NotFound(path));
        }
        Ok(())
    }

    async fn finish(
        ctx: &mut ave_actors::ActorContext<Reboot>,
    ) -> Result<(), ActorError> {
        let request_actor: Option<ave_actors::ActorRef<RequestManager>> =
            ctx.parent().await;

        if let Some(request_actor) = request_actor {
            request_actor
                .tell(RequestManagerMessage::FinishReboot)
                .await?
        } else {
            let path = ctx.path().parent();
            return Err(ActorError::NotFound(path));
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

    async fn pre_start(
        &mut self,
        _ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        Ok(())
    }

    async fn pre_stop(
        &mut self,
        _ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        Ok(())
    }
}

#[async_trait]
impl Handler<Reboot> for Reboot {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RebootMessage,
        ctx: &mut ave_actors::ActorContext<Reboot>,
    ) -> Result<(), ActorError> {
        match msg {
            RebootMessage::Init => {
                match get_last_sn(ctx, &self.governance_id).await {
                    Ok(sn) => self.actual_sn = sn,
                    Err(e) => {
                        error!(
                            TARGET_REBOOT,
                            "Init, can not get last sn: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = self.sleep(ctx).await {
                    error!(TARGET_REBOOT, "Init, can not sleep: {}", e);
                    return Err(emit_fail(ctx, e).await);
                };
            }
            RebootMessage::Update => {
                let actual_sn = self.actual_sn;

                match get_last_sn(ctx, &self.governance_id).await {
                    Ok(sn) => self.actual_sn = sn,
                    Err(e) => {
                        error!(
                            TARGET_REBOOT,
                            "Init, can not get last sn: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if actual_sn == self.actual_sn {
                    self.count += 1;
                }

                if self.count >= 3 {
                    if let Err(e) = Self::finish(ctx).await {
                        error!(
                            TARGET_REBOOT,
                            "Update, can not finish reboot: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                } else {
                    if let Err(e) = self.sleep(ctx).await {
                        error!(TARGET_REBOOT, "Init, can not sleep: {}", e);
                        return Err(emit_fail(ctx, e).await);
                    };
                }
            }
        };

        Ok(())
    }
}
