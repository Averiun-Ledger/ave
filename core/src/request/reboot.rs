use std::time::Duration;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message, NotPersistentActor,
};
use ave_common::identity::DigestIdentifier;
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span};

use crate::model::common::{emit_fail, subject::get_gov_sn};

use super::manager::{RequestManager, RequestManagerMessage};

const TARGET_REBOOT: &str = "Ave-Request-Reboot";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reboot {
    request_id: DigestIdentifier,
    governance_id: DigestIdentifier,
    actual_sn: u64,
    count: u64,
}

impl Reboot {
    pub fn new(governance_id: DigestIdentifier, request_id: DigestIdentifier) -> Self {
        Self {
            request_id,
            governance_id,
            actual_sn: 0,
            count: 0,
        }
    }

    async fn sleep(
        &self,
        ctx: &mut ave_actors::ActorContext<Reboot>,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let request = RebootMessage::Update;
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if let Err(e) = actor.tell(request).await {
                error!(
                    TARGET_REBOOT,
                    "Sleep, can not send Update message to Reboot actor: {}", e
                );
            }
        });

        Ok(())
    }

    async fn finish(
        &self,
        ctx: &mut ave_actors::ActorContext<Reboot>,
    ) -> Result<(), ActorError> {
        let request_actor = ctx.get_parent::<RequestManager>().await?;

        request_actor
            .tell(RequestManagerMessage::FinishReboot {request_id: self.request_id.clone()})
            .await?;

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

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Reboot", id = id)
        } else {
            info_span!("Reboot", id = id)
        }
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
                match get_gov_sn(ctx, &self.governance_id).await {
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

                match get_gov_sn(ctx, &self.governance_id).await {
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
                    if let Err(e) = self.finish(ctx).await {
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
