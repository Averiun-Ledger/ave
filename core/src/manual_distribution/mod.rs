use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span, warn};

use crate::{
    distribution::{Distribution, DistributionMessage, DistributionType},
    model::common::{emit_fail},
};

const TARGET_MANUAL_DISTRIBUTION: &str = "Ave-Node-ManualDistribution";

pub struct ManualDistribution {
    our_key: Arc<PublicKey>,
}

impl ManualDistribution {
    pub fn new(our_key: Arc<PublicKey>) -> Self {
        Self { our_key }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum ManualDistributionMessage {
    Update(DigestIdentifier),
}

impl Message for ManualDistributionMessage {}

impl NotPersistentActor for ManualDistribution {}

#[async_trait]
impl Actor for ManualDistribution {
    type Message = ManualDistributionMessage;
    type Event = ();
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "ManualDistribution", id = id)
        } else {
            info_span!("ManualDistribution", id = id)
        }
    }
}

#[async_trait]
impl Handler<ManualDistribution> for ManualDistribution {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ManualDistributionMessage,
        ctx: &mut ave_actors::ActorContext<ManualDistribution>,
    ) -> Result<(), ActorError> {
        match msg {
            ManualDistributionMessage::Update(subject_id) => {
                let (is_owner, _is_pending) =
                    subject_owner(ctx, &subject_id.to_string()).await?;

                if !is_owner {
                    let e = "We are not subject owner";
                    warn!(TARGET_MANUAL_DISTRIBUTION, "Update, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }

                let distribution = Distribution::new(
                    self.our_key.clone(),
                    DistributionType::Manual,
                );
                let request_id = format!("M_{}", subject_id);

                let (ledger, last_state) =
                    Self::get_last_ledger(ctx, &subject_id.to_string()).await?;

                let Some(last_state) = last_state else {
                    let e = "Can not obtain last state";
                    error!(TARGET_MANUAL_DISTRIBUTION, "Update, {}", e);
                    return Err(ActorError::Functional(e.to_string()));
                };

                let ledger = if ledger.len() != 1 {
                    let e = "Failed to get the latest event from the ledger";
                    error!(TARGET_MANUAL_DISTRIBUTION, "Update, {}", e);
                    return Err(ActorError::Functional(e.to_string()));
                } else {
                    ledger[0].clone()
                };

                let distribution_actor = ctx.create_child(&request_id, distribution).await.map_err(|e| {
                    warn!(TARGET_MANUAL_DISTRIBUTION, "Update, Can not create distribution child: {}", e);
                    ActorError::Functional("There was already a manual distribution in progress".to_owned())
                })?;

                if let Err(e) = distribution_actor
                    .tell(DistributionMessage::Create {
                        request_id,
                        event: last_state.event,
                        ledger: Box::new(ledger),
                        last_proof: last_state.proof,
                        last_vali_res: last_state.vali_res,
                    })
                    .await
                {
                    let e = format!("Can not create manual update: {}", e);
                    error!(TARGET_MANUAL_DISTRIBUTION, "Update, {}", e);
                    return Err(ActorError::Functional(e.to_string()));
                };

                Ok(())
            }
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<ManualDistribution>,
    ) -> ChildAction {
        error!(TARGET_MANUAL_DISTRIBUTION, "OnChildFault, {}", error);
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
