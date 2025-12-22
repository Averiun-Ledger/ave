use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler,
    Message, NotPersistentActor,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::{
    distribution::{Distribution, DistributionMessage, DistributionType},
    governance::{Governance, GovernanceMessage, GovernanceResponse},
    model::common::{emit_fail, node::subject_owner},
    subject::{LastStateData, SignedLedger},
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};

const TARGET_MANUAL_DISTRIBUTION: &str = "Ave-Node-ManualDistribution";

pub struct ManualDistribution {
    our_key: PublicKey,
}

impl ManualDistribution {
    pub fn new(our_key: PublicKey) -> Self {
        Self { our_key }
    }
    async fn get_last_ledger(
        ctx: &mut ActorContext<ManualDistribution>,
        subject_id: &str,
    ) -> Result<(Vec<SignedLedger>, Option<LastStateData>), ActorError> {
        let path = ActorPath::from(format!("/user/node/{}", subject_id));

        if let Some(tracker_actor) =
            ctx.system().get_actor::<Tracker>(&path).await
        {
            let response =
                tracker_actor.ask(TrackerMessage::GetLastLedger).await?;
            match response {
                TrackerResponse::Ledger { ledger, last_state } => {
                    Ok((ledger, last_state))
                }
                _ => Err(ActorError::UnexpectedResponse(
                    path,
                    "TrackerResponse::Ledger".to_owned(),
                )),
            }
        } else if let Some(governance_actor) =
            ctx.system().get_actor::<Governance>(&path).await
        {
            let response = governance_actor
                .ask(GovernanceMessage::GetLastLedger)
                .await?;
            match response {
                GovernanceResponse::Ledger { ledger, last_state } => {
                    Ok((ledger, last_state))
                }
                _ => Err(ActorError::UnexpectedResponse(
                    path,
                    "GovernanceResponse::Ledger".to_owned(),
                )),
            }
        } else {
            Err(ActorError::NotFound(path))
        }
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
