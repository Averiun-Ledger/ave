use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    Namespace,
    identity::{DigestIdentifier, PublicKey},
};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    distribution::{Distribution, DistributionMessage, DistributionType},
    governance::model::WitnessesData,
    helpers::network::service::NetworkSender,
    model::common::{
        emit_fail,
        node::i_can_send_last_ledger,
        subject::{get_gov, get_last_ledger_event},
    },
};

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
                let data = i_can_send_last_ledger(ctx, &subject_id)
                    .await
                    .map_err(|e| {
                        error!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to check if we can send last ledger"
                        );
                        e
                    })?;

                let Some(data) = data else {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Not the owner of the subject nor rejected transfer"
                    );
                    return Err(ActorError::Functional {
                        description: "Not the owner of the subject, nor have I refused the transfer".to_owned(),
                    });
                };

                let ledger = get_last_ledger_event(ctx, &subject_id)
                    .await
                    .map_err(|e| {
                        error!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to get last ledger event"
                        );
                        e
                    })?;

                let Some(ledger) = ledger else {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "No ledger event found for subject"
                    );
                    return Err(ActorError::Functional {
                        description: "Cannot obtain last ledger event"
                            .to_string(),
                    });
                };

                let governance_id =
                    if let Some(governance_id) = &data.get_governance_id() {
                        governance_id.clone()
                    } else {
                        subject_id.clone()
                    };

                let gov = get_gov(ctx, &governance_id).await.map_err(|e| {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        governance_id = %governance_id,
                        error = %e,
                        "Failed to get governance"
                    );
                    e
                })?;

                let schema_id = data.get_schema_id();

                let is_gov = schema_id.is_gov();
                let witnesses_data = if is_gov {
                    WitnessesData::Gov
                } else {
                    WitnessesData::Schema {
                        creator: (*self.our_key).clone(),
                        schema_id: schema_id.clone(),
                        namespace: Namespace::from(data.get_namespace()),
                    }
                };

                let mut witnesses =
                    gov.get_witnesses(witnesses_data).map_err(|e| {
                        error!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            is_gov = is_gov,
                            error = %e,
                            "Failed to get witnesses from governance"
                        );
                        ActorError::Functional {
                            description: e.to_string(),
                        }
                    })?;

                witnesses.remove(&*self.our_key);
                if witnesses.is_empty() {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "No witnesses available for manual distribution"
                    );
                    return Err(ActorError::Functional {
                        description: "No witnesses available to manually send the last ledger event".to_string()
                    });
                }

                let witnesses_count = witnesses.len();

                let Some(network) = ctx
                    .system()
                    .get_helper::<Arc<NetworkSender>>("network")
                    .await
                else {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Network helper not found"
                    );
                    return Err(ActorError::Helper {
                        name: "network".to_owned(),
                        reason: "Not found".to_owned(),
                    });
                };

                let distribution =
                    Distribution::new(network, DistributionType::Manual);

                let distribution_actor = ctx.create_child(&subject_id.to_string(), distribution).await.map_err(|e| {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        error = %e,
                        "Manual distribution already in progress"
                    );
                    ActorError::Functional {
                        description: "Manual distribution already in progress for this subject".to_owned()
                    }
                })?;

                if let Err(e) = distribution_actor
                    .tell(DistributionMessage::Create {
                        witnesses: witnesses.clone(),
                        ledger: Box::new(ledger),
                    })
                    .await
                {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        witnesses_count = witnesses_count,
                        error = %e,
                        "Failed to start manual distribution"
                    );
                    return Err(ActorError::Functional {
                        description: format!(
                            "Failed to start manual distribution: {}",
                            e
                        ),
                    });
                };

                debug!(
                    msg_type = "Update",
                    subject_id = %subject_id,
                    witnesses_count = witnesses_count,
                    is_gov = is_gov,
                    "Manual distribution started successfully"
                );

                Ok(())
            }
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<ManualDistribution>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child actor fault in manual distribution"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
