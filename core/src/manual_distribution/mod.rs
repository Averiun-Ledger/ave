use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    distribution::{Distribution, DistributionMessage, DistributionType},
    governance::model::WitnessesData,
    helpers::network::service::NetworkSender,
    model::common::{
        distribution_plan::build_tracker_event_distribution_plan,
        emit_fail,
        node::i_can_send_last_ledger,
        subject::{
            acquire_subject, get_gov, get_last_ledger_event,
            get_tracker_window as resolve_tracker_window,
        },
    },
    model::event::{Ledger, Protocols, ValidationMetadata},
    request::types::{DistributionPlanEntry, DistributionPlanMode},
    subject::Metadata,
};

pub struct ManualDistribution {
    our_key: Arc<PublicKey>,
}

impl ManualDistribution {
    pub const fn new(our_key: Arc<PublicKey>) -> Self {
        Self { our_key }
    }

    fn tracker_delivery_mode(
        sn: u64,
        ranges: &[crate::governance::witnesses_register::TrackerDeliveryRange],
    ) -> Option<DistributionPlanMode> {
        ranges
            .iter()
            .find(|range| range.from_sn <= sn && sn <= range.to_sn)
            .map(|range| match range.mode {
                crate::governance::witnesses_register::TrackerDeliveryMode::Clear => {
                    DistributionPlanMode::Clear
                }
                crate::governance::witnesses_register::TrackerDeliveryMode::Opaque => {
                    DistributionPlanMode::Opaque
                }
            })
    }

    fn tracker_metadata_from_ledger(
        ledger: &Ledger,
    ) -> Result<Metadata, ActorError> {
        let validation = match &ledger.protocols {
            Protocols::Create { validation, .. }
            | Protocols::TrackerFactFull { validation, .. }
            | Protocols::Transfer { validation, .. }
            | Protocols::TrackerConfirm { validation, .. }
            | Protocols::Reject { validation, .. }
            | Protocols::EOL { validation, .. } => validation,
            _ => {
                return Err(ActorError::FunctionalCritical {
                    description: format!(
                        "Unsupported tracker ledger protocols for manual distribution: {:?}",
                        ledger.get_event_request_type()
                    ),
                });
            }
        };

        let ValidationMetadata::Metadata(metadata) =
            &validation.validation_metadata
        else {
            return Err(ActorError::FunctionalCritical {
                description: "Missing validation metadata in tracker ledger"
                    .to_owned(),
            });
        };

        Ok((**metadata).clone())
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

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ManualDistribution"),
            |parent_span| info_span!(parent: parent_span, "ManualDistribution"),
        )
    }
}

#[async_trait]
impl Handler<Self> for ManualDistribution {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ManualDistributionMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
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

                let is_tracker = data.get_governance_id().is_some();
                let ledger = if is_tracker {
                    let lease = acquire_subject(
                        ctx,
                        &subject_id,
                        format!("manual_distribution:{}", subject_id),
                        None,
                        true,
                    )
                    .await?;
                    let ledger = get_last_ledger_event(ctx, &subject_id).await;
                    lease.finish(ctx).await?;
                    ledger
                } else {
                    get_last_ledger_event(ctx, &subject_id).await
                }
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
                    data.get_governance_id().as_ref().map_or_else(
                        || subject_id.clone(),
                        |governance_id| governance_id.clone(),
                    );

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
                let recipients = if is_gov {
                    let mut witnesses =
                        gov.get_witnesses(WitnessesData::Gov).map_err(|e| {
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
                    witnesses
                        .into_iter()
                        .map(|node| DistributionPlanEntry {
                            node,
                            mode: DistributionPlanMode::Clear,
                        })
                        .collect::<Vec<_>>()
                } else {
                    let metadata = Self::tracker_metadata_from_ledger(&ledger)?;
                    let event_request =
                        ledger.get_event_request().ok_or_else(|| {
                            ActorError::FunctionalCritical {
                                description:
                                    "Missing event request in tracker ledger"
                                        .to_owned(),
                            }
                        })?;
                    let candidates = build_tracker_event_distribution_plan(
                        &gov,
                        &event_request,
                        &metadata,
                        true,
                    )
                    .map_err(|description| ActorError::FunctionalCritical {
                        description,
                    })?;

                    let mut distribution_plan = Vec::new();

                    for candidate in candidates {
                        let witness = candidate.node;
                        if witness == *self.our_key {
                            continue;
                        }

                        let window = resolve_tracker_window(
                            ctx,
                            &governance_id,
                            &subject_id,
                            witness.clone(),
                            data.get_namespace(),
                            schema_id.clone(),
                            ledger.sn.checked_sub(1),
                        )
                        .await;

                        let (sn, _, _, ranges) = match window {
                            Ok(window) => window,
                            Err(e) => {
                                warn!(
                                    msg_type = "Update",
                                    subject_id = %subject_id,
                                    witness = %witness,
                                    error = %e,
                                    "Skipping witness because tracker window could not be resolved"
                                );
                                continue;
                            }
                        };

                        let Some(sn) = sn else {
                            continue;
                        };

                        if sn < ledger.sn {
                            continue;
                        }

                        let Some(mode) =
                            Self::tracker_delivery_mode(ledger.sn, &ranges)
                        else {
                            continue;
                        };

                        distribution_plan.push(DistributionPlanEntry {
                            node: witness,
                            mode,
                        });
                    }

                    distribution_plan
                };

                if recipients.is_empty() {
                    warn!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "No witnesses available for manual distribution"
                    );
                    return Err(ActorError::Functional {
                        description: "No witnesses available to manually send the last ledger event".to_string()
                    });
                }

                let witnesses_count = recipients.len();

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

                let distribution = Distribution::new(
                    network,
                    DistributionType::Manual,
                    DigestIdentifier::default(),
                );

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
                        distribution_plan: recipients,
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
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child actor fault in manual distribution"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
