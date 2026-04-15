use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    identity::{DigestIdentifier, PublicKey},
    request::EventRequest,
    schematype::ReservedWords,
};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    distribution::{Distribution, DistributionMessage, DistributionType},
    governance::{
        data::GovernanceData,
        model::{RoleTypes, WitnessesData},
    },
    helpers::network::service::NetworkSender,
    model::common::{
        emit_fail,
        node::i_can_send_last_ledger,
        subject::{
            acquire_subject, get_gov, get_last_ledger_event,
        },
    },
    request::types::{DistributionPlanEntry, DistributionPlanMode},
};

pub struct ManualDistribution {
    our_key: Arc<PublicKey>,
}

impl ManualDistribution {
    pub const fn new(our_key: Arc<PublicKey>) -> Self {
        Self { our_key }
    }

    fn tracker_fact_mode_for_creator(
        governance_data: &GovernanceData,
        schema_id: &ave_common::SchemaType,
        namespace: &ave_common::Namespace,
        creator: &PublicKey,
        witness: &PublicKey,
        viewpoints: &std::collections::BTreeSet<String>,
    ) -> DistributionPlanMode {
        let Some(witness_name) = governance_data
            .members
            .iter()
            .find(|(_, key)| *key == witness)
            .map(|(name, _)| name.clone())
        else {
            return DistributionPlanMode::Opaque;
        };

        let Some(creator_name) = governance_data
            .members
            .iter()
            .find(|(_, key)| *key == creator)
            .map(|(name, _)| name.clone())
        else {
            return DistributionPlanMode::Opaque;
        };

        let Some(roles_schema) = governance_data.roles_schema.get(schema_id)
        else {
            return DistributionPlanMode::Opaque;
        };

        let Some(role_creator) =
            roles_schema
                .creator
                .get(&ave_common::governance::RoleCreator::create(
                    &creator_name,
                    namespace.clone(),
                ))
        else {
            return DistributionPlanMode::Opaque;
        };

        let is_generic_witness =
            roles_schema.hash_this_rol(
                RoleTypes::Witness,
                namespace.clone(),
                &witness_name,
            ) || governance_data.roles_tracker_schemas.hash_this_rol(
                RoleTypes::Witness,
                namespace.clone(),
                &witness_name,
            );

        let allows_clear =
            role_creator.witnesses.iter().any(|creator_witness| {
                let applies = creator_witness.name == witness_name
                    || (creator_witness.name
                        == ReservedWords::Witnesses.to_string()
                        && is_generic_witness);

                if !applies {
                    return false;
                }

                creator_witness
                    .viewpoints
                    .contains(&ReservedWords::AllViewpoints.to_string())
                    || viewpoints.is_empty()
                    || viewpoints.is_subset(&creator_witness.viewpoints)
            });

        if allows_clear {
            DistributionPlanMode::Clear
        } else {
            DistributionPlanMode::Opaque
        }
    }

    fn build_tracker_manual_plan(
        governance_data: &GovernanceData,
        schema_id: ave_common::SchemaType,
        namespace: ave_common::Namespace,
        event_request: &EventRequest,
        signer: &PublicKey,
    ) -> Result<Vec<DistributionPlanEntry>, ActorError> {
        let witnesses = governance_data
            .get_witnesses(WitnessesData::Schema {
                creator: signer.clone(),
                schema_id: schema_id.clone(),
                namespace: namespace.clone(),
            })
            .map_err(|e| ActorError::Functional {
                description: e.to_string(),
            })?;

        Ok(witnesses
            .into_iter()
            .map(|node| {
                let mode = match event_request {
                    EventRequest::Fact(fact_request) => {
                        Self::tracker_fact_mode_for_creator(
                            governance_data,
                            &schema_id,
                            &namespace,
                            signer,
                            &node,
                            &fact_request.viewpoints,
                        )
                    }
                    _ => DistributionPlanMode::Clear,
                };

                DistributionPlanEntry { node, mode }
            })
            .collect())
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

                let is_gov = data.get_schema_id().is_gov();

                let ledger = if is_gov {
                    get_last_ledger_event(ctx, &subject_id).await
                } else {
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
                };

                let ledger = ledger.map_err(|e| {
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

                let schema_id = data.get_schema_id();
                let recipients = if is_gov {
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

                    let Some(event_request) = ledger.get_event_request() else {
                        return Err(ActorError::Functional {
                            description: "Missing event request in tracker ledger".to_owned(),
                        });
                    };

                    Self::build_tracker_manual_plan(
                        &gov,
                        schema_id.clone(),
                        ave_common::Namespace::from(data.get_namespace()),
                        &event_request,
                        &ledger.ledger_seal_signature.signer,
                    )?
                    .into_iter()
                    .filter(|entry| entry.node != *self.our_key)
                    .collect::<Vec<_>>()
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
