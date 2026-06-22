use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    distribution::coordinator::{DistriCoordinator, DistriCoordinatorMessage},
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::{common::crash_system, event::Ledger},
    request::manager::{RequestManager, RequestManagerMessage},
    request::types::{DistributionPlanEntry, DistributionPlanMode},
};

macro_rules! handle_distri_error {
    ($ctx:expr, $result:expr, $msg_type:expr, $subject_id:expr, $message:expr) => {
        match $result {
            Ok(v) => Ok(v),
            Err(e) => {
                if let ActorError::FunctionalCritical { .. } = e {
                    error!(
                        msg_type = $msg_type,
                        subject_id = %$subject_id,
                        error = %e,
                        "{}",
                        $message
                    );
                    Err(crash_system($ctx, e).await)
                } else {
                    warn!(
                        msg_type = $msg_type,
                        subject_id = %$subject_id,
                        error = %e,
                        "{}",
                        $message
                    );
                    Err(e)
                }
            }
        }
    };
    ($ctx:expr, $result:expr, $msg_type:expr, $subject_id:expr, $message:expr, sender = $sender:expr) => {
        match $result {
            Ok(v) => Ok(v),
            Err(e) => {
                if let ActorError::FunctionalCritical { .. } = e {
                    error!(
                        msg_type = $msg_type,
                        subject_id = %$subject_id,
                        sender = %$sender,
                        error = %e,
                        "{}",
                        $message
                    );
                    Err(crash_system($ctx, e).await)
                } else {
                    warn!(
                        msg_type = $msg_type,
                        subject_id = %$subject_id,
                        sender = %$sender,
                        error = %e,
                        "{}",
                        $message
                    );
                    Err(e)
                }
            }
        }
    };
    ($ctx:expr, $result:expr, $msg_type:expr, $subject_id:expr, $message:expr, sender = $sender:expr, sn = $sn:expr) => {
        match $result {
            Ok(v) => Ok(v),
            Err(e) => {
                if let ActorError::FunctionalCritical { .. } = e {
                    error!(
                        msg_type = $msg_type,
                        subject_id = %$subject_id,
                        sn = $sn,
                        sender = %$sender,
                        error = %e,
                        "{}",
                        $message
                    );
                    Err(crash_system($ctx, e).await)
                } else {
                    warn!(
                        msg_type = $msg_type,
                        subject_id = %$subject_id,
                        sn = $sn,
                        sender = %$sender,
                        error = %e,
                        "{}",
                        $message
                    );
                    Err(e)
                }
            }
        }
    };
}

pub mod coordinator;
pub mod error;
pub mod processor;
pub mod transfer_verifier;
pub mod worker;

#[derive(Debug, Clone)]
pub enum DistributionType {
    Manual,
    Request,
}

pub struct Distribution {
    network: Arc<NetworkSender>,
    witnesses: HashSet<PublicKey>,
    distribution_type: DistributionType,
    subject_id: DigestIdentifier,
    request_id: DigestIdentifier,
}

impl Distribution {
    fn observe_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("distribution", result);
        }
    }

    pub fn new(
        network: Arc<NetworkSender>,
        distribution_type: DistributionType,
        request_id: DigestIdentifier,
    ) -> Self {
        Self {
            request_id,
            network,
            distribution_type,
            witnesses: HashSet::new(),
            subject_id: DigestIdentifier::default(),
        }
    }

    fn check_witness(&mut self, witness: PublicKey) -> bool {
        self.witnesses.remove(&witness)
    }

    fn project_ledger_for_mode(
        ledger: &Ledger,
        mode: &DistributionPlanMode,
    ) -> Result<Ledger, ActorError> {
        match mode {
            DistributionPlanMode::Clear => Ok(ledger.clone()),
            DistributionPlanMode::Opaque => {
                ledger.to_tracker_opaque().map_err(Into::into)
            }
        }
    }

    async fn create_distributor(
        &self,
        ctx: &mut ActorContext<Self>,
        ledger: Ledger,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        let child = ctx
            .create_child(
                &format!("{}", signer),
                DistriCoordinator {
                    node_key: signer.clone(),
                    network: self.network.clone(),
                },
            )
            .await;
        let distributor_actor = match child {
            Ok(child) => child,
            Err(e) => {
                error!(
                    msg_type = "CreateDistributor",
                    subject_id = %self.subject_id,
                    witness = %signer,
                    error = %e,
                    "Failed to create distributor coordinator"
                );
                return Err(e);
            }
        };

        let request_id = match self.distribution_type {
            DistributionType::Manual => {
                format!("node/manual_distribution/{}", self.subject_id)
            }
            DistributionType::Request => {
                format!("request/{}/distribution", self.subject_id)
            }
        };

        distributor_actor
            .tell(DistriCoordinatorMessage::NetworkDistribution {
                request_id,
                ledger: Box::new(ledger),
            })
            .await
    }

    async fn end_request(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if matches!(self.distribution_type, DistributionType::Request) {
            let req_actor = ctx.get_parent::<RequestManager>().await?;
            req_actor
                .tell(RequestManagerMessage::FinishRequest {
                    request_id: self.request_id.clone(),
                })
                .await?;
        } else {
            ctx.stop(None).await;
        }

        Ok(())
    }
}

#[async_trait]
impl Actor for Distribution {
    type Event = ();
    type Message = DistributionMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Distribution", id),
            |parent_span| info_span!(parent: parent_span, "Distribution", id),
        )
    }
}

#[derive(Debug, Clone)]
pub enum DistributionMessage {
    Create {
        ledger: Box<Ledger>,
        distribution_plan: Vec<DistributionPlanEntry>,
    },
    Response {
        sender: PublicKey,
    },
}

impl Message for DistributionMessage {}

impl NotPersistentActor for Distribution {}

#[async_trait]
impl Handler<Self> for Distribution {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: DistributionMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            DistributionMessage::Create {
                ledger,
                distribution_plan,
            } => {
                self.witnesses = distribution_plan
                    .iter()
                    .map(|entry| entry.node.clone())
                    .collect();
                self.subject_id = ledger.get_subject_id();
                let clear_ledger = (*ledger).clone();
                let opaque_ledger = if distribution_plan.iter().any(|entry| {
                    matches!(entry.mode, DistributionPlanMode::Opaque)
                }) {
                    Some(Self::project_ledger_for_mode(
                        &clear_ledger,
                        &DistributionPlanMode::Opaque,
                    )?)
                } else {
                    None
                };

                debug!(
                    msg_type = "Create",
                    subject_id = %self.subject_id,
                    witnesses_count = distribution_plan.len(),
                    distribution_type = ?self.distribution_type,
                    "Starting distribution to witnesses"
                );

                for entry in distribution_plan {
                    let ledger = match entry.mode {
                        DistributionPlanMode::Clear => clear_ledger.clone(),
                        DistributionPlanMode::Opaque => opaque_ledger
                            .clone()
                            .ok_or_else(|| ActorError::FunctionalCritical {
                                description: format!(
                                    "Missing opaque distribution projection for subject {}",
                                    self.subject_id
                                ),
                            })?,
                    };

                    self.create_distributor(ctx, ledger, entry.node).await?
                }

                debug!(
                    msg_type = "Create",
                    subject_id = %self.subject_id,
                    "All distributor coordinators created"
                );
            }
            DistributionMessage::Response { sender } => {
                let removed = self.check_witness(sender.clone());
                let remaining_witnesses = self.witnesses.len();

                if !removed {
                    warn!(
                        msg_type = "Response",
                        subject_id = %self.subject_id,
                        sender = %sender,
                        remaining_witnesses = remaining_witnesses,
                        "Ignoring response from unexpected or already-processed witness"
                    );
                    return Ok(());
                }

                debug!(
                    msg_type = "Response",
                    subject_id = %self.subject_id,
                    sender = %sender,
                    remaining_witnesses = remaining_witnesses,
                    "Distribution response received"
                );

                if remaining_witnesses == 0 {
                    Self::observe_event("success");
                    debug!(
                        msg_type = "Response",
                        subject_id = %self.subject_id,
                        "All witnesses responded, ending distribution"
                    );

                    if let Err(e) = self.end_request(ctx).await {
                        error!(
                            msg_type = "Response",
                            subject_id = %self.subject_id,
                            request_id = %self.request_id,
                            error = %e,
                            "Failed to end distribution request"
                        );
                        return Err(crash_system(ctx, e).await);
                    };
                }
            }
        }

        Ok(())
    }
}
