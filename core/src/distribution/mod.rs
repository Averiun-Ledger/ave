use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use tracing::{Span, debug, error, info_span};

use crate::{
    distribution::coordinator::{DistriCoordinator, DistriCoordinatorMessage},
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::common::emit_fail,
    request::manager::{RequestManager, RequestManagerMessage},
    subject::SignedLedger,
};

pub mod coordinator;
pub mod error;
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

    async fn create_distributors(
        &self,
        ctx: &mut ActorContext<Self>,
        ledger: SignedLedger,
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
        ledger: Box<SignedLedger>,
        witnesses: HashSet<PublicKey>,
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
        _sender: ActorPath,
        msg: DistributionMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            DistributionMessage::Create { ledger, witnesses } => {
                self.witnesses.clone_from(&witnesses);
                self.subject_id = ledger.content().get_subject_id();

                debug!(
                    msg_type = "Create",
                    subject_id = %self.subject_id,
                    witnesses_count = witnesses.len(),
                    distribution_type = ?self.distribution_type,
                    "Starting distribution to witnesses"
                );

                for witness in witnesses.iter() {
                    self.create_distributors(
                        ctx,
                        *ledger.clone(),
                        witness.clone(),
                    )
                    .await?
                }

                debug!(
                    msg_type = "Create",
                    subject_id = %self.subject_id,
                    "All distributor coordinators created"
                );
            }
            DistributionMessage::Response { sender } => {
                debug!(
                    msg_type = "Response",
                    subject_id = %self.subject_id,
                    sender = %sender,
                    remaining_witnesses = self.witnesses.len(),
                    "Distribution response received"
                );

                if self.check_witness(sender.clone())
                    && self.witnesses.is_empty()
                {
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
                        return Err(emit_fail(ctx, e).await);
                    };
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
        Self::observe_event("error");
        error!(
            subject_id = %self.subject_id,
            request_id = %self.request_id,
            distribution_type = ?self.distribution_type,
            error = %error,
            "Child fault in distribution actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
