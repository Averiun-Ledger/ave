use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use tracing::{Span, error, info_span};

use crate::{
    distribution::coordinator::{DistriCoordinator, DistriCoordinatorMessage},
    helpers::network::service::NetworkSender,
    model::common::emit_fail,
    request::manager::{RequestManager, RequestManagerMessage},
    subject::SignedLedger,
};

pub mod coordinator;
pub mod error;
pub mod worker;

const TARGET_DISTRIBUTION: &str = "Ave-Distribution";

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
}

impl Distribution {
    pub fn new(
        network: Arc<NetworkSender>,
        distribution_type: DistributionType,
    ) -> Self {
        Distribution {
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
        ctx: &mut ActorContext<Distribution>,
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
            Err(e) => return Err(e),
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
                ledger,
            })
            .await
    }

    async fn end_request(
        &self,
        ctx: &mut ActorContext<Distribution>,
    ) -> Result<(), ActorError> {
        if let DistributionType::Request = self.distribution_type {
            let req_actor = ctx.get_parent::<RequestManager>().await?;
            req_actor.tell(RequestManagerMessage::FinishRequest).await?;
        } else {
            ctx.stop(None);
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
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Distribution", id = id)
        } else {
            info_span!("Distribution", id = id)
        }
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
impl Handler<Distribution> for Distribution {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: DistributionMessage,
        ctx: &mut ActorContext<Distribution>,
    ) -> Result<(), ActorError> {
        match msg {
            DistributionMessage::Create { ledger, witnesses } => {
                self.witnesses.clone_from(&witnesses);
                self.subject_id =
                    ledger.content().event_request.content().get_subject_id();

                for witness in witnesses.iter() {
                    self.create_distributors(
                        ctx,
                        *ledger.clone(),
                        witness.clone(),
                    )
                    .await?
                }
            }
            DistributionMessage::Response { sender } => {
                if self.check_witness(sender) && self.witnesses.is_empty() {
                    if let Err(e) = self.end_request(ctx).await {
                        error!(
                            TARGET_DISTRIBUTION,
                            "Response, can not end distribution: {}", e
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
        ctx: &mut ActorContext<Distribution>,
    ) -> ChildAction {
        error!(TARGET_DISTRIBUTION, "OnChildFault, {}", error);
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
