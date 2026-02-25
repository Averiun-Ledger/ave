use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey, Signed},
};
use network::ComunicateInfo;
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    evaluation::worker::{EvalWorker, EvalWorkerMessage},
    helpers::network::service::NetworkSender,
    model::common::{emit_fail, node::try_to_update},
};

use super::request::EvaluationReq;

#[derive(Clone, Debug)]
pub struct EvaluationSchema {
    pub our_key: Arc<PublicKey>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub schema_id: SchemaType,
    pub sn: u64,
    pub creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
    pub init_state: ValueWrapper,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
}

#[derive(Debug, Clone)]
pub enum EvaluationSchemaMessage {
    NetworkRequest {
        evaluation_req: Box<Signed<EvaluationReq>>,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    Update {
        creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
        sn: u64,
        gov_version: u64,
        init_state: ValueWrapper,
    },
}

impl Message for EvaluationSchemaMessage {}

impl NotPersistentActor for EvaluationSchema {}

#[async_trait]
impl Actor for EvaluationSchema {
    type Event = ();
    type Message = EvaluationSchemaMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "EvaluationSchema", id)
        } else {
            info_span!("EvaluationSchema", id)
        }
    }
}

#[async_trait]
impl Handler<Self> for EvaluationSchema {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: EvaluationSchemaMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            EvaluationSchemaMessage::NetworkRequest {
                evaluation_req,
                info,
                sender,
            } => {
                if sender != evaluation_req.signature().signer {
                    warn!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        signer = %evaluation_req.signature().signer,
                        "Signer and sender are not the same"
                    );
                    return Ok(());
                }

                if self.governance_id != evaluation_req.content().governance_id
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_governance_id = %self.governance_id,
                        received_governance_id = %evaluation_req.content().governance_id,
                        "Invalid governance_id"
                    );
                    return Ok(());
                }

                if self.schema_id != evaluation_req.content().schema_id {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_schema_id = ?self.schema_id,
                        received_schema_id = ?evaluation_req.content().schema_id,
                        "Invalid schema_id"
                    );
                    return Ok(());
                }

                if let Some(ns) = self.creators.get(&sender) {
                    if !ns.contains(&evaluation_req.content().namespace) {
                        warn!(
                            msg_type = "NetworkRequest",
                            sender = %sender,
                            namespace = ?evaluation_req.content().namespace,
                            "Invalid sender namespace"
                        );
                        return Ok(());
                    }
                } else {
                    warn!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        "Sender is not a creator"
                    );
                    return Ok(());
                }

                if self.gov_version < evaluation_req.content().gov_version
                    && let Err(e) =
                        try_to_update(ctx, self.governance_id.clone(), None)
                            .await
                {
                    error!(
                        msg_type = "NetworkRequest",
                        error = %e,
                        "Failed to update governance"
                    );
                    return Err(emit_fail(ctx, e).await);
                }

                let child = ctx
                    .create_child(
                        &format!("{}", evaluation_req.signature().signer),
                        EvalWorker {
                            node_key: sender.clone(),
                            our_key: self.our_key.clone(),
                            init_state: Some(self.init_state.clone()),
                            governance_id: self.governance_id.clone(),
                            gov_version: self.gov_version,
                            sn: self.sn,
                            hash: self.hash,
                            network: self.network.clone(),
                            stop: true,
                        },
                    )
                    .await;

                let evaluator_actor = match child {
                    Ok(child) => child,
                    Err(e) => {
                        if let ActorError::Exists { .. } = e {
                            warn!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Evaluator actor already exists"
                            );
                            return Ok(());
                        } else {
                            error!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Failed to create evaluator actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                if let Err(e) = evaluator_actor
                    .tell(EvalWorkerMessage::NetworkRequest {
                        evaluation_req: *evaluation_req,
                        info,
                        sender: sender.clone(),
                    })
                    .await
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        error = %e,
                        "Failed to send request to evaluator"
                    );
                } else {
                    debug!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        "Evaluation request delegated to worker"
                    );
                }
            }
            EvaluationSchemaMessage::Update {
                creators,
                sn,
                gov_version,
                init_state,
            } => {
                self.creators = creators;
                self.gov_version = gov_version;
                self.sn = sn;
                self.init_state = init_state;

                debug!(
                    msg_type = "Update",
                    sn = self.sn,
                    gov_version = self.gov_version,
                    "Schema updated successfully"
                );
            }
        };
        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ave_actors::ChildAction {
        error!(
            governance_id = %self.governance_id,
            schema_id = ?self.schema_id,
            gov_version = self.gov_version,
            sn = self.sn,
            error = %error,
            "Child fault in evaluation schema actor"
        );
        emit_fail(ctx, error).await;
        ave_actors::ChildAction::Stop
    }
}
