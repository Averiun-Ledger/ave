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
    request::EventRequest,
};
use ave_network::ComunicateInfo;
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    evaluation::worker::{EvalWorker, EvalWorkerMessage},
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::common::emit_fail,
};

use super::request::{EvalWorkerContext, EvaluationReq};

#[derive(Clone, Debug)]
pub struct EvaluationSchema {
    pub our_key: Arc<PublicKey>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub schema_id: SchemaType,
    pub sn: u64,
    pub members: BTreeSet<PublicKey>,
    pub creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
    pub issuers: BTreeMap<PublicKey, BTreeSet<Namespace>>,
    pub issuer_any: bool,
    pub schema_viewpoints: BTreeSet<String>,
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
        members: BTreeSet<PublicKey>,
        creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
        issuers: BTreeMap<PublicKey, BTreeSet<Namespace>>,
        issuer_any: bool,
        schema_viewpoints: BTreeSet<String>,
        sn: u64,
        gov_version: u64,
        init_state: ValueWrapper,
    },
}

impl Message for EvaluationSchemaMessage {}

impl NotPersistentActor for EvaluationSchema {}

impl EvaluationSchema {
    fn context_for_request(
        &self,
        evaluation_req: &EvaluationReq,
    ) -> EvalWorkerContext {
        match evaluation_req.event_request.content() {
            EventRequest::Fact(_) => EvalWorkerContext::TrackerFact {
                issuers: self
                    .issuers
                    .iter()
                    .filter(|(_, namespaces)| {
                        namespaces.iter().any(|issuer_namespace| {
                            issuer_namespace
                                .is_ancestor_or_equal_of(&evaluation_req.namespace)
                        })
                    })
                    .map(|(issuer, _)| issuer.clone())
                    .collect(),
                issuer_any: self.issuer_any,
                schema_viewpoints: self.schema_viewpoints.clone(),
            },
            EventRequest::Transfer(_) => EvalWorkerContext::TrackerTransfer {
                members: self.members.clone(),
                creators: self.creators.clone(),
            },
            _ => EvalWorkerContext::Empty,
        }
    }
}

#[async_trait]
impl Actor for EvaluationSchema {
    type Event = ();
    type Message = EvaluationSchemaMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("EvaluationSchema", id),
            |parent_span| info_span!(parent: parent_span, "EvaluationSchema", id),
        )
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
                let observe = |result: &'static str| {
                    if let Some(metrics) = try_core_metrics() {
                        metrics
                            .observe_schema_event("evaluation_schema", result);
                    }
                };
                if sender != evaluation_req.signature().signer {
                    observe("rejected");
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
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_governance_id = %self.governance_id,
                        received_governance_id = %evaluation_req.content().governance_id,
                        "Invalid governance_id"
                    );
                    return Ok(());
                }

                if self.schema_id != evaluation_req.content().schema_id {
                    observe("rejected");
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
                        observe("rejected");
                        warn!(
                            msg_type = "NetworkRequest",
                            sender = %sender,
                            namespace = ?evaluation_req.content().namespace,
                            "Invalid sender namespace"
                        );
                        return Ok(());
                    }
                } else {
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        "Sender is not a creator"
                    );
                    return Ok(());
                }

                if self.gov_version < evaluation_req.content().gov_version {
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        local_gov_version = self.gov_version,
                        request_gov_version = evaluation_req.content().gov_version,
                        governance_id = %self.governance_id,
                        sender = %sender,
                        "Ignoring request with newer governance version; service nodes must update governance through resilience protocols"
                    );
                    return Ok(());
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
                            context: self
                                .context_for_request(evaluation_req.content()),
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
                            observe("rejected");
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
                    observe("delegated");
                    debug!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        "Evaluation request delegated to worker"
                    );
                }
            }
            EvaluationSchemaMessage::Update {
                members,
                creators,
                issuers,
                issuer_any,
                schema_viewpoints,
                sn,
                gov_version,
                init_state,
            } => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_schema_event("evaluation_schema", "update");
                }
                self.members = members;
                self.creators = creators;
                self.issuers = issuers;
                self.issuer_any = issuer_any;
                self.schema_viewpoints = schema_viewpoints;
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
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_schema_event("evaluation_schema", "child_fault");
        }
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
