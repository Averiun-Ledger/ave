//! # Evaluation module.
//! This module contains the evaluation logic for the Ave protocol.
//!
use crate::{
    evaluation::{
        coordinator::{EvalCoordinator, EvalCoordinatorMessage},
        worker::{EvalWorker, EvalWorkerMessage},
        response::{EvaluatorError, ResponseSummary},
    },
    governance::model::Quorum,
    helpers::network::service::NetworkSender,
    model::{
        common::{emit_fail, send_reboot_to_req, take_random_signers},
        event::{EvaluationData, EvaluationResponse},
    },
    request::manager::{RequestManager, RequestManagerMessage},
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::{
    ValueWrapper,
    identity::{
        CryptoError, DigestIdentifier, HashAlgorithm, PublicKey, Signature,
        Signed, hash_borsh,
    },
};

use request::EvaluationReq;
use response::{EvaluationRes, EvaluatorResponse as EvalRes};

use tracing::{Span, debug, error, info_span, warn};

pub mod compiler;
pub mod coordinator;
pub mod worker;
pub mod request;
pub mod response;
pub mod runner;
pub mod schema;

use std::{collections::HashSet, sync::Arc};
pub struct Evaluation {
    our_key: Arc<PublicKey>,
    // Quorum
    quorum: Quorum,
    // Actual responses
    evaluators_response: Vec<EvalRes>,
    // Evaluators quantity
    evaluators_quantity: u32,

    evaluators_signatures: Vec<Signature>,

    request: Signed<EvaluationReq>,

    hash: HashAlgorithm,

    network: Arc<NetworkSender>,

    request_id: String,

    version: u64,

    errors: Vec<EvaluatorError>,

    evaluation_request_hash: DigestIdentifier,

    reboot: bool,

    current_evaluators: HashSet<PublicKey>,

    pending_evaluators: HashSet<PublicKey>,

    init_state: Option<ValueWrapper>,
}

impl Evaluation {
    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<EvaluationReq>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Evaluation {
            our_key,
            hash,
            network,
            request,
            quorum,
            init_state,
            current_evaluators: HashSet::new(),
            errors: vec![],
            evaluation_request_hash: DigestIdentifier::default(),
            evaluators_quantity: 0,
            evaluators_response: vec![],
            evaluators_signatures: vec![],
            pending_evaluators: HashSet::new(),
            reboot: false,
            request_id: String::default(),
            version: 0,
        }
    }

    async fn end_evaluators(
        &self,
        ctx: &mut ActorContext<Evaluation>,
    ) -> Result<(), ActorError> {
        for evaluator in self.current_evaluators.clone() {
            if evaluator == *self.our_key {
                let child: Option<ActorRef<EvalWorker>> =
                    ctx.get_child(&evaluator.to_string()).await;
                if let Some(child) = child {
                    child.ask_stop().await?;
                }
            } else {
                let child: Option<ActorRef<EvalCoordinator>> =
                    ctx.get_child(&evaluator.to_string()).await;
                if let Some(child) = child {
                    child.ask_stop().await?;
                }
            }
        }

        Ok(())
    }

    fn check_evaluator(&mut self, evaluator: PublicKey) -> bool {
        self.current_evaluators.remove(&evaluator)
    }

    async fn create_evaluators(
        &self,
        ctx: &mut ActorContext<Evaluation>,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        if signer != *self.our_key {
            let child = ctx
                .create_child(
                    &format!("{}", signer),
                    EvalCoordinator::new(
                        signer.clone(),
                        self.request_id.to_string(),
                        self.version,
                        self.network.clone(),
                    ),
                )
                .await?;

            child
                .tell(EvalCoordinatorMessage::NetworkEvaluation {
                    evaluation_req: self.request.clone(),
                    node_key: signer,
                })
                .await?
        } else {
            let child = ctx
                .create_child(
                    &format!("{}", signer),
                    EvalWorker {
                        init_state: self.init_state.clone(),
                        node_key: (*self.our_key).clone(),
                        our_key: self.our_key.clone(),
                        governance_id: self
                            .request
                            .content()
                            .governance_id
                            .clone(),
                        gov_version: self.request.content().gov_version,
                        sn: self.request.content().sn,
                        hash: self.hash,
                        network: self.network.clone(),
                    },
                )
                .await?;

            child
                .tell(EvalWorkerMessage::LocalEvaluation {
                    evaluation_req: self.request.clone(),
                })
                .await?
        }

        Ok(())
    }

    fn check_responses(&self) -> ResponseSummary {
        let res_set: HashSet<EvalRes> =
            HashSet::from_iter(self.evaluators_response.iter().cloned());
        let error_set: HashSet<EvaluatorError> =
            HashSet::from_iter(self.errors.iter().cloned());

        if res_set.len() == 1 && error_set.is_empty() {
            ResponseSummary::Ok
        } else if error_set.len() == 1 && res_set.is_empty() {
            ResponseSummary::Error
        } else {
            ResponseSummary::Reboot
        }
    }

    fn build_evaluation_data(
        &self,
        is_ok: bool,
    ) -> Result<EvaluationData, ActorError> {
        if is_ok {
            Ok(EvaluationData {
                eval_req_signature: self.request.signature().clone(),
                eval_req_hash: self.evaluation_request_hash.clone(),
                evaluators_signatures: self.evaluators_signatures.clone(),
                response: EvaluationResponse::Ok(
                    self.evaluators_response[0].clone(),
                ),
            })
        } else {
            Ok(EvaluationData {
                eval_req_signature: self.request.signature().clone(),
                eval_req_hash: self.evaluation_request_hash.clone(),
                evaluators_signatures: self.evaluators_signatures.clone(),
                response: EvaluationResponse::Error(self.errors[0].clone()),
            })
        }
    }

    async fn send_evaluation_to_req(
        &self,
        ctx: &mut ActorContext<Evaluation>,
        response: EvaluationData,
    ) -> Result<(), ActorError> {
        let req_path =
            ActorPath::from(format!("/user/request/{}", self.request_id));
        let req_actor: Option<ActorRef<RequestManager>> =
            ctx.system().get_actor(&req_path).await;

        if let Some(req_actor) = req_actor {
            req_actor
                .tell(RequestManagerMessage::EvaluationRes {
                    eval_req: self.request.content().clone(),
                    eval_res: response,
                })
                .await?;
        } else {
            return Err(ActorError::NotFound { path: req_path });
        };

        Ok(())
    }

    fn create_eval_req_hash(&self) -> Result<DigestIdentifier, CryptoError> {
        hash_borsh(&*self.hash.hasher(), &self.request)
    }
}

#[derive(Debug, Clone)]
pub enum EvaluationMessage {
    Create {
        request_id: String,
        version: u64,
        signers: HashSet<PublicKey>,
    },
    Response {
        evaluation_res: EvaluationRes,
        sender: PublicKey,
        signature: Option<Signature>,
    },
}

impl Message for EvaluationMessage {}

impl NotPersistentActor for Evaluation {}

#[async_trait]
impl Actor for Evaluation {
    type Event = ();
    type Message = EvaluationMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Evaluation", id = id)
        } else {
            info_span!("Evaluation", id = id)
        }
    }
}

#[async_trait]
impl Handler<Evaluation> for Evaluation {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: EvaluationMessage,
        ctx: &mut ActorContext<Evaluation>,
    ) -> Result<(), ActorError> {
        match msg {
            EvaluationMessage::Create {
                request_id,
                version,
                signers,
            } => {
                let eval_req_hash = match self.create_eval_req_hash() {
                    Ok(digest) => digest,
                    Err(e) => {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to create evaluation request hash"
                        );
                        return Err(emit_fail(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!("Cannot create evaluation request hash: {}", e)
                            },
                        )
                        .await);
                    }
                };

                self.evaluation_request_hash = eval_req_hash;
                self.evaluators_quantity = signers.len() as u32;
                self.request_id = request_id.to_string();
                self.version = version;

                let evaluators_quantity = self.quorum.get_signers(
                    self.evaluators_quantity,
                    signers.len() as u32,
                );

                let (current_eval, pending_eval) =
                    take_random_signers(signers, evaluators_quantity as usize);
                self.current_evaluators.clone_from(&current_eval);
                self.pending_evaluators.clone_from(&pending_eval);

                for signer in current_eval.clone() {
                    if let Err(e) =
                        self.create_evaluators(ctx, signer.clone()).await
                    {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            signer = %signer,
                            "Failed to create evaluator"
                        );
                    }
                }

                debug!(
                    msg_type = "Create",
                    request_id = %request_id,
                    version = version,
                    evaluators_count = current_eval.len(),
                    "Evaluation created and evaluators initialized"
                );
            }
            EvaluationMessage::Response {
                evaluation_res,
                sender,
                signature,
            } => {
                if !self.reboot {
                    // If node is in evaluator list
                    if self.check_evaluator(sender.clone()) {
                        // Check type of validation
                        match evaluation_res {
                            EvaluationRes::Response {
                                response,
                                eval_req_hash,
                                ..
                            } => {
                                let Some(signature) = signature else {
                                    error!(
                                        msg_type = "Response",
                                        sender = %sender,
                                        "Evaluation response without signature"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Evaluation Response solver without signature".to_owned(),
                                    });
                                };

                                if eval_req_hash != self.evaluation_request_hash
                                {
                                    error!(
                                        msg_type = "Response",
                                        expected_hash = %self.evaluation_request_hash,
                                        received_hash = %eval_req_hash,
                                        "Invalid evaluation request hash"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Evaluation Response, Invalid evaluation request hash".to_owned(),
                                    });
                                }

                                self.evaluators_signatures.push(signature);
                                self.evaluators_response.push(response);
                            }
                            EvaluationRes::TimeOut => {
                                // Do nothing
                            }
                            EvaluationRes::Abort(error) => {
                                todo!("Me dijeron que abortara")
                            }
                            EvaluationRes::Error {
                                error,
                                eval_req_hash,
                                ..
                            } => {
                                if let Some(signature) = signature {
                                    self.evaluators_signatures.push(signature);
                                } else {
                                    error!(
                                        msg_type = "Response",
                                        sender = %sender,
                                        "Evaluation error without signature"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Evaluation Error solver without signature".to_owned(),
                                    });
                                }

                                if eval_req_hash != self.evaluation_request_hash
                                {
                                    error!(
                                        msg_type = "Response",
                                        expected_hash = %self.evaluation_request_hash,
                                        received_hash = %eval_req_hash,
                                        "Invalid evaluation request hash"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Evaluation Response, Invalid evaluation request hash".to_owned(),
                                    });
                                }
                                self.errors.push(error);
                            }
                            EvaluationRes::Reboot => {
                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    &self.request_id,
                                    self.request
                                        .content()
                                        .governance_id
                                        .clone(),
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }

                                self.reboot = true;

                                if let Err(e) = self.end_evaluators(ctx).await {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to end evaluators"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                                debug!(
                                    msg_type = "Response",
                                    request_id = %self.request_id,
                                    "Reboot requested, evaluators stopped"
                                );

                                ctx.stop(None).await;
                                return Ok(());
                            }
                        };

                        if self.quorum.check_quorum(
                            self.evaluators_quantity,
                            self.evaluators_response.len() as u32,
                        ) {
                            let summary = self.check_responses();
                            if let ResponseSummary::Reboot = summary {
                                todo!(
                                    "Respuestas diferentes, hay que hacer reboot, pero no tengo por qué actualizar la gov"
                                )
                            }

                            let response = match self
                                .build_evaluation_data(summary.is_ok())
                            {
                                Ok(response) => response,
                                Err(e) => {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to create evaluation response"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };

                            if let Err(e) =
                                self.send_evaluation_to_req(ctx, response.clone()).await
                            {
                                error!(
                                    msg_type = "Response",
                                    error = %e,
                                    "Failed to send evaluation to request actor"
                                );
                                return Err(emit_fail(ctx, e).await);
                            };

                            debug!(
                                msg_type = "Response",
                                request_id = %self.request_id,
                                version = self.version,
                                is_ok = summary.is_ok(),
                                "Evaluation completed and sent to request"
                            );

                            ctx.stop(None).await;
                        } else if self.current_evaluators.is_empty()
                            && !self.pending_evaluators.is_empty()
                        {
                            let evaluators_quantity = self.quorum.get_signers(
                                self.evaluators_quantity,
                                self.pending_evaluators.len() as u32,
                            );

                            let (current_eval, pending_eval) =
                                take_random_signers(
                                    self.pending_evaluators.clone(),
                                    evaluators_quantity as usize,
                                );
                            self.current_evaluators.clone_from(&current_eval);
                            self.pending_evaluators.clone_from(&pending_eval);

                            for signer in current_eval.clone() {
                                if let Err(e) = self
                                    .create_evaluators(ctx, signer.clone())
                                    .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        signer = %signer,
                                        "Failed to create evaluator from pending pool"
                                    );
                                }
                            }

                            debug!(
                                msg_type = "Response",
                                new_evaluators = current_eval.len(),
                                "Created additional evaluators from pending pool"
                            );
                        } else if self.current_evaluators.is_empty() {
                            todo!(
                                "Reboot, no tengo el quorum, hay que actualizar la governance y reintentarlo"
                            );
                        }
                    } else {
                        warn!(
                            msg_type = "Response",
                            sender = %sender,
                            "Response from unexpected sender"
                        );
                    }
                }
            }
        }

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Evaluation>,
    ) -> ChildAction {
        error!(error = %error, "Child fault occurred");
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[cfg(test)]
mod tests {
    use std::{str::FromStr, time::Duration};

    use ave_actors::{ActorPath, ActorRef, SystemRef};
    use ave_common::{
        RequestState, ValueWrapper,
        identity::{
            Blake3Hasher, DigestIdentifier, KeyPair, KeyPairAlgorithm, Signed,
            hash_borsh,
        },
    };
    use serde_json::json;
    use tempfile::TempDir;
    use test_log::test;

    use crate::{
        EventRequest, FactRequest, NodeMessage, NodeResponse,
        approval::approver::ApprovalStateRes,
        governance::{
            Governance, GovernanceMessage, GovernanceResponse,
            data::GovernanceData,
        },
        model::{
            Namespace, SignTypesNode,
            event::LedgerValue,
            request::{SchemaType, TransferRequest},
        },
        node::Node,
        query::{Query, QueryMessage, QueryResponse},
        request::{
            RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
            tracking::{
                RequestTracking, RequestTrackingMessage,
                RequestTrackingResponse,
            },
        },
        subject::laststate::{LastState, LastStateMessage, LastStateResponse},
        tracker::{Tracker, TrackerMessage, TrackerResponse},
        validation::tests::create_subject_gov,
    };

    #[test(tokio::test)]
    async fn test_fact_gov() {
        let (
            _system,
            node_actor,
            request_actor,
            query_actor,
            subject_actor,
            last_state_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_subject_gov().await;

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(json!({
                "members": {
                    "add": [
                        {
                            "name": "AveNode1",
                            "key": "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                        }
                    ]
                }
            })),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                fact_request.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(fact_request, signature);

        let RequestHandlerResponse::Ok(request_id) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(1)).await;

        let RequestTrackingResponse::Info(state) = tracking
            .ask(RequestTrackingMessage::SearchRequest(
                request_id.request_id.clone(),
            ))
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(RequestState::Approval, state.state);
        let QueryResponse::ApprovalState(data) = query_actor
            .ask(QueryMessage::GetApproval {
                subject_id: subject_id.to_string(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(data.state, "Pending");

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.to_string(),
                state: ApprovalStateRes::RespondedAccepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to RespondedAccepted",
                subject_id.to_string()
            )
        );

        tokio::time::sleep(Duration::from_secs(1)).await;
        let QueryResponse::ApprovalState(data) = query_actor
            .ask(QueryMessage::GetApproval {
                subject_id: subject_id.to_string(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(data.state, "RespondedAccepted");

        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(event.content().subject_id, subject_id);
        assert_eq!(event.content().event_request, signed_event_req);
        assert_eq!(event.content().sn, 1);
        assert_eq!(event.content().gov_version, 0);
        assert_eq!(
            event.content().value,
            LedgerValue::Patch(ValueWrapper(json!([
                {"op":"add","path":"/members/AveNode1","value":"EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"}])))
        );
        assert!(event.content().eval_success.unwrap());
        assert!(event.content().appr_required);
        assert!(event.content().appr_success.unwrap());
        assert!(event.content().vali_success);
        assert!(!event.content().evaluators.unwrap().is_empty());
        assert!(!event.content().approvers.unwrap().is_empty());
        assert!(!event.content().validators.is_empty());

        assert_eq!(metadata.subject_id, subject_id);
        assert_eq!(metadata.governance_id.to_string(), "");
        assert_eq!(metadata.name.unwrap(), "Name");
        assert_eq!(metadata.description.unwrap(), "Description");
        assert_eq!(metadata.genesis_gov_version, 0);
        assert_eq!(metadata.schema_id.to_string(), "governance");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 1);
        assert!(metadata.active);

        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);
        // TODO MEJORAR
        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());
    }

    #[test(tokio::test)]
    async fn test_transfer_req() {
        let (
            _system,
            node_actor,
            request_actor,
            _query_actor,
            subject_actor,
            last_state_actor,
            _tracking,
            subject_id,
            _dir,
        ) = create_subject_gov().await;

        let new_owner = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(json!({
                "members": {
                    "add": [
                        {
                            "name": "TestMember",
                            "key": new_owner.public_key().to_string()
                        }
                    ]
                }
            })),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                fact_request.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(fact_request, signature);

        let RequestHandlerResponse::Ok(_request_id) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(9)).await;

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.to_string(),
                state: ApprovalStateRes::RespondedAccepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to RespondedAccepted",
                subject_id.to_string()
            )
        );

        let transfer_reques = EventRequest::Transfer(TransferRequest {
            subject_id: subject_id.clone(),
            new_owner: new_owner.public_key().clone(),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                transfer_reques.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(transfer_reques, signature);

        let RequestHandlerResponse::Ok(_response) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(10)).await;

        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(event.content().subject_id, subject_id);
        assert_eq!(event.content().event_request, signed_event_req);
        assert_eq!(event.content().sn, 2);
        assert_eq!(event.content().gov_version, 1);
        assert_eq!(
            event.content().value,
            LedgerValue::Patch(ValueWrapper(serde_json::Value::String(
                "[]".to_owned(),
            ),))
        );
        assert!(event.content().eval_success.unwrap());
        assert!(!event.content().appr_required);
        assert!(event.content().appr_success.is_none());
        assert!(event.content().vali_success);
        assert!(!event.content().evaluators.unwrap().is_empty());
        assert!(event.content().approvers.is_none(),);
        assert!(!event.content().validators.is_empty());

        assert_eq!(metadata.subject_id, subject_id);
        assert_eq!(metadata.governance_id.to_string(), "");
        assert_eq!(metadata.genesis_gov_version, 0);
        assert_eq!(metadata.name.unwrap(), "Name");
        assert_eq!(metadata.description.unwrap(), "Description");
        assert_eq!(metadata.schema_id.to_string(), "governance");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 2);
        assert_eq!(metadata.new_owner.unwrap(), new_owner.public_key());
        assert!(metadata.active);

        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 2);
        // TODO MEJORAR
        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());

        if !request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .is_err()
        {
            panic!("Invalid response")
        }
    }

    async fn init_gov_sub() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        ActorRef<Query>,
        ActorRef<Governance>,
        ActorRef<LastState>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let (
            system,
            node_actor,
            request_actor,
            query_actor,
            subject_actor,
            last_state_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_subject_gov().await;

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(json!({
                "schemas": {
                    "add": [
                        {
                            "id": "Example",
                            "contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==",
                            "initial_value": {
                                "one": 0,
                                "two": 0,
                                "three": 0
                            }
                        }
                    ]
                },
                "roles": {
                    "all_schemas": {
                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "validator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "witness": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                        }
                    },
                    "schema":
                        [
                        {
                            "schema_id": "Example",
                                "add": {
                                    "creator": [
                                        {
                                            "name": "Owner",
                                            "namespace": [],
                                            "quantity": 2
                                        }
                                    ],
                                    "issuer": [
                                        {
                                            "name": "Owner",
                                            "namespace": [],
                                        }
                                    ]
                                }
                        }
                    ]
                }
            })),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                fact_request.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(fact_request, signature);

        let RequestHandlerResponse::Ok(request_id) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(9)).await;

        let RequestTrackingResponse::Info(_state) = tracking
            .ask(RequestTrackingMessage::SearchRequest(
                request_id.request_id.clone(),
            ))
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(3)).await;

        let QueryResponse::ApprovalState(data) = query_actor
            .ask(QueryMessage::GetApproval {
                subject_id: subject_id.to_string(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(data.state, "Pending");

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.to_string(),
                state: ApprovalStateRes::RespondedAccepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to RespondedAccepted",
                subject_id.to_string()
            )
        );

        tokio::time::sleep(Duration::from_secs(1)).await;
        let QueryResponse::ApprovalState(data) = query_actor
            .ask(QueryMessage::GetApproval {
                subject_id: subject_id.to_string(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(data.state, "RespondedAccepted");

        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(event.content().subject_id, subject_id);
        assert_eq!(event.content().event_request, signed_event_req);
        assert_eq!(event.content().sn, 1);
        assert_eq!(event.content().gov_version, 0);

        assert_eq!(
            event.content().value,
            LedgerValue::Patch(ValueWrapper(
                json!([{"op":"add","path":"/policies_schema/Example","value":{"evaluate":"majority","validate":"majority"}},{"op":"add","path":"/roles_all_schemas/evaluator/0","value":{"name":"Owner","namespace":[]}},{"op":"add","path":"/roles_all_schemas/validator/0","value":{"name":"Owner","namespace":[]}},{"op":"add","path":"/roles_all_schemas/witness/0","value":{"name":"Owner","namespace":[]}},{"op":"add","path":"/roles_schema/Example","value":{"creator":[{"name":"Owner","namespace":[],"quantity":2,"witnesses":["Witnesses"]}],"evaluator":[],"issuer":{"any":false,"users":[{"name":"Owner","namespace":[]}]},"validator":[],"witness":[]}},{"op":"add","path":"/schemas/Example","value":{"contract":"dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==","initial_value":{"one":0,"three":0,"two":0}}}])
            ))
        );
        assert!(event.content().eval_success.unwrap());
        assert!(event.content().appr_required);
        assert!(event.content().appr_success.unwrap());
        assert!(event.content().vali_success);
        assert!(!event.content().evaluators.unwrap().is_empty());
        assert!(!event.content().approvers.unwrap().is_empty());
        assert!(!event.content().validators.is_empty());

        assert_eq!(metadata.subject_id, subject_id);
        assert_eq!(metadata.governance_id.to_string(), "");
        assert_eq!(metadata.genesis_gov_version, 0);
        assert_eq!(metadata.name.unwrap(), "Name");
        assert_eq!(metadata.description.unwrap(), "Description");
        assert_eq!(metadata.schema_id.to_string(), "governance");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 1);
        assert!(metadata.active);

        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);
        // TODO MEJORAR
        assert!(!gov.members.is_empty());
        assert!(!gov.roles_schema.is_empty());
        assert!(!gov.schemas.is_empty());
        assert!(!gov.policies_schema.is_empty());

        (
            system,
            node_actor,
            request_actor,
            query_actor,
            subject_actor,
            last_state_actor,
            tracking,
            subject_id,
            _dir,
        )
    }

    #[test(tokio::test)]
    async fn test_fact_sub() {
        init_gov_sub().await;
    }

    async fn create_subject() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        ActorRef<Query>,
        ActorRef<Tracker>,
        ActorRef<LastState>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let (
            system,
            node_actor,
            request_actor,
            query_actor,
            _subject_actor,
            _last_state_actor,
            tracking,
            gov_id,
            _dir,
        ) = init_gov_sub().await;

        let create_request = EventRequest::Create(crate::CreateRequest {
            name: Some("Subject Name".to_owned()),
            description: Some("Subject Description".to_owned()),
            governance_id: gov_id.clone(),
            schema_id: SchemaType::Type("Example".to_owned()),
            namespace: Namespace::new(),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                create_request.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(create_request, signature);

        let RequestHandlerResponse::Ok(request_id) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(1)).await;

        let RequestTrackingResponse::Info(state) = tracking
            .ask(RequestTrackingMessage::SearchRequest(
                request_id.request_id.clone(),
            ))
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(RequestState::Finish, state.state);

        let last_state_actor: ActorRef<LastState> = system
            .get_actor(&ActorPath::from(format!(
                "/user/node/{}/last_state",
                request_id.subject_id
            )))
            .await
            .unwrap();

        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_actor: ActorRef<Tracker> = system
            .get_actor(&ActorPath::from(format!(
                "/user/node/{}",
                request_id.subject_id
            )))
            .await
            .unwrap();

        let TrackerResponse::Metadata(metadata) = subject_actor
            .ask(TrackerMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            event.content().subject_id.to_string(),
            request_id.subject_id
        );
        assert_eq!(event.content().event_request, signed_event_req);
        assert_eq!(event.content().sn, 0);
        assert_eq!(event.content().gov_version, 1);
        assert_eq!(
            event.content().value,
            LedgerValue::Patch(ValueWrapper(json!({
                "one": 0, "three": 0, "two": 0
            })))
        );

        assert_eq!(
            event.content().state_hash,
            hash_borsh(&Blake3Hasher, &metadata.properties).unwrap()
        );
        assert!(event.content().eval_success.is_none());
        assert!(!event.content().appr_required);
        assert!(event.content().appr_success.is_none());
        assert!(event.content().vali_success);
        assert_eq!(
            event.content().hash_prev_event,
            DigestIdentifier::default()
        );
        assert!(event.content().evaluators.is_none());
        assert!(event.content().approvers.is_none(),);
        assert!(!event.content().validators.is_empty());

        assert_eq!(metadata.subject_id.to_string(), request_id.subject_id);
        assert_eq!(metadata.governance_id.to_string(), gov_id.to_string());
        assert_eq!(metadata.name.unwrap(), "Subject Name");
        assert_eq!(metadata.description.unwrap(), "Subject Description");
        assert_eq!(metadata.genesis_gov_version, 1);
        assert_eq!(metadata.schema_id.to_string(), "Example");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 0);
        assert!(metadata.active);

        (
            system,
            node_actor,
            request_actor,
            query_actor,
            subject_actor,
            last_state_actor,
            tracking,
            DigestIdentifier::from_str(&request_id.subject_id).unwrap(),
            _dir,
        )
    }

    #[test(tokio::test)]
    async fn test_create_subject() {
        let _ = create_subject().await;
    }

    #[test(tokio::test)]
    async fn test_subject_events() {
        let (
            _system,
            node_actor,
            request_actor,
            _query_actor,
            subject_actor,
            last_state_actor,
            _tracking,
            subject_id,
            _dir,
        ) = create_subject().await;

        let fact_request = EventRequest::Fact(crate::FactRequest {
            subject_id,
            payload: ValueWrapper(json!({
                "ModOne": {
                    "data": 100
                }
            })),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                fact_request.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(fact_request, signature);

        let RequestHandlerResponse::Ok(request_id) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(1)).await;
        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let TrackerResponse::Metadata(metadata) = subject_actor
            .ask(TrackerMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            event.content().subject_id.to_string(),
            request_id.subject_id
        );
        assert_eq!(event.content().event_request, signed_event_req);
        assert_eq!(event.content().sn, 1);
        assert_eq!(event.content().gov_version, 1);
        assert_eq!(
            event.content().state_hash,
            hash_borsh(&Blake3Hasher, &metadata.properties).unwrap()
        );
        assert!(event.content().eval_success.unwrap());
        assert!(!event.content().appr_required);
        assert!(event.content().appr_success.is_none());
        assert!(event.content().vali_success);
        assert!(!event.content().evaluators.unwrap().is_empty());
        assert!(event.content().approvers.is_none(),);
        assert!(!event.content().validators.is_empty());

        assert_eq!(metadata.subject_id.to_string(), request_id.subject_id);
        assert_eq!(metadata.genesis_gov_version, 1);
        assert_eq!(metadata.name.unwrap(), "Subject Name");
        assert_eq!(metadata.description.unwrap(), "Subject Description");
        assert_eq!(metadata.schema_id.to_string(), "Example");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 1);
        assert!(metadata.active);
        assert!(metadata.properties.0["one"].as_u64().unwrap() == 100);
        assert!(metadata.properties.0["two"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["three"].as_u64().unwrap() == 0);
    }
}
