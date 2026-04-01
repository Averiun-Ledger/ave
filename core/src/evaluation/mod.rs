//! # Evaluation module.
//! This module contains the evaluation logic for the Ave protocol.
//!
use crate::{
    evaluation::{
        coordinator::{EvalCoordinator, EvalCoordinatorMessage},
        response::{EvaluatorError, ResponseSummary},
        worker::{EvalWorker, EvalWorkerMessage},
    },
    governance::model::Quorum,
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::{
        common::{
            abort_req, emit_fail, send_reboot_to_req, take_random_signers,
        },
        event::{EvaluationData, EvaluationResponse},
    },
    request::manager::{RebootType, RequestManager, RequestManagerMessage},
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
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
pub mod request;
pub mod response;
pub mod runner;
pub mod schema;
pub mod worker;

use std::{collections::HashSet, sync::Arc};
pub struct Evaluation {
    our_key: Arc<PublicKey>,
    // Quorum
    quorum: Quorum,
    // Actual responses
    evaluators_response: Vec<(EvalRes, DigestIdentifier)>,
    // Evaluators quantity
    evaluators_quantity: u32,

    evaluators_signatures: Vec<Signature>,

    request: Signed<EvaluationReq>,

    hash: HashAlgorithm,

    network: Arc<NetworkSender>,

    request_id: DigestIdentifier,

    version: u64,

    errors: Vec<(EvaluatorError, DigestIdentifier)>,

    evaluation_request_hash: DigestIdentifier,

    reboot: bool,

    current_evaluators: HashSet<PublicKey>,

    pending_evaluators: HashSet<PublicKey>,

    init_state: Option<ValueWrapper>,
}

impl Evaluation {
    fn observe_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("evaluation", result);
        }
    }

    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<EvaluationReq>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
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
            request_id: DigestIdentifier::default(),
            version: 0,
        }
    }

    fn check_evaluator(&mut self, evaluator: PublicKey) -> bool {
        self.current_evaluators.remove(&evaluator)
    }

    async fn create_evaluators(
        &self,
        ctx: &mut ActorContext<Self>,
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
                        self.hash,
                    ),
                )
                .await?;

            child
                .tell(EvalCoordinatorMessage::NetworkEvaluation {
                    evaluation_req: Box::new(self.request.clone()),
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
                        stop: true,
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
        let res_set: HashSet<(EvalRes, DigestIdentifier)> =
            HashSet::from_iter(self.evaluators_response.iter().cloned());
        let error_set: HashSet<(EvaluatorError, DigestIdentifier)> =
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
                response: EvaluationResponse::Ok {
                    result: self.evaluators_response[0].0.clone(),
                    result_hash: self.evaluators_response[0].1.clone(),
                },
            })
        } else {
            Ok(EvaluationData {
                eval_req_signature: self.request.signature().clone(),
                eval_req_hash: self.evaluation_request_hash.clone(),
                evaluators_signatures: self.evaluators_signatures.clone(),
                response: EvaluationResponse::Error {
                    result: self.errors[0].0.clone(),
                    result_hash: self.errors[0].1.clone(),
                },
            })
        }
    }

    async fn send_evaluation_to_req(
        &self,
        ctx: &ActorContext<Self>,
        response: EvaluationData,
    ) -> Result<(), ActorError> {
        let req_actor = ctx.get_parent::<RequestManager>().await?;

        req_actor
            .tell(RequestManagerMessage::EvaluationRes {
                request_id: self.request_id.clone(),
                eval_req: Box::new(self.request.content().clone()),
                eval_res: response,
            })
            .await
    }

    fn create_eval_req_hash(&self) -> Result<DigestIdentifier, CryptoError> {
        hash_borsh(&*self.hash.hasher(), &self.request)
    }

    fn ensure_eval_req_hash(
        &self,
        eval_req_hash: DigestIdentifier,
    ) -> Result<(), ActorError> {
        if eval_req_hash != self.evaluation_request_hash {
            error!(
                msg_type = "Response",
                expected_hash = %self.evaluation_request_hash,
                received_hash = %eval_req_hash,
                "Invalid evaluation request hash"
            );
            return Err(ActorError::Functional {
                description:
                    "Evaluation Response, Invalid evaluation request hash"
                        .to_owned(),
            });
        }

        Ok(())
    }

    fn store_response_result(
        &mut self,
        result: response::EvaluationResult,
        result_hash: DigestIdentifier,
        result_hash_signature: Signature,
    ) -> Result<(), ActorError> {
        match result {
            response::EvaluationResult::Ok {
                response,
                eval_req_hash,
                ..
            } => {
                self.ensure_eval_req_hash(eval_req_hash)?;
                self.evaluators_response.push((response, result_hash));
            }
            response::EvaluationResult::Error {
                error,
                eval_req_hash,
                ..
            } => {
                self.ensure_eval_req_hash(eval_req_hash)?;
                self.errors.push((error, result_hash));
            }
        }

        self.evaluators_signatures.push(result_hash_signature);
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum EvaluationMessage {
    Create {
        request_id: DigestIdentifier,
        version: u64,
        signers: HashSet<PublicKey>,
    },
    Response {
        evaluation_res: EvaluationRes,
        sender: PublicKey,
    },
}

impl Message for EvaluationMessage {}

impl NotPersistentActor for Evaluation {}

#[async_trait]
impl Actor for Evaluation {
    type Event = ();
    type Message = EvaluationMessage;
    type Response = ();

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Evaluation"),
            |parent_span| info_span!(parent: parent_span, "Evaluation"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Evaluation {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: EvaluationMessage,
        ctx: &mut ActorContext<Self>,
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
                                description: format!(
                                    "Cannot create evaluation request hash: {}",
                                    e
                                ),
                            },
                        )
                        .await);
                    }
                };

                self.evaluation_request_hash = eval_req_hash;
                self.evaluators_quantity = signers.len() as u32;
                self.request_id = request_id.clone();
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
            } => {
                if !self.reboot {
                    // If node is in evaluator list
                    if self.check_evaluator(sender.clone()) {
                        // Check type of validation
                        match evaluation_res {
                            EvaluationRes::Response {
                                result,
                                result_hash,
                                result_hash_signature,
                            } => {
                                self.store_response_result(
                                    result,
                                    result_hash,
                                    result_hash_signature,
                                )?;
                            }
                            EvaluationRes::TimeOut => {
                                Self::observe_event("timeout");
                            }
                            EvaluationRes::Abort(error) => {
                                Self::observe_event("abort");
                                if let Err(e) = abort_req(
                                    ctx,
                                    self.request_id.clone(),
                                    sender.clone(),
                                    error.clone(),
                                    self.request.content().sn,
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        request_id = %self.request_id,
                                        sender = %sender,
                                        abort_reason = %error,
                                        error = %e,
                                        "Failed to abort request"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                                debug!(
                                    msg_type = "Response",
                                    request_id = %self.request_id,
                                    sender = %sender,
                                    abort_reason = %error,
                                    "Evaluation aborted"
                                );

                                return Ok(());
                            }
                            EvaluationRes::Reboot => {
                                Self::observe_event("reboot");
                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content()
                                        .governance_id
                                        .clone(),
                                    RebootType::Normal,
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

                                return Ok(());
                            }
                        };

                        if self.quorum.check_quorum(
                            self.evaluators_quantity,
                            (self.evaluators_response.len() + self.errors.len())
                                as u32,
                        ) {
                            let summary = self.check_responses();
                            if matches!(summary, ResponseSummary::Reboot)
                                && let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content()
                                        .governance_id
                                        .clone(),
                                    RebootType::Diff,
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
                            if matches!(summary, ResponseSummary::Reboot) {
                                Self::observe_event("reboot");
                                return Ok(());
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

                            if let Err(e) = self
                                .send_evaluation_to_req(ctx, response.clone())
                                .await
                            {
                                error!(
                                    msg_type = "Response",
                                    error = %e,
                                    "Failed to send evaluation to request actor"
                                );
                                return Err(emit_fail(ctx, e).await);
                            };

                            if !matches!(summary, ResponseSummary::Reboot) {
                                Self::observe_event(if summary.is_ok() {
                                    "success"
                                } else {
                                    "error"
                                });
                            }

                            debug!(
                                msg_type = "Response",
                                request_id = %self.request_id,
                                version = self.version,
                                is_ok = summary.is_ok(),
                                "Evaluation completed and sent to request"
                            );
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
                        } else if self.current_evaluators.is_empty()
                            && let Err(e) = send_reboot_to_req(
                                ctx,
                                self.request_id.clone(),
                                self.request.content().governance_id.clone(),
                                RebootType::TimeOut,
                            )
                            .await
                        {
                            error!(
                                msg_type = "Response",
                                error = %e,
                                "Failed to send reboot to request actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        } else if self.current_evaluators.is_empty() {
                            Self::observe_event("reboot");
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
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        Self::observe_event("error");
        error!(
            request_id = %self.request_id,
            version = self.version,
            error = %error,
            "Child fault in evaluation actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[cfg(test)]
pub mod tests {
    use std::{str::FromStr, sync::Arc, time::Duration};

    use ave_actors::{ActorError, ActorPath, ActorRef, SystemRef};
    use ave_common::{
        DataToSinkEvent, Namespace, SchemaType, ValueWrapper,
        bridge::request::{ApprovalState, ApprovalStateRes},
        identity::{DigestIdentifier, PublicKey, Signed},
        request::{CreateRequest, FactRequest, TransferRequest},
        response::{EvalResDB, RequestEventDB, RequestState},
    };
    use serde_json::json;
    use tempfile::TempDir;
    use test_log::test;

    use crate::{
        EventRequest, NodeMessage, NodeResponse,
        governance::{
            Governance, GovernanceMessage, GovernanceResponse,
            data::GovernanceData,
        },
        helpers::db::{ExternalDB, ReadStore},
        model::common::node::SignTypesNode,
        node::Node,
        node::subject_manager::{
            SubjectManager, SubjectManagerMessage, SubjectManagerResponse,
        },
        request::{
            RequestData, RequestHandler, RequestHandlerMessage,
            RequestHandlerResponse,
            tracking::{
                RequestTracking, RequestTrackingMessage,
                RequestTrackingResponse,
            },
        },
        subject::Metadata,
        tracker::{Tracker, TrackerMessage, TrackerResponse},
        validation::tests::create_gov,
    };

    async fn get_subject_state(
        db: &Arc<ExternalDB>,
        subject_id: &DigestIdentifier,
        expected_sn: u64,
    ) -> ave_common::response::SubjectDB {
        let started = tokio::time::Instant::now();
        loop {
            match db.get_subject_state(&subject_id.to_string()).await {
                Ok(state) if state.sn >= expected_sn => return state,
                Ok(_) | Err(_)
                    if started.elapsed() < Duration::from_secs(5) =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(state) => {
                    panic!(
                        "subject state not updated in time for {}: expected sn >= {}, got {}",
                        subject_id, expected_sn, state.sn
                    );
                }
                Err(error) => {
                    panic!(
                        "subject state not available in time for {}: {}",
                        subject_id, error
                    );
                }
            }
        }
    }

    async fn get_event_sn(
        db: &Arc<ExternalDB>,
        subject_id: &DigestIdentifier,
        sn: u64,
    ) -> ave_common::response::LedgerDB {
        let started = tokio::time::Instant::now();
        loop {
            match db.get_event_sn(&subject_id.to_string(), sn).await {
                Ok(event) => return event,
                Err(_) if started.elapsed() < Duration::from_secs(5) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    panic!(
                        "event {} for {} not available in time: {}",
                        sn, subject_id, error
                    );
                }
            }
        }
    }

    pub async fn emit_request(
        request: EventRequest,
        node_actor: &ActorRef<Node>,
        request_actor: &ActorRef<RequestHandler>,
        tracking_actor: &ActorRef<RequestTracking>,
        wait_request_state: bool,
    ) -> RequestData {
        let response = node_actor
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::EventRequest(request.clone()),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(request, signature);

        let RequestHandlerResponse::Ok(request_data) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        if wait_request_state {
            wait_request(tracking_actor, request_data.request_id.clone()).await;
        }

        request_data
    }

    pub async fn wait_request(
        tracking_actor: &ActorRef<RequestTracking>,
        request_id: DigestIdentifier,
    ) {
        loop {
            if let Ok(RequestTrackingResponse::Info(state)) = tracking_actor
                .ask(RequestTrackingMessage::SearchRequest(request_id.clone()))
                .await
            {
                match state.state {
                    RequestState::Approval
                    | RequestState::Abort { .. }
                    | RequestState::Invalid { .. }
                    | RequestState::Finish => break,
                    _ => {}
                }
            } else {
                tokio::time::sleep(Duration::from_secs(1)).await;
            };
        }
    }

    async fn get_sink_events(
        node_actor: &ActorRef<Node>,
        subject_id: &DigestIdentifier,
        from_sn: u64,
        to_sn: Option<u64>,
        limit: u64,
    ) -> ave_common::response::SinkEventsPage {
        let response = node_actor
            .ask(NodeMessage::GetSinkEvents {
                subject_id: subject_id.clone(),
                from_sn,
                to_sn,
                limit,
            })
            .await
            .unwrap();

        let NodeResponse::SinkEvents(events) = response else {
            panic!("Invalid response")
        };

        events
    }

    async fn get_sink_events_error(
        node_actor: &ActorRef<Node>,
        subject_id: &DigestIdentifier,
        from_sn: u64,
        to_sn: Option<u64>,
        limit: u64,
    ) -> ActorError {
        node_actor
            .ask(NodeMessage::GetSinkEvents {
                subject_id: subject_id.clone(),
                from_sn,
                to_sn,
                limit,
            })
            .await
            .unwrap_err()
    }

    async fn get_tracker_metadata(
        system: &SystemRef,
        subject_id: &DigestIdentifier,
    ) -> Metadata {
        let subject_manager = system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .unwrap();
        let requester = format!("evaluation_test:{}", subject_id);

        let SubjectManagerResponse::Up = subject_manager
            .ask(SubjectManagerMessage::Up {
                subject_id: subject_id.clone(),
                requester: requester.clone(),
                create_ledger: None,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_actor: ActorRef<Tracker> = system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{}",
                subject_id
            )))
            .await
            .unwrap();

        let metadata = match subject_actor
            .ask(TrackerMessage::GetMetadata)
            .await
            .unwrap()
        {
            TrackerResponse::Metadata(metadata) => *metadata,
            _ => panic!("Invalid response"),
        };

        let SubjectManagerResponse::Finish = subject_manager
            .ask(SubjectManagerMessage::Finish {
                subject_id: subject_id.clone(),
                requester,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        metadata
    }

    #[test(tokio::test)]
    async fn test_fact_gov() {
        let (
            _system,
            node_actor,
            request_actor,
            db,
            subject_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_gov().await;

        let payload = ValueWrapper(json!({
            "members": {
                "add": [
                    {
                        "name": "AveNode1",
                        "key": "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                    }
                ]
            }
        }));
        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: payload.clone(),
            viewpoints: Default::default(),
        });

        let request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let RequestHandlerResponse::Approval(Some((.., state))) = request_actor
            .ask(RequestHandlerMessage::GetApproval {
                subject_id: subject_id.clone(),
                state: Some(ApprovalState::Pending),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(state.to_string(), "pending");

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.clone(),
                state: ApprovalStateRes::Accepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to accepted",
                subject_id.to_string()
            )
        );

        wait_request(&tracking, request_data.request_id).await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_data = get_subject_state(&db, &subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

        let RequestEventDB::GovernanceFact {
            payload: request_payload,
            evaluation_response,
            approval_success,
        } = event.data
        else {
            panic!()
        };

        let EvalResDB::Patch(_) = evaluation_response else {
            panic!("");
        };

        assert!(approval_success.unwrap());

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, subject_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(payload.0, request_payload);
        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);
        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());
    }

    #[test(tokio::test)]
    async fn test_fact_fail_gov() {
        let (
            _system,
            node_actor,
            request_actor,
            db,
            subject_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_gov().await;

        let payload = ValueWrapper(json!({
            "members": {
                "add": [
                    {
                        "name": "Owner",
                        "key": "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                    }
                ]
            }
        }));
        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: payload.clone(),
            viewpoints: Default::default(),
        });

        let _request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_data = get_subject_state(&db, &subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

        let RequestEventDB::GovernanceFact {
            payload: request_payload,
            evaluation_response,
            approval_success,
        } = event.data
        else {
            panic!()
        };

        let EvalResDB::Error(e) = evaluation_response else {
            panic!("");
        };

        assert_eq!(
            "runner error: invalid event: [check_members] invalid event: member name cannot be 'Owner' (reserved word)",
            e
        );
        assert!(approval_success.is_none());

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, subject_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(payload.0, request_payload);
        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 0);
        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());
    }

    #[test(tokio::test)]
    async fn test_transfer_gov() {
        let (
            _system,
            node_actor,
            request_actor,
            db,
            subject_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_gov().await;

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(json!({
                "members": {
                    "add": [
                        {
                            "name": "TestMember",
                            "key": "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                        }
                    ]
                }
            })),
            viewpoints: Default::default(),
        });

        let _request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.clone(),
                state: ApprovalStateRes::Accepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to accepted",
                subject_id.to_string()
            )
        );

        let transfer_request = EventRequest::Transfer(TransferRequest {
            subject_id: subject_id.clone(),
            new_owner: PublicKey::from_str(
                "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE",
            )
            .unwrap(),
        });

        let _request_data = emit_request(
            transfer_request.clone(),
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_data = get_subject_state(&db, &subject_id, 2).await;
        let event = get_event_sn(&db, &subject_id, 2).await;

        let RequestEventDB::Transfer {
            evaluation_error,
            new_owner: new_owner_transfer,
        } = event.data
        else {
            panic!()
        };

        assert!(evaluation_error.is_none());

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, subject_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert_eq!(
            new_owner_transfer,
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
        );
        assert_eq!(
            subject_data.new_owner.unwrap(),
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
        );
        assert_eq!(
            metadata.new_owner.unwrap().to_string(),
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
        );

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 2);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 2);
        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());

        let response = node_actor
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::EventRequest(transfer_request.clone()),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(transfer_request, signature);

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

    #[test(tokio::test)]
    async fn test_transfer_fail_gov() {
        let (
            _system,
            node_actor,
            request_actor,
            db,
            subject_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_gov().await;

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(json!({
                "members": {
                    "add": [
                        {
                            "name": "TestMember",
                            "key": "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                        }
                    ]
                }
            })),
            viewpoints: Default::default(),
        });

        let _request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.clone(),
                state: ApprovalStateRes::Accepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to accepted",
                subject_id.to_string()
            )
        );

        let transfer_request = EventRequest::Transfer(TransferRequest {
            subject_id: subject_id.clone(),
            new_owner: PublicKey::from_str(
                "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbA",
            )
            .unwrap(),
        });

        let _request_data = emit_request(
            transfer_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_data = get_subject_state(&db, &subject_id, 2).await;
        let event = get_event_sn(&db, &subject_id, 2).await;

        let RequestEventDB::Transfer {
            evaluation_error,
            new_owner: new_owner_transfer,
        } = event.data
        else {
            panic!()
        };

        assert_eq!(
            "runner error: invalid event: [execute_transfer_gov] invalid event: 'new owner EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbA' is not a member of governance",
            evaluation_error.unwrap()
        );

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, subject_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert_eq!(
            new_owner_transfer,
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbA"
        );
        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 2);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);
        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());
    }

    async fn init_gov_with_member_and_schema() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        Arc<ExternalDB>,
        ActorRef<Governance>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let (
            system,
            node_actor,
            request_actor,
            db,
            subject_actor,
            tracking,
            subject_id,
            _dir,
        ) = create_gov().await;

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(json!({
                "members": {
                    "add": [
                        {
                            "name": "TestMember",
                            "key": "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                        }
                    ]
                },
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
                    "tracker_schemas": {
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
                                        },
                                        {
                                            "name": "TestMember",
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
            viewpoints: Default::default(),
        });

        let request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let RequestHandlerResponse::Approval(Some((.., state))) = request_actor
            .ask(RequestHandlerMessage::GetApproval {
                subject_id: subject_id.clone(),
                state: Some(ApprovalState::Pending),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(state.to_string(), "pending");

        let RequestHandlerResponse::Response(res) = request_actor
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id: subject_id.clone(),
                state: ApprovalStateRes::Accepted,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        assert_eq!(
            res,
            format!(
                "The approval request for subject {} has changed to accepted",
                subject_id.to_string()
            )
        );

        wait_request(&tracking, request_data.request_id).await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };
        let subject_data = get_subject_state(&db, &subject_id, 1).await;

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, subject_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);
        assert!(!gov.members.is_empty());
        assert!(!gov.roles_schema.is_empty());
        assert!(!gov.schemas.is_empty());
        assert!(!gov.policies_schema.is_empty());

        (
            system,
            node_actor,
            request_actor,
            db,
            subject_actor,
            tracking,
            subject_id,
            _dir,
        )
    }

    #[test(tokio::test)]
    async fn test_fact_gov_2() {
        init_gov_with_member_and_schema().await;
    }

    async fn create_tracker() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        Arc<ExternalDB>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let (
            system,
            node_actor,
            request_actor,
            db,
            _subject_actor,
            tracking,
            gov_id,
            _dir,
        ) = init_gov_with_member_and_schema().await;

        let create_request = EventRequest::Create(CreateRequest {
            name: Some("Subject Name".to_owned()),
            description: Some("Subject Description".to_owned()),
            governance_id: gov_id.clone(),
            schema_id: SchemaType::Type("Example".to_owned()),
            namespace: Namespace::new(),
        });

        let request_data = emit_request(
            create_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let subject_id = request_data.subject_id.clone();

        let metadata = get_tracker_metadata(&system, &subject_id).await;

        let subject_data = get_subject_state(&db, &subject_id, 0).await;
        let event = get_event_sn(&db, &subject_id, 0).await;

        let RequestEventDB::Create {
            name,
            description,
            schema_id,
            namespace,
        } = event.data
        else {
            panic!()
        };

        assert_eq!(metadata.name, name);
        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Subject Name");

        assert_eq!(metadata.description, description);
        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Subject Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, gov_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 1);

        assert_eq!(metadata.schema_id.to_string(), schema_id);
        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Type("Example".to_string()));

        assert_eq!(metadata.namespace.to_string(), namespace);
        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 0);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        assert!(metadata.properties.0["one"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["two"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["three"].as_u64().unwrap() == 0);

        (
            system,
            node_actor,
            request_actor,
            db,
            tracking,
            request_data.subject_id,
            gov_id,
            _dir,
        )
    }

    #[test(tokio::test)]
    async fn test_create_tracker() {
        let _ = create_tracker().await;
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_tracker_create() {
        let (
            _system,
            node_actor,
            _request_actor,
            _db,
            _tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let replay =
            get_sink_events(&node_actor, &subject_id, 0, None, 100).await;

        assert_eq!(replay.from_sn, 0);
        assert_eq!(replay.to_sn, None);
        assert_eq!(replay.limit, 100);
        assert!(!replay.has_more);
        assert!(replay.next_sn.is_none());
        assert_eq!(replay.events.len(), 1);

        let event = &replay.events[0];
        assert!(!event.public_key.is_empty());
        assert!(event.sink_timestamp > 0);
        match &event.payload {
            DataToSinkEvent::Create {
                governance_id,
                subject_id: replay_subject_id,
                owner,
                schema_id,
                namespace,
                sn,
                gov_version,
                state,
            } => {
                assert_eq!(
                    governance_id.as_deref(),
                    Some(gov_id.to_string().as_str())
                );
                assert_eq!(replay_subject_id, &subject_id.to_string());
                assert_eq!(schema_id, &SchemaType::Type("Example".to_owned()));
                assert_eq!(namespace, "");
                assert_eq!(*sn, 0);
                assert_eq!(*gov_version, 1);
                assert!(!owner.is_empty());
                assert_eq!(state["one"].as_u64().unwrap(), 0);
                assert_eq!(state["two"].as_u64().unwrap(), 0);
                assert_eq!(state["three"].as_u64().unwrap(), 0);
            }
            other => panic!("Unexpected event: {other:?}"),
        }
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_tracker_pagination() {
        let (
            _system,
            node_actor,
            request_actor,
            _db,
            tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let payload = json!({
            "ModOne": {
                "data": 100
            }
        });

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(payload.clone()),
            viewpoints: Default::default(),
        });

        let _request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let first_page =
            get_sink_events(&node_actor, &subject_id, 0, None, 1).await;
        assert_eq!(first_page.events.len(), 1);
        assert!(first_page.has_more);
        assert_eq!(first_page.next_sn, Some(1));
        match &first_page.events[0].payload {
            DataToSinkEvent::Create {
                governance_id,
                subject_id: replay_subject_id,
                sn,
                ..
            } => {
                assert_eq!(
                    governance_id.as_deref(),
                    Some(gov_id.to_string().as_str())
                );
                assert_eq!(replay_subject_id, &subject_id.to_string());
                assert_eq!(*sn, 0);
            }
            other => panic!("Unexpected event: {other:?}"),
        }

        let second_page =
            get_sink_events(&node_actor, &subject_id, 1, None, 10).await;
        assert_eq!(second_page.events.len(), 1);
        assert!(!second_page.has_more);
        assert!(second_page.next_sn.is_none());
        match &second_page.events[0].payload {
            DataToSinkEvent::Fact {
                governance_id,
                subject_id: replay_subject_id,
                payload: replay_payload,
                sn,
                gov_version,
                ..
            } => {
                assert_eq!(
                    governance_id.as_deref(),
                    Some(gov_id.to_string().as_str())
                );
                assert_eq!(replay_subject_id, &subject_id.to_string());
                assert_eq!(replay_payload, &payload);
                assert_eq!(*sn, 1);
                assert_eq!(*gov_version, 1);
            }
            other => panic!("Unexpected event: {other:?}"),
        }
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_governance_create() {
        let (
            _system,
            node_actor,
            _request_actor,
            _db,
            _subject_actor,
            _tracking,
            subject_id,
            _dir,
        ) = create_gov().await;

        let replay =
            get_sink_events(&node_actor, &subject_id, 0, None, 100).await;

        assert_eq!(replay.events.len(), 1);
        assert!(!replay.has_more);
        assert!(replay.next_sn.is_none());

        match &replay.events[0].payload {
            DataToSinkEvent::Create {
                governance_id,
                subject_id: replay_subject_id,
                schema_id,
                sn,
                gov_version,
                ..
            } => {
                assert!(governance_id.is_none());
                assert_eq!(replay_subject_id, &subject_id.to_string());
                assert_eq!(schema_id, &SchemaType::Governance);
                assert_eq!(*sn, 0);
                assert_eq!(*gov_version, 0);
            }
            other => panic!("Unexpected event: {other:?}"),
        }
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_tracker_transfer() {
        let (
            _system,
            node_actor,
            request_actor,
            _db,
            tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let transfer_request = EventRequest::Transfer(TransferRequest {
            subject_id: subject_id.clone(),
            new_owner: PublicKey::from_str(
                "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE",
            )
            .unwrap(),
        });

        let _request_data = emit_request(
            transfer_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let replay =
            get_sink_events(&node_actor, &subject_id, 1, Some(1), 100).await;

        assert_eq!(replay.events.len(), 1);
        assert!(!replay.has_more);
        assert!(replay.next_sn.is_none());

        match &replay.events[0].payload {
            DataToSinkEvent::Transfer {
                governance_id,
                subject_id: replay_subject_id,
                schema_id,
                owner,
                new_owner,
                sn,
                gov_version,
            } => {
                assert_eq!(
                    governance_id.as_deref(),
                    Some(gov_id.to_string().as_str())
                );
                assert_eq!(replay_subject_id, &subject_id.to_string());
                assert_eq!(schema_id, &SchemaType::Type("Example".to_owned()));
                assert!(!owner.is_empty());
                assert_eq!(
                    new_owner,
                    "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
                );
                assert_eq!(*sn, 1);
                assert_eq!(*gov_version, 1);
            }
            other => panic!("Unexpected event: {other:?}"),
        }
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_invalid_range() {
        let (
            _system,
            node_actor,
            _request_actor,
            _db,
            _tracking,
            subject_id,
            _gov_id,
            _dir,
        ) = create_tracker().await;

        let error =
            get_sink_events_error(&node_actor, &subject_id, 5, Some(4), 100)
                .await;

        let ActorError::Functional { description } = error else {
            panic!("Expected functional error")
        };
        assert_eq!(description, "Replay range requires from_sn <= to_sn");
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_invalid_limit() {
        let (
            _system,
            node_actor,
            _request_actor,
            _db,
            _tracking,
            subject_id,
            _gov_id,
            _dir,
        ) = create_tracker().await;

        let error =
            get_sink_events_error(&node_actor, &subject_id, 0, None, 0).await;

        let ActorError::Functional { description } = error else {
            panic!("Expected functional error")
        };
        assert_eq!(description, "Replay limit must be greater than zero");
    }

    #[test(tokio::test)]
    async fn test_replay_sink_events_subject_not_found() {
        let (
            _system,
            node_actor,
            _request_actor,
            _db,
            _tracking,
            _subject_id,
            _gov_id,
            _dir,
        ) = create_tracker().await;

        let missing = DigestIdentifier::from_str(
            "B3B7tbY0OWp5jVq3OKYwYGQnM2zJ5V8i3G5znQJg4s8A",
        )
        .unwrap();

        let error =
            get_sink_events_error(&node_actor, &missing, 0, None, 100).await;

        let ActorError::NotFound { path } = error else {
            panic!("Expected not found error")
        };
        assert_eq!(
            path,
            ActorPath::from(format!("/user/node/subject_manager/{}", missing))
        );
    }

    #[test(tokio::test)]
    async fn test_fact_tracker() {
        let (
            system,
            node_actor,
            request_actor,
            db,
            tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let payload = json!({
            "ModOne": {
                "data": 100
            }
        });

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(payload.clone()),
            viewpoints: Default::default(),
        });

        let request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let metadata = get_tracker_metadata(&system, &subject_id).await;

        let subject_data =
            get_subject_state(&db, &request_data.subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

        let RequestEventDB::TrackerFact {
            payload: payload_db,
            viewpoints,
            evaluation_response,
        } = event.data
        else {
            panic!()
        };
        assert!(viewpoints.is_empty());

        let EvalResDB::Patch(_) = evaluation_response else {
            panic!("");
        };

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Subject Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Subject Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, gov_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 1);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Type("Example".to_string()));

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(payload, payload_db);
        assert_eq!(metadata.properties.0, subject_data.properties);
        assert!(metadata.properties.0["one"].as_u64().unwrap() == 100);
        assert!(metadata.properties.0["two"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["three"].as_u64().unwrap() == 0);
    }

    #[test(tokio::test)]
    async fn test_fact_fail_tracker() {
        let (
            system,
            node_actor,
            request_actor,
            db,
            tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let payload = json!({
            "ModOne": {
                "not_exist": "error"
            }
        });

        let fact_request = EventRequest::Fact(FactRequest {
            subject_id: subject_id.clone(),
            payload: ValueWrapper(payload.clone()),
            viewpoints: Default::default(),
        });

        let request_data = emit_request(
            fact_request,
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let metadata = get_tracker_metadata(&system, &subject_id).await;

        let subject_data =
            get_subject_state(&db, &request_data.subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

        let RequestEventDB::TrackerFact {
            payload: payload_db,
            viewpoints,
            evaluation_response,
        } = event.data
        else {
            panic!()
        };
        assert!(viewpoints.is_empty());

        let EvalResDB::Error(e) = evaluation_response else {
            panic!("");
        };

        assert_eq!(
            "runner error: contract failed: contract returned failure: Contract execution in running was not successful: Can not convert Event from value",
            e
        );
        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Subject Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Subject Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, gov_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 1);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Type("Example".to_string()));

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(payload, payload_db);
        assert_eq!(metadata.properties.0, subject_data.properties);
        assert!(metadata.properties.0["one"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["two"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["three"].as_u64().unwrap() == 0);
    }

    #[test(tokio::test)]
    async fn test_transfer_tracker() {
        let (
            system,
            node_actor,
            request_actor,
            db,
            tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let transfer_request = EventRequest::Transfer(TransferRequest {
            subject_id: subject_id.clone(),
            new_owner: PublicKey::from_str(
                "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE",
            )
            .unwrap(),
        });

        let _request_data = emit_request(
            transfer_request.clone(),
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let metadata = get_tracker_metadata(&system, &subject_id).await;

        let subject_data = get_subject_state(&db, &subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

        let RequestEventDB::Transfer {
            evaluation_error,
            new_owner: new_owner_transfer,
        } = event.data
        else {
            panic!()
        };

        assert!(evaluation_error.is_none());

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Subject Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Subject Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, gov_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 1);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Type("Example".to_string()));

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert_eq!(
            new_owner_transfer,
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
        );
        assert_eq!(
            subject_data.new_owner.unwrap(),
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
        );
        assert_eq!(
            metadata.new_owner.unwrap().to_string(),
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"
        );

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        assert!(metadata.properties.0["one"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["two"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["three"].as_u64().unwrap() == 0);

        let response = node_actor
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::EventRequest(transfer_request.clone()),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(transfer_request, signature);

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

    #[test(tokio::test)]
    async fn test_transfer_fail_tracker() {
        let (
            system,
            node_actor,
            request_actor,
            db,
            tracking,
            subject_id,
            gov_id,
            _dir,
        ) = create_tracker().await;

        let transfer_request = EventRequest::Transfer(TransferRequest {
            subject_id: subject_id.clone(),
            new_owner: PublicKey::from_str(
                "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbA",
            )
            .unwrap(),
        });

        let _request_data = emit_request(
            transfer_request.clone(),
            &node_actor,
            &request_actor,
            &tracking,
            true,
        )
        .await;

        let metadata = get_tracker_metadata(&system, &subject_id).await;

        let subject_data = get_subject_state(&db, &subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

        let RequestEventDB::Transfer {
            evaluation_error,
            new_owner: new_owner_transfer,
        } = event.data
        else {
            panic!()
        };

        assert_eq!(
            "runner error: invalid event: [execute_transfer_not_gov] invalid event: 'new owner EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbA' is not a member of governance",
            evaluation_error.unwrap()
        );

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Subject Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Subject Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, gov_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 1);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Type("Example".to_string()));

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert_eq!(
            new_owner_transfer,
            "EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbA"
        );
        assert!(subject_data.new_owner.is_none(),);
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        assert!(metadata.properties.0["one"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["two"].as_u64().unwrap() == 0);
        assert!(metadata.properties.0["three"].as_u64().unwrap() == 0);
    }
}
