//! # Evaluation module.
//! This module contains the evaluation logic for the Ave protocol.
//!

pub mod compiler;
pub mod evaluator;
pub mod request;
pub mod response;
mod runner;
pub mod schema;

use crate::{
    auth::WitnessesAuth,
    governance::{
        data::GovernanceData,
        model::{ProtocolTypes, Quorum},
    },
    model::{
        SignTypesNode,
        common::{
            emit_fail,
            node::{get_sign, try_to_update},
            send_reboot_to_req,
            subject::{get_metadata, get_signers_quorum_gov_version},
            take_random_signers,
        },
        event::{LedgerValue, ProtocolsError, ProtocolsSignatures},
        request::{EventRequest, SchemaType},
    },
    request::manager::{RequestManager, RequestManagerMessage},
    subject::Metadata,
    system::ConfigHelper,
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::{
    ValueWrapper,
    identity::{PublicKey, Signature, Signed, hash_borsh},
};
use evaluator::{Evaluator, EvaluatorMessage};
use request::{EvaluationReq, SubjectContext};
use response::{EvalLedgerResponse, EvaluationRes, Response as EvalRes};
use serde_json::json;
use tracing::{error, warn};

const TARGET_EVALUATION: &str = "Ave-Evaluation";

use std::collections::HashSet;
// TODO cuando se recibe una evaluación, validación lo que sea debería venir firmado y comprobar que es de quien dice ser, cuando llega por la network y cuando la envía un usuario.
#[derive(Default)]
pub struct Evaluation {
    node_key: PublicKey,
    // Quorum
    quorum: Quorum,
    // Actual responses
    evaluators_response: Vec<EvalRes>,
    // Evaluators quantity
    evaluators_quantity: u32,

    evaluators_signatures: Vec<ProtocolsSignatures>,

    request_id: String,

    version: u64,

    errors: String,

    signed_eval_req: Option<Signed<EvaluationReq>>,

    reboot: bool,

    current_evaluators: HashSet<PublicKey>,

    pending_evaluators: HashSet<PublicKey>,
}

impl Evaluation {
    pub fn new(node_key: PublicKey) -> Self {
        Evaluation {
            node_key,
            ..Default::default()
        }
    }

    async fn end_evaluators(
        &self,
        ctx: &mut ActorContext<Evaluation>,
    ) -> Result<(), ActorError> {
        for evaluator in self.current_evaluators.clone() {
            let child: Option<ActorRef<Evaluator>> =
                ctx.get_child(&evaluator.to_string()).await;
            if let Some(child) = child {
                child.ask_stop().await?;
            }
        }

        Ok(())
    }

    fn check_evaluator(&mut self, evaluator: PublicKey) -> bool {
        self.current_evaluators.remove(&evaluator)
    }

    fn create_evaluation_req(
        &self,
        event_request: Signed<EventRequest>,
        metadata: Metadata,
        state: ValueWrapper,
        gov_state_init_state: ValueWrapper,
        gov_version: u64,
    ) -> EvaluationReq {
        EvaluationReq {
            event_request: event_request.clone(),
            context: SubjectContext {
                subject_id: metadata.subject_id,
                governance_id: metadata.governance_id,
                schema_id: metadata.schema_id,
                is_owner: self.node_key == event_request.signature.signer,
                namespace: metadata.namespace,
            },
            new_owner: metadata.new_owner,
            state,
            gov_state_init_state,
            sn: metadata.sn + 1,
            gov_version,
        }
    }

    async fn create_evaluators(
        &self,
        ctx: &mut ActorContext<Evaluation>,
        evaluation_req: Signed<EvaluationReq>,
        schema_id: &SchemaType,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        // Create Evaluator child
        let child = ctx
            .create_child(
                &format!("{}", signer),
                Evaluator::new(
                    self.request_id.to_string(),
                    self.version,
                    signer.clone(),
                ),
            )
            .await;
        let evaluator_actor = match child {
            Ok(child) => child,
            Err(e) => return Err(e),
        };

        // Check node_key
        let our_key = self.node_key.clone();
        // We are signer
        if signer == our_key {
            evaluator_actor
                .tell(EvaluatorMessage::LocalEvaluation {
                    evaluation_req: evaluation_req.content,
                    our_key: signer,
                })
                .await?
        }
        // Other node is signer
        else {
            evaluator_actor
                .tell(EvaluatorMessage::NetworkEvaluation {
                    evaluation_req,
                    node_key: signer,
                    schema_id: schema_id.to_owned(),
                })
                .await?
        }

        Ok(())
    }

    fn check_responses(&self) -> bool {
        let set: HashSet<EvalRes> =
            HashSet::from_iter(self.evaluators_response.iter().cloned());

        set.len() == 1
    }

    async fn fail_evaluation(
        &self,
        ctx: &mut ActorContext<Evaluation>,
    ) -> Result<EvalLedgerResponse, ActorError> {
        let hash = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.hash_algorithm
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        let (state, gov_id) = if let Some(req) = self.signed_eval_req.clone() {
            let gov_id = if req.content.context.governance_id.is_empty() {
                req.content.context.subject_id
            } else {
                req.content.context.governance_id
            };
            (req.content.state, gov_id)
        } else {
            return Err(ActorError::FunctionalFail(
                "Can not get eval request".to_owned(),
            ));
        };

        let state_hash = match hash_borsh(&*hash.hasher(), &state) {
            Ok(state_hash) => state_hash,
            Err(e) => {
                return Err(ActorError::FunctionalFail(format!(
                    "Can not obtaing state hash: {}",
                    e
                )));
            }
        };

        let mut error = self.errors.clone();
        if self.errors.is_empty() {
            "who: ALL, error: No evaluator was able to evaluate the event."
                .clone_into(&mut error);

            let all_time_out = self
                .evaluators_signatures
                .iter()
                .all(|x| matches!(x, ProtocolsSignatures::TimeOut(_)));

            if all_time_out {
                try_to_update(ctx, gov_id, WitnessesAuth::Witnesses).await?
            }
        }

        Ok(EvalLedgerResponse {
            value: LedgerValue::Error(ProtocolsError {
                evaluation: Some(error),
                validation: None,
            }),
            state_hash,
            eval_success: false,
            appr_required: false,
        })
    }

    async fn send_evaluation_to_req(
        &self,
        ctx: &mut ActorContext<Evaluation>,
        response: EvalLedgerResponse,
    ) -> Result<(), ActorError> {
        let req_path =
            ActorPath::from(format!("/user/request/{}", self.request_id));
        let req_actor: Option<ActorRef<RequestManager>> =
            ctx.system().get_actor(&req_path).await;

        let request = if let Some(req) = self.signed_eval_req.clone() {
            req.content
        } else {
            return Err(ActorError::FunctionalFail(
                "Can not get eval request".to_owned(),
            ));
        };

        if let Some(req_actor) = req_actor {
            req_actor
                .tell(RequestManagerMessage::EvaluationRes {
                    request: Box::new(request),
                    response,
                    signatures: self.evaluators_signatures.clone(),
                })
                .await?;
        } else {
            return Err(ActorError::NotFound(req_path));
        };

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum EvaluationMessage {
    Create {
        request_id: String,
        version: u64,
        request: Signed<EventRequest>,
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
                request,
            } => {
                let (subject_id, confirm) = match request.content.clone() {
                    EventRequest::Fact(event) => (event.subject_id, false),
                    EventRequest::Transfer(event) => (event.subject_id, false),
                    EventRequest::Confirm(event) => (event.subject_id, true),
                    _ => {
                        let e = "Only can evaluate Fact, Transfer and Confirm request";
                        error!(TARGET_EVALUATION, "Create, {}", e);

                        return Err(emit_fail(
                            ctx,
                            ActorError::FunctionalFail(e.to_owned()),
                        )
                        .await);
                    }
                };

                let metadata =
                    match get_metadata(ctx, &subject_id.to_string()).await {
                        Ok(metadata) => metadata,
                        Err(e) => {
                            error!(
                                TARGET_EVALUATION,
                                "Create, can not get metadata: {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                if confirm && !metadata.governance_id.is_empty() {
                    let e = "Confirm event in trazability subjects can not evaluate";
                    error!(TARGET_EVALUATION, "Create, {}", e);

                    return Err(emit_fail(
                        ctx,
                        ActorError::FunctionalFail(e.to_owned()),
                    )
                    .await);
                }

                let governance = if metadata.governance_id.is_empty() {
                    metadata.subject_id.clone()
                } else {
                    metadata.governance_id.clone()
                };

                let (state, gov_state_init_state) =
                    if let EventRequest::Transfer(_) = request.content.clone() {
                        if metadata.governance_id.is_empty() {
                            (
                                metadata.properties.clone(),
                                ValueWrapper(json!({})),
                            )
                        } else {
                            let metadata_gov = match get_metadata(
                                ctx,
                                &metadata.governance_id.to_string(),
                            )
                            .await
                            {
                                Ok(metadata) => metadata,
                                Err(e) => {
                                    error!(
                                        TARGET_EVALUATION,
                                        "Create, can not get metadata: {}", e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };

                            (
                                metadata.properties.clone(),
                                metadata_gov.properties,
                            )
                        }
                    } else if let EventRequest::Fact(_) =
                        request.content.clone()
                    {
                        if metadata.governance_id.is_empty() {
                            (
                                metadata.properties.clone(),
                                ValueWrapper(json!({})),
                            )
                        } else {
                            let metadata_gov = match get_metadata(
                                ctx,
                                &metadata.governance_id.to_string(),
                            )
                            .await
                            {
                                Ok(metadata) => metadata,
                                Err(e) => {
                                    error!(
                                        TARGET_EVALUATION,
                                        "Create, can not get metadata: {}", e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };

                            let governance = match GovernanceData::try_from(
                                metadata_gov.properties.clone(),
                            ) {
                                Ok(gov) => gov,
                                Err(e) => {
                                    let e = format!(
                                        "can not convert governance from properties: {}",
                                        e
                                    );
                                    error!(TARGET_EVALUATION, "Create, {}", e);
                                    return Err(emit_fail(
                                        ctx,
                                        ActorError::FunctionalFail(e),
                                    )
                                    .await);
                                }
                            };

                            let init_value = match governance
                                .get_init_state(&metadata.schema_id)
                            {
                                Ok(init_value) => init_value,
                                Err(e) => {
                                    let e = format!(
                                        "can not obtain schema {} from governance: {}",
                                        metadata.schema_id, e
                                    );
                                    error!(TARGET_EVALUATION, "Create, {}", e);
                                    return Err(emit_fail(
                                        ctx,
                                        ActorError::FunctionalFail(e),
                                    )
                                    .await);
                                }
                            };

                            (metadata.properties.clone(), init_value)
                        }
                    } else {
                        (metadata.properties.clone(), ValueWrapper(json!({})))
                    };

                let (signers, quorum, gov_version) =
                    match get_signers_quorum_gov_version(
                        ctx,
                        &governance.to_string(),
                        &metadata.schema_id,
                        metadata.namespace.clone(),
                        ProtocolTypes::Evaluation,
                    )
                    .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            error!(
                                TARGET_EVALUATION,
                                "Create, can not get signers quorum and gov version: {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                let eval_req = self.create_evaluation_req(
                    request,
                    metadata.clone(),
                    state,
                    gov_state_init_state,
                    gov_version,
                );

                let signature = match get_sign(
                    ctx,
                    SignTypesNode::EvaluationReq(eval_req.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            TARGET_EVALUATION,
                            "Create, can not sign eval request: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let signed_evaluation_req: Signed<EvaluationReq> = Signed {
                    content: eval_req,
                    signature,
                };

                self.evaluators_response = vec![];
                self.signed_eval_req = Some(signed_evaluation_req.clone());
                self.quorum = quorum;
                self.evaluators_quantity = signers.len() as u32;
                self.request_id = request_id.to_string();
                self.version = version;
                self.evaluators_signatures = vec![];
                self.errors = String::default();
                self.reboot = false;

                if signers.is_empty() {
                    warn!(
                        TARGET_EVALUATION,
                        "Create, There are no evaluators available for the {} scheme",
                        metadata.schema_id
                    );

                    let response = match self.fail_evaluation(ctx).await {
                        Ok(res) => res,
                        Err(e) => {
                            error!(
                                TARGET_EVALUATION,
                                "Create, can not create evaluation response: {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };
                    if let Err(e) =
                        self.send_evaluation_to_req(ctx, response).await
                    {
                        error!(
                            TARGET_EVALUATION,
                            "Create, can send evaluation to request actor: {}",
                            e
                        );
                        return Err(emit_fail(ctx, e).await);
                    };
                }

                let evaluators_quantity = self.quorum.get_signers(
                    self.evaluators_quantity,
                    signers.len() as u32,
                );

                let (current_eval, pending_eval) =
                    take_random_signers(signers, evaluators_quantity as usize);
                self.current_evaluators.clone_from(&current_eval);
                self.pending_evaluators.clone_from(&pending_eval);

                for signer in current_eval {
                    if let Err(e) = self
                        .create_evaluators(
                            ctx,
                            signed_evaluation_req.clone(),
                            &metadata.schema_id,
                            signer.clone(),
                        )
                        .await
                    {
                        error!(
                            TARGET_EVALUATION,
                            "Can not create evaluator {}: {}", signer, e
                        );
                    }
                }
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
                            EvaluationRes::Response(response) => {
                                if let Some(signature) = signature {
                                    self.evaluators_signatures.push(
                                        ProtocolsSignatures::Signature(
                                            signature,
                                        ),
                                    );
                                } else {
                                    let e =
                                        "Evaluation solver whitout signature"
                                            .to_owned();
                                    error!(
                                        TARGET_EVALUATION,
                                        "Response, {}", e
                                    );
                                    return Err(ActorError::Functional(e));
                                }

                                self.evaluators_response.push(response);
                            }
                            EvaluationRes::TimeOut(timeout) => self
                                .evaluators_signatures
                                .push(ProtocolsSignatures::TimeOut(timeout)),
                            EvaluationRes::Error(error) => {
                                self.errors = format!(
                                    "{} who: {}, error: {}.",
                                    self.errors, sender, error
                                );
                            }
                            EvaluationRes::Reboot => {
                                let governance_id = if let Some(req) =
                                    self.signed_eval_req.clone()
                                {
                                    req.content.context.governance_id
                                } else {
                                    let e = ActorError::FunctionalFail(
                                        "Can not get eval request".to_owned(),
                                    );
                                    error!(
                                        TARGET_EVALUATION,
                                        "Response, can not get eval request: {}",
                                        e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    &self.request_id,
                                    governance_id,
                                )
                                .await
                                {
                                    error!(
                                        TARGET_EVALUATION,
                                        "Response, can not send reboot to Request actor: {}",
                                        e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                                self.reboot = true;

                                if let Err(e) = self.end_evaluators(ctx).await {
                                    error!(
                                        TARGET_EVALUATION,
                                        "Response, can not end evaluators: {}",
                                        e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                                return Ok(());
                            }
                        };

                        if self.quorum.check_quorum(
                            self.evaluators_quantity,
                            self.evaluators_response.len() as u32,
                        ) {
                            let response = if self.check_responses() {
                                EvalLedgerResponse::from(
                                    self.evaluators_response[0].clone(),
                                )
                            } else {
                                self.errors = format!(
                                    "{} who: ALL, error: Several evaluations were correct, but there are some different.",
                                    self.errors
                                );
                                match self.fail_evaluation(ctx).await {
                                    Ok(res) => res,
                                    Err(e) => {
                                        error!(
                                            TARGET_EVALUATION,
                                            "Response, can not create evaluation response: {}",
                                            e
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                            };

                            if let Err(e) =
                                self.send_evaluation_to_req(ctx, response).await
                            {
                                error!(
                                    TARGET_EVALUATION,
                                    "Response, can send evaluation to request actor: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            };
                        } else if self.current_evaluators.is_empty()
                            && !self.pending_evaluators.is_empty()
                        {
                            if let Some(req) = self.signed_eval_req.clone() {
                                let evaluators_quantity =
                                    self.quorum.get_signers(
                                        self.evaluators_quantity,
                                        self.pending_evaluators.len() as u32,
                                    );

                                let (current_eval, pending_eval) =
                                    take_random_signers(
                                        self.pending_evaluators.clone(),
                                        evaluators_quantity as usize,
                                    );
                                self.current_evaluators
                                    .clone_from(&current_eval);
                                self.pending_evaluators
                                    .clone_from(&pending_eval);

                                for signer in current_eval {
                                    if let Err(e) = self
                                        .create_evaluators(
                                            ctx,
                                            req.clone(),
                                            &req.content.context.schema_id,
                                            signer.clone(),
                                        )
                                        .await
                                    {
                                        error!(
                                            TARGET_EVALUATION,
                                            "Can not create evaluator {}: {}",
                                            signer,
                                            e
                                        );
                                    }
                                }
                            } else {
                                let e = ActorError::FunctionalFail(
                                    "Can not get evaluation request".to_owned(),
                                );
                                error!(
                                    TARGET_EVALUATION,
                                    "Response, can not get evaluation request: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            };
                        } else if self.current_evaluators.is_empty() {
                            let response = match self.fail_evaluation(ctx).await
                            {
                                Ok(res) => res,
                                Err(e) => {
                                    error!(
                                        TARGET_EVALUATION,
                                        "Response, can not create evaluation response: {}",
                                        e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };
                            if let Err(e) =
                                self.send_evaluation_to_req(ctx, response).await
                            {
                                error!(
                                    TARGET_EVALUATION,
                                    "Response, can send evaluation to request actor: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            };
                        }
                    } else {
                        warn!(
                            TARGET_EVALUATION,
                            "Response, A response has been received from someone we were not expecting."
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
        error!(TARGET_EVALUATION, "OnChildFault, {}", error);
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
            tracking::{RequestTracking, RequestTrackingMessage, RequestTrackingResponse},
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

        let signed_event_req = Signed {
            content: fact_request,
            signature,
        };

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

        assert_eq!(event.content.subject_id, subject_id);
        assert_eq!(event.content.event_request, signed_event_req);
        assert_eq!(event.content.sn, 1);
        assert_eq!(event.content.gov_version, 0);
        assert_eq!(
            event.content.value,
            LedgerValue::Patch(ValueWrapper(json!([
                {"op":"add","path":"/members/AveNode1","value":"EUrVnqpwo9EKBvMru4wWLMpJgOTKM5gZnxApRmjrRbbE"}])))
        );
        assert!(event.content.eval_success.unwrap());
        assert!(event.content.appr_required);
        assert!(event.content.appr_success.unwrap());
        assert!(event.content.vali_success);
        assert!(!event.content.evaluators.unwrap().is_empty());
        assert!(!event.content.approvers.unwrap().is_empty());
        assert!(!event.content.validators.is_empty());

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

        let signed_event_req = Signed {
            content: fact_request,
            signature,
        };

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

        let signed_event_req = Signed {
            content: transfer_reques,
            signature,
        };

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

        assert_eq!(event.content.subject_id, subject_id);
        assert_eq!(event.content.event_request, signed_event_req);
        assert_eq!(event.content.sn, 2);
        assert_eq!(event.content.gov_version, 1);
        assert_eq!(
            event.content.value,
            LedgerValue::Patch(ValueWrapper(serde_json::Value::String(
                "[]".to_owned(),
            ),))
        );
        assert!(event.content.eval_success.unwrap());
        assert!(!event.content.appr_required);
        assert!(event.content.appr_success.is_none());
        assert!(event.content.vali_success);
        assert!(!event.content.evaluators.unwrap().is_empty());
        assert!(event.content.approvers.is_none(),);
        assert!(!event.content.validators.is_empty());

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

        let signed_event_req = Signed {
            content: fact_request,
            signature,
        };

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
            .ask(RequestTrackingMessage::SearchRequest( request_id.request_id.clone()))
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

        assert_eq!(event.content.subject_id, subject_id);
        assert_eq!(event.content.event_request, signed_event_req);
        assert_eq!(event.content.sn, 1);
        assert_eq!(event.content.gov_version, 0);

        assert_eq!(
            event.content.value,
            LedgerValue::Patch(ValueWrapper(
                json!([{"op":"add","path":"/policies_schema/Example","value":{"evaluate":"majority","validate":"majority"}},{"op":"add","path":"/roles_all_schemas/evaluator/0","value":{"name":"Owner","namespace":[]}},{"op":"add","path":"/roles_all_schemas/validator/0","value":{"name":"Owner","namespace":[]}},{"op":"add","path":"/roles_all_schemas/witness/0","value":{"name":"Owner","namespace":[]}},{"op":"add","path":"/roles_schema/Example","value":{"creator":[{"name":"Owner","namespace":[],"quantity":2,"witnesses":["Witnesses"]}],"evaluator":[],"issuer":{"any":false,"users":[{"name":"Owner","namespace":[]}]},"validator":[],"witness":[]}},{"op":"add","path":"/schemas/Example","value":{"contract":"dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==","initial_value":{"one":0,"three":0,"two":0}}}])
            ))
        );
        assert!(event.content.eval_success.unwrap());
        assert!(event.content.appr_required);
        assert!(event.content.appr_success.unwrap());
        assert!(event.content.vali_success);
        assert!(!event.content.evaluators.unwrap().is_empty());
        assert!(!event.content.approvers.unwrap().is_empty());
        assert!(!event.content.validators.is_empty());

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

        let signed_event_req = Signed {
            content: create_request,
            signature,
        };

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
            .ask(RequestTrackingMessage::SearchRequest( request_id.request_id.clone()))
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

        assert_eq!(event.content.subject_id.to_string(), request_id.subject_id);
        assert_eq!(event.content.event_request, signed_event_req);
        assert_eq!(event.content.sn, 0);
        assert_eq!(event.content.gov_version, 1);
        assert_eq!(
            event.content.value,
            LedgerValue::Patch(ValueWrapper(json!({
                "one": 0, "three": 0, "two": 0
            })))
        );

        assert_eq!(
            event.content.state_hash,
            hash_borsh(&Blake3Hasher, &metadata.properties).unwrap()
        );
        assert!(event.content.eval_success.is_none());
        assert!(!event.content.appr_required);
        assert!(event.content.appr_success.is_none());
        assert!(event.content.vali_success);
        assert_eq!(event.content.hash_prev_event, DigestIdentifier::default());
        assert!(event.content.evaluators.is_none());
        assert!(event.content.approvers.is_none(),);
        assert!(!event.content.validators.is_empty());

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

        let signed_event_req = Signed {
            content: fact_request,
            signature,
        };

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

        assert_eq!(event.content.subject_id.to_string(), request_id.subject_id);
        assert_eq!(event.content.event_request, signed_event_req);
        assert_eq!(event.content.sn, 1);
        assert_eq!(event.content.gov_version, 1);
        assert_eq!(
            event.content.state_hash,
            hash_borsh(&Blake3Hasher, &metadata.properties).unwrap()
        );
        assert!(event.content.eval_success.unwrap());
        assert!(!event.content.appr_required);
        assert!(event.content.appr_success.is_none());
        assert!(event.content.vali_success);
        assert!(!event.content.evaluators.unwrap().is_empty());
        assert!(event.content.approvers.is_none(),);
        assert!(!event.content.validators.is_empty());

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
