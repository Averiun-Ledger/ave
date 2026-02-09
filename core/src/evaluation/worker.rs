use std::{collections::BTreeMap, sync::Arc};

use crate::{
    evaluation::{
        request::EvaluateData,
        response::{
            EvalRunnerError, EvaluatorError, EvaluatorResponse as EvalRes,
        },
        runner::types::EvaluateInfo,
    },
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData, model::Schema,
    },
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::common::{
        emit_fail,
        node::{SignTypesNode, UpdateData, get_sign, update_ledger_network},
    },
    subject::RequestSubjectData,
    system::ConfigHelper,
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::{
    SchemaType, ValueWrapper,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
};

use json_patch::{diff};
use network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};

use serde_json::Value;
use tracing::{Span, debug, error, info_span, warn};

use super::{
    Evaluation, EvaluationMessage,
    compiler::{Compiler, CompilerMessage},
    request::EvaluationReq,
    response::EvaluationRes,
    runner::{Runner, RunnerMessage, RunnerResponse, types::RunnerResult},
};

/// A struct representing a EvalWorker actor.
#[derive(Clone, Debug)]
pub struct EvalWorker {
    pub node_key: PublicKey,
    pub our_key: Arc<PublicKey>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub sn: u64,
    pub init_state: Option<ValueWrapper>,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
    pub stop: bool
}

impl EvalWorker {
    async fn execute_contract(
        &self,
        ctx: &mut ActorContext<EvalWorker>,
        runner_data: EvaluateInfo,
        is_owner: bool,
    ) -> Result<RunnerResponse, ActorError> {
        let runner_actor = ctx.create_child("runner", Runner).await?;

        let response = runner_actor
            .ask(RunnerMessage {
                data: runner_data,
                is_owner,
            })
            .await;
        runner_actor.ask_stop().await?;

        response
    }

    async fn compile_contracts(
        &self,
        ctx: &mut ActorContext<EvalWorker>,
        ids: &[SchemaType],
        schemas: BTreeMap<SchemaType, Schema>,
    ) -> Result<(), ActorError> {
        let contracts_path = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.contracts_path
        } else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            });
        };

        for id in ids {
            let Some(schema) = schemas.get(id) else {
                return Err(ActorError::Functional { description: "There is a contract that requires compilation but its scheme could not be found".to_owned()});
            };

            let compiler_path = ActorPath::from(format!(
                "/user/node/{}/{}_compiler",
                self.governance_id, id
            ));
            let compiler_actor =
                ctx.system().get_actor::<Compiler>(&compiler_path).await?;

            compiler_actor
                .ask(CompilerMessage::Compile {
                    contract_name: format!("{}_{}", self.governance_id, id),
                    contract: schema.contract.clone(),
                    initial_value: schema.initial_value.0.clone(),
                    contract_path: contracts_path
                        .join("contracts")
                        .join(format!("{}_{}", self.governance_id, id)),
                })
                .await?
        }
        Ok(())
    }

    async fn check_governance(
        &self,
        gov_version: u64,
    ) -> Result<bool, ActorError> {
        match gov_version.cmp(&self.gov_version) {
            std::cmp::Ordering::Equal => {
                // If it is the same it means that we have the latest version of governance, we are up to date.
            }
            std::cmp::Ordering::Greater => {
                // Me llega una versión mayor a la mía.
                let data = UpdateData {
                    sn: self.sn,
                    gov_version: self.gov_version,
                    subject_id: self.governance_id.clone(),
                    other_node: self.node_key.clone(),
                };
                update_ledger_network(data, self.network.clone()).await?;
                let e = ActorError::Functional {
                    description: "Abort evaluation, update is required"
                        .to_owned(),
                };
                return Err(e);
            }
            std::cmp::Ordering::Less => {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn evaluate(
        &self,
        ctx: &mut ActorContext<EvalWorker>,
        evaluation_req: &EvaluationReq,
    ) -> Result<RunnerResult, EvaluatorError> {
        let runner_data =
            evaluation_req.build_evaluate_info(&self.init_state)?;

        // Mirar la parte final de execute contract.
        let response = self
            .execute_contract(ctx, runner_data, evaluation_req.signer_is_owner)
            .await
            .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;

        let (result, compilations) = match response {
            RunnerResponse::Ok {
                result,
                compilations,
            } => (result, compilations),
            RunnerResponse::Error(runner_error) => {
                return Err(EvaluatorError::from(runner_error));
            }
        };

        if self.init_state.is_none() && !compilations.is_empty() {
            let governance_data = GovernanceData::try_from(
                result.final_state.clone(),
            )
            .map_err(|e| {
                let e = format!(
                    "can not convert GovernanceData from properties: {}",
                    e
                );
                EvaluatorError::InternalError(e.to_string())
            })?;

            // TODO SI falla eliminar los new_compilers y borrar de CONTRACTS.
            let _new_compilers = self
                .create_compilers(ctx, &compilations)
                .await
                .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;

            self.compile_contracts(ctx, &compilations, governance_data.schemas)
                .await
                .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;
        }

        Ok(result)
    }

    async fn create_compilers(
        &self,
        ctx: &mut ActorContext<EvalWorker>,
        ids: &[SchemaType],
    ) -> Result<Vec<SchemaType>, ActorError> {
        let subject_path =
            ActorPath::from(format!("/user/node/{}", self.governance_id));
        let subject =
            ctx.system().get_actor::<Governance>(&subject_path).await?;

        let response = subject
            .ask(GovernanceMessage::CreateCompilers(ids.to_vec()))
            .await?;

        match response {
            GovernanceResponse::NewCompilers(new_compilers) => {
                Ok(new_compilers)
            }
            _ => Err(ActorError::UnexpectedResponse {
                path: subject_path,
                expected: "GovernanceResponse::NewCompilers".to_owned(),
            }),
        }
    }

    fn generate_json_patch(
        prev_state: &Value,
        new_state: &Value,
    ) -> Result<Value, EvaluatorError> {
        let patch = diff(prev_state, new_state);
        serde_json::to_value(patch).map_err(|e| {
            EvaluatorError::InternalError(format!("Can not generate json patch {}", e))
        })
    }

    fn build_response(
        &self,
        evaluation: RunnerResult,
        evaluation_req: Signed<EvaluationReq>,
    ) -> Result<EvaluationRes, EvaluatorError> {
        let eval_req_hash =
            hash_borsh(&*self.hash.hasher(), &evaluation_req)
                .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;

        let EvaluationReq {
            event_request,
            governance_id,
            sn,
            gov_version,
            namespace,
            schema_id,
            signer,
            ..
        } = evaluation_req.content().clone();

        let req_subject_data_hash = hash_borsh(
            &*self.hash.hasher(),
            &RequestSubjectData {
                namespace,
                schema_id,
                subject_id: event_request.content().get_subject_id(),
                governance_id,
                sn,
                gov_version,
                signer,
            },
        )
        .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;

        let (patch, properties_hash) = match &evaluation_req.content().data {
            EvaluateData::GovFact { state, .. } => {
                let properties_hash =
                    hash_borsh(&*self.hash.hasher(), &evaluation.final_state)
                        .map_err(|e| {
                        EvaluatorError::InternalError(e.to_string())
                    })?;

                let state = state.to_value_wrapper();
                let patch = Self::generate_json_patch(
                    &state.0,
                    &evaluation.final_state.0,
                )?;

                (ValueWrapper(patch), properties_hash)
            }
            EvaluateData::AllSchemasFact { state, .. } => {
                let properties_hash =
                    hash_borsh(&*self.hash.hasher(), &evaluation.final_state)
                        .map_err(|e| {
                        EvaluatorError::InternalError(e.to_string())
                    })?;

                let patch = Self::generate_json_patch(
                    &state.0,
                    &evaluation.final_state.0,
                )?;

                (ValueWrapper(patch), properties_hash)
            }
            EvaluateData::GovTransfer { state } => {
                let state = state.to_value_wrapper();   
                let properties_hash = hash_borsh(&*self.hash.hasher(), &state)
                    .map_err(|e| {
                        EvaluatorError::InternalError(e.to_string())
                    })?;
                    
                (evaluation.final_state, properties_hash)
            }
            EvaluateData::GovConfirm { state } => {
                let properties_hash =
                    hash_borsh(&*self.hash.hasher(), &evaluation.final_state)
                        .map_err(|e| {
                        EvaluatorError::InternalError(e.to_string())
                    })?;

                let state = state.to_value_wrapper();
                let patch = Self::generate_json_patch(
                    &state.0,
                    &evaluation.final_state.0,
                )?;

                (ValueWrapper(patch), properties_hash)
            }
            EvaluateData::AllSchemasTransfer {
                state, ..
            } => {
                let properties_hash =
                    hash_borsh(&*self.hash.hasher(), &state)
                        .map_err(|e| {
                            EvaluatorError::InternalError(e.to_string())
                        })?;

                (evaluation.final_state, properties_hash)
            }
        };

        Ok(EvaluationRes::Response {
            response: EvalRes {
                patch,
                properties_hash,
                appr_required: evaluation.approval_required,
            },
            eval_req_hash,
            req_subject_data_hash,
        })
    }

    fn build_response_error(
        &self,
        evaluator_error: EvaluatorError,
        evaluation_req: Signed<EvaluationReq>,
    ) -> Result<EvaluationRes, EvaluatorError> {
        match &evaluator_error {
            EvaluatorError::InvalidEventSignature
            | EvaluatorError::InvalidEventRequest(..) => {
                return Ok(EvaluationRes::Abort(evaluator_error.to_string()));
            }
            EvaluatorError::Runner(eval_runner_error) => {
                match eval_runner_error {
                    EvalRunnerError::ContractNotFound(..) => {
                        return Ok(EvaluationRes::Abort(
                            evaluator_error.to_string(),
                        ));
                    }
                    _ => {}
                }
            }
            _ => {}
        };

        let eval_req_hash =
            hash_borsh(&*self.hash.hasher(), &evaluation_req)
                .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;

        let EvaluationReq {
            event_request,
            governance_id,
            sn,
            gov_version,
            namespace,
            schema_id,
            signer,
            ..
        } = evaluation_req.content().clone();

        let req_subject_data_hash = hash_borsh(
            &*self.hash.hasher(),
            &RequestSubjectData {
                namespace,
                schema_id,
                subject_id: event_request.content().get_subject_id(),
                governance_id,
                sn,
                gov_version,
                signer,
            },
        )
        .map_err(|e| EvaluatorError::InternalError(e.to_string()))?;

        Ok(EvaluationRes::Error {
            error: evaluator_error,
            eval_req_hash,
            req_subject_data_hash,
        })
    }

    async fn create_res(
        &self,
        ctx: &mut ActorContext<EvalWorker>,
        reboot: bool,
        evaluation_req: &Signed<EvaluationReq>,
    ) -> Result<EvaluationRes, EvaluatorError> {
        let evaluation = if reboot {
            EvaluationRes::Reboot
        } else {
            match self.evaluate(ctx, evaluation_req.content()).await {
                Ok(evaluation) => {
                    self.build_response(evaluation, evaluation_req.clone())?
                }
                Err(error) => {
                    if let EvaluatorError::InternalError(..) = &error {
                        return Err(error);
                    } else {
                        self.build_response_error(
                            error,
                            evaluation_req.clone(),
                        )?
                    }
                }
            }
        };

        Ok(evaluation)
    }

    fn check_data(
        &self,
        evaluation_req: &Signed<EvaluationReq>,
    ) -> Result<(), EvaluatorError> {
        let event_is_for_gov = evaluation_req.content().data.is_gov_event();
        match (self.init_state.is_none(), event_is_for_gov) {
            (true, false) => return Err(EvaluatorError::InvalidEventRequest(
                "Evaluator is for governance but eval request is for tracker"
                    .to_owned(),
            )),
            (false, true) => return Err(EvaluatorError::InvalidEventRequest(
                "Evaluator is for tracker but eval request is for governance"
                    .to_owned(),
            )),
            _ => {}
        };

        if evaluation_req.content().governance_id != self.governance_id {
            return Err(EvaluatorError::InvalidEventRequest(format!(
                "Evaluator governance_id {} and eval request governance_id {} are different",
                self.governance_id,
                evaluation_req.content().governance_id
            )));
        }

        if evaluation_req.verify().is_err() {
            return Err(EvaluatorError::InvalidEventSignature);
        }

        if evaluation_req.content().event_request.verify().is_err() {
            return Err(EvaluatorError::InvalidEventSignature);
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum EvalWorkerMessage {
    UpdateGovVersion {
        gov_version: u64   
    },
    LocalEvaluation {
        evaluation_req: Signed<EvaluationReq>,
    },
    NetworkRequest {
        evaluation_req: Signed<EvaluationReq>,
        sender: PublicKey,
        info: ComunicateInfo,
    },
}

impl Message for EvalWorkerMessage {}

#[async_trait]
impl Actor for EvalWorker {
    type Event = ();
    type Message = EvalWorkerMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "EvalWorker", id)
        } else {
            info_span!("EvalWorker", id)
        }
    }
}

impl NotPersistentActor for EvalWorker {}

#[async_trait]
impl Handler<EvalWorker> for EvalWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: EvalWorkerMessage,
        ctx: &mut ActorContext<EvalWorker>,
    ) -> Result<(), ActorError> {
        match msg {
            EvalWorkerMessage::UpdateGovVersion { gov_version } => {
                self.gov_version = gov_version;
            }
            EvalWorkerMessage::LocalEvaluation { evaluation_req } => {
                let evaluation =
                    match self.create_res(ctx, false, &evaluation_req).await {
                        Ok(eval) => eval,
                        Err(e) => {
                            error!(
                                msg_type = "LocalEvaluation",
                                error = %e,
                                "Failed to create evaluation response"
                            );
                            return Err(emit_fail(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: e.to_string(),
                                },
                            )
                            .await);
                        }
                    };

                let signature = match get_sign(
                    ctx,
                    SignTypesNode::EvaluationRes(evaluation.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            msg_type = "LocalEvaluation",
                            error = %e,
                            "Failed to sign evaluator response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                match ctx.get_parent::<Evaluation>().await {
                    Ok(evaluation_actor) => {
                        if let Err(e) = evaluation_actor
                            .tell(EvaluationMessage::Response {
                                evaluation_res: evaluation.clone(),
                                sender: (*self.our_key).clone(),
                                signature: Some(signature),
                            })
                            .await
                        {
                            error!(
                                msg_type = "LocalEvaluation",
                                error = %e,
                                "Failed to send response to evaluation actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }

                        debug!(
                            msg_type = "LocalEvaluation",
                            "Local evaluation completed successfully"
                        );
                    }
                    Err(e) => {
                        error!(
                            msg_type = "LocalEvaluation",
                            path = %ctx.path().parent(),
                            "Evaluation actor not found"
                        );
                        return Err(e);
                    }
                }

                ctx.stop(None).await;
            }
            EvalWorkerMessage::NetworkRequest {
                evaluation_req,
                info,
                sender,
            } => {
                if sender != evaluation_req.signature().signer
                    || sender != self.node_key
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_sender = %self.node_key,
                        received_sender = %sender,
                        signer = %evaluation_req.signature().signer,
                        "Unexpected sender"
                    );
                    if self.stop {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                // TODO MUCHO CUIDADO COn esto
                let reboot = match self
                    .check_governance(evaluation_req.content().gov_version)
                    .await
                {
                    Ok(reboot) => reboot,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to check governance"
                        );
                        if let ActorError::Functional { .. } = e {
                            if self.stop {
                                ctx.stop(None).await;
                            }
                            return Err(e);
                        } else {
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                let evaluation = if let Err(error) =
                    self.check_data(&evaluation_req)
                {
                    match self
                        .build_response_error(error, evaluation_req.clone())
                    {
                        Ok(eval) => eval,
                        Err(e) => {
                            error!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Failed to build error response"
                            );
                            return Err(emit_fail(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: e.to_string(),
                                },
                            )
                            .await);
                        }
                    }
                } else {
                    match self.create_res(ctx, reboot, &evaluation_req).await {
                        Ok(eval) => eval,
                        Err(e) => {
                            error!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Internal error during evaluation"
                            );
                            return Err(emit_fail(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: e.to_string(),
                                },
                            )
                            .await);
                        }
                    }
                };

                let signature = match get_sign(
                    ctx,
                    SignTypesNode::EvaluationRes(evaluation.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to sign response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    request_id: info.request_id.clone(),
                    version: info.version,
                    receiver_actor: format!(
                        "/user/request/{}/evaluation/{}",
                        evaluation_req
                            .content()
                            .event_request
                            .content()
                            .get_subject_id(),
                        self.our_key.clone()
                    ),
                };

                let signed_response: Signed<EvaluationRes> =
                    Signed::from_parts(evaluation, signature);
                if let Err(e) = self
                    .network
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::EvaluationRes {
                                res: signed_response,
                            },
                        },
                    })
                    .await
                {
                    error!(
                        msg_type = "NetworkRequest",
                        error = %e,
                        "Failed to send response to network"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkRequest",
                    request_id = %info.request_id,
                    version = info.version,
                    sender = %sender,
                    "Network evaluation request processed successfully"
                );

                if self.stop {
                    ctx.stop(None).await;
                }
            }
        }

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<EvalWorker>,
    ) -> ChildAction {
        error!(
            governance_id = %self.governance_id,
            gov_version = self.gov_version,
            sn = self.sn,
            node_key = %self.node_key,
            error = %error,
            "Child fault in evaluation worker"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
