use std::{collections::HashSet, sync::Arc};

use crate::{
    approval::response::ApprovalRes,
    evaluation::response::EvaluationRes,
    governance::{
        data::GovernanceData,
        model::Quorum,
        roles_register::{RoleDataRegister, SearchRole},
    },
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{
        common::{
            check_quorum_signers, emit_fail, get_actual_roles_register,
            get_validation_roles_register,
            node::{
                SignTypesNode, UpdateData, get_sign, update_ledger_network,
            },
        },
        event::{ApprovalData, EvaluationData, EvaluationResponse},
        request::EventRequestType,
    },
    subject::{Metadata, RequestSubjectData},
    validation::{
        request::{ActualProtocols, LastData},
        response::ValidatorError,
    },
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::{
    SchemaType, ValueWrapper,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
    request::EventRequest,
};

use json_patch::{Patch, patch};
use network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, NotPersistentActor,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Validation, ValidationMessage, request::ValidationReq,
    response::ValidationRes,
};

/// A struct representing a ValiWorker actor.
#[derive(Clone, Debug)]
pub struct ValiWorker {
    pub node_key: PublicKey,
    pub our_key: Arc<PublicKey>,
    pub init_state: Option<ValueWrapper>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub sn: u64,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
}

impl ValiWorker {
    async fn check_governance(
        &self,
        ctx: &mut ActorContext<ValiWorker>,
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
                update_ledger_network(ctx, data).await?;
                let e = ActorError::Functional {
                    description: "Abort Validation, update is required"
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

    fn check_data(
        &self,
        validation_req: &Signed<ValidationReq>,
    ) -> Result<(), ValidatorError> {
        if !validation_req.content().is_valid() {
            return Err(ValidatorError::InvalidData {
                value: "validation request",
            });
        }

        let governance_id = validation_req
            .content()
            .get_governance_id()
            .map_err(|_| ValidatorError::InvalidData {
                value: "governance_id",
            })?;

        if governance_id != self.governance_id {
            return Err(ValidatorError::InvalidData {
                value: "governance_id",
            });
        }

        if validation_req.verify().is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "validation request",
            });
        }

        if validation_req
            .content()
            .get_signed_event_request()
            .verify()
            .is_err()
        {
            return Err(ValidatorError::InvalidSignature {
                data: "event request",
            });
        }

        Ok(())
    }

    fn check_metadata(
        event_type: &EventRequestType,
        metadata: &Metadata,
        gov_version: u64,
    ) -> Result<(), ValidatorError> {
        let is_gov = metadata.schema_id.is_gov();

        if let Some(name) = &metadata.name
            && (name.is_empty() || name.len() > 100)
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata name",
            });
        }

        if let Some(description) = &metadata.description
            && (description.is_empty() || description.len() > 200)
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata description",
            });
        }

        if metadata.subject_id.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata subject_id",
            });
        }

        if is_gov && !metadata.governance_id.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata governance_id",
            });
        } else if !is_gov && metadata.governance_id.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata governance_id",
            });
        }

        if is_gov && metadata.genesis_gov_version != 0 {
            return Err(ValidatorError::InvalidData {
                value: "metadata genesis_gov_version",
            });
        } else if !is_gov && metadata.genesis_gov_version == 0 {
            return Err(ValidatorError::InvalidData {
                value: "metadata genesis_gov_version",
            });
        }

        if metadata.genesis_gov_version > gov_version {
            return Err(ValidatorError::InvalidData {
                value: "metadata genesis_gov_version",
            });
        }

        if metadata.sn == 0 && !metadata.prev_ledger_event_hash.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata prev_ledger_event_hash",
            });
        } else if metadata.sn != 0 && metadata.prev_ledger_event_hash.is_empty()
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata prev_ledger_event_hash",
            });
        }

        match &metadata.schema_id {
            SchemaType::Type(schema_id) => {
                if schema_id.is_empty() {
                    return Err(ValidatorError::InvalidData {
                        value: "metadata schema_id",
                    });
                }
            }
            SchemaType::AllSchemas => {
                return Err(ValidatorError::InvalidData {
                    value: "metadata schema_id",
                });
            }
            _ => {}
        };

        if is_gov && !metadata.namespace.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata namespace",
            });
        }

        if metadata.creator.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata creator",
            });
        }

        if metadata.owner.is_empty() {
            return Err(ValidatorError::InvalidData {
                value: "metadata owner",
            });
        }

        if let Some(new_owner) = &metadata.new_owner {
            if new_owner.is_empty() || new_owner == &metadata.owner {
                return Err(ValidatorError::InvalidData {
                    value: "metadata new owner",
                });
            }
        };

        if !metadata.active {
            return Err(ValidatorError::InvalidData {
                value: "metadata active",
            });
        }

        match event_type {
            EventRequestType::Create => {
                return Err(ValidatorError::InvalidData {
                    value: "Event request type",
                });
            }
            EventRequestType::Confirm | EventRequestType::Reject => {
                if metadata.new_owner.is_none() {
                    return Err(ValidatorError::InvalidData {
                        value: "Event request type",
                    });
                }
            }
            EventRequestType::Fact
            | EventRequestType::Transfer
            | EventRequestType::EOL => {
                if metadata.new_owner.is_some() {
                    return Err(ValidatorError::InvalidData {
                        value: "Event request type",
                    });
                }
            }
        };

        Ok(())
    }

    fn check_basic_data(
        request: &Signed<EventRequest>,
        metadata: &Metadata,
        vali_req_signer: &PublicKey,
        gov_version: u64,
        sn: u64,
    ) -> Result<(), ValidatorError> {
        // // Check event request.

        // todo mover a check
        if request.verify().is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "event request",
            });
        }

        Self::check_metadata(
            &EventRequestType::from(request.content()),
            metadata,
            gov_version,
        )?;

        if !request.content().check_request_signature(
            &request.signature().signer,
            &metadata.owner,
            &metadata.new_owner,
        ) {
            return Err(ValidatorError::InvalidSigner {
                signer: request.signature().signer.to_string(),
            });
        }

        // subject
        if request.content().get_subject_id() != metadata.subject_id {
            return Err(ValidatorError::InvalidData {
                value: "Subject_id",
            });
        }

        // vali request signer
        let signer = if let Some(new_owner) = metadata.new_owner.clone() {
            new_owner
        } else {
            metadata.owner.clone()
        };

        if &signer != vali_req_signer {
            return Err(ValidatorError::InvalidSigner {
                signer: vali_req_signer.to_string(),
            });
        }

        // sn
        if sn != metadata.sn + 1 {
            return Err(ValidatorError::InvalidData { value: "sn" });
        }
        Ok(())
    }

    fn check_approval_signers(
        agrees: &HashSet<PublicKey>,
        disagrees: &HashSet<PublicKey>,
        timeout: &HashSet<PublicKey>,
        workers: &HashSet<PublicKey>,
    ) -> bool {
        agrees.is_subset(workers)
            && disagrees.is_subset(workers)
            && timeout.is_subset(workers)
    }

    fn check_approval_quorum(
        agrees: u32,
        timeout: u32,
        quorum: &Quorum,
        workers: &HashSet<PublicKey>,
        approved: bool,
    ) -> bool {
        quorum.check_quorum(workers.len() as u32, agrees + timeout) && approved
    }

    fn check_approval(
        approval: ApprovalData,
        appr_data: RoleDataRegister,
        req_subject_data_hash: DigestIdentifier,
        signer: PublicKey,
    ) -> Result<(), ValidatorError> {
        if signer != approval.approval_req_signature.signer {
            return Err(ValidatorError::InvalidSigner {
                signer: signer.to_string(),
            });
        }

        let agrees = approval
            .approvers_agrees_signatures
            .iter()
            .map(|x| x.signer.clone())
            .collect::<HashSet<PublicKey>>();

        let timeout = approval
            .approvers_timeout
            .iter()
            .map(|x| x.who.clone())
            .collect::<HashSet<PublicKey>>();

        let disagrees = approval
            .approvers_disagrees_signatures
            .iter()
            .map(|x| x.signer.clone())
            .collect::<HashSet<PublicKey>>();

        if !Self::check_approval_signers(
            &agrees,
            &disagrees,
            &timeout,
            &appr_data.workers,
        ) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval signers",
            });
        }

        if !Self::check_approval_quorum(
            agrees.len() as u32,
            timeout.len() as u32,
            &appr_data.quorum,
            &appr_data.workers,
            approval.approved,
        ) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify approval quorum",
            });
        }

        let agrees_res = ApprovalRes::Response {
            approval_req_hash: approval.approval_req_hash.clone(),
            agrees: true,
            req_subject_data_hash: req_subject_data_hash.clone(),
        };
        for signature in approval.approvers_agrees_signatures.iter() {
            let signed_res =
                Signed::from_parts(agrees_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "approval agrees signature",
                });
            }
        }

        let disagrees_res = ApprovalRes::Response {
            approval_req_hash: approval.approval_req_hash.clone(),
            agrees: false,
            req_subject_data_hash,
        };
        for signature in approval.approvers_disagrees_signatures.iter() {
            let signed_res =
                Signed::from_parts(disagrees_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "approval disagrees signature",
                });
            }
        }

        Ok(())
    }

    fn check_evaluation(
        &self,
        evaluation: EvaluationData,
        eval_data: RoleDataRegister,
        mut properties: ValueWrapper,
        req_subject_data_hash: DigestIdentifier,
        signer: PublicKey,
    ) -> Result<(bool, ValueWrapper), ValidatorError> {
        if signer != evaluation.eval_req_signature.signer {
            return Err(ValidatorError::InvalidSigner {
                signer: signer.to_string(),
            });
        }

        if !check_quorum_signers(
            &evaluation
                .evaluators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &eval_data.quorum,
            &eval_data.workers,
        ) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify evaluation quorum",
            });
        }

        let eval_res = match evaluation.response.clone() {
            EvaluationResponse::Ok(evaluator_response) => {
                EvaluationRes::Response {
                    response: evaluator_response,
                    eval_req_hash: evaluation.eval_req_hash.clone(),
                    req_subject_data_hash,
                }
            }
            EvaluationResponse::Error(evaluator_error) => {
                EvaluationRes::Error {
                    error: evaluator_error,
                    eval_req_hash: evaluation.eval_req_hash.clone(),
                    req_subject_data_hash,
                }
            }
        };

        for signature in evaluation.evaluators_signatures.iter() {
            let signed_res =
                Signed::from_parts(eval_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "evaluation signature",
                });
            }
        }

        let appr_required = if let Some(evaluator_res) =
            evaluation.evaluator_res()
        {
            let json_patch =
                serde_json::from_value::<Patch>(evaluator_res.patch.0)
                    .map_err(|_| ValidatorError::InvalidData {
                        value: "evaluation patch",
                    })?;

            patch(&mut properties.0, &json_patch).map_err(|_| {
                ValidatorError::InvalidOperation {
                    action: "apply patch",
                }
            })?;

            let properties_hash = hash_borsh(&*self.hash.hasher(), &properties)
                .map_err(|e| ValidatorError::InternalError {
                    problem: e.to_string(),
                })?;

            if properties_hash != evaluator_res.properties_hash {
                return Err(ValidatorError::InvalidData {
                    value: "properties_hash",
                });
            }

            evaluator_res.appr_required
        } else {
            false
        };

        Ok((appr_required, properties))
    }

    async fn check_actual_protocols(
        &self,
        ctx: &mut ActorContext<ValiWorker>,
        metadata: &Metadata,
        actual_protocols: &ActualProtocols,
        event_type: &EventRequestType,
        gov_version: u64,
        signer: PublicKey,
    ) -> Result<Option<ValueWrapper>, ValidatorError> {
        if !actual_protocols
            .check_protocols(metadata.schema_id.is_gov(), event_type)
        {
            return Err(ValidatorError::InvalidData {
                value: "actual protocols",
            });
        }

        let (evaluation, approval) = match &actual_protocols {
            ActualProtocols::None => (None, None),
            ActualProtocols::Eval { eval_data } => {
                (Some(eval_data.clone()), None)
            }
            ActualProtocols::EvalApprove {
                eval_data,
                approval_data,
            } => (Some(eval_data.clone()), Some(approval_data.clone())),
        };

        let properties = if let Some(evaluation) = evaluation {
            let req_subject_data_hash = hash_borsh(
                &*self.hash.hasher(),
                &RequestSubjectData {
                    subject_id: metadata.subject_id.clone(),
                    governance_id: metadata.governance_id.clone(),
                    sn: metadata.sn + 1,
                    namespace: metadata.namespace.clone(),
                    schema_id: metadata.schema_id.clone(),
                    gov_version: gov_version,
                    signer: signer.clone(),
                },
            )
            .map_err(|e| ValidatorError::InternalError {
                problem: e.to_string(),
            })?;

            let (eval_data, appro_data) = get_actual_roles_register(
                ctx,
                &metadata.governance_id.to_string(),
                SearchRole {
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                },
                approval.is_some(),
                gov_version,
            )
            .await
            .map_err(|e| {
                if let ActorError::UnexpectedResponse { .. } = e {
                    ValidatorError::InvalidData {
                        value: "gov_version",
                    }
                } else {
                    ValidatorError::InternalError {
                        problem: e.to_string(),
                    }
                }
            })?;

            let (appr_required, properties) = self.check_evaluation(
                evaluation,
                eval_data,
                metadata.properties.clone(),
                req_subject_data_hash.clone(),
                signer.clone(),
            )?;

            if let Some(approval) = approval
                && let Some(appr_data) = appro_data
            {
                if !appr_required {
                    return Err(ValidatorError::InvalidData {
                        value: "evaluation appr_required",
                    });
                }

                Self::check_approval(
                    approval,
                    appr_data,
                    req_subject_data_hash,
                    signer,
                )?;
            } else if appr_required {
                return Err(ValidatorError::InvalidData {
                    value: "evaluation appr_required",
                });
            }

            Some(properties)
        } else {
            None
        };

        Ok(properties)
    }

    async fn check_last_vali_data(
        &self,
        ctx: &mut ActorContext<ValiWorker>,
        metadata: &Metadata,
        last_validation: &LastData,
    ) -> Result<(), ValidatorError> {
        let vali_data = get_validation_roles_register(
            ctx,
            &metadata.governance_id.to_string(),
            SearchRole {
                schema_id: metadata.schema_id.clone(),
                namespace: metadata.namespace.clone(),
            },
            last_validation.gov_version,
        )
        .await
        .map_err(|e| {
            if let ActorError::UnexpectedResponse { .. } = e {
                ValidatorError::InvalidData {
                    value: "gov_version",
                }
            } else {
                ValidatorError::InternalError {
                    problem: e.to_string(),
                }
            }
        })?;

        if !check_quorum_signers(
            &last_validation
                .vali_data
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &vali_data.quorum,
            &vali_data.workers,
        ) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify validation quorum",
            });
        }

        let vali_req_hash =
            last_validation.vali_data.validation_req_hash.clone();
        let vali_res = if metadata.sn == 0 {
            ValidationRes::Create {
                vali_req_hash,
                subject_metadata: metadata.clone(),
            }
        } else {
            let hash_metadata =
                hash_borsh(&*self.hash.hasher(), &metadata.clone()).map_err(
                    |e| ValidatorError::InternalError {
                        problem: e.to_string(),
                    },
                )?;

            ValidationRes::Response {
                vali_req_hash,
                modified_metadata_hash: hash_metadata,
            }
        };

        for signature in last_validation.vali_data.validators_signatures.iter()
        {
            let signed_res =
                Signed::from_parts(vali_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "evaluation signature",
                });
            }
        }

        Ok(())
    }

    fn create_modified_metadata(
        is_success: bool,
        event_request: &EventRequest,
        properties: Option<ValueWrapper>,
        mut metadata: Metadata,
    ) -> Result<Metadata, ValidatorError> {
        metadata.sn += 1;

        if !is_success {
            return Ok(metadata);
        }

        match event_request {
            EventRequest::Create(..) => {
                return Err(ValidatorError::InvalidData {
                    value: "Event request type",
                });
            }
            EventRequest::Fact(..) => {
                if let Some(properties) = properties {
                    metadata.properties = properties;
                }
            }
            EventRequest::Transfer(transfer_request) => {
                metadata.new_owner = Some(transfer_request.new_owner.clone());
            }
            EventRequest::Confirm(..) => {
                if let Some(new_owner) = metadata.new_owner.take() {
                    metadata.owner = new_owner;
                } else {
                    return Err(ValidatorError::InvalidData {
                        value: "new owner",
                    });
                }

                if let Some(properties) = properties {
                    metadata.properties = properties;
                }
            }
            EventRequest::Reject(..) => metadata.new_owner = None,
            EventRequest::EOL(..) => metadata.active = false,
        }

        Ok(metadata)
    }

    async fn create_res(
        &self,
        ctx: &mut ActorContext<ValiWorker>,
        reboot: bool,
        validation_req: &Signed<ValidationReq>,
    ) -> Result<ValidationRes, ValidatorError> {
        if reboot {
            Ok(ValidationRes::Reboot)
        } else {
            match validation_req.content() {
                ValidationReq::Create {
                    event_request,
                    gov_version,
                } => {
                    // todo Check is valid en check_data
                    if let EventRequest::Create(create) =
                        event_request.content()
                    {
                        if let Some(name) = &create.name
                            && (name.is_empty() || name.len() > 100)
                        {
                            return Err(ValidatorError::InvalidData {
                                value: "create event name",
                            });
                        }

                        if let Some(description) = &create.description
                            && (description.is_empty()
                                || description.len() > 200)
                        {
                            return Err(ValidatorError::InvalidData {
                                value: "create event description",
                            });
                        }

                        let subject_id =
                            hash_borsh(&*self.hash.hasher(), &event_request)
                                .map_err(|e| ValidatorError::InternalError {
                                    problem: e.to_string(),
                                })?;

                        let init_state =
                            if let Some(init_state) = &self.init_state {
                                init_state.clone()
                            } else {
                                let governance_data = GovernanceData::new(
                                    validation_req.signature().signer.clone(),
                                );

                                governance_data.to_value_wrapper()
                            };

                        let subject_metadata = Metadata {
                            name: create.name.clone(),
                            description: create.description.clone(),
                            subject_id: subject_id,
                            governance_id: create.governance_id.clone(),
                            genesis_gov_version: *gov_version,
                            prev_ledger_event_hash: DigestIdentifier::default(),
                            schema_id: create.schema_id.clone(),
                            namespace: create.namespace.clone(),
                            sn: 0,
                            creator: validation_req.signature().signer.clone(),
                            owner: validation_req.signature().signer.clone(),
                            new_owner: None,
                            active: true,
                            properties: init_state,
                        };

                        let vali_req_hash =
                            hash_borsh(&*self.hash.hasher(), &validation_req)
                                .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                        Ok(ValidationRes::Create {
                            vali_req_hash,
                            subject_metadata,
                        })
                    } else {
                        Err(ValidatorError::InvalidData {
                            value: "event type",
                        })
                    }
                }
                ValidationReq::Event {
                    actual_protocols,
                    event_request,
                    metadata,
                    last_data,
                    gov_version,
                    sn,
                    ..
                } => {
                    let signer = validation_req.signature().signer.clone();
                    Self::check_basic_data(
                        event_request,
                        metadata,
                        &signer,
                        *gov_version,
                        *sn,
                    )?;

                    let properties = self
                        .check_actual_protocols(
                            ctx,
                            metadata,
                            actual_protocols,
                            &EventRequestType::from(event_request.content()),
                            *gov_version,
                            signer,
                        )
                        .await?;

                    self.check_last_vali_data(ctx, metadata, last_data).await?;

                    let is_success = actual_protocols.is_success();

                    let modified_metadata = Self::create_modified_metadata(
                        is_success,
                        &event_request.content(),
                        properties,
                        metadata.clone(),
                    )?;

                    let vali_req_hash =
                        hash_borsh(&*self.hash.hasher(), &validation_req)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                    let modified_metadata_hash =
                        hash_borsh(&*self.hash.hasher(), &modified_metadata)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                    Ok(ValidationRes::Response {
                        vali_req_hash,
                        modified_metadata_hash,
                    })
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValiWorkerMessage {
    LocalValidation {
        validation_req: Signed<ValidationReq>,
    },
    NetworkRequest {
        validation_req: Signed<ValidationReq>,
        sender: PublicKey,
        info: ComunicateInfo,
    },
}

impl Message for ValiWorkerMessage {}

#[async_trait]
impl Actor for ValiWorker {
    type Event = ();
    type Message = ValiWorkerMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "ValiWorker", id = id)
        } else {
            info_span!("ValiWorker", id = id)
        }
    }
}

impl NotPersistentActor for ValiWorker {}

#[async_trait]
impl Handler<ValiWorker> for ValiWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ValiWorkerMessage,
        ctx: &mut ActorContext<ValiWorker>,
    ) -> Result<(), ActorError> {
        match msg {
            ValiWorkerMessage::LocalValidation { validation_req } => {
                let validation =
                    match self.create_res(ctx, false, &validation_req).await {
                        Ok(vali) => vali,
                        Err(e) => {
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
                    SignTypesNode::ValidationRes(validation.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            msg_type = "LocalValidation",
                            error = %e,
                            "Failed to sign validator response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                // Valiuatiob path.
                let validation_path = ctx.path().parent();

                let validation_actor: Option<ActorRef<Validation>> =
                    ctx.system().get_actor(&validation_path).await;

                // Send response of validation to parent
                if let Some(validation_actor) = validation_actor {
                    validation_actor
                        .tell(ValidationMessage::Response {
                            validation_res: validation,
                            sender: (*self.our_key).clone(),
                            signature: Some(signature),
                        })
                        .await?;

                    debug!(
                        msg_type = "LocalValidation",
                        "Validation completed and sent to parent"
                    );
                } else {
                    error!(
                        msg_type = "LocalValidation",
                        "Failed to obtain Validation actor"
                    );
                    return Err(ActorError::NotFound {
                        path: validation_path,
                    });
                }

                ctx.stop(None).await;
            }
            ValiWorkerMessage::NetworkRequest {
                validation_req,
                info,
                sender,
            } => {
                if sender != validation_req.signature().signer
                    || sender != self.node_key
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_sender = %self.node_key,
                        received_sender = %sender,
                        signer = %validation_req.signature().signer,
                        "Unexpected sender"
                    );
                    if self.init_state.is_some() {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                // TODO MUCHO CUIDADO COn esto
                let reboot = match self
                    .check_governance(
                        ctx,
                        validation_req.content().get_gov_version(),
                    )
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
                            if self.init_state.is_some() {
                                ctx.stop(None).await;
                            }

                            return Err(e);
                        } else {
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                let validation = if let Err(error) =
                    self.check_data(&validation_req)
                {
                    ValidationRes::Abort(error.to_string())
                } else {
                    match self.create_res(ctx, reboot, &validation_req).await {
                        Ok(vali) => vali,
                        Err(e) => {
                            if let ValidatorError::InternalError { .. } = e {
                                error!(
                                    msg_type = "NetworkRequest",
                                    error = %e,
                                    "Internal error during validation"
                                );

                                return Err(emit_fail(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: e.to_string(),
                                    },
                                )
                                .await);
                            }
                            ValidationRes::Abort(e.to_string())
                        }
                    }
                };

                let signature = match get_sign(
                    ctx,
                    SignTypesNode::ValidationRes(validation.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to sign validation response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let new_info = ComunicateInfo {
                    receiver: sender,
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/node/{}/validation/{}",
                        validation_req
                            .content()
                            .get_signed_event_request()
                            .content()
                            .get_subject_id(),
                        self.our_key.clone()
                    ),
                };

                let signed_response: Signed<ValidationRes> =
                    Signed::from_parts(validation, signature);
                if let Err(e) = self
                    .network
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info.clone(),
                            message: ActorMessage::ValidationRes {
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
                } else {
                    debug!(
                        msg_type = "NetworkRequest",
                        receiver = %new_info.receiver,
                        request_id = %new_info.request_id,
                        "Validation response sent to network"
                    );
                }

                if self.init_state.is_some() {
                    ctx.stop(None).await;
                }
            }
        }

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<ValiWorker>,
    ) -> ChildAction {
        error!(error = %error, "Child fault occurred");
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
