use std::{collections::HashSet, sync::Arc};

use crate::{
    approval::response::ApprovalRes,
    evaluation::response::EvaluationResult,
    governance::{
        data::GovernanceData,
        model::Quorum,
        role_register::{RoleDataRegister, SearchRole},
    },
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{
        common::{
            check_quorum_signers, emit_fail, get_actual_roles_register,
            get_validation_roles_register,
            node::{SignTypesNode, get_sign},
        },
        event::{
            ApprovalData, EvaluationData, EvaluationResponse,
            ValidationMetadata,
        },
    },
    subject::{Metadata, MetadataWithoutProperties, RequestSubjectData},
    validation::{
        request::{ActualProtocols, LastData},
        response::ValidatorError,
    },
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::{
    ValueWrapper,
    bridge::request::EventRequestType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
    request::EventRequest,
};
use borsh::{BorshDeserialize, BorshSerialize};

use ave_network::ComunicateInfo;
use json_patch::{Patch, patch};
use std::collections::BTreeSet;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Validation, ValidationMessage, request::ValidationReq,
    response::ValidationRes,
};

/// A struct representing a ValiWorker actor.
#[derive(
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct CurrentRequestRoles {
    pub evaluation: RoleDataRegister,
    pub approval: RoleDataRegister,
}

#[derive(Clone, Debug)]
pub struct CurrentWorkerRoles {
    pub evaluation: RoleDataRegister,
    pub approval: RoleDataRegister,
}

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
    pub current_roles: CurrentWorkerRoles,
    pub stop: bool,
}

impl ValiWorker {
    fn event_request_hash(
        &self,
        event_request: &Signed<EventRequest>,
    ) -> Result<DigestIdentifier, ValidatorError> {
        hash_borsh(&*self.hash.hasher(), event_request).map_err(|e| {
            ValidatorError::InternalError {
                problem: e.to_string(),
            }
        })
    }

    fn viewpoints_hash(
        &self,
        event_request: &EventRequest,
    ) -> Result<DigestIdentifier, ValidatorError> {
        let viewpoints = match event_request {
            EventRequest::Fact(fact_request) => fact_request.viewpoints.clone(),
            _ => BTreeSet::new(),
        };

        hash_borsh(&*self.hash.hasher(), &viewpoints).map_err(|e| {
            ValidatorError::InternalError {
                problem: e.to_string(),
            }
        })
    }

    fn current_evaluation_roles(&self) -> RoleDataRegister {
        self.current_roles.evaluation.clone()
    }

    fn current_approval_roles(&self) -> RoleDataRegister {
        self.current_roles.approval.clone()
    }

    async fn check_governance(
        &self,
        gov_version: u64,
    ) -> Result<bool, ActorError> {
        match self.gov_version.cmp(&gov_version) {
            std::cmp::Ordering::Less => {
                warn!(
                    local_gov_version = self.gov_version,
                    request_gov_version = gov_version,
                    governance_id = %self.governance_id,
                    sender = %self.node_key,
                    "Received request with a higher governance version; ignoring request"
                );
                Err(ActorError::Functional {
                    description:
                        "Abort validation, request governance version is higher than local"
                            .to_owned(),
                })
            }
            std::cmp::Ordering::Equal => {
                // If it is the same it means that we have the latest version of governance, we are up to date.
                Ok(false)
            }
            std::cmp::Ordering::Greater => Ok(true),
        }
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

        if is_gov && metadata.governance_id != metadata.subject_id
            || !is_gov && metadata.governance_id == metadata.subject_id
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata governance_id",
            });
        }

        if is_gov && metadata.genesis_gov_version != 0
            || !is_gov && metadata.genesis_gov_version == 0
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata genesis_gov_version",
            });
        }

        if metadata.genesis_gov_version > gov_version {
            return Err(ValidatorError::InvalidData {
                value: "metadata genesis_gov_version",
            });
        }

        if metadata.sn == 0 && !metadata.prev_ledger_event_hash.is_empty()
            || metadata.sn != 0 && metadata.prev_ledger_event_hash.is_empty()
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata prev_ledger_event_hash",
            });
        };

        if !metadata.schema_id.is_valid_in_request() {
            return Err(ValidatorError::InvalidData {
                value: "metadata schema_id",
            });
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

        if let Some(new_owner) = &metadata.new_owner
            && (new_owner.is_empty() || new_owner == &metadata.owner)
        {
            return Err(ValidatorError::InvalidData {
                value: "metadata new owner",
            });
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
            | EventRequestType::Eol => {
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
        // Check event request.

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
        let signer = metadata
            .new_owner
            .clone()
            .unwrap_or_else(|| metadata.owner.clone());

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
        if approved {
            quorum.check_quorum(workers.len() as u32, agrees + timeout)
        } else {
            !quorum.check_quorum(workers.len() as u32, agrees + timeout)
        }
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
                    data: "approval agrees",
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
                    data: "approval disagrees",
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

        let (eval_result, result_hash) = match evaluation.response.clone() {
            EvaluationResponse::Ok {
                result,
                result_hash,
            } => (
                EvaluationResult::Ok {
                    response: result,
                    eval_req_hash: evaluation.eval_req_hash.clone(),
                    req_subject_data_hash,
                },
                result_hash,
            ),
            EvaluationResponse::Error {
                result,
                result_hash,
            } => (
                EvaluationResult::Error {
                    error: result,
                    eval_req_hash: evaluation.eval_req_hash.clone(),
                    req_subject_data_hash,
                },
                result_hash,
            ),
        };

        let eval_result_hash = hash_borsh(&*self.hash.hasher(), &eval_result)
            .map_err(|e| ValidatorError::InternalError {
            problem: e.to_string(),
        })?;

        if eval_result_hash != result_hash {
            return Err(ValidatorError::InvalidData {
                value: "eval result hash",
            });
        }

        for signature in evaluation.evaluators_signatures.iter() {
            if signature.verify(&eval_result_hash).is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "evaluation",
                });
            }
        }

        let appr_required = if let Some(evaluator_res) =
            evaluation.evaluator_response_ok()
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
        ctx: &mut ActorContext<Self>,
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
                    gov_version,
                    signer: signer.clone(),
                },
            )
            .map_err(|e| ValidatorError::InternalError {
                problem: e.to_string(),
            })?;

            let (eval_data, appro_data) = if gov_version == self.gov_version {
                (
                    self.current_evaluation_roles(),
                    approval.as_ref().map(|_| self.current_approval_roles()),
                )
            } else {
                get_actual_roles_register(
                    ctx,
                    &metadata.governance_id,
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
                        ValidatorError::OutOfVersion
                    } else {
                        ValidatorError::InternalError {
                            problem: e.to_string(),
                        }
                    }
                })?
            };

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
        ctx: &mut ActorContext<Self>,
        metadata: &Metadata,
        last_validation: &LastData,
    ) -> Result<(), ValidatorError> {
        let vali_data = get_validation_roles_register(
            ctx,
            &metadata.governance_id,
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
                subject_metadata: Box::new(metadata.clone()),
            }
        } else {
            let ValidationMetadata::ModifiedHash {
                event_request_hash,
                viewpoints_hash,
                ..
            } = &last_validation.vali_data.validation_metadata
            else {
                return Err(ValidatorError::InvalidData {
                    value: "last validation metadata",
                });
            };

            let meta_wo_props =
                MetadataWithoutProperties::from(metadata.clone());
            let meta_wo_props_hash =
                hash_borsh(&*self.hash.hasher(), &meta_wo_props).map_err(
                    |e| ValidatorError::InternalError {
                        problem: e.to_string(),
                    },
                )?;

            let propierties_hash =
                hash_borsh(&*self.hash.hasher(), &metadata.properties)
                    .map_err(|e| ValidatorError::InternalError {
                        problem: e.to_string(),
                    })?;

            ValidationRes::Response {
                vali_req_hash,
                modified_metadata_without_propierties_hash: meta_wo_props_hash,
                propierties_hash,
                event_request_hash: event_request_hash.clone(),
                viewpoints_hash: viewpoints_hash.clone(),
            }
        };

        for signature in last_validation.vali_data.validators_signatures.iter()
        {
            let signed_res =
                Signed::from_parts(vali_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "last validation",
                });
            }
        }

        Ok(())
    }

    fn create_modified_metadata(
        is_success: bool,
        event_request: &EventRequest,
        properties: Option<ValueWrapper>,
        ledger_hash: DigestIdentifier,
        mut metadata: Metadata,
    ) -> Result<Metadata, ValidatorError> {
        metadata.sn += 1;

        metadata.prev_ledger_event_hash = ledger_hash;

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

        if metadata.schema_id.is_gov() {
            let mut gov_data =
                serde_json::from_value::<GovernanceData>(metadata.properties.0)
                    .map_err(|_| ValidatorError::InvalidData {
                        value: "metadata properties",
                    })?;

            gov_data.version += 1;
            metadata.properties = gov_data.to_value_wrapper();
        }

        Ok(metadata)
    }

    async fn create_res(
        &self,
        ctx: &mut ActorContext<Self>,
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
                    subject_id,
                } => {
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

                        if !create.schema_id.is_valid_in_request() {
                            return Err(ValidatorError::InvalidData {
                                value: "create event schema_id",
                            });
                        }

                        if create.schema_id.is_gov() {
                            if !create.governance_id.is_empty() {
                                return Err(ValidatorError::InvalidData {
                                    value: "create event governance_id",
                                });
                            }

                            if !create.namespace.is_empty() {
                                return Err(ValidatorError::InvalidData {
                                    value: "create event namespace",
                                });
                            }
                        } else if create.governance_id.is_empty() {
                            return Err(ValidatorError::InvalidData {
                                value: "create event governance_id",
                            });
                        }

                        let subject_id_worker =
                            hash_borsh(&*self.hash.hasher(), &event_request)
                                .map_err(|e| ValidatorError::InternalError {
                                    problem: e.to_string(),
                                })?;

                        if subject_id != &subject_id_worker {
                            return Err(ValidatorError::InvalidData {
                                value: "subject_id",
                            });
                        }

                        let init_state = self.init_state.as_ref().map_or_else(
                            || {
                                let governance_data = GovernanceData::new(
                                    validation_req.signature().signer.clone(),
                                );

                                governance_data.to_value_wrapper()
                            },
                            |init_state| init_state.clone(),
                        );

                        let governance_id = if create.schema_id.is_gov() {
                            subject_id.clone()
                        } else {
                            create.governance_id.clone()
                        };

                        let subject_metadata = Metadata {
                            name: create.name.clone(),
                            description: create.description.clone(),
                            subject_id: subject_id_worker,
                            governance_id,
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
                            subject_metadata: Box::new(subject_metadata),
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
                    ledger_hash,
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
                        event_request.content(),
                        properties,
                        ledger_hash.clone(),
                        *metadata.clone(),
                    )?;

                    let vali_req_hash =
                        hash_borsh(&*self.hash.hasher(), &validation_req)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                    let meta_wo_props = MetadataWithoutProperties::from(
                        modified_metadata.clone(),
                    );
                    let meta_wo_props_hash =
                        hash_borsh(&*self.hash.hasher(), &meta_wo_props)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                    let propierties_hash = hash_borsh(
                        &*self.hash.hasher(),
                        &modified_metadata.properties,
                    )
                    .map_err(|e| {
                        ValidatorError::InternalError {
                            problem: e.to_string(),
                        }
                    })?;

                    let event_request_hash =
                        self.event_request_hash(event_request)?;
                    let viewpoints_hash =
                        self.viewpoints_hash(event_request.content())?;

                    Ok(ValidationRes::Response {
                        vali_req_hash,
                        modified_metadata_without_propierties_hash:
                            meta_wo_props_hash,
                        propierties_hash,
                        event_request_hash,
                        viewpoints_hash,
                    })
                }
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValiWorkerMessage {
    UpdateCurrentRoles {
        gov_version: u64,
        current_roles: CurrentWorkerRoles,
    },
    LocalValidation {
        validation_req: Box<Signed<ValidationReq>>,
    },
    NetworkRequest {
        validation_req: Box<Signed<ValidationReq>>,
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
        parent_span.map_or_else(
            || info_span!("ValiWorker", id),
            |parent_span| info_span!(parent: parent_span, "ValiWorker", id),
        )
    }
}

impl NotPersistentActor for ValiWorker {}

#[async_trait]
impl Handler<Self> for ValiWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ValiWorkerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ValiWorkerMessage::UpdateCurrentRoles {
                gov_version,
                current_roles,
            } => {
                self.gov_version = gov_version;
                self.current_roles = current_roles;
            }
            ValiWorkerMessage::LocalValidation { validation_req } => {
                let validation =
                    match self.create_res(ctx, false, &validation_req).await {
                        Ok(vali) => vali,
                        Err(e) => {
                            if matches!(e, ValidatorError::OutOfVersion) {
                                ValidationRes::Reboot
                            } else {
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

                match ctx.get_parent::<Validation>().await {
                    Ok(validation_actor) => {
                        validation_actor
                            .tell(ValidationMessage::Response {
                                validation_res: Box::new(validation),
                                sender: (*self.our_key).clone(),
                                signature: Some(signature),
                            })
                            .await?;

                        debug!(
                            msg_type = "LocalValidation",
                            "Validation completed and sent to parent"
                        );
                    }
                    Err(e) => {
                        error!(
                            msg_type = "LocalValidation",
                            "Failed to obtain Validation actor"
                        );
                        return Err(e);
                    }
                };

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
                    if self.stop {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                let reboot = match self
                    .check_governance(
                        validation_req.content().get_gov_version(),
                    )
                    .await
                {
                    Ok(reboot) => reboot,
                    Err(e) => {
                        warn!(
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
                            } else if matches!(e, ValidatorError::OutOfVersion)
                            {
                                ValidationRes::Reboot
                            } else {
                                ValidationRes::Abort(e.to_string())
                            }
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
                        "/user/request/{}/validation/{}",
                        validation_req.content().get_subject_id(),
                        self.our_key.clone()
                    ),
                };

                let signed_response: Signed<ValidationRes> =
                    Signed::from_parts(validation, signature);
                if let Err(e) = self
                    .network
                    .send_command(ave_network::CommandHelper::SendMessage {
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
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            node_key = %self.node_key,
            governance_id = %self.governance_id,
            gov_version = self.gov_version,
            sn = self.sn,
            error = %error,
            "Child fault in validation worker"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
