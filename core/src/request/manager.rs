use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::bridge::request::EventRequestType;
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signed,
};
use ave_common::request::EventRequest;
use ave_common::response::RequestState;
use ave_common::{Namespace, SchemaType, ValueWrapper};
use borsh::{BorshDeserialize, BorshSerialize};
use ave_network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{Span, debug, error, info, info_span, warn};

use crate::approval::request::ApprovalReq;
use crate::distribution::{
    Distribution, DistributionMessage, DistributionType,
};
use crate::evaluation::request::EvaluateData;
use crate::evaluation::response::EvaluatorResponse;
use crate::governance::data::GovernanceData;
use crate::governance::model::{
    HashThisRole, ProtocolTypes, Quorum, RoleTypes, WitnessesData,
};
use crate::governance::role_register::RoleDataRegister;
use crate::helpers::network::service::NetworkSender;
use crate::metrics::try_core_metrics;
use crate::model::common::distribution_plan::build_tracker_event_distribution_plan;
use crate::model::common::node::{SignTypesNode, get_sign, get_subject_data};
use crate::model::common::subject::{
    acquire_subject, create_subject, get_gov, get_gov_sn,
    get_last_ledger_event, get_metadata, make_obsolete, update_ledger,
};
use crate::model::common::{purge_storage, send_to_tracking};
use crate::model::event::{
    ApprovalData, EvaluationData, Ledger, LedgerSeal, Protocols, ValidationData,
};
use crate::node::SubjectData;
use crate::request::error::RequestManagerError;
use crate::request::tracking::RequestTrackingMessage;
use crate::request::{RequestHandler, RequestHandlerMessage};
use crate::subject::Metadata;
use crate::system::ConfigHelper;

use crate::validation::request::{ActualProtocols, LastData, ValidationReq};
use crate::validation::worker::CurrentRequestRoles;
use crate::{
    ActorMessage, NetworkMessage, Validation, ValidationMessage,
    approval::{Approval, ApprovalMessage},
    auth::{Auth, AuthMessage, AuthResponse},
    db::Storable,
    evaluation::{Evaluation, EvaluationMessage, request::EvaluationReq},
    model::common::emit_fail,
    update::{Update, UpdateMessage, UpdateNew, UpdateType},
};

use super::{
    reboot::{Reboot, RebootMessage},
    types::{
        DistributionPlanEntry, DistributionPlanMode, ReqManInitMessage,
        RequestManagerState,
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestManager {
    #[serde(skip)]
    helpers: Option<(HashAlgorithm, Arc<NetworkSender>)>,
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    #[serde(skip)]
    id: DigestIdentifier,
    #[serde(skip)]
    subject_id: DigestIdentifier,
    #[serde(skip)]
    governance_id: Option<DigestIdentifier>,
    #[serde(skip)]
    retry_timeout: u64,
    #[serde(skip)]
    retry_diff: u64,
    #[serde(skip)]
    request_started_at: Option<Instant>,
    #[serde(skip)]
    current_phase: Option<&'static str>,
    #[serde(skip)]
    current_phase_started_at: Option<Instant>,
    command: ReqManInitMessage,
    request: Option<Signed<EventRequest>>,
    state: RequestManagerState,
    version: u64,
}

#[derive(Debug, Clone)]
pub enum RebootType {
    Normal,
    Diff,
    TimeOut,
}

pub struct InitRequestManager {
    pub our_key: Arc<PublicKey>,
    pub subject_id: DigestIdentifier,
    pub governance_id: Option<DigestIdentifier>,
    pub helpers: (HashAlgorithm, Arc<NetworkSender>),
}

impl BorshSerialize for RequestManager {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        BorshSerialize::serialize(&self.command, writer)?;
        BorshSerialize::serialize(&self.state, writer)?;
        BorshSerialize::serialize(&self.version, writer)?;
        BorshSerialize::serialize(&self.request, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for RequestManager {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let command = ReqManInitMessage::deserialize_reader(reader)?;
        let state = RequestManagerState::deserialize_reader(reader)?;
        let version = u64::deserialize_reader(reader)?;
        let request =
            Option::<Signed<EventRequest>>::deserialize_reader(reader)?;

        let our_key = Arc::new(PublicKey::default());
        let subject_id = DigestIdentifier::default();
        let id = DigestIdentifier::default();

        Ok(Self {
            retry_diff: 0,
            retry_timeout: 0,
            request_started_at: None,
            current_phase: None,
            current_phase_started_at: None,
            helpers: None,
            our_key,
            id,
            subject_id,
            governance_id: None,
            command,
            request,
            state,
            version,
        })
    }
}

impl RequestManager {
    fn retry_seconds_for_attempt(schedule: &[u64], attempt: u64) -> u64 {
        let default = schedule.last().copied().unwrap_or(1).max(1);
        let idx = attempt.saturating_sub(1) as usize;
        schedule.get(idx).copied().unwrap_or(default).max(1)
    }

    fn begin_request_metrics(&mut self) {
        self.request_started_at = Some(Instant::now());
        self.current_phase = None;
        self.current_phase_started_at = None;

        if let Some(metrics) = try_core_metrics() {
            metrics.observe_request_started();
        }
    }

    fn ensure_request_metrics_started(&mut self) {
        if self.request_started_at.is_none() {
            self.request_started_at = Some(Instant::now());
        }
    }

    fn start_phase_metrics(&mut self, phase: &'static str) {
        self.ensure_request_metrics_started();
        self.finish_phase_metrics();
        self.current_phase = Some(phase);
        self.current_phase_started_at = Some(Instant::now());
    }

    fn finish_phase_metrics(&mut self) {
        let Some(phase) = self.current_phase.take() else {
            self.current_phase_started_at = None;
            return;
        };
        let Some(started_at) = self.current_phase_started_at.take() else {
            return;
        };

        if let Some(metrics) = try_core_metrics() {
            metrics.observe_request_phase(phase, started_at.elapsed());
        }
    }

    fn finish_request_metrics(&mut self, result: &'static str) {
        self.finish_phase_metrics();

        if let Some(started_at) = self.request_started_at.take()
            && let Some(metrics) = try_core_metrics()
        {
            metrics.observe_request_terminal(result, started_at.elapsed());
        }
    }

    //////// EVAL
    ////////////////////////////////////////////////
    //Revisado
    async fn build_evaluation(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), RequestManagerError> {
        let Some(request) = self.request.clone() else {
            return Err(RequestManagerError::RequestNotSet);
        };

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Evaluation),
            },
            ctx,
        )
        .await;

        let metadata = self.check_data_eval(ctx, &request).await?;

        let (signed_evaluation_req, quorum, signers, init_state) =
            self.build_request_eval(ctx, &metadata, &request).await?;

        if signers.is_empty() {
            warn!(
                request_id = %self.id,
                schema_id = %metadata.schema_id,
                "No evaluators available for schema"
            );

            return Err(RequestManagerError::NoEvaluatorsAvailable {
                schema_id: metadata.schema_id.to_string(),
                governance_id: signed_evaluation_req
                    .content()
                    .governance_id
                    .clone(),
            });
        }

        self.run_evaluation(
            ctx,
            signed_evaluation_req.clone(),
            quorum,
            init_state,
            signers,
        )
        .await
    }

    // revisado
    const fn needs_subject_manager(&self) -> bool {
        self.governance_id.is_some()
    }

    fn requester_id(&self) -> String {
        self.id.to_string()
    }

    fn build_distribution_plan(
        &self,
        validation_req: &ValidationReq,
        governance_data: Option<&GovernanceData>,
    ) -> Result<Vec<DistributionPlanEntry>, RequestManagerError> {
        let mut plan: HashMap<PublicKey, DistributionPlanMode> = HashMap::new();

        match validation_req {
            ValidationReq::Create { event_request, .. } => {
                let EventRequest::Create(create) = event_request.content()
                else {
                    return Err(
                        RequestManagerError::InvalidEventRequestForEvaluation,
                    );
                };

                if create.schema_id.is_gov() {
                    return Ok(Vec::new());
                }

                let Some(governance_data) = governance_data else {
                    return Err(RequestManagerError::ActorError(
                        ActorError::FunctionalCritical {
                            description:
                                "Missing governance data for distribution plan"
                                    .to_owned(),
                        },
                    ));
                };
                let witnesses =
                    governance_data.get_witnesses(WitnessesData::Schema {
                        creator: event_request.signature().signer.clone(),
                        schema_id: create.schema_id.clone(),
                        namespace: create.namespace.clone(),
                    })?;

                for witness in witnesses {
                    plan.insert(witness, DistributionPlanMode::Clear);
                }
            }
            ValidationReq::Event {
                actual_protocols,
                event_request,
                metadata,
                ..
            } => {
                if metadata.schema_id.is_gov() {
                    return Ok(Vec::new());
                }

                let Some(governance_data) = governance_data else {
                    return Err(RequestManagerError::ActorError(
                        ActorError::FunctionalCritical {
                            description:
                                "Missing governance data for distribution plan"
                                    .to_owned(),
                        },
                    ));
                };
                let protocols_success = actual_protocols.is_success();

                return build_tracker_event_distribution_plan(
                    governance_data,
                    event_request.content(),
                    metadata,
                    protocols_success,
                )
                .map_err(|description| {
                    RequestManagerError::ActorError(
                        ActorError::FunctionalCritical { description },
                    )
                });
            }
        }

        Ok(plan
            .into_iter()
            .map(|(node, mode)| DistributionPlanEntry { node, mode })
            .collect())
    }

    async fn check_data_eval(
        &self,
        ctx: &mut ActorContext<Self>,
        request: &Signed<EventRequest>,
    ) -> Result<Metadata, RequestManagerError> {
        let (subject_id, confirm) = match request.content().clone() {
            EventRequest::Fact(event) => (event.subject_id, false),
            EventRequest::Transfer(event) => (event.subject_id, false),
            EventRequest::Confirm(event) => (event.subject_id, true),
            _ => {
                return Err(
                    RequestManagerError::InvalidEventRequestForEvaluation,
                );
            }
        };

        let lease = acquire_subject(
            ctx,
            &self.subject_id,
            self.requester_id(),
            None,
            self.needs_subject_manager(),
        )
        .await?;
        let metadata = get_metadata(ctx, &subject_id).await;
        lease.finish(ctx).await?;
        let metadata = metadata?;

        if confirm && !metadata.schema_id.is_gov() {
            return Err(RequestManagerError::ConfirmNotEvaluableForTracker);
        }

        Ok(metadata)
    }

    async fn get_governance_data(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<GovernanceData, RequestManagerError> {
        let governance_id =
            self.governance_id.as_ref().unwrap_or(&self.subject_id);
        Ok(get_gov(ctx, governance_id).await?)
    }

    async fn build_request_eval(
        &self,
        ctx: &mut ActorContext<Self>,
        metadata: &Metadata,
        request: &Signed<EventRequest>,
    ) -> Result<
        (
            Signed<EvaluationReq>,
            Quorum,
            HashSet<PublicKey>,
            Option<ValueWrapper>,
        ),
        RequestManagerError,
    > {
        let is_gov = metadata.schema_id.is_gov();

        let request_type = EventRequestType::from(request.content());
        let (evaluate_data, governance_data, init_state) = match (
            is_gov,
            request_type.clone(),
        ) {
            (true, EventRequestType::Fact) => {
                let state =
                    GovernanceData::try_from(metadata.properties.clone())?;

                (
                    EvaluateData::GovFact {
                        state: state.clone(),
                    },
                    state,
                    None,
                )
            }
            (true, EventRequestType::Transfer) => {
                let state =
                    GovernanceData::try_from(metadata.properties.clone())?;

                (
                    EvaluateData::GovTransfer {
                        state: state.clone(),
                    },
                    state,
                    None,
                )
            }
            (true, EventRequestType::Confirm) => {
                let state =
                    GovernanceData::try_from(metadata.properties.clone())?;

                (
                    EvaluateData::GovConfirm {
                        state: state.clone(),
                    },
                    state,
                    None,
                )
            }
            (false, EventRequestType::Fact) => {
                let governance_data =
                    get_gov(ctx, &metadata.governance_id).await?;

                let init_state =
                    governance_data.get_init_state(&metadata.schema_id)?;
                let schema_viewpoints = governance_data
                    .schemas
                    .get(&metadata.schema_id)
                    .ok_or_else(|| {
                        crate::governance::error::GovernanceError::SchemaDoesNotExist {
                            schema_id: metadata.schema_id.to_string(),
                        }
                    })?
                    .viewpoints
                    .clone();

                (
                    EvaluateData::TrackerSchemasFact {
                        contract: format!(
                            "{}_{}",
                            metadata.governance_id, metadata.schema_id
                        ),
                        state: metadata.properties.clone(),
                        schema_viewpoints,
                    },
                    governance_data,
                    Some(init_state),
                )
            }
            (false, EventRequestType::Transfer) => {
                let governance_data =
                    get_gov(ctx, &metadata.governance_id).await?;
                (
                    EvaluateData::TrackerSchemasTransfer {
                        governance_data: governance_data.clone(),
                        namespace: metadata.namespace.clone(),
                        schema_id: metadata.schema_id.clone(),
                        state: metadata.properties.clone(),
                    },
                    governance_data,
                    None,
                )
            }
            _ => {
                error!(
                    request_id = %self.id,
                    is_gov = is_gov,
                    request_type = ?request_type,
                    "Invalid event request type for evaluation state"
                );
                return Err(
                    RequestManagerError::InvalidEventRequestForEvaluation,
                );
            }
        };

        let (signers, quorum) = governance_data.get_quorum_and_signers(
            ProtocolTypes::Evaluation,
            &metadata.schema_id,
            metadata.namespace.clone(),
        )?;

        let eval_req = EvaluationReq {
            event_request: request.clone(),
            data: evaluate_data,
            sn: metadata.sn + 1,
            gov_version: governance_data.version,
            namespace: metadata.namespace.clone(),
            schema_id: metadata.schema_id.clone(),
            signer: (*self.our_key).clone(),
            signer_is_owner: *self.our_key == request.signature().signer,
            governance_id: metadata.governance_id.clone(),
        };

        let signature = get_sign(
            ctx,
            SignTypesNode::EvaluationReq(Box::new(eval_req.clone())),
        )
        .await?;

        let signed_evaluation_req: Signed<EvaluationReq> =
            Signed::from_parts(eval_req, signature);
        Ok((signed_evaluation_req, quorum, signers, init_state))
    }

    async fn run_evaluation(
        &mut self,
        ctx: &mut ActorContext<Self>,
        request: Signed<EvaluationReq>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        signers: HashSet<PublicKey>,
    ) -> Result<(), RequestManagerError> {
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(RequestManagerError::HelpersNotInitialized);
        };

        self.start_phase_metrics("evaluation");
        info!("Init evaluation {}", self.id);
        let child = ctx
            .create_child(
                "evaluation",
                Evaluation::new(
                    self.our_key.clone(),
                    request,
                    quorum,
                    init_state,
                    hash,
                    network,
                ),
            )
            .await?;

        child
            .tell(EvaluationMessage::Create {
                request_id: self.id.clone(),
                version: self.version,
                signers,
            })
            .await?;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Evaluation,
            },
        )
        .await?;

        Ok(())
    }
    //////// APPROVE
    ////////////////////////////////////////////////
    async fn build_request_appro(
        &self,
        ctx: &mut ActorContext<Self>,
        eval_req: EvaluationReq,
        evaluator_res: EvaluatorResponse,
    ) -> Result<Signed<ApprovalReq>, RequestManagerError> {
        let request = ApprovalReq {
            subject_id: self.subject_id.clone(),
            sn: eval_req.sn,
            gov_version: eval_req.gov_version,
            patch: evaluator_res.patch,
            signer: eval_req.signer,
        };

        let signature =
            get_sign(ctx, SignTypesNode::ApprovalReq(request.clone())).await?;

        let signed_approval_req: Signed<ApprovalReq> =
            Signed::from_parts(request, signature);

        Ok(signed_approval_req)
    }

    async fn build_approval(
        &mut self,
        ctx: &mut ActorContext<Self>,
        eval_req: EvaluationReq,
        eval_res: EvaluatorResponse,
    ) -> Result<(), RequestManagerError> {
        let request = self.build_request_appro(ctx, eval_req, eval_res).await?;

        let governance_data =
            get_gov(ctx, &request.content().subject_id).await?;

        let (signers, quorum) = governance_data.get_quorum_and_signers(
            ProtocolTypes::Approval,
            &SchemaType::Governance,
            Namespace::new(),
        )?;

        if signers.is_empty() {
            warn!(
                request_id = %self.id,
                schema_id = %SchemaType::Governance,
                "No approvers available for schema"
            );

            return Err(RequestManagerError::NoApproversAvailable {
                schema_id: SchemaType::Governance.to_string(),
                governance_id: self
                    .governance_id
                    .clone()
                    .unwrap_or_else(|| self.subject_id.clone()),
            });
        }

        self.run_approval(ctx, request, quorum, signers).await
    }

    async fn run_approval(
        &mut self,
        ctx: &mut ActorContext<Self>,
        request: Signed<ApprovalReq>,
        quorum: Quorum,
        signers: HashSet<PublicKey>,
    ) -> Result<(), RequestManagerError> {
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(RequestManagerError::HelpersNotInitialized);
        };

        self.start_phase_metrics("approval");
        info!("Init approval {}", self.id);
        let child = ctx
            .create_child(
                "approval",
                Approval::new(
                    self.our_key.clone(),
                    request,
                    quorum,
                    signers,
                    hash,
                    network,
                ),
            )
            .await?;

        child
            .tell(ApprovalMessage::Create {
                request_id: self.id.clone(),
                version: self.version,
            })
            .await?;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Approval,
            },
        )
        .await?;

        Ok(())
    }

    //////// VALI
    ////////////////////////////////////////////////
    async fn build_validation_req(
        &mut self,
        ctx: &mut ActorContext<Self>,
        eval: Option<(EvaluationReq, EvaluationData)>,
        appro_data: Option<ApprovalData>,
    ) -> Result<
        (
            Signed<ValidationReq>,
            Quorum,
            HashSet<PublicKey>,
            Option<ValueWrapper>,
            CurrentRequestRoles,
        ),
        RequestManagerError,
    > {
        let (
            vali_req,
            quorum,
            signers,
            init_state,
            current_request_roles,
            schema_id,
            governance_data,
        ) = self.build_validation_data(ctx, eval, appro_data).await?;

        if signers.is_empty() {
            let governance_id = vali_req.get_governance_id().map_err(|error| {
                error!(
                    request_id = %self.id,
                    schema_id = %schema_id,
                    error = %error,
                    "Validation request has invalid governance_id"
                );
                RequestManagerError::ActorError(
                    ActorError::FunctionalCritical {
                        description: format!(
                            "Validation request has invalid governance_id: {}",
                            error
                        ),
                    },
                )
            })?;

            warn!(
                request_id = %self.id,
                schema_id = %schema_id,
                "No validators available for schema"
            );

            return Err(RequestManagerError::NoValidatorsAvailable {
                schema_id: schema_id.to_string(),
                governance_id,
            });
        }

        let signature = get_sign(
            ctx,
            SignTypesNode::ValidationReq(Box::new(vali_req.clone())),
        )
        .await?;

        let distribution_plan =
            self.build_distribution_plan(&vali_req, governance_data.as_ref())?;

        let signed_validation_req: Signed<ValidationReq> =
            Signed::from_parts(vali_req, signature);

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Validation {
                    request: Box::new(signed_validation_req.clone()),
                    quorum: quorum.clone(),
                    init_state: init_state.clone(),
                    current_request_roles: current_request_roles.clone(),
                    signers: signers.clone(),
                    distribution_plan: distribution_plan.clone(),
                }),
            },
            ctx,
        )
        .await;

        Ok((
            signed_validation_req,
            quorum,
            signers,
            init_state,
            current_request_roles,
        ))
    }

    async fn build_validation_data(
        &self,
        ctx: &mut ActorContext<Self>,
        eval: Option<(EvaluationReq, EvaluationData)>,
        appro_data: Option<ApprovalData>,
    ) -> Result<
        (
            ValidationReq,
            Quorum,
            HashSet<PublicKey>,
            Option<ValueWrapper>,
            CurrentRequestRoles,
            SchemaType,
            Option<GovernanceData>,
        ),
        RequestManagerError,
    > {
        let Some(request) = self.request.clone() else {
            return Err(RequestManagerError::RequestNotSet);
        };

        if let EventRequest::Create(create) = request.content() {
            if create.schema_id.is_gov() {
                let governance_data =
                    GovernanceData::new((*self.our_key).clone());
                let (signers, quorum) = governance_data
                    .get_quorum_and_signers(
                        ProtocolTypes::Validation,
                        &SchemaType::Governance,
                        Namespace::new(),
                    )?;

                Ok((
                    ValidationReq::Create {
                        event_request: request.clone(),
                        gov_version: 0,
                        subject_id: self.subject_id.clone(),
                    },
                    quorum,
                    signers,
                    None,
                    CurrentRequestRoles {
                        evaluation: RoleDataRegister {
                            workers: HashSet::new(),
                            quorum: Quorum::default(),
                        },
                        approval: RoleDataRegister {
                            workers: HashSet::new(),
                            quorum: Quorum::default(),
                        },
                    },
                    SchemaType::Governance,
                    None,
                ))
            } else {
                let governance_data =
                    get_gov(ctx, &create.governance_id).await?;

                let (signers, quorum) = governance_data
                    .get_quorum_and_signers(
                        ProtocolTypes::Validation,
                        &create.schema_id,
                        create.namespace.clone(),
                    )?;

                let init_state =
                    governance_data.get_init_state(&create.schema_id)?;

                Ok((
                    ValidationReq::Create {
                        event_request: request.clone(),
                        gov_version: governance_data.version,
                        subject_id: self.subject_id.clone(),
                    },
                    quorum,
                    signers,
                    Some(init_state),
                    CurrentRequestRoles {
                        evaluation: RoleDataRegister {
                            workers: HashSet::new(),
                            quorum: Quorum::default(),
                        },
                        approval: RoleDataRegister {
                            workers: HashSet::new(),
                            quorum: Quorum::default(),
                        },
                    },
                    create.schema_id.clone(),
                    Some(governance_data),
                ))
            }
        } else {
            let Some((hash, ..)) = self.helpers else {
                return Err(RequestManagerError::HelpersNotInitialized);
            };

            let governance_data = self.get_governance_data(ctx).await?;

            let (actual_protocols, gov_version, sn) =
                if let Some((eval_req, eval_data)) = eval {
                    if let Some(approval_data) = appro_data.clone() {
                        (
                            ActualProtocols::EvalApprove {
                                eval_data,
                                approval_data,
                            },
                            eval_req.gov_version,
                            Some(eval_req.sn),
                        )
                    } else {
                        (
                            ActualProtocols::Eval { eval_data },
                            eval_req.gov_version,
                            Some(eval_req.sn),
                        )
                    }
                } else {
                    (ActualProtocols::None, governance_data.version, None)
                };

            let lease = acquire_subject(
                ctx,
                &self.subject_id,
                self.requester_id(),
                None,
                self.needs_subject_manager(),
            )
            .await?;
            let metadata = get_metadata(ctx, &self.subject_id).await;
            let last_ledger_event = match metadata {
                Ok(metadata) => {
                    let last_ledger_event =
                        get_last_ledger_event(ctx, &self.subject_id).await;
                    lease.finish(ctx).await?;
                    (metadata, last_ledger_event?)
                }
                Err(error) => {
                    lease.finish(ctx).await?;
                    return Err(error.into());
                }
            };

            let (metadata, last_ledger_event) = last_ledger_event;

            if gov_version != governance_data.version {
                return Err(RequestManagerError::GovernanceVersionChanged {
                    governance_id: metadata.governance_id,
                    expected: gov_version,
                    current: governance_data.version,
                });
            }

            let sn = if let Some(sn) = sn {
                sn
            } else {
                metadata.sn + 1
            };

            let (signers, quorum) = governance_data.get_quorum_and_signers(
                ProtocolTypes::Validation,
                &metadata.schema_id,
                metadata.namespace.clone(),
            )?;

            let Some(last_ledger_event) = last_ledger_event else {
                return Err(RequestManagerError::LastLedgerEventNotFound);
            };

            let ledger_hash = last_ledger_event.ledger_hash(hash)?;
            let schema_id = metadata.schema_id.clone();

            let current_request_roles =
                if gov_version == governance_data.version {
                    let (evaluation_workers, evaluation_quorum) =
                        governance_data.get_quorum_and_signers(
                            ProtocolTypes::Evaluation,
                            &metadata.schema_id,
                            metadata.namespace.clone(),
                        )?;

                    let (approval_workers, approval_quorum) =
                        if appro_data.is_some() {
                            governance_data.get_quorum_and_signers(
                                ProtocolTypes::Approval,
                                &SchemaType::Governance,
                                Namespace::new(),
                            )?
                        } else {
                            (HashSet::new(), Quorum::default())
                        };

                    CurrentRequestRoles {
                        evaluation: RoleDataRegister {
                            workers: evaluation_workers,
                            quorum: evaluation_quorum,
                        },
                        approval: RoleDataRegister {
                            workers: approval_workers,
                            quorum: approval_quorum,
                        },
                    }
                } else {
                    CurrentRequestRoles {
                        evaluation: RoleDataRegister {
                            workers: HashSet::new(),
                            quorum: Quorum::default(),
                        },
                        approval: RoleDataRegister {
                            workers: HashSet::new(),
                            quorum: Quorum::default(),
                        },
                    }
                };

            Ok((
                ValidationReq::Event {
                    actual_protocols: Box::new(actual_protocols),
                    event_request: request.clone(),
                    metadata: Box::new(metadata),
                    last_data: Box::new(LastData {
                        vali_data: last_ledger_event
                            .protocols
                            .get_validation_data(),
                        gov_version: last_ledger_event.gov_version,
                    }),
                    gov_version,
                    ledger_hash,
                    sn,
                },
                quorum,
                signers,
                None,
                current_request_roles,
                schema_id,
                Some(governance_data),
            ))
        }
    }

    async fn run_validation(
        &mut self,
        ctx: &mut ActorContext<Self>,
        request: Signed<ValidationReq>,
        quorum: Quorum,
        signers: HashSet<PublicKey>,
        init_state: Option<ValueWrapper>,
        current_request_roles: CurrentRequestRoles,
    ) -> Result<(), RequestManagerError> {
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(RequestManagerError::HelpersNotInitialized);
        };

        self.start_phase_metrics("validation");
        info!("Init validation {}", self.id);
        let child = ctx
            .create_child(
                "validation",
                Validation::new(
                    self.our_key.clone(),
                    request,
                    init_state,
                    current_request_roles,
                    quorum,
                    hash,
                    network,
                ),
            )
            .await?;

        child
            .tell(ValidationMessage::Create {
                request_id: self.id.clone(),
                version: self.version,
                signers,
            })
            .await?;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Validation,
            },
        )
        .await?;

        Ok(())
    }
    //////// Distribution
    ////////////////////////////////////////////////
    async fn build_ledger(
        &mut self,
        ctx: &mut ActorContext<Self>,
        val_req: ValidationReq,
        val_res: ValidationData,
        distribution_plan: Vec<DistributionPlanEntry>,
    ) -> Result<Ledger, RequestManagerError> {
        let Some((hash, ..)) = self.helpers else {
            return Err(RequestManagerError::HelpersNotInitialized);
        };

        let (protocols, ledger_seal) = match val_req {
            ValidationReq::Create {
                event_request,
                gov_version,
                ..
            } => {
                let protocols = Protocols::Create {
                    event_request,
                    validation: val_res,
                };

                let protocols_hash = protocols.hash_for_ledger(&hash)?;

                let ledger_seal = LedgerSeal {
                    gov_version,
                    sn: 0,
                    prev_ledger_event_hash: DigestIdentifier::default(),
                    protocols_hash,
                };

                (protocols, ledger_seal)
            }
            ValidationReq::Event {
                actual_protocols,
                event_request,
                ledger_hash,
                metadata,
                gov_version,
                sn,
                ..
            } => {
                let protocols = Protocols::build(
                    metadata.schema_id.is_gov(),
                    event_request,
                    *actual_protocols,
                    val_res,
                )?;

                let protocols_hash = protocols.hash_for_ledger(&hash)?;

                let ledger_seal = LedgerSeal {
                    gov_version,
                    sn,
                    prev_ledger_event_hash: ledger_hash,
                    protocols_hash,
                };

                (protocols, ledger_seal)
            }
        };

        let signature =
            get_sign(ctx, SignTypesNode::LedgerSeal(ledger_seal.clone()))
                .await?;

        let ledger = Ledger {
            gov_version: ledger_seal.gov_version,
            sn: ledger_seal.sn,
            prev_ledger_event_hash: ledger_seal.prev_ledger_event_hash,
            ledger_seal_signature: signature,
            protocols,
        };

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::UpdateSubject {
                    ledger: ledger.clone(),
                    distribution_plan: distribution_plan.clone(),
                }),
            },
            ctx,
        )
        .await;

        Ok(ledger)
    }

    async fn update_subject(
        &mut self,
        ctx: &mut ActorContext<Self>,
        ledger: Ledger,
        distribution_plan: Vec<DistributionPlanEntry>,
    ) -> Result<(), RequestManagerError> {
        if ledger.get_event_request_type().is_create_event() {
            if let Err(e) = create_subject(ctx, ledger.clone()).await {
                if let ActorError::Functional { .. } = e {
                    return Err(RequestManagerError::CheckLimit);
                }
                return Err(e.into());
            }
        } else {
            let lease = acquire_subject(
                ctx,
                &self.subject_id,
                self.requester_id(),
                None,
                self.needs_subject_manager(),
            )
            .await?;
            let update_result =
                update_ledger(ctx, &self.subject_id, vec![ledger.clone()])
                    .await;
            lease.finish(ctx).await?;
            update_result?;
        }

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Distribution {
                    ledger,
                    distribution_plan,
                }),
            },
            ctx,
        )
        .await;

        Ok(())
    }

    async fn build_distribution(
        &mut self,
        ctx: &mut ActorContext<Self>,
        ledger: Ledger,
        mut distribution_plan: Vec<DistributionPlanEntry>,
    ) -> Result<bool, RequestManagerError> {
        let is_governance = match ledger.get_event_request() {
            Some(EventRequest::Create(create)) => create.schema_id.is_gov(),
            Some(_) => self.governance_id.is_none(),
            None => false,
        };

        if is_governance {
            let governance_id = ledger.get_subject_id();
            let governance_data = get_gov(ctx, &governance_id).await?;
            distribution_plan = governance_data
                .get_witnesses(WitnessesData::Gov)?
                .into_iter()
                .map(|node| DistributionPlanEntry {
                    node,
                    mode: DistributionPlanMode::Clear,
                })
                .collect();
        }

        if distribution_plan.is_empty() {
            return Ok(false);
        }

        distribution_plan.retain(|entry| entry.node != *self.our_key);

        if distribution_plan.is_empty() {
            warn!(
                request_id = %self.id,
                "No witnesses available for distribution"
            );
            return Ok(false);
        }

        self.run_distribution(ctx, distribution_plan, ledger)
            .await?;

        Ok(true)
    }

    async fn run_distribution(
        &mut self,
        ctx: &mut ActorContext<Self>,
        distribution_plan: Vec<DistributionPlanEntry>,
        ledger: Ledger,
    ) -> Result<(), RequestManagerError> {
        let Some((.., network)) = self.helpers.clone() else {
            return Err(RequestManagerError::HelpersNotInitialized);
        };

        self.start_phase_metrics("distribution");
        info!("Init distribution {}", self.id);
        let child = ctx
            .create_child(
                "distribution",
                Distribution::new(
                    network,
                    DistributionType::Request,
                    self.id.clone(),
                ),
            )
            .await?;

        child
            .tell(DistributionMessage::Create {
                ledger: Box::new(ledger),
                distribution_plan,
            })
            .await?;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Distribution,
            },
        )
        .await?;

        Ok(())
    }

    //////// Reboot
    ////////////////////////////////////////////////
    async fn init_wait(
        &self,
        ctx: &mut ActorContext<Self>,
        governance_id: &DigestIdentifier,
    ) -> Result<(), RequestManagerError> {
        let Some(config): Option<ConfigHelper> =
            ctx.system().get_helper("config").await
        else {
            return Err(RequestManagerError::ActorError(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            }));
        };
        let actor = ctx
            .create_child(
                "reboot",
                Reboot::new(
                    governance_id.clone(),
                    self.id.clone(),
                    config.sync_reboot.stability_check_interval_secs,
                    config.sync_reboot.stability_check_max_retries,
                ),
            )
            .await?;

        actor.tell(RebootMessage::Init).await?;

        Ok(())
    }

    async fn init_update(
        &self,
        ctx: &mut ActorContext<Self>,
        governance_id: &DigestIdentifier,
    ) -> Result<(), RequestManagerError> {
        let Some((.., network)) = self.helpers.clone() else {
            return Err(RequestManagerError::HelpersNotInitialized);
        };

        let gov_sn = get_gov_sn(ctx, governance_id).await?;

        let governance_data = get_gov(ctx, governance_id).await?;

        let mut witnesses = {
            let gov_witnesses =
                governance_data.get_witnesses(WitnessesData::Gov)?;

            let auth_witnesses =
                Self::get_witnesses_auth(ctx, governance_id.clone())
                    .await
                    .unwrap_or_default();

            gov_witnesses
                .union(&auth_witnesses)
                .cloned()
                .collect::<HashSet<PublicKey>>()
        };

        witnesses.remove(&self.our_key);

        if witnesses.is_empty() {
            if let Ok(actor) = ctx.reference().await {
                actor
                    .tell(RequestManagerMessage::FinishReboot {
                        request_id: self.id.clone(),
                    })
                    .await?;
            };
        } else if witnesses.len() == 1 {
            let Some(objetive) = witnesses.iter().next() else {
                error!(
                    request_id = %self.id,
                    governance_id = %governance_id,
                    "Witness set became empty while selecting single reboot target"
                );
                return Err(RequestManagerError::ActorError(
                    ActorError::FunctionalCritical {
                        description:
                            "Witness set became empty while selecting single reboot target"
                                .to_owned(),
                    },
                ));
            };
            let info = ComunicateInfo {
                receiver: objetive.clone(),
                request_id: String::default(),
                version: 0,
                receiver_actor: format!(
                    "/user/node/distributor_{}",
                    governance_id
                ),
            };

            network
                .send_command(ave_network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info,
                        message: ActorMessage::DistributionLedgerReq {
                            actual_sn: Some(gov_sn),
                            target_sn: None,
                            subject_id: governance_id.clone(),
                        },
                    },
                })
                .await?;

            let Ok(actor) = ctx.reference().await else {
                return Ok(());
            };

            actor
                .tell(RequestManagerMessage::RebootWait {
                    request_id: self.id.clone(),
                    governance_id: governance_id.clone(),
                })
                .await?;
        } else {
            let Some(config): Option<ConfigHelper> =
                ctx.system().get_helper("config").await
            else {
                return Ok(());
            };
            let data = UpdateNew {
                network,
                subject_id: governance_id.clone(),
                our_sn: Some(gov_sn),
                witnesses,
                update_type: UpdateType::Request {
                    subject_id: self.subject_id.clone(),
                    id: self.id.clone(),
                },
                subject_kind_hint: Some(
                    crate::update::UpdateSubjectKind::Governance,
                ),
                round_retry_interval_secs: config
                    .sync_update
                    .round_retry_interval_secs,
                max_round_retries: config.sync_update.max_round_retries,
                witness_retry_count: config.sync_update.witness_retry_count,
                witness_retry_interval_secs: config
                    .sync_update
                    .witness_retry_interval_secs,
            };

            let updater = Update::new(data);
            let Ok(child) = ctx.create_child("update", updater).await else {
                let Ok(actor) = ctx.reference().await else {
                    return Ok(());
                };

                actor
                    .tell(RequestManagerMessage::RebootWait {
                        request_id: self.id.clone(),
                        governance_id: governance_id.clone(),
                    })
                    .await?;

                return Ok(());
            };

            child.tell(UpdateMessage::Run).await?;
        }

        Ok(())
    }

    async fn get_witnesses_auth(
        ctx: &ActorContext<Self>,
        governance_id: DigestIdentifier,
    ) -> Result<HashSet<PublicKey>, RequestManagerError> {
        let path = ActorPath::from("/user/node/auth");
        let actor = ctx.system().get_actor::<Auth>(&path).await?;

        let response = actor
            .ask(AuthMessage::GetAuth {
                subject_id: governance_id,
            })
            .await?;

        match response {
            AuthResponse::Witnesses(witnesses) => Ok(witnesses),
            _ => Err(RequestManagerError::ActorError(
                ActorError::UnexpectedResponse {
                    path,
                    expected: "AuthResponse::Witnesses".to_owned(),
                },
            )),
        }
    }

    //////// General
    ////////////////////////////////////////////////
    async fn send_reboot(
        &self,
        ctx: &ActorContext<Self>,
        governance_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        let Ok(actor) = ctx.reference().await else {
            return Ok(());
        };

        actor
            .tell(RequestManagerMessage::Reboot {
                request_id: self.id.clone(),
                governance_id,
                reboot_type: RebootType::TimeOut,
            })
            .await
    }

    async fn match_error(
        &mut self,
        ctx: &mut ActorContext<Self>,
        error: RequestManagerError,
    ) {
        match error {
            RequestManagerError::NoEvaluatorsAvailable {
                governance_id,
                ..
            }
            | RequestManagerError::NoApproversAvailable {
                governance_id, ..
            }
            | RequestManagerError::NoValidatorsAvailable {
                governance_id,
                ..
            }
            | RequestManagerError::GovernanceVersionChanged {
                governance_id,
                ..
            } => {
                if let Err(e) = self.send_reboot(ctx, governance_id).await {
                    emit_fail(ctx, e).await;
                }
            }
            RequestManagerError::CheckLimit
            | RequestManagerError::Governance(..)
            | RequestManagerError::NotIssuer
            | RequestManagerError::NotCreator => {
                if let Err(e) = self
                    .abort_request(
                        ctx,
                        error.to_string(),
                        None,
                        (*self.our_key).clone(),
                    )
                    .await
                {
                    emit_fail(
                        ctx,
                        ActorError::FunctionalCritical {
                            description: e.to_string(),
                        },
                    )
                    .await;
                }
            }
            _ => {
                emit_fail(
                    ctx,
                    ActorError::FunctionalCritical {
                        description: error.to_string(),
                    },
                )
                .await;
            }
        }
    }

    async fn finish_request(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), RequestManagerError> {
        self.finish_request_metrics("finished");
        info!("Ending {}", self.id);
        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Finish,
            },
        )
        .await?;

        self.on_event(RequestManagerEvent::Finish, ctx).await;

        self.end_request(ctx).await?;

        Ok(())
    }

    async fn reboot(
        &mut self,
        ctx: &mut ActorContext<Self>,
        reboot_type: RebootType,
        governance_id: DigestIdentifier,
    ) -> Result<(), RequestManagerError> {
        let Some(config): Option<ConfigHelper> =
            ctx.system().get_helper("config").await
        else {
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            }
            .into());
        };
        self.start_phase_metrics("reboot");
        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Reboot),
            },
            ctx,
        )
        .await;

        let Ok(actor) = ctx.reference().await else {
            return Ok(());
        };

        let request_id = self.id.clone();

        match reboot_type {
            RebootType::Normal => {
                info!("Launching Normal reboot {}", self.id);
                send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: self.id.clone(),
                        state: RequestState::Reboot,
                    },
                )
                .await?;

                actor
                    .tell(RequestManagerMessage::RebootUpdate {
                        request_id,
                        governance_id,
                    })
                    .await?;
            }
            RebootType::Diff => {
                info!("Launching Diff reboot {}", self.id);
                self.retry_diff += 1;

                let seconds = Self::retry_seconds_for_attempt(
                    &config.sync_reboot.diff_retry_schedule_secs,
                    self.retry_diff,
                );

                info!(
                    "Launching Diff reboot {}, try: {}, seconds: {}",
                    self.id, self.retry_diff, seconds
                );

                send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: self.id.clone(),
                        state: RequestState::RebootDiff {
                            seconds,
                            count: self.retry_diff,
                        },
                    },
                )
                .await?;

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    let _ = actor
                        .tell(RequestManagerMessage::RebootUpdate {
                            request_id,
                            governance_id,
                        })
                        .await;
                });
            }
            RebootType::TimeOut => {
                self.retry_timeout += 1;

                let seconds = Self::retry_seconds_for_attempt(
                    &config.sync_reboot.timeout_retry_schedule_secs,
                    self.retry_timeout,
                );

                info!(
                    "Launching TimeOut reboot {}, try: {}, seconds: {}",
                    self.id, self.retry_timeout, seconds
                );
                send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: self.id.clone(),
                        state: RequestState::RebootTimeOut {
                            seconds,
                            count: self.retry_timeout,
                        },
                    },
                )
                .await?;

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    let _ = actor
                        .tell(RequestManagerMessage::RebootUpdate {
                            request_id,
                            governance_id,
                        })
                        .await;
                });
            }
        }

        Ok(())
    }

    async fn match_command(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), RequestManagerError> {
        match self.command {
            ReqManInitMessage::Evaluate => self.build_evaluation(ctx).await,
            ReqManInitMessage::Validate => {
                let (
                    request,
                    quorum,
                    signers,
                    init_state,
                    current_request_roles,
                ) = self.build_validation_req(ctx, None, None).await?;

                self.run_validation(
                    ctx,
                    request,
                    quorum,
                    signers,
                    init_state,
                    current_request_roles,
                )
                .await
            }
        }
    }

    async fn check_request_roles_after_reboot(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), RequestManagerError> {
        let Some(request) = self.request.clone() else {
            return Err(RequestManagerError::RequestNotSet);
        };

        let gov = self.get_governance_data(ctx).await?;
        let subject_data = match request.content() {
            EventRequest::Create(..) => None,
            _ => get_subject_data(ctx, &self.subject_id).await?,
        };

        let creator_scope = match request.content() {
            EventRequest::Create(create) if !create.schema_id.is_gov() => {
                Some((create.schema_id.clone(), create.namespace.clone()))
            }
            _ => subject_data.as_ref().and_then(|subject_data| {
                match subject_data {
                    SubjectData::Tracker {
                        schema_id,
                        namespace,
                        ..
                    } => Some((
                        schema_id.clone(),
                        Namespace::from(namespace.clone()),
                    )),
                    _ => None,
                }
            }),
        };

        if let Some((schema_id, namespace)) = creator_scope
            && !gov.has_this_role(HashThisRole::Schema {
                who: (*self.our_key).clone(),
                role: RoleTypes::Creator,
                schema_id,
                namespace,
            })
        {
            return Err(RequestManagerError::NotCreator);
        }

        if let EventRequest::Fact { .. } = request.content() {
            let Some(subject_data) = subject_data else {
                return Err(RequestManagerError::SubjecData);
            };

            match subject_data {
                SubjectData::Tracker {
                    schema_id,
                    namespace,
                    ..
                } => {
                    if !gov.has_this_role(HashThisRole::Schema {
                        who: request.signature().signer.clone(),
                        role: RoleTypes::Issuer,
                        schema_id,
                        namespace: Namespace::from(namespace),
                    }) {
                        return Err(RequestManagerError::NotIssuer);
                    }
                }
                SubjectData::Governance { .. } => {
                    if !gov.has_this_role(HashThisRole::Gov {
                        who: request.signature().signer.clone(),
                        role: RoleTypes::Issuer,
                    }) {
                        return Err(RequestManagerError::NotIssuer);
                    }
                }
            }
        }

        Ok(())
    }

    async fn stops_childs(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), RequestManagerError> {
        match self.state {
            RequestManagerState::Reboot => {
                if let Ok(actor) = ctx.get_child::<Update>("update").await {
                    actor.ask_stop().await?;
                };
                if let Ok(actor) = ctx.get_child::<Reboot>("reboot").await {
                    actor.ask_stop().await?;
                };
            }
            RequestManagerState::Evaluation => {
                if let Ok(actor) =
                    ctx.get_child::<Evaluation>("evaluation").await
                {
                    actor.ask_stop().await?;
                };
            }
            RequestManagerState::Approval { .. } => {
                if let Ok(actor) = ctx.get_child::<Approval>("approval").await {
                    actor.ask_stop().await?;
                };
                let _ = make_obsolete(ctx, &self.subject_id).await;
            }
            RequestManagerState::Validation { .. } => {
                if let Ok(actor) =
                    ctx.get_child::<Validation>("validation").await
                {
                    actor.ask_stop().await?;
                };
            }
            RequestManagerState::Distribution { .. } => {
                if let Ok(actor) =
                    ctx.get_child::<Distribution>("distribution").await
                {
                    actor.ask_stop().await?;
                };
            }
            _ => {}
        }

        Ok(())
    }

    async fn abort_request(
        &mut self,
        ctx: &mut ActorContext<Self>,
        error: String,
        sn: Option<u64>,
        who: PublicKey,
    ) -> Result<(), RequestManagerError> {
        self.stops_childs(ctx).await?;

        self.finish_request_metrics("aborted");
        info!("Aborting {}", self.id);
        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Abort {
                    subject_id: self.subject_id.to_string(),
                    error,
                    sn,
                    who: who.to_string(),
                },
            },
        )
        .await?;

        self.on_event(RequestManagerEvent::Finish, ctx).await;

        self.end_request(ctx).await?;

        Ok(())
    }

    async fn end_request(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(), RequestManagerError> {
        let actor = ctx.get_parent::<RequestHandler>().await?;
        actor
            .tell(RequestHandlerMessage::EndHandling {
                subject_id: self.subject_id.clone(),
            })
            .await?;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum RequestManagerMessage {
    Run {
        request_id: DigestIdentifier,
    },
    FirstRun {
        command: ReqManInitMessage,
        request: Signed<EventRequest>,
        request_id: DigestIdentifier,
    },
    Abort {
        request_id: DigestIdentifier,
        who: PublicKey,
        reason: String,
        sn: u64,
    },
    ManualAbort,
    PurgeStorage,
    Reboot {
        request_id: DigestIdentifier,
        governance_id: DigestIdentifier,
        reboot_type: RebootType,
    },
    RebootUpdate {
        request_id: DigestIdentifier,
        governance_id: DigestIdentifier,
    },
    RebootWait {
        request_id: DigestIdentifier,
        governance_id: DigestIdentifier,
    },
    FinishReboot {
        request_id: DigestIdentifier,
    },
    EvaluationRes {
        request_id: DigestIdentifier,
        eval_req: Box<EvaluationReq>,
        eval_res: EvaluationData,
    },
    ApprovalRes {
        request_id: DigestIdentifier,
        appro_res: ApprovalData,
    },
    ValidationRes {
        request_id: DigestIdentifier,
        val_req: Box<ValidationReq>,
        val_res: ValidationData,
    },
    FinishRequest {
        request_id: DigestIdentifier,
    },
}

impl Message for RequestManagerMessage {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RequestManagerEvent {
    Finish,
    UpdateState {
        state: Box<RequestManagerState>,
    },
    UpdateVersion {
        version: u64,
    },
    SafeState {
        command: ReqManInitMessage,
        request: Signed<EventRequest>,
    },
}

impl Event for RequestManagerEvent {}

#[async_trait]
impl Actor for RequestManager {
    type Event = RequestManagerEvent;
    type Message = RequestManagerMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("RequestManager", id),
            |parent_span| info_span!(parent: parent_span, "RequestManager", id),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) =
            self.init_store("request_manager", None, false, ctx).await
        {
            error!(
                error = %e,
                subject_id = %self.subject_id,
                "Failed to initialize store"
            );
            return Err(e);
        }

        if self.governance_id.is_none()
            && let Some(request) = &self.request
            && let EventRequest::Create(create) = request.content()
            && !create.schema_id.is_gov()
        {
            self.governance_id = Some(create.governance_id.clone());
        }

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for RequestManager {
    // The async state machine inlines all sub-futures and exceeds the default
    // threshold; a proper fix would require boxing every large sub-future.
    #[allow(clippy::large_stack_frames)]
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RequestManagerMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            RequestManagerMessage::RebootUpdate {
                governance_id,
                request_id,
            } => {
                if request_id == self.id {
                    info!("Init reboot update {}", self.id);
                    debug!(
                        msg_type = "RebootUpdate",
                        request_id = %self.id,
                        governance_id = %governance_id,
                        "Initializing reboot update"
                    );

                    if let Err(e) = self.init_update(ctx, &governance_id).await
                    {
                        error!(
                            msg_type = "RebootUpdate",
                            request_id = %self.id,
                            governance_id = %governance_id,
                            error = %e,
                            "Failed to initialize reboot update"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    }
                }
            }
            RequestManagerMessage::RebootWait {
                governance_id,
                request_id,
            } => {
                if request_id == self.id {
                    info!("Init reboot wait {}", self.id);
                    debug!(
                        msg_type = "RebootWait",
                        request_id = %self.id,
                        governance_id = %governance_id,
                        "Initializing reboot wait"
                    );

                    if let Err(e) = self.init_wait(ctx, &governance_id).await {
                        error!(
                            msg_type = "RebootWait",
                            request_id = %self.id,
                            governance_id = %governance_id,
                            error = %e,
                            "Failed to initialize reboot wait"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    }
                }
            }
            RequestManagerMessage::Reboot {
                governance_id,
                request_id,
                reboot_type,
            } => {
                if request_id == self.id {
                    if matches!(self.state, RequestManagerState::Reboot) {
                        debug!(
                            msg_type = "Reboot",
                            request_id = %self.id,
                            governance_id = %governance_id,
                            reboot_type = ?reboot_type,
                            "Already in reboot state, ignoring"
                        );
                    } else {
                        debug!(
                            msg_type = "Reboot",
                            request_id = %self.id,
                            governance_id = %governance_id,
                            reboot_type = ?reboot_type,
                            "Initiating reboot"
                        );
                        if let Err(e) = self.stops_childs(ctx).await {
                            error!(
                                msg_type = "Reboot",
                                request_id = %self.id,
                                governance_id = %governance_id,
                                error = %e,
                                "Failed to stop childs"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        };
                        if let Err(e) = self
                            .reboot(ctx, reboot_type, governance_id.clone())
                            .await
                        {
                            error!(
                                msg_type = "Reboot",
                                request_id = %self.id,
                                governance_id = %governance_id,
                                error = %e,
                                "Failed to initiate reboot"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    }
                }
            }
            RequestManagerMessage::FinishReboot { request_id } => {
                if request_id == self.id {
                    info!("Init reboot finish {}", self.id);
                    debug!(
                        msg_type = "FinishReboot",
                        request_id = %self.id,
                        version = self.version,
                        "Reboot completed, resuming request"
                    );
                    self.on_event(
                        RequestManagerEvent::UpdateVersion {
                            version: self.version + 1,
                        },
                        ctx,
                    )
                    .await;

                    if let Err(e) = send_to_tracking(
                        ctx,
                        RequestTrackingMessage::UpdateVersion {
                            request_id: self.id.clone(),
                            version: self.version,
                        },
                    )
                    .await
                    {
                        error!(
                            msg_type = "FinishReboot",
                            request_id = %self.id,
                            version = self.version,
                            error = %e,
                            "Failed to send version update to tracking"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }

                    if let Err(e) =
                        self.check_request_roles_after_reboot(ctx).await
                    {
                        error!(
                            msg_type = "FinishReboot",
                            request_id = %self.id,
                            error = %e,
                            "Failed to check signatures after reboot"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    }

                    if let Err(e) = self.match_command(ctx).await {
                        error!(
                            msg_type = "FinishReboot",
                            request_id = %self.id,
                            error = %e,
                            "Failed to execute command after reboot"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    }
                }
            }
            RequestManagerMessage::Abort {
                request_id,
                who,
                reason,
                sn,
            } => {
                if request_id == self.id {
                    warn!(
                        msg_type = "Abort",
                        state = %self.state,
                        request_id = %self.id,
                        who = %who,
                        reason = %reason,
                        sn = sn,
                        "Request abort received"
                    );
                    if let Err(e) =
                        self.abort_request(ctx, reason, Some(sn), who).await
                    {
                        error!(
                            msg_type = "Abort",
                            request_id = %self.id,
                            error = %e,
                            "Failed to abort request"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    }
                }
            }
            RequestManagerMessage::ManualAbort => {
                match &self.state {
                    RequestManagerState::Reboot
                    | RequestManagerState::Starting
                    | RequestManagerState::Evaluation
                    | RequestManagerState::Approval { .. }
                    | RequestManagerState::Validation { .. } => {
                        if let Err(e) = self
                            .abort_request(
                                ctx,
                                "The user manually aborted the request"
                                    .to_owned(),
                                None,
                                (*self.our_key).clone(),
                            )
                            .await
                        {
                            error!(
                                msg_type = "Abort",
                                request_id = %self.id,
                                error = %e,
                                "Failed to abort request"
                            );
                            self.match_error(ctx, e).await;
                        }
                    }
                    _ => {
                        info!(
                            "The request is in a state that cannot be aborted {}, state: {}",
                            self.id, self.state
                        );
                    }
                }

                return Ok(());
            }
            RequestManagerMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    subject_id = %self.subject_id,
                    "Purged request manager storage"
                );

                return Ok(());
            }
            RequestManagerMessage::FirstRun {
                command,
                request,
                request_id,
            } => {
                self.id = request_id.clone();
                self.begin_request_metrics();
                debug!(
                    msg_type = "FirstRun",
                    request_id = %request_id,
                    command = ?command,
                    "First run of request manager"
                );
                self.on_event(
                    RequestManagerEvent::SafeState { command, request },
                    ctx,
                )
                .await;

                if let Err(e) = self.match_command(ctx).await {
                    error!(
                        msg_type = "FirstRun",
                        request_id = %self.id,
                        error = %e,
                        "Failed to execute initial command"
                    );
                    self.match_error(ctx, e).await;
                    return Ok(());
                };
            }
            RequestManagerMessage::Run { request_id } => {
                self.id = request_id;
                self.ensure_request_metrics_started();

                debug!(
                    msg_type = "Run",
                    request_id = %self.id,
                    state = ?self.state,
                    version = self.version,
                    "Running request manager"
                );
                match self.state.clone() {
                    RequestManagerState::Starting
                    | RequestManagerState::Reboot => {
                        if let Err(e) = self.match_command(ctx).await {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "Starting/Reboot",
                                error = %e,
                                "Failed to execute command"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        };
                    }
                    RequestManagerState::Evaluation => {
                        if let Err(e) = self.build_evaluation(ctx).await {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "Evaluation",
                                error = %e,
                                "Failed to build evaluation"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    }

                    RequestManagerState::Approval { eval_req, eval_res } => {
                        let Some(evaluator_res) =
                            eval_res.evaluator_response_ok()
                        else {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "Approval",
                                "Approval state is missing a successful evaluator response"
                            );
                            self.match_error(
                                ctx,
                                RequestManagerError::InvalidRequestState {
                                    expected:
                                        "approval state with successful evaluator response",
                                    got:
                                        "approval state without successful evaluator response",
                                },
                            )
                            .await;
                            return Ok(());
                        };

                        if let Err(e) = self
                            .build_approval(ctx, eval_req, evaluator_res)
                            .await
                        {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "Approval",
                                error = %e,
                                "Failed to build approval"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    }
                    RequestManagerState::Validation {
                        request,
                        quorum,
                        init_state,
                        current_request_roles,
                        signers,
                        distribution_plan: _,
                    } => {
                        if let Err(e) = self
                            .run_validation(
                                ctx,
                                *request,
                                quorum,
                                signers,
                                init_state,
                                current_request_roles,
                            )
                            .await
                        {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "Validation",
                                error = %e,
                                "Failed to run validation"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        };
                    }
                    RequestManagerState::UpdateSubject {
                        ledger,
                        distribution_plan,
                    } => {
                        if let Err(e) = self
                            .update_subject(
                                ctx,
                                ledger.clone(),
                                distribution_plan.clone(),
                            )
                            .await
                        {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "UpdateSubject",
                                error = %e,
                                "Failed to update subject"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        };

                        match self
                            .build_distribution(ctx, ledger, distribution_plan)
                            .await
                        {
                            Ok(in_distribution) => {
                                if !in_distribution
                                    && let Err(e) =
                                        self.finish_request(ctx).await
                                {
                                    error!(
                                        msg_type = "Run",
                                        request_id = %self.id,
                                        state = "UpdateSubject",
                                        error = %e,
                                        "Failed to finish request after build distribution"
                                    );
                                    self.match_error(ctx, e).await;
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                error!(
                                    msg_type = "Run",
                                    request_id = %self.id,
                                    state = "UpdateSubject",
                                    error = %e,
                                    "Failed to build distribution"
                                );
                                self.match_error(ctx, e).await;
                                return Ok(());
                            }
                        };
                    }
                    RequestManagerState::Distribution {
                        ledger,
                        distribution_plan,
                    } => {
                        match self
                            .build_distribution(ctx, ledger, distribution_plan)
                            .await
                        {
                            Ok(in_distribution) => {
                                if !in_distribution
                                    && let Err(e) =
                                        self.finish_request(ctx).await
                                {
                                    error!(
                                        msg_type = "Run",
                                        request_id = %self.id,
                                        state = "Distribution",
                                        error = %e,
                                        "Failed to finish request after build distribution"
                                    );
                                    self.match_error(ctx, e).await;
                                    return Ok(());
                                }
                            }
                            Err(e) => {
                                error!(
                                    msg_type = "Run",
                                    request_id = %self.id,
                                    state = "Distribution",
                                    error = %e,
                                    "Failed to build distribution"
                                );
                                self.match_error(ctx, e).await;
                                return Ok(());
                            }
                        };
                    }
                    RequestManagerState::End => {
                        if let Err(e) = self.end_request(ctx).await {
                            error!(
                                msg_type = "Run",
                                request_id = %self.id,
                                state = "End",
                                error = %e,
                                "Failed to end request"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    }
                };
            }
            RequestManagerMessage::EvaluationRes {
                eval_req,
                eval_res,
                request_id,
            } => {
                if request_id == self.id {
                    debug!(
                        msg_type = "EvaluationRes",
                        request_id = %self.id,
                        version = self.version,
                        "Evaluation result received"
                    );
                    if let Err(e) = self.stops_childs(ctx).await {
                        error!(
                            msg_type = "EvaluationRes",
                            request_id = %self.id,
                            error = %e,
                            "Failed to stop childs"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    };

                    if let Some(evaluator_res) =
                        eval_res.evaluator_response_ok()
                        && evaluator_res.appr_required
                    {
                        debug!(
                            msg_type = "EvaluationRes",
                            request_id = %self.id,
                            "Approval required, proceeding to approval phase"
                        );
                        self.on_event(
                            RequestManagerEvent::UpdateState {
                                state: Box::new(
                                    RequestManagerState::Approval {
                                        eval_req: *eval_req.clone(),
                                        eval_res: eval_res.clone(),
                                    },
                                ),
                            },
                            ctx,
                        )
                        .await;

                        if let Err(e) = self
                            .build_approval(ctx, *eval_req, evaluator_res)
                            .await
                        {
                            error!(
                                msg_type = "EvaluationRes",
                                request_id = %self.id,
                                error = %e,
                                "Failed to build approval"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    } else {
                        debug!(
                            msg_type = "EvaluationRes",
                            request_id = %self.id,
                            "Approval not required, proceeding to validation phase"
                        );
                        let (
                            request,
                            quorum,
                            signers,
                            init_state,
                            current_request_roles,
                        ) = match self
                            .build_validation_req(
                                ctx,
                                Some((*eval_req, eval_res)),
                                None,
                            )
                            .await
                        {
                            Ok(data) => data,
                            Err(e) => {
                                error!(
                                    msg_type = "EvaluationRes",
                                    request_id = %self.id,
                                    error = %e,
                                    "Failed to build validation request"
                                );
                                self.match_error(ctx, e).await;
                                return Ok(());
                            }
                        };

                        if let Err(e) = self
                            .run_validation(
                                ctx,
                                request,
                                quorum,
                                signers,
                                init_state,
                                current_request_roles,
                            )
                            .await
                        {
                            error!(
                                msg_type = "EvaluationRes",
                                request_id = %self.id,
                                error = %e,
                                "Failed to run validation"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        };
                    }
                }
            }
            RequestManagerMessage::ApprovalRes {
                appro_res,
                request_id,
            } => {
                if request_id == self.id {
                    let _ = make_obsolete(ctx, &self.subject_id).await;
                    debug!(
                        msg_type = "ApprovalRes",
                        request_id = %self.id,
                        version = self.version,
                        "Approval result received"
                    );
                    if let Err(e) = self.stops_childs(ctx).await {
                        error!(
                            msg_type = "ApprovalRes",
                            request_id = %self.id,
                            error = %e,
                            "Failed to stop childs"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    };

                    let RequestManagerState::Approval { eval_req, eval_res } =
                        self.state.clone()
                    else {
                        error!(
                            msg_type = "ApprovalRes",
                            request_id = %self.id,
                            state = ?self.state,
                            "Invalid state for approval response"
                        );
                        let e = ActorError::FunctionalCritical {
                            description: "Invalid request state".to_owned(),
                        };
                        return Err(emit_fail(ctx, e).await);
                    };
                    let (
                        request,
                        quorum,
                        signers,
                        init_state,
                        current_request_roles,
                    ) = match self
                        .build_validation_req(
                            ctx,
                            Some((eval_req, eval_res)),
                            Some(appro_res),
                        )
                        .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            error!(
                                msg_type = "ApprovalRes",
                                request_id = %self.id,
                                error = %e,
                                "Failed to build validation request"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    };

                    if let Err(e) = self
                        .run_validation(
                            ctx,
                            request,
                            quorum,
                            signers,
                            init_state,
                            current_request_roles,
                        )
                        .await
                    {
                        error!(
                            msg_type = "ApprovalRes",
                            request_id = %self.id,
                            error = %e,
                            "Failed to run validation"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    };
                }
            }
            RequestManagerMessage::ValidationRes {
                val_res,
                val_req,
                request_id,
            } => {
                if request_id == self.id {
                    debug!(
                        msg_type = "ValidationRes",
                        request_id = %self.id,
                        version = self.version,
                        "Validation result received"
                    );
                    if let Err(e) = self.stops_childs(ctx).await {
                        error!(
                                msg_type = "ValidationRes",
                                request_id = %self.id,
                                error = %e,
                                "Failed to stop childs"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    };

                    let distribution_plan = match &self.state {
                        RequestManagerState::Validation {
                            distribution_plan,
                            ..
                        } => distribution_plan.clone(),
                        _ => {
                            error!(
                                msg_type = "ValidationRes",
                                request_id = %self.id,
                                state = ?self.state,
                                "Invalid state for validation response"
                            );
                            self.match_error(
                                ctx,
                                RequestManagerError::InvalidRequestState {
                                    expected: "Validation",
                                    got: "Other",
                                },
                            )
                            .await;
                            return Ok(());
                        }
                    };

                    let signed_ledger = match self
                        .build_ledger(
                            ctx,
                            *val_req,
                            val_res,
                            distribution_plan.clone(),
                        )
                        .await
                    {
                        Ok(signed_ledger) => signed_ledger,
                        Err(e) => {
                            error!(
                                msg_type = "ValidationRes",
                                request_id = %self.id,
                                error = %e,
                                "Failed to build ledger"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    };

                    if let Err(e) = self
                        .update_subject(
                            ctx,
                            signed_ledger.clone(),
                            distribution_plan.clone(),
                        )
                        .await
                    {
                        error!(
                            msg_type = "ValidationRes",
                            request_id = %self.id,
                            error = %e,
                            "Failed to update subject"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    };

                    match self
                        .build_distribution(
                            ctx,
                            signed_ledger,
                            distribution_plan,
                        )
                        .await
                    {
                        Ok(in_distribution) => {
                            if !in_distribution
                                && let Err(e) = self.finish_request(ctx).await
                            {
                                error!(
                                    msg_type = "ValidationRes",
                                    request_id = %self.id,
                                    error = %e,
                                    "Failed to finish request after build distribution"
                                );
                                self.match_error(ctx, e).await;
                                return Ok(());
                            }
                        }
                        Err(e) => {
                            error!(
                                msg_type = "ValidationRes",
                                request_id = %self.id,
                                error = %e,
                                "Failed to build distribution"
                            );
                            self.match_error(ctx, e).await;
                            return Ok(());
                        }
                    };
                }
            }
            RequestManagerMessage::FinishRequest { request_id } => {
                if request_id == self.id {
                    debug!(
                        msg_type = "FinishRequest",
                        request_id = %self.id,
                        version = self.version,
                        "Finishing request"
                    );

                    if let Err(e) = self.stops_childs(ctx).await {
                        error!(
                            msg_type = "FinishRequest",
                            request_id = %self.id,
                            error = %e,
                            "Failed to stop childs"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    };

                    if let Err(e) = self.finish_request(ctx).await {
                        error!(
                            msg_type = "FinishRequest",
                            request_id = %self.id,
                            error = %e,
                            "Failed to finish request"
                        );
                        self.match_error(ctx, e).await;
                        return Ok(());
                    }
                }
            }
        }

        Ok(())
    }

    async fn on_event(
        &mut self,
        event: RequestManagerEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        let event_type = match &event {
            RequestManagerEvent::Finish => "Finish",
            RequestManagerEvent::UpdateState { .. } => "UpdateState",
            RequestManagerEvent::UpdateVersion { .. } => "UpdateVersion",
            RequestManagerEvent::SafeState { .. } => "SafeState",
        };

        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event_type = event_type,
                request_id = %self.id,
                error = %e,
                "Failed to persist event"
            );
            emit_fail(ctx, e).await;
        };
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            request_id = %self.id,
            version = self.version,
            state = ?self.state,
            error = %error,
            "Child fault in request manager"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for RequestManager {
    type Persistence = LightPersistence;
    type InitParams = InitRequestManager;

    fn update(&mut self, state: Self) {
        self.command = state.command;
        self.request = state.request;
        self.state = state.state;
        self.version = state.version;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            retry_diff: 0,
            retry_timeout: 0,
            request_started_at: None,
            current_phase: None,
            current_phase_started_at: None,
            our_key: params.our_key,
            id: DigestIdentifier::default(),
            subject_id: params.subject_id,
            governance_id: params.governance_id,
            command: ReqManInitMessage::Evaluate,
            request: None,
            state: RequestManagerState::Starting,
            version: 0,
            helpers: Some(params.helpers),
        }
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RequestManagerEvent::Finish => {
                debug!(
                    event_type = "Finish",
                    request_id = %self.id,
                    "Applying finish event"
                );
                self.state = RequestManagerState::End;
                self.request = None;
                self.id = DigestIdentifier::default();
            }
            RequestManagerEvent::UpdateState { state } => {
                debug!(
                    event_type = "UpdateState",
                    request_id = %self.id,
                    old_state = ?self.state,
                    new_state = ?state,
                    "Applying state update"
                );
                self.state = *state.clone()
            }
            RequestManagerEvent::UpdateVersion { version } => {
                debug!(
                    event_type = "UpdateVersion",
                    request_id = %self.id,
                    old_version = self.version,
                    new_version = version,
                    "Applying version update"
                );
                self.state = RequestManagerState::Starting;
                self.version = *version
            }
            RequestManagerEvent::SafeState { command, request } => {
                debug!(
                    event_type = "SafeState",
                    request_id = %self.id,
                    command = ?command,
                    "Applying safe state"
                );
                self.version = 0;
                self.retry_diff = 0;
                self.retry_timeout = 0;
                self.state = RequestManagerState::Starting;
                self.request = Some(request.clone());
                self.command = command.clone();
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for RequestManager {}
