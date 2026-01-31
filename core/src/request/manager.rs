use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Event,
    Handler, Message,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
};
use ave_common::request::EventRequest;
use ave_common::response::RequestState;
use ave_common::{Namespace, SchemaType, ValueWrapper};
use borsh::{BorshDeserialize, BorshSerialize};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;
use tracing::{Span, error, info, info_span, warn};

use crate::approval::request::ApprovalReq;
use crate::approval::response::ApprovalRes;
use crate::distribution::{
    Distribution, DistributionMessage, DistributionType,
};
use crate::evaluation::request::EvaluateData;
use crate::evaluation::response::EvaluatorResponse;
use crate::governance::data::GovernanceData;
use crate::governance::model::{ProtocolTypes, Quorum, WitnessesData};
use crate::governance::{Governance, GovernanceMessage, GovernanceResponse};
use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::{SignTypesNode, get_sign, get_subject_data};
use crate::model::common::subject::{
    create_subject, get_gov, get_gov_sn, get_last_ledger_event, get_metadata,
    update_ledger,
};
use crate::model::common::{purge_storage, send_to_tracking};
use crate::model::event::{
    ApprovalData, EvaluationData, Ledger, Protocols, ValidationData,
};
use crate::model::request::EventRequestType;
use crate::node::SubjectData;
use crate::request::tracking::RequestTrackingMessage;
use crate::subject::{Metadata, SignedLedger};
use crate::system::ConfigHelper;
use crate::tracker::{Tracker, TrackerMessage, TrackerResponse};
use crate::validation::request::{ActualProtocols, LastData, ValidationReq};
use crate::{
    ActorMessage, NetworkMessage, Validation, ValidationMessage,
    approval::{Approval, ApprovalMessage},
    auth::{Auth, AuthMessage, AuthResponse, AuthWitness},
    db::Storable,
    evaluation::{Evaluation, EvaluationMessage, request::EvaluationReq},
    model::common::emit_fail,
    node::{Node, NodeMessage},
    update::{Update, UpdateMessage, UpdateNew, UpdateType},
};

const TARGET_MANAGER: &str = "Ave-Request-Manager";

use super::{
    RequestHandler, RequestHandlerMessage,
    reboot::{Reboot, RebootMessage},
    types::{ReqManInitMessage, RequestManagerState},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestManager {
    #[serde(skip)]
    helpers: Option<(HashAlgorithm, Arc<NetworkSender>)>,
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    #[serde(skip)]
    id: String,
    #[serde(skip)]
    subject_id: DigestIdentifier,
    #[serde(skip)]
    retry_timeout: u64,
    #[serde(skip)]
    retry_diff: u64,
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

pub enum InitRequestManager {
    Init {
        our_key: Arc<PublicKey>,
        id: String,
        subject_id: DigestIdentifier,
        command: ReqManInitMessage,
        request: Box<Signed<EventRequest>>,
        helpers: (HashAlgorithm, Arc<NetworkSender>),
    },
    Continue {
        our_key: Arc<PublicKey>,
        id: String,
        subject_id: DigestIdentifier,
        helpers: (HashAlgorithm, Arc<NetworkSender>),
    },
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
        let id = String::default();

        Ok(Self {
            retry_diff: 0,
            retry_timeout: 0,
            helpers: None,
            our_key,
            id,
            subject_id,
            command,
            request,
            state,
            version,
        })
    }
}

impl RequestManager {
    //////// EVAL
    ////////////////////////////////////////////////
    async fn build_evaluation(
        &mut self,
        ctx: &mut ActorContext<RequestManager>,
    ) -> Result<(), ActorError> {
        let Some(request) = self.request.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Request is None".to_string(),
            });
        };

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Evaluation),
            },
            ctx,
        )
        .await;

        let metadata = Self::check_data_eval(ctx, &request).await?;

        let (signed_evaluation_req, quorum, signers, init_state) =
            self.build_request_eval(ctx, &metadata, &request).await?;

        if signers.is_empty() {
            warn!(
                TARGET_MANAGER,
                "Create, There are no evaluators available for the {} scheme",
                metadata.schema_id
            );

            return Err(ActorError::Functional {
                description: "No evaluators could be obtained".to_string(),
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

    async fn check_data_eval(
        ctx: &mut ActorContext<RequestManager>,
        request: &Signed<EventRequest>,
    ) -> Result<Metadata, ActorError> {
        let (subject_id, confirm) = match request.content().clone() {
            EventRequest::Fact(event) => (event.subject_id, false),
            EventRequest::Transfer(event) => (event.subject_id, false),
            EventRequest::Confirm(event) => (event.subject_id, true),
            _ => {
                return Err(ActorError::FunctionalCritical {
                    description:
                        "Only can evaluate Fact, Transfer and Confirm request"
                            .to_owned(),
                });
            }
        };

        let metadata = get_metadata(ctx, &subject_id).await?;

        if confirm && !metadata.schema_id.is_gov() {
            return Err(ActorError::FunctionalCritical {
                description: "Confirm event in trackers can not evaluate"
                    .to_owned(),
            });
        }

        Ok(metadata)
    }

    async fn build_request_eval(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        metadata: &Metadata,
        request: &Signed<EventRequest>,
    ) -> Result<
        (
            Signed<EvaluationReq>,
            Quorum,
            HashSet<PublicKey>,
            Option<ValueWrapper>,
        ),
        ActorError,
    > {
        let is_gov = metadata.schema_id.is_gov();

        let request_type = EventRequestType::from(request.content());
        let (evaluate_data, governance_data, init_state) = match (
            is_gov,
            request_type,
        ) {
            (true, EventRequestType::Fact) => {
                let state = GovernanceData::try_from(
                    metadata.properties.clone(),
                )
                .map_err(|e| {
                    let e = format!(
                        "can not convert GovernanceData from properties: {}",
                        e
                    );
                    ActorError::FunctionalCritical { description: e }
                })?;

                (
                    EvaluateData::GovFact {
                        state: state.clone(),
                    },
                    state,
                    None,
                )
            }
            (true, EventRequestType::Transfer) => {
                let state = GovernanceData::try_from(
                    metadata.properties.clone(),
                )
                .map_err(|e| {
                    let e = format!(
                        "can not convert GovernanceData from properties: {}",
                        e
                    );
                    ActorError::FunctionalCritical { description: e }
                })?;

                (
                    EvaluateData::GovTransfer {
                        state: state.clone(),
                    },
                    state,
                    None,
                )
            }
            (true, EventRequestType::Confirm) => {
                let state = GovernanceData::try_from(
                    metadata.properties.clone(),
                )
                .map_err(|e| {
                    let e = format!(
                        "can not convert GovernanceData from properties: {}",
                        e
                    );
                    ActorError::FunctionalCritical { description: e }
                })?;

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

                let init_state = governance_data
                    .get_init_state(&metadata.schema_id)
                    .map_err(|e| {
                        let e = format!(
                            "can not obtain schema {} from governance: {}",
                            metadata.schema_id, e
                        );
                        ActorError::FunctionalCritical { description: e }
                    })?;

                (
                    EvaluateData::AllSchemasFact {
                        contract: format!(
                            "{}_{}",
                            metadata.governance_id, metadata.schema_id
                        ),
                        state: metadata.properties.clone(),
                    },
                    governance_data,
                    Some(init_state),
                )
            }
            (false, EventRequestType::Transfer) => {
                let governance_data =
                    get_gov(ctx, &metadata.governance_id).await?;
                (
                    EvaluateData::AllSchemasTransfer {
                        governance_data: governance_data.clone(),
                        namespace: metadata.namespace.clone(),
                        schema_id: metadata.schema_id.clone(),
                    },
                    governance_data,
                    None,
                )
            }
            _ => unreachable!(
                "It was previously verified that the matched cases are the only possible ones"
            ),
        };

        let (signers, quorum) = governance_data
            .get_quorum_and_signers(
                ProtocolTypes::Evaluation,
                &metadata.schema_id,
                metadata.namespace.clone(),
            )
            .map_err(|e| ActorError::Functional {
                description: e.to_string(),
            })?;

        let governance_id = if is_gov {
            metadata.subject_id.clone()
        } else {
            metadata.governance_id.clone()
        };

        let eval_req = self.create_req_eval(
            request,
            evaluate_data,
            metadata.sn,
            metadata.namespace.clone(),
            metadata.schema_id.clone(),
            governance_data.version,
            governance_id.clone(),
        );

        let signature =
            get_sign(ctx, SignTypesNode::EvaluationReq(eval_req.clone()))
                .await?;

        let signed_evaluation_req: Signed<EvaluationReq> =
            Signed::from_parts(eval_req, signature);
        Ok((signed_evaluation_req, quorum, signers, init_state))
    }

    fn create_req_eval(
        &self,
        event_request: &Signed<EventRequest>,
        data: EvaluateData,
        sn: u64,
        namespace: Namespace,
        schema_id: SchemaType,
        gov_version: u64,
        governance_id: DigestIdentifier,
    ) -> EvaluationReq {
        EvaluationReq {
            event_request: event_request.clone(),
            data,
            sn: sn + 1,
            gov_version,
            namespace,
            schema_id,
            signer: (*self.our_key).clone(),
            signer_is_owner: *self.our_key == event_request.signature().signer,
            governance_id,
        }
    }

    async fn run_evaluation(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        request: Signed<EvaluationReq>,
        quorum: Quorum,
        init_state: Option<ValueWrapper>,
        signers: HashSet<PublicKey>,
    ) -> Result<(), ActorError> {
        info!(TARGET_MANAGER, "Init evaluation {}", self.id);
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers is None".to_string(),
            });
        };

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
                error: None,
            },
        )
        .await
    }
    //////// APPROVE
    ////////////////////////////////////////////////
    async fn build_request_appro(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        eval_req: EvaluationReq,
        evaluator_res: EvaluatorResponse,
    ) -> Result<Signed<ApprovalReq>, ActorError> {
        let request = ApprovalReq {
            event_request: eval_req.event_request,
            sn: eval_req.sn,
            gov_version: eval_req.gov_version,
            patch: evaluator_res.patch,
            properties_hash: evaluator_res.properties_hash,
            signer: eval_req.signer,
        };

        let signature =
            get_sign(ctx, SignTypesNode::ApprovalReq(request.clone())).await?;

        let signed_approval_req: Signed<ApprovalReq> =
            Signed::from_parts(request, signature);

        Ok(signed_approval_req)
    }

    async fn build_approval(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        eval_req: EvaluationReq,
        evaluator_res: EvaluatorResponse,
    ) -> Result<(), ActorError> {
        let request = self
            .build_request_appro(ctx, eval_req, evaluator_res)
            .await?;

        let governance_data = get_gov(
            ctx,
            &request.content().event_request.content().get_subject_id(),
        )
        .await?;

        let (signers, quorum) = governance_data
            .get_quorum_and_signers(
                ProtocolTypes::Approval,
                &SchemaType::Governance,
                Namespace::new(),
            )
            .map_err(|e| ActorError::Functional {
                description: e.to_string(),
            })?;

        if signers.is_empty() {
            warn!(
                TARGET_MANAGER,
                "Create, There are no approvers available for the {} scheme",
                SchemaType::Governance
            );

            return Err(ActorError::Functional {
                description: "No approvers could be obtained".to_string(),
            });
        }

        self.run_approval(ctx, request, quorum, signers).await
    }

    async fn run_approval(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        request: Signed<ApprovalReq>,
        quorum: Quorum,
        signers: HashSet<PublicKey>,
    ) -> Result<(), ActorError> {
        info!(TARGET_MANAGER, "Init approval {}", self.id);
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers is None".to_string(),
            });
        };

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
                error: None,
            },
        )
        .await
    }

    //////// VALI
    ////////////////////////////////////////////////
    async fn build_validation_req(
        &mut self,
        ctx: &mut ActorContext<RequestManager>,
        eval: Option<(EvaluationReq, EvaluationData)>,
        appro_data: Option<ApprovalData>,
    ) -> Result<
        (
            Signed<ValidationReq>,
            Quorum,
            HashSet<PublicKey>,
            Option<ValueWrapper>,
        ),
        ActorError,
    > {
        let (vali_req, quorum, signers, init_state, schema_id) =
            self.build_validation_data(ctx, eval, appro_data).await?;

        if signers.is_empty() {
            warn!(
                TARGET_MANAGER,
                "Create, There are no validators available for the {} scheme",
                schema_id
            );

            return Err(ActorError::Functional {
                description: "No validators could be obtained".to_string(),
            });
        }

        let signature = get_sign(
            ctx,
            SignTypesNode::ValidationReq(Box::new(vali_req.clone())),
        )
        .await?;

        let signed_validation_req: Signed<ValidationReq> =
            Signed::from_parts(vali_req, signature);

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Validation {
                    request: signed_validation_req.clone(),
                    quorum: quorum.clone(),
                    init_state: init_state.clone(),
                    signers: signers.clone(),
                }),
            },
            ctx,
        )
        .await;

        Ok((signed_validation_req, quorum, signers, init_state))
    }

    async fn build_validation_data(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        eval: Option<(EvaluationReq, EvaluationData)>,
        appro_data: Option<ApprovalData>,
    ) -> Result<
        (
            ValidationReq,
            Quorum,
            HashSet<PublicKey>,
            Option<ValueWrapper>,
            SchemaType,
        ),
        ActorError,
    > {
        let Some(request) = self.request.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Request is None".to_string(),
            });
        };

        if let EventRequest::Create(create) = request.content() {
            if create.schema_id == SchemaType::Governance {
                let governance_data =
                    GovernanceData::new((*self.our_key).clone());
                let (signers, quorum) = governance_data
                    .get_quorum_and_signers(
                        ProtocolTypes::Validation,
                        &SchemaType::Governance,
                        Namespace::new(),
                    )
                    .map_err(|e| ActorError::Functional {
                        description: e.to_string(),
                    })?;

                Ok((
                    ValidationReq::Create {
                        event_request: request.clone(),
                        gov_version: 0,
                    },
                    quorum,
                    signers,
                    None,
                    SchemaType::Governance,
                ))
            } else {
                let governance_data = get_gov(ctx, &self.subject_id).await?;
                let (signers, quorum) = governance_data
                    .get_quorum_and_signers(
                        ProtocolTypes::Validation,
                        &create.schema_id,
                        create.namespace.clone(),
                    )
                    .map_err(|e| ActorError::Functional {
                        description: e.to_string(),
                    })?;

                let init_state = governance_data
                    .get_init_state(&create.schema_id)
                    .map_err(|e| ActorError::Functional {
                        description: e.to_string(),
                    })?;

                Ok((
                    ValidationReq::Create {
                        event_request: request.clone(),
                        gov_version: governance_data.version,
                    },
                    quorum,
                    signers,
                    Some(init_state),
                    create.schema_id.clone(),
                ))
            }
        } else {
            let Some((hash, ..)) = self.helpers else {
                return Err(ActorError::FunctionalCritical {
                    description: "Helpers is None".to_string(),
                });
            };

            let governance_data = get_gov(ctx, &self.subject_id).await?;

            let (actual_protocols, gov_version, sn) =
                if let Some((eval_req, eval_data)) = eval {
                    if let Some(approval_data) = appro_data {
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

            let metadata = get_metadata(ctx, &self.subject_id).await?;
            let sn = if let Some(sn) = sn {
                sn
            } else {
                metadata.sn + 1
            };

            let (signers, quorum) = governance_data
                .get_quorum_and_signers(
                    ProtocolTypes::Validation,
                    &metadata.schema_id,
                    metadata.namespace.clone(),
                )
                .map_err(|e| ActorError::Functional {
                    description: e.to_string(),
                })?;

            let init_state = governance_data
                .get_init_state(&metadata.schema_id)
                .map_err(|e| {
                    let e = format!(
                        "can not obtain schema {} from governance: {}",
                        metadata.schema_id, e
                    );
                    ActorError::FunctionalCritical { description: e }
                })?;

            let last_ledger_event =
                get_last_ledger_event(ctx, &self.subject_id).await?;

            let Some(last_ledger_event) = last_ledger_event else {
                todo!()
            };

            let ledger_hash = hash_borsh(&*hash.hasher(), &last_ledger_event.0)
                .map_err(|e| ActorError::FunctionalCritical {
                    description: format!(
                        "Can not creacte actual ledger event hash: {}",
                        e
                    ),
                })?;

            let schema_id = metadata.schema_id.clone();

            Ok((
                ValidationReq::Event {
                    actual_protocols,
                    event_request: request.clone(),
                    metadata,
                    last_data: LastData {
                        vali_data: last_ledger_event
                            .content()
                            .protocols
                            .get_validation_data(),
                        gov_version: last_ledger_event.content().gov_version,
                    },
                    gov_version,
                    ledger_hash,
                    sn,
                },
                quorum,
                signers,
                Some(init_state),
                schema_id,
            ))
        }
    }

    async fn run_validation(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        request: Signed<ValidationReq>,
        quorum: Quorum,
        signers: HashSet<PublicKey>,
        init_state: Option<ValueWrapper>,
    ) -> Result<(), ActorError> {
        info!(TARGET_MANAGER, "Init validation {}", self.id);
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers is None".to_string(),
            });
        };

        let child = ctx
            .create_child(
                "validation",
                Validation::new(
                    self.our_key.clone(),
                    request,
                    init_state,
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
                error: None,
            },
        )
        .await
    }
    //////// Distribution
    ////////////////////////////////////////////////
    async fn build_ledger(
        &mut self,
        ctx: &mut ActorContext<RequestManager>,
        val_req: ValidationReq,
        val_res: ValidationData,
    ) -> Result<SignedLedger, ActorError> {
        let ledger = match val_req {
            ValidationReq::Create {
                event_request,
                gov_version,
            } => Ledger {
                event_request,
                gov_version,
                sn: 0,
                prev_ledger_event_hash: DigestIdentifier::default(),
                protocols: Protocols::Create {
                    validation: val_res,
                },
            },
            ValidationReq::Event {
                actual_protocols,
                event_request,
                metadata,
                gov_version,
                sn,
                ledger_hash,
                ..
            } => Ledger {
                gov_version,
                sn,
                prev_ledger_event_hash: ledger_hash,
                protocols: Protocols::build(
                    metadata.schema_id.is_gov(),
                    EventRequestType::from(event_request.content()),
                    actual_protocols,
                    val_res,
                )?,
                event_request,
            },
        };

        let signature =
            get_sign(ctx, SignTypesNode::Ledger(ledger.clone())).await?;

        let ledger = SignedLedger(Signed::from_parts(ledger, signature));

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::UpdateSubject {
                    ledger: ledger.clone(),
                }),
            },
            ctx,
        )
        .await;

        Ok(ledger)
    }

    async fn update_subject(
        &mut self,
        ctx: &mut ActorContext<RequestManager>,
        ledger: SignedLedger,
    ) -> Result<(), ActorError> {
        if ledger.content().event_request.content().is_create_event() {
            create_subject(ctx, ledger.clone()).await?;
        } else {
            update_ledger(ctx, &self.subject_id, vec![ledger.clone()]).await?;
        }

        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Distribution { ledger }),
            },
            ctx,
        )
        .await;

        Ok(())
    }

    async fn build_distribution(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        ledger: SignedLedger,
    ) -> Result<bool, ActorError> {
        let witnesses = self
            .build_distribution_data(ctx, ledger.signature().signer.clone())
            .await?;

        let Some(witnesses) = witnesses else {
            return Ok(false);
        };

        if witnesses.is_empty() {
            warn!("");
            return Ok(false);
        }

        self.run_distribution(ctx, witnesses, ledger).await?;

        Ok(true)
    }

    async fn build_distribution_data(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        creator: PublicKey,
    ) -> Result<Option<HashSet<PublicKey>>, ActorError> {
        let Some(request) = self.request.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Request is None".to_string(),
            });
        };

        let witnesses = if let EventRequest::Create(create) = request.content()
        {
            if create.schema_id == SchemaType::Governance {
                None
            } else {
                let governance_data = get_gov(ctx, &self.subject_id).await?;
                let witnesses = governance_data
                    .get_witnesses(WitnessesData::Schema {
                        creator,
                        schema_id: create.schema_id.clone(),
                        namespace: create.namespace.clone(),
                    })
                    .map_err(|e| ActorError::Functional {
                        description: e.to_string(),
                    })?;

                Some(witnesses)
            }
        } else {
            let data = get_subject_data(ctx, &self.subject_id).await?;
            let Some(data) = data else {
                return Err(ActorError::FunctionalCritical {
                    description: "Can not obtain subject data".to_owned(),
                });
            };

            let governance_data = get_gov(ctx, &self.subject_id).await?;

            let witnesses = match data {
                SubjectData::Governance => governance_data
                    .get_witnesses(WitnessesData::Gov)
                    .map_err(|e| ActorError::Functional {
                        description: e.to_string(),
                    })?,
                SubjectData::Tracker {
                    schema_id,
                    namespace,
                    ..
                } => governance_data
                    .get_witnesses(WitnessesData::Schema {
                        creator,
                        schema_id,
                        namespace: Namespace::from(namespace),
                    })
                    .map_err(|e| ActorError::Functional {
                        description: e.to_string(),
                    })?,
            };

            Some(witnesses)
        };

        Ok(witnesses)
    }

    async fn run_distribution(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        witnesses: HashSet<PublicKey>,
        ledger: SignedLedger,
    ) -> Result<(), ActorError> {
        info!(TARGET_MANAGER, "Init distribution {}", self.id);
        let Some((.., network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers is None".to_string(),
            });
        };

        let child = ctx
            .create_child(
                "distribution",
                Distribution::new(network, DistributionType::Request),
            )
            .await?;

        child
            .tell(DistributionMessage::Create {
                ledger: Box::new(ledger),
                witnesses,
            })
            .await?;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Distribution,
                error: None,
            },
        )
        .await
    }

    //////// Reboot
    ////////////////////////////////////////////////
    async fn init_update(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        governance_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let Some((.., network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers is None".to_string(),
            });
        };

        let gov_sn = get_gov_sn(ctx, governance_id).await?;
        let governance_data = get_gov(ctx, governance_id).await?;

        let witnesses = {
            let gov_witnesses = governance_data
                .get_witnesses(WitnessesData::Gov)
                .map_err(|e| ActorError::FunctionalCritical {
                    description: e.to_string(),
                })?;

            let auth_witnesses =
                Self::get_witnesses_auth(ctx, governance_id.clone())
                    .await
                    .unwrap_or_default();

            gov_witnesses
                .union(&auth_witnesses)
                .cloned()
                .collect::<HashSet<PublicKey>>()
        };

        if witnesses.is_empty() {
            todo!("reboot");
        } else if witnesses.len() == 1 {
            let objetive = witnesses.iter().next().expect("len is 1");
            let info = ComunicateInfo {
                receiver: objetive.clone(),
                request_id: String::default(),
                version: 0,
                receiver_actor: format!(
                    "/user/node/distributor_{}",
                    governance_id
                ),
            };

            if let Err(e) = network
                .send_command(network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info,
                        message: ActorMessage::DistributionLedgerReq {
                            actual_sn: Some(gov_sn),
                            subject_id: governance_id.clone(),
                        },
                    },
                })
                .await
            {
                return Err(emit_fail(ctx, e).await);
            };

            let actor = ctx.reference().await?;
            actor
                .tell(RequestManagerMessage::RebootWait {
                    governance_id: governance_id.clone(),
                })
                .await?
        } else {
            let data = UpdateNew {
                network,
                subject_id: governance_id.clone(),
                our_sn: Some(gov_sn),
                witnesses,
                update_type: UpdateType::Auth,
            };

            let updater = Update::new(data);
            let Ok(child) =
                ctx.create_child(&governance_id.to_string(), updater).await
            else {
                let actor = ctx.reference().await?;
                return actor
                    .tell(RequestManagerMessage::RebootWait {
                        governance_id: governance_id.clone(),
                    })
                    .await;
            };

            if let Err(e) = child.tell(UpdateMessage::Run).await {
                return Err(emit_fail(ctx, e).await);
            }
        }

        Ok(())
    }

    async fn get_witnesses_auth(
        ctx: &mut ActorContext<RequestManager>,
        governance_id: DigestIdentifier,
    ) -> Result<HashSet<PublicKey>, ActorError> {
        let path = ActorPath::from("/user/node/auth");
        let actor = ctx.system().get_actor::<Auth>(&path).await?;
        let response = actor
            .ask(AuthMessage::GetAuth {
                subject_id: governance_id,
            })
            .await?;

        match response {
            AuthResponse::Witnesses(witnesses) => Ok(witnesses),
            _ => Err(ActorError::UnexpectedResponse {
                expected: "AuthResponse::Witnesses".to_owned(),
                path,
            }),
        }
    }

    //////// General
    ////////////////////////////////////////////////
    async fn finish_request(
        &mut self,
        ctx: &mut ActorContext<RequestManager>,
    ) -> Result<(), ActorError> {
        self.on_event(RequestManagerEvent::Finish, ctx).await;
        self.end_request(ctx).await?;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: self.id.clone(),
                state: RequestState::Finish,
                error: None,
            },
        )
        .await
    }

    async fn reboot(
        &mut self,
        ctx: &mut ActorContext<RequestManager>,
        reboot_type: RebootType,
        governance_id: DigestIdentifier,
    ) -> Result<(), ActorError> {
        self.on_event(
            RequestManagerEvent::UpdateState {
                state: Box::new(RequestManagerState::Reboot),
            },
            ctx,
        )
        .await;

        let actor = ctx.reference().await?;

        match reboot_type {
            RebootType::Normal => {
                actor
                    .tell(RequestManagerMessage::RebootUpdate { governance_id })
                    .await?;
            }
            RebootType::Diff => {
                self.retry_diff += 1;

                let seconds = match self.retry_diff {
                    1 => 10,
                    2 => 20,
                    3 => 30,
                    _ => 60,
                };

                send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: self.id.clone(),
                        state: RequestState::RebootDiff {
                            seconds,
                            count: self.retry_diff,
                        },
                        error: None,
                    },
                )
                .await?;

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    actor
                        .tell(RequestManagerMessage::RebootUpdate {
                            governance_id,
                        })
                        .await;
                });
            }
            RebootType::TimeOut => {
                self.retry_timeout += 1;

                let seconds = match self.retry_timeout {
                    1 => 30,
                    2 => 60,
                    3 => 120,
                    _ => 300,
                };

                send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: self.id.clone(),
                        state: RequestState::RebootTimeOut {
                            seconds,
                            count: self.retry_timeout,
                        },
                        error: None,
                    },
                )
                .await?;

                tokio::spawn(async move {
                    tokio::time::sleep(Duration::from_secs(seconds)).await;
                    actor
                        .tell(RequestManagerMessage::RebootUpdate {
                            governance_id,
                        })
                        .await;
                });
            }
        }

        Ok(())
    }

    ////////////////////////////////////////////////
    ////////////////////////////////////////////////
    ////////////////////////////////////////////////
    async fn end_request(
        &self,
        ctx: &mut ActorContext<RequestManager>,
    ) -> Result<(), ActorError> {
        let request_path = ActorPath::from("/user/request");
        let request_actor: Option<ActorRef<RequestHandler>> =
            ctx.system().get_actor(&request_path).await;

        if let Some(request_actor) = request_actor {
            request_actor
                .tell(RequestHandlerMessage::EndHandling {
                    id: self.id.clone(),
                    subject_id: self.subject_id.to_string(),
                })
                .await?
        } else {
            return Err(ActorError::NotFound(request_path));
        };

        Ok(())
    }

    async fn abort_request(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        error: &str,
    ) -> Result<(), ActorError> {
        let request_path = ActorPath::from("/user/request");
        let request_actor: Option<ActorRef<RequestHandler>> =
            ctx.system().get_actor(&request_path).await;

        if let Some(request_actor) = request_actor {
            request_actor
                .tell(RequestHandlerMessage::AbortRequest {
                    id: self.id.clone(),
                    subject_id: self.subject_id.to_string(),
                    error: error.to_string(),
                })
                .await?
        } else {
            return Err(ActorError::NotFound(request_path));
        };

        Ok(())
    }

    async fn abort_request_manager(
        &self,
        ctx: &mut ActorContext<RequestManager>,
        error: &str,
        delete_subj: bool,
    ) -> Result<(), ActorError> {
        error!(TARGET_MANAGER, "Aborting request {}", self.id);

        if let EventRequest::Create(create_request) = &self.request.content {
            error!(TARGET_MANAGER, "Deleting Subject {}", self.subject_id);
            if delete_subj {
                Self::delete_subject(
                    ctx,
                    &self.subject_id,
                    create_request.schema_id.is_gov(),
                )
                .await?;
            }
        }

        self.abort_request(ctx, error).await?;

        purge_storage(ctx).await?;
        ctx.stop(None).await;

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum RequestManagerMessage {
    Run,
    FirstRun,
    Abort,
    RebootUpdate {
        governance_id: DigestIdentifier,
    },
    RebootWait {
        governance_id: DigestIdentifier,
    },
    Reboot {
        governance_id: DigestIdentifier,
    },
    RebootTiemOut {
        governance_id: DigestIdentifier,
    },
    RebootDiff {
        governance_id: DigestIdentifier,
    },
    FinishReboot,
    EvaluationRes {
        eval_req: EvaluationReq,
        eval_res: EvaluationData,
    },
    ApprovalRes {
        appro_res: ApprovalData,
    },
    ValidationRes {
        val_req: ValidationReq,
        val_res: ValidationData,
    },
    FinishRequest,
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
        request: Option<Signed<EventRequest>>,
        state: Box<RequestManagerState>,
        version: u64,
    },
}

impl Event for RequestManagerEvent {}

#[async_trait]
impl Actor for RequestManager {
    type Event = RequestManagerEvent;
    type Message = RequestManagerMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RequestManager", id = id)
        } else {
            info_span!("RequestManager", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("request_manager", None, false, ctx).await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<RequestManager> for RequestManager {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RequestManagerMessage,
        ctx: &mut ave_actors::ActorContext<RequestManager>,
    ) -> Result<(), ActorError> {
        match msg {
            RequestManagerMessage::RebootUpdate { governance_id } => {
                info!(TARGET_MANAGER, "Init reboot update {}", self.id);

                if let Err(e) = self.init_update(ctx, &governance_id).await {
                    error!(
                        TARGET_MANAGER,
                        "Reboot, a problem in init reboot: {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                }
            }
            RequestManagerMessage::RebootWait { governance_id } => {
                info!(TARGET_MANAGER, "Init reboot wait {}", self.id);
                let reboot_actor = match ctx
                    .create_child("reboot", Reboot::new(governance_id.clone()))
                    .await
                {
                    Ok(actor) => actor,
                    Err(e) => {
                        error!(
                            TARGET_MANAGER,
                            "Reboot, can not create Reboot actor: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = reboot_actor.tell(RebootMessage::Init).await {
                    error!(
                        TARGET_MANAGER,
                        "Reboot, can not send Init message to Reboot actor: {}",
                        e
                    );
                    return Err(emit_fail(ctx, e).await);
                }
            }
            RequestManagerMessage::RebootDiff { governance_id } => {
                if let Err(e) =
                    self.reboot(ctx, RebootType::Diff, governance_id).await
                {
                    error!("");
                    return Err(emit_fail(ctx, e).await);
                }
            }
            RequestManagerMessage::RebootTiemOut { governance_id } => {
                if let Err(e) =
                    self.reboot(ctx, RebootType::TimeOut, governance_id).await
                {
                    error!("");
                    return Err(emit_fail(ctx, e).await);
                }
            }
            RequestManagerMessage::Reboot { governance_id } => {
                if let Err(e) =
                    self.reboot(ctx, RebootType::Normal, governance_id).await
                {
                    error!("");
                    return Err(emit_fail(ctx, e).await);
                }
            }
            RequestManagerMessage::FinishReboot => {
                info!(TARGET_MANAGER, "Finish reboot {}", self.id);
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
                        TARGET_MANAGER,
                        "FinishReboot, can not update tracking: {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                }

                match self.command {
                    ReqManInitMessage::Evaluate => {
                        if let Err(e) = self.build_evaluation(ctx).await {
                            error!(
                                TARGET_MANAGER,
                                "FinishReboot, can not init evaluation: {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        };
                    }
                    ReqManInitMessage::Validate => {
                        let (request, quorum, signers, init_value) = match self
                            .build_validation_req(ctx, None, None)
                            .await
                        {
                            Ok(data) => data,
                            Err(e) => {
                                error!(
                                    TARGET_MANAGER,
                                    "FinishReboot, can not build validation data: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        };

                        if let Err(e) = self
                            .run_validation(
                                ctx, request, quorum, signers, init_value,
                            )
                            .await
                        {
                            error!(
                                TARGET_MANAGER,
                                "FinishReboot, can not run validation: {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        };
                    }
                };
            }
            RequestManagerMessage::Abort => {
                todo!("Abort")
            }
            RequestManagerMessage::Run | RequestManagerMessage::FirstRun => {
                if let RequestManagerMessage::FirstRun = msg {
                    self.on_event(
                        RequestManagerEvent::SafeState {
                            command: self.command.clone(),
                            request: self.request.clone(),
                            state: Box::new(self.state.clone()),
                            version: self.version,
                        },
                        ctx,
                    )
                    .await;
                }

                info!(TARGET_MANAGER, "Running {}", self.id);
                match self.state.clone() {
                    RequestManagerState::Starting
                    | RequestManagerState::Reboot => {
                        match self.command {
                            ReqManInitMessage::Evaluate => {
                                if let Err(e) = self.build_evaluation(ctx).await
                                {
                                    error!(
                                        TARGET_MANAGER,
                                        "Run, can not init evaluation: {}", e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };
                            }
                            ReqManInitMessage::Validate => {
                                let (request, quorum, signers, init_state) =
                                    match self
                                        .build_validation_req(ctx, None, None)
                                        .await
                                    {
                                        Ok(data) => data,
                                        Err(e) => {
                                            error!(
                                                TARGET_MANAGER,
                                                "FinishReboot, can not build validation data: {}",
                                                e
                                            );
                                            return Err(emit_fail(ctx, e).await);
                                        }
                                    };

                                if let Err(e) = self
                                    .run_validation(
                                        ctx, request, quorum, signers,
                                        init_state,
                                    )
                                    .await
                                {
                                    error!(
                                        TARGET_MANAGER,
                                        "FinishReboot, can not run validation: {}",
                                        e
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };
                            }
                        };
                    }
                    RequestManagerState::Evaluation => {
                        if let Err(e) = self.build_evaluation(ctx).await {
                            error!(
                                TARGET_MANAGER,
                                "Evaluation, can not init evaluation: {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }

                    RequestManagerState::EvaluationRes {
                        eval_req,
                        eval_res,
                    } => {
                        if let Some(evaluator_res) = eval_res.evaluator_res()
                            && evaluator_res.appr_required
                        {
                            if let Err(e) = self
                                .build_approval(ctx, eval_req, evaluator_res)
                                .await
                            {
                                error!(
                                    TARGET_MANAGER,
                                    "Evaluation, can not init approval: {}", e
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        } else {
                            let (request, quorum, signers, init_state) =
                                match self
                                    .build_validation_req(
                                        ctx,
                                        Some((eval_req, eval_res)),
                                        None,
                                    )
                                    .await
                                {
                                    Ok(data) => data,
                                    Err(e) => {
                                        error!(
                                            TARGET_MANAGER,
                                            "FinishReboot, can not build validation data: {}",
                                            e
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                };

                            if let Err(e) = self
                                .run_validation(
                                    ctx, request, quorum, signers, init_state,
                                )
                                .await
                            {
                                error!(
                                    TARGET_MANAGER,
                                    "FinishReboot, can not run validation: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            };
                        }
                    }
                    RequestManagerState::Validation {
                        request,
                        quorum,
                        init_state,
                        signers,
                    } => {
                        if let Err(e) = self
                            .run_validation(
                                ctx, request, quorum, signers, init_state,
                            )
                            .await
                        {
                            error!(
                                TARGET_MANAGER,
                                "FinishReboot, can not run validation: {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        };
                    }
                    RequestManagerState::ValidationRes { val_req, val_res } => {
                        let signed_ledger = match self
                            .build_ledger(ctx, val_req, val_res)
                            .await
                        {
                            Ok(signed_ledger) => signed_ledger,
                            Err(e) => {
                                error!(
                                    TARGET_MANAGER,
                                    "ValidationRes, can not build signed ledger: {}",
                                    e
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        };

                        if let Err(e) = self
                            .update_subject(ctx, signed_ledger.clone())
                            .await
                        {
                            todo!()
                        };

                        match self.build_distribution(ctx, signed_ledger).await
                        {
                            Ok(in_distribution) => {
                                if !in_distribution {
                                    if let Err(e) =
                                        self.finish_request(ctx).await
                                    {
                                        error!(
                                            TARGET_MANAGER,
                                            "FinishRequest, can not end request: {}",
                                            e
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                            }
                            Err(e) => {
                                todo!()
                            }
                        };
                    }
                    RequestManagerState::UpdateSubject { ledger } => {
                        if let Err(e) =
                            self.update_subject(ctx, ledger.clone()).await
                        {
                            todo!()
                        };

                        match self.build_distribution(ctx, ledger).await {
                            Ok(in_distribution) => {
                                if !in_distribution {
                                    if let Err(e) =
                                        self.finish_request(ctx).await
                                    {
                                        error!(
                                            TARGET_MANAGER,
                                            "FinishRequest, can not end request: {}",
                                            e
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                            }
                            Err(e) => {
                                todo!()
                            }
                        };
                    }
                    RequestManagerState::Distribution { ledger } => {
                        match self.build_distribution(ctx, ledger).await {
                            Ok(in_distribution) => {
                                if !in_distribution {
                                    if let Err(e) =
                                        self.finish_request(ctx).await
                                    {
                                        error!(
                                            TARGET_MANAGER,
                                            "FinishRequest, can not end request: {}",
                                            e
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                            }
                            Err(e) => {
                                todo!()
                            }
                        };
                    }
                    RequestManagerState::End => {
                        if let Err(e) = self.end_request(ctx).await {
                            error!(
                                TARGET_MANAGER,
                                "FinishRequest, can not end request: {}", e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };
            }
            RequestManagerMessage::EvaluationRes { eval_req, eval_res } => {
                self.on_event(
                    RequestManagerEvent::UpdateState {
                        state: Box::new(RequestManagerState::EvaluationRes {
                            eval_req: eval_req.clone(),
                            eval_res: eval_res.clone(),
                        }),
                    },
                    ctx,
                )
                .await;

                if let Some(evaluator_res) = eval_res.evaluator_res()
                    && evaluator_res.appr_required
                {
                    if let Err(e) =
                        self.build_approval(ctx, eval_req, evaluator_res).await
                    {
                        error!(
                            TARGET_MANAGER,
                            "Evaluation, can not init evaluation: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                } else {
                    let (request, quorum, signers, init_state) = match self
                        .build_validation_req(
                            ctx,
                            Some((eval_req, eval_res)),
                            None,
                        )
                        .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            error!(
                                TARGET_MANAGER,
                                "FinishReboot, can not build validation data: {}",
                                e
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                    if let Err(e) = self
                        .run_validation(
                            ctx, request, quorum, signers, init_state,
                        )
                        .await
                    {
                        error!(
                            TARGET_MANAGER,
                            "FinishReboot, can not run validation: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    };
                }
            }
            RequestManagerMessage::ApprovalRes { appro_res } => {
                let RequestManagerState::EvaluationRes { eval_req, eval_res } =
                    self.state.clone()
                else {
                    let e = ActorError::FunctionalCritical {
                        description: "Invalid request state".to_owned(),
                    };
                    error!(TARGET_MANAGER, "ApprovalRes, {}", e);
                    return Err(emit_fail(ctx, e).await);
                };
                let (request, quorum, signers, init_state) = match self
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
                            TARGET_MANAGER,
                            "ApprovalRes, can not build validation data: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) = self
                    .run_validation(ctx, request, quorum, signers, init_state)
                    .await
                {
                    error!(
                        TARGET_MANAGER,
                        "ApprovalRes, can not run validation: {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                };
            }
            RequestManagerMessage::ValidationRes { val_res, val_req } => {
                let signed_ledger = match self
                    .build_ledger(ctx, val_req, val_res)
                    .await
                {
                    Ok(signed_ledger) => signed_ledger,
                    Err(e) => {
                        error!(
                            TARGET_MANAGER,
                            "ValidationRes, can not build signed ledger: {}", e
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                if let Err(e) =
                    self.update_subject(ctx, signed_ledger.clone()).await
                {
                    todo!()
                };

                match self.build_distribution(ctx, signed_ledger).await {
                    Ok(in_distribution) => {
                        if !in_distribution {
                            if let Err(e) = self.finish_request(ctx).await {
                                error!(
                                    TARGET_MANAGER,
                                    "FinishRequest, can not end request: {}", e
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                    }
                    Err(e) => {
                        todo!()
                    }
                };
            }
            RequestManagerMessage::FinishRequest => {
                info!(TARGET_MANAGER, "Finish request {}", self.id);

                if let Err(e) = self.finish_request(ctx).await {
                    error!(
                        TARGET_MANAGER,
                        "FinishRequest, can not end request: {}", e
                    );
                    return Err(emit_fail(ctx, e).await);
                }
            }
        }

        Ok(())
    }

    async fn on_event(
        &mut self,
        event: RequestManagerEvent,
        ctx: &mut ActorContext<RequestManager>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_MANAGER,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<RequestManager>,
    ) -> ChildAction {
        error!(TARGET_MANAGER, "OnChildFault, {}", error);
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
        match params {
            InitRequestManager::Init {
                our_key,
                id,
                subject_id,
                command,
                request,
                helpers,
            } => Self {
                retry_diff: 0,
                retry_timeout: 0,
                our_key,
                id,
                subject_id,
                command,
                request: Some(*request),
                state: RequestManagerState::Starting,
                version: 0,
                helpers: Some(helpers),
            },
            InitRequestManager::Continue {
                our_key,
                id,
                subject_id,
                helpers,
            } => Self {
                retry_diff: 0,
                retry_timeout: 0,
                our_key,
                id,
                subject_id,
                command: ReqManInitMessage::Evaluate,
                request: None,
                state: RequestManagerState::Starting,
                version: 0,
                helpers: Some(helpers),
            },
        }
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RequestManagerEvent::Finish => {
                self.state = RequestManagerState::End;
                self.request = None;
                self.id = String::default();
            }
            RequestManagerEvent::UpdateState { state } => {
                self.state = *state.clone()
            }
            RequestManagerEvent::UpdateVersion { version } => {
                self.version = *version
            }
            RequestManagerEvent::SafeState {
                command,
                request,
                state,
                version,
            } => {
                self.version = *version;
                self.state = *state.clone();
                self.request = request.clone();
                self.command = command.clone();
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for RequestManager {}
