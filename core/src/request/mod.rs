use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message, Response, Sink,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::Namespace;
use ave_common::bridge::request::{
    ApprovalState, ApprovalStateRes, EventRequestType,
};
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signed, TimeStamp, hash_borsh,
};
use ave_common::request::EventRequest;
use ave_common::response::{
    RequestState, RequestsInManager, RequestsInManagerSubject,
};

use borsh::{BorshDeserialize, BorshSerialize};
use error::RequestHandlerError;
use manager::{RequestManager, RequestManagerMessage};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tracing::{Span, error, info_span};
use types::ReqManInitMessage;

use crate::approval::persist::{
    ApprPersist, ApprPersistMessage, ApprPersistResponse,
};
use crate::approval::request::ApprovalReq;
use crate::db::Storable;
use crate::governance::events::GovernanceEvent;
use crate::governance::model::{HashThisRole, RoleTypes};
use crate::helpers::db::ExternalDB;
use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::{get_subject_data, i_owner_new_owner};
use crate::model::common::subject::{get_gov, get_version};
use crate::model::common::{
    check_subject_creation, emit_fail, send_to_tracking,
};
use crate::node::{Node, NodeMessage, NodeResponse, SubjectData};
use crate::request::manager::InitRequestManager;
use crate::request::tracking::{RequestTracking, RequestTrackingMessage};
use crate::system::ConfigHelper;

pub mod error;
pub mod manager;
pub mod reboot;
pub mod tracking;
pub mod types;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestData {
    pub request_id: DigestIdentifier,
    pub subject_id: DigestIdentifier,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestHandler {
    #[serde(skip)]
    helpers: Option<(HashAlgorithm, Arc<NetworkSender>)>,
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    handling: HashMap<DigestIdentifier, DigestIdentifier>,
    in_queue: HashMap<
        DigestIdentifier,
        VecDeque<(Signed<EventRequest>, DigestIdentifier)>,
    >,
}

impl BorshSerialize for RequestHandler {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the fields we want to persist, skipping 'owner'
        BorshSerialize::serialize(&self.handling, writer)?;
        BorshSerialize::serialize(&self.in_queue, writer)?;
        Ok(())
    }
}

impl BorshDeserialize for RequestHandler {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let handling =
            HashMap::<DigestIdentifier, DigestIdentifier>::deserialize_reader(
                reader,
            )?;
        let in_queue = HashMap::<
            DigestIdentifier,
            VecDeque<(Signed<EventRequest>, DigestIdentifier)>,
        >::deserialize_reader(reader)?;

        let our_key = Arc::new(PublicKey::default());

        Ok(Self {
            helpers: None,
            our_key,
            handling,
            in_queue,
        })
    }
}

impl RequestHandler {
    async fn check_signature(
        ctx: &mut ActorContext<Self>,
        our_key: PublicKey,
        signer: PublicKey,
        governance_id: &DigestIdentifier,
        event_request: &EventRequestType,
        subject_data: SubjectData,
    ) -> Result<(), ActorError> {
        match event_request {
            EventRequestType::Create
            | EventRequestType::Transfer
            | EventRequestType::Confirm
            | EventRequestType::Reject
            | EventRequestType::Eol => {
                if signer != our_key {
                    return Err(ActorError::Functional { description: "In the events of Create, Transfer, Confirm, Reject or EOL, the event must be signed by the node".to_string() });
                }
            }
            EventRequestType::Fact => {
                let gov = get_gov(ctx, governance_id).await?;
                match subject_data {
                    SubjectData::Tracker {
                        schema_id,
                        namespace,
                        ..
                    } => {
                        if !gov.has_this_role(HashThisRole::Schema {
                            who: signer,
                            role: RoleTypes::Issuer,
                            schema_id,
                            namespace: Namespace::from(namespace),
                        }) {
                            return Err(ActorError::Functional {
                            description:
                                "In fact events, the signer has to be an issuer"
                                    .to_string(),
                        });
                        }
                    }
                    SubjectData::Governance { .. } => {
                        if !gov.has_this_role(HashThisRole::Gov {
                            who: signer,
                            role: RoleTypes::Issuer,
                        }) {
                            return Err(ActorError::Functional {
                            description:
                                "In fact events, the signer has to be an issuer"
                                    .to_string(),
                        });
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn queued_event(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let request_actor = ctx.reference().await?;
        request_actor
            .tell(RequestHandlerMessage::PopQueue {
                subject_id: subject_id.to_owned(),
            })
            .await
    }

    async fn error_queue_handling(
        &mut self,
        ctx: &mut ActorContext<Self>,
        error: String,
        subject_id: &DigestIdentifier,
        request_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        self.on_event(
            RequestHandlerEvent::Invalid {
                subject_id: subject_id.to_owned(),
            },
            ctx,
        )
        .await;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: request_id.clone(),
                state: RequestState::Invalid {
                    error,
                    sn: None,
                    subject_id: subject_id.to_string(),
                    who: self.our_key.to_string(),
                },
            },
        )
        .await?;

        Self::queued_event(ctx, subject_id).await
    }

    async fn change_approval(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        state: ApprovalStateRes,
    ) -> Result<(), RequestHandlerError> {
        if state == ApprovalStateRes::Obsolete {
            return Err(RequestHandlerError::ObsoleteApproval);
        }

        let approver_path =
            ActorPath::from(format!("/user/node/subject_manager/{}/approver", subject_id));
        let approver_actor = ctx
            .system()
            .get_actor::<ApprPersist>(&approver_path)
            .await
            .map_err(|_| {
                RequestHandlerError::ApprovalNotFound(subject_id.to_string())
            })?;

        approver_actor
            .tell(ApprPersistMessage::ChangeResponse {
                response: state.clone(),
            })
            .await
            .map_err(|_| RequestHandlerError::ApprovalChangeFailed)
    }

    async fn get_approval(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        state: Option<ApprovalState>,
    ) -> Result<Option<(ApprovalReq, ApprovalState)>, RequestHandlerError> {
        let approver_path =
            ActorPath::from(format!("/user/node/subject_manager/{}/approver", subject_id));
        let approver_actor = ctx
            .system()
            .get_actor::<ApprPersist>(&approver_path)
            .await
            .map_err(|_| {
                RequestHandlerError::ApprovalNotFound(subject_id.to_string())
            })?;

        let response = approver_actor
            .ask(ApprPersistMessage::GetApproval { state })
            .await
            .map_err(|_| RequestHandlerError::ApprovalGetFailed)?;

        let res = match response {
            ApprPersistResponse::Ok => None,
            ApprPersistResponse::Approval { request, state } => {
                Some((request, state))
            }
        };

        Ok(res)
    }

    async fn get_all_approvals(
        ctx: &ActorContext<Self>,
        state: Option<ApprovalState>,
    ) -> Result<Vec<(ApprovalReq, ApprovalState)>, ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor = ctx.system().get_actor::<Node>(&node_path).await?;
        let response = node_actor.ask(NodeMessage::GetGovernances).await?;
        let vec = match response {
            NodeResponse::Governances(govs) => govs,
            _ => {
                return Err(ActorError::UnexpectedResponse {
                    path: node_path,
                    expected: "NodeResponse::Governances".to_string(),
                });
            }
        };

        let mut responses = vec![];
        for governance in vec.iter() {
            let approver_path =
                ActorPath::from(format!("/user/node/subject_manager/{}/approver", governance));
            if let Ok(approver_actor) =
                ctx.system().get_actor::<ApprPersist>(&approver_path).await
            {
                let response = approver_actor
                    .ask(ApprPersistMessage::GetApproval {
                        state: state.clone(),
                    })
                    .await?;

                match response {
                    ApprPersistResponse::Ok => {}
                    ApprPersistResponse::Approval { request, state } => {
                        responses.push((request, state))
                    }
                };
            };
        }

        Ok(responses)
    }

    async fn check_owner_new_owner(
        ctx: &mut ActorContext<Self>,
        request: &EventRequest,
    ) -> Result<(), RequestHandlerError> {
        match request {
            EventRequest::Create(..) => {}
            EventRequest::Fact(..)
            | EventRequest::Transfer(..)
            | EventRequest::EOL(..) => {
                let subject_id = request.get_subject_id();
                let (i_owner, i_new_owner) =
                    i_owner_new_owner(ctx, &subject_id).await?;
                if !i_owner {
                    return Err(RequestHandlerError::NotOwner(
                        subject_id.to_string(),
                    ));
                }

                if i_new_owner.is_some() {
                    return Err(RequestHandlerError::PendingNewOwner(
                        subject_id.to_string(),
                    ));
                }
            }
            EventRequest::Confirm(..) | EventRequest::Reject(..) => {
                let subject_id = request.get_subject_id();
                let (i_owner, i_new_owner) =
                    i_owner_new_owner(ctx, &subject_id).await?;
                if i_owner {
                    return Err(RequestHandlerError::IsOwner(
                        subject_id.to_string(),
                    ));
                }

                if let Some(new_owner) = i_new_owner {
                    if !new_owner {
                        return Err(RequestHandlerError::NotNewOwner(
                            subject_id.to_string(),
                        ));
                    }
                } else {
                    return Err(RequestHandlerError::NoNewOwnerPending(
                        subject_id.to_string(),
                    ));
                }
            }
        };
        Ok(())
    }

    fn check_event_request(
        request: &EventRequest,
        is_gov: bool,
    ) -> Result<(), RequestHandlerError> {
        match request {
            EventRequest::Create(create_request) => {
                if let Some(name) = &create_request.name
                    && (name.is_empty() || name.len() > 100)
                {
                    return Err(RequestHandlerError::InvalidName);
                }

                if let Some(description) = &create_request.description
                    && (description.is_empty() || description.len() > 200)
                {
                    return Err(RequestHandlerError::InvalidDescription);
                }

                if !create_request.schema_id.is_valid_in_request() {
                    return Err(RequestHandlerError::InvalidSchemaId);
                }

                if is_gov {
                    if !create_request.governance_id.is_empty() {
                        return Err(
                            RequestHandlerError::GovernanceIdMustBeEmpty,
                        );
                    }

                    if !create_request.namespace.is_empty() {
                        return Err(RequestHandlerError::NamespaceMustBeEmpty);
                    }
                } else if create_request.governance_id.is_empty() {
                    return Err(RequestHandlerError::GovernanceIdRequired);
                }
            }
            EventRequest::Transfer(transfer_request) => {
                if transfer_request.new_owner.is_empty() {
                    return Err(RequestHandlerError::TransferNewOwnerEmpty);
                }
            }
            EventRequest::Confirm(confirm_request) => {
                if is_gov {
                    if let Some(name_old_owner) =
                        &confirm_request.name_old_owner
                        && name_old_owner.is_empty()
                    {
                        return Err(
                            RequestHandlerError::ConfirmNameOldOwnerEmpty,
                        );
                    }
                } else if confirm_request.name_old_owner.is_some() {
                    return Err(
                        RequestHandlerError::ConfirmTrackerNameOldOwner,
                    );
                }
            }
            EventRequest::Fact(fact_request) => {
                if is_gov
                    && serde_json::from_value::<GovernanceEvent>(
                        fact_request.payload.0.clone(),
                    )
                    .is_err()
                {
                    return Err(RequestHandlerError::GovFactInvalidEvent);
                }
            }
            EventRequest::Reject(..) | EventRequest::EOL(..) => {}
        }

        Ok(())
    }

    async fn build_subject_data(
        ctx: &mut ActorContext<Self>,
        request: &EventRequest,
    ) -> Result<SubjectData, RequestHandlerError> {
        let subject_data = match request {
            EventRequest::Create(create_request) => {
                if create_request.schema_id.is_gov() {
                    SubjectData::Governance { active: true }
                } else {
                    SubjectData::Tracker {
                        governance_id: create_request.governance_id.clone(),
                        schema_id: create_request.schema_id.clone(),
                        namespace: create_request.namespace.to_string(),
                        active: true,
                    }
                }
            }
            EventRequest::Fact(..)
            | EventRequest::Transfer(..)
            | EventRequest::Confirm(..)
            | EventRequest::Reject(..)
            | EventRequest::EOL(..) => {
                let subject_id = request.get_subject_id();
                let Some(subject_data) =
                    get_subject_data(ctx, &subject_id).await?
                else {
                    return Err(RequestHandlerError::SubjectDataNotFound(
                        subject_id.to_string(),
                    ));
                };

                subject_data
            }
        };

        Ok(subject_data)
    }

    async fn check_creation(
        ctx: &mut ActorContext<Self>,
        subject_data: SubjectData,
        event_request: &EventRequestType,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        match event_request {
            EventRequestType::Create | EventRequestType::Confirm => {
                if let SubjectData::Tracker {
                    governance_id,
                    schema_id,
                    namespace,
                    ..
                } = subject_data
                {
                    let version = get_version(ctx, &governance_id).await?;
                    check_subject_creation(
                        ctx,
                        &governance_id,
                        signer,
                        version,
                        namespace,
                        schema_id,
                    )
                    .await?;
                }
            }
            _ => {}
        }

        Ok(())
    }

    fn build_request_id_subject_id(
        hash: HashAlgorithm,
        request: &Signed<EventRequest>,
    ) -> Result<(DigestIdentifier, DigestIdentifier), RequestHandlerError> {
        match &request.content() {
            EventRequest::Create(..) => {
                let request_id = hash_borsh(
                    &*hash.hasher(),
                    &(request.clone(), TimeStamp::now().as_nanos()),
                )
                .map_err(|e| {
                    RequestHandlerError::RequestIdHash(e.to_string())
                })?;

                let subject_id =
                    hash_borsh(&*hash.hasher(), request).map_err(|e| {
                        RequestHandlerError::SubjectIdHash(e.to_string())
                    })?;

                Ok((request_id, subject_id))
            }
            EventRequest::Fact(..)
            | EventRequest::Transfer(..)
            | EventRequest::Confirm(..)
            | EventRequest::Reject(..)
            | EventRequest::EOL(..) => {
                let request_id = hash_borsh(
                    &*hash.hasher(),
                    &(request.clone(), TimeStamp::now().as_nanos()),
                )
                .map_err(|e| {
                    RequestHandlerError::RequestIdHash(e.to_string())
                })?;

                Ok((request_id, request.content().get_subject_id()))
            }
        }
    }

    async fn handle_queue_request(
        &mut self,
        ctx: &mut ActorContext<Self>,
        request: Signed<EventRequest>,
        request_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        is_gov: bool,
        governance_id: Option<DigestIdentifier>,
    ) -> Result<(), ActorError> {
        let Some(helpers) = self.helpers.clone() else {
            let e = " Can not obtain helpers".to_string();

            return Err(ActorError::FunctionalCritical { description: e });
        };

        let in_handling = self.handling.contains_key(subject_id);
        let in_queue = self.in_queue.contains_key(subject_id);

        if !in_handling && !in_queue {
            let command = Self::build_req_manager_init_msg(
                &EventRequestType::from(request.content()),
                is_gov,
            );
            let init_data = InitRequestManager {
                our_key: self.our_key.clone(),
                subject_id: subject_id.clone(),
                governance_id,
                helpers,
            };

            let actor = ctx
                .create_child(
                    &subject_id.to_string(),
                    RequestManager::initial(init_data),
                )
                .await?;
            actor
                .tell(RequestManagerMessage::FirstRun {
                    command,
                    request,
                    request_id: request_id.clone(),
                })
                .await?;

            self.on_event(
                RequestHandlerEvent::EventToHandling {
                    subject_id: subject_id.clone(),
                    request_id: request_id.clone(),
                },
                ctx,
            )
            .await;

            send_to_tracking(
                ctx,
                RequestTrackingMessage::UpdateState {
                    request_id: request_id.clone(),
                    state: RequestState::Handling,
                },
            )
            .await?;
        } else {
            self.on_event(
                RequestHandlerEvent::EventToQueue {
                    subject_id: subject_id.clone(),
                    event: request,
                    request_id: request_id.clone(),
                },
                ctx,
            )
            .await;

            send_to_tracking(
                ctx,
                RequestTrackingMessage::UpdateState {
                    request_id: request_id.clone(),
                    state: RequestState::InQueue,
                },
            )
            .await?;
        }

        Ok(())
    }

    const fn build_req_manager_init_msg(
        event_request: &EventRequestType,
        is_gov: bool,
    ) -> ReqManInitMessage {
        match event_request {
            EventRequestType::Create => ReqManInitMessage::Validate,
            EventRequestType::Fact => ReqManInitMessage::Evaluate,
            EventRequestType::Transfer => ReqManInitMessage::Evaluate,
            EventRequestType::Confirm => {
                if is_gov {
                    ReqManInitMessage::Evaluate
                } else {
                    ReqManInitMessage::Validate
                }
            }
            EventRequestType::Reject => ReqManInitMessage::Validate,
            EventRequestType::Eol => ReqManInitMessage::Validate,
        }
    }

    async fn check_in_queue(
        ctx: &mut ActorContext<Self>,
        request: &Signed<EventRequest>,
        our_key: PublicKey,
    ) -> Result<bool, RequestHandlerError> {
        if let EventRequest::Create(..) = request.content() {
            return Err(RequestHandlerError::CreationNotQueued);
        }

        Self::check_owner_new_owner(ctx, request.content()).await?;

        let subject_data =
            Self::build_subject_data(ctx, request.content()).await?;
        let event_request_type = EventRequestType::from(request.content());
        let signer = request.signature().signer.clone();
        let governance_id = subject_data
            .get_governance_id()
            .unwrap_or_else(|| request.content().get_subject_id());
        let is_gov = subject_data.get_schema_id().is_gov();

        if !subject_data.get_active() {
            return Err(RequestHandlerError::SubjectNotActive(
                request.content().get_subject_id().to_string(),
            ));
        }

        Self::check_signature(
            ctx,
            our_key,
            signer.clone(),
            &governance_id,
            &event_request_type,
            subject_data.clone(),
        )
        .await?;

        Self::check_creation(ctx, subject_data, &event_request_type, signer)
            .await?;

        Ok(is_gov)
    }

    async fn in_queue_to_handling(
        &mut self,
        ctx: &mut ActorContext<Self>,
        request: Signed<EventRequest>,
        request_id: &DigestIdentifier,
        is_gov: bool,
    ) -> Result<(), ActorError> {
        let command = Self::build_req_manager_init_msg(
            &EventRequestType::from(request.content()),
            is_gov,
        );
        let subject_id = request.content().get_subject_id();

        let actor = ctx
            .get_child::<RequestManager>(&subject_id.to_string())
            .await?;

        actor
            .tell(RequestManagerMessage::FirstRun {
                command,
                request,
                request_id: request_id.clone(),
            })
            .await?;

        self.on_event(
            RequestHandlerEvent::EventToHandling {
                subject_id: subject_id.clone(),
                request_id: request_id.clone(),
            },
            ctx,
        )
        .await;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: request_id.clone(),
                state: RequestState::Handling,
            },
        )
        .await
    }

    async fn end_child(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let actor = ctx
            .get_child::<RequestManager>(&subject_id.to_string())
            .await?;
        actor.ask_stop().await
    }

    async fn manual_abort_request(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let actor = ctx
            .get_child::<RequestManager>(&subject_id.to_string())
            .await?;

        actor.tell(RequestManagerMessage::ManualAbort).await
    }
}

#[derive(Debug, Clone)]
pub enum RequestHandlerMessage {
    NewRequest {
        request: Signed<EventRequest>,
    },
    RequestInManager,
    RequestInManagerSubjectId {
        subject_id: DigestIdentifier,
    },
    ChangeApprovalState {
        subject_id: DigestIdentifier,
        state: ApprovalStateRes,
    },
    GetApproval {
        subject_id: DigestIdentifier,
        state: Option<ApprovalState>,
    },
    GetAllApprovals {
        state: Option<ApprovalState>,
    },
    PopQueue {
        subject_id: DigestIdentifier,
    },
    EndHandling {
        subject_id: DigestIdentifier,
    },
    AbortRequest {
        subject_id: DigestIdentifier,
    },
}

impl Message for RequestHandlerMessage {}

#[derive(Debug, Clone)]
pub enum RequestHandlerResponse {
    RequestInManager(RequestsInManager),
    RequestInManagerSubjectId(RequestsInManagerSubject),
    Ok(RequestData),
    Response(String),
    Approval(Option<(ApprovalReq, ApprovalState)>),
    Approvals(Vec<(ApprovalReq, ApprovalState)>),
    None,
}

impl Response for RequestHandlerResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RequestHandlerEvent {
    EventToQueue {
        subject_id: DigestIdentifier,
        event: Signed<EventRequest>,
        request_id: DigestIdentifier,
    },
    Invalid {
        subject_id: DigestIdentifier,
    },
    FinishHandling {
        subject_id: DigestIdentifier,
    },
    EventToHandling {
        subject_id: DigestIdentifier,
        request_id: DigestIdentifier,
    },
}

impl Event for RequestHandlerEvent {}

#[async_trait]
impl Actor for RequestHandler {
    type Event = RequestHandlerEvent;
    type Message = RequestHandlerMessage;
    type Response = RequestHandlerResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("RequestHandler"),
            |parent_span| info_span!(parent: parent_span, "RequestHandler"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.init_store("request", None, false, ctx).await {
            error!(
                error = %e,
                "Failed to initialize store during pre_start"
            );
            return Err(e);
        }

        let Some(ext_db): Option<Arc<ExternalDB>> =
            ctx.system().get_helper("ext_db").await
        else {
            error!("External database helper not found");
            return Err(ActorError::Helper {
                name: "ext_db".to_string(),
                reason: "Not found".to_string(),
            });
        };

        let tracking_size = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.tracking_size
        } else {
            error!(
                helper = "config",
                "Config helper not found during pre_start"
            );
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_string(),
            });
        };

        let tracking = match ctx
            .create_child("tracking", RequestTracking::new(tracking_size))
            .await
        {
            Ok(actor) => actor,
            Err(e) => {
                error!(
                    error = %e,
                    "Failed to create tracking child during pre_start"
                );
                return Err(e);
            }
        };

        let sink =
            Sink::new(tracking.subscribe(), ext_db.get_request_tracking());

        ctx.system().run_sink(sink).await;

        let Some((hash, network)) = self.helpers.clone() else {
            let e = " Can not obtain helpers".to_string();
            error!(
                error = %e,
                "Failed to obtain helpers during pre_start"
            );
            ctx.system().crash_system();
            return Err(ActorError::FunctionalCritical { description: e });
        };

        for (subject_id, request_id) in self.handling.clone() {
            let governance_id = get_subject_data(ctx, &subject_id)
                .await?
                .and_then(|data| data.get_governance_id());
            let request_manager_init = InitRequestManager {
                our_key: self.our_key.clone(),
                subject_id: subject_id.clone(),
                governance_id,
                helpers: (hash, network.clone()),
            };

            let request_manager_actor = match ctx
                .create_child(
                    &subject_id.to_string(),
                    RequestManager::initial(request_manager_init),
                )
                .await
            {
                Ok(actor) => actor,
                Err(e) => {
                    error!(
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to create request manager child during pre_start"
                    );
                    return Err(e);
                }
            };

            if let Err(e) = request_manager_actor
                .tell(RequestManagerMessage::Run {
                    request_id: request_id.clone(),
                })
                .await
            {
                error!(
                    subject_id = %subject_id,
                    request_id = %request_id,
                    error = %e,
                    "Failed to send Run message to request manager during pre_start"
                );
                return Err(e);
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for RequestHandler {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RequestHandlerMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<RequestHandlerResponse, ActorError> {
        match msg {
            RequestHandlerMessage::RequestInManagerSubjectId { subject_id } => {
                let handling =
                    self.handling.get(&subject_id).map(|x| x.to_string());
                let in_queue = self.in_queue.get(&subject_id).map(|x| {
                    x.iter().map(|x| x.1.to_string()).collect::<Vec<String>>()
                });

                Ok(RequestHandlerResponse::RequestInManagerSubjectId(
                    RequestsInManagerSubject { handling, in_queue },
                ))
            }
            RequestHandlerMessage::RequestInManager => Ok(
                RequestHandlerResponse::RequestInManager(RequestsInManager {
                    handling: self
                        .handling
                        .iter()
                        .map(|x| (x.0.to_string(), x.1.to_string()))
                        .collect(),
                    in_queue: self
                        .in_queue
                        .iter()
                        .map(|x| {
                            (
                                x.0.to_string(),
                                x.1.iter()
                                    .map(|x| x.1.to_string())
                                    .collect::<Vec<String>>(),
                            )
                        })
                        .collect(),
                }),
            ),
            RequestHandlerMessage::AbortRequest { subject_id } => {
                self.manual_abort_request(ctx, &subject_id).await?;
                Ok(RequestHandlerResponse::None)
            }
            RequestHandlerMessage::ChangeApprovalState {
                subject_id,
                state,
            } => {
                Self::change_approval(ctx, &subject_id, state.clone())
                    .await
                    .map_err(|e| {
                        error!(
                            error = %e,
                            "ChangeApprovalState failed"
                        );
                        ActorError::from(e)
                    })?;

                Ok(RequestHandlerResponse::Response(format!(
                    "The approval request for subject {} has changed to {}",
                    subject_id, state
                )))
            }
            RequestHandlerMessage::GetApproval { subject_id, state } => {
                let res = Self::get_approval(ctx, &subject_id, state.clone())
                    .await
                    .map_err(ActorError::from)?;

                Ok(RequestHandlerResponse::Approval(res))
            }
            RequestHandlerMessage::GetAllApprovals { state } => {
                let res = Self::get_all_approvals(ctx, state.clone())
                    .await
                    .map_err(|e| {
                        error!(
                            error = %e,
                            "GetAllApprovals failed"
                        );
                        e
                    })?;

                Ok(RequestHandlerResponse::Approvals(res))
            }
            RequestHandlerMessage::NewRequest { request } => {
                if let Err(e) = request.verify() {
                    let err = RequestHandlerError::SignatureVerification(
                        e.to_string(),
                    );
                    error!(error = %err, "Request signature verification failed");
                    return Err(ActorError::from(err));
                };

                let Some((hash, ..)) = self.helpers.clone() else {
                    let err = RequestHandlerError::HelpersNotInitialized;
                    error!(
                        msg_type = "NewRequest",
                        error = %err,
                        "Helpers not initialized"
                    );
                    return Err(emit_fail(ctx, ActorError::from(err)).await);
                };

                if let Err(e) =
                    Self::check_owner_new_owner(ctx, request.content()).await
                {
                    error!(
                        msg_type = "NewRequest",
                        error = %e,
                        "Owner or new owner check failed"
                    );
                    return Err(ActorError::from(e));
                }

                let subject_data = match Self::build_subject_data(
                    ctx,
                    request.content(),
                )
                .await
                {
                    Ok(data) => data,
                    Err(e) => {
                        error!(
                            msg_type = "NewRequest",
                            error = %e,
                            "Failed to build subject data"
                        );
                        return Err(ActorError::from(e));
                    }
                };
                let event_request_type =
                    EventRequestType::from(request.content());
                let signer = request.signature().signer.clone();
                let governance_id = subject_data.get_governance_id();
                let governance_subject_id = governance_id
                    .clone()
                    .unwrap_or_else(|| request.content().get_subject_id());
                let is_gov = subject_data.get_schema_id().is_gov();

                if !subject_data.get_active() {
                    let subject_id = request.content().get_subject_id();
                    error!(
                        msg_type = "NewRequest",
                        subject_id = %subject_id,
                        "Subject is not active"
                    );
                    return Err(ActorError::from(
                        RequestHandlerError::SubjectNotActive(
                            subject_id.to_string(),
                        ),
                    ));
                }

                if let Err(e) =
                    Self::check_event_request(request.content(), is_gov)
                {
                    error!(
                        msg_type = "NewRequest",
                        error = %e,
                        "Event request validation failed"
                    );
                    return Err(ActorError::from(e));
                }

                if let Err(e) = Self::check_signature(
                    ctx,
                    (*self.our_key).clone(),
                    signer.clone(),
                    &governance_subject_id,
                    &event_request_type,
                    subject_data.clone(),
                )
                .await
                {
                    error!(
                        msg_type = "NewRequest",
                        governance_id = %governance_subject_id,
                        error = %e,
                        "Signature check failed"
                    );
                    return Err(e);
                }

                if let Err(e) = Self::check_creation(
                    ctx,
                    subject_data,
                    &event_request_type,
                    signer,
                )
                .await
                {
                    error!(
                        msg_type = "NewRequest",
                        error = %e,
                        "Creation check failed"
                    );
                    return Err(e);
                }

                let (request_id, subject_id) =
                    match Self::build_request_id_subject_id(hash, &request) {
                        Ok(ids) => ids,
                        Err(e) => {
                            error!(
                                msg_type = "NewRequest",
                                error = %e,
                                "Failed to build request ID and subject ID"
                            );
                            return Err(ActorError::from(e));
                        }
                    };

                if let Err(e) = self
                    .handle_queue_request(
                        ctx,
                        request,
                        &request_id,
                        &subject_id,
                        is_gov,
                        governance_id,
                    )
                    .await
                {
                    error!(
                        msg_type = "NewRequest",
                        request_id = %request_id,
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to handle queue request"
                    );
                    return Err(e);
                }

                Ok(RequestHandlerResponse::Ok(RequestData {
                    request_id,
                    subject_id,
                }))
            }
            RequestHandlerMessage::PopQueue { subject_id } => {
                let (event, request_id) = if let Some(events) =
                    self.in_queue.get(&subject_id)
                {
                    if let Some((event, request_id)) =
                        events.clone().pop_front()
                    {
                        (event, request_id)
                    } else {
                        if let Err(e) = Self::end_child(ctx, &subject_id).await
                        {
                            error!(
                                msg_type = "PopQueue",
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to end child actor when queue is empty"
                            );
                            ctx.system().crash_system();
                            return Err(e);
                        }
                        return Ok(RequestHandlerResponse::None);
                    }
                } else {
                    if let Err(e) = Self::end_child(ctx, &subject_id).await {
                        error!(
                            msg_type = "PopQueue",
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to end child actor when no events available"
                        );
                        ctx.system().crash_system();
                        return Err(e);
                    }
                    return Ok(RequestHandlerResponse::None);
                };

                let is_gov = match Self::check_in_queue(
                    ctx,
                    &event,
                    (*self.our_key).clone(),
                )
                .await
                {
                    Ok(is_gov) => is_gov,
                    Err(e) => {
                        if let Err(e) = self
                            .error_queue_handling(
                                ctx,
                                e.to_string(),
                                &subject_id,
                                &request_id,
                            )
                            .await
                        {
                            error!(
                                msg_type = "PopQueue",
                                subject_id = %subject_id,
                                request_id = %request_id,
                                error = %e,
                                "Failed to handle queue error"
                            );
                            ctx.system().crash_system();
                            return Err(e);
                        };

                        return Ok(RequestHandlerResponse::None);
                    }
                };

                if let Err(e) = self
                    .in_queue_to_handling(ctx, event, &request_id, is_gov)
                    .await
                {
                    error!(
                        msg_type = "PopQueue",
                        request_id = %request_id,
                        error = %e,
                        "Failed to transition from queue to handling"
                    );
                    ctx.system().crash_system();
                    return Err(e);
                }

                Ok(RequestHandlerResponse::None)
            }
            RequestHandlerMessage::EndHandling { subject_id } => {
                self.on_event(
                    RequestHandlerEvent::FinishHandling {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                if let Err(e) = Self::queued_event(ctx, &subject_id).await {
                    error!(
                        msg_type = "EndHandling",
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to enqueue next event"
                    );
                    ctx.system().crash_system();
                    return Err(e);
                }

                Ok(RequestHandlerResponse::None)
            }
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child fault in request handler"
        );
        ctx.system().crash_system();
        ChildAction::Stop
    }

    async fn on_event(
        &mut self,
        event: RequestHandlerEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                error = %e,
                "Failed to persist event"
            );
            ctx.system().crash_system();
        };
    }
}

#[async_trait]
impl Storable for RequestHandler {}

#[async_trait]
impl PersistentActor for RequestHandler {
    type Persistence = LightPersistence;
    type InitParams = (Arc<PublicKey>, (HashAlgorithm, Arc<NetworkSender>));

    fn update(&mut self, state: Self) {
        self.in_queue = state.in_queue;
        self.handling = state.handling;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            our_key: params.0,
            helpers: Some(params.1),
            handling: HashMap::new(),
            in_queue: HashMap::new(),
        }
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RequestHandlerEvent::EventToQueue {
                subject_id,
                event,
                request_id,
            } => {
                self.in_queue
                    .entry(subject_id.clone())
                    .or_default()
                    .push_back((event.clone(), request_id.clone()));
            }
            RequestHandlerEvent::Invalid { subject_id } => {
                if let Some(vec) = self.in_queue.get_mut(subject_id) {
                    vec.pop_front();
                    if vec.is_empty() {
                        self.in_queue.remove(subject_id);
                    }
                }
            }
            RequestHandlerEvent::EventToHandling {
                subject_id,
                request_id,
            } => {
                self.handling.insert(subject_id.clone(), request_id.clone());
                if let Some(vec) = self.in_queue.get_mut(subject_id) {
                    vec.pop_front();
                    if vec.is_empty() {
                        self.in_queue.remove(subject_id);
                    }
                }
            }
            RequestHandlerEvent::FinishHandling { subject_id } => {
                self.handling.remove(subject_id);
            }
        };

        Ok(())
    }
}
