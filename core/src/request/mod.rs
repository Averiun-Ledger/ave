use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Event,
    Handler, Message, Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::{Namespace, SchemaType};
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
};
use ave_common::request::{CreateRequest, EventRequest};
use ave_common::response::RequestState;
use borsh::{BorshDeserialize, BorshSerialize};
use manager::{RequestManager, RequestManagerMessage};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tracing::{error, info};
use types::ReqManInitMessage;

use crate::approval::types::ApprovalStateRes;
use crate::governance::data::GovernanceData;
use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::subject_owner;
use crate::model::common::send_to_tracking;
use crate::model::common::subject::{get_gov, get_metadata, get_quantity};
use crate::request::manager::InitRequestManager;
use crate::request::tracking::{RequestTracking, RequestTrackingMessage};
use crate::system::ConfigHelper;
use crate::{
    Node, NodeMessage, NodeResponse,
    db::Storable,
    governance::model::CreatorQuantity,
};

pub mod manager;
pub mod reboot;
pub mod tracking;
pub mod types;

const TARGET_REQUEST: &str = "Ave-Request";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequestData {
    pub request_id: String,
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestHandler {
    #[serde(skip)]
    helpers: Option<(HashAlgorithm, Arc<NetworkSender>)>,
    #[serde(skip)]
    node_key: PublicKey,
    handling: HashMap<String, String>,
    in_queue: HashMap<String, VecDeque<Signed<EventRequest>>>,
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
        let handling = HashMap::<String, String>::deserialize_reader(reader)?;
        let in_queue =
             HashMap::<String, VecDeque<Signed<EventRequest>>>::deserialize_reader(reader)?;

        let node_key = PublicKey::default();

        Ok(Self {
            helpers: None,
            node_key,
            handling,
            in_queue,
        })
    }
}

impl RequestHandler {
    async fn queued_event(
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
    ) -> Result<(), ActorError> {
        let request_path = ActorPath::from("/user/request");
        let request_actor: Option<ave_actors::ActorRef<RequestHandler>> =
            ctx.system().get_actor(&request_path).await;

        if let Some(request_actor) = request_actor {
            request_actor
                .tell(RequestHandlerMessage::PopQueue {
                    subject_id: subject_id.to_owned(),
                })
                .await?
        } else {
            return Err(ActorError::NotFound(request_path));
        }
        Ok(())
    }

    async fn create_subject(
        ctx: &mut ActorContext<RequestHandler>,
        create_req: CreateRequest,
        request: Signed<EventRequest>,
    ) -> Result<DigestIdentifier, ActorError> {
        let hash = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.hash_algorithm
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        let subject_id = hash_borsh(&*hash.hasher(), &request)
            .map_err(|e| ActorError::Functional(e.to_string()))?;

        let data = if create_req.schema_id.is_gov() {
            let gov = GovernanceData::new(request.signature().signer.clone());
            let value = gov.to_value_wrapper();

            CreateSubjectData {
                create_req,
                subject_id,
                creator: request.signature().signer.clone(),
                genesis_gov_version: 0,
                value,
            }
        } else {
            let governance =
                get_gov(ctx, &create_req.governance_id.to_string()).await?;
            let value = governance
                .get_init_state(&create_req.schema_id)
                .map_err(|e| ActorError::Functional(e.to_string()))?;

            CreateSubjectData {
                create_req,
                subject_id,
                creator: request.signature().signer.clone(),
                genesis_gov_version: governance.version,
                value,
            }
        };

        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ave_actors::ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        let response = if let Some(node_actor) = node_actor {
            node_actor
                .ask(NodeMessage::CreateNewSubjectReq(data.clone()))
                .await?
        } else {
            return Err(ActorError::NotFound(node_path));
        };

        match response {
            NodeResponse::SonWasCreated => Ok(data.subject_id),
            _ => Err(ActorError::UnexpectedResponse(
                node_path,
                "NodeResponse::SonWasCreated".to_owned(),
            )),
        }
    }

    async fn error_queue_handling(
        &mut self,
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
    ) -> Result<(), ActorError> {
        self.on_event(
            RequestHandlerEvent::Invalid {
                subject_id: subject_id.to_owned(),
            },
            ctx,
        )
        .await;

        RequestHandler::queued_event(ctx, subject_id).await
    }

    async fn error(
        &mut self,
        ctx: &mut ActorContext<RequestHandler>,
        e: &str,
        subject_id: &str,
        request_id: &str,
    ) -> Result<RequestHandlerResponse, ActorError> {
        error!(TARGET_REQUEST, "PopQueue, {} for {}", e, subject_id);
        if let Err(e) = self.error_queue_handling(ctx, subject_id).await {
            error!(
                TARGET_REQUEST,
                "PopQueue, Can not enqueue next event: {}", e
            );
            ctx.system().stop_system();
            return Err(e);
        }

        if let Err(e) = send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: request_id.to_string(),
                state: RequestState::Invalid,
                error: Some(e.to_string()),
            },
        )
        .await
        {
            error!(TARGET_REQUEST, "PopQueue, can not update tracking: {}", e);
            ctx.system().stop_system();
            return Err(e);
        }

        Ok(RequestHandlerResponse::None)
    }

    pub async fn check_creations(
        &self,
        message: &str,
        ctx: &mut ActorContext<RequestHandler>,
        governance_id: &str,
        schema_id: SchemaType,
        namespace: Namespace,
        gov: GovernanceData,
    ) -> Result<(), ActorError> {
        if let Some(max_quantity) = gov.max_creations(
            &self.node_key,
            schema_id.clone(),
            namespace.clone(),
        ) {
            if let CreatorQuantity::Quantity(max_quantity) = max_quantity {
                let quantity = match get_quantity(
                    ctx,
                    governance_id.to_string(),
                    schema_id.clone(),
                    self.node_key.to_string(),
                    namespace.to_string(),
                )
                .await
                {
                    Ok(quantity) => quantity,
                    Err(e) => {
                        error!(
                            TARGET_REQUEST,
                            "{}, can not get subject quatity of node: {}",
                            message,
                            e
                        );
                        return Err(ActorError::Functional(format!(
                            "Can not get subject quatity of node: {}",
                            e
                        )));
                    }
                };

                if quantity >= max_quantity as usize {
                    error!(
                        TARGET_REQUEST,
                        "{}, The maximum number of subjects you can create for schema_id {} in governance {} has been reached.",
                        message,
                        schema_id,
                        governance_id
                    );
                    return Err(ActorError::Functional(format!(
                        "The maximum number of subjects you can create for schema_id {} in governance {} has been reached.",
                        schema_id, governance_id
                    )));
                }
            }

            Ok(())
        } else {
            let e = "The Scheme does not exist or does not have permissions for the creation of subjects, it needs to be assigned the creator role.";
            error!(TARGET_REQUEST, "{}, {}", message, e);

            Err(ActorError::Functional(e.to_owned()))
        }
    }

    async fn abort_request(
        &mut self,
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
        request_id: &str,
        error: &str,
    ) -> Result<(), ActorError> {
        self.on_event(
            RequestHandlerEvent::Abort {
                subject_id: subject_id.to_owned(),
            },
            ctx,
        )
        .await;

        send_to_tracking(
            ctx,
            RequestTrackingMessage::UpdateState {
                request_id: request_id.to_string(),
                state: RequestState::Abort,
                error: Some(error.to_string()),
            },
        )
        .await?;

        RequestHandler::queued_event(ctx, subject_id).await?;

        Ok(())
    }

    async fn approval(
        &self,
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
        state: ApprovalStateRes,
    ) -> Result<(), ActorError> {
        let approver_path =
            ActorPath::from(format!("/user/node/{}/approver", subject_id));
        let approver_actor: Option<ActorRef<ApproverPersist>> =
            ctx.system().get_actor(&approver_path).await;

        if let Some(approver_actor) = approver_actor {
            approver_actor
                .tell(ApproverPersistMessage::ChangeResponse {
                    response: state.clone(),
                })
                .await
        } else {
            Err(ActorError::NotFound(approver_path))
        }
    }
}

// Enviar un evento sin firmar
// Enviar un evento firmado
// Aprobar

#[derive(Debug, Clone)]
pub enum RequestHandlerMessage {
    NewRequest {
        request: Signed<EventRequest>,
    },
    ChangeApprovalState {
        subject_id: String,
        state: ApprovalStateRes,
    },
    PopQueue {
        subject_id: String,
    },
    EndHandling {
        subject_id: String,
        id: String,
    },
    AbortRequest {
        subject_id: String,
        id: String,
        error: String,
    },
}

impl Message for RequestHandlerMessage {}

#[derive(Debug, Clone)]
pub enum RequestHandlerResponse {
    Ok(RequestData),
    Response(String),
    None,
}

impl Response for RequestHandlerResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RequestHandlerEvent {
    EventToQueue {
        subject_id: String,
        event: Signed<EventRequest>,
    },
    Invalid {
        subject_id: String,
    },
    Abort {
        subject_id: String,
    },
    FinishHandling {
        subject_id: String,
    },
    EventToHandling {
        subject_id: String,
        request_id: String,
    },
}

impl Event for RequestHandlerEvent {}

#[async_trait]
impl Actor for RequestHandler {
    type Event = RequestHandlerEvent;
    type Message = RequestHandlerMessage;
    type Response = RequestHandlerResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("request", None, false, ctx).await?;

        let tracking_size = if let Some(config) =
            ctx.system().get_helper::<ConfigHelper>("config").await
        {
            config.tracking_size
        } else {
            return Err(ActorError::NotHelper("config".to_owned()));
        };

        ctx.create_child("tracking", RequestTracking::new(tracking_size))
            .await?;

        let Some((hash,network)) = self.helpers.clone() else {
            let e = " Can not obtain helpers".to_string();

            ctx.system().stop_system();
            return Err(ActorError::FunctionalFail(e));
        };

        for (subject_id, request_id) in self.handling.clone() {
            let request_manager_init = InitRequestManager::Continue {
                our_key: self.node_key.clone(),
                id: request_id.clone(),
                subject_id,
                helpers: (hash.clone(), network.clone()),
            };

            let request_manager_actor = ctx
                .create_child(
                    &request_id,
                    RequestManager::initial(request_manager_init),
                )
                .await?;

            request_manager_actor
                .tell(RequestManagerMessage::Run)
                .await?;
        }

        Ok(())
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<RequestHandler> for RequestHandler {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RequestHandlerMessage,
        ctx: &mut ave_actors::ActorContext<RequestHandler>,
    ) -> Result<RequestHandlerResponse, ActorError> {
        match msg {
            RequestHandlerMessage::AbortRequest {
                subject_id,
                id,
                error,
            } => {
                info!(
                    TARGET_REQUEST,
                    "AbortRequest, Aborting request {} for {}: {}",
                    id,
                    subject_id,
                    error
                );

                if let Err(e) =
                    self.abort_request(ctx, &subject_id, &id, &error).await
                {
                    error!(TARGET_REQUEST, "AbortRequest, {}", e);
                    ctx.system().stop_system();
                    return Err(e);
                };

                Ok(RequestHandlerResponse::None)
            }
            RequestHandlerMessage::ChangeApprovalState {
                subject_id,
                state,
            } => {
                info!(
                    TARGET_REQUEST,
                    "ChangeApprovalState, new approval for {}, approval response: {}",
                    subject_id,
                    state
                );

                if state == ApprovalStateRes::Obsolete {
                    error!(
                        TARGET_REQUEST,
                        "ChangeApprovalState, Invalid approval response"
                    );
                    return Err(ActorError::Functional(
                        "Invalid Response".to_owned(),
                    ));
                }

                if let Err(e) =
                    self.approval(ctx, &subject_id, state.clone()).await
                {
                    error!(TARGET_REQUEST, "ChangeApprovalState, {}", e);

                    return Err(e);
                }

                Ok(RequestHandlerResponse::Response(format!(
                    "The approval request for subject {} has changed to {}",
                    subject_id, state
                )))
            }
            RequestHandlerMessage::NewRequest { request } => {
                if let Err(e) = request.verify() {
                    error!(
                        TARGET_REQUEST,
                        "NewRequest, can not verify new request: {}", e
                    );
                    return Err(ActorError::Functional(format!(
                        "Can not verify request signature {}",
                        e
                    )));
                };

                let hash = if let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config").await
                {
                    config.hash_algorithm
                } else {
                    return Err(ActorError::NotHelper("config".to_owned()));
                };

                let subject_id = request.content().get_subject_id();

                let (is_owner,is_pending) = subject_owner(
                    ctx,
                    &subject_id.to_string(),
                ).await.map_err(|e| {
                    error!(TARGET_REQUEST, "NewRequest, Could not determine if the node is the owner of the subject: {}", e);
                    ActorError::Functional(format!(
                        "An error has occurred: {}",
                        e
                    ))
                })?;

                if !is_owner
                    && !is_pending
                    && !request.content().is_create_event()
                {
                    let e = "An event is being sent to a subject that does not belong to us or its creation is pending completion, and the subject is not pending event confirmation.";
                    error!(TARGET_REQUEST, "NewRequest, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }

                if is_owner && is_pending {
                    let e = "We are the owner of the subject but this subject is pending transfer";
                    error!(TARGET_REQUEST, "NewRequest, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }

                let metadata = match request.content().clone() {
                    EventRequest::Create(create_request) => {
                        if let Some(name) = create_request.name.clone()
                            && (name.is_empty() || name.len() > 100)
                        {
                            let e = "The subject name must be less than 100 characters or not be empty.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        if let Some(description) =
                            create_request.description.clone()
                            && (description.is_empty()
                                || description.len() > 200)
                        {
                            let e = "The subject description must be less than 200 characters or not be empty.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        // verificar que el firmante sea el nodo.
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign creation events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        if create_request.schema_id.is_gov() {
                            if !create_request.namespace.is_empty() {
                                let e = "The creation event is for a governance, the namespace must be empty.";
                                error!(TARGET_REQUEST, "NewRequest, {}", e);
                                return Err(ActorError::Functional(
                                    e.to_owned(),
                                ));
                            }

                            if !create_request.governance_id.is_empty() {
                                let e = "The creation event is for a governance, the governance_id must be empty.";
                                error!(TARGET_REQUEST, "NewRequest, {}", e);
                                return Err(ActorError::Functional(
                                    e.to_owned(),
                                ));
                            }
                        } else {
                            if create_request.governance_id.is_empty() {
                                let e = "The creation event is for a traceability subject, the governance_id cannot be empty.";
                                error!(TARGET_REQUEST, "NewRequest, {}", e);
                                return Err(ActorError::Functional(
                                    e.to_owned(),
                                ));
                            }

                            let gov = match get_gov(
                                ctx,
                                &create_request.governance_id.to_string(),
                            )
                            .await
                            {
                                Ok(gov) => gov,
                                Err(e) => {
                                    error!(
                                        TARGET_REQUEST,
                                        "NewRequest, can not get governance: {}",
                                        e
                                    );
                                    return Err(ActorError::Functional(
                                        format!(
                                            "It has not been possible to obtain governance: {}",
                                            e
                                        ),
                                    ));
                                }
                            };

                            self.check_creations(
                                "NewRequest",
                                ctx,
                                &create_request.governance_id.to_string(),
                                create_request.schema_id.clone(),
                                create_request.namespace.clone(),
                                gov,
                            )
                            .await?;
                        }
                        let subject_id = match RequestHandler::create_subject(
                            ctx,
                            create_request,
                            request.clone(),
                        )
                        .await
                        {
                            Ok(subject_id) => subject_id,
                            Err(e) => {
                                error!(
                                    TARGET_REQUEST,
                                    "NewRequest, An error has occurred and the subject could not be created: {}",
                                    e
                                );
                                return Err(ActorError::Functional(format!(
                                    "An error has occurred and the subject could not be created: {}",
                                    e
                                )));
                            }
                        };

                        let request_id = hash_borsh(&*hash.hasher(), &request)
                            .map_err(|e| {
                                error!(TARGET_REQUEST, "NewRequest, Can not obtain request hash id: {}", e);
                                ActorError::Functional(format!(
                                    "Can not obtain request hash id: {}",
                                    e
                                ))
                            })?
                            .to_string();

                        self.on_event(
                            RequestHandlerEvent::EventToQueue {
                                subject_id: subject_id.to_string(),
                                event: request,
                            },
                            ctx,
                        )
                        .await;

                        if let Err(e) = send_to_tracking(
                            ctx,
                            RequestTrackingMessage::UpdateState {
                                request_id: request_id.clone(),
                                state: RequestState::InQueue,
                                error: None,
                            },
                        )
                        .await
                        {
                            error!(
                                TARGET_REQUEST,
                                "NewRequest, can not update tracking: {}", e
                            );
                            ctx.system().stop_system();
                            return Err(e);
                        }

                        if let Err(e) = RequestHandler::queued_event(
                            ctx,
                            &subject_id.to_string(),
                        )
                        .await
                        {
                            error!(
                                TARGET_REQUEST,
                                "NewRequest, Can not enqueue new event: {}", e
                            );
                            ctx.system().stop_system();
                            return Err(e);
                        }

                        return Ok(RequestHandlerResponse::Ok(RequestData {
                            request_id,
                            subject_id: subject_id.to_string(),
                        }));
                    }
                    EventRequest::Fact(fact_request) => {
                        let metadata = get_metadata(
                            ctx,
                            &fact_request.subject_id.to_string(),
                        )
                        .await?;

                        if metadata.new_owner.is_some() {
                            let e = "After Transfer event only can emit Confirm or Reject event";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        metadata
                    }
                    EventRequest::Transfer(transfer_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign transfer events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        let metadata = get_metadata(
                            ctx,
                            &transfer_request.subject_id.to_string(),
                        )
                        .await?;

                        if metadata.new_owner.is_some() {
                            let e = "After Transfer event only can emit Confirm or Reject event";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        metadata
                    }
                    EventRequest::Confirm(confirm_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign Confirm events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }
                        let metadata = get_metadata(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                        )
                        .await?;

                        let Some(new_owner) = metadata.new_owner.clone() else {
                            let e = "Confirm event need Transfer event before";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        };

                        if new_owner != self.node_key {
                            let e = "You are not new owner";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        if !metadata.schema_id.is_gov() {
                            let gov = match get_gov(
                                ctx,
                                &metadata.governance_id.to_string(),
                            )
                            .await
                            {
                                Ok(gov) => gov,
                                Err(e) => {
                                    error!(
                                        TARGET_REQUEST,
                                        "NewRequest, can not get governance: {}",
                                        e
                                    );
                                    return Err(ActorError::Functional(
                                        format!(
                                            "It has not been possible to obtain governance: {}",
                                            e
                                        ),
                                    ));
                                }
                            };

                            self.check_creations(
                                "NewRequest",
                                ctx,
                                &metadata.governance_id.to_string(),
                                metadata.schema_id.clone(),
                                metadata.namespace.clone(),
                                gov,
                            )
                            .await?;
                        }

                        metadata
                    }
                    EventRequest::Reject(reject_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign reject events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }
                        let metadata = get_metadata(
                            ctx,
                            &reject_request.subject_id.to_string(),
                        )
                        .await?;

                        let Some(new_owner) = metadata.new_owner.clone() else {
                            let e = "Reject event need Transfer event before";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        };

                        if new_owner != self.node_key {
                            let e = "You are not new owner";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        metadata
                    }
                    EventRequest::EOL(eol_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign eol events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        let metadata = get_metadata(
                            ctx,
                            &eol_request.subject_id.to_string(),
                        )
                        .await?;

                        if metadata.new_owner.is_some() {
                            let e = "After Transfer event only can emit Confirm or Reject event";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional(e.to_owned()));
                        }

                        metadata
                    }
                };

                if !metadata.active {
                    let e = "The subject is no longer active.";
                    error!(TARGET_REQUEST, "NewRequest, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }

                let request_id = hash_borsh(&*hash.hasher(), &request)
                    .map_err(|e| {
                        error!(
                            TARGET_REQUEST,
                            "NewRequest, Can not obtain request id hash id: {}",
                            e
                        );
                        ActorError::Functional(format!(
                            "Can not obtain request id hash id: {}",
                            e
                        ))
                    })?
                    .to_string();

                self.on_event(
                    RequestHandlerEvent::EventToQueue {
                        subject_id: metadata.subject_id.to_string(),
                        event: request,
                    },
                    ctx,
                )
                .await;

                if let Err(e) = send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: request_id.clone(),
                        state: RequestState::InQueue,
                        error: None,
                    },
                )
                .await
                {
                    error!(
                        TARGET_REQUEST,
                        "NewRequest, can not update tracking: {}", e
                    );
                    ctx.system().stop_system();
                    return Err(e);
                }

                if !self.handling.contains_key(&metadata.subject_id.to_string())
                    && let Err(e) = RequestHandler::queued_event(
                        ctx,
                        &metadata.subject_id.to_string(),
                    )
                    .await
                {
                    error!(
                        TARGET_REQUEST,
                        "NewRequest, Can not enqueue new event: {}", e
                    );
                    ctx.system().stop_system();
                    return Err(e);
                }

                Ok(RequestHandlerResponse::Ok(RequestData {
                    request_id,
                    subject_id: metadata.subject_id.to_string(),
                }))
            }
            RequestHandlerMessage::PopQueue { subject_id } => {
                if self.handling.contains_key(&subject_id) {
                    // Se está manejando otro evento para este sujeto.
                    return Ok(RequestHandlerResponse::None);
                }

                let hash = if let Some(config) =
                    ctx.system().get_helper::<ConfigHelper>("config").await
                {
                    config.hash_algorithm
                } else {
                    return Err(ActorError::NotHelper("config".to_owned()));
                };

                let event = if let Some(events) = self.in_queue.get(&subject_id)
                {
                    if let Some(event) = events.clone().pop_front() {
                        event
                    } else {
                        // No hay más eventos pendientes.
                        return Ok(RequestHandlerResponse::None);
                    }
                } else {
                    // es imposible que no sea un option
                    return Ok(RequestHandlerResponse::None);
                };

                let request_id = match hash_borsh(&*hash.hasher(), &event) {
                    Ok(request_id) => request_id.to_string(),
                    Err(e) => {
                        // YA previamente se ha generado el request id, por lo que no debería haber problema
                        error!(
                            TARGET_REQUEST,
                            "PopQueue, Can not obtain request id hash id: {}",
                            e
                        );
                        let e = ActorError::Functional(format!(
                            "Can not obtain request id hash id: {}",
                            e
                        ));
                        ctx.system().stop_system();
                        return Err(e);
                    }
                };

                let metadata = match get_metadata(ctx, &subject_id.to_string())
                    .await
                {
                    Ok(metadata) => metadata,
                    Err(e) => {
                        error!(
                            TARGET_REQUEST,
                            "PopQueue, Can not obtain subject metadata: {}", e
                        );
                        ctx.system().stop_system();
                        return Err(e);
                    }
                };

                if !metadata.active {
                    let e = "Subject is not active";
                    return self.error(ctx, e, &subject_id, &request_id).await;
                }

                let gov = match get_gov(ctx, &subject_id).await {
                    Ok(gov) => gov,
                    Err(e) => {
                        error!(
                            TARGET_REQUEST,
                            "PopQueue, Can not get governance: {}", e
                        );
                        return Err(ActorError::Functional(format!(
                            "It has not been possible to obtain governance: {}",
                            e
                        )));
                    }
                };

                if !event.content().check_signers(
                    &event.signature().signer,
                    &metadata,
                    &gov,
                ) {
                    let e = "Invalid signer for this event";
                    return self.error(ctx, e, &subject_id, &request_id).await;
                }

                let command = match event.content().clone() {
                    EventRequest::Create(create_request) => {
                        if !create_request.schema_id.is_gov()
                            && let Err(e) = self
                                .check_creations(
                                    "PopQueue",
                                    ctx,
                                    &metadata.governance_id.to_string(),
                                    metadata.schema_id,
                                    metadata.namespace.clone(),
                                    gov,
                                )
                                .await
                        {
                            return self
                                .error(
                                    ctx,
                                    &e.to_string(),
                                    &subject_id,
                                    &request_id,
                                )
                                .await;
                        }

                        ReqManInitMessage::Validate
                    }

                    EventRequest::Confirm(confirm_req) => {
                        if metadata.schema_id.is_gov() {
                            if let Some(name) = confirm_req.name_old_owner
                                && name.is_empty()
                            {
                                let e = "Name of old owner can not be a empty String";
                                return self
                                    .error(ctx, e, &subject_id, &request_id)
                                    .await;
                            }

                            ReqManInitMessage::Evaluate
                        } else {
                            if confirm_req.name_old_owner.is_some() {
                                let e = "Name of old owner must be None";
                                return self
                                    .error(ctx, e, &subject_id, &request_id)
                                    .await;
                            }

                            if let Err(e) = self
                                .check_creations(
                                    "PopQueue",
                                    ctx,
                                    &metadata.governance_id.to_string(),
                                    metadata.schema_id,
                                    metadata.namespace.clone(),
                                    gov,
                                )
                                .await
                            {
                                return self
                                    .error(
                                        ctx,
                                        &e.to_string(),
                                        &subject_id,
                                        &request_id,
                                    )
                                    .await;
                            };

                            ReqManInitMessage::Validate
                        }
                    }
                    EventRequest::Fact(_) | EventRequest::Transfer(_) => {
                        ReqManInitMessage::Evaluate
                    }

                    _ => ReqManInitMessage::Validate,
                };

                let Some(helpers) = self.helpers.clone() else {
                    let e = " Can not obtain helpers".to_string();
                    error!(TARGET_REQUEST, "PopQueue, {}", e);

                    ctx.system().stop_system();
                    return Err(ActorError::FunctionalFail(e));
                };

                let request_manager_init = InitRequestManager::Init {
                    our_key: self.node_key.clone(),
                    id: request_id.clone(),
                    subject_id: subject_id.clone(),
                    command,
                    request: Box::new(event.clone()),
                    helpers,
                };

                let request_actor = match ctx
                    .create_child(
                        &request_id.clone(),
                        RequestManager::initial(request_manager_init),
                    )
                    .await
                {
                    Ok(request_actor) => request_actor,
                    Err(e) => {
                        error!(
                            TARGET_REQUEST,
                            "PopQueue, Can not create request manager actor: {}",
                            e
                        );
                        ctx.system().stop_system();
                        return Err(e);
                    }
                };

                info!(TARGET_REQUEST, "New Request {}!!!", request_id);
                if let Err(e) =
                    request_actor.tell(RequestManagerMessage::FirstRun).await
                {
                    error!(
                        TARGET_REQUEST,
                        "PopQueue, Can not send message to request manager actor: {}",
                        e
                    );
                    ctx.system().stop_system();
                    return Err(e);
                };

                self.on_event(
                    RequestHandlerEvent::EventToHandling {
                        subject_id: subject_id.clone(),
                        request_id,
                    },
                    ctx,
                )
                .await;

                Ok(RequestHandlerResponse::None)
            }
            RequestHandlerMessage::EndHandling { subject_id, id } => {
                self.on_event(
                    RequestHandlerEvent::FinishHandling {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                if let Err(e) = send_to_tracking(
                    ctx,
                    RequestTrackingMessage::UpdateState {
                        request_id: id.clone(),
                        state: RequestState::Finish,
                        error: None,
                    },
                )
                .await
                {
                    error!(
                        TARGET_REQUEST,
                        "EndHandling, Can not send event update to RequestTracking: {}",
                        e
                    );
                    ctx.system().stop_system();
                    return Err(e);
                }

                if let Err(e) =
                    RequestHandler::queued_event(ctx, &subject_id).await
                {
                    error!(
                        TARGET_REQUEST,
                        "EndHandling, Can not enqueue next event: {}", e
                    );
                    ctx.system().stop_system();
                    return Err(e);
                }

                Ok(RequestHandlerResponse::None)
            }
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<RequestHandler>,
    ) -> ChildAction {
        error!(TARGET_REQUEST, "OnChildFault, {}", error);
        ctx.system().stop_system();
        ChildAction::Stop
    }

    async fn on_event(
        &mut self,
        event: RequestHandlerEvent,
        ctx: &mut ActorContext<RequestHandler>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_REQUEST,
                "OnEvent, can not persist information: {}", e
            );
            ctx.system().stop_system();
        };
    }
}

#[async_trait]
impl Storable for RequestHandler {}

#[async_trait]
impl PersistentActor for RequestHandler {
    type Persistence = LightPersistence;
    type InitParams = (PublicKey, (HashAlgorithm, Arc<NetworkSender>));

    fn update(&mut self, state: Self) {
        self.in_queue = state.in_queue;
        self.handling = state.handling;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        RequestHandler {
            node_key: params.0,
            helpers: Some(params.1),
            handling: HashMap::new(),
            in_queue: HashMap::new(),
        }
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RequestHandlerEvent::Abort { subject_id } => {
                self.handling.remove(subject_id);
            }
            RequestHandlerEvent::EventToQueue { subject_id, event } => {
                if let Some(vec) = self.in_queue.get_mut(subject_id) {
                    vec.push_back(event.clone());
                } else {
                    let mut vec = VecDeque::new();
                    vec.push_back(event.clone());
                    self.in_queue.insert(subject_id.clone(), vec);
                };
            }
            RequestHandlerEvent::Invalid { subject_id } => {
                if let Some(vec) = self.in_queue.get_mut(subject_id) {
                    vec.pop_front();
                }
            }
            RequestHandlerEvent::EventToHandling {
                subject_id,
                request_id,
            } => {
                self.handling.insert(subject_id.clone(), request_id.clone());
                if let Some(vec) = self.in_queue.get_mut(subject_id) {
                    vec.pop_front();
                }
            }
            RequestHandlerEvent::FinishHandling { subject_id } => {
                self.handling.remove(subject_id);
            }
        };

        Ok(())
    }
}
