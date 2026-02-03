use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Event,
    Handler, Message, Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
};
use ave_common::request::EventRequest;
use ave_common::response::RequestState;
use ave_common::{Namespace, SchemaType};
use borsh::{BorshDeserialize, BorshSerialize};
use manager::{RequestManager, RequestManagerMessage};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use tracing::{Span, error, info, info_span};
use types::ReqManInitMessage;

use crate::approval::persist::{
    ApprPersist, ApprPersistMessage, ApprPersistResponse,
};
use crate::approval::request::ApprovalReq;
use crate::approval::types::{ApprovalState, ApprovalStateRes};
use crate::governance::data::GovernanceData;
use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::i_owner_new_owner;
use crate::model::common::{emit_fail, send_to_tracking};
use crate::model::common::subject::{get_gov, get_metadata};
use crate::node::{Node, NodeMessage, NodeResponse};
use crate::request::manager::InitRequestManager;
use crate::request::tracking::{RequestTracking, RequestTrackingMessage};
use crate::system::ConfigHelper;
use crate::{db::Storable, governance::model::CreatorQuantity};

pub mod error;
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
    our_key: Arc<PublicKey>,
    handling: HashMap<DigestIdentifier, DigestIdentifier>,
    in_queue: HashMap<DigestIdentifier, VecDeque<Signed<EventRequest>>>,
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
            VecDeque<Signed<EventRequest>>,
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
    async fn queued_event(
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
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
        todo!()
    }

    async fn change_approval(
        &self,
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
        state: ApprovalStateRes,
    ) -> Result<(), ActorError> {
        if state == ApprovalStateRes::Obsolete {
            return Err(ActorError::Functional {
                description:
                    "A user cannot mark a request approval as obsolete"
                        .to_owned(),
            });
        }

        let approver_path =
            ActorPath::from(format!("/user/node/{}/approver", subject_id));
        let approver_actor = ctx
            .system()
            .get_actor::<ApprPersist>(&approver_path)
            .await.map_err(|e| {
                error!("");
                ActorError::Functional {description: format!("No approval was found for {}, so the node likely no longer has the role of approver", subject_id)}
            })?;

        approver_actor
            .tell(ApprPersistMessage::ChangeResponse {
                response: state.clone(),
            })
            .await
            .map_err(|e| {
                error!("");
                ActorError::Functional {
                    description:
                        "The approval request status could not be changed"
                            .to_owned(),
                }
            })
    }

    async fn get_approval(
        &self,
        ctx: &mut ActorContext<RequestHandler>,
        subject_id: &str,
        state: Option<ApprovalState>,
    ) -> Result<Option<(ApprovalReq, ApprovalState)>, ActorError> {
        let approver_path =
            ActorPath::from(format!("/user/node/{}/approver", subject_id));
        let approver_actor = ctx
            .system()
            .get_actor::<ApprPersist>(&approver_path)
            .await.map_err(|e| {
                error!("");
                ActorError::Functional {description: format!("No approval was found for {}, so the node likely no longer has the role of approver", subject_id)}
            })?;

        let response = approver_actor
            .ask(ApprPersistMessage::GetApproval { state })
            .await.map_err(|e| {
                error!("");
                ActorError::Functional {
                    description:
                        "The status of the approval request could not be obtained"
                            .to_owned(),
                }
            })?;

        let res = match response {
            ApprPersistResponse::Ok => None,
            ApprPersistResponse::Approval { request, state } => {
                Some((request, state))
            }
        };

        Ok(res)
    }

    async fn get_all_approvals(
        &self,
        ctx: &mut ActorContext<RequestHandler>,
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
                ActorPath::from(format!("/user/node/{}/approver", governance));
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

    async fn check_owner_new_owner(&self, 
        ctx: &mut ActorContext<RequestHandler>,
        request: &EventRequest) -> Result<(), ActorError>{
        match request {
            EventRequest::Create(..) => {}
            EventRequest::Fact(..)
            | EventRequest::Transfer(..)
            | EventRequest::EOL(..) => {
                let (i_owner, i_new_owner) = i_owner_new_owner(ctx, &request.get_subject_id()).await?;
                if !i_owner {
                    return Err(ActorError::Functional { description: "The event is a Fact, Transfer, or EOL event, and we are not the owner of the subject".to_owned() });
                }

                if i_new_owner.is_some() {
                    return Err(ActorError::Functional { description: "The event is a Fact, Transfer, or EOL event, and there is a pending new_owner".to_owned() });
                }
            }
            EventRequest::Confirm(..) | EventRequest::Reject(..) => {
                let (i_owner, i_new_owner) = i_owner_new_owner(ctx, &request.get_subject_id()).await?;
                if i_owner {
                    return Err(ActorError::Functional { description: "The event is a Confirm or Reject event, and we are the owner of the subject".to_owned() });
                }

                if let Some(new_owner) = i_new_owner {
                    if !new_owner {
                        return Err(ActorError::Functional { description: "The event is a Confirm or Reject event, and we are not the new owner of the subject".to_owned() });
                    }
                } else {
                    return Err(ActorError::Functional { description: "The event is a Confirm or Reject event, and there is no new owner pending".to_owned() });
                }
            }
        };
        Ok(())
    }

    async fn check_event_request(&self) -> Result<(), ActorError>{
        
        
        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum RequestHandlerMessage {
    NewRequest {
        request: Signed<EventRequest>,
    },
    ChangeApprovalState {
        subject_id: String,
        state: ApprovalStateRes,
    },
    GetApproval {
        subject_id: String,
        state: Option<ApprovalState>,
    },
    GetAllApprovals {
        state: Option<ApprovalState>,
    },
    PopQueue {
        subject_id: String,
    },
    EndHandling {
        subject_id: String,
        id: String,
    },
}

impl Message for RequestHandlerMessage {}

#[derive(Debug, Clone)]
pub enum RequestHandlerResponse {
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

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RequestHandler", id = id)
        } else {
            info_span!("RequestHandler", id = id)
        }
    }

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
            return Err(ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_string(),
            });
        };

        ctx.create_child("tracking", RequestTracking::new(tracking_size))
            .await?;

        let Some((hash, network)) = self.helpers.clone() else {
            let e = " Can not obtain helpers".to_string();

            ctx.system().stop_system();
            return Err(ActorError::FunctionalCritical { description: e });
        };

        for (subject_id, request_id) in self.handling.clone() {
            let request_manager_init = InitRequestManager {
                our_key: self.our_key.clone(),
                subject_id: subject_id.clone(),
                helpers: (hash.clone(), network.clone()),
            };

            let request_manager_actor = ctx
                .create_child(
                    &subject_id.to_string(),
                    RequestManager::initial(request_manager_init),
                )
                .await?;

            request_manager_actor
                .tell(RequestManagerMessage::Run { request_id })
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
            RequestHandlerMessage::ChangeApprovalState {
                subject_id,
                state,
            } => {
                if let Err(e) =
                    self.change_approval(ctx, &subject_id, state.clone()).await
                {
                    error!(TARGET_REQUEST, "ChangeApprovalState, {}", e);

                    return Err(e);
                }

                Ok(RequestHandlerResponse::Response(format!(
                    "The approval request for subject {} has changed to {}",
                    subject_id, state
                )))
            }
            RequestHandlerMessage::GetApproval { subject_id, state } => {
                let res = self
                    .get_approval(ctx, &subject_id, state.clone())
                    .await
                    .map_err(|e| {
                        error!("");
                        e
                    })?;

                Ok(RequestHandlerResponse::Approval(res))
            }
            RequestHandlerMessage::GetAllApprovals { state } => {
                let res = self
                    .get_all_approvals(ctx, state.clone())
                    .await
                    .map_err(|e| {
                        error!("");
                        e
                    })?;

                Ok(RequestHandlerResponse::Approvals(res))
            }
            RequestHandlerMessage::NewRequest { request } => {
                if let Err(e) = request.verify() {
                    error!(
                        ""
                    );
                    return Err(ActorError::Functional {
                        description: format!(
                            "Can not verify request signature {}",
                            e
                        ),
                    });
                };

                let Some((hash, network)) = self.helpers.clone() else {
                    return Err(emit_fail(ctx, ActorError::FunctionalCritical {
                        description: "Helpers are None".to_owned(),
                    }).await)
                };

                self.check_owner_new_owner(ctx, &request.content()).await?;







                let metadata = match request.content().clone() {
                    EventRequest::Create(create_request) => {
                        if let Some(name) = create_request.name.clone()
                            && (name.is_empty() || name.len() > 100)
                        {
                            let e = "The subject name must be less than 100 characters or not be empty.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        if let Some(description) =
                            create_request.description.clone()
                            && (description.is_empty()
                                || description.len() > 200)
                        {
                            let e = "The subject description must be less than 200 characters or not be empty.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        // verificar que el firmante sea el nodo.
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign creation events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        if create_request.schema_id.is_gov() {
                            if !create_request.namespace.is_empty() {
                                let e = "The creation event is for a governance, the namespace must be empty.";
                                error!(TARGET_REQUEST, "NewRequest, {}", e);
                                return Err(ActorError::Functional {
                                    description: e.to_owned(),
                                });
                            }

                            if !create_request.governance_id.is_empty() {
                                let e = "The creation event is for a governance, the governance_id must be empty.";
                                error!(TARGET_REQUEST, "NewRequest, {}", e);
                                return Err(ActorError::Functional {
                                    description: e.to_owned(),
                                });
                            }
                        } else {
                            if create_request.governance_id.is_empty() {
                                let e = "The creation event is for a traceability subject, the governance_id cannot be empty.";
                                error!(TARGET_REQUEST, "NewRequest, {}", e);
                                return Err(ActorError::Functional {
                                    description: e.to_owned(),
                                });
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
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        metadata
                    }
                    EventRequest::Transfer(transfer_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign transfer events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        let metadata = get_metadata(
                            ctx,
                            &transfer_request.subject_id.to_string(),
                        )
                        .await?;

                        if metadata.new_owner.is_some() {
                            let e = "After Transfer event only can emit Confirm or Reject event";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        metadata
                    }
                    EventRequest::Confirm(confirm_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign Confirm events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }
                        let metadata = get_metadata(
                            ctx,
                            &confirm_request.subject_id.to_string(),
                        )
                        .await?;

                        let Some(new_owner) = metadata.new_owner.clone() else {
                            let e = "Confirm event need Transfer event before";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        };

                        if new_owner != self.node_key {
                            let e = "You are not new owner";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
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
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }
                        let metadata = get_metadata(
                            ctx,
                            &reject_request.subject_id.to_string(),
                        )
                        .await?;

                        let Some(new_owner) = metadata.new_owner.clone() else {
                            let e = "Reject event need Transfer event before";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        };

                        if new_owner != self.node_key {
                            let e = "You are not new owner";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        metadata
                    }
                    EventRequest::EOL(eol_request) => {
                        if request.signature().signer != self.node_key {
                            let e = "Only the node can sign eol events.";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        let metadata = get_metadata(
                            ctx,
                            &eol_request.subject_id.to_string(),
                        )
                        .await?;

                        if metadata.new_owner.is_some() {
                            let e = "After Transfer event only can emit Confirm or Reject event";
                            error!(TARGET_REQUEST, "NewRequest, {}", e);
                            return Err(ActorError::Functional {
                                description: e.to_owned(),
                            });
                        }

                        metadata
                    }
                };

                if !metadata.active {
                    let e = "The subject is no longer active.";
                    error!(TARGET_REQUEST, "NewRequest, {}", e);
                    return Err(ActorError::Functional {
                        description: e.to_owned(),
                    });
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
