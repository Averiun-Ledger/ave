#![recursion_limit = "256"]
pub mod config;
pub mod error;

pub mod approval;
pub mod auth;
pub mod db;
pub mod distribution;
pub mod evaluation;
pub mod external_db;
pub mod governance;
pub mod helpers;
pub mod manual_distribution;
pub mod model;
pub mod node;
pub mod query;
pub mod request;
pub mod subject;
pub mod system;
pub mod tracker;
pub mod update;
pub mod validation;

use std::collections::HashSet;
use std::sync::Arc;

use auth::{Auth, AuthMessage, AuthResponse, AuthWitness};
use ave_actors::{ActorPath, ActorRef, PersistentActor};
use ave_common::bridge::request::{
    ApprovalState, ApprovalStateRes, EventRequestType, EventsQuery,
};
use ave_common::identity::keys::KeyPair;
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};
use ave_common::request::EventRequest;
use ave_common::response::{
    GovsData, LedgerDB, MonitorNetworkState, PaginatorAborts, PaginatorEvents,
    RequestInfo, RequestInfoExtend, RequestsInManager,
    RequestsInManagerSubject, SubjectDB, SubjsData,
};
use config::Config as AveBaseConfig;
use error::Error;
use helpers::network::*;
use intermediary::Intermediary;
use manual_distribution::{ManualDistribution, ManualDistributionMessage};
use network::{MachineSpec, Monitor, MonitorMessage, MonitorResponse, NetworkWorker};

use node::register::{Register, RegisterMessage, RegisterResponse};
use node::{Node, NodeMessage, NodeResponse, TransferSubject};
use query::{Query, QueryMessage, QueryResponse};
use request::{
    RequestData, RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
};
use system::system;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};
use validation::{Validation, ValidationMessage};

use crate::approval::request::ApprovalReq;
use crate::config::SinkAuth;
use crate::helpers::db::ExternalDB;
use crate::model::common::node::SignTypesNode;
use crate::node::InitParamsNode;
use crate::request::tracking::{
    RequestTracking, RequestTrackingMessage, RequestTrackingResponse,
};

#[cfg(all(feature = "sqlite", feature = "rocksdb"))]
compile_error!("Select only one: 'sqlite' or 'rocksdb'");

#[cfg(not(any(feature = "sqlite", feature = "rocksdb")))]
compile_error!("You must enable 'sqlite' or 'rocksdb'");

#[cfg(not(feature = "ext-sqlite"))]
compile_error!("You must enable 'ext-sqlite'");

#[cfg(all(feature = "test", not(test), not(debug_assertions)))]
compile_error!(
    "The 'test' feature should only be used during development/testing"
);

#[derive(Clone)]
pub struct Api {
    peer_id: String,
    public_key: String,
    request: ActorRef<RequestHandler>,
    node: ActorRef<Node>,
    auth: ActorRef<Auth>,
    query: ActorRef<Query>,
    register: ActorRef<Register>,
    monitor: ActorRef<Monitor>,
    manual_dis: ActorRef<ManualDistribution>,
    tracking: ActorRef<RequestTracking>,
}

impl Api {
    /// Creates a new `Api`.
    pub async fn build(
        keys: KeyPair,
        config: AveBaseConfig,
        sink_auth: SinkAuth,
        password: &str,
        token: &CancellationToken,
    ) -> Result<(Self, Vec<JoinHandle<()>>), Error> {
        debug!("Creating Api");

        let (system, runner) =
            system(config.clone(), sink_auth, password, token.clone())
                .await
                .map_err(|e| {
                    error!(error = %e, "Failed to create system");
                    e
                })?;

        let newtork_monitor = Monitor::default();
        let newtork_monitor_actor = system
            .create_root_actor("network_monitor", newtork_monitor)
            .await
            .map_err(|e| {
                error!(error = %e, "Can not create network_monitor actor");
                Error::ActorCreation {
                    actor: "network_monitor".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let spec = config.spec.map(MachineSpec::from);

        let mut worker: NetworkWorker<NetworkMessage> = NetworkWorker::new(
            &keys,
            config.network.clone(),
            Some(newtork_monitor_actor.clone()),
            token.clone(),
            spec,
        )
        .map_err(|e| {
            error!(error = %e, "Can not create networt");
            Error::Network(e.to_string())
        })?;

        // Create worker
        let service = Intermediary::build(
            worker.service().sender().clone(),
            system.clone(),
            token.clone(),
        );

        let peer_id = worker.local_peer_id().to_string();

        worker.add_helper_sender(service.sender());

        system.add_helper("network", service.clone()).await;

        let worker_runner = tokio::spawn(async move {
            let _ = worker.run().await;
        });

        let public_key = Arc::new(keys.public_key());
        let node_actor = system
            .create_root_actor(
                "node",
                Node::initial(InitParamsNode {
                    key_pair: keys.clone(),
                    hash: config.hash_algorithm,
                    is_service: config.is_service,
                    public_key: public_key.clone(),
                }),
            )
            .await
            .map_err(|e| {
                error!(error = %e, "Init system, can not create node actor");
                Error::ActorCreation {
                    actor: "node".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let register_actor: ActorRef<Register> = system
            .get_actor(&ActorPath::from("/user/node/register"))
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get register actor");
                e
            })?;

        let manual_dis_actor: ActorRef<ManualDistribution> = system
            .get_actor(&ActorPath::from("/user/node/manual_distribution"))
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get manual_distribution actor");
                e
            })?;

        let auth_actor: ActorRef<Auth> = system
            .get_actor(&ActorPath::from("/user/node/auth"))
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get auth actor");
                e
            })?;

        let request_actor = system
            .create_root_actor(
                "request",
                RequestHandler::initial((
                    public_key,
                    (config.hash_algorithm, service),
                )),
            )
            .await
            .map_err(|e| {
                error!(error = %e, "Init system, can not create request actor");
                Error::ActorCreation {
                    actor: "request".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let tracking_actor: ActorRef<RequestTracking> = system
            .get_actor(&ActorPath::from("/user/request/tracking"))
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get tracking actor");
                e
            })?;

        let Some(ext_db) = system.get_helper::<Arc<ExternalDB>>("ext_db").await
        else {
            error!("External database helper not found");
            return Err(Error::MissingResource {
                name: "ext_db".to_string(),
                reason: "External database helper not found".to_string(),
            });
        };

        let query = Query::new(ext_db);
        let query_actor = system
            .create_root_actor("query", query)
            .await
            .map_err(|e| {
                error!(error = %e, "Init system, can not create query actor");
                Error::ActorCreation {
                    actor: "query".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let tasks = Vec::from([runner, worker_runner]);

        Ok((
            Self {
                public_key: keys.public_key().to_string(),
                peer_id,
                request: request_actor,
                auth: auth_actor,
                node: node_actor,
                query: query_actor,
                register: register_actor,
                monitor: newtork_monitor_actor,
                manual_dis: manual_dis_actor,
                tracking: tracking_actor,
            },
            tasks,
        ))
    }

    ///////// General
    ////////////////////////////

    pub fn peer_id(&self) -> &str {
        &self.peer_id
    }

    pub fn public_key(&self) -> &str {
        &self.public_key
    }

    ///////// Network
    ////////////////////////////
    pub async fn get_network_state(
        &self,
    ) -> Result<MonitorNetworkState, Error> {
        let response =
            self.monitor.ask(MonitorMessage::State).await.map_err(|e| {
                warn!(error = %e, "Unable to retrieve network state");
                Error::NetworkState(e.to_string())
            })?;

        match response {
            MonitorResponse::State(state) => Ok(state),
            _ => {
                warn!("Unexpected response from network monitor");
                Err(Error::UnexpectedResponse {
                    actor: "network_monitor".to_string(),
                    expected: "State".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    ///////// Request
    ////////////////////////////

    pub async fn get_requests_in_manager(
        &self,
    ) -> Result<RequestsInManager, Error> {
        let response = self
            .request
            .ask(RequestHandlerMessage::RequestInManager)
            .await
            .map_err(|e| {
                warn!(error = %e, "Request processing failed");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        match response {
            RequestHandlerResponse::RequestInManager(request) => Ok(request),
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "RequestInManager".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_requests_in_manager_subject_id(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<RequestsInManagerSubject, Error> {
        let response = self
            .request
            .ask(RequestHandlerMessage::RequestInManagerSubjectId {
                subject_id,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Request processing failed");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        match response {
            RequestHandlerResponse::RequestInManagerSubjectId(request) => {
                Ok(request)
            }
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "RequestInManagerSubjectId".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn external_request(
        &self,
        request: Signed<EventRequest>,
    ) -> Result<RequestData, Error> {
        let response = self
            .request
            .ask(RequestHandlerMessage::NewRequest { request })
            .await
            .map_err(|e| {
                warn!(error = %e, "Request processing failed");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        match response {
            RequestHandlerResponse::Ok(request_data) => Ok(request_data),
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "Ok".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn own_request(
        &self,
        request: EventRequest,
    ) -> Result<RequestData, Error> {
        let response = self
            .node
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                request.clone(),
            )))
            .await
            .map_err(|e| {
                warn!(error = %e, "Node was unable to sign the request");
                Error::SigningFailed(e.to_string())
            })?;

        let signature = match response {
            NodeResponse::SignRequest(signature) => signature,
            _ => {
                warn!("Unexpected response from node");
                return Err(Error::UnexpectedResponse {
                    actor: "node".to_string(),
                    expected: "SignRequest".to_string(),
                    received: "other".to_string(),
                });
            }
        };

        let signed_event_req = Signed::from_parts(request, signature);

        let response = self
            .request
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to send request");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        match response {
            RequestHandlerResponse::Ok(request_data) => Ok(request_data),
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "Ok".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_approval(
        &self,
        subject_id: DigestIdentifier,
        state: Option<ApprovalState>,
    ) -> Result<Option<(ApprovalReq, ApprovalState)>, Error> {
        let response = self
            .request
            .ask(RequestHandlerMessage::GetApproval { state, subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get approval request");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        match response {
            RequestHandlerResponse::Approval(data) => Ok(data),
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "Approval".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_approvals(
        &self,
        state: Option<ApprovalState>,
    ) -> Result<Vec<(ApprovalReq, ApprovalState)>, Error> {
        let response = self
            .request
            .ask(RequestHandlerMessage::GetAllApprovals { state })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get approval requests");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        match response {
            RequestHandlerResponse::Approvals(data) => Ok(data),
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "Approvals".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn approve(
        &self,
        subject_id: DigestIdentifier,
        state: ApprovalStateRes,
    ) -> Result<String, Error> {
        if let ApprovalStateRes::Obsolete = state {
            warn!("Cannot set approval state to Obsolete");
            return Err(Error::InvalidApprovalState("Obsolete".to_string()));
        }

        let response = self
            .request
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id,
                state,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to change approval state");
                Error::ApprovalUpdateFailed(e.to_string())
            })?;

        match response {
            RequestHandlerResponse::Response(res) => Ok(res),
            _ => {
                warn!("Unexpected response from request handler");
                Err(Error::UnexpectedResponse {
                    actor: "request".to_string(),
                    expected: "Response".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn manual_request_abort(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.request
            .tell(RequestHandlerMessage::AbortRequest { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to abort request");
                Error::ActorCommunication {
                    actor: "request".to_string(),
                }
            })?;

        Ok("Trying to abort".to_string())
    }

    ///////// Tracking
    ////////////////////////////
    pub async fn get_request_state(
        &self,
        request_id: DigestIdentifier,
    ) -> Result<RequestInfo, Error> {
        let response = self
            .tracking
            .ask(RequestTrackingMessage::SearchRequest(request_id.clone()))
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get request state");
                Error::ActorCommunication {
                    actor: "tracking".to_string(),
                }
            })?;

        match response {
            RequestTrackingResponse::Info(state) => Ok(state),
            RequestTrackingResponse::NotFound => {
                Err(Error::RequestNotFound(request_id.to_string()))
            }
            _ => {
                warn!("Unexpected response from tracking");
                Err(Error::UnexpectedResponse {
                    actor: "tracking".to_string(),
                    expected: "Info".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn all_request_state(
        &self,
    ) -> Result<Vec<RequestInfoExtend>, Error> {
        let response = self
            .tracking
            .ask(RequestTrackingMessage::AllRequests)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get all request states");
                Error::ActorCommunication {
                    actor: "tracking".to_string(),
                }
            })?;

        match response {
            RequestTrackingResponse::AllInfo(state) => Ok(state),
            _ => {
                warn!("Unexpected response from tracking");
                Err(Error::UnexpectedResponse {
                    actor: "tracking".to_string(),
                    expected: "AllInfo".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    ///////// Node
    ////////////////////////////

    pub async fn get_pending_transfers(
        &self,
    ) -> Result<Vec<TransferSubject>, Error> {
        let response =
            self.node.ask(NodeMessage::PendingTransfers).await.map_err(
                |e| {
                    warn!(error = %e, "Failed to get pending transfers");
                    Error::ActorCommunication {
                        actor: "node".to_string(),
                    }
                },
            )?;

        let NodeResponse::PendingTransfers(pending) = response else {
            warn!("Unexpected response from node");
            return Err(Error::UnexpectedResponse {
                actor: "node".to_string(),
                expected: "PendingTransfers".to_string(),
                received: "other".to_string(),
            });
        };

        Ok(pending)
    }

    ///////// Auth
    ////////////////////////////

    pub async fn auth_subject(
        &self,
        subject_id: DigestIdentifier,
        witnesses: AuthWitness,
    ) -> Result<String, Error> {
        self.auth
            .tell(AuthMessage::NewAuth {
                subject_id,
                witness: witnesses,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Authentication operation failed");
                Error::AuthOperation(e.to_string())
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn all_auth_subjects(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response =
            self.auth.ask(AuthMessage::GetAuths).await.map_err(|e| {
                error!(error = %e, "Failed to get auth subjects");
                Error::ActorCommunication {
                    actor: "auth".to_string(),
                }
            })?;

        match response {
            AuthResponse::Auths { subjects } => Ok(subjects),
            _ => {
                warn!("Unexpected response from auth");
                Err(Error::UnexpectedResponse {
                    actor: "auth".to_string(),
                    expected: "Auths".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn witnesses_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<HashSet<PublicKey>, Error> {
        let response = self
            .auth
            .ask(AuthMessage::GetAuth {
                subject_id: subject_id.clone(),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get witnesses for subject");
                Error::ActorCommunication {
                    actor: "auth".to_string(),
                }
            })?;

        match response {
            AuthResponse::Witnesses(witnesses) => Ok(witnesses),
            _ => {
                warn!("Unexpected response from auth");
                Err(Error::UnexpectedResponse {
                    actor: "auth".to_string(),
                    expected: "Witnesses".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn delete_auth_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.auth
            .tell(AuthMessage::DeleteAuth { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to delete auth subject");
                Error::AuthOperation(e.to_string())
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn update_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        let response = self
            .auth
            .ask(AuthMessage::Update {
                subject_id: subject_id.clone(),
                objective: None,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to update subject");
                Error::UpdateFailed(subject_id.to_string(), e.to_string())
            })?;

        match response {
            AuthResponse::None => Ok("Update in progress".to_owned()),
            _ => {
                warn!("Unexpected response from auth");
                Err(Error::UnexpectedResponse {
                    actor: "auth".to_string(),
                    expected: "None".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    ///////// manual distribution
    ////////////////////////////

    pub async fn manual_distribution(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.manual_dis
            .ask(ManualDistributionMessage::Update(subject_id.clone()))
            .await
            .map_err(|e| {
                warn!(error = %e, "Manual distribution failed");
                Error::DistributionFailed(subject_id.to_string())
            })?;

        Ok("Manual distribution in progress".to_owned())
    }

    ///////// Register
    ////////////////////////////
    pub async fn all_govs(
        &self,
        active: Option<bool>,
    ) -> Result<Vec<GovsData>, Error> {
        let response = self
            .register
            .ask(RegisterMessage::GetGovs { active })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get governances");
                Error::ActorCommunication {
                    actor: "register".to_string(),
                }
            })?;

        match response {
            RegisterResponse::Govs { governances } => Ok(governances),
            _ => {
                warn!("Unexpected response from register");
                Err(Error::UnexpectedResponse {
                    actor: "register".to_string(),
                    expected: "Govs".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn all_subjs(
        &self,
        governance_id: DigestIdentifier,
        active: Option<bool>,
        schema_id: Option<String>,
    ) -> Result<Vec<SubjsData>, Error> {
        let response = self
            .register
            .ask(RegisterMessage::GetSubj {
                gov_id: governance_id.to_string(),
                active,
                schema_id,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get subjects");
                Error::ActorCommunication {
                    actor: "register".to_string(),
                }
            })?;

        match response {
            RegisterResponse::Subjs { subjects } => Ok(subjects),
            _ => {
                warn!("Unexpected response from register");
                Err(Error::UnexpectedResponse {
                    actor: "register".to_string(),
                    expected: "Subjs".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    ///////// Query
    ////////////////////////////
    pub async fn get_events(
        &self,
        subject_id: DigestIdentifier,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, Error> {
        let response = self
            .query
            .ask(QueryMessage::GetEvents { subject_id, query })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get events");
                Error::ActorCommunication {
                    actor: "query".to_string(),
                }
            })?;

        match response {
            QueryResponse::PagEvents(data) => Ok(data),
            QueryResponse::Error(e) => Err(Error::QueryFailed(e)),
            _ => {
                warn!("Unexpected response from query");
                Err(Error::UnexpectedResponse {
                    actor: "query".to_string(),
                    expected: "PagEvents".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_aborts(
        &self,
        subject_id: DigestIdentifier,
        request_id: Option<DigestIdentifier>,
        sn: Option<u64>,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorAborts, Error> {
        let response = self
            .query
            .ask(QueryMessage::GetAborts {
                subject_id,
                request_id,
                sn,
                quantity,
                page,
                reverse,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get aborts");
                Error::ActorCommunication {
                    actor: "query".to_string(),
                }
            })?;

        match response {
            QueryResponse::PagAborts(data) => Ok(data),
            QueryResponse::Error(e) => Err(Error::QueryFailed(e)),
            _ => {
                warn!("Unexpected response from query");
                Err(Error::UnexpectedResponse {
                    actor: "query".to_string(),
                    expected: "PagAborts".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_event_sn(
        &self,
        subject_id: DigestIdentifier,
        sn: u64,
    ) -> Result<LedgerDB, Error> {
        let response = self
            .query
            .ask(QueryMessage::GetEventSn {
                subject_id: subject_id.clone(),
                sn,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get event");
                Error::ActorCommunication {
                    actor: "query".to_string(),
                }
            })?;

        match response {
            QueryResponse::Event(data) => Ok(data),
            QueryResponse::Error(_e) => Err(Error::EventNotFound {
                subject: subject_id.to_string(),
                sn,
            }),
            _ => {
                warn!("Unexpected response from query");
                Err(Error::UnexpectedResponse {
                    actor: "query".to_string(),
                    expected: "Event".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_first_or_end_events(
        &self,
        subject_id: DigestIdentifier,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, Error> {
        let response = self
            .query
            .ask(QueryMessage::GetFirstOrEndEvents {
                subject_id,
                quantity,
                reverse,
                event_type,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get events");
                Error::ActorCommunication {
                    actor: "query".to_string(),
                }
            })?;

        match response {
            QueryResponse::Events(data) => Ok(data),
            QueryResponse::Error(e) => Err(Error::QueryFailed(e)),
            _ => {
                warn!("Unexpected response from query");
                Err(Error::UnexpectedResponse {
                    actor: "query".to_string(),
                    expected: "Events".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn get_subject_state(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<SubjectDB, Error> {
        let response = self
            .query
            .ask(QueryMessage::GetSubject {
                subject_id: subject_id.clone(),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get subject state");
                Error::ActorCommunication {
                    actor: "query".to_string(),
                }
            })?;

        match response {
            QueryResponse::Subject(data) => Ok(data),
            QueryResponse::Error(_e) => {
                Err(Error::SubjectNotFound(subject_id.to_string()))
            }
            _ => {
                warn!("Unexpected response from query");
                Err(Error::UnexpectedResponse {
                    actor: "query".to_string(),
                    expected: "Subject".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }
}
