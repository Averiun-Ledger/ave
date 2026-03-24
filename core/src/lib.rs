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
pub mod metrics;
pub mod model;
pub mod node;
pub mod request;
pub mod subject;
pub mod system;
pub mod tracker;
pub mod update;
pub mod validation;

use std::collections::HashSet;
use std::str::FromStr;
use std::sync::Arc;

use auth::{Auth, AuthMessage, AuthResponse, AuthWitness};
use ave_actors::{ActorError, ActorPath, ActorRef, PersistentActor};
use ave_common::bridge::request::{
    AbortsQuery, ApprovalState, ApprovalStateRes, EventRequestType,
    EventsQuery, SinkEventsQuery,
};
use ave_common::identity::keys::KeyPair;
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};
use ave_common::request::EventRequest;
use ave_common::response::{
    GovsData, LedgerDB, MonitorNetworkState, PaginatorAborts, PaginatorEvents,
    RequestInfo, RequestInfoExtend, RequestsInManager,
    RequestsInManagerSubject, SinkEventsPage, SubjectDB, SubjsData,
};
use config::Config as AveBaseConfig;
use error::Error;
use helpers::network::*;
use intermediary::Intermediary;
use manual_distribution::{ManualDistribution, ManualDistributionMessage};
use network::{
    MachineSpec, Monitor, MonitorMessage, MonitorResponse, NetworkWorker,
};

use node::{Node, NodeMessage, NodeResponse, TransferSubject};
use prometheus_client::registry::Registry;
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
use crate::helpers::db::{
    DatabaseError as ExternalDatabaseError, ExternalDB, ReadStore,
};
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
    safe_mode: bool,
    db: Arc<ExternalDB>,
    request: ActorRef<RequestHandler>,
    node: ActorRef<Node>,
    auth: ActorRef<Auth>,
    monitor: ActorRef<Monitor>,
    manual_dis: ActorRef<ManualDistribution>,
    tracking: ActorRef<RequestTracking>,
}

fn preserve_functional_actor_error<F>(err: ActorError, fallback: F) -> Error
where
    F: FnOnce(ActorError) -> Error,
{
    match err {
        ActorError::Functional { description } => {
            Error::ActorError(description)
        }
        ActorError::FunctionalCritical { description } => {
            Error::Internal(description)
        }
        ActorError::NotFound { path } => Error::MissingResource {
            name: path.to_string(),
            reason: "Actor not found".to_string(),
        },
        other => fallback(other),
    }
}

fn actor_communication_error(actor: &'static str, err: ActorError) -> Error {
    preserve_functional_actor_error(err, |_| Error::ActorCommunication {
        actor: actor.to_string(),
    })
}

fn safe_mode_error() -> Error {
    Error::SafeMode(
        "node is running in safe mode; mutating operations are disabled"
            .to_string(),
    )
}

impl Api {
    fn ensure_mutations_allowed(&self) -> Result<(), Error> {
        if self.safe_mode {
            return Err(safe_mode_error());
        }
        Ok(())
    }

    /// Creates a new `Api`.
    pub async fn build(
        keys: KeyPair,
        config: AveBaseConfig,
        sink_auth: SinkAuth,
        registry: &mut Registry,
        password: &str,
        graceful_token: CancellationToken,
        crash_token: CancellationToken,
    ) -> Result<(Self, Vec<JoinHandle<()>>), Error> {
        debug!("Creating Api");

        let (system, runner) = system(
            config.clone(),
            sink_auth,
            password,
            graceful_token.clone(),
            crash_token.clone(),
        )
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
        let network_metrics = network::metrics::register(registry);
        crate::metrics::register(registry);

        let mut worker: NetworkWorker<NetworkMessage> = NetworkWorker::new(
            &keys,
            config.network.clone(),
            Some(newtork_monitor_actor.clone()),
            graceful_token.clone(),
            crash_token.clone(),
            spec,
            Some(network_metrics),
        )
        .map_err(|e| {
            error!(error = %e, "Can not create networt");
            Error::Network(e.to_string())
        })?;

        // Create worker
        let service = Intermediary::build(
            worker.service().sender(),
            system.clone(),
            graceful_token.clone(),
            crash_token.clone(),
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

        ext_db.register_prometheus_metrics(registry);

        let tasks = Vec::from([runner, worker_runner]);

        Ok((
            Self {
                public_key: keys.public_key().to_string(),
                peer_id,
                safe_mode: config.safe_mode,
                db: ext_db,
                request: request_actor,
                auth: auth_actor,
                node: node_actor,
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
                preserve_functional_actor_error(e, |e| {
                    Error::NetworkState(e.to_string())
                })
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
                actor_communication_error("request", e)
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
                actor_communication_error("request", e)
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
        self.ensure_mutations_allowed()?;
        let response = self
            .request
            .ask(RequestHandlerMessage::NewRequest { request })
            .await
            .map_err(|e| {
                warn!(error = %e, "Request processing failed");
                actor_communication_error("request", e)
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
        self.ensure_mutations_allowed()?;
        let response = self
            .node
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::EventRequest(request.clone()),
            )))
            .await
            .map_err(|e| {
                warn!(error = %e, "Node was unable to sign the request");
                preserve_functional_actor_error(e, |e| {
                    Error::SigningFailed(e.to_string())
                })
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
                actor_communication_error("request", e)
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
                actor_communication_error("request", e)
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
                actor_communication_error("request", e)
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
        self.ensure_mutations_allowed()?;
        if state == ApprovalStateRes::Obsolete {
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
                preserve_functional_actor_error(e, |e| {
                    Error::ApprovalUpdateFailed(e.to_string())
                })
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
        self.ensure_mutations_allowed()?;
        self.request
            .tell(RequestHandlerMessage::AbortRequest { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to abort request");
                actor_communication_error("request", e)
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
                actor_communication_error("tracking", e)
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
                actor_communication_error("tracking", e)
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
                    actor_communication_error("node", e)
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
        self.ensure_mutations_allowed()?;
        self.auth
            .tell(AuthMessage::NewAuth {
                subject_id,
                witness: witnesses,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Authentication operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn all_auth_subjects(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response =
            self.auth.ask(AuthMessage::GetAuths).await.map_err(|e| {
                error!(error = %e, "Failed to get auth subjects");
                actor_communication_error("auth", e)
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
                actor_communication_error("auth", e)
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
        self.ensure_mutations_allowed()?;
        self.auth
            .tell(AuthMessage::DeleteAuth { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to delete auth subject");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn update_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        let response = self
            .auth
            .ask(AuthMessage::Update {
                subject_id: subject_id.clone(),
                objective: None,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to update subject");
                preserve_functional_actor_error(e, |e| {
                    Error::UpdateFailed(subject_id.to_string(), e.to_string())
                })
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
        self.ensure_mutations_allowed()?;
        self.manual_dis
            .ask(ManualDistributionMessage::Update(subject_id.clone()))
            .await
            .map_err(|e| {
                warn!(error = %e, "Manual distribution failed");
                preserve_functional_actor_error(e, |_| {
                    Error::DistributionFailed(subject_id.to_string())
                })
            })?;

        Ok("Manual distribution in progress".to_owned())
    }

    ///////// Register
    ////////////////////////////
    pub async fn all_govs(
        &self,
        active: Option<bool>,
    ) -> Result<Vec<GovsData>, Error> {
        self.db.get_governances(active).await.map_err(|e| {
            warn!(error = %e, "Failed to get governances");
            Error::QueryFailed(e.to_string())
        })
    }

    pub async fn all_subjs(
        &self,
        governance_id: DigestIdentifier,
        active: Option<bool>,
        schema_id: Option<String>,
    ) -> Result<Vec<SubjsData>, Error> {
        let governance_id = governance_id.to_string();
        match self
            .db
            .get_subjects(&governance_id, active, schema_id)
            .await
        {
            Ok(subjects) => Ok(subjects),
            Err(ExternalDatabaseError::GovernanceNotFound(_)) => {
                Err(Error::GovernanceNotFound(governance_id))
            }
            Err(e) => {
                warn!(error = %e, "Failed to get subjects");
                Err(Error::QueryFailed(e.to_string()))
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
        let subject_id_str = subject_id.to_string();

        match self.db.get_events(&subject_id_str, query).await {
            Ok(data) => Ok(data),
            Err(ExternalDatabaseError::NoEvents(_)) => {
                Err(Error::NoEventsFound(subject_id_str))
            }
            Err(e) => {
                warn!(error = %e, "Failed to get events");
                Err(Error::QueryFailed(e.to_string()))
            }
        }
    }

    pub async fn get_sink_events(
        &self,
        subject_id: DigestIdentifier,
        query: SinkEventsQuery,
    ) -> Result<SinkEventsPage, Error> {
        let response = self
            .node
            .ask(NodeMessage::GetSinkEvents {
                subject_id,
                from_sn: query.from_sn.unwrap_or(0),
                to_sn: query.to_sn,
                limit: query.limit.unwrap_or(100),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to replay sink events");
                Error::from(e)
            })?;

        match response {
            NodeResponse::SinkEvents(events) => Ok(events),
            _ => Err(Error::UnexpectedResponse {
                actor: "node".to_string(),
                expected: "SinkEvents".to_string(),
                received: "other".to_string(),
            }),
        }
    }

    pub async fn get_aborts(
        &self,
        subject_id: DigestIdentifier,
        query: AbortsQuery,
    ) -> Result<PaginatorAborts, Error> {
        let subject_id_str = subject_id.to_string();
        let request_id = if let Some(request_id) = query.request_id.as_ref() {
            Some(
                DigestIdentifier::from_str(request_id)
                    .map_err(|e| Error::InvalidQueryParams(e.to_string()))?
                    .to_string(),
            )
        } else {
            None
        };
        let query = AbortsQuery {
            request_id,
            sn: query.sn,
            quantity: query.quantity,
            page: query.page,
            reverse: query.reverse,
        };

        self.db
            .get_aborts(&subject_id_str, query)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get aborts");
                Error::QueryFailed(e.to_string())
            })
    }

    pub async fn get_event_sn(
        &self,
        subject_id: DigestIdentifier,
        sn: u64,
    ) -> Result<LedgerDB, Error> {
        let subject_id_str = subject_id.to_string();

        match self.db.get_event_sn(&subject_id_str, sn).await {
            Ok(data) => Ok(data),
            Err(ExternalDatabaseError::EventNotFound { .. }) => {
                Err(Error::EventNotFound {
                    subject: subject_id_str,
                    sn,
                })
            }
            Err(e) => {
                warn!(error = %e, "Failed to get event");
                Err(Error::QueryFailed(e.to_string()))
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
        let subject_id_str = subject_id.to_string();

        match self
            .db
            .get_first_or_end_events(
                &subject_id_str,
                quantity,
                reverse,
                event_type,
            )
            .await
        {
            Ok(data) => Ok(data),
            Err(ExternalDatabaseError::NoEvents(_)) => {
                Err(Error::NoEventsFound(subject_id_str))
            }
            Err(e) => {
                warn!(error = %e, "Failed to get events");
                Err(Error::QueryFailed(e.to_string()))
            }
        }
    }

    pub async fn get_subject_state(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<SubjectDB, Error> {
        let subject_id_str = subject_id.to_string();

        match self.db.get_subject_state(&subject_id_str).await {
            Ok(data) => Ok(data),
            Err(ExternalDatabaseError::SubjectNotFound(_)) => {
                Err(Error::SubjectNotFound(subject_id_str))
            }
            Err(e) => {
                warn!(error = %e, "Failed to get subject state");
                Err(Error::QueryFailed(e.to_string()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_actors::{ActorError, ActorPath};

    #[test]
    fn preserves_functional_actor_errors() {
        let error = preserve_functional_actor_error(
            ActorError::Functional {
                description: "Is not a Creator".to_string(),
            },
            |_| Error::ActorCommunication {
                actor: "request".to_string(),
            },
        );

        assert!(
            matches!(error, Error::ActorError(message) if message == "Is not a Creator")
        );
    }

    #[test]
    fn preserves_not_found_actor_errors() {
        let error = preserve_functional_actor_error(
            ActorError::NotFound {
                path: ActorPath::from("/user/request"),
            },
            |_| Error::ActorCommunication {
                actor: "request".to_string(),
            },
        );

        assert!(matches!(
            error,
            Error::MissingResource { name, .. } if name == "/user/request"
        ));
    }
}
