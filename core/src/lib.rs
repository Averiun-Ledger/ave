#![recursion_limit = "256"]
pub mod config;
pub mod error;

pub(crate) mod api_input_validation;
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
pub mod sink;
pub mod subject;
pub mod system;
pub mod tracker;
pub mod update;
pub mod validation;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use auth::{
    AuthWitness, SubjectAccess, SubjectAccessMessage, SubjectAccessResponse,
};
use ave_actors::{ActorError, ActorPath, ActorRef, PersistentActor, SystemRef};
use ave_common::Error as CommonError;
use ave_common::bridge::request::{
    AbortsQuery, ApprovalState, ApprovalStateRes, EventRequestType,
    EventsQuery, SinkEventsQuery, SinkReplayItem, SinkReplayRequest,
};
use ave_common::identity::keys::KeyPair;
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};
use ave_common::request::EventRequest;
use ave_common::response::{
    GovsData, LedgerDB, MonitorNetworkState, PaginatorAborts, PaginatorEvents,
    RequestInfo, RequestInfoExtend, RequestsInManager,
    RequestsInManagerSubject, SinkEventsPage, SinkReplayError,
    SinkReplayResponse, SubjectDB, SubjsData,
};
use ave_common::{
    bridge::request::SinksQuery,
    bridge::response::{SinkInfo, SinkManagerTarget, SinkStatusInfo},
    sink::{SinkConfigEntry, SinkServer, SinkTarget},
};
use ave_network::{
    MachineSpec, Monitor, MonitorMessage, MonitorResponse, NetworkWorker,
    NetworkWorkerRuntime,
};
use config::Config as AveBaseConfig;
use error::Error;
use helpers::network::*;
use intermediary::Intermediary;
use manual_distribution::{ManualDistribution, ManualDistributionMessage};

use node::{Node, NodeMessage, NodeResponse, TransferSubject};
use prometheus_client::registry::Registry;
use request::{
    RequestData, RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
};
use sink::{SinkRegistry, SinkRegistryMessage, SinkRegistryResponse};
use system::system;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use validation::{Validation, ValidationMessage};

use crate::api_input_validation::{
    parse_request_id, require_non_empty_str, require_positive_u64,
    validate_aborts_query, validate_event_request, validate_events_query,
    validate_governance_id, validate_request_id, validate_sink_events_query,
    validate_sink_replay_request, validate_sinks_query, validate_subject_id,
};
use crate::approval::request::ApprovalReq;
use crate::helpers::db::{
    DatabaseError as ExternalDatabaseError, ExternalDB, ReadStore,
};
use crate::model::common::node::SignTypesNode;

use crate::node::InitParamsNode;
use crate::node::subject_manager::{
    SubjectManager, SubjectManagerMessage, SubjectManagerResponse,
};
use crate::request::tracking::{
    RequestTracking, RequestTrackingMessage, RequestTrackingResponse,
};
use crate::sink::{
    SinkManager, SinkManagerDetailedStatus, SinkManagerMessage,
    SinkManagerResponse,
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
    deleting_subject: Arc<tokio::sync::Mutex<Option<DigestIdentifier>>>,
    db: Arc<ExternalDB>,
    request: ActorRef<RequestHandler>,
    node: ActorRef<Node>,
    subject_manager: ActorRef<SubjectManager>,
    subject_access: ActorRef<SubjectAccess>,
    monitor: ActorRef<Monitor>,
    manual_dis: Option<ActorRef<ManualDistribution>>,
    tracking: Option<ActorRef<RequestTracking>>,
    system: SystemRef,
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

fn safe_mode_required_error(operation: &'static str) -> Error {
    Error::SafeMode(format!(
        "{operation} is only available while node is running in safe mode"
    ))
}

impl Api {
    async fn begin_subject_deletion(
        &self,
        subject_id: &DigestIdentifier,
    ) -> Result<(), Error> {
        {
            let mut deleting = self.deleting_subject.lock().await;
            if let Some(active_subject_id) = deleting.as_ref() {
                return Err(Error::InvalidRequestState(format!(
                    "subject deletion already in progress for '{}'",
                    active_subject_id
                )));
            }
            *deleting = Some(subject_id.clone());
        }
        Ok(())
    }

    async fn end_subject_deletion(&self, subject_id: &DigestIdentifier) {
        let mut deleting = self.deleting_subject.lock().await;
        if deleting.as_ref() == Some(subject_id) {
            *deleting = None;
        }
    }

    fn ensure_mutations_allowed(&self) -> Result<(), Error> {
        if self.safe_mode {
            return Err(safe_mode_error());
        }
        Ok(())
    }

    fn ensure_safe_mode_required(
        &self,
        operation: &'static str,
    ) -> Result<(), Error> {
        if !self.safe_mode {
            return Err(safe_mode_required_error(operation));
        }
        Ok(())
    }

    async fn subject_data(
        &self,
        subject_id: &DigestIdentifier,
    ) -> Result<node::SubjectData, Error> {
        let response = self
            .node
            .ask(NodeMessage::GetSubjectData(subject_id.clone()))
            .await
            .map_err(|e| actor_communication_error("node", e))?;

        let NodeResponse::SubjectData(subject_data) = response else {
            return Err(Error::UnexpectedResponse {
                actor: "node".to_string(),
                expected: "NodeResponse::SubjectData".to_string(),
                received: "other".to_string(),
            });
        };

        subject_data
            .ok_or_else(|| Error::SubjectNotFound(subject_id.to_string()))
    }

    async fn governance_trackers(
        &self,
        governance_id: &DigestIdentifier,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response = self
            .node
            .ask(NodeMessage::GovernanceTrackers(governance_id.clone()))
            .await
            .map_err(|e| actor_communication_error("node", e))?;

        let NodeResponse::GovernanceTrackers(trackers) = response else {
            return Err(Error::UnexpectedResponse {
                actor: "node".to_string(),
                expected: "NodeResponse::GovernanceTrackers".to_string(),
                received: "other".to_string(),
            });
        };

        Ok(trackers)
    }

    async fn purge_common_subject_state(
        &self,
        subject_id: &DigestIdentifier,
        cleanup_errors: &mut Vec<String>,
    ) {
        match self
            .request
            .ask(RequestHandlerMessage::PurgeSubject {
                subject_id: subject_id.clone(),
            })
            .await
        {
            Ok(RequestHandlerResponse::None) => {}
            Ok(other) => cleanup_errors
                .push(format!("request: unexpected response {other:?}")),
            Err(err) => cleanup_errors.push(format!("request: {err}")),
        }

        // Clear all subject access state for this subject
        match self
            .subject_access
            .ask(SubjectAccessMessage::ClearSubject {
                subject_id: subject_id.clone(),
            })
            .await
        {
            Ok(SubjectAccessResponse::None) => {}
            Ok(other) => cleanup_errors.push(format!(
                "subject_access clear: unexpected response {other:?}"
            )),
            Err(err) => {
                cleanup_errors.push(format!("subject_access clear: {err}"))
            }
        }

        if let Err(err) = self.db.delete_subject(&subject_id.to_string()).await
        {
            cleanup_errors.push(format!("external_db: {err}"));
        }
    }

    async fn delete_subject_from_node(
        &self,
        subject_id: &DigestIdentifier,
        cleanup_errors: &mut Vec<String>,
    ) {
        match self
            .node
            .ask(NodeMessage::DeleteSubject(subject_id.clone()))
            .await
        {
            Ok(NodeResponse::Ok) => {}
            Ok(other) => cleanup_errors
                .push(format!("node: unexpected response {other:?}")),
            Err(err) => cleanup_errors.push(format!("node: {err}")),
        }
    }

    /// Creates a new `Api`.
    pub async fn build(
        keys: KeyPair,
        config: AveBaseConfig,
        sinks: Vec<SinkConfigEntry>,
        registry: &mut Registry,
        password: &str,
        graceful_token: CancellationToken,
        crash_token: CancellationToken,
    ) -> Result<(Self, Vec<JoinHandle<()>>), Error> {
        debug!("Creating Api");

        config.validate().map_err(|e| match e {
            CommonError::InvalidConfiguration { component, reason } => {
                Error::InvalidConfiguration { component, reason }
            }
            other => Error::InvalidConfiguration {
                component: "node".to_string(),
                reason: other.to_string(),
            },
        })?;

        let (system, runner) = system(
            config.clone(),
            sinks,
            password,
            graceful_token.clone(),
            crash_token.clone(),
            #[cfg(feature = "prometheus")]
            Some(registry),
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
        let network_metrics = ave_network::metrics::register(registry);
        crate::metrics::register(registry);

        let mut worker: NetworkWorker<NetworkMessage> = NetworkWorker::new(
            &keys,
            config.network.clone(),
            config.safe_mode,
            NetworkWorkerRuntime {
                monitor: Some(newtork_monitor_actor.clone()),
                graceful_token: graceful_token.clone(),
                crash_token: crash_token.clone(),
                machine_spec: spec,
                metrics: Some(network_metrics),
            },
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

        system.add_helper("network", service.clone());

        let public_key = Arc::new(keys.public_key());
        let node_actor = system
            .create_root_actor(
                "node",
                Node::initial(InitParamsNode {
                    key_pair: keys.clone(),
                    hash: config.hash_algorithm,
                    is_service: config.is_service,
                    only_clear_events: config.only_clear_events,
                    ledger_batch_size: config.sync.ledger_batch_size as u64,
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

        let manual_dis_actor = if config.safe_mode {
            None
        } else {
            Some(
                system
                    .get_actor(&ActorPath::from(
                        "/user/node/manual_distribution",
                    ))
                    .await
                    .map_err(|e| {
                        error!(
                            error = %e,
                            "Failed to get manual_distribution actor"
                        );
                        e
                    })?,
            )
        };

        let subject_access_actor: ActorRef<SubjectAccess> = system
            .get_actor(&ActorPath::from("/user/node/auth"))
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get subject_access actor");
                e
            })?;

        let subject_manager_actor: ActorRef<SubjectManager> = system
            .get_actor(&ActorPath::from("/user/node/subject_manager"))
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get subject_manager actor");
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

        let tracking_actor = if config.safe_mode {
            None
        } else {
            Some(
                system
                    .get_actor(&ActorPath::from("/user/request/tracking"))
                    .await
                    .map_err(|e| {
                        error!(error = %e, "Failed to get tracking actor");
                        e
                    })?,
            )
        };

        let Some(ext_db) = system.get_helper::<Arc<ExternalDB>>("ext_db")
        else {
            error!("External database helper not found");
            return Err(Error::MissingResource {
                name: "ext_db".to_string(),
                reason: "External database helper not found".to_string(),
            });
        };

        ext_db.register_prometheus_metrics(registry);

        let worker_runner = tokio::spawn(async move {
            let _ = worker.run().await;
        });

        let tasks = Vec::from([runner, worker_runner]);

        Ok((
            Self {
                public_key: keys.public_key().to_string(),
                peer_id,
                safe_mode: config.safe_mode,
                deleting_subject: Arc::new(tokio::sync::Mutex::new(None)),
                db: ext_db,
                request: request_actor,
                subject_access: subject_access_actor,
                node: node_actor,
                subject_manager: subject_manager_actor,
                monitor: newtork_monitor_actor,
                manual_dis: manual_dis_actor,
                tracking: tracking_actor,
                system: system.clone(),
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
        validate_subject_id(&subject_id)?;
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
        validate_event_request(request.content())?;
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
        validate_event_request(&request)?;
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
        validate_subject_id(&subject_id)?;
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
        validate_subject_id(&subject_id)?;
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
        validate_subject_id(&subject_id)?;
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
        validate_request_id(&request_id)?;
        let Some(tracking) = &self.tracking else {
            return Err(Error::SafeMode(
                "request tracking is unavailable while node is running in safe mode"
                    .to_string(),
            ));
        };
        let response = tracking
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
        let Some(tracking) = &self.tracking else {
            return Err(Error::SafeMode(
                "request tracking is unavailable while node is running in safe mode"
                    .to_string(),
            ));
        };
        let response = tracking
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

    ///////// Subject Access
    ////////////////////////////

    pub async fn authorize_governance(
        &self,
        subject_id: DigestIdentifier,
        witnesses: AuthWitness,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        self.subject_access
            .tell(SubjectAccessMessage::AuthorizeGov {
                subject_id,
                witnesses,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Authorize governance operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn disauthorize_governance(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        self.subject_access
            .tell(SubjectAccessMessage::DisauthorizeGov { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Disauthorize governance operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn authorized_governances(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::GetAuthorizedGovs)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get authorized governances");
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Subjects(subjects) => Ok(subjects),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "Subjects".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn is_governance_authorized(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<bool, Error> {
        validate_subject_id(&subject_id)?;
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::IsGovAuthorized { subject_id })
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to check governance authorization");
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Bool(v) => Ok(v),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "Bool".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn ban_tracker(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        self.subject_access
            .tell(SubjectAccessMessage::BanTracker { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Ban tracker operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn unban_tracker(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        self.subject_access
            .tell(SubjectAccessMessage::UnbanTracker { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Unban tracker operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn banned_trackers(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::GetBannedTrackers)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get banned trackers");
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Subjects(subjects) => Ok(subjects),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "Subjects".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn is_tracker_banned(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<bool, Error> {
        validate_subject_id(&subject_id)?;
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::IsTrackerBanned { subject_id })
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to check tracker ban status");
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Bool(v) => Ok(v),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "Bool".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn add_sync_peer(
        &self,
        subject_id: DigestIdentifier,
        peers: Vec<PublicKey>,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        if peers.is_empty() {
            return Err(Error::InvalidQueryParams(
                "peers must not be empty".to_owned(),
            ));
        }
        self.subject_access
            .tell(SubjectAccessMessage::AddSyncPeers { subject_id, peers })
            .await
            .map_err(|e| {
                warn!(error = %e, "Add sync peer operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn remove_sync_peer(
        &self,
        subject_id: DigestIdentifier,
        peers: Vec<PublicKey>,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        if peers.is_empty() {
            return Err(Error::InvalidQueryParams(
                "peers must not be empty".to_owned(),
            ));
        }
        self.subject_access
            .tell(SubjectAccessMessage::RemoveSyncPeers { subject_id, peers })
            .await
            .map_err(|e| {
                warn!(error = %e, "Remove sync peer operation failed");
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        Ok("Ok".to_owned())
    }

    pub async fn sync_peers(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<HashSet<PublicKey>, Error> {
        validate_subject_id(&subject_id)?;
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::GetSyncPeers { subject_id })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to get sync peers");
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Peers(peers) => Ok(peers),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "Peers".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn subjects_with_sync_peers(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::GetSubjectsWithSyncPeers)
            .await
            .map_err(|e| {
                error!(error = %e, "Failed to get subjects with sync peers");
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Subjects(subjects) => Ok(subjects),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "Subjects".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn update_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.update_subject_with_options(subject_id, false).await
    }

    pub async fn update_subject_with_options(
        &self,
        subject_id: DigestIdentifier,
        strict: bool,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::Update {
                subject_id: subject_id.clone(),
                objective: None,
                strict,
            })
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to update subject");
                preserve_functional_actor_error(e, |e| {
                    Error::UpdateFailed(subject_id.to_string(), e.to_string())
                })
            })?;

        match response {
            SubjectAccessResponse::None => Ok("Update in progress".to_owned()),
            _ => {
                warn!("Unexpected response from subject_access");
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
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
        validate_subject_id(&subject_id)?;
        let Some(manual_dis) = &self.manual_dis else {
            return Err(safe_mode_error());
        };
        manual_dis
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

    pub async fn get_sinks(
        &self,
        query: SinksQuery,
    ) -> Result<Vec<SinkInfo>, Error> {
        validate_sinks_query(&query)?;
        let registrations = self.get_sink_registry().await?;

        // Group registered sinks by their manager target so we can query only
        // the relevant sink managers.
        let mut by_manager: HashMap<
            SinkManagerTarget,
            Vec<crate::sink::SinkRegistration>,
        > = HashMap::new();
        for reg in &registrations {
            let target = manager_target_from_registration(reg)?;
            by_manager.entry(target).or_default().push(reg.clone());
        }

        let mut set = tokio::task::JoinSet::new();
        for target in by_manager.keys() {
            let target = target.clone();
            let path = manager_path(&target);
            let system = self.system.clone();
            set.spawn(async move {
                let Ok(actor) = system.get_actor::<SinkManager>(&path).await else {
                    return Ok(None);
                };
                match actor.ask(SinkManagerMessage::GetDetailedStatus).await {
                    Ok(SinkManagerResponse::DetailedStatus(status)) => Ok(Some(status)),
                    Ok(other) => {
                        warn!(
                            manager = ?target,
                            response = ?other,
                            "Unexpected response from sink manager"
                        );
                        Err(Error::UnexpectedResponse {
                            actor: "sink_manager".to_string(),
                            expected: "DetailedStatus".to_string(),
                            received: format!("{other:?}"),
                        })
                    }
                    Err(e) => {
                        warn!(manager = ?target, error = %e, "Failed to query sink manager status");
                        Err(actor_communication_error("sink_manager", e))
                    }
                }
            });
        }

        let mut statuses_by_manager: HashMap<
            SinkManagerTarget,
            SinkManagerDetailedStatus,
        > = HashMap::new();
        while let Some(res) = set.join_next().await {
            let response = res.map_err(|e| {
                warn!(error = %e, "Sink manager status task panicked");
                Error::Internal(format!("sink manager status task failed: {e}"))
            })?;
            let Some(status) = response? else {
                continue;
            };
            let target = manager_target_from_status(&status);
            statuses_by_manager.insert(target, status);
        }

        let config_helper = self
            .system
            .get_helper::<system::ConfigHelper>("config")
            .ok_or_else(|| {
                Error::Internal("ConfigHelper not available".to_string())
            })?;
        let sinks_config = &config_helper.sinks;

        let mut infos = Vec::new();
        for reg in registrations {
            let manager = manager_target_from_registration(&reg)?;
            let status = statuses_by_manager.get(&manager);
            let sink_status = status
                .and_then(|s| s.sinks.iter().find(|st| st.sink == reg.name));
            let (target, server) =
                find_sink_config(sinks_config, &manager, &reg.name);
            let in_config = reg.from_config;
            let running =
                in_config && sink_status.is_some_and(|st| st.blocked.is_none());
            infos.push(SinkInfo {
                name: reg.name,
                target,
                manager,
                in_config,
                running,
                blocked: sink_status.and_then(|st| st.blocked.clone()),
                lagging_subjects: sink_status
                    .map(|st| st.lagging_subjects)
                    .unwrap_or_default(),
                last_error: sink_status
                    .and_then(|st| st.last_error.clone()),
                server,
            });
        }

        // Include residual sinks reported by a manager but missing from the
        // registry. This can happen when the registry state was lost while the
        // sink manager still holds persisted cursors.
        let registered_keys: std::collections::HashSet<_> = infos
            .iter()
            .map(|info| (info.manager.clone(), info.name.clone()))
            .collect();
        for (manager, status) in &statuses_by_manager {
            for sink_status in &status.sinks {
                if !registered_keys
                    .contains(&(manager.clone(), sink_status.sink.clone()))
                {
                    infos.push(SinkInfo {
                        name: sink_status.sink.clone(),
                        target: None,
                        manager: manager.clone(),
                        in_config: false,
                        running: false,
                        blocked: sink_status.blocked.clone(),
                        lagging_subjects: sink_status.lagging_subjects,
                        last_error: sink_status.last_error.clone(),
                        server: None,
                    });
                }
            }
        }

        infos.retain(|info| sink_info_matches_query(info, &query));
        infos.sort_by(|a, b| {
            manager_sort_key(&a.manager)
                .cmp(&manager_sort_key(&b.manager))
                .then_with(|| a.name.cmp(&b.name))
        });

        Ok(infos)
    }

    pub async fn get_sinks_status(&self) -> Result<Vec<SinkStatusInfo>, Error> {
        let query = SinksQuery {
            in_config: Some(true),
            ..SinksQuery::default()
        };
        self.get_sinks(query).await.map(|infos| {
            infos
                .into_iter()
                .map(|info| SinkStatusInfo {
                    name: info.name,
                    target: info.target,
                    manager: info.manager,
                    in_config: info.in_config,
                    running: info.running,
                    blocked: info.blocked,
                    lagging_subjects: info.lagging_subjects,
                    last_error: info.last_error,
                    transport: info
                        .server
                        .as_ref()
                        .map(|server| server.transport.kind().to_string()),
                })
                .collect()
        })
    }

    async fn get_sink_registry(
        &self,
    ) -> Result<Vec<crate::sink::SinkRegistration>, Error> {
        let path = ActorPath::from("/user/node/sink_registry");
        let registry =
            self.system.get_actor::<SinkRegistry>(&path).await.map_err(
                |e| {
                    warn!(error = %e, "Failed to get sink registry actor");
                    actor_communication_error("sink_registry", e)
                },
            )?;
        let response = registry
            .ask(SinkRegistryMessage::GetSinkRegistry)
            .await
            .map_err(|e| {
                warn!(error = %e, "Failed to query sink registry");
                actor_communication_error("sink_registry", e)
            })?;
        match response {
            SinkRegistryResponse::Registry(regs) => Ok(regs),
            other => {
                warn!(response = ?other, "Unexpected response from sink registry");
                Err(Error::UnexpectedResponse {
                    actor: "sink_registry".to_string(),
                    expected: "Registry".to_string(),
                    received: format!("{other:?}"),
                })
            }
        }
    }

    async fn get_sink_registration(
        &self,
        name: &str,
    ) -> Result<crate::sink::SinkRegistration, Error> {
        let path = ActorPath::from("/user/node/sink_registry");
        let registry =
            self.system.get_actor::<SinkRegistry>(&path).await.map_err(
                |e| {
                    warn!(error = %e, "Failed to get sink registry actor");
                    actor_communication_error("sink_registry", e)
                },
            )?;
        let response = registry
            .ask(SinkRegistryMessage::GetSink {
                name: name.to_owned(),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %name, "Failed to query sink registry");
                actor_communication_error("sink_registry", e)
            })?;
        match response {
            SinkRegistryResponse::Sink(Some(reg)) => Ok(reg),
            SinkRegistryResponse::Sink(None) => {
                Err(Error::SinkNotFound(name.to_string()))
            }
            other => {
                warn!(response = ?other, sink = %name, "Unexpected response from sink registry");
                Err(Error::UnexpectedResponse {
                    actor: "sink_registry".to_string(),
                    expected: "Sink".to_string(),
                    received: format!("{other:?}"),
                })
            }
        }
    }

    async fn unregister_sink(&self, name: &str) -> Result<(), Error> {
        let path = ActorPath::from("/user/node/sink_registry");
        let registry =
            self.system.get_actor::<SinkRegistry>(&path).await.map_err(
                |e| {
                    warn!(error = %e, "Failed to get sink registry actor");
                    actor_communication_error("sink_registry", e)
                },
            )?;
        registry
            .tell(SinkRegistryMessage::UnregisterSink {
                name: name.to_owned(),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %name, "Failed to unregister sink");
                actor_communication_error("sink_registry", e)
            })?;
        Ok(())
    }

    pub async fn unblock_sink(&self, sink_name: String) -> Result<(), Error> {
        self.ensure_mutations_allowed()?;
        require_non_empty_str("sink_name", &sink_name)?;
        let registration = self.get_sink_registration(&sink_name).await?;
        let target = manager_target_from_registration(&registration)?;
        let path = manager_path(&target);
        let manager = self
            .system
            .get_actor::<SinkManager>(&path)
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %sink_name, "Failed to get sink manager actor");
                actor_communication_error("sink_manager", e)
            })?;
        manager
            .tell(SinkManagerMessage::UnblockSink {
                sink: sink_name.clone(),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %sink_name, "Failed to unblock sink");
                actor_communication_error("sink_manager", e)
            })?;
        Ok(())
    }

    /// Delete all persisted cursors and transient state for a sink.
    ///
    /// This operation is only available while the node is running in safe mode.
    /// The sink manager is located through the sink registry, so callers only
    /// need to provide the unique sink name.
    pub async fn delete_sink_cursors(
        &self,
        sink_name: String,
    ) -> Result<(), Error> {
        self.ensure_safe_mode_required("sink cursor deletion")?;
        require_non_empty_str("sink_name", &sink_name)?;

        let registration = self.get_sink_registration(&sink_name).await?;
        let target = manager_target_from_registration(&registration)?;
        let path = manager_path(&target);
        let manager = self
            .system
            .get_actor::<SinkManager>(&path)
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %sink_name, "Failed to get sink manager actor");
                actor_communication_error("sink_manager", e)
            })?;

        manager
            .tell(SinkManagerMessage::DeleteSinkCursors {
                sink: sink_name.clone(),
            })
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %sink_name, "Failed to delete sink cursors");
                actor_communication_error("sink_manager", e)
            })?;

        if !registration.from_config {
            self.unregister_sink(&sink_name).await?;
        }

        Ok(())
    }

    /// Manually replay events for specific subject/sink pairs.
    ///
    /// Each item rewinds the sink cursor for the subject to `from_sn - 1`, marks
    /// the subject as lagging and triggers a catch-up. The catch-up will deliver
    /// events from `from_sn` up to the last seen event.
    ///
    /// Only available outside safe mode.
    pub async fn replay_sink_events(
        &self,
        request: SinkReplayRequest,
    ) -> Result<SinkReplayResponse, Error> {
        self.ensure_mutations_allowed()?;
        validate_sink_replay_request(&request)?;

        // Resolve each distinct sink once in parallel instead of once per item.
        let unique_sinks: HashSet<String> = request
            .requests
            .iter()
            .map(|item| item.sink.clone())
            .collect();

        let mut registration_futures = Vec::with_capacity(unique_sinks.len());
        for sink in unique_sinks {
            registration_futures.push(async move {
                self.get_sink_registration(&sink)
                    .await
                    .map(|registration| (sink, registration))
            });
        }

        let registration_results =
            futures::future::join_all(registration_futures).await;
        let mut registrations: HashMap<String, crate::sink::SinkRegistration> =
            HashMap::new();
        let mut errors: Vec<SinkReplayError> = Vec::new();

        for result in registration_results {
            match result {
                Ok((sink, registration)) => {
                    registrations.insert(sink, registration);
                }
                Err(e) => {
                    // The sink name is lost here because get_sink_registration failed
                    // before returning it. We log the error; the individual items for
                    // this sink will be reported below using the request data.
                    warn!(error = %e, "Failed to resolve sink for replay");
                }
            }
        }

        let mut by_manager: HashMap<ActorPath, Vec<SinkReplayItem>> =
            HashMap::new();

        for item in request.requests {
            match registrations.get(&item.sink) {
                Some(registration) => {
                    match manager_target_from_registration(registration) {
                        Ok(target) => {
                            let path = manager_path(&target);
                            by_manager.entry(path).or_default().push(item);
                        }
                        Err(e) => {
                            warn!(
                                sink = %item.sink,
                                subject_id = %item.subject_id,
                                from_sn = %item.from_sn,
                                error = %e,
                                "Failed to determine manager for replay item"
                            );
                            errors.push(SinkReplayError {
                                sink: item.sink,
                                subject_id: item.subject_id,
                                from_sn: item.from_sn,
                                reason: e.to_string(),
                            });
                        }
                    }
                }
                None => {
                    warn!(
                        sink = %item.sink,
                        subject_id = %item.subject_id,
                        from_sn = %item.from_sn,
                        "Sink not found for replay item"
                    );
                    let sink_name = item.sink.clone();
                    errors.push(SinkReplayError {
                        sink: sink_name.clone(),
                        subject_id: item.subject_id,
                        from_sn: item.from_sn,
                        reason: Error::SinkNotFound(sink_name).to_string(),
                    });
                }
            }
        }

        let mut processed = Vec::new();

        for (path, items) in by_manager {
            let manager = match self
                .system
                .get_actor::<crate::sink::manager::SinkManager>(&path)
                .await
            {
                Ok(manager) => manager,
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path,
                        "Failed to get sink manager actor for replay"
                    );
                    let reason = actor_communication_error("sink_manager", e)
                        .to_string();
                    for item in items {
                        errors.push(SinkReplayError {
                            sink: item.sink,
                            subject_id: item.subject_id,
                            from_sn: item.from_sn,
                            reason: reason.clone(),
                        });
                    }
                    continue;
                }
            };

            let response = match manager
                .ask(crate::sink::manager::SinkManagerMessage::ReplayEvents {
                    requests: items.clone(),
                })
                .await
            {
                Ok(response) => response,
                Err(e) => {
                    warn!(
                        error = %e,
                        path = %path,
                        "Failed to send replay request to sink manager"
                    );
                    let reason = actor_communication_error("sink_manager", e)
                        .to_string();
                    for item in items {
                        errors.push(SinkReplayError {
                            sink: item.sink,
                            subject_id: item.subject_id,
                            from_sn: item.from_sn,
                            reason: reason.clone(),
                        });
                    }
                    continue;
                }
            };

            match response {
                crate::sink::manager::SinkManagerResponse::ReplayResult(
                    mut res,
                ) => {
                    processed.append(&mut res.processed);
                    errors.append(&mut res.errors);
                }
                other => {
                    warn!(
                        response = ?other,
                        path = %path,
                        "Unexpected response from sink manager for replay"
                    );
                    let reason = Error::UnexpectedResponse {
                        actor: "sink_manager".to_string(),
                        expected: "ReplayResult".to_string(),
                        received: format!("{other:?}"),
                    }
                    .to_string();
                    for item in items {
                        errors.push(SinkReplayError {
                            sink: item.sink,
                            subject_id: item.subject_id,
                            from_sn: item.from_sn,
                            reason: reason.clone(),
                        });
                    }
                }
            }
        }

        Ok(SinkReplayResponse { processed, errors })
    }

    /// Run a non-persistent end-to-end test of a sink.
    ///
    /// Performs a health check and sends a test payload using the sink's real
    /// configuration (auth, signature, compression). No cursor is advanced and
    /// no state is persisted.
    pub async fn test_sink(&self, sink_name: String) -> Result<(), Error> {
        self.ensure_mutations_allowed()?;
        require_non_empty_str("sink_name", &sink_name)?;

        let registration = self.get_sink_registration(&sink_name).await?;
        let target = manager_target_from_registration(&registration)?;
        let path = manager_path(&target);
        let manager = self
            .system
            .get_actor::<crate::sink::manager::SinkManager>(&path)
            .await
            .map_err(|e| {
                warn!(error = %e, sink = %sink_name, "Failed to get sink manager actor");
                actor_communication_error("sink_manager", e)
            })?;

        match manager
            .ask(crate::sink::manager::SinkManagerMessage::TestSink {
                sink: sink_name.clone(),
            })
            .await
        {
            Ok(crate::sink::manager::SinkManagerResponse::TestResult(
                result,
            )) => result.map_err(Error::SinkTestFailed),
            Ok(other) => {
                warn!(
                    sink = %sink_name,
                    response = ?other,
                    "Unexpected response from sink manager for test"
                );
                Err(Error::UnexpectedResponse {
                    actor: "sink_manager".to_string(),
                    expected: "TestResult".to_string(),
                    received: format!("{other:?}"),
                })
            }
            Err(e) => {
                warn!(error = %e, sink = %sink_name, "Failed to test sink");
                Err(actor_communication_error("sink_manager", e))
            }
        }
    }

    pub async fn delete_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_safe_mode_required("subject deletion")?;
        validate_subject_id(&subject_id)?;
        self.begin_subject_deletion(&subject_id).await?;

        let result = async {
            let subject_data = self.subject_data(&subject_id).await?;

            match subject_data {
                node::SubjectData::Governance { .. } => {
                    info!(
                        subject_id = %subject_id,
                        subject_type = "governance",
                        "Deleting subject"
                    );
                    let trackers =
                        self.governance_trackers(&subject_id).await?;
                    if !trackers.is_empty() {
                        return Err(Error::GovernanceHasTrackers {
                            governance_id: subject_id.to_string(),
                            trackers: trackers
                                .into_iter()
                                .map(|tracker| tracker.to_string())
                                .collect(),
                        });
                    }
                    let mut cleanup_errors = Vec::new();

                    match self
                        .subject_manager
                        .ask(SubjectManagerMessage::DeleteGovernance {
                            subject_id: subject_id.clone(),
                        })
                        .await
                    {
                        Ok(SubjectManagerResponse::DeleteGovernance) => {}
                        Ok(other) => cleanup_errors.push(format!(
                            "subject_manager: unexpected response {other:?}"
                        )),
                        Err(err) => cleanup_errors
                            .push(format!("subject_manager: {err}")),
                    }

                    self.purge_common_subject_state(
                        &subject_id,
                        &mut cleanup_errors,
                    )
                    .await;

                    self.delete_subject_from_node(
                        &subject_id,
                        &mut cleanup_errors,
                    )
                    .await;

                    if cleanup_errors.is_empty() {
                        info!(
                            subject_id = %subject_id,
                            subject_type = "governance",
                            "Subject deleted successfully"
                        );
                        Ok("Governance deleted successfully".to_owned())
                    } else {
                        Err(Error::Internal(format!(
                            "governance deletion completed partially: {}",
                            cleanup_errors.join("; ")
                        )))
                    }
                }
                node::SubjectData::Tracker { .. } => {
                    info!(
                        subject_id = %subject_id,
                        subject_type = "tracker",
                        "Deleting subject"
                    );
                    let mut cleanup_errors = Vec::new();

                    self.purge_common_subject_state(
                        &subject_id,
                        &mut cleanup_errors,
                    )
                    .await;

                    match self
                        .subject_manager
                        .ask(SubjectManagerMessage::DeleteTracker {
                            subject_id: subject_id.clone(),
                        })
                        .await
                    {
                        Ok(SubjectManagerResponse::DeleteTracker) => {}
                        Ok(other) => cleanup_errors.push(format!(
                            "subject_manager: unexpected response {other:?}"
                        )),
                        Err(err) => cleanup_errors
                            .push(format!("subject_manager: {err}")),
                    }

                    self.delete_subject_from_node(
                        &subject_id,
                        &mut cleanup_errors,
                    )
                    .await;

                    if cleanup_errors.is_empty() {
                        info!(
                            subject_id = %subject_id,
                            subject_type = "tracker",
                            "Subject deleted successfully"
                        );
                        Ok("Tracker deleted successfully".to_owned())
                    } else {
                        Err(Error::Internal(format!(
                            "tracker deletion completed partially: {}",
                            cleanup_errors.join("; ")
                        )))
                    }
                }
            }
        }
        .await;

        self.end_subject_deletion(&subject_id).await;
        result
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
        validate_governance_id(&governance_id)?;
        if let Some(schema_id) = schema_id.as_ref() {
            require_non_empty_str("schema_id", schema_id)?;
        }
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
        validate_subject_id(&subject_id)?;
        validate_events_query(&query)?;
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
        validate_subject_id(&subject_id)?;
        validate_sink_events_query(&query)?;

        let subject_id_str = subject_id.to_string();
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
                match e {
                    ActorError::NotFound { .. } => {
                        Error::SubjectNotFound(subject_id_str.clone())
                    }
                    _ => Error::from(e),
                }
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
        validate_subject_id(&subject_id)?;
        validate_aborts_query(&query)?;

        let subject_id_str = subject_id.to_string();
        let request_id = if let Some(request_id) = query.request_id.as_ref() {
            Some(parse_request_id(request_id)?.to_string())
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
        validate_subject_id(&subject_id)?;
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
        validate_subject_id(&subject_id)?;
        if let Some(quantity) = quantity {
            require_positive_u64("quantity", quantity)?;
        }
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
        validate_subject_id(&subject_id)?;
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

fn manager_target_from_status(
    status: &SinkManagerDetailedStatus,
) -> SinkManagerTarget {
    if status.is_governance {
        SinkManagerTarget::Node
    } else {
        SinkManagerTarget::Governance {
            governance_id: status.governance_id.clone().unwrap_or_default(),
        }
    }
}

fn manager_target_from_registration(
    reg: &crate::sink::SinkRegistration,
) -> Result<SinkManagerTarget, Error> {
    if reg.schema_id == "governance" {
        Ok(SinkManagerTarget::Node)
    } else if let Some(gov_id) = &reg.governance_id {
        Ok(SinkManagerTarget::Governance {
            governance_id: gov_id.clone(),
        })
    } else {
        Err(Error::Internal(format!(
            "sink '{}' has schema '{}' but no governance_id",
            reg.name, reg.schema_id
        )))
    }
}

fn manager_path(target: &SinkManagerTarget) -> ActorPath {
    match target {
        SinkManagerTarget::Node => {
            ActorPath::from("/user/node/node_sink_manager")
        }
        SinkManagerTarget::Governance { governance_id } => {
            ActorPath::from(format!(
                "/user/node/subject_manager/{}/sink_manager",
                governance_id
            ))
        }
    }
}

fn find_sink_config(
    sinks: &[SinkConfigEntry],
    manager: &SinkManagerTarget,
    sink_name: &str,
) -> (Option<SinkTarget>, Option<SinkServer>) {
    for entry in sinks {
        let SinkTarget::Schema {
            schema_id,
            governance_id: target_gov_id,
        } = &entry.target;
        let applies = match (schema_id.as_str(), target_gov_id, manager) {
            ("governance", None, SinkManagerTarget::Node) => true,
            (
                _,
                Some(target_gov_id),
                SinkManagerTarget::Governance { governance_id },
            ) => target_gov_id == governance_id,
            _ => false,
        };
        if applies
            && let Some(server) =
                entry.servers.iter().find(|s| s.server == sink_name)
        {
            return (Some(entry.target.clone()), Some(server.clone()));
        }
    }
    (None, None)
}

fn sink_info_matches_query(info: &SinkInfo, query: &SinksQuery) -> bool {
    if let Some(name) = &query.name
        && info.name != *name
    {
        return false;
    }
    if let Some(target) = &query.target {
        let matches = match info.target.as_ref() {
            Some(SinkTarget::Schema { schema_id, .. }) => {
                (target == "governance" && schema_id == "governance")
                    || (target == "schema" && schema_id != "governance")
            }
            None => false,
        };
        if !matches {
            return false;
        }
    }
    if let Some(schema_id) = &query.schema_id {
        let matches = matches!(
            info.target.as_ref(),
            Some(SinkTarget::Schema { schema_id: id, .. }) if id == schema_id
        );
        if !matches {
            return false;
        }
    }
    if let Some(governance_id) = &query.governance_id {
        let matches = matches!(
            info.target.as_ref(),
            Some(SinkTarget::Schema { governance_id: id, .. }) if id.as_ref() == Some(governance_id)
        );
        if !matches {
            return false;
        }
    }
    if let Some(in_config) = query.in_config
        && info.in_config != in_config
    {
        return false;
    }
    if let Some(running) = query.running
        && info.running != running
    {
        return false;
    }
    true
}

fn manager_sort_key(manager: &SinkManagerTarget) -> String {
    match manager {
        SinkManagerTarget::Node => "node".to_string(),
        SinkManagerTarget::Governance { governance_id } => {
            format!("governance:{governance_id}")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_actors::{ActorError, ActorPath};
    use ave_common::sink::{HttpSinkConfig, SinkTransportConfig};

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

    #[test]
    fn finds_sink_config_for_node_manager() {
        let server = SinkServer {
            server: "gov_sink".to_string(),
            transport: SinkTransportConfig::Http(Box::new(HttpSinkConfig {
                url: "http://example.com".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        let entry = SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "governance".to_string(),
                governance_id: None,
            },
            servers: vec![server.clone()],
        };
        let (target, found_server) =
            find_sink_config(&[entry], &SinkManagerTarget::Node, "gov_sink");
        assert!(
            matches!(target, Some(SinkTarget::Schema { schema_id, .. }) if schema_id == "governance")
        );
        assert_eq!(found_server.unwrap().server, "gov_sink");
    }

    #[test]
    fn finds_sink_config_for_governance_manager() {
        let server = SinkServer {
            server: "schema_sink".to_string(),
            transport: SinkTransportConfig::Http(Box::new(HttpSinkConfig {
                url: "http://example.com".to_string(),
                ..Default::default()
            })),
            ..Default::default()
        };
        let entry = SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "schema1".to_string(),
                governance_id: Some("gov1".to_string()),
            },
            servers: vec![server.clone()],
        };
        let manager = SinkManagerTarget::Governance {
            governance_id: "gov1".to_string(),
        };
        let (target, found_server) =
            find_sink_config(&[entry], &manager, "schema_sink");
        assert!(matches!(target, Some(SinkTarget::Schema { .. })));
        assert_eq!(found_server.unwrap().server, "schema_sink");
    }

    #[test]
    fn sink_info_query_filters_by_name() {
        let info = SinkInfo {
            name: "foo".to_string(),
            target: Some(SinkTarget::Schema {
                schema_id: "governance".to_string(),
                governance_id: None,
            }),
            manager: SinkManagerTarget::Node,
            in_config: true,
            running: true,
            blocked: None,
            lagging_subjects: 0,
            last_error: None,
            server: None,
        };
        assert!(sink_info_matches_query(
            &info,
            &SinksQuery {
                name: Some("foo".to_string()),
                ..Default::default()
            }
        ));
        assert!(!sink_info_matches_query(
            &info,
            &SinksQuery {
                name: Some("bar".to_string()),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn sink_info_query_filters_by_running_and_in_config() {
        let info = SinkInfo {
            name: "foo".to_string(),
            target: Some(SinkTarget::Schema {
                schema_id: "governance".to_string(),
                governance_id: None,
            }),
            manager: SinkManagerTarget::Node,
            in_config: true,
            running: false,
            blocked: Some("boom".to_string()),
            lagging_subjects: 0,
            last_error: None,
            server: None,
        };
        assert!(sink_info_matches_query(
            &info,
            &SinksQuery {
                in_config: Some(true),
                ..Default::default()
            }
        ));
        assert!(!sink_info_matches_query(
            &info,
            &SinksQuery {
                running: Some(true),
                ..Default::default()
            }
        ));
    }

    #[test]
    fn sink_info_query_filters_by_governance_id() {
        let info = SinkInfo {
            name: "schema_sink".to_string(),
            target: Some(SinkTarget::Schema {
                schema_id: "schema1".to_string(),
                governance_id: Some("gov1".to_string()),
            }),
            manager: SinkManagerTarget::Governance {
                governance_id: "gov1".to_string(),
            },
            in_config: true,
            running: true,
            blocked: None,
            lagging_subjects: 0,
            last_error: None,
            server: None,
        };
        assert!(sink_info_matches_query(
            &info,
            &SinksQuery {
                governance_id: Some("gov1".to_string()),
                ..Default::default()
            }
        ));
        assert!(!sink_info_matches_query(
            &info,
            &SinksQuery {
                governance_id: Some("gov2".to_string()),
                ..Default::default()
            }
        ));
    }
}
