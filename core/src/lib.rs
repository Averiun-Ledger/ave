#![recursion_limit = "256"]
pub mod config;
pub mod error;

pub(crate) mod api_input_validation;
pub mod approval;
pub mod auth;
pub mod compilation;
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
pub mod watchdog;

/// Embedded compiler service for tests (lib tests and integration tests
/// built with the `test` feature).
#[cfg(feature = "test")]
pub mod test_compiler;

/// Contract fixtures shared by unit tests and integration suites.
#[cfg(any(test, feature = "test"))]
pub mod test_contracts;

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use auth::{
    AuthWitness, SubjectAccess, SubjectAccessMessage, SubjectAccessResponse,
};
use ave_actors::{
    ActorError, ActorPath, ActorRef, ActorTreeNode, PersistentActor, SystemRef,
};
use ave_common::Error as CommonError;
use ave_common::bridge::request::{
    AbortsQuery, ApprovalState, ApprovalStateRes, EventRequestType,
    EventsQuery, IncidentsQuery, SinkEventsQuery, SinkReplayItem,
    SinkReplayRequest,
};
use ave_common::identity::keys::KeyPair;
use ave_common::identity::{DigestIdentifier, PublicKey, Signed};
use ave_common::request::EventRequest;
use ave_common::response::{
    GovsData, LedgerDB, MonitorNetworkState, PaginatorAborts, PaginatorEvents,
    RequestInfo, RequestInfoExtend, RequestsInManager,
    RequestsInManagerSubject, SinkEventsPage, SinkReplayError,
    SinkReplayResponse, SubjectDB, SubjsData, WatchdogIncidentRow,
};
use ave_common::{
    bridge::request::SinksQuery,
    bridge::response::{
        ActorTreeNodeView, ActorTreeResponse, SinkDeliveryState, SinkInfo,
        SinkManagerTarget, SinkServerView, SinkStatusInfo,
    },
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

use node::{
    Node, NodeMessage, NodeResponse, SINK_REPLAY_LEDGER_BATCH_SIZE,
    TransferSubject,
};
use prometheus_client::registry::Registry;
use request::{
    RequestData, RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
    error::APPROVAL_CONFLICT_PREFIX,
};
use sink::{SinkRegistry, SinkRegistryMessage, SinkRegistryResponse};
use system::system;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, warn};
use validation::{Validation, ValidationMessage};

use crate::api_input_validation::page_sorted;
pub use crate::api_input_validation::{
    DEFAULT_QUERY_LIMIT, MAX_QUERY_LIMIT, parse_request_id,
    require_non_empty_str, require_positive_u64, require_query_limit,
    resolve_page, validate_aborts_query, validate_actor_tree_query,
    validate_event_request, validate_events_query, validate_governance_id,
    validate_incidents_query, validate_request_id, validate_sink_events_query,
    validate_sink_replay_request, validate_sinks_query, validate_subject_id,
};
use crate::approval::request::StoredApproval;
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
use crate::tracker::{Tracker, TrackerMessage, TrackerResponse};

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

/// Holds the subject-deletion guard until the deletion completes: on
/// normal completion disarm it after `end_subject_deletion`; on
/// cancellation `Drop` releases it so a later deletion is not blocked
/// until restart.
struct SubjectDeletionGuard<'a> {
    deleting: &'a Arc<tokio::sync::Mutex<Option<DigestIdentifier>>>,
    subject_id: DigestIdentifier,
    armed: bool,
}

impl SubjectDeletionGuard<'_> {
    fn disarm(mut self) {
        self.armed = false;
    }
}

impl Drop for SubjectDeletionGuard<'_> {
    fn drop(&mut self) {
        if self.armed
            && let Ok(mut deleting) = self.deleting.try_lock()
            && deleting.as_ref() == Some(&self.subject_id)
        {
            *deleting = None;
        }
    }
}

/// Collects subtrees rooted at nodes carrying `wanted` as their
/// last path segment (subject actors are named by subject id).
fn collect_subject_roots<'a>(
    node: &'a ActorTreeNode,
    wanted: &str,
    matched: &mut Vec<&'a ActorTreeNode>,
) {
    if node.path.rsplit('/').next() == Some(wanted) {
        matched.push(node);
    } else {
        for child in &node.children {
            collect_subject_roots(child, wanted, matched);
        }
    }
}

/// Flattens one subtree in pre-order, appending at most
/// `*budget` entries so the partial view stays ordered and
/// parents always precede their children.
fn flatten_tree_node(
    node: &ActorTreeNode,
    depth: u64,
    budget: &mut u64,
    out: &mut Vec<ActorTreeNodeView>,
) {
    if *budget == 0 {
        return;
    }
    *budget -= 1;
    out.push(ActorTreeNodeView {
        path: node.path.clone(),
        actor_type: node.actor_type.clone(),
        depth,
    });
    for child in &node.children {
        flatten_tree_node(child, depth + 1, budget, out);
    }
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

    /// RAII counterpart of the begin/end deletion guard: a cancelled
    /// deletion future would otherwise hold the guard until restart.
    fn deletion_guard(
        &self,
        subject_id: &DigestIdentifier,
    ) -> SubjectDeletionGuard<'_> {
        SubjectDeletionGuard {
            deleting: &self.deleting_subject,
            subject_id: subject_id.clone(),
            armed: true,
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
        info!(msg_type = "ApiStart", "Creating Api");

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
            error!(msg_type = "System", error = %e, "Failed to create system");
            e
        })?;

        let newtork_monitor = Monitor::default();
        let newtork_monitor_actor = system
            .create_root_actor("network_monitor", newtork_monitor)
            .await
            .map_err(|e| {
                error!(
                    msg_type = "System",
                    error = %e,
                    "Can not create network_monitor actor"
                );
                Error::ActorCreation {
                    actor: "network_monitor".to_string(),
                    reason: e.to_string(),
                }
            })?;

        let spec = config.spec.map(MachineSpec::from);
        let network_metrics = ave_network::metrics::register(registry);
        let core_metrics = crate::metrics::register(registry);
        core_metrics.set_build_info(env!("CARGO_PKG_VERSION"));
        core_metrics.set_safe_mode(config.safe_mode);

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
            error!(msg_type = "System",
                msg_type = "NetInit",
                error = %e,
                "Can not create network"
            );
            Error::Network(e.to_string())
        })?;

        // Create worker
        let service = Intermediary::build(
            worker.service().sender(),
            system.clone(),
            graceful_token.clone(),
            crash_token.clone(),
            config.network.max_app_message_bytes,
        );

        let peer_id = worker.local_peer_id().to_string();

        worker.add_helper_sender(service.inbound_sender());

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
                error!(
                    msg_type = "System",
                    error = %e,
                    "Init system, can not create node actor"
                );
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
                        error!(msg_type = "System",
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
                error!(
                    msg_type = "System",
                    error = %e,
                    "Failed to get subject_access actor"
                );
                e
            })?;

        let subject_manager_actor: ActorRef<SubjectManager> = system
            .get_actor(&ActorPath::from("/user/node/subject_manager"))
            .await
            .map_err(|e| {
                error!(
                    msg_type = "System",
                    error = %e,
                    "Failed to get subject_manager actor"
                );
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
                error!(
                    msg_type = "System",
                    error = %e,
                    "Init system, can not create request actor"
                );
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
                        error!(
                            msg_type = "System",
                            error = %e,
                            "Failed to get tracking actor"
                        );
                        e
                    })?,
            )
        };

        let Some(ext_db) = system.get_helper::<Arc<ExternalDB>>("ext_db")
        else {
            error!(msg_type = "System", "External database helper not found");
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Unable to retrieve network state"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::NetworkState(e.to_string())
                })
            })?;

        match response {
            MonitorResponse::State(state) => Ok(state),
            _ => {
                error!(
                    msg_type = "NetState",
                    "Unexpected response from network monitor"
                );
                Err(Error::UnexpectedResponse {
                    actor: "network_monitor".to_string(),
                    expected: "State".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    ///////// Actors
    ////////////////////////////

    /// Snapshots the live supervision forest for ops: every node
    /// carries its path and concrete type. `subject` prunes the
    /// forest to subtrees rooted at that subject id; `limit`
    /// truncates in pre-order and reports it via `truncated`.
    pub fn get_actor_tree(
        &self,
        subject: Option<DigestIdentifier>,
        limit: u64,
    ) -> Result<ActorTreeResponse, Error> {
        use ave_common::bridge::request::MAX_TREE_LIMIT;
        if let Some(ref subject) = subject {
            validate_subject_id(subject)?;
        }
        require_positive_u64("limit", limit)?;
        if limit > MAX_TREE_LIMIT {
            return Err(Error::InvalidQueryParams(format!(
                "limit must not exceed {MAX_TREE_LIMIT}"
            )));
        }
        let forest = self.system.actor_tree();
        let roots: Vec<&ActorTreeNode> = match subject {
            None => forest.iter().collect(),
            Some(ref subject) => {
                let wanted = subject.to_string();
                let mut matched = Vec::new();
                for root in &forest {
                    collect_subject_roots(root, &wanted, &mut matched);
                }
                if matched.is_empty() {
                    return Err(Error::SubjectNotFound(wanted));
                }
                matched
            }
        };
        let total: u64 = roots.iter().map(|n| n.size() as u64).sum();
        let mut nodes = Vec::new();
        let mut budget = limit;
        for root in roots {
            flatten_tree_node(root, 0, &mut budget, &mut nodes);
            if budget == 0 {
                break;
            }
        }
        Ok(ActorTreeResponse {
            nodes,
            total,
            truncated: total > limit,
        })
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Request processing failed"
                );
                actor_communication_error("request", e)
            })?;

        match response {
            RequestHandlerResponse::RequestInManager(request) => Ok(request),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Request processing failed"
                );
                actor_communication_error("request", e)
            })?;

        match response {
            RequestHandlerResponse::RequestInManagerSubjectId(request) => {
                Ok(request)
            }
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
            .ask(RequestHandlerMessage::NewRequest {
                request: Arc::new(request),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Request processing failed"
                );
                actor_communication_error("request", e)
            })?;

        match response {
            RequestHandlerResponse::Ok(request_data) => Ok(request_data),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Node was unable to sign the request"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::SigningFailed(e.to_string())
                })
            })?;

        let signature = match response {
            NodeResponse::SignRequest(signature) => signature,
            _ => {
                warn!(msg_type = "ApiRequest", "Unexpected response from node");
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
                request: Arc::new(signed_event_req),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to send request"
                );
                actor_communication_error("request", e)
            })?;

        match response {
            RequestHandlerResponse::Ok(request_data) => Ok(request_data),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
    ) -> Result<Option<StoredApproval>, Error> {
        validate_subject_id(&subject_id)?;
        let response = self
            .request
            .ask(RequestHandlerMessage::GetApproval { state, subject_id })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get approval request"
                );
                actor_communication_error("request", e)
            })?;

        match response {
            RequestHandlerResponse::Approval(data) => Ok(data),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
        limit: u64,
        offset: u64,
    ) -> Result<Vec<StoredApproval>, Error> {
        let response = self
            .request
            .ask(RequestHandlerMessage::GetAllApprovals { state })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get approval requests"
                );
                actor_communication_error("request", e)
            })?;

        match response {
            RequestHandlerResponse::Approvals(data) => {
                // Approvers answer per governance in spawn order, so
                // sort for stable pages before slicing.
                Ok(page_sorted(data, limit, offset, |x| {
                    x.request.subject_id.to_string()
                }))
            }
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
        expected_request_id: String,
        expected_version: u64,
        expected_issued_at: u64,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        if state == ApprovalStateRes::Obsolete {
            warn!(
                msg_type = "ApiRequest",
                "Cannot set approval state to Obsolete"
            );
            return Err(Error::InvalidApprovalState("Obsolete".to_string()));
        }

        let response = self
            .request
            .ask(RequestHandlerMessage::ChangeApprovalState {
                subject_id,
                state,
                expected_request_id,
                expected_version,
                expected_issued_at,
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to change approval state"
                );
                if let ActorError::Functional { description } = &e
                    && description.starts_with(APPROVAL_CONFLICT_PREFIX)
                {
                    return Error::InvalidApprovalState(description.clone());
                }
                preserve_functional_actor_error(e, |e| {
                    Error::ApprovalUpdateFailed(e.to_string())
                })
            })?;

        match response {
            RequestHandlerResponse::Response(res) => Ok(res),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from request handler"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to abort request"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get request state"
                );
                actor_communication_error("tracking", e)
            })?;

        match response {
            RequestTrackingResponse::Info(state) => Ok(state),
            RequestTrackingResponse::NotFound => {
                Err(Error::RequestNotFound(request_id.to_string()))
            }
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from tracking"
                );
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
        limit: u64,
        offset: u64,
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get all request states"
                );
                actor_communication_error("tracking", e)
            })?;

        match response {
            RequestTrackingResponse::AllInfo(state) => {
                Ok(page_sorted(state, limit, offset, |x| x.request_id.clone()))
            }
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from tracking"
                );
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

    /// Clean-shutdown handshake: persists the clean marker on the
    /// node so the next boot skips reconciliation. Best-effort with
    /// a bound: shutdown must proceed even if the node never answers
    /// (the next boot then syncs, which is always safe).
    pub async fn prepare_clean_shutdown(&self) {
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
            self.node.ask(NodeMessage::PrepareCleanShutdown),
        )
        .await
        {
            Ok(Ok(_)) => debug!("Clean shutdown marker persisted"),
            Ok(Err(e)) => {
                warn!(msg_type = "ApiRequest",
                    error = %e,
                    "Failed to persist clean shutdown marker; next boot will reconcile"
                );
            }
            Err(_) => {
                warn!(
                    msg_type = "ApiRequest",
                    "Timed out persisting clean shutdown marker; next boot will reconcile"
                );
            }
        }
    }

    pub async fn get_pending_transfers(
        &self,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<TransferSubject>, Error> {
        let response =
            self.node.ask(NodeMessage::PendingTransfers).await.map_err(
                |e| {
                    warn!(
                        msg_type = "ApiRequest",
                        error = %e,
                        "Failed to get pending transfers"
                    );
                    actor_communication_error("node", e)
                },
            )?;

        let NodeResponse::PendingTransfers(pending) = response else {
            warn!(msg_type = "ApiRequest", "Unexpected response from node");
            return Err(Error::UnexpectedResponse {
                actor: "node".to_string(),
                expected: "PendingTransfers".to_string(),
                received: "other".to_string(),
            });
        };

        Ok(page_sorted(pending, limit, offset, |x| {
            x.subject_id.to_string()
        }))
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
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::AuthorizeGov {
                subject_id,
                witnesses,
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Authorize governance operation failed"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        match response {
            SubjectAccessResponse::None => Ok("Ok".to_owned()),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "None".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn disauthorize_governance(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::DisauthorizeGov { subject_id })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Disauthorize governance operation failed"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        match response {
            SubjectAccessResponse::None => Ok("Ok".to_owned()),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "None".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn authorized_governances(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::GetAuthorizedGovs)
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "AuthQuery",
                    error = %e,
                    "Failed to get authorized governances"
                );
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Subjects(subjects) => Ok(subjects),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
                warn!(
                    msg_type = "AuthQuery",
                    error = %e,
                    "Failed to check governance authorization"
                );
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Bool(v) => Ok(v),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::BanTracker { subject_id })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Ban tracker operation failed"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        match response {
            SubjectAccessResponse::None => Ok("Ok".to_owned()),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "None".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn unban_tracker(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::UnbanTracker { subject_id })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Unban tracker operation failed"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::AuthOperation(e.to_string())
                })
            })?;

        match response {
            SubjectAccessResponse::None => Ok("Ok".to_owned()),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
                Err(Error::UnexpectedResponse {
                    actor: "subject_access".to_string(),
                    expected: "None".to_string(),
                    received: "other".to_string(),
                })
            }
        }
    }

    pub async fn banned_trackers(
        &self,
    ) -> Result<Vec<DigestIdentifier>, Error> {
        let response = self
            .subject_access
            .ask(SubjectAccessMessage::GetBannedTrackers)
            .await
            .map_err(|e| {
                error!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get banned trackers"
                );
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Subjects(subjects) => Ok(subjects),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
                error!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to check tracker ban status"
                );
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Bool(v) => Ok(v),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Add sync peer operation failed"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Remove sync peer operation failed"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get sync peers"
                );
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Peers(peers) => Ok(peers),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
                error!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get subjects with sync peers"
                );
                actor_communication_error("subject_access", e)
            })?;

        match response {
            SubjectAccessResponse::Subjects(subjects) => Ok(subjects),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to update subject"
                );
                preserve_functional_actor_error(e, |e| {
                    Error::UpdateFailed(subject_id.to_string(), e.to_string())
                })
            })?;

        match response {
            SubjectAccessResponse::None => Ok("Update in progress".to_owned()),
            _ => {
                warn!(
                    msg_type = "ApiRequest",
                    "Unexpected response from subject_access"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Manual distribution failed"
                );
                preserve_functional_actor_error(e, |_| {
                    Error::DistributionFailed(subject_id.to_string())
                })
            })?;

        Ok("Manual distribution in progress".to_owned())
    }

    /// Lifts a tracker on demand so its boot healing runs (register
    /// reconcile, projection gap-fill, sink cursor review), then
    /// releases it. The `Up` round trip completes `pre_start`
    /// synchronously; async catch-ups continue through the sink
    /// chain, which lifts the subject itself as needed. Trackers
    /// only: governance subjects boot with the node, and lifting
    /// one by id is rejected below.
    pub async fn lift_subject_for_sync(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<String, Error> {
        self.ensure_mutations_allowed()?;
        validate_subject_id(&subject_id)?;
        const REQUESTER: &str = "manual-sync";
        match self
            .subject_manager
            .ask(SubjectManagerMessage::Up {
                subject_id: subject_id.clone(),
                requester: REQUESTER.to_owned(),
                create_ledger: None,
            })
            .await
        {
            Ok(SubjectManagerResponse::Up) => {}
            Ok(other) => {
                return Err(Error::UnexpectedResponse {
                    actor: "subject_manager".to_owned(),
                    expected: "Up".to_owned(),
                    received: format!("{other:?}"),
                });
            }
            Err(e) => {
                return Err(actor_communication_error("subject_manager", e));
            }
        }
        let lifted_is_tracker = match self
            .system
            .get_actor::<Tracker>(&ActorPath::from(format!(
                "/user/node/subject_manager/{subject_id}"
            )))
            .await
        {
            Ok(tracker) => {
                match tracker.ask(TrackerMessage::GetMetadata).await {
                    Ok(TrackerResponse::Metadata(metadata)) => {
                        metadata.subject_id == subject_id
                    }
                    _ => false,
                }
            }
            Err(_) => false,
        };
        if let Err(e) = self
            .subject_manager
            .ask(SubjectManagerMessage::Finish {
                subject_id: subject_id.clone(),
                requester: REQUESTER.to_owned(),
            })
            .await
        {
            warn!(
                msg_type = "ApiRequest",
                error = %e,
                "Manual sync lift finished without release"
            );
        }
        if !lifted_is_tracker {
            return Err(Error::SubjectNotFound(subject_id.to_string()));
        }
        Ok(subject_id.to_string())
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
                let Ok(actor) = system.get_actor::<SinkManager>(&path).await
                else {
                    return Ok(None);
                };
                match actor.ask(SinkManagerMessage::GetDetailedStatus).await {
                    Ok(SinkManagerResponse::DetailedStatus(status)) => {
                        Ok(Some(status))
                    }
                    Ok(other) => {
                        warn!(msg_type = "ApiRequest",
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
                        warn!(
                            msg_type = "ApiRequest",
                            manager = ?target,
                            error = %e,
                            "Failed to query sink manager status"
                        );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Sink manager status task panicked"
                );
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
                last_error: sink_status.and_then(|st| st.last_error.clone()),
                transport: server
                    .as_ref()
                    .map(|s| s.transport.kind().to_string()),
                server: server.map(SinkServerView::from),
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
                        transport: None,
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

    /// Returns the full view of a single sink, located by its unique name.
    ///
    /// Covers both registered sinks and residual ones reported by a manager
    /// but missing from the registry, exactly like [`Self::get_sinks`].
    pub async fn get_sink(&self, sink_name: String) -> Result<SinkInfo, Error> {
        require_non_empty_str("sink_name", &sink_name)?;
        self.get_sinks(SinksQuery::default())
            .await?
            .into_iter()
            .find(|info| info.name == sink_name)
            .ok_or(Error::SinkNotFound(sink_name))
    }

    pub async fn get_sinks_status(&self) -> Result<Vec<SinkStatusInfo>, Error> {
        // No in_config filter: residual sinks (removed from the config but
        // still tracked by the manager) must be visible in the status view.
        self.get_sinks(SinksQuery::default()).await.map(|infos| {
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
                    transport: info.transport,
                })
                .collect()
        })
    }

    /// Per-subject delivery cursors for the ops audit view: which sink
    /// has delivered which subject up to which sn, and whether it
    /// lags. Optionally filtered by subject and/or sink; unknown
    /// sinks report `SinkNotFound`, unknown subjects simply have no
    /// rows. Read-only: never boots subjects.
    pub async fn get_sink_deliveries(
        &self,
        subject: Option<DigestIdentifier>,
        sink: Option<String>,
    ) -> Result<Vec<SinkDeliveryState>, Error> {
        if let Some(ref subject) = subject {
            validate_subject_id(subject)?;
        }
        if let Some(ref sink) = sink {
            require_non_empty_str("sink", sink)?;
        }
        let mut paths: Vec<ActorPath> = Vec::new();
        if let Some(ref sink) = sink {
            let registration = self.get_sink_registration(sink).await?;
            paths.push(manager_path(&manager_target_from_registration(
                &registration,
            )?));
        } else {
            let registrations = self.get_sink_registry().await?;
            let mut targets = HashSet::new();
            for registration in &registrations {
                if let Ok(target) =
                    manager_target_from_registration(registration)
                {
                    targets.insert(target);
                }
            }
            for target in targets {
                paths.push(manager_path(&target));
            }
            paths.push(manager_path(&SinkManagerTarget::Node));
        }
        paths.sort();
        paths.dedup();
        let subject_filter = subject.map(|id| id.to_string());
        let mut out = Vec::new();
        for path in paths {
            let Ok(manager) = self.system.get_actor::<SinkManager>(&path).await
            else {
                continue;
            };
            let response = manager
                .ask(crate::sink::SinkManagerMessage::GetDeliveryCursors {
                    subject: subject_filter.clone(),
                })
                .await
                .map_err(|e| actor_communication_error("sink_manager", e))?;
            match response {
                SinkManagerResponse::DeliveryCursors(rows) => {
                    out.extend(rows.into_iter().map(|row| SinkDeliveryState {
                        sink: row.sink,
                        subject_id: row.subject_id,
                        cursor_sn: row.cursor_sn,
                        last_seen_sn: row.last_seen_sn,
                        lagging: row.lagging,
                    }));
                }
                SinkManagerResponse::Ok => {}
                other => {
                    return Err(Error::UnexpectedResponse {
                        actor: "sink_manager".to_owned(),
                        expected: "DeliveryCursors".to_owned(),
                        received: format!("{other:?}"),
                    });
                }
            }
        }
        if let Some(ref wanted) = sink {
            out.retain(|row| &row.sink == wanted);
        }
        out.sort_by(|a, b| {
            (&a.sink, &a.subject_id).cmp(&(&b.sink, &b.subject_id))
        });
        Ok(out)
    }

    async fn get_sink_registry(
        &self,
    ) -> Result<Vec<crate::sink::SinkRegistration>, Error> {
        let path = ActorPath::from("/user/node/sink_registry");
        let registry =
            self.system.get_actor::<SinkRegistry>(&path).await.map_err(
                |e| {
                    warn!(
                        msg_type = "ApiRequest",
                        error = %e,
                        "Failed to get sink registry actor"
                    );
                    actor_communication_error("sink_registry", e)
                },
            )?;
        let response = registry
            .ask(SinkRegistryMessage::GetSinkRegistry)
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to query sink registry"
                );
                actor_communication_error("sink_registry", e)
            })?;
        match response {
            SinkRegistryResponse::Registry(regs) => Ok(regs),
            other => {
                warn!(
                    msg_type = "ApiRequest",
                    response = ?other,
                    "Unexpected response from sink registry"
                );
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
                    warn!(
                        msg_type = "ApiRequest",
                        error = %e,
                        "Failed to get sink registry actor"
                    );
                    actor_communication_error("sink_registry", e)
                },
            )?;
        let response = registry
            .ask(SinkRegistryMessage::GetSink {
                name: name.to_owned(),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %name,
                    "Failed to query sink registry"
                );
                actor_communication_error("sink_registry", e)
            })?;
        match response {
            SinkRegistryResponse::Sink(Some(reg)) => Ok(reg),
            SinkRegistryResponse::Sink(None) => {
                Err(Error::SinkNotFound(name.to_string()))
            }
            other => {
                warn!(
                    msg_type = "ApiRequest",
                    response = ?other,
                    sink = %name,
                    "Unexpected response from sink registry"
                );
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
                    warn!(
                        msg_type = "ApiRequest",
                        error = %e,
                        "Failed to get sink registry actor"
                    );
                    actor_communication_error("sink_registry", e)
                },
            )?;
        registry
            .tell(SinkRegistryMessage::UnregisterSink {
                name: name.to_owned(),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %name,
                    "Failed to unregister sink"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %sink_name,
                    "Failed to get sink manager actor"
                );
                actor_communication_error("sink_manager", e)
            })?;
        manager
            .tell(SinkManagerMessage::UnblockSink {
                sink: sink_name.clone(),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %sink_name,
                    "Failed to unblock sink"
                );
                actor_communication_error("sink_manager", e)
            })?;
        Ok(())
    }

    /// Reset all persisted cursors and transient state for a sink.
    ///
    /// This operation is only available while the node is running in safe mode.
    /// The sink manager is located through the sink registry, so callers only
    /// need to provide the unique sink name.
    pub async fn reset_sink_cursors(
        &self,
        sink_name: String,
    ) -> Result<(), Error> {
        self.ensure_safe_mode_required("sink cursor reset")?;
        require_non_empty_str("sink_name", &sink_name)?;

        let registration = self.get_sink_registration(&sink_name).await?;
        let target = manager_target_from_registration(&registration)?;
        let path = manager_path(&target);
        let manager = self
            .system
            .get_actor::<SinkManager>(&path)
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %sink_name,
                    "Failed to get sink manager actor"
                );
                actor_communication_error("sink_manager", e)
            })?;

        manager
            .tell(SinkManagerMessage::ResetSinkCursors {
                sink: sink_name.clone(),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %sink_name,
                    "Failed to reset sink cursors"
                );
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
                    warn!(
                        msg_type = "ApiRequest",
                        error = %e,
                        "Failed to resolve sink for replay"
                    );
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
                            warn!(msg_type = "ApiRequest",
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
                    warn!(msg_type = "ApiRequest",
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
                    warn!(msg_type = "ApiRequest",
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
                    warn!(msg_type = "ApiRequest",
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
                    warn!(msg_type = "ApiRequest",
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %sink_name,
                    "Failed to get sink manager actor"
                );
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
            )) => result.map_err(|e| match e {
                crate::sink::manager::SinkTestError::NotConfigured => {
                    Error::SinkNotConfigured(sink_name.clone())
                }
                crate::sink::manager::SinkTestError::Internal(reason) => {
                    Error::Internal(format!(
                        "sink '{sink_name}' test: {reason}"
                    ))
                }
                crate::sink::manager::SinkTestError::Delivery(reason) => {
                    Error::SinkTestFailed(reason)
                }
            }),
            Ok(other) => {
                warn!(msg_type = "ApiRequest",
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    sink = %sink_name,
                    "Failed to test sink"
                );
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
        let guard = self.deletion_guard(&subject_id);

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

                    // Order matters: the manager purge reads node
                    // registration, and the external database goes last
                    // so no queries observe a half-deleted subject.
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

                    // Unregister from the node only on a clean run: a
                    // partial failure keeps the registration so a retry
                    // re-enters through the normal path (every step
                    // above tolerates already-deleted state).
                    if cleanup_errors.is_empty() {
                        self.delete_subject_from_node(
                            &subject_id,
                            &mut cleanup_errors,
                        )
                        .await;
                    }

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

                    self.purge_common_subject_state(
                        &subject_id,
                        &mut cleanup_errors,
                    )
                    .await;

                    // Unregister from the node only on a clean run: a
                    // partial failure keeps the registration so a retry
                    // re-enters through the normal path (every step
                    // above tolerates already-deleted state).
                    if cleanup_errors.is_empty() {
                        self.delete_subject_from_node(
                            &subject_id,
                            &mut cleanup_errors,
                        )
                        .await;
                    }

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
        guard.disarm();
        result
    }

    ///////// Register
    ////////////////////////////
    pub async fn all_govs(
        &self,
        active: Option<bool>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<GovsData>, Error> {
        self.db
            .get_governances(active, limit, offset)
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get governances"
                );
                Error::QueryFailed(e.to_string())
            })
    }

    pub async fn all_subjs(
        &self,
        governance_id: DigestIdentifier,
        active: Option<bool>,
        schema_id: Option<String>,
        limit: u64,
        offset: u64,
    ) -> Result<Vec<SubjsData>, Error> {
        validate_governance_id(&governance_id)?;
        if let Some(schema_id) = schema_id.as_ref() {
            require_non_empty_str("schema_id", schema_id)?;
        }
        let governance_id = governance_id.to_string();
        match self
            .db
            .get_subjects(&governance_id, active, schema_id, limit, offset)
            .await
        {
            Ok(subjects) => Ok(subjects),
            Err(ExternalDatabaseError::GovernanceNotFound(_)) => {
                Err(Error::GovernanceNotFound(governance_id))
            }
            Err(e) => {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get subjects"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get events"
                );
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
            .ask(NodeMessage::GetSubjectData(subject_id.clone()))
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get subject data for sink replay"
                );
                Error::from(e)
            })?;
        let NodeResponse::SubjectData(subject_data) = response else {
            warn!(msg_type = "ApiRequest", "Unexpected response from node");
            return Err(Error::UnexpectedResponse {
                actor: "node".to_string(),
                expected: "SubjectData".to_string(),
                received: "other".to_string(),
            });
        };
        let Some(subject_data) = subject_data else {
            return Err(Error::SubjectNotFound(subject_id_str));
        };

        Node::replay_sink_events(crate::node::SinkReplayInput {
            system: &self.system,
            subject_manager: &self.subject_manager,
            our_key: &self.public_key,
            subject_data,
            subject_id: &subject_id,
            from_sn: query.from_sn.unwrap_or(0),
            to_sn: query.to_sn,
            limit: query.limit.unwrap_or(100),
            ledger_batch_size: SINK_REPLAY_LEDGER_BATCH_SIZE,
        })
        .await
        .map_err(|e| {
            warn!(
                msg_type = "ApiRequest",
                error = %e,
                "Failed to replay sink events"
            );
            Error::from(e)
        })
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get aborts"
                );
                Error::QueryFailed(e.to_string())
            })
    }

    pub async fn get_recent_incidents(
        &self,
        query: IncidentsQuery,
    ) -> Result<Vec<WatchdogIncidentRow>, Error> {
        validate_incidents_query(&query)?;
        self.db.get_recent_incidents(query).await.map_err(|e| {
            warn!(
                msg_type = "ApiRequest",
                error = %e,
                "Failed to get watchdog incidents"
            );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get event"
                );
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
            require_query_limit("quantity", quantity)?;
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get events"
                );
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
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to get subject state"
                );
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

/// Test-only control surface (feature `test`): deterministic fault
/// injection, message injection and introspection for the e2e suites.
/// The faults live at the node's single network chokepoint (the
/// intermediary), so the test drives the exact interleaving.
#[cfg(feature = "test")]
impl Api {
    /// Arms the one-shot tracker-resolve fault on this node's
    /// distributor: the next evidence-ledger reload fails right
    /// after a successful `Up`. Test deliveries address the
    /// node-level distributor, which always exists.
    pub async fn test_fail_next_tracker_resolve(&self) -> Result<(), Error> {
        use crate::distribution::worker::{DistriWorker, DistriWorkerMessage};
        let actor = self
            .system
            .get_actor::<DistriWorker>(&ActorPath::from(
                "/user/node/distributor",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Distributor actor not found".to_owned(),
            })?;
        actor
            .tell(DistriWorkerMessage::TestFailNextTrackerResolve)
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Failed to arm tracker resolve fault".to_owned(),
            })
    }

    fn test_faults(
        &self,
    ) -> Result<helpers::network::test_faults::SharedFaultRegistry, Error> {
        self.system
            .get_helper::<helpers::network::test_faults::SharedFaultRegistry>(
                "test_faults",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "test_faults".to_owned(),
                reason: "Test fault registry helper not found".to_owned(),
            })
    }

    /// Installs a network fault rule on this node.
    pub async fn test_install_fault(
        &self,
        rule: helpers::network::test_faults::FaultRule,
    ) -> Result<(), Error> {
        let faults = self.test_faults()?;
        // Test infrastructure: the lock is never held across an await;
        // on poisoning (a test already panicked) keep going with the
        // guarded state.
        faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .install(rule);
        Ok(())
    }

    /// Clears every fault rule and drops every held message.
    pub async fn test_clear_faults(&self) -> Result<(), Error> {
        let faults = self.test_faults()?;
        faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
        Ok(())
    }

    /// How many messages are currently held by fault rules.
    pub async fn test_held_count(&self) -> Result<usize, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .held_count();
        Ok(count)
    }

    /// Outbound messages currently held by fault rules, so the test can
    /// craft a signed answer to what the node tried to send.
    pub async fn test_held_outbound(
        &self,
    ) -> Result<Vec<NetworkMessage>, Error> {
        let faults = self.test_faults()?;
        let messages = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .held_outbound_messages();
        Ok(messages)
    }

    /// Delivers every held message through the node's normal flow and
    /// removes the hold rules. Returns how many messages were
    /// delivered.
    pub async fn test_release_held(&self) -> Result<usize, Error> {
        let faults = self.test_faults()?;
        let commands = {
            let mut faults = faults
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let commands = faults.take_held_commands();
            commands
                .into_iter()
                .map(|command| {
                    let control = faults.control_sender_for(&command);
                    (control, command)
                })
                .collect::<Vec<_>>()
        };
        let count = commands.len();
        for (control, command) in commands {
            // A closed channel means the node is shutting down:
            // nothing to deliver to, and a test fault is never fatal.
            let _ = control.send(command).await;
        }
        Ok(count)
    }

    async fn test_witnesses_register(
        &self,
        governance_id: &DigestIdentifier,
    ) -> Result<
        ActorRef<crate::governance::witnesses_register::WitnessesRegister>,
        Error,
    > {
        self.system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/witnesses_register"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "witnesses_register".to_owned(),
                reason: "Witnesses register actor not found".to_owned(),
            })
    }

    /// Tells a raw ownership transfer straight to this node's
    /// witnesses register, bypassing evaluation: replays the exact
    /// boot-recovery interleaving (independent tells, no barrier)
    /// that a dirty reboot re-sends.
    pub async fn test_witnesses_transfer(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        sn: u64,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), Error> {
        use crate::governance::witnesses_register::{
            WitnessesRegisterMessage, WitnessesRegisterResponse,
        };
        let actor = self.test_witnesses_register(governance_id).await?;
        match actor
            .ask(WitnessesRegisterMessage::Transfer {
                subject_id,
                sn,
                new_owner,
                gov_version,
            })
            .await?
        {
            WitnessesRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "witnesses_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Tells a raw ownership creation straight to this node's
    /// witnesses register (see `test_witnesses_transfer`): replays
    /// the genesis a boot-recovery re-send would repeat.
    pub async fn test_witnesses_create(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), Error> {
        use crate::governance::witnesses_register::{
            WitnessesRegisterMessage, WitnessesRegisterResponse,
        };
        let actor = self.test_witnesses_register(governance_id).await?;
        match actor
            .ask(WitnessesRegisterMessage::Create {
                subject_id,
                owner,
                gov_version,
            })
            .await?
        {
            WitnessesRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "witnesses_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Tells a raw ownership confirmation straight to this node's
    /// witnesses register (see `test_witnesses_transfer`).
    pub async fn test_witnesses_confirm(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    ) -> Result<(), Error> {
        use crate::governance::witnesses_register::{
            WitnessesRegisterMessage, WitnessesRegisterResponse,
        };
        let actor = self.test_witnesses_register(governance_id).await?;
        match actor
            .ask(WitnessesRegisterMessage::Confirm {
                subject_id,
                sn,
                gov_version,
            })
            .await?
        {
            WitnessesRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "witnesses_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Tells a raw ownership rejection straight to this node's
    /// witnesses register (see `test_witnesses_transfer`).
    pub async fn test_witnesses_reject(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    ) -> Result<(), Error> {
        use crate::governance::witnesses_register::{
            WitnessesRegisterMessage, WitnessesRegisterResponse,
        };
        let actor = self.test_witnesses_register(governance_id).await?;
        match actor
            .ask(WitnessesRegisterMessage::Reject {
                subject_id,
                sn,
                gov_version,
            })
            .await?
        {
            WitnessesRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "witnesses_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Reads back this node's ownership view of a subject: actual
    /// owner, pending new owner, old owners with their last sn (by
    /// key), and how many stints the log holds.
    pub async fn test_witnesses_ownership(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<
        (
            Option<PublicKey>,
            Option<PublicKey>,
            Vec<(PublicKey, u64)>,
            usize,
        ),
        Error,
    > {
        use crate::governance::witnesses_register::{
            WitnessesRegisterMessage, WitnessesRegisterResponse,
        };
        let actor = self.test_witnesses_register(governance_id).await?;
        match actor
            .ask(WitnessesRegisterMessage::GetOwnership { subject_id })
            .await?
        {
            WitnessesRegisterResponse::Ownership {
                owner,
                pending,
                old_owners,
                stints,
            } => Ok((owner, pending, old_owners, stints)),
            _ => Err(Error::UnexpectedResponse {
                actor: "witnesses_register".to_owned(),
                expected: "Ownership".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Reads back this node's stored transfer proof for a subject:
    /// the verified transfer sn with the sender it was verified
    /// from, if any. Read-only; used to pin that rejected batches
    /// leave no proof behind.
    pub async fn test_get_verified_transfer_sn(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<Option<(u64, PublicKey)>, Error> {
        use crate::governance::transfer_verification_register::{
            TransferVerificationRegister, TransferVerificationRegisterMessage,
            TransferVerificationRegisterResponse,
        };
        let actor = self
            .system
            .get_actor::<TransferVerificationRegister>(&ActorPath::from(
                format!(
                    "/user/node/subject_manager/\
                    {governance_id}/transfer_verification_register"
                ),
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "transfer_verification_register".to_owned(),
                reason: "Transfer verification register not found".to_owned(),
            })?;
        match actor
            .ask(TransferVerificationRegisterMessage::GetVerifiedTransferSn {
                subject_id,
            })
            .await?
        {
            TransferVerificationRegisterResponse::VerifiedTransferSn(
                result,
            ) => Ok(result),
            _ => Err(Error::UnexpectedResponse {
                actor: "transfer_verification_register".to_owned(),
                expected: "VerifiedTransferSn".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Reads back the stored transfer proof with its hash when the
    /// register keeps one (migrated proofs always carry it; legacy
    /// proofs read back as `None`). Used to pin exact-identity
    /// replay: only a proof whose stored hash matches the aux under
    /// test may cover it.
    pub async fn test_get_verified_transfer_detail(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<Option<(u64, PublicKey, Option<DigestIdentifier>, bool)>, Error>
    {
        use crate::governance::transfer_verification_register::{
            TransferVerificationRegister, TransferVerificationRegisterMessage,
            TransferVerificationRegisterResponse,
        };
        let actor = self
            .system
            .get_actor::<TransferVerificationRegister>(&ActorPath::from(
                format!(
                    "/user/node/subject_manager/\
                    {governance_id}/transfer_verification_register"
                ),
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "transfer_verification_register".to_owned(),
                reason: "Transfer verification register not found".to_owned(),
            })?;
        match actor
            .ask(
                TransferVerificationRegisterMessage::GetVerifiedTransferDetail {
                    subject_id,
                },
            )
            .await?
        {
            TransferVerificationRegisterResponse::VerifiedTransferDetail(
                result,
            ) => Ok(result),
            _ => Err(Error::UnexpectedResponse {
                actor: "transfer_verification_register".to_owned(),
                expected: "VerifiedTransferDetail".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    async fn test_record_verified_transfer_inner(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
        transfer_hash: Option<DigestIdentifier>,
    ) -> Result<(), Error> {
        use crate::governance::transfer_verification_register::{
            TransferVerificationRegister, TransferVerificationRegisterMessage,
            TransferVerificationRegisterResponse,
        };
        let actor = self
            .system
            .get_actor::<TransferVerificationRegister>(&ActorPath::from(
                format!(
                    "/user/node/subject_manager/\
                    {governance_id}/transfer_verification_register"
                ),
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "transfer_verification_register".to_owned(),
                reason: "Transfer verification register not found".to_owned(),
            })?;
        let message = match transfer_hash {
            Some(transfer_hash) => {
                TransferVerificationRegisterMessage::RecordVerifiedTransferV2 {
                    subject_id,
                    transfer_sn,
                    sender,
                    transfer_hash,
                }
            }
            None => {
                TransferVerificationRegisterMessage::RecordVerifiedTransfer {
                    subject_id,
                    transfer_sn,
                    sender,
                }
            }
        };
        match actor.ask(message).await? {
            TransferVerificationRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "transfer_verification_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Records a legacy transfer proof without hash, like journals
    /// written before proofs carried one. Used to prove that legacy
    /// proofs never auto-cover an aux (they must be revalidated
    /// once and replaced by a hashed proof).
    pub async fn test_record_legacy_verified_transfer(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
    ) -> Result<(), Error> {
        self.test_record_verified_transfer_inner(
            governance_id,
            subject_id,
            transfer_sn,
            sender,
            None,
        )
        .await
    }

    /// Records a hashed proof directly so tests can exercise SN-only
    /// mismatches independently from legacy migration.
    pub async fn test_record_hashed_verified_transfer(
        &self,
        governance_id: &DigestIdentifier,
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
        transfer_hash: DigestIdentifier,
    ) -> Result<(), Error> {
        self.test_record_verified_transfer_inner(
            governance_id,
            subject_id,
            transfer_sn,
            sender,
            Some(transfer_hash),
        )
        .await
    }

    /// Arms a one-shot visibility fault on the node's distributor:
    /// the next modes lookup fails. Test deliveries address the
    /// node-level distributor, which always exists.
    pub async fn test_fail_next_tracker_delivery_modes(
        &self,
    ) -> Result<(), Error> {
        self.test_arm_modes_fault(false).await
    }

    /// Same as above, but the next lookup answers with no modes.
    pub async fn test_empty_next_tracker_delivery_modes(
        &self,
    ) -> Result<(), Error> {
        self.test_arm_modes_fault(true).await
    }

    /// Parks (`pause == true`) or releases a first-copy rollback
    /// barrier on this node: while paused, a failed first copy
    /// waits instead of deleting, so a test can interleave a valid
    /// copy and prove it survives. The flag lives in the shared
    /// test registry, never in a worker mailbox (which would stay
    /// blocked while parked).
    pub async fn test_pause_rollback(&self, pause: bool) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_rollback_paused(pause);
        Ok(())
    }

    /// How many times a first-copy rollback barrier was hit on this
    /// node: proves a concurrency test really interleaved instead
    /// of passing vacuously.
    pub async fn test_rollback_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .rollback_hold_count();
        Ok(count)
    }

    /// How many first-copy rollbacks backed off instead of
    /// deleting: proves the stale rollback saw the valid copy and
    /// spared it, rather than never running.
    pub async fn test_rollback_skip_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .rollback_skip_count();
        Ok(count)
    }

    /// Parks (`pause == true`) or releases the serving-read
    /// barrier on this node: while paused, a `get_ledger` that
    /// just acquired its per-read lease waits before resolving
    /// the tracker, so a test can overlap a second read and prove
    /// both own independent leases. The flag lives in the shared
    /// test registry, never in a worker mailbox (which would stay
    /// blocked while parked).
    pub async fn test_pause_get_ledger_up(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_get_ledger_up_paused(pause);
        Ok(())
    }

    /// How many serving reads parked at the `Up` barrier on this
    /// node: proves the interleaving really happened instead of
    /// passing vacuously when only one read ran.
    pub async fn test_get_ledger_up_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get_ledger_up_hold_count();
        Ok(count)
    }

    /// Parks (`pause == true`) or releases an exhausted `Auth`
    /// retry round on this node: while paused, a round that reached
    /// its retry budget with the target still ahead waits before
    /// stopping, so a test can interleave the final response before
    /// the stop drains it. The flag lives in the shared test
    /// registry, never in the actor mailbox (which would stay
    /// blocked while parked).
    pub async fn test_pause_update_retry_exhausted(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_update_retry_exhausted_paused(pause);
        Ok(())
    }

    /// How many exhausted retry rounds parked on this node: proves
    /// the parked round really reached its retry budget instead of
    /// passing vacuously on an early stop.
    pub async fn test_update_retry_exhausted_hold_count(
        &self,
    ) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .update_retry_exhausted_hold_count();
        Ok(count)
    }

    /// Parks or releases a tracker-sync serving request immediately
    /// after its initial governance-version read, before listing the
    /// register. Used to interleave a governance update deterministically.
    pub async fn test_pause_tracker_sync_version(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_tracker_sync_version_paused(pause);
        Ok(())
    }

    /// Number of tracker-sync requests parked after their initial
    /// governance-version read.
    pub async fn test_tracker_sync_version_hold_count(
        &self,
    ) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .tracker_sync_version_hold_count();
        Ok(count)
    }

    /// Arms a one-shot resolve failure for the next serving read
    /// on this node: that `get_ledger` fails right after its `Up`
    /// instead of resolving the tracker. The following reads
    /// proceed normally.
    pub async fn test_arm_fail_get_ledger_resolve(
        &self,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .arm_fail_get_ledger_resolve();
        Ok(())
    }

    /// Arms a one-shot sink-setup failure for the next subject
    /// creation on this node. The creation fails before touching
    /// any state; the following ones proceed normally.
    pub async fn test_arm_fail_next_sink(&self) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .arm_fail_next_sink();
        Ok(())
    }

    /// Arms a one-shot node-registration failure for the next
    /// subject creation on this node. Genesis already landed when it
    /// fires; the following creations proceed normally.
    pub async fn test_arm_fail_next_node_register(
        &self,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .arm_fail_next_node_register();
        Ok(())
    }

    /// Test-only: whether Node has completed registration of a
    /// subject. External projections may already contain genesis
    /// while creation is still partial, so they cannot answer this.
    pub async fn test_node_has_subject(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<bool, Error> {
        match self
            .node
            .ask(NodeMessage::GetSubjectData(subject_id))
            .await?
        {
            NodeResponse::SubjectData(data) => Ok(data.is_some()),
            _ => Err(Error::UnexpectedResponse {
                actor: "node".to_owned(),
                expected: "SubjectData".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: runs a subject creation through the subject
    /// manager with the given genesis ledger, surfacing partial
    /// creations instead of confirming them.
    pub async fn test_up_subject_with_create(
        &self,
        subject_id: DigestIdentifier,
        ledger: crate::model::event::Ledger,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::Up {
                subject_id,
                requester: "test-create".to_owned(),
                create_ledger: Some(Box::new(ledger)),
            })
            .await?
        {
            SubjectManagerResponse::Up => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "Up".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Attempt id captured when the rollback barrier last fired:
    /// lets a test prove which parked copy it is asserting on.
    pub async fn test_rollback_attempt(&self) -> Result<Option<u64>, Error> {
        let faults = self.test_faults()?;
        Ok(faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .rollback_attempt())
    }

    pub async fn test_pause_before_apply(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_before_apply_paused(pause);
        Ok(())
    }

    pub async fn test_before_apply_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .before_apply_hold_count();
        Ok(count)
    }

    /// Attempt id captured when the pre-apply barrier first fired,
    /// if any: lets a test prove the stale rollback belongs to a
    /// different attempt than the interleaved valid copy.
    pub async fn test_before_apply_attempt(
        &self,
    ) -> Result<Option<u64>, Error> {
        let faults = self.test_faults()?;
        Ok(faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .before_apply_attempt())
    }

    /// Worker path where the pre-apply barrier first fired, if any:
    /// proves the parked batch went through the expected worker.
    pub async fn test_before_apply_worker(
        &self,
    ) -> Result<Option<String>, Error> {
        let faults = self.test_faults()?;
        Ok(faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .before_apply_worker())
    }

    /// Parks (`pause == true`) or releases the post-acquire barrier
    /// on this node: while paused, a per-subject worker that just
    /// acquired its lease waits before applying, so a test can
    /// interleave a concurrent attempt while the guard is provably
    /// held. The flag lives in the shared test registry, never in
    /// a worker mailbox.
    pub async fn test_pause_after_acquire(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_after_acquire_paused(pause);
        Ok(())
    }

    /// How many times the post-acquire barrier was hit on this node:
    /// proves the parked copy really owns its lease.
    pub async fn test_after_acquire_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .after_acquire_hold_count();
        Ok(count)
    }

    /// Attempt id captured when the post-acquire barrier first
    /// fired, if any: lets a test prove which parked attempt it is
    /// asserting on.
    pub async fn test_after_acquire_attempt(
        &self,
    ) -> Result<Option<u64>, Error> {
        let faults = self.test_faults()?;
        Ok(faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .after_acquire_attempt())
    }

    /// Parks (`pause == true`) or releases the post-success barrier
    /// on this node: while paused, a per-subject worker whose copy
    /// just recorded success waits before its flow returns, so a
    /// test can hold a successful attempt active while another
    /// attempt finishes. The flag lives in the shared test
    /// registry, never in a worker mailbox.
    pub async fn test_pause_post_success(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_post_success_paused(pause);
        Ok(())
    }

    /// How many times the post-success barrier was hit on this node:
    /// proves the held copy really recorded its success first.
    pub async fn test_post_success_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .post_success_hold_count();
        Ok(count)
    }

    /// Attempt id captured when the post-success barrier first
    /// fired, if any: lets a test prove which successful attempt it
    /// is holding active.
    pub async fn test_post_success_attempt(
        &self,
    ) -> Result<Option<u64>, Error> {
        let faults = self.test_faults()?;
        Ok(faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .post_success_attempt())
    }

    /// Parks (`pause == true`) or releases the single-push
    /// post-update barrier on this node: while paused, a pushed
    /// event waits right after the update decision (applied or
    /// skipped) so a test can pin that the push landed before
    /// asserting on what it recorded. The flag lives in the shared
    /// test registry, never in a worker mailbox.
    pub async fn test_pause_single_updated(
        &self,
        pause: bool,
    ) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_single_updated_paused(pause);
        Ok(())
    }

    /// How many times the single-push post-update barrier was hit on
    /// this node: proves the push really went through the update
    /// decision instead of passing vacuously.
    pub async fn test_single_updated_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .single_updated_hold_count();
        Ok(count)
    }

    /// Attempt the single-push entry point assigned for a subject,
    /// if any: lets a test tell the skipped push apart from the
    /// parked batch it interleaves with.
    pub async fn test_single_push_attempt(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<Option<u64>, Error> {
        let faults = self.test_faults()?;
        Ok(faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .single_push_attempt(&subject_id.to_string()))
    }

    /// Parks (`pause == true`) or releases the pre-purge barrier on
    /// this node: while paused, a first-copy rollback waits after
    /// its metadata read but before the atomic purge, so a test can
    /// interleave a valid apply and prove the purge backs off. The
    /// flag lives in the shared test registry, never in a worker
    /// mailbox.
    pub async fn test_pause_pre_purge(&self, pause: bool) -> Result<(), Error> {
        self.test_faults()?
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .set_pre_purge_paused(pause);
        Ok(())
    }

    /// How many times the pre-purge barrier was hit on this node:
    /// proves the rollback really reached the purge gate with a
    /// stale tip instead of passing vacuously.
    pub async fn test_pre_purge_hold_count(&self) -> Result<u64, Error> {
        let faults = self.test_faults()?;
        let count = faults
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .pre_purge_hold_count();
        Ok(count)
    }

    /// Verification workload for a subject: events fed to the aux
    /// evidence replay and full local reloads performed, in that
    /// order. Lets scale tests pin the incremental check linear
    /// instead of re-scanning the prefix per aux. Test deliveries
    /// address the node-level distributor, which always exists.
    pub async fn test_verify_stats(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::transfer_verifier::SharedVerifyStats>(
                "verify_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "verify_stats".to_owned(),
                reason: "Verify stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot(&subject_id))
    }

    /// Origin-encoding counters: messages forwarded with the
    /// sender's encoding and messages encoded at the intermediary
    /// because they bypassed the sender, in that order. Lets
    /// transport tests prove the single serialization is reused end
    /// to end instead of re-encoded per hop.
    pub async fn test_encode_stats(&self) -> Result<(u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::helpers::network::intermediary::SharedEncodeStats>(
                "encode_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "encode_stats".to_owned(),
                reason: "Encode stats helper not found".to_owned(),
            })?;
        let guard = stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok((guard.forwarded, guard.fallback_encodes))
    }

    /// Number of deferred-acquisition triggers received by one
    /// governance actor. Runtime-only observability; no persisted
    /// state or artifact behavior is changed by this accessor.
    pub async fn test_deferred_acquisition_count(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<u64, Error> {
        use crate::governance::{
            Governance, GovernanceMessage, GovernanceResponse,
        };
        let actor = self
            .system
            .get_actor::<Governance>(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "governance".to_owned(),
                reason: "Governance actor not found".to_owned(),
            })?;
        match actor
            .ask(GovernanceMessage::TestDeferredAcquisitionCount)
            .await?
        {
            GovernanceResponse::DeferredAcquisitionCount(count) => Ok(count),
            _ => Err(Error::UnexpectedResponse {
                actor: "governance".to_owned(),
                expected: "DeferredAcquisitionCount".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: idle certifications reported by the governance
    /// version sync of one governance. Silent, failed or backed-off
    /// rounds must never increment it; a completed round with no
    /// superior peer reports exactly once per version.
    pub async fn test_version_sync_idle_count(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<u64, Error> {
        let actor = self
            .system
            .get_actor::<crate::governance::version_sync::GovernanceVersionSync>(
                &ActorPath::from(format!(
                    "/user/node/subject_manager/{}/version_sync",
                    governance_id
                )),
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync not found".to_owned(),
            })?;
        match actor
            .ask(
                crate::governance::version_sync::GovernanceVersionSyncMessage::GetIdleRounds,
            )
            .await?
        {
            crate::governance::version_sync::GovernanceVersionSyncResponse::IdleRounds(
                rounds,
            ) => Ok(rounds),
            _ => Err(Error::UnexpectedResponse {
                actor: "version_sync".to_owned(),
                expected: "IdleRounds".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: opens a governance version-sync round on demand
    /// by delivering a tick to the actor. Lets a test drive rounds
    /// without waiting for the configured interval.
    pub async fn test_version_sync_tick(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<crate::governance::version_sync::GovernanceVersionSync>(
                &ActorPath::from(format!(
                    "/user/node/subject_manager/{}/version_sync",
                    governance_id
                )),
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync not found".to_owned(),
            })?;
        actor
            .tell(
                crate::governance::version_sync::GovernanceVersionSyncMessage::Tick,
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync tell failed".to_owned(),
            })?;
        Ok(())
    }

    /// Test-only version sync round state: round, whether a round is
    /// open and pending peers. Read-only, no state change: also serves
    /// as an ask barrier ensuring prior tells were processed before
    /// asserting idle never fires.
    pub async fn test_version_sync_state(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<(u64, bool, usize), Error> {
        use crate::governance::version_sync::{
            GovernanceVersionSync, GovernanceVersionSyncMessage,
            GovernanceVersionSyncResponse,
        };
        let actor = self
            .system
            .get_actor::<GovernanceVersionSync>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/version_sync",
                governance_id
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync not found".to_owned(),
            })?;
        match actor
            .ask(GovernanceVersionSyncMessage::GetState)
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync state failed".to_owned(),
            })? {
            GovernanceVersionSyncResponse::State {
                round,
                round_open,
                pending_peers,
            } => Ok((round, round_open, pending_peers)),
            _ => Err(Error::UnexpectedResponse {
                actor: "version_sync".to_owned(),
                expected: "State".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: delivers a stale round timeout to the governance
    /// version sync of one governance. Lets a test prove an old
    /// timeout can not close the active round, drain its peers or
    /// cancel its timer.
    pub async fn test_version_sync_stale_timeout(
        &self,
        governance_id: DigestIdentifier,
        round: u64,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<crate::governance::version_sync::GovernanceVersionSync>(
                &ActorPath::from(format!(
                    "/user/node/subject_manager/{}/version_sync",
                    governance_id
                )),
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync not found".to_owned(),
            })?;
        actor
            .tell(
                crate::governance::version_sync::GovernanceVersionSyncMessage::RoundTimeout {
                    round,
                },
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync tell failed".to_owned(),
            })?;
        Ok(())
    }

    /// Test-only: overrides the boot-node flag of the governance
    /// version sync of one governance. Lets a test prove silence
    /// never certifies the tip even with `has_boot_nodes == false`,
    /// without changing the real network topology.
    pub async fn test_version_sync_set_has_boot_nodes(
        &self,
        governance_id: DigestIdentifier,
        value: bool,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<crate::governance::version_sync::GovernanceVersionSync>(
                &ActorPath::from(format!(
                    "/user/node/subject_manager/{}/version_sync",
                    governance_id
                )),
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync not found".to_owned(),
            })?;
        actor
            .tell(
                crate::governance::version_sync::GovernanceVersionSyncMessage::SetHasBootNodes(
                    value,
                ),
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "version_sync".to_owned(),
                reason: "Version sync tell failed".to_owned(),
            })?;
        Ok(())
    }

    /// Test-only: rounds with a live updater child for one witness
    /// of one subject's update. Lets a test prove a new sweep
    /// addressed a peer however its requests were faulted.
    pub async fn test_update_updater_rounds(
        &self,
        subject_id: DigestIdentifier,
        witness: PublicKey,
    ) -> Result<Vec<u64>, Error> {
        let mut rounds = Vec::new();
        for round in 0..=5 {
            let path = ActorPath::from(format!(
                "/user/node/auth/{subject_id}/{witness}_{round}"
            ));
            if self
                .system
                .get_actor::<crate::update::updater::Updater>(&path)
                .await
                .is_ok()
            {
                rounds.push(round);
            }
        }
        Ok(rounds)
    }

    /// Test-only: delivers a stale completion to the update actor
    /// of one subject. Lets a test prove a completion from another
    /// generation never stops the live sweep.
    pub async fn test_update_done(
        &self,
        subject_id: DigestIdentifier,
        sn: u64,
        round: u64,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<crate::update::Update>(&ActorPath::from(format!(
                "/user/node/auth/{subject_id}"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "update".to_owned(),
                reason: "Update not found".to_owned(),
            })?;
        actor
            .tell(crate::update::UpdateMessage::DistributionDone { sn, round })
            .await
            .map_err(|_| Error::MissingResource {
                name: "update".to_owned(),
                reason: "Update tell failed".to_owned(),
            })?;
        Ok(())
    }

    /// Test-only: whether the update actor of one subject is still
    /// alive. Lets a test prove a stale completion did not stop the
    /// live sweep.
    pub async fn test_update_alive(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<bool, Error> {
        Ok(self
            .system
            .get_actor::<crate::update::Update>(&ActorPath::from(format!(
                "/user/node/auth/{subject_id}"
            )))
            .await
            .is_ok())
    }

    /// Test-only: asks this node's governance actor to start a
    /// manual catch-up round, the same entry point the tracker sync
    /// nudge uses. Lets a test drive the `gov_manual_update`
    /// supervised round without staging a full sync cycle.
    pub async fn test_trigger_gov_update(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<(), Error> {
        use crate::governance::{Governance, GovernanceMessage};
        let actor = self
            .system
            .get_actor::<Governance>(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "governance".to_owned(),
                reason: "Governance actor not found".to_owned(),
            })?;
        actor
            .tell(GovernanceMessage::TriggerGovUpdate)
            .await
            .map_err(|_| Error::MissingResource {
                name: "governance".to_owned(),
                reason: "Governance trigger tell failed".to_owned(),
            })?;
        Ok(())
    }

    /// Test-only: opens a tracker sync round on demand by delivering
    /// a tick to the actor. Lets a test drive fetch/update cycles
    /// without waiting for the configured interval.
    pub async fn test_tracker_sync_tick(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<crate::governance::tracker_sync::TrackerSync>(
                &ActorPath::from(format!(
                    "/user/node/subject_manager/{}/tracker_sync",
                    governance_id
                )),
            )
            .await
            .map_err(|_| Error::MissingResource {
                name: "tracker_sync".to_owned(),
                reason: "Tracker sync not found".to_owned(),
            })?;
        actor
            .tell(crate::governance::tracker_sync::TrackerSyncMessage::Tick)
            .await
            .map_err(|_| Error::MissingResource {
                name: "tracker_sync".to_owned(),
                reason: "Tracker sync tell failed".to_owned(),
            })?;
        Ok(())
    }

    /// Test-only tracker sync round state: round, next nonce, pages
    /// this cycle and whether fetch/update timeouts are armed. Read-only,
    /// no state change: also serves as an ask barrier ensuring prior
    /// tells (injected pages) were processed before asserting no minting.
    pub async fn test_tracker_sync_state(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<(u64, u64, u32, bool, bool), Error> {
        use crate::governance::tracker_sync::{
            TrackerSync, TrackerSyncMessage, TrackerSyncResponse,
        };
        let actor = self
            .system
            .get_actor::<TrackerSync>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/tracker_sync",
                governance_id
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "tracker_sync".to_owned(),
                reason: "Tracker sync not found".to_owned(),
            })?;
        match actor.ask(TrackerSyncMessage::GetState).await.map_err(|_| {
            Error::MissingResource {
                name: "tracker_sync".to_owned(),
                reason: "Tracker sync state failed".to_owned(),
            }
        })? {
            TrackerSyncResponse::State {
                round,
                next_nonce,
                pages_this_cycle,
                has_fetch_timeout,
                has_update_timeout,
            } => Ok((
                round,
                next_nonce,
                pages_this_cycle,
                has_fetch_timeout,
                has_update_timeout,
            )),
            _ => Err(Error::UnexpectedResponse {
                actor: "tracker_sync".to_owned(),
                expected: "State".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Retained staged prefix per node: subjects holding events,
    /// staged events and staged bytes, in that order. Lets tests
    /// pin the deferred-store budget exactly instead of inferring
    /// retention from side effects. Test deliveries address the
    /// node-level distributor, which always exists.
    pub async fn test_deferred_stats(
        &self,
    ) -> Result<(usize, u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::deferred::SharedDeferredStats>(
                "deferred_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "deferred_stats".to_owned(),
                reason: "Deferred stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot())
    }

    /// Stored staged prefix per node, including the pruned dead
    /// head still in RAM: same shape as the live stats. Lets
    /// tests pin the real memory budget instead of only the live
    /// suffix.
    pub async fn test_deferred_retained_stats(
        &self,
    ) -> Result<(usize, u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::deferred::SharedDeferredStats>(
                "deferred_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "deferred_stats".to_owned(),
                reason: "Deferred stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot_retained())
    }

    /// Truncation-window builds for one subject: how many times
    /// `process_ledger_chunks` built the window to detect a truncated
    /// batch. Lets a test prove the window is only built when the
    /// sender claims completeness, never for partial batches.
    pub async fn test_truncation_window_calls(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<u64, Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::processor::SharedTruncationStats>(
                "truncation_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "truncation_stats".to_owned(),
                reason: "Truncation stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .count(&subject_id))
    }

    /// Fragment reassembly counters: assemblies, ready mains, ready
    /// auxes, decode attempts and expiries, in that order. Lets tests
    /// prove payload-hash rejection without decode, mixing rejection
    /// without apply and timer expiry without further messages.
    pub async fn test_fragment_stats(
        &self,
    ) -> Result<(u64, u64, u64, u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::worker::SharedFragStats>(
                "frag_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "frag_stats".to_owned(),
                reason: "Frag stats helper not found".to_owned(),
            })?;
        let guard = stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        Ok((
            guard.assemblies,
            guard.ready_mains,
            guard.ready_auxes,
            guard.decode_attempts,
            guard.expired,
        ))
    }

    /// Total fragment assemblies held across workers: in-flight plus
    /// ready sides. Lets expiry tests prove memory returns to zero
    /// without further messages.
    pub async fn test_fragment_assembly_len(&self) -> Result<usize, Error> {
        let (assemblies, ready_mains, ready_auxes, _, _) =
            self.test_fragment_stats().await?;
        Ok((assemblies + ready_mains + ready_auxes) as usize)
    }

    /// Replaces the node-level distributor's deferred-store bounds
    /// (subjects, events and bytes, per subject and global) so a
    /// test can trigger overflow with a handful of events.
    /// Production always uses the compiled-in defaults.
    pub async fn test_set_deferred_limits(
        &self,
        limits: crate::distribution::deferred::DeferredLimits,
    ) -> Result<(), Error> {
        use crate::distribution::worker::{DistriWorker, DistriWorkerMessage};
        let actor = self
            .system
            .get_actor::<DistriWorker>(&ActorPath::from(
                "/user/node/distributor",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Distributor actor not found".to_owned(),
            })?;
        actor
            .tell(DistriWorkerMessage::TestSetDeferredLimits { limits })
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Failed to set deferred limits".to_owned(),
            })
    }

    /// Buffer workload for the incremental suffix assembly:
    /// cloned events, merge/dedup visits and reordered elements,
    /// in that order. Lets scale tests pin the assembly linear
    /// instead of re-scanning or re-sorting the retained prefix
    /// per aux.
    pub async fn test_buffer_stats(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(u64, u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::transfer_verifier::SharedVerifyStats>(
                "verify_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "verify_stats".to_owned(),
                reason: "Verify stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .buffer_snapshot(&subject_id))
    }

    /// Drops the saved verification cursor for one subject on the
    /// node-level distributor, like an LRU eviction, while keeping
    /// any staged prefix. Test-only.
    pub async fn test_evict_verify_cursor(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(), Error> {
        use crate::distribution::worker::{DistriWorker, DistriWorkerMessage};
        let actor = self
            .system
            .get_actor::<DistriWorker>(&ActorPath::from(
                "/user/node/distributor",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Distributor actor not found".to_owned(),
            })?;
        actor
            .ask(DistriWorkerMessage::TestEvictVerifyCursor { subject_id })
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Failed to evict verify cursor".to_owned(),
            })
    }

    /// Authoritative rebuilds from genesis for a subject: tells an
    /// incremental suffix replay apart from a full scan.
    pub async fn test_full_rebuilds(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<u64, Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::transfer_verifier::SharedVerifyStats>(
                "verify_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "verify_stats".to_owned(),
                reason: "Verify stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .full_rebuilds(&subject_id))
    }

    /// Successful evaluation-role resolutions for a subject: proves
    /// repeated events reuse the cached register instead of
    /// resolving per event.
    pub async fn test_roles_resolved(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<u64, Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::transfer_verifier::SharedVerifyStats>(
                "verify_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "verify_stats".to_owned(),
                reason: "Verify stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .roles_resolved(&subject_id))
    }

    /// Ownership work for the incremental access projection: cloned
    /// entries and visited entries, in that order. Fact-only tails
    /// reuse the cached decision and add nothing.
    pub async fn test_ownership_stats(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::distribution::transfer_verifier::SharedVerifyStats>(
                "verify_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "verify_stats".to_owned(),
                reason: "Verify stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .ownership_snapshot(&subject_id))
    }

    /// Read-only view of the last successful copy attempt for a
    /// subject: proves a concurrent valid copy really registered
    /// instead of the rollback passing vacuously.
    pub async fn test_get_last_success(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<Option<u64>, Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::GetLastSuccess { subject_id })
            .await?
        {
            SubjectManagerResponse::LastSuccess(result) => Ok(result),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "LastSuccess".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: whether the external subject row still exists
    /// for a subject. Lets rollback tests prove the purge cleared
    /// the register instead of only the tracker state.
    pub async fn test_has_subject_entry(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<bool, Error> {
        use crate::governance::subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        };
        let actor = self
            .system
            .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/subject_register"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject register".to_owned(),
                reason: "Subject register not found".to_owned(),
            })?;
        match actor
            .ask(SubjectRegisterMessage::HasSubject { subject_id })
            .await?
        {
            SubjectRegisterResponse::SubjectPresent(present) => Ok(present),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_register".to_owned(),
                expected: "SubjectPresent".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: delete a subject register entry, simulating a
    /// crash cut that lost the derived write while later markers
    /// persisted. The next dirty boot must replay it from the ledger.
    pub async fn test_delete_subject_register_entry(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<(), Error> {
        use crate::governance::subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        };
        let actor = self
            .system
            .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/subject_register"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject register".to_owned(),
                reason: "Subject register not found".to_owned(),
            })?;
        match actor
            .ask(SubjectRegisterMessage::DeleteSubject { subject_id })
            .await?
        {
            SubjectRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: move both ownership projections to one owner,
    /// leaving the tracker ledger and its markers untouched. Used to
    /// plant a crash cut where Create/Confirm-derived state stayed
    /// behind a later fact.
    pub async fn test_move_ownership_projection(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
        owner: PublicKey,
        schema_id: ave_common::SchemaType,
        namespace: String,
        gov_version: u64,
    ) -> Result<(), Error> {
        use crate::governance::subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        };
        let data = match self.node.ask(NodeMessage::GetSubjectData(subject_id.clone())).await? {
            NodeResponse::SubjectData(Some(data)) => data,
            NodeResponse::SubjectData(None) => {
                return Err(Error::MissingResource {
                    name: "subject".to_owned(),
                    reason: "Subject is not registered in node".to_owned(),
                });
            }
            _ => {
                return Err(Error::UnexpectedResponse {
                    actor: "node".to_owned(),
                    expected: "SubjectData".to_owned(),
                    received: "other".to_owned(),
                });
            }
        };
        match self
            .node
            .ask(NodeMessage::DeleteSubject(subject_id.clone()))
            .await?
        {
            NodeResponse::Ok => {}
            _ => {
                return Err(Error::UnexpectedResponse {
                    actor: "node".to_owned(),
                    expected: "Ok".to_owned(),
                    received: "other".to_owned(),
                });
            }
        }
        match self
            .node
            .ask(NodeMessage::RegisterSubject {
                owner: owner.clone(),
                subject_id: subject_id.clone(),
                data,
            })
            .await?
        {
            NodeResponse::Ok => {}
            _ => {
                return Err(Error::UnexpectedResponse {
                    actor: "node".to_owned(),
                    expected: "Ok".to_owned(),
                    received: "other".to_owned(),
                });
            }
        }
        let actor = self
            .system
            .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/subject_register"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject register".to_owned(),
                reason: "Subject register not found".to_owned(),
            })?;
        match actor
            .ask(SubjectRegisterMessage::UpdateSubject {
                new_owner: owner.clone(),
                old_owner: owner,
                subject_id,
                namespace,
                schema_id,
                gov_version,
            })
            .await?
        {
            SubjectRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: read node ownership/pending state and whether the
    /// subject register contains the subject under the expected owner.
    pub async fn test_ownership_projection(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
        owner: PublicKey,
        schema_id: ave_common::SchemaType,
        namespace: String,
    ) -> Result<(bool, Option<bool>, bool), Error> {
        use crate::governance::subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        };
        let (node_owner, node_pending) = match self
            .node
            .ask(NodeMessage::IOwnerNewOwnerSubject(subject_id.clone()))
            .await?
        {
            NodeResponse::IOwnerNewOwner {
                i_owner,
                i_new_owner,
            } => (i_owner, i_new_owner),
            _ => {
                return Err(Error::UnexpectedResponse {
                    actor: "node".to_owned(),
                    expected: "IOwnerNewOwner".to_owned(),
                    received: "other".to_owned(),
                });
            }
        };
        let actor = self
            .system
            .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/subject_register"
            )))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject register".to_owned(),
                reason: "Subject register not found".to_owned(),
            })?;
        match actor
            .ask(SubjectRegisterMessage::GetSubjectsByOwnerSchemaBatch {
                queries: vec![(owner, schema_id, namespace)],
            })
            .await?
        {
            SubjectRegisterResponse::SubjectsBatch(entries) => Ok((
                node_owner,
                node_pending,
                entries.first().is_some_and(|subjects| {
                    subjects.contains(&subject_id)
                }),
            )),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_register".to_owned(),
                expected: "SubjectsBatch".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: ensure the per-subject distributor actor
    /// exists without touching any subject state. Lets a test park
    /// a first copy on its own worker while another worker applies
    /// the concurrent valid copy. Idempotent.
    pub async fn test_ensure_distributor(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(), Error> {
        let response = self
            .node
            .ask(NodeMessage::EnsureDistributor {
                subject_id: subject_id.clone(),
            })
            .await
            .map_err(|e| {
                warn!(
                    msg_type = "ApiRequest",
                    error = %e,
                    "Failed to ensure subject distributor"
                );
                actor_communication_error("node", e)
            })?;
        match response {
            NodeResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "node".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Whether the subject currently has live requesters: a stale
    /// rollback must only be evaluated once nobody is using it.
    pub async fn test_has_live_requesters(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<bool, Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::HasLiveRequesters { subject_id })
            .await?
        {
            SubjectManagerResponse::HasLiveRequesters(live) => Ok(live),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "HasLiveRequesters".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: live requester ids for one subject, sorted. Lets
    /// tests prove duplicate attempts own independent leases
    /// instead of sharing (and double-closing) one entry.
    pub async fn test_list_requesters(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<Vec<String>, Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::ListRequesters { subject_id })
            .await?
        {
            SubjectManagerResponse::Requesters(requesters) => Ok(requesters),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "Requesters".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: the last boot reconcile report for one tracker
    /// subject, as (events walked, derived writes re-sent). Lets a
    /// regression test pin the exact replay size instead of
    /// inferring it from converged state.
    pub async fn test_tracker_reconcile_report(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(u64, u64), Error> {
        let stats = self
            .system
            .get_helper::<crate::tracker::reconcile::SharedReconcileStats>(
                "reconcile_stats",
            )
            .ok_or_else(|| Error::MissingResource {
                name: "reconcile_stats".to_owned(),
                reason: "Reconcile stats helper not found".to_owned(),
            })?;
        Ok(stats
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .snapshot(&subject_id))
    }

    /// Test-only: how many subjects hold a success record right
    /// now. Finished copies must leave this at zero instead of
    /// leaking one entry per historical subject.
    pub async fn test_last_success_len(&self) -> Result<usize, Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor.ask(SubjectManagerMessage::GetLastSuccessLen).await? {
            SubjectManagerResponse::LastSuccessLen(len) => Ok(len),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "LastSuccessLen".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: how many copy attempts are in flight right now.
    /// Successful and failed paths alike must close theirs.
    pub async fn test_active_attempts_len(&self) -> Result<usize, Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::GetActiveAttemptsLen)
            .await?
        {
            SubjectManagerResponse::ActiveAttemptsLen(len) => Ok(len),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "ActiveAttemptsLen".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: hold a subject requester directly, so a rollback
    /// can be proven to back off on live requesters. Release with
    /// `test_release_requester`.
    pub async fn test_hold_requester(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::Up {
                subject_id,
                requester: "test-hold".to_owned(),
                create_ledger: None,
            })
            .await?
        {
            SubjectManagerResponse::Up => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "Up".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Test-only: release the requester held by
    /// `test_hold_requester`.
    pub async fn test_release_requester(
        &self,
        subject_id: DigestIdentifier,
    ) -> Result<(), Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::Finish {
                subject_id,
                requester: "test-hold".to_owned(),
            })
            .await?
        {
            SubjectManagerResponse::Finish => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "Finish".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Read-only attempt-ownership check: whether a rollback with
    /// this attempt id would purge the subject now. Used to pin
    /// that a stale attempt is declined while a valid copy stands.
    pub async fn test_should_purge(
        &self,
        subject_id: DigestIdentifier,
        attempt: u64,
    ) -> Result<bool, Error> {
        let actor = self
            .system
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "subject_manager".to_owned(),
                reason: "Subject manager not found".to_owned(),
            })?;
        match actor
            .ask(SubjectManagerMessage::ShouldPurge {
                subject_id,
                attempt,
            })
            .await?
        {
            SubjectManagerResponse::ShouldPurge(owned) => Ok(owned),
            _ => Err(Error::UnexpectedResponse {
                actor: "subject_manager".to_owned(),
                expected: "ShouldPurge".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    async fn test_arm_modes_fault(&self, empty: bool) -> Result<(), Error> {
        use crate::distribution::worker::{DistriWorker, DistriWorkerMessage};
        // Test deliveries address the node-level distributor, so the
        // fault lives there: one flag per worker, consumed once.
        let actor = self
            .system
            .get_actor::<DistriWorker>(&ActorPath::from(
                "/user/node/distributor",
            ))
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Distributor actor not found".to_owned(),
            })?;
        actor
            .tell(DistriWorkerMessage::TestFailNextModes { empty })
            .await
            .map_err(|_| Error::MissingResource {
                name: "distributor".to_owned(),
                reason: "Failed to arm modes fault".to_owned(),
            })
    }

    /// Tells a test-crafted approval vote directly to a validator
    /// worker's mailbox, bypassing the network: once this returns the
    /// message is queued, so anything the worker receives afterwards
    /// is processed after it. Fails if the worker does not exist.
    pub async fn test_tell_approval_vote(
        &self,
        worker_actor: &str,
        vote: Signed<crate::approval::response::ApprovalRes>,
        request_id: &str,
        version: u64,
        from: PublicKey,
    ) -> Result<(), Error> {
        let worker = self
            .system
            .get_actor::<crate::validation::worker::ValiWorker>(
                &ActorPath::from(worker_actor),
            )
            .await?;
        worker
            .tell(
                crate::validation::worker::ValiWorkerMessage::ApprovalResponse {
                    approval_res: Box::new(vote),
                    request_id: request_id.to_owned(),
                    version,
                    sender: from,
                },
            )
            .await?;
        Ok(())
    }

    /// Delivers a test-crafted message to this node as if it came from
    /// `from` over the network.
    pub async fn test_inject_inbound(
        &self,
        message: NetworkMessage,
        from: &PublicKey,
    ) -> Result<(), Error> {
        let faults = self.test_faults()?;
        let control = {
            let faults = faults
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            faults.inbound_sender()
        };
        let command =
            helpers::network::test_faults::TestFaultRegistry::inject_command(
                message, from,
            )
            .map_err(Error::Network)?;
        control
            .send(command)
            .await
            .map_err(|e| Error::Network(e.to_string()))
    }

    /// Whether the contract module is currently resident in memory
    /// (the `contracts` map).
    pub async fn test_has_contract_module(&self, contract_name: &str) -> bool {
        let Some(contracts) = self.system.get_helper::<Arc<
            tokio::sync::RwLock<
                HashMap<String, Arc<ave_contract_sdk::runtime::CompiledModule>>,
            >,
        >>("contracts") else {
            return false;
        };
        contracts.read().await.contains_key(contract_name)
    }

    /// Snapshot of the fetch state machine of a contract, if the node
    /// has any fetch observability recorded for it.
    pub async fn test_fetch_obs(
        &self,
        contract_name: &str,
    ) -> Option<compilation::contract_compiler::FetchObs> {
        let obs = self
            .system
            .get_helper::<compilation::contract_compiler::SharedFetchObs>(
                "test_fetch_obs",
            )?;
        let obs = obs.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        obs.get(contract_name).cloned()
    }

    /// Full ledger event of a governance at `sn`, exposing the anchored
    /// phase evidence (evaluation, approval and validation data) for
    /// test assertions.
    pub async fn test_get_ledger_event(
        &self,
        subject_id: DigestIdentifier,
        sn: u64,
    ) -> Result<crate::model::event::Ledger, Error> {
        let actor: ActorRef<crate::governance::Governance> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{subject_id}"
            )))
            .await?;
        let response = actor
            .ask(crate::governance::GovernanceMessage::GetLedger {
                lo_sn: sn.checked_sub(1),
                hi_sn: sn,
            })
            .await?;
        match response {
            crate::governance::GovernanceResponse::Ledger {
                ledger, ..
            } => ledger.into_iter().find(|event| event.sn == sn).ok_or(
                Error::EventNotFound {
                    subject: subject_id.to_string(),
                    sn,
                },
            ),
            _ => Err(Error::UnexpectedResponse {
                actor: "governance".to_owned(),
                expected: "Ledger".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Full ledger events of a tracker up to `hi_sn`, for test
    /// assertions and forged-message fixtures.
    pub async fn test_get_tracker_ledger(
        &self,
        subject_id: DigestIdentifier,
        hi_sn: u64,
    ) -> Result<Vec<crate::model::event::Ledger>, Error> {
        use crate::node::subject_manager::SubjectManagerMessage;
        // Trackers stop when no requester holds them: lift explicitly,
        // read, then release, mirroring the lease pattern.
        self.subject_manager
            .ask(SubjectManagerMessage::Up {
                subject_id: subject_id.clone(),
                requester: "test-read".to_owned(),
                create_ledger: None,
            })
            .await?;
        let actor: ActorRef<crate::tracker::Tracker> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{subject_id}"
            )))
            .await?;
        let response = actor
            .ask(crate::tracker::TrackerMessage::GetLedger {
                lo_sn: None,
                hi_sn,
            })
            .await?;
        let _ = self
            .subject_manager
            .ask(SubjectManagerMessage::Finish {
                subject_id: subject_id.clone(),
                requester: "test-read".to_owned(),
            })
            .await;
        match response {
            crate::tracker::TrackerResponse::Ledger { ledger, .. } => {
                Ok(ledger)
            }
            _ => Err(Error::UnexpectedResponse {
                actor: "tracker".to_owned(),
                expected: "Ledger".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Purges one governance register store, for crash-recovery
    /// tests: wiping derived state is strictly worse than any crash
    /// window, so healing from a purge proves healing from a crash.
    /// `register` is one of: role, subject, witnesses, sn, contract,
    /// transfer_verification.
    pub async fn test_purge_register(
        &self,
        governance_id: DigestIdentifier,
        register: &str,
    ) -> Result<(), Error> {
        use ave_actors::ActorPath;
        let base = format!("/user/node/subject_manager/{governance_id}");
        match register {
            "role" => {
                use crate::governance::role_register::{
                    RoleRegister, RoleRegisterMessage,
                };
                let actor: ActorRef<RoleRegister> = self
                    .system
                    .get_actor(&ActorPath::from(format!(
                        "{base}/role_register"
                    )))
                    .await?;
                actor.ask(RoleRegisterMessage::PurgeStorage).await.map_err(
                    |e| actor_communication_error("role_register", e),
                )?;
            }
            "subject" => {
                use crate::governance::subject_register::{
                    SubjectRegister, SubjectRegisterMessage,
                };
                let actor: ActorRef<SubjectRegister> = self
                    .system
                    .get_actor(&ActorPath::from(format!(
                        "{base}/subject_register"
                    )))
                    .await?;
                actor
                    .ask(SubjectRegisterMessage::PurgeStorage)
                    .await
                    .map_err(|e| {
                        actor_communication_error("subject_register", e)
                    })?;
            }
            "witnesses" => {
                use crate::governance::witnesses_register::{
                    WitnessesRegister, WitnessesRegisterMessage,
                };
                let actor: ActorRef<WitnessesRegister> = self
                    .system
                    .get_actor(&ActorPath::from(format!(
                        "{base}/witnesses_register"
                    )))
                    .await?;
                actor
                    .ask(WitnessesRegisterMessage::PurgeStorage)
                    .await
                    .map_err(|e| {
                        actor_communication_error("witnesses_register", e)
                    })?;
            }
            "sn" => {
                use crate::governance::sn_register::{
                    SnRegister, SnRegisterMessage,
                };
                let actor: ActorRef<SnRegister> = self
                    .system
                    .get_actor(&ActorPath::from(format!("{base}/sn_register")))
                    .await?;
                actor
                    .ask(SnRegisterMessage::PurgeStorage)
                    .await
                    .map_err(|e| actor_communication_error("sn_register", e))?;
            }
            "contract" => {
                use crate::governance::contract_register::{
                    ContractRegister, ContractRegisterMessage,
                };
                let actor: ActorRef<ContractRegister> = self
                    .system
                    .get_actor(&ActorPath::from(format!(
                        "{base}/contract_register"
                    )))
                    .await?;
                actor
                    .ask(ContractRegisterMessage::PurgeStorage)
                    .await
                    .map_err(|e| {
                        actor_communication_error("contract_register", e)
                    })?;
            }
            "transfer_verification" => {
                use crate::governance::transfer_verification_register::{
                    TransferVerificationRegister,
                    TransferVerificationRegisterMessage,
                };
                let actor: ActorRef<TransferVerificationRegister> = self
                    .system
                    .get_actor(&ActorPath::from(format!(
                        "{base}/transfer_verification_register"
                    )))
                    .await?;
                actor
                    .ask(TransferVerificationRegisterMessage::PurgeStorage)
                    .await
                    .map_err(|e| {
                        actor_communication_error(
                            "transfer_verification_register",
                            e,
                        )
                    })?;
            }
            other => {
                return Err(Error::UnexpectedResponse {
                    actor: "test_purge_register".to_string(),
                    expected: "known register name".to_string(),
                    received: other.to_string(),
                });
            }
        }
        Ok(())
    }

    /// Visibility ranges of a tracker as currently stored, for
    /// crash-recovery tests: boot reconcile must leave them ordered,
    /// non-overlapping and with `from_sn <= to_sn`. Returns
    /// `(stored, events)` with `(from_sn, to_sn, visibility)` tuples
    /// in stored order.
    pub async fn test_get_tracker_visibility(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<
        (
            Vec<(u64, Option<u64>, String)>,
            Vec<(u64, Option<u64>, String)>,
        ),
        Error,
    > {
        use crate::governance::witnesses_register::{
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        };
        let actor: ActorRef<WitnessesRegister> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/witnesses_register"
            )))
            .await?;
        let response = actor
            .ask(WitnessesRegisterMessage::GetTrackerVisibilityState {
                subject_id,
            })
            .await
            .map_err(|e| actor_communication_error("witnesses_register", e))?;
        match response {
            WitnessesRegisterResponse::TrackerVisibilityState { state } => {
                Ok((
                    state
                        .stored_ranges
                        .iter()
                        .map(|range| {
                            (
                                range.from_sn,
                                range.to_sn,
                                format!("{:?}", range.visibility),
                            )
                        })
                        .collect(),
                    state
                        .event_ranges
                        .iter()
                        .map(|range| {
                            (
                                range.from_sn,
                                range.to_sn,
                                format!("{:?}", range.visibility),
                            )
                        })
                        .collect(),
                ))
            }
            _ => Err(Error::UnexpectedResponse {
                actor: "witnesses_register".to_owned(),
                expected: "TrackerVisibilityState".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Gov-version windows of a tracker as currently stored, for
    /// crash-recovery tests: boot reconcile must rewrite the same
    /// boundaries the live path wrote. Returns
    /// `(from_sn, to_sn, gov_version)` ranges in order.
    pub async fn test_get_gov_version_window(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
        from_sn: u64,
        to_sn: u64,
    ) -> Result<Vec<(u64, u64, u64)>, Error> {
        use crate::governance::sn_register::{
            SnRegister, SnRegisterMessage, SnRegisterResponse,
        };
        let actor: ActorRef<SnRegister> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/sn_register"
            )))
            .await?;
        let response = actor
            .ask(SnRegisterMessage::GetGovVersionWindow {
                subject_id,
                from_sn,
                to_sn,
            })
            .await
            .map_err(|e| actor_communication_error("sn_register", e))?;
        match response {
            SnRegisterResponse::GovVersionWindow(ranges) => Ok(ranges
                .into_iter()
                .map(|range| (range.from_sn, range.to_sn, range.gov_version))
                .collect()),
            _ => Err(Error::UnexpectedResponse {
                actor: "sn_register".to_owned(),
                expected: "GovVersionWindow".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Deletes a single subject entry from the sn register, simulating
    /// a register that lags behind the ledger (independent tells, no
    /// barrier). The ledger, grants and other registers are untouched.
    pub async fn test_delete_sn_subject(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
    ) -> Result<(), Error> {
        use crate::governance::sn_register::{
            SnRegister, SnRegisterMessage, SnRegisterResponse,
        };
        let actor: ActorRef<SnRegister> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/sn_register"
            )))
            .await?;
        let response = actor
            .ask(SnRegisterMessage::DeleteSubject { subject_id })
            .await
            .map_err(|e| actor_communication_error("sn_register", e))?;
        match response {
            SnRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "sn_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Batch sn lookups for one subject, in input-version order, so a
    /// test can pin `NotSn` against a live ledger without guessing.
    pub async fn test_get_sns(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
        gov_versions: Vec<u64>,
    ) -> Result<Vec<crate::governance::sn_register::SnLimit>, Error> {
        use crate::governance::sn_register::{
            SnRegister, SnRegisterMessage, SnRegisterResponse,
        };
        let actor: ActorRef<SnRegister> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/sn_register"
            )))
            .await?;
        let response = actor
            .ask(SnRegisterMessage::GetSns {
                subject_id,
                gov_versions,
            })
            .await
            .map_err(|e| actor_communication_error("sn_register", e))?;
        match response {
            SnRegisterResponse::Sns(results) => Ok(results),
            _ => Err(Error::UnexpectedResponse {
                actor: "sn_register".to_owned(),
                expected: "Sns".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Restores one exact sn mapping, so a test can rebuild the real
    /// register state after wiping it. No version is invented here:
    /// callers re-register pairs they read before the wipe.
    pub async fn test_register_sn(
        &self,
        governance_id: DigestIdentifier,
        subject_id: DigestIdentifier,
        gov_version: u64,
        sn: u64,
    ) -> Result<(), Error> {
        use crate::governance::sn_register::{
            SnRegister, SnRegisterMessage, SnRegisterResponse,
        };
        let actor: ActorRef<SnRegister> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/sn_register"
            )))
            .await?;
        let response = actor
            .ask(SnRegisterMessage::RegisterSn {
                subject_id,
                gov_version,
                sn,
            })
            .await
            .map_err(|e| actor_communication_error("sn_register", e))?;
        match response {
            SnRegisterResponse::Ok => Ok(()),
            _ => Err(Error::UnexpectedResponse {
                actor: "sn_register".to_owned(),
                expected: "Ok".to_owned(),
                received: "other".to_owned(),
            }),
        }
    }

    /// Governance-schema evaluator keys in the role register, for
    /// test assertions on what UpdateLedger applied.
    pub async fn test_gov_evaluators(
        &self,
        governance_id: DigestIdentifier,
    ) -> Result<Vec<PublicKey>, Error> {
        use crate::governance::role_register::{
            RoleRegister, RoleRegisterMessage, RoleRegisterResponse, SearchRole,
        };
        use ave_common::{Namespace, SchemaType};
        let actor: ActorRef<RoleRegister> = self
            .system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{governance_id}/role_register"
            )))
            .await?;
        let version = match actor
            .ask(RoleRegisterMessage::GetVersion)
            .await
            .map_err(|e| actor_communication_error("role_register", e))?
        {
            RoleRegisterResponse::Version(version) => version,
            _ => {
                return Err(Error::UnexpectedResponse {
                    actor: "role_register".to_string(),
                    expected: "Version".to_string(),
                    received: "other".to_string(),
                });
            }
        };
        let response = actor
            .ask(RoleRegisterMessage::SearchActualRoles {
                version,
                evaluation: SearchRole {
                    schema_id: SchemaType::Governance,
                    namespace: Namespace::new(),
                },
                approval: false,
                compilation: false,
            })
            .await
            .map_err(|e| actor_communication_error("role_register", e))?;
        match response {
            RoleRegisterResponse::ActualRoles { evaluation, .. } => {
                Ok(evaluation.workers.into_iter().collect())
            }
            _ => Err(Error::UnexpectedResponse {
                actor: "role_register".to_string(),
                expected: "ActualRoles".to_string(),
                received: "other".to_string(),
            }),
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
            servers: vec![server],
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
            servers: vec![server],
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
            transport: None,
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
            transport: None,
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
