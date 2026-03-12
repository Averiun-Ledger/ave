use std::{collections::HashSet, sync::Arc};

use crate::{
    auth::{
        AuthDatabase, admin_handlers, apikey_handlers, login_handler,
        middleware::{ApiKeyAuthNew, audit_log_middleware, check_permission},
        models::{AuthContext, ErrorResponse},
        system_handlers,
    },
    config_types::ConfigHttp,
    error::HttpError,
};

use ave_bridge::ave_common::{
    bridge::request::{
        AbortsQuery, ApprovalQuery, BridgeSignedEventRequest, EventsQuery,
        FirstEndEvents, GovQuery, SubjectQuery,
    },
    response::{ApprovalEntry, RequestData, RequestInfoExtend},
};
use ave_bridge::{
    Bridge, MonitorNetworkState,
    ave_common::{
        bridge::request::ApprovalStateRes,
        response::{
            GovsData, LedgerDB, PaginatorAborts, PaginatorEvents, RequestInfo,
            RequestsInManager, RequestsInManagerSubject, SubjectDB, SubjsData,
            TransferSubject,
        },
    },
    http::ProxyConfig,
};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{FromRequestParts, Path, Query},
    http::{Request, StatusCode},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use serde_qs::axum::QsQuery;
use tower::ServiceBuilder;

use crate::doc::ApiDoc;
use axum::http::Method;
use utoipa::OpenApi;
use utoipa_swagger_ui::SwaggerUi;

///////// General
////////////////////////////

/// Get peer ID
///
/// Returns the libp2p peer identifier of this node.
#[utoipa::path(
    get,
    path = "/peer-id",
    operation_id = "getPeerId",
    tag = "Node",
    responses(
        (status = 200, description = "The libp2p peer ID of this node", body = String),
    ),
    security(("api_key" = []))
)]
pub async fn get_peer_id(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Json<String> {
    Json(bridge.get_peer_id().to_string())
}

/// Get public key
///
/// Returns the cryptographic public key of this node.
#[utoipa::path(
    get,
    path = "/public-key",
    operation_id = "getPublicKey",
    tag = "Node",
    responses(
        (status = 200, description = "The public key of this node", body = String),
    ),
    security(("api_key" = []))
)]
pub async fn get_public_key(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Json<String> {
    Json(bridge.get_public_key().to_string())
}

/// Get node configuration
///
/// Returns the current configuration of the node.
#[utoipa::path(
    get,
    path = "/config",
    operation_id = "getConfig",
    tag = "Node",
    responses(
        (status = 200, description = "Current node configuration", body = ConfigHttp),
    ),
    security(("api_key" = []))
)]
pub async fn get_config(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Json<ConfigHttp> {
    Json(ConfigHttp::from(bridge.get_config()))
}

///////// Network
////////////////////////////

/// Get network state
///
/// Returns the current state of the P2P network connections.
#[utoipa::path(
    get,
    path = "/network-state",
    operation_id = "getNetworkState",
    tag = "Node",
    responses(
        (status = 200, description = "Current network state", body = MonitorNetworkState),
        (status = 502, description = "Network error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_network_state(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<MonitorNetworkState>, HttpError> {
    Ok(Json(bridge.get_network_state().await?))
}

///////// Request
////////////////////////////

/// Get all requests in manager
///
/// Returns all event requests currently being processed by the request manager.
#[utoipa::path(
    get,
    path = "/requests-in-manager",
    operation_id = "getRequestsInManager",
    tag = "Request",
    responses(
        (status = 200, description = "All requests currently being managed", body = RequestsInManager),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_requests_in_manager(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<RequestsInManager>, HttpError> {
    Ok(Json(bridge.get_requests_in_manager().await?))
}

/// Get requests in manager by subject
///
/// Returns event requests for a specific subject currently being processed.
#[utoipa::path(
    get,
    path = "/requests-in-manager/{subject_id}",
    operation_id = "getRequestsInManagerBySubject",
    tag = "Request",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Requests for the specified subject", body = RequestsInManagerSubject),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_requests_in_manager_subject_id(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<RequestsInManagerSubject>, HttpError> {
    Ok(Json(
        bridge
            .get_requests_in_manager_subject_id(subject_id)
            .await?,
    ))
}

/// Submit an event request
///
/// Submits a signed event request to the ledger. Supports create, fact, transfer,
/// confirm, reject, and EOL event types.
#[utoipa::path(
    post,
    path = "/request",
    operation_id = "postEventRequest",
    tag = "Request",
    request_body = BridgeSignedEventRequest,
    responses(
        (status = 200, description = "Event request accepted", body = RequestData),
        (status = 400, description = "Invalid event request", body = ErrorResponse),
        (status = 409, description = "Conflict with current state", body = ErrorResponse),
        (status = 422, description = "Validation failed", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn post_event_request(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Json(request): Json<BridgeSignedEventRequest>,
) -> Result<Json<RequestData>, HttpError> {
    Ok(Json(bridge.post_event_request(request).await?))
}

/// Get approval for a subject
///
/// Returns the pending approval request for a specific subject, optionally filtered by state.
#[utoipa::path(
    get,
    path = "/approval/{subject_id}",
    operation_id = "getApproval",
    tag = "Approval",
    params(
        ("subject_id" = String, Path, description = "Subject identifier"),
        ApprovalQuery
    ),
    responses(
        (status = 200, description = "Approval details for the subject", body = Option<ApprovalEntry>),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Approval not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_approval(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Query(parameters): Query<ApprovalQuery>,
) -> Result<Json<Option<ApprovalEntry>>, HttpError> {
    Ok(Json(
        bridge.get_approval(subject_id, parameters.state).await?,
    ))
}

/// List all approvals
///
/// Returns all pending approval requests, optionally filtered by state.
#[utoipa::path(
    get,
    path = "/approval",
    operation_id = "getApprovals",
    tag = "Approval",
    params(ApprovalQuery),
    responses(
        (status = 200, description = "List of all approvals", body = Vec<ApprovalEntry>),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_approvals(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Query(parameters): Query<ApprovalQuery>,
) -> Result<Json<Vec<ApprovalEntry>>, HttpError> {
    Ok(Json(bridge.get_approvals(parameters.state).await?))
}

/// Update approval state
///
/// Approves or rejects a pending approval for the specified subject.
#[utoipa::path(
    patch,
    path = "/approval/{subject_id}",
    operation_id = "patchApproval",
    tag = "Approval",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    request_body = ApprovalStateRes,
    responses(
        (status = 200, description = "Approval state updated", body = String),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Approval not found", body = ErrorResponse),
        (status = 409, description = "Invalid approval state transition", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn patch_approve(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Json(state): Json<ApprovalStateRes>,
) -> Result<Json<String>, HttpError> {
    Ok(Json(bridge.patch_approve(subject_id, state).await?))
}

/// Abort a pending request
///
/// Manually aborts a pending event request for the specified subject.
#[utoipa::path(
    post,
    path = "/request-abort/{subject_id}",
    operation_id = "postManualRequestAbort",
    tag = "Approval",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Request aborted successfully", body = String),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn post_manual_request_abort(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, HttpError> {
    Ok(Json(bridge.post_manual_request_abort(subject_id).await?))
}

///////// Tracking
////////////////////////////

/// Get request state
///
/// Returns the current lifecycle state of a specific event request.
#[utoipa::path(
    get,
    path = "/request/{request_id}",
    operation_id = "getRequestState",
    tag = "Tracking",
    params(
        ("request_id" = String, Path, description = "Request identifier")
    ),
    responses(
        (status = 200, description = "Current state of the request", body = RequestInfo),
        (status = 400, description = "Invalid request ID", body = ErrorResponse),
        (status = 404, description = "Request not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_request_state(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(request_id): Path<String>,
) -> Result<Json<RequestInfo>, HttpError> {
    Ok(Json(bridge.get_request_state(request_id).await?))
}

/// List all request states
///
/// Returns the lifecycle state of all tracked event requests.
#[utoipa::path(
    get,
    path = "/request",
    operation_id = "getAllRequestStates",
    tag = "Tracking",
    responses(
        (status = 200, description = "All tracked request states", body = Vec<RequestInfoExtend>),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_all_request_state(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<Vec<RequestInfoExtend>>, HttpError> {
    Ok(Json(bridge.get_all_request_state().await?))
}
///////// Node
////////////////////////////

/// Get pending transfers
///
/// Returns all subjects with pending ownership transfers.
#[utoipa::path(
    get,
    path = "/pending-transfers",
    operation_id = "getPendingTransfers",
    tag = "Transfer",
    responses(
        (status = 200, description = "List of pending transfers", body = Vec<TransferSubject>),
        (status = 404, description = "No pending transfers", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_pending_transfers(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<Vec<TransferSubject>>, HttpError> {
    Ok(Json(bridge.get_pending_transfers().await?))
}

///////// Auth
////////////////////////////

/// Set witnesses for a subject
///
/// Configures the witness public keys authorized to approve events for the specified subject.
#[utoipa::path(
    put,
    path = "/auth/{subject_id}",
    operation_id = "putAuthSubject",
    tag = "Authorization",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    request_body = Vec<String>,
    responses(
        (status = 200, description = "Witnesses set for subject", body = String),
        (status = 400, description = "Invalid subject ID or public key", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn put_auth_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Json(witnesses): Json<Vec<String>>,
) -> Result<Json<String>, HttpError> {
    Ok(Json(bridge.put_auth_subject(subject_id, witnesses).await?))
}

/// List all authorized subjects
///
/// Returns the IDs of all subjects with authorization rules configured.
#[utoipa::path(
    get,
    path = "/auth",
    operation_id = "getAllAuthSubjects",
    tag = "Authorization",
    responses(
        (status = 200, description = "List of subject IDs with authorization rules", body = Vec<String>),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_all_auth_subjects(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<Vec<String>>, HttpError> {
    Ok(Json(bridge.get_all_auth_subjects().await?))
}

/// Get witnesses for a subject
///
/// Returns the set of witness public keys configured for the specified subject.
#[utoipa::path(
    get,
    path = "/auth/{subject_id}",
    operation_id = "getWitnessesSubject",
    tag = "Authorization",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Set of witness public keys", body = Vec<String>),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Witnesses not found for subject", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_witnesses_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<HashSet<String>>, HttpError> {
    Ok(Json(bridge.get_witnesses_subject(subject_id).await?))
}

/// Delete authorization for a subject
///
/// Removes all authorization rules for the specified subject.
#[utoipa::path(
    delete,
    path = "/auth/{subject_id}",
    operation_id = "deleteAuthSubject",
    tag = "Authorization",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Authorization rules deleted", body = String),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn delete_auth_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, HttpError> {
    Ok(Json(bridge.delete_auth_subject(subject_id).await?))
}

/// Trigger subject update
///
/// Triggers a manual synchronization update for the specified subject.
#[utoipa::path(
    post,
    path = "/update/{subject_id}",
    operation_id = "postUpdateSubject",
    tag = "Authorization",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Subject update triggered", body = String),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn post_update_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, HttpError> {
    Ok(Json(bridge.post_update_subject(subject_id).await?))
}

///////// manual distribution
////////////////////////////

/// Trigger manual distribution
///
/// Manually triggers event distribution to network peers for the specified subject.
#[utoipa::path(
    post,
    path = "/manual-distribution/{subject_id}",
    operation_id = "postManualDistribution",
    tag = "Distribution",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Manual distribution triggered", body = String),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn post_manual_distribution(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, HttpError> {
    Ok(Json(bridge.post_manual_distribution(subject_id).await?))
}

///////// Register
////////////////////////////

/// List all governances
///
/// Returns all governance structures, optionally filtered by active status.
#[utoipa::path(
    get,
    path = "/subjects",
    operation_id = "getAllGovs",
    tag = "Register",
    params(GovQuery),
    responses(
        (status = 200, description = "List of governances", body = Vec<GovsData>),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_all_govs(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Query(parameters): Query<GovQuery>,
) -> Result<Json<Vec<GovsData>>, HttpError> {
    Ok(Json(bridge.get_all_govs(parameters.active).await?))
}

/// List subjects under a governance
///
/// Returns all subjects belonging to the specified governance, optionally
/// filtered by active status and schema ID.
#[utoipa::path(
    get,
    path = "/subjects/{governance_id}",
    operation_id = "getAllSubjs",
    tag = "Register",
    params(
        ("governance_id" = String, Path, description = "Governance identifier"),
        SubjectQuery
    ),
    responses(
        (status = 200, description = "List of subjects under the governance", body = Vec<SubjsData>),
        (status = 400, description = "Invalid governance ID", body = ErrorResponse),
        (status = 404, description = "Governance not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_all_subjs(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(governance_id): Path<String>,
    Query(parameters): Query<SubjectQuery>,
) -> Result<Json<Vec<SubjsData>>, HttpError> {
    Ok(Json(
        bridge
            .get_all_subjs(
                governance_id,
                parameters.active,
                parameters.schema_id,
            )
            .await?,
    ))
}

///////// Query
////////////////////////////

/// Get events for a subject
///
/// Returns a paginated list of events for the specified subject with optional
/// time range filters.
#[utoipa::path(
    get,
    path = "/events/{subject_id}",
    operation_id = "getEvents",
    tag = "Ledger",
    params(
        ("subject_id" = String, Path, description = "Subject identifier"),
        EventsQuery
    ),
    responses(
        (status = 200, description = "Paginated list of events", body = PaginatorEvents),
        (status = 400, description = "Invalid subject ID or query params", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_events(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    QsQuery(parameters): QsQuery<EventsQuery>,
) -> Result<Json<PaginatorEvents>, HttpError> {
    Ok(Json(bridge.get_events(subject_id, parameters).await?))
}

/// Get aborts for a subject
///
/// Returns a paginated list of aborted events for the specified subject.
#[utoipa::path(
    get,
    path = "/aborts/{subject_id}",
    operation_id = "getAborts",
    tag = "Ledger",
    params(
        ("subject_id" = String, Path, description = "Subject identifier"),
        AbortsQuery
    ),
    responses(
        (status = 200, description = "Paginated list of aborted events", body = PaginatorAborts),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_aborts(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Query(parameters): Query<AbortsQuery>,
) -> Result<Json<PaginatorAborts>, HttpError> {
    Ok(Json(bridge.get_aborts(subject_id, parameters).await?))
}

/// Get event by sequence number
///
/// Returns a specific event by its sequence number within a subject's ledger.
#[utoipa::path(
    get,
    path = "/events/{subject_id}/{sn}",
    operation_id = "getEventSn",
    tag = "Ledger",
    params(
        ("subject_id" = String, Path, description = "Subject identifier"),
        ("sn" = u64, Path, description = "Event sequence number")
    ),
    responses(
        (status = 200, description = "Event at the given sequence number", body = LedgerDB),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Event not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_event_sn(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path((subject_id, sn)): Path<(String, u64)>,
) -> Result<Json<LedgerDB>, HttpError> {
    Ok(Json(bridge.get_event_sn(subject_id, sn).await?))
}

/// Get first or last events
///
/// Returns the first or last events for a subject, useful for finding the
/// genesis event or the latest events.
#[utoipa::path(
    get,
    path = "/events-first-last/{subject_id}",
    operation_id = "getFirstOrEndEvents",
    tag = "Ledger",
    params(
        ("subject_id" = String, Path, description = "Subject identifier"),
        FirstEndEvents
    ),
    responses(
        (status = 200, description = "First and/or last events for the subject", body = Vec<LedgerDB>),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found or no events", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_first_or_end_events(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Query(parameters): Query<FirstEndEvents>,
) -> Result<Json<Vec<LedgerDB>>, HttpError> {
    Ok(Json(
        bridge
            .get_first_or_end_events(
                subject_id,
                parameters.quantity,
                parameters.reverse,
                parameters.event_type,
            )
            .await?,
    ))
}

/// Get subject state
///
/// Returns the current state of a subject including its metadata and properties.
#[utoipa::path(
    get,
    path = "/state/{subject_id}",
    operation_id = "getSubjectState",
    tag = "Ledger",
    params(
        ("subject_id" = String, Path, description = "Subject identifier")
    ),
    responses(
        (status = 200, description = "Current state of the subject", body = SubjectDB),
        (status = 400, description = "Invalid subject ID", body = ErrorResponse),
        (status = 404, description = "Subject not found", body = ErrorResponse),
        (status = 500, description = "Internal server error", body = ErrorResponse),
    ),
    security(("api_key" = []))
)]
pub async fn get_subject_state(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<SubjectDB>, HttpError> {
    Ok(Json(bridge.get_subject_state(subject_id).await?))
}

async fn audit_layer(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    let auth_ctx = req.extensions().get::<Arc<AuthContext>>().cloned();
    let db = req.extensions().get::<Arc<AuthDatabase>>().cloned();

    audit_log_middleware(auth_ctx, db, req, next).await
}

/// Resources recognized by the permission system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    User,
    NodeSystem,
    NodeSubject,
    NodeRequest,
    UserApiKey,
    NodeManagement,
}

impl Resource {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::NodeSystem => "node_system",
            Self::NodeSubject => "node_subject",
            Self::NodeRequest => "node_request",
            Self::UserApiKey => "user_api_key",
            Self::NodeManagement => "node_management",
        }
    }
}

/// Actions recognized by the permission system.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl Action {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "get",
            Self::Post => "post",
            Self::Put => "put",
            Self::Patch => "patch",
            Self::Delete => "delete",
        }
    }
}

/// Result of looking up a route's permission requirement.
pub enum PermissionResult {
    /// Route uses inline handler-level checks (admin routes). Allow through.
    AllowAny,
    /// Route requires the caller to hold the given resource + action.
    Require(Resource, Action),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RouteMethodSpec {
    Get,
    Post,
    Put,
    Patch,
    Delete,
}

impl RouteMethodSpec {
    fn matches(self, method: &Method) -> bool {
        match self {
            Self::Get => *method == Method::GET,
            Self::Post => *method == Method::POST,
            Self::Put => *method == Method::PUT,
            Self::Patch => *method == Method::PATCH,
            Self::Delete => *method == Method::DELETE,
        }
    }
}

fn path_matches_template(template: &str, path: &str) -> bool {
    let mut template_segments = template.split('/').filter(|segment| !segment.is_empty());
    let mut path_segments = path.split('/').filter(|segment| !segment.is_empty());

    loop {
        match (template_segments.next(), path_segments.next()) {
            (None, None) => return true,
            (Some(template_segment), Some(path_segment)) => {
                let is_param = template_segment.starts_with('{')
                    && template_segment.ends_with('}');
                if !is_param && template_segment != path_segment {
                    return false;
                }
            }
            _ => return false,
        }
    }
}

macro_rules! main_route_catalog {
    ($callback:ident, $($args:tt)*) => {
        $callback!($($args)*, get, "/peer-id", get_peer_id, require NodeSystem Get);
        $callback!($($args)*, get, "/public-key", get_public_key, require NodeSystem Get);
        $callback!($($args)*, get, "/config", get_config, require NodeManagement Get);
        $callback!($($args)*, get, "/network-state", get_network_state, require NodeSystem Get);
        $callback!($($args)*, get, "/requests-in-manager", get_requests_in_manager, require NodeRequest Get);
        $callback!($($args)*, get, "/requests-in-manager/{subject_id}", get_requests_in_manager_subject_id, require NodeRequest Get);
        $callback!($($args)*, get, "/approval", get_approvals, require NodeSubject Get);
        $callback!($($args)*, get, "/approval/{subject_id}", get_approval, require NodeSubject Get);
        $callback!($($args)*, patch, "/approval/{subject_id}", patch_approve, require NodeSubject Patch);
        $callback!($($args)*, post, "/request-abort/{subject_id}", post_manual_request_abort, require NodeSubject Post);
        $callback!($($args)*, post, "/request", post_event_request, require NodeRequest Post);
        $callback!($($args)*, get, "/request", get_all_request_state, require NodeRequest Get);
        $callback!($($args)*, get, "/request/{request_id}", get_request_state, require NodeRequest Get);
        $callback!($($args)*, get, "/pending-transfers", get_pending_transfers, require NodeSubject Get);
        $callback!($($args)*, get, "/auth", get_all_auth_subjects, require NodeSubject Get);
        $callback!($($args)*, put, "/auth/{subject_id}", put_auth_subject, require NodeSubject Put);
        $callback!($($args)*, get, "/auth/{subject_id}", get_witnesses_subject, require NodeSubject Get);
        $callback!($($args)*, delete, "/auth/{subject_id}", delete_auth_subject, require NodeSubject Delete);
        $callback!($($args)*, post, "/update/{subject_id}", post_update_subject, require NodeSubject Post);
        $callback!($($args)*, post, "/manual-distribution/{subject_id}", post_manual_distribution, require NodeSubject Post);
        $callback!($($args)*, get, "/subjects", get_all_govs, require NodeSubject Get);
        $callback!($($args)*, get, "/subjects/{governance_id}", get_all_subjs, require NodeSubject Get);
        $callback!($($args)*, get, "/events/{subject_id}", get_events, require NodeSubject Get);
        $callback!($($args)*, get, "/events/{subject_id}/{sn}", get_event_sn, require NodeSubject Get);
        $callback!($($args)*, get, "/aborts/{subject_id}", get_aborts, require NodeSubject Get);
        $callback!($($args)*, get, "/events-first-last/{subject_id}", get_first_or_end_events, require NodeSubject Get);
        $callback!($($args)*, get, "/state/{subject_id}", get_subject_state, require NodeSubject Get);
        $callback!($($args)*, external_get, "/metrics", metrics_endpoint, require NodeManagement Get);
    };
}

macro_rules! auth_route_catalog {
    ($callback:ident, $($args:tt)*) => {
        $callback!($($args)*, get, "/admin/users", admin_handlers::list_users, allow_any);
        $callback!($($args)*, post, "/admin/users", admin_handlers::create_user, allow_any);
        $callback!($($args)*, get, "/admin/users/{user_id}", admin_handlers::get_user, allow_any);
        $callback!($($args)*, put, "/admin/users/{user_id}", admin_handlers::update_user, allow_any);
        $callback!($($args)*, delete, "/admin/users/{user_id}", admin_handlers::delete_user, allow_any);
        $callback!($($args)*, post, "/admin/users/{user_id}/password", admin_handlers::reset_user_password, allow_any);
        $callback!($($args)*, post, "/admin/users/{user_id}/roles/{role_id}", admin_handlers::assign_role, allow_any);
        $callback!($($args)*, delete, "/admin/users/{user_id}/roles/{role_id}", admin_handlers::remove_role, allow_any);
        $callback!($($args)*, get, "/admin/users/{user_id}/permissions", admin_handlers::get_user_permissions, allow_any);
        $callback!($($args)*, post, "/admin/users/{user_id}/permissions", admin_handlers::set_user_permission, allow_any);
        $callback!($($args)*, delete, "/admin/users/{user_id}/permissions", admin_handlers::remove_user_permission, allow_any);
        $callback!($($args)*, get, "/admin/roles", admin_handlers::list_roles, allow_any);
        $callback!($($args)*, post, "/admin/roles", admin_handlers::create_role, allow_any);
        $callback!($($args)*, get, "/admin/roles/{role_id}", admin_handlers::get_role, allow_any);
        $callback!($($args)*, put, "/admin/roles/{role_id}", admin_handlers::update_role, allow_any);
        $callback!($($args)*, delete, "/admin/roles/{role_id}", admin_handlers::delete_role, allow_any);
        $callback!($($args)*, get, "/admin/roles/{role_id}/permissions", admin_handlers::get_role_permissions, allow_any);
        $callback!($($args)*, post, "/admin/roles/{role_id}/permissions", admin_handlers::set_role_permission, allow_any);
        $callback!($($args)*, delete, "/admin/roles/{role_id}/permissions", admin_handlers::remove_role_permission, allow_any);
        $callback!($($args)*, post, "/admin/api-keys/user/{user_id}", apikey_handlers::create_api_key_for_user, allow_any);
        $callback!($($args)*, get, "/admin/api-keys/user/{user_id}", apikey_handlers::list_user_api_keys_admin, allow_any);
        $callback!($($args)*, get, "/admin/api-keys", apikey_handlers::list_all_api_keys, allow_any);
        $callback!($($args)*, get, "/admin/api-keys/{key_id}", apikey_handlers::get_api_key, allow_any);
        $callback!($($args)*, delete, "/admin/api-keys/{key_id}", apikey_handlers::revoke_api_key, allow_any);
        $callback!($($args)*, post, "/admin/api-keys/{key_id}/rotate", apikey_handlers::rotate_api_key, allow_any);
        $callback!($($args)*, put, "/admin/api-keys/{key_id}/plan", apikey_handlers::assign_api_key_plan, allow_any);
        $callback!($($args)*, get, "/admin/api-keys/{key_id}/quota", apikey_handlers::get_api_key_quota_status, allow_any);
        $callback!($($args)*, post, "/admin/api-keys/{key_id}/quota-extensions", apikey_handlers::add_api_key_quota_extension, allow_any);
        $callback!($($args)*, get, "/admin/usage-plans", apikey_handlers::list_usage_plans, allow_any);
        $callback!($($args)*, post, "/admin/usage-plans", apikey_handlers::create_usage_plan, allow_any);
        $callback!($($args)*, get, "/admin/usage-plans/{plan_id}", apikey_handlers::get_usage_plan, allow_any);
        $callback!($($args)*, put, "/admin/usage-plans/{plan_id}", apikey_handlers::update_usage_plan, allow_any);
        $callback!($($args)*, delete, "/admin/usage-plans/{plan_id}", apikey_handlers::delete_usage_plan, allow_any);
        $callback!($($args)*, get, "/admin/resources", system_handlers::list_resources, allow_any);
        $callback!($($args)*, get, "/admin/actions", system_handlers::list_actions, allow_any);
        $callback!($($args)*, get, "/admin/audit-logs", system_handlers::query_audit_logs, allow_any);
        $callback!($($args)*, get, "/admin/audit-logs/stats", system_handlers::get_audit_stats, allow_any);
        $callback!($($args)*, get, "/admin/rate-limits/stats", system_handlers::get_rate_limit_stats, allow_any);
        $callback!($($args)*, get, "/admin/config", system_handlers::list_system_config, allow_any);
        $callback!($($args)*, put, "/admin/config/{key}", system_handlers::update_system_config, allow_any);
        $callback!($($args)*, get, "/me", system_handlers::get_me, require User Get);
        $callback!($($args)*, get, "/me/permissions", system_handlers::get_my_permissions, require User Get);
        $callback!($($args)*, get, "/me/permissions/detailed", system_handlers::get_my_permissions_detailed, require User Get);
        $callback!($($args)*, post, "/me/api-keys", apikey_handlers::create_my_api_key, require UserApiKey Post);
        $callback!($($args)*, get, "/me/api-keys", apikey_handlers::list_my_api_keys, require UserApiKey Get);
        $callback!($($args)*, delete, "/me/api-keys/{name}", apikey_handlers::revoke_my_api_key, require UserApiKey Delete);
    };
}

macro_rules! public_auth_route_catalog {
    ($callback:ident, $($args:tt)*) => {
        $callback!($($args)*, post, "/login", login_handler::login);
        $callback!($($args)*, post, "/change-password", login_handler::change_password);
    };
}

macro_rules! append_catalog_route {
    ($router:ident, get, $path:literal, $handler:path, $($access:tt)+) => {
        $router = $router.route($path, get($handler));
    };
    ($router:ident, post, $path:literal, $handler:path, $($access:tt)+) => {
        $router = $router.route($path, post($handler));
    };
    ($router:ident, put, $path:literal, $handler:path, $($access:tt)+) => {
        $router = $router.route($path, put($handler));
    };
    ($router:ident, patch, $path:literal, $handler:path, $($access:tt)+) => {
        $router = $router.route($path, patch($handler));
    };
    ($router:ident, delete, $path:literal, $handler:path, $($access:tt)+) => {
        $router = $router.route($path, delete($handler));
    };
    ($router:ident, external_get, $path:literal, $handler:ident, $($access:tt)+) => {};
}

macro_rules! append_public_route {
    ($router:ident, get, $path:literal, $handler:path) => {
        $router = $router.route($path, get($handler));
    };
    ($router:ident, post, $path:literal, $handler:path) => {
        $router = $router.route($path, post($handler));
    };
}

macro_rules! match_catalog_route {
    ($method:expr, $path:expr, get, $template:literal, $handler:path, allow_any) => {
        if RouteMethodSpec::Get.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::AllowAny);
        }
    };
    ($method:expr, $path:expr, post, $template:literal, $handler:path, allow_any) => {
        if RouteMethodSpec::Post.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::AllowAny);
        }
    };
    ($method:expr, $path:expr, put, $template:literal, $handler:path, allow_any) => {
        if RouteMethodSpec::Put.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::AllowAny);
        }
    };
    ($method:expr, $path:expr, patch, $template:literal, $handler:path, allow_any) => {
        if RouteMethodSpec::Patch.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::AllowAny);
        }
    };
    ($method:expr, $path:expr, delete, $template:literal, $handler:path, allow_any) => {
        if RouteMethodSpec::Delete.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::AllowAny);
        }
    };
    ($method:expr, $path:expr, get, $template:literal, $handler:path, require $resource:ident $action:ident) => {
        if RouteMethodSpec::Get.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::Require(Resource::$resource, Action::$action));
        }
    };
    ($method:expr, $path:expr, post, $template:literal, $handler:path, require $resource:ident $action:ident) => {
        if RouteMethodSpec::Post.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::Require(Resource::$resource, Action::$action));
        }
    };
    ($method:expr, $path:expr, put, $template:literal, $handler:path, require $resource:ident $action:ident) => {
        if RouteMethodSpec::Put.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::Require(Resource::$resource, Action::$action));
        }
    };
    ($method:expr, $path:expr, patch, $template:literal, $handler:path, require $resource:ident $action:ident) => {
        if RouteMethodSpec::Patch.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::Require(Resource::$resource, Action::$action));
        }
    };
    ($method:expr, $path:expr, delete, $template:literal, $handler:path, require $resource:ident $action:ident) => {
        if RouteMethodSpec::Delete.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::Require(Resource::$resource, Action::$action));
        }
    };
    ($method:expr, $path:expr, external_get, $template:literal, $handler:ident, require $resource:ident $action:ident) => {
        if RouteMethodSpec::Get.matches($method) && path_matches_template($template, $path) {
            return Some(PermissionResult::Require(Resource::$resource, Action::$action));
        }
    };
}

pub fn build_routes(
    doc: bool,
    proxy_config: ProxyConfig,
    bridge: Bridge,
    auth_db: Option<Arc<AuthDatabase>>,
    #[cfg(feature = "prometheus")] registry: std::sync::Arc<
        tokio::sync::Mutex<prometheus_client::registry::Registry>,
    >,
) -> Router {
    let bridge = Arc::new(bridge);
    let proxy = Arc::new(proxy_config);

    let mut main_routes = Router::new();
    main_route_catalog!(append_catalog_route, main_routes);
    let main_routes = main_routes.layer(
        ServiceBuilder::new()
            .layer(Extension(bridge))
            .layer(Extension(proxy.clone())),
    );

    let doc_routes = if doc {
        Some(
            SwaggerUi::new("/doc/")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
    } else {
        None
    };

    if let Some(db) = auth_db {
        let protected_layers = ServiceBuilder::new()
            .layer(Extension(db.clone()))
            .layer(Extension(proxy.clone()))
            .layer(middleware::from_extractor::<ApiKeyAuthNew>())
            .layer(middleware::from_fn(permission_layer))
            .layer(middleware::from_fn(audit_layer));

        let mut protected_routes = Router::new();
        auth_route_catalog!(append_catalog_route, protected_routes);
        let authed = Router::new().merge(main_routes).merge(protected_routes);
        #[cfg(feature = "prometheus")]
        let authed =
            authed.merge(ave_bridge::prometheus::build_routes(registry));
        let authed = authed.layer(protected_layers);

        let mut public_auth_routes = Router::new();
        public_auth_route_catalog!(append_public_route, public_auth_routes);
        let mut app = public_auth_routes
            .layer(
                ServiceBuilder::new()
                    .layer(Extension(db))
                    .layer(Extension(proxy.clone())),
            )
            .merge(authed);

        if let Some(doc_routes) = doc_routes {
            app = app.merge(doc_routes);
        }

        app
    } else {
        let app = main_routes;
        #[cfg(feature = "prometheus")]
        let app = app.merge(ave_bridge::prometheus::build_routes(registry));
        let mut app = app;
        if let Some(doc_routes) = doc_routes {
            app = app.merge(doc_routes);
        }
        app
    }
}

pub async fn permission_layer(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    // Skip docs
    if req.uri().path().starts_with("/doc") {
        return next.run(req).await;
    }

    let mut req = req;

    // Ensure auth context is present; if not, try to run the extractor inline
    let auth_ctx = match req.extensions().get::<Arc<AuthContext>>().cloned() {
        Some(ctx) => ctx,
        None => {
            let (mut parts, body) = req.into_parts();
            match ApiKeyAuthNew::from_request_parts(&mut parts, &()).await {
                Ok(_) => {
                    req = Request::from_parts(parts, body);
                    match req.extensions().get::<Arc<AuthContext>>().cloned() {
                        Some(ctx) => ctx,
                        None => {
                            return (
                                StatusCode::UNAUTHORIZED,
                                Json(ErrorResponse {
                                    error: "Authentication required"
                                        .to_string(),
                                }),
                            )
                                .into_response();
                        }
                    }
                }
                Err(rejection) => return rejection.into_response(),
            }
        }
    };

    // Block service keys from admin and key management endpoints outright
    if !auth_ctx.is_management_key
        && (req.uri().path().starts_with("/admin")
            || req.uri().path().starts_with("/me/api-keys"))
    {
        return (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse {
                error: "Service API keys cannot access administration or key management endpoints"
                    .into(),
            }),
        )
            .into_response();
    }

    match permission_for(req.method(), req.uri().path()) {
        None => {
            return (
                StatusCode::FORBIDDEN,
                Json(ErrorResponse {
                    error: "Access denied".into(),
                }),
            )
                .into_response();
        }
        Some(PermissionResult::AllowAny) => {}
        Some(PermissionResult::Require(resource, action)) => {
            if let Err(resp) =
                check_permission(&auth_ctx, resource.as_str(), action.as_str())
            {
                return resp.into_response();
            }
        }
    }

    next.run(req).await
}

/// Maps an HTTP method + path to the permission required to access it.
///
/// Returns:
/// - `Some(AllowAny)` — any authenticated user may proceed (admin routes use inline checks).
/// - `Some(Require(r, a))` — caller must hold permission `r:a`.
/// - `None` — route not recognized; access is **denied**.
pub fn permission_for(method: &Method, path: &str) -> Option<PermissionResult> {
    main_route_catalog!(match_catalog_route, method, path);
    auth_route_catalog!(match_catalog_route, method, path);
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_bridge::auth::{
        ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig,
        SessionConfig,
    };
    use axum::{
        Router,
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::{delete, get, post},
    };
    use tower::ServiceExt;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn build_db() -> Arc<AuthDatabase> {
        #[allow(deprecated)]
        let tmp = tempfile::tempdir().unwrap().into_path();
        let config = AuthConfig {
            durability: false,
            enable: true,
            database_path: tmp.join("test.db"),
            superadmin: "admin".to_string(),
            api_key: ApiKeyConfig::default(),
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        };
        Arc::new(AuthDatabase::new(config, "AdminPass123!", None).unwrap())
    }

    fn auth_ctx_for_role(db: &AuthDatabase, role: &str) -> Arc<AuthContext> {
        let role = db.get_role_by_name(role).unwrap();
        let perms = db.get_role_permissions(role.id).unwrap();
        let role_name = role.name.expect("role name");
        Arc::new(AuthContext {
            user_id: 1,
            username: role_name.clone(),
            roles: vec![role_name],
            permissions: perms,
            api_key_id: "00000000-0000-0000-0000-000000000001".to_string(),
            is_management_key: true,
            ip_address: None,
        })
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        ctx: Arc<AuthContext>,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ctx);

        app.clone().oneshot(req).await.unwrap().status()
    }

    fn router() -> Router {
        Router::new()
            .route("/events/abc", get(ok_handler))
            .route("/subjects", get(ok_handler))
            .route("/request", post(ok_handler).get(ok_handler))
            .route("/request/123", get(ok_handler))
            .route("/manual-distribution/abc", post(ok_handler))
            .route("/auth/abc", delete(ok_handler))
            .route("/approval/abc", get(ok_handler).patch(ok_handler))
            .route("/peer-id", get(ok_handler))
            .layer(middleware::from_fn(permission_layer))
    }

    fn router_with_auth(db: Arc<AuthDatabase>) -> Router {
        Router::new()
            .route("/peer-id", get(ok_handler))
            // Mirror production order using ServiceBuilder.
            .layer(
                ServiceBuilder::new()
                    .layer(Extension(db))
                    .layer(middleware::from_extractor::<ApiKeyAuthNew>())
                    .layer(middleware::from_fn(permission_layer)),
            )
    }

    #[tokio::test]
    async fn data_role_limited_to_reads() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "data");
        let app = router();

        // data role has node_subject:get - should be allowed
        let status = call(&app, Method::GET, "/events/abc", ctx.clone()).await;
        assert_eq!(status, StatusCode::OK);

        // data role has node_request:get - should be allowed
        let status = call(&app, Method::GET, "/request/123", ctx.clone()).await;
        assert_eq!(status, StatusCode::OK);

        // data role does NOT have node_subject:post - should be forbidden
        let status =
            call(&app, Method::POST, "/manual-distribution/abc", ctx.clone())
                .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // data role does NOT have node_request:post - should be forbidden
        let status = call(&app, Method::POST, "/request", ctx).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn manager_role_allows_subject_writes() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "manager");
        let app = router();

        let status =
            call(&app, Method::POST, "/manual-distribution/abc", ctx.clone())
                .await;
        assert_eq!(status, StatusCode::OK);

        let status = call(&app, Method::POST, "/request", ctx).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn sender_role_only_allows_send_event() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "sender");
        let app = router();

        let ok_status = call(&app, Method::POST, "/request", ctx.clone()).await;
        assert_eq!(ok_status, StatusCode::OK);

        let ok_get = call(&app, Method::GET, "/request/123", ctx.clone()).await;
        assert_eq!(ok_get, StatusCode::OK);

        let forbidden =
            call(&app, Method::POST, "/manual-distribution/abc", ctx).await;
        assert_eq!(forbidden, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn api_key_auth_populates_context_for_permission_layer() {
        let db = build_db();
        let app = router_with_auth(db.clone());

        // Login to get API key
        let (api_key, _) = db
            .create_api_key(1, Some("perm_layer"), None, None, false)
            .expect("create api key");

        let req = Request::builder()
            .method(Method::GET)
            .uri("/peer-id")
            .header("X-API-Key", api_key)
            .body(Body::empty())
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }
}
