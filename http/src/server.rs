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
    Ok(Json(
        bridge
            .get_aborts(
                subject_id,
                parameters.request_id,
                parameters.sn,
                parameters.quantity,
                parameters.page,
                parameters.reverse,
            )
            .await?,
    ))
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

pub fn build_routes(
    doc: bool,
    bridge: Bridge,
    auth_db: Option<Arc<AuthDatabase>>,
    #[cfg(feature = "prometheus")] registry: std::sync::Arc<
        prometheus_client::registry::Registry,
    >,
) -> Router {
    let bridge = Arc::new(bridge);

    let main_routes = Router::new()
        .route("/peer-id", get(get_peer_id))
        .route("/public-key", get(get_public_key))
        .route("/config", get(get_config))
        .route("/network-state", get(get_network_state))
        .route("/requests-in-manager", get(get_requests_in_manager))
        .route(
            "/requests-in-manager/{subject_id}",
            get(get_requests_in_manager_subject_id),
        )
        .route("/approval", get(get_approvals))
        .route("/approval/{subject_id}", get(get_approval))
        .route("/approval/{subject_id}", patch(patch_approve))
        .route(
            "/request-abort/{subject_id}",
            post(post_manual_request_abort),
        )
        .route("/request", post(post_event_request))
        .route("/request", get(get_all_request_state))
        .route("/request/{request_id}", get(get_request_state))
        .route("/pending-transfers", get(get_pending_transfers))
        .route("/auth", get(get_all_auth_subjects))
        .route("/auth/{subject_id}", put(put_auth_subject))
        .route("/auth/{subject_id}", get(get_witnesses_subject))
        .route("/auth/{subject_id}", delete(delete_auth_subject))
        .route("/update/{subject_id}", post(post_update_subject))
        .route(
            "/manual-distribution/{subject_id}",
            post(post_manual_distribution),
        )
        .route("/subjects", get(get_all_govs))
        .route("/subjects/{governance_id}", get(get_all_subjs))
        .route("/events/{subject_id}", get(get_events))
        .route("/events/{subject_id}/{sn}", get(get_event_sn))
        .route("/aborts/{subject_id}", get(get_aborts))
        .route(
            "/events-first-last/{subject_id}",
            get(get_first_or_end_events),
        )
        .route("/state/{subject_id}", get(get_subject_state))
        .layer(ServiceBuilder::new().layer(Extension(bridge)));

    let doc_routes = if doc {
        Some(
            SwaggerUi::new("/doc/")
                .url("/api-docs/openapi.json", ApiDoc::openapi()),
        )
    } else {
        None
    };

    if let Some(db) = auth_db {
        // Apply layers in declared order (outer -> inner) using ServiceBuilder.
        let protected_layers = ServiceBuilder::new()
            // 1) DB extension must run first so extractors can see it.
            .layer(Extension(db.clone()))
            // 2) Extract API key and inject AuthContext.
            .layer(middleware::from_extractor::<ApiKeyAuthNew>())
            // 3) Enforce permissions with the injected context.
            .layer(middleware::from_fn(permission_layer))
            // 4) Enforce read-only mode.
            .layer(middleware::from_fn(read_only_layer))
            // 5) Audit logs (runs outermost).
            .layer(middleware::from_fn(audit_layer));

        let protected_routes = Router::new()
            .route(
                "/admin/users",
                get(admin_handlers::list_users)
                    .post(admin_handlers::create_user),
            )
            .route(
                "/admin/users/{user_id}",
                get(admin_handlers::get_user)
                    .put(admin_handlers::update_user)
                    .delete(admin_handlers::delete_user),
            )
            .route(
                "/admin/users/{user_id}/password",
                post(admin_handlers::reset_user_password),
            )
            .route(
                "/admin/users/{user_id}/roles/{role_id}",
                post(admin_handlers::assign_role)
                    .delete(admin_handlers::remove_role),
            )
            .route(
                "/admin/users/{user_id}/permissions",
                get(admin_handlers::get_user_permissions)
                    .post(admin_handlers::set_user_permission)
                    .delete(admin_handlers::remove_user_permission),
            )
            .route(
                "/admin/roles",
                get(admin_handlers::list_roles)
                    .post(admin_handlers::create_role),
            )
            .route(
                "/admin/roles/{role_id}",
                get(admin_handlers::get_role)
                    .put(admin_handlers::update_role)
                    .delete(admin_handlers::delete_role),
            )
            .route(
                "/admin/roles/{role_id}/permissions",
                get(admin_handlers::get_role_permissions)
                    .post(admin_handlers::set_role_permission)
                    .delete(admin_handlers::remove_role_permission),
            )
            .route(
                "/admin/api-keys/user/{user_id}",
                post(apikey_handlers::create_api_key_for_user)
                    .get(apikey_handlers::list_user_api_keys_admin),
            )
            .route("/admin/api-keys", get(apikey_handlers::list_all_api_keys))
            .route(
                "/admin/api-keys/{key_id}",
                get(apikey_handlers::get_api_key)
                    .delete(apikey_handlers::revoke_api_key),
            )
            .route(
                "/admin/api-keys/{key_id}/rotate",
                post(apikey_handlers::rotate_api_key),
            )
            .route("/admin/resources", get(system_handlers::list_resources))
            .route("/admin/actions", get(system_handlers::list_actions))
            .route("/admin/audit-logs", get(system_handlers::query_audit_logs))
            .route(
                "/admin/audit-logs/stats",
                get(system_handlers::get_audit_stats),
            )
            .route(
                "/admin/rate-limits/stats",
                get(system_handlers::get_rate_limit_stats),
            )
            .route("/admin/config", get(system_handlers::list_system_config))
            .route(
                "/admin/config/{key}",
                put(system_handlers::update_system_config),
            )
            .route("/me", get(system_handlers::get_me))
            .route("/me/permissions", get(system_handlers::get_my_permissions))
            .route(
                "/me/permissions/detailed",
                get(system_handlers::get_my_permissions_detailed),
            )
            .route(
                "/me/api-keys",
                post(apikey_handlers::create_my_api_key)
                    .get(apikey_handlers::list_my_api_keys),
            )
            .route(
                "/me/api-keys/{name}",
                delete(apikey_handlers::revoke_my_api_key),
            )
            // Authentication is enforced by the outer `protected_layers`.
            // Avoid adding the extractor here to prevent double execution
            // (which was incrementing rate-limit counters twice).
            ;

        // Routes that require authentication & permission checks
        let authed = Router::new().merge(main_routes).merge(protected_routes);
        #[cfg(feature = "prometheus")]
        let authed =
            authed.merge(ave_bridge::prometheus::build_routes(registry));
        let authed = authed.layer(protected_layers);

        // Login remains unauthenticated but needs DB extension
        let mut app = Router::new()
            .route("/login", post(login_handler::login))
            .route("/change-password", post(login_handler::change_password))
            .layer(ServiceBuilder::new().layer(Extension(db)))
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

async fn read_only_layer(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    next.run(req).await
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
    use Action::*;
    use PermissionResult::*;
    use Resource::*;

    // Admin routes perform their own inline permission checks inside each handler.
    if path.starts_with("/admin/") {
        return Some(AllowAny);
    }

    let (resource, action) = match (method, path) {
        // Event requests
        (&Method::POST, "/request") => (NodeRequest, Post),
        (&Method::GET, "/request") => (NodeRequest, Get),
        (&Method::GET, p) if p.starts_with("/request/") => (NodeRequest, Get),

        // Requests in manager
        (&Method::GET, "/requests-in-manager") => (NodeRequest, Get),
        (&Method::GET, p) if p.starts_with("/requests-in-manager/") => {
            (NodeRequest, Get)
        }

        // Approvals
        (&Method::GET, "/approval") => (NodeSubject, Get),
        (&Method::GET, p) if p.starts_with("/approval/") => (NodeSubject, Get),
        (&Method::PATCH, p) if p.starts_with("/approval/") => {
            (NodeSubject, Patch)
        }

        // Request abort
        (&Method::POST, p) if p.starts_with("/request-abort/") => {
            (NodeSubject, Post)
        }

        // Ledger subject queries
        (&Method::GET, p) if p.starts_with("/events-first-last/") => {
            (NodeSubject, Get)
        }
        (&Method::GET, p) if p.starts_with("/events/") => (NodeSubject, Get),
        (&Method::GET, p) if p.starts_with("/aborts/") => (NodeSubject, Get),

        // Authorization / witnesses
        (&Method::GET, "/auth") => (NodeSubject, Get),
        (&Method::GET, p) if p.starts_with("/auth/") => (NodeSubject, Get),
        (&Method::PUT, p) if p.starts_with("/auth/") => (NodeSubject, Put),
        (&Method::DELETE, p) if p.starts_with("/auth/") => {
            (NodeSubject, Delete)
        }

        // Updates / distribution
        (&Method::POST, p) if p.starts_with("/update/") => (NodeSubject, Post),
        (&Method::POST, p) if p.starts_with("/manual-distribution/") => {
            (NodeSubject, Post)
        }

        // User self-service
        (&Method::GET, "/me") => (User, Get),
        (&Method::GET, "/me/permissions") => (User, Get),
        (&Method::GET, "/me/permissions/detailed") => (User, Get),

        // Self API keys (management key required)
        (&Method::GET, "/me/api-keys") => (UserApiKey, Get),
        (&Method::POST, "/me/api-keys") => (UserApiKey, Post),
        (&Method::DELETE, p) if p.starts_with("/me/api-keys/") => {
            (UserApiKey, Delete)
        }

        // Ledger info
        (&Method::GET, p) if p.starts_with("/state/") => (NodeSubject, Get),

        // Register - governances and subjects
        (&Method::GET, "/subjects") => (NodeSubject, Get),
        (&Method::GET, p) if p.starts_with("/subjects/") => (NodeSubject, Get),

        // Transfers
        (&Method::GET, "/pending-transfers") => (NodeSubject, Get),

        // Node/system info
        (&Method::GET, "/public-key") => (NodeSystem, Get),
        (&Method::GET, "/peer-id") => (NodeSystem, Get),
        (&Method::GET, "/network-state") => (NodeSystem, Get),

        // Node management (manager + superadmin only)
        (&Method::GET, "/config") => (NodeManagement, Get),
        (&Method::GET, "/metrics") => (NodeManagement, Get),

        // Unknown route → deny
        _ => return None,
    };

    Some(Require(resource, action))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_bridge::auth::{
        ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig,
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
