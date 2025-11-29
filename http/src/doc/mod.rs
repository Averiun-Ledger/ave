use crate::{
    auth::handlers::{
        ErrorResponse as AuthErrorResponse, LoginRequest, LoginResponse,
    },
    config_types::{
        AveConfigHttp, ConfigHttp, LoggingHttp, LoggingOutputHttp,
        NetworkConfigHttp, SinkConfigHttp, SinkServerHttp,
    },
    server::*,
};
use ave_bridge::{
    // Request types from ave-common re-exported by bridge
    BridgeSignedEventRequest, BridgeEventRequest, BridgeCreateRequest,
    BridgeFactRequest, BridgeTransferRequest, BridgeEOLRequest,
    BridgeConfirmRequest, BridgeRejectRequest, BridgeSignature,
    // Response types from ave-common re-exported by bridge
    ApprovalReqInfo, ApproveInfo, ConfirmRequestInfo, CreateRequestInfo,
    EOLRequestInfo, EventInfo, EventRequestInfo, FactInfo, FactRequestInfo,
    GovsData, Namespace, Paginator, PaginatorEvents, ProtocolsError,
    ProtocolsSignaturesInfo, RegisterDataSubj, RejectRequestInfo, RequestData,
    RequestInfo, SignatureInfo, SignaturesInfo, SignedInfo, SubjectInfo,
    TimeOutResponseInfo, TransferRequestInfo, TransferSubject,
};
use utoipa::OpenApi;

/// # Ave HTTP API
///
/// RESTful API for interacting with Ave Ledger nodes using HTTP protocol.
///
/// ## Overview
///
/// This API provides comprehensive access to Ave Ledger functionality including:
/// - **Event Management**: Create, query, and manage blockchain events
/// - **Subject Management**: Create and manage subjects (digital assets/entities)
/// - **Governance**: Manage governance structures and policies
/// - **Approvals**: Handle approval workflows for events
/// - **Transfers**: Manage subject ownership transfers
/// - **Authentication**: Secure API access with API keys
///
/// ## Authentication
///
/// Most endpoints require authentication using API keys obtained through the `/login` endpoint.
/// Include the API key in the `x-api-key` header for authenticated requests.
///
/// ## Event Types
///
/// - **Create**: Initialize new subjects in the ledger
/// - **Fact**: Update subject state with new data
/// - **Transfer**: Transfer subject ownership to a new owner
/// - **Confirm**: Confirm reception of a transferred subject
/// - **EOL**: Mark a subject as end-of-life
/// - **Reject**: Reject a transfer request
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ave HTTP API",
        description = "RESTful API for Ave Ledger - A distributed ledger technology for managing digital assets and events with governance, approvals, and cryptographic security.",
        version = "0.7.5",
        contact(
            name = "Ave Information",
            url = "https://www.averiun.com/",
            email = "info@averiun.com"
        ),
        license(
            name = "MIT",
            url = "https://opensource.org/licenses/MIT"
        )
    ),
    paths(
        crate::auth::handlers::login,
        send_event_request,
        get_request_state,
        get_approval,
        patch_approval,
        put_auth,
        get_all_auth_subjects,
        get_witnesses_subject,
        delete_auth_subject,
        update_subject,
        manual_distribution,
        get_all_govs,
        get_all_subjects,
        get_events,
        get_state,
        get_signatures,
        get_controller_id,
        get_peer_id,
        get_first_or_end_events,
        get_event_sn,
        check_transfer,
        get_config,
        get_keys,
        get_pending_transfers
    ),
    components(
        schemas(
            // Authentication schemas
            LoginRequest,
            LoginResponse,
            AuthErrorResponse,

            // Query parameter schemas
            SubjectQuery,
            GovQuery,
            EventsQuery,
            EventSnQuery,
            EventFirstLastQuery,

            // Request schemas - Event requests that can be sent
            BridgeSignedEventRequest,
            BridgeEventRequest,
            BridgeCreateRequest,
            BridgeFactRequest,
            BridgeTransferRequest,
            BridgeEOLRequest,
            BridgeConfirmRequest,
            BridgeRejectRequest,
            BridgeSignature,

            // Response schemas - Event data structures
            PaginatorEvents,
            Paginator,
            EventInfo,
            EventRequestInfo,
            ProtocolsError,

            // Request Info schemas - Detailed event request information
            CreateRequestInfo,
            FactRequestInfo,
            TransferRequestInfo,
            ConfirmRequestInfo,
            EOLRequestInfo,
            RejectRequestInfo,

            // Subject and Governance schemas
            SubjectInfo,
            RegisterDataSubj,
            GovsData,
            Namespace,

            // Request status schemas
            RequestData,
            RequestInfo,

            // Approval schemas
            ApproveInfo,
            ApprovalReqInfo,
            SignedInfo<FactInfo>,
            FactInfo,

            // Signature schemas
            SignaturesInfo,
            ProtocolsSignaturesInfo,
            SignatureInfo,
            TimeOutResponseInfo,

            // Transfer schemas
            TransferSubject,

            // Configuration schemas
            ConfigHttp,
            AveConfigHttp,
            NetworkConfigHttp,
            LoggingHttp,
            LoggingOutputHttp,
            SinkConfigHttp,
            SinkServerHttp
        )
    ),
    tags(
        (name = "Authentication", description = "Endpoints for API authentication and access control. Use the /login endpoint to obtain API keys for subsequent requests."),
        (name = "Event Request", description = "Submit and manage event requests. Events are state changes in the ledger including creating subjects, updating data, and transferring ownership."),
        (name = "Approval", description = "Manage approval workflows for events. Some events require explicit approval before being committed to the ledger."),
        (name = "Authorization", description = "Configure authorization rules for subjects. Define which witnesses can approve events for specific subjects."),
        (name = "Subject", description = "Query and manage subjects (digital assets/entities). Subjects represent any trackable entity in the ledger with its own state and history."),
        (name = "Governance", description = "Query governance structures. Governances define the rules, schemas, and policies for subject creation and management."),
        (name = "Event", description = "Query event history and details. Events represent all state changes that have occurred for subjects in the ledger."),
        (name = "Signature", description = "Query cryptographic signatures. Signatures prove the authenticity and integrity of events from various participants."),
        (name = "Transfer", description = "Manage subject ownership transfers. Transfer endpoints handle the process of changing subject ownership between parties."),
        (name = "Node", description = "Query node information and configuration. Access node identity, network status, and configuration details."),
    )
)]
pub struct ApiDoc;
