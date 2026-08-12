use crate::config_types::MachineSpecHttp;
use crate::error::GovernanceHasTrackersError;
use crate::server::{self};
use crate::{
    auth::{
        admin_handlers::{self, ResetPasswordRequest},
        apikey_handlers,
        login_handler::{self, ChangePasswordRequest},
        models::{
            Action, ApiKeyInfo, ApiKeyQuotaStatus, AssignApiKeyPlanRequest,
            AuditApiKeyCount, AuditLog, AuditLogPage, AuditStats,
            AuditUserCount, AuditValueCount, CreateApiKeyRequest,
            CreateApiKeyResponse, CreateQuotaExtensionRequest,
            CreateRoleRequest, CreateUsagePlanRequest, CreateUserRequest,
            ErrorResponse, LoginRequest, LoginResponse, Permission,
            QuotaExtensionInfo, RateLimitApiKeyStats, RateLimitEndpointStats,
            RateLimitIpEndpointStats, RateLimitIpStats, RateLimitStats,
            Resource, RevokeApiKeyRequest, Role, RoleInfo, RotateApiKeyRequest,
            SetPermissionRequest, SystemConfig, SystemConfigPage,
            UpdateRoleRequest, UpdateSystemConfigRequest,
            UpdateUsagePlanRequest, UpdateUserRequest, UsagePlan, UserInfo,
        },
        system_handlers::{
            self, DetailedPermissionsResponse, RolePermissionsInfo,
        },
    },
    config_types::{
        ApiKeyConfigHttp, AuthConfigHttp, AveConfigHttp, AveStoreConfigHttp,
        ConfigHttp, ControlListConfigHttp, CorsConfigHttp,
        EndpointRateLimitHttp, GovernanceSyncConfigHttp, HashAlgorithmHttp,
        HttpConfigHttp, HttpProxyConfigHttp, HttpSinkConfigHttp,
        HttpTlsConfigHttp, HttpTlsVersionHttp, KafkaAcksHttp,
        KafkaCompressionHttp, KafkaSaslMechanismHttp, KafkaSecurityConfigHttp,
        KafkaSinkConfigHttp, KafkaTlsConfigHttp, KeyPairAlgorithmHttp,
        LockoutConfigHttp, LoggingHttp, LoggingOutputHttp, LoggingRotationHttp,
        MemoryLimitsConfigHttp, NetworkConfigHttp, NodeTypeHttp,
        OAuth2GrantTypeHttp, ProxyConfigHttp, RateLimitConfigHttp,
        RebootSyncConfigHttp, RoutingConfigHttp, RoutingNodeHttp,
        SelfSignedCertConfigHttp, SessionConfigHttp, SinkAuthConfigHttp,
        SinkAuthMethodHttp, SinkCompressionHttp, SinkConfigEntryHttp,
        SinkConfigHttp, SinkServerHttp, SinkTargetHttp,
        SinkTransportConfigHttp, SyncConfigHttp, TrackerSyncConfigHttp,
        UpdateSyncConfigHttp,
    },
};
use ave_bridge::MonitorNetworkState;
use ave_bridge::ave_common::{
    Namespace, SchemaType,
    bridge::{
        request::{
            AbortsQuery, ApprovalQuery, ApprovalState, ApprovalStateRes,
            BridgeConfirmRequest, BridgeCreateRequest, BridgeEOLRequest,
            BridgeEventRequest, BridgeFactRequest, BridgeRejectRequest,
            BridgeSignedEventRequest, BridgeTransferRequest, EventRequestType,
            EventsQuery, FirstEndEvents, GovQuery, SinkEventsQuery,
            SinkReplayItem, SinkReplayRequest, SubjectQuery,
            UpdateSubjectQuery,
        },
        signature::BridgeSignature,
    },
    response::{
        AbortDB, ApprovalEntry, ApprovalReq, EvalResDB, GovsData, LedgerDB,
        Paginator, PaginatorAborts, PaginatorEvents, RequestData,
        RequestEventDB, RequestInfo, RequestInfoExtend, RequestState,
        RequestsInManager, RequestsInManagerSubject, SinkEventsPage, SinkInfo,
        SinkManagerTarget, SinkReplayError, SinkReplayResponse, SinkStatusInfo,
        SubjectDB, SubjsData, TimeRange, TransferSubject,
    },
};

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new(
                    "X-API-Key",
                ))),
            );
        }
    }
}

/// Removes paths whose routes only exist when certain cargo features are
/// enabled, so the generated document always matches the binary.
struct FeatureGatedPathsAddon;

impl Modify for FeatureGatedPathsAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        #[cfg(not(feature = "prometheus"))]
        openapi.paths.paths.remove("/metrics");
        #[cfg(feature = "prometheus")]
        let _ = openapi;
    }
}

/// # Ave HTTP API
///
/// RESTful API for interacting with Ave Ledger nodes.
#[derive(OpenApi)]
#[openapi(
    info(
        title = "Ave HTTP API",
        description = "RESTful API for Ave Ledger — a distributed ledger technology for managing digital assets and events with governance, approvals, and cryptographic security.\n\n## Authentication\n\nWhen the authentication system is enabled, most endpoints require an `X-API-Key` header.\nObtain an API key through the `POST /login` endpoint.\nWhen authentication is disabled in the node configuration, endpoints are accessible without credentials.\n\nProtected endpoints return `401 Unauthorized` when the API key is missing or invalid, and `403 Forbidden` when the key does not hold the permission required by the endpoint.\nEndpoints that mutate node state return `503 Service Unavailable` while the node is running in safe mode.",
        version = "0.12.0",
        contact(
            name = "Averiun",
            url = "https://www.averiun.com/",
            email = "info@averiun.com"
        ),
        license(
            name = "AGPL-3.0-only",
            url = "https://www.gnu.org/licenses/agpl-3.0.html"
        )
    ),
    paths(
        // ── Authentication ──────────────────────────────────────
        login_handler::login,
        login_handler::change_password,

        // ── Node ────────────────────────────────────────────────
        server::get_peer_id,
        server::get_public_key,
        server::get_config,
        server::get_network_state,

        // ── Request ─────────────────────────────────────────────
        server::get_requests_in_manager,
        server::get_requests_in_manager_subject_id,
        server::post_event_request,

        // ── Approval ────────────────────────────────────────────
        server::get_approval,
        server::get_approvals,
        server::patch_approve,
        server::post_manual_request_abort,

        // ── Tracking ────────────────────────────────────────────
        server::get_request_state,
        server::get_all_request_state,

        // ── Transfer ────────────────────────────────────────────
        server::get_pending_transfers,

        // ── SubjectAccess ──────────────────────────────────────
        server::authorize_governance,
        server::disauthorize_governance,
        server::authorized_governances,
        server::is_governance_authorized,
        server::ban_tracker,
        server::unban_tracker,
        server::banned_trackers,
        server::is_tracker_banned,
        server::get_sync_peers,
        server::add_sync_peer,
        server::remove_sync_peer,
        server::subjects_with_sync_peers,
        server::post_update_subject,

        // ── Distribution ────────────────────────────────────────
        server::post_manual_distribution,

        // ── Register ────────────────────────────────────────────
        server::get_all_govs,
        server::get_all_subjs,

        // ── Ledger ──────────────────────────────────────────────
        server::get_events,
        server::get_sink_events,
        server::get_aborts,
        server::get_event_sn,
        server::get_first_or_end_events,
        server::get_subject_state,

        // ── User Management (admin) ─────────────────────────────
        admin_handlers::create_user,
        admin_handlers::list_users,
        admin_handlers::get_user,
        admin_handlers::update_user,
        admin_handlers::delete_user,
        admin_handlers::reset_user_password,
        admin_handlers::assign_role,
        admin_handlers::remove_role,
        admin_handlers::get_user_permissions,
        admin_handlers::set_user_permission,
        admin_handlers::remove_user_permission,

        // ── Role Management (admin) ─────────────────────────────
        admin_handlers::create_role,
        admin_handlers::list_roles,
        admin_handlers::get_role,
        admin_handlers::update_role,
        admin_handlers::delete_role,
        admin_handlers::get_role_permissions,
        admin_handlers::set_role_permission,
        admin_handlers::remove_role_permission,

        // ── API Key Management (admin) ──────────────────────────
        apikey_handlers::create_api_key_for_user,
        apikey_handlers::list_all_api_keys,
        apikey_handlers::list_user_api_keys_admin,
        apikey_handlers::get_api_key,
        apikey_handlers::revoke_api_key,
        apikey_handlers::rotate_api_key,
        apikey_handlers::assign_api_key_plan,
        apikey_handlers::get_api_key_quota_status,
        apikey_handlers::add_api_key_quota_extension,
        apikey_handlers::create_usage_plan,
        apikey_handlers::list_usage_plans,
        apikey_handlers::get_usage_plan,
        apikey_handlers::update_usage_plan,
        apikey_handlers::delete_usage_plan,

        // ── My Account ──────────────────────────────────────────
        apikey_handlers::create_my_api_key,
        apikey_handlers::list_my_api_keys,
        apikey_handlers::revoke_my_api_key,
        system_handlers::get_me,
        system_handlers::get_my_permissions,
        system_handlers::get_my_permissions_detailed,

        // ── System (admin) ──────────────────────────────────────
        system_handlers::list_resources,
        system_handlers::list_actions,
        system_handlers::query_audit_logs,
        system_handlers::get_audit_stats,
        system_handlers::get_rate_limit_stats,
        system_handlers::list_system_config,
        system_handlers::update_system_config,

        // ── Sink ──────────────────────────────────────────────
        server::get_sinks,
        server::get_sinks_status,
        server::unblock_sink,
        server::test_sink,
        server::reset_sink_cursors,
        server::replay_sink_events,

        // ── Maintenance ─────────────────────────────────────────
        server::delete_subject,

        // ── Observability ───────────────────────────────────────
        server::get_metrics,
    ),
    components(
        schemas(
            // ── Error ───────────────────────────────────────────
            ErrorResponse,
            GovernanceHasTrackersError,

            // ── Authentication ──────────────────────────────────
            LoginRequest,
            LoginResponse,
            ChangePasswordRequest,

            // ── User management ─────────────────────────────────
            UserInfo,
            CreateUserRequest,
            UpdateUserRequest,
            ResetPasswordRequest,

            // ── Role management ─────────────────────────────────
            Role,
            RoleInfo,
            CreateRoleRequest,
            UpdateRoleRequest,

            // ── Permissions ─────────────────────────────────────
            Permission,
            SetPermissionRequest,
            Resource,
            Action,
            DetailedPermissionsResponse,
            RolePermissionsInfo,

            // ── API keys ────────────────────────────────────────
            ApiKeyInfo,
            CreateApiKeyRequest,
            CreateApiKeyResponse,
            RotateApiKeyRequest,
            RevokeApiKeyRequest,
            AssignApiKeyPlanRequest,
            CreateQuotaExtensionRequest,
            QuotaExtensionInfo,
            ApiKeyQuotaStatus,
            UsagePlan,
            CreateUsagePlanRequest,
            UpdateUsagePlanRequest,

            // ── Audit & system ──────────────────────────────────
            AuditLog,
            AuditLogPage,
            AuditStats,
            AuditValueCount,
            AuditUserCount,
            AuditApiKeyCount,
            RateLimitStats,
            RateLimitApiKeyStats,
            RateLimitIpStats,
            RateLimitEndpointStats,
            RateLimitIpEndpointStats,
            SystemConfig,
            SystemConfigPage,
            UpdateSystemConfigRequest,

            // ── Query parameters ────────────────────────────────
            SubjectQuery,
            UpdateSubjectQuery,
            GovQuery,
            ApprovalQuery,
            EventsQuery,
            SinkEventsQuery,
            AbortsQuery,
            FirstEndEvents,

            // ── Event request types ─────────────────────────────
            BridgeSignedEventRequest,
            BridgeEventRequest,
            BridgeCreateRequest,
            BridgeFactRequest,
            BridgeTransferRequest,
            BridgeEOLRequest,
            BridgeConfirmRequest,
            BridgeRejectRequest,
            BridgeSignature,
            ApprovalStateRes,
            ApprovalState,

            // ── Ledger response types ───────────────────────────
            RequestData,
            RequestInfoExtend,
            RequestInfo,
            RequestState,
            RequestsInManager,
            RequestsInManagerSubject,
            ApprovalReq,
            ApprovalEntry,
            GovsData,
            SubjsData,
            SchemaType,
            Namespace,
            TransferSubject,
            MonitorNetworkState,
            LedgerDB,
            RequestEventDB,
            EvalResDB,
            PaginatorEvents,
            SinkEventsPage,
            PaginatorAborts,
            Paginator,
            AbortDB,
            SubjectDB,
            TimeRange,
            EventRequestType,

            // ── Sink response / request types ─────────────────────
            SinkInfo,
            SinkStatusInfo,
            SinkManagerTarget,
            SinkReplayRequest,
            SinkReplayItem,
            SinkReplayResponse,
            SinkReplayError,

            // ── Configuration ───────────────────────────────────
            ConfigHttp,
            AveConfigHttp,
            KeyPairAlgorithmHttp,
            HashAlgorithmHttp,
            SyncConfigHttp,
            GovernanceSyncConfigHttp,
            TrackerSyncConfigHttp,
            UpdateSyncConfigHttp,
            RebootSyncConfigHttp,
            NetworkConfigHttp,
            NodeTypeHttp,
            MemoryLimitsConfigHttp,
            RoutingConfigHttp,
            RoutingNodeHttp,
            ControlListConfigHttp,
            HttpConfigHttp,
            ProxyConfigHttp,
            CorsConfigHttp,
            SelfSignedCertConfigHttp,
            AuthConfigHttp,
            ApiKeyConfigHttp,
            LockoutConfigHttp,
            RateLimitConfigHttp,
            EndpointRateLimitHttp,
            SessionConfigHttp,
            LoggingHttp,
            LoggingOutputHttp,
            LoggingRotationHttp,
            SinkConfigHttp,
            SinkConfigEntryHttp,
            SinkServerHttp,
            SinkTargetHttp,
            SinkTransportConfigHttp,
            HttpSinkConfigHttp,
            HttpProxyConfigHttp,
            SinkCompressionHttp,
            HttpTlsConfigHttp,
            HttpTlsVersionHttp,
            OAuth2GrantTypeHttp,
            KafkaAcksHttp,
            KafkaCompressionHttp,
            KafkaSaslMechanismHttp,
            KafkaSecurityConfigHttp,
            KafkaSinkConfigHttp,
            KafkaTlsConfigHttp,
            SinkAuthConfigHttp,
            SinkAuthMethodHttp,
            AveStoreConfigHttp,
            MachineSpecHttp
        )
    ),
    modifiers(&SecurityAddon, &FeatureGatedPathsAddon),
    tags(
        (name = "Authentication", description = "Login and password management. Use POST /login to obtain an API key."),
        (name = "Node", description = "Node identity, configuration, and network status."),
        (name = "Request", description = "Submit and track event requests in the processing pipeline."),
        (name = "Approval", description = "Manage approval workflows for governance events."),
        (name = "Tracking", description = "Track the lifecycle state of submitted requests."),
        (name = "Transfer", description = "Manage subject ownership transfers between parties."),
        (name = "SubjectAccess", description = "Governance allowlisting, tracker banning, and sync peer management."),
        (name = "Distribution", description = "Trigger manual event distribution to network peers."),
        (name = "Register", description = "Query governances and subjects in the ledger registry."),
        (name = "Ledger", description = "Query event history, aborts, and subject state from the ledger."),
        (name = "User Management", description = "CRUD operations for user accounts (admin only)."),
        (name = "Role Management", description = "CRUD operations for roles and role permissions (admin only)."),
        (name = "API Key Management", description = "Create, list, rotate, and revoke API keys (admin only)."),
        (name = "My Account", description = "Self-service endpoints for the authenticated user."),
        (name = "System", description = "System resources, actions, and configuration (admin only)."),
        (name = "Audit Logs", description = "Query and analyze audit log entries (admin only)."),
        (name = "Sink", description = "Manage and inspect external sinks (HTTP, Kafka, gRPC)."),
    )
)]
pub struct ApiDoc;
