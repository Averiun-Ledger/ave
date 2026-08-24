//! Response payloads returned by the Ave API.

use crate::{
    DataToSink, SchemaType,
    bridge::request::{ApprovalState, EventRequestType, SinkReplayItem},
    sink::{
        GrpcSinkConfig, HttpSinkConfig, KafkaAcks, KafkaCompression,
        KafkaKeyStrategy, KafkaSaslMechanism, KafkaSecurityConfig,
        KafkaSinkConfig, SinkAuthMethod, SinkCompression, SinkServer,
        SinkTarget, SinkTransportConfig, SinkTypes,
    },
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::{BTreeSet, HashMap},
    fmt::Display,
};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Approval entry with request data and current state.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct ApprovalEntry {
    /// The approval request details
    pub request: ApprovalReq,
    /// Current state of the approval
    pub state: ApprovalState,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Ord, PartialOrd,
)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SubjsData {
    pub subject_id: String,
    pub schema_id: SchemaType,
    pub active: bool,
    pub namespace: String,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GovsData {
    pub governance_id: String,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TransferSubject {
    pub name: Option<String>,
    pub subject_id: String,
    pub new_owner: String,
    pub actual_owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct ApprovalReq {
    /// The signed event request.
    pub subject_id: String,
    /// The sequence number of the event.
    pub sn: u64,
    /// The version of the governance contract.
    pub gov_version: u64,
    /// The patch to apply to the state.
    pub patch: Value,

    pub signer: String,
}

/// Network status exposed by monitoring endpoints.
#[derive(Clone, Debug, Serialize, Deserialize, Default, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum MonitorNetworkState {
    /// Connecting to others network nodes
    #[default]
    Connecting,
    /// Connected to others netowrk nodes
    Running,
    /// Can not connect to others network nodes
    Down,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct LedgerDB {
    pub subject_id: String,
    pub sn: u64,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
    pub sink_timestamp: u64,
    pub event: RequestEventDB,
    pub event_type: EventRequestType,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestsInManager {
    pub handling: HashMap<String, String>,
    pub in_queue: HashMap<String, Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestsInManagerSubject {
    pub handling: Option<String>,
    pub in_queue: Option<Vec<String>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct AbortDB {
    pub request_id: String,
    pub subject_id: String,
    pub sn: Option<u64>,
    pub error: String,
    pub who: String,
    pub abort_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum RequestEventDB {
    Create {
        name: Option<String>,
        description: Option<String>,
        schema_id: String,
        namespace: String,
    },
    TrackerFactFull {
        payload: Value,
        viewpoints: Vec<String>,
        evaluation_response: EvalResDB,
    },
    TrackerFactOpaque {
        viewpoints: Vec<String>,
        evaluation_success: bool,
    },
    GovernanceFact {
        payload: Value,
        evaluation_response: EvalResDB,
        approval_success: Option<bool>,
    },
    Transfer {
        evaluation_error: Option<String>,
        new_owner: String,
    },
    TrackerConfirm,
    GovernanceConfirm {
        name_old_owner: Option<String>,
        evaluation_response: EvalResDB,
    },
    Reject,
    EOL,
}

impl RequestEventDB {
    pub const fn get_event_type(&self) -> EventRequestType {
        match self {
            Self::Create { .. } => EventRequestType::Create,
            Self::TrackerFactFull { .. }
            | Self::GovernanceFact { .. }
            | Self::TrackerFactOpaque { .. } => EventRequestType::Fact,
            Self::Transfer { .. } => EventRequestType::Transfer,
            Self::TrackerConfirm | Self::GovernanceConfirm { .. } => {
                EventRequestType::Confirm
            }
            Self::Reject => EventRequestType::Reject,
            Self::EOL => EventRequestType::Eol,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum EvalResDB {
    Patch(Value),
    Error(String),
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(rename_all = "snake_case")]
pub enum TrackerVisibilityModeDB {
    Full,
    Opaque,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrackerStoredVisibilityDB {
    Full,
    Only { viewpoints: Vec<String> },
    None,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerStoredVisibilityRangeDB {
    pub from_sn: u64,
    pub to_sn: Option<u64>,
    pub visibility: TrackerStoredVisibilityDB,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TrackerEventVisibilityDB {
    NonFact,
    Fact { viewpoints: Vec<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerEventVisibilityRangeDB {
    pub from_sn: u64,
    pub to_sn: Option<u64>,
    pub visibility: TrackerEventVisibilityDB,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TrackerVisibilityStateDB {
    pub mode: TrackerVisibilityModeDB,
    pub stored_ranges: Vec<TrackerStoredVisibilityRangeDB>,
    pub event_ranges: Vec<TrackerEventVisibilityRangeDB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SubjectDB {
    pub name: Option<String>,
    pub description: Option<String>,
    pub subject_id: String,
    pub governance_id: String,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: Option<String>,
    pub schema_id: String,
    pub namespace: String,
    pub sn: u64,
    pub creator: String,
    pub owner: String,
    pub new_owner: Option<String>,
    pub active: bool,
    pub tracker_visibility: Option<TrackerVisibilityStateDB>,
    pub properties: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct PaginatorEvents {
    pub paginator: Paginator,
    pub events: Vec<LedgerDB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkEventsPage {
    pub from_sn: u64,
    pub to_sn: Option<u64>,
    pub limit: u64,
    pub next_sn: Option<u64>,
    pub has_more: bool,
    pub events: Vec<DataToSink>,
}

/// Identifies where a sink instance is running.
#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq, Hash)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkManagerTarget {
    Node,
    Governance { governance_id: String },
}

/// Full information about a sink instance.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkInfo {
    pub name: String,
    pub target: Option<SinkTarget>,
    pub manager: SinkManagerTarget,
    pub in_config: bool,
    pub running: bool,
    pub blocked: Option<String>,
    pub lagging_subjects: usize,
    /// Last transient error reported by the sink worker, if any. Cleared when
    /// the sink recovers, is unblocked, or has no lagging subjects.
    pub last_error: Option<String>,
    /// Delivery transport kind (`"http"`, `"kafka"`, `"grpc"`). `None` when
    /// the sink is not present in the current configuration.
    pub transport: Option<String>,
    /// Sanitized view of the server configuration (see [`SinkServerView`]).
    /// `None` when the sink is not present in the current configuration.
    pub server: Option<SinkServerView>,
}

/// Sanitized view of a sink server configuration, as exposed by the API.
///
/// Mirrors the delivery-relevant parts of [`SinkServer`]: credentials
/// (usernames, auth endpoints, proxy settings) and internal tuning
/// (timeouts, retries, pool sizes, health-check internals) are omitted.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkServerView {
    /// Event types delivered to this sink.
    pub events: BTreeSet<SinkTypes>,
    /// Delivery transport and its public configuration.
    pub transport: SinkTransportView,
}

/// Sanitized delivery transport configuration, tagged like
/// [`SinkTransportConfig`] (`"http"`, `"kafka"`, `"grpc"`).
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTransportView {
    Http(HttpSinkView),
    Kafka(KafkaSinkView),
    Grpc(GrpcSinkView),
}

/// Authentication method of a sink delivery, without credentials or
/// endpoints.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkAuthKind {
    BearerToken,
    ApiKey,
    Basic,
    #[serde(rename = "oauth2")]
    OAuth2,
}

/// Security posture of a Kafka sink, without credentials.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum KafkaSecurityView {
    Plaintext,
    Ssl,
    SaslPlaintext { mechanism: KafkaSaslMechanism },
    SaslSsl { mechanism: KafkaSaslMechanism },
}

/// Public HTTP delivery configuration of a sink.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct HttpSinkView {
    /// URL endpoint template (`{{schema-id}}`, `{{subject-id}}` and
    /// `{{event-type}}` placeholders).
    pub url: String,
    /// Authentication method, if any. Credentials are omitted.
    pub auth: Option<SinkAuthKind>,
    /// Optional dedicated health-check URL.
    pub health_check_url: Option<String>,
    /// Whether TLS customization (extra CA, mTLS, pinning, minimum version)
    /// is configured. Certificate paths are omitted.
    pub tls: bool,
    /// Deliveries are signed with the node's Ed25519 identity.
    pub signature: bool,
    pub signature_version: u8,
    /// Events are delivered in batches (single POST with a JSON array).
    pub batch_delivery: bool,
    pub compression: SinkCompression,
    /// Custom static headers added to every delivery.
    pub headers: HashMap<String, String>,
}

/// Public Kafka delivery configuration of a sink.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct KafkaSinkView {
    /// Comma-separated list of `host:port` bootstrap brokers.
    pub bootstrap_servers: String,
    /// Topic template (`{{schema-id}}`, `{{subject-id}}`, `{{event-type}}`
    /// placeholders).
    pub topic: String,
    /// Producer client id.
    pub client_id: String,
    /// Security protocol and SASL mechanism. The username is omitted.
    pub security: KafkaSecurityView,
    /// Whether TLS customization (extra CA, mTLS) is configured. Certificate
    /// paths are omitted.
    pub tls: bool,
    /// Deliveries are signed with the node's Ed25519 identity.
    pub signature: bool,
    pub signature_version: u8,
    pub acks: KafkaAcks,
    pub compression: KafkaCompression,
    /// Strategy used to derive the message key of each delivery.
    pub key_strategy: KafkaKeyStrategy,
    /// Events are delivered in batches (single message with a JSON array).
    pub batch_delivery: bool,
    /// Kafka transactions are used for exactly-once producer semantics.
    pub transactional: bool,
    /// Custom static headers added to every delivered message.
    pub headers: HashMap<String, String>,
}

/// Public gRPC delivery configuration of a sink.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct GrpcSinkView {
    /// Server endpoint (`http://`, `https://` or `dns:///host:port`).
    pub endpoint: String,
    /// Authentication method, if any. Credentials are omitted.
    pub auth: Option<SinkAuthKind>,
    /// Whether TLS customization (extra CA, mTLS) is configured. Certificate
    /// paths are omitted.
    pub tls: bool,
    /// Deliveries are signed with the node's Ed25519 identity.
    pub signature: bool,
    pub compression: SinkCompression,
    /// Events are delivered in batches (single request with a JSON array
    /// payload).
    pub batch_delivery: bool,
    /// Custom static metadata added to every RPC.
    pub headers: HashMap<String, String>,
}

impl From<SinkServer> for SinkServerView {
    fn from(value: SinkServer) -> Self {
        Self {
            events: value.events,
            transport: value.transport.into(),
        }
    }
}

impl From<SinkTransportConfig> for SinkTransportView {
    fn from(value: SinkTransportConfig) -> Self {
        match value {
            SinkTransportConfig::Http(config) => Self::Http((*config).into()),
            SinkTransportConfig::Kafka(config) => Self::Kafka((*config).into()),
            SinkTransportConfig::Grpc(config) => Self::Grpc((*config).into()),
        }
    }
}

impl From<SinkAuthMethod> for SinkAuthKind {
    fn from(value: SinkAuthMethod) -> Self {
        match value {
            SinkAuthMethod::BearerToken => Self::BearerToken,
            SinkAuthMethod::ApiKey => Self::ApiKey,
            SinkAuthMethod::Basic { .. } => Self::Basic,
            SinkAuthMethod::OAuth2(_) => Self::OAuth2,
        }
    }
}

impl From<KafkaSecurityConfig> for KafkaSecurityView {
    fn from(value: KafkaSecurityConfig) -> Self {
        match value {
            KafkaSecurityConfig::Plaintext => Self::Plaintext,
            KafkaSecurityConfig::Ssl => Self::Ssl,
            KafkaSecurityConfig::SaslPlaintext { mechanism, .. } => {
                Self::SaslPlaintext { mechanism }
            }
            KafkaSecurityConfig::SaslSsl { mechanism, .. } => {
                Self::SaslSsl { mechanism }
            }
        }
    }
}

impl From<HttpSinkConfig> for HttpSinkView {
    fn from(value: HttpSinkConfig) -> Self {
        Self {
            url: value.url,
            auth: value.auth.map(SinkAuthKind::from),
            health_check_url: value.health_check_url,
            tls: value.tls.is_some(),
            signature: value.signature,
            signature_version: value.signature_version,
            batch_delivery: value.batch_delivery,
            compression: value.compression,
            headers: value.headers,
        }
    }
}

impl From<KafkaSinkConfig> for KafkaSinkView {
    fn from(value: KafkaSinkConfig) -> Self {
        Self {
            bootstrap_servers: value.bootstrap_servers,
            topic: value.topic,
            client_id: value.client_id,
            security: value.security.into(),
            tls: value.tls.is_some(),
            signature: value.signature,
            signature_version: value.signature_version,
            acks: value.acks,
            compression: value.compression,
            key_strategy: value.key_strategy,
            batch_delivery: value.batch_delivery,
            transactional: value.transactional,
            headers: value.headers,
        }
    }
}

impl From<GrpcSinkConfig> for GrpcSinkView {
    fn from(value: GrpcSinkConfig) -> Self {
        Self {
            endpoint: value.endpoint,
            auth: value.auth.map(SinkAuthKind::from),
            tls: value.tls.is_some(),
            signature: value.signature,
            compression: value.compression,
            batch_delivery: value.batch_delivery,
            headers: value.headers,
        }
    }
}

/// Reduced sink information for the quick `/sinks/status` view.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkStatusInfo {
    pub name: String,
    pub target: Option<SinkTarget>,
    pub manager: SinkManagerTarget,
    pub in_config: bool,
    pub running: bool,
    pub blocked: Option<String>,
    pub lagging_subjects: usize,
    /// Last transient error reported by the sink worker, if any. Cleared when
    /// the sink recovers, is unblocked, or has no lagging subjects.
    pub last_error: Option<String>,
    /// Delivery transport kind (`"http"`, `"kafka"`, `"grpc"`). `None` when
    /// the sink is not present in the current configuration.
    pub transport: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct PaginatorAborts {
    pub paginator: Paginator,
    pub events: Vec<AbortDB>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct Paginator {
    pub pages: u64,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestInfo {
    pub state: RequestState,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestInfoExtend {
    pub request_id: String,
    pub state: RequestState,
    pub version: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub enum RequestState {
    // Handler
    InQueue,
    Handling,
    Invalid {
        subject_id: String,
        who: String,
        sn: Option<u64>,
        error: String,
    },
    // Manager
    Abort {
        subject_id: String,
        who: String,
        sn: Option<u64>,
        error: String,
    },
    Reboot,
    RebootDiff {
        seconds: u64,
        count: u64,
    },
    RebootTimeOut {
        seconds: u64,
        count: u64,
    },
    Compilation,
    Evaluation,
    Approval,
    Validation,
    Distribution,
    Finish,
}

impl Display for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Handling => write!(f, "Handling"),
            Self::Abort {
                subject_id,
                who,
                sn,
                error,
            } => {
                let sn_text = sn
                    .as_ref()
                    .map_or_else(|| "None".to_string(), |sn| format!("{sn}"));

                write!(
                    f,
                    "Abort, subject_id: {}, who: {}, sn: {}, error: {}",
                    subject_id, who, sn_text, error
                )
            }
            Self::InQueue => write!(f, "In Queue"),
            Self::Invalid {
                subject_id,
                who,
                sn,
                error,
            } => {
                let sn_text = sn
                    .as_ref()
                    .map_or_else(|| "None".to_string(), |sn| format!("{sn}"));

                write!(
                    f,
                    "Abort, subject_id: {}, who: {}, sn: {}, error: {}",
                    subject_id, who, sn_text, error
                )
            }
            Self::Finish => write!(f, "Finish"),
            Self::Reboot => write!(f, "Reboot"),
            Self::RebootDiff { seconds, count } => {
                write!(f, "Reboot diff, try: {}, seconds: {}", count, seconds)
            }
            Self::RebootTimeOut { seconds, count } => write!(
                f,
                "Reboot timeout, try: {}, seconds: {}",
                count, seconds
            ),
            Self::Compilation => write!(f, "Compilation"),
            Self::Evaluation => write!(f, "Evaluation"),
            Self::Approval => write!(f, "Approval"),
            Self::Validation => write!(f, "Validation"),
            Self::Distribution => write!(f, "Distribution"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct RequestData {
    pub request_id: String,
    pub subject_id: String,
}

/// Error entry for a single failed manual sink replay item.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkReplayError {
    pub sink: String,
    pub subject_id: String,
    pub from_sn: u64,
    pub reason: String,
}

/// Result of a manual sink replay request.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct SinkReplayResponse {
    pub processed: Vec<SinkReplayItem>,
    pub errors: Vec<SinkReplayError>,
}

/// Time range filter for querying events by timestamp.
/// Both `from` and `to` are optional and should be ISO 8601 strings (e.g., "2024-01-15T14:30:00Z").
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct TimeRange {
    /// Start of the range (inclusive). ISO 8601 format.
    pub from: Option<String>,
    /// End of the range (inclusive). ISO 8601 format.
    pub to: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_subjs_data_deserialize_with_custom_schema() {
        let json = r#"{
            "subject_id": "sub1",
            "schema_id": "custom_schema",
            "active": false,
            "namespace": "ns",
            "name": null,
            "description": null
        }"#;
        let decoded: SubjsData = serde_json::from_str(json).unwrap();
        assert_eq!(
            decoded.schema_id,
            SchemaType::Type("custom_schema".to_string())
        );
        assert!(!decoded.active);
        assert_eq!(decoded.name, None);
    }

    #[test]
    fn test_approval_entry_deserialize_variants() {
        for state in [
            ApprovalState::Pending,
            ApprovalState::Accepted,
            ApprovalState::Rejected,
        ] {
            let entry = ApprovalEntry {
                request: ApprovalReq {
                    subject_id: "sub1".to_string(),
                    sn: 1,
                    gov_version: 1,
                    patch: json!({}),
                    signer: "signer".to_string(),
                },
                state: state.clone(),
            };
            let json_str = serde_json::to_string(&entry).unwrap();
            let decoded: ApprovalEntry =
                serde_json::from_str(&json_str).unwrap();
            assert_eq!(decoded.state, state);
        }
    }

    #[test]
    fn test_time_range_deserialize_empty() {
        let decoded: TimeRange = serde_json::from_str("{}").unwrap();
        assert_eq!(decoded.from, None);
        assert_eq!(decoded.to, None);
    }

    #[test]
    fn test_tracker_stored_visibility_deserialize_full_and_none() {
        let full: TrackerStoredVisibilityDB =
            serde_json::from_str(r#"{"kind":"full"}"#).unwrap();
        assert_eq!(full, TrackerStoredVisibilityDB::Full);

        let none: TrackerStoredVisibilityDB =
            serde_json::from_str(r#"{"kind":"none"}"#).unwrap();
        assert_eq!(none, TrackerStoredVisibilityDB::None);
    }
}
