//! Response types from Ave API

use crate::namespace::Namespace;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::HashSet, fmt::Display};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ProtocolsError {
    pub evaluation: Option<String>,
    pub validation: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct PaginatorEvents {
    pub paginator: Paginator,
    pub events: Vec<EventInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct CreateRequestInfo {
    pub name: Option<String>,
    pub description: Option<String>,
    pub governance_id: String,
    pub schema_id: String,
    pub namespace: Namespace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct TransferRequestInfo {
    pub subject_id: String,
    pub new_owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ConfirmRequestInfo {
    pub subject_id: String,
    pub name_old_owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct EOLRequestInfo {
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct FactRequestInfo {
    pub subject_id: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RejectRequestInfo {
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum EventRequestInfo {
    Create(CreateRequestInfo),
    Fact(FactRequestInfo),
    Transfer(TransferRequestInfo),
    Confirm(ConfirmRequestInfo),
    EOL(EOLRequestInfo),
    Reject(RejectRequestInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct EventInfo {
    pub subject_id: String,
    pub sn: u64,
    pub patch: Option<Value>,
    pub error: Option<ProtocolsError>,
    pub event_req: EventRequestInfo,
    pub succes: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignaturesDB {
    pub subject_id: String,
    pub sn: u64,
    pub signatures_eval: Option<String>,
    pub signatures_appr: Option<String>,
    pub signatures_vali: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignaturesInfo {
    pub subject_id: String,
    pub sn: u64,
    pub signatures_eval: Option<HashSet<ProtocolsSignaturesInfo>>,
    pub signatures_appr: Option<HashSet<ProtocolsSignaturesInfo>>,
    pub signatures_vali: HashSet<ProtocolsSignaturesInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum ProtocolsSignaturesInfo {
    Signature(SignatureInfo),
    TimeOut(TimeOutResponseInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct TimeOutResponseInfo {
    pub who: String,
    pub re_trys: u32,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SubjectDB {
    pub name: Option<String>,
    pub description: Option<String>,
    pub subject_id: String,
    pub governance_id: String,
    pub genesis_gov_version: u64,
    pub namespace: String,
    pub schema_id: String,
    pub owner: String,
    pub creator: String,
    pub active: String,
    pub sn: u64,
    pub properties: String,
    pub new_owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SubjectInfo {
    pub name: String,
    pub description: String,
    pub subject_id: String,
    pub governance_id: String,
    pub genesis_gov_version: u64,
    pub namespace: String,
    pub schema_id: String,
    pub owner: String,
    pub creator: String,
    pub active: bool,
    pub sn: u64,
    pub properties: Value,
    pub new_owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct EventDB {
    pub subject_id: String,
    pub sn: u64,
    pub patch: Option<String>,
    pub error: Option<String>,
    pub event_req: String,
    pub succes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct Paginator {
    pub pages: u64,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RequestInfo {
    pub state: RequestState,
    pub version: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub enum RequestState {
    Abort,
    InQueue,
    Invalid,
    Finish,
    Reboot,
    Evaluation,
    Approval,
    Validation,
    Distribution,
}

impl Display for RequestState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RequestState::Abort => write!(f, "Abort"),
            RequestState::InQueue => write!(f, "In Queue"),
            RequestState::Invalid => write!(f, "Invalid"),
            RequestState::Finish => write!(f, "Finish"),
            RequestState::Reboot => write!(f, "Reboot"),
            RequestState::Evaluation => write!(f, "Evaluation"),
            RequestState::Approval => write!(f, "Approval"),
            RequestState::Validation => write!(f, "Validation"),
            RequestState::Distribution => write!(f, "Distribution"),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ApproveInfo {
    pub state: String,
    pub request: ApprovalReqInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct ApprovalReqInfo {
    /// The signed event request
    pub event_request: SignedInfo<FactInfo>,
    /// The sequence number of the event
    pub sn: u64,
    /// The version of the governance contract
    pub gov_version: u64,
    /// The patch to apply to the state
    pub patch: Value,
    /// The hash of the state after applying the patch
    pub state_hash: String,
    /// The hash of the previous event
    pub hash_prev_event: String,
    /// The hash of the previous event
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct FactInfo {
    pub payload: Value,
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignedInfo<T: Serialize + Clone> {
    /// The data that is signed
    pub content: T,
    /// The signature accompanying the data
    pub signature: SignatureInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SignatureInfo {
    /// Signer identifier
    pub signer: String,
    /// Timestamp of the signature
    pub timestamp: u64,
    /// Hash of the content signed
    pub content_hash: String,
    /// The signature itself
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct RequestData {
    pub request_id: String,
    pub subject_id: String,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, Ord, PartialEq, PartialOrd, Eq,
)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SubjsData {
    pub subject_id: String,
    pub schema_id: String,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct GovsData {
    pub governance_id: String,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct TransferSubject {
    pub name: String,
    pub subject_id: String,
    pub new_owner: String,
    pub actual_owner: String,
}
