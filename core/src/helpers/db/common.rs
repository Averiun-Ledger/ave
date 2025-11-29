use std::collections::HashSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::model::{Namespace, event::ProtocolsError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PaginatorEvents {
    pub paginator: Paginator,
    pub events: Vec<EventInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateRequestInfo {
    pub name: Option<String>,
    pub description: Option<String>,
    pub governance_id: String,
    pub schema_id: String,
    pub namespace: Namespace,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferRequestInfo {
    pub subject_id: String,
    pub new_owner: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfirmRequestInfo {
    pub subject_id: String,
    pub name_old_owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EOLRequestInfo {
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactRequestInfo {
    pub subject_id: String,
    pub payload: Value,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RejectRequestInfo {
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum EventRequestInfo {
    Create(CreateRequestInfo),
    Fact(FactRequestInfo),
    Transfer(TransferRequestInfo),
    Confirm(ConfirmRequestInfo),
    EOL(EOLRequestInfo),
    Reject(RejectRequestInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventInfo {
    pub subject_id: String,
    pub sn: u64,
    pub patch: Option<Value>,
    pub error: Option<ProtocolsError>,
    pub event_req: EventRequestInfo,
    pub succes: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignaturesDB {
    pub subject_id: String,
    pub sn: u64,
    pub signatures_eval: Option<String>,
    pub signatures_appr: Option<String>,
    pub signatures_vali: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignaturesInfo {
    pub subject_id: String,
    pub sn: u64,
    pub signatures_eval: Option<HashSet<ProtocolsSignaturesInfo>>,
    pub signatures_appr: Option<HashSet<ProtocolsSignaturesInfo>>,
    pub signatures_vali: HashSet<ProtocolsSignaturesInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub enum ProtocolsSignaturesInfo {
    Signature(SignatureInfo),
    TimeOut(TimeOutResponseInfo),
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct TimeOutResponseInfo {
    pub who: String,
    pub re_trys: u32,
    pub timestamp: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
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
pub struct EventDB {
    pub subject_id: String,
    pub sn: u64,
    pub patch: Option<String>,
    pub error: Option<String>,
    pub event_req: String,
    pub succes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Paginator {
    pub pages: u64,
    pub next: Option<u64>,
    pub prev: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RequestInfo {
    pub status: String,
    pub version: u64,
    pub error: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApproveInfo {
    pub state: String,
    pub request: ApprovalReqInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovalReqInfo {
    /// The signed event request.
    pub event_request: SignedInfo<FactInfo>,
    /// The sequence number of the event.
    pub sn: u64,
    /// The version of the governance contract.
    pub gov_version: u64,
    /// The patch to apply to the state.
    pub patch: Value,
    /// The hash of the state after applying the patch.
    pub state_hash: String,
    /// The hash of the previous event.
    pub hash_prev_event: String,
    /// The hash of the previous event.
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FactInfo {
    pub payload: Value,
    pub subject_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedInfo<T: Serialize + Clone> {
    /// The data that is signed
    pub content: T,
    /// The signature accompanying the data
    pub signature: SignatureInfo,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
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

impl TryFrom<crate::approval::request::ApprovalReq> for ApprovalReqInfo {
    type Error = String;

    fn try_from(value: crate::approval::request::ApprovalReq) -> Result<Self, Self::Error> {
        use crate::model::request::EventRequest;

        // Extract the FactRequest from EventRequest
        let fact_request = match value.event_request.content {
            EventRequest::Fact(fact) => fact,
            _ => return Err("Expected Fact event request in ApprovalReq".to_string()),
        };

        // Convert Signature to SignatureInfo
        let signature_info = SignatureInfo {
            signer: value.event_request.signature.signer.to_string(),
            timestamp: value.event_request.signature.timestamp.0,
            content_hash: value.event_request.signature.content_hash.to_string(),
            value: value.event_request.signature.value.to_string(),
        };

        // Convert FactRequest to FactInfo
        let fact_info = FactInfo {
            payload: fact_request.payload.0,
            subject_id: fact_request.subject_id.to_string(),
        };

        Ok(ApprovalReqInfo {
            event_request: SignedInfo {
                content: fact_info,
                signature: signature_info,
            },
            sn: value.sn,
            gov_version: value.gov_version,
            patch: value.patch.0,
            state_hash: value.state_hash.to_string(),
            hash_prev_event: value.hash_prev_event.to_string(),
            subject_id: value.subject_id.to_string(),
        })
    }
}
