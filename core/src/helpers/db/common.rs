use serde::{Deserialize, Serialize};

// Re-export types from ave-common
pub use ave_common::{
    ApprovalReqInfo, ApproveInfo, EventInfo, FactInfo, Paginator, PaginatorEvents,
    ProtocolsSignaturesInfo, RequestInfo, SignatureInfo, SignaturesInfo, SignedInfo,
    SubjectInfo, TimeOutResponseInfo,
};

// Internal database types that are NOT part of the public API
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
pub struct EventDB {
    pub subject_id: String,
    pub sn: u64,
    pub patch: Option<String>,
    pub error: Option<String>,
    pub event_req: String,
    pub succes: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignaturesDB {
    pub subject_id: String,
    pub sn: u64,
    pub signatures_eval: Option<String>,
    pub signatures_appr: Option<String>,
    pub signatures_vali: String,
}

// Keep the TryFrom implementation here since it depends on internal core types
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
