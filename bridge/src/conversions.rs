//! Type conversions between Bridge API types and internal Core types
//!
//! This module re-exports and provides convenience functions for conversions
//! that are now implemented as traits in ave-common.

use ave_common::bridge::request::BridgeEventRequest;
use ave_common::request::EventRequest;
use ave_common::response::{
    ApprovalReq as ApprovalReqCommon, RequestData,
    TransferSubject as TransferSubjectCommon,
};

use ave_core::approval::request::ApprovalReq;
use ave_core::node::TransferSubject;

use crate::error::BridgeError;

// ============================================================================
// Conversion functions that delegate to the From/TryFrom traits
// ============================================================================

pub fn bridge_to_event_request(
    request: BridgeEventRequest,
) -> Result<EventRequest, BridgeError> {
    EventRequest::try_from(request)
        .map_err(|e| BridgeError::InvalidEventRequest(e.to_string()))
}

pub fn core_approval_req_to_common(data: ApprovalReq) -> ApprovalReqCommon {
    ApprovalReqCommon {
        subject_id: data.subject_id.to_string(),
        sn: data.sn,
        gov_version: data.gov_version,
        patch: data.patch.0,
        signer: data.signer.to_string(),
        issued_at: data.issued_at.as_nanos(),
        deadline: data.deadline.as_nanos(),
    }
}

pub fn core_tranfer_subject_to_common(
    data: TransferSubject,
) -> TransferSubjectCommon {
    TransferSubjectCommon {
        name: data.name,
        subject_id: data.subject_id.to_string(),
        new_owner: data.new_owner.to_string(),
        actual_owner: data.actual_owner.to_string(),
    }
}

pub fn core_request_to_common(
    data: ave_core::request::RequestData,
) -> RequestData {
    RequestData {
        request_id: data.request_id.to_string(),
        subject_id: data.subject_id.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::{
        ValueWrapper,
        identity::{
            DigestIdentifier, KeyPair, TimeStamp, keys::Ed25519Signer,
        },
    };

    fn core_req() -> ApprovalReq {
        let signer = Ed25519Signer::generate().unwrap();
        ApprovalReq {
            subject_id: DigestIdentifier::default(),
            sn: 7,
            gov_version: 3,
            patch: ValueWrapper(serde_json::json!({"op": "add"})),
            signer: KeyPair::Ed25519(signer).public_key(),
            issued_at: TimeStamp::from_nanos(111),
            deadline: TimeStamp::from_nanos(222),
        }
    }

    #[test]
    fn approval_window_maps_to_nanos() {
        let request = core_req();
        let common = core_approval_req_to_common(request.clone());
        assert_eq!(common.subject_id, request.subject_id.to_string());
        assert_eq!(common.sn, 7);
        assert_eq!(common.gov_version, 3);
        assert_eq!(common.signer, request.signer.to_string());
        assert_eq!(common.issued_at, 111);
        assert_eq!(common.deadline, 222);
    }
}
