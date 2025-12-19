//! Type conversions between Bridge API types and internal Core types
//!
//! This module provides conversions between the lightweight ave-common types
//! used for API communication and the internal core types used for business logic.

use std::str::FromStr;

use ave_common::{
    BridgeConfirmRequest, BridgeCreateRequest, BridgeEOLRequest,
    BridgeEventRequest, BridgeFactRequest, BridgeRejectRequest,
    BridgeTransferRequest, Namespace, ValueWrapper,
    identity::{DigestIdentifier, PublicKey},
};
use core::{
    error::Error,
    model::request::{
        ConfirmRequest, CreateRequest, EOLRequest, EventRequest, FactRequest, RejectRequest, SchemaType, TransferRequest
    },
};

pub fn bridge_to_event_request(
    request: BridgeEventRequest,
) -> Result<EventRequest, Error> {
    match request {
        BridgeEventRequest::Create(request) => {
            Ok(EventRequest::Create(bridge_to_create_request(request)?))
        }
        BridgeEventRequest::Fact(request) => {
            Ok(EventRequest::Fact(bridge_to_fact_request(request)?))
        }
        BridgeEventRequest::Transfer(request) => {
            Ok(EventRequest::Transfer(bridge_to_transfer_request(request)?))
        }
        BridgeEventRequest::EOL(request) => {
            Ok(EventRequest::EOL(bridge_to_eol_request(request)?))
        }
        BridgeEventRequest::Confirm(request) => {
            Ok(EventRequest::Confirm(bridge_to_confirm_request(request)?))
        }
        BridgeEventRequest::Reject(request) => {
            Ok(EventRequest::Reject(bridge_to_reject_request(request)?))
        }
    }
}

pub fn bridge_to_reject_request(
    request: BridgeRejectRequest,
) -> Result<RejectRequest, Error> {
    Ok(RejectRequest {
        subject_id: DigestIdentifier::from_str(&request.subject_id).map_err(
            |_| Error::Bridge("Invalid subject identifier".to_string()),
        )?,
    })
}

pub fn bridge_to_create_request(
    request: BridgeCreateRequest,
) -> Result<CreateRequest, Error> {
    Ok(CreateRequest {
        name: request.name,
        description: request.description,
        governance_id: DigestIdentifier::from_str(
            &request.governance_id.unwrap_or_default(),
        )
        .map_err(|_| {
            Error::Bridge("Invalid governance identifier".to_string())
        })?,
        schema_id: SchemaType::from_str(&request.schema_id).map_err(|e| {
            Error::Bridge(e)
        })?,
        namespace: Namespace::from(request.namespace.unwrap_or_default()),
    })
}

pub fn bridge_to_fact_request(
    request: BridgeFactRequest,
) -> Result<FactRequest, Error> {
    Ok(FactRequest {
        subject_id: DigestIdentifier::from_str(&request.subject_id).map_err(
            |_| Error::Bridge("Invalid subject identifier".to_string()),
        )?,
        payload: ValueWrapper(request.payload),
    })
}

pub fn bridge_to_transfer_request(
    request: BridgeTransferRequest,
) -> Result<TransferRequest, Error> {
    Ok(TransferRequest {
        subject_id: DigestIdentifier::from_str(&request.subject_id).map_err(
            |_| Error::Bridge("Invalid subject identifier".to_string()),
        )?,
        new_owner: PublicKey::from_str(&request.new_owner)
            .map_err(|_| Error::Bridge("Invalid public key".to_string()))?,
    })
}

pub fn bridge_to_eol_request(
    request: BridgeEOLRequest,
) -> Result<EOLRequest, Error> {
    Ok(EOLRequest {
        subject_id: DigestIdentifier::from_str(&request.subject_id).map_err(
            |_| Error::Bridge("Invalid subject identifier".to_string()),
        )?,
    })
}

pub fn bridge_to_confirm_request(
    request: BridgeConfirmRequest,
) -> Result<ConfirmRequest, Error> {
    Ok(ConfirmRequest {
        subject_id: DigestIdentifier::from_str(&request.subject_id).map_err(
            |_| Error::Bridge("Invalid subject identifier".to_string()),
        )?,
        name_old_owner: request.name_old_owner,
    })
}

// Convert from Core types to Common types for API responses
use ave_common::{GovsData, RegisterDataSubj, RequestData, TransferSubject};

pub fn core_request_to_common(data: core::request::RequestData) -> RequestData {
    RequestData {
        request_id: data.request_id,
        subject_id: data.subject_id,
    }
}

pub fn core_transfer_to_common(
    transfer: core::node::TransferSubject,
) -> TransferSubject {
    TransferSubject {
        name: transfer.name,
        subject_id: transfer.subject_id,
        new_owner: transfer.new_owner,
        actual_owner: transfer.actual_owner,
    }
}

pub fn core_gov_to_common(gov: core::node::register::GovsData) -> GovsData {
    GovsData {
        governance_id: gov.governance_id,
        active: gov.active,
        name: gov.name,
        description: gov.description,
    }
}

pub fn core_subj_to_common(
    subj: core::node::register::RegisterDataSubj,
) -> RegisterDataSubj {
    RegisterDataSubj {
        subject_id: subj.subject_id,
        schema_id: subj.schema_id.to_string(),
        active: subj.active,
        name: subj.name,
        description: subj.description,
    }
}
