//! Type conversions between Bridge API types and internal Core types
//!
//! This module re-exports and provides convenience functions for conversions
//! that are now implemented as traits in ave-common.

use ave_common::bridge::conversions::ConversionError;
use ave_common::{
    BridgeConfirmRequest, BridgeCreateRequest, BridgeEOLRequest,
    BridgeEventRequest, BridgeFactRequest, BridgeRejectRequest,
    BridgeTransferRequest,
};
use core::{
    error::Error,
    model::request::{
        ConfirmRequest, CreateRequest, EOLRequest, EventRequest, FactRequest,
        RejectRequest, TransferRequest,
    },
};

// ============================================================================
// Conversion functions that delegate to the From/TryFrom traits
// ============================================================================

pub fn bridge_to_event_request(
    request: BridgeEventRequest,
) -> Result<EventRequest, Error> {
    EventRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

pub fn bridge_to_reject_request(
    request: BridgeRejectRequest,
) -> Result<RejectRequest, Error> {
    RejectRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

pub fn bridge_to_create_request(
    request: BridgeCreateRequest,
) -> Result<CreateRequest, Error> {
    CreateRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

pub fn bridge_to_fact_request(
    request: BridgeFactRequest,
) -> Result<FactRequest, Error> {
    FactRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

pub fn bridge_to_transfer_request(
    request: BridgeTransferRequest,
) -> Result<TransferRequest, Error> {
    TransferRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

pub fn bridge_to_eol_request(
    request: BridgeEOLRequest,
) -> Result<EOLRequest, Error> {
    EOLRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

pub fn bridge_to_confirm_request(
    request: BridgeConfirmRequest,
) -> Result<ConfirmRequest, Error> {
    ConfirmRequest::try_from(request).map_err(|e| Error::Bridge(e.to_string()))
}

// ============================================================================
// Convert from Core types to Common types for API responses
// ============================================================================

use ave_common::{GovsData, RequestData, SubjsData, TransferSubject};

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

pub fn core_subj_to_common(subj: core::node::register::SubjsData) -> SubjsData {
    SubjsData {
        subject_id: subj.subject_id,
        schema_id: subj.schema_id.to_string(),
        active: subj.active,
        name: subj.name,
        description: subj.description,
    }
}
