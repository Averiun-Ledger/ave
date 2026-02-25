//! Type conversions between Bridge API types and internal types
//!
//! This module provides trait-based conversions between the lightweight bridge types
//! used for API communication and the internal types used for business logic.

use std::str::FromStr;

use ave_identity::{DigestIdentifier, PublicKey, Signed};

use crate::{
    Namespace, SchemaType, ValueWrapper,
    bridge::request::{
        BridgeConfirmRequest, BridgeCreateRequest, BridgeEOLRequest,
        BridgeEventRequest, BridgeFactRequest, BridgeRejectRequest,
        BridgeSignedEventRequest, BridgeTransferRequest,
    },
    error::ConversionError,
    request::{
        ConfirmRequest, CreateRequest, EOLRequest, EventRequest, FactRequest,
        RejectRequest, TransferRequest,
    },
    signature::BridgeSignature,
};

// ============================================================================
// EventRequest conversions
// ============================================================================

impl From<Signed<EventRequest>> for BridgeSignedEventRequest {
    fn from(value: Signed<EventRequest>) -> Self {
        let request = BridgeEventRequest::from(value.content().clone());
        let signature = Some(BridgeSignature::from(value.signature().clone()));

        Self { request, signature }
    }
}

impl From<EventRequest> for BridgeSignedEventRequest {
    fn from(value: EventRequest) -> Self {
        let request = BridgeEventRequest::from(value);
        let signature = None;

        Self { request, signature }
    }
}

impl From<EventRequest> for BridgeEventRequest {
    fn from(request: EventRequest) -> Self {
        match request {
            EventRequest::Create(req) => Self::Create(req.into()),
            EventRequest::Fact(req) => Self::Fact(req.into()),
            EventRequest::Transfer(req) => {
                Self::Transfer(req.into())
            }
            EventRequest::EOL(req) => Self::Eol(req.into()),
            EventRequest::Confirm(req) => {
                Self::Confirm(req.into())
            }
            EventRequest::Reject(req) => Self::Reject(req.into()),
        }
    }
}

impl TryFrom<BridgeEventRequest> for EventRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeEventRequest) -> Result<Self, Self::Error> {
        match request {
            BridgeEventRequest::Create(req) => {
                Ok(Self::Create(req.try_into()?))
            }
            BridgeEventRequest::Fact(req) => {
                Ok(Self::Fact(req.try_into()?))
            }
            BridgeEventRequest::Transfer(req) => {
                Ok(Self::Transfer(req.try_into()?))
            }
            BridgeEventRequest::Eol(req) => {
                Ok(Self::EOL(req.try_into()?))
            }
            BridgeEventRequest::Confirm(req) => {
                Ok(Self::Confirm(req.try_into()?))
            }
            BridgeEventRequest::Reject(req) => {
                Ok(Self::Reject(req.try_into()?))
            }
        }
    }
}

// ============================================================================
// CreateRequest conversions
// ============================================================================

impl From<CreateRequest> for BridgeCreateRequest {
    fn from(request: CreateRequest) -> Self {
        Self {
            name: request.name,
            description: request.description,
            governance_id: Some(request.governance_id.to_string()),
            schema_id: request.schema_id.to_string(),
            namespace: Some(request.namespace.to_string()),
        }
    }
}

impl TryFrom<BridgeCreateRequest> for CreateRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeCreateRequest) -> Result<Self, Self::Error> {
        let governance_id = if let Some(governance_id) = request.governance_id {
            DigestIdentifier::from_str(&governance_id).map_err(|e| {
                ConversionError::InvalidGovernanceId(e.to_string())
            })?
        } else {
            DigestIdentifier::default()
        };

        let schema_id = SchemaType::from_str(&request.schema_id)
            .map_err(ConversionError::InvalidSchemaId)?;

        let namespace = if let Some(namespace) = request.namespace {
            Namespace::from(namespace)
        } else {
            Namespace::new()
        };

        Ok(Self {
            name: request.name,
            description: request.description,
            governance_id,
            schema_id,
            namespace,
        })
    }
}

// ============================================================================
// FactRequest conversions
// ============================================================================

impl From<FactRequest> for BridgeFactRequest {
    fn from(request: FactRequest) -> Self {
        Self {
            subject_id: request.subject_id.to_string(),
            payload: request.payload.0,
        }
    }
}

impl TryFrom<BridgeFactRequest> for FactRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeFactRequest) -> Result<Self, Self::Error> {
        let subject_id = DigestIdentifier::from_str(&request.subject_id)
            .map_err(|e| ConversionError::InvalidSubjectId(e.to_string()))?;

        Ok(Self {
            subject_id,
            payload: ValueWrapper(request.payload),
        })
    }
}

// ============================================================================
// TransferRequest conversions
// ============================================================================

impl From<TransferRequest> for BridgeTransferRequest {
    fn from(request: TransferRequest) -> Self {
        Self {
            subject_id: request.subject_id.to_string(),
            new_owner: request.new_owner.to_string(),
        }
    }
}

impl TryFrom<BridgeTransferRequest> for TransferRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeTransferRequest) -> Result<Self, Self::Error> {
        let subject_id = DigestIdentifier::from_str(&request.subject_id)
            .map_err(|e| ConversionError::InvalidSubjectId(e.to_string()))?;

        let new_owner = PublicKey::from_str(&request.new_owner)
            .map_err(|e| ConversionError::InvalidPublicKey(e.to_string()))?;

        Ok(Self {
            subject_id,
            new_owner,
        })
    }
}

// ============================================================================
// EOLRequest conversions
// ============================================================================

impl From<EOLRequest> for BridgeEOLRequest {
    fn from(request: EOLRequest) -> Self {
        Self {
            subject_id: request.subject_id.to_string(),
        }
    }
}

impl TryFrom<BridgeEOLRequest> for EOLRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeEOLRequest) -> Result<Self, Self::Error> {
        let subject_id = DigestIdentifier::from_str(&request.subject_id)
            .map_err(|e| ConversionError::InvalidSubjectId(e.to_string()))?;

        Ok(Self { subject_id })
    }
}

// ============================================================================
// ConfirmRequest conversions
// ============================================================================

impl From<ConfirmRequest> for BridgeConfirmRequest {
    fn from(request: ConfirmRequest) -> Self {
        Self {
            subject_id: request.subject_id.to_string(),
            name_old_owner: request.name_old_owner,
        }
    }
}

impl TryFrom<BridgeConfirmRequest> for ConfirmRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeConfirmRequest) -> Result<Self, Self::Error> {
        let subject_id = DigestIdentifier::from_str(&request.subject_id)
            .map_err(|e| ConversionError::InvalidSubjectId(e.to_string()))?;

        Ok(Self {
            subject_id,
            name_old_owner: request.name_old_owner,
        })
    }
}

// ============================================================================
// RejectRequest conversions
// ============================================================================

impl From<RejectRequest> for BridgeRejectRequest {
    fn from(request: RejectRequest) -> Self {
        Self {
            subject_id: request.subject_id.to_string(),
        }
    }
}

impl TryFrom<BridgeRejectRequest> for RejectRequest {
    type Error = ConversionError;

    fn try_from(request: BridgeRejectRequest) -> Result<Self, Self::Error> {
        let subject_id = DigestIdentifier::from_str(&request.subject_id)
            .map_err(|e| ConversionError::InvalidSubjectId(e.to_string()))?;

        Ok(Self { subject_id })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_fact_request_conversion() {
        let bridge_fact = BridgeFactRequest {
            subject_id: "BKZgYibuHNJjiNS179FUDpLGgdLq0C04TZRGb6AXMd1s"
                .to_string(),
            payload: json!({"test": "value"}),
        };

        let fact: Result<FactRequest, _> = bridge_fact.clone().try_into();
        assert!(fact.is_ok());

        let fact = fact.unwrap();
        let bridge_back: BridgeFactRequest = fact.into();
        assert_eq!(bridge_back.subject_id, bridge_fact.subject_id);
    }

    #[test]
    fn test_create_request_conversion() {
        let bridge_create = BridgeCreateRequest {
            name: Some("Test".to_string()),
            description: Some("Test description".to_string()),
            governance_id: Some(
                "BKZgYibuHNJjiNS179FUDpLGgdLq0C04TZRGb6AXMd1s".to_string(),
            ),
            schema_id: "governance".to_string(),
            namespace: Some("test.namespace".to_string()),
        };

        let create: Result<CreateRequest, _> = bridge_create.try_into();
        assert!(create.is_ok());
    }

    #[test]
    fn test_create_request_missing_governance_id() {
        let bridge_create = BridgeCreateRequest {
            name: Some("Test".to_string()),
            description: Some("Test description".to_string()),
            governance_id: None,
            schema_id: "governance".to_string(),
            namespace: Some("test.namespace".to_string()),
        };

        let create: Result<CreateRequest, _> = bridge_create.try_into();
        assert!(create.is_ok());
    }

    #[test]
    fn test_invalid_subject_id() {
        let bridge_fact = BridgeFactRequest {
            subject_id: "invalid_id".to_string(),
            payload: json!({"test": "value"}),
        };

        let fact: Result<FactRequest, _> = bridge_fact.try_into();
        assert!(fact.is_err());
        assert!(matches!(
            fact.unwrap_err(),
            ConversionError::InvalidSubjectId(_)
        ));
    }
}
