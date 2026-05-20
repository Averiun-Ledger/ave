//! API representation of signed metadata.

use crate::{
    error::SignatureError,
    identity::{
        DigestIdentifier, PublicKey, Signature, SignatureIdentifier, TimeStamp,
    },
};
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, str::FromStr};

#[cfg(feature = "openapi")]
use utoipa::ToSchema;

#[cfg(feature = "typescript")]
use ts_rs::TS;

/// Signature payload used by bridge requests and responses.
#[derive(Serialize, Deserialize, Debug, Clone)]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
pub struct BridgeSignature {
    /// Public key of the issuer
    pub signer: String,
    /// Timestamp at which the signature was made
    pub timestamp: u64,
    /// Signature value
    pub value: String,
    /// Content hash
    pub content_hash: String,
}

impl From<Signature> for BridgeSignature {
    fn from(signature: Signature) -> Self {
        Self {
            signer: signature.signer.to_string(),
            timestamp: signature.timestamp.as_nanos(),
            value: signature.value.to_string(),
            content_hash: signature.content_hash.to_string(),
        }
    }
}

impl TryFrom<BridgeSignature> for Signature {
    type Error = SignatureError;

    fn try_from(signature: BridgeSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            signer: PublicKey::from_str(&signature.signer)
                .map_err(|e| SignatureError::InvalidPublicKey(e.to_string()))?,
            timestamp: TimeStamp::from_nanos(signature.timestamp),
            value: SignatureIdentifier::from_str(&signature.value)
                .map_err(|e| SignatureError::InvalidSignature(e.to_string()))?,
            content_hash: DigestIdentifier::from_str(&signature.content_hash)
                .map_err(|e| {
                SignatureError::InvalidContentHash(e.to_string())
            })?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::keys::Ed25519Signer;
    use borsh::BorshSerialize;

    #[derive(Debug, Clone, PartialEq, Eq, BorshSerialize)]
    struct TestContent {
        data: String,
    }

    #[test]
    fn test_bridge_signature_from_signature_roundtrip() {
        let signer = Ed25519Signer::generate().unwrap();
        let content = TestContent {
            data: "hello".to_string(),
        };
        let signature = Signature::new(&content, &signer).unwrap();

        let bridge: BridgeSignature = signature.clone().into();
        assert!(!bridge.signer.is_empty());
        assert!(bridge.timestamp > 0);
        assert!(!bridge.value.is_empty());
        assert!(!bridge.content_hash.is_empty());

        let back: Signature = bridge.try_into().unwrap();
        assert_eq!(signature.signer, back.signer);
        assert_eq!(signature.timestamp, back.timestamp);
        assert_eq!(signature.value, back.value);
        assert_eq!(signature.content_hash, back.content_hash);
    }

    #[test]
    fn test_bridge_signature_try_from_invalid_signer() {
        let bridge = BridgeSignature {
            signer: "not-a-valid-key".to_string(),
            timestamp: 0,
            value: "Eabc".to_string(),
            content_hash: DigestIdentifier::default().to_string(),
        };
        let result: Result<Signature, _> = bridge.try_into();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignatureError::InvalidPublicKey(_)));
    }

    #[test]
    fn test_bridge_signature_try_from_invalid_signature() {
        let signer = Ed25519Signer::generate().unwrap();
        let content = TestContent {
            data: "test".to_string(),
        };
        let signature = Signature::new(&content, &signer).unwrap();

        let bridge = BridgeSignature {
            signer: signature.signer.to_string(),
            timestamp: 0,
            value: "not-valid".to_string(),
            content_hash: DigestIdentifier::default().to_string(),
        };
        let result: Result<Signature, _> = bridge.try_into();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignatureError::InvalidSignature(_)));
    }

    #[test]
    fn test_bridge_signature_try_from_invalid_content_hash() {
        let signer = Ed25519Signer::generate().unwrap();
        let content = TestContent {
            data: "test".to_string(),
        };
        let signature = Signature::new(&content, &signer).unwrap();

        let bridge = BridgeSignature {
            signer: signature.signer.to_string(),
            timestamp: 0,
            value: signature.value.to_string(),
            content_hash: "bad-hash".to_string(),
        };
        let result: Result<Signature, _> = bridge.try_into();
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignatureError::InvalidContentHash(_)));
    }

    #[test]
    fn test_bridge_signature_serde_rejects_missing_fields() {
        // Missing required fields should fail deserialization.
        let json = r#"{"signer":"Eabc","timestamp":123}"#;
        assert!(serde_json::from_str::<BridgeSignature>(json).is_err());
    }
}
