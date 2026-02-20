//! Signature model.
//!

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

/// Signature model for API communication
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
