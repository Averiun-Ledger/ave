//! Signature model.
//!

use borsh::{BorshDeserialize, BorshSerialize};
use identity::{
    DigestIdentifier, PublicKey, Signature, SignatureIdentifier, Signed, TimeStamp
};
use core::{
    error::Error,
};
use serde::{Deserialize, Serialize};

use std::{fmt::Debug, str::FromStr};

/// Signature model.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BridgeSignature {
    /// Public key of the issuer
    signer: String, // PublicKey
    /// Timestamp at which the signature was made
    timestamp: u64,
    /// Signature value
    value: String, // SignatureIdentifier,
    /// Content hash
    content_hash: String,
}

impl From<Signature> for BridgeSignature {
    fn from(signature: Signature) -> Self {
        Self {
            signer: signature.signer.to_string(),
            timestamp: signature.timestamp.0,
            value: signature.value.to_string(),
            content_hash: signature.content_hash.to_string(),
        }
    }
}

impl TryFrom<BridgeSignature> for Signature {
    type Error = Error;
    fn try_from(signature: BridgeSignature) -> Result<Self, Self::Error> {
        Ok(Self {
            signer: PublicKey::from_str(&signature.signer)
                .map_err(|_| Error::Bridge("key identifier".to_owned()))?,
            timestamp: TimeStamp(signature.timestamp),
            value: SignatureIdentifier::from_str(&signature.value).map_err(
                |_| Error::Bridge("signature identifier".to_owned()),
            )?,
            content_hash: DigestIdentifier::from_str(&signature.content_hash)
                .map_err(|_| {
                Error::Bridge("digest identifier".to_owned())
            })?,
        })
    }
}

/// Signed content.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BridgeSigned<T>
where
    T: Clone + Debug,
{
    /// Content
    #[serde(flatten)]
    pub content: T,
    /// Signature
    pub signature: BridgeSignature,
}

impl<C, T> From<Signed<C>> for BridgeSigned<T>
where
    C: BorshDeserialize + BorshSerialize + Clone + Debug,
    T: From<C> + Clone + Debug,
{
    fn from(signed: Signed<C>) -> Self {
        Self {
            content: signed.content.into(),
            signature: signed.signature.into(),
        }
    }
}

impl<C, T> TryFrom<BridgeSigned<T>> for Signed<C>
where
    C: BorshDeserialize + BorshSerialize + Clone + Debug,
    T: Into<C> + Clone + Debug,
{
    type Error = Error;
    fn try_from(signed: BridgeSigned<T>) -> Result<Self, Error> {
        Ok(Self {
            content: signed.content.into(),
            signature: signed.signature.try_into()?,
        })
    }
}
