//! Signed values with metadata.
//!
//! These types keep the signature, signer, timestamp and content hash together
//! so callers can store or transmit a self-describing signed payload.

use crate::{
    error::CryptoError,
    hash::{BLAKE3_HASHER, DigestIdentifier, Hash as HashTrait},
    keys::{DSA, PublicKey, SignatureIdentifier},
    timestamp::TimeStamp,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::hash::Hash;
use subtle::ConstantTimeEq;

/// Signature metadata plus the signature bytes.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Hash,
    Ord,
    PartialOrd,
)]
pub struct Signature {
    /// Public key of the signer.
    pub signer: PublicKey,
    /// Creation timestamp.
    pub timestamp: TimeStamp,
    /// Hash of the serialized content and timestamp.
    pub content_hash: DigestIdentifier,
    /// Signature bytes.
    pub value: SignatureIdentifier,
}

impl Signature {
    /// Signs `content`.
    ///
    /// The method serializes `(content, timestamp)` with Borsh, hashes the
    /// result with Blake3 and signs that digest.
    pub fn new<T: BorshSerialize>(
        content: &T,
        signer: &dyn DSA,
    ) -> Result<Self, CryptoError> {
        let timestamp = TimeStamp::now();

        // Serialize content + timestamp together for signing
        // This single serialization is used for both hashing and later verification
        let signing_payload = (content, &timestamp);
        let payload_bytes = borsh::to_vec(&signing_payload)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        // Hash the payload
        let content_hash = BLAKE3_HASHER.hash(&payload_bytes);

        // Sign the hash (not the full payload for efficiency)
        let signature_bytes =
            signer.sign(content_hash.hash_bytes()).map_err(|_| {
                CryptoError::SigningError(
                    "Failed to create signature".to_string(),
                )
            })?;

        // Create public key wrapper with the algorithm from the signer
        let public_key =
            PublicKey::new(signer.algorithm(), signer.public_key_bytes())?;

        Ok(Self {
            signer: public_key,
            timestamp,
            content_hash,
            value: signature_bytes,
        })
    }

    /// Verifies this signature against `content`.
    pub fn verify<T: BorshSerialize>(
        &self,
        content: &T,
    ) -> Result<(), CryptoError> {
        // Recreate the signing payload
        let signing_payload = (content, &self.timestamp);
        let payload_bytes = borsh::to_vec(&signing_payload)
            .map_err(|e| CryptoError::SerializationError(e.to_string()))?;

        // Hash the payload
        let computed_hash = BLAKE3_HASHER.hash(&payload_bytes);

        // Verify hash matches using constant-time comparison
        let hash_matches = computed_hash
            .hash_bytes()
            .ct_eq(self.content_hash.hash_bytes());
        if hash_matches.unwrap_u8() != 1 {
            return Err(CryptoError::HashError(
                "Content hash mismatch".to_string(),
            ));
        }

        // Verify the signature
        self.signer
            .verify(self.content_hash.hash_bytes(), &self.value)
    }
}

/// Content bundled together with its signature metadata.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
    Hash,
)]
pub struct Signed<T>
where
    T: BorshSerialize + BorshDeserialize + Clone,
{
    /// Signed content.
    content: T,
    /// Signature metadata for `content`.
    signature: Signature,
}

impl<T: BorshSerialize + BorshDeserialize + Clone> Signed<T> {
    /// Signs `content` and stores the resulting metadata alongside it.
    pub fn new(content: T, signer: &dyn DSA) -> Result<Self, CryptoError> {
        let signature = Signature::new(&content, signer)?;
        Ok(Self { content, signature })
    }

    /// Creates a signed value from pre-existing parts.
    pub const fn from_parts(content: T, signature: Signature) -> Self {
        Self { content, signature }
    }

    /// Verifies the stored content against the stored signature.
    pub fn verify(&self) -> Result<(), CryptoError> {
        self.signature.verify(&self.content)
    }

    /// Returns the signature metadata.
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

    /// Returns the signed content.
    pub const fn content(&self) -> &T {
        &self.content
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Ed25519Signer;

    #[derive(
        Debug,
        Clone,
        PartialEq,
        Eq,
        BorshSerialize,
        BorshDeserialize,
        Serialize,
        Deserialize,
    )]
    struct TestData {
        value: String,
        number: u64,
    }

    #[test]
    fn test_signature_creation_and_verification() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "test message".to_string(),
            number: 42,
        };

        let signature = Signature::new(&data, &signer).unwrap();
        assert!(signature.verify(&data).is_ok());
    }

    #[test]
    fn test_signature_fails_with_wrong_content() {
        let signer = Ed25519Signer::generate().unwrap();
        let data1 = TestData {
            value: "message 1".to_string(),
            number: 1,
        };
        let data2 = TestData {
            value: "message 2".to_string(),
            number: 2,
        };

        let signature = Signature::new(&data1, &signer).unwrap();
        assert!(signature.verify(&data2).is_err());
    }

    #[test]
    fn test_signed_creation() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "signed data".to_string(),
            number: 123,
        };

        let signed = Signed::new(data.clone(), &signer).unwrap();
        assert_eq!(signed.content, data);
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_signed_verification() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "verify me".to_string(),
            number: 999,
        };

        let signed = Signed::new(data, &signer).unwrap();
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_signed_from_parts() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "test".to_string(),
            number: 1,
        };

        let signature = Signature::new(&data, &signer).unwrap();
        let signed = Signed::from_parts(data.clone(), signature);

        assert_eq!(signed.content().value, "test");
        assert!(signed.verify().is_ok());
    }

    #[test]
    fn test_signer_accessor() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "test".to_string(),
            number: 1,
        };

        let signed = Signed::new(data, &signer).unwrap();
        let public_key = signed.signature().signer.clone();

        // Verify the public key matches
        let expected_pubkey = PublicKey::new(
            crate::keys::DSAlgorithm::Ed25519,
            signer.public_key_bytes(),
        )
        .unwrap();

        assert_eq!(public_key, expected_pubkey);
    }

    #[test]
    fn test_timestamp_is_set() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "test".to_string(),
            number: 1,
        };

        let before = TimeStamp::now();
        let signed = Signed::new(data, &signer).unwrap();
        let after = TimeStamp::now();

        let ts = signed.signature().timestamp;
        assert!(ts >= before);
        assert!(ts <= after);
    }

    #[test]
    fn test_signature_serialization() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "serialize me".to_string(),
            number: 456,
        };

        let signature = Signature::new(&data, &signer).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&signature).unwrap();

        // Deserialize back
        let deserialized: Signature = serde_json::from_str(&json).unwrap();

        // Should still verify
        assert!(deserialized.verify(&data).is_ok());
    }

    #[test]
    fn test_signed_serialization() {
        let signer = Ed25519Signer::generate().unwrap();
        let data = TestData {
            value: "roundtrip".to_string(),
            number: 789,
        };

        let signed = Signed::new(data, &signer).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&signed).unwrap();

        // Deserialize back
        let deserialized: Signed<TestData> =
            serde_json::from_str(&json).unwrap();

        // Should still verify
        assert!(deserialized.verify().is_ok());
        assert_eq!(deserialized.content().value, "roundtrip");
    }
}
