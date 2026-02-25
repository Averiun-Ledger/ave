//! High-level signature structures with metadata
//!
//! This module provides signature structures that include additional metadata
//! like timestamps and content hashes, suitable for auditable signing operations.

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

/// A complete signature that includes metadata
///
/// This structure includes:
/// - The signer's public key
/// - A timestamp of when the signature was created
/// - A hash of the signed content
/// - The cryptographic signature itself
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
    /// The public key of the signer
    pub signer: PublicKey,
    /// Timestamp when the signature was created
    pub timestamp: TimeStamp,
    /// Hash of the content that was signed
    pub content_hash: DigestIdentifier,
    /// The cryptographic signature
    pub value: SignatureIdentifier,
}

impl Signature {
    /// Create a new signature for the given content
    ///
    /// This method:
    /// 1. Captures the current timestamp
    /// 2. Serializes the content together with the timestamp
    /// 3. Hashes the serialized payload using Blake3
    /// 4. Signs the hash with the provided signer
    ///
    /// The timestamp is included in the signed data to prevent replay attacks
    /// and provide temporal context for the signature.
    ///
    /// # Arguments
    /// * `content` - The content to sign (must implement BorshSerialize)
    /// * `signer` - Any signer implementing the DSA trait
    ///
    /// # Example
    /// ```
    /// use ave_identity::signature::Signature;
    /// use ave_identity::keys::Ed25519Signer;
    /// use borsh::{BorshSerialize, BorshDeserialize};
    ///
    /// #[derive(BorshSerialize, BorshDeserialize)]
    /// struct MyData {
    ///     value: String,
    /// }
    ///
    /// let signer = Ed25519Signer::generate().expect("Failed to generate signer");
    /// let data = MyData { value: "test".to_string() };
    /// let signature = Signature::new(&data, &signer).unwrap();
    /// ```
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

    /// Verify the signature against the given content
    ///
    /// # Arguments
    /// * `content` - The content to verify (must implement BorshSerialize)
    ///
    /// # Returns
    /// `Ok(())` if the signature is valid, `Err(CryptoError)` otherwise
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

/// A signed data structure that pairs content with its signature
///
/// This generic structure can wrap any type that implements BorshSerialize
/// and BorshDeserialize, ensuring the data and its signature are kept together.
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
    /// The actual data content
    content: T,
    /// The signature for this content
    signature: Signature,
}

impl<T: BorshSerialize + BorshDeserialize + Clone> Signed<T> {
    /// Create a new signed data structure
    ///
    /// # Arguments
    /// * `content` - The content to sign
    /// * `signer` - Any signer implementing the DSA trait
    pub fn new(content: T, signer: &dyn DSA) -> Result<Self, CryptoError> {
        let signature = Signature::new(&content, signer)?;
        Ok(Self { content, signature })
    }

    /// Create from existing content and signature
    pub const fn from_parts(content: T, signature: Signature) -> Self {
        Self { content, signature }
    }

    /// Verify the signature matches the content
    pub fn verify(&self) -> Result<(), CryptoError> {
        self.signature.verify(&self.content)
    }

    /// Get the signer's public key
    pub const fn signature(&self) -> &Signature {
        &self.signature
    }

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
