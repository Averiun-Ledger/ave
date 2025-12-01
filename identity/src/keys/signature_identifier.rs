//! Digital signature identifier with algorithm identification

use crate::common::{AlgorithmIdentifiedBytes, base64_encoding};
use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{DSAlgorithm, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH};

/// Digital signature identifier with algorithm identification
///
/// The output contains:
/// - 1 byte: algorithm identifier
/// - N bytes: actual signature value (length depends on algorithm)
#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Ord,
    PartialOrd,
)]
pub struct SignatureIdentifier {
    inner: AlgorithmIdentifiedBytes<DSAlgorithm>,
}

impl SignatureIdentifier {
    /// Create a new signature identifier
    pub fn new(
        algorithm: DSAlgorithm,
        signature: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let expected_len = algorithm.signature_length();
        Ok(Self {
            inner: AlgorithmIdentifiedBytes::new(
                algorithm,
                signature,
                expected_len,
            )?,
        })
    }

    /// Get the algorithm used
    #[inline]
    pub fn algorithm(&self) -> DSAlgorithm {
        self.inner.algorithm
    }

    /// Get the signature bytes (without identifier)
    #[inline]
    pub fn signature_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the full bytes including algorithm identifier
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner
            .to_bytes_with_prefix(self.inner.algorithm.identifier())
    }

    /// Parse from bytes (includes algorithm identifier)
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidSignatureFormat(
                "Empty bytes".to_string(),
            ));
        }

        let algorithm = DSAlgorithm::from_identifier(bytes[0])?;
        let expected_len = algorithm.signature_length();

        let inner = AlgorithmIdentifiedBytes::from_bytes_with_prefix(
            bytes,
            DSAlgorithm::from_identifier,
            expected_len,
            "SignatureIdentifier",
        )?;

        Ok(Self { inner })
    }

    // Internal method for Base64 encoding
    #[inline]
    fn to_base64(&self) -> String {
        // Format: algorithm_char + base64(signature_bytes)
        // Example: "E" + base64(signature) for Ed25519
        let algorithm_char = self.inner.algorithm.identifier() as char;
        let data_base64 = base64_encoding::encode(&self.inner.bytes);
        format!("{}{}", algorithm_char, data_base64)
    }

    /// Verify the signature against the message and public key
    pub fn verify(
        &self,
        message: &[u8],
        public_key: &[u8],
    ) -> Result<(), CryptoError> {
        match self.inner.algorithm {
            DSAlgorithm::Ed25519 => {
                // Verify public key length
                if public_key.len() != ED25519_PUBLIC_KEY_LENGTH {
                    return Err(CryptoError::InvalidPublicKey(format!(
                        "Invalid public key length: expected {} bytes, got {}",
                        ED25519_PUBLIC_KEY_LENGTH,
                        public_key.len()
                    )));
                }

                // Verify signature length
                if self.inner.bytes.len() != ED25519_SIGNATURE_LENGTH {
                    return Err(CryptoError::InvalidSignatureFormat(format!(
                        "Invalid signature length: expected {} bytes, got {}",
                        ED25519_SIGNATURE_LENGTH,
                        self.inner.bytes.len()
                    )));
                }

                let verifying_key = VerifyingKey::from_bytes(
                    public_key.try_into().map_err(|_| {
                        CryptoError::InvalidPublicKey(
                            "Invalid length".to_string(),
                        )
                    })?,
                )
                .map_err(|e| CryptoError::InvalidPublicKey(e.to_string()))?;

                let signature = Ed25519Signature::from_bytes(
                    self.inner.bytes.as_slice().try_into().map_err(|_| {
                        CryptoError::InvalidSignatureFormat(
                            "Invalid length".to_string(),
                        )
                    })?,
                );

                verifying_key
                    .verify(message, &signature)
                    .map_err(|_| CryptoError::SignatureVerificationFailed)
            }
        }
    }
}

impl fmt::Debug for SignatureIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SignatureIdentifier")
            .field("algorithm", &self.inner.algorithm)
            .field("signature", &base64_encoding::encode(&self.inner.bytes))
            .finish()
    }
}

impl fmt::Display for SignatureIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Serialize for SignatureIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for SignatureIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for SignatureIdentifier {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Format: algorithm_char + base64(signature_bytes)
        // First character is the algorithm identifier
        let mut chars = s.chars();
        let algorithm_char = chars.next().ok_or_else(|| {
            CryptoError::InvalidSignatureFormat("Empty string".to_string())
        })?;

        let algorithm = DSAlgorithm::from_identifier(algorithm_char as u8)?;

        // Rest is base64-encoded signature data
        let data_str: String = chars.collect();
        let signature_bytes = base64_encoding::decode(&data_str)
            .map_err(|e| CryptoError::Base64DecodeError(e.to_string()))?;

        // Validate length
        let expected_len = algorithm.signature_length();
        if signature_bytes.len() != expected_len {
            return Err(CryptoError::InvalidDataLength {
                expected: expected_len,
                actual: signature_bytes.len(),
            });
        }

        Ok(Self {
            inner: AlgorithmIdentifiedBytes {
                algorithm,
                bytes: signature_bytes,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DSA, Ed25519Signer};

    #[test]
    fn test_signature_to_string() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Hello, World!";

        let signature = signer.sign(message).unwrap();
        let sig_str = signature.to_string();

        // Should be able to parse back
        let parsed: SignatureIdentifier = sig_str.parse().unwrap();
        assert_eq!(signature, parsed);
    }

    #[test]
    fn test_signature_verify_wrong_message() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Hello, World!";

        let signature = signer.sign(message).unwrap();
        let public_key = signer.public_key();

        // Should fail with wrong message
        let result = signature.verify(b"Wrong message", public_key.as_bytes());
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_bytes_roundtrip() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Test data";

        let signature = signer.sign(message).unwrap();
        let bytes = signature.to_bytes();

        // First byte should be algorithm identifier 'E'
        assert_eq!(bytes[0], b'E');

        // Should parse back correctly
        let parsed = SignatureIdentifier::from_bytes(&bytes).unwrap();
        assert_eq!(signature, parsed);
    }

    #[test]
    fn test_algorithm_detection() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Test data";

        let signature = signer.sign(message).unwrap();
        let sig_str = signature.to_string();

        // Parse should automatically detect Ed25519
        let parsed: SignatureIdentifier = sig_str.parse().unwrap();
        assert_eq!(parsed.algorithm(), DSAlgorithm::Ed25519);
    }

    #[test]
    fn test_serde_serialization() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Test serialization";

        let signature = signer.sign(message).unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&signature).unwrap();

        // Deserialize back
        let deserialized: SignatureIdentifier =
            serde_json::from_str(&json).unwrap();

        assert_eq!(signature, deserialized);
    }

    #[test]
    fn test_invalid_signature_length() {
        // Create an invalid signature with wrong length
        let invalid_sig = SignatureIdentifier::new(
            DSAlgorithm::Ed25519,
            vec![0u8; 32], // Only 32 bytes instead of 64
        );

        // SignatureIdentifier::new should catch this
        assert!(invalid_sig.is_err());
    }
}
