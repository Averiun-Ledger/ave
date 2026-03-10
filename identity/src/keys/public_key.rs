//! Public key wrapper with an embedded algorithm identifier.

use crate::common::{AlgorithmIdentifiedBytes, base64_encoding};
use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{DSAlgorithm, SignatureIdentifier};

/// Public key bytes plus the algorithm used to interpret them.
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
pub struct PublicKey {
    inner: AlgorithmIdentifiedBytes<DSAlgorithm>,
}

impl PublicKey {
    /// Creates a public key and validates the byte length for `algorithm`.
    pub fn new(
        algorithm: DSAlgorithm,
        key_bytes: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let expected_len = algorithm.public_key_length();
        Ok(Self {
            inner: AlgorithmIdentifiedBytes::new(
                algorithm,
                key_bytes,
                expected_len,
            )?,
        })
    }

    /// Returns the key algorithm.
    #[inline]
    pub const fn algorithm(&self) -> DSAlgorithm {
        self.inner.algorithm
    }

    /// Returns the raw key bytes, without the identifier.
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Serializes the key as `identifier || key_bytes`.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner
            .to_bytes_with_prefix(self.inner.algorithm.identifier())
    }

    /// Parses a key from `identifier || key_bytes`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CryptoError> {
        if bytes.is_empty() {
            return Err(CryptoError::InvalidPublicKey(
                "Empty bytes".to_string(),
            ));
        }

        let algorithm = DSAlgorithm::from_identifier(bytes[0])?;
        let expected_len = algorithm.public_key_length();

        let inner = AlgorithmIdentifiedBytes::from_bytes_with_prefix(
            bytes,
            DSAlgorithm::from_identifier,
            expected_len,
            "PublicKey",
        )?;

        Ok(Self { inner })
    }

    // Internal method for Base64 encoding
    #[inline]
    fn to_base64(&self) -> String {
        // Special case: empty key serializes as empty string
        if self.is_empty() {
            String::new()
        } else {
            // Format: algorithm_char + base64(key_bytes)
            // Example: "E" + base64(public_key) for Ed25519
            let algorithm_char = self.inner.algorithm.identifier() as char;
            let data_base64 = base64_encoding::encode(&self.inner.bytes);
            format!("{}{}", algorithm_char, data_base64)
        }
    }

    /// Verifies `signature` against `message`.
    pub fn verify(
        &self,
        message: &[u8],
        signature: &SignatureIdentifier,
    ) -> Result<(), CryptoError> {
        if self.inner.algorithm != signature.algorithm() {
            return Err(CryptoError::InvalidSignatureFormat(format!(
                "Algorithm mismatch: key is {}, signature is {}",
                self.inner.algorithm,
                signature.algorithm()
            )));
        }
        signature.verify(message, &self.inner.bytes)
    }

    /// Returns `true` when this is the empty placeholder value.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }
}

impl Default for PublicKey {
    fn default() -> Self {
        Self {
            inner: AlgorithmIdentifiedBytes {
                algorithm: DSAlgorithm::Ed25519,
                bytes: Vec::new(),
            },
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PublicKey")
            .field("algorithm", &self.inner.algorithm)
            .field("key", &base64_encoding::encode(&self.inner.bytes))
            .finish()
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Serialize for PublicKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for PublicKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for PublicKey {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Special case: empty string deserializes to default (empty) key
        if s.is_empty() {
            return Ok(Self::default());
        }

        // Format: algorithm_char + base64(key_bytes)
        // First character is the algorithm identifier
        let mut chars = s.chars();
        let algorithm_char = chars.next().ok_or_else(|| {
            CryptoError::InvalidPublicKey("Empty string".to_string())
        })?;

        let algorithm = DSAlgorithm::from_identifier(algorithm_char as u8)?;

        // Rest is base64-encoded key data
        let data_str: String = chars.collect();
        let key_bytes = base64_encoding::decode(&data_str)
            .map_err(|e| CryptoError::Base64DecodeError(e.to_string()))?;

        // Validate length
        let expected_len = algorithm.public_key_length();
        if key_bytes.len() != expected_len {
            return Err(CryptoError::InvalidDataLength {
                expected: expected_len,
                actual: key_bytes.len(),
            });
        }

        Ok(Self {
            inner: AlgorithmIdentifiedBytes {
                algorithm,
                bytes: key_bytes,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{DSA, Ed25519Signer};

    #[test]
    fn test_public_key_wrapper() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Test message";

        let signature = signer.sign(message).unwrap();

        // Create public key wrapper
        let public_key =
            PublicKey::new(DSAlgorithm::Ed25519, signer.public_key_bytes())
                .unwrap();

        // Verify using wrapper
        assert!(public_key.verify(message, &signature).is_ok());

        // Test serialization
        let key_str = public_key.to_string();

        // Ed25519 public key should start with 'E'
        assert!(
            key_str.starts_with('E'),
            "Ed25519 public key should start with 'E', got: {}",
            key_str
        );

        let parsed: PublicKey = key_str.parse().unwrap();
        assert_eq!(public_key, parsed);
    }

    #[test]
    fn test_public_key_serde() {
        let signer = Ed25519Signer::generate().unwrap();

        let public_key =
            PublicKey::new(DSAlgorithm::Ed25519, signer.public_key_bytes())
                .unwrap();

        // Serialize to JSON
        let json = serde_json::to_string(&public_key).unwrap();

        // Deserialize back
        let deserialized: PublicKey = serde_json::from_str(&json).unwrap();

        assert_eq!(public_key, deserialized);
    }

    #[test]
    fn test_default_public_key() {
        let default_key = PublicKey::default();

        // Should have Ed25519 algorithm
        assert_eq!(default_key.algorithm(), DSAlgorithm::Ed25519);

        // Should have empty bytes
        assert_eq!(default_key.as_bytes().len(), 0);

        // Should be marked as empty
        assert!(default_key.is_empty());
    }

    #[test]
    fn test_is_empty() {
        // Default key should be empty
        let empty_key = PublicKey::default();
        assert!(empty_key.is_empty());

        // Real key should not be empty
        let signer = Ed25519Signer::generate().unwrap();
        let real_key =
            PublicKey::new(DSAlgorithm::Ed25519, signer.public_key_bytes())
                .unwrap();
        assert!(!real_key.is_empty());
    }
}
