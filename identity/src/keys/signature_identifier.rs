//! Signature wrapper with an embedded algorithm identifier.

use crate::common::{AlgorithmIdentifiedBytes, base64_encoding};
use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use ed25519_dalek::{Signature as Ed25519Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{DSAlgorithm, ED25519_PUBLIC_KEY_LENGTH, ED25519_SIGNATURE_LENGTH};

/// Signature bytes plus the algorithm used to verify them.
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
    /// Creates a signature and validates the byte length for `algorithm`.
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

    /// Returns the signature algorithm.
    #[inline]
    pub const fn algorithm(&self) -> DSAlgorithm {
        self.inner.algorithm
    }

    /// Returns the raw signature bytes, without the identifier.
    #[inline]
    pub fn signature_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Serializes the signature as `identifier || signature_bytes`.
    #[inline]
    pub fn to_bytes(&self) -> Vec<u8> {
        self.inner
            .to_bytes_with_prefix(self.inner.algorithm.identifier())
    }

    /// Parses a signature from `identifier || signature_bytes`.
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

    /// Verifies `message` with `public_key`.
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
    fn test_signature_identifier_from_str_invalid_algorithm() {
        let err = "Xabc123".parse::<SignatureIdentifier>().unwrap_err();
        assert!(
            matches!(err, CryptoError::UnknownAlgorithm(_)),
            "expected UnknownAlgorithm, got {:?}",
            err
        );
    }

    #[test]
    fn test_signature_identifier_from_str_invalid_base64() {
        let err = "E!!!".parse::<SignatureIdentifier>().unwrap_err();
        assert!(
            matches!(err, CryptoError::Base64DecodeError(_)),
            "expected Base64DecodeError, got {:?}",
            err
        );
    }

    #[test]
    fn test_from_bytes_empty() {
        let err = SignatureIdentifier::from_bytes(&[]).unwrap_err();
        match err {
            CryptoError::InvalidSignatureFormat(msg) => {
                assert_eq!(msg, "Empty bytes");
            }
            other => panic!("expected InvalidSignatureFormat, got {:?}", other),
        }
    }

    #[test]
    fn test_from_bytes_invalid_length() {
        // Valid identifier 'E' (0x45) for Ed25519, but wrong signature length
        let err = SignatureIdentifier::from_bytes(&[0x45, 1, 2, 3]).unwrap_err();
        match err {
            CryptoError::InvalidDataLength { expected, actual } => {
                assert_eq!(expected, 65); // 1 prefix + 64 signature
                assert_eq!(actual, 4);
            }
            other => panic!("expected InvalidDataLength, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_invalid_public_key_length() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Hello";
        let sig = signer.sign(message).unwrap();
        let err = sig.verify(message, &[1, 2, 3]).unwrap_err();
        match err {
            CryptoError::InvalidPublicKey(msg) => {
                assert!(msg.contains("Invalid public key length"));
            }
            other => panic!("expected InvalidPublicKey, got {:?}", other),
        }
    }

    #[test]
    fn test_verify_invalid_signature_length() {
        let signer = Ed25519Signer::generate().unwrap();
        let message = b"Hello";
        let sig = signer.sign(message).unwrap();

        // Serialize via Borsh, then manually truncate the inner bytes to 32.
        // Borsh layout: [algorithm (1), vec_len (4 u32 little-endian), sig_bytes (64)] = 69 bytes.
        let mut bytes = borsh::to_vec(&sig).unwrap();
        bytes[1..5].copy_from_slice(&(32u32).to_le_bytes());
        bytes.truncate(1 + 4 + 32);
        let corrupted: SignatureIdentifier = borsh::from_slice(&bytes).unwrap();

        let public_key = signer.public_key();
        let err = corrupted.verify(message, public_key.as_bytes()).unwrap_err();
        match err {
            CryptoError::InvalidSignatureFormat(msg) => {
                assert!(msg.contains("Invalid signature length"));
            }
            other => panic!("expected InvalidSignatureFormat, got {:?}", other),
        }
    }
}
