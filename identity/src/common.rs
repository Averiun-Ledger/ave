//! Common utilities for algorithm-identified structures
//!
//! This module provides shared functionality for structures that use
//! 1-byte algorithm identifiers as prefixes.

use base64::{Engine as _, engine::general_purpose};
use borsh::{BorshDeserialize, BorshSerialize};
use std::fmt;

/// Base64 encoding/decoding utilities using URL-safe encoding without padding
pub mod base64_encoding {
    use super::*;

    /// Encode bytes to Base64 URL-safe string (no padding)
    #[inline]
    pub fn encode(bytes: &[u8]) -> String {
        general_purpose::URL_SAFE_NO_PAD.encode(bytes)
    }

    /// Decode Base64 URL-safe string to bytes
    #[inline]
    pub fn decode(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
        general_purpose::URL_SAFE_NO_PAD.decode(s)
    }
}

/// Common pattern for algorithm-identified bytes (hash, signature, public key)
///
/// This eliminates code duplication across DigestIdentifier, SignatureIdentifier, and PublicKey
#[derive(BorshSerialize, BorshDeserialize, Ord, PartialOrd)]
pub struct AlgorithmIdentifiedBytes<A> {
    pub algorithm: A,
    pub bytes: Vec<u8>,
}

impl<A> AlgorithmIdentifiedBytes<A> {
    /// Create with validation
    pub fn new(
        algorithm: A,
        bytes: Vec<u8>,
        expected_len: usize,
    ) -> Result<Self, crate::error::CryptoError> {
        if bytes.len() != expected_len {
            return Err(crate::error::CryptoError::InvalidDataLength {
                expected: expected_len,
                actual: bytes.len(),
            });
        }
        Ok(Self { algorithm, bytes })
    }

    /// Get bytes without prefix
    #[inline]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl<A> AlgorithmIdentifiedBytes<A>
where
    A: Copy,
{
    /// Build bytes with algorithm identifier prefix
    pub fn to_bytes_with_prefix(&self, prefix: u8) -> Vec<u8> {
        let mut result = Vec::with_capacity(1 + self.bytes.len());
        result.push(prefix);
        result.extend_from_slice(&self.bytes);
        result
    }

    /// Parse from bytes with algorithm identifier
    pub fn from_bytes_with_prefix<F, E>(
        bytes: &[u8],
        parse_algorithm: F,
        expected_len: usize,
        error_name: &str,
    ) -> Result<Self, crate::error::CryptoError>
    where
        F: FnOnce(u8) -> Result<A, E>,
        E: std::fmt::Display,
    {
        if bytes.is_empty() {
            return Err(crate::error::CryptoError::InvalidDataLength {
                expected: 1 + expected_len,
                actual: 0,
            });
        }

        let id = bytes[0];
        let algorithm = parse_algorithm(id).map_err(|e| {
            crate::error::CryptoError::UnknownAlgorithm(format!(
                "{}: {}",
                error_name, e
            ))
        })?;

        // Validate total length
        if bytes.len() != 1 + expected_len {
            return Err(crate::error::CryptoError::InvalidDataLength {
                expected: 1 + expected_len,
                actual: bytes.len(),
            });
        }

        Ok(Self {
            algorithm,
            bytes: bytes[1..].to_vec(),
        })
    }
}

impl<A: Clone> Clone for AlgorithmIdentifiedBytes<A> {
    fn clone(&self) -> Self {
        Self {
            algorithm: self.algorithm.clone(),
            bytes: self.bytes.clone(),
        }
    }
}

impl<A: PartialEq> PartialEq for AlgorithmIdentifiedBytes<A> {
    fn eq(&self, other: &Self) -> bool {
        self.algorithm == other.algorithm && self.bytes == other.bytes
    }
}

impl<A: Eq> Eq for AlgorithmIdentifiedBytes<A> {}

impl<A: std::hash::Hash> std::hash::Hash for AlgorithmIdentifiedBytes<A> {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.algorithm.hash(state);
        self.bytes.hash(state);
    }
}

impl<A: fmt::Debug> fmt::Debug for AlgorithmIdentifiedBytes<A> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AlgorithmIdentifiedBytes")
            .field("algorithm", &self.algorithm)
            .field("bytes", &base64_encoding::encode(&self.bytes))
            .finish()
    }
}
