//! Generic hash functions with algorithm identification
//!
//! This module provides a generic interface for hash functions with automatic
//! algorithm identification via 1-byte prefixes.
//!
//! ## Example
//!
//! ```rust
//! use ave_common::identity::hash::{Hash, Blake3Hasher, DigestIdentifier};
//!
//! let hasher = Blake3Hasher;
//! let data = b"Hello, World!";
//!
//! // Compute hash
//! let hash = hasher.hash(data);
//!
//! // Convert to string (includes algorithm identifier)
//! let hash_str = hash.to_string();
//!
//! // Parse from string (automatically detects algorithm)
//! let parsed: DigestIdentifier = hash_str.parse().unwrap();
//!
//! // Verify
//! assert_eq!(hash, parsed);
//! ```

use crate::common::{AlgorithmIdentifiedBytes, base64_encoding};
use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

/// 1-byte identifier for Blake3 hash algorithm: 'B'
const BLAKE3_ID: u8 = b'B';

/// Blake3 hash output length in bytes
pub const BLAKE3_OUTPUT_LENGTH: usize = 32;

/// Trait for hash algorithms with algorithm identification
pub trait Hash {
    /// Get the algorithm identifier (1 byte)
    fn algorithm_id(&self) -> u8;

    /// Get the expected output length in bytes (excluding identifier)
    fn output_length(&self) -> usize;

    /// Compute hash of the input data
    fn hash(&self, data: &[u8]) -> DigestIdentifier;

    /// Get the algorithm enum variant
    fn algorithm(&self) -> HashAlgorithm;
}

/// Compute hash of any value that implements BorshSerialize
///
/// This is a convenience function that serializes the value using Borsh
/// and then hashes it using the specified hasher.
///
/// # Example
///
/// ```
/// use ave_common::identity::{hash_borsh, BLAKE3_HASHER};
/// use borsh::BorshSerialize;
///
/// #[derive(BorshSerialize)]
/// struct MyData {
///     value: u64,
/// }
///
/// let data = MyData { value: 42 };
/// let hash = hash_borsh(&BLAKE3_HASHER, &data).unwrap();
/// ```
#[inline]
pub fn hash_borsh<T: BorshSerialize>(
    hasher: &dyn Hash,
    value: &T,
) -> Result<DigestIdentifier, CryptoError> {
    let serialized = borsh::to_vec(value)
        .map_err(|e| CryptoError::SerializationError(e.to_string()))?;
    Ok(hasher.hash(&serialized))
}

/// Enumeration of supported hash algorithms
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum HashAlgorithm {
    Blake3,
}

impl HashAlgorithm {
    /// Get the 1-byte identifier for this algorithm
    pub fn identifier(&self) -> u8 {
        match self {
            HashAlgorithm::Blake3 => BLAKE3_ID,
        }
    }

    /// Get the output length for this algorithm (excluding identifier)
    pub fn output_length(&self) -> usize {
        match self {
            HashAlgorithm::Blake3 => BLAKE3_OUTPUT_LENGTH,
        }
    }

    /// Parse algorithm from 1-byte identifier
    pub fn from_identifier(id: u8) -> Result<Self, CryptoError> {
        match id {
            BLAKE3_ID => Ok(HashAlgorithm::Blake3),
            _ => Err(CryptoError::UnknownAlgorithm(format!("{}", id as char))),
        }
    }

    /// Create a hasher instance for this algorithm
    pub fn hasher(&self) -> Box<dyn Hash> {
        match self {
            HashAlgorithm::Blake3 => Box::new(Blake3Hasher),
        }
    }
}

impl fmt::Display for HashAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            HashAlgorithm::Blake3 => write!(f, "Blake3"),
        }
    }
}

/// Digest identifier with algorithm identification
///
/// The output contains:
/// - 1 byte: algorithm identifier
/// - N bytes: actual hash value (length depends on algorithm)
#[derive(Clone, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Ord, PartialOrd)]
pub struct DigestIdentifier {
    inner: AlgorithmIdentifiedBytes<HashAlgorithm>,
}

impl DigestIdentifier {
    /// Create a new hash output
    pub fn new(
        algorithm: HashAlgorithm,
        hash: Vec<u8>,
    ) -> Result<Self, CryptoError> {
        let expected_len = algorithm.output_length();
        Ok(Self {
            inner: AlgorithmIdentifiedBytes::new(
                algorithm,
                hash,
                expected_len,
            )?,
        })
    }

    /// Get the algorithm used
    #[inline]
    pub fn algorithm(&self) -> HashAlgorithm {
        self.inner.algorithm
    }

    /// Get the hash bytes (without identifier)
    #[inline]
    pub fn hash_bytes(&self) -> &[u8] {
        self.inner.as_bytes()
    }

    /// Get the hash as a fixed-size array
    ///
    /// This method converts the hash bytes into an array of the specified size.
    /// The size must match the algorithm's output length.
    ///
    /// # Errors
    /// Returns an error if the requested size doesn't match the algorithm's output length.
    ///
    /// # Example
    /// ```
    /// use ave_common::identity::{BLAKE3_HASHER, hash::{BLAKE3_OUTPUT_LENGTH, Hash}};
    ///
    /// let hash = BLAKE3_HASHER.hash(b"Hello, World!");
    /// let array: [u8; 32] = hash.hash_array().unwrap();
    /// assert_eq!(array.len(), BLAKE3_OUTPUT_LENGTH);
    /// ```
    pub fn hash_array<const N: usize>(&self) -> Result<[u8; N], CryptoError> {
        let hash_bytes = self.hash_bytes();
        let expected_len = self.algorithm().output_length();

        if N != expected_len {
            return Err(CryptoError::InvalidDataLength {
                expected: expected_len,
                actual: N,
            });
        }

        hash_bytes
            .try_into()
            .map_err(|_| CryptoError::InvalidDataLength {
                expected: N,
                actual: hash_bytes.len(),
            })
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
            return Err(CryptoError::InvalidHashFormat(
                "Empty bytes".to_string(),
            ));
        }

        let algorithm = HashAlgorithm::from_identifier(bytes[0])?;
        let expected_len = algorithm.output_length();

        let inner = AlgorithmIdentifiedBytes::from_bytes_with_prefix(
            bytes,
            HashAlgorithm::from_identifier,
            expected_len,
            "DigestIdentifier",
        )?;

        Ok(Self { inner })
    }

    // Internal method for Base64 encoding
    #[inline]
    fn to_base64(&self) -> String {
        // Special case: empty digest serializes as empty string
        if self.is_empty() {
            String::new()
        } else {
            // Format: algorithm_char + base64(hash_bytes)
            // Example: "B" + base64(hash) for Blake3
            let algorithm_char = self.inner.algorithm.identifier() as char;
            let data_base64 = base64_encoding::encode(&self.inner.bytes);
            format!("{}{}", algorithm_char, data_base64)
        }
    }

    /// Verify that this hash matches the given data using the embedded algorithm
    pub fn verify(&self, data: &[u8]) -> bool {
        let hasher = self.inner.algorithm.hasher();
        let computed = hasher.hash(data);
        computed == *self
    }

    /// Check if this is an empty digest (created via Default)
    ///
    /// Returns `true` if the hash bytes are empty, which indicates
    /// this digest was created using `Default::default()`.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.inner.bytes.is_empty()
    }
}

impl Default for DigestIdentifier {
    /// Creates an empty digest identifier using Blake3 algorithm
    ///
    /// This is primarily useful for initialization purposes.
    /// Use `is_empty()` to check if a digest was created via `default()`.
    fn default() -> Self {
        Self {
            inner: AlgorithmIdentifiedBytes {
                algorithm: HashAlgorithm::Blake3,
                bytes: Vec::new(),
            },
        }
    }
}

impl fmt::Debug for DigestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DigestIdentifier")
            .field("algorithm", &self.inner.algorithm)
            .field("hash", &base64_encoding::encode(&self.inner.bytes))
            .finish()
    }
}

impl fmt::Display for DigestIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_base64())
    }
}

impl Serialize for DigestIdentifier {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_str(&self.to_base64())
    }
}

impl<'de> Deserialize<'de> for DigestIdentifier {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = <String as Deserialize>::deserialize(deserializer)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl std::str::FromStr for DigestIdentifier {
    type Err = CryptoError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        // Special case: empty string deserializes to default (empty) digest
        if s.is_empty() {
            return Ok(Self::default());
        }

        // Format: algorithm_char + base64(hash_bytes)
        // First character is the algorithm identifier
        let mut chars = s.chars();
        let algorithm_char = chars.next().ok_or_else(|| {
            CryptoError::InvalidHashFormat("Empty string".to_string())
        })?;

        let algorithm = HashAlgorithm::from_identifier(algorithm_char as u8)?;

        // Rest is base64-encoded hash data
        let data_str: String = chars.collect();
        let hash_bytes = base64_encoding::decode(&data_str)
            .map_err(|e| CryptoError::Base64DecodeError(e.to_string()))?;

        // Validate length
        let expected_len = algorithm.output_length();
        if hash_bytes.len() != expected_len {
            return Err(CryptoError::InvalidDataLength {
                expected: expected_len,
                actual: hash_bytes.len(),
            });
        }

        Ok(Self {
            inner: AlgorithmIdentifiedBytes {
                algorithm,
                bytes: hash_bytes,
            },
        })
    }
}

/// Blake3 hasher implementation (32 bytes output)
#[derive(Debug, Clone, Copy)]
pub struct Blake3Hasher;

/// Global constant instance of Blake3 hasher for efficient reuse
pub const BLAKE3_HASHER: Blake3Hasher = Blake3Hasher;

impl Hash for Blake3Hasher {
    fn algorithm_id(&self) -> u8 {
        BLAKE3_ID
    }

    fn output_length(&self) -> usize {
        BLAKE3_OUTPUT_LENGTH
    }

    fn hash(&self, data: &[u8]) -> DigestIdentifier {
        let hash = blake3::hash(data);
        let hash_bytes = hash.as_bytes();

        // Blake3 always produces exactly 32 bytes, so this will never fail
        DigestIdentifier::new(HashAlgorithm::Blake3, hash_bytes.to_vec())
            .expect("Blake3 always produces 32 bytes")
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::Blake3
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_blake3_hash() {
        let hasher = Blake3Hasher;
        let data = b"Hello, World!";

        let hash = hasher.hash(data);
        assert_eq!(hash.algorithm(), HashAlgorithm::Blake3);
        assert_eq!(hash.hash_bytes().len(), 32);
    }

    #[test]
    fn test_hash_to_string() {
        let hasher = Blake3Hasher;
        let data = b"Hello, World!";

        let hash = hasher.hash(data);
        let hash_str = hash.to_string();

        // String representation should not be empty
        assert!(!hash_str.is_empty());

        // Blake3 hash should start with 'B'
        assert!(hash_str.starts_with('B'), "Blake3 hash should start with 'B', got: {}", hash_str);

        // Should be able to parse back
        let parsed: DigestIdentifier = hash_str.parse().unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_hash_verify() {
        let hasher = Blake3Hasher;
        let data = b"Hello, World!";

        let hash = hasher.hash(data);

        // Should verify with correct data
        assert!(hash.verify(data));

        // Should fail with incorrect data
        assert!(!hash.verify(b"Different data"));
    }

    #[test]
    fn test_hash_bytes_roundtrip() {
        let hasher = Blake3Hasher;
        let data = b"Test data";

        let hash = hasher.hash(data);
        let bytes = hash.to_bytes();

        // First byte should be algorithm identifier 'B'
        assert_eq!(bytes[0], b'B');

        // Should parse back correctly
        let parsed = DigestIdentifier::from_bytes(&bytes).unwrap();
        assert_eq!(hash, parsed);
    }

    #[test]
    fn test_algorithm_detection() {
        let hasher = Blake3Hasher;
        let data = b"Test data";

        let hash = hasher.hash(data);
        let hash_str = hash.to_string();

        // Parse should automatically detect Blake3
        let parsed: DigestIdentifier = hash_str.parse().unwrap();
        assert_eq!(parsed.algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_invalid_algorithm_identifier() {
        let mut bytes = vec![b'X']; // Invalid identifier
        bytes.extend_from_slice(&[0u8; 32]); // Add 32 bytes of data

        let result = DigestIdentifier::from_bytes(&bytes);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            CryptoError::UnknownAlgorithm(_)
        ));
    }

    #[test]
    fn test_serde_serialization() {
        let hasher = Blake3Hasher;
        let data = b"Test serialization";

        let hash = hasher.hash(data);

        // Serialize to JSON
        let json = serde_json::to_string(&hash).unwrap();

        // Deserialize back
        let deserialized: DigestIdentifier =
            serde_json::from_str(&json).unwrap();

        assert_eq!(hash, deserialized);
    }

    #[test]
    fn test_hash_borsh() {
        use crate::hash_borsh;

        #[derive(BorshSerialize)]
        struct TestData {
            value: u64,
            name: String,
        }

        let data = TestData {
            value: 42,
            name: "test".to_string(),
        };

        // Hash using borsh serialization
        let hash1 = hash_borsh(&BLAKE3_HASHER, &data).unwrap();

        // Manually serialize and hash to verify
        let serialized = borsh::to_vec(&data).unwrap();
        let hash2 = BLAKE3_HASHER.hash(&serialized);

        // Both methods should produce the same hash
        assert_eq!(hash1, hash2);
        assert_eq!(hash1.algorithm(), HashAlgorithm::Blake3);
    }

    #[test]
    fn test_hash_borsh_deterministic() {
        use crate::hash_borsh;

        #[derive(BorshSerialize)]
        struct TestData {
            x: u32,
            y: u32,
        }

        let data1 = TestData { x: 10, y: 20 };
        let data2 = TestData { x: 10, y: 20 };

        let hash1 = hash_borsh(&BLAKE3_HASHER, &data1).unwrap();
        let hash2 = hash_borsh(&BLAKE3_HASHER, &data2).unwrap();

        // Same data should produce same hash
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_default_digest_identifier() {
        let default_digest = DigestIdentifier::default();

        // Default should be empty
        assert!(default_digest.is_empty());

        // Default should use Blake3 algorithm
        assert_eq!(default_digest.algorithm(), HashAlgorithm::Blake3);

        // Should have empty bytes
        assert_eq!(default_digest.hash_bytes().len(), 0);
    }

    #[test]
    fn test_is_empty() {
        // Default digest is empty
        let empty = DigestIdentifier::default();
        assert!(empty.is_empty());

        // Hashed data is not empty
        let hasher = Blake3Hasher;
        let hash = hasher.hash(b"test data");
        assert!(!hash.is_empty());
        assert_eq!(hash.hash_bytes().len(), 32);
    }

    #[test]
    fn test_hash_array() {
        let hasher = Blake3Hasher;
        let data = b"Test data for array conversion";
        let hash = hasher.hash(data);

        // Get as array of correct size (Blake3 = 32 bytes)
        let array: [u8; 32] = hash.hash_array().unwrap();
        assert_eq!(array.len(), 32);
        assert_eq!(&array[..], hash.hash_bytes());

        // Wrong size should fail
        let result: Result<[u8; 64], _> = hash.hash_array();
        assert!(result.is_err());
        match result.unwrap_err() {
            CryptoError::InvalidDataLength { expected, actual } => {
                assert_eq!(expected, 32);
                assert_eq!(actual, 64);
            }
            _ => panic!("Expected InvalidDataLength error"),
        }
    }

    #[test]
    fn test_hash_array_type_inference() {
        let hasher = Blake3Hasher;
        let hash = hasher.hash(b"test");

        // Type inference should work
        let array = hash.hash_array::<32>().unwrap();
        assert_eq!(array.len(), 32);

        // Verify content matches
        for (i, byte) in array.iter().enumerate() {
            assert_eq!(*byte, hash.hash_bytes()[i]);
        }
    }

    #[test]
    fn test_empty_digest_serialization() {
        let empty = DigestIdentifier::default();

        // Should serialize to empty string
        assert_eq!(empty.to_string(), "");

        // Should parse from empty string
        let parsed: DigestIdentifier = "".parse().unwrap();
        assert!(parsed.is_empty());
        assert_eq!(parsed.algorithm(), HashAlgorithm::Blake3);

        // Round trip should work
        let serialized = empty.to_string();
        let deserialized: DigestIdentifier = serialized.parse().unwrap();
        assert!(deserialized.is_empty());
        assert_eq!(deserialized.algorithm(), empty.algorithm());
    }

    #[test]
    fn test_empty_digest_serde() {
        use serde_json;

        let empty = DigestIdentifier::default();

        // Should serialize to empty string in JSON
        let json = serde_json::to_string(&empty).unwrap();
        assert_eq!(json, "\"\"");

        // Should deserialize from empty string
        let deserialized: DigestIdentifier = serde_json::from_str("\"\"").unwrap();
        assert!(deserialized.is_empty());
        assert_eq!(deserialized.algorithm(), HashAlgorithm::Blake3);
    }
    
    #[test]
    fn test_empty_digest_bincode() {
        let empty = DigestIdentifier::default();

        println!("\n=== EMPTY DIGEST BINCODE TEST ===");
        println!("Is empty: {}", empty.is_empty());
        println!("String representation: '{}'", empty.to_string());

        // Should serialize with bincode
        let bytes = borsh::to_vec(&empty).unwrap();

        println!("Serialized length: {}", bytes.len());
        println!("Serialized bytes: {:?}", bytes);

        // Should deserialize with bincode
        let result: DigestIdentifier = borsh::from_slice(&bytes).unwrap();
        
        assert!(result.is_empty());
        assert_eq!(result.algorithm(), HashAlgorithm::Blake3);
    }
}
