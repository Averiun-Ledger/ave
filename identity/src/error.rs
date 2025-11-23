//! Error types for cryptographic operations
//!
//! This module defines all error types that can occur during cryptographic
//! operations in the identity crate.
//!
//! ## Error Handling Examples
//!
//! ### Handling Signature Verification Errors
//!
//! ```rust
//! use identity::keys::{KeyPair, KeyPairAlgorithm};
//! use identity::error::CryptoError;
//!
//! let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
//! let message = b"Hello, World!";
//! let signature = keypair.sign(message).unwrap();
//! let public_key = keypair.public_key();
//!
//! // Verify signature
//! match public_key.verify(message, &signature) {
//!     Ok(()) => println!("Signature is valid"),
//!     Err(CryptoError::SignatureVerificationFailed) => {
//!         eprintln!("Invalid signature or tampered data");
//!     }
//!     Err(CryptoError::InvalidSignatureFormat(msg)) => {
//!         eprintln!("Malformed signature: {}", msg);
//!     }
//!     Err(e) => eprintln!("Unexpected error: {}", e),
//! }
//! ```
//!
//! ### Handling Key Parsing Errors
//!
//! ```rust
//! use identity::keys::PublicKey;
//! use identity::error::CryptoError;
//!
//! let key_str = "EInvalidData";
//!
//! match key_str.parse::<PublicKey>() {
//!     Ok(key) => println!("Successfully parsed public key"),
//!     Err(CryptoError::Base64DecodeError(msg)) => {
//!         eprintln!("Invalid encoding: {}", msg);
//!     }
//!     Err(CryptoError::UnknownAlgorithm(id)) => {
//!         eprintln!("Unknown algorithm identifier: {}", id);
//!     }
//!     Err(CryptoError::InvalidPublicKey(msg)) => {
//!         eprintln!("Invalid public key: {}", msg);
//!     }
//!     Err(e) => eprintln!("Unexpected error: {}", e),
//! }
//! ```
//!
//! ### Handling Hash Parsing Errors
//!
//! ```rust
//! use identity::hash::DigestIdentifier;
//! use identity::error::CryptoError;
//!
//! let hash_str = "BInvalidHashData";
//!
//! match hash_str.parse::<DigestIdentifier>() {
//!     Ok(hash) => println!("Successfully parsed hash"),
//!     Err(CryptoError::Base64DecodeError(msg)) => {
//!         eprintln!("Invalid encoding: {}", msg);
//!     }
//!     Err(CryptoError::UnknownAlgorithm(id)) => {
//!         eprintln!("Unknown hash algorithm: {}", id);
//!     }
//!     Err(CryptoError::InvalidHashFormat(msg)) => {
//!         eprintln!("Invalid hash format: {}", msg);
//!     }
//!     Err(e) => eprintln!("Unexpected error: {}", e),
//! }
//! ```
//!
//! ### Handling Serialization Errors
//!
//! ```rust
//! use identity::{hash_borsh, BLAKE3_HASHER};
//! use identity::error::CryptoError;
//! use borsh::BorshSerialize;
//!
//! #[derive(BorshSerialize)]
//! struct MyData {
//!     value: u64,
//! }
//!
//! let data = MyData { value: 42 };
//!
//! match hash_borsh(&BLAKE3_HASHER, &data) {
//!     Ok(hash) => println!("Hash: {}", hash),
//!     Err(CryptoError::SerializationError(msg)) => {
//!         eprintln!("Failed to serialize data: {}", msg);
//!     }
//!     Err(e) => eprintln!("Unexpected error: {}", e),
//! }
//! ```

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone)]
pub enum CryptoError {
    /// Returned when an unrecognized algorithm identifier is encountered.
    ///
    /// This typically occurs when parsing Base64-encoded data with an unknown
    /// algorithm prefix (e.g., not 'B' for Blake3 or 'E' for Ed25519).
    #[error("Unknown algorithm identifier: {0}")]
    UnknownAlgorithm(String),

    /// Returned when hash data is malformed or has incorrect structure.
    ///
    /// Common causes:
    /// - Missing algorithm identifier
    /// - Incorrect data length for the algorithm
    /// - Corrupted Base64 encoding
    #[error("Invalid hash format: {0}")]
    InvalidHashFormat(String),

    /// Returned when signature data is malformed or has incorrect structure.
    ///
    /// Common causes:
    /// - Missing algorithm identifier
    /// - Incorrect signature length for the algorithm
    /// - Corrupted Base64 encoding
    #[error("Invalid signature format: {0}")]
    InvalidSignatureFormat(String),

    /// Returned when cryptographic signature verification fails.
    ///
    /// This indicates that either:
    /// - The signature was not created by the claimed signer
    /// - The signed data has been modified
    /// - The signature is invalid or corrupted
    #[error("Signature verification failed")]
    SignatureVerificationFailed,

    /// Returned when a public key is invalid or malformed.
    ///
    /// Common causes:
    /// - Incorrect key length
    /// - Invalid key format for the algorithm
    /// - Corrupted key data
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Returned when a secret key is invalid or malformed.
    ///
    /// Common causes:
    /// - Incorrect key length
    /// - Invalid key format
    /// - Decryption failure from secure storage
    #[error("Invalid secret key: {0}")]
    InvalidSecretKey(String),

    /// Returned when attempting signing operations on a verification-only instance.
    ///
    /// This occurs when a signer is created from a public key only (using
    /// `from_public_key()`) and then used to sign data. Such instances can
    /// only verify signatures, not create them.
    #[error("No secret key available for signing (verification-only instance)")]
    MissingSecretKey,

    /// Returned when Base64 decoding fails.
    #[error("Base64 decode error: {0}")]
    Base64DecodeError(String),

    /// Returned when data has an unexpected length.
    ///
    /// This is a validation error that occurs when the actual data size
    /// doesn't match the expected size for a specific algorithm or operation.
    #[error("Invalid data length: expected {expected}, got {actual}")]
    InvalidDataLength { expected: usize, actual: usize },

    /// Returned when Borsh serialization/deserialization fails.
    #[error("Serialization error: {0}")]
    SerializationError(String),

    /// Returned when hash computation or verification fails.
    #[error("Hash computation failed: {0}")]
    HashError(String),

    /// Returned when a signing operation fails.
    #[error("Signing failed: {0}")]
    SigningError(String),

    /// Returned when an algorithm is not supported by this implementation.
    ///
    /// This occurs when attempting to use a cryptographic algorithm that
    /// is recognized but not implemented in the current version.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// Returned when PKCS#8 DER parsing fails.
    #[error("Invalid PKCS#8 DER format: {0}")]
    InvalidDerFormat(String),
}
