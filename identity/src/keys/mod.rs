//! Cryptographic keys and digital signatures with algorithm identification
//!
//! This module provides a generic interface for digital signature algorithms with automatic
//! algorithm identification via 1-byte prefixes.
//!
//! ## Example
//!
//! ```rust
//! use ave_identity::keys::{KeyPair, KeyPairAlgorithm, DSA};
//!
//! // Generate a key pair (algorithm-agnostic)
//! let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).expect("Failed to generate key pair");
//!
//! let message = b"Hello, World!";
//!
//! // Sign message using generic interface
//! let signature = keypair.sign(message).unwrap();
//!
//! // Convert to string (includes algorithm identifier)
//! let sig_str = signature.to_string();
//!
//! // Get public key
//! let public_key = keypair.public_key();
//!
//! // Verify signature
//! assert!(public_key.verify(message, &signature).is_ok());
//! ```
//!
//! ## Direct Algorithm Usage
//!
//! You can also use specific algorithm implementations directly:
//!
//! ```rust
//! use ave_identity::keys::{DSA, Ed25519Signer};
//!
//! let signer = Ed25519Signer::generate().unwrap();
//! let signature = signer.sign(b"message").unwrap();
//! ```

use crate::error::CryptoError;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::fmt;

// Sub-modules
mod ed25519;
mod keypair;
mod public_key;
mod signature_identifier;

// Re-exports
pub use ed25519::{
    ED25519_ID, ED25519_PUBLIC_KEY_LENGTH, ED25519_SECRET_KEY_LENGTH,
    ED25519_SIGNATURE_LENGTH, Ed25519Signer,
};
pub use keypair::{KeyPair, KeyPairAlgorithm};
pub use public_key::PublicKey;
pub use signature_identifier::SignatureIdentifier;

/// Trait for digital signature algorithms with algorithm identification
pub trait DSA {
    /// Get the algorithm identifier (1 byte)
    fn algorithm_id(&self) -> u8;

    /// Get the expected signature length in bytes (excluding identifier)
    fn signature_length(&self) -> usize;

    /// Sign the message
    fn sign(&self, message: &[u8]) -> Result<SignatureIdentifier, CryptoError>;

    /// Get the algorithm enum variant
    fn algorithm(&self) -> DSAlgorithm;

    /// Get the public key bytes
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// Enumeration of supported digital signature algorithms
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
pub enum DSAlgorithm {
    Ed25519,
}

impl DSAlgorithm {
    /// Get the 1-byte identifier for this algorithm
    pub fn identifier(&self) -> u8 {
        match self {
            DSAlgorithm::Ed25519 => ED25519_ID,
        }
    }

    /// Get the signature length for this algorithm (excluding identifier)
    pub fn signature_length(&self) -> usize {
        match self {
            DSAlgorithm::Ed25519 => ED25519_SIGNATURE_LENGTH,
        }
    }

    /// Get the public key length for this algorithm
    pub fn public_key_length(&self) -> usize {
        match self {
            DSAlgorithm::Ed25519 => ED25519_PUBLIC_KEY_LENGTH,
        }
    }

    /// Parse algorithm from 1-byte identifier
    pub fn from_identifier(id: u8) -> Result<Self, CryptoError> {
        match id {
            ED25519_ID => Ok(DSAlgorithm::Ed25519),
            _ => Err(CryptoError::UnknownAlgorithm(format!("{}", id as char))),
        }
    }
}

impl fmt::Display for DSAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DSAlgorithm::Ed25519 => write!(f, "Ed25519"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_size_constants() {
        // Verify our constants match the library constants
        use ed25519_dalek::{
            PUBLIC_KEY_LENGTH, SECRET_KEY_LENGTH, SIGNATURE_LENGTH,
        };

        assert_eq!(ED25519_PUBLIC_KEY_LENGTH, PUBLIC_KEY_LENGTH);
        assert_eq!(ED25519_SECRET_KEY_LENGTH, SECRET_KEY_LENGTH);
        assert_eq!(ED25519_SIGNATURE_LENGTH, SIGNATURE_LENGTH);
    }
}
