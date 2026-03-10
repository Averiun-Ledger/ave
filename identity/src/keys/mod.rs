//! Key and signature primitives.
//!
//! The public API is split in two layers:
//! - [`KeyPair`] for an algorithm-agnostic entry point
//! - concrete implementations such as [`Ed25519Signer`] when you want the
//!   algorithm explicitly
//!
//! Public keys and signatures carry a one-byte algorithm identifier so they can
//! be serialized and parsed without extra metadata.

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

/// Common interface for supported signature algorithms.
pub trait DSA {
    /// Returns the one-byte identifier for this algorithm.
    fn algorithm_id(&self) -> u8;

    /// Returns the signature length, excluding the identifier byte.
    fn signature_length(&self) -> usize;

    /// Signs `message`.
    fn sign(&self, message: &[u8]) -> Result<SignatureIdentifier, CryptoError>;

    /// Returns the enum variant for this algorithm.
    fn algorithm(&self) -> DSAlgorithm;

    /// Returns the raw public key bytes.
    fn public_key_bytes(&self) -> Vec<u8>;
}

/// Digital signature algorithms supported by this crate.
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
    /// Returns the one-byte identifier for this algorithm.
    pub const fn identifier(&self) -> u8 {
        match self {
            Self::Ed25519 => ED25519_ID,
        }
    }

    /// Returns the signature length, excluding the identifier byte.
    pub const fn signature_length(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_SIGNATURE_LENGTH,
        }
    }

    /// Returns the public key length for this algorithm.
    pub const fn public_key_length(&self) -> usize {
        match self {
            Self::Ed25519 => ED25519_PUBLIC_KEY_LENGTH,
        }
    }

    /// Parses an algorithm from its one-byte identifier.
    pub fn from_identifier(id: u8) -> Result<Self, CryptoError> {
        match id {
            ED25519_ID => Ok(Self::Ed25519),
            _ => Err(CryptoError::UnknownAlgorithm(format!("{}", id as char))),
        }
    }
}

impl fmt::Display for DSAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ed25519 => write!(f, "Ed25519"),
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
