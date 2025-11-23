//! # Crypto Module
//!
//! A generic cryptographic module with algorithm identification via single-letter prefixes
//! and secure key storage using encrypted memory.
//!
//! This module provides generic traits for hash functions and digital signatures,
//! with each algorithm identified by a unique 1-byte (single letter) prefix.
//!
//! ## Design
//!
//! - Each algorithm has a 1-byte identifier (e.g., 'B' for Blake3)
//! - The identifier is prepended to the output (hash or signature)
//! - When parsing from Base64 strings, the first character identifies the algorithm
//! - Generic traits allow easy addition of new algorithms
//! - Private keys are stored encrypted in memory using `memsecurity` crate
//!
//! ## Security Features
//!
//! - **Encrypted storage**: Private keys are encrypted using ASCON AEAD
//! - **Automatic zeroization**: Memory is cleared when keys are dropped
//! - **Memory locking**: Keys are locked in RAM (mlock) to prevent swap
//! - **Temporary decryption**: Keys are only decrypted during signing operations
//!
//! ## Currently Supported Algorithms
//!
//! - **Hash**: Blake3 (32 bytes) with identifier 'B'
//! - **Signature**: Ed25519 with identifier 'E'
//!
//! ## Modules
//!
//! - [`hash`]: Hash functions with algorithm identification
//! - [`keys`]: Digital signature algorithms and key management
//! - [`signature`]: High-level signature structures with metadata
//! - [`timestamp`]: Timestamp utilities for signatures
//! - [`error`]: Error types for cryptographic operations

mod common;
pub mod error;
pub mod hash;
pub mod keys;
pub mod signature;
pub mod timestamp;

pub use error::CryptoError;
pub use hash::{
    BLAKE3_HASHER, Blake3Hasher, DigestIdentifier, Hash, HashAlgorithm,
    hash_borsh,
};
pub use keys::{
    DSA, DSAlgorithm, KeyPair, KeyPairAlgorithm, PublicKey, SignatureIdentifier,
};
pub use signature::{Signature, Signed};
pub use timestamp::TimeStamp;
