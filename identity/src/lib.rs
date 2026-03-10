//! Cryptographic primitives used by Ave.
//!
//! The crate exposes:
//! - hashes with algorithm identifiers
//! - Ed25519 key generation, signing and verification
//! - signed payloads with timestamp and content hash
//! - compact string formats for hashes, public keys and signatures
//!
//! Current identifiers:
//! - `B`: Blake3 digest
//! - `E`: Ed25519 key or signature
//!
//! Secret keys are kept in encrypted memory through `memsecurity` and are
//! decrypted only when a signing operation needs them.
//!
//! ```rust
//! use ave_identity::{BLAKE3_HASHER, Hash, KeyPair, KeyPairAlgorithm};
//!
//! let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
//! let digest = BLAKE3_HASHER.hash(b"hello");
//! let signature = keypair.sign(digest.hash_bytes()).unwrap();
//!
//! assert!(keypair.public_key().verify(digest.hash_bytes(), &signature).is_ok());
//! ```

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
