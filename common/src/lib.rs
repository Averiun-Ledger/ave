//! # Ave Common
//!
//! Common types and utilities for Ave without heavy dependencies.
//!
//! This crate re-exports essential types needed for working with Ave,
//! such as identity and cryptography, without pulling in heavy dependencies
//! like wasmtime that don't compile on all architectures.
//!
//! ## Usage
//!
//! ```rust
//! use ave_common::{
//!     identity::{KeyPair, Signature, KeyPairAlgorithm},
//!     ValueWrapper,
//! };
//!
//! // Create a new keypair
//! let keypair = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();
//!
//! // Sign some data
//! let data = b"Hello, Ave!";
//! let signature = Signature::new(data, &keypair).unwrap();
//!
//! // Verify signature
//! assert!(signature.verify(data).is_ok());
//!
//! // Use ValueWrapper
//! let value = ValueWrapper::default();
//! ```

// Re-export the entire identity module
pub use ave_identity as identity;
pub use borsh;

pub mod wrapper;
// Internal modules
pub mod error;
pub mod namespace;
pub mod bridge;
pub mod request;
pub mod schematype;

// Re-export commonly used types
pub use error::Error;
pub use schematype::SchemaType;
pub use namespace::Namespace;
pub use bridge::*;
pub use wrapper::ValueWrapper;
