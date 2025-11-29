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
//! use ave_common::identity::{KeyPair, Signature};
//! use ave_common::ValueWrapper;
//!
//! // Create a new keypair
//! let keypair = KeyPair::default();
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

// Re-export ValueWrapper from ave-contract-sdk
pub use ave_contract_sdk::ValueWrapper;
