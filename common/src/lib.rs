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
//!     identity::{KeyPair, Signature},
//!     ValueWrapper,
//!     BridgeEventRequest,
//!     BridgeFactRequest,
//! };
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

pub mod wrapper;
// Internal modules
pub mod error;
pub mod namespace;
pub mod request;
pub mod response;
pub mod signature;

// Re-export commonly used types
pub use wrapper::ValueWrapper;
pub use error::Error;
pub use namespace::Namespace;
pub use request::*;
pub use response::*;
pub use signature::*;
