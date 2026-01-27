//! # Ave Common
//!
//! Common types and utilities for Ave without heavy dependencies.
//!
//! This crate re-exports essential types needed for working with Ave,
//! such as identity and cryptography, without pulling in heavy dependencies
//! like wasmtime that don't compile on all architectures.

// Internal modules
// Internal modules
#[cfg(feature = "common")]
pub mod error;

#[cfg(feature = "common")]
pub mod bridge;

#[cfg(feature = "common")]
pub mod request;

#[cfg(feature = "common")]
pub mod schematype;

#[cfg(feature = "common")]
pub mod namespace;

#[cfg(feature = "value-wrapper")]
pub mod wrapper;

// Re-exports
#[cfg(feature = "common")]
pub use ave_identity as identity;

#[cfg(feature = "common")]
pub use bridge::*;

#[cfg(feature = "common")]
pub use schematype::SchemaType;

#[cfg(feature = "common")]
pub use namespace::Namespace;

#[cfg(feature = "value-wrapper")]
pub use wrapper::ValueWrapper;
