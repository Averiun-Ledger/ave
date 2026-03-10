//! Shared types used across the Ave workspace.
//!
//! `ave-common` keeps request, governance, bridge and utility types in one
//! crate with a small dependency surface. It is intended for code that needs
//! Ave domain models without depending on heavier runtime crates.
//!
//! Main areas:
//! - request types for ledger events
//! - governance payloads and policy models
//! - bridge types for API-facing serialization
//! - utility wrappers such as [`SchemaType`], [`Namespace`] and [`ValueWrapper`]
//!
//! Feature flags:
//! - `common`: enables the domain and bridge models
//! - `value-wrapper`: enables [`ValueWrapper`]
//! - `openapi`: derives `utoipa` schemas
//! - `typescript`: derives TypeScript exports
//!
//! ```rust
//! use ave_common::{Namespace, SchemaType};
//! use ave_common::identity::DigestIdentifier;
//! use ave_common::request::{CreateRequest, EventRequest};
//!
//! let request = EventRequest::Create(CreateRequest {
//!     name: Some("subject".to_string()),
//!     description: None,
//!     governance_id: DigestIdentifier::default(),
//!     schema_id: SchemaType::Governance,
//!     namespace: Namespace::from("demo.root"),
//! });
//!
//! assert!(request.is_create_event());
//! ```
#[cfg(feature = "common")]
pub mod governance;

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

#[cfg(feature = "common")]
pub mod sink;

#[cfg(feature = "value-wrapper")]
pub mod wrapper;

// Re-exports
#[cfg(feature = "common")]
pub use ave_identity as identity;

#[cfg(feature = "common")]
pub use bridge::*;

#[cfg(feature = "common")]
pub use error::{ConversionError, Error, SignatureError};

#[cfg(feature = "common")]
pub use schematype::SchemaType;

#[cfg(feature = "common")]
pub use namespace::Namespace;

#[cfg(feature = "common")]
pub use sink::*;

#[cfg(feature = "value-wrapper")]
pub use wrapper::ValueWrapper;
