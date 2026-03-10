//! API-facing bridge models.
//!
//! The bridge namespace contains transport-oriented request, response and
//! signature types together with conversions to and from the internal models.

pub mod conversions;
pub mod request;
pub mod response;
pub mod signature;
