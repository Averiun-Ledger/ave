//! # Error module.
//!


/// Error type.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    /// Sink error.
    #[error("Sink error: {0}")]
    Sink(String),
    /// JSONPatch error.
    #[error("JSON patch error: {0}")]
    JSONPatch(String),
    /// NetworkHelper error.
    #[error("NetworkHelper error: {0}")]
    NetworkHelper(String),
    /// Network error.
    #[error("Network error: {0}")]
    Network(String),
    /// Ext_db error.
    #[error("Ext DB error: {0}")]
    ExtDB(String),
    /// System error.
    #[error("System error: {0}")]
    System(String),
    /// Protocols error.
    #[error("Protocols error: {0}")]
    Protocols(String),
    /// Compiler error.

    /// Auth error.
    #[error("Api error: {0}")]
    Api(String),
    /// Node error.
    #[error("Node error: {0}")]
    Node(String),
    /// Signature
    #[error("Signature error: {0}")]
    Signature(String),
    /// Password
    #[error("Password error: {0}")]
    Password(String),
    /// Governance error.
    #[error("Governance error: {0}")]
    Governance(String),
    /// Subject error.

    /// Tracker error.
    #[error("Tracker error: {0}")]
    Tracker(String),
    /// Bridge error.
    #[error("Subject error: {0}")]
    Bridge(String),
    /// Bridge error.
    #[error("RequestTracking error: {0}")]
    RequestTracking(String),
}
