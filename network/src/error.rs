//! # Network errors.

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Errors produced by the network layer.
#[derive(Debug, Error, Serialize, Deserialize, Clone)]
pub enum Error {
    /// Failed to extract or decode the local Ed25519 secret key.
    #[error("failed to extract Ed25519 secret key: {0}")]
    KeyExtraction(String),

    /// Failed to initialise the Noise authentication layer.
    #[error("failed to build Noise transport: {0}")]
    NoiseBuild(String),

    /// Failed to initialise the DNS transport.
    #[error("failed to build DNS transport: {0}")]
    DnsBuild(String),

    /// A multiaddress string could not be parsed or is invalid.
    #[error("invalid multiaddress: {0}")]
    InvalidAddress(String),

    /// The swarm could not start listening on the requested address.
    #[error("failed to listen on address: {0}")]
    Listen(String),

    /// Failed to send a response on a request-response channel.
    #[error("failed to send response on request-response channel")]
    ResponseSend,

    /// No reachable bootstrap node; the network is unavailable.
    #[error("cannot connect to the ave network: no reachable bootstrap node")]
    NoBootstrapNode,

    /// The network task was cancelled via its cancellation token.
    #[error("network task cancelled")]
    Cancelled,

    /// Failed to forward a command to the network worker.
    #[error("failed to send command to network worker: {0}")]
    CommandSend(String),
}
