//! Artifact fetch between nodes of a governance: an evaluator without
//! the compiler role obtains the official contract artifact from the
//! network instead of compiling it. The governance version is always
//! negotiated FIRST — different versions mean different contracts, so
//! there is nothing to talk about — and the received bytes are verified
//! against the compilation evidence anchored in the requester's own
//! ledger before anything is persisted.

use ave_common::identity::DigestIdentifier;
use serde::{Deserialize, Serialize};

/// The official artifact of a contract, as served over the network.
/// Only the wasm bytes cross the wire: the precompiled artifact is
/// engine-specific and is regenerated locally after verifying the hash.
/// The toolchain fingerprint is cache-hygiene metadata of the build that
/// produced the wasm (the security anchor is the wasm hash itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactData {
    pub wasm: Vec<u8>,
    pub toolchain_fingerprint: Option<DigestIdentifier>,
}

/// Answer to the light availability probe, after negotiating the
/// governance version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactProbeResult {
    /// Same governance version and the official artifact is registered:
    /// the peer can serve it.
    CanServe,
    /// The peer can not serve it (it does not have it or it is itself
    /// behind): try another one.
    NotServed,
    /// The peer is applying an update (compiling and promoting the new
    /// artifacts): wait and retry the SAME peer — after a contract
    /// change every compiler is busy at once, so moving to another one
    /// is pointless.
    Busy,
    /// The requester's governance version is behind: sync and retry.
    Outdated { gov_version: u64 },
}

/// Answer to the artifact request, after negotiating the governance
/// version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ArtifactFetchResult {
    /// The official artifact bytes.
    Artifact(ArtifactData),
    /// The peer can not serve it (it does not have it or it is itself
    /// behind): try another one.
    NotServed,
    /// The peer started applying an update after answering the probe:
    /// wait and retry the SAME peer.
    Busy,
    /// The requester's governance version is behind: sync and retry.
    Outdated { gov_version: u64 },
}
