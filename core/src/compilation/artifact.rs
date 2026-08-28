//! Artifact fetch between nodes of a governance: an evaluator without
//! the compiler role obtains the official contract artifact from the
//! network instead of compiling it. The governance version is always
//! negotiated FIRST — different versions mean different contracts, so
//! there is nothing to talk about — and the received bytes are verified
//! against the compilation evidence anchored in the requester's own
//! ledger before anything is persisted.

use ave_common::identity::DigestIdentifier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Largest zstd payload an artifact response may carry. The remaining 64 KiB
/// is reserved for the MessagePack-serialized response envelope.
pub const MAX_ARTIFACT_WIRE_BYTES: usize = 960 * 1024;
/// Bounds decompression and the subsequent Wasmtime preparation work.
pub const MAX_ARTIFACT_UNCOMPRESSED_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, Error)]
pub enum ArtifactTransferError {
    #[error("artifact compression failed: {details}")]
    Compression { details: String },
    #[error("artifact decompression failed: {details}")]
    Decompression { details: String },
    #[error("compressed artifact is too large for the network: {size} bytes (max {max})")]
    TooLarge { size: usize, max: usize },
    #[error("artifact is too large after decompression: {size} bytes (max {max})")]
    UncompressedTooLarge { size: usize, max: usize },
}

/// The official artifact of a contract, as served over the network. The wasm
/// crosses the wire compressed with zstd; the precompiled artifact is
/// engine-specific and is regenerated locally after verifying the hash.
/// The toolchain fingerprint is cache-hygiene metadata of the build that
/// produced the wasm (the security anchor is the wasm hash itself).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArtifactData {
    pub compressed_wasm: Vec<u8>,
    pub toolchain_fingerprint: Option<DigestIdentifier>,
}

impl ArtifactData {
    pub fn from_wasm(
        wasm: &[u8],
        toolchain_fingerprint: Option<DigestIdentifier>,
    ) -> Result<Self, ArtifactTransferError> {
        if wasm.len() > MAX_ARTIFACT_UNCOMPRESSED_BYTES {
            return Err(ArtifactTransferError::UncompressedTooLarge {
                size: wasm.len(),
                max: MAX_ARTIFACT_UNCOMPRESSED_BYTES,
            });
        }
        let compressed_wasm = zstd::bulk::compress(wasm, 0).map_err(|error| {
            ArtifactTransferError::Compression {
                details: error.to_string(),
            }
        })?;
        if compressed_wasm.len() > MAX_ARTIFACT_WIRE_BYTES {
            return Err(ArtifactTransferError::TooLarge {
                size: compressed_wasm.len(),
                max: MAX_ARTIFACT_WIRE_BYTES,
            });
        }

        Ok(Self {
            compressed_wasm,
            toolchain_fingerprint,
        })
    }

    pub fn decompress(&self) -> Result<Vec<u8>, ArtifactTransferError> {
        zstd::bulk::decompress(
            &self.compressed_wasm,
            MAX_ARTIFACT_UNCOMPRESSED_BYTES,
        )
        .map_err(|error| ArtifactTransferError::Decompression {
            details: error.to_string(),
        })
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_data_round_trips_compressed_wasm() {
        let wasm = vec![42_u8; 128 * 1024];

        let artifact = ArtifactData::from_wasm(&wasm, None)
            .expect("compressing a wasm artifact must succeed");

        assert!(artifact.compressed_wasm.len() < wasm.len());
        assert_eq!(artifact.decompress().expect("artifact must decompress"), wasm);
    }

    #[test]
    fn artifact_data_rejects_compressed_payload_over_budget() {
        let wasm = (0..MAX_ARTIFACT_WIRE_BYTES + 4096)
            .scan(0x7f4a_7c15_u64, |state, _| {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                Some((*state >> 24) as u8)
            })
            .collect::<Vec<_>>();

        let result = ArtifactData::from_wasm(&wasm, None);

        assert!(matches!(
            result,
            Err(ArtifactTransferError::TooLarge { .. })
        ));
    }

    #[test]
    fn artifact_data_rejects_wasm_over_decompression_budget() {
        let wasm = vec![0_u8; MAX_ARTIFACT_UNCOMPRESSED_BYTES + 1];

        let result = ArtifactData::from_wasm(&wasm, None);

        assert!(matches!(
            result,
            Err(ArtifactTransferError::UncompressedTooLarge { .. })
        ));
    }

    #[test]
    fn artifact_data_rejects_corrupt_compressed_wasm() {
        let corrupt = ArtifactData {
            compressed_wasm: vec![1, 2, 3],
            toolchain_fingerprint: None,
        };
        assert!(matches!(
            corrupt.decompress(),
            Err(ArtifactTransferError::Decompression { .. })
        ));
    }

    #[test]
    fn artifact_data_rejects_oversized_decompressed_wasm() {
        let compressed_wasm = zstd::bulk::compress(
            &vec![0_u8; MAX_ARTIFACT_UNCOMPRESSED_BYTES + 1],
            0,
        )
        .expect("compressing a test artifact must succeed");
        let oversized = ArtifactData {
            compressed_wasm,
            toolchain_fingerprint: None,
        };
        assert!(matches!(
            oversized.decompress(),
            Err(ArtifactTransferError::Decompression { .. })
        ));
    }
}
