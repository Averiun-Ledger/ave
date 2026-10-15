//! Contract-source decoding shared by the node and the off-chain
//! verification tool.
//!
//! Base64, then bounded zstd, then size cap. Build, filesystem and
//! engine errors stay in core: only the decode/hash shapes move,
//! with a narrow error.

use crate::identity::{DigestIdentifier, HashAlgorithm, hash_borsh};

use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
use thiserror::Error;

/// Decode-stage failures: the caller's bytes never reach a build.
#[derive(Debug, Error, Clone)]
pub enum ContractSourceError {
    #[error("base64 decode failed: {details}")]
    Base64DecodeFailed { details: String },
    #[error("contract source decompression failed: {details}")]
    SourceDecompressionFailed { details: String },
    #[error("contract source too large: {size} bytes (max {max})")]
    ContractSourceTooLarge { size: usize, max: usize },
    #[error("serialization error [{context}]: {details}")]
    SerializationError { context: String, details: String },
}

/// Maximum accepted contract source size, like the node enforces.
pub const MAX_CONTRACT_SOURCE_BYTES: usize = 1024 * 1024;

/// zstd frame magic number (little-endian 0xFD2FB528).
///
/// A base64-decoded contract payload starting with these bytes is
/// a compressed source; anything else is a plain UTF-8 source — a
/// Rust source can never begin with this non-UTF-8 prefix, so the
/// formats are unambiguous and both stay accepted (plain payloads
/// in already-committed events keep replaying).
pub const ZSTD_MAGIC: [u8; 4] = [0x28, 0xB5, 0x2F, 0xFD];

/// Decodes a governance-event contract payload into source bytes.
///
/// Base64, then bounded zstd decompression when the decoded payload
/// carries the
/// zstd magic number. Deterministic and identical on every node.
pub fn decode_contract_source(
    contract: &str,
) -> Result<Vec<u8>, ContractSourceError> {
    let decoded = BASE64_STANDARD.decode(contract).map_err(|e| {
        ContractSourceError::Base64DecodeFailed {
            details: e.to_string(),
        }
    })?;
    if decoded.starts_with(&ZSTD_MAGIC) {
        return zstd::bulk::decompress(&decoded, MAX_CONTRACT_SOURCE_BYTES)
            .map_err(|e| ContractSourceError::SourceDecompressionFailed {
                details: e.to_string(),
            });
    }
    if decoded.len() > MAX_CONTRACT_SOURCE_BYTES {
        return Err(ContractSourceError::ContractSourceTooLarge {
            size: decoded.len(),
            max: MAX_CONTRACT_SOURCE_BYTES,
        });
    }
    Ok(decoded)
}

/// Validates that `contract` is a well-formed contract payload: base64
/// carrying a plain or zstd-compressed source within
/// [`MAX_CONTRACT_SOURCE_BYTES`].
///
/// The node runs this cheap local check before delegating a build to the
/// compiler: a malformed payload is a request error
/// ([`ContractSourceError::Base64DecodeFailed`] and friends), not a build
/// error, and must not be conflated with "the contract does not compile".
pub fn validate_contract_source(contract: &str) -> Result<(), ContractSourceError> {
    decode_contract_source(contract).map(|_| ())
}

pub fn hash_bytes(
    hash: HashAlgorithm,
    bytes: &[u8],
    context: &'static str,
) -> Result<DigestIdentifier, ContractSourceError> {
    // Slices serialize exactly like `Vec` in Borsh (length prefix plus raw
    // bytes), so hashing the slice directly keeps every digest identical
    // while sparing a multi-megabyte clone on hot paths.
    hash_borsh(&*hash.hasher(), &bytes).map_err(|e| {
        ContractSourceError::SerializationError {
            context: context.to_owned(),
            details: e.to_string(),
        }
    })
}
