//! Pure contract compilation pipeline for the Averiun Ledger.
//!
//! This crate prepares contract projects, builds them to
//! `wasm32-unknown-unknown` with cargo, precompiles and validates the
//! resulting artifacts through the `ave-contract-sdk` runtime, and
//! produces the artifact metadata records persisted by the governance
//! contract register. It has no dependency on the actor system or on
//! `ave-core`.

pub mod error;
mod pipeline;

#[cfg(feature = "client")]
mod client;
#[cfg(feature = "server")]
mod config;
#[cfg(feature = "server")]
mod service;

pub use error::CompilerError;
pub use pipeline::{
    ContractArtifactRecord, build_contract_record, build_wasm,
    compilation_toml, hash_bytes, load_artifact_precompiled,
    load_artifact_wasm, map_runtime_error_to_compiler_error,
    metadata_matches, persist_artifact, precompile_module,
    toolchain_fingerprint, validate_module, validate_source_base64,
};
#[cfg(feature = "client")]
pub use client::{CompileOutcome, CompilerClient};
#[cfg(any(feature = "client", feature = "server"))]
pub use ave_common::compiler::pb;
#[cfg(feature = "server")]
pub use config::ServiceConfig;
#[cfg(feature = "server")]
pub use service::{CompilerServer, ServiceError};
#[cfg(feature = "test")]
pub use pipeline::{
    global_cache_entry_dir, persist_global_cache_artifact,
    try_load_global_cache,
};
