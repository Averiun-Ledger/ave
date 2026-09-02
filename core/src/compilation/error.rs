use thiserror::Error;

pub use ave_contract_sdk::runtime::InvalidModuleKind;

#[derive(Debug, Error, Clone)]
pub enum CompilerError {
    #[error("invalid contract path [{path}]: {details}")]
    InvalidContractPath { path: String, details: String },

    #[error("base64 decode failed: {details}")]
    Base64DecodeFailed { details: String },

    #[error("directory creation failed [{path}]: {details}")]
    DirectoryCreationFailed { path: String, details: String },

    #[error("file write failed [{path}]: {details}")]
    FileWriteFailed { path: String, details: String },

    #[error("file read failed [{path}] ({kind:?}): {details}")]
    FileReadFailed {
        path: String,
        kind: std::io::ErrorKind,
        details: String,
    },

    #[error("cargo build failed: {details}")]
    CargoBuildFailed { details: String },

    #[error("cargo build timed out after {secs} seconds")]
    BuildTimeout { secs: u64 },

    #[error("compilation failed")]
    CompilationFailed,

    #[error("compilers unavailable: {details}")]
    CompilersUnavailable { details: String },

    #[error("compiler toolchain mismatch: expected {expected}, got {actual}")]
    ToolchainMismatch { expected: String, actual: String },

    #[error("invalid compiler attestation signature")]
    InvalidAttestationSignature,

    #[error(
        "compiler attestation mismatch: known wasm hash {expected}, got {actual}"
    )]
    AttestationMismatch { expected: String, actual: String },

    #[error("missing helper: {name}")]
    MissingHelper { name: &'static str },

    #[error("contract register failed: {details}")]
    ContractRegisterFailed { details: String },

    #[error("toolchain fingerprint failed: {details}")]
    ToolchainFingerprintFailed { details: String },

    #[error("wasm precompile failed: {details}")]
    WasmPrecompileFailed { details: String },

    #[error("wasm deserialization failed: {details}")]
    WasmDeserializationFailed { details: String },

    #[error("invalid module: {kind}")]
    InvalidModule { kind: InvalidModuleKind },

    #[error("fuel limit error: {details}")]
    FuelLimitError { details: String },

    #[error("instantiation failed: {details}")]
    InstantiationFailed { details: String },

    #[error("entry point not found: {function}")]
    EntryPointNotFound { function: &'static str },

    #[error("contract execution failed: {details}")]
    ContractExecutionFailed { details: String },

    #[error("serialization error [{context}]: {details}")]
    SerializationError {
        context: &'static str,
        details: String,
    },

    #[error("invalid contract output: {details}")]
    InvalidContractOutput { details: String },

    #[error("memory allocation failed: {details}")]
    MemoryAllocationFailed { details: String },

    #[error("contract check failed: {error}")]
    ContractCheckFailed { error: String },

    #[error("engine creation failed: {details}")]
    EngineCreation { details: String },

    #[error(
        "fetched artifact hash mismatch: expected {expected}, got {actual}"
    )]
    FetchedArtifactMismatch { expected: String, actual: String },

    #[error("fetched artifact decompression failed: {details}")]
    FetchedArtifactDecompressionFailed { details: String },

    #[error("missing ledger anchor for artifact [{contract_name}]")]
    MissingArtifactAnchor { contract_name: String },

    #[error("artifact hash does not match ledger anchor: expected {expected}, got {actual}")]
    ArtifactAnchorMismatch { expected: String, actual: String },
}

impl CompilerError {
    pub fn file_read(path: impl Into<String>, error: std::io::Error) -> Self {
        Self::FileReadFailed {
            path: path.into(),
            kind: error.kind(),
            details: error.to_string(),
        }
    }
}
