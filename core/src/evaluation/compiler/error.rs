use crate::model::common::contract::ContractError;
use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum CompilerError {
    #[error("base64 decode failed: {details}")]
    Base64DecodeFailed { details: String },

    #[error("directory creation failed [{path}]: {details}")]
    DirectoryCreationFailed { path: String, details: String },

    #[error("file write failed [{path}]: {details}")]
    FileWriteFailed { path: String, details: String },

    #[error("file read failed [{path}]: {details}")]
    FileReadFailed { path: String, details: String },

    #[error("cargo build failed: {details}")]
    CargoBuildFailed { details: String },

    #[error("compilation failed")]
    CompilationFailed,

    #[error("missing helper: {name}")]
    MissingHelper { name: &'static str },

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
}

#[derive(Debug, Clone)]
pub enum InvalidModuleKind {
    UnknownImportFunction { name: String },
    NonFunctionImport { import_type: String },
    MissingImports { missing: Vec<String> },
}

impl std::fmt::Display for InvalidModuleKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownImportFunction { name } => {
                write!(
                    f,
                    "module has function '{}' that is not contemplated in the SDK",
                    name
                )
            }
            Self::NonFunctionImport { import_type } => {
                write!(
                    f,
                    "module has a '{}' import that is not a function",
                    import_type
                )
            }
            Self::MissingImports { missing } => {
                write!(
                    f,
                    "module is missing SDK imports: {}",
                    missing.join(", ")
                )
            }
        }
    }
}

impl From<ContractError> for CompilerError {
    fn from(error: ContractError) -> Self {
        match error {
            ContractError::MemoryAllocationFailed { details } => {
                Self::MemoryAllocationFailed { details }
            }
            ContractError::InvalidPointer { pointer } => {
                Self::MemoryAllocationFailed {
                    details: format!("invalid pointer: {}", pointer),
                }
            }
            ContractError::WriteOutOfBounds { offset, size } => {
                Self::MemoryAllocationFailed {
                    details: format!(
                        "write out of bounds: offset {} >= size {}",
                        offset, size
                    ),
                }
            }
            ContractError::AllocationTooLarge { size, max } => {
                Self::MemoryAllocationFailed {
                    details: format!(
                        "allocation size {} exceeds maximum of {} bytes",
                        size, max
                    ),
                }
            }
            ContractError::TotalMemoryExceeded { total, max } => {
                Self::MemoryAllocationFailed {
                    details: format!(
                        "total memory {} exceeds maximum of {} bytes",
                        total, max
                    ),
                }
            }
            ContractError::AllocationOverflow => {
                Self::MemoryAllocationFailed {
                    details: "memory allocation would overflow".to_string(),
                }
            }
            ContractError::LinkerError { function, details } => {
                Self::InstantiationFailed {
                    details: format!(
                        "linker error [{}]: {}",
                        function, details
                    ),
                }
            }
        }
    }
}
