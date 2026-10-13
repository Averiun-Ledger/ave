//! Phase-verification errors shared by the node and the
//! off-chain verification tool.

use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum ValidatorError {
    #[error("Can not verify {data} signature")]
    InvalidSignature { data: &'static str },
    #[error("The signer {signer} is not what was expected")]
    InvalidSigner { signer: String },
    #[error("The value {value} does not match the expected value")]
    InvalidData { value: &'static str },
    #[error("An internal problem has occurred: {problem}")]
    InternalError { problem: String },
    #[error("The action could not be performed: {action}")]
    InvalidOperation { action: &'static str },
    #[error("The governance version is different from what was expected")]
    OutOfVersion,
}
