use ave_common::identity::DigestIdentifier;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::subject::Metadata;

/// A Enum representing a validation response.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum ValidationRes {
    Response {
        vali_req_hash: DigestIdentifier,
        modified_metadata_without_propierties_hash: DigestIdentifier,
        propierties_hash: DigestIdentifier,
        event_request_hash: DigestIdentifier,
        viewpoints_hash: DigestIdentifier,
    },
    Create {
        vali_req_hash: DigestIdentifier,
        subject_metadata: Box<Metadata>,
    },
    Abort(String),
    TimeOut,
    Reboot,
}

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

pub enum ResponseSummary {
    Reboot,
    Ok,
}
