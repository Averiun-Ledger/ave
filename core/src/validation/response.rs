use crate::{
    governance::role_register::RoleDataRegister,
    model::{
        common::check_quorum_signers,
        event::{ApprovalData, ValidationData, ValidationMetadata},
    },
    subject::Metadata,
};
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
};

use anyhow::{Result, bail};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use thiserror::Error;

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
        /// Hash of the approval evidence the validator verified inside
        /// the validation request. `Some` only for requests that
        /// required approval.
        approval_data_hash: Option<DigestIdentifier>,
    },
    Create {
        vali_req_hash: DigestIdentifier,
        subject_metadata: Box<Metadata>,
    },
    Abort(String),
    TimeOut,
    Reboot,
    /// The validator can not validate right now for reasons unrelated to
    /// the request (it is going down mid-validation): not a verdict. The
    /// requester drops the validator from the current set, pulls fresh
    /// ones from the pending pool and only reboots the request when no
    /// validator can answer at all.
    ///
    /// Added at the end of the enum on purpose: borsh encodes the variant
    /// ordinal, so existing variants keep their wire value. Nodes running
    /// older code can not deserialize it and treat the message as lost —
    /// the same outcome as the validator not answering.
    Unavailable,
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

/// Approval tally hash of an approval evidence, when present.
pub fn approval_data_hash_of(
    hash: &HashAlgorithm,
    approval: Option<&ApprovalData>,
) -> Result<Option<DigestIdentifier>> {
    match approval {
        Some(data) => Ok(Some(
            hash_borsh(&*hash.hasher(), data)
                .map_err(|e| anyhow::anyhow!("approval hash: {e}"))?,
        )),
        None => Ok(None),
    }
}

/// The validation result the validators of an event signed.
///
/// Read off the event's own stored components (mirrors the subject
/// verifier: post-state hashes plus the current request and
/// approval hashes). Genesis carries genesis metadata instead of
/// a hash bundle.
pub fn validation_result_from_parts(
    validation: &ValidationData,
    approval_data_hash: Option<DigestIdentifier>,
) -> Result<ValidationRes> {
    match &validation.validation_metadata {
        ValidationMetadata::Metadata(metadata) => {
            Ok(ValidationRes::Create {
                vali_req_hash: validation.validation_req_hash.clone(),
                subject_metadata: metadata.clone(),
            })
        }
        ValidationMetadata::ModifiedHash {
            modified_metadata_without_propierties_hash,
            propierties_hash,
            event_request_hash,
            viewpoints_hash,
        } => Ok(ValidationRes::Response {
            vali_req_hash: validation.validation_req_hash.clone(),
            modified_metadata_without_propierties_hash:
                modified_metadata_without_propierties_hash.clone(),
            propierties_hash: propierties_hash.clone(),
            event_request_hash: event_request_hash.clone(),
            viewpoints_hash: viewpoints_hash.clone(),
            approval_data_hash,
        }),
    }
}

/// Validator signatures over the rebuilt result plus their quorum.
pub fn check_validation_signatures(
    validation: &ValidationData,
    rebuilt: &ValidationRes,
    validators: &RoleDataRegister,
) -> Result<()> {
    for signature in validation.validators_signatures.iter() {
        let signed =
            Signed::from_parts(rebuilt.clone(), signature.clone());
        if signed.verify().is_err() {
            bail!("validator signature invalid");
        }
    }
    let signers: HashSet<PublicKey> = validation
        .validators_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    if signers.is_empty() {
        bail!("no validator signatures");
    }
    if !check_quorum_signers(&signers, &validators.quorum, &validators.workers)
    {
        bail!("validator quorum not reached");
    }
    Ok(())
}

pub enum ResponseSummary {
    Reboot,
    Ok,
}
