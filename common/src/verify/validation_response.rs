//! Validation response shared by the node and the off-chain
//! verification tool.

use super::subject_metadata::Metadata;
use crate::identity::DigestIdentifier;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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
