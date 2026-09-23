use ave_common::identity::{DigestIdentifier, PublicKey};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum ApprovalRes {
    Response {
        approval_req_hash: DigestIdentifier,
        agrees: bool,
        req_subject_data_hash: DigestIdentifier,
    },
    /// The approver is alive but has not decided yet (manual voting).
    Pending,
    /// The approver cannot vote: it does not track the subject or its
    /// governance version is behind the request one.
    Unavailable,
    /// The approver is ahead of the request's governance version: the
    /// requester built the request on a stale governance and must abort
    /// it. Carries the reason for the abort.
    Abort(String),
    /// Signed by a VALIDATOR, not by the approver: after the deadline the
    /// approver `who` never answered, so the validator attests the
    /// timeout. If the approver's vote arrives later it wins over this
    /// attestation (both must never coexist in the final evidence).
    TimeOut {
        approval_req_hash: DigestIdentifier,
        who: PublicKey,
    },
}

/// Acknowledgement of an approval collection request (validator →
/// requester). Flow control only — it is not evidence, so it is not
/// signed: the coordinator gates it on the transport sender.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum ApprovalCollectAck {
    /// Static checks passed: the validator opened the collection.
    Accepted,
    /// The validator is behind the request's governance version and can
    /// not serve it: the requester replaces it from the pending pool.
    Unavailable,
    /// The requester is behind the validator's governance version: it
    /// must sync its governance and reboot the request.
    Reboot,
}
