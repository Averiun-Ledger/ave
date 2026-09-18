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
