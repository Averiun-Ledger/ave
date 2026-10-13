//! Approval evidence data shared by the node and the off-chain
//! verification tool.

use crate::identity::{DigestIdentifier, PublicKey, Signature, TimeStamp};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct ApprovalData {
    pub approval_req_signature: Signature,
    pub approval_req_hash: DigestIdentifier,
    /// Anchored from the signed `ApprovalReq` so the request can be
    /// rebuilt exactly during verification.
    pub issued_at: TimeStamp,
    pub deadline: TimeStamp,
    pub approvers_agrees_signatures: Vec<Signature>,
    pub approvers_disagrees_signatures: Vec<Signature>,
    /// Approvers that signed both an accept and a reject for the same
    /// request: excluded from both tallies and counted as absent. The
    /// pair of signatures is the portable evidence of the misbehavior.
    pub double_votes: Vec<(Signature, Signature)>,
    /// Approvers that never answered before the deadline, each with the
    /// validator-signed timeout attestations (signed `ApprovalRes::TimeOut`)
    /// that prove the absence instead of leaving it implicit. Sorted by
    /// approver key, then by validator key. Empty in early closures. An
    /// approver present here must NOT appear in any of the vote lists
    /// (a late answer wins over the timeout attestation).
    pub approvers_timeouts: Vec<(PublicKey, Vec<Signature>)>,
    pub approved: bool,
}
