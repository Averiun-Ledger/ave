use ave_common::{
    ValueWrapper,
    bridge::request::ApprovalState,
    identity::{DigestIdentifier, PublicKey, TimeStamp},
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing an approval request.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct ApprovalReq {
    /// The signed event request.
    pub subject_id: DigestIdentifier,
    /// The sequence number of the event.
    pub sn: u64,
    /// The version of the governance contract.
    pub gov_version: u64,
    /// The patch to apply to the state.
    pub patch: ValueWrapper,

    pub signer: PublicKey,
    /// When the owner issued the request. Together with `deadline` it
    /// fixes the approval window for every node, so validator churn can
    /// never restart it.
    pub issued_at: TimeStamp,
    /// Approvers that have not voted by this instant are counted as
    /// absent. Must be at least `issued_at + MIN_APPROVAL_WINDOW`.
    pub deadline: TimeStamp,
}

/// A stored approval vote with the collection coordinates that
/// identify exactly which request the decision belongs to. Voters
/// echo the coordinates back, so a replaced request conflicts
/// instead of receiving a stale vote.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct StoredApproval {
    /// The voted approval request.
    pub request: ApprovalReq,
    /// Current state of the vote.
    pub state: ApprovalState,
    /// Collection request id that produced this vote.
    pub request_id: String,
    /// Collection version that produced this vote.
    pub version: u64,
}
