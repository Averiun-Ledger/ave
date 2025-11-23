use crate::{
    model::{ ValueWrapper, request::EventRequest, },
};
use identity::{DigestIdentifier, Signed};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

const TARGET_REQUEST: &str = "Ave-Approval-Request";

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
    pub event_request: Signed<EventRequest>,
    /// The sequence number of the event.
    pub sn: u64,
    /// The version of the governance contract.
    pub gov_version: u64,
    /// The patch to apply to the state.
    pub patch: ValueWrapper,
    /// The hash of the state after applying the patch.
    pub state_hash: DigestIdentifier,
    /// The hash of the previous event.
    pub hash_prev_event: DigestIdentifier,
    /// The hash of the previous event.
    pub subject_id: DigestIdentifier,
}
