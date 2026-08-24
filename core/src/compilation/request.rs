use ave_common::{
    identity::{DigestIdentifier, Signed},
    request::EventRequest,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing a compilation request. Only governance fact
/// events that add a schema or change a contract (or its initial value)
/// go through the compilation phase, and only the governance owner can
/// request it — the same shape as the governance evaluation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct CompilationReq {
    /// The signed event request.
    pub event_request: Signed<EventRequest>,

    pub governance_id: DigestIdentifier,

    pub sn: u64,

    pub gov_version: u64,
}
