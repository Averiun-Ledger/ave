use ave_common::{
    governance::GovernanceEvent,
    identity::{DigestIdentifier, Signed},
    request::EventRequest,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

/// A struct representing a compilation request.
///
/// Only governance fact
/// events that add a schema or change a contract (or its initial value)
/// go through the compilation phase, and only the governance owner can
/// request it — the same shape as the governance evaluation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct CompilationReq {
    /// The signed event request.
    pub event_request: Arc<Signed<EventRequest>>,

    pub governance_id: DigestIdentifier,

    pub sn: u64,

    pub gov_version: u64,

    /// Effective build pin for this request: the event's pin when it
    /// changes it, else the committed pin. Builders select their local
    /// toolchain by it (or stand down) and votes carry it, so the
    /// request hash cryptographically binds the pin.
    pub pin: String,
}

/// Effective build pin for a compilation request, computed identically
/// by requester and validators.
///
/// The event's pin when it changes it, else the committed pin. Single
/// source so both sides can never disagree on what was requested.
pub fn effective_pin(
    event_request: &EventRequest,
    committed_pin: &str,
) -> String {
    match event_request {
        EventRequest::Fact(fact_request) => {
            serde_json::from_value::<GovernanceEvent>(
                fact_request.payload.0.clone(),
            )
            .ok()
            .and_then(|event| event.toolchain)
            .unwrap_or_else(|| committed_pin.to_owned())
        }
        _ => committed_pin.to_owned(),
    }
}
