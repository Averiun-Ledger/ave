use crate::{
    model::{
         Namespace, ValueWrapper, request::EventRequest,
    },
};
use identity::{
    DigestIdentifier, PublicKey, Signed,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

/// A struct representing an evaluation request.
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
pub struct EvaluationReq {
    /// The signed event request.
    pub event_request: Signed<EventRequest>,
    /// The context in which the evaluation is being performed.
    pub context: SubjectContext,
    /// The sequence number of the event.
    pub sn: u64,
    /// The version of the governance contract.
    pub gov_version: u64,

    pub gov_state_init_state: ValueWrapper,

    pub state: ValueWrapper,

    pub new_owner: Option<PublicKey>,
}

/// A struct representing the context in which the evaluation is being performed.
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
pub struct SubjectContext {
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub schema_id: String,
    pub is_owner: bool,
    pub namespace: Namespace,
}