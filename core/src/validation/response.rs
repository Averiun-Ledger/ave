use crate::model::network::TimeOutResponse;
use ave_common::identity::Signature;

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
    Signature(Signature),
    TimeOut(TimeOutResponse),
    Error(String),
    Reboot,
}
