use crate::{
    model::{ network::TimeOutResponse},
};
use identity::{Signature};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};


const TARGET_RESPONSE: &str = "Ave-Validation-Response";

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
