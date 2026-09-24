use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Default,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BorshDeserialize,
    BorshSerialize,
)]
pub enum VotationType {
    #[default]
    Manual,
    AlwaysAccept,
}
