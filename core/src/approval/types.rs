use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};


#[derive(
    Default,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    PartialEq,
    BorshDeserialize,
    BorshSerialize,
)]
pub enum VotationType {
    #[default]
    Manual,
    AlwaysAccept,
}

impl From<bool> for VotationType {
    fn from(passvotation: bool) -> Self {
        if passvotation {
            return Self::AlwaysAccept;
        }
        Self::Manual
    }
}
