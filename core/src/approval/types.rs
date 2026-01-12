use std::fmt::Display;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ApprovalStateRes {
    /// Request for approval which is in responded status and accepted
    RespondedAccepted,
    /// Request for approval which is in responded status and rejected
    RespondedRejected,
    /// The approval entity is obsolete.
    Obsolete,
}

impl Display for ApprovalStateRes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            ApprovalStateRes::RespondedAccepted => {
                "RespondedAccepted".to_owned()
            }
            ApprovalStateRes::RespondedRejected => {
                "RespondedRejected".to_owned()
            }
            ApprovalStateRes::Obsolete => "Obsolete".to_owned(),
        };
        write!(f, "{}", string,)
    }
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BorshDeserialize,
    BorshSerialize,
)]
pub enum ApprovalState {
    /// The approval entity is pending a response.
    #[default]
    Pending,
    /// Request for approval which is in responded status and accepted
    RespondedAccepted,
    /// Request for approval which is in responded status and rejected
    RespondedRejected,
    /// The approval entity is obsolete.
    Obsolete,
}

impl Display for ApprovalState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let string = match self {
            ApprovalState::RespondedAccepted => "RespondedAccepted".to_owned(),
            ApprovalState::RespondedRejected => "RespondedRejected".to_owned(),
            ApprovalState::Obsolete => "Obsolete".to_owned(),
            ApprovalState::Pending => "Pending".to_owned(),
        };
        write!(f, "{}", string,)
    }
}

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