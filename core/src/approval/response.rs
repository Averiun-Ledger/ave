use crate::model::{ network::TimeOutResponse};
use identity::Signature;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

use super::request::ApprovalReq;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum ApprovalRes {
    Response(Signature, bool),
    TimeOut(TimeOutResponse),
}

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
pub struct ApprovalSignature {
    pub request: ApprovalReq,
    pub response: bool,
}