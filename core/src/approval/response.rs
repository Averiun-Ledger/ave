use crate::model::network::TimeOut;
use ave_common::identity::DigestIdentifier;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

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
    Response {
        approval_req_hash: DigestIdentifier,
        agrees: bool,
        req_subject_data_hash: DigestIdentifier
    },
    TimeOut(TimeOut),
}