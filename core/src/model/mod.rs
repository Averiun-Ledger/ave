//! # Data model for Ave base.
//!
//! This module contains the data model for the Ave base.
//!

pub mod common;
pub mod event;
pub mod network;
pub mod patch;
pub mod request;

use event::{Event as AveEvent, Ledger, ProofEvent};
pub use ave_common::Namespace;

use crate::{
    EventRequest,
    approval::{
        request::ApprovalReq,
        response::{ApprovalRes, ApprovalSignature},
    },
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    validation::{
        proof::ValidationProof, request::ValidationReq, response::ValidationRes,
    },
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignTypesNode {
    EventRequest(EventRequest),
    Validation(Box<ValidationProof>),
    ValidationProofEvent(ProofEvent),
    ValidationReq(Box<ValidationReq>),
    ValidationRes(ValidationRes),
    EvaluationReq(EvaluationReq),
    EvaluationRes(EvaluationRes),
    ApprovalRes(Box<ApprovalRes>),
    ApprovalReq(ApprovalReq),
    ApprovalSignature(ApprovalSignature),
    Ledger(Ledger),
    Event(AveEvent),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignTypesSubject {
    Validation(ValidationProof),
}