use ave_actors::Message;
use ave_common::{
    SchemaType,
    identity::{DigestIdentifier, PublicKey, Signed},
};
use ave_network::{ComunicateInfo, Delivery};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    compilation::{request::CompilationReq, response::CompilationRes},
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    governance::witnesses_register::CurrentWitnessSubject,
    model::event::Ledger,
    update::UpdateWitnessOffer,
    validation::{request::ValidationReq, response::ValidationRes},
};

pub mod error;
pub mod intermediary;
pub mod service;
#[cfg(feature = "test")]
pub mod test_faults;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub enum ActorMessage {
    ValidationReq {
        req: Signed<ValidationReq>,
    },
    ValidationRes {
        res: Signed<ValidationRes>,
    },
    EvaluationReq {
        req: Box<Signed<EvaluationReq>>,
    },
    EvaluationRes {
        res: EvaluationRes,
    },
    ApprovalReq {
        req: Signed<ApprovalReq>,
        /// Actor path the asking validator listens on for the vote.
        asker_actor: String,
    },
    /// A validator re-asks an approver for its vote without resending
    /// the full request (approval phase, validator → approver). The
    /// approver answers from its stored request, or with `NeedFull`
    /// when it never received it. A validator on an older release
    /// fails to decode this ask and stays silent on it (its full
    /// first probe still works) — liveness degrades to full probes,
    /// never to silence.
    ApprovalHashPing {
        approval_req_hash: DigestIdentifier,
        /// Actor path the asking validator listens on for the vote.
        asker_actor: String,
    },
    /// The requester asks a validator to collect the approver votes for
    /// this approval request (approval phase, owner → validator).
    ApprovalCollectReq {
        req: Signed<ApprovalReq>,
    },
    /// A validator acknowledges a collection request (approval phase,
    /// validator → owner coordinator).
    ApprovalCollectAck {
        approval_req_hash: DigestIdentifier,
        ack: crate::approval::response::ApprovalCollectAck,
    },
    ApprovalRes {
        res: Box<Signed<ApprovalRes>>,
    },
    /// A validator pushes a newly observed approver vote to the
    /// requester.
    ApprovalVoteReport {
        res: Box<Signed<ApprovalRes>>,
    },
    /// The requester asks a validator for the votes observed so far
    /// (keepalive). `wanted` holds the approvers the requester still
    /// needs evidence about; `None` asks for the full snapshot (legacy
    /// behavior and periodic backstop). Unknown fields are ignored on
    /// decode, so a validator on an older release answers the full
    /// snapshot — liveness degrades to full probes, never to silence.
    ApprovalStatusReq {
        approval_req_hash: DigestIdentifier,
        wanted: Option<HashSet<PublicKey>>,
    },
    /// A validator answers the keepalive ask with its votes.
    ApprovalStatusRes {
        approval_req_hash: DigestIdentifier,
        votes: Vec<Signed<ApprovalRes>>,
    },
    DistributionLastEventReq {
        ledger: Box<Ledger>,
    },
    DistributionLastEventRes,
    DistributionLedgerReq {
        actual_sn: Option<u64>,
        target_sn: Option<u64>,
        subject_id: DigestIdentifier,
        already_verified_transfer_sn: Option<u64>,
    },
    DistributionLedgerRes {
        ledger: Vec<Ledger>,
        is_all: bool,
        transfer_event: Option<Box<Ledger>>,
    },
    DistributionGetLastSn {
        subject_id: DigestIdentifier,
        actual_sn: Option<u64>,
        receiver_actor: String,
    },
    UpdateNoOffer,
    UpdateOffer {
        offer: UpdateWitnessOffer,
    },
    GovernanceVersionReq {
        subject_id: DigestIdentifier,
        receiver_actor: String,
    },
    GovernanceVersionRes {
        version: u64,
    },
    TrackerSyncReq {
        subject_id: DigestIdentifier,
        request_nonce: u64,
        governance_version: u64,
        after_subject_id: Option<DigestIdentifier>,
        limit: usize,
        receiver_actor: String,
    },
    TrackerSyncRes {
        request_nonce: u64,
        governance_version: u64,
        items: Vec<CurrentWitnessSubject>,
        next_cursor: Option<DigestIdentifier>,
    },
    CompilationReq {
        req: Box<Signed<CompilationReq>>,
    },
    CompilationRes {
        res: CompilationRes,
    },
    ArtifactProbeReq {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        receiver_actor: String,
    },
    ArtifactProbeRes {
        request_nonce: u64,
        result: crate::compilation::artifact::ArtifactProbeResult,
    },
    ArtifactReq {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        receiver_actor: String,
    },
    ArtifactRes {
        request_nonce: u64,
        result: crate::compilation::artifact::ArtifactFetchResult,
    },
}

/// Wire version spoken by this node. Bumped only when a new
/// `ActorMessage` variant without a legacy fallback ships; every
/// variant today requires v1. Messages carry the sender version so a
/// newer node can degrade to the peer version instead of silencing an
/// older one. The peer-version map ships with the first v2 variant.
pub const WIRE_VERSION: u32 = 1;

const fn default_wire_version() -> u32 {
    1
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMessage {
    pub info: ComunicateInfo,
    pub message: ActorMessage,
    #[serde(default = "default_wire_version")]
    pub wire_version: u32,
}

impl NetworkMessage {
    pub const fn new(info: ComunicateInfo, message: ActorMessage) -> Self {
        Self {
            info,
            message,
            wire_version: WIRE_VERSION,
        }
    }

    /// Minimum wire version understanding this message. Every variant
    /// today is v1; a future variant without a legacy fallback returns
    /// a higher version and the sender degrades for older peers.
    pub const fn required_wire_version(message: &ActorMessage) -> u32 {
        let _ = message;
        1
    }
}

impl Message for NetworkMessage {}

/// Delivery policy of a protocol message.
///
/// A sender with its own retry
/// machine (a coordinator with retry, a probe or keepalive schedule, a
/// periodic sync tick) retransmits by design, so its messages are
/// `Direct` and never buffered; only one-shot pushes whose sole backup
/// is a slow cycle are `Queued`.
///
/// The network is a best-effort async boundary: `Ok` on send means the
/// attempt was accepted, not that the peer received it. A `Direct`
/// message to an unknown/unidentified peer is dropped (counted, redial
/// kicked) and the domain retry owns recovery.
pub const fn delivery_of(message: &ActorMessage) -> Delivery {
    match message {
        ActorMessage::ApprovalVoteReport { .. } => Delivery::Queued,
        _ => Delivery::Direct,
    }
}

#[cfg(test)]
mod tests {
    use ave_common::identity::DSAlgorithm;

    use super::*;

    #[derive(Serialize)]
    struct LegacyMessage<'a> {
        info: &'a ComunicateInfo,
        message: &'a ActorMessage,
    }

    fn sample() -> (ComunicateInfo, ActorMessage) {
        let receiver = PublicKey::new(DSAlgorithm::Ed25519, vec![1u8; 32])
            .expect("sample key");
        (
            ComunicateInfo {
                request_id: String::from("req"),
                version: 0,
                receiver,
                receiver_actor: String::from("actor"),
            },
            ActorMessage::DistributionLastEventRes,
        )
    }

    #[test]
    fn wire_version_defaults_to_one_for_legacy_bytes() {
        let (info, message) = sample();
        let bytes = rmp_serde::to_vec(&LegacyMessage {
            info: &info,
            message: &message,
        })
        .expect("encode legacy");
        let decoded: NetworkMessage =
            rmp_serde::from_slice(&bytes).expect("decode legacy");
        assert_eq!(decoded.wire_version, 1);
    }

    #[test]
    fn new_messages_stamp_current_wire_version() {
        let (info, message) = sample();
        assert_eq!(NetworkMessage::required_wire_version(&message), 1);
        let bytes = rmp_serde::to_vec(&NetworkMessage::new(info, message))
            .expect("encode");
        let decoded: NetworkMessage =
            rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.wire_version, WIRE_VERSION);
    }
}
