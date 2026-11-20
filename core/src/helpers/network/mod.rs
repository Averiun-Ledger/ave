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
    DistributionLastEventRes {
        event_hash: DigestIdentifier,
    },
    DistributionLedgerReq {
        actual_sn: Option<u64>,
        target_sn: Option<u64>,
        subject_id: DigestIdentifier,
        already_verified_transfer_sn: Option<u64>,
        /// Governance scope the requester is syncing: the receiver
        /// only serves this request from that governance. New peers
        /// always set it; a missing value is a legacy request that
        /// predates scope binding.
        expected_governance_id: Option<DigestIdentifier>,
    },
    DistributionLedgerRes {
        ledger: Vec<Ledger>,
        is_all: bool,
        transfer_event: Option<Box<Ledger>>,
        /// Echo of the request scope above: the receiver validates
        /// the served prefix (and any Create in it) against this
        /// before writing anything.
        expected_governance_id: Option<DigestIdentifier>,
    },
    /// One bounded chunk of a single event that exceeds the wire cap
    /// (fragmented by identity, verified by hash before delivery).
    /// Version 2 shape: older peers fail to decode it and drop it
    /// instead of mistaking a partial payload for a valid batch.
    /// Main and auxiliary fragments share the same group identity
    /// (the main event hash) so the receiver only delivers when both
    /// sides complete and verify.
    DistributionLedgerFrag {
        subject_id: DigestIdentifier,
        /// Identity of this fragmented payload: ledger hash with the
        /// sender configured algorithm. Duplicates and reorders key
        /// on it within the group.
        event_hash: DigestIdentifier,
        event_sn: u64,
        total_bytes: u64,
        chunk_index: u32,
        chunk_total: u32,
        chunk: Vec<u8>,
        /// Hash of the joined Borsh bytes, verified before any
        /// deserialization. Different from the ledger hash, which is
        /// checked after decoding.
        payload_hash: DigestIdentifier,
        /// True for auxiliary transfer fragments, false for the main
        /// event. Both sides share the group below.
        is_aux: bool,
        /// Main event identity this fragment belongs to. For main
        /// fragments it equals `event_hash`; for aux fragments it
        /// names the main event the aux authorizes.
        group_hash: DigestIdentifier,
        /// Main event sequence number the group delivers.
        group_sn: u64,
        /// When set on main fragments, the aux hash the receiver
        /// must also complete before delivery. None means the main
        /// event needs no aux.
        aux_hash: Option<DigestIdentifier>,
        /// Tip-completeness of the response this event belongs to.
        is_all: bool,
        /// Push (last-event) delivery on completion when true, pull
        /// (ledger batch) delivery when false.
        is_push: bool,
        /// Scope echoed from the pull request (`None` on pushes and
        /// legacy requests): the receiver validates the reassembled
        /// Create against it before writing.
        expected_governance_id: Option<DigestIdentifier>,
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

/// Wire version spoken by this node.
///
/// Version 2 covers hash-bound acks, bounded fragments with payload
/// hashes and scoped pull copies. Older peers speaking v1 fail to
/// decode those shapes and drop them; the sender treats the lack of
/// a v2 ack as an explicit incompatibility instead of a slow copy.
/// Unmodified v1 messages keep byte-identical encodings.
pub const WIRE_VERSION: u32 = 2;

const fn default_wire_version() -> u32 {
    1
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct NetworkMessage {
    pub info: ComunicateInfo,
    pub message: ActorMessage,
    #[serde(default = "default_wire_version")]
    pub wire_version: u32,
    /// Wire bytes computed once at the origin: the intermediary
    /// forwards them without re-encoding. Never serialized, so the
    /// external bytes are identical with or without it.
    #[serde(skip)]
    pub encoded: Option<Vec<u8>>,
}

impl NetworkMessage {
    pub const fn new(info: ComunicateInfo, message: ActorMessage) -> Self {
        Self {
            info,
            message,
            wire_version: WIRE_VERSION,
            encoded: None,
        }
    }

    /// Minimum wire version understanding this message. Fragments,
    /// hash-bound acks and scoped pull copies require v2; every other
    /// variant stays v1 so mixed connections keep working for
    /// unmodified traffic.
    pub const fn required_wire_version(message: &ActorMessage) -> u32 {
        match message {
            ActorMessage::DistributionLedgerFrag { .. }
            | ActorMessage::DistributionLastEventRes { .. } => 2,
            ActorMessage::DistributionLedgerReq {
                expected_governance_id: Some(_),
                ..
            }
            | ActorMessage::DistributionLedgerRes {
                expected_governance_id: Some(_),
                ..
            } => 2,
            _ => 1,
        }
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
            ActorMessage::DistributionLastEventRes {
                event_hash: DigestIdentifier::default(),
            },
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
        assert_eq!(NetworkMessage::required_wire_version(&message), 2);
        let bytes = rmp_serde::to_vec(&NetworkMessage::new(info, message))
            .expect("encode");
        let decoded: NetworkMessage =
            rmp_serde::from_slice(&bytes).expect("decode");
        assert_eq!(decoded.wire_version, WIRE_VERSION);
    }
}
