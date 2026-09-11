//! Test-only fault injection and network control (feature `test`).
//!
//! Deterministic hooks for the e2e suites: rules installed from the test
//! match on message kind, direction and peer, and act on the traffic at
//! the node's single network chokepoint (the intermediary). Held
//! messages are delivered only when the test releases them, so the test
//! drives the exact interleaving — no sleeps, no log tracing. The whole
//! module is compiled out of production builds.

use super::{ActorMessage, NetworkMessage};
use crate::compilation::artifact::{ArtifactData, ArtifactFetchResult};
use ave_common::identity::PublicKey;
use ave_network::CommandHelper as Command;
use bytes::Bytes;
use std::sync::{Arc, Mutex};
use tokio::sync::mpsc;

/// Direction of the traffic a rule matches.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultDirection {
    /// Messages this node sends.
    Outbound,
    /// Messages this node receives.
    Inbound,
}

/// The network message a rule matches: one unit per `ActorMessage`
/// variant, so adding a protocol variant forces a decision here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultMessage {
    ValidationReq,
    ValidationRes,
    EvaluationReq,
    EvaluationRes,
    ApprovalReq,
    ApprovalRes,
    DistributionLastEventReq,
    DistributionLastEventRes,
    DistributionLedgerReq,
    DistributionLedgerRes,
    DistributionGetLastSn,
    UpdateNoOffer,
    UpdateOffer,
    GovernanceVersionReq,
    GovernanceVersionRes,
    TrackerSyncReq,
    TrackerSyncRes,
    CompilationReq,
    CompilationRes,
    ArtifactProbeReq,
    ArtifactProbeRes,
    ArtifactReq,
    ArtifactRes,
}

pub(crate) fn classify(message: &ActorMessage) -> FaultMessage {
    match message {
        ActorMessage::ValidationReq { .. } => FaultMessage::ValidationReq,
        ActorMessage::ValidationRes { .. } => FaultMessage::ValidationRes,
        ActorMessage::EvaluationReq { .. } => FaultMessage::EvaluationReq,
        ActorMessage::EvaluationRes { .. } => FaultMessage::EvaluationRes,
        ActorMessage::ApprovalReq { .. } => FaultMessage::ApprovalReq,
        ActorMessage::ApprovalRes { .. } => FaultMessage::ApprovalRes,
        ActorMessage::DistributionLastEventReq { .. } => {
            FaultMessage::DistributionLastEventReq
        }
        ActorMessage::DistributionLastEventRes => {
            FaultMessage::DistributionLastEventRes
        }
        ActorMessage::DistributionLedgerReq { .. } => {
            FaultMessage::DistributionLedgerReq
        }
        ActorMessage::DistributionLedgerRes { .. } => {
            FaultMessage::DistributionLedgerRes
        }
        ActorMessage::DistributionGetLastSn { .. } => {
            FaultMessage::DistributionGetLastSn
        }
        ActorMessage::UpdateNoOffer => FaultMessage::UpdateNoOffer,
        ActorMessage::UpdateOffer { .. } => FaultMessage::UpdateOffer,
        ActorMessage::GovernanceVersionReq { .. } => {
            FaultMessage::GovernanceVersionReq
        }
        ActorMessage::GovernanceVersionRes { .. } => {
            FaultMessage::GovernanceVersionRes
        }
        ActorMessage::TrackerSyncReq { .. } => FaultMessage::TrackerSyncReq,
        ActorMessage::TrackerSyncRes { .. } => FaultMessage::TrackerSyncRes,
        ActorMessage::CompilationReq { .. } => FaultMessage::CompilationReq,
        ActorMessage::CompilationRes { .. } => FaultMessage::CompilationRes,
        ActorMessage::ArtifactProbeReq { .. } => {
            FaultMessage::ArtifactProbeReq
        }
        ActorMessage::ArtifactProbeRes { .. } => {
            FaultMessage::ArtifactProbeRes
        }
        ActorMessage::ArtifactReq { .. } => FaultMessage::ArtifactReq,
        ActorMessage::ArtifactRes { .. } => FaultMessage::ArtifactRes,
    }
}

/// What a matching rule does with the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaultAction {
    /// The message never leaves / is never delivered. Outbound, the
    /// sender's `send_command` still succeeds — a silent loss.
    Drop,
    /// The message is kept aside until the test calls `release_held`.
    /// Releasing delivers everything held and removes every hold rule:
    /// to hold the next batch too, install the rule again.
    Hold,
    /// `ArtifactRes` carrying bytes only: the compressed payload is
    /// replaced with garbage — the receiver's decompression fails.
    CorruptCompressed,
    /// `ArtifactRes` carrying bytes only: the wasm inside is corrupted
    /// and recompressed — decompression succeeds, the hash does not
    /// match the anchor.
    CorruptWasm,
    /// Outbound only: the sender's `send_command` fails as if the
    /// network channel were closed. Ignored for inbound traffic.
    FailSend,
}

/// A fault rule: matching messages get `action` applied while it lasts.
#[derive(Debug, Clone)]
pub struct FaultRule {
    pub direction: FaultDirection,
    pub message: FaultMessage,
    /// Restrict to a peer (outbound receiver / inbound sender); `None`
    /// matches every peer.
    pub peer: Option<PublicKey>,
    /// How many messages the rule fires on; `None` fires until cleared.
    pub remaining: Option<usize>,
    pub action: FaultAction,
}

/// Verdict of the outbound check, applied by `NetworkSender`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum OutboundVerdict {
    Pass,
    Drop,
    Held,
    FailSend,
}

/// Verdict of the inbound check, applied by the intermediary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InboundVerdict {
    Pass,
    Drop,
    Held,
}

/// A message kept aside by a hold rule, ready to be re-injected into
/// the node's normal flow on release.
#[derive(Debug)]
enum HeldMessage {
    Outbound { message: NetworkMessage },
    Inbound { sender: [u8; 32], raw: Bytes },
}

/// The per-node fault registry: rules plus the held messages, with the
/// node's own command channel to re-inject releases and test-crafted
/// inbound messages.
#[derive(Debug)]
pub struct TestFaultRegistry {
    rules: Vec<FaultRule>,
    held: Vec<HeldMessage>,
    control: mpsc::Sender<Command<NetworkMessage>>,
}

impl TestFaultRegistry {
    pub fn new(control: mpsc::Sender<Command<NetworkMessage>>) -> Self {
        Self {
            rules: Vec::new(),
            held: Vec::new(),
            control,
        }
    }

    pub fn install(&mut self, rule: FaultRule) {
        self.rules.push(rule);
    }

    pub fn clear(&mut self) {
        self.rules.clear();
        self.held.clear();
    }

    pub fn held_count(&self) -> usize {
        self.held.len()
    }

    /// Finds the first live rule matching the traffic and consumes one
    /// of its occurrences.
    fn take_matching(
        &mut self,
        direction: FaultDirection,
        kind: FaultMessage,
        peer: &PublicKey,
    ) -> Option<FaultAction> {
        let index = self
            .rules
            .iter()
            .position(|rule| {
                rule.direction == direction
                    && rule.message == kind
                    && rule.peer.as_ref().is_none_or(|p| p == peer)
                    && rule.remaining != Some(0)
            })?;
        let action = self.rules[index].action;
        if let Some(remaining) = &mut self.rules[index].remaining {
            *remaining -= 1;
            if *remaining == 0 {
                self.rules.remove(index);
            }
        }
        Some(action)
    }

    /// Outbound check, run by `NetworkSender` before the command
    /// channel so `FailSend` can fail the send itself.
    pub(crate) fn check_outbound(
        &mut self,
        message: &mut NetworkMessage,
    ) -> OutboundVerdict {
        let Some(action) = self.take_matching(
            FaultDirection::Outbound,
            classify(&message.message),
            &message.info.receiver,
        ) else {
            return OutboundVerdict::Pass;
        };
        match action {
            FaultAction::Drop => OutboundVerdict::Drop,
            FaultAction::Hold => {
                self.held.push(HeldMessage::Outbound {
                    message: message.clone(),
                });
                OutboundVerdict::Held
            }
            FaultAction::CorruptCompressed | FaultAction::CorruptWasm => {
                corrupt_artifact(message, action);
                OutboundVerdict::Pass
            }
            FaultAction::FailSend => OutboundVerdict::FailSend,
        }
    }

    /// Inbound check, run by the intermediary after deserialization.
    /// Held messages are stored raw for a faithful re-injection.
    pub(crate) fn check_inbound(
        &mut self,
        sender_key: &PublicKey,
        sender: [u8; 32],
        raw: &Bytes,
        message: &mut NetworkMessage,
    ) -> InboundVerdict {
        let Some(action) = self.take_matching(
            FaultDirection::Inbound,
            classify(&message.message),
            sender_key,
        ) else {
            return InboundVerdict::Pass;
        };
        match action {
            FaultAction::Drop => InboundVerdict::Drop,
            FaultAction::Hold => {
                self.held.push(HeldMessage::Inbound {
                    sender,
                    raw: raw.clone(),
                });
                InboundVerdict::Held
            }
            FaultAction::CorruptCompressed | FaultAction::CorruptWasm => {
                corrupt_artifact(message, action);
                InboundVerdict::Pass
            }
            // There is no `send_command` on the receiving side.
            FaultAction::FailSend => InboundVerdict::Pass,
        }
    }

    /// Takes every held message out as re-injection commands and
    /// removes the hold rules: released messages must flow. The caller
    /// sends the commands AFTER dropping the lock.
    pub fn take_held_commands(
        &mut self,
    ) -> Vec<Command<NetworkMessage>> {
        self.rules.retain(|rule| rule.action != FaultAction::Hold);
        std::mem::take(&mut self.held)
            .into_iter()
            .map(|held| match held {
                HeldMessage::Outbound { message } => {
                    Command::SendMessage { message }
                }
                HeldMessage::Inbound { sender, raw } => {
                    Command::ReceivedMessage {
                        sender,
                        message: raw,
                    }
                }
            })
            .collect()
    }

    /// The node's own command channel, to re-inject releases and
    /// test-crafted inbound messages.
    pub fn control_sender(
        &self,
    ) -> mpsc::Sender<Command<NetworkMessage>> {
        self.control.clone()
    }

    /// Builds the inbound command that delivers a test-crafted message
    /// to this node as if it came from `from` over the network.
    pub fn inject_command(
        message: NetworkMessage,
        from: &PublicKey,
    ) -> Result<Command<NetworkMessage>, String> {
        let raw = rmp_serde::to_vec(&message)
            .map_err(|e| format!("can not serialize message: {}", e))?;
        let sender: [u8; 32] = from
            .as_bytes()
            .try_into()
            .map_err(|_| "public key is not 32 bytes".to_owned())?;
        Ok(Command::ReceivedMessage {
            sender,
            message: Bytes::from(raw),
        })
    }
}

/// The registry handle shared by the network sender, the intermediary
/// and the test-facing API.
pub type SharedFaultRegistry = Arc<Mutex<TestFaultRegistry>>;

/// Applies a corruption action to an `ArtifactRes` payload; any other
/// message passes through untouched.
fn corrupt_artifact(message: &mut NetworkMessage, action: FaultAction) {
    let ActorMessage::ArtifactRes { result, .. } = &mut message.message
    else {
        return;
    };
    let ArtifactFetchResult::Artifact(data) = result else {
        return;
    };
    match action {
        FaultAction::CorruptCompressed => {
            // Not valid zstd: the receiver's decompression fails.
            data.compressed_wasm = vec![0xFF; 64];
        }
        FaultAction::CorruptWasm => {
            // Valid zstd over wrong bytes: the receiver's hash check
            // against the anchor fails.
            let Ok(mut wasm) = data.decompress() else {
                return;
            };
            if let Some(byte) = wasm.first_mut() {
                *byte ^= 0xFF;
            }
            if let Ok(corrupted) = ArtifactData::from_wasm(
                &wasm,
                data.toolchain_fingerprint.clone(),
            ) {
                *data = corrupted;
            }
        }
        _ => {}
    }
}
