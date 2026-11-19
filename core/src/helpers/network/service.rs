//! # Helper service
//!

use ave_actors::ActorError;
use ave_network::CommandHelper as Command;
use tokio::sync::mpsc::Sender;
use tracing::error;

use super::NetworkMessage;
#[cfg(feature = "test")]
use super::test_faults::{OutboundVerdict, SharedFaultRegistry};

/// The Helper service.
#[derive(Debug, Clone)]
pub struct NetworkSender {
    /// Outbound command sender: actor traffic toward the network.
    command_sender: Sender<Command<NetworkMessage>>,
    /// Inbound command sender: traffic from the network toward the
    /// actors. Priority goes to the outbound channel, so inbound
    /// bursts never stall deadline-driven votes.
    inbound_sender: Option<Sender<Command<NetworkMessage>>>,
    /// Effective wire cap shared with the batch builder: messages
    /// are measured once here and rejected loudly instead of being
    /// retried in a loop by a worker that can not shrink them.
    max_message_bytes: usize,
    /// Test-only fault registry, consulted before anything reaches the
    /// command channel so an injected failure can fail the send itself.
    #[cfg(feature = "test")]
    faults: SharedFaultRegistry,
}

impl NetworkSender {
    /// Create a new `NetworkSender`.
    #[cfg(not(feature = "test"))]
    pub const fn new(command_sender: Sender<Command<NetworkMessage>>) -> Self {
        Self {
            command_sender,
            inbound_sender: None,
            max_message_bytes: ave_network::MAX_APP_MESSAGE_BYTES,
        }
    }

    /// Create a new `NetworkSender`.
    #[cfg(feature = "test")]
    pub fn new(
        command_sender: Sender<Command<NetworkMessage>>,
        faults: SharedFaultRegistry,
    ) -> Self {
        Self {
            command_sender,
            inbound_sender: None,
            max_message_bytes: ave_network::MAX_APP_MESSAGE_BYTES,
            faults,
        }
    }

    /// Override the effective wire cap (production wires the
    /// configured value; tests keep the compiled-in default unless
    /// they set their own).
    pub const fn with_max_message_bytes(mut self, max: usize) -> Self {
        self.max_message_bytes = max;
        self
    }

    /// Effective wire cap enforced at the origin.
    pub const fn max_message_bytes(&self) -> usize {
        self.max_message_bytes
    }

    /// Attach the inbound channel. The intermediary wires it at build;
    /// unit harnesses without one keep the single-channel behavior.
    pub fn with_inbound_sender(
        mut self,
        sender: Sender<Command<NetworkMessage>>,
    ) -> Self {
        self.inbound_sender = Some(sender);
        self
    }

    /// Sender for traffic coming from the network (received messages).
    /// Falls back to the outbound channel when no inbound one exists.
    pub fn inbound_sender(&self) -> Sender<Command<NetworkMessage>> {
        self.inbound_sender
            .clone()
            .unwrap_or_else(|| self.command_sender.clone())
    }

    /// Send command to the network worker.
    pub async fn send_command(
        &self,
        command: Command<NetworkMessage>,
    ) -> Result<(), ActorError> {
        #[cfg(feature = "test")]
        let command = match command {
            Command::SendMessage {
                mut message,
                delivery,
            } => {
                // Test infrastructure: the lock is never held across an
                // await; on poisoning (a test already panicked) keep
                // going with the guarded state.
                let verdict = self
                    .faults
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .check_outbound(&mut message);
                match verdict {
                    OutboundVerdict::Pass => {
                        Command::SendMessage { message, delivery }
                    }
                    OutboundVerdict::Drop | OutboundVerdict::Held => {
                        return Ok(());
                    }
                    OutboundVerdict::FailSend => {
                        return Err(ActorError::Functional {
                            description:
                                "injected test fault: network send failed"
                                    .to_owned(),
                        });
                    }
                }
            }
            other => other,
        };

        // Serialize once at the origin: the encoding is measured
        // against the effective cap here (loud error, no silent
        // retry loop downstream) and travels with the message so
        // the intermediary forwards it without re-encoding. Fault
        // mutations above already applied, so the stored bytes are
        // exactly what the peer receives.
        if let Command::SendMessage {
            mut message, delivery, ..
        } = command
        {
            let encoded = rmp_serde::to_vec(&message).map_err(|e| {
                error!(
                    error = %e,
                    "Failed to serialize outbound network message"
                );
                ActorError::Functional {
                    description: e.to_string(),
                }
            })?;
            if encoded.len() > self.max_message_bytes {
                error!(
                    size = encoded.len(),
                    max = self.max_message_bytes,
                    "Outbound network message exceeds the wire cap"
                );
                return Err(ActorError::Functional {
                    description: format!(
                        "Outbound network message ({} bytes) exceeds the wire cap ({} bytes)",
                        encoded.len(),
                        self.max_message_bytes
                    ),
                });
            }
            message.encoded = Some(encoded);

            let sender = self.command_sender.clone();
            sender.send(Command::SendMessage { message, delivery }).await.map_err(|e| {
                error!(
                    error = %e,
                    "Failed to send command to network worker"
                );
                ActorError::Functional {
                    description: e.to_string(),
                }
            })
        } else {
            let sender = match &command {
                Command::ReceivedMessage { .. } => self.inbound_sender(),
                Command::SendMessage { .. } => self.command_sender.clone(),
            };
            sender.send(command).await.map_err(|e| {
                error!(
                    error = %e,
                    "Failed to send command to network worker"
                );
                ActorError::Functional {
                    description: e.to_string(),
                }
            })
        }
    }

    /// Send a message to the Helper worker.
    pub fn sender(&self) -> Sender<Command<NetworkMessage>> {
        self.command_sender.clone()
    }
}

/// Origin-encoding transport contracts: one serialization per send,
/// measured once against the effective cap. The exact buffer travels
/// with the message so the intermediary forwards it instead of
/// re-encoding; faults run before that single encode.
#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};
    use tokio::sync::mpsc;

    use ave_common::identity::{
        DigestIdentifier, PublicKey, keys::DSAlgorithm,
    };

    use crate::compilation::artifact::{
        ArtifactData, ArtifactFetchResult,
    };
    use crate::helpers::network::{
        ActorMessage, NetworkMessage, delivery_of,
    };
    use crate::helpers::network::test_faults::{
        FaultAction, FaultDirection, FaultMessage, FaultRule,
        SharedFaultRegistry, TestFaultRegistry,
    };

    fn test_key() -> PublicKey {
        PublicKey::new(DSAlgorithm::Ed25519, vec![0u8; 32]).unwrap()
    }

    fn test_message() -> NetworkMessage {
        NetworkMessage::new(
            ave_network::ComunicateInfo {
                receiver: test_key(),
                request_id: String::new(),
                version: 0,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::DistributionLastEventRes {
                event_hash: DigestIdentifier::default(),
            },
        )
    }

    fn test_sender(
        tx: mpsc::Sender<Command<NetworkMessage>>,
        cap: usize,
    ) -> (NetworkSender, SharedFaultRegistry) {
        let faults: SharedFaultRegistry =
            Arc::new(Mutex::new(TestFaultRegistry::new(tx.clone())));
        (
            NetworkSender::new(tx, faults.clone())
                .with_max_message_bytes(cap),
            faults,
        )
    }

    #[tokio::test]
    async fn sender_encodes_once_and_enforces_exact_cap() {
        let message = test_message();
        let expected = rmp_serde::to_vec(&message).unwrap();
        let len = expected.len();

        // Exact cap: accepted, and the single encoding travels with
        // the message instead of being recomputed downstream.
        let (tx, mut rx) = mpsc::channel(8);
        let (sender, _) = test_sender(tx, len);
        sender
            .send_command(Command::SendMessage {
                message: message.clone(),
                delivery: delivery_of(&message.message),
            })
            .await
            .unwrap();
        let forwarded = match rx.recv().await.unwrap() {
            Command::SendMessage { message, .. } => message,
            Command::ReceivedMessage { .. } => {
                panic!("expected an outbound send, got inbound")
            }
        };
        assert_eq!(
            forwarded.encoded,
            Some(expected),
            "the origin encoding must travel untouched"
        );

        // One byte over: loud rejection, nothing forwarded and no
        // silent retry downstream.
        let (tx, mut rx) = mpsc::channel(8);
        let (sender, _) = test_sender(tx, len - 1);
        assert!(
            sender
                .send_command(Command::SendMessage {
                    message,
                    delivery: delivery_of(
                        &forwarded.message
                    ),
                })
                .await
                .is_err(),
            "cap+1 must fail at the origin"
        );
        assert!(
            rx.try_recv().is_err(),
            "a rejected message must never reach the worker"
        );
    }

    #[tokio::test]
    async fn sender_applies_faults_before_the_single_encode() {
        // Dropped messages never reach the encode: the fault is
        // evaluated first, and the next message still encodes once.
        let (tx, mut rx) = mpsc::channel(8);
        let (sender, faults) = test_sender(tx, usize::MAX);
        faults.lock().unwrap().install(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventRes,
            peer: None,
            remaining: Some(1),
            action: FaultAction::Drop,
        });
        let message = test_message();
        sender
            .send_command(Command::SendMessage {
                message: message.clone(),
                delivery: delivery_of(&message.message),
            })
            .await
            .unwrap();
        assert!(
            rx.try_recv().is_err(),
            "a dropped message must not be encoded nor sent"
        );
        sender
            .send_command(Command::SendMessage {
                message: message.clone(),
                delivery: delivery_of(&message.message),
            })
            .await
            .unwrap();
        let forwarded = match rx.recv().await.unwrap() {
            Command::SendMessage { message, .. } => message,
            Command::ReceivedMessage { .. } => {
                panic!("expected an outbound send, got inbound")
            }
        };
        assert_eq!(
            forwarded.encoded,
            Some(rmp_serde::to_vec(&message).unwrap()),
            "the message after a drop still encodes exactly once"
        );

        // Corruption mutates before encoding: the single stored
        // encoding already carries the faulted bytes.
        let artifact = NetworkMessage::new(
            ave_network::ComunicateInfo {
                receiver: test_key(),
                request_id: String::new(),
                version: 0,
                receiver_actor: "/user/node/distributor".to_owned(),
            },
            ActorMessage::ArtifactRes {
                request_nonce: 7,
                result: ArtifactFetchResult::Artifact(ArtifactData {
                    compressed_wasm: vec![1, 2, 3, 4],
                    toolchain_fingerprint: None,
                }),
            },
        );
        let plain = rmp_serde::to_vec(&artifact).unwrap();
        faults.lock().unwrap().install(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::ArtifactRes,
            peer: None,
            remaining: Some(1),
            action: FaultAction::CorruptCompressed,
        });
        sender
            .send_command(Command::SendMessage {
                message: artifact,
                delivery: delivery_of(&forwarded.message),
            })
            .await
            .unwrap();
        let corrupted = match rx.recv().await.unwrap() {
            Command::SendMessage { message, .. } => message,
            Command::ReceivedMessage { .. } => {
                panic!("expected an outbound send, got inbound")
            }
        };
        let stored = corrupted.encoded.expect("stored encoding");
        assert_ne!(
            stored, plain,
            "the fault mutation must land in the single encoding"
        );
    }
}
