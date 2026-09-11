//! # Helper service
//!

use ave_actors::ActorError;
use ave_network::CommandHelper as Command;
use tokio::sync::mpsc::Sender;
use tracing::error;

#[cfg(feature = "test")]
use super::test_faults::{OutboundVerdict, SharedFaultRegistry};
use super::NetworkMessage;

/// The Helper service.
#[derive(Debug, Clone)]
pub struct NetworkSender {
    /// The command sender to communicate with the worker.
    command_sender: Sender<Command<NetworkMessage>>,
    /// Test-only fault registry, consulted before anything reaches the
    /// command channel so an injected failure can fail the send itself.
    #[cfg(feature = "test")]
    faults: SharedFaultRegistry,
}

impl NetworkSender {
    /// Create a new `NetworkSender`.
    #[cfg(not(feature = "test"))]
    pub const fn new(command_sender: Sender<Command<NetworkMessage>>) -> Self {
        Self { command_sender }
    }

    /// Create a new `NetworkSender`.
    #[cfg(feature = "test")]
    pub fn new(
        command_sender: Sender<Command<NetworkMessage>>,
        faults: SharedFaultRegistry,
    ) -> Self {
        Self {
            command_sender,
            faults,
        }
    }

    /// Send command to the network worker.
    pub async fn send_command(
        &self,
        command: Command<NetworkMessage>,
    ) -> Result<(), ActorError> {
        #[cfg(feature = "test")]
        let command = match command {
            Command::SendMessage { mut message } => {
                // Test infrastructure: the lock is never held across an
                // await and poisoning only means the test panicked.
                #[allow(clippy::unwrap_used)]
                let verdict = self
                    .faults
                    .lock()
                    .unwrap()
                    .check_outbound(&mut message);
                match verdict {
                    OutboundVerdict::Pass => Command::SendMessage { message },
                    OutboundVerdict::Drop | OutboundVerdict::Held => {
                        return Ok(())
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

        self.command_sender.send(command).await.map_err(|e| {
            error!(
                error = %e,
                "Failed to send command to network worker"
            );
            ActorError::Functional {
                description: e.to_string(),
            }
        })
    }

    /// Send a message to the Helper worker.
    pub fn sender(&self) -> Sender<Command<NetworkMessage>> {
        self.command_sender.clone()
    }
}
