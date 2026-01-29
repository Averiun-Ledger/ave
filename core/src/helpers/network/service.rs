//! # Helper service
//!

use ave_actors::ActorError;
use network::CommandHelper as Command;
use tokio::sync::mpsc::Sender;

use super::NetworkMessage;

/// The Helper service.
#[derive(Debug, Clone)]
pub struct NetworkSender {
    /// The command sender to communicate with the worker.
    command_sender: Sender<Command<NetworkMessage>>,
}

impl NetworkSender {
    /// Create a new `NetworkSender`.
    pub fn new(command_sender: Sender<Command<NetworkMessage>>) -> Self {
        Self { command_sender }
    }

    /// Send command to the network worker.
    pub async fn send_command(
        &self,
        command: Command<NetworkMessage>,
    ) -> Result<(), ActorError> {
        self.command_sender.send(command).await.map_err(|e| {
            ActorError::Functional{description: e.to_string()}
        })
    }

    /// Send a message to the Helper worker.
    pub fn sender(&self) -> Sender<Command<NetworkMessage>> {
        self.command_sender.clone()
    }
}
