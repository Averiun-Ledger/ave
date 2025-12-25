//! # Helper service
//!

use crate::Error;
use ave_actors::ActorError;
use network::CommandHelper as Command;
use tokio::sync::mpsc::Sender;

use super::NetworkMessage;

/// The Helper service.
#[derive(Debug, Clone)]
pub struct HelperService {
    /// The command sender to communicate with the worker.
    command_sender: Sender<Command<NetworkMessage>>,
}

impl HelperService {
    /// Create a new `HelperService`.
    pub fn new(command_sender: Sender<Command<NetworkMessage>>) -> Self {
        Self { command_sender }
    }

    /// Send command to the network worker.
    pub async fn send_command(
        &mut self,
        command: Command<NetworkMessage>,
    ) -> Result<(), ActorError> {
        self.command_sender
            .send(command)
            .await
            .map_err(|e|  ActorError::Functional(Error::Network(e.to_string()).to_string()))
    }

    /// Send a message to the Helper worker.
    pub fn sender(&self) -> Sender<Command<NetworkMessage>> {
        self.command_sender.clone()
    }
}
