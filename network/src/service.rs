//! # Network service
//!

use crate::{Command, Error};

use tokio::sync::mpsc::Sender;

/// The network service.
#[derive(Debug, Clone)]
pub struct NetworkService {
    /// The command sender to communicate with the worker.
    command_sender: Sender<Command>,
}

impl NetworkService {
    /// Create a new `NetworkService`.
    pub const fn new(command_sender: Sender<Command>) -> Self {
        Self { command_sender }
    }

    /// Send command to the network worker.
    pub async fn send_command(
        &mut self,
        command: Command,
    ) -> Result<(), Error> {
        self.command_sender
            .send(command)
            .await
            .map_err(|e| Error::CommandSend(e.to_string()))
    }

    /// Send a message to the network worker.
    pub fn sender(&self) -> Sender<Command> {
        self.command_sender.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Command;
    use bytes::Bytes;
    use libp2p::PeerId;

    #[tokio::test]
    async fn test_send_command() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(10);
        let mut service = NetworkService::new(tx);

        let peer = PeerId::random();
        let command = Command::SendMessage {
            peer,
            message: Bytes::from_static(b"hello"),
        };

        service.send_command(command).await.unwrap();

        let received = rx.recv().await;
        assert!(received.is_some());
    }

    #[test]
    fn test_sender() {
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let service = NetworkService::new(tx.clone());
        assert_eq!(service.sender().capacity(), tx.capacity());
    }
}
