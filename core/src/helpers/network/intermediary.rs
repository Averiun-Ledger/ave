use crate::{
    approval::{
        light::{ApprLight, ApprLightMessage},
        persist::{ApprPersist, ApprPersistMessage},
    },
    distribution::{
        coordinator::{DistriCoordinator, DistriCoordinatorMessage},
        worker::{DistriWorker, DistriWorkerMessage},
    },
    evaluation::{
        coordinator::{EvalCoordinator, EvalCoordinatorMessage},
        schema::{EvaluationSchema, EvaluationSchemaMessage},
        worker::{EvalWorker, EvalWorkerMessage},
    },
    update::updater::{Updater, UpdaterMessage},
    validation::{
        coordinator::{ValiCoordinator, ValiCoordinatorMessage},
        schema::{ValidationSchema, ValidationSchemaMessage},
        worker::{ValiWorker, ValiWorkerMessage},
    },
};

use super::error::IntermediaryError;

use super::ActorMessage;
use super::{NetworkMessage, service::NetworkSender};
use ave_actors::{ActorPath, SystemRef};
use ave_common::identity::{DSAlgorithm, PublicKey};
use bytes::Bytes;
use network::Command as NetworkCommand;
use network::CommandHelper as Command;
use network::{PeerId, PublicKeyEd25519};
use rmp_serde::Deserializer;
use serde::Deserialize;
use std::{io::Cursor, sync::Arc};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

pub struct Intermediary;

impl Intermediary {
    pub fn build(
        network_sender: mpsc::Sender<NetworkCommand>,
        system: SystemRef,
        token: CancellationToken,
    ) -> Arc<NetworkSender> {
        let (command_sender, mut command_receiver) = mpsc::channel(10000);

        tokio::spawn(async move {
            loop {
                tokio::select! {
                    command = command_receiver.recv() => {
                        if let Some(command) = command && let Err(e) = Self::handle_command(command, &system, &network_sender).await {
                                error!(
                                    error = %e,
                                    "Network intermediary command handling failed"
                                );
                                if let IntermediaryError::NetworkSendFailed { .. } = e {
                                    error!("Network send failed, cancelling token and stopping intermediary");
                                    token.cancel();
                                    break;
                                }
                        }
                    },
                    _ = token.cancelled() => {
                        debug!("Network intermediary cancelled, stopping");
                        break;
                    }
                }
            }
        });

        Arc::new(NetworkSender::new(command_sender))
    }

    async fn handle_command(
        command: Command<NetworkMessage>,
        system: &SystemRef,
        network_sender: &mpsc::Sender<NetworkCommand>,
    ) -> Result<(), IntermediaryError> {
        match command {
            Command::SendMessage { message } => {
                let receiver = message.info.receiver.clone();
                let receiver_actor = message.info.receiver_actor.clone();

                let node_peer = Intermediary::to_peer_id(
                    &message.info.receiver,
                )
                .map_err(|e| {
                    error!(
                        receiver = %receiver,
                        receiver_actor = %receiver_actor,
                        error = %e,
                        "Failed to convert public key to peer ID"
                    );
                    e
                })?;

                let network_message =
                    rmp_serde::to_vec(&message).map_err(|error| {
                        error!(
                            receiver = %receiver,
                            receiver_actor = %receiver_actor,
                            error = %error,
                            "Failed to serialize network message"
                        );
                        IntermediaryError::SerializationFailed {
                            details: error.to_string(),
                        }
                    })?;

                if let Err(error) = network_sender
                    .send(NetworkCommand::SendMessage {
                        peer: node_peer,
                        message: Bytes::from(network_message),
                    })
                    .await
                {
                    error!(
                        receiver = %receiver,
                        receiver_actor = %receiver_actor,
                        error = %error,
                        "Failed to send message to network"
                    );
                    return Err(IntermediaryError::NetworkSendFailed {
                        details: error.to_string(),
                    });
                };

                debug!(
                    receiver = %receiver,
                    receiver_actor = %receiver_actor,
                    "Message sent to network successfully"
                );
            }
            Command::ReceivedMessage { message, sender } => {
                let sender =
                    match PublicKey::new(DSAlgorithm::Ed25519, sender.to_vec())
                    {
                        Ok(sender) => sender,
                        Err(e) => {
                            error!(
                                error = %e,
                                "Failed to parse sender public key"
                            );
                            return Err(IntermediaryError::InvalidPublicKey {
                                details: e.to_string(),
                            });
                        }
                    };

                let cur = Cursor::new(message.to_vec());
                let mut de = Deserializer::new(cur);

                let message: NetworkMessage =
                    match Deserialize::deserialize(&mut de) {
                        Ok(message) => message,
                        Err(e) => {
                            error!(
                                sender = %sender.clone(),
                                error = %e,
                                "Failed to deserialize network message"
                            );
                            return Err(
                                IntermediaryError::DeserializationFailed {
                                    details: e.to_string(),
                                },
                            );
                        }
                    };

                let path = ActorPath::from(message.info.receiver_actor.clone());
                let request_id = message.info.request_id.clone();
                match message.message {
                    ActorMessage::DistributionGetLastSn { subject_id } => {
                        let actor = system
                            .get_actor::<DistriWorker>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;

                        actor
                            .tell(DistriWorkerMessage::GetLastSn {
                                subject_id,
                                info: message.info,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::AuthLastSn { sn } => {
                        let actor = system
                            .get_actor::<Updater>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;
                        actor
                            .tell(UpdaterMessage::NetworkResponse {
                                sn,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::ValidationReq { req } => {
                        let Ok(schema_id) = req.content().get_schema_id()
                        else {
                            error!(
                                sender = %sender.clone(),
                                path = %path,
                                "Invalid schema ID in validation request"
                            );
                            return Err(IntermediaryError::InvalidSchemaId);
                        };

                        // Validator actor.
                        if schema_id.is_gov() {
                            let actor = system
                                .get_actor::<ValiWorker>(&path)
                                .await
                                .map_err(|_| {
                                    IntermediaryError::ActorNotFound {
                                        path: path.to_string(),
                                    }
                                })?;

                            actor
                                .tell(ValiWorkerMessage::NetworkRequest {
                                    validation_req: Box::new(req),
                                    info: message.info,
                                    sender: sender.clone(),
                                })
                                .await
                                .map_err(|e| {
                                    IntermediaryError::SendMessageFailed {
                                        path: path.to_string(),
                                        details: e.to_string(),
                                    }
                                })?;
                        } else {
                            let actor = system
                                .get_actor::<ValidationSchema>(&path)
                                .await
                                .map_err(|_| {
                                    IntermediaryError::ActorNotFound {
                                        path: path.to_string(),
                                    }
                                })?;

                            actor
                                .tell(ValidationSchemaMessage::NetworkRequest {
                                    validation_req: Box::new(req),
                                    info: message.info,
                                    sender: sender.clone(),
                                })
                                .await
                                .map_err(|e| {
                                    IntermediaryError::SendMessageFailed {
                                        path: path.to_string(),
                                        details: e.to_string(),
                                    }
                                })?;
                        }
                    }
                    ActorMessage::EvaluationReq { req } => {
                        if req.content().schema_id.is_gov() {
                            let actor = system
                                .get_actor::<EvalWorker>(&path)
                                .await
                                .map_err(|_| {
                                    IntermediaryError::ActorNotFound {
                                        path: path.to_string(),
                                    }
                                })?;
                            actor
                                .tell(EvalWorkerMessage::NetworkRequest {
                                    evaluation_req: *req,
                                    info: message.info,
                                    sender: sender.clone(),
                                })
                                .await
                                .map_err(|e| {
                                    IntermediaryError::SendMessageFailed {
                                        path: path.to_string(),
                                        details: e.to_string(),
                                    }
                                })?;
                        } else {
                            let actor = system
                                .get_actor::<EvaluationSchema>(&path)
                                .await
                                .map_err(|_| {
                                    IntermediaryError::ActorNotFound {
                                        path: path.to_string(),
                                    }
                                })?;

                            actor
                                .tell(EvaluationSchemaMessage::NetworkRequest {
                                    evaluation_req: req,
                                    info: message.info,
                                    sender: sender.clone(),
                                })
                                .await
                                .map_err(|e| {
                                    IntermediaryError::SendMessageFailed {
                                        path: path.to_string(),
                                        details: e.to_string(),
                                    }
                                })?;
                        }
                    }
                    ActorMessage::ApprovalReq { req } => {
                        let actor = system
                            .get_actor::<ApprPersist>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;

                        actor
                            .tell(ApprPersistMessage::NetworkRequest {
                                approval_req: req,
                                info: message.info,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::DistributionLastEventReq { ledger } => {
                        let actor = match system
                            .get_actor::<DistriWorker>(&path)
                            .await
                        {
                            Ok(actor) => actor,
                            Err(..) => {
                                debug!(
                                    original_path = %path,
                                    fallback_path = "/user/node/distributor",
                                    "Distributor not found at path, using fallback"
                                );
                                let path =
                                    ActorPath::from("/user/node/distributor");
                                system
                                    .get_actor::<DistriWorker>(&path)
                                    .await
                                    .map_err(|_| {
                                        IntermediaryError::ActorNotFound {
                                            path: path.to_string(),
                                        }
                                    })?
                            }
                        };

                        actor
                            .tell(DistriWorkerMessage::LastEventDistribution {
                                ledger,
                                info: message.info,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::DistributionLedgerReq {
                        actual_sn,
                        subject_id,
                    } => {
                        let actor = system
                            .get_actor::<DistriWorker>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;

                        actor
                            .tell(DistriWorkerMessage::SendDistribution {
                                actual_sn,
                                subject_id,
                                info: message.info,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::ValidationRes { res } => {
                        let actor = system
                            .get_actor::<ValiCoordinator>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;

                        actor
                            .tell(ValiCoordinatorMessage::NetworkResponse {
                                validation_res: Box::new(res),
                                request_id: message.info.request_id,
                                version: message.info.version,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::EvaluationRes { res } => {
                        let actor = system
                            .get_actor::<EvalCoordinator>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;

                        actor
                            .tell(EvalCoordinatorMessage::NetworkResponse {
                                evaluation_res: Box::new(res),
                                request_id: message.info.request_id,
                                version: message.info.version,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::ApprovalRes { res } => {
                        let actor = system
                            .get_actor::<ApprLight>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;
                        actor
                            .tell(ApprLightMessage::NetworkResponse {
                                approval_res: *res,
                                request_id: message.info.request_id,
                                version: message.info.version,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::DistributionLedgerRes { ledger, is_all } => {
                        let actor = match system
                            .get_actor::<DistriWorker>(&path)
                            .await
                        {
                            Ok(actor) => actor,
                            Err(_) => {
                                debug!(
                                    original_path = %path,
                                    fallback_path = "/user/node/distributor",
                                    "Distributor not found at path, using fallback"
                                );
                                let path =
                                    ActorPath::from("/user/node/distributor");
                                system
                                    .get_actor::<DistriWorker>(&path)
                                    .await
                                    .map_err(|_| {
                                        IntermediaryError::ActorNotFound {
                                            path: path.to_string(),
                                        }
                                    })?
                            }
                        };

                        actor
                            .tell(DistriWorkerMessage::LedgerDistribution {
                                ledger,
                                info: message.info,
                                is_all,
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                    ActorMessage::DistributionLastEventRes => {
                        let actor = system
                            .get_actor::<DistriCoordinator>(&path)
                            .await
                            .map_err(|_| IntermediaryError::ActorNotFound {
                                path: path.to_string(),
                            })?;
                        actor
                            .tell(DistriCoordinatorMessage::NetworkResponse {
                                sender: sender.clone(),
                            })
                            .await
                            .map_err(|e| {
                                IntermediaryError::SendMessageFailed {
                                    path: path.to_string(),
                                    details: e.to_string(),
                                }
                            })?;
                    }
                }

                debug!(
                    sender = %sender,
                    path = %path,
                    request_id = %request_id,
                    "Network message routed to actor successfully"
                );
            }
        }

        Ok(())
    }

    fn to_peer_id(public_key: &PublicKey) -> Result<PeerId, IntermediaryError> {
        match public_key.algorithm() {
            DSAlgorithm::Ed25519 => {
                let pk_ed =
                    PublicKeyEd25519::try_from_bytes(public_key.as_bytes())
                        .map_err(|e| {
                            IntermediaryError::PeerIdConversionFailed {
                                details: e.to_string(),
                            }
                        })?;

                let pk = network::PublicKeyLibP2P::from(pk_ed);
                Ok(pk.to_peer_id())
            }
        }
    }
}

#[cfg(test)]
mod tests {}
