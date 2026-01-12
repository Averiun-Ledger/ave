use crate::{
    Error,
    approval::{
        light::{ApprLight, ApprLightMessage},
        persist::{ApprPersist, ApprPersistMessage},
    },
    distribution::distributor::{Distributor, DistributorMessage},
    evaluation::{
        coordinator::{EvalCoordinator, EvalCoordinatorMessage},
        worker::{EvalWorker, EvalWorkerMessage},
        schema::{EvaluationSchema, EvaluationSchemaMessage},
    },
    update::updater::{Updater, UpdaterMessage},
    validation::{
        schema::{ValidationSchema, ValidationSchemaMessage},
        coordinator::{ValiCoordinator, ValiCoordinatorMessage},
        worker::{ValiWorker, ValiWorkerMessage},
    },
};

use super::ActorMessage;
use super::{NetworkMessage, service::NetworkSender};
use ave_actors::{ActorPath, ActorRef, SystemRef};
use ave_common::{
    Namespace,
    identity::{DSAlgorithm, PublicKey},
};
use bytes::Bytes;
use network::Command as NetworkCommand;
use network::CommandHelper as Command;
use network::{PeerId, PublicKeyEd25519};
use rmp_serde::Deserializer;
use serde::Deserialize;
use std::{io::Cursor, sync::Arc};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::error;

const TARGET_NETWORK: &str = "Ave-Helper-Network";

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
                                error!(TARGET_NETWORK, "{}", e);
                                if let Error::Network(_) = e {
                                    token.cancel();
                                    break;
                                }
                        }
                    },
                    _ = token.cancelled() => {
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
    ) -> Result<(), Error> {
        match command {
            Command::SendMessage { message } => {
                // Public key to peer_id
                let node_peer =
                    Intermediary::to_peer_id(&message.info.receiver)?;

                // Message to Vec<u8>
                let network_message =
                    rmp_serde::to_vec(&message).map_err(|error| {
                        Error::NetworkHelper(format!("{}", error))
                    })?;
                // Send message to network
                if let Err(error) = network_sender
                    .send(NetworkCommand::SendMessage {
                        peer: node_peer,
                        message: Bytes::from(network_message),
                    })
                    .await
                {
                    return Err(Error::Network(format!(
                        "Can not send message to network: {}",
                        error
                    )));
                };
            }
            Command::ReceivedMessage { message, sender } => {
                let sender = match PublicKey::new(
                    DSAlgorithm::Ed25519,
                    sender.to_vec(),
                ) {
                    Ok(sender) => sender,
                    Err(e) => {
                        return Err(Error::NetworkHelper(format!(
                            "Can not convert sender bytes public key into PublicKey: {}",
                            e
                        )));
                    }
                };

                let cur = Cursor::new(message.to_vec());
                let mut de = Deserializer::new(cur);

                let message: NetworkMessage =
                    match Deserialize::deserialize(&mut de) {
                        Ok(message) => message,
                        Err(e) => {
                            return Err(Error::NetworkHelper(format!(
                                "Can not deserialize message: {}",
                                e
                            )));
                        }
                    };

                match message.message {
                    ActorMessage::TransferRes { res } => {
                        let authorizer_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        let authorizer_actor: Option<ActorRef<Updater>> =
                            system.get_actor(&authorizer_path).await;

                        if let Some(authorizer_actor) = authorizer_actor {
                            if let Err(e) = authorizer_actor
                                .tell(UpdaterMessage::TransferResponse {
                                    res,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    authorizer_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                authorizer_path
                            )));
                        };
                    }
                    ActorMessage::Transfer { subject_id } => {
                        let distributor_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        let distributor_actor: Option<ActorRef<Distributor>> =
                            system.get_actor(&distributor_path).await;

                        if let Some(distributor_actor) = distributor_actor {
                            if let Err(e) = distributor_actor
                                .tell(DistributorMessage::Transfer {
                                    subject_id: subject_id.to_string(),
                                    info: message.info,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    distributor_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                distributor_path
                            )));
                        };
                    }
                    ActorMessage::DistributionGetLastSn { subject_id } => {
                        let distributor_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        let distributor_actor: Option<ActorRef<Distributor>> =
                            system.get_actor(&distributor_path).await;

                        if let Some(distributor_actor) = distributor_actor {
                            if let Err(e) = distributor_actor
                                .tell(DistributorMessage::GetLastSn {
                                    subject_id: subject_id.to_string(),
                                    info: message.info,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    distributor_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                distributor_path
                            )));
                        };
                    }
                    ActorMessage::AuthLastSn { sn } => {
                        let authorizer_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        let authorizer_actor: Option<ActorRef<Updater>> =
                            system.get_actor(&authorizer_path).await;

                        if let Some(authorizer_actor) = authorizer_actor {
                            if let Err(e) = authorizer_actor
                                .tell(UpdaterMessage::NetworkResponse {
                                    sn,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    authorizer_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                authorizer_path
                            )));
                        };
                    }
                    ActorMessage::ValidationReq { req } => {
                        // Validator path.
                        let validator_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );

                        let Ok(schema_id) = req.content().get_schema_id()
                        else {
                            return Err(Error::NetworkHelper(
                                "Can not get schema_id from validation request"
                                    .to_string(),
                            ));
                        };

                        // Validator actor.
                        if schema_id.is_gov() {
                            let validator_actor: Option<ActorRef<ValiWorker>> =
                                system.get_actor(&validator_path).await;

                            // We obtain the validator
                            if let Some(validator_actor) = validator_actor {
                                if let Err(e) = validator_actor
                                    .tell(ValiWorkerMessage::NetworkRequest {
                                        validation_req: req,
                                        info: message.info,
                                        sender,
                                    })
                                    .await
                                {
                                    return Err(Error::NetworkHelper(format!(
                                        "Can not send a message to {}: {}",
                                        validator_path, e
                                    )));
                                };
                            } else {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not get Actor: {}",
                                    validator_path
                                )));
                            };
                        } else {
                            let validator_actor: Option<
                                ActorRef<ValidationSchema>,
                            > = system.get_actor(&validator_path).await;

                            // We obtain the validator
                            if let Some(validator_actor) = validator_actor {
                                if let Err(e) = validator_actor
                                    .tell(ValidationSchemaMessage::NetworkRequest {
                                        validation_req: req,
                                        info: message.info,
                                        sender,
                                    })
                                    .await
                                    {
                                        return Err(Error::NetworkHelper(format!("Can not send a message to {}: {}",validator_path, e)));
                                    };
                            } else {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not get Actor: {}",
                                    validator_path
                                )));
                            };
                        }
                    }
                    ActorMessage::EvaluationReq { req } => {
                        // Evaluator path.
                        let evaluator_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );

                        if req.content().schema_id.is_gov() {
                            // Evaluator actor.
                            let evaluator_actor: Option<ActorRef<EvalWorker>> =
                                system.get_actor(&evaluator_path).await;

                            // We obtain the validator
                            if let Some(evaluator_actor) = evaluator_actor {
                                if let Err(e) = evaluator_actor
                                    .tell(EvalWorkerMessage::NetworkRequest {
                                        evaluation_req: req,
                                        info: message.info,
                                        sender,
                                    })
                                    .await
                                {
                                    return Err(Error::NetworkHelper(format!(
                                        "Can not send a message to {}: {}",
                                        evaluator_path, e
                                    )));
                                };
                            } else {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not get Actor: {}",
                                    evaluator_path
                                )));
                            };
                        } else {
                            // Evaluator actor.
                            let evaluator_actor: Option<
                                ActorRef<EvaluationSchema>,
                            > = system.get_actor(&evaluator_path).await;

                            // We obtain the validator
                            if let Some(evaluator_actor) = evaluator_actor {
                                if let Err(e) = evaluator_actor
                            .tell(EvaluationSchemaMessage::NetworkRequest {
                                evaluation_req: Box::new(req),
                                info: message.info,
                                sender
                            })
                            .await
                            {
                                return Err(Error::NetworkHelper(format!("Can not send a message to {}: {}",evaluator_path, e)));
                            };
                            } else {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not get Actor: {}",
                                    evaluator_path
                                )));
                            };
                        }
                    }
                    ActorMessage::ApprovalReq { req } => {
                        let approver_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );

                        // Evaluator actor.
                        let approver_actor: Option<ActorRef<ApprPersist>> =
                            system.get_actor(&approver_path).await;

                        // We obtain the validator
                        if let Some(approver_actor) = approver_actor {
                            if let Err(e) = approver_actor
                                .tell(ApprPersistMessage::NetworkRequest {
                                    approval_req: req,
                                    info: message.info,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    approver_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                approver_path
                            )));
                        };
                    }
                    ActorMessage::DistributionLastEventReq {
                        event,
                        ledger,
                        last_proof,
                        last_vali_res,
                    } => {
                        // Distributor path.
                        let distributor_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );

                        // SI ESTE sdistributor no está disponible quiere decir que el sujeto no existe, enviarlo al distributor del nodo
                        let distributor_actor: Option<ActorRef<Distributor>> =
                            system.get_actor(&distributor_path).await;

                        let distributor_actor = if let Some(distributor_actor) =
                            distributor_actor
                        {
                            distributor_actor
                        } else {
                            let node_distributor_path =
                                ActorPath::from("/user/node/distributor");
                            let node_distributor_actor: Option<
                                ActorRef<Distributor>,
                            > = system.get_actor(&node_distributor_path).await;
                            if let Some(node_distributor_actor) =
                                node_distributor_actor
                            {
                                node_distributor_actor
                            } else {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not get Actor: {}",
                                    node_distributor_path
                                )));
                            }
                        };

                        // We obtain the validator
                        if let Err(e) = distributor_actor
                            .tell(DistributorMessage::LastEventDistribution {
                                event: *event,
                                ledger: *ledger,
                                info: message.info,
                                last_proof: last_proof.clone(),
                                last_vali_res,
                                sender,
                            })
                            .await
                        {
                            return Err(Error::NetworkHelper(format!(
                                "Can not send a message to {}: {}",
                                distributor_actor.path(),
                                e
                            )));
                        };
                    }
                    ActorMessage::DistributionLedgerReq {
                        gov_version,
                        actual_sn,
                        subject_id,
                    } => {
                        let distributor_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        // Validator actor.
                        let distributor_actor: Option<ActorRef<Distributor>> =
                            system.get_actor(&distributor_path).await;

                        if let Some(distributor_actor) = distributor_actor {
                            if let Err(e) = distributor_actor
                                .tell(DistributorMessage::SendDistribution {
                                    gov_version,
                                    actual_sn,
                                    subject_id: subject_id.to_string(),
                                    info: message.info,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    distributor_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                distributor_path
                            )));
                        };
                    }
                    ActorMessage::ValidationRes { res } => {
                        // Validator path.
                        let validator_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        // Validator actor.
                        let validator_actor: Option<ActorRef<ValiCoordinator>> =
                            system.get_actor(&validator_path).await;

                        // We obtain the validator
                        if let Some(validator_actor) = validator_actor {
                            if let Err(e) = validator_actor
                                .tell(ValiCoordinatorMessage::NetworkResponse {
                                    validation_res: res,
                                    request_id: message.info.request_id,
                                    version: message.info.version,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    validator_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                validator_path
                            )));
                        };
                    }
                    ActorMessage::EvaluationRes { res } => {
                        // Validator path.
                        let evaluator_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        // Validator actor.
                        let evaluator_actor: Option<ActorRef<EvalCoordinator>> =
                            system.get_actor(&evaluator_path).await;

                        // We obtain the validator
                        if let Some(evaluator_actor) = evaluator_actor {
                            if let Err(e) = evaluator_actor
                                .tell(EvalCoordinatorMessage::NetworkResponse {
                                    evaluation_res: res,
                                    request_id: message.info.request_id,
                                    version: message.info.version,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    evaluator_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                evaluator_path
                            )));
                        }
                    }
                    ActorMessage::ApprovalRes { res } => {
                        // Validator path.
                        let approver_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        // Validator actor.
                        let approver_actor: Option<ActorRef<ApprLight>> =
                            system.get_actor(&approver_path).await;

                        // We obtain the validator
                        if let Some(approver_actor) = approver_actor {
                            if let Err(e) = approver_actor
                                .tell(ApprLightMessage::NetworkResponse {
                                    approval_res: *res,
                                    request_id: message.info.request_id,
                                    version: message.info.version,
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    approver_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                approver_path
                            )));
                        }
                    }
                    ActorMessage::DistributionLedgerRes {
                        ledger,
                        last_state,
                        namespace,
                        schema_id,
                        governance_id,
                    } => {
                        // Distributor path.
                        let distributor_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );

                        // SI ESTE sdistributor no está disponible quiere decir que el sujeto no existe, enviarlo al distributor del nodo
                        let distributor_actor: Option<ActorRef<Distributor>> =
                            system.get_actor(&distributor_path).await;

                        let distributor_actor = if let Some(distributor_actor) =
                            distributor_actor
                        {
                            distributor_actor
                        } else {
                            let node_distributor_path =
                                ActorPath::from("/user/node/distributor");
                            let node_distributor_actor: Option<
                                ActorRef<Distributor>,
                            > = system.get_actor(&node_distributor_path).await;
                            if let Some(node_distributor_actor) =
                                node_distributor_actor
                            {
                                node_distributor_actor
                            } else {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not get Actor: {}",
                                    node_distributor_path
                                )));
                            }
                        };

                        let namespace = Namespace::from(namespace);

                        // We obtain the validator
                        if let Err(e) = distributor_actor
                            .tell(DistributorMessage::LedgerDistribution {
                                events: ledger,
                                info: message.info,
                                last_state,
                                schema_id,
                                namespace,
                                governance_id,
                                sender,
                            })
                            .await
                        {
                            return Err(Error::NetworkHelper(format!(
                                "Can not send a message to {}: {}",
                                distributor_actor.path(),
                                e
                            )));
                        };
                    }
                    ActorMessage::DistributionLastEventRes => {
                        // Validator path.
                        let distributor_path = ActorPath::from(
                            message.info.receiver_actor.clone(),
                        );
                        // Validator actor.
                        let distributor_actor: Option<ActorRef<Distributor>> =
                            system.get_actor(&distributor_path).await;

                        // We obtain the validator
                        if let Some(evaluator_actor) = distributor_actor {
                            if let Err(e) = evaluator_actor
                                .tell(DistributorMessage::NetworkResponse {
                                    sender,
                                })
                                .await
                            {
                                return Err(Error::NetworkHelper(format!(
                                    "Can not send a message to {}: {}",
                                    distributor_path, e
                                )));
                            };
                        } else {
                            return Err(Error::NetworkHelper(format!(
                                "Can not get Actor: {}",
                                distributor_path
                            )));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn to_peer_id(public_key: &PublicKey) -> Result<PeerId, Error> {
        match public_key.algorithm() {
            DSAlgorithm::Ed25519 => {
                let pk_ed = PublicKeyEd25519::try_from_bytes(public_key.as_bytes()).map_err(|e|
                    Error::NetworkHelper(format!("Invalid Ed25519 public key, can not convert to PeerID: {}", e)))?;

                let pk = network::PublicKeyLibP2P::from(pk_ed);
                Ok(pk.to_peer_id())
            }
        }
    }
}

#[cfg(test)]
mod tests {}
