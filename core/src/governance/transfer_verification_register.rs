use std::collections::HashMap;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::{
    db::Storable,
    model::common::{emit_fail, purge_storage},
};

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct TransferVerificationRegister {
    register: HashMap<DigestIdentifier, (u64, PublicKey)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransferVerificationRegisterMessage {
    PurgeStorage,
    Remove {
        subject_id: DigestIdentifier,
    },
    RecordVerifiedTransfer {
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
    },
    GetVerifiedTransferSn {
        subject_id: DigestIdentifier,
    },
}

impl Message for TransferVerificationRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::PurgeStorage
                | Self::RecordVerifiedTransfer { .. }
                | Self::Remove { .. }
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransferVerificationRegisterResponse {
    Ok,
    VerifiedTransferSn(Option<(u64, PublicKey)>),
}

impl Response for TransferVerificationRegisterResponse {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum TransferVerificationRegisterEvent {
    Remove {
        subject_id: DigestIdentifier,
    },
    RecordVerifiedTransfer {
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
    },
}

impl Event for TransferVerificationRegisterEvent {}

#[async_trait]
impl Actor for TransferVerificationRegister {
    type Message = TransferVerificationRegisterMessage;
    type Event = TransferVerificationRegisterEvent;
    type Response = TransferVerificationRegisterResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("TransferVerificationRegister"),
            |parent_span| {
                info_span!(parent: parent_span, "TransferVerificationRegister")
            },
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self
            .init_store(
                "transfer_verification_register",
                Some(ctx.path().parent().key().to_owned()),
                false,
                ctx,
            )
            .await
        {
            error!(
                error = %e,
                "Failed to initialize transfer_verification_register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for TransferVerificationRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TransferVerificationRegisterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<TransferVerificationRegisterResponse, ActorError> {
        match msg {
            TransferVerificationRegisterMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    "Transfer verification register storage purged"
                );

                Ok(TransferVerificationRegisterResponse::Ok)
            }
            TransferVerificationRegisterMessage::Remove {
                subject_id,
            } => {
                self.on_event(
                    TransferVerificationRegisterEvent::Remove {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Remove",
                    subject_id = %subject_id,
                    "Transfer verification register entry removed"
                );

                Ok(TransferVerificationRegisterResponse::Ok)
            }
            TransferVerificationRegisterMessage::RecordVerifiedTransfer {
                subject_id,
                transfer_sn,
                sender,
            } => {
                self.on_event(
                    TransferVerificationRegisterEvent::RecordVerifiedTransfer {
                        subject_id: subject_id.clone(),
                        transfer_sn,
                        sender: sender.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "RecordVerifiedTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Transfer verification recorded"
                );

                Ok(TransferVerificationRegisterResponse::Ok)
            }
            TransferVerificationRegisterMessage::GetVerifiedTransferSn {
                subject_id,
            } => {
                let result = self.register.get(&subject_id).cloned();

                debug!(
                    msg_type = "GetVerifiedTransferSn",
                    subject_id = %subject_id,
                    verified = ?result,
                    "Transfer verification lookup completed"
                );

                Ok(
                    TransferVerificationRegisterResponse::VerifiedTransferSn(
                        result,
                    ),
                )
            }
        }
    }

    async fn on_event(
        &mut self,
        event: TransferVerificationRegisterEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist transfer verification register event"
            );
            emit_fail(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for TransferVerificationRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(
        &mut self,
        event: &Self::Event,
    ) -> Result<(), ActorError> {
        match event {
            TransferVerificationRegisterEvent::Remove {
                subject_id,
            } => {
                self.register.remove(subject_id);

                debug!(
                    event_type = "Remove",
                    subject_id = %subject_id,
                    "Transfer verification register state removed"
                );
            }
            TransferVerificationRegisterEvent::RecordVerifiedTransfer {
                subject_id,
                transfer_sn,
                sender,
            } => {
                self.register
                    .entry(subject_id.to_owned())
                    .and_modify(|(existing_sn, existing_sender)| {
                        if *transfer_sn > *existing_sn {
                            *existing_sn = *transfer_sn;
                            *existing_sender = sender.clone();
                        }
                    })
                    .or_insert((*transfer_sn, sender.clone()));

                debug!(
                    event_type = "RecordVerifiedTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Transfer verification register state updated"
                );
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for TransferVerificationRegister {}
