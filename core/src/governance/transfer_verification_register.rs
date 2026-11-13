use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::PersistentActor;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::{
    db::Storable,
    model::common::{crash_system, purge_storage},
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
    register: HashMap<DigestIdentifier, (u64, PublicKey, bool)>,
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
    /// Records an unverified passage hint: the aux could not be
    /// evidence-checked yet, so the proof stays speculative until a
    /// later batch verifies or refutes it. Never overwrites an
    /// existing entry: the first verifier wins, and only a firm
    /// record (or removal) replaces it.
    RecordSpeculativeTransfer {
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
    },
    GetVerifiedTransferSn {
        subject_id: DigestIdentifier,
    },
    /// Same lookup as above, but also reports whether the proof is
    /// still speculative (recorded without evidence). Used to decide
    /// re-verification, free passage and rollback; the plain lookup
    /// keeps reporting any proof so callers observe H6 behavior.
    GetVerifiedTransferDetail {
        subject_id: DigestIdentifier,
    },
}

impl Message for TransferVerificationRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::PurgeStorage
                | Self::RecordVerifiedTransfer { .. }
                | Self::RecordSpeculativeTransfer { .. }
                | Self::Remove { .. }
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransferVerificationRegisterResponse {
    Ok,
    VerifiedTransferSn(Option<(u64, PublicKey)>),
    VerifiedTransferDetail(Option<(u64, PublicKey, bool)>),
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
    RecordSpeculativeTransfer {
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
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

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
        _: ActorPath,
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
            TransferVerificationRegisterMessage::Remove { subject_id } => {
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
            TransferVerificationRegisterMessage::RecordSpeculativeTransfer {
                subject_id,
                transfer_sn,
                sender,
            } => {
                self.on_event(
                    TransferVerificationRegisterEvent::RecordSpeculativeTransfer {
                        subject_id: subject_id.clone(),
                        transfer_sn,
                        sender: sender.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "RecordSpeculativeTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Speculative transfer hint recorded"
                );

                Ok(TransferVerificationRegisterResponse::Ok)
            }
            TransferVerificationRegisterMessage::GetVerifiedTransferSn {
                subject_id,
            } => {
                let result = self
                    .register
                    .get(&subject_id)
                    .cloned()
                    .map(|(sn, sender, _)| (sn, sender));

                debug!(
                    msg_type = "GetVerifiedTransferSn",
                    subject_id = %subject_id,
                    verified = ?result,
                    "Transfer verification lookup completed"
                );

                Ok(TransferVerificationRegisterResponse::VerifiedTransferSn(
                    result,
                ))
            }
            TransferVerificationRegisterMessage::GetVerifiedTransferDetail {
                subject_id,
            } => {
                let result = self.register.get(&subject_id).cloned();

                debug!(
                    msg_type = "GetVerifiedTransferDetail",
                    subject_id = %subject_id,
                    verified = ?result,
                    "Transfer verification detail lookup completed"
                );

                Ok(
                    TransferVerificationRegisterResponse::VerifiedTransferDetail(
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
        if let Err(e) = self.persist(event, ctx).await {
            error!(
                error = %e,
                "Failed to persist transfer verification register event"
            );
            crash_system(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for TransferVerificationRegister {
    type InitParams = ();
    type State = Self;

    /// Pruned event log: only the latest snapshot plus pending
    /// events touch disk. History nobody replays is deleted with
    /// every snapshot instead of accumulating forever.
    fn prune_events_on_snapshot() -> bool {
        true
    }

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            TransferVerificationRegisterEvent::Remove { subject_id } => {
                inner.register.remove(subject_id);

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
                inner
                    .register
                    .entry(subject_id.to_owned())
                    .and_modify(
                        |(existing_sn, existing_sender, speculative)| {
                            if *transfer_sn > *existing_sn
                                || (*transfer_sn == *existing_sn
                                    && *speculative)
                            {
                                *existing_sn = *transfer_sn;
                                *existing_sender = sender.clone();
                                *speculative = false;
                            }
                        },
                    )
                    .or_insert_with(|| {
                        (*transfer_sn, sender.clone(), false)
                    });

                debug!(
                    event_type = "RecordVerifiedTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Transfer verification register state updated"
                );
            }
            TransferVerificationRegisterEvent::RecordSpeculativeTransfer {
                subject_id,
                transfer_sn,
                sender,
            } => {
                inner
                    .register
                    .entry(subject_id.to_owned())
                    .or_insert_with(|| {
                        (*transfer_sn, sender.clone(), true)
                    });

                debug!(
                    event_type = "RecordSpeculativeTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Speculative transfer hint stored"
                );
            }
        };

        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        Arc::new(self.clone())
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        *self = (*state).clone();
    }
}

#[async_trait]
impl Storable for TransferVerificationRegister {}
