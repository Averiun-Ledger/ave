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
    register: HashMap<
        DigestIdentifier,
        (u64, PublicKey, Option<DigestIdentifier>, bool),
    >,
}

/// Previous on-disk shape (without the transfer hash): only used to
/// migrate v1 snapshots. New writes always carry the hash.
#[derive(BorshDeserialize, BorshSerialize)]
struct V1TransferVerificationRegister {
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
    /// Same as `RecordVerifiedTransfer`, plus the verified aux hash.
    /// New writes always use this variant; the hashless one only
    /// replays journals written before hashes were recorded, and
    /// those entries never auto-cover: they are revalidated once
    /// and replaced.
    RecordVerifiedTransferV2 {
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
        transfer_hash: DigestIdentifier,
    },
    GetVerifiedTransferSn {
        subject_id: DigestIdentifier,
    },
    /// Same lookup as above, but also reports whether the proof is
    /// still speculative (recorded without evidence). Used to decide
    /// re-verification, free passage and rollback; the plain lookup
    /// keeps reporting any proof so per-sender filtering still
    /// applies to firm proofs.
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
                | Self::RecordVerifiedTransferV2 { .. }
                | Self::RecordSpeculativeTransfer { .. }
                | Self::Remove { .. }
        )
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransferVerificationRegisterResponse {
    Ok,
    VerifiedTransferSn(Option<(u64, PublicKey)>),
    VerifiedTransferDetail(
        Option<(u64, PublicKey, Option<DigestIdentifier>, bool)>,
    ),
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
    /// Same as `RecordVerifiedTransfer`, plus the verified aux hash.
    /// Appended last so old journals keep decoding: variant indices
    /// of history are untouched. New writes always carry the hash;
    /// the hashless variant is read-only history.
    RecordVerifiedTransferV2 {
        subject_id: DigestIdentifier,
        transfer_sn: u64,
        sender: PublicKey,
        transfer_hash: DigestIdentifier,
    },
}

/// Previous on-disk event shape (without the hashed variant): only
/// used to replay v1 journals. Never written by new code.
#[derive(BorshDeserialize, BorshSerialize)]
enum V1TransferVerificationRegisterEvent {
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
            TransferVerificationRegisterMessage::RecordVerifiedTransferV2 {
                subject_id,
                transfer_sn,
                sender,
                transfer_hash,
            } => {
                use TransferVerificationRegisterEvent as ProofEvent;
                self.on_event(
                    ProofEvent::RecordVerifiedTransferV2 {
                        subject_id: subject_id.clone(),
                        transfer_sn,
                        sender: sender.clone(),
                        transfer_hash: transfer_hash.clone(),
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
                    .map(|(sn, sender, _, _)| (sn, sender));

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

    const EVENT_VERSION: u32 = 2;
    const STATE_VERSION: u32 = 2;

    fn upcast_event(
        version: u32,
        bytes: &[u8],
    ) -> Result<Self::Event, ActorError>
    where
        Self::Event: BorshDeserialize,
    {
        match version {
            1 => {
                use TransferVerificationRegisterEvent as Current;
                use V1TransferVerificationRegisterEvent as Previous;
                let old: Previous = borsh::from_slice(bytes).map_err(|e| {
                    ActorError::InvalidConfiguration {
                        component: "persistent event".to_owned(),
                        reason: format!("cannot decode event version 1: {e}"),
                    }
                })?;
                Ok(match old {
                    Previous::Remove { subject_id } => {
                        Current::Remove { subject_id }
                    }
                    Previous::RecordVerifiedTransfer {
                        subject_id,
                        transfer_sn,
                        sender,
                    } => Current::RecordVerifiedTransfer {
                        subject_id,
                        transfer_sn,
                        sender,
                    },
                    Previous::RecordSpeculativeTransfer {
                        subject_id,
                        transfer_sn,
                        sender,
                    } => Current::RecordSpeculativeTransfer {
                        subject_id,
                        transfer_sn,
                        sender,
                    },
                })
            }
            2 => borsh::from_slice(bytes).map_err(|e| {
                ActorError::InvalidConfiguration {
                    component: "persistent event".to_owned(),
                    reason: format!("cannot decode event version 2: {e}"),
                }
            }),
            _ => Err(ActorError::InvalidConfiguration {
                component: "persistent event".to_owned(),
                reason: format!(
                    "unsupported event version {version} (current 2)"
                ),
            }),
        }
    }

    fn upcast_state(
        version: u32,
        bytes: &[u8],
    ) -> Result<(Self::State, u64), ActorError>
    where
        Self::State: BorshDeserialize,
    {
        match version {
            1 => {
                let (old, counter): (V1TransferVerificationRegister, u64) =
                    borsh::from_slice(bytes).map_err(|e| {
                        ActorError::InvalidConfiguration {
                            component: "persistent state".to_owned(),
                            reason: format!(
                                "cannot decode state version 1: {e}"
                            ),
                        }
                    })?;
                let register = old
                    .register
                    .into_iter()
                    .map(|(subject_id, (sn, sender, speculative))| {
                        (subject_id, (sn, sender, None, speculative))
                    })
                    .collect();
                Ok((Self { register }, counter))
            }
            2 => borsh::from_slice(bytes).map_err(|e| {
                ActorError::InvalidConfiguration {
                    component: "persistent state".to_owned(),
                    reason: format!("cannot decode state version 2: {e}"),
                }
            }),
            _ => Err(ActorError::InvalidConfiguration {
                component: "persistent state".to_owned(),
                reason: format!(
                    "unsupported state version {version} (current 2)"
                ),
            }),
        }
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
                        |(
                            existing_sn,
                            existing_sender,
                            existing_hash,
                            speculative,
                        )| {
                            if *transfer_sn > *existing_sn
                                || (*transfer_sn == *existing_sn
                                    && *speculative)
                            {
                                *existing_sn = *transfer_sn;
                                *existing_sender = sender.clone();
                                // Legacy entries carry no hash: never retain
                                // one from the proof they replace.
                                *existing_hash = None;
                                *speculative = false;
                            }
                        },
                    )
                    .or_insert_with(|| {
                        (*transfer_sn, sender.clone(), None, false)
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
                inner.register.entry(subject_id.to_owned()).or_insert_with(
                    || (*transfer_sn, sender.clone(), None, true),
                );

                debug!(
                    event_type = "RecordSpeculativeTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Speculative transfer hint stored"
                );
            }
            TransferVerificationRegisterEvent::RecordVerifiedTransferV2 {
                subject_id,
                transfer_sn,
                sender,
                transfer_hash,
            } => {
                inner
                    .register
                    .entry(subject_id.to_owned())
                    .and_modify(
                        |(
                            existing_sn,
                            existing_sender,
                            existing_hash,
                            speculative,
                        )| {
                            // Higher sn always wins. Same sn replaces a
                            // speculative hint or a legacy hashless proof
                            // from the same sender; a firm hashed proof
                            // from another sender is never stolen.
                            if *transfer_sn > *existing_sn
                                || (*transfer_sn == *existing_sn
                                    && *existing_sender == *sender
                                    && (*speculative
                                        || existing_hash.is_none()))
                            {
                                *existing_sn = *transfer_sn;
                                *existing_sender = sender.clone();
                                *existing_hash = Some(transfer_hash.clone());
                                *speculative = false;
                            }
                        },
                    )
                    .or_insert_with(|| {
                        (
                            *transfer_sn,
                            sender.clone(),
                            Some(transfer_hash.clone()),
                            false,
                        )
                    });

                debug!(
                    event_type = "RecordVerifiedTransfer",
                    subject_id = %subject_id,
                    transfer_sn = transfer_sn,
                    sender = %sender,
                    "Transfer verification register state updated"
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

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::identity::{DSAlgorithm, HashAlgorithm};

    fn subject(byte: u8) -> DigestIdentifier {
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![byte; 32]).unwrap()
    }

    fn sender(byte: u8) -> PublicKey {
        PublicKey::new(DSAlgorithm::Ed25519, vec![byte; 32]).unwrap()
    }

    #[test]
    fn v1_upcasts_keep_legacy_proofs_hashless() {
        let subject_id = subject(1);
        let sender = sender(2);
        let previous =
            V1TransferVerificationRegisterEvent::RecordVerifiedTransfer {
                subject_id: subject_id.clone(),
                transfer_sn: 3,
                sender: sender.clone(),
            };
        let bytes = borsh::to_vec(&previous).unwrap();
        let current =
            <TransferVerificationRegister as PersistentActor>::upcast_event(
                1, &bytes,
            )
            .unwrap();
        assert!(matches!(
            &current,
            TransferVerificationRegisterEvent::RecordVerifiedTransfer {
                subject_id: id,
                transfer_sn: 3,
                sender: proof_sender,
            } if id == &subject_id && proof_sender == &sender
        ));
        let state = TransferVerificationRegister::apply(
            Arc::new(TransferVerificationRegister::default()),
            &current,
        )
        .unwrap();
        assert_eq!(
            state.register.get(&subject_id),
            Some(&(3, sender.clone(), None, false))
        );

        let remove = V1TransferVerificationRegisterEvent::Remove {
            subject_id: subject_id.clone(),
        };
        let bytes = borsh::to_vec(&remove).unwrap();
        let current =
            <TransferVerificationRegister as PersistentActor>::upcast_event(
                1, &bytes,
            )
            .unwrap();
        assert!(matches!(
            current,
            TransferVerificationRegisterEvent::Remove { subject_id: id }
                if id == subject_id
        ));

        let speculative =
            V1TransferVerificationRegisterEvent::RecordSpeculativeTransfer {
                subject_id: subject_id.clone(),
                transfer_sn: 4,
                sender: sender.clone(),
            };
        let bytes = borsh::to_vec(&speculative).unwrap();
        let current =
            <TransferVerificationRegister as PersistentActor>::upcast_event(
                1, &bytes,
            )
            .unwrap();
        assert!(matches!(
            current,
            TransferVerificationRegisterEvent::RecordSpeculativeTransfer {
                subject_id: id,
                transfer_sn: 4,
                sender: proof_sender,
            } if id == subject_id && proof_sender == sender
        ));
    }

    #[test]
    fn v1_state_upcast_preserves_counter_and_marks_hashless() {
        let subject_id = subject(3);
        let sender = sender(4);
        let previous = V1TransferVerificationRegister {
            register: HashMap::from([
                (subject_id.clone(), (3, sender.clone(), false)),
                (subject(5), (7, sender.clone(), true)),
            ]),
        };
        let bytes = borsh::to_vec(&(previous, 17u64)).unwrap();
        let (state, counter) =
            <TransferVerificationRegister as PersistentActor>::upcast_state(
                1, &bytes,
            )
            .unwrap();
        assert_eq!(counter, 17);
        assert_eq!(
            state.register.get(&subject_id),
            Some(&(3, sender.clone(), None, false))
        );
        assert_eq!(
            state.register.get(&subject(5)),
            Some(&(7, sender, None, true))
        );
    }

    #[test]
    fn legacy_replacement_clears_the_previous_hash() {
        let subject_id = subject(6);
        let sender = sender(7);
        let initial = TransferVerificationRegister {
            register: HashMap::from([(
                subject_id.clone(),
                (3, sender.clone(), Some(subject(8)), false),
            )]),
        };
        let state = TransferVerificationRegister::apply(
            Arc::new(initial),
            &TransferVerificationRegisterEvent::RecordVerifiedTransfer {
                subject_id: subject_id.clone(),
                transfer_sn: 4,
                sender: sender.clone(),
            },
        )
        .unwrap();
        assert_eq!(
            state.register.get(&subject_id),
            Some(&(4, sender, None, false))
        );
    }

    #[test]
    fn v2_state_roundtrip_preserves_exact_proof() {
        let subject_id = subject(9);
        let sender = sender(10);
        let transfer_hash = subject(11);
        let initial = TransferVerificationRegister {
            register: HashMap::from([(
                subject_id.clone(),
                (4, sender.clone(), Some(transfer_hash.clone()), false),
            )]),
        };
        let bytes = borsh::to_vec(&(initial, 23u64)).unwrap();
        let (state, counter) =
            <TransferVerificationRegister as PersistentActor>::upcast_state(
                2, &bytes,
            )
            .unwrap();
        assert_eq!(counter, 23);
        assert_eq!(
            state.register.get(&subject_id),
            Some(&(4, sender, Some(transfer_hash), false))
        );
    }
}
