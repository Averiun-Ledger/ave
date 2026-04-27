use std::{
    collections::{BTreeMap, BTreeSet},
    str::FromStr,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    db::Storable,
    model::common::{
        check_witness_access, emit_fail, node::get_subject_data, purge_storage,
    },
    node::SubjectData,
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Hash,
    PartialEq,
    Eq,
    Ord,
    PartialOrd,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct TransferHint {
    pub sender: PublicKey,
    pub transfer_sn: u64,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct TransferHintRegister {
    pending: BTreeMap<DigestIdentifier, BTreeMap<u64, BTreeSet<PublicKey>>>,
    malicious: BTreeMap<DigestIdentifier, BTreeMap<u64, BTreeSet<PublicKey>>>,
    our_key: PublicKey,
}

impl TransferHintRegister {
    pub fn new(our_key: PublicKey) -> Self {
        Self {
            pending: BTreeMap::new(),
            malicious: BTreeMap::new(),
            our_key,
        }
    }

    fn governance_id(
        ctx: &ActorContext<Self>,
    ) -> Result<DigestIdentifier, ActorError> {
        DigestIdentifier::from_str(&ctx.path().parent().key()).map_err(|e| {
            ActorError::FunctionalCritical {
                description: format!(
                    "failed to parse governance id from path: {e}"
                ),
            }
        })
    }

    async fn verify_hint(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        hint: &TransferHint,
    ) -> Result<bool, ActorError> {
        let governance_id = Self::governance_id(ctx)?;
        let Some(SubjectData::Tracker {
            schema_id,
            namespace,
            ..
        }) = get_subject_data(ctx, subject_id).await?
        else {
            return Ok(false);
        };

        let tracker = ctx
            .system()
            .get_actor::<Tracker>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}",
                subject_id
            )))
            .await?;
        let response = tracker
            .ask(TrackerMessage::GetLedger {
                lo_sn: Some(hint.transfer_sn.saturating_sub(1)),
                hi_sn: hint.transfer_sn,
            })
            .await?;

        let TrackerResponse::Ledger { ledger, .. } = response else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}",
                    subject_id
                )),
                expected: "TrackerResponse::Ledger".to_owned(),
            });
        };

        let Some(transfer_ledger) =
            ledger.into_iter().find(|ledger| ledger.sn == hint.transfer_sn)
        else {
            return Ok(false);
        };

        if !matches!(
            transfer_ledger.get_event_request_type(),
            ave_common::bridge::request::EventRequestType::Transfer
        ) {
            return Ok(false);
        }

        let sender_limit = check_witness_access(
            ctx,
            &governance_id,
            subject_id,
            hint.sender.clone(),
            namespace.clone(),
            schema_id.clone(),
        )
        .await?;

        let receiver_limit = check_witness_access(
            ctx,
            &governance_id,
            subject_id,
            self.our_key.clone(),
            namespace,
            schema_id,
        )
        .await?;

        let sender_ok =
            sender_limit.is_some_and(|limit| limit >= hint.transfer_sn);
        let receiver_ok =
            receiver_limit.is_some_and(|limit| limit >= hint.transfer_sn);

        Ok(sender_ok && receiver_ok)
    }

    fn is_marked_malicious(
        &self,
        subject_id: &DigestIdentifier,
        hint: &TransferHint,
    ) -> bool {
        self.malicious
            .get(subject_id)
            .and_then(|by_sn| by_sn.get(&hint.transfer_sn))
            .is_some_and(|senders| senders.contains(&hint.sender))
    }

    fn collect_pending_up_to_sn(
        &self,
        subject_id: &DigestIdentifier,
        sn: u64,
    ) -> Vec<TransferHint> {
        self.pending
            .get(subject_id)
            .map(|by_sn| {
                by_sn
                    .range(..=sn)
                    .flat_map(|(transfer_sn, senders)| {
                        senders.iter().cloned().map(|sender| TransferHint {
                            sender,
                            transfer_sn: *transfer_sn,
                        })
                    })
                    .collect()
            })
            .unwrap_or_default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransferHintRegisterMessage {
    PurgeStorage,
    DeleteSubject {
        subject_id: DigestIdentifier,
    },
    RegisterHint {
        subject_id: DigestIdentifier,
        sender: PublicKey,
        transfer_sn: u64,
    },
    VerifySubjectSn {
        subject_id: DigestIdentifier,
        sn: u64,
    },
}

impl Message for TransferHintRegisterMessage {
    fn is_critical(&self) -> bool {
        true
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum TransferHintRegisterResponse {
    Ok,
}

impl Response for TransferHintRegisterResponse {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum TransferHintRegisterEvent {
    DeleteSubject {
        subject_id: DigestIdentifier,
    },
    RegisterHint {
        subject_id: DigestIdentifier,
        hint: TransferHint,
    },
    RemoveHint {
        subject_id: DigestIdentifier,
        hint: TransferHint,
    },
    MarkMalicious {
        subject_id: DigestIdentifier,
        hint: TransferHint,
    },
}

impl Event for TransferHintRegisterEvent {}

#[async_trait]
impl Actor for TransferHintRegister {
    type Message = TransferHintRegisterMessage;
    type Event = TransferHintRegisterEvent;
    type Response = TransferHintRegisterResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("TransferHintRegister"),
            |parent_span| {
                info_span!(parent: parent_span, "TransferHintRegister")
            },
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        if let Err(e) = self
            .init_store("transfer_hint_register", Some(prefix), false, ctx)
            .await
        {
            error!(
                error = %e,
                "Failed to initialize transfer_hint_register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for TransferHintRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TransferHintRegisterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<TransferHintRegisterResponse, ActorError> {
        match msg {
            TransferHintRegisterMessage::PurgeStorage => {
                self.pending.clear();
                self.malicious.clear();
                purge_storage(ctx).await?;
                debug!(
                    msg_type = "PurgeStorage",
                    "Transfer hint register storage purged"
                );
            }
            TransferHintRegisterMessage::DeleteSubject { subject_id } => {
                self.on_event(
                    TransferHintRegisterEvent::DeleteSubject {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Transfer hints removed for subject"
                );
            }
            TransferHintRegisterMessage::RegisterHint {
                subject_id,
                sender,
                transfer_sn,
            } => {
                let hint = TransferHint {
                    sender,
                    transfer_sn,
                };

                if self.is_marked_malicious(&subject_id, &hint) {
                    warn!(
                        msg_type = "RegisterHint",
                        subject_id = %subject_id,
                        transfer_sn = transfer_sn,
                        sender = %hint.sender,
                        "Ignoring hint already marked as malicious"
                    );
                } else {
                    self.on_event(
                        TransferHintRegisterEvent::RegisterHint {
                            subject_id: subject_id.clone(),
                            hint: hint.clone(),
                        },
                        ctx,
                    )
                    .await;

                    debug!(
                        msg_type = "RegisterHint",
                        subject_id = %subject_id,
                        transfer_sn = transfer_sn,
                        sender = %hint.sender,
                        "Transfer hint registered"
                    );
                }
            }
            TransferHintRegisterMessage::VerifySubjectSn { subject_id, sn } => {
                let hints = self.collect_pending_up_to_sn(&subject_id, sn);

                for hint in hints {
                    if self.verify_hint(ctx, &subject_id, &hint).await? {
                        self.on_event(
                            TransferHintRegisterEvent::RemoveHint {
                                subject_id: subject_id.clone(),
                                hint: hint.clone(),
                            },
                            ctx,
                        )
                        .await;

                        debug!(
                            msg_type = "VerifySubjectSn",
                            subject_id = %subject_id,
                            current_sn = sn,
                            transfer_sn = hint.transfer_sn,
                            sender = %hint.sender,
                            "Transfer hint verified and removed"
                        );
                    } else {
                        self.on_event(
                            TransferHintRegisterEvent::MarkMalicious {
                                subject_id: subject_id.clone(),
                                hint: hint.clone(),
                            },
                            ctx,
                        )
                        .await;

                        warn!(
                            msg_type = "VerifySubjectSn",
                            subject_id = %subject_id,
                            current_sn = sn,
                            transfer_sn = hint.transfer_sn,
                            sender = %hint.sender,
                            "Transfer hint marked as malicious"
                        );
                    }
                }
            }
        }

        Ok(TransferHintRegisterResponse::Ok)
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ave_actors::ChildAction {
        error!(
            error = %error,
            "Child fault in transfer hint register"
        );
        emit_fail(ctx, error).await;
        ave_actors::ChildAction::Stop
    }

    async fn on_event(
        &mut self,
        event: TransferHintRegisterEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                error = %e,
                "Failed to persist transfer hint register event"
            );
            return;
        }
    }
}

#[async_trait]
impl PersistentActor for TransferHintRegister {
    type Persistence = LightPersistence;
    type InitParams = PublicKey;

    fn create_initial(params: Self::InitParams) -> Self {
        Self::new(params)
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            TransferHintRegisterEvent::DeleteSubject { subject_id } => {
                self.pending.remove(&subject_id);
                self.malicious.remove(&subject_id);
            }
            TransferHintRegisterEvent::RegisterHint { subject_id, hint } => {
                self.pending
                    .entry(subject_id.clone())
                    .or_default()
                    .entry(hint.transfer_sn)
                    .or_default()
                    .insert(hint.sender.clone());
            }
            TransferHintRegisterEvent::RemoveHint { subject_id, hint } => {
                if let Some(by_sn) = self.pending.get_mut(&subject_id) {
                    let mut remove_subject = false;
                    if let Some(senders) = by_sn.get_mut(&hint.transfer_sn) {
                        senders.remove(&hint.sender);
                        if senders.is_empty() {
                            by_sn.remove(&hint.transfer_sn);
                        }
                    }
                    if by_sn.is_empty() {
                        remove_subject = true;
                    }
                    if remove_subject {
                        self.pending.remove(&subject_id);
                    }
                }
            }
            TransferHintRegisterEvent::MarkMalicious {
                subject_id,
                hint,
            } => {
                if let Some(by_sn) = self.pending.get_mut(&subject_id) {
                    let mut remove_subject = false;
                    if let Some(senders) = by_sn.get_mut(&hint.transfer_sn) {
                        senders.remove(&hint.sender);
                        if senders.is_empty() {
                            by_sn.remove(&hint.transfer_sn);
                        }
                    }
                    if by_sn.is_empty() {
                        remove_subject = true;
                    }
                    if remove_subject {
                        self.pending.remove(&subject_id);
                    }
                }
                self.malicious
                    .entry(subject_id.clone())
                    .or_default()
                    .entry(hint.transfer_sn)
                    .or_default()
                    .insert(hint.sender.clone());
            }
        }

        Ok(())
    }
}

impl Storable for TransferHintRegister {}
