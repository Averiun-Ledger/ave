use std::collections::{HashMap, HashSet};
use std::hash::Hash;

use crate::model::common::emit_fail;
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::PublicKey;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::db::Storable;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct TransferRegister {
    register: HashMap<String, TransferData>,
    gov_sn: u64,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct TransferData {
    actual_owner: PublicKey,
    actual_new_owner: Option<PublicKey>,
    sn: u64,
    old_owners: HashSet<OldOwnerData>,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct OldOwnerData {
    sn: u64,
    old_owner: PublicKey,
}

impl PartialOrd for OldOwnerData {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for OldOwnerData {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.old_owner).cmp(&other.old_owner)
    }
}

impl Hash for OldOwnerData {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.old_owner.hash(state);
    }
}

impl PartialEq for OldOwnerData {
    fn eq(&self, other: &Self) -> bool {
        self.old_owner == other.old_owner
    }
}

impl Eq for OldOwnerData {}

#[derive(Debug, Clone)]
pub enum TransferRegisterMessage {
    UpdateSnGov {
        sn: u64,
    },
    UpdateSn {
        subject_id: String,
        sn: u64,
    },
    Create {
        subject_id: String,
        owner: PublicKey,
    },
    Transfer {
        subject_id: String,
        new_owner: PublicKey,
    },
    Confirm {
        subject_id: String,
        sn: u64,
    },
    Reject {
        subject_id: String,
        sn: u64,
    },
    Access {
        subject_id: String,
        node: PublicKey,
    },
}

impl Message for TransferRegisterMessage {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum TransferRegisterEvent {
    UpdateSnGov {
        sn: u64,
    },
    UpdateSn {
        subject_id: String,
        sn: u64,
    },
    Create {
        subject_id: String,
        owner: PublicKey,
    },
    Transfer {
        subject_id: String,
        new_owner: PublicKey,
    },
    Confirm {
        subject_id: String,
        sn: u64,
    },
    Reject {
        subject_id: String,
        sn: u64,
    },
}

impl Event for TransferRegisterEvent {}

pub enum TransferRegisterResponse {
    Access { sn: Option<u64> },
    Ok,
}

impl Response for TransferRegisterResponse {}

#[async_trait]
impl Actor for TransferRegister {
    type Event = TransferRegisterEvent;
    type Message = TransferRegisterMessage;
    type Response = TransferRegisterResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "TransferRegister", id = id)
        } else {
            info_span!("TransferRegister", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) =
            self.init_store("transfer_register", None, true, ctx).await
        {
            error!(
                error = %e,
                "Failed to initialize transfer register store"
            );
            return Err(e);
        }
        Ok(())
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.stop_store(ctx).await {
            error!(
                error = %e,
                "Failed to stop transfer register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<TransferRegister> for TransferRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TransferRegisterMessage,
        ctx: &mut ActorContext<TransferRegister>,
    ) -> Result<TransferRegisterResponse, ActorError> {
        match msg {
            TransferRegisterMessage::UpdateSnGov { sn } => {
                self.on_event(TransferRegisterEvent::UpdateSnGov { sn }, ctx)
                    .await;

                debug!(
                    msg_type = "UpdateSnGov",
                    sn = sn,
                    "Sequence number updated"
                );
            }
            TransferRegisterMessage::UpdateSn { sn, subject_id } => {
                self.on_event(
                    TransferRegisterEvent::UpdateSn {
                        sn,
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "UpdateSn",
                    subject_id = %subject_id,
                    sn = sn,
                    "Sequence number updated"
                );
            }
            TransferRegisterMessage::Create { subject_id, owner } => {
                self.on_event(
                    TransferRegisterEvent::Create {
                        subject_id: subject_id.clone(),
                        owner: owner.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Create",
                    subject_id = %subject_id,
                    owner = %owner,
                    "Transfer entry created"
                );
            }
            TransferRegisterMessage::Transfer {
                subject_id,
                new_owner,
            } => {
                self.on_event(
                    TransferRegisterEvent::Transfer {
                        subject_id: subject_id.clone(),
                        new_owner: new_owner.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Transfer",
                    subject_id = %subject_id,
                    new_owner = %new_owner,
                    "New transfer registered"
                );
            }
            TransferRegisterMessage::Reject { subject_id, sn } => {
                self.on_event(
                    TransferRegisterEvent::Reject {
                        subject_id: subject_id.clone(),
                        sn,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Reject",
                    subject_id = %subject_id,
                    sn = sn,
                    "The transfer was rejected"
                );
            }
            TransferRegisterMessage::Confirm { subject_id, sn } => {
                self.on_event(
                    TransferRegisterEvent::Confirm {
                        subject_id: subject_id.clone(),
                        sn,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Confirm",
                    subject_id = %subject_id,
                    sn = sn,
                    "The transfer was confirmed"
                );
            }
            TransferRegisterMessage::Access { subject_id, node } => {
                let sn = if let Some(data) = self.register.get(&subject_id) {
                    if data.actual_owner == node {
                        Some(data.sn)
                    } else if let Some(new_owner) = &data.actual_new_owner
                        && new_owner == &node
                    {
                        Some(data.sn)
                    } else if let Some(old_data) =
                        data.old_owners.get(&OldOwnerData {
                            sn: 0,
                            old_owner: node.clone(),
                        })
                    {
                        Some(old_data.sn)
                    } else {
                        None
                    }
                } else {
                    None
                };

                debug!(
                    msg_type = "Access",
                    subject_id = %subject_id,
                    node = %node,
                    sn = sn,
                    "Checked access status"
                );

                return Ok(TransferRegisterResponse::Access { sn });
            }
        };

        Ok(TransferRegisterResponse::Ok)
    }

    async fn on_event(
        &mut self,
        event: TransferRegisterEvent,
        ctx: &mut ActorContext<TransferRegister>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist transfer register event"
            );
            emit_fail(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for TransferRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            TransferRegisterEvent::UpdateSnGov { sn } => {
                self.gov_sn = *sn;

                debug!(
                    event_type = "UpdateSnGov",
                    sn = sn,
                    "Sequence number updated"
                );
            }
            TransferRegisterEvent::UpdateSn { subject_id, sn } => {
                if let Some(data) = self.register.get_mut(subject_id) {
                    data.sn = *sn;

                    debug!(
                        event_type = "UpdateSn",
                        subject_id = %subject_id,
                        sn = sn,
                        "Sequence number updated"
                    );
                } else {
                    error!(
                        event_type = "UpdateSn",
                        subject_id = %subject_id,
                        "Subject not found in register"
                    );
                };
            }
            TransferRegisterEvent::Create { subject_id, owner } => {
                self.register
                    .entry(subject_id.clone())
                    .or_default()
                    .actual_owner = owner.clone();

                debug!(
                    event_type = "Create",
                    subject_id = %subject_id,
                    owner = %owner,
                    "Transfer entry created"
                );
            }
            TransferRegisterEvent::Transfer {
                subject_id,
                new_owner,
            } => {
                if let Some(data) = self.register.get_mut(subject_id) {
                    data.actual_new_owner = Some(new_owner.clone());

                    debug!(
                        event_type = "Transfer",
                        subject_id = %subject_id,
                        new_owner = %new_owner,
                        "Transfer initiated"
                    );
                } else {
                    error!(
                        event_type = "Transfer",
                        subject_id = %subject_id,
                        new_owner = %new_owner,
                        "Subject not found in register"
                    );
                };
            }
            TransferRegisterEvent::Confirm { subject_id, sn } => {
                if let Some(data) = self.register.get_mut(subject_id) {
                    let new_owner = data.actual_new_owner.take();

                    if let Some(new_owner) = new_owner {
                        data.old_owners.insert(OldOwnerData {
                            sn: *sn,
                            old_owner: data.actual_owner.clone(),
                        });
                        data.actual_owner = new_owner;

                        debug!(
                            event_type = "Confirm",
                            subject_id = %subject_id,
                            sn = sn,
                            "Transfer confirmed"
                        );
                    } else {
                        error!(
                            event_type = "Confirm",
                            subject_id = %subject_id,
                            sn = sn,
                            "No pending new owner to confirm"
                        );
                    };
                } else {
                    error!(
                        event_type = "Confirm",
                        subject_id = %subject_id,
                        sn = sn,
                        "Subject not found in register"
                    );
                };
            }
            TransferRegisterEvent::Reject { subject_id, sn } => {
                if let Some(data) = self.register.get_mut(subject_id) {
                    let new_owner = data.actual_new_owner.take();

                    if let Some(new_owner) = new_owner {
                        data.old_owners.insert(OldOwnerData {
                            sn: *sn,
                            old_owner: new_owner.clone(),
                        });

                        debug!(
                            event_type = "Reject",
                            subject_id = %subject_id,
                            sn = sn,
                            "Transfer rejected"
                        );
                    } else {
                        error!(
                            event_type = "Reject",
                            subject_id = %subject_id,
                            sn = sn,
                            "No pending new owner to reject"
                        );
                    };
                } else {
                    error!(
                        event_type = "Reject",
                        subject_id = %subject_id,
                        sn = sn,
                        "Subject not found in register"
                    );
                };
            }
        };

        Ok(())
    }
}

impl Storable for TransferRegister {}
