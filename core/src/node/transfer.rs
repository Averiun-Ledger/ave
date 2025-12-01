use std::collections::{HashMap, HashSet};

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
use tracing::error;

use crate::db::Storable;

const TARGET_TRANSFER: &str = "Ave-Node-TransferRegister";

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
    old_owners: HashMap<String, HashSet<PublicKey>>,
}

#[derive(Debug, Clone)]
pub enum TransferRegisterMessage {
    RegisterNewOldOwner {
        subject_id: String,
        old: PublicKey,
        new: PublicKey,
    },
    IsOldOwner {
        subject_id: String,
        old: PublicKey,
    },
}

impl Message for TransferRegisterMessage {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum TransferRegisterEvent {
    RegisterNewOldOwner {
        subject_id: String,
        old: PublicKey,
        new: PublicKey,
    },
}

impl Event for TransferRegisterEvent {}

pub enum TransferRegisterResponse {
    IsOwner(bool),
    Ok,
}

impl Response for TransferRegisterResponse {}

#[async_trait]
impl Actor for TransferRegister {
    type Event = TransferRegisterEvent;
    type Message = TransferRegisterMessage;
    type Response = TransferRegisterResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("transfer_register", None, true, ctx).await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
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
            TransferRegisterMessage::RegisterNewOldOwner {
                old,
                new,
                subject_id,
            } => {
                self.on_event(
                    TransferRegisterEvent::RegisterNewOldOwner {
                        old,
                        new,
                        subject_id,
                    },
                    ctx,
                )
                .await
            }
            TransferRegisterMessage::IsOldOwner { subject_id, old } => {
                return Ok(TransferRegisterResponse::IsOwner(
                    if let Some(old_owners) = self.old_owners.get(&subject_id) {
                        old_owners.contains(&old)
                    } else {
                        false
                    },
                ));
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
                TARGET_TRANSFER,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };
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
            TransferRegisterEvent::RegisterNewOldOwner {
                old,
                new,
                subject_id,
            } => {
                if let Some(old_owners) = self.old_owners.get_mut(subject_id) {
                    old_owners.remove(new);
                    old_owners.insert(old.clone());
                } else {
                    self.old_owners.insert(
                        subject_id.clone(),
                        HashSet::from([old.clone()]),
                    );
                };
            }
        };

        Ok(())
    }
}

impl Storable for TransferRegister {}
