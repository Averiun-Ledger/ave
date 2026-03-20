use std::collections::HashMap;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler,
    LightPersistence, Message, PersistentActor, Response,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span};

use crate::{db::Storable, model::common::emit_fail};

use super::ContractArtifactRecord;

#[derive(
    Default,
    Clone,
    Debug,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct ContractRegister {
    contracts: HashMap<String, ContractArtifactRecord>,
}

impl ContractRegister {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub enum ContractRegisterMessage {
    GetMetadata {
        contract_name: String,
    },
    ListContracts,
    DeleteMetadata {
        contract_name: String,
    },
    SetMetadata {
        contract_name: String,
        metadata: ContractArtifactRecord,
    },
}

impl Message for ContractRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(self, Self::SetMetadata { .. } | Self::DeleteMetadata { .. })
    }
}

#[derive(Debug, Clone)]
pub enum ContractRegisterResponse {
    Metadata(Option<ContractArtifactRecord>),
    Contracts(Vec<String>),
    Ok,
}

impl Response for ContractRegisterResponse {}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub enum ContractRegisterEvent {
    DeleteMetadata {
        contract_name: String,
    },
    SetMetadata {
        contract_name: String,
        metadata: ContractArtifactRecord,
    },
}

impl Event for ContractRegisterEvent {}

#[async_trait]
impl Actor for ContractRegister {
    type Event = ContractRegisterEvent;
    type Message = ContractRegisterMessage;
    type Response = ContractRegisterResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ContractRegister"),
            |parent_span| info_span!(parent: parent_span, "ContractRegister"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        self.init_store("contract_register", Some(prefix), false, ctx)
            .await
    }
}

#[async_trait]
impl Handler<Self> for ContractRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ContractRegisterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<ContractRegisterResponse, ActorError> {
        match msg {
            ContractRegisterMessage::ListContracts => Ok(
                ContractRegisterResponse::Contracts(
                    self.contracts.keys().cloned().collect(),
                ),
            ),
            ContractRegisterMessage::GetMetadata { contract_name } => Ok(
                ContractRegisterResponse::Metadata(
                    self.contracts.get(&contract_name).cloned(),
                ),
            ),
            ContractRegisterMessage::DeleteMetadata { contract_name } => {
                self.on_event(
                    ContractRegisterEvent::DeleteMetadata {
                        contract_name,
                    },
                    ctx,
                )
                .await;

                Ok(ContractRegisterResponse::Ok)
            }
            ContractRegisterMessage::SetMetadata {
                contract_name,
                metadata,
            } => {
                self.on_event(
                    ContractRegisterEvent::SetMetadata {
                        contract_name,
                        metadata,
                    },
                    ctx,
                )
                .await;

                Ok(ContractRegisterResponse::Ok)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: ContractRegisterEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist contract register event"
            );
            emit_fail(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for ContractRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::new()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            ContractRegisterEvent::DeleteMetadata { contract_name } => {
                self.contracts.remove(contract_name);
            }
            ContractRegisterEvent::SetMetadata {
                contract_name,
                metadata,
            } => {
                self.contracts
                    .insert(contract_name.clone(), metadata.clone());
            }
        }

        Ok(())
    }
}

#[async_trait]
impl Storable for ContractRegister {}
