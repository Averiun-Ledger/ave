use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler,
    LightPersistence, Message, PersistentActor, Response,
};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span};

use ave_common::identity::DigestIdentifier;

use crate::{
    db::Storable,
    evaluation::compiler::ContractArtifactRecord,
    model::common::{crash_system, purge_storage},
};

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
    /// Ledger-anchored wasm hash per official contract name: the
    /// compilation evidence of the last committed event that touched the
    /// contract, recorded at apply time by every node — whether or not
    /// it holds the artifact bytes. It is the local projection used to
    /// request and verify artifacts fetched from the network.
    anchors: HashMap<String, DigestIdentifier>,
}

impl ContractRegister {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Clone)]
pub enum ContractRegisterMessage {
    PurgeStorage,
    GetMetadata {
        contract_name: String,
    },
    GetAnchor {
        contract_name: String,
    },
    /// Registered contract names: artifact entries and anchor-only ones.
    ListContracts,
    /// Contract names with artifact metadata only (no anchor-only
    /// entries): what the startup sweep prunes by role. Anchors are a
    /// ledger projection and are never swept.
    ListArtifacts,
    /// Forgets everything about the contract: artifact metadata and
    /// ledger anchor.
    DeleteMetadata {
        contract_name: String,
    },
    /// Forgets only the artifact metadata, keeping the ledger anchor:
    /// the anchor is a projection of the applied events and remains
    /// valid regardless of the node's roles.
    DeleteArtifact {
        contract_name: String,
    },
    SetMetadata {
        contract_name: String,
        metadata: ContractArtifactRecord,
    },
    SetAnchor {
        contract_name: String,
        wasm_hash: DigestIdentifier,
    },
}

impl Message for ContractRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::PurgeStorage
                | Self::SetMetadata { .. }
                | Self::DeleteMetadata { .. }
                | Self::DeleteArtifact { .. }
                | Self::SetAnchor { .. }
        )
    }
}

#[derive(Debug, Clone)]
pub enum ContractRegisterResponse {
    Metadata(Option<ContractArtifactRecord>),
    Anchor(Option<DigestIdentifier>),
    Contracts(Vec<String>),
    Ok,
}

impl Response for ContractRegisterResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum ContractRegisterEvent {
    DeleteMetadata {
        contract_name: String,
    },
    DeleteArtifact {
        contract_name: String,
    },
    SetMetadata {
        contract_name: String,
        metadata: ContractArtifactRecord,
    },
    SetAnchor {
        contract_name: String,
        wasm_hash: DigestIdentifier,
    },
}

impl Event for ContractRegisterEvent {}

#[async_trait]
impl Actor for ContractRegister {
    type Event = ContractRegisterEvent;
    type Message = ContractRegisterMessage;
    type Response = ContractRegisterResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

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
        self.init_store(
            "contract_register",
            Some(ctx.path().parent().key().to_owned()),
            false,
            ctx,
        )
        .await
    }
}

#[async_trait]
impl Handler<Self> for ContractRegister {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: ContractRegisterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<ContractRegisterResponse, ActorError> {
        match msg {
            ContractRegisterMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                Ok(ContractRegisterResponse::Ok)
            }
            ContractRegisterMessage::ListContracts => {
                Ok(ContractRegisterResponse::Contracts(
                    self.contracts
                        .keys()
                        .chain(self.anchors.keys())
                        .cloned()
                        .collect::<std::collections::BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                ))
            }
            ContractRegisterMessage::ListArtifacts => {
                Ok(ContractRegisterResponse::Contracts(
                    self.contracts.keys().cloned().collect(),
                ))
            }
            ContractRegisterMessage::GetMetadata { contract_name } => {
                Ok(ContractRegisterResponse::Metadata(
                    self.contracts.get(&contract_name).cloned(),
                ))
            }
            ContractRegisterMessage::GetAnchor { contract_name } => {
                Ok(ContractRegisterResponse::Anchor(
                    self.anchors.get(&contract_name).cloned(),
                ))
            }
            ContractRegisterMessage::DeleteMetadata { contract_name } => {
                self.on_event(
                    ContractRegisterEvent::DeleteMetadata { contract_name },
                    ctx,
                )
                .await;

                Ok(ContractRegisterResponse::Ok)
            }
            ContractRegisterMessage::DeleteArtifact { contract_name } => {
                self.on_event(
                    ContractRegisterEvent::DeleteArtifact { contract_name },
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
            ContractRegisterMessage::SetAnchor {
                contract_name,
                wasm_hash,
            } => {
                self.on_event(
                    ContractRegisterEvent::SetAnchor {
                        contract_name,
                        wasm_hash,
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
        if let Err(e) = self.persist(event, ctx).await {
            error!(
                error = %e,
                "Failed to persist contract register event"
            );
            crash_system(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for ContractRegister {
    type Persistence = LightPersistence;
    type InitParams = ();
    type State = Self;

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::new()
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            ContractRegisterEvent::DeleteMetadata { contract_name } => {
                inner.contracts.remove(contract_name);
                inner.anchors.remove(contract_name);
            }
            ContractRegisterEvent::DeleteArtifact { contract_name } => {
                inner.contracts.remove(contract_name);
            }
            ContractRegisterEvent::SetMetadata {
                contract_name,
                metadata,
            } => {
                inner
                    .contracts
                    .insert(contract_name.clone(), metadata.clone());
            }
            ContractRegisterEvent::SetAnchor {
                contract_name,
                wasm_hash,
            } => {
                inner
                    .anchors
                    .insert(contract_name.clone(), wasm_hash.clone());
            }
        }

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
impl Storable for ContractRegister {}
