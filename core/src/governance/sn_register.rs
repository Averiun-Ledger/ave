use std::collections::HashMap;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::SchemaType;
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::model::common::CeilingMap;
use crate::{db::Storable, model::common::emit_fail};

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
pub struct OwnerSchema {
    pub owner: PublicKey,
    pub schema_id: SchemaType,
    pub namespace: String,
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct SnRegister {
    register: HashMap<DigestIdentifier, CeilingMap<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SnRegisterMessage {
    RegisterSn {
        subject_id: DigestIdentifier,
        gov_version: u64,
        sn: u64,
    },
    GetSn {
        subject_id: DigestIdentifier,
        gov_version: u64,
    },
}

impl Message for SnRegisterMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SnLimit {
    Sn(u64),
    LastSn,
    NotSn,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SnRegisterResponse {
    Ok,
    Sn(SnLimit),
}

impl Response for SnRegisterResponse {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum SnRegisterEvent {
    RegisterSn {
        subject_id: DigestIdentifier,
        gov_version: u64,
        sn: u64,
    },
}

impl Event for SnRegisterEvent {}

#[async_trait]
impl Actor for SnRegister {
    type Message = SnRegisterMessage;
    type Event = SnRegisterEvent;
    type Response = SnRegisterResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "SnRegister", id = id)
        } else {
            info_span!("SnRegister", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        if let Err(e) = self
            .init_store("sn_register", Some(prefix), false, ctx)
            .await
        {
            error!(
                error = %e,
                "Failed to initialize sn_register store"
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
                "Failed to stop sn_register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<SnRegister> for SnRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SnRegisterMessage,
        ctx: &mut ave_actors::ActorContext<SnRegister>,
    ) -> Result<SnRegisterResponse, ActorError> {
        match msg {
            SnRegisterMessage::GetSn {
                subject_id,
                gov_version,
            } => {
                let response = if let Some(gov_version_register) =
                    self.register.get(&subject_id)
                    && let Some(last) = gov_version_register.last()
                {
                    if gov_version > *last.0 {
                        SnRegisterResponse::Sn(SnLimit::LastSn)
                    } else if let Some(sn) =
                        gov_version_register.get_prev_or_equal(gov_version)
                    {
                        SnRegisterResponse::Sn(SnLimit::Sn(sn))
                    } else {
                        SnRegisterResponse::Sn(SnLimit::NotSn)
                    }
                } else {
                    SnRegisterResponse::Sn(SnLimit::NotSn)
                };

                debug!(
                    msg_type = "GetSn",
                    subject_id = %subject_id,
                    gov_version = gov_version,
                    "Sn lookup completed"
                );

                Ok(response)
            }
            SnRegisterMessage::RegisterSn {
                subject_id,
                gov_version,
                sn,
            } => {
                self.on_event(
                    SnRegisterEvent::RegisterSn {
                        subject_id: subject_id.clone(),
                        gov_version,
                        sn,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "RegisterSn",
                    subject_id = %subject_id,
                    gov_version = gov_version,
                    sn = sn,
                    "Sn registered"
                );

                Ok(SnRegisterResponse::Ok)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SnRegisterEvent,
        ctx: &mut ActorContext<SnRegister>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist sn register event"
            );
            emit_fail(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for SnRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            SnRegisterEvent::RegisterSn {
                subject_id,
                gov_version,
                sn,
            } => {
                self.register
                    .entry(subject_id.to_owned())
                    .or_default()
                    .insert(*gov_version, *sn);

                debug!(
                    event_type = "RegisterSn",
                    subject_id = %subject_id,
                    gov_version = gov_version,
                    sn = sn,
                    "Sn register state updated"
                );
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for SnRegister {}
