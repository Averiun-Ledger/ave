use crate::{
    model::{
        common::emit_fail,
        event::{Event as AveEvent, ProtocolsSignatures},
    },
    validation::proof::ValidationProof,
};
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::Signed;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::db::Storable;

const TARGET_LASTSTATE: &str = "Ave-Subject-LastState";

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct LastState {
    proof: Option<ValidationProof>,
    event: Option<Signed<AveEvent>>,
    vali_res: Vec<ProtocolsSignatures>,
}

#[derive(Debug, Clone)]
pub enum LastStateMessage {
    UpdateLastState {
        proof: Box<ValidationProof>,
        event: Box<Signed<AveEvent>>,
        vali_res: Vec<ProtocolsSignatures>,
    },
    GetLastState,
}

impl Message for LastStateMessage {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct LastStateEvent {
    pub proof: ValidationProof,
    pub event: Signed<AveEvent>,
    pub vali_res: Vec<ProtocolsSignatures>,
}

impl Event for LastStateEvent {}

#[derive(Debug, Clone)]
pub enum LastStateResponse {
    LastState {
        proof: Box<ValidationProof>,
        event: Box<Signed<AveEvent>>,
        vali_res: Vec<ProtocolsSignatures>,
    },
    LessThanOurSn,
    Ok,
}

impl Response for LastStateResponse {}

#[async_trait]
impl Actor for LastState {
    type Event = LastStateEvent;
    type Message = LastStateMessage;
    type Response = LastStateResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        self.init_store("last_state", Some(prefix), true, ctx).await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<LastState> for LastState {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: LastStateMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<LastStateResponse, ActorError> {
        match msg {
            LastStateMessage::UpdateLastState {
                proof,
                event,
                vali_res,
            } => {
                if let Some(last_proof) = &self.proof
                    && last_proof.sn >= proof.sn
                {
                    return Ok(LastStateResponse::LessThanOurSn);
                }

                self.on_event(
                    LastStateEvent {
                        event: *event,
                        proof: *proof,
                        vali_res,
                    },
                    ctx,
                )
                .await;

                Ok(LastStateResponse::Ok)
            }
            LastStateMessage::GetLastState => {
                if let Some(proof) = self.proof.clone()
                    && let Some(event) = self.event.clone()
                {
                    Ok(LastStateResponse::LastState {
                        proof: Box::new(proof),
                        event: Box::new(event),
                        vali_res: self.vali_res.clone(),
                    })
                } else {
                    Err(ActorError::Functional(
                        "The last state is not saved yet".to_owned(),
                    ))
                }
            }
        }
    }

    async fn on_event(
        &mut self,
        event: LastStateEvent,
        ctx: &mut ActorContext<LastState>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_LASTSTATE,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event).await {
            error!(
                TARGET_LASTSTATE,
                "PublishEvent, can not publish event: {}", e
            );
            emit_fail(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for LastState {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self {
            proof: None,
            event: None,
            vali_res: vec![],
        }
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        self.proof = Some(event.proof.clone());
        self.event = Some(event.event.clone());
        self.vali_res = event.vali_res.clone();

        Ok(())
    }
}

impl Storable for LastState {}
