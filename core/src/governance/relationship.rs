use std::collections::HashMap;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{error, warn};

use crate::model::request::SchemaType;
use crate::{
    db::Storable, governance::model::CreatorQuantity, model::common::emit_fail,
};

const TARGET_RELATIONSHIP: &str = "Ave-Node-RelationShip";

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
    pub owner: String,
    pub schema_id: SchemaType,
    pub namespace: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum DeleteTypes {
    Request { id: String },
}

#[derive(
    Clone,
    Debug,
    Serialize,
    Deserialize,
    Default,
    Eq,
    PartialEq,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct RelationShip {
    subjects: HashMap<OwnerSchema, Vec<String>>,
}

impl RelationShip {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelationShipMessage {
    GetSubjectsCount(OwnerSchema),
    RegisterNewSubject {
        data: OwnerSchema,
        subject_id: String,
        max_quantity: CreatorQuantity,
    },
    DeleteSubject {
        data: OwnerSchema,
        subject_id: String,
    },
}

impl Message for RelationShipMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RelationShipResponse {
    Count(usize),
    None,
}

impl Response for RelationShipResponse {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RelationShipEvent {
    NewRegister { data: OwnerSchema, subject_id: String },
    DeleteSubject { data: OwnerSchema, subject_id: String },
}

impl Event for RelationShipEvent {}

#[async_trait]
impl Actor for RelationShip {
    type Message = RelationShipMessage;
    type Event = RelationShipEvent;
    type Response = RelationShipResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        self.init_store("relation_ship", Some(prefix), false, ctx).await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<RelationShip> for RelationShip {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RelationShipMessage,
        ctx: &mut ave_actors::ActorContext<RelationShip>,
    ) -> Result<RelationShipResponse, ActorError> {
        match msg {
            RelationShipMessage::GetSubjectsCount(owner_schema) => {
                if let Some(vec) = self.subjects.get(&owner_schema) {
                    Ok(RelationShipResponse::Count(vec.len()))
                } else {
                    Ok(RelationShipResponse::Count(0))
                }
            }
            RelationShipMessage::RegisterNewSubject {
                data,
                subject_id,
                max_quantity,
            } => {
                let quantity = if let Some(vec) = self.subjects.get(&data)
                {
                    vec.len()
                } else {
                    0
                };

                if let CreatorQuantity::Quantity(max_quantity) = max_quantity
                    && quantity >= max_quantity as usize
                {
                    let e = "Maximum number of subjects reached";
                    warn!(TARGET_RELATIONSHIP, "RegisterNewSubject, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }

                self.on_event(
                    RelationShipEvent::NewRegister { data, subject_id },
                    ctx,
                )
                .await;
                Ok(RelationShipResponse::None)
            }
            RelationShipMessage::DeleteSubject { data, subject_id } => {
                self.on_event(
                    RelationShipEvent::DeleteSubject { data, subject_id },
                    ctx,
                )
                .await;
                Ok(RelationShipResponse::None)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: RelationShipEvent,
        ctx: &mut ActorContext<RelationShip>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_RELATIONSHIP,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };
    }
}

#[async_trait]
impl PersistentActor for RelationShip {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RelationShipEvent::NewRegister { data, subject_id } => {
                self.subjects
                    .entry(data.clone())
                    .or_default()
                    .push(subject_id.clone());
            }
            RelationShipEvent::DeleteSubject { data, subject_id } => {
                self.subjects.entry(data.clone()).and_modify(|vec| {
                    if let Some(pos) =
                        vec.iter().position(|x| x.clone() == subject_id.clone())
                    {
                        vec.remove(pos);
                    } else {
                        error!(TARGET_RELATIONSHIP, "An attempt was made to delete a subject that was not registered");
                    };
                });
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for RelationShip {}
