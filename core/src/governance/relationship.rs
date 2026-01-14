use std::collections::HashMap;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::SchemaType;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    db::Storable, governance::model::CreatorQuantity, model::common::emit_fail,
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

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RelationShip", id = id)
        } else {
            info_span!("RelationShip", id = id)
        }
    }

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
                let count = if let Some(vec) = self.subjects.get(&owner_schema) {
                    vec.len()
                } else {
                    0
                };

                debug!(
                    msg_type = "GetSubjectsCount",
                    owner = %owner_schema.owner,
                    schema_id = %owner_schema.schema_id,
                    namespace = %owner_schema.namespace,
                    count = count,
                    "Returning subjects count"
                );

                Ok(RelationShipResponse::Count(count))
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
                    warn!(
                        msg_type = "RegisterNewSubject",
                        owner = %data.owner,
                        schema_id = %data.schema_id,
                        namespace = %data.namespace,
                        current_quantity = quantity,
                        max_quantity = max_quantity,
                        "Maximum number of subjects reached"
                    );
                    return Err(ActorError::Functional {description: "Maximum number of subjects reached".to_owned()});
                }

                self.on_event(
                    RelationShipEvent::NewRegister { data: data.clone(), subject_id: subject_id.clone() },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "RegisterNewSubject",
                    owner = %data.owner,
                    schema_id = %data.schema_id,
                    namespace = %data.namespace,
                    subject_id = %subject_id,
                    "New subject registered successfully"
                );

                Ok(RelationShipResponse::None)
            }
            RelationShipMessage::DeleteSubject { data, subject_id } => {
                self.on_event(
                    RelationShipEvent::DeleteSubject { data: data.clone(), subject_id: subject_id.clone() },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "DeleteSubject",
                    owner = %data.owner,
                    schema_id = %data.schema_id,
                    namespace = %data.namespace,
                    subject_id = %subject_id,
                    "Subject deleted successfully"
                );

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
                error = %e,
                "Failed to persist event"
            );
            emit_fail(ctx, e).await;
        } else {
            debug!("Event persisted successfully");
        }
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

                debug!(
                    event_type = "NewRegister",
                    owner = %data.owner,
                    schema_id = %data.schema_id,
                    namespace = %data.namespace,
                    subject_id = %subject_id,
                    "Applied new register event"
                );
            }
            RelationShipEvent::DeleteSubject { data, subject_id } => {
                self.subjects.entry(data.clone()).and_modify(|vec| {
                    if let Some(pos) =
                        vec.iter().position(|x| x.clone() == subject_id.clone())
                    {
                        vec.remove(pos);
                        debug!(
                            event_type = "DeleteSubject",
                            owner = %data.owner,
                            schema_id = %data.schema_id,
                            namespace = %data.namespace,
                            subject_id = %subject_id,
                            "Applied delete subject event"
                        );
                    } else {
                        error!(
                            event_type = "DeleteSubject",
                            owner = %data.owner,
                            schema_id = %data.schema_id,
                            namespace = %data.namespace,
                            subject_id = %subject_id,
                            "Attempt to delete unregistered subject"
                        );
                    };
                });
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for RelationShip {}
