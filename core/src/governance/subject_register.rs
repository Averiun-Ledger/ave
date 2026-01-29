use std::collections::{HashMap, HashSet};

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
pub struct SubjectRegister {
    register: HashMap<
        (PublicKey, SchemaType, String),
        (CeilingMap<CreatorQuantity>, HashSet<DigestIdentifier>),
    >,
}

impl SubjectRegister {
    fn check(
        &self,
        creator: &PublicKey,
        namespace: &String,
        schema_id: &SchemaType,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        if let Some((creator_quantity, subjects)) = self.register.get(&(
            creator.clone(),
            schema_id.clone(),
            namespace.clone(),
        )) {
            if let Some(quantity) =
                creator_quantity.get_prev_or_equal(gov_version)
            {
                match quantity {
                    CreatorQuantity::Quantity(quantity) => {
                        if subjects.len() + 1 > quantity as usize {
                            return Err(ActorError::Functional {
                                description:
                                    "Maximum number of subjects reached"
                                        .to_owned(),
                            });
                        }
                    }
                    CreatorQuantity::Infinity => {}
                };

                Ok(())
            } else {
                Err(ActorError::Functional {
                    description: "Can not get Creator Quantity".to_owned(),
                })
            }
        } else {
            Err(ActorError::Functional {
                description: "Is not a Creator".to_owned(),
            })
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubjectRegisterMessage {
    Check {
        creator: PublicKey,
        gov_version: u64,
        namespace: String,
        schema_id: SchemaType,
    },
    RegisterData {
        gov_version: u64,
        data: Vec<(PublicKey, SchemaType, String, CreatorQuantity)>,
    },
    CreateSubject {
        creator: PublicKey,
        subject_id: DigestIdentifier,
        namespace: String,
        schema_id: SchemaType,
        gov_version: u64,
    },
    UpdateSubject {
        new_owner: PublicKey,
        old_owner: PublicKey,
        subject_id: DigestIdentifier,
        namespace: String,
        schema_id: SchemaType,
        gov_version: u64,
    },
}

impl Message for SubjectRegisterMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubjectRegisterResponse {
    Ok,
}

impl Response for SubjectRegisterResponse {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum SubjectRegisterEvent {
    RegisterData {
        gov_version: u64,
        data: Vec<(PublicKey, SchemaType, String, CreatorQuantity)>,
    },
    CreateSubject {
        creator: PublicKey,
        subject_id: DigestIdentifier,
        namespace: String,
        schema_id: SchemaType,
    },
    UpdateSubject {
        new_owner: PublicKey,
        old_owner: PublicKey,
        subject_id: DigestIdentifier,
        namespace: String,
        schema_id: SchemaType,
    },
}

impl Event for SubjectRegisterEvent {}

#[async_trait]
impl Actor for SubjectRegister {
    type Message = SubjectRegisterMessage;
    type Event = SubjectRegisterEvent;
    type Response = SubjectRegisterResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "SubjectRegister", id = id)
        } else {
            info_span!("SubjectRegister", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        self.init_store("subject_register", Some(prefix), false, ctx)
            .await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<SubjectRegister> for SubjectRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SubjectRegisterMessage,
        ctx: &mut ave_actors::ActorContext<SubjectRegister>,
    ) -> Result<SubjectRegisterResponse, ActorError> {
        match msg {
            SubjectRegisterMessage::RegisterData { gov_version, data } => {
                self.on_event(
                    SubjectRegisterEvent::RegisterData { gov_version, data },
                    ctx,
                )
                .await;

                Ok(SubjectRegisterResponse::Ok)
            }
            SubjectRegisterMessage::CreateSubject {
                creator,
                subject_id,
                namespace,
                schema_id,
                gov_version,
            } => {
                self.check(&creator, &namespace, &schema_id, gov_version)?;

                self.on_event(
                    SubjectRegisterEvent::CreateSubject {
                        creator,
                        subject_id,
                        namespace,
                        schema_id,
                    },
                    ctx,
                )
                .await;

                Ok(SubjectRegisterResponse::Ok)
            }
            SubjectRegisterMessage::UpdateSubject {
                new_owner,
                old_owner,
                subject_id,
                namespace,
                schema_id,
                gov_version,
            } => {
                self.check(&new_owner, &namespace, &schema_id, gov_version)?;
                self.on_event(
                    SubjectRegisterEvent::UpdateSubject {
                        new_owner,
                        old_owner,
                        subject_id,
                        namespace,
                        schema_id,
                    },
                    ctx,
                )
                .await;

                Ok(SubjectRegisterResponse::Ok)
            }
            SubjectRegisterMessage::Check {
                creator,
                gov_version,
                namespace,
                schema_id,
            } => {
                self.check(&creator, &namespace, &schema_id, gov_version)?;

                Ok(SubjectRegisterResponse::Ok)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SubjectRegisterEvent,
        ctx: &mut ActorContext<SubjectRegister>,
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
impl PersistentActor for SubjectRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            SubjectRegisterEvent::RegisterData { gov_version, data } => {
                for (creator, schema_id, namespace, quantity) in data.iter() {
                    self.register
                        .entry((
                            creator.to_owned(),
                            schema_id.to_owned(),
                            namespace.to_owned(),
                        ))
                        .or_insert((CeilingMap::new(), HashSet::new()))
                        .0
                        .insert(*gov_version, quantity.to_owned());
                }
            }
            SubjectRegisterEvent::CreateSubject {
                creator,
                subject_id,
                namespace,
                schema_id,
            } => {
                self.register
                    .entry((
                        creator.to_owned(),
                        schema_id.to_owned(),
                        namespace.to_owned(),
                    ))
                    .or_insert((CeilingMap::new(), HashSet::new()))
                    .1
                    .insert(subject_id.to_owned());
            }
            SubjectRegisterEvent::UpdateSubject {
                new_owner,
                old_owner,
                subject_id,
                namespace,
                schema_id,
            } => {
                self.register
                    .entry((
                        new_owner.to_owned(),
                        schema_id.to_owned(),
                        namespace.to_owned(),
                    ))
                    .or_insert((CeilingMap::new(), HashSet::new()))
                    .1
                    .insert(subject_id.to_owned());

                self.register
                    .entry((
                        old_owner.to_owned(),
                        schema_id.to_owned(),
                        namespace.to_owned(),
                    ))
                    .or_insert((CeilingMap::new(), HashSet::new()))
                    .1
                    .remove(subject_id);
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for SubjectRegister {}
