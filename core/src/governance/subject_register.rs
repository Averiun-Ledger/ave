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
    db::Storable,
    governance::model::CreatorQuantity,
    model::common::{emit_fail, purge_storage},
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
    register: HashMap<RegisterData, (RegisterCreations, RegisterSubjects)>,
}

type RegisterData = (PublicKey, SchemaType, String);
type RegisterCreations = CeilingMap<CreatorQuantity>;
type RegisterSubjects = HashSet<DigestIdentifier>;

impl SubjectRegister {
    fn check(
        &self,
        creator: &PublicKey,
        namespace: &str,
        schema_id: &SchemaType,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        if let Some((creator_quantity, subjects)) = self.register.get(&(
            creator.clone(),
            schema_id.clone(),
            namespace.to_owned(),
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
    PurgeStorage,
    Check {
        creator: PublicKey,
        gov_version: u64,
        namespace: String,
        schema_id: SchemaType,
    },
    GetSubjectsByOwnerSchema {
        owner: PublicKey,
        schema_id: SchemaType,
        namespace: String,
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
    DeleteSubject {
        subject_id: DigestIdentifier,
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

impl Message for SubjectRegisterMessage {
    fn is_critical(&self) -> bool {
        match self {
            Self::PurgeStorage
            | Self::RegisterData { .. }
            | Self::CreateSubject { .. }
            | Self::DeleteSubject { .. }
            | Self::UpdateSubject { .. } => true,
            Self::Check { .. } | Self::GetSubjectsByOwnerSchema { .. } => false,
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SubjectRegisterResponse {
    Ok,
    Subjects(Vec<DigestIdentifier>),
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
    DeleteSubject {
        subject_id: DigestIdentifier,
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

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("SubjectRegister"),
            |parent_span| info_span!(parent: parent_span, "SubjectRegister"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        if let Err(e) = self
            .init_store("subject_register", Some(prefix), false, ctx)
            .await
        {
            error!(
                error = %e,
                "Failed to initialize subject_register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for SubjectRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: SubjectRegisterMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<SubjectRegisterResponse, ActorError> {
        match msg {
            SubjectRegisterMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    "Subject register storage purged"
                );

                return Ok(SubjectRegisterResponse::Ok);
            }
            SubjectRegisterMessage::GetSubjectsByOwnerSchema {
                owner,
                schema_id,
                namespace,
            } => {
                let subjects = self
                    .register
                    .get(&(owner, schema_id, namespace))
                    .map(|(_, subjects)| {
                        let mut subjects =
                            subjects.iter().cloned().collect::<Vec<_>>();
                        subjects.sort();
                        subjects
                    })
                    .unwrap_or_default();

                return Ok(SubjectRegisterResponse::Subjects(subjects));
            }
            SubjectRegisterMessage::RegisterData { gov_version, data } => {
                let data_count = data.len();
                self.on_event(
                    SubjectRegisterEvent::RegisterData { gov_version, data },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "RegisterData",
                    gov_version = gov_version,
                    data_count = data_count,
                    "Creator data registered"
                );

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
                        creator: creator.clone(),
                        subject_id: subject_id.clone(),
                        namespace: namespace.clone(),
                        schema_id: schema_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "CreateSubject",
                    subject_id = %subject_id,
                    creator = %creator,
                    schema_id = ?schema_id,
                    "Subject created in register"
                );

                Ok(SubjectRegisterResponse::Ok)
            }
            SubjectRegisterMessage::DeleteSubject { subject_id } => {
                self.on_event(
                    SubjectRegisterEvent::DeleteSubject {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Subject removed from register"
                );

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
                        new_owner: new_owner.clone(),
                        old_owner: old_owner.clone(),
                        subject_id: subject_id.clone(),
                        namespace: namespace.clone(),
                        schema_id: schema_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "UpdateSubject",
                    subject_id = %subject_id,
                    old_owner = %old_owner,
                    new_owner = %new_owner,
                    "Subject ownership updated"
                );

                Ok(SubjectRegisterResponse::Ok)
            }
            SubjectRegisterMessage::Check {
                creator,
                gov_version,
                namespace,
                schema_id,
            } => {
                self.check(&creator, &namespace, &schema_id, gov_version)?;

                debug!(
                    msg_type = "Check",
                    creator = %creator,
                    schema_id = ?schema_id,
                    "Creator check passed"
                );

                Ok(SubjectRegisterResponse::Ok)
            }
        }
    }

    async fn on_event(
        &mut self,
        event: SubjectRegisterEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist subject register event"
            );
            emit_fail(ctx, e).await;
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
                        .or_insert_with(|| (CeilingMap::new(), HashSet::new()))
                        .0
                        .insert(*gov_version, quantity.to_owned());
                }

                debug!(
                    event_type = "RegisterData",
                    gov_version = gov_version,
                    data_count = data.len(),
                    "Creator data applied to state"
                );
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
                    .or_insert_with(|| (CeilingMap::new(), HashSet::new()))
                    .1
                    .insert(subject_id.to_owned());

                debug!(
                    event_type = "CreateSubject",
                    subject_id = %subject_id,
                    creator = %creator,
                    "Subject added to register state"
                );
            }
            SubjectRegisterEvent::DeleteSubject { subject_id } => {
                for (_, subjects) in self.register.values_mut() {
                    subjects.remove(subject_id);
                }

                debug!(
                    event_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Subject removed from register state"
                );
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
                    .or_insert_with(|| (CeilingMap::new(), HashSet::new()))
                    .1
                    .insert(subject_id.to_owned());

                self.register
                    .entry((
                        old_owner.to_owned(),
                        schema_id.to_owned(),
                        namespace.to_owned(),
                    ))
                    .or_insert_with(|| (CeilingMap::new(), HashSet::new()))
                    .1
                    .remove(subject_id);

                debug!(
                    event_type = "UpdateSubject",
                    subject_id = %subject_id,
                    old_owner = %old_owner,
                    new_owner = %new_owner,
                    "Subject ownership updated in state"
                );
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for SubjectRegister {}
