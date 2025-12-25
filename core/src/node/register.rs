use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{error, warn};

use crate::model::request::SchemaType;
use crate::{db::Storable, model::common::emit_fail};

const TARGET_REGISTER: &str = "Ave-Node-Register";

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RegisterDataSubj {
    pub schema_id: SchemaType,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RegisterDataGov {
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct GovsData {
    pub governance_id: String,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SubjsData {
    pub subject_id: String,
    pub schema_id: SchemaType,
    pub active: bool,
    pub name: Option<String>,
    pub description: Option<String>,
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
pub struct Register {
    register_gov: HashMap<String, RegisterDataGov>,
    register_subj: HashMap<String, HashMap<String, RegisterDataSubj>>,
}

#[derive(Debug, Clone)]
pub enum RegisterMessage {
    GetGovs {
        active: Option<bool>,
    },
    GetSubj {
        gov_id: String,
        active: Option<bool>,
        schema_id: Option<String>,
    },
    RegisterGov {
        gov_id: String,
        name: Option<String>,
        description: Option<String>,
    },
    EOLGov {
        gov_id: String,
    },
    RegisterSubj {
        gov_id: String,
        subject_id: String,
        schema_id: SchemaType,
        name: Option<String>,
        description: Option<String>,
    },
    EOLSubj {
        gov_id: String,
        subj_id: String,
    },
}

impl Message for RegisterMessage {}

#[derive(Debug, Clone)]
pub enum RegisterResponse {
    Govs { governances: Vec<GovsData> },
    Subjs { subjects: Vec<SubjsData> },
    None,
}

impl Response for RegisterResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum RegisterEvent {
    RegisterGov {
        gov_id: String,
        data: RegisterDataGov,
    },
    EOLGov {
        gov_id: String,
    },
    RegisterSubj {
        gov_id: String,
        subject_id: String,
        data: RegisterDataSubj,
    },
    EOLSubj {
        gov_id: String,
        subj_id: String,
    },
}

impl Event for RegisterEvent {}

#[async_trait]
impl Actor for Register {
    type Event = RegisterEvent;
    type Message = RegisterMessage;
    type Response = RegisterResponse;

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.init_store("register", None, false, ctx).await
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.stop_store(ctx).await
    }
}

#[async_trait]
impl Handler<Register> for Register {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RegisterMessage,
        ctx: &mut ave_actors::ActorContext<Register>,
    ) -> Result<RegisterResponse, ActorError> {
        match msg {
            RegisterMessage::GetGovs { active } => {
                if let Some(active) = active {
                    return Ok(RegisterResponse::Govs {
                        governances: self
                            .register_gov
                            .iter()
                            .filter(|x| x.1.active == active)
                            .map(|x| GovsData {
                                active: x.1.active,
                                governance_id: x.0.clone(),
                                description: x.1.description.clone(),
                                name: x.1.name.clone(),
                            })
                            .collect(),
                    });
                } else {
                    return Ok(RegisterResponse::Govs {
                        governances: self
                            .register_gov
                            .iter()
                            .map(|x| GovsData {
                                active: x.1.active,
                                governance_id: x.0.clone(),
                                description: x.1.description.clone(),
                                name: x.1.name.clone(),
                            })
                            .collect(),
                    });
                }
            }
            RegisterMessage::GetSubj {
                gov_id,
                active,
                schema_id,
            } => {
                let subjects = self.register_subj.get(&gov_id.to_string());
                if let Some(subjects) = subjects {
                    let mut subj = vec![];
                    for (subject_id, data) in subjects {
                        if let Some(active) = active
                            && data.active != active
                        {
                            continue;
                        };

                        if let Some(schema_id) = schema_id.clone()
                            && data.schema_id.to_string() != schema_id
                        {
                            continue;
                        }

                        subj.push(SubjsData {
                            schema_id: data.schema_id.clone(),
                            subject_id: subject_id.clone(),
                            active: data.active,
                            name: data.name.clone(),
                            description: data.description.clone(),
                        });
                    }

                    return Ok(RegisterResponse::Subjs { subjects: subj });
                } else {
                    let e = "Governance id is not registered";
                    warn!(TARGET_REGISTER, "GetSubj, {}", e);
                    return Err(ActorError::Functional(e.to_owned()));
                }
            }
            RegisterMessage::RegisterGov {
                gov_id,
                description,
                name,
            } => {
                self.on_event(
                    RegisterEvent::RegisterGov {
                        gov_id,
                        data: RegisterDataGov {
                            active: true,
                            name,
                            description,
                        },
                    },
                    ctx,
                )
                .await
            }
            RegisterMessage::EOLGov { gov_id } => {
                self.on_event(RegisterEvent::EOLGov { gov_id }, ctx).await
            }
            RegisterMessage::RegisterSubj {
                gov_id,
                subject_id,
                schema_id,
                name,
                description,
            } => {
                self.on_event(
                    RegisterEvent::RegisterSubj {
                        gov_id,
                        subject_id,
                        data: RegisterDataSubj {
                            schema_id,
                            active: true,
                            name,
                            description,
                        },
                    },
                    ctx,
                )
                .await
            }
            RegisterMessage::EOLSubj { gov_id, subj_id } => {
                self.on_event(RegisterEvent::EOLSubj { gov_id, subj_id }, ctx)
                    .await
            }
        }
        Ok(RegisterResponse::None)
    }

    async fn on_event(
        &mut self,
        event: RegisterEvent,
        ctx: &mut ActorContext<Register>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                TARGET_REGISTER,
                "OnEvent, can not persist information: {}", e
            );
            emit_fail(ctx, e).await;
        };
    }
}

#[async_trait]
impl PersistentActor for Register {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            RegisterEvent::EOLGov { gov_id } => {
                if let Some(gov) = self.register_gov.get_mut(gov_id) {
                    gov.active = false;
                };
            }
            RegisterEvent::EOLSubj { gov_id, subj_id } => {
                self.register_subj
                    .get_mut(gov_id)
                    .map(|x| x.get_mut(subj_id).map(|x| x.active = false));
            }
            RegisterEvent::RegisterGov { gov_id, data } => {
                self.register_gov.insert(gov_id.clone(), data.clone());
                self.register_subj.insert(gov_id.clone(), HashMap::new());
            }
            RegisterEvent::RegisterSubj {
                gov_id,
                subject_id,
                data,
            } => {
                self.register_subj
                    .entry(gov_id.clone())
                    .or_default()
                    .insert(subject_id.clone(), data.clone());
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for Register {}
