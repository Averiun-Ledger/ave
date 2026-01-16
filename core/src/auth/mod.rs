use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message, Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::{collections::HashMap, vec};
use tracing::{Span, debug, error, info_span, warn};

use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::{get_node_subject_data, subject_old};
use crate::model::common::subject::get_gov;
use crate::update::UpdateType;
use crate::{
    ActorMessage, NetworkMessage,
    db::Storable,
    governance::model::WitnessesData,
    model::common::emit_fail,
    update::{Update, UpdateMessage, UpdateNew, UpdateRes},
};

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum AuthWitness {
    One(PublicKey),
    Many(Vec<PublicKey>),
    None,
}

impl AuthWitness {
    fn merge(self, other: AuthWitness) -> AuthWitness {
        match (self, other) {
            (AuthWitness::None, w) | (w, AuthWitness::None) => w,
            (AuthWitness::One(x), AuthWitness::One(y)) => {
                AuthWitness::Many(vec![x, y])
            }
            (AuthWitness::One(x), AuthWitness::Many(mut y)) => {
                y.push(x);
                AuthWitness::Many(y)
            }
            (AuthWitness::Many(mut x), AuthWitness::One(y)) => {
                x.push(y);
                AuthWitness::Many(x)
            }
            (AuthWitness::Many(mut x), AuthWitness::Many(y)) => {
                x.extend(y);
                AuthWitness::Many(x)
            }
        }
    }
}

fn merge_options(
    opt1: Option<AuthWitness>,
    opt2: Option<AuthWitness>,
) -> Option<AuthWitness> {
    match (opt1, opt2) {
        (Some(w1), Some(w2)) => Some(w1.merge(w2)),
        (Some(w), None) | (None, Some(w)) => Some(w),
        (None, None) => None,
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Auth {
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    #[serde(skip)]
    network: Option<Arc<NetworkSender>>,

    auth: HashMap<String, AuthWitness>,
}

impl BorshSerialize for Auth {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the fields we want to persist, skipping 'owner'
        BorshSerialize::serialize(&self.auth, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for Auth {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let auth = HashMap::<String, AuthWitness>::deserialize_reader(reader)?;

        let our_key = Arc::new(PublicKey::default());
        let network = None;

        Ok(Self {
            network,
            our_key,
            auth,
        })
    }
}

impl Auth {
    async fn create_req_schema(
        ctx: &mut ActorContext<Auth>,
        subject_id: DigestIdentifier,
    ) -> Result<(u64, ActorMessage), ActorError> {
        let subject_id_string = subject_id.to_string();
        'req: {
            let Ok(Some((subject_data, _))) =
                get_node_subject_data(ctx, &subject_id_string).await
            else {
                break 'req;
            };

            let gov_id = if let Some(gov_id) = subject_data.governance_id {
                gov_id
            } else {
                subject_id_string.clone()
            };

            let gov = get_gov(ctx, &gov_id).await?;

            return Ok((
                subject_data.sn,
                ActorMessage::DistributionLedgerReq {
                    gov_version: Some(gov.version),
                    actual_sn: Some(subject_data.sn),
                    subject_id,
                },
            ));
        }
        Ok((
            0,
            ActorMessage::DistributionLedgerReq {
                gov_version: None,
                actual_sn: None,
                subject_id,
            },
        ))
    }
}

#[derive(Debug, Clone)]
pub enum AuthMessage {
    CheckTransfer {
        subject_id: DigestIdentifier,
    },
    NewAuth {
        subject_id: DigestIdentifier,
        witness: AuthWitness,
    },
    GetAuths,
    GetAuth {
        subject_id: DigestIdentifier,
    },
    DeleteAuth {
        subject_id: DigestIdentifier,
    },
    Update {
        subject_id: DigestIdentifier,
        more_info: WitnessesAuth,
    },
}

#[derive(Debug, Clone)]
pub enum WitnessesAuth {
    None,
    Owner(PublicKey),
    Witnesses,
}

impl Message for AuthMessage {}

#[derive(Debug, Clone)]
pub enum AuthResponse {
    Auths { subjects: Vec<String> },
    Witnesses(AuthWitness),
    None,
}

impl Response for AuthResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum AuthEvent {
    NewAuth {
        subject_id: String,
        witness: AuthWitness,
    },
    DeleteAuth {
        subject_id: String,
    },
}

impl Event for AuthEvent {}

#[async_trait]
impl Actor for Auth {
    type Event = AuthEvent;
    type Message = AuthMessage;
    type Response = AuthResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Auth", id = id)
        } else {
            info_span!("Auth", id = id)
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.init_store("auth", None, false, ctx).await {
            error!(
                error = %e,
                "Failed to initialize auth store"
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
                "Failed to stop auth store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Auth> for Auth {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: AuthMessage,
        ctx: &mut ave_actors::ActorContext<Auth>,
    ) -> Result<AuthResponse, ActorError> {
        match msg {
            AuthMessage::CheckTransfer { subject_id } => {
                let is_pending = subject_old(
                    ctx,
                    &subject_id.to_string(),
                )
                .await.map_err(|e| {
                    error!(
                        msg_type = "CheckTransfer",
                        subject_id = %subject_id,
                        error = %e,
                        "Could not determine if the node is the owner of the subject"
                    );
                    ActorError::Functional { description: format!(
                        "An error has occurred: {}",
                        e
                    )}
                })?;

                let Some(network) = self.network.clone() else {
                    error!(
                        msg_type = "CheckTransfer",
                        subject_id = %subject_id,
                        "Network is none"
                    );
                    return Err(ActorError::FunctionalCritical {
                        description: "network is none".to_string(),
                    });
                };

                if !is_pending {
                    error!(
                        msg_type = "CheckTransfer",
                        subject_id = %subject_id,
                        "Check transfer sent for subject not pending to confirm or reject"
                    );
                    return Err(ActorError::Functional {
                        description: "A Check transfer is being sent for a subject that is not pending to confirm or reject event".to_owned(),
                    });
                }

                let witness = self.auth.get(&subject_id.to_string());
                if let Some(witness) = witness {
                    let witnesses = match witness {
                        AuthWitness::One(key_identifier) => {
                            vec![key_identifier.clone()]
                        }
                        AuthWitness::Many(vec) => {
                            vec.clone()
                        }
                        AuthWitness::None => {
                            error!(
                                msg_type = "CheckTransfer",
                                subject_id = %subject_id,
                                "Subject has no witnesses to ask for update"
                            );
                            return Err(ActorError::Functional{description: "The subject has no witnesses to try to ask for an update.".to_owned()});
                        }
                    }.iter().cloned().collect();
                    let data = UpdateNew {
                        network,
                        subject_id: subject_id.clone(),
                        our_key: self.our_key.clone(),
                        response: None,
                        witnesses,
                        request: None,
                        update_type: UpdateType::Transfer,
                    };

                    let authorization = Update::new(data);
                    let child = ctx
                        .create_child(
                            &format!("transfer_{}", subject_id),
                            authorization,
                        )
                        .await?;

                    if let Err(e) = child.tell(UpdateMessage::Run).await {
                        return Err(emit_fail(ctx, e).await);
                    }

                    debug!(
                        msg_type = "CheckTransfer",
                        subject_id = %subject_id,
                        "Transfer check initiated successfully"
                    );
                } else {
                    error!(
                        msg_type = "CheckTransfer",
                        subject_id = %subject_id,
                        "Subject has not been authorized"
                    );
                    return Err(ActorError::Functional {
                        description: "The subject has not been authorized".to_owned(),
                    });
                }
            }
            AuthMessage::GetAuth { subject_id } => {
                if let Some(witnesses) = self.auth.get(&subject_id.to_string())
                {
                    debug!(
                        msg_type = "GetAuth",
                        subject_id = %subject_id,
                        "Retrieved auth witnesses"
                    );
                    return Ok(AuthResponse::Witnesses(witnesses.clone()));
                } else {
                    warn!(
                        msg_type = "GetAuth",
                        subject_id = %subject_id,
                        "Subject has not been authorized"
                    );
                    return Err(ActorError::Functional {
                        description: "The subject has not been authorized".to_owned(),
                    });
                }
            }
            AuthMessage::DeleteAuth { subject_id } => {
                self.on_event(
                    AuthEvent::DeleteAuth {
                        subject_id: subject_id.to_string(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "DeleteAuth",
                    subject_id = %subject_id,
                    "Auth deleted successfully"
                );
            }
            AuthMessage::NewAuth {
                subject_id,
                witness,
            } => {
                self.on_event(
                    AuthEvent::NewAuth {
                        subject_id: subject_id.to_string(),
                        witness,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "NewAuth",
                    subject_id = %subject_id,
                    "New auth created successfully"
                );
            }
            AuthMessage::GetAuths => {
                let subjects: Vec<String> = self.auth.keys().cloned().collect();
                debug!(
                    msg_type = "GetAuths",
                    count = subjects.len(),
                    "Retrieved all authorized subjects"
                );
                return Ok(AuthResponse::Auths { subjects });
            }
            AuthMessage::Update {
                subject_id,
                more_info,
            } => {
                let Some(network) = self.network.clone() else {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Network is none"
                    );
                    return Err(ActorError::FunctionalCritical {
                        description: "network is none".to_string(),
                    });
                };

                let more_witness = match more_info {
                    WitnessesAuth::None => None,
                    WitnessesAuth::Owner(key_identifier) => {
                        Some(AuthWitness::One(key_identifier))
                    }
                    WitnessesAuth::Witnesses => {
                        match get_gov(ctx, &subject_id.to_string()).await {
                            Ok(gov) => {
                                let witnesses = gov
                                    .get_witnesses(WitnessesData::Gov)
                                    .map_err(|e| ActorError::Functional {
                                        description: format!(
                                            "Can not obtain witnesses: {}",
                                            e
                                        ),
                                    })?;
                                Some(AuthWitness::Many(Vec::from_iter(
                                    witnesses.iter().cloned(),
                                )))
                            }
                            Err(e) => {
                                warn!(
                                    msg_type = "Update",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Governance not found when attempting to use explicit witnesses"
                                );
                                Some(AuthWitness::None)
                            }
                        }
                    }
                };

                let auth_witness =
                    self.auth.get(&subject_id.to_string()).cloned();
                let witness = merge_options(more_witness, auth_witness);

                if let Some(witness) = witness {
                    let (sn, request) = match Auth::create_req_schema(
                        ctx,
                        subject_id.clone(),
                    )
                    .await
                    {
                        Ok(data) => data,
                        Err(e) => {
                            error!(
                                msg_type = "Update",
                                subject_id = %subject_id,
                                error = %e,
                                "Cannot obtain request, sn, schema_id"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                    match witness {
                        AuthWitness::One(key_identifier) => {
                            let info = ComunicateInfo {
                                receiver: key_identifier.clone(),
                                request_id: String::default(),
                                version: 0,
                                receiver_actor: format!(
                                    "/user/node/distributor_{}",
                                    subject_id
                                ),
                            };

                            if let Err(e) = network
                                .send_command(
                                    network::CommandHelper::SendMessage {
                                        message: NetworkMessage {
                                            info,
                                            message: request,
                                        },
                                    },
                                )
                                .await
                            {
                                error!(
                                    msg_type = "Update",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Cannot send response to network"
                                );
                                return Err(emit_fail(ctx, e).await);
                            };

                            debug!(
                                msg_type = "Update",
                                subject_id = %subject_id,
                                "Update message sent to single witness"
                            );
                        }
                        AuthWitness::Many(vec) => {
                            let witnesses = vec.iter().cloned().collect();
                            let data = UpdateNew {
                                network,
                                subject_id: subject_id.clone(),
                                our_key: self.our_key.clone(),
                                response: Some(UpdateRes::Sn(sn)),
                                witnesses,
                                request: Some(request),
                                update_type: crate::update::UpdateType::Auth,
                            };

                            let updater = Update::new(data);
                            let child = ctx
                                .create_child(&subject_id.to_string(), updater)
                                .await?;

                            if let Err(e) = child.tell(UpdateMessage::Run).await
                            {
                                return Err(emit_fail(ctx, e).await);
                            }

                            debug!(
                                msg_type = "Update",
                                subject_id = %subject_id,
                                "Update process initiated with multiple witnesses"
                            );
                        }
                        AuthWitness::None => {
                            error!(
                                msg_type = "Update",
                                subject_id = %subject_id,
                                "Subject has no witnesses to ask for update"
                            );
                            return Err(ActorError::Functional {
                                description: "The subject has no witnesses to try to ask for an update.".to_owned(),
                            });
                        }
                    };
                } else {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Subject has not been authorized"
                    );
                    return Err(ActorError::Functional {
                        description: "The subject has not been authorized".to_owned(),
                    });
                }
            }
        };

        Ok(AuthResponse::None)
    }

    async fn on_event(
        &mut self,
        event: AuthEvent,
        ctx: &mut ActorContext<Auth>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                error = %e,
                "Failed to persist auth event"
            );
            emit_fail(ctx, e).await;
        } else {
            debug!("Auth event persisted successfully");
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Auth>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child actor fault"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for Auth {
    type Persistence = LightPersistence;
    type InitParams = (Arc<PublicKey>, Arc<NetworkSender>);

    fn update(&mut self, state: Self) {
        self.auth = state.auth;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            network: Some(params.1),
            our_key: params.0,
            auth: HashMap::new(),
        }
    }

    /// Change node state.
    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            AuthEvent::NewAuth {
                subject_id,
                witness,
            } => {
                self.auth.insert(subject_id.clone(), witness.clone());
                debug!(
                    event_type = "NewAuth",
                    subject_id = %subject_id,
                    "Applied new auth"
                );
            }
            AuthEvent::DeleteAuth { subject_id } => {
                self.auth.remove(subject_id);
                debug!(
                    event_type = "DeleteAuth",
                    subject_id = %subject_id,
                    "Applied auth deletion"
                );
            }
        };

        Ok(())
    }
}

#[async_trait]
impl Storable for Auth {}
