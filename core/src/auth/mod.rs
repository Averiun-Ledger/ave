use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Event, Handler,
    Message, Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::Namespace;
use ave_common::identity::{DigestIdentifier, PublicKey};
use borsh::{BorshDeserialize, BorshSerialize};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::collections::HashSet;
use std::sync::Arc;
use tracing::{Span, debug, error, info, info_span, warn};

use crate::helpers::network::service::NetworkSender;
use crate::model::common::node::get_subject_data;
use crate::model::common::subject::{
    get_gov, get_gov_sn, get_tracker_sn_creator,
};
use crate::node::SubjectData;
use crate::update::UpdateType;
use crate::{
    ActorMessage, NetworkMessage,
    db::Storable,
    governance::model::WitnessesData,
    model::common::emit_fail,
    update::{Update, UpdateMessage, UpdateNew},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Auth {
    #[serde(skip)]
    network: Option<Arc<NetworkSender>>,

    auth: HashMap<DigestIdentifier, HashSet<PublicKey>>,
}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum AuthWitness {
    One(PublicKey),
    Many(Vec<PublicKey>),
    None,
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
        let auth = HashMap::<DigestIdentifier, HashSet<PublicKey>>::deserialize_reader(reader)?;
        let network = None;

        Ok(Self { network, auth })
    }
}

impl Auth {
    async fn build_update_data(
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<(HashSet<PublicKey>, Option<u64>), ActorError> {
        let data = get_subject_data(ctx, subject_id).await?;

        let (witnesses, actual_sn) = if let Some(data) = &data {
            match data {
                SubjectData::Tracker {
                    governance_id,
                    schema_id,
                    namespace,
                    ..
                } => {
                    if let Some((creator, sn)) =
                        get_tracker_sn_creator(ctx, governance_id, subject_id)
                            .await?
                    {
                        let gov = get_gov(ctx, governance_id).await?;
                        let witnesses = gov
                            .get_witnesses(WitnessesData::Schema {
                                creator,
                                schema_id: schema_id.clone(),
                                namespace: Namespace::from(
                                    namespace.to_owned(),
                                ),
                            })
                            .map_err(|e| {
                                error!(
                                    subject_id = %subject_id,
                                    governance_id = %governance_id,
                                    error = %e,
                                    "Failed to get witnesses for tracker schema"
                                );
                                ActorError::Functional {
                                    description: e.to_string(),
                                }
                            })?;

                        (witnesses, Some(sn))
                    } else {
                        (HashSet::default(), None)
                    }
                }
                SubjectData::Governance { .. } => {
                    let gov = get_gov(ctx, subject_id).await?;
                    let witnesses =
                        gov.get_witnesses(WitnessesData::Gov).map_err(|e| {
                            error!(
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to get witnesses for governance"
                            );
                            ActorError::Functional {
                                description: e.to_string(),
                            }
                        })?;

                    let sn = get_gov_sn(ctx, subject_id).await?;

                    (witnesses, Some(sn))
                }
            }
        } else {
            (HashSet::default(), None)
        };

        Ok((witnesses, actual_sn))
    }
}

#[derive(Debug, Clone)]
pub enum AuthMessage {
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
        objective: Option<PublicKey>,
    },
}

impl Message for AuthMessage {}

#[derive(Debug, Clone)]
pub enum AuthResponse {
    Auths { subjects: Vec<DigestIdentifier> },
    Witnesses(HashSet<PublicKey>),
    None,
}

impl Response for AuthResponse {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum AuthEvent {
    NewAuth {
        subject_id: DigestIdentifier,
        witness: AuthWitness,
    },
    DeleteAuth {
        subject_id: DigestIdentifier,
    },
}

impl Event for AuthEvent {}

#[async_trait]
impl Actor for Auth {
    type Event = AuthEvent;
    type Message = AuthMessage;
    type Response = AuthResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Auth"),
            |parent_span| info_span!(parent: parent_span, "Auth"),
        )
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
impl Handler<Self> for Auth {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: AuthMessage,
        ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<AuthResponse, ActorError> {
        match msg {
            AuthMessage::GetAuth { subject_id } => {
                if let Some(witnesses) = self.auth.get(&subject_id) {
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
                        description: "The subject has not been authorized"
                            .to_owned(),
                    });
                }
            }
            AuthMessage::DeleteAuth { subject_id } => {
                self.on_event(
                    AuthEvent::DeleteAuth {
                        subject_id: subject_id.clone(),
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
                if !subject_id.is_empty() {
                    self.on_event(
                        AuthEvent::NewAuth {
                            subject_id: subject_id.clone(),
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
            }
            AuthMessage::GetAuths => {
                let subjects: Vec<DigestIdentifier> =
                    self.auth.keys().cloned().collect();
                debug!(
                    msg_type = "GetAuths",
                    count = subjects.len(),
                    "Retrieved all authorized subjects"
                );
                return Ok(AuthResponse::Auths { subjects });
            }
            AuthMessage::Update {
                subject_id,
                objective,
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

                let (witnesses, actual_sn) = {
                    let (mut witnesses, actual_sn) =
                        Self::build_update_data(ctx, &subject_id).await?;

                    if let Some(witness) = objective {
                        witnesses.insert(witness);
                    }

                    let auth_witnesses =
                        self.auth.get(&subject_id).cloned().unwrap_or_default();

                    (
                        witnesses
                            .union(&auth_witnesses)
                            .cloned()
                            .collect::<HashSet<PublicKey>>(),
                        actual_sn,
                    )
                };

                if witnesses.is_empty() {
                    error!(
                        msg_type = "Update",
                        subject_id = %subject_id,
                        "Subject has no witnesses to ask for update"
                    );
                    return Err(ActorError::Functional {
                        description: "The subject has no witnesses to try to ask for an update".to_owned(),
                    });
                } else if witnesses.len() == 1 {
                    let objetive = witnesses.iter().next().expect("len is 1");
                    let info = ComunicateInfo {
                        receiver: objetive.clone(),
                        request_id: String::default(),
                        version: 0,
                        receiver_actor: format!(
                            "/user/node/distributor_{}",
                            subject_id
                        ),
                    };

                    if let Err(e) = network
                        .send_command(network::CommandHelper::SendMessage {
                            message: NetworkMessage {
                                info,
                                message: ActorMessage::DistributionLedgerReq {
                                    actual_sn,
                                    subject_id: subject_id.clone(),
                                },
                            },
                        })
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
                } else {
                    let data = UpdateNew {
                        network,
                        subject_id: subject_id.clone(),
                        our_sn: actual_sn,
                        witnesses,
                        update_type: UpdateType::Auth,
                    };

                    let updater = Update::new(data);
                    if let Ok(child) =
                        ctx.create_child(&subject_id.to_string(), updater).await
                    {
                        if let Err(e) = child.tell(UpdateMessage::Run).await {
                            error!(
                                msg_type = "Update",
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to send Run message to update actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }

                        debug!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            "Update process initiated with multiple witnesses"
                        );
                    } else {
                        info!(
                            msg_type = "Update",
                            subject_id = %subject_id,
                            "An update is already in progress."
                        );
                    };
                }
            }
        };

        Ok(AuthResponse::None)
    }

    async fn on_event(
        &mut self,
        event: AuthEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist auth event"
            );
            emit_fail(ctx, e).await;
        }
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            error = %error,
            "Child actor fault in auth"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[async_trait]
impl PersistentActor for Auth {
    type Persistence = LightPersistence;
    type InitParams = Arc<NetworkSender>;

    fn update(&mut self, state: Self) {
        self.auth = state.auth;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            network: Some(params),
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
                let witnesses = match witness {
                    AuthWitness::One(public_key) => {
                        HashSet::from([public_key.clone()])
                    }
                    AuthWitness::Many(items) => items.iter().cloned().collect(),
                    AuthWitness::None => HashSet::default(),
                };

                self.auth.insert(subject_id.clone(), witnesses);
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
