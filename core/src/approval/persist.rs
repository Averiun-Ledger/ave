use std::sync::Arc;

use crate::{
    ActorMessage, NetworkMessage,
    approval::types::VotationType,
    db::Storable,
    governance::data::GovernanceData,
    helpers::network::service::NetworkSender,
    model::common::{
        emit_fail,
        node::{SignTypesNode, UpdateData, get_sign, update_ledger_network},
        subject::get_metadata,
    },
    subject::RequestSubjectData,
};
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::{
    Namespace, SchemaType,
    bridge::request::{ApprovalState, ApprovalStateRes},
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
};
use borsh::{BorshDeserialize, BorshSerialize};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use super::{
    Approval, ApprovalMessage, request::ApprovalReq, response::ApprovalRes,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprPersist {
    #[serde(skip)]
    helpers: Option<(HashAlgorithm, Arc<NetworkSender>)>,
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    #[serde(skip)]
    subject_id: DigestIdentifier,
    #[serde(skip)]
    pass_votation: VotationType,
    #[serde(skip)]
    node_key: PublicKey,
    request_id: String,
    version: u64,
    state: Option<ApprovalState>,
    request: Option<Signed<ApprovalReq>>,
}

impl BorshSerialize for ApprPersist {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the fields we want to persist, skipping 'owner'
        BorshSerialize::serialize(&self.request_id, writer)?;
        BorshSerialize::serialize(&self.version, writer)?;
        BorshSerialize::serialize(&self.state, writer)?;
        BorshSerialize::serialize(&self.request, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for ApprPersist {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let request_id = String::deserialize_reader(reader)?;
        let version = u64::deserialize_reader(reader)?;
        let state = Option::<ApprovalState>::deserialize_reader(reader)?;
        let request =
            Option::<Signed<ApprovalReq>>::deserialize_reader(reader)?;

        let node_key = PublicKey::default();
        let our_key = Arc::new(PublicKey::default());
        let pass_votation = VotationType::AlwaysAccept;
        let subject_id = DigestIdentifier::default();

        Ok(Self {
            helpers: None,
            our_key,
            request_id,
            version,
            subject_id,
            pass_votation,
            state,
            request,
            node_key,
        })
    }
}

pub struct InitApprPersist {
    pub our_key: Arc<PublicKey>,
    pub node_key: PublicKey,
    pub subject_id: DigestIdentifier,
    pub pass_votation: VotationType,
    pub helpers: (HashAlgorithm, Arc<NetworkSender>),
}

impl ApprPersist {
    async fn check_governance(
        &self,
        ctx: &mut ActorContext<ApprPersist>,
        governance_id: &DigestIdentifier,
        gov_version: u64,
    ) -> Result<(), ActorError> {
        let Some((.., network)) = &self.helpers else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers are None".to_owned(),
            });
        };

        let metadata = get_metadata(ctx, governance_id).await?;
        let governance =
            match GovernanceData::try_from(metadata.properties.clone()) {
                Ok(gov) => gov,
                Err(e) => {
                    error!(
                        governance_id = %governance_id,
                        error = %e,
                        "Failed to convert governance from properties"
                    );
                    return Err(ActorError::FunctionalCritical {
                        description: format!(
                            "can not convert governance from properties: {}",
                            e
                        ),
                    });
                }
            };

        match gov_version.cmp(&governance.version) {
            std::cmp::Ordering::Equal => {
                // If it is the same it means that we have the latest version of governance, we are up to date.
            }
            std::cmp::Ordering::Greater => {
                // Me llega una versión mayor a la mía.
                let data = UpdateData {
                    sn: metadata.sn,
                    gov_version: governance.version,
                    subject_id: governance_id.clone(),
                    other_node: self.node_key.clone(),
                };
                update_ledger_network(data, network.clone()).await?;
            }
            std::cmp::Ordering::Less => {
                // TODO Por ahora no vamos hacer nada, pero esto quiere decir que el owner perdió el ledger
                // lo recuperó pero no recibió la última versión. Aquí se podría haber producido un fork.
                // Esto ocurre solo en la aprobación porque solo se realiza en las gobernanzas.
            }
        }

        Ok(())
    }

    async fn send_response(
        &self,
        ctx: &mut ActorContext<ApprPersist>,
        request: Signed<ApprovalReq>,
        response: bool,
        request_id: &str,
        version: u64,
    ) -> Result<(), ActorError> {
        let Some((hash, network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers are None".to_owned(),
            });
        };

        let approval_req_hash =
            hash_borsh(&*hash.hasher(), &request).map_err(|e| {
                ActorError::FunctionalCritical {
                    description: format!(
                        "Can not obtain approval request hash {}",
                        e
                    ),
                }
            })?;

        let req_subject_data_hash = hash_borsh(
            &*hash.hasher(),
            &RequestSubjectData {
                subject_id: request.content().subject_id.clone(),
                governance_id: request.content().subject_id.clone(),
                sn: request.content().sn,
                namespace: Namespace::new(),
                schema_id: SchemaType::Governance,
                gov_version: request.content().gov_version,
                signer: request.content().signer.clone(),
            },
        )
        .map_err(|e| ActorError::FunctionalCritical {
            description: format!("Can not obtain approval request hash {}", e),
        })?;

        let res = ApprovalRes::Response {
            approval_req_hash,
            agrees: response,
            req_subject_data_hash,
        };
        let sign_type = SignTypesNode::ApprovalRes(Box::new(res.clone()));
        let signature = get_sign(ctx, sign_type).await?;

        let subject_id = request.content().subject_id.clone();
        if self.node_key == *self.our_key {
            // Approval actor.
            let subject_id = ctx.path().parent().key();
            let approval_actor = ctx
                .system()
                .get_actor::<Approval>(&ActorPath::from(&format!(
                    "/user/request/{}/approval",
                    subject_id
                )))
                .await;
            if let Ok(approval_actor) = approval_actor {
                approval_actor
                    .tell(ApprovalMessage::Response {
                        approval_res: res,
                        sender: (*self.our_key).clone(),
                        signature: Some(signature),
                    })
                    .await?;
            }
        } else {
            let signed_response: Signed<ApprovalRes> =
                Signed::from_parts(res, signature);

            let new_info = ComunicateInfo {
                receiver: self.node_key.clone(),
                request_id: request_id.to_string(),
                version,
                receiver_actor: format!(
                    "/user/request/{}/approval/{}",
                    subject_id, self.our_key
                ),
            };

            if let Err(e) = network
                .send_command(network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info: new_info,
                        message: ActorMessage::ApprovalRes {
                            res: Box::new(signed_response),
                        },
                    },
                })
                .await
            {
                return Err(emit_fail(ctx, e).await);
            };
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ApprPersistMessage {
    MakeObsolete,
    // Mensaje para aprobar localmente
    LocalApproval {
        request_id: DigestIdentifier,
        version: u64,
        approval_req: Signed<ApprovalReq>,
    },
    // Mensaje para pedir aprobación desde el helper y devolver ahi
    NetworkRequest {
        approval_req: Signed<ApprovalReq>,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    GetApproval {
        state: Option<ApprovalState>,
    },
    ChangeResponse {
        response: ApprovalStateRes,
    }, // Necesito poder emitir un evento de aprobación, no solo el automático
}

impl Message for ApprPersistMessage {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum ApprPersistEvent {
    ChangeState {
        state: ApprovalState,
    },
    SafeState {
        subject_id: DigestIdentifier,
        request_id: String,
        version: u64,
        request: Box<Signed<ApprovalReq>>,
        state: ApprovalState,
    },
}

impl Event for ApprPersistEvent {}

pub enum ApprPersistResponse {
    Ok,
    Approval {
        request: ApprovalReq,
        state: ApprovalState,
    },
}

impl Response for ApprPersistResponse {}

#[async_trait]
impl Actor for ApprPersist {
    type Event = ApprPersistEvent;
    type Message = ApprPersistMessage;
    type Response = ApprPersistResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "ApprPersist")
        } else {
            info_span!("ApprPersist")
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        if let Err(e) = self
            .init_store("approver", Some(prefix.clone()), false, ctx)
            .await
        {
            error!(
                error = %e,
                "Failed to initialize approver store"
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
                "Failed to stop approver store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<ApprPersist> for ApprPersist {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ApprPersistMessage,
        ctx: &mut ActorContext<ApprPersist>,
    ) -> Result<ApprPersistResponse, ActorError> {
        match msg {
            ApprPersistMessage::GetApproval { state } => {
                let res = if let Some(req) = &self.request
                    && let Some(req_state) = &self.state
                {
                    if let Some(query) = state {
                        if &query == req_state {
                            ApprPersistResponse::Approval {
                                request: req.content().clone(),
                                state: query,
                            }
                        } else {
                            ApprPersistResponse::Ok
                        }
                    } else {
                        ApprPersistResponse::Approval {
                            request: req.content().clone(),
                            state: req_state.clone(),
                        }
                    }
                } else {
                    ApprPersistResponse::Ok
                };

                return Ok(res);
            }
            ApprPersistMessage::MakeObsolete => {
                let state = if let Some(state) = self.state.clone() {
                    state
                } else {
                    return Ok(ApprPersistResponse::Ok);
                };

                if state == ApprovalState::Pending {
                    self.on_event(
                        ApprPersistEvent::ChangeState {
                            state: ApprovalState::Obsolete,
                        },
                        ctx,
                    )
                    .await;

                    debug!(
                        msg_type = "MakeObsolete",
                        "State changed to obsolete"
                    );
                }
            }
            ApprPersistMessage::ChangeResponse { response } => {
                let Some(state) = self.state.clone() else {
                    warn!(
                        msg_type = "ChangeResponse",
                        "Approval state not found"
                    );
                    return Err(ActorError::Functional {
                        description: "Can not get approval state".to_owned(),
                    });
                };

                if response == ApprovalStateRes::Obsolete {
                    warn!(
                        msg_type = "ChangeResponse",
                        "Invalid state transition to Obsolete"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "New state is Obsolete, is an invalid state"
                                .to_owned(),
                    });
                }

                if state == ApprovalState::Pending {
                    let (response, state) =
                        if ApprovalStateRes::Accepted == response {
                            (true, ApprovalState::Accepted)
                        } else {
                            (false, ApprovalState::Rejected)
                        };

                    let Some(approval_req) = self.request.clone() else {
                        error!(
                            msg_type = "ChangeResponse",
                            "Approval request not found"
                        );
                        return Err(ActorError::Functional {
                            description: "Can not get approval request"
                                .to_owned(),
                        });
                    };

                    if let Err(e) = self
                        .send_response(
                            ctx,
                            approval_req,
                            response,
                            &self.request_id.to_string(),
                            self.version,
                        )
                        .await
                    {
                        error!(
                            msg_type = "ChangeResponse",
                            error = %e,
                            "Failed to send approval response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    };

                    debug!(
                        msg_type = "ChangeResponse",
                        new_state = ?state,
                        "State changed successfully"
                    );

                    self.on_event(ApprPersistEvent::ChangeState { state }, ctx)
                        .await;
                }
            }
            // aprobar si esta por defecto
            ApprPersistMessage::LocalApproval {
                request_id,
                version,
                approval_req,
            } => {
                if request_id.to_string() != self.request_id
                    || version != self.version
                {
                    let state =
                        if self.pass_votation == VotationType::AlwaysAccept {
                            if let Err(e) = self
                                .send_response(
                                    ctx,
                                    approval_req.clone(),
                                    true,
                                    &request_id.to_string(),
                                    version,
                                )
                                .await
                            {
                                error!(
                                    msg_type = "LocalApproval",
                                    error = %e,
                                    "Failed to send approval response"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }

                            ApprovalState::Accepted
                        } else {
                            ApprovalState::Pending
                        };

                    debug!(
                        msg_type = "LocalApproval",
                        request_id = %request_id,
                        version = version,
                        new_state = ?state,
                        "New approval request processed"
                    );

                    self.on_event(
                        ApprPersistEvent::SafeState {
                            subject_id: self.subject_id.clone(),
                            version,
                            request_id: request_id.to_string(),
                            request: Box::new(approval_req),
                            state,
                        },
                        ctx,
                    )
                    .await;
                } else if let Some(state) = self.state.clone() {
                    let response = if state == ApprovalState::Accepted {
                        true
                    } else if state == ApprovalState::Rejected {
                        false
                    } else {
                        return Ok(ApprPersistResponse::Ok);
                    };

                    if let Err(e) = self
                        .send_response(
                            ctx,
                            approval_req.clone(),
                            response,
                            &request_id.to_string(),
                            version,
                        )
                        .await
                    {
                        error!(
                            msg_type = "LocalApproval",
                            error = %e,
                            "Failed to resend approval response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }

                    debug!(
                        msg_type = "LocalApproval",
                        request_id = %request_id,
                        version = version,
                        "Response resent successfully"
                    );
                }
            }
            ApprPersistMessage::NetworkRequest {
                approval_req,
                info,
                sender,
            } => {
                if sender != approval_req.signature().signer
                    || sender != self.node_key
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_sender = %self.node_key,
                        received_sender = %sender,
                        "Unexpected sender"
                    );
                    return Ok(ApprPersistResponse::Ok);
                }

                if info.request_id != self.request_id
                    || info.version != self.version
                {
                    if let Err(e) = approval_req.verify() {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Invalid approval signature"
                        );
                        return Err(ActorError::Functional {
                            description: format!(
                                "Can not verify signature of request: {}",
                                e
                            ),
                        });
                    }

                    if let Err(e) = self
                        .check_governance(
                            ctx,
                            &approval_req.content().subject_id,
                            approval_req.content().gov_version,
                        )
                        .await
                    {
                        warn!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to check governance"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }

                    let state =
                        if self.pass_votation == VotationType::AlwaysAccept {
                            ApprovalState::Accepted
                        } else {
                            ApprovalState::Pending
                        };

                    self.on_event(
                        ApprPersistEvent::SafeState {
                            subject_id: self.subject_id.clone(),
                            request_id: info.request_id.clone(),
                            version: info.version,
                            request: Box::new(approval_req.clone()),
                            state: state.clone(),
                        },
                        ctx,
                    )
                    .await;

                    if state == ApprovalState::Accepted
                        && let Err(e) = self
                            .send_response(
                                ctx,
                                approval_req.clone(),
                                true,
                                &info.request_id,
                                info.version,
                            )
                            .await
                    {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to send approval response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    };

                    debug!(
                        msg_type = "NetworkRequest",
                        request_id = %info.request_id,
                        version = info.version,
                        new_state = ?state,
                        "Network approval request processed"
                    );
                } else if !self.request_id.is_empty() {
                    let state = if let Some(state) = self.state.clone() {
                        state
                    } else {
                        warn!(
                            msg_type = "NetworkRequest",
                            "Approval state not found"
                        );
                        let e = ActorError::FunctionalCritical {
                            description: "Can not get state".to_owned(),
                        };
                        return Err(emit_fail(ctx, e).await);
                    };

                    let response = if ApprovalState::Accepted == state {
                        true
                    } else if ApprovalState::Rejected == state {
                        false
                    } else {
                        return Ok(ApprPersistResponse::Ok);
                    };

                    let approval_req =
                        if let Some(approval_req) = self.request.clone() {
                            approval_req
                        } else {
                            error!(
                                msg_type = "NetworkRequest",
                                "Approval request not found"
                            );
                            let e = ActorError::FunctionalCritical {
                                description: "Can not get approve request"
                                    .to_owned(),
                            };
                            return Err(emit_fail(ctx, e).await);
                        };

                    if let Err(e) = self
                        .send_response(
                            ctx,
                            approval_req.clone(),
                            response,
                            &self.request_id.to_string(),
                            self.version,
                        )
                        .await
                    {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to resend approval response"
                        );
                        return Err(emit_fail(ctx, e).await);
                    };

                    debug!(
                        msg_type = "NetworkRequest",
                        request_id = %self.request_id,
                        version = self.version,
                        "Response resent successfully"
                    );
                }
            }
        }
        Ok(ApprPersistResponse::Ok)
    }

    async fn on_event(
        &mut self,
        event: ApprPersistEvent,
        ctx: &mut ActorContext<ApprPersist>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(error = %e, "Failed to persist event");
            emit_fail(ctx, e).await;
        };

        if let Err(e) = ctx.publish_event(event).await {
            error!(error = %e, "Failed to publish event");
            emit_fail(ctx, e).await;
        };
    }
}

// Debemos persistir el estado de la petición hasta que se apruebe
#[async_trait]
impl PersistentActor for ApprPersist {
    type Persistence = LightPersistence;
    type InitParams = InitApprPersist;

    fn update(&mut self, state: Self) {
        self.request_id = state.request_id;
        self.version = state.version;
        self.state = state.state;
        self.request = state.request;
    }

    fn create_initial(params: Self::InitParams) -> Self {
        let Self::InitParams {
            our_key,
            node_key,
            subject_id,
            pass_votation,
            helpers,
        } = params;

        Self {
            helpers: Some(helpers),
            node_key,
            our_key,
            request_id: String::default(),
            version: 0,
            subject_id,
            pass_votation,
            state: None,
            request: None,
        }
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            ApprPersistEvent::ChangeState { state, .. } => {
                debug!(
                    event_type = "ChangeState",
                    new_state = ?state,
                    "Approval state changed"
                );
                self.state = Some(state.clone());
            }
            ApprPersistEvent::SafeState {
                request,
                state,
                request_id,
                version,
                ..
            } => {
                debug!(
                    event_type = "SafeState",
                    request_id = %request_id,
                    version = version,
                    new_state = ?state,
                    "Approval state saved"
                );
                self.version = *version;
                self.request_id.clone_from(request_id);
                self.request = Some(*request.clone());
                self.state = Some(state.clone());
            }
        };

        Ok(())
    }
}

impl Storable for ApprPersist {}
