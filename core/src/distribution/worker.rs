use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    Namespace, SchemaType,
    identity::{DigestIdentifier, PublicKey},
};
use network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage, Node, NodeMessage, NodeResponse,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        model::{HashThisRole, RoleTypes},
    },
    helpers::network::service::NetworkSender,
    model::{
        common::{
            check_subject_creation, check_witness_access, emit_fail,
            node::{get_subject_data, try_to_update},
            subject::{
                acquire_subject, create_subject, get_gov, get_gov_sn,
                update_ledger,
            },
        },
        event::Ledger,
    },
    node::SubjectData,
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};

use tracing::{Span, debug, error, info_span, warn};

use super::error::DistributorError;

pub struct DistriWorker {
    pub our_key: Arc<PublicKey>,
    pub network: Arc<NetworkSender>,
}

impl DistriWorker {
    fn requester_id(
        kind: &str,
        subject_id: &DigestIdentifier,
        info: &ComunicateInfo,
        sender: &PublicKey,
    ) -> String {
        format!(
            "{kind}:{subject_id}:{sender}:{}:{}",
            info.request_id, info.version
        )
    }

    async fn get_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        hi_sn: u64,
        lo_sn: Option<u64>,
        is_gov: bool,
    ) -> Result<(Vec<Ledger>, bool), ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}",
            subject_id
        ));

        if is_gov {
            let governance_actor =
                ctx.system().get_actor::<Governance>(&path).await?;

            let response = governance_actor
                .ask(GovernanceMessage::GetLedger { lo_sn, hi_sn })
                .await?;

            match response {
                GovernanceResponse::Ledger { ledger, is_all } => {
                    Ok((ledger, is_all))
                }
                _ => Err(ActorError::UnexpectedResponse {
                    expected: "GovernanceResponse::Ledger".to_owned(),
                    path,
                }),
            }
        } else {
            let lease = acquire_subject(
                ctx,
                subject_id,
                format!("send_distribution:{subject_id}"),
                None,
                true,
            )
            .await?;
            let tracker_actor =
                ctx.system().get_actor::<Tracker>(&path).await?;
            let response = tracker_actor
                .ask(TrackerMessage::GetLedger { lo_sn, hi_sn })
                .await;
            lease.finish(ctx).await?;
            let response = response?;

            match response {
                TrackerResponse::Ledger { ledger, is_all } => {
                    Ok((ledger, is_all))
                }
                _ => Err(ActorError::UnexpectedResponse {
                    expected: "TrackerResponse::Ledger".to_owned(),
                    path,
                }),
            }
        }
    }

    async fn authorized_subj(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<(bool, Option<SubjectData>), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor = ctx.system().get_actor::<Node>(&node_path).await?;

        let response = node_actor
            .ask(NodeMessage::AuthData(subject_id.to_owned()))
            .await?;
        match response {
            NodeResponse::AuthData { auth, subject_data } => {
                Ok((auth, subject_data))
            }
            _ => Err(ActorError::UnexpectedResponse {
                expected: "NodeResponse::AuthData".to_owned(),
                path: node_path,
            }),
        }
    }

    async fn check_auth(
        &self,
        ctx: &mut ActorContext<Self>,
        signer: PublicKey,
        ledger: Ledger,
    ) -> Result<(bool, bool), ActorError> {
        let subject_id = ledger.get_subject_id();
        // Si está auth o si soy el dueño del sujeto.
        let (auth, subject_data) =
            self.authorized_subj(ctx, &subject_id).await?;

        // Extraer schema_id, namespace y governance_id según si conocemos el sujeto o no
        let (schema_id, namespace, governance_id) = if let Some(ref data) =
            subject_data
        {
            // Lo conozco
            match data {
                SubjectData::Tracker {
                    governance_id,
                    schema_id,
                    namespace,
                    ..
                } => {
                    let namespace = Namespace::from(namespace.clone());
                    (schema_id.clone(), namespace, Some(governance_id.clone()))
                }
                SubjectData::Governance { .. } => {
                    (SchemaType::Governance, Namespace::new(), None)
                }
            }
        } else {
            // No lo conozco - debe ser evento Create
            if let Some(create) = ledger.get_create_event() {
                if !create.schema_id.is_gov() && create.governance_id.is_empty()
                {
                    return Err(
                        DistributorError::MissingGovernanceIdInCreate {
                            subject_id: subject_id.clone(),
                        }
                        .into(),
                    );
                }

                let gov_id = if create.schema_id.is_gov() {
                    None
                } else {
                    Some(create.governance_id.clone())
                };

                (create.schema_id.clone(), create.namespace.clone(), gov_id)
            } else {
                // No es el primer evento, necesito el primero
                try_to_update(ctx, subject_id, Some(signer)).await?;
                return Err(DistributorError::UpdatingSubject.into());
            }
        };

        let is_gov = schema_id.is_gov();
        // Verificar autorización
        if is_gov {
            // Es una gobernanza
            if !auth {
                return Err(DistributorError::GovernanceNotAuthorized.into());
            }
        } else {
            // Es un Tracker - verificar rol de witness si no está autorizado
            if !auth {
                let Some(governance_id) = governance_id else {
                    error!(
                        subject_id = %subject_id,
                        "Tracker subject is missing governance_id during authorization check"
                    );
                    return Err(DistributorError::MissingGovernanceId {
                        subject_id: subject_id.clone(),
                    }
                    .into());
                };
                let gov = get_gov(ctx, &governance_id).await.map_err(|e| {
                    DistributorError::GetGovernanceFailed {
                        details: e.to_string(),
                    }
                })?;

                match gov.version.cmp(&ledger.gov_version) {
                    std::cmp::Ordering::Less => {
                        return Err(
                            DistributorError::GovernanceVersionMismatch {
                                our_version: gov.version,
                                their_version: ledger.gov_version,
                            }
                            .into(),
                        );
                    }
                    std::cmp::Ordering::Equal => {}
                    std::cmp::Ordering::Greater => {}
                };

                if !gov.has_this_role(HashThisRole::SchemaWitness {
                    who: (*self.our_key).clone(),
                    creator: signer,
                    schema_id,
                    namespace,
                }) {
                    return Err(DistributorError::NotWitness.into());
                }
            }
        }

        Ok((is_gov, subject_data.is_some()))
    }

    async fn check_witness(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
    ) -> Result<(u64, bool), ActorError> {
        let data = get_subject_data(ctx, subject_id).await?;

        let Some(data) = data else {
            return Err(DistributorError::SubjectNotFound.into());
        };

        match data {
            SubjectData::Tracker {
                governance_id,
                schema_id,
                namespace,
                ..
            } => {
                let Some(sn) = check_witness_access(
                    ctx,
                    &governance_id,
                    subject_id,
                    sender,
                    namespace,
                    schema_id,
                )
                .await?
                else {
                    return Err(DistributorError::SenderNoAccess.into());
                };

                Ok((sn, false))
            }
            SubjectData::Governance { .. } => {
                let gov = get_gov(ctx, subject_id).await.map_err(|e| {
                    DistributorError::GetGovernanceFailed {
                        details: e.to_string(),
                    }
                })?;

                if !gov.has_this_role(HashThisRole::Gov {
                    who: sender.clone(),
                    role: RoleTypes::Witness,
                }) {
                    return Err(DistributorError::SenderNotMember {
                        sender: sender.to_string(),
                    }
                    .into());
                }

                Ok((get_gov_sn(ctx, subject_id).await?, true))
            }
        }
    }
}

#[async_trait]
impl Actor for DistriWorker {
    type Event = ();
    type Message = DistriWorkerMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("DistriWorker", id),
            |parent_span| info_span!(parent: parent_span, "DistriWorker", id),
        )
    }
}

#[derive(Debug, Clone)]
pub enum DistriWorkerMessage {
    GetLastSn {
        subject_id: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    },
    GetGovernanceVersion {
        subject_id: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    },
    // Un nodo nos solicitó la copia del ledger.
    SendDistribution {
        actual_sn: Option<u64>,
        subject_id: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    // Nos llega una replica, guardarla en informar que la hemos recivido
    LastEventDistribution {
        ledger: Box<Ledger>,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    LedgerDistribution {
        ledger: Vec<Ledger>,
        is_all: bool,
        info: ComunicateInfo,
        sender: PublicKey,
    },
}

impl Message for DistriWorkerMessage {}

impl NotPersistentActor for DistriWorker {}

#[async_trait]
impl Handler<Self> for DistriWorker {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: DistriWorkerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            DistriWorkerMessage::GetLastSn {
                subject_id,
                info,
                sender,
                receiver_actor,
            } => {
                let (sn, ..) = match self
                    .check_witness(ctx, &subject_id, sender.clone())
                    .await
                {
                    Ok(sn) => sn,
                    Err(e) => {
                        if let ActorError::Functional { .. } = e {
                            warn!(
                                msg_type = "GetLastSn",
                                subject_id = %subject_id,
                                sender = %sender,
                                error = %e,
                                "Witness check failed"
                            );
                            return Err(e);
                        } else {
                            error!(
                                msg_type = "GetLastSn",
                                subject_id = %subject_id,
                                sender = %sender,
                                error = %e,
                                "Witness check failed"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor,
                };

                if let Err(e) = self
                    .network
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::AuthLastSn { sn },
                        },
                    })
                    .await
                {
                    error!(
                        msg_type = "GetLastSn",
                        subject_id = %subject_id,
                        sn = sn,
                        error = %e,
                        "Failed to send last SN response to network"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                debug!(
                    msg_type = "GetLastSn",
                    subject_id = %subject_id,
                    sn = sn,
                    sender = %sender,
                    "Last SN response sent successfully"
                );
            }
            DistriWorkerMessage::GetGovernanceVersion {
                subject_id,
                info,
                sender,
                receiver_actor,
            } => {
                let auth_ok = match self
                    .check_witness(ctx, &subject_id, sender.clone())
                    .await
                {
                    Ok(..) => true,
                    Err(e) => {
                        if matches!(e, ActorError::Functional { .. }) {
                            warn!(
                                msg_type = "GetGovernanceVersion",
                                subject_id = %subject_id,
                                sender = %sender,
                                error = %e,
                                "Witness check failed, falling back to auth state"
                            );

                            let auth_path = ActorPath::from("/user/node/auth");
                            let auth_actor = match ctx
                                .system()
                                .get_actor::<crate::auth::Auth>(&auth_path)
                                .await
                            {
                                Ok(auth_actor) => auth_actor,
                                Err(e) => {
                                    error!(
                                        msg_type = "GetGovernanceVersion",
                                        subject_id = %subject_id,
                                        sender = %sender,
                                        error = %e,
                                        "Failed to get auth actor"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };

                            match auth_actor
                                .ask(crate::auth::AuthMessage::GetAuth {
                                    subject_id: subject_id.clone(),
                                })
                                .await
                            {
                                Ok(crate::auth::AuthResponse::Witnesses(
                                    witnesses,
                                )) => witnesses.contains(&sender),
                                Ok(response) => {
                                    error!(
                                        msg_type = "GetGovernanceVersion",
                                        subject_id = %subject_id,
                                        sender = %sender,
                                        response = ?response,
                                        "Unexpected response from auth actor"
                                    );
                                    return Err(ActorError::UnexpectedResponse {
                                        path: auth_path,
                                        expected: "AuthResponse::Witnesses"
                                            .to_owned(),
                                    });
                                }
                                Err(e) => {
                                    error!(
                                        msg_type = "GetGovernanceVersion",
                                        subject_id = %subject_id,
                                        sender = %sender,
                                        error = %e,
                                        "Failed to query auth actor"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            }
                        } else {
                            error!(
                                msg_type = "GetGovernanceVersion",
                                subject_id = %subject_id,
                                sender = %sender,
                                error = %e,
                                "Witness check failed"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                if !auth_ok {
                    warn!(
                        msg_type = "GetGovernanceVersion",
                        subject_id = %subject_id,
                        sender = %sender,
                        "Sender does not have access to governance version"
                    );
                    return Err(DistributorError::SenderNoAccess.into());
                }

                let governance_path = ActorPath::from(format!(
                    "/user/node/subject_manager/{}",
                    subject_id
                ));
                let governance_actor = ctx
                    .system()
                    .get_actor::<Governance>(&governance_path)
                    .await?;
                let response =
                    governance_actor.ask(GovernanceMessage::GetVersion).await?;
                let GovernanceResponse::Version(version) = response else {
                    return Err(ActorError::UnexpectedResponse {
                        path: governance_path,
                        expected: "GovernanceResponse::Version".to_owned(),
                    });
                };

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor,
                };

                if let Err(e) = self
                    .network
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::GovernanceVersionRes {
                                version,
                            },
                        },
                    })
                    .await
                {
                    error!(
                        msg_type = "GetGovernanceVersion",
                        subject_id = %subject_id,
                        sender = %sender,
                        error = %e,
                        "Failed to send governance version response to network"
                    );
                    return Err(emit_fail(ctx, e).await);
                }
            }
            DistriWorkerMessage::SendDistribution {
                actual_sn,
                info,
                subject_id,
                sender,
            } => {
                let (hi_sn, is_gov) = match self
                    .check_witness(ctx, &subject_id, sender.clone())
                    .await
                {
                    Ok(sn) => sn,
                    Err(e) => {
                        if let ActorError::Functional { .. } = e {
                            warn!(
                                msg_type = "SendDistribution",
                                subject_id = %subject_id,
                                sender = %sender,
                                error = %e,
                                "Witness check failed"
                            );
                            return Err(e);
                        } else {
                            error!(
                                msg_type = "SendDistribution",
                                subject_id = %subject_id,
                                sender = %sender,
                                error = %e,
                                "Witness check failed"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                if let Some(actual_sn) = actual_sn
                    && actual_sn >= hi_sn
                {
                    warn!(
                        msg_type = "SendDistribution",
                        subject_id = %subject_id,
                        actual_sn = actual_sn,
                        witness_sn = hi_sn,
                        "Requester SN is >= witness SN, nothing to send"
                    );
                    return Err(DistributorError::ActualSnBiggerThanWitness {
                        actual_sn,
                        witness_sn: hi_sn,
                    }
                    .into());
                };

                let (ledger, is_all) = match self
                    .get_ledger(ctx, &subject_id, hi_sn, actual_sn, is_gov)
                    .await
                {
                    Ok(res) => res,
                    Err(e) => {
                        error!(
                            msg_type = "SendDistribution",
                            subject_id = %subject_id,
                            hi_sn = hi_sn,
                            actual_sn = ?actual_sn,
                            is_gov = is_gov,
                            error = %e,
                            "Failed to obtain ledger"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/node/distributor_{}",
                        subject_id
                    ),
                };

                if let Err(e) = self
                    .network
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::DistributionLedgerRes {
                                ledger: ledger.clone(),
                                is_all,
                            },
                        },
                    })
                    .await
                {
                    error!(
                        msg_type = "SendDistribution",
                        subject_id = %subject_id,
                        ledger_count = ledger.len(),
                        is_all = is_all,
                        error = %e,
                        "Failed to send ledger response to network"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                debug!(
                    msg_type = "SendDistribution",
                    subject_id = %subject_id,
                    sender = %sender,
                    ledger_count = ledger.len(),
                    is_all = is_all,
                    hi_sn = hi_sn,
                    actual_sn = ?actual_sn,
                    "Ledger distribution sent successfully"
                );
            }
            DistriWorkerMessage::LastEventDistribution {
                ledger,
                info,
                sender,
            } => {
                let subject_id = ledger.get_subject_id();
                let sn = ledger.sn;

                let (is_gov, ..) = match self
                    .check_auth(ctx, sender.clone(), *ledger.clone())
                    .await
                {
                    Ok(is_gov) => is_gov,
                    Err(e) => {
                        if let ActorError::Functional { .. } = e {
                            warn!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                sender = %sender,
                                error = %e,
                                "Authorization check failed"
                            );
                            return Err(e);
                        } else {
                            error!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                sender = %sender,
                                error = %e,
                                "Authorization check failed"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                let lease = if ledger.is_create_event() {
                    if let Err(e) = create_subject(ctx, *ledger.clone()).await {
                        if let ActorError::Functional { .. } = e {
                            warn!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                error = %e,
                                "Failed to create subject from create event"
                            );
                            return Err(e);
                        } else {
                            error!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                error = %e,
                                "Failed to create subject from create event"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    };

                    None
                } else {
                    let requester = Self::requester_id(
                        "last_event_distribution",
                        &subject_id,
                        &info,
                        &sender,
                    );
                    let lease = if !is_gov {
                        match acquire_subject(
                            ctx,
                            &subject_id,
                            requester.clone(),
                            None,
                            true,
                        )
                        .await
                        {
                            Ok(lease) => Some(lease),
                            Err(e) => {
                                error!(
                                    msg_type = "LastEventDistribution",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to bring up tracker for subject update"
                                );
                                let error = DistributorError::UpTrackerFailed {
                                    details: e.to_string(),
                                };
                                return Err(emit_fail(ctx, error.into()).await);
                            }
                        }
                    } else {
                        None
                    };

                    let update_result =
                        update_ledger(ctx, &subject_id, vec![*ledger.clone()])
                            .await;

                    if let Some(lease) = lease.clone()
                        && update_result.is_err()
                    {
                        lease.finish(ctx).await?;
                    }

                    match update_result {
                        Ok((last_sn, _, _)) if last_sn < ledger.sn => {
                            debug!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                last_sn = last_sn,
                                received_sn = sn,
                                "SN gap detected, requesting full ledger"
                            );

                            let new_info = ComunicateInfo {
                                receiver: sender,
                                request_id: info.request_id,
                                version: info.version,
                                receiver_actor: format!(
                                    "/user/node/distributor_{}",
                                    subject_id
                                ),
                            };

                            if let Err(e) = self.network.send_command(network::CommandHelper::SendMessage {
                                    message: NetworkMessage {
                                        info: new_info,
                                        message: ActorMessage::DistributionLedgerReq {
                                            actual_sn: Some(last_sn),
                                            subject_id: subject_id.clone(),
                                        },
                                    },
                                }).await {
                                    error!(
                                        msg_type = "LastEventDistribution",
                                        subject_id = %subject_id,
                                        last_sn = last_sn,
                                        error = %e,
                                        "Failed to request ledger from network"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                            if let Some(lease) = lease.clone() {
                                lease.finish(ctx).await?;
                            }

                            return Ok(());
                        }
                        Ok((..)) => lease,
                        Err(e) => {
                            if let ActorError::Functional { .. } = e.clone() {
                                warn!(
                                    msg_type = "LastEventDistribution",
                                    subject_id = %subject_id,
                                    sn = sn,
                                    error = %e,
                                    "Failed to update subject ledger"
                                );
                                return Err(e);
                            } else {
                                error!(
                                    msg_type = "LastEventDistribution",
                                    subject_id = %subject_id,
                                    sn = sn,
                                    error = %e,
                                    "Failed to update subject ledger"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                    }
                };

                let new_info = ComunicateInfo {
                    receiver: sender.clone(),
                    receiver_actor: format!(
                        "/user/{}/{}",
                        info.request_id,
                        info.receiver.clone()
                    ),
                    request_id: info.request_id.clone(),
                    version: info.version,
                };

                if let Err(e) = self
                    .network
                    .send_command(network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info,
                            message: ActorMessage::DistributionLastEventRes,
                        },
                    })
                    .await
                {
                    error!(
                        msg_type = "LastEventDistribution",
                        subject_id = %subject_id,
                        sn = sn,
                        error = %e,
                        "Failed to send distribution acknowledgment"
                    );
                    return Err(emit_fail(ctx, e).await);
                };

                if let Some(lease) = lease {
                    lease.finish(ctx).await?;
                }

                debug!(
                    msg_type = "LastEventDistribution",
                    subject_id = %subject_id,
                    sn = sn,
                    sender = %sender,
                    is_gov = is_gov,
                    "Last event distribution processed successfully"
                );
            }
            DistriWorkerMessage::LedgerDistribution {
                mut ledger,
                is_all,
                info,
                sender,
            } => {
                if ledger.is_empty() {
                    warn!(
                        msg_type = "LedgerDistribution",
                        sender = %sender,
                        "Received empty ledger distribution"
                    );
                    return Err(DistributorError::EmptyEvents.into());
                }

                let subject_id = ledger[0].get_subject_id();
                let ledger_count = ledger.len();
                let first_sn = ledger[0].sn;

                let (is_gov, is_register) = match self
                    .check_auth(ctx, sender.clone(), ledger[0].clone())
                    .await
                {
                    Ok(data) => data,
                    Err(e) => {
                        if let ActorError::Functional { .. } = e {
                            warn!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                sender = %sender,
                                ledger_count = ledger_count,
                                error = %e,
                                "Authorization check failed"
                            );
                            return Err(e);
                        } else {
                            error!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                sender = %sender,
                                ledger_count = ledger_count,
                                error = %e,
                                "Authorization check failed"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                let lease = if ledger[0].is_create_event() && !is_register {
                    let create_ledger = ledger[0].clone();
                    let requester = Self::requester_id(
                        "ledger_distribution_create",
                        &subject_id,
                        &info,
                        &sender,
                    );

                    let lease = if is_gov {
                        if let Err(e) =
                            create_subject(ctx, create_ledger.clone()).await
                        {
                            if let ActorError::Functional { .. } = e {
                                warn!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to create subject from ledger"
                                );
                                return Err(e);
                            } else {
                                error!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to create subject from ledger"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        };
                        None
                    } else {
                        let request = create_ledger
                            .get_create_event()
                            .ok_or_else(|| {
                                error!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    "Create ledger is missing create event payload"
                                );
                                DistributorError::MissingCreateEventInCreateLedger {
                                    subject_id: subject_id.clone(),
                                }
                            })?;

                        if let Err(e) = check_subject_creation(
                            ctx,
                            &request.governance_id,
                            create_ledger.ledger_seal_signature.signer.clone(),
                            create_ledger.gov_version,
                            request.namespace.to_string(),
                            request.schema_id,
                        )
                        .await
                        {
                            if let ActorError::Functional { .. } = e {
                                warn!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to validate subject creation from ledger"
                                );
                                return Err(e);
                            } else {
                                error!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to validate subject creation from ledger"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }

                        match acquire_subject(
                            ctx,
                            &subject_id,
                            requester,
                            Some(create_ledger),
                            true,
                        )
                        .await
                        {
                            Ok(lease) => Some(lease),
                            Err(e) => {
                                if let ActorError::Functional { .. } = e {
                                    warn!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %e,
                                        "Failed to create subject from ledger"
                                    );
                                    return Err(e);
                                } else {
                                    error!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %e,
                                        "Failed to create subject from ledger"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            }
                        }
                    };

                    let _event = ledger.remove(0);
                    lease
                } else {
                    if ledger[0].is_create_event() && is_register {
                        let _event = ledger.remove(0);
                    }

                    let requester = Self::requester_id(
                        "ledger_distribution",
                        &subject_id,
                        &info,
                        &sender,
                    );
                    if !ledger.is_empty() && !is_gov {
                        match acquire_subject(
                            ctx,
                            &subject_id,
                            requester.clone(),
                            None,
                            true,
                        )
                        .await
                        {
                            Ok(lease) => Some(lease),
                            Err(e) => {
                                error!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    error = %e,
                                    "Failed to bring up tracker for subject update"
                                );
                                let error = DistributorError::UpTrackerFailed {
                                    details: e.to_string(),
                                };
                                return Err(emit_fail(ctx, error.into()).await);
                            }
                        }
                    } else {
                        None
                    }
                };

                let lease = if !ledger.is_empty() {
                    let update_result =
                        update_ledger(ctx, &subject_id, ledger).await;

                    if let Some(lease) = lease.clone()
                        && update_result.is_err()
                    {
                        lease.finish(ctx).await?;
                    }

                    match update_result {
                        Ok((last_sn, _, _)) => {
                            if !is_all {
                                debug!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    last_sn = last_sn,
                                    "Partial ledger received, requesting more"
                                );

                                let new_info = ComunicateInfo {
                                    receiver: sender.clone(),
                                    request_id: info.request_id.clone(),
                                    version: info.version,
                                    receiver_actor: format!(
                                        "/user/node/distributor_{}",
                                        subject_id
                                    ),
                                };

                                if let Err(e) = self
                                    .network
                                    .send_command(network::CommandHelper::SendMessage {
                                        message: NetworkMessage {
                                            info: new_info,
                                            message: ActorMessage::DistributionLedgerReq {
                                                actual_sn: Some(last_sn),
                                                subject_id: subject_id.clone(),
                                            },
                                        },
                                    })
                                    .await
                                {
                                    error!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        last_sn = last_sn,
                                        error = %e,
                                        "Failed to request more ledger entries"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };
                            }

                            lease
                        }
                        Err(e) => {
                            if let ActorError::Functional { .. } = e.clone() {
                                warn!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    first_sn = first_sn,
                                    ledger_count = ledger_count,
                                    error = %e,
                                    "Failed to update subject ledger"
                                );
                                return Err(e);
                            } else {
                                error!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    first_sn = first_sn,
                                    ledger_count = ledger_count,
                                    error = %e,
                                    "Failed to update subject ledger"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }
                        }
                    }
                } else {
                    lease
                };

                if let Some(lease) = lease {
                    lease.finish(ctx).await?;
                }

                debug!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    sender = %sender,
                    ledger_count = ledger_count,
                    is_all = is_all,
                    is_gov = is_gov,
                    "Ledger distribution processed successfully"
                );
            }
        };

        Ok(())
    }
}
