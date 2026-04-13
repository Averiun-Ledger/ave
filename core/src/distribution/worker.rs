use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    Namespace, SchemaType,
    bridge::request::EventRequestType,
    identity::{DigestIdentifier, PublicKey},
};
use network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage, Node, NodeMessage, NodeResponse,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        model::{HashThisRole, RoleTypes},
        witnesses_register::{
            TrackerDeliveryMode, TrackerDeliveryRange, WitnessesRegister,
            WitnessesRegisterMessage, WitnessesRegisterResponse,
        },
    },
    helpers::network::service::NetworkSender,
    model::{
        common::{
            check_subject_creation, check_witness_access, emit_fail,
            node::{get_subject_data, try_to_update},
            subject::{
                acquire_subject, create_subject, get_gov, get_gov_sn,
                get_tracker_window as resolve_tracker_window, update_ledger,
            },
        },
        event::Ledger,
    },
    node::SubjectData,
    tracker::{Tracker, TrackerMessage, TrackerResponse},
    update::{UpdateSubjectKind, UpdateWitnessOffer},
};

use tracing::{Span, debug, error, info_span, warn};

use super::error::DistributorError;

pub struct DistriWorker {
    pub our_key: Arc<PublicKey>,
    pub network: Arc<NetworkSender>,
    pub ledger_batch_size: u64,
}

impl DistriWorker {
    fn is_owner_boundary_event(ledger: &Ledger) -> bool {
        matches!(
            ledger.get_event_request_type(),
            EventRequestType::Transfer
                | EventRequestType::Confirm
                | EventRequestType::Reject
        )
    }

    fn safe_unknown_prefix_len(ledger: &[Ledger], auth: bool) -> usize {
        if auth {
            return ledger.len();
        }

        ledger
            .iter()
            .enumerate()
            .skip(1)
            .find_map(|(idx, entry)| {
                Self::is_owner_boundary_event(entry).then_some(idx)
            })
            .unwrap_or(ledger.len())
    }

    async fn tracker_access_limit(
        &self,
        ctx: &mut ActorContext<Self>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        node: PublicKey,
        namespace: String,
        schema_id: SchemaType,
    ) -> Result<Option<u64>, ActorError> {
        check_witness_access(
            ctx,
            governance_id,
            subject_id,
            node,
            namespace,
            schema_id,
        )
        .await
    }

    async fn create_participant_allowed(
        &self,
        ctx: &ActorContext<Self>,
        governance_id: &DigestIdentifier,
        owner: &PublicKey,
        node: &PublicKey,
        namespace: &Namespace,
        schema_id: &SchemaType,
        gov_version: u64,
    ) -> Result<bool, ActorError> {
        let actor_path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/witnesses_register",
            governance_id
        ));
        let actor: ActorRef<WitnessesRegister> =
            ctx.system().get_actor(&actor_path).await?;
        let response = actor
            .ask(WitnessesRegisterMessage::CreateAccess {
                owner: owner.clone(),
                node: node.clone(),
                namespace: namespace.to_string(),
                schema_id: schema_id.clone(),
                gov_version,
            })
            .await?;

        match response {
            WitnessesRegisterResponse::CreateAccess { allowed } => {
                Ok(allowed)
            }
            _ => Err(ActorError::UnexpectedResponse {
                path: actor_path,
                expected: "WitnessesRegisterResponse::CreateAccess".to_owned(),
            }),
        }
    }

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

    fn build_response_info(
        &self,
        sender: PublicKey,
        info: &ComunicateInfo,
        receiver_actor: String,
    ) -> ComunicateInfo {
        ComunicateInfo {
            receiver: sender,
            request_id: info.request_id.clone(),
            version: info.version,
            receiver_actor,
        }
    }

    async fn send_network_message(
        &self,
        info: ComunicateInfo,
        message: ActorMessage,
    ) -> Result<(), ActorError> {
        self.network
            .send_command(network::CommandHelper::SendMessage {
                message: NetworkMessage { info, message },
            })
            .await
    }

    async fn get_governance_version(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<u64, ActorError> {
        let data = get_subject_data(ctx, subject_id).await?;
        let Some(SubjectData::Governance { .. }) = data else {
            return Err(DistributorError::SubjectNotFound.into());
        };

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

        Ok(version)
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
        sender: PublicKey,
        ledger: &[Ledger],
    ) -> Result<(bool, bool, usize), ActorError> {
        let first_ledger = ledger
            .first()
            .ok_or(DistributorError::EmptyEvents)
            .map_err(ActorError::from)?;
        let subject_id = first_ledger.get_subject_id();
        let (auth, subject_data) =
            self.authorized_subj(ctx, &subject_id).await?;

        if first_ledger.is_create_event() {
            let create =
                first_ledger
                    .get_create_event()
                    .ok_or_else(|| {
                        DistributorError::MissingCreateEventInCreateLedger {
                            subject_id: subject_id.clone(),
                        }
                    })?;
            let create_owner = first_ledger.ledger_seal_signature.signer.clone();

            if create.schema_id.is_gov() {
                if !auth {
                    return Err(
                        DistributorError::GovernanceNotAuthorized.into()
                    );
                }

                return Ok((
                    true,
                    subject_data.is_some(),
                    Self::safe_unknown_prefix_len(ledger, auth),
                ));
            }

            if create.governance_id.is_empty() {
                return Err(DistributorError::MissingGovernanceIdInCreate {
                    subject_id: subject_id.clone(),
                }
                .into());
            }

            if !auth {
                let sender_allowed = self
                    .create_participant_allowed(
                        ctx,
                        &create.governance_id,
                        &create_owner,
                        &sender,
                        &create.namespace,
                        &create.schema_id,
                        first_ledger.gov_version,
                    )
                    .await?;
                if !sender_allowed {
                    return Err(DistributorError::SenderNoAccess.into());
                }

                let receiver_allowed = self
                    .create_participant_allowed(
                        ctx,
                        &create.governance_id,
                        &create_owner,
                        self.our_key.as_ref(),
                        &create.namespace,
                        &create.schema_id,
                        first_ledger.gov_version,
                    )
                    .await?;
                if !receiver_allowed {
                    return Err(DistributorError::NotWitness.into());
                }
            }

            return Ok((
                false,
                subject_data.is_some(),
                Self::safe_unknown_prefix_len(ledger, auth),
            ));
        }

        let Some(data) = subject_data else {
            try_to_update(ctx, subject_id, Some(sender)).await?;
            return Err(DistributorError::UpdatingSubject.into());
        };

        match data {
            SubjectData::Governance { .. } => {
                if !auth {
                    return Err(
                        DistributorError::GovernanceNotAuthorized.into()
                    );
                }

                Ok((true, true, ledger.len()))
            }
            SubjectData::Tracker {
                governance_id,
                schema_id,
                namespace,
                ..
            } => {
                if auth {
                    return Ok((false, true, ledger.len()));
                }

                let target_sn = ledger
                    .last()
                    .map(|entry| entry.sn)
                    .unwrap_or(first_ledger.sn);

                let sender_limit = self
                    .tracker_access_limit(
                        ctx,
                        &governance_id,
                        &subject_id,
                        sender,
                        namespace.clone(),
                        schema_id.clone(),
                    )
                    .await?;
                let receiver_limit = self
                    .tracker_access_limit(
                        ctx,
                        &governance_id,
                        &subject_id,
                        (*self.our_key).clone(),
                        namespace,
                        schema_id,
                    )
                    .await?;

                if sender_limit.is_none_or(|sn| sn < target_sn) {
                    return Err(DistributorError::SenderNoAccess.into());
                }

                if receiver_limit.is_none_or(|sn| sn < target_sn) {
                    return Err(DistributorError::NotWitness.into());
                }

                Ok((false, true, ledger.len()))
            }
        }
    }

    async fn get_tracker_window(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        actual_sn: Option<u64>,
    ) -> Result<(u64, Option<u64>, bool, Vec<TrackerDeliveryRange>), ActorError>
    {
        let data = get_subject_data(ctx, subject_id).await?;

        let Some(SubjectData::Tracker {
            governance_id,
            schema_id,
            namespace,
            ..
        }) = data
        else {
            return Err(DistributorError::SubjectNotFound.into());
        };

        let (sn, clear_sn, is_all, ranges) = resolve_tracker_window(
            ctx,
            &governance_id,
            subject_id,
            sender,
            namespace,
            schema_id,
            actual_sn,
        )
        .await?;

        let Some(sn) = sn else {
            return Err(DistributorError::SenderNoAccess.into());
        };

        Ok((sn, clear_sn, is_all, ranges))
    }

    fn tracker_delivery_mode(
        ranges: &[TrackerDeliveryRange],
        sn: u64,
    ) -> Option<TrackerDeliveryMode> {
        ranges
            .iter()
            .find(|range| range.from_sn <= sn && sn <= range.to_sn)
            .map(|range| range.mode.clone())
    }

    fn project_tracker_ledger(
        ledger: Vec<Ledger>,
        ranges: &[TrackerDeliveryRange],
    ) -> Result<Vec<Ledger>, ActorError> {
        let mut projected = Vec::with_capacity(ledger.len());

        for event in ledger {
            let Some(mode) = Self::tracker_delivery_mode(ranges, event.sn)
            else {
                return Err(ActorError::FunctionalCritical {
                    description: format!(
                        "Missing tracker delivery range for sn {}",
                        event.sn
                    ),
                });
            };

            match mode {
                TrackerDeliveryMode::Clear => projected.push(event),
                TrackerDeliveryMode::Opaque => projected
                    .push(event.to_tracker_opaque().map_err(ActorError::from)?),
            }
        }

        Ok(projected)
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
                    sender.clone(),
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

    async fn build_last_sn_offer(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        actual_sn: Option<u64>,
    ) -> Result<UpdateWitnessOffer, ActorError> {
        let data = get_subject_data(ctx, subject_id).await?;
        let Some(data) = data else {
            return Err(DistributorError::SubjectNotFound.into());
        };

        match data {
            SubjectData::Tracker { .. } => {
                let (sn, clear_sn, _, ranges) = self
                    .get_tracker_window(ctx, subject_id, sender, actual_sn)
                    .await?;
                Ok(UpdateWitnessOffer {
                    kind: UpdateSubjectKind::Tracker,
                    sn,
                    clear_sn,
                    ranges,
                })
            }
            SubjectData::Governance { .. } => {
                let (sn, ..) =
                    self.check_witness(ctx, subject_id, sender).await?;
                Ok(UpdateWitnessOffer {
                    kind: UpdateSubjectKind::Governance,
                    sn,
                    clear_sn: None,
                    ranges: Vec::new(),
                })
            }
        }
    }

    async fn build_distribution_batch(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        actual_sn: Option<u64>,
        target_sn: Option<u64>,
    ) -> Result<(Vec<Ledger>, bool, u64), ActorError> {
        let data = get_subject_data(ctx, subject_id).await?;
        let Some(data) = data else {
            return Err(DistributorError::SubjectNotFound.into());
        };

        match data {
            SubjectData::Tracker { .. } => {
                let (window_sn, clear_sn, window_is_all, ranges) = self
                    .get_tracker_window(ctx, subject_id, sender, actual_sn)
                    .await?;

                if let Some(actual_sn) = actual_sn
                    && actual_sn >= window_sn
                {
                    return Err(DistributorError::ActualSnBiggerThanWitness {
                        actual_sn,
                        witness_sn: window_sn,
                    }
                    .into());
                }

                let hi_sn = clear_sn
                    .filter(|clear_sn| {
                        actual_sn.is_none_or(|actual_sn| *clear_sn > actual_sn)
                    })
                    .unwrap_or(window_sn);
                let hi_sn = target_sn.unwrap_or(hi_sn).min(window_sn);

                let (ledger, raw_is_all) = self
                    .get_ledger(ctx, subject_id, hi_sn, actual_sn, false)
                    .await?;

                let ledger = Self::project_tracker_ledger(ledger, &ranges)?;
                let is_all = raw_is_all && window_is_all && hi_sn == window_sn;
                Ok((ledger, is_all, hi_sn))
            }
            SubjectData::Governance { .. } => {
                let (witness_hi_sn, ..) =
                    self.check_witness(ctx, subject_id, sender).await?;

                if let Some(actual_sn) = actual_sn
                    && actual_sn >= witness_hi_sn
                {
                    return Err(DistributorError::ActualSnBiggerThanWitness {
                        actual_sn,
                        witness_sn: witness_hi_sn,
                    }
                    .into());
                }

                let from_sn = actual_sn.map_or(0, |sn| sn.saturating_add(1));
                let batch_hi_sn = from_sn
                    .saturating_add(self.ledger_batch_size)
                    .saturating_sub(1)
                    .min(witness_hi_sn);
                let batch_hi_sn =
                    target_sn.unwrap_or(batch_hi_sn).min(batch_hi_sn);

                let (ledger, raw_is_all) = self
                    .get_ledger(ctx, subject_id, batch_hi_sn, actual_sn, true)
                    .await?;

                let is_all = raw_is_all && batch_hi_sn == witness_hi_sn;
                Ok((ledger, is_all, batch_hi_sn))
            }
        }
    }

    async fn request_ledger_from_sender(
        &self,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        info: &ComunicateInfo,
        actual_sn: u64,
    ) -> Result<(), ActorError> {
        let new_info = self.build_response_info(
            sender,
            info,
            format!("/user/node/distributor_{}", subject_id),
        );

        self.send_network_message(
            new_info,
            ActorMessage::DistributionLedgerReq {
                actual_sn: Some(actual_sn),
                target_sn: None,
                subject_id: subject_id.clone(),
            },
        )
        .await
    }

    async fn handle_get_last_sn(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
        actual_sn: Option<u64>,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    ) -> Result<(), ActorError> {
        let offer = self
            .build_last_sn_offer(ctx, &subject_id, sender.clone(), actual_sn)
            .await?;
        let new_info =
            self.build_response_info(sender.clone(), &info, receiver_actor);

        self.send_network_message(
            new_info,
            ActorMessage::UpdateOffer {
                offer: offer.clone(),
            },
        )
        .await?;

        debug!(
            msg_type = "GetLastSn",
            subject_id = %subject_id,
            sn = offer.sn,
            clear_sn = ?offer.clear_sn,
            sender = %sender,
            "Last SN response sent successfully"
        );

        Ok(())
    }

    async fn handle_get_governance_version(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    ) -> Result<(), ActorError> {
        let version = self.get_governance_version(ctx, &subject_id).await?;
        let new_info =
            self.build_response_info(sender.clone(), &info, receiver_actor);

        self.send_network_message(
            new_info,
            ActorMessage::GovernanceVersionRes { version },
        )
        .await?;

        Ok(())
    }

    async fn handle_send_distribution(
        &self,
        ctx: &mut ActorContext<Self>,
        actual_sn: Option<u64>,
        target_sn: Option<u64>,
        info: ComunicateInfo,
        subject_id: DigestIdentifier,
        sender: PublicKey,
    ) -> Result<(), ActorError> {
        let (ledger, is_all, hi_sn) = self
            .build_distribution_batch(
                ctx,
                &subject_id,
                sender.clone(),
                actual_sn,
                target_sn,
            )
            .await?;

        let new_info = self.build_response_info(
            sender.clone(),
            &info,
            format!("/user/node/distributor_{}", subject_id),
        );

        self.send_network_message(
            new_info,
            ActorMessage::DistributionLedgerRes {
                ledger: ledger.clone(),
                is_all,
            },
        )
        .await?;

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

        Ok(())
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
        actual_sn: Option<u64>,
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
        target_sn: Option<u64>,
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
                actual_sn,
                info,
                sender,
                receiver_actor,
            } => match self
                .handle_get_last_sn(
                    ctx,
                    subject_id.clone(),
                    actual_sn,
                    info,
                    sender.clone(),
                    receiver_actor,
                )
                .await
            {
                Ok(()) => {}
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
            },
            DistriWorkerMessage::GetGovernanceVersion {
                subject_id,
                info,
                sender,
                receiver_actor,
            } => match self
                .handle_get_governance_version(
                    ctx,
                    subject_id.clone(),
                    info,
                    sender.clone(),
                    receiver_actor,
                )
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    if let ActorError::Functional { .. } = e {
                        warn!(
                            msg_type = "GetGovernanceVersion",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Subject is not a governance"
                        );
                        return Err(e);
                    } else {
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
            },
            DistriWorkerMessage::SendDistribution {
                actual_sn,
                target_sn,
                info,
                subject_id,
                sender,
            } => match self
                .handle_send_distribution(
                    ctx,
                    actual_sn,
                    target_sn,
                    info,
                    subject_id.clone(),
                    sender.clone(),
                )
                .await
            {
                Ok(()) => {}
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
                            "Failed to send ledger response to network"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                }
            },
            DistriWorkerMessage::LastEventDistribution {
                ledger,
                info,
                sender,
            } => {
                let subject_id = ledger.get_subject_id();
                let sn = ledger.sn;

                let single_ledger = [(*ledger).clone()];
                let (is_gov, ..) = match self
                    .check_auth(ctx, sender.clone(), &single_ledger)
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
                                "SN gap detected, requesting update"
                            );

                            if let Err(e) = self
                                .request_ledger_from_sender(
                                    &subject_id,
                                    sender.clone(),
                                    &info,
                                    last_sn,
                                )
                                .await
                            {
                                error!(
                                    msg_type = "LastEventDistribution",
                                    subject_id = %subject_id,
                                    last_sn = last_sn,
                                    error = %e,
                                    "Failed to request ledger from network"
                                );
                                return Err(emit_fail(ctx, e).await);
                            }

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

                let new_info = self.build_response_info(
                    sender.clone(),
                    &info,
                    format!(
                        "/user/{}/{}",
                        info.request_id,
                        info.receiver.clone()
                    ),
                );

                if let Err(e) = self
                    .send_network_message(
                        new_info,
                        ActorMessage::DistributionLastEventRes,
                    )
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
                let (is_gov, is_register, safe_prefix_len) = match self
                    .check_auth(ctx, sender.clone(), &ledger)
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

                let original_len = ledger.len();
                let mut is_all = is_all;
                if safe_prefix_len < ledger.len() {
                    ledger.truncate(safe_prefix_len);
                    is_all = false;
                }

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

                                if let Err(e) = self
                                    .request_ledger_from_sender(
                                        &subject_id,
                                        sender.clone(),
                                        &info,
                                        last_sn,
                                    )
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
                    ledger_count = original_len,
                    is_all = is_all,
                    is_gov = is_gov,
                    "Ledger distribution processed successfully"
                );
            }
        };

        Ok(())
    }
}
