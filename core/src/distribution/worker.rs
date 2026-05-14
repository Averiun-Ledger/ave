use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    SchemaType,
    bridge::request::EventRequestType,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey},
};
use ave_network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage, Node, NodeMessage, NodeResponse,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        model::{HashThisRole, RoleTypes},
        witnesses_register::{
            GovVersionLimit, HiSnLimit, TrackerDeliveryMode,
            TrackerDeliveryRange,
            TransferData, WitnessesRegister,
        },
    },
    helpers::network::service::NetworkSender,
    model::{
        common::{
            check_witness_status,
            emit_fail,
            get_verified_transfer_sn, node::get_subject_data,
            subject::{
                acquire_subject, get_gov, get_gov_sn,
                get_local_subject_sn,
                get_tracker_window as resolve_tracker_window,
                check_simulated_transfer_hi_sn_limit,
                check_witness_status_and_window,
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

pub(crate) struct DistributionAuth {
    pub(crate) is_gov: bool,
    pub(crate) is_register: bool,
    pub(crate) safe_hi_sn: u64,
}

pub struct DistriWorker {
    pub our_key: Arc<PublicKey>,
    pub network: Arc<NetworkSender>,
    pub ledger_batch_size: u64,
    pub hash: HashAlgorithm,
    pub(crate) transfer_verifier: super::transfer_verifier::TransferVerifier,
}

use super::transfer_verifier::TransferSimulationResult;

pub(crate) struct CheckAuthCommon {
    pub(crate) subject_id: DigestIdentifier,
    pub(crate) subject_data: Option<SubjectData>,
    pub(crate) schema_id: SchemaType,
    pub(crate) governance_id: DigestIdentifier,
    pub(crate) namespace: String,
    pub(crate) is_gov: bool,
}

impl DistriWorker {
    fn concrete_hi_sn_limit(
        limit: HiSnLimit,
        offered_hi_sn: u64,
    ) -> Option<u64> {
        match limit {
            HiSnLimit::None => None,
            HiSnLimit::Infinity => Some(offered_hi_sn),
            HiSnLimit::Sn(limit) => Some(limit.min(offered_hi_sn)),
        }
    }

    fn concrete_gov_version_limit(
        ledger: &[Ledger],
        limit: GovVersionLimit,
        offered_hi_sn: u64,
    ) -> Option<u64> {
        match limit {
            GovVersionLimit::None => None,
            GovVersionLimit::Infinity => Some(offered_hi_sn),
            GovVersionLimit::Version(limit) => ledger
                .iter()
                .take_while(|event| event.gov_version <= limit)
                .last()
                .map(|event| event.sn.min(offered_hi_sn)),
        }
    }

    pub(crate) async fn send_last_event_ack(
        &self,
        sender: PublicKey,
        info: &ComunicateInfo,
    ) -> Result<(), ActorError> {
        let new_info = self.build_response_info(
            sender,
            info,
            format!("/user/{}/{}", info.request_id, info.receiver.clone()),
        );

        self.send_network_message(
            new_info,
            ActorMessage::DistributionLastEventRes,
        )
        .await
    }

    pub(crate) fn requester_id(
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
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage { info, message },
            })
            .await
    }

    async fn send_no_offer_response(
        &self,
        info: &ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    ) -> Result<(), ActorError> {
        let new_info = self.build_response_info(sender, info, receiver_actor);
        self.send_network_message(new_info, ActorMessage::UpdateNoOffer)
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

    async fn check_auth_common(
        &self,
        ctx: &mut ActorContext<Self>,
        sender: PublicKey,
        info: &ComunicateInfo,
        ledger: &[Ledger],
    ) -> Result<CheckAuthCommon, ActorError> {
        let first_ledger =
            ledger.first().ok_or(DistributorError::EmptyEvents)?;
        let subject_id = first_ledger.get_subject_id();
        let (auth, subject_data) =
            self.authorized_subj(ctx, &subject_id).await?;

        let (schema_id, governance_id, namespace) = if let Some(ref data) =
            subject_data
        {
            match data {
                SubjectData::Tracker {
                    governance_id,
                    schema_id,
                    namespace,
                    ..
                } => (
                    schema_id.clone(),
                    Some(governance_id.clone()),
                    namespace.clone(),
                ),
                SubjectData::Governance { .. } => {
                    (SchemaType::Governance, None, String::default())
                }
            }
        } else {
            if let Some(create) = first_ledger.get_create_event() {
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

                (create.schema_id, gov_id, create.namespace.to_string())
            } else {
                self.request_ledger_from_sender(
                    ctx,
                    &subject_id,
                    sender.clone(),
                    info,
                    None,
                )
                .await?;
                return Err(DistributorError::UpdatingSubject.into());
            }
        };

        let is_gov = schema_id.is_gov();
        if is_gov {
            if !auth {
                return Err(DistributorError::GovernanceNotAuthorized.into());
            }
            return Ok(CheckAuthCommon {
                subject_id,
                subject_data,
                schema_id,
                governance_id: DigestIdentifier::default(),
                namespace,
                is_gov: true,
            });
        }

        let Some(governance_id) = governance_id else {
            error!(
                msg_type = "CheckAuthCommon",
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

        if gov.version < first_ledger.gov_version {
            return Err(DistributorError::GovernanceVersionMismatch {
                our_version: gov.version,
                their_version: first_ledger.gov_version,
            }
            .into());
        }

        Ok(CheckAuthCommon {
            subject_id,
            subject_data,
            schema_id,
            governance_id,
            namespace,
            is_gov: false,
        })
    }

    pub(crate) async fn check_auth_batch(
        &self,
        ctx: &mut ActorContext<Self>,
        sender: PublicKey,
        ledger: &[Ledger],
        offered_hi_sn: u64,
        common: &CheckAuthCommon,
        transfer_event: Option<&Ledger>,
        transfer_simulation: Option<&TransferSimulationResult>,
        verified_transfer_sn: Option<u64>,
    ) -> Result<DistributionAuth, ActorError> {
        if common.is_gov {
            return Ok(DistributionAuth {
                is_gov: true,
                is_register: common.subject_data.is_some(),
                safe_hi_sn: offered_hi_sn,
            });
        }

        let CheckAuthCommon { subject_id, schema_id, governance_id, namespace, .. } = common;

        // subject_data puede haber cambiado entre iteraciones del loop de
        // LedgerDistribution (ej. subject creado en chunk anterior). Si
        // check_auth_common no lo encontró, refrescamos desde Node.
        let is_register = if common.subject_data.is_none() {
            get_subject_data(ctx, &subject_id).await?.is_some()
        } else {
            true
        };

        // 1. Batch actual trae un transfer_event nuevo y la simulación dice Witness
        if let (Some(transfer_event), Some(TransferSimulationResult::Witness)) = (transfer_event, transfer_simulation) {
            let chunk_first_sn = ledger.first().ok_or(DistributorError::EmptyEvents)?.sn;
            if chunk_first_sn <= transfer_event.sn {
                return Ok(DistributionAuth {
                    is_gov: false,
                    is_register,
                    safe_hi_sn: transfer_event.sn.min(offered_hi_sn),
                });
            }
        }

        // 2. Tenemos un transfer verificado anteriormente y el chunk está dentro
        //    de su rango de free passage. Vía libre hasta verified_transfer_sn.
        let chunk_first_sn = ledger.first().ok_or(DistributorError::EmptyEvents)?.sn;
        if let Some(verified_sn) = verified_transfer_sn {
            if chunk_first_sn <= verified_sn {
                return Ok(DistributionAuth {
                    is_gov: false,
                    is_register,
                    safe_hi_sn: offered_hi_sn.min(verified_sn),
                });
            }
        }

        // 3. Witness limits normales
        let safe_hi_sn = if is_register {
            let receiver_status = check_witness_status(
                ctx,
                governance_id,
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
                Some(subject_id.clone()),
                None,
                None,
            )
            .await?;

            let receiver_limit = Self::concrete_gov_version_limit(
                ledger,
                receiver_status.gov_version_limit,
                offered_hi_sn,
            );


            let Some(receiver_limit) = receiver_limit else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };

            receiver_limit.min(offered_hi_sn)
        } else {
            let first_ledger = ledger.first().ok_or(DistributorError::EmptyEvents)?;
            let owner = first_ledger.ledger_seal_signature.signer.clone();
            let gov_version = first_ledger.gov_version;
            let transfer_data =
                Some(WitnessesRegister::transfer_data_from_ledger(&subject_id, ledger)?);

            let (witness_status, receiver_window_sn, ..) = check_witness_status_and_window(
                ctx,
                &governance_id,
                &subject_id,
                transfer_data,
                (*self.our_key).clone(),
                sender.clone(),
                namespace.clone(),
                schema_id.clone(),
                None,
                Some(owner),
                Some(gov_version),
            )
            .await?;

            let receiver_hi_limit = Self::concrete_hi_sn_limit(
                witness_status.hi_sn_limit,
                offered_hi_sn,
            );

            let receiver_create_gov_limit = Self::concrete_gov_version_limit(
                ledger,
                witness_status.create_gov_version_limit,
                offered_hi_sn,
            );

            let raw_receiver_limit = [
                receiver_hi_limit,
                receiver_create_gov_limit,
                receiver_window_sn,
            ]
            .into_iter()
            .flatten()
            .max();

            let Some(receiver_limit) = raw_receiver_limit else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };

            receiver_limit.min(offered_hi_sn)
        };

        // Seguridad: capar en Confirm/Reject para evitar distribución más allá de
        // cambios de ownership.
        let safe_hi_sn = if let Some(boundary) = ledger.iter().find_map(|event| {
            matches!(
                event.get_event_request_type(),
                EventRequestType::Confirm | EventRequestType::Reject
            )
            .then_some(event.sn)
        }) {
            safe_hi_sn.min(boundary)
        } else {
            safe_hi_sn
        };

        Ok(DistributionAuth {
            is_gov: false,
            is_register,
            safe_hi_sn,
        })
    }

    pub(crate) async fn check_auth_single(
        &self,
        ctx: &mut ActorContext<Self>,
        sender: PublicKey,
        info: &ComunicateInfo,
        ledger: &[Ledger],
        offered_hi_sn: u64,
    ) -> Result<DistributionAuth, ActorError> {
        let common = self.check_auth_common(ctx, sender.clone(), info, ledger).await?;
        if common.is_gov {
            return Ok(DistributionAuth {
                is_gov: true,
                is_register: common.subject_data.is_some(),
                safe_hi_sn: offered_hi_sn,
            });
        }

        let CheckAuthCommon { subject_id, subject_data, schema_id, governance_id, namespace, .. } = common;
        let first_ledger = ledger.first().ok_or(DistributorError::EmptyEvents)?;

        if subject_data.is_none() && !first_ledger.is_create_event() {
            self.request_ledger_from_sender(
                ctx,
                &subject_id,
                sender.clone(),
                info,
                None,
            )
            .await?;
            return Err(DistributorError::UpdatingSubject.into());
        }

        if matches!(first_ledger.get_event_request_type(), EventRequestType::Transfer) {
            let simulated_limit = check_simulated_transfer_hi_sn_limit(
                ctx,
                &governance_id,
                &subject_id,
                first_ledger.clone(),
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
            )
            .await?;

            if matches!(simulated_limit, HiSnLimit::None) {
                return Err(DistributorError::ReceiverNoAccess.into());
            }

            return Ok(DistributionAuth {
                is_gov: false,
                is_register: subject_data.is_some(),
                safe_hi_sn: offered_hi_sn,
            });
        }

        let safe_hi_sn = if subject_data.is_some() {
            let receiver_status = check_witness_status(
                ctx,
                &governance_id,
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
                Some(subject_id.clone()),
                None,
                None,
            )
            .await?;

            let receiver_limit = Self::concrete_gov_version_limit(
                ledger,
                receiver_status.gov_version_limit,
                offered_hi_sn,
            );

            let Some(receiver_limit) = receiver_limit else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };

            let mut safe_hi_sn = receiver_limit.min(offered_hi_sn);

            if let Some(boundary) = ledger.iter().find_map(|event| {
                matches!(
                    event.get_event_request_type(),
                    EventRequestType::Confirm | EventRequestType::Reject
                )
                .then_some(event.sn)
            }) {
                safe_hi_sn = safe_hi_sn.min(boundary);
            }

            safe_hi_sn
        } else {
            let owner = first_ledger.ledger_seal_signature.signer.clone();
            let gov_version = first_ledger.gov_version;
            let transfer_data =
                Some(WitnessesRegister::transfer_data_from_ledger(&subject_id, ledger)?);

            let (witness_status, receiver_window_sn, ..) = check_witness_status_and_window(
                ctx,
                &governance_id,
                &subject_id,
                transfer_data,
                (*self.our_key).clone(),
                sender.clone(),
                namespace.clone(),
                schema_id.clone(),
                None,
                Some(owner),
                Some(gov_version),
            )
            .await?;

            let receiver_hi_limit = Self::concrete_hi_sn_limit(
                witness_status.hi_sn_limit,
                offered_hi_sn,
            );

            let receiver_create_gov_limit = Self::concrete_gov_version_limit(
                ledger,
                witness_status.create_gov_version_limit,
                offered_hi_sn,
            );

            let raw_receiver_limit = [
                receiver_hi_limit,
                receiver_create_gov_limit,
                receiver_window_sn,
            ]
            .into_iter()
            .flatten()
            .max();

            let Some(receiver_limit) = raw_receiver_limit else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };

            receiver_limit.min(offered_hi_sn)
        };

        // Seguridad: capar en Confirm/Reject para coherencia con check_auth_batch.
        let safe_hi_sn = if let Some(boundary) = ledger.iter().find_map(|event| {
            matches!(
                event.get_event_request_type(),
                EventRequestType::Confirm | EventRequestType::Reject
            )
            .then_some(event.sn)
        }) {
            safe_hi_sn.min(boundary)
        } else {
            safe_hi_sn
        };

        Ok(DistributionAuth {
            is_gov: false,
            is_register: subject_data.is_some(),
            safe_hi_sn,
        })
    }




    pub(crate) fn split_off_after_safe_hi(
        ledger: &mut Vec<Ledger>,
        safe_hi_sn: u64,
    ) -> Vec<Ledger> {
        let split_index =
            ledger.partition_point(|event| event.sn <= safe_hi_sn);
        ledger.split_off(split_index)
    }

    async fn get_tracker_window(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        actual_sn: Option<u64>,
        data: &SubjectData,
    ) -> Result<
        (
            u64,
            Option<u64>,
            Option<u64>,
            bool,
            Vec<TrackerDeliveryRange>,
        ),
        ActorError,
    > {
        let SubjectData::Tracker {
            governance_id,
            schema_id,
            namespace,
            ..
        } = data
        else {
            return Err(DistributorError::SubjectNotFound.into());
        };

        let (sn, transfer_sn, clear_sn, is_all, ranges) =
            resolve_tracker_window(
                ctx,
                &governance_id,
                subject_id,
                sender.clone(),
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
                actual_sn,
            )
            .await?;

        let Some(sn) = sn else {
            let witness_status = check_witness_status(
                ctx,
                governance_id,
                sender.clone(),
                namespace.clone(),
                schema_id.clone(),
                Some(subject_id.clone()),
                None,
                None,
            )
            .await?;

            return match (actual_sn, witness_status.access_sn) {
                (Some(actual_sn), Some(witness_sn))
                    if actual_sn >= witness_sn =>
                {
                    Err(DistributorError::ActualSnBiggerThanWitness {
                        actual_sn,
                        witness_sn,
                    }
                    .into())
                }
                _ => Err(DistributorError::SenderNoAccess.into()),
            };
        };

        Ok((sn, transfer_sn, clear_sn, is_all, ranges))
    }

    fn tracker_delivery_mode(
        ranges: &[TrackerDeliveryRange],
        sn: u64,
    ) -> Option<TrackerDeliveryMode> {
        let idx = ranges.partition_point(|range| range.to_sn < sn);
        if idx < ranges.len() && ranges[idx].from_sn <= sn {
            Some(ranges[idx].mode.clone())
        } else {
            None
        }
    }

    fn project_tracker_ledger(
        ledger: Vec<Ledger>,
        ranges: &[TrackerDeliveryRange],
    ) -> Result<Vec<Ledger>, ActorError> {
        let mut projected = Vec::with_capacity(ledger.len());

        for event in ledger {
            let Some(mode) = Self::tracker_delivery_mode(ranges, event.sn)
            else {
                return Err(ActorError::Functional {
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
        data: &SubjectData,
    ) -> Result<(u64, bool), ActorError> {
        match data {
            SubjectData::Tracker {
                governance_id,
                schema_id,
                namespace,
                ..
            } => {
                let witness_status = check_witness_status(
                    ctx,
                    governance_id,
                    sender.clone(),
                    namespace.clone(),
                    schema_id.clone(),
                    Some(subject_id.clone()),
                    None,
                    None,
                )
                .await?;

                let Some(sn) = witness_status.access_sn else {
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
                let (sn, _, clear_sn, _, ranges) = self
                    .get_tracker_window(
                        ctx,
                        subject_id,
                        sender.clone(),
                        actual_sn,
                        &data,
                    )
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
                    self.check_witness(ctx, subject_id, sender.clone(), &data).await?;
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
        already_verified_transfer_sn: Option<u64>,
    ) -> Result<(Vec<Ledger>, bool, u64, Option<Ledger>), ActorError> {
        let data = get_subject_data(ctx, subject_id).await?;
        let Some(data) = data else {
            return Err(DistributorError::SubjectNotFound.into());
        };

        match data {
            SubjectData::Tracker { .. } => {
                let (window_sn, transfer_sn, clear_sn, _, ranges) = self
                    .get_tracker_window(ctx, subject_id, sender.clone(), actual_sn, &data)
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

                let from_sn = actual_sn.map_or(0, |sn| sn.saturating_add(1));
                let batch_hi_sn = from_sn
                    .saturating_add(self.ledger_batch_size)
                    .saturating_sub(1)
                    .min(window_sn);
                let preferred_hi_sn = clear_sn
                    .filter(|clear_sn| {
                        actual_sn.is_none_or(|actual_sn| *clear_sn > actual_sn)
                    })
                    .unwrap_or(window_sn);
                let preferred_hi_sn =
                    if from_sn == 0 && preferred_hi_sn == 0 && window_sn > 0 {
                        window_sn
                    } else {
                        preferred_hi_sn
                    };
                let hi_sn = target_sn
                    .unwrap_or(preferred_hi_sn)
                    .min(preferred_hi_sn)
                    .min(batch_hi_sn);

                let (ledger, raw_is_all) = self
                    .get_ledger(ctx, subject_id, hi_sn, actual_sn, false)
                    .await?;

                let transfer_event = if let Some(transfer_sn) = transfer_sn {
                    if already_verified_transfer_sn
                        .is_some_and(|verified| verified >= transfer_sn)
                    {
                        None
                    } else {
                        let idx = ledger.partition_point(|event| event.sn < transfer_sn);
                        if idx < ledger.len() && ledger[idx].sn == transfer_sn {
                            Some(ledger[idx].clone())
                        } else {
                            let (mut event_ledger, _) = self
                                .get_ledger(
                                    ctx,
                                    subject_id,
                                    transfer_sn,
                                    Some(transfer_sn.saturating_sub(1)),
                                    false,
                                )
                                .await?;
                            let ev = event_ledger.pop();
                            ev
                        }
                    }
                } else {
                    None
                };

                let ledger = Self::project_tracker_ledger(ledger, &ranges)?;
                let is_all = raw_is_all && hi_sn == window_sn;
                Ok((ledger, is_all, hi_sn, transfer_event))
            }
            SubjectData::Governance { .. } => {
                let (witness_hi_sn, ..) =
                    self.check_witness(ctx, subject_id, sender, &data).await?;

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
                Ok((ledger, is_all, batch_hi_sn, None))
            }
        }
    }

    pub(crate) async fn request_ledger_from_sender(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        info: &ComunicateInfo,
        actual_sn: Option<u64>,
    ) -> Result<(), ActorError> {
        let verified = match get_subject_data(ctx, subject_id).await? {
            Some(SubjectData::Tracker { governance_id, .. }) => {
                match get_verified_transfer_sn(ctx, &governance_id, subject_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            msg_type = "RequestLedger",
                            subject_id = %subject_id,
                            error = %e,
                            "get_verified_transfer_sn failed"
                        );
                        None
                    }
                }
            }
            Some(SubjectData::Governance { .. }) => {
                match get_verified_transfer_sn(ctx, subject_id, subject_id).await {
                    Ok(v) => v,
                    Err(e) => {
                        warn!(
                            msg_type = "RequestLedger",
                            subject_id = %subject_id,
                            error = %e,
                            "get_verified_transfer_sn failed"
                        );
                        None
                    }
                }
            }
            None => None,
        };

        // Only tell the sender we already verified the transfer if this
        // specific sender is the one we verified it with. Otherwise the new
        // sender must send us the transfer_event so we can verify it.
        let already_verified_transfer_sn = verified
            .filter(|(_, verified_sender)| *verified_sender == sender)
            .map(|(sn, _)| sn);

        let new_info = self.build_response_info(
            sender,
            info,
            format!("/user/node/distributor_{}", subject_id),
        );

        self.send_network_message(
            new_info,
            ActorMessage::DistributionLedgerReq {
                actual_sn,
                target_sn: None,
                subject_id: subject_id.clone(),
                already_verified_transfer_sn,
            },
        )
        .await
    }

    pub(crate) async fn ensure_next_sn_or_request_update(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        received_first_sn: u64,
        info: &ComunicateInfo,
        sender: PublicKey,
    ) -> Result<bool, ActorError> {
        let subject_data = get_subject_data(ctx, subject_id).await?;

        match subject_data {
            Some(_) => {
                let Some(local_sn) =
                    get_local_subject_sn(ctx, subject_id).await?
                else {
                    self.request_ledger_from_sender(
                        ctx, subject_id, sender, info, None,
                    )
                    .await?;
                    return Ok(false);
                };
                let expected_sn = local_sn.saturating_add(1);

                if received_first_sn <= local_sn {
                    return Ok(false);
                }

                if received_first_sn != expected_sn {
                    debug!(
                        msg_type = "EnsureNextSn",
                        subject_id = %subject_id,
                        local_last_sn = local_sn,
                        expected_sn = expected_sn,
                        received_first_sn = received_first_sn,
                        "SN mismatch detected before authorization, requesting update"
                    );

                    self.request_ledger_from_sender(
                        ctx,
                        subject_id,
                        sender,
                        info,
                        Some(local_sn),
                    )
                    .await?;

                    return Ok(false);
                }
            }
            None => {
                if received_first_sn != 0 {
                    debug!(
                        msg_type = "EnsureNextSn",
                        subject_id = %subject_id,
                        received_first_sn = received_first_sn,
                        "Subject not present locally and first SN is not 0, requesting update"
                    );

                    self.request_ledger_from_sender(
                        ctx, subject_id, sender, info, None,
                    )
                    .await?;

                    return Ok(false);
                }
            }
        }

        Ok(true)
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
        already_verified_transfer_sn: Option<u64>,
    ) -> Result<(), ActorError> {
        let (ledger, is_all, hi_sn, transfer_event) = self
            .build_distribution_batch(
                ctx,
                &subject_id,
                sender.clone(),
                actual_sn,
                target_sn,
                already_verified_transfer_sn,
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
                transfer_event,
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
        already_verified_transfer_sn: Option<u64>,
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
        transfer_event: Option<Ledger>,
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
                    info.clone(),
                    sender.clone(),
                    receiver_actor.clone(),
                )
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    if let ActorError::FunctionalCritical { .. } = e {
                        error!(
                            msg_type = "GetLastSn",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Witness check failed"
                        );
                        return Err(emit_fail(ctx, e).await);
                    } else {
                        warn!(
                            msg_type = "GetLastSn",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Witness check failed"
                        );
                        self.send_no_offer_response(
                            &info,
                            sender.clone(),
                            receiver_actor,
                        )
                        .await?;
                        return Ok(());
                    }
                }
            },
            DistriWorkerMessage::GetGovernanceVersion {
                subject_id,
                info,
                sender,
                receiver_actor,
            } => {
                let result = self
                    .handle_get_governance_version(
                        ctx,
                        subject_id.clone(),
                        info,
                        sender.clone(),
                        receiver_actor,
                    )
                    .await;
                handle_distri_error!(
                    ctx,
                    result,
                    "GetGovernanceVersion",
                    &subject_id,
                    "Subject is not a governance",
                    sender = &sender
                )?;
            }
            DistriWorkerMessage::SendDistribution {
                actual_sn,
                target_sn,
                info,
                subject_id,
                sender,
                already_verified_transfer_sn,
            } => {
                let result = self
                    .handle_send_distribution(
                        ctx,
                        actual_sn,
                        target_sn,
                        info,
                        subject_id.clone(),
                        sender.clone(),
                        already_verified_transfer_sn,
                    )
                    .await;
                handle_distri_error!(
                    ctx,
                    result,
                    "SendDistribution",
                    &subject_id,
                    "Witness check failed",
                    sender = &sender
                )?;
            }
            DistriWorkerMessage::LastEventDistribution {
                ledger,
                info,
                sender,
            } => {
                self.process_last_event_distribution(ctx, *ledger, info, sender).await?;
            }
            DistriWorkerMessage::LedgerDistribution {
                mut ledger,
                is_all,
                transfer_event,
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

                ledger.sort_by_key(|event| event.sn);

                let subject_id = ledger[0].get_subject_id();
                let ledger_count = ledger.len();
                let first_sn = ledger[0].sn;

                if !self
                    .ensure_next_sn_or_request_update(
                        ctx,
                        &subject_id,
                        first_sn,
                        &info,
                        sender.clone(),
                    )
                    .await?
                {
                    return Ok(());
                }

                let common = self.check_auth_common(ctx, sender.clone(), &info, &ledger).await?;
                let subject_id = ledger[0].get_subject_id();

                let transfer_simulation = if let Some(ref transfer_event) = transfer_event {
                    if !common.is_gov {
                        match self.transfer_verifier.verify_and_simulate(
                            ctx,
                            &subject_id,
                            &ledger,
                            sender.clone(),
                            transfer_event,
                        ).await? {
                            TransferSimulationResult::Witness => Some(TransferSimulationResult::Witness),
                            TransferSimulationResult::NotWitness => {
                                return Err(DistributorError::ReceiverNoAccess.into());
                            }
                        }
                    } else {
                        None
                    }
                } else {
                    None
                };

                let mut verified_transfer_sn = if !common.is_gov {
                    match get_verified_transfer_sn(ctx, &common.governance_id, &subject_id).await {
                        Ok(v) => v
                            .filter(|(_, verified_sender)| *verified_sender == sender)
                            .map(|(sn, _)| sn),
                        Err(e) => {
                            warn!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                error = %e,
                                "get_verified_transfer_sn failed"
                            );
                            None
                        }
                    }
                } else {
                    None
                };

                let pending_ledger = ledger;
                let sender_is_all = is_all;

                self.process_ledger_chunks(
                    ctx,
                    pending_ledger,
                    sender_is_all,
                    &common,
                    transfer_event.as_ref(),
                    transfer_simulation,
                    verified_transfer_sn,
                    &info,
                    sender.clone(),
                    subject_id.clone(),
                    ledger_count,
                ).await?;

                debug!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    sender = %sender,
                    ledger_count = ledger_count,
                    is_all = is_all,
                    "Ledger distribution processed successfully"
                );
            }
        };

        Ok(())
    }
}
