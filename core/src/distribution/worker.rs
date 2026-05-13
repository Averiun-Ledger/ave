use std::{collections::HashSet, sync::Arc};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    Namespace, SchemaType,
    bridge::request::EventRequestType,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey, Signed},
    request::EventRequest,
};
use ave_network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage, Node, NodeMessage, NodeResponse,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        model::{HashThisRole, RoleTypes},
        role_register::SearchRole,

        witnesses_register::{
            GovVersionLimit, HiSnLimit, TrackerDeliveryMode,
            TrackerDeliveryRange,
        },
    },
    helpers::network::service::NetworkSender,
    model::{
        common::{
            check_create_gov_version_limit, check_gov_version_limit, check_subject_creation,
            check_quorum_signers, check_witness_access, check_witness_hi_sn_limit,
            check_witness_status,
            get_verified_transfer_sn, record_verified_transfer,
            emit_fail, get_validation_roles_register, node::get_subject_data,
            subject::{
                acquire_subject, create_subject, get_gov, get_gov_sn,
                get_local_subject_sn,
                get_tracker_window as resolve_tracker_window,
                get_tracker_window_from_ledger as resolve_tracker_window_from_ledger,
                check_simulated_transfer_hi_sn_limit,
                update_ledger,
            },
        },
        event::{Ledger, LedgerSeal, Protocols, ValidationMetadata},
    },
    validation::response::ValidationRes,
    node::SubjectData,
    tracker::{Tracker, TrackerMessage, TrackerResponse},
    update::{UpdateSubjectKind, UpdateWitnessOffer},
};

use tracing::{Span, debug, error, info_span, warn};

use super::error::DistributorError;

struct DistributionAuth {
    is_gov: bool,
    is_register: bool,
    safe_hi_sn: u64,
}

pub struct DistriWorker {
    pub our_key: Arc<PublicKey>,
    pub network: Arc<NetworkSender>,
    pub ledger_batch_size: u64,
    pub hash: HashAlgorithm,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TransferSimulationResult {
    /// La simulación fue afirmativa: el nodo es testigo del owner/new_owner.
    Witness,
    /// La simulación devolvió None: no somos testigo.
    NotWitness,
}

struct CheckAuthCommon {
    subject_id: DigestIdentifier,
    subject_data: Option<SubjectData>,
    schema_id: SchemaType,
    governance_id: DigestIdentifier,
    namespace: String,
    is_gov: bool,
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

    async fn send_last_event_ack(
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

    async fn check_auth_batch(
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

        // Optimización: solo consultar subject_data fresco si era None.
        // Si ya era Some, lo único que puede cambiar es active, pero sigue siendo Some.
        let is_register = if common.subject_data.is_none() {
            get_subject_data(ctx, &subject_id).await?.is_some()
        } else {
            true
        };

        // 1. Batch actual trae un transfer_event nuevo y la simulación dice Witness
        if let (Some(transfer_event), Some(TransferSimulationResult::Witness)) = (transfer_event, transfer_simulation) {
            let chunk_first_sn = ledger.first().ok_or(DistributorError::EmptyEvents)?.sn;
            println!("[check_auth_batch] camino1_check chunk_first={} transfer_event.sn={} cond={}", chunk_first_sn, transfer_event.sn, chunk_first_sn <= transfer_event.sn);
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
            println!("[check_auth_batch] camino2_check chunk_first={} verified_sn={} cond={}", chunk_first_sn, verified_sn, chunk_first_sn <= verified_sn);
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
            let receiver_gov_limit = check_gov_version_limit(
                ctx,
                &governance_id,
                &subject_id,
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
            )
            .await?;

            let receiver_gov_limit_clone = receiver_gov_limit.clone();
            let receiver_limit = Self::concrete_gov_version_limit(
                ledger,
                receiver_gov_limit,
                offered_hi_sn,
            );

            println!("[check_auth_batch subject_data=Some] subject={} sender={} receiver_gov_limit={:?} receiver_limit={:?} offered_hi_sn={}",
                subject_id, sender, receiver_gov_limit_clone, receiver_limit, offered_hi_sn);

            let Some(receiver_limit) = receiver_limit else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };

            receiver_limit.min(offered_hi_sn)
        } else {
            let owner = ledger.first().ok_or(DistributorError::EmptyEvents)?.ledger_seal_signature.signer.clone();
            let gov_version = ledger.first().ok_or(DistributorError::EmptyEvents)?.gov_version;

            let witness_status = check_witness_status(
                ctx,
                &governance_id,
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
                Some(subject_id.clone()),
                Some(owner.clone()),
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

            let (receiver_window_sn, ..) = resolve_tracker_window_from_ledger(
                ctx,
                &governance_id,
                &subject_id,
                ledger.to_vec(),
                (*self.our_key).clone(),
                sender.clone(),
                namespace.clone(),
                schema_id.clone(),
                None,
            )
            .await?;

            println!("[check_auth_batch subject_data=None] subject={} sender={} receiver_hi={:?} create_gov={:?} window={:?}", subject_id, sender, receiver_hi_limit, receiver_create_gov_limit, receiver_window_sn);
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

    async fn check_auth_single(
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
            let receiver_gov_limit = check_gov_version_limit(
                ctx,
                &governance_id,
                &subject_id,
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
            )
            .await?;

            let receiver_limit = Self::concrete_gov_version_limit(
                ledger,
                receiver_gov_limit,
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

            let witness_status = check_witness_status(
                ctx,
                &governance_id,
                (*self.our_key).clone(),
                namespace.clone(),
                schema_id.clone(),
                Some(subject_id.clone()),
                Some(owner.clone()),
                Some(first_ledger.gov_version),
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

            let (receiver_window_sn, ..) = resolve_tracker_window_from_ledger(
                ctx,
                &governance_id,
                &subject_id,
                ledger.to_vec(),
                (*self.our_key).clone(),
                sender.clone(),
                namespace.clone(),
                schema_id.clone(),
                None,
            )
            .await?;

            println!("[check_auth_batch subject_data=None] subject={} sender={} receiver_hi={:?} create_gov={:?} window={:?}", subject_id, sender, receiver_hi_limit, receiver_create_gov_limit, receiver_window_sn);
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



    async fn verify_transfer_light(
        &self,
        ctx: &mut ActorContext<Self>,
        transfer_event: &Ledger,
        expected_subject_id: &DigestIdentifier,
        ledger: &Ledger,
    ) -> Result<(DigestIdentifier, bool), DistributorError> {
        // 1. El protocolo debe ser Transfer.
        let (event_request, evaluation, validation) = match &transfer_event.protocols {
            Protocols::Transfer { event_request, evaluation, validation } => {
                (event_request, evaluation, validation)
            }
            _ => {
                return Err(DistributorError::TransferEventInvalid {
                    details: "protocol is not Transfer".to_string(),
                });
            }
        };

        if !evaluation.is_ok() {
            return Err(DistributorError::TransferEventInvalid {
                details: "transfer evaluation is not ok".to_string(),
            });
        }

        if validation.validators_signatures.is_empty() {
            return Err(DistributorError::TransferEventInvalid {
                details: "transfer validation signatures are empty".to_string(),
            });
        }

        let ValidationMetadata::ModifiedHash {
            modified_metadata_without_propierties_hash,
            propierties_hash,
            event_request_hash,
            viewpoints_hash,
        } = &validation.validation_metadata
        else {
            return Err(DistributorError::TransferEventInvalid {
                details: "invalid validation metadata type".to_string(),
            });
        };

        let validation_res = ValidationRes::Response {
            vali_req_hash: validation.validation_req_hash.clone(),
            modified_metadata_without_propierties_hash:
                modified_metadata_without_propierties_hash.clone(),
            propierties_hash: propierties_hash.clone(),
            event_request_hash: event_request_hash.clone(),
            viewpoints_hash: viewpoints_hash.clone(),
        };

        for signature in validation.validators_signatures.iter() {
            let signed_res =
                Signed::from_parts(validation_res.clone(), signature.clone());
            if signed_res.verify().is_err() {
                return Err(DistributorError::TransferEventInvalid {
                    details: "invalid validator signature".to_string(),
                });
            }
        }

        // 2. El EventRequest interno debe ser Transfer.
        let transfer = match event_request.content() {
            EventRequest::Transfer(t) => t,
            _ => {
                return Err(DistributorError::TransferEventInvalid {
                    details: "event request is not Transfer".to_string(),
                });
            }
        };

        // 3. Verificar firma del ledger_seal.
        let protocols_hash = transfer_event
            .protocols
            .hash_for_ledger(&self.hash)
            .map_err(|e| DistributorError::TransferEventInvalid {
                details: format!("protocol hash failed: {}", e),
            })?;

        let ledger_seal = LedgerSeal {
            gov_version: transfer_event.gov_version,
            sn: transfer_event.sn,
            prev_ledger_event_hash: transfer_event.prev_ledger_event_hash.clone(),
            protocols_hash,
        };

        if transfer_event
            .ledger_seal_signature
            .verify(&ledger_seal)
            .is_err()
        {
            return Err(DistributorError::TransferEventInvalid {
                details: "ledger seal signature invalid".to_string(),
            });
        }

        // 4. Verificar firma del event_request.
        if event_request.verify().is_err() {
            return Err(DistributorError::TransferEventInvalid {
                details: "event request signature invalid".to_string(),
            });
        }

        // 5. Coherencia interna: ambos signers deben coincidir.
        let ledger_signer = &transfer_event.ledger_seal_signature.signer;
        let request_signer = &event_request.signature().signer;
        if ledger_signer != request_signer {
            return Err(DistributorError::TransferEventInvalid {
                details: format!(
                    "signer mismatch: ledger_signer={}, request_signer={}",
                    ledger_signer, request_signer
                ),
            });
        }

        // 6. Verificar subject_id.
        if event_request.content().get_subject_id() != *expected_subject_id {
            return Err(DistributorError::TransferEventInvalid {
                details: "subject id mismatch".to_string(),
            });
        }

        // 7. Coherencia del Transfer: no puedes transferirte a ti mismo.
        if transfer.new_owner == *request_signer {
            return Err(DistributorError::TransferEventInvalid {
                details: "new_owner is the same as signer".to_string(),
            });
        }

        // 8. Verificar quorum de validación.
        let subject_data = get_subject_data(ctx, expected_subject_id).await
            .map_err(|e| DistributorError::TransferEventInvalid {
                details: format!("failed to get subject data: {}", e),
            })?;

        let (governance_id, schema_id, namespace, is_register) = match subject_data {
            Some(SubjectData::Tracker { governance_id, schema_id, namespace, .. }) => {
                (governance_id, schema_id, Namespace::from(namespace), true)
            }
            Some(SubjectData::Governance { .. }) => {
                return Err(DistributorError::TransferEventInvalid {
                    details: "subject is governance".to_string(),
                });
            }
            None => {
                let Some(create) = ledger.get_create_event() else {
                    return Err(DistributorError::TransferEventInvalid {
                        details: "ledger has no create event".to_string(),
                    });
                };
                if create.schema_id.is_gov() || create.governance_id.is_empty() {
                    return Err(DistributorError::TransferEventInvalid {
                        details: "invalid create event for transfer hint".to_string(),
                    });
                }

                (create.governance_id.clone(), create.schema_id.clone(), create.namespace.clone(), false)
            }
        };

        let role_data = get_validation_roles_register(
            ctx,
            &governance_id,
            SearchRole {
                schema_id,
                namespace,
            },
            transfer_event.gov_version,
        )
        .await
        .map_err(|e| DistributorError::TransferEventInvalid {
            details: format!("failed to get validation roles: {}", e),
        })?;

        if !check_quorum_signers(
            &validation
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<_>>(),
            &role_data.quorum,
            &role_data.workers,
        ) {
            return Err(DistributorError::TransferEventInvalid {
                details: "quorum check failed".to_string(),
            });
        }

        Ok((governance_id, is_register))
    }

    /// Verifica criptográficamente un transfer_event, simula si el nodo local
    /// sigue siendo testigo tras esa transferencia, y si es así lo registra en
    /// el TransferVerificationRegister.
    async fn verify_and_simulate_transfer(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        sender: PublicKey,
        transfer_event: &Ledger,
    ) -> Result<TransferSimulationResult, ActorError> {
        let first_ledger = sender_ledger.first().ok_or_else(|| ActorError::Functional {
            description: "Empty sender ledger in verify_and_simulate_transfer".to_string(),
        })?;
        let (governance_id, _) = self
            .verify_transfer_light(ctx, transfer_event, subject_id, first_ledger)
            .await?;

        let (schema_id, namespace) =
            if let Some(data) = get_subject_data(ctx, subject_id).await? {
                match data {
                    SubjectData::Tracker {
                        schema_id,
                        namespace,
                        ..
                    } => (schema_id, namespace),
                    SubjectData::Governance { .. } => {
                        (SchemaType::Governance, String::default())
                    }
                }
            } else {
                let create = sender_ledger
                    .iter()
                    .find(|l| l.is_create_event())
                    .and_then(|l| l.get_create_event())
                    .ok_or_else(|| ActorError::Functional {
                        description: "Cannot resolve metadata needed for simulation: no create event in sender ledger".to_string(),
                    })?;
                (create.schema_id, create.namespace.to_string())
            };

        let simulated_limit = check_simulated_transfer_hi_sn_limit(
            ctx,
            &governance_id,
            subject_id,
            transfer_event.clone(),
            (*self.our_key).clone(),
            namespace,
            schema_id,
        )
        .await?;

        if !matches!(simulated_limit, HiSnLimit::None) {
            println!("[verify_and_simulate_transfer] subject={} sender={} result=Witness", subject_id, sender);
            Ok(TransferSimulationResult::Witness)
        } else {
            println!("[verify_and_simulate_transfer] subject={} sender={} result=NotWitness", subject_id, sender);
            Ok(TransferSimulationResult::NotWitness)
        }
    }

    fn split_off_after_safe_hi(
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
            let witness_sn = check_witness_access(
                ctx,
                &governance_id,
                subject_id,
                sender.clone(),
                namespace,
                schema_id,
            )
            .await?;

            return match (actual_sn, witness_sn) {
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
                let (sn, _, clear_sn, _, ranges) = self
                    .get_tracker_window(
                        ctx,
                        subject_id,
                        sender.clone(),
                        actual_sn,
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
                    self.check_witness(ctx, subject_id, sender.clone()).await?;
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
                    .get_tracker_window(ctx, subject_id, sender.clone(), actual_sn)
                    .await?;

                println!("[build_distribution_batch] subject={} sender={} actual_sn={:?} window_sn={} transfer_sn={:?} clear_sn={:?}",
                    subject_id, sender, actual_sn, window_sn, transfer_sn, clear_sn);

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
                    } else if let Some(event) =
                        ledger.iter().find(|event| event.sn == transfer_sn)
                    {
                        Some(event.clone())
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
                } else {
                    println!("[build_distribution_batch] subject={} sender={} transfer_sn=None", subject_id, sender);
                    None
                };

                println!("[build_distribution_batch] subject={} sender={} transfer_event.is_some={} already_verified={:?}", subject_id, sender, transfer_event.is_some(), already_verified_transfer_sn);
                let ledger = Self::project_tracker_ledger(ledger, &ranges)?;
                let is_all = raw_is_all && hi_sn == window_sn;
                Ok((ledger, is_all, hi_sn, transfer_event))
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
                Ok((ledger, is_all, batch_hi_sn, None))
            }
        }
    }

    async fn request_ledger_from_sender(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        info: &ComunicateInfo,
        actual_sn: Option<u64>,
    ) -> Result<(), ActorError> {
        let verified = match get_subject_data(ctx, subject_id).await? {
            Some(SubjectData::Tracker { governance_id, .. }) => {
                get_verified_transfer_sn(ctx, &governance_id, subject_id)
                    .await
                    .ok()
                    .flatten()
            }
            Some(SubjectData::Governance { .. }) => {
                get_verified_transfer_sn(ctx, subject_id, subject_id)
                    .await
                    .ok()
                    .flatten()
            }
            None => None,
        };

        // Only tell the sender we already verified the transfer if this
        // specific sender is the one we verified it with. Otherwise the new
        // sender must send us the transfer_event so we can verify it.
        let already_verified_transfer_sn = verified
            .filter(|(_, verified_sender)| *verified_sender == sender)
            .map(|(sn, _)| sn);

        println!("[request_ledger_from_sender] subject={} sender={} already_verified={:?}", subject_id, sender, already_verified_transfer_sn);
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

    async fn ensure_next_sn_or_request_update(
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

        println!("[request_ledger_from_sender] subject={} sender={} already_verified={:?}", subject_id, sender, already_verified_transfer_sn);
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
                    if let ActorError::FunctionalCritical { .. } = e {
                        error!(
                            msg_type = "GetGovernanceVersion",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Failed to send governance version response to network"
                        );
                        return Err(emit_fail(ctx, e).await);
                    } else {
                        warn!(
                            msg_type = "GetGovernanceVersion",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Subject is not a governance"
                        );
                        return Err(e);
                    }
                }
            },
            DistriWorkerMessage::SendDistribution {
                actual_sn,
                target_sn,
                info,
                subject_id,
                sender,
                already_verified_transfer_sn,
            } => match self
                .handle_send_distribution(
                    ctx,
                    actual_sn,
                    target_sn,
                    info,
                    subject_id.clone(),
                    sender.clone(),
                    already_verified_transfer_sn,
                )
                .await
            {
                Ok(()) => {}
                Err(e) => {
                    if let ActorError::FunctionalCritical { .. } = e {
                        error!(
                            msg_type = "SendDistribution",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Failed to send ledger response to network"
                        );
                        return Err(emit_fail(ctx, e).await);
                    } else {
                        warn!(
                            msg_type = "SendDistribution",
                            subject_id = %subject_id,
                            sender = %sender,
                            error = %e,
                            "Witness check failed"
                        );
                        return Err(e);
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

                if !self
                    .ensure_next_sn_or_request_update(
                        ctx,
                        &subject_id,
                        sn,
                        &info,
                        sender.clone(),
                    )
                    .await?
                {
                    if let Some(local_sn) =
                        get_local_subject_sn(ctx, &subject_id).await?
                        && local_sn >= sn
                    {
                        self.send_last_event_ack(sender.clone(), &info).await?;
                    }
                    return Ok(());
                }

                let auth = match self
                    .check_auth_single(
                        ctx,
                        sender.clone(),
                        &info,
                        std::slice::from_ref(&*ledger),
                        sn,
                    )
                    .await
                {
                    Ok(auth) => auth,
                    Err(e) => {
                        if let ActorError::FunctionalCritical { .. } = e {
                            error!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                sender = %sender,
                                error = %e,
                                "Authorization check failed"
                            );
                            return Err(emit_fail(ctx, e).await);
                        } else {
                            warn!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                sender = %sender,
                                error = %e,
                                "Authorization check failed"
                            );
                            return Err(e);
                        }
                    }
                };

                let is_gov = auth.is_gov;

                if !is_gov && auth.safe_hi_sn < sn {
                    warn!(
                        msg_type = "LastEventDistribution",
                        subject_id = %subject_id,
                        sn = sn,
                        safe_hi_sn = auth.safe_hi_sn,
                        sender = %sender,
                        "Discarding event above current receiver access limit"
                    );
                    return Err(DistributorError::ReceiverNoAccess.into());
                }

                let lease = if ledger.is_create_event() {
                    if let Err(e) = create_subject(ctx, *ledger.clone()).await {
                        if let ActorError::FunctionalCritical { .. } = e {
                            error!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                error = %e,
                                "Failed to create subject from create event"
                            );
                            return Err(emit_fail(ctx, e).await);
                        } else {
                            warn!(
                                msg_type = "LastEventDistribution",
                                subject_id = %subject_id,
                                sn = sn,
                                error = %e,
                                "Failed to create subject from create event"
                            );
                            return Err(e);
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
                                    ctx,
                                    &subject_id,
                                    sender.clone(),
                                    &info,
                                    Some(last_sn),
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
                            if let ActorError::FunctionalCritical { .. } =
                                e.clone()
                            {
                                error!(
                                    msg_type = "LastEventDistribution",
                                    subject_id = %subject_id,
                                    sn = sn,
                                    error = %e,
                                    "Failed to update subject ledger"
                                );
                                return Err(emit_fail(ctx, e).await);
                            } else {
                                warn!(
                                    msg_type = "LastEventDistribution",
                                    subject_id = %subject_id,
                                    sn = sn,
                                    error = %e,
                                    "Failed to update subject ledger"
                                );
                                return Err(e);
                            }
                        }
                    }
                };

                if let Err(e) =
                    self.send_last_event_ack(sender.clone(), &info).await
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
                        match self.verify_and_simulate_transfer(
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
                    get_verified_transfer_sn(ctx, &common.governance_id, &subject_id).await.ok().flatten()
                        .filter(|(_, verified_sender)| *verified_sender == sender)
                        .map(|(sn, _)| sn)
                } else {
                    None
                };

                let mut pending_ledger = ledger;
                let sender_is_all = is_all;
                let mut transfer_recorded = false;

                loop {
                    let chunk_first_sn = pending_ledger[0].sn;
                    let chunk_offered_hi_sn = pending_ledger
                        .last()
                        .map(|event| event.sn)
                        .unwrap_or(chunk_first_sn);

                    println!("[LedgerDistribution loop] subject={} sender={} chunk_first={} chunk_last={} ledger_len={} transfer_event.sn={:?} transfer_simulation={:?} verified_transfer_sn={:?}",
                        subject_id, sender, chunk_first_sn, chunk_offered_hi_sn, pending_ledger.len(),
                        transfer_event.as_ref().map(|e| e.sn), transfer_simulation.is_some(), verified_transfer_sn);

                    let auth = self
                        .check_auth_batch(
                            ctx,
                            sender.clone(),
                            &pending_ledger,
                            chunk_offered_hi_sn,
                            &common,
                            transfer_event.as_ref(),
                            transfer_simulation.as_ref(),
                            verified_transfer_sn,
                        )
                        .await?;

                    println!("[LedgerDistribution loop] subject={} sender={} auth.safe_hi_sn={} auth.is_register={}",
                        subject_id, sender, auth.safe_hi_sn, auth.is_register);

                    if !transfer_recorded && transfer_simulation.is_some() && !common.is_gov {
                        if let Some(ref transfer_event) = transfer_event {
                            record_verified_transfer(
                                ctx,
                                &common.governance_id,
                                &subject_id,
                                transfer_event.sn,
                                sender.clone(),
                            ).await?;
                            transfer_recorded = true;
                            // Refrescar verified_transfer_sn para que la siguiente
                            // iteración del loop pueda usar Path C (free passage).
                            verified_transfer_sn = Some(transfer_event.sn);
                        }
                    }

                    let is_gov = auth.is_gov;
                    let is_register = auth.is_register;
                    let safe_hi_sn = auth.safe_hi_sn;

                    let remaining_ledger = Self::split_off_after_safe_hi(
                        &mut pending_ledger,
                        safe_hi_sn,
                    );
                    println!("[LedgerDistribution loop] subject={} sender={} safe_hi={} pending_len={} remaining_len={}",
                        subject_id, sender, safe_hi_sn, pending_ledger.len(), remaining_ledger.len());
                    if pending_ledger.is_empty() {
                        warn!(
                            msg_type = "LedgerDistribution",
                            subject_id = %subject_id,
                            sender = %sender,
                            safe_hi_sn = safe_hi_sn,
                            "Discarding ledger batch above current receiver access limit"
                        );
                        return Err(DistributorError::ReceiverNoAccess.into());
                    }

                    let chunk_is_all =
                        remaining_ledger.is_empty() && sender_is_all;

                    let lease = if pending_ledger[0].is_create_event()
                        && !is_register
                    {
                        let create_ledger = pending_ledger[0].clone();
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
                                if let ActorError::FunctionalCritical {
                                    ..
                                } = e
                                {
                                    error!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %e,
                                        "Failed to create subject from ledger"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                } else {
                                    warn!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %e,
                                        "Failed to create subject from ledger"
                                    );
                                    return Err(e);
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
                                create_ledger
                                    .ledger_seal_signature
                                    .signer
                                    .clone(),
                                create_ledger.gov_version,
                                request.namespace.to_string(),
                                request.schema_id,
                            )
                            .await
                            {
                                if let ActorError::FunctionalCritical {
                                    ..
                                } = e
                                {
                                    error!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %e,
                                        "Failed to validate subject creation from ledger"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                } else {
                                    warn!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %e,
                                        "Failed to validate subject creation from ledger"
                                    );
                                    return Err(e);
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
                                    if let ActorError::FunctionalCritical {
                                        ..
                                    } = e
                                    {
                                        error!(
                                            msg_type = "LedgerDistribution",
                                            subject_id = %subject_id,
                                            error = %e,
                                            "Failed to create subject from ledger"
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    } else {
                                        warn!(
                                            msg_type = "LedgerDistribution",
                                            subject_id = %subject_id,
                                            error = %e,
                                            "Failed to create subject from ledger"
                                        );
                                        return Err(e);
                                    }
                                }
                            }
                        };

                        let _event = pending_ledger.remove(0);
                        lease
                    } else {
                        if pending_ledger[0].is_create_event() && is_register {
                            let _event = pending_ledger.remove(0);
                        }

                        let requester = Self::requester_id(
                            "ledger_distribution",
                            &subject_id,
                            &info,
                            &sender,
                        );
                        if !pending_ledger.is_empty() && !is_gov {
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
                                    let error =
                                        DistributorError::UpTrackerFailed {
                                            details: e.to_string(),
                                        };
                                    return Err(
                                        emit_fail(ctx, error.into()).await
                                    );
                                }
                            }
                        } else {
                            None
                        }
                    };

                    let applied_hi_sn = pending_ledger
                        .last()
                        .map(|event| event.sn)
                        .unwrap_or(safe_hi_sn);

                    if !pending_ledger.is_empty() {
                        let update_result =
                            update_ledger(ctx, &subject_id, pending_ledger)
                                .await;

                        if let Some(lease) = lease.clone()
                            && update_result.is_err()
                        {
                            lease.finish(ctx).await?;
                        }

                        match update_result {
                            Ok((last_sn, _, _)) => {
                                if let Some(lease) = lease.clone() {
                                    lease.finish(ctx).await?;
                                }

                                if !remaining_ledger.is_empty() {
                                    pending_ledger = remaining_ledger;
                                    continue;
                                }

                                if !chunk_is_all {
                                    debug!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        last_sn = last_sn,
                                        "Partial ledger received, requesting more"
                                    );

                                    if let Err(e) = self
                                        .request_ledger_from_sender(
                                            ctx,
                                            &subject_id,
                                            sender.clone(),
                                            &info,
                                            Some(last_sn),
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
                            }
                            Err(e) => {
                                if let ActorError::FunctionalCritical {
                                    ..
                                } = e.clone()
                                {
                                    error!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        first_sn = chunk_first_sn,
                                        ledger_count = ledger_count,
                                        error = %e,
                                        "Failed to update subject ledger"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                } else {
                                    warn!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        first_sn = chunk_first_sn,
                                        ledger_count = ledger_count,
                                        error = %e,
                                        "Failed to update subject ledger"
                                    );
                                    return Err(e);
                                }
                            }
                        }
                    } else {
                        if let Some(lease) = lease.clone() {
                            lease.finish(ctx).await?;
                        }

                        if !remaining_ledger.is_empty() {
                            pending_ledger = remaining_ledger;
                            continue;
                        }

                        if !chunk_is_all {
                            debug!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                last_sn = applied_hi_sn,
                                "Partial ledger received, requesting more"
                            );

                            if let Err(e) = self
                                .request_ledger_from_sender(
                                    ctx,
                                    &subject_id,
                                    sender.clone(),
                                    &info,
                                    Some(applied_hi_sn),
                                )
                                .await
                            {
                                error!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    last_sn = applied_hi_sn,
                                    error = %e,
                                    "Failed to request more ledger entries"
                                );
                                return Err(emit_fail(ctx, e).await);
                            };
                        }
                    }

                    break;
                }

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
