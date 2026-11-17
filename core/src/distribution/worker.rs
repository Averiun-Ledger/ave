use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

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
    auth::{SubjectAccess, SubjectAccessMessage, SubjectAccessResponse},
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        model::{HashThisRole, RoleTypes},
        witnesses_register::{
            GovVersionLimit, HiSnLimit, TrackerDeliveryMode,
            TrackerDeliveryRange, WitnessesRegister,
        },
    },
    helpers::network::{delivery_of, service::NetworkSender},
    model::{
        common::{
            OwnerContext, TrackerIdentity, TrackerParams, TrackerPeers,
            check_witness_status, crash_system, get_verified_transfer_sn_firm,
            node::get_subject_data,
            subject::{
                acquire_subject, check_witness_status_and_window, get_gov_sn,
                get_local_subject_sn,
                get_tracker_window as resolve_tracker_window, get_version,
                has_role,
            },
        },
        event::{EvaluationResponse, Ledger, Protocols},
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
    /// Batches deferred while their aux evidence is uncheckable.
    /// They are applied, in order, once a later batch lets the aux
    /// verify; refutation or a fresh copy discards them. Memory-only:
    /// never persisted, so a reboot starts clean. Keyed by subject
    /// because the node-level worker multiplexes many of them.
    /// Bounded by count, events and bytes (see `DeferredStore`):
    /// overflow evicts whole chains instead of growing forever.
    pub(crate) deferred: super::deferred::DeferredStore,
    /// Saved verification prefixes, keyed by subject: later aux
    /// checks resume the replay from the tip instead of reloading
    /// and re-scanning the whole prefix. Volatile like `deferred`;
    /// identity-checked on every use, LRU-bounded, and dropped on
    /// rollback so no purge ever reuses a stale chain.
    pub(crate) verify_cursors: super::transfer_verifier::VerifyCursorStore,
    /// Incremental authorization state for staged chains: lets the
    /// `without_aux` check process only the new tail per delivery
    /// instead of rebuilding ownership and evidence over the whole
    /// retained prefix. Dropped with the staged prefix it covers.
    pub(crate) pending_auth: HashMap<DigestIdentifier, PendingAuthState>,
    pub(crate) attempt_clock: Arc<AtomicU64>,
    /// Test-only one-shot visibility fault: 0 none, 1 fail, 2 empty.
    /// Atomic so the shared `&self` receipt helpers can consume it;
    /// production never arms it.
    #[cfg(feature = "test")]
    pub(crate) test_modes_fault: std::sync::atomic::AtomicU8,
}

use super::transfer_verifier::TransferSimulationResult;

pub(crate) struct CheckAuthCommon {
    pub(crate) subject_id: DigestIdentifier,
    pub(crate) subject_data: Option<SubjectData>,
    pub(crate) schema_id: SchemaType,
    pub(crate) governance_id: DigestIdentifier,
    pub(crate) namespace: String,
    pub(crate) is_gov: bool,
    pub(crate) gov_version: u64,
}

/// Incremental authorization state for one staged chain: the
/// chain-derived facts already evaluated over the held prefix, so
/// each new batch only processes its own tail. The access decision
/// itself is never cached: every delivery re-runs the witness
/// check against current governance. Invalidated whenever the
/// staged prefix is dropped, taken, evicted or proved divergent.
pub(crate) struct PendingAuthState {
    tip_sn: Option<u64>,
    tip_hash: Option<DigestIdentifier>,
    is_register: bool,
    max_gov_version: u64,
    first_confirm_reject: Option<u64>,
    has_inline_transfer: bool,
    /// Whether the retained chain is known to contain the Create
    /// event: computed once per rebuild and extended with the new
    /// tail only, so link checks never rescan the prefix.
    has_create: bool,
    transfer_data: Option<crate::governance::witnesses_register::TransferData>,
    proven_inline: HashSet<u64>,
    auth_metadata: Option<crate::subject::Metadata>,
    auth_roles: super::transfer_verifier::RoleCache,
    broken: bool,
    /// Frozen gov-window boundary for one limit version: once the
    /// retained chain outgrows a `Version` limit, later events can
    /// only share the same or a higher gov version (chain order),
    /// so the boundary never moves again until the entry is dropped
    /// (prune, take, eviction) or the limit version changes. This
    /// keeps the exceeding corner O(1) per delivery instead of
    /// rescanning the retained prefix each time.
    frozen_gov_window: Option<(u64, Option<u64>)>,
}

impl PendingAuthState {
    fn fresh(is_register: bool) -> Self {
        Self {
            tip_sn: None,
            tip_hash: None,
            is_register,
            max_gov_version: 0,
            first_confirm_reject: None,
            has_inline_transfer: false,
            has_create: false,
            transfer_data: None,
            proven_inline: HashSet::new(),
            auth_metadata: None,
            auth_roles: super::transfer_verifier::RoleCache::new(),
            broken: false,
            frozen_gov_window: None,
        }
    }
}

pub(crate) struct TransferBatch<'a> {
    pub event: Option<&'a Ledger>,
    pub simulation: Option<TransferSimulationResult>,
    pub verified_sn: Option<u64>,
}

pub(crate) struct DistributionContext {
    pub info: ComunicateInfo,
    pub sender: PublicKey,
    pub subject_id: DigestIdentifier,
    pub sender_is_all: bool,
    pub ledger_count: usize,
    pub attempt: u64,
}

pub(crate) struct DistributionRange {
    pub actual_sn: Option<u64>,
    pub target_sn: Option<u64>,
    pub already_verified_transfer_sn: Option<u64>,
}

impl DistriWorker {
    /// Snapshots one subject's staged prefix into the test-only
    /// stats helper, live and stored. Called after every mutation
    /// so the exact accounting the tests assert can never drift
    /// silently. Test-only: production pays nothing here.
    #[cfg(feature = "test")]
    fn note_deferred_stats(
        ctx: &mut ActorContext<Self>,
        store: &super::deferred::DeferredStore,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) =
            ctx.system().get_helper::<super::deferred::SharedDeferredStats>(
                "deferred_stats",
            )
        {
            let (live_events, live_bytes) = store.live(subject_id);
            let (stored_events, stored_bytes) = store.retained(subject_id);
            stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .note(
                    subject_id,
                    live_events,
                    live_bytes,
                    stored_events,
                    stored_bytes,
                );
        }
    }

    /// Sender-side batch budget, clamped to the shared inbound
    /// limit: a configured size above it must shrink the window,
    /// never emit a batch the receiver drops on sight.
    pub(crate) fn capped_batch_size(configured: u64) -> u64 {
        configured
            .min(crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS as u64)
    }

    /// Test-only auth work counter: visits over new tail events
    /// during the incremental `without_aux` check. Keeps the total
    /// buffer/auth work linear instead of rescanning the retained
    /// prefix per delivery.
    #[cfg(feature = "test")]
    fn note_auth_work(
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        visited: u64,
    ) {
        use super::transfer_verifier::SharedVerifyStats;
        if visited == 0 {
            return;
        }
        if let Some(stats) = ctx.system().get_helper::<SharedVerifyStats>("verify_stats") {
            stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add_buffer_work(subject_id, 0, visited, 0);
        }
    }

    /// Test-only buffer clone counter for the worker side: the
    /// screened ownership copy duplicates the batch once instead
    /// of rescanning it per delivery.
    #[cfg(feature = "test")]
    fn note_buffer_cloned(
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        cloned: u64,
    ) {
        use super::transfer_verifier::SharedVerifyStats;
        if cloned == 0 {
            return;
        }
        if let Some(stats) = ctx.system().get_helper::<SharedVerifyStats>("verify_stats") {
            stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add_buffer_work(subject_id, cloned, 0, 0);
        }
    }

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
            GovVersionLimit::Version(limit) => {
                let idx =
                    ledger.partition_point(|event| event.gov_version <= limit);
                ledger
                    .get(idx.saturating_sub(1))
                    .map(|event| event.sn.min(offered_hi_sn))
            }
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
        let delivery = delivery_of(&message);
        self.network
            .send_command(ave_network::CommandHelper::SendMessage {
                delivery,
                message: NetworkMessage::new(info, message),
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
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) -> Result<u64, ActorError> {
        // Deliberately unauthenticated: ex-witnesses and members need
        // the version to sync governance at all; only a u64 is
        // disclosed and the ledger itself stays gated.
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
    ) -> Result<(bool, bool, Option<SubjectData>), ActorError> {
        // Two independent reads, never nested handler waits: Node
        // asking SubjectAccess while it waits on Node deadlocks the
        // central actor against an in-flight Update (no timeout on
        // either `ask`). Flags come straight from SubjectAccess, data
        // straight from Node; the distributor awaits both itself.
        let access_path = ActorPath::from("/user/node/auth");
        let access_actor = ctx
            .system()
            .get_actor::<SubjectAccess>(&access_path)
            .await?;
        let access_response = access_actor
            .ask(SubjectAccessMessage::GetAccessInfo {
                subject_id: subject_id.clone(),
            })
            .await?;
        let (is_gov_authorized, is_tracker_banned) = match access_response {
            SubjectAccessResponse::AccessInfo {
                is_gov_authorized,
                is_tracker_banned,
            } => (is_gov_authorized, is_tracker_banned),
            _ => {
                return Err(ActorError::UnexpectedResponse {
                    expected: "SubjectAccessResponse::AccessInfo".to_owned(),
                    path: access_path,
                });
            }
        };

        let node_path = ActorPath::from("/user/node");
        let node_actor = ctx.system().get_actor::<Node>(&node_path).await?;
        let node_response = node_actor
            .ask(NodeMessage::GetSubjectData(subject_id.clone()))
            .await?;
        let subject_data = match node_response {
            NodeResponse::SubjectData(data) => data,
            _ => {
                return Err(ActorError::UnexpectedResponse {
                    expected: "NodeResponse::SubjectData".to_owned(),
                    path: node_path,
                });
            }
        };
        Ok((is_gov_authorized, is_tracker_banned, subject_data))
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
        let (is_gov_authorized, is_tracker_banned, subject_data) =
            self.authorized_subj(ctx, &subject_id).await?;

        if is_tracker_banned {
            return Err(DistributorError::TrackerBanned.into());
        }

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
                    None,
                )
                .await?;
                return Err(DistributorError::UpdatingSubject.into());
            }
        };

        let is_gov = schema_id.is_gov();
        if is_gov {
            if !is_gov_authorized {
                return Err(DistributorError::GovernanceNotAuthorized.into());
            }
            return Ok(CheckAuthCommon {
                subject_id,
                subject_data,
                schema_id,
                governance_id: DigestIdentifier::default(),
                namespace,
                is_gov: true,
                gov_version: 0,
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

        let gov_version =
            get_version(ctx, &governance_id).await.map_err(|e| {
                DistributorError::GetGovernanceFailed {
                    details: e.to_string(),
                }
            })?;

        if gov_version < first_ledger.gov_version {
            return Err(DistributorError::GovernanceVersionMismatch {
                our_version: gov_version,
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
            gov_version,
        })
    }

    pub(crate) async fn check_auth_batch(
        &self,
        ctx: &mut ActorContext<Self>,
        sender: PublicKey,
        ledger: &[Ledger],
        offered_hi_sn: u64,
        common: &CheckAuthCommon,
        transfer_batch: TransferBatch<'_>,
    ) -> Result<DistributionAuth, ActorError> {
        if common.is_gov {
            return Ok(DistributionAuth {
                is_gov: true,
                is_register: common.subject_data.is_some(),
                safe_hi_sn: offered_hi_sn,
            });
        }

        let CheckAuthCommon {
            subject_id,
            schema_id,
            governance_id,
            namespace,
            gov_version,
            ..
        } = common;

        // The suffix must not run ahead of our governance: the first
        // event check in check_auth_common is not enough, an inline
        // transfer could otherwise smuggle a newer gov_version.
        // Counted as visits: the scan is linear in the batch.
        #[cfg(feature = "test")]
        Self::note_auth_work(ctx, subject_id, ledger.len() as u64);
        if ledger.iter().any(|e| e.gov_version > *gov_version) {
            let their = ledger
                .iter()
                .map(|e| e.gov_version)
                .max()
                .unwrap_or(*gov_version);
            return Err(DistributorError::GovernanceVersionMismatch {
                our_version: *gov_version,
                their_version: their,
            }
            .into());
        }

        // subject_data puede haber cambiado entre iteraciones del loop de
        // LedgerDistribution (ej. subject creado en chunk anterior). Si
        // check_auth_common no lo encontró, refrescamos desde Node.
        let is_register = if common.subject_data.is_none() {
            get_subject_data(ctx, subject_id).await?.is_some()
        } else {
            true
        };

        // 1. Batch actual trae un transfer_event nuevo y la simulación dice Witness
        // (firm proof only, or passage without proof for a complete
        // but unjudgeable chain: an unproven aux never opens passage
        // here, the worker holds partial batches unapplied instead).
        if let (Some(transfer_event), Some(simulation)) =
            (transfer_batch.event, transfer_batch.simulation.as_ref())
            && matches!(
                simulation,
                TransferSimulationResult::Witness
                    | TransferSimulationResult::WitnessUnverified
            )
        {
            let chunk_first_sn =
                ledger.first().ok_or(DistributorError::EmptyEvents)?.sn;
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
        let chunk_first_sn =
            ledger.first().ok_or(DistributorError::EmptyEvents)?.sn;
        if let Some(verified_sn) = transfer_batch.verified_sn
            && chunk_first_sn <= verified_sn
        {
            return Ok(DistributionAuth {
                is_gov: false,
                is_register,
                safe_hi_sn: offered_hi_sn.min(verified_sn),
            });
        }

        // 3. Witness limits normales
        let safe_hi_sn = if is_register {
            let receiver_status = check_witness_status(
                ctx,
                governance_id,
                (*self.our_key).clone(),
                Some(subject_id.clone()),
                TrackerIdentity {
                    namespace: namespace.clone(),
                    schema_id: schema_id.clone(),
                },
                OwnerContext {
                    owner: None,
                    gov_version: None,
                },
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
            let first_ledger =
                ledger.first().ok_or(DistributorError::EmptyEvents)?;
            // Pre-authentication: an unvalidated inline transfer
            // must never authorize its own prefix. Verify every
            // inline transfer before rebuilding ownership from it.
            // Failed transfers are valid history and stay copyable:
            // they grant no ownership (the rebuild below only opens
            // it on success), so only the success proof requires
            // an Ok evaluation. Each transfer is also linked to
            // its batch predecessor up front. The map build below
            // visits every event once: counted, not moved off-book.
            #[cfg(feature = "test")]
            Self::note_auth_work(ctx, subject_id, ledger.len() as u64);
            let by_sn: HashMap<u64, &Ledger> = ledger
                .iter()
                .map(|event| (event.sn, event))
                .fold(HashMap::new(), |mut map, (sn, event)| {
                    map.entry(sn).or_insert(event);
                    map
                });
            for event in ledger.iter().filter(|e| {
                matches!(e.get_event_request_type(), EventRequestType::Transfer)
            }) {
                let prev = event
                    .sn
                    .checked_sub(1)
                    .and_then(|prev_sn| by_sn.get(&prev_sn).copied());
                self.transfer_verifier
                    .verify_light(
                        ctx,
                        event,
                        subject_id,
                        first_ledger,
                        false,
                        prev,
                    )
                    .await?;
            }
            let owner = first_ledger.ledger_seal_signature.signer.clone();
            let gov_version = first_ledger.gov_version;
            // Evidence binding: a transfer whose evaluation does not
            // reproduce over the batch prefix itself must not open
            // pending ownership. With inline transfers, rebuild
            // ownership from a screened copy where unverified ones
            // stay failed history: the batch can still be copied on
            // independent rights, and the apply backstop plus
            // first-copy rollback cover the rest. The screened copy
            // only feeds this reconstruction.
            let has_inline_transfer = ledger.iter().any(|event| {
                matches!(
                    event.get_event_request_type(),
                    EventRequestType::Transfer
                )
            });
            let transfer_data = if has_inline_transfer {
                let proven = self
                    .transfer_verifier
                    .verified_inline_transfers(
                        ctx,
                        governance_id,
                        subject_id,
                        ledger,
                    )
                    .await;
                if ledger.iter().all(|event| {
                    !matches!(
                        event.get_event_request_type(),
                        EventRequestType::Transfer
                    ) || proven.contains(&event.sn)
                }) {
                    Some(WitnessesRegister::transfer_data_from_ledger(
                        subject_id, ledger,
                    )?)
                } else {
                    let mut screened = ledger.to_vec();
                    #[cfg(feature = "test")]
                    Self::note_buffer_cloned(
                        ctx,
                        subject_id,
                        screened.len() as u64,
                    );
                    for event in screened.iter_mut().filter(|event| {
                        matches!(
                            event.get_event_request_type(),
                            EventRequestType::Transfer
                        ) && !proven.contains(&event.sn)
                    }) {
                        if let Protocols::Transfer { evaluation, .. } =
                            &mut event.protocols
                            && evaluation.is_ok()
                        {
                            use crate::evaluation::response::EvaluatorError;
                            evaluation.response = EvaluationResponse::Error {
                                result: EvaluatorError::InvalidEventSignature,
                                result_hash: DigestIdentifier::default(),
                            };
                        }
                    }
                    Some(WitnessesRegister::transfer_data_from_ledger(
                        subject_id, &screened,
                    )?)
                }
            } else {
                Some(WitnessesRegister::transfer_data_from_ledger(
                    subject_id, ledger,
                )?)
            };

            let (witness_status, receiver_window_sn, ..) =
                check_witness_status_and_window(
                    ctx,
                    governance_id,
                    subject_id,
                    transfer_data,
                    TrackerPeers {
                        node: (*self.our_key).clone(),
                        sender: sender.clone(),
                    },
                    TrackerParams {
                        namespace: namespace.clone(),
                        schema_id: schema_id.clone(),
                        actual_sn: None,
                    },
                    OwnerContext {
                        owner: Some(owner),
                        gov_version: Some(gov_version),
                    },
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

        // Cap at Confirm/Reject so distribution never runs past
        // ownership changes. The scan below visits every event
        // once per check: counted so optimizing the merge can not
        // hide work here.
        #[cfg(feature = "test")]
        Self::note_auth_work(ctx, subject_id, ledger.len() as u64);
        let safe_hi_sn = ledger
            .iter()
            .find_map(|event| {
                matches!(
                    event.get_event_request_type(),
                    EventRequestType::Confirm | EventRequestType::Reject
                )
                .then_some(event.sn)
            })
            .map_or(safe_hi_sn, |boundary| safe_hi_sn.min(boundary));

        Ok(DistributionAuth {
            is_gov: false,
            is_register,
            safe_hi_sn,
        })
    }

    /// Incremental `without_aux` authorization over staged prefix plus
    /// current batch, without flattening or rescanning the retained
    /// chain per delivery. Chain-derived facts (ownership, inline
    /// proofs, gov max, first boundary) are cached per subject and
    /// extended only with the new tail; the access decision itself
    /// is re-evaluated every time against current governance. The
    /// `offered_hi` is always the last SN of the current batch, so
    /// the current batch participates in the decision instead of
    /// authorizing only the already-held prefix.
    #[allow(clippy::too_many_arguments)]
    async fn check_auth_without_aux_incremental(
        ctx: &mut ActorContext<Self>,
        verifier: &super::transfer_verifier::TransferVerifier,
        hash: HashAlgorithm,
        our_key: &PublicKey,
        pending_auth: &mut HashMap<DigestIdentifier, PendingAuthState>,
        sender: PublicKey,
        held: &[Ledger],
        current: &[Ledger],
        offered_hi: u64,
        common: &CheckAuthCommon,
    ) -> Result<DistributionAuth, ActorError> {
        use crate::governance::witnesses_register::WitnessesRegister;
        use ave_common::bridge::request::EventRequestType;

        if common.is_gov {
            return Ok(DistributionAuth {
                is_gov: true,
                is_register: common.subject_data.is_some(),
                safe_hi_sn: offered_hi,
            });
        }
        let subject_id = &common.subject_id;
        let is_register = if common.subject_data.is_none() {
            get_subject_data(ctx, subject_id).await?.is_some()
        } else {
            true
        };
        // Gov versions must not run ahead: compare cached max plus
        // the new tail instead of rescanning the held prefix.
        let held_tip_sn = held.last().map(|event| event.sn);
        let held_tip_hash = held
            .last()
            .and_then(|event| event.ledger_hash(hash).ok());
        let state_needs_rebuild = match pending_auth.get(subject_id) {
            Some(state) => {
                state.is_register != is_register
                    || state.tip_sn != held_tip_sn
                    || match (&state.tip_hash, &held_tip_hash) {
                        (Some(cached), Some(held_hash)) => cached != held_hash,
                        _ => false,
                    }
            }
            None => true,
        };
        if state_needs_rebuild {
            let mut fresh = PendingAuthState::fresh(is_register);
            let mut max_gov = 0u64;
            let mut first_boundary: Option<u64> = None;
            let mut has_inline = false;
            let mut has_create = false;
            for event in held.iter() {
                max_gov = max_gov.max(event.gov_version);
                if event.is_create_event() {
                    has_create = true;
                }
                if matches!(
                    event.get_event_request_type(),
                    EventRequestType::Confirm | EventRequestType::Reject
                ) && first_boundary.is_none()
                {
                    first_boundary = Some(event.sn);
                }
                if matches!(
                    event.get_event_request_type(),
                    EventRequestType::Transfer
                ) {
                    has_inline = true;
                }
            }
            fresh.max_gov_version = max_gov;
            fresh.first_confirm_reject = first_boundary;
            fresh.has_inline_transfer = has_inline;
            fresh.has_create = has_create;
            fresh.tip_sn = held_tip_sn;
            fresh.tip_hash = held_tip_hash.clone();
            if !is_register && !held.is_empty() {
                let Some(create) =
                    held.iter().find(|event| event.is_create_event())
                else {
                    fresh.broken = true;
                    pending_auth.insert(subject_id.clone(), fresh);
                    #[cfg(feature = "test")]
                    Self::note_auth_work(ctx, subject_id, held.len() as u64);
                    return Err(DistributorError::ReceiverNoAccess.into());
                };
                let Some(mut metadata) =
                    super::transfer_verifier::TransferVerifier::genesis_metadata(
                        held,
                    )
                else {
                    fresh.broken = true;
                    pending_auth.insert(subject_id.clone(), fresh);
                    #[cfg(feature = "test")]
                    Self::note_auth_work(ctx, subject_id, held.len() as u64);
                    return Err(DistributorError::ReceiverNoAccess.into());
                };
                let mut roles = super::transfer_verifier::RoleCache::new();
                let tail = if held.first().is_some_and(|first| first.sn == 0) {
                    &held[1..]
                } else {
                    &held[..]
                };
                let (proven, _, _, _) = verifier
                    .verify_chain(
                        ctx,
                        &common.governance_id,
                        &mut metadata,
                        tail,
                        &mut roles,
                    )
                    .await;
                let mut data =
                    WitnessesRegister::init_transfer_data(create);
                for event in held.iter() {
                    if event.sn == create.sn {
                        continue;
                    }
                    let allow = matches!(
                        event.get_event_request_type(),
                        EventRequestType::Transfer
                    ) && proven.contains(&event.sn);
                    // Non-transfer events always apply their close
                    // logic; transfers only open when proven.
                    if matches!(
                        event.get_event_request_type(),
                        EventRequestType::Transfer
                    ) {
                        WitnessesRegister::apply_transfer_data_event(
                            &mut data,
                            event,
                            allow,
                        );
                    } else {
                        WitnessesRegister::apply_transfer_data_event(
                            &mut data, event, false,
                        );
                    }
                }
                fresh.transfer_data = Some(data);
                fresh.proven_inline = proven;
                fresh.auth_metadata = Some(metadata);
                fresh.auth_roles = roles;
            }
            pending_auth.insert(subject_id.clone(), fresh);
            #[cfg(feature = "test")]
            Self::note_auth_work(ctx, subject_id, held.len() as u64);
        }
        // Extend the cached chain facts with the current tail only.
        let current_max: u64;
        {
            let state = pending_auth
                .get_mut(subject_id)
                .ok_or(DistributorError::ReceiverNoAccess)?;
            for event in current.iter() {
                state.max_gov_version =
                    state.max_gov_version.max(event.gov_version);
                if state.first_confirm_reject.is_none()
                    && matches!(
                        event.get_event_request_type(),
                        EventRequestType::Confirm | EventRequestType::Reject
                    )
                {
                    state.first_confirm_reject = Some(event.sn);
                }
                if matches!(
                    event.get_event_request_type(),
                    EventRequestType::Transfer
                ) {
                    state.has_inline_transfer = true;
                }
                if event.is_create_event() {
                    state.has_create = true;
                }
            }
            current_max = state.max_gov_version;
            // Cryptographic link for new transfers only: the previous
            // event is either earlier in the current batch or the held
            // tip, never a rescan of the whole prefix.
            let held_has_create = state.has_create;
            for (idx, event) in current.iter().enumerate() {
                if !matches!(
                    event.get_event_request_type(),
                    EventRequestType::Transfer
                ) {
                    continue;
                }
                let prev = if idx > 0 {
                    Some(&current[idx - 1])
                } else {
                    held.last()
                };
                // verify_light needs the batch Create for metadata
                // when the subject is still unknown: prefer the held
                // Create, else the current one.
                let light_ledger = if held_has_create {
                    held.first().unwrap_or(&current[0])
                } else {
                    &current[0]
                };
                if verifier
                    .verify_light(
                        ctx,
                        event,
                        subject_id,
                        light_ledger,
                        false,
                        prev,
                    )
                    .await
                    .is_err()
                {
                    // A forged inline transfer fails the batch before
                    // any ownership is rebuilt from it. Count the tail
                    // scanned so far: the failure below must not hide
                    // work already spent.
                    #[cfg(feature = "test")]
                    Self::note_auth_work(
                        ctx,
                        subject_id,
                        current.len() as u64,
                    );
                    return Err(DistributorError::ReceiverNoAccess.into());
                }
            }
            if !is_register && !state.broken {
                // Ensure a genesis pre-state exists: either already
                // cached from the held prefix or starting in the
                // current batch.
                if state.auth_metadata.is_none() {
                    let combined_starts_with_create = held
                        .first()
                        .is_some_and(|first| {
                            first.is_create_event() && first.sn == 0
                        })
                        || current.first().is_some_and(|first| {
                            first.is_create_event() && first.sn == 0
                        });
                    if !combined_starts_with_create {
                        #[cfg(feature = "test")]
                        Self::note_auth_work(
                            ctx,
                            subject_id,
                            current.len() as u64,
                        );
                        return Err(
                            DistributorError::ReceiverNoAccess.into()
                        );
                    }
                    let combined_for_genesis: Vec<Ledger> = held
                        .iter()
                        .chain(current.iter())
                        .cloned()
                        .collect();
                    let Some(metadata) =
                        super::transfer_verifier::TransferVerifier::genesis_metadata(
                            &combined_for_genesis,
                        )
                    else {
                        state.broken = true;
                        #[cfg(feature = "test")]
                        Self::note_auth_work(
                            ctx,
                            subject_id,
                            current.len() as u64,
                        );
                        return Err(
                            DistributorError::ReceiverNoAccess.into()
                        );
                    };
                    let Some(create) = combined_for_genesis
                        .iter()
                        .find(|event| event.is_create_event())
                        .cloned()
                    else {
                        state.broken = true;
                        #[cfg(feature = "test")]
                        Self::note_auth_work(
                            ctx,
                            subject_id,
                            current.len() as u64,
                        );
                        return Err(
                            DistributorError::ReceiverNoAccess.into()
                        );
                    };
                    state.auth_metadata = Some(metadata);
                    state.auth_roles =
                        super::transfer_verifier::RoleCache::new();
                    state.transfer_data = Some(
                        WitnessesRegister::init_transfer_data(&create),
                    );
                    // Replay any held events past genesis that were
                    // skipped because metadata was missing: they are
                    // at most the held prefix once, right after the
                    // Create becomes available.
                    if !held.is_empty() {
                        let held_tail = if held.first().is_some_and(|first| {
                            first.sn == 0 && first.is_create_event()
                        }) {
                            &held[1..]
                        } else {
                            &held[..]
                        };
                        if !held_tail.is_empty() {
                            let metadata_ref = state
                                .auth_metadata
                                .as_mut()
                                .ok_or(DistributorError::ReceiverNoAccess)?;
                            let roles_ref = &mut state.auth_roles;
                            let (proven, _, _, _) = verifier
                                .verify_chain(
                                    ctx,
                                    &common.governance_id,
                                    metadata_ref,
                                    held_tail,
                                    roles_ref,
                                )
                                .await;
                            for sn in proven.iter() {
                                state.proven_inline.insert(*sn);
                            }
                            if let Some(data) =
                                state.transfer_data.as_mut()
                            {
                                for event in held_tail.iter() {
                                    let allow = matches!(
                                        event.get_event_request_type(),
                                        EventRequestType::Transfer
                                    ) && state.proven_inline.contains(&event.sn);
                                    if matches!(
                                        event.get_event_request_type(),
                                        EventRequestType::Transfer
                                    ) {
                                        WitnessesRegister::apply_transfer_data_event(
                                            data, event, allow,
                                        );
                                    } else {
                                        WitnessesRegister::apply_transfer_data_event(
                                            data, event, false,
                                        );
                                    }
                                }
                            }
                        }
                    }
                }
                if let Some(metadata) = state.auth_metadata.as_mut() {
                    let roles = &mut state.auth_roles;
                    // Replay only the uncovered tail: the batch may
                    // still carry genesis or already-verified events
                    // (first delivery, or a sender re-send), which
                    // must be skipped instead of breaking the chain.
                    let skip = current.partition_point(|event| {
                        event.sn <= metadata.sn
                    });
                    let (proven, refuted, _, _) = verifier
                        .verify_chain(
                            ctx,
                            &common.governance_id,
                            metadata,
                            &current[skip..],
                            roles,
                        )
                        .await;
                    for sn in proven.iter() {
                        state.proven_inline.insert(*sn);
                    }
                    if !refuted.is_empty() {
                        state.broken = true;
                    }
                    // Extend ownership with the new tail only,
                    // screening unverified transfers.
                    if let Some(data) = state.transfer_data.as_mut() {
                        for event in current.iter() {
                            let allow = matches!(
                                event.get_event_request_type(),
                                EventRequestType::Transfer
                            ) && state.proven_inline.contains(&event.sn);
                            if matches!(
                                event.get_event_request_type(),
                                EventRequestType::Transfer
                            ) {
                                WitnessesRegister::apply_transfer_data_event(
                                    data, event, allow,
                                );
                            } else {
                                WitnessesRegister::apply_transfer_data_event(
                                    data, event, false,
                                );
                            }
                        }
                    }
                    state.tip_sn = current.last().map(|event| event.sn);
                    state.tip_hash = current
                        .last()
                        .and_then(|event| event.ledger_hash(hash).ok());
                }
            } else if is_register {
                state.tip_sn = current.last().map(|event| event.sn);
                state.tip_hash = current
                    .last()
                    .and_then(|event| event.ledger_hash(hash).ok());
            }
            #[cfg(feature = "test")]
            Self::note_auth_work(ctx, subject_id, current.len() as u64);
        }
        if current_max > common.gov_version {
            return Err(DistributorError::GovernanceVersionMismatch {
                our_version: common.gov_version,
                their_version: current_max,
            }
            .into());
        }
        let is_register_now = if common.subject_data.is_none() {
            get_subject_data(ctx, subject_id).await?.is_some()
        } else {
            true
        };
        if is_register_now {
            let receiver_status = check_witness_status(
                ctx,
                &common.governance_id,
                (*our_key).clone(),
                Some(subject_id.clone()),
                TrackerIdentity {
                    namespace: common.namespace.clone(),
                    schema_id: common.schema_id.clone(),
                },
                OwnerContext {
                    owner: None,
                    gov_version: None,
                },
            )
            .await?;
            // Gov-version window over the combined chain without
            // rescanning held: if the cached max fits, only the new
            // tail decides; the exceeding corner reuses a frozen
            // boundary per limit version instead of rescanning on
            // every delivery.
            let (receiver_limit, _window_scanned) = {
                let state = pending_auth
                    .get_mut(subject_id)
                    .ok_or(DistributorError::ReceiverNoAccess)?;
                Self::gov_window_limit_combined(
                    state,
                    held,
                    current,
                    receiver_status.gov_version_limit,
                    offered_hi,
                )
            };
            #[cfg(feature = "test")]
            Self::note_auth_work(ctx, subject_id, _window_scanned);
            let Some(receiver_limit) = receiver_limit else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };
            let mut safe_hi_sn = receiver_limit.min(offered_hi);
            let boundary = pending_auth
                .get(subject_id)
                .and_then(|state| state.first_confirm_reject);
            if let Some(boundary) = boundary {
                safe_hi_sn = safe_hi_sn.min(boundary);
            }
            return Ok(DistributionAuth {
                is_gov: false,
                is_register: true,
                safe_hi_sn,
            });
        }
        // Unregistered: rebuild-free ownership from the cache,
        // re-evaluated against current governance every delivery.
        let (transfer_data, first_event) = {
            let state = pending_auth
                .get(subject_id)
                .ok_or(DistributorError::ReceiverNoAccess)?;
            let Some(data) = state.transfer_data.clone() else {
                return Err(DistributorError::ReceiverNoAccess.into());
            };
            let first = held
                .first()
                .or_else(|| current.first())
                .cloned()
                .ok_or(DistributorError::ReceiverNoAccess)?;
            (data, first)
        };
        let owner = first_event.ledger_seal_signature.signer.clone();
        let gov_version = first_event.gov_version;
        let (witness_status, receiver_window_sn, ..) =
            check_witness_status_and_window(
                ctx,
                &common.governance_id,
                subject_id,
                Some(transfer_data),
                TrackerPeers {
                    node: (*our_key).clone(),
                    sender: sender.clone(),
                },
                TrackerParams {
                    namespace: common.namespace.clone(),
                    schema_id: common.schema_id.clone(),
                    actual_sn: None,
                },
                OwnerContext {
                    owner: Some(owner),
                    gov_version: Some(gov_version),
                },
            )
            .await?;
        let receiver_hi_limit =
            Self::concrete_hi_sn_limit(witness_status.hi_sn_limit, offered_hi);
        let (receiver_create_gov_limit, _window_scanned) = {
            let state = pending_auth
                .get_mut(subject_id)
                .ok_or(DistributorError::ReceiverNoAccess)?;
            Self::gov_window_limit_combined(
                state,
                held,
                current,
                witness_status.create_gov_version_limit,
                offered_hi,
            )
        };
        #[cfg(feature = "test")]
        Self::note_auth_work(ctx, subject_id, _window_scanned);
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
        let mut safe_hi_sn = receiver_limit.min(offered_hi);
        if let Some(boundary) = pending_auth
            .get(subject_id)
            .and_then(|state| state.first_confirm_reject)
        {
            safe_hi_sn = safe_hi_sn.min(boundary);
        }
        Ok(DistributionAuth {
            is_gov: false,
            is_register: false,
            safe_hi_sn,
        })
    }

    /// Gov-version window over held plus current without flattening:
    /// when every held event fits, only the new tail is scanned
    /// (`partition_point` over `current`, logarithmic probes
    /// uncounted). Once the retained chain outgrows the limit, later
    /// events can only share the same or a higher gov version
    /// (chain order), so the boundary is frozen per limit version
    /// and reused O(1) instead of rescanning the retained prefix
    /// on every delivery. Prune, take, drop and eviction discard
    /// the whole auth cache entry, so a frozen boundary can never
    /// outlive the prefix it was computed over; a narrower limit
    /// after a governance change recomputes once. Returns the
    /// limit and the number of scanned events, so the single scan
    /// stays instrumented instead of moving work off-counters.
    #[allow(clippy::too_many_arguments)]
    fn gov_window_limit_combined(
        state: &mut PendingAuthState,
        held: &[Ledger],
        current: &[Ledger],
        limit: GovVersionLimit,
        offered_hi_sn: u64,
    ) -> (Option<u64>, u64) {
        match limit {
            GovVersionLimit::None => (None, 0),
            GovVersionLimit::Infinity => (Some(offered_hi_sn), 0),
            GovVersionLimit::Version(version) => {
                if state.max_gov_version <= version {
                    let idx = current
                        .partition_point(|event| event.gov_version <= version);
                    if idx == 0 {
                        if held.is_empty() {
                            (None, 0)
                        } else {
                            (
                                held.last()
                                    .map(|event| event.sn.min(offered_hi_sn)),
                                0,
                            )
                        }
                    } else {
                        (
                            current
                                .get(idx - 1)
                                .map(|event| event.sn.min(offered_hi_sn)),
                            0,
                        )
                    }
                } else if let Some((cached_version, cached)) =
                    state.frozen_gov_window
                    && cached_version == version
                {
                    (cached.map(|sn| sn.min(offered_hi_sn)), 0)
                } else {
                    // Single full scan per limit version: it breaks at
                    // the first event past the window (fail-closed on
                    // non-monotonic input), and later deliveries reuse
                    // the frozen result above.
                    let mut combined_sn: Option<u64> = None;
                    let mut scanned = 0u64;
                    for event in held.iter().chain(current.iter()) {
                        scanned += 1;
                        if event.gov_version <= version {
                            combined_sn = Some(event.sn);
                        } else {
                            break;
                        }
                    }
                    state.frozen_gov_window = Some((version, combined_sn));
                    (combined_sn.map(|sn| sn.min(offered_hi_sn)), scanned)
                }
            }
        }
    }

    pub(crate) async fn check_auth_single(
        &mut self,
        ctx: &mut ActorContext<Self>,
        sender: PublicKey,
        info: &ComunicateInfo,
        ledger: &[Ledger],
        offered_hi_sn: u64,
        attempt: u64,
    ) -> Result<DistributionAuth, ActorError> {
        let common = self
            .check_auth_common(ctx, sender.clone(), info, ledger)
            .await?;
        if common.is_gov {
            return Ok(DistributionAuth {
                is_gov: true,
                is_register: common.subject_data.is_some(),
                safe_hi_sn: offered_hi_sn,
            });
        }

        let CheckAuthCommon {
            subject_id,
            subject_data,
            schema_id,
            governance_id,
            namespace,
            ..
        } = common;
        let first_ledger =
            ledger.first().ok_or(DistributorError::EmptyEvents)?;

        if subject_data.is_none() && !first_ledger.is_create_event() {
            self.request_ledger_from_sender(
                ctx,
                &subject_id,
                sender.clone(),
                info,
                None,
                subject_data.clone(),
            )
            .await?;
            return Err(DistributorError::UpdatingSubject.into());
        }

        if matches!(
            first_ledger.get_event_request_type(),
            EventRequestType::Transfer
        ) {
            // Same bar as the batch path: cryptographic verification
            // plus simulation, not simulation alone. An unproven aux
            // grants nothing and fails closed without writing; a
            // refuted one rolls back and fails.
            let single_buffered = self.deferred.view(&subject_id);
            match self
                .transfer_verifier
                .verify_and_simulate(
                    &mut self.verify_cursors,
                    ctx,
                    &subject_id,
                    ledger,
                    first_ledger,
                    single_buffered,
                )
                .await?
            {
                TransferSimulationResult::Witness
                | TransferSimulationResult::WitnessUnverified => {}
                TransferSimulationResult::WitnessUnproven => {
                    return Err(DistributorError::ReceiverNoAccess.into());
                }
                TransferSimulationResult::Refuted => {
                    self.rollback_refuted_aux(
                        ctx,
                        &governance_id,
                        &subject_id,
                        first_ledger.sn,
                        attempt,
                    )
                    .await;
                    return Err(DistributorError::ReceiverNoAccess.into());
                }
                TransferSimulationResult::NotWitness => {
                    return Err(DistributorError::ReceiverNoAccess.into());
                }
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
                Some(subject_id.clone()),
                TrackerIdentity {
                    namespace: namespace.clone(),
                    schema_id: schema_id.clone(),
                },
                OwnerContext {
                    owner: None,
                    gov_version: None,
                },
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
            // Same pre-authentication bar as batches: a lone inline
            // transfer is verified before rebuilding ownership from
            // it (no batch predecessor exists for the link check).
            if matches!(
                first_ledger.get_event_request_type(),
                EventRequestType::Transfer
            ) {
                self.transfer_verifier
                    .verify_light(
                        ctx,
                        first_ledger,
                        &subject_id,
                        first_ledger,
                        false,
                        None,
                    )
                    .await?;
            }
            let transfer_data =
                Some(WitnessesRegister::transfer_data_from_ledger(
                    &subject_id,
                    ledger,
                )?);

            let (witness_status, receiver_window_sn, ..) =
                check_witness_status_and_window(
                    ctx,
                    &governance_id,
                    &subject_id,
                    transfer_data,
                    TrackerPeers {
                        node: (*self.our_key).clone(),
                        sender: sender.clone(),
                    },
                    TrackerParams {
                        namespace: namespace.clone(),
                        schema_id: schema_id.clone(),
                        actual_sn: None,
                    },
                    OwnerContext {
                        owner: Some(owner),
                        gov_version: Some(gov_version),
                    },
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
        let safe_hi_sn = ledger
            .iter()
            .find_map(|event| {
                matches!(
                    event.get_event_request_type(),
                    EventRequestType::Confirm | EventRequestType::Reject
                )
                .then_some(event.sn)
            })
            .map_or(safe_hi_sn, |boundary| safe_hi_sn.min(boundary));

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

    pub(crate) async fn get_tracker_window(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        actual_sn: Option<u64>,
        data: &SubjectData,
    ) -> Result<
        (u64, Option<u64>, Option<u64>, Vec<TrackerDeliveryRange>),
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

        let (sn, transfer_sn, clear_sn, ranges) = resolve_tracker_window(
            ctx,
            governance_id,
            subject_id,
            sender.clone(),
            (*self.our_key).clone(),
            TrackerParams {
                namespace: namespace.clone(),
                schema_id: schema_id.clone(),
                actual_sn,
            },
        )
        .await?;

        let Some(sn) = sn else {
            let witness_status = check_witness_status(
                ctx,
                governance_id,
                sender.clone(),
                Some(subject_id.clone()),
                TrackerIdentity {
                    namespace: namespace.clone(),
                    schema_id: schema_id.clone(),
                },
                OwnerContext {
                    owner: None,
                    gov_version: None,
                },
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

        Ok((sn, transfer_sn, clear_sn, ranges))
    }

    fn project_tracker_ledger(
        ledger: Vec<Ledger>,
        ranges: &[TrackerDeliveryRange],
    ) -> Result<Vec<Ledger>, ActorError> {
        let mut projected = Vec::with_capacity(ledger.len());
        let mut range_idx = 0;

        for event in ledger {
            while range_idx < ranges.len() && ranges[range_idx].to_sn < event.sn
            {
                range_idx += 1;
            }

            let mode = if range_idx < ranges.len()
                && ranges[range_idx].from_sn <= event.sn
            {
                ranges[range_idx].mode.clone()
            } else {
                let coverage = ranges
                    .iter()
                    .map(|r| format!("{}-{}:{:?}", r.from_sn, r.to_sn, r.mode))
                    .collect::<Vec<_>>()
                    .join(",");
                return Err(ActorError::Functional {
                    description: format!(
                        "Missing tracker delivery range for sn {} (ranges: [{}])",
                        event.sn, coverage
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
                    Some(subject_id.clone()),
                    TrackerIdentity {
                        namespace: namespace.clone(),
                        schema_id: schema_id.clone(),
                    },
                    OwnerContext {
                        owner: None,
                        gov_version: None,
                    },
                )
                .await?;

                let Some(sn) = witness_status.access_sn else {
                    return Err(DistributorError::SenderNoAccess.into());
                };

                Ok((sn, false))
            }
            SubjectData::Governance { .. } => {
                let is_witness = has_role(
                    ctx,
                    subject_id,
                    HashThisRole::Gov {
                        who: sender.clone(),
                        role: RoleTypes::Witness,
                    },
                )
                .await
                .map_err(|e| {
                    DistributorError::GetGovernanceFailed {
                        details: e.to_string(),
                    }
                })?;

                if !is_witness {
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
                let (sn, _, clear_sn, ranges) = self
                    .get_tracker_window(
                        ctx,
                        subject_id,
                        sender.clone(),
                        actual_sn,
                        &data,
                    )
                    .await?;
                // The updater only ever consults the range covering its
                // next SN (next_tracker_range): shipping the whole suffix
                // wastes the 1 MiB wire budget on ranges no one reads.
                // Ranges are contiguous from from_sn, so the head always
                // covers the requester's next event; a stale offer simply
                // stops matching and the next sweep re-offers.
                let ranges = ranges.into_iter().take(1).collect();
                Ok(UpdateWitnessOffer {
                    kind: UpdateSubjectKind::Tracker,
                    sn,
                    clear_sn,
                    ranges,
                })
            }
            SubjectData::Governance { .. } => {
                let (sn, ..) = self
                    .check_witness(ctx, subject_id, sender.clone(), &data)
                    .await?;
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
                let (window_sn, transfer_sn, clear_sn, ranges) = self
                    .get_tracker_window(
                        ctx,
                        subject_id,
                        sender.clone(),
                        actual_sn,
                        &data,
                    )
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
                    .saturating_add(Self::capped_batch_size(
                        self.ledger_batch_size,
                    ))
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
                        let idx = ledger
                            .partition_point(|event| event.sn < transfer_sn);
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
                            event_ledger.pop()
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
                    .saturating_add(Self::capped_batch_size(
                        self.ledger_batch_size,
                    ))
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

    /// Tip of the deferred (received but unapplied) prefix for a
    /// subject, if any. Deferred batches never count as applied
    /// state; they only let the receiver ask for the continuation
    /// instead of replaying what it already holds.
    pub(crate) fn deferred_tip(
        &self,
        subject_id: &DigestIdentifier,
    ) -> Option<u64> {
        self.deferred.tip(subject_id)
    }

    /// Prunes staged events at or below the applied tip, then
    /// reports the retained counters for the test-only stats. The
    /// prune itself is a partition over the ascending buffer, not
    /// a re-sort. A prune that drops events invalidates the
    /// incremental auth state covering them.
    pub(crate) fn prune_deferred(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        applied_tip: Option<u64>,
    ) {
        let dropped = self.deferred.prune(subject_id, applied_tip);
        if dropped > 0 {
            self.pending_auth.remove(subject_id);
        }
        #[cfg(feature = "test")]
        {
            Self::note_deferred_stats(ctx, &self.deferred, subject_id);
            if dropped > 0 {
                Self::note_auth_work(ctx, subject_id, dropped);
            }
        }
        let _ = ctx;
    }

    /// Stages a batch whose aux can not be checked yet: it is held
    /// unapplied (deduplicated, pruned past the applied tip) until
    /// a later batch completes the evidence chain. The ingress
    /// `ensure` gate only lets the direct continuation through, so
    /// every incoming event is newer than everything staged:
    /// appending keeps the order with no scan and no re-sort.
    pub(crate) fn stage_deferred(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        batch: Vec<Ledger>,
        applied_tip: Option<u64>,
    ) -> Vec<DigestIdentifier> {
        debug_assert!(
            batch.windows(2).all(|w| w[0].sn < w[1].sn),
            "staged batches must arrive strictly ascending"
        );
        #[cfg(feature = "test")]
        let staged_len = batch.len() as u64;
        let evicted =
            self.deferred.stage(subject_id, batch, applied_tip);
        for evicted_subject in &evicted {
            self.verify_cursors.invalidate(evicted_subject);
            self.pending_auth.remove(evicted_subject);
        }
        #[cfg(feature = "test")]
        {
            Self::note_deferred_stats(ctx, &self.deferred, subject_id);
            for evicted_subject in &evicted {
                Self::note_deferred_stats(ctx, &self.deferred, evicted_subject);
            }
            Self::note_auth_work(ctx, subject_id, staged_len);
        }
        let _ = ctx;
        evicted
    }

    /// Moves the live staged prefix out for the apply path. The
    /// store forgets it: every exit from the apply loop either
    /// applied it, rolled the copy back (which drops leftovers),
    /// or fails the batch (whose sender re-sends anything still
    /// needed). The incremental auth state covering it goes with
    /// it: the next delivery rebuilds from the new tip.
    pub(crate) fn take_deferred_prefix(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        applied_tip: Option<u64>,
    ) -> Vec<Ledger> {
        let (prefix, _moved) = self.deferred.take(subject_id, applied_tip);
        self.pending_auth.remove(subject_id);
        #[cfg(feature = "test")]
        {
            Self::note_deferred_stats(ctx, &self.deferred, subject_id);
            // The take drains the dead head in place: surviving
            // events shift once, and only when a dead head exists.
            // Count the real moves as visits so the buffer totals
            // stay exact instead of hiding work.
            Self::note_auth_work(ctx, subject_id, _moved);
        }
        let _ = ctx;
        prefix
    }

    /// Drops deferred state for a subject: its chain proved forged
    /// or its copy is being rolled back, so nothing staged may be
    /// applied later. The sender re-sends anything still needed.
    pub(crate) fn drop_deferred(
        &mut self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        self.deferred.drop(subject_id);
        self.pending_auth.remove(subject_id);
        #[cfg(feature = "test")]
        Self::note_deferred_stats(ctx, &self.deferred, subject_id);
        let _ = ctx;
    }

    pub(crate) async fn request_ledger_from_sender(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sender: PublicKey,
        info: &ComunicateInfo,
        actual_sn: Option<u64>,
        subject_data: Option<SubjectData>,
    ) -> Result<(), ActorError> {
        let verified = match subject_data {
            Some(SubjectData::Tracker { governance_id, .. }) => {
                match get_verified_transfer_sn_firm(
                    ctx,
                    &governance_id,
                    subject_id,
                )
                .await
                {
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
                match get_verified_transfer_sn_firm(ctx, subject_id, subject_id)
                    .await
                {
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

        // Deferred batches count as held, never as applied: the next
        // expected sn continues past both.
        let buffered_tip = self.deferred_tip(subject_id);
        if subject_data.is_some() {
            let Some(local_sn) = get_local_subject_sn(ctx, subject_id).await?
            else {
                self.request_ledger_from_sender(
                    ctx,
                    subject_id,
                    sender,
                    info,
                    None,
                    subject_data.clone(),
                )
                .await?;
                return Ok(false);
            };
            let held_tip = local_sn.max(buffered_tip.unwrap_or(0));
            // Without any applied or deferred event only sn 0 may
            // start a copy; otherwise the continuation follows the
            // furthest held tip, deferred or applied alike.
            let expected_sn = if local_sn == 0 && buffered_tip.is_none() {
                1
            } else {
                held_tip.saturating_add(1)
            };

            if received_first_sn <= held_tip {
                // Stale head but possibly fresh tail (race with a
                // concurrent push): ask from our tip instead of
                // dropping the newer events with the batch.
                debug!(
                    msg_type = "EnsureNextSn",
                    subject_id = %subject_id,
                    local_last_sn = local_sn,
                    received_first_sn = received_first_sn,
                    "Stale batch head, requesting from local tip"
                );

                self.request_ledger_from_sender(
                    ctx,
                    subject_id,
                    sender.clone(),
                    info,
                    Some(held_tip),
                    subject_data.clone(),
                )
                .await?;

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
                    Some(held_tip),
                    subject_data.clone(),
                )
                .await?;

                return Ok(false);
            }
        } else if let Some(buffered_tip) = buffered_tip {
            // Nothing applied yet, but a deferred prefix is held:
            // only its direct continuation may proceed, and it still
            // needs its evidence checked downstream.
            if received_first_sn != buffered_tip.saturating_add(1) {
                debug!(
                    subject_id = %subject_id,
                    received_first_sn = received_first_sn,
                    expected_sn = buffered_tip.saturating_add(1),
                    "Gap past the deferred prefix, requesting update"
                );

                self.request_ledger_from_sender(
                    ctx,
                    subject_id,
                    sender,
                    info,
                    Some(buffered_tip),
                    subject_data.clone(),
                )
                .await?;

                return Ok(false);
            }
        } else {
            if received_first_sn != 0 {
                debug!(
                    msg_type = "EnsureNextSn",
                    subject_id = %subject_id,
                    received_first_sn = received_first_sn,
                    "Subject not present locally and first SN is not 0, requesting update"
                );

                self.request_ledger_from_sender(
                    ctx, subject_id, sender, info, None, None,
                )
                .await?;

                return Ok(false);
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
        ctx: &ActorContext<Self>,
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
        info: ComunicateInfo,
        subject_id: DigestIdentifier,
        sender: PublicKey,
        range: DistributionRange,
    ) -> Result<(), ActorError> {
        let (ledger, is_all, hi_sn, transfer_event) = self
            .build_distribution_batch(
                ctx,
                &subject_id,
                sender.clone(),
                range.actual_sn,
                range.target_sn,
                range.already_verified_transfer_sn,
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
                transfer_event: transfer_event.map(Box::new),
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
            actual_sn = ?range.actual_sn,
            "Ledger distribution sent successfully"
        );

        Ok(())
    }

    /// Processes an inbound ledger batch under the shared distribution
    /// error policy: `FunctionalCritical` fails the node loud (like the
    /// last-event path) instead of being discarded in the tell handler.
    async fn handle_ledger_distribution(
        &mut self,
        ctx: &mut ActorContext<Self>,
        mut ledger: Vec<Ledger>,
        is_all: bool,
        transfer_event: Option<Box<Ledger>>,
        info: ComunicateInfo,
        sender: PublicKey,
    ) -> Result<(), ActorError> {
        {}
        if ledger.is_empty() {
            warn!(
                msg_type = "LedgerDistribution",
                sender = %sender,
                "Empty ledger batch rejected"
            );
            if let Some(metrics) = crate::metrics::try_core_metrics() {
                metrics.observe_distribution_failure("empty_batch");
            }
            return Err(DistributorError::EmptyEvents.into());
        }
        // Bound inbound batch size before spending auth/verify CPU:
        // the store itself rejects oversized ranges, and honest
        // batches stay near ledger_batch_size. Oversized batches
        // are dropped.
        if ledger.len()
            > crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS
        {
            warn!(
                msg_type = "LedgerDistribution",
                sender = %sender,
                ledger_count = ledger.len(),
                "Oversized ledger batch rejected"
            );
            if let Some(metrics) = crate::metrics::try_core_metrics() {
                metrics.observe_distribution_failure("oversized_batch");
            }
            return Err(DistributorError::ReceiverNoAccess.into());
        }
        if !ledger.windows(2).all(|w| w[0].sn <= w[1].sn) {
            ledger.sort_by_key(|event| event.sn);
        }
        // Extra temprano: el ledger solo acepta el siguiente sn, pero
        // un hueco/duplicado aquí se rechaza antes de gastar auth.
        if !ledger
            .windows(2)
            .all(|w| w[0].sn.checked_add(1) == Some(w[1].sn))
        {
            warn!(
                msg_type = "LedgerDistribution",
                sender = %sender,
                ledger_count = ledger.len(),
                "Non-contiguous ledger batch rejected"
            );
            if let Some(metrics) = crate::metrics::try_core_metrics() {
                metrics.observe_distribution_failure("gapped_batch");
            }
            return Err(DistributorError::ReceiverNoAccess.into());
        }
        // All events must belong to the same subject before any
        // auth or ownership work: a transfer from another subject
        // must never authorize this batch.
        let first_subject = ledger[0].get_subject_id();
        if ledger.iter().any(|e| e.get_subject_id() != first_subject) {
            warn!(
                msg_type = "LedgerDistribution",
                sender = %sender,
                "Mixed-subject ledger batch rejected"
            );
            if let Some(metrics) = crate::metrics::try_core_metrics() {
                metrics.observe_distribution_failure("mixed_subject");
            }
            return Err(DistributorError::MixedSubjectBatch.into());
        }

        let subject_id = ledger[0].get_subject_id();
        let ledger_count = ledger.len();
        let first_sn = ledger[0].sn;
        let attempt = self.attempt_clock.fetch_add(1, Ordering::SeqCst);

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

        // A continuation past a held prefix carries its Create in
        // the buffer: authorize against the held chain so a Fact-only
        // tail can still be gated and flushed in order instead of
        // failing for a missing subject it never creates alone. The
        // held view is pruned once here and borrowed below for both
        // authorization and evidence; nothing re-reads or clones
        // the buffer again in this delivery. Registered subjects
        // keep their local metadata for auth but still hand the
        // held prefix to the evidence check, so a cursor eviction
        // can never hide staged events from the rebuild.
        let applied_for_held =
            get_local_subject_sn(ctx, &subject_id).await.ok().flatten();
        self.prune_deferred(ctx, &subject_id, applied_for_held);
        let held_view = self.deferred.view(&subject_id);
        let held_prefix: &[Ledger] = if held_view
            .last()
            .is_some_and(|last| last.sn.saturating_add(1) == first_sn)
        {
            held_view
        } else {
            &[]
        };
        // Hold the registration flag for the auth-source choice
        // below: an unknown subject needs the held Create to
        // resolve its metadata, a registered one authenticates
        // from its local record while the verifier still sees the
        // staged prefix.
        let has_subject = get_subject_data(ctx, &subject_id)
            .await
            .ok()
            .flatten()
            .is_some();
        let common = if !held_prefix.is_empty() && !has_subject {
            self.check_auth_common(ctx, sender.clone(), &info, held_prefix)
                .await?
        } else {
            self.check_auth_common(ctx, sender.clone(), &info, &ledger)
                .await?
        };
        let subject_id = ledger[0].get_subject_id();

        let mut transfer_simulation = if let Some(ref transfer_event) =
            transfer_event
        {
            if !common.is_gov {
                if transfer_event.gov_version > common.gov_version {
                    return Err(DistributorError::GovernanceVersionMismatch {
                        our_version: common.gov_version,
                        their_version: transfer_event.gov_version,
                    }
                    .into());
                }
                // Deferred batches held for this subject count as
                // prefix when rechecking the aux below. The view was
                // pruned once above and is borrowed, not cloned.
                match self
                    .transfer_verifier
                    .verify_and_simulate(
                        &mut self.verify_cursors,
                        ctx,
                        &subject_id,
                        &ledger,
                        transfer_event,
                        held_prefix,
                    )
                    .await?
                {
                    TransferSimulationResult::Witness => {
                        Some(TransferSimulationResult::Witness)
                    }
                    // Unproven aux: the chain is incomplete, so the
                    // batch is held unapplied until the missing events
                    // arrive. Unverifiable aux chains (complete but
                    // unjudgeable) flow through below instead: like
                    // the apply path, they open passage without ever
                    // recording a proof.
                    TransferSimulationResult::WitnessUnproven => {
                        Some(TransferSimulationResult::WitnessUnproven)
                    }
                    TransferSimulationResult::WitnessUnverified => {
                        Some(TransferSimulationResult::WitnessUnverified)
                    }
                    // Refuted aux: forged hint with a checkable chain.
                    // Drop any held prefix it poisoned, then fail
                    // without writing anything new.
                    TransferSimulationResult::Refuted => {
                        self.drop_deferred(ctx, &subject_id);
                        self.rollback_refuted_aux(
                            ctx,
                            &common.governance_id,
                            &subject_id,
                            transfer_event.sn,
                            attempt,
                        )
                        .await;
                        return Err(DistributorError::ReceiverNoAccess.into());
                    }
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
        // An unproven aux never opens passage nor records
        // anything, however the sender flags the batch. When the
        // prefix is authorized on its own rights, copy it now
        // without any proof and let a later batch verify the aux;
        // otherwise hold the batch unapplied and ask for the
        // continuation instead. A later batch with the full chain
        // verifies or refutes; silence leaves no trace behind.
        // The decision covers staged prefix plus current batch in
        // order, with the current tail end as the offered tip, and
        // runs incrementally over the new tail only.
        if transfer_simulation
            == Some(TransferSimulationResult::WitnessUnproven)
        {
            let offered_hi = ledger
                .last()
                .map(|event| event.sn)
                .unwrap_or(first_sn);
            // Borrow disjoint fields at once: the held view for the
            // chain, the verifier and keys for the check, and the
            // auth cache mutably for the incremental state.
            let without_aux = Self::check_auth_without_aux_incremental(
                ctx,
                &self.transfer_verifier,
                self.hash,
                &self.our_key,
                &mut self.pending_auth,
                sender.clone(),
                held_prefix,
                &ledger,
                offered_hi,
                &common,
            )
            .await;
            let prefix_open = matches!(without_aux, Ok(auth)
                if auth.safe_hi_sn >= first_sn);
            if prefix_open {
                transfer_simulation = None;
            } else {
                let applied_tip =
                    get_local_subject_sn(ctx, &subject_id).await.ok().flatten();
                let evicted = self.stage_deferred(
                    ctx,
                    &subject_id,
                    ledger,
                    applied_tip,
                );
                for evicted_subject in &evicted {
                    self.verify_cursors.invalidate(evicted_subject);
                    self.pending_auth.remove(evicted_subject);
                }
                let from_sn = applied_tip.max(self.deferred_tip(&subject_id));
                self.request_ledger_from_sender(
                    ctx,
                    &subject_id,
                    sender,
                    &info,
                    from_sn,
                    common.subject_data.clone(),
                )
                .await?;
                return Ok(());
            }
        }

        let verified_transfer_sn = if !common.is_gov {
            match get_verified_transfer_sn_firm(
                ctx,
                &common.governance_id,
                &subject_id,
            )
            .await
            {
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
            &common,
            TransferBatch {
                event: transfer_event.as_deref(),
                simulation: transfer_simulation,
                verified_sn: verified_transfer_sn,
            },
            DistributionContext {
                info,
                sender: sender.clone(),
                subject_id: subject_id.clone(),
                sender_is_all,
                ledger_count,
                attempt,
            },
        )
        .await?;

        debug!(
            msg_type = "LedgerDistribution",
            subject_id = %subject_id,
            sender = %sender,
            ledger_count = ledger_count,
            is_all = is_all,
            "Ledger distribution processed successfully"
        );

        Ok(())
    }
}

#[async_trait]
impl Actor for DistriWorker {
    type Event = ();
    type Message = DistriWorkerMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

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
        transfer_event: Option<Box<Ledger>>,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    /// Test-only fault injection: the next visibility lookup for
    /// this worker fails (`empty == false`) or returns no modes
    /// (`empty == true`), exercising the fail-closed receipt paths.
    /// One-shot and local to this worker; production never sets it.
    #[cfg(feature = "test")]
    TestFailNextModes { empty: bool },
    /// Test-only fault injection: the next evidence-ledger reload
    /// fails its tracker resolve right after a successful `Up`,
    /// exercising the lease release on that path. One-shot and
    /// local to this worker; production never sets it.
    #[cfg(feature = "test")]
    TestFailNextTrackerResolve,
    /// Test-only deferred-store bounds: replaces this worker's
    /// limits (subjects, events and bytes, per subject and global)
    /// so a test can trigger overflow with a handful of events.
    /// Production always uses the compiled-in defaults.
    #[cfg(feature = "test")]
    TestSetDeferredLimits {
        limits: super::deferred::DeferredLimits,
    },
    /// Test-only cursor eviction: drops the saved verification
    /// prefix for one subject, with the same effect as an LRU
    /// eviction, while keeping any staged prefix. Lets a test
    /// prove the rebuild path rejoins the deferred chain.
    #[cfg(feature = "test")]
    TestEvictVerifyCursor {
        subject_id: DigestIdentifier,
    },
}

impl Message for DistriWorkerMessage {}

impl NotPersistentActor for DistriWorker {}

#[async_trait]
impl Handler<Self> for DistriWorker {
    async fn handle_message(
        &mut self,
        _: ActorPath,
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
                        return Err(crash_system(ctx, e).await);
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
                        info,
                        subject_id.clone(),
                        sender.clone(),
                        DistributionRange {
                            actual_sn,
                            target_sn,
                            already_verified_transfer_sn,
                        },
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
                self.process_last_event_distribution(
                    ctx, *ledger, info, sender,
                )
                .await?;
            }
            DistriWorkerMessage::LedgerDistribution {
                ledger,
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
                let subject_id = ledger[0].get_subject_id();
                let result = self
                    .handle_ledger_distribution(
                        ctx,
                        ledger,
                        is_all,
                        transfer_event,
                        info,
                        sender.clone(),
                    )
                    .await;
                handle_distri_error!(
                    ctx,
                    result,
                    "LedgerDistribution",
                    subject_id,
                    "Ledger distribution failed",
                    sender = &sender
                )?;
            }
            #[cfg(feature = "test")]
            DistriWorkerMessage::TestFailNextModes { empty } => {
                let code = u8::from(empty) + 1;
                self.test_modes_fault
                    .store(code, std::sync::atomic::Ordering::SeqCst);
                debug!(
                    msg_type = "TestFailNextModes",
                    empty = empty,
                    "Armed one-shot visibility fault"
                );
            }
            #[cfg(feature = "test")]
            DistriWorkerMessage::TestSetDeferredLimits { limits } => {
                let evicted = self.deferred.set_limits(limits);
                for evicted_subject in &evicted {
                    self.verify_cursors.invalidate(evicted_subject);
                    self.pending_auth.remove(evicted_subject);
                }
                for subject_id in evicted {
                    Self::note_deferred_stats(ctx, &self.deferred, &subject_id);
                }
                debug!(
                    msg_type = "TestSetDeferredLimits",
                    max_subjects = limits.max_subjects,
                    max_events_per_subject = limits.max_events_per_subject,
                    max_bytes_per_subject = limits.max_bytes_per_subject,
                    max_events_global = limits.max_events_global,
                    max_bytes_global = limits.max_bytes_global,
                    "Deferred store bounds replaced for tests"
                );
            }
            #[cfg(feature = "test")]
            DistriWorkerMessage::TestFailNextTrackerResolve => {
                self.transfer_verifier.test_tracker_resolve_fault.store(
                    1,
                    std::sync::atomic::Ordering::SeqCst,
                );
                debug!(
                    msg_type = "TestFailNextTrackerResolve",
                    "Armed one-shot tracker resolve fault"
                );
            }
            #[cfg(feature = "test")]
            DistriWorkerMessage::TestEvictVerifyCursor { subject_id } => {
                self.verify_cursors.invalidate(&subject_id);
                debug!(
                    msg_type = "TestEvictVerifyCursor",
                    subject_id = %subject_id,
                    "Verify cursor evicted for tests"
                );
            }
        };

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use ave_common::identity::{
        TimeStamp,
        keys::{DSAlgorithm, SignatureIdentifier},
    };

    use crate::model::event::{
        EvaluationDataOpaque, EvaluationResponseOpaque, OpaqueData,
        ValidationData, ValidationMetadata,
    };

    fn window_ledger(sn: u64, gov_version: u64) -> Ledger {
        let key = PublicKey::new(DSAlgorithm::Ed25519, vec![0u8; 32]).unwrap();
        let sig = ave_common::identity::Signature {
            signer: key.clone(),
            timestamp: TimeStamp::from_nanos(0),
            content_hash: DigestIdentifier::default(),
            value: SignatureIdentifier::new(
                DSAlgorithm::Ed25519,
                vec![0u8; 64],
            )
            .unwrap(),
        };
        Ledger {
            gov_version,
            sn,
            prev_ledger_event_hash: DigestIdentifier::default(),
            ledger_seal_signature: sig.clone(),
            protocols: Protocols::TrackerFactOpaque {
                event_request_hash: DigestIdentifier::default(),
                evaluation: EvaluationDataOpaque {
                    eval_req_signature: sig.clone(),
                    eval_req_hash: DigestIdentifier::default(),
                    evaluators_signatures: Vec::new(),
                    viewpoints: BTreeSet::new(),
                    response: EvaluationResponseOpaque::Ok {
                        result_hash: DigestIdentifier::default(),
                    },
                },
                validation: ValidationData {
                    validation_req_signature: sig.clone(),
                    validation_req_hash: DigestIdentifier::default(),
                    validators_signatures: Vec::new(),
                    validation_metadata:
                        ValidationMetadata::ModifiedHash {
                            modified_metadata_without_propierties_hash:
                                DigestIdentifier::default(),
                            propierties_hash: DigestIdentifier::default(),
                            event_request_hash: DigestIdentifier::default(),
                            viewpoints_hash: DigestIdentifier::default(),
                        },
                },
                data: OpaqueData {
                    subject_id: DigestIdentifier::default(),
                    event_request_timestamp: TimeStamp::from_nanos(0),
                    signer: key,
                },
            },
        }
    }

    #[test]
    fn frozen_gov_window_scans_once_then_reuses() {
        let mut state = PendingAuthState::fresh(false);
        state.max_gov_version = 2;
        let held =
            vec![window_ledger(0, 1), window_ledger(1, 2)];
        let current = vec![window_ledger(2, 2)];
        let (first, scanned) = DistriWorker::gov_window_limit_combined(
            &mut state,
            &held,
            &current,
            GovVersionLimit::Version(1),
            2,
        );
        assert_eq!(first, Some(0), "the boundary stops before gov 2");
        assert!(scanned > 0, "the first exceeding scan is counted");
        let (second, rescanned) = DistriWorker::gov_window_limit_combined(
            &mut state,
            &held,
            &current,
            GovVersionLimit::Version(1),
            2,
        );
        assert_eq!(second, first, "the frozen boundary is stable");
        assert_eq!(rescanned, 0, "the hit is O(1)");
        let (wider, _) = DistriWorker::gov_window_limit_combined(
            &mut state,
            &held,
            &current,
            GovVersionLimit::Version(2),
            2,
        );
        assert_eq!(wider, Some(2), "a new limit version recomputes");
    }

    #[test]
    fn capped_batch_size_never_exceeds_shared_max() {
        assert_eq!(
            DistriWorker::capped_batch_size(100),
            100,
            "honest sizes pass through unchanged"
        );
        assert_eq!(
            DistriWorker::capped_batch_size(
                crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS as u64
            ),
            crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS as u64,
            "the shared max itself is accepted"
        );
        assert_eq!(
            DistriWorker::capped_batch_size(
                crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS as u64 + 1
            ),
            crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS as u64,
            "an unvalidated larger size clamps instead of emitting an oversized batch"
        );
        assert_eq!(
            DistriWorker::capped_batch_size(u64::MAX),
            crate::config::MAX_DISTRIBUTION_LEDGER_EVENTS as u64,
            "no configured value can produce a batch the receiver drops on sight"
        );
    }
}
