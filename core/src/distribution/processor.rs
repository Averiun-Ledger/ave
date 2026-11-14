use std::sync::Arc;

use ave_actors::{ActorContext, ActorError, ActorPath};
use ave_common::SchemaType;
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_network::ComunicateInfo;

use crate::helpers::db::ExternalDB;

use crate::model::common::subject::{
    acquire_subject, create_subject, get_local_subject_sn,
    get_subject_path_and_data, update_ledger,
};
use crate::model::common::{
    check_subject_creation, crash_system, record_speculative_transfer,
    record_verified_transfer, remove_verified_transfer,
};
use crate::{
    distribution::error::DistributorError,
    distribution::transfer_verifier::TransferSimulationResult,
    distribution::worker::{
        CheckAuthCommon, DistriWorker, DistributionContext, TransferBatch,
    },
    governance::{
        Governance, GovernanceMessage, witnesses_register::TrackerDeliveryMode,
        sn_register::{
            SnRegister, SnRegisterMessage, SnRegisterResponse,
        },
        subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        },
        transfer_verification_register::{
            TransferVerificationRegister, TransferVerificationRegisterMessage,
            TransferVerificationRegisterResponse,
        },
        witnesses_register::{
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        },
    },
    model::event::{Ledger, Protocols},
    node::{
        Node, NodeMessage,
        subject_manager::{
            SubjectManager, SubjectManagerMessage, SubjectManagerResponse,
        },
    },
    sink::{SinkManager, SinkManagerMessage},
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};
use tracing::{debug, error, warn};

impl DistriWorker {
    pub(crate) async fn process_ledger_chunks(
        &mut self,
        ctx: &mut ActorContext<Self>,
        mut pending_ledger: Vec<Ledger>,
        common: &CheckAuthCommon,
        transfer_batch: TransferBatch<'_>,
        dist_ctx: DistributionContext,
    ) -> Result<(), ActorError> {
        let mut transfer_recorded = false;
        let sender_is_all = dist_ctx.sender_is_all;
        let mut verified_transfer_sn = transfer_batch.verified_sn;
        let info = &dist_ctx.info;
        let sender = dist_ctx.sender;
        let subject_id = dist_ctx.subject_id;
        let ledger_count = dist_ctx.ledger_count;
        let transfer_event = transfer_batch.event;
        let transfer_simulation = transfer_batch.simulation;

        // Deferred prefix first: batches held back while their aux
        // was uncheckable rejoin here, in order, before the current
        // batch. Stale entries (already applied by another path) are
        // pruned; anything genuinely new keeps its original order.
        let applied_tip =
            get_local_subject_sn(ctx, &subject_id).await.ok().flatten();
        let mut prefix = self.deferred_prefix(&subject_id, applied_tip);
        if !prefix.is_empty() {
            prefix.extend(pending_ledger);
            pending_ledger = prefix;
        }

        // Truncation detection: the sender's `is_all` is a claim, so
        // the offered tip is checked against our own window and
        // against any verified transfer floor. A batch claiming
        // completeness below either is treated as partial (more is
        // requested) instead of stalling short. The window is only
        // built when the sender claims completeness: otherwise the
        // flag below is false by definition and the build is pure
        // waste on every batch.
        let window_sn: Option<u64> = if !sender_is_all || common.is_gov {
            None
        } else if let Some(data) = common.subject_data.as_ref() {
            self.get_tracker_window(
                ctx,
                &subject_id,
                (*self.our_key).clone(),
                None,
                data,
            )
            .await
            .ok()
            .map(|(sn, _, _, _)| sn)
        } else {
            None
        };

        loop {
            if pending_ledger.is_empty() {
                break;
            }
            let chunk_first_sn = pending_ledger[0].sn;
            let chunk_offered_hi_sn = pending_ledger
                .last()
                .map(|event| event.sn)
                .unwrap_or(chunk_first_sn);

            let auth = self
                .check_auth_batch(
                    ctx,
                    sender.clone(),
                    &pending_ledger,
                    chunk_offered_hi_sn,
                    common,
                    TransferBatch {
                        event: transfer_event,
                        simulation: transfer_simulation,
                        verified_sn: verified_transfer_sn,
                    },
                )
                .await?;

            // A proven aux records a firm proof and opens verified
            // free passage for the rest of the loop. An unproven aux
            // still opens speculative passage (the sender fetches it
            // ahead of the window by design), but the proof stays
            // speculative until a later batch rechecks the evidence;
            // refuting it then rolls the subject back.
            if !transfer_recorded
                && !common.is_gov
                && let Some(transfer_event) = transfer_event
            {
                if matches!(
                    transfer_simulation,
                    Some(TransferSimulationResult::Witness)
                ) {
                    record_verified_transfer(
                        ctx,
                        &common.governance_id,
                        &subject_id,
                        transfer_event.sn,
                        sender.clone(),
                    )
                    .await?;
                    transfer_recorded = true;
                    // Refresh verified_transfer_sn so the next loop
                    // iteration can use Path C (free passage).
                    verified_transfer_sn = Some(transfer_event.sn);
                } else if matches!(
                    transfer_simulation,
                    Some(TransferSimulationResult::WitnessUnproven)
                ) {
                    // No one-shot flag here: a later chunk in this
                    // same loop may still verify the aux and record
                    // it firm below. The register itself keeps the
                    // first speculative entry.
                    record_speculative_transfer(
                        ctx,
                        &common.governance_id,
                        &subject_id,
                        transfer_event.sn,
                        sender.clone(),
                    )
                    .await?;
                }
            }

            let is_gov = auth.is_gov;
            let is_register = auth.is_register;
            let safe_hi_sn = auth.safe_hi_sn;

            let remaining_ledger =
                Self::split_off_after_safe_hi(&mut pending_ledger, safe_hi_sn);
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

            self.reproject_receipt_visibility(
                ctx,
                &mut pending_ledger,
                &subject_id,
                &sender,
                common,
            )
            .await?;

            let verify_floor = verified_transfer_sn
                .into_iter()
                .chain(transfer_event.map(|e| e.sn))
                .max();
            let truncated = if sender_is_all {
                let below_window = window_sn
                    .is_some_and(|window| chunk_offered_hi_sn < window);
                let below_floor = verify_floor
                    .is_some_and(|floor| chunk_offered_hi_sn < floor);
                below_window || below_floor
            } else {
                false
            };
            if truncated {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    sender = %sender,
                    offered_hi_sn = chunk_offered_hi_sn,
                    window_sn = window_sn,
                    "Batch claims completeness below our window; requesting more"
                );
                if let Some(metrics) = crate::metrics::try_core_metrics() {
                    metrics.observe_distribution_failure("truncated_batch");
                }
            }
            let chunk_is_all =
                remaining_ledger.is_empty() && sender_is_all && !truncated;

            #[cfg(feature = "test")]
            {
                if !is_register && dist_ctx.info.request_id.is_empty() {
                    let mut noted = false;
                    while Self::before_apply_paused(ctx) {
                        if !noted {
                            Self::note_before_apply_hold(ctx);
                            noted = true;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(
                            100,
                        ))
                        .await;
                    }
                }
            }
            let lease = if pending_ledger[0].is_create_event() && !is_register {
                let create_ledger = pending_ledger[0].clone();
                let requester = Self::requester_id(
                    "ledger_distribution_create",
                    &subject_id,
                    info,
                    &sender,
                );

                let lease = if is_gov {
                    let result =
                        create_subject(ctx, create_ledger.clone()).await;
                    handle_distri_error!(
                        ctx,
                        result,
                        "LedgerDistribution",
                        &subject_id,
                        "Failed to create subject from ledger"
                    )?;
                    None
                } else {
                    let request =
                        create_ledger.get_create_event().ok_or_else(|| {
                            error!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                "Create ledger is missing create event payload"
                            );
                            DistributorError::MissingCreateEventInCreateLedger {
                                subject_id: subject_id.clone(),
                            }
                        })?;

                    let result = check_subject_creation(
                        ctx,
                        &request.governance_id,
                        create_ledger.ledger_seal_signature.signer.clone(),
                        create_ledger.gov_version,
                        request.namespace.to_string(),
                        request.schema_id,
                    )
                    .await;
                    handle_distri_error!(
                        ctx,
                        result,
                        "LedgerDistribution",
                        &subject_id,
                        "Failed to validate subject creation from ledger"
                    )?;

                    let result = acquire_subject(
                        ctx,
                        &subject_id,
                        requester,
                        Some(create_ledger),
                        true,
                    )
                    .await;
                    Some(handle_distri_error!(
                        ctx,
                        result,
                        "LedgerDistribution",
                        &subject_id,
                        "Failed to create subject from ledger"
                    )?)
                };

                let _ = pending_ledger.remove(0);
                lease
            } else {
                if pending_ledger[0].is_create_event() && is_register {
                    let _ = pending_ledger.remove(0);
                }

                let requester = Self::requester_id(
                    "ledger_distribution",
                    &subject_id,
                    info,
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
                            // Remote-triggered bring-up failure must not stop
                            // the node: reject the batch, keep local crash
                            // policy to the caller's taxonomy check.
                            warn!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                error = %e,
                                "Failed to bring up tracker for subject update"
                            );
                            return Err(e);
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
                // Chunk fingerprint for the rollback below: tip sn
                // plus the first event signer, captured before the
                // apply moves anything.
                let chunk_tip_sn = pending_ledger
                    .last()
                    .map(|event| event.sn)
                    .unwrap_or(safe_hi_sn);
                let chunk_signer = pending_ledger
                    .first()
                    .map(|event| {
                        event.ledger_seal_signature.signer.clone()
                    });
                let update_result = update_ledger(
                    ctx,
                    &subject_id,
                    pending_ledger,
                    // Governance catch-up defers artifact acquisition to
                    // the certified tip; tracker apply never
                    // compiles.
                    is_gov,
                )
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
                        if !common.is_gov
                            && let Ok(manager) = ctx
                                .system()
                                .get_actor::<SubjectManager>(&ActorPath::from(
                                    "/user/node/subject_manager",
                                ))
                                .await
                            && let Err(error) = manager
                                .ask(SubjectManagerMessage::NoteSuccess {
                                    subject_id: subject_id.clone(),
                                    attempt: dist_ctx.attempt,
                                })
                                .await
                        {
                            warn!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                error = %error,
                                "Failed to note successful copy attempt",
                            );
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
                                    info,
                                    Some(last_sn),
                                    common.subject_data.clone(),
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
                                return Err(crash_system(ctx, e).await);
                            };
                        } else if is_gov {
                            // The catch-up round reached the
                            // witness-certified tip: run the deferred
                            // artifact acquisition pass.
                            self.trigger_deferred_acquisition(ctx, &subject_id)
                                .await;
                        } else {
                            self.notify_update_done(ctx, &subject_id, last_sn)
                                .await;
                        }
                    }
                    Err(e) => {
                        if transfer_recorded && !common.is_gov {
                            if let Err(remove_err) = remove_verified_transfer(
                                ctx,
                                &common.governance_id,
                                &subject_id,
                            )
                            .await
                            {
                                warn!(
                                    msg_type = "LedgerDistribution",
                                    subject_id = %subject_id,
                                    error = %remove_err,
                                    "Failed to drop transfer proof"
                                );
                            }
                        }
                        // A failed first copy must leave no trace:
                        // the prefix was authorized by a suffix the
                        // apply just rejected, so drop the subject
                        // created in this batch instead of keeping
                        // its Create and valid events persisted.
                        if !is_register && !common.is_gov {
                            if let Some(lease) = lease {
                                if let Err(finish_err) =
                                    lease.finish(ctx).await
                                {
                                    warn!(
                                        msg_type = "LedgerDistribution",
                                        subject_id = %subject_id,
                                        error = %finish_err,
                                        "Failed to release subject lease",
                                    );
                                }
                            }
                            self.rollback_first_copy(
                                ctx,
                                &common.governance_id,
                                &subject_id,
                                chunk_tip_sn,
                                chunk_signer,
                                dist_ctx.attempt,
                            )
                            .await;
                        }
                        if let ActorError::FunctionalCritical { .. } = e.clone()
                        {
                            error!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                first_sn = chunk_first_sn,
                                ledger_count = ledger_count,
                                error = %e,
                                "Failed to update subject ledger"
                            );
                            return Err(crash_system(ctx, e).await);
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
                            info,
                            Some(applied_hi_sn),
                            common.subject_data.clone(),
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
                        return Err(crash_system(ctx, e).await);
                    };
                } else if is_gov {
                    // The catch-up round reached the witness-certified
                    // tip: run the deferred artifact acquisition pass.
                    self.trigger_deferred_acquisition(ctx, &subject_id).await;
                } else {
                    self.notify_update_done(ctx, &subject_id, applied_hi_sn)
                        .await;
                }
            }

            break;
        }

        Ok(())
    }

    /// Records a first-copy rollback skip for tests proving a
    /// concurrent valid copy was spared. Best-effort and silent
    /// outside tests: in production this is a no-op.
    async fn note_rollback_skip(_ctx: &mut ActorContext<Self>) {
        #[cfg(feature = "test")]
        {
            use crate::helpers::network::test_faults::SharedFaultRegistry;
            if let Some(registry) =
                _ctx.system().get_helper::<SharedFaultRegistry>("test_faults")
            {
                if let Ok(mut faults) = registry.lock() {
                    faults.note_rollback_skip();
                }
            }
        }
    }

    /// Drops a forged aux once its chain proves it: only a still
    /// recorded proof for that exact aux triggers the purge below;
    /// anything else just drops the held prefix and fails. The purge
    /// itself stays attempt-owned (see `rollback_first_copy`): a
    /// concurrent valid copy is never deleted.
    pub(crate) async fn rollback_refuted_aux(
        &mut self,
        ctx: &mut ActorContext<Self>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        aux_sn: u64,
        attempt: u64,
    ) {
        // The chain this aux belongs to just proved forged: drop
        // anything we held back for it before deciding about the
        // purge below.
        self.drop_deferred(subject_id);
        let speculative = matches!(
            crate::model::common::get_verified_transfer_detail(
                ctx,
                governance_id,
                subject_id,
            )
            .await,
            Ok(Some((sn, _, true))) if sn == aux_sn
        );
        if !speculative {
            return;
        }
        if let Err(error) =
            remove_verified_transfer(ctx, governance_id, subject_id).await
        {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Failed to drop refuted transfer proof",
            );
        }
        self.rollback_first_copy(
            ctx,
            governance_id,
            subject_id,
            aux_sn,
            None,
            attempt,
        )
        .await;
    }

    /// Releases the reload requester above: keeps no tracker
    /// alive on the rollback paths that back off after reloading.
    /// Best-effort; a missing entry is a no-op.
    async fn finish_rollback_up(
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Ok(manager) = ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
        {
            if let Err(error) = manager
                .ask(SubjectManagerMessage::Finish {
                    subject_id: subject_id.clone(),
                    requester: "rollback".to_owned(),
                })
                .await
            {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Rollback reload requester not released",
                );
            }
        }
    }

    /// Best-effort teardown of a tracker first-created in a batch
    /// whose reception just failed: either its apply errored, or a
    /// forged aux it speculatively followed got refuted once its
    /// chain became checkable. Only subject-scoped state is
    /// dropped (tracker ledger and actor, per-subject register
    /// entries, node registration, database row): the shared
    /// governance registers keep running for the other subjects.
    /// Never masks the original error: every failure is logged and
    /// the caller still returns it.
    ///
    /// Attempt-owned: the purge only runs when nothing else uses
    /// or advanced the subject (no live requesters, tip below the
    /// failed chunk, ownership untouched since creation). A
    /// concurrent valid copy is never deleted.
    /// Test-only rollback barrier: pause here while a test interleaves
    /// a valid copy on another worker. The flag lives in the shared
    /// test registry, never in this worker's mailbox (which stays
    /// blocked while parked). Production never arms it.
    #[cfg(feature = "test")]
    fn rollback_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry.lock().ok().map(|faults| {
                    faults.rollback_paused()
                })
            })
            .unwrap_or(false)
    }

    /// Test-only pre-apply barrier: pauses a first copy based on
    /// an injected batch (empty request id) before it writes, so a
    /// test can interleave a valid Create and prove the later
    /// rollback spares it. Update traffic (real request id) never
    /// pauses. Production never arms it.
    #[cfg(feature = "test")]
    fn before_apply_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry.lock().ok().map(|faults| {
                    faults.before_apply_paused()
                })
            })
            .unwrap_or(false)
    }

    #[cfg(feature = "test")]
    fn note_before_apply_hold(ctx: &ActorContext<Self>) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) =
            ctx.system().get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_before_apply_hold();
        }
    }

    /// Test-only rollback barrier hit: lets a test prove the
    /// interleaving really happened instead of passing vacuously.
    /// Production never arms it.
    #[cfg(feature = "test")]
    fn note_rollback_hold(ctx: &ActorContext<Self>) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) =
            ctx.system().get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_rollback_hold();
        }
    }

    async fn rollback_first_copy(
        &mut self,
        ctx: &mut ActorContext<Self>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        chunk_tip_sn: u64,
        baseline_owner: Option<PublicKey>,
        attempt: u64,
    ) {
        // The failed copy is being torn down: anything held back
        // for it is stale by definition and must not be applied
        // later.
        self.drop_deferred(subject_id);
        // Test barrier: pause here while a test interleaves a valid
        // copy on another worker. Production never arms it.
        #[cfg(feature = "test")]
        {
            let mut noted = false;
            while Self::rollback_paused(ctx) {
                if !noted {
                    Self::note_rollback_hold(ctx);
                    noted = true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100))
                    .await;
            }
        }
        // Someone else is mid-copy: only our lease was released
        // above, never purge shared state.
        match ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
        {
            Ok(manager) => match manager
                .ask(SubjectManagerMessage::HasLiveRequesters {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(SubjectManagerResponse::HasLiveRequesters(true)) => {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        "Rollback skipped: live requesters",
                    );
                    Self::note_rollback_skip(ctx).await;
                    Self::finish_rollback_up(ctx, subject_id).await;
                    return;
                }
                Ok(SubjectManagerResponse::HasLiveRequesters(false)) => {}
                Ok(_) => {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        "Rollback skipped: unexpected requesters response",
                    );
                    Self::note_rollback_skip(ctx).await;
                    Self::finish_rollback_up(ctx, subject_id).await;
                    return;
                }
                Err(error) => {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        error = %error,
                        "Rollback skipped: requesters unreadable",
                    );
                    Self::note_rollback_skip(ctx).await;
                    Self::finish_rollback_up(ctx, subject_id).await;
                    return;
                }
            },
            Err(error) => {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Rollback skipped: subject manager unavailable",
                );
                Self::note_rollback_skip(ctx).await;
                Self::finish_rollback_up(ctx, subject_id).await;
                return;
            }
        }
        // Attempt gate: only the failed attempt itself may be
        // removed. Another attempt that completed after this one
        // started owns the current state, even at sn 0 with the
        // same owner: never purge a concurrent valid copy.
        let owned = match ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
        {
            Ok(manager) => match manager
                .ask(SubjectManagerMessage::ShouldPurge {
                    subject_id: subject_id.clone(),
                    attempt,
                })
                .await
            {
                Ok(SubjectManagerResponse::ShouldPurge(owned)) => owned,
                Ok(_) => false,
                Err(_) => false,
            },
            Err(_) => false,
        };
        if !owned {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                "Rollback skipped: concurrent valid copy",
            );
            Self::note_rollback_skip(ctx).await;
            Self::finish_rollback_up(ctx, subject_id).await;
            return;
        }
        // Progress gate: only the failed attempt itself may be
        // removed. Anything at or past the failed chunk tip, or with
        // rotated ownership or a pending transfer, belongs to
        // someone else's valid copy.
        //
        // The failed apply already released our lease, so an idle
        // tracker for the failed attempt is already stopped: reload
        // it from the store to purge the persisted prefix. A live
        // tracker means someone else is using it; the gates below
        // spare it.
        let tracker_path = ActorPath::from(format!(
            "/user/node/subject_manager/{subject_id}"
        ));
        if ctx.system().get_actor::<Tracker>(&tracker_path).await.is_err()
        {
            match ctx
                .system()
                .get_actor::<SubjectManager>(&ActorPath::from(
                    "/user/node/subject_manager",
                ))
                .await
            {
                Ok(manager) => {
                    if let Err(error) = manager
                        .ask(SubjectManagerMessage::Up {
                            subject_id: subject_id.clone(),
                            requester: "rollback".to_owned(),
                            create_ledger: None,
                        })
                        .await
                    {
                        warn!(
                            msg_type = "LedgerDistribution",
                            subject_id = %subject_id,
                            error = %error,
                            "Rollback skipped: subject reload failed",
                        );
                        Self::note_rollback_skip(ctx).await;
                        Self::finish_rollback_up(ctx, subject_id).await;
                        return;
                    }
                }
                Err(error) => {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        error = %error,
                        "Rollback skipped: subject manager unavailable",
                    );
                    Self::note_rollback_skip(ctx).await;
                    Self::finish_rollback_up(ctx, subject_id).await;
                    return;
                }
            }
        }
        let tracker = match ctx.system().get_actor::<Tracker>(&tracker_path).await
        {
            Ok(tracker) => tracker,
            Err(error) => {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Tracker unavailable for rollback",
                );
                Self::note_rollback_skip(ctx).await;
                Self::finish_rollback_up(ctx, subject_id).await;
                return;
            }
        };
        let (current_sn, current_owner, current_pending) = match tracker
            .ask(TrackerMessage::GetMetadata)
            .await
        {
            Ok(TrackerResponse::Metadata(meta)) => (
                meta.sn,
                meta.owner.clone(),
                meta.new_owner.clone(),
            ),
            Ok(other) => {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    response = ?other,
                    "Unexpected metadata response on rollback",
                );
                Self::note_rollback_skip(ctx).await;
                Self::finish_rollback_up(ctx, subject_id).await;
                return;
            }
            Err(error) => {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Metadata unreadable for rollback",
                );
                Self::note_rollback_skip(ctx).await;
                Self::finish_rollback_up(ctx, subject_id).await;
                return;
            }
        };
        if current_sn >= chunk_tip_sn {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                current_sn = current_sn,
                chunk_tip_sn = chunk_tip_sn,
                "Rollback skipped: subject progressed past the failed chunk",
            );
            Self::note_rollback_skip(ctx).await;
            Self::finish_rollback_up(ctx, subject_id).await;
            return;
        }
        if current_pending.is_some()
            || baseline_owner.as_ref().is_some_and(|baseline| {
                baseline != &current_owner
            })
        {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                "Rollback skipped: ownership moved past the failed attempt",
            );
            Self::note_rollback_skip(ctx).await;
            Self::finish_rollback_up(ctx, subject_id).await;
            return;
        }
        // Atomic check-and-purge: the tracker refuses when it moved
        // past the observed tip after this check.
        match tracker
            .ask(TrackerMessage::PurgeIfUnchanged {
                expected_sn: current_sn,
            })
            .await
        {
            Ok(TrackerResponse::PurgeIfUnchanged { purged: true }) => {}
            Ok(_) => {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    "Rollback skipped: tracker moved during rollback",
                );
                Self::note_rollback_skip(ctx).await;
                Self::finish_rollback_up(ctx, subject_id).await;
                return;
            }
            Err(error) => {
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Failed to purge tracker on rollback",
                );
                Self::note_rollback_skip(ctx).await;
                Self::finish_rollback_up(ctx, subject_id).await;
                return;
            }
        }
        // The purge (or the reload, when there was nothing stored)
        // holds no requester from here on.
        Self::finish_rollback_up(ctx, subject_id).await;
        // The failed attempt left no transfer proof behind: drop any
        // anyway so a rejected batch never opens future passage.
        if let Err(error) = remove_verified_transfer(
            ctx,
            governance_id,
            subject_id,
        )
        .await
        {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Failed to drop transfer proof on rollback",
            );
        }
        let gov_path =
            format!("/user/node/subject_manager/{governance_id}");
        match ctx
            .system()
            .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                "{gov_path}/subject_register"
            )))
            .await
        {
            Ok(register) => match register
                .ask(SubjectRegisterMessage::DeleteSubject {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(SubjectRegisterResponse::Ok) => {}
                Ok(other) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    response = ?other,
                    "Unexpected subject register response on rollback",
                ),
                Err(error) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Failed to clear subject register on rollback",
                ),
            },
            Err(error) => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Subject register unavailable for rollback",
            ),
        }
        match ctx
            .system()
            .get_actor::<SnRegister>(&ActorPath::from(format!(
                "{gov_path}/sn_register"
            )))
            .await
        {
            Ok(register) => match register
                .ask(SnRegisterMessage::DeleteSubject {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(SnRegisterResponse::Ok) => {}
                Ok(other) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    response = ?other,
                    "Unexpected sn register response on rollback",
                ),
                Err(error) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Failed to clear sn register on rollback",
                ),
            },
            Err(error) => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Sn register unavailable for rollback",
            ),
        }
        match ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "{gov_path}/witnesses_register"
            )))
            .await
        {
            Ok(register) => match register
                .ask(WitnessesRegisterMessage::DeleteSubject {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(WitnessesRegisterResponse::Ok) => {}
                Ok(_) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    "Unexpected witnesses response on rollback",
                ),
                Err(error) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Failed to clear witnesses register on rollback",
                ),
            },
            Err(error) => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Witnesses register unavailable for rollback",
            ),
        }
        match ctx
            .system()
            .get_actor::<TransferVerificationRegister>(&ActorPath::from(
                format!("{gov_path}/transfer_verification_register"),
            ))
            .await
        {
            Ok(register) => match register
                .ask(TransferVerificationRegisterMessage::Remove {
                    subject_id: subject_id.clone(),
                })
                .await
            {
                Ok(TransferVerificationRegisterResponse::Ok) => {}
                Ok(other) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    response = ?other,
                    "Unexpected proof register response on rollback",
                ),
                Err(error) => warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %error,
                    "Failed to clear proof register on rollback",
                ),
            },
            Err(error) => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Proof register unavailable for rollback",
            ),
        }
        let node_path = ActorPath::from("/user/node");
        match ctx.system().get_actor::<Node>(&node_path).await {
            Ok(node) => {
                if let Err(error) = node
                    .ask(NodeMessage::DeleteSubject(subject_id.clone()))
                    .await
                {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        error = %error,
                        "Failed to unregister subject on rollback",
                    );
                }
            }
            Err(error) => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Node unavailable for rollback",
            ),
        }
        // The apply already published state to the external database:
        // drop that row too, or the subject would stay queryable.
        // Sink tracking follows the same best-effort rule: untrack
        // the subject without touching the shared manager.
        match ctx
            .system()
            .get_actor::<SinkManager>(&ActorPath::from(format!(
                "{gov_path}/sink_manager"
            )))
            .await
        {
            Ok(sink_manager) => {
                if let Err(error) = sink_manager
                    .tell(SinkManagerMessage::RemoveSubject {
                        subject_id: subject_id.to_string(),
                    })
                    .await
                {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        error = %error,
                        "Failed to untrack subject on rollback",
                    );
                }
            }
            Err(error) => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Sink manager unavailable for rollback",
            ),
        }
        match ctx.system().get_helper::<Arc<ExternalDB>>("ext_db") {
            Some(db) => {
                if let Err(error) =
                    db.delete_subject(&subject_id.to_string()).await
                {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        error = %error,
                        "Failed to delete subject row on rollback",
                    );
                }
            }
            None => warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                "External database unavailable for rollback",
            ),
        }
    }
    /// Receipt-side visibility: the sender's projection is a claim.
    /// Every full fact is re-checked event by event against our own
    /// register: opaque modes are masked locally, clear modes pass.
    /// Events above our governance version pass through: with a
    /// lagging governance we cannot judge grants yet, and blocking
    /// would wedge legit sync.
    async fn reproject_receipt_visibility(
        &self,
        ctx: &mut ActorContext<Self>,
        ledger: &mut [Ledger],
        subject_id: &DigestIdentifier,
        sender: &PublicKey,
        common: &CheckAuthCommon,
    ) -> Result<(), ActorError> {
        if common.is_gov || ledger.is_empty() {
            return Ok(());
        }
        let has_full = ledger
            .iter()
            .any(|e| matches!(e.protocols, Protocols::TrackerFactFull { .. }));
        if !has_full {
            return Ok(());
        }
        let modes = self
            .tracker_delivery_modes(
                ctx,
                &common.governance_id,
                subject_id,
                (*self.our_key).clone(),
                common.namespace.clone(),
                common.schema_id.clone(),
                ledger,
            )
            .await
            .map_err(|e| DistributorError::VisibilityCheckFailed {
                details: e.to_string(),
            })?;
        if modes.len() != ledger.len() {
            return Err(DistributorError::VisibilityCheckFailed {
                details: format!(
                    "modes cover {} of {} events",
                    modes.len(),
                    ledger.len()
                ),
            }
            .into());
        }
        for (event, mode) in ledger.iter_mut().zip(modes.iter()) {
            if !matches!(event.protocols, Protocols::TrackerFactFull { .. }) {
                continue;
            }
            if event.gov_version > common.gov_version {
                continue;
            }
            if matches!(mode, TrackerDeliveryMode::Opaque) {
                *event = event.to_tracker_opaque().map_err(|e| {
                    ActorError::Functional {
                        description: format!(
                            "Failed to mask opaque fact: {e:?}"
                        ),
                    }
                })?;
                warn!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    sender = %sender,
                    sn = event.sn,
                    "Masked over-clear fact on receipt"
                );
                if let Some(metrics) = crate::metrics::try_core_metrics() {
                    metrics.observe_distribution_failure("visibility_remasked");
                }
            }
        }
        Ok(())
    }

    async fn tracker_delivery_modes(
        &self,
        ctx: &mut ActorContext<Self>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        node: PublicKey,
        namespace: String,
        schema_id: SchemaType,
        ledger: &[Ledger],
    ) -> Result<Vec<TrackerDeliveryMode>, ActorError> {
        // Test-only one-shot fault: fail the lookup or answer with
        // no modes, so the fail-closed receipt paths can be pinned.
        // Production never arms this flag.
        #[cfg(feature = "test")]
        match self
            .test_modes_fault
            .swap(0, std::sync::atomic::Ordering::SeqCst)
        {
            0 => {}
            1 => {
                return Err(ActorError::Functional {
                    description: "test modes fault".to_string(),
                });
            }
            _ => return Ok(Vec::new()),
        }
        use crate::governance::witnesses_register::{
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        };
        use ave_actors::ActorPath;
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{governance_id}/witnesses_register"
        ));
        let actor = ctx.system().get_actor::<WitnessesRegister>(&path).await?;
        let response = actor
            .ask(WitnessesRegisterMessage::GetTrackerDeliveryModes {
                subject_id: subject_id.clone(),
                node,
                namespace,
                schema_id,
                ledger: ledger.to_vec(),
            })
            .await?;
        match response {
            WitnessesRegisterResponse::TrackerDeliveryModes { modes } => {
                Ok(modes)
            }
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "WitnessesRegisterResponse::TrackerDeliveryModes"
                    .to_owned(),
            }),
        }
    }

    /// A governance catch-up round reached the witness-certified tip:
    /// notify the governance actor that the deferred artifact
    /// acquisition pass is due. A missing actor means the
    /// governance was purged mid-sync: the pass is moot, drop it.
    async fn trigger_deferred_acquisition(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        let path = match get_subject_path_and_data(ctx, subject_id).await {
            Ok((path, _)) => path,
            Err(e) => {
                debug!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %e,
                    "Governance actor not found, dropping deferred acquisition trigger"
                );
                return;
            }
        };

        match ctx.system().get_actor::<Governance>(&path).await {
            Ok(governance_actor) => {
                if let Err(e) = governance_actor
                    .tell(GovernanceMessage::RunDeferredAcquisition)
                    .await
                {
                    warn!(
                        msg_type = "LedgerDistribution",
                        subject_id = %subject_id,
                        error = %e,
                        "Failed to trigger the deferred acquisition pass"
                    );
                }
            }
            Err(e) => {
                debug!(
                    msg_type = "LedgerDistribution",
                    subject_id = %subject_id,
                    error = %e,
                    "Governance actor not found, dropping deferred acquisition trigger"
                );
            }
        }
    }

    /// Best-effort completion signal to the update round
    /// supervising this subject, if any: reaching the sender
    /// certified tip satisfies its target, so its retry timer is
    /// moot and the actor can stop now instead of lingering for
    /// it. Partial rounds send nothing; their timer still
    /// supervises them. A missing actor just means no round is
    /// running.
    async fn notify_update_done(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sn: u64,
    ) {
        use crate::update::{Update, UpdateMessage};
        let path = ave_actors::ActorPath::from(format!(
            "/user/node/auth/{subject_id}"
        ));
        let Ok(actor) = ctx.system().get_actor::<Update>(&path).await else {
            return;
        };
        let _ = actor.tell(UpdateMessage::DistributionDone { sn }).await;
    }

    pub(crate) async fn process_last_event_distribution(
        &mut self,
        ctx: &mut ActorContext<Self>,
        mut ledger: Ledger,
        info: ComunicateInfo,
        sender: PublicKey,
    ) -> Result<(), ActorError> {
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

        let result = self
            .check_auth_single(
                ctx,
                sender.clone(),
                &info,
                std::slice::from_ref(&ledger),
                sn,
            )
            .await;
        let auth = handle_distri_error!(
            ctx,
            result,
            "LastEventDistribution",
            &subject_id,
            "Authorization check failed",
            sender = &sender,
            sn = sn
        )?;

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

        if !is_gov
            && matches!(ledger.protocols, Protocols::TrackerFactFull { .. })
        {
            let Some(crate::node::SubjectData::Tracker {
                governance_id,
                schema_id,
                namespace,
                ..
            }) = crate::model::common::node::get_subject_data(ctx, &subject_id)
                .await
                .map_err(|e| DistributorError::VisibilityCheckFailed {
                    details: format!("unreadable subject data: {e}"),
                })?
            else {
                return Err(DistributorError::VisibilityCheckFailed {
                    details: "no usable tracker data for pushed fact"
                        .to_owned(),
                }
                .into());
            };
            let our_gov =
                crate::model::common::subject::get_version(ctx, &governance_id)
                    .await
                    .map_err(|e| DistributorError::VisibilityCheckFailed {
                        details: e.to_string(),
                    })?;
            // A fact newer than our governance cannot be judged yet:
            // leave it for the catch-up round, which runs the same
            // check once the version lands.
            if ledger.gov_version <= our_gov {
                let modes = self
                    .tracker_delivery_modes(
                        ctx,
                        &governance_id,
                        &subject_id,
                        (*self.our_key).clone(),
                        namespace,
                        schema_id,
                        std::slice::from_ref(&ledger),
                    )
                    .await
                    .map_err(|e| DistributorError::VisibilityCheckFailed {
                        details: e.to_string(),
                    })?;
                match modes.first() {
                    Some(
                        crate::governance::witnesses_register::TrackerDeliveryMode::Opaque,
                    ) => {
                        ledger = ledger.to_tracker_opaque().map_err(|e| {
                            ActorError::Functional {
                                description: format!(
                                    "Failed to mask pushed fact: {e:?}"
                                ),
                            }
                        })?;
                        warn!(
                            msg_type = "LastEventDistribution",
                            subject_id = %subject_id,
                            sender = %sender,
                            sn = sn,
                            "Masked over-clear pushed fact"
                        );
                    }
                    Some(_) => {}
                    None => {
                        return Err(
                            DistributorError::VisibilityCheckFailed {
                                details: "empty modes for pushed fact"
                                    .to_owned(),
                            }
                            .into(),
                        );
                    }
                }
            }
        }

        let lease = if ledger.is_create_event() {
            let result = create_subject(ctx, ledger.clone()).await;
            handle_distri_error!(
                ctx,
                result,
                "LastEventDistribution",
                &subject_id,
                "Failed to create subject from create event"
            )?;
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
                        warn!(
                            msg_type = "LastEventDistribution",
                            subject_id = %subject_id,
                            error = %e,
                            "Failed to bring up tracker for subject update"
                        );
                        return Err(e);
                    }
                }
            } else {
                None
            };

            let update_result = update_ledger(
                ctx,
                &subject_id,
                vec![ledger.clone()],
                // A last-event push is live propagation of an event the
                // network just committed: this node is at the tip,
                // acquire the artifact now (only catch-up defers it).
                false,
            )
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
                            None,
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
                        return Err(crash_system(ctx, e).await);
                    }

                    if let Some(lease) = lease.clone() {
                        lease.finish(ctx).await?;
                    }

                    // The received event is ours even with a gap behind:
                    // ack it so the sender stops retrying, the missing
                    // range was already re-requested above.
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
                        return Err(crash_system(ctx, e).await);
                    };

                    return Ok(());
                }
                Ok((..)) => lease,
                Err(e) => {
                    if let ActorError::FunctionalCritical { .. } = e.clone() {
                        error!(
                            msg_type = "LastEventDistribution",
                            subject_id = %subject_id,
                            sn = sn,
                            error = %e,
                            "Failed to update subject ledger"
                        );
                        return Err(crash_system(ctx, e).await);
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

        if let Err(e) = self.send_last_event_ack(sender.clone(), &info).await {
            error!(
                msg_type = "LastEventDistribution",
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Failed to send distribution acknowledgment"
            );
            return Err(crash_system(ctx, e).await);
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
        Ok(())
    }
}
