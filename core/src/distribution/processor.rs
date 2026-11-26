use std::sync::Arc;
use std::sync::atomic::Ordering;

use ave_actors::{ActorContext, ActorError, ActorPath};
use ave_common::SchemaType;
use ave_common::bridge::request::EventRequestType;
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_network::ComunicateInfo;

use crate::helpers::db::ExternalDB;

use crate::model::common::subject::{
    acquire_subject, create_subject, get_local_subject_sn,
    get_subject_path_and_data, update_ledger,
};
use crate::model::common::{
    check_subject_creation, crash_system, record_verified_transfer,
    remove_verified_transfer,
};
use crate::{
    distribution::error::DistributorError,
    distribution::transfer_verifier::AuxEvidence,
    distribution::transfer_verifier::AuxEvidenceInput,
    distribution::transfer_verifier::TransferSimulationResult,
    distribution::worker::{
        CheckAuthCommon, DistriWorker, DistributionContext, TransferBatch,
    },
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        sn_register::{SnRegister, SnRegisterMessage, SnRegisterResponse},
        subject_register::{
            SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
        },
        transfer_verification_register::{
            TransferVerificationRegister, TransferVerificationRegisterMessage,
            TransferVerificationRegisterResponse,
        },
        witnesses_register::TrackerDeliveryMode,
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

/// What `DistriWorker::tracker_delivery_modes` resolves: the
/// identity and schema of the events under review plus the events
/// themselves. Bundled so the visibility check keeps a short
/// signature.
struct TrackerDeliveryQuery<'a> {
    governance_id: &'a DigestIdentifier,
    subject_id: &'a DigestIdentifier,
    node: PublicKey,
    namespace: String,
    schema_id: SchemaType,
    ledger: &'a [Ledger],
}

/// Test-only truncation-window call counter, shared across workers
/// via the `truncation_stats` helper. Counts, per subject, how many
/// times `process_ledger_chunks` built the window to detect a
/// truncated batch. The call only happens when the sender claims
/// completeness, so a test can prove the window build is skipped for
/// partial batches. Zero cost in production: the struct, helper and
/// call site only exist under `#[cfg(feature = "test")]`.
#[cfg(feature = "test")]
#[derive(Debug, Default)]
pub(crate) struct TruncationStatsRegistry {
    checks: std::collections::HashMap<DigestIdentifier, u64>,
}

#[cfg(feature = "test")]
pub(crate) type SharedTruncationStats =
    std::sync::Arc<std::sync::Mutex<TruncationStatsRegistry>>;

#[cfg(feature = "test")]
impl TruncationStatsRegistry {
    pub(crate) fn note(&mut self, subject_id: &DigestIdentifier) {
        *self.checks.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn count(&self, subject_id: &DigestIdentifier) -> u64 {
        self.checks.get(subject_id).copied().unwrap_or(0)
    }
}

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
        // Proof write deferred until the chunk applies: the tracker
        // consumes the register when it applies any transfer, so
        // recording before the apply would let an earlier inline
        // transfer wipe the proof this batch just earned.
        let mut pending_proof: Option<(u64, DigestIdentifier)> = None;
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
        let mut prefix =
            self.take_deferred_prefix(ctx, &subject_id, applied_tip);
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
            #[cfg(feature = "test")]
            Self::note_truncation_window_check(ctx, &subject_id);
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
            // A proven aux records a firm proof once its chunk
            // applies, and opens verified free passage for the rest
            // of the loop. An unproven aux never reaches this loop:
            // the worker holds partial batches with incomplete
            // chains unapplied until the missing events arrive,
            // and copies own-rights prefixes with no aux at all.
            // An unverifiable aux (complete chain whose evidence
            // can not be rebuilt) opens passage like the apply
            // path trusts it, but records nothing.
            // Fail closed here as defense in depth: an unproven aux
            // that somehow arrives fails without recording anything.
            if !transfer_recorded
                && !common.is_gov
                && let Some(transfer_event) = transfer_event
            {
                if matches!(
                    transfer_simulation,
                    Some(TransferSimulationResult::Witness)
                ) {
                    // Refresh verified_transfer_sn so the next loop
                    // iteration can use Path C (free passage). The
                    // register write waits until the chunk applies
                    // (see pending_proof below).
                    verified_transfer_sn = Some(transfer_event.sn);
                    match transfer_event.ledger_hash(self.hash) {
                        Ok(aux_hash) => {
                            pending_proof = Some((transfer_event.sn, aux_hash));
                        }
                        Err(error) => {
                            warn!(
                                msg_type = "LedgerDistribution",
                                subject_id = %subject_id,
                                sn = transfer_event.sn,
                                error = %error,
                                "Proven aux hash failed, recording no proof"
                            );
                        }
                    }
                } else if matches!(
                    transfer_simulation,
                    Some(TransferSimulationResult::WitnessUnproven)
                ) {
                    return Err(DistributorError::ReceiverNoAccess.into());
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

            // Evidence preflight: every successful inline transfer in
            // this chunk must survive the same evidence check the
            // apply runs, over the same local prefix plus sender
            // suffix, before the chunk becomes visible, journaled or
            // sunk. A refuted transfer rejects the whole chunk here,
            // so no prefix is ever persisted in clear on the word of
            // a transfer the apply would reject right after. It runs
            // before any acquisition, so a rejected chunk owns no
            // lease, subject or write to release.
            self.preflight_inline_transfers(
                ctx,
                &pending_ledger,
                common,
                TransferBatch {
                    event: transfer_event,
                    simulation: transfer_simulation,
                    verified_sn: verified_transfer_sn,
                },
                dist_ctx.attempt,
            )
            .await?;

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
                // Only per-subject distributors pause here, and only
                // for injected batches (empty request id): the
                // node-level distributor stays free for the
                // interleaved valid copy, which carries its own
                // request id. Update-driven traffic shares the empty
                // request id, so the worker check is what tells both
                // apart.
                if !is_register
                    && dist_ctx.info.request_id.is_empty()
                    && !Self::worker_path(ctx).ends_with("/distributor")
                {
                    let mut noted = false;
                    while Self::before_apply_paused(ctx) {
                        if !noted {
                            Self::note_before_apply_hold(ctx, dist_ctx.attempt);
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
                    dist_ctx.attempt,
                );

                let lease = if is_gov {
                    // A governance copy is only valid for the
                    // governance it was requested from: a Create for
                    // another scope is rejected before any write.
                    if let Some(expected) = &dist_ctx.expected_governance_id
                        && *expected != subject_id
                    {
                        return Err(DistributorError::UnexpectedGovernance {
                            expected: expected.clone(),
                            found: subject_id.clone(),
                        }
                        .into());
                    }
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

                    // The copy was requested under a governance scope:
                    // a Create declaring another one is rejected
                    // before validation, ownership, workers or any
                    // write. A legacy request without scope keeps the
                    // hosted-governance check below.
                    if let Some(expected) = &dist_ctx.expected_governance_id
                        && *expected != request.governance_id
                    {
                        return Err(DistributorError::UnexpectedGovernance {
                            expected: expected.clone(),
                            found: request.governance_id.clone(),
                        }
                        .into());
                    }

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
                    dist_ctx.attempt,
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

            #[cfg(feature = "test")]
            {
                // Test-only barrier after the lease is owned but
                // before anything applies: lets a test prove the
                // guard is held while a concurrent attempt runs.
                // Only injected batches (empty request id) pause
                // here, on any worker, so two duplicates can park at
                // once holding their own leases; production never
                // arms it. Unlike the pre-apply barrier it also
                // covers continuations on registered subjects.
                if dist_ctx.info.request_id.is_empty() {
                    let mut noted = false;
                    while Self::after_acquire_paused(ctx) {
                        if !noted {
                            Self::note_after_acquire_hold(
                                ctx,
                                dist_ctx.attempt,
                            );
                            noted = true;
                        }
                        tokio::time::sleep(std::time::Duration::from_millis(
                            100,
                        ))
                        .await;
                    }
                }
            }

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
                    .map(|event| event.ledger_seal_signature.signer.clone());
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
                        // The tracker consumes the register when it
                        // applies a transfer: if this chunk already
                        // applied the proven aux itself, the proof is
                        // spent and must not be resurrected here.
                        if let Some((proof_sn, proof_hash)) =
                            pending_proof.take()
                            && last_sn < proof_sn
                        {
                            record_verified_transfer(
                                ctx,
                                &common.governance_id,
                                &subject_id,
                                proof_sn,
                                sender.clone(),
                                proof_hash,
                            )
                            .await?;
                            transfer_recorded = true;
                        }
                        Self::note_copy_success(
                            ctx,
                            &subject_id,
                            dist_ctx.attempt,
                        )
                        .await;

                        #[cfg(feature = "test")]
                        {
                            // Post-success barrier: only a per-subject
                            // worker pauses here, after its success was
                            // recorded but before its flow returns, and
                            // only for injected batches (empty request
                            // id). Lets a test hold a successful copy
                            // active while another attempt finishes, to
                            // prove the shield survives. Production
                            // never arms it.
                            if !is_register
                                && dist_ctx.info.request_id.is_empty()
                                && !Self::worker_path(ctx)
                                    .ends_with("/distributor")
                            {
                                let mut noted = false;
                                while Self::post_success_paused(ctx) {
                                    if !noted {
                                        Self::note_post_success_hold(
                                            ctx,
                                            dist_ctx.attempt,
                                        );
                                        noted = true;
                                    }
                                    tokio::time::sleep(
                                        std::time::Duration::from_millis(100),
                                    )
                                    .await;
                                }
                            }
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
                            // A governance batch claiming completeness is
                            // only certified by the supervising update
                            // round: notify it with the applied tip and let
                            // it decide (by ledger SN, failed events
                            // included) whether the offered target was
                            // reached. The deferred pass runs there on
                            // certification; only an unsupervised copy
                            // (periodic version sync with no update round)
                            // runs it here directly.
                            let notified = self
                                .notify_update_done(
                                    ctx,
                                    &subject_id,
                                    last_sn,
                                    info.version,
                                    true,
                                )
                                .await;
                            if !notified {
                                self.trigger_deferred_acquisition(
                                    ctx,
                                    &subject_id,
                                )
                                .await;
                            }
                        } else {
                            self.notify_update_done(
                                ctx,
                                &subject_id,
                                last_sn,
                                info.version,
                                false,
                            )
                            .await;
                        }
                    }
                    Err(e) => {
                        if transfer_recorded
                            && !common.is_gov
                            && let Err(remove_err) = remove_verified_transfer(
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
                        // A failed first copy must leave no trace:
                        // the prefix was authorized by a suffix the
                        // apply just rejected, so drop the subject
                        // created in this batch instead of keeping
                        // its Create and valid events persisted. The
                        // lease of this attempt already closed above:
                        // finishing it again here would close a
                        // duplicate attempt sharing the batch, so the
                        // rollback below only checks the guard.
                        if !is_register && !common.is_gov {
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

                // Create-only batch: the creation above already
                // applied SN0, so record it even though no update
                // ran. Stale duplicates (already registered) record
                // nothing.
                if !is_register {
                    Self::note_copy_success(ctx, &subject_id, dist_ctx.attempt)
                        .await;
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
                    // Same certified-tip rule as the apply path above:
                    // the supervising update decides by ledger SN,
                    // unsupervised version-sync copies run it here.
                    let notified = self
                        .notify_update_done(
                            ctx,
                            &subject_id,
                            applied_hi_sn,
                            info.version,
                            true,
                        )
                        .await;
                    if !notified {
                        self.trigger_deferred_acquisition(ctx, &subject_id)
                            .await;
                    }
                } else {
                    self.notify_update_done(
                        ctx,
                        &subject_id,
                        applied_hi_sn,
                        info.version,
                        false,
                    )
                    .await;
                }
            }

            break;
        }

        Ok(())
    }

    /// Records a copy attempt as started so the success record
    /// survives while the attempt is in flight, including a parked
    /// rollback. Best-effort like `note_copy_success`: a registry
    /// failure must not fail the copy itself.
    pub(crate) async fn begin_attempt(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        attempt: u64,
    ) {
        if let Ok(manager) = ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            && let Err(error) = manager
                .ask(SubjectManagerMessage::BeginAttempt {
                    subject_id: subject_id.clone(),
                    attempt,
                })
                .await
        {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Failed to note copy attempt start",
            );
        }
    }

    /// Records a copy attempt as finished: when no attempt stays
    /// active the attempt set and the success record for the subject
    /// are dropped. Best-effort; runs on every exit path via the
    /// entry-point wrappers, never skipped on early returns.
    pub(crate) async fn end_attempt(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        attempt: u64,
    ) {
        if let Ok(manager) = ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            && let Err(error) = manager
                .ask(SubjectManagerMessage::EndAttempt {
                    subject_id: subject_id.clone(),
                    attempt,
                })
                .await
        {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Failed to note copy attempt end",
            );
        }
    }

    /// Records a successful copy step under this batch attempt
    /// so a later failed first copy cannot purge it. Best-effort
    /// with a warning: a registry failure must not fail the copy
    /// itself. Only call after the creation or application has
    /// actually succeeded.
    async fn note_copy_success(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        attempt: u64,
    ) {
        if let Ok(manager) = ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            && let Err(error) = manager
                .ask(SubjectManagerMessage::NoteSuccess {
                    subject_id: subject_id.clone(),
                    attempt,
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
    }

    /// Records a first-copy rollback skip for tests proving a
    /// concurrent valid copy was spared. Best-effort and silent
    /// outside tests: in production this is a no-op.
    async fn note_rollback_skip(_ctx: &mut ActorContext<Self>) {
        #[cfg(feature = "test")]
        {
            use crate::helpers::network::test_faults::SharedFaultRegistry;
            if let Some(registry) = _ctx
                .system()
                .get_helper::<SharedFaultRegistry>("test_faults")
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
        self.drop_deferred(ctx, subject_id);
        let speculative = matches!(
            crate::model::common::get_verified_transfer_detail(
                ctx,
                governance_id,
                subject_id,
            )
            .await,
            Ok(Some((sn, _, _, true))) if sn == aux_sn
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
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Ok(manager) = ctx
            .system()
            .get_actor::<SubjectManager>(&ActorPath::from(
                "/user/node/subject_manager",
            ))
            .await
            && let Err(error) = manager
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

    /// Best-effort teardown of a tracker first-created in a batch
    /// whose reception just failed: either its apply errored, or a
    /// forged aux got refuted once its chain became checkable.
    /// Only subject-scoped state is dropped (tracker ledger and
    /// actor, per-subject register entries, node registration,
    /// database row): the shared governance registers keep running
    /// for the other subjects.
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
                registry.lock().ok().map(|faults| faults.rollback_paused())
            })
            .unwrap_or(false)
    }

    /// Path of the worker running this handler, for tests
    /// proving on which distributor a batch parked.
    #[cfg(feature = "test")]
    fn worker_path(ctx: &ActorContext<Self>) -> String {
        ctx.path().to_string()
    }

    /// Test-only truncation-window call counter: records one call
    /// for this subject right before building the window used for
    /// truncation detection. Production never reads it.
    #[cfg(feature = "test")]
    fn note_truncation_window_check(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) = ctx
            .system()
            .get_helper::<SharedTruncationStats>("truncation_stats")
            && let Ok(mut guard) = stats.lock()
        {
            guard.note(subject_id);
        }
    }

    #[cfg(feature = "test")]
    fn before_apply_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry
                    .lock()
                    .ok()
                    .map(|faults| faults.before_apply_paused())
            })
            .unwrap_or(false)
    }

    /// Test-only post-success barrier hit: lets a test hold a copy
    /// whose success is already recorded while another attempt
    /// finishes. Production never arms it.
    #[cfg(feature = "test")]
    fn post_success_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry
                    .lock()
                    .ok()
                    .map(|faults| faults.post_success_paused())
            })
            .unwrap_or(false)
    }

    #[cfg(feature = "test")]
    fn note_post_success_hold(ctx: &ActorContext<Self>, attempt: u64) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_post_success_hold(attempt);
        }
    }

    /// Test-only post-update barrier for single pushes: lets a
    /// test pin that the pushed event went through the update
    /// decision (applied or skipped) before asserting on it.
    /// Production never arms it.
    #[cfg(feature = "test")]
    fn single_updated_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry
                    .lock()
                    .ok()
                    .map(|faults| faults.single_updated_paused())
            })
            .unwrap_or(false)
    }

    #[cfg(feature = "test")]
    fn note_single_updated_hold(ctx: &ActorContext<Self>) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_single_updated_hold();
        }
    }

    /// Test-only record of the attempt a single push owns: lets a
    /// test tell the skipped push apart from the parked batch it
    /// interleaves with. Production never reads it.
    #[cfg(feature = "test")]
    fn note_single_push_attempt(
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        attempt: u64,
    ) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_single_push_attempt(subject_id.to_string(), attempt);
        }
    }

    /// Test-only post-acquire barrier hit: lets a test prove the
    /// lease is owned while the copy is still parked before
    /// applying. Production never arms it.
    #[cfg(feature = "test")]
    fn after_acquire_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry
                    .lock()
                    .ok()
                    .map(|faults| faults.after_acquire_paused())
            })
            .unwrap_or(false)
    }

    #[cfg(feature = "test")]
    fn note_after_acquire_hold(ctx: &ActorContext<Self>, attempt: u64) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_after_acquire_hold(attempt);
        }
    }

    /// Test-only pre-purge barrier hit: lets a test interleave a
    /// valid apply between the rollback metadata read and the
    /// atomic purge. Production never arms it.
    #[cfg(feature = "test")]
    fn pre_purge_paused(ctx: &ActorContext<Self>) -> bool {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        ctx.system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            .and_then(|registry| {
                registry.lock().ok().map(|faults| faults.pre_purge_paused())
            })
            .unwrap_or(false)
    }

    #[cfg(feature = "test")]
    fn note_pre_purge_hold(ctx: &ActorContext<Self>) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_pre_purge_hold();
        }
    }

    #[cfg(feature = "test")]
    fn note_before_apply_hold(ctx: &ActorContext<Self>, attempt: u64) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_before_apply_hold(attempt, ctx.path().to_string());
        }
    }

    /// Test-only rollback barrier hit: lets a test prove the
    /// interleaving really happened instead of passing vacuously.
    /// Production never arms it.
    #[cfg(feature = "test")]
    fn note_rollback_hold(ctx: &ActorContext<Self>, attempt: u64) {
        use crate::helpers::network::test_faults::SharedFaultRegistry;
        if let Some(registry) = ctx
            .system()
            .get_helper::<SharedFaultRegistry>("test_faults")
            && let Ok(mut faults) = registry.lock()
        {
            faults.note_rollback_hold(attempt);
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
        self.drop_deferred(ctx, subject_id);
        // Test barrier: pause here while a test interleaves a valid
        // copy on another worker. Production never arms it.
        #[cfg(feature = "test")]
        {
            let mut noted = false;
            while Self::rollback_paused(ctx) {
                if !noted {
                    Self::note_rollback_hold(ctx, attempt);
                    noted = true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
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
        let tracker_path =
            ActorPath::from(format!("/user/node/subject_manager/{subject_id}"));
        if ctx
            .system()
            .get_actor::<Tracker>(&tracker_path)
            .await
            .is_err()
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
        let tracker =
            match ctx.system().get_actor::<Tracker>(&tracker_path).await {
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
        let (current_sn, current_owner, current_pending) =
            match tracker.ask(TrackerMessage::GetMetadata).await {
                Ok(TrackerResponse::Metadata(meta)) => {
                    (meta.sn, meta.owner.clone(), meta.new_owner.clone())
                }
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
            || baseline_owner
                .as_ref()
                .is_some_and(|baseline| baseline != &current_owner)
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
        #[cfg(feature = "test")]
        {
            // Pre-purge barrier: pauses after the metadata read but
            // before the atomic purge, so a test can interleave a
            // valid apply and prove the purge backs off instead of
            // deleting. Production never arms it.
            let mut noted = false;
            while Self::pre_purge_paused(ctx) {
                if !noted {
                    Self::note_pre_purge_hold(ctx);
                    noted = true;
                }
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
            }
        }
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
        // The purge executed: no validated prefix survives it, so
        // the saved replay tip dies here too instead of shadowing
        // the next copy with a stale chain.
        self.verify_cursors.invalidate(subject_id);
        // The purge (or the reload, when there was nothing stored)
        // holds no requester from here on.
        Self::finish_rollback_up(ctx, subject_id).await;
        // The failed attempt left no transfer proof behind: drop any
        // anyway so a rejected batch never opens future passage.
        if let Err(error) =
            remove_verified_transfer(ctx, governance_id, subject_id).await
        {
            warn!(
                msg_type = "LedgerDistribution",
                subject_id = %subject_id,
                error = %error,
                "Failed to drop transfer proof on rollback",
            );
        }
        let gov_path = format!("/user/node/subject_manager/{governance_id}");
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

    /// Evidence preflight for inline transfers: every successful
    /// transfer inside this chunk must survive the same evidence
    /// check the apply runs, over the same local prefix plus sender
    /// suffix, before the chunk becomes visible, journaled or sunk.
    /// A checkable-but-refuted transfer rejects the whole chunk here
    /// instead of letting its prefix persist in clear and fail right
    /// after. An unjudgeable chain keeps the apply envelope
    /// semantics (passage without proof); an incomplete chain fails
    /// closed without writing. Transfers already judged with this
    /// batch (proven aux, unjudgeable aux) or under a firm proof
    /// reuse that verdict instead of replaying the prefix.
    async fn preflight_inline_transfers(
        &mut self,
        ctx: &mut ActorContext<Self>,
        chunk: &[Ledger],
        common: &CheckAuthCommon,
        batch: TransferBatch<'_>,
        attempt: u64,
    ) -> Result<(), ActorError> {
        if common.is_gov {
            return Ok(());
        }
        let mut pending: Vec<&Ledger> = Vec::new();
        for event in chunk {
            if !matches!(
                event.get_event_request_type(),
                EventRequestType::Transfer
            ) {
                continue;
            }
            let Protocols::Transfer { evaluation, .. } = &event.protocols
            else {
                continue;
            };
            if !evaluation.is_ok() {
                // Failed transfers are history without ownership
                // effects: the apply copies them on independent
                // rights and they can not unmask the prefix.
                continue;
            }
            if batch.event.is_some_and(|aux| {
                aux.sn == event.sn
                    && aux
                        .ledger_hash(self.hash)
                        .ok()
                        .zip(event.ledger_hash(self.hash).ok())
                        .is_some_and(|(left, right)| left == right)
            }) && matches!(
                batch.simulation,
                Some(
                    TransferSimulationResult::Witness
                        | TransferSimulationResult::WitnessUnverified
                )
            ) {
                continue;
            }
            // Verified-sn floor removed: it skipped by sn alone and
            // let a forged inline with the same sn reuse the genuine
            // aux verdict. The aux-identity check above already covers
            // the same-event case by hash.
            // Already covered by the validated prefix: transfers at or
            // below the tip were judged when the cursor advanced past
            // them, so they need no replay. At the exact tip, same sn
            // with different bytes is a divergence that must verify
            // instead of reusing the tip verdict.
            if let Some((tip_sn, tip_hash)) =
                self.verify_cursors.covered_tip(&common.subject_id)
            {
                if event.sn < tip_sn {
                    continue;
                }
                if event.sn == tip_sn
                    && let Ok(event_hash) = event.ledger_hash(self.hash)
                    && event_hash == tip_hash
                {
                    continue;
                }
            }
            pending.push(event);
        }
        if pending.is_empty() {
            return Ok(());
        }
        // Single scratch cursor for the whole preflight: it advances
        // between transfers so a chain of transfers reuses one
        // incremental rebuild instead of paying one full rebuild per
        // transfer. The production cursor stays untouched and is
        // restored on every exit below.
        let saved_cursors = self.verify_cursors.clone();
        let mut scratch = saved_cursors.clone();
        let mut refuted_sn: Option<u64> = None;
        let mut missing = false;
        for transfer_event in &pending {
            // Read-only check: the verdict must not advance,
            // invalidate or otherwise disturb the cursor the apply
            // path resumes from. All replay state stays in the
            // scratch above.
            let verdict = self
                .transfer_verifier
                .verify_aux_evidence(
                    &mut scratch,
                    ctx,
                    AuxEvidenceInput {
                        governance_id: &common.governance_id,
                        subject_id: &common.subject_id,
                        sender_ledger: chunk,
                        transfer_event,
                        buffered: &[],
                    },
                )
                .await;
            match verdict {
                AuxEvidence::Proven | AuxEvidence::Unverifiable => {}
                AuxEvidence::Missing => {
                    missing = true;
                    break;
                }
                AuxEvidence::Refuted => {
                    refuted_sn = Some(transfer_event.sn);
                    break;
                }
            }
        }
        // Production cursor never advances here: the scratch above
        // is discarded in favour of the entry state.
        self.verify_cursors = saved_cursors;
        if let Some(sn) = refuted_sn {
            self.drop_deferred(ctx, &common.subject_id);
            self.rollback_refuted_aux(
                ctx,
                &common.governance_id,
                &common.subject_id,
                sn,
                attempt,
            )
            .await;
            return Err(DistributorError::ReceiverNoAccess.into());
        }
        if missing {
            return Err(DistributorError::ReceiverNoAccess.into());
        }
        Ok(())
    }

    /// Receipt-side visibility: the sender's projection is a claim.
    /// Every full fact is re-checked event by event against our own
    /// register: opaque modes are masked locally, clear modes pass.
    /// Events above our governance version pass through: with a
    /// lagging governance we cannot judge grants yet, and blocking
    /// would wedge legit sync.
    async fn reproject_receipt_visibility(
        &self,
        ctx: &ActorContext<Self>,
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
                TrackerDeliveryQuery {
                    governance_id: &common.governance_id,
                    subject_id,
                    node: (*self.our_key).clone(),
                    namespace: common.namespace.clone(),
                    schema_id: common.schema_id.clone(),
                    ledger,
                },
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
        ctx: &ActorContext<Self>,
        query: TrackerDeliveryQuery<'_>,
    ) -> Result<Vec<TrackerDeliveryMode>, ActorError> {
        let TrackerDeliveryQuery {
            governance_id,
            subject_id,
            node,
            namespace,
            schema_id,
            ledger,
        } = query;
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
    /// running. For governance also tries the manual round; reports
    /// whether any round was notified so governance copies only run
    /// deferred acquisition when no supervisor exists (unsupervised
    /// version-sync path). Trackers only use the auth round.
    async fn notify_update_done(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sn: u64,
        round: u64,
        is_gov: bool,
    ) -> bool {
        use crate::update::{Update, UpdateMessage};
        let mut notified = false;
        let auth_path = ave_actors::ActorPath::from(format!(
            "/user/node/auth/{subject_id}"
        ));
        if let Ok(actor) =
            ctx.system().get_actor::<Update>(&auth_path).await
            && actor
                .tell(UpdateMessage::DistributionDone { sn, round })
                .await
                .is_ok()
        {
            notified = true;
        }
        if is_gov
            && let Ok(actor) = ctx
                .system()
                .get_actor::<Update>(&ave_actors::ActorPath::from(format!(
                    "/user/node/subject_manager/{subject_id}/gov_manual_update"
                )))
                .await
            && actor
                .tell(UpdateMessage::DistributionDone { sn, round })
                .await
                .is_ok()
        {
            notified = true;
        }
        notified
    }

    pub(crate) async fn process_last_event_distribution(
        &mut self,
        ctx: &mut ActorContext<Self>,
        ledger: Ledger,
        info: ComunicateInfo,
        sender: PublicKey,
    ) -> Result<(), ActorError> {
        // Attempt lifecycle: every pushed event owns an attempt
        // from here until this entry point returns, including error
        // paths that never reach the tracker.
        let subject_id = ledger.get_subject_id();
        let attempt = self.attempt_clock.fetch_add(1, Ordering::SeqCst);
        Self::begin_attempt(ctx, &subject_id, attempt).await;
        #[cfg(feature = "test")]
        Self::note_single_push_attempt(ctx, &subject_id, attempt);
        let result = self
            .run_last_event_distribution(ctx, ledger, info, sender, attempt)
            .await;
        Self::end_attempt(ctx, &subject_id, attempt).await;
        result
    }

    /// Hash of the locally stored event at `sn`, if readable. Used
    /// by the stale-push branch: only a byte-identical duplicate
    /// earns an ACK, never a same-SN divergence.
    async fn local_event_hash(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: &DigestIdentifier,
        sn: u64,
    ) -> Result<Option<DigestIdentifier>, ActorError> {
        let (path, subject_data) =
            get_subject_path_and_data(ctx, subject_id).await?;
        // `lo_sn` is exclusive in `GetLedger`: ask from just below.
        let lo_sn = sn.checked_sub(1);
        let found: Option<Ledger> = match subject_data {
            crate::node::SubjectData::Tracker { .. } => {
                let lease = acquire_subject(
                    ctx,
                    subject_id,
                    format!("stale_push_check:{subject_id}"),
                    None,
                    true,
                )
                .await?;
                let tracker_actor =
                    match ctx.system().get_actor::<Tracker>(&path).await {
                        Ok(actor) => actor,
                        Err(error) => {
                            lease.finish(ctx).await?;
                            return Err(error.into());
                        }
                    };
                let response = tracker_actor
                    .ask(TrackerMessage::GetLedger { lo_sn, hi_sn: sn })
                    .await;
                lease.finish(ctx).await?;
                match response? {
                    TrackerResponse::Ledger { mut ledger, .. } => ledger.pop(),
                    _ => {
                        return Err(ActorError::UnexpectedResponse {
                            path,
                            expected: "TrackerResponse::Ledger".to_owned(),
                        });
                    }
                }
            }
            crate::node::SubjectData::Governance { .. } => {
                let governance_actor =
                    ctx.system().get_actor::<Governance>(&path).await?;
                match governance_actor
                    .ask(GovernanceMessage::GetLedger { lo_sn, hi_sn: sn })
                    .await?
                {
                    GovernanceResponse::Ledger { mut ledger, .. } => {
                        ledger.pop()
                    }
                    _ => {
                        return Err(ActorError::UnexpectedResponse {
                            path,
                            expected: "GovernanceResponse::Ledger".to_owned(),
                        });
                    }
                }
            }
        };
        found
            .filter(|event| event.sn == sn)
            .map(|event| {
                event.ledger_hash(self.hash).map_err(|e| {
                    ActorError::Functional {
                        description: format!("Can not hash local event: {e}"),
                    }
                })
            })
            .transpose()
    }

    pub(crate) async fn run_last_event_distribution(
        &mut self,
        ctx: &mut ActorContext<Self>,
        mut ledger: Ledger,
        info: ComunicateInfo,
        sender: PublicKey,
        attempt: u64,
    ) -> Result<(), ActorError> {
        let subject_id = ledger.get_subject_id();
        let sn = ledger.sn;
        // Identity of the exact bytes the sender put on the wire,
        // captured before any local masking: the ack must name it
        // back so the sender only completes this generation.
        let received_hash = ledger.ledger_hash(self.hash).map_err(|e| {
            ActorError::Functional {
                description: format!("Can not hash received event: {e}"),
            }
        })?;

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
                // Stale push: only an identical duplicate earns an
                // ACK. A same-SN divergence is never acknowledged (the
                // correction request above already went out); acking
                // the received hash would confirm bytes we do not hold.
                match self.local_event_hash(ctx, &subject_id, sn).await? {
                    Some(local_hash) if local_hash == received_hash => {
                        self.send_last_event_ack(
                            sender.clone(),
                            &info,
                            &received_hash,
                        )
                        .await?;
                    }
                    Some(_) => {
                        warn!(
                            msg_type = "LastEventDistribution",
                            subject_id = %subject_id,
                            sn = sn,
                            "Stale push diverges from local event, no ack",
                        );
                        if let Some(metrics) =
                            crate::metrics::try_core_metrics()
                        {
                            metrics.observe_distribution_failure(
                                "stale_divergent_push",
                            );
                        }
                    }
                    None => {
                        warn!(
                            msg_type = "LastEventDistribution",
                            subject_id = %subject_id,
                            sn = sn,
                            "Stale push for unreadable local event, no ack",
                        );
                    }
                }
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
                attempt,
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
                        TrackerDeliveryQuery {
                            governance_id: &governance_id,
                            subject_id: &subject_id,
                            node: (*self.our_key).clone(),
                            namespace,
                            schema_id,
                            ledger: std::slice::from_ref(&ledger),
                        },
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
            Self::note_copy_success(ctx, &subject_id, attempt).await;
            None
        } else {
            let requester = Self::requester_id(
                "last_event_distribution",
                &subject_id,
                &info,
                &sender,
                attempt,
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

            #[cfg(feature = "test")]
            {
                // Test-only barrier right after the single-push
                // update decision (applied or skipped): lets a test
                // pin that the push landed before asserting on what
                // it did or did not record. Production never arms it.
                let mut noted = false;
                while Self::single_updated_paused(ctx) {
                    if !noted {
                        Self::note_single_updated_hold(ctx);
                        noted = true;
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(100))
                        .await;
                }
            }

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
                    if let Err(e) = self
                        .send_last_event_ack(
                            sender.clone(),
                            &info,
                            &received_hash,
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
                        return Err(crash_system(ctx, e).await);
                    };

                    return Ok(());
                }
                Ok((..)) => {
                    Self::note_copy_success(ctx, &subject_id, attempt).await;
                    lease
                }
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

        if let Err(e) = self
            .send_last_event_ack(sender.clone(), &info, &received_hash)
            .await
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
