use ave_actors::{ActorContext, ActorError};
use ave_common::SchemaType;
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_network::ComunicateInfo;

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
    distribution::worker::{
        CheckAuthCommon, DistriWorker, DistributionContext, TransferBatch,
    },
    governance::{
        Governance, GovernanceMessage, witnesses_register::TrackerDeliveryMode,
    },
    model::event::{Ledger, Protocols},
};
use tracing::{debug, error, warn};

impl DistriWorker {
    pub(crate) async fn process_ledger_chunks(
        &self,
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

            if !transfer_recorded
                && transfer_simulation.is_some()
                && !common.is_gov
                && let Some(transfer_event) = transfer_event
            {
                record_verified_transfer(
                    ctx,
                    &common.governance_id,
                    &subject_id,
                    transfer_event.sn,
                    sender.clone(),
                )
                .await?;
                transfer_recorded = true;
                // Refrescar verified_transfer_sn para que la siguiente
                // iteración del loop pueda usar Path C (free passage).
                verified_transfer_sn = Some(transfer_event.sn);
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
        &self,
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
            let data =
                crate::model::common::node::get_subject_data(ctx, &subject_id)
                    .await
                    .ok()
                    .flatten()
                    .filter(|data| {
                        matches!(data, crate::node::SubjectData::Tracker { .. })
                    });
            if let Some(crate::node::SubjectData::Tracker {
                governance_id,
                schema_id,
                namespace,
                ..
            }) = data
            {
                let our_gov = crate::model::common::subject::get_version(
                    ctx,
                    &governance_id,
                )
                .await
                .map_err(|e| {
                    DistributorError::VisibilityCheckFailed {
                        details: e.to_string(),
                    }
                })?;
                // A fact newer than our governance cannot be judged
                // yet: leave it for the catch-up round, which runs
                // the same check once the version lands.
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
                        .map_err(|e| {
                            DistributorError::VisibilityCheckFailed {
                                details: e.to_string(),
                            }
                        })?;
                    match modes.first() {
                        Some(
                            crate::governance::witnesses_register::TrackerDeliveryMode::Opaque,
                        ) => {
                            ledger = ledger.to_tracker_opaque().map_err(
                                |e| ActorError::Functional {
                                    description: format!(
                                        "Failed to mask pushed fact: {e:?}"
                                    ),
                                },
                            )?;
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
