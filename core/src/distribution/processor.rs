use ave_actors::{ActorContext, ActorError};
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_network::ComunicateInfo;

use crate::{
    distribution::error::DistributorError,
    distribution::transfer_verifier::TransferSimulationResult,
    distribution::worker::{CheckAuthCommon, DistriWorker},
    model::event::Ledger,
};
use crate::model::common::{
    check_subject_creation, emit_fail, record_verified_transfer,
};
use crate::model::common::subject::{
    acquire_subject, create_subject, get_local_subject_sn, update_ledger,
};
use tracing::{debug, error, warn};

impl DistriWorker {
    pub(crate) async fn process_ledger_chunks(
        &self,
        ctx: &mut ActorContext<Self>,
        mut pending_ledger: Vec<Ledger>,
        sender_is_all: bool,
        common: &CheckAuthCommon,
        transfer_event: Option<&Ledger>,
        transfer_simulation: Option<TransferSimulationResult>,
        mut verified_transfer_sn: Option<u64>,
        info: &ComunicateInfo,
        sender: PublicKey,
        subject_id: DigestIdentifier,
        ledger_count: usize,
    ) -> Result<(), ActorError> {
        let mut transfer_recorded = false;

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
                    &common,
                    transfer_event,
                    transfer_simulation.as_ref(),
                    verified_transfer_sn,
                )
                .await?;


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
                    let result = create_subject(ctx, create_ledger.clone()).await;
                    handle_distri_error!(
                        ctx,
                        result,
                        "LedgerDistribution",
                        &subject_id,
                        "Failed to create subject from ledger"
                    )?;
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

                    let result = check_subject_creation(
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
                        return Err(emit_fail(ctx, e).await);
                    };
                }
            }

            break;
        }

        Ok(())
    }


    pub(crate) async fn process_last_event_distribution(
        &self,
        ctx: &mut ActorContext<Self>,
        ledger: Ledger,
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
                            update_ledger(ctx, &subject_id, vec![ledger.clone()])
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
        Ok(())
    }
}
