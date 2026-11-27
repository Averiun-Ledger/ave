use std::collections::HashMap;

use crate::model::common::{
    Interval, TrackerEventVisibility, TrackerStoredVisibility,
    TrackerVisibilityState,
};
use crate::model::event::{Ledger, Protocols};
use ave_actors::ActorError;
use ave_common::identity::DigestIdentifier;
use ave_common::request::EventRequest;
use tracing::{debug, warn};

use super::{
    OwnershipStint, OwnershipStintOutcome, TransferData, WitnessesRegister,
};

impl WitnessesRegister {
    pub(crate) fn transfer_data_from_ledger(
        subject_id: &DigestIdentifier,
        ledger: &[Ledger],
    ) -> Result<TransferData, ActorError> {
        let Some(first_ledger) = ledger.first() else {
            return Err(ActorError::Functional {
                description: format!(
                    "Missing first ledger while reconstructing tracker window for {subject_id}"
                ),
            });
        };

        if !first_ledger.is_create_event() {
            return Err(ActorError::Functional {
                description: format!(
                    "Missing create event while reconstructing tracker window for {subject_id}"
                ),
            });
        }

        let mut data = TransferData {
            actual_owner: first_ledger.ledger_seal_signature.signer.clone(),
            actual_new_owner_data: None,
            sn: first_ledger.sn,
            gov_version: first_ledger.gov_version,
            old_owners: HashMap::new(),
            ownership_transitions: Vec::new(),
            visibility_state: TrackerVisibilityState::default(),
        };
        data.visibility_state.record_event(
            0,
            TrackerStoredVisibility::Full,
            TrackerEventVisibility::NonFact,
        );

        for event in ledger {
            data.sn = event.sn;

            debug!(
                msg_type = "TransferDataFromLedger",
                subject_id = %subject_id,
                event.sn = event.sn,
                event_type = ?event.get_event_request_type(),
                actual_owner = %data.actual_owner,
                actual_new_owner = ?data.actual_new_owner_data.as_ref().map(|(o,_)| o),
                "Processing ledger event"
            );

            match event.get_event_request() {
                Some(EventRequest::Transfer(transfer_request)) => {
                    // Mirror the live tracker path: a pending transfer
                    // is only staged on successful evaluation, so a
                    // failed one must not open a reception window.
                    let ok = matches!(&event.protocols,
                        Protocols::Transfer { evaluation, .. }
                        if evaluation.evaluator_response_ok().is_some());
                    if ok {
                        data.actual_new_owner_data = Some((
                            transfer_request.new_owner,
                            event.gov_version,
                        ));
                    }
                }
                Some(EventRequest::Confirm(..)) => {
                    if let Some((new_owner, new_owner_gov_version)) =
                        data.actual_new_owner_data.take()
                    {
                        let entry = data
                            .old_owners
                            .entry(data.actual_owner.clone())
                            .or_default();
                        entry.sn = event.sn;
                        entry.interval_gov_version.insert(Interval {
                            lo: data.gov_version,
                            hi: event.gov_version,
                        });

                        // Mirrors the live path: no tracker event can
                        // commit between Transfer and Confirm while a new
                        // owner is pending, so the transfer is the
                        // immediately preceding SN.
                        let from_sn = data
                            .ownership_transitions
                            .last()
                            .map_or(0, |stint| stint.exit_sn.saturating_add(1));
                        data.ownership_transitions.push(OwnershipStint {
                            owner: data.actual_owner.clone(),
                            incoming_transfer_sn: event.sn.saturating_sub(1),
                            exit_sn: event.sn,
                            outcome: OwnershipStintOutcome::Confirmed,
                            from_sn,
                            gov_lo: data.gov_version,
                            gov_hi: event.gov_version,
                        });

                        data.actual_owner = new_owner;
                        data.gov_version = new_owner_gov_version;
                    } else {
                        warn!(
                            msg_type = "TransferDataFromLedger",
                            subject_id = %subject_id,
                            event.sn = event.sn,
                            "Confirm event without pending Transfer"
                        );
                    }
                }
                Some(EventRequest::Reject(..)) => {
                    if let Some((new_owner, new_owner_gov_version)) =
                        data.actual_new_owner_data.take()
                    {
                        let entry = data
                            .old_owners
                            .entry(new_owner.clone())
                            .or_default();
                        entry.sn = event.sn;
                        entry.interval_gov_version.insert(Interval {
                            lo: new_owner_gov_version,
                            hi: event.gov_version,
                        });

                        // Mirrors the live path: the rejected proposal is
                        // logged so the rejected node can copy, marked as
                        // rejected so it never links another owner's chain.
                        let from_sn = data
                            .ownership_transitions
                            .last()
                            .map_or(0, |stint| stint.exit_sn.saturating_add(1));
                        data.ownership_transitions.push(OwnershipStint {
                            owner: new_owner,
                            incoming_transfer_sn: event.sn.saturating_sub(1),
                            exit_sn: event.sn,
                            outcome: OwnershipStintOutcome::Rejected,
                            from_sn,
                            gov_lo: new_owner_gov_version,
                            gov_hi: event.gov_version,
                        });
                    } else {
                        warn!(
                            msg_type = "TransferDataFromLedger",
                            subject_id = %subject_id,
                            event.sn = event.sn,
                            "Reject event without pending Transfer"
                        );
                    }
                }
                _ => {}
            }
        }

        Ok(data)
    }

    /// Initial ownership state from a Create event, without replaying
    /// any tail. Lets the incremental authorization cache start from
    /// genesis and extend with new events only.
    pub(crate) fn init_transfer_data(first_ledger: &Ledger) -> TransferData {
        let mut data = TransferData {
            actual_owner: first_ledger.ledger_seal_signature.signer.clone(),
            actual_new_owner_data: None,
            sn: first_ledger.sn,
            gov_version: first_ledger.gov_version,
            old_owners: HashMap::new(),
            ownership_transitions: Vec::new(),
            visibility_state: TrackerVisibilityState::default(),
        };
        data.visibility_state.record_event(
            0,
            TrackerStoredVisibility::Full,
            TrackerEventVisibility::NonFact,
        );
        data
    }

    /// Applies one ledger event to an ownership state built by
    /// `init_transfer_data`. A Transfer only stages pending
    /// ownership when `allow_transfer` holds: the caller passes
    /// whether its Ok evaluation genuinely reproduced, so
    /// unverified Transfers stay failed history without cloning a
    /// screened copy. Confirm and Reject close pending ownership
    /// exactly like the full rebuild.
    pub(crate) fn apply_transfer_data_event(
        data: &mut TransferData,
        event: &Ledger,
        allow_transfer: bool,
    ) {
        data.sn = event.sn;
        match event.get_event_request() {
            Some(EventRequest::Transfer(transfer_request)) => {
                let ok = matches!(&event.protocols,
                    Protocols::Transfer { evaluation, .. }
                    if evaluation.evaluator_response_ok().is_some());
                if ok && allow_transfer {
                    data.actual_new_owner_data =
                        Some((transfer_request.new_owner, event.gov_version));
                }
            }
            Some(EventRequest::Confirm(..)) => {
                if let Some((new_owner, new_owner_gov_version)) =
                    data.actual_new_owner_data.take()
                {
                    let entry = data
                        .old_owners
                        .entry(data.actual_owner.clone())
                        .or_default();
                    entry.sn = event.sn;
                    entry.interval_gov_version.insert(Interval {
                        lo: data.gov_version,
                        hi: event.gov_version,
                    });
                    data.ownership_transitions.push(OwnershipStint {
                        owner: data.actual_owner.clone(),
                        incoming_transfer_sn: event.sn.saturating_sub(1),
                        exit_sn: event.sn,
                        outcome: OwnershipStintOutcome::Confirmed,
                        from_sn: data.ownership_transitions.last().map_or(
                            0,
                            |stint| stint.exit_sn.saturating_add(1),
                        ),
                        gov_lo: data.gov_version,
                        gov_hi: event.gov_version,
                    });
                    data.actual_owner = new_owner;
                    data.gov_version = new_owner_gov_version;
                }
            }
            Some(EventRequest::Reject(..)) => {
                if let Some((new_owner, new_owner_gov_version)) =
                    data.actual_new_owner_data.take()
                {
                    let entry =
                        data.old_owners.entry(new_owner.clone()).or_default();
                    entry.sn = event.sn;
                    entry.interval_gov_version.insert(Interval {
                        lo: new_owner_gov_version,
                        hi: event.gov_version,
                    });
                    data.ownership_transitions.push(OwnershipStint {
                        owner: new_owner,
                        incoming_transfer_sn: event.sn.saturating_sub(1),
                        exit_sn: event.sn,
                        outcome: OwnershipStintOutcome::Rejected,
                        from_sn: data.ownership_transitions.last().map_or(
                            0,
                            |stint| stint.exit_sn.saturating_add(1),
                        ),
                        gov_lo: new_owner_gov_version,
                        gov_hi: event.gov_version,
                    });
                }
            }
            _ => {}
        }
    }
}
