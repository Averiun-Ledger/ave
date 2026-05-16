use std::collections::HashMap;

use crate::model::common::{
    Interval, TrackerEventVisibility, TrackerStoredVisibility,
    TrackerVisibilityState,
};
use crate::model::event::Ledger;
use ave_actors::ActorError;
use ave_common::identity::DigestIdentifier;
use ave_common::request::EventRequest;
use tracing::{debug, warn};

use super::{
    TransferData, WitnessesRegister,
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
                    data.actual_new_owner_data =
                        Some((transfer_request.new_owner, event.gov_version));
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
                        let entry = data.old_owners.entry(new_owner).or_default();
                        entry.sn = event.sn;
                        entry.interval_gov_version.insert(Interval {
                            lo: new_owner_gov_version,
                            hi: event.gov_version,
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

}
