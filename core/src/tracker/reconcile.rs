//! Boot reconciliation for tracker subjects: replay derived
//! writes so governance registers catch up to the persisted tip.
//!
//! The tracker re-drive skips already-persisted events
//! (`InvalidSequenceNumber` → `continue`), losing the fire-forget
//! bulk writes of skipped events: sn registrations and visibility
//! records. The replay re-sends them scan-ordered from the ledger.
//! Rare tells (ownership, register upserts) are ask-confirmed live:
//! an Ok means the target journaled before replying, so they are
//! durable and never replay.
//!
//! Ordering: the replay waits for its own governance first, so the
//! governance's own replay (register entries, creators) is done
//! before this tracker writes into shared registers. Every target
//! write is idempotent and the replayed sequence is identical to
//! the live one, so re-sending converges instead of corrupting.
//! Sinks never re-emit here (sink catch-up owns that).

use ave_actors::{ActorContext, ActorError, ActorPath, ActorRef};
use tracing::debug;

use super::Tracker;
use crate::governance::sn_register::{
    SnRegister, SnRegisterMessage, SnRegisterResponse,
};
use crate::governance::witnesses_register::{
    WitnessesRegister, WitnessesRegisterMessage, WitnessesRegisterResponse,
};
use crate::model::common::{TrackerVisibilityState, get_n_events};
use crate::model::event::Ledger;

/// Ledger page size for the reconcile scan.
const RECONCILE_PAGE: u64 = 256;

/// Whether visibility ranges cover the tip sn on both stored and
/// event sides (exact check, not a marker: ranges are ordered and
/// non-overlapping by invariant).
fn visibility_covers_tip(state: &TrackerVisibilityState, sn: u64) -> bool {
    state.stored_ranges.iter().any(|range| {
        range.from_sn <= sn && range.to_sn.is_none_or(|to| sn <= to)
    }) && state.event_ranges.iter().any(|range| {
        range.from_sn <= sn && range.to_sn.is_none_or(|to| sn <= to)
    })
}

/// Latest recorded sn across visibility ranges (latest range
/// starts, an under-approximation — safe direction for bounding).
fn visibility_max_sn(state: &TrackerVisibilityState) -> u64 {
    state
        .stored_ranges
        .last()
        .map(|range| range.from_sn)
        .max(state.event_ranges.last().map(|range| range.from_sn))
        .unwrap_or(0)
}

/// What one replay pass reconciled, for the report.
#[derive(Debug, Default)]
pub struct TrackerReconcileReport {
    /// Ledger events walked.
    pub versions_seen: u64,
    /// Derived writes re-sent.
    pub writes_resent: u64,
}

/// Folded replay state: the previous event (for the
/// version-transition sn write). Rare tells are ask-confirmed live
/// and never replay, so no property fold is needed: every replayed
/// write derives from the event itself, and visibility mode resolves
/// to tip state (only the current mode is ever read; per-sn range
/// data is event-intrinsic).
#[derive(Default)]
struct TrackerReconcileFold {
    prev: Option<(u64, u64)>,
}

impl Tracker {
    /// Replays derived writes from the ledger so shared registers
    /// catch up to the persisted tip. Runs inside `pre_start`
    /// (before the mailbox opens) after its own governance replay.
    /// Only the tail past the lowest processed-sn marker rescans: crash cuts are suffixes of single-sender FIFO
    /// streams, so everything below it landed. Safe to re-run: every
    /// write is key-anchored with immutable per-key data.
    pub(crate) async fn reconcile_registers(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<TrackerReconcileReport, ActorError> {
        // Order after this tracker's own governance replay: its
        // register entries must exist before writing into them. Other
        // governances reconciling never blocks this tracker.
        crate::model::common::node::wait_governance_ready(
            ctx,
            &self.governance_id,
        )
        .await?;
        // Clean boot (or already reconciled this boot): the tip
        // landed everywhere instead of trusting the flag blindly. A
        // graceful drain processes every critical send — and both
        // writes below are critical — so tip markers at tip mean
        // complete. Otherwise fall through to the tail below.
        if self.skip_reconcile && self.tip_landed(ctx).await? {
            debug!(
                subject_id = %self.subject_metadata.subject_id,
                "Boot reconciliation skipped (clean boot)"
            );
            return Ok(TrackerReconcileReport::default());
        }
        let mut report = TrackerReconcileReport::default();
        let mut fold = TrackerReconcileFold::default();

        // Witness entry missing (wiped register) blocks every
        // visibility write below (the handler ignores unknown
        // subjects): recreate it first. The read above doubles as the
        // tail marker query, so this costs nothing extra. Idempotent:
        // a present entry is never default-empty.
        let (tail_start, entry_missing) = self.replay_tail_start(ctx).await?;
        if entry_missing {
            use crate::model::common::get_last_event;
            let tip_gov_version = get_last_event(ctx)
                .await?
                .map(|event: Ledger| event.gov_version)
                .unwrap_or(self.genesis_gov_version);
            let witnesses_register = ctx
                .system()
                .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                    "/user/node/subject_manager/{}/witnesses_register",
                    self.governance_id
                )))
                .await?;
            witnesses_register
                .tell(WitnessesRegisterMessage::Create {
                    subject_id: self.subject_metadata.subject_id.clone(),
                    gov_version: tip_gov_version,
                    owner: self.subject_metadata.owner.clone(),
                })
                .await?;
        }
        if tail_start > 0 {
            // Seed the version-transition write below with the event
            // right before the tail (best effort: a miss just skips
            // one redundant transition write, never correctness —
            // the underlying mapping is covered by the tail itself).
            let before: Vec<Ledger> =
                get_n_events(ctx, tail_start.saturating_sub(1), 1).await?;
            if let Some(prev_event) = before.first()
                && prev_event.sn + 1 == tail_start
            {
                fold.prev = Some((prev_event.gov_version, prev_event.sn));
            }
        }

        let sn_register = ctx
            .system()
            .get_actor::<SnRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/sn_register",
                self.governance_id
            )))
            .await?;

        let mut last_sn = tail_start;
        loop {
            let events: Vec<Ledger> =
                get_n_events(ctx, last_sn, RECONCILE_PAGE).await?;
            if events.is_empty() {
                break;
            }
            for event in &events {
                last_sn = last_sn.max(event.sn);
                self.reconcile_ledger_event(
                    ctx,
                    &sn_register,
                    event,
                    &mut fold,
                    &mut report,
                )
                .await?;
            }
            if (events.len() as u64) < RECONCILE_PAGE {
                break;
            }
        }

        // Post-batch sn cursor, like the live path sends after
        // applying (absolute set with the tip sn: no-op when already
        // there, heal when the tell was lost). This single write
        // replaces the per-event post-apply writes: they all
        // overwrote the same entry.
        if report.versions_seen > 0 {
            if let Some((gov_version, sn)) = fold.prev {
                sn_register
                    .tell(SnRegisterMessage::RegisterSn {
                        subject_id: self.subject_metadata.subject_id.clone(),
                        gov_version,
                        sn: if sn == 0 { 0 } else { sn + 1 },
                    })
                    .await?;
                report.writes_resent += 1;
            }
            let witnesses_register = ctx
                .system()
                .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                    "/user/node/subject_manager/{}/witnesses_register",
                    self.governance_id
                )))
                .await?;
            witnesses_register
                .tell(WitnessesRegisterMessage::UpdateSn {
                    subject_id: self.subject_metadata.subject_id.clone(),
                    sn: self.subject_metadata.sn,
                })
                .await?;
        }

        debug!(
            subject_id = %self.subject_metadata.subject_id,
            versions_seen = report.versions_seen,
            writes_resent = report.writes_resent,
            "Tracker boot reconciliation complete"
        );
        Ok(report)
    }

    /// Whether the tip event provably landed on both registers:
    /// its sn mapping is recorded and its visibility range covers
    /// it. Crash cuts are suffixes, so a landed tip means nothing
    /// below is missing either.
    async fn tip_landed(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<bool, ActorError> {
        use crate::model::common::get_last_event;
        let Some(tip): Option<Ledger> = get_last_event(ctx).await? else {
            return Ok(true);
        };
        let sn_register = ctx
            .system()
            .get_actor::<SnRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/sn_register",
                self.governance_id
            )))
            .await?;
        let SnRegisterResponse::MaxSn(sn_max) = sn_register
            .ask(SnRegisterMessage::GetMaxSn {
                subject_id: self.subject_metadata.subject_id.clone(),
            })
            .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}/sn_register",
                    self.governance_id
                )),
                expected: "SnRegisterResponse::MaxSn".to_owned(),
            });
        };
        if sn_max != Some(tip.sn) {
            return Ok(false);
        }
        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        let WitnessesRegisterResponse::TrackerVisibilityState { state } =
            witnesses_register
                .ask(WitnessesRegisterMessage::GetTrackerVisibilityState {
                    subject_id: self.subject_metadata.subject_id.clone(),
                })
                .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}/witnesses_register",
                    self.governance_id
                )),
                expected: "WitnessesRegisterResponse::TrackerVisibilityState"
                    .to_owned(),
            });
        };
        Ok(visibility_covers_tip(&state, tip.sn))
    }

    /// Lowest processed-sn marker across the sn map (highest
    /// recorded sn) and the visibility ranges (latest range start,
    /// an under-approximation — safe direction). Read-only queries.
    /// Unknown markers read as full scan (safe direction). Also
    /// reports whether the witnesses subject entry is missing
    /// (default-empty state), in which case the caller recreates it.
    async fn replay_tail_start(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<(u64, bool), ActorError> {
        let sn_register = ctx
            .system()
            .get_actor::<SnRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/sn_register",
                self.governance_id
            )))
            .await?;
        let SnRegisterResponse::MaxSn(sn_max) = sn_register
            .ask(SnRegisterMessage::GetMaxSn {
                subject_id: self.subject_metadata.subject_id.clone(),
            })
            .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}/sn_register",
                    self.governance_id
                )),
                expected: "SnRegisterResponse::MaxSn".to_owned(),
            });
        };
        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        let WitnessesRegisterResponse::TrackerVisibilityState { state } =
            witnesses_register
                .ask(WitnessesRegisterMessage::GetTrackerVisibilityState {
                    subject_id: self.subject_metadata.subject_id.clone(),
                })
                .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "/user/node/subject_manager/{}/witnesses_register",
                    self.governance_id
                )),
                expected: "WitnessesRegisterResponse::TrackerVisibilityState"
                    .to_owned(),
            });
        };
        Ok((
            sn_max.unwrap_or(0).min(visibility_max_sn(&state)),
            state.stored_ranges.is_empty() && state.event_ranges.is_empty(),
        ))
    }

    /// Replays one ledger event's sn registration. Visibility is
    /// handled by the caller loop; ownership tells are ask-confirmed
    /// live and never replay.
    async fn reconcile_ledger_event(
        &self,
        ctx: &ActorContext<Self>,
        sn_register: &ActorRef<SnRegister>,
        event: &Ledger,
        fold: &mut TrackerReconcileFold,
        report: &mut TrackerReconcileReport,
    ) -> Result<(), ActorError> {
        report.versions_seen += 1;
        // Visibility is recorded for every event live: replay all of
        // them with tip mode (only the current mode is read; per-sn
        // range data is event-intrinsic, so duplicates converge).
        self.record_visibility_event(ctx, event, self.visibility_mode)
            .await?;
        report.writes_resent += 1;
        // Sn registration mirrors the live path exactly. The live
        // path sends pre-apply sn (ledger sn, dense) at transition
        // and post-apply sn (ledger sn + 1, genesis excluded) at the
        // end; both are map overwrites with identical data.
        // Ownership events need nothing here: their tells are
        // ask-confirmed live, hence durable.
        if let Some((prev_gov, _)) = fold.prev
            && event.gov_version != prev_gov
        {
            sn_register
                .tell(SnRegisterMessage::RegisterSn {
                    subject_id: self.subject_metadata.subject_id.clone(),
                    gov_version: prev_gov,
                    sn: event.sn,
                })
                .await?;
            report.writes_resent += 1;
        }
        // No per-event post-apply write: every one overwrites the
        // same map entry, so only the last survives. It goes once
        // after the loop, like the witnesses tip cursor below.
        fold.prev = Some((event.gov_version, event.sn));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{visibility_covers_tip, visibility_max_sn};
    use crate::model::common::{
        TrackerEventVisibility, TrackerEventVisibilityRange,
        TrackerStoredVisibility, TrackerStoredVisibilityRange,
        TrackerVisibilityMode, TrackerVisibilityState,
    };

    fn state(
        stored: Vec<(u64, Option<u64>)>,
        events: Vec<(u64, Option<u64>)>,
    ) -> TrackerVisibilityState {
        TrackerVisibilityState {
            mode: TrackerVisibilityMode::Full,
            stored_ranges: stored
                .into_iter()
                .map(|(from_sn, to_sn)| TrackerStoredVisibilityRange {
                    from_sn,
                    to_sn,
                    visibility: TrackerStoredVisibility::Full,
                })
                .collect(),
            event_ranges: events
                .into_iter()
                .map(|(from_sn, to_sn)| TrackerEventVisibilityRange {
                    from_sn,
                    to_sn,
                    visibility: TrackerEventVisibility::NonFact,
                })
                .collect(),
        }
    }

    #[test]
    fn visibility_markers_cover_tip() {
        let state = state(vec![(0, Some(4)), (5, None)], vec![(0, None)]);
        assert!(visibility_covers_tip(&state, 4));
        assert!(visibility_covers_tip(&state, 5));
        assert!(visibility_covers_tip(&state, 9000));
        assert!(!visibility_covers_tip(&state_empty(), 0));
    }

    #[test]
    fn visibility_max_sn_under_approximates() {
        let state = state(vec![(0, Some(4)), (5, None)], vec![(0, None)]);
        // Latest range starts: safe lower bound of the true maximum.
        assert_eq!(visibility_max_sn(&state), 5);
        assert_eq!(visibility_max_sn(&state_empty()), 0);
    }

    fn state_empty() -> TrackerVisibilityState {
        state(vec![], vec![])
    }
}
