//! Boot reconciliation for tracker subjects: replay derived
//! writes so governance registers catch up to the persisted tip.
//!
//! The tracker re-drive skips already-persisted events
//! (`InvalidSequenceNumber` → `continue`), losing the fire-forget
//! bulk writes of skipped events: sn registrations and visibility
//! records. The replay re-sends them scan-ordered from the ledger.
//! Ownership derives (node, subject register, witnesses) run after
//! the tracker journal live, so a crash can only leave them behind:
//! the tail replay re-sends them in ledger order. Every target
//! write is idempotent and convergent, so re-sending heals instead
//! of corrupting.
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
use crate::governance::subject_register::{
    SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
};
use crate::governance::transfer_verification_register::{
    TransferVerificationRegister, TransferVerificationRegisterMessage,
    TransferVerificationRegisterResponse,
};
use crate::governance::witnesses_register::{
    WitnessesRegister, WitnessesRegisterMessage, WitnessesRegisterResponse,
};
use crate::model::common::{TrackerVisibilityState, get_n_events};
use crate::model::event::{Ledger, Protocols};
use crate::node::{
    Node, NodeMessage, NodeResponse, SubjectData, TransferSubject,
};
#[cfg(feature = "test")]
use crate::system::ConfigHelper;
use ave_common::request::EventRequest;

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

/// Test-only reconcile workload counters: the last boot report per
/// subject, so a regression test can pin the exact replay size
/// instead of inferring it from converged state. Same lifetime
/// and threading as the other test-only registries.
#[cfg(feature = "test")]
#[derive(Debug, Default)]
pub struct ReconcileStatsRegistry {
    reports: std::collections::HashMap<
        ave_common::identity::DigestIdentifier,
        (u64, u64),
    >,
}

/// Test-only shared reconcile counters, exposed through the
/// `reconcile_stats` helper.
#[cfg(feature = "test")]
pub type SharedReconcileStats =
    std::sync::Arc<std::sync::Mutex<ReconcileStatsRegistry>>;

#[cfg(feature = "test")]
impl ReconcileStatsRegistry {
    fn note(
        &mut self,
        subject_id: &ave_common::identity::DigestIdentifier,
        report: &TrackerReconcileReport,
    ) {
        self.reports.insert(
            subject_id.clone(),
            (report.versions_seen, report.writes_resent),
        );
    }

    pub fn snapshot(
        &self,
        subject_id: &ave_common::identity::DigestIdentifier,
    ) -> (u64, u64) {
        self.reports.get(subject_id).copied().unwrap_or_default()
    }
}

/// Folded replay state: the previous event (for the
/// version-transition sn write). Every replayed write derives from
/// the event itself, and visibility mode resolves to tip state
/// (only the current mode is ever read; per-sn range data is
/// event-intrinsic).
#[derive(Default)]
struct TrackerReconcileFold {
    prev: Option<(u64, u64)>,
}

impl Tracker {
    /// Replays derived writes from the ledger so shared registers
    /// catch up to the persisted tip. Runs inside `pre_start`
    /// (before the mailbox opens) after its own governance replay.
    /// Marker gaps are suffixes of single-sender FIFO streams, so
    /// normally only their tail rescans. Ownership projections are
    /// verified independently and force a genesis walk when they
    /// diverge below those markers. Safe to re-run: every write is
    /// key-anchored with immutable per-key data.
    pub(crate) async fn reconcile_registers(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<TrackerReconcileReport, ActorError> {
        // No ledger history (unknown subject lifted manually): nothing
        // to replay, and the registers below do not exist either.
        if crate::model::common::get_last_event(ctx).await?.is_none() {
            return Ok(TrackerReconcileReport::default());
        }
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
        // graceful drain processes every critical send, and the live
        // path awaits every ownership ask before the visibility tell,
        // so tip markers at tip mean complete. Derived destinations
        // are verified too: a cut below the markers (or a second
        // crash inside a previous replay) would otherwise skip
        // forever. Otherwise fall through to the tail below.
        let landed = self.tip_landed(ctx).await?;
        let owned = self.ownership_landed(ctx).await?;
        if self.skip_reconcile && landed && owned {
            debug!(
                subject_id = %self.subject_metadata.subject_id,
                "Boot reconciliation skipped (clean boot)"
            );
            return Ok(TrackerReconcileReport::default());
        }
        // Registers boot alongside this tracker: a first pass can
        // read them before their journals replayed, healing nothing
        // while looking diverged, or miss a write racing the walk.
        // Re-verify after each pass, bounded: every pass is
        // idempotent, and a later pass sees settled registers. The
        // returned report is the last pass.
        let mut report = TrackerReconcileReport::default();
        let mut reconciled = false;
        for _ in 0..3 {
            report = TrackerReconcileReport::default();
            self.replay_once(ctx, &mut report).await?;
            reconciled = self.ownership_landed(ctx).await?;
            if reconciled {
                break;
            }
        }
        if !reconciled {
            return Err(ActorError::Functional {
                description: format!(
                    "Tracker {} ownership projections did not converge after three reconciliation passes",
                    self.subject_metadata.subject_id
                ),
            });
        }

        debug!(
            subject_id = %self.subject_metadata.subject_id,
            versions_seen = report.versions_seen,
            writes_resent = report.writes_resent,
            "Tracker boot reconciliation complete"
        );
        #[cfg(feature = "test")]
        if let Some(stats) = ctx
            .system()
            .get_helper::<SharedReconcileStats>("reconcile_stats")
            && let Ok(mut guard) = stats.lock()
        {
            guard.note(&self.subject_metadata.subject_id, &report);
        }
        Ok(report)
    }

    /// One replay pass over the ledger from the tail (or genesis
    /// when derived writes are missing below the markers). Every
    /// write is key-anchored and idempotent, so repeated passes
    /// converge instead of corrupting.
    async fn replay_once(
        &self,
        ctx: &mut ActorContext<Self>,
        report: &mut TrackerReconcileReport,
    ) -> Result<(), ActorError> {
        let mut fold = TrackerReconcileFold::default();

        // Witness entry missing (wiped register) blocks every
        // visibility write below (the handler ignores unknown
        // subjects): recreate it first. The read above doubles as the
        // tail marker query, so this costs nothing extra. Idempotent:
        // a present entry is never default-empty.
        let (mut tail_start, entry_missing) =
            self.replay_tail_start(ctx).await?;
        if !self.ownership_landed(ctx).await? {
            // Derived writes lost below the markers (a cut between
            // their landing and a later visibility/sn persist, or a
            // second crash inside a previous replay): the tail would
            // start past the missing event and keep the divergence.
            // Walk the derives from genesis instead; every write is
            // key-anchored and idempotent, so this only costs a pass
            // on genuinely diverged boots.
            tail_start = 0;
        }
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
        // Per-node page size — TEST BUILDS ONLY (production always
        // uses 256): tests override it per node to cross page
        // boundaries with small ledgers. A missing helper reads as
        // the default (today's behavior).
        #[cfg(feature = "test")]
        let page = ctx
            .system()
            .get_helper::<ConfigHelper>("config")
            .map(|config| config.reconcile_page)
            .unwrap_or(RECONCILE_PAGE);
        #[cfg(not(feature = "test"))]
        let page = RECONCILE_PAGE;
        loop {
            let events: Vec<Ledger> = get_n_events(ctx, last_sn, page).await?;
            if events.is_empty() {
                break;
            }
            for event in &events {
                // Advance past the processed event: the store range is
                // inclusive on both ends, so resuming at max(sn) would
                // re-apply the boundary event (non-idempotent).
                last_sn = last_sn.max(event.sn.saturating_add(1));
                self.reconcile_ledger_event(
                    ctx,
                    &sn_register,
                    event,
                    &mut fold,
                    report,
                )
                .await?;
            }
            if (events.len() as u64) < page {
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
                        sn,
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
        Ok(())
    }

    /// Whether the tip event provably landed on both marker
    /// registers: its sn mapping is recorded and its visibility range
    /// covers it. Ownership projections are checked separately because
    /// a replay crash can leave them behind even with these markers
    /// at the tip.
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

    /// Whether the derived ownership writes for the persisted tip
    /// provably landed. Node must agree on effective and pending
    /// ownership, the subject register must contain the subject under
    /// its effective owner, and no proof already consumed by the local
    /// ledger may remain. A proof above the local tip is still needed
    /// by a deferred copy and is not divergence. Inactive subjects read
    /// as landed here: their external row is healed by the register
    /// backstop instead. Actor errors propagate and fail the boot loud.
    async fn ownership_landed(
        &self,
        ctx: &ActorContext<Self>,
    ) -> Result<bool, ActorError> {
        if !self.subject_metadata.active {
            return Ok(true);
        }
        let subject_id = self.subject_metadata.subject_id.clone();
        let node_path = ActorPath::from("/user/node");
        let node = ctx.system().get_actor::<Node>(&node_path).await?;
        let NodeResponse::IOwnerNewOwner {
            i_owner,
            i_new_owner,
        } = node
            .ask(NodeMessage::IOwnerNewOwnerSubject(subject_id.clone()))
            .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: node_path,
                expected: "NodeResponse::IOwnerNewOwner".to_owned(),
            });
        };
        let expected_owner = *self.our_key == self.subject_metadata.owner;
        let expected_pending = self
            .subject_metadata
            .new_owner
            .as_ref()
            .map(|owner| owner == self.our_key.as_ref());
        if i_owner != expected_owner || i_new_owner != expected_pending {
            return Ok(false);
        }

        // A known-but-unregistered subject answers (false, None) just
        // like an absent one above: require the Node entry itself, or
        // a cut between genesis apply and registration would read as
        // landed while lift and sync still miss the subject.
        let NodeResponse::SubjectData(data) = node
            .ask(NodeMessage::GetSubjectData(subject_id.clone()))
            .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: node_path,
                expected: "NodeResponse::SubjectData".to_owned(),
            });
        };
        if !matches!(data, Some(SubjectData::Tracker { .. })) {
            return Ok(false);
        }

        let gov_path =
            format!("/user/node/subject_manager/{}", self.governance_id);
        let subject_register_path =
            ActorPath::from(format!("{gov_path}/subject_register"));
        let subject_register = ctx
            .system()
            .get_actor::<SubjectRegister>(&subject_register_path)
            .await?;
        let SubjectRegisterResponse::SubjectsBatch(entries) = subject_register
            .ask(SubjectRegisterMessage::GetSubjectsByOwnerSchemaBatch {
                queries: vec![(
                    self.subject_metadata.owner.clone(),
                    self.subject_metadata.schema_id.clone(),
                    self.namespace.to_string(),
                )],
            })
            .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: subject_register_path,
                expected: "SubjectRegisterResponse::SubjectsBatch".to_owned(),
            });
        };
        if !entries
            .first()
            .is_some_and(|subjects| subjects.contains(&subject_id))
        {
            return Ok(false);
        }

        // A pending transfer is always the tip. The tail therefore
        // replays its proof consumption without requiring a genesis
        // walk solely for that proof.
        if self.subject_metadata.new_owner.is_some() {
            return Ok(true);
        }
        let transfer_verification_register = ctx
            .system()
            .get_actor::<TransferVerificationRegister>(&ActorPath::from(
                format!("{gov_path}/transfer_verification_register"),
            ))
            .await?;
        let stale = matches!(
            transfer_verification_register
                .ask(
                    TransferVerificationRegisterMessage::GetVerifiedTransferSn {
                        subject_id: subject_id.clone(),
                    },
                )
                .await?,
            TransferVerificationRegisterResponse::VerifiedTransferSn(
                Some((proof_sn, _)),
            ) if proof_sn <= self.subject_metadata.sn
        );
        Ok(!stale)
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

    /// Replays one ledger event's sn registration, visibility record
    /// and ownership derives. Ownership mirrors the live path in
    /// ledger order: node, subject register and witnesses writes that
    /// may have been lost between the journal persist and their own
    /// landing. Every write is idempotent and convergent.
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
        // path sends the pre-apply sn (last sn of the outgoing
        // version) at transition and the post-apply sn (tip sn
        // itself) at the close; both are map overwrites with
        // identical data.
        if let Some((prev_gov, prev_sn)) = fold.prev
            && event.gov_version != prev_gov
        {
            sn_register
                .tell(SnRegisterMessage::RegisterSn {
                    subject_id: self.subject_metadata.subject_id.clone(),
                    gov_version: prev_gov,
                    sn: prev_sn,
                })
                .await?;
            report.writes_resent += 1;
        }
        // Ownership derives mirror the live path in ledger order.
        // The live path persists the tracker journal first, so a cut
        // can only leave these behind: re-sending converges. No
        // gating here (unlike live): any replaying node heals the
        // shared registers even when the original sender crashed.
        self.reconcile_ownership_event(ctx, event, report).await?;
        // No per-event post-apply write: every one overwrites the
        // same map entry, so only the last survives. It goes once
        // after the loop, like the witnesses tip cursor below.
        fold.prev = Some((event.gov_version, event.sn));
        Ok(())
    }

    /// Re-sends one ledger event's ownership derives. Failed transfer
    /// events carry no ownership effect, exactly like the live path.
    async fn reconcile_ownership_event(
        &self,
        ctx: &ActorContext<Self>,
        event: &Ledger,
        report: &mut TrackerReconcileReport,
    ) -> Result<(), ActorError> {
        let subject_id = self.subject_metadata.subject_id.clone();
        if event.is_create_event() {
            let owner = event.ledger_seal_signature.signer.clone();
            let node = ctx
                .system()
                .get_actor::<Node>(&ActorPath::from("/user/node"))
                .await?;
            // The live path registers the subject in Node after the
            // genesis apply: a cut between the two leaves the ledger
            // persisted without the entry, and lift/sync miss the
            // subject. Re-sending converges (same data, idempotent).
            node.tell(NodeMessage::RegisterSubject {
                owner: owner.clone(),
                subject_id: subject_id.clone(),
                data: SubjectData::Tracker {
                    governance_id: self.governance_id.clone(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    namespace: self.namespace.to_string(),
                    active: true,
                },
            })
            .await?;
            report.writes_resent += 1;
            let witnesses_register = ctx
                .system()
                .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                    "/user/node/subject_manager/{}/witnesses_register",
                    self.governance_id
                )))
                .await?;
            witnesses_register
                .tell(WitnessesRegisterMessage::Create {
                    subject_id: subject_id.clone(),
                    gov_version: event.gov_version,
                    owner: owner.clone(),
                })
                .await?;
            report.writes_resent += 1;
            let subject_register = ctx
                .system()
                .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                    "/user/node/subject_manager/{}/subject_register",
                    self.governance_id
                )))
                .await?;
            subject_register
                .tell(SubjectRegisterMessage::CreateSubject {
                    creator: owner,
                    subject_id,
                    namespace: self.namespace.to_string(),
                    schema_id: self.subject_metadata.schema_id.clone(),
                    gov_version: event.gov_version,
                })
                .await?;
            report.writes_resent += 1;
            return Ok(());
        }
        let Some(event_request) = event.get_event_request() else {
            return Ok(());
        };
        let node = ctx
            .system()
            .get_actor::<Node>(&ActorPath::from("/user/node"))
            .await?;
        let witnesses_register = ctx
            .system()
            .get_actor::<WitnessesRegister>(&ActorPath::from(format!(
                "/user/node/subject_manager/{}/witnesses_register",
                self.governance_id
            )))
            .await?;
        match &event_request {
            EventRequest::Transfer(transfer_request) => {
                let transfer_ok = matches!(
                    &event.protocols,
                    Protocols::Transfer { evaluation, .. }
                    if evaluation.evaluator_response_ok().is_some()
                );
                if !transfer_ok {
                    return Ok(());
                }
                node.tell(NodeMessage::TransferSubject(TransferSubject {
                    name: self.subject_metadata.name.clone(),
                    subject_id: subject_id.clone(),
                    new_owner: transfer_request.new_owner.clone(),
                    actual_owner: event.ledger_seal_signature.signer.clone(),
                }))
                .await?;
                report.writes_resent += 1;
                witnesses_register
                    .tell(WitnessesRegisterMessage::Transfer {
                        subject_id: subject_id.clone(),
                        sn: event.sn,
                        new_owner: transfer_request.new_owner.clone(),
                        gov_version: event.gov_version,
                    })
                    .await?;
                report.writes_resent += 1;
                let transfer_verification_register = ctx
                    .system()
                    .get_actor::<TransferVerificationRegister>(&ActorPath::from(format!(
                        "/user/node/subject_manager/{}/transfer_verification_register",
                        self.governance_id
                    )))
                    .await?;
                // Only remove a proof this transfer consumed: a newer
                // proof (speculative, for a later transfer) must
                // survive the replay, and a genesis walk replays every
                // older transfer. Missing proof: nothing to remove.
                let verified = transfer_verification_register
                    .ask(TransferVerificationRegisterMessage::GetVerifiedTransferSn {
                        subject_id: subject_id.clone(),
                    })
                    .await?;
                let consumed = matches!(
                    verified,
                    TransferVerificationRegisterResponse::VerifiedTransferSn(
                        Some((proof_sn, _)),
                    ) if proof_sn <= event.sn
                );
                if consumed {
                    transfer_verification_register
                        .tell(TransferVerificationRegisterMessage::Remove {
                            subject_id: subject_id.clone(),
                        })
                        .await?;
                    report.writes_resent += 1;
                }
            }
            EventRequest::Reject(..) => {
                node.tell(NodeMessage::RejectTransfer(subject_id.clone()))
                    .await?;
                report.writes_resent += 1;
                witnesses_register
                    .tell(WitnessesRegisterMessage::Reject {
                        subject_id,
                        sn: event.sn,
                        gov_version: event.gov_version,
                    })
                    .await?;
                report.writes_resent += 1;
            }
            EventRequest::Confirm(..) => {
                node.tell(NodeMessage::ConfirmTransfer(subject_id.clone()))
                    .await?;
                report.writes_resent += 1;
                // Convergent move: the register drops the subject from
                // every matching owner entry, so the recorded old owner
                // does not need to be exact on replay.
                let new_owner = event.ledger_seal_signature.signer.clone();
                let subject_register = ctx
                    .system()
                    .get_actor::<SubjectRegister>(&ActorPath::from(format!(
                        "/user/node/subject_manager/{}/subject_register",
                        self.governance_id
                    )))
                    .await?;
                subject_register
                    .tell(SubjectRegisterMessage::UpdateSubject {
                        new_owner: new_owner.clone(),
                        old_owner: new_owner,
                        subject_id: subject_id.clone(),
                        namespace: self.namespace.to_string(),
                        schema_id: self.subject_metadata.schema_id.clone(),
                        gov_version: event.gov_version,
                    })
                    .await?;
                report.writes_resent += 1;
                witnesses_register
                    .tell(WitnessesRegisterMessage::Confirm {
                        subject_id,
                        sn: event.sn,
                        gov_version: event.gov_version,
                    })
                    .await?;
                report.writes_resent += 1;
            }
            EventRequest::EOL(..) => {
                node.tell(NodeMessage::EOLSubject {
                    subject_id,
                    i_owner: *self.our_key == self.subject_metadata.owner,
                })
                .await?;
                report.writes_resent += 1;
            }
            _ => {}
        }
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
