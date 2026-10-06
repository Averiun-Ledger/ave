//! Boot reconciliation (AUD-088/092/106): replay register updates
//! from the ledger so derived state catches up to the persisted tip.
//!
//! Crash windows between ledger persist and register updates leave
//! registers permanently behind: the re-drive skips persisted events
//! (`InvalidSequenceNumber` → `continue`) and the missed updates
//! never run. Recomputing updates from CURRENT properties can not
//! fix removals (already-removed members/schemas resolve to
//! nothing), so this replays version by version from the ledger
//! itself with EXACT era state: every scanned event folds through
//! the real `PersistentActor::apply`, so each derivation sees the
//! same pre-event properties the live path saw (the live builders
//! run before persist/apply). No mirrors, no reimplemented folds:
//! identical inputs through identical code give identical updates.
//!
//! - fact events reuse the live builders (`roles_update_fact` +
//!   `roles_update_remove_fact` + creator builder) on pre-event
//!   properties, so member/schema removals resolve exactly;
//! - confirm events reuse the live rotation builder
//!   (`roles_update_remove_confirm`) on pre-confirm properties,
//!   with owner keys from the folded `subject_metadata` (transfer
//!   sets pending, confirm rotates — same as live);
//! - every update message carries its ledger event version, so
//!   intervals and ceiling maps land historically accurate.
//!
//! Only idempotent bulk effects replay: version-keyed register
//! writes (same version + data = same keys, and handlers skip
//! stale versions themselves). Rare tells (ownership rotation,
//! register upserts, acquisition cleanup) are ask-confirmed live:
//! an Ok means the target journaled before replying, so they are
//! durable and never replay. Properties mutations never re-run
//! (already at tip, atomic with persist) and sinks self-heal via
//! `StartupReady` catch-up.
//!
//! Residuals (documented, not silent): witness detail on
//! long-dead grants resolves against current properties; contract
//! and transfer-verification families keep their existing recovery
//! paths (sn registrations replay tracker-side).

use std::sync::Arc;

use ave_actors::{ActorContext, ActorError, ActorPath, PersistentActor};
use ave_common::governance::GovernanceEvent;
use ave_common::request::EventRequest;
use tracing::debug;

use super::events::{
    governance_event_roles_update_fact, governance_event_update_creator_change,
};
use super::role_register::{
    RoleRegister, RoleRegisterMessage, RoleRegisterResponse,
};
use super::subject_register::{
    SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
};
use super::witnesses_register::{
    WitnessesRegister, WitnessesRegisterMessage, WitnessesRegisterResponse,
};
use super::{Governance, GovernanceState};
use crate::model::common::get_n_events;
use crate::model::event::Ledger;
use crate::node::{Node, NodeMessage};

/// Ledger page size for the reconcile scan.
const RECONCILE_PAGE: u64 = 256;

/// What one replay pass reconciled, for the report.
#[derive(Debug, Default)]
pub struct ReconcileReport {
    /// Ledger versions walked.
    pub versions_seen: u64,
    /// Role update messages sent.
    pub role_updates: u64,
}

/// Folded replay state: exact era properties. Every scanned event
/// folds through the real `apply`, so derivations always see the
/// pre-event state the live path saw.
#[derive(Debug)]
struct ReconcileFold {
    era: Arc<GovernanceState>,
}

impl Default for ReconcileFold {
    fn default() -> Self {
        Self {
            era: Arc::new(GovernanceState {
                subject_metadata: Default::default(),
                properties: Default::default(),
            }),
        }
    }
}

impl Governance {
    /// Highest processed version per bulk register (role version,
    /// subject and witnesses walk maximums). Read-only queries: no
    /// state changes, no compat risk. A missing register fails the
    /// boot loud (children are created before this runs).
    async fn replay_markers(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(u64, u64, u64), ActorError> {
        let register = ctx.get_child::<RoleRegister>("role_register").await?;
        let RoleRegisterResponse::Version(role_version) =
            register.ask(RoleRegisterMessage::GetVersion).await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!("{}/role_register", ctx.path())),
                expected: "RoleRegisterResponse::Version".to_owned(),
            });
        };
        let register =
            ctx.get_child::<SubjectRegister>("subject_register").await?;
        let SubjectRegisterResponse::MaxVersion(subject_max) =
            register.ask(SubjectRegisterMessage::GetMaxVersion).await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "{}/subject_register",
                    ctx.path()
                )),
                expected: "SubjectRegisterResponse::MaxVersion".to_owned(),
            });
        };
        let register = ctx
            .get_child::<WitnessesRegister>("witnesses_register")
            .await?;
        let WitnessesRegisterResponse::MaxVersion(witnesses_max) = register
            .ask(WitnessesRegisterMessage::GetMaxVersion)
            .await?
        else {
            return Err(ActorError::UnexpectedResponse {
                path: ActorPath::from(format!(
                    "{}/witnesses_register",
                    ctx.path()
                )),
                expected: "WitnessesRegisterResponse::MaxVersion".to_owned(),
            });
        };
        Ok((role_version, subject_max, witnesses_max))
    }

    /// Best-effort reconciled report upward for resume ordering
    /// and tracker waits.
    async fn report_reconciled(&self, ctx: &mut ActorContext<Self>) {
        if let Ok(node) =
            ctx.system().get_actor::<Node>(&"/user/node".into()).await
        {
            let _ = node
                .tell(NodeMessage::GovernanceReconciled {
                    governance_id: self.subject_metadata.subject_id.clone(),
                })
                .await;
        }
    }

    /// Replays register updates from the ledger so every register
    /// family catches up to the persisted tip. Runs inside
    /// `pre_start` (before the mailbox opens: race-free by actor
    /// sequentiality). Safe to re-run: every write is version-keyed
    /// and identical data is a no-op (handlers skip stale versions
    /// themselves).
    pub(crate) async fn reconcile_registers(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<ReconcileReport, ActorError> {
        // Clean boot (or already reconciled this boot): trust the
        // role version alone instead of the flag blindly (a crash
        // between the handshake and the drain end would lie
        // otherwise). A graceful drain processes every critical send
        // — and every bulk write is critical — so role at tip means
        // nothing is missing anywhere. Walk markers are not consulted
        // here: legitimate removals lower them, which would force
        // useless replays. The node still counts this report to flip
        // readiness.
        if self.skip_reconcile {
            let (role_marker, _, _) = self.replay_markers(ctx).await?;
            if role_marker == self.properties.version {
                self.report_reconciled(ctx).await;
                debug!(
                    governance_id = %self.subject_metadata.subject_id,
                    "Boot reconciliation skipped (clean boot)"
                );
                return Ok(ReconcileReport::default());
            }
            debug!(
                governance_id = %self.subject_metadata.subject_id,
                "Clean flag set but role behind tip: replaying"
            );
        }
        let mut report = ReconcileReport::default();
        let mut fold = ReconcileFold::default();

        // Send markers: highest processed version per bulk register.
        // Crash cuts are suffixes of single-sender FIFO streams, so
        // every version at or below a marker landed on that register;
        // only newer versions resend (duplicates would converge
        // anyway, filters just spare the writes). Reads still walk
        // the whole ledger: derivations need exact era properties,
        // which only fold forward from genesis.
        let markers = self.replay_markers(ctx).await?;
        // Event-level send filter: resend from the lowest marker
        // (duplicates to caught-up streams converge harmlessly;
        // anything below every marker landed).
        let (role_marker, subject_marker, witnesses_marker) = markers;
        let min_marker = role_marker.min(subject_marker).min(witnesses_marker);

        let mut last_sn = 0u64;
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
                    event,
                    min_marker,
                    &mut fold,
                    &mut report,
                )
                .await?;
            }
            if (events.len() as u64) < RECONCILE_PAGE {
                break;
            }
        }

        // Role register version marker catches up to the tip: it
        // only moves forward and lookups resolve previous versions,
        // so jumping it is exact.
        if self.properties.version > 0 {
            if let Ok(register) =
                ctx.get_child::<RoleRegister>("role_register").await
            {
                let _ = register
                    .tell(RoleRegisterMessage::UpdateVersion {
                        version: self.properties.version,
                    })
                    .await;
            }
        }

        // Report boot reconciliation upward. Best-effort tell: the
        // node counts reports for resume ordering and tracker waits.
        self.report_reconciled(ctx).await;

        debug!(
            governance_id = %self.subject_metadata.subject_id,
            versions_seen = report.versions_seen,
            role_updates = report.role_updates,
            "Boot reconciliation complete"
        );
        Ok(report)
    }

    /// Replays one ledger event's bulk register updates, then
    /// advances the era fold through the real `apply`. Every re-sent
    /// write is idempotent and scan-ordered, so the replayed sequence
    /// converges to exactly what the live path produced. Rare tells
    /// (ownership, register upserts) are ask-confirmed live and never
    /// replay; properties mutations and sink emits are deliberately
    /// NOT replayed (see module docs).
    async fn reconcile_ledger_event(
        &self,
        ctx: &mut ActorContext<Self>,
        event: &Ledger,
        min_marker: u64,
        fold: &mut ReconcileFold,
        report: &mut ReconcileReport,
    ) -> Result<(), ActorError> {
        report.versions_seen += 1;
        // Era state BEFORE this event: removals and creator changes
        // derive pre-persist, exactly like the live derivation block.
        let pre = fold.era.clone();
        if let Some(event_request) = event.get_event_request() {
            // Same success gates as the live path: failed events only
            // leave their ledger record, so there is nothing to replay
            // for them. Mirrors `verify_new_ledger_events` exactly.
            let fact_ok = matches!(
                &event.protocols,
                crate::model::event::Protocols::GovFact {
                    evaluation,
                    approval,
                    ..
                }
                if evaluation
                    .as_ref()
                    .and_then(|evaluation| evaluation.evaluator_response_ok())
                    .is_some()
                    && approval
                        .as_ref()
                        .is_some_and(|approval| approval.approved)
            );
            let confirm_ok = matches!(
                &event.protocols,
                crate::model::event::Protocols::GovConfirm {
                    evaluation,
                    ..
                }
                if evaluation.evaluator_response_ok().is_some()
            );
            match event_request {
                EventRequest::Fact(fact_request) if fact_ok => {
                    // A committed payload that does not deserialize
                    // is local corruption: fail loud, like the live
                    // path crashes on it.
                    let gov_event: GovernanceEvent = serde_json::from_value(
                        fact_request.payload.0.clone(),
                    )
                    .map_err(|e| ActorError::Functional {
                        description: format!(
                            "reconcile: can not parse governance event: {e}"
                        ),
                    })?;
                    let rm_members = gov_event
                        .members
                        .as_ref()
                        .map_or_else(|| None, |members| members.remove.clone());
                    let rm_schemas = gov_event
                        .schemas
                        .as_ref()
                        .map_or_else(|| None, |schemas| schemas.remove.clone());
                    // Same builders, same pre-event state as live:
                    // removals resolve exactly.
                    let rm_roles = pre
                        .properties
                        .roles_update_remove_fact(rm_members, rm_schemas);
                    let creator_update = governance_event_update_creator_change(
                        &gov_event,
                        &pre.properties.members,
                        &pre.properties.roles_schema,
                    );
                    // Advance era state with the REAL apply fold first:
                    // the live path rebuilds the final update AFTER
                    // persist, with post-event members (same-event
                    // add+grant resolves), so the replay must too.
                    // Identical inputs give identical properties; a
                    // failure means persisted events no longer fold:
                    // broken node, fail the boot loud.
                    fold.era = Governance::apply(pre, event)?;
                    let post = fold.era.clone();
                    let update = governance_event_roles_update_fact(
                        &gov_event,
                        &post.properties.members,
                        Some(rm_roles),
                    );
                    // The live path sends the post-apply version (which
                    // counts this event), not the event's creation
                    // version. The bound is inclusive: same-version
                    // repeats share the marker, and ordered resend
                    // converges (later versions re-apply over).
                    if post.properties.version >= min_marker {
                        self.update_registers_fact(
                            ctx,
                            post.properties.version,
                            update,
                            creator_update,
                        )
                        .await?;
                        report.role_updates += 1;
                    }
                    // Fold already advanced above; return directly so
                    // the shared fold below does not run twice.
                    return Ok(());
                }
                EventRequest::Confirm(..) if confirm_ok => {
                    // Owner rotation: transfer staged the pending key,
                    // confirm rotates it (same as live `apply`). A
                    // confirm without pending owner is a broken ledger:
                    // fail loud, like live apply errors on it.
                    let Some(new_owner) =
                        pre.subject_metadata.new_owner.clone()
                    else {
                        return Err(ActorError::Functional {
                            description:
                                "reconcile: confirm without pending owner"
                                    .to_owned(),
                        });
                    };
                    // Owner rotation is ask-confirmed live, hence durable;
                    // only the register data replays here.
                    let update = pre.properties.roles_update_remove_confirm(
                        &pre.subject_metadata.owner,
                        &new_owner,
                    );
                    // Era advances through the real fold first: the
                    // live path sends the post-apply version.
                    fold.era = Governance::apply(pre, event)?;
                    if fold.era.properties.version >= min_marker {
                        self.update_registers_confirm(
                            ctx,
                            fold.era.properties.version,
                            update,
                        )
                        .await?;
                        report.role_updates += 1;
                    }
                    // Fold already advanced above; the shared fold
                    // below must not run twice for this event.
                    if event.sn == 0 {
                        debug_assert_eq!(event.gov_version, 0);
                        self.first_role_register_with(
                            ctx,
                            &fold.era.subject_metadata.owner.clone(),
                        )
                        .await?;
                        report.role_updates += 1;
                    }
                    return Ok(());
                }
                // Transfers, rejects, EOLs and opaque events carry no
                // bulk register writes: their tells are ask-confirmed
                // live, hence durable. They still fold below so era
                // state stays exact.
                _ => {}
            }
        }
        // Advance era state with the REAL apply fold: identical inputs
        // (same events, same order) give identical properties, so the
        // next event derives from exact era state. A failure here
        // means persisted events no longer fold: broken node, fail
        // the boot loud.
        fold.era = Governance::apply(pre, event)?;
        // Genesis (sn 0 doubles as the full-scan detector: tail
        // scans never see it): replay the v0 seed with genesis-era
        // owner. The register upsert is ask-confirmed live, hence
        // durable; only the versioned seed (cheap, idempotent) replays.
        if event.sn == 0 {
            // Tripwire for the tail invariant (versions number ledger
            // events): genesis always carries version 0.
            debug_assert_eq!(event.gov_version, 0);
            self.first_role_register_with(
                ctx,
                &fold.era.subject_metadata.owner.clone(),
            )
            .await?;
            report.role_updates += 1;
        }
        Ok(())
    }
}
