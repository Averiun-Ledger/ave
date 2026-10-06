//! Node watchdog: extreme-case backstop against silent phase hangs.
//!
//! Every request phase gets a watchdog armed from its own honest
//! worst-case budget × 1.5 margin. On expiry the node decides
//! nothing — it diagnoses (phase, elapsed vs budget), publishes a
//! system incident to the tracking sinks (recorded in the query
//! database `watchdog_incidents` table, separate from `aborts`),
//! and reboots visibly (indistinguishable from quorum loss, same
//! recovery path).
//! This is node monitoring, not consensus: nominal operation must
//! never trip it.
//!
//! Budgets span honest worst cases by construction (retries,
//! rounds, replacements included), so a healthy phase can not
//! outlive its envelope — there is deliberately no per-vote
//! renewal, which would only mask budget errors. If an envelope
//! ever proves tight, the incident log itself shows where
//! (expected vs elapsed per phase).
//!
//! Future protocols: implement one budget fn below and arm it at
//! the phase entry. Nothing else to wire.

use std::time::Duration;

use ave_common::identity::{DigestIdentifier, TimeStamp};

use crate::compilation::coordinator as compilation_coord;
use crate::compilation::pipeline::BUILD_TIMEOUT;
use crate::evaluation::coordinator as evaluation_coord;
use crate::validation::coordinator as validation_coord;

/// Margin numerator/denominator over the computed worst case (3/2 =
/// 1.5×, per user decision).
pub const MARGIN_NUMERATOR: u64 = 3;
/// Margin denominator, see [`MARGIN_NUMERATOR`].
pub const MARGIN_DENOMINATOR: u64 = 2;

/// Absolute floor: absurdly small computations still get a sane
/// window, and no phase is ever watched tighter than this.
pub const FLOOR_SECS: u64 = 300;

/// Phase names shared with `start_phase_metrics` call sites: the
/// fire handler matches on them, so a rename must move both
/// together (a mismatch fails OPEN — the watchdog never fires).
pub const PHASE_COMPILATION: &str = "compilation";
/// See [`PHASE_COMPILATION`].
pub const PHASE_EVALUATION: &str = "evaluation";
/// See [`PHASE_COMPILATION`].
pub const PHASE_APPROVAL: &str = "approval";
/// See [`PHASE_COMPILATION`].
pub const PHASE_VALIDATION: &str = "validation";

/// Coordination slack reused by every phase envelope.
///
/// Pool replacements, ACK waits and every micro-timer without its
/// own named bound. Deliberately generous (extreme backstop, not
/// tight detection). If a phase grows a new bounded wait, either
/// reference it here like the ones below or confirm this slack
/// still covers it.
pub const COORD_SLACK_SECS: u64 = 600;

/// Local compute bound per worker.
///
/// Wasmtime execution (fuel-capped, milliseconds in practice), init
/// checks and result delivery. Orders of magnitude above observed;
/// the envelope assumes it per worker sequentially.
pub const LOCAL_COMPUTE_BOUND_SECS: u64 = 300;

/// Post-deadline grace for approval: attestation rounds and
/// validator replacements after the collection deadline.
pub const APPROVAL_GRACE_SECS: u64 = 900;

/// One full send-retry cycle from attempts × interval. Every
/// coordinator exposes both as `pub(crate)` consts precisely so
/// this envelope follows retunes.
const fn send_cycle_secs(attempts: usize, interval_secs: u64) -> u64 {
    attempts as u64 * interval_secs
}

const fn apply_margin(secs: u64) -> Duration {
    Duration::from_secs(
        secs.saturating_mul(MARGIN_NUMERATOR)
            .div_ceil(MARGIN_DENOMINATOR),
    )
}

/// Worst-case budget for a compilation phase.
///
/// Per schema one full local build plus one remote result wait plus
/// its send cycle (builds are parallel in practice; the envelope
/// assumes sequential so it can never undercount). All terms
/// reference the defining constants.
pub fn budget_for_compilation(schemas: u32) -> Duration {
    let per_schema = BUILD_TIMEOUT
        .as_secs()
        .saturating_add(compilation_coord::RESULT_DEADLINE.as_secs());
    let per_schema = per_schema.saturating_add(send_cycle_secs(
        compilation_coord::SEND_RETRY_ATTEMPTS,
        compilation_coord::SEND_RETRY_INTERVAL_SECS,
    ));
    let computed = COORD_SLACK_SECS
        .saturating_add(per_schema.saturating_mul(schemas as u64));
    apply_margin(computed).max(Duration::from_secs(FLOOR_SECS))
}

/// Worst-case budget for an evaluation phase over `workers`
/// evaluators: per worker one send cycle plus local compute,
/// sequentially (replacements run one pool round after another).
pub fn budget_for_evaluation(workers: u32) -> Duration {
    let per_worker = send_cycle_secs(
        evaluation_coord::SEND_RETRY_ATTEMPTS,
        evaluation_coord::SEND_RETRY_INTERVAL_SECS,
    )
    .saturating_add(LOCAL_COMPUTE_BOUND_SECS);
    let computed = COORD_SLACK_SECS
        .saturating_add(per_worker.saturating_mul(workers as u64));
    apply_margin(computed).max(Duration::from_secs(FLOOR_SECS))
}

/// Worst-case budget for a validation phase over `workers`
/// validators: same shape as evaluation.
pub fn budget_for_validation(workers: u32) -> Duration {
    let per_worker = send_cycle_secs(
        validation_coord::SEND_RETRY_ATTEMPTS,
        validation_coord::SEND_RETRY_INTERVAL_SECS,
    )
    .saturating_add(LOCAL_COMPUTE_BOUND_SECS);
    let computed = COORD_SLACK_SECS
        .saturating_add(per_worker.saturating_mul(workers as u64));
    apply_margin(computed).max(Duration::from_secs(FLOOR_SECS))
}

/// Worst-case budget for an approval collection closing at
/// `deadline`: the remaining window plus post-deadline grace.
pub fn budget_for_approval(deadline: TimeStamp, now: TimeStamp) -> Duration {
    let remaining = deadline
        .as_nanos()
        .saturating_sub(now.as_nanos())
        .div_ceil(1_000_000_000);
    let computed = remaining.saturating_add(APPROVAL_GRACE_SECS);
    apply_margin(computed).max(Duration::from_secs(FLOOR_SECS))
}

/// Builds the diagnosis sentence from manager-known facts. New
/// protocols extend the format here, never at call sites.
pub fn incident_detail(
    phase: &str,
    expected_secs: u64,
    elapsed_secs: u64,
    request_id: &DigestIdentifier,
    gov_version: u64,
) -> String {
    format!(
        "phase {phase} produced nothing for {elapsed_secs}s against a {expected_secs}s worst-case budget          (request {request_id}, gov_version {gov_version});          the request was rebooted, no verdict was recorded"
    )
}
