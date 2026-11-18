use std::collections::HashMap;

use ave_common::identity::DigestIdentifier;
use borsh::object_length;

use crate::metrics::try_core_metrics;
use crate::model::event::Ledger;

/// Bounds for staged first-copy prefixes, per worker. A staged
/// batch is a prefix the receiver could not verify yet; without
/// bounds a sender trickling one event per batch (or fanning out
/// over subjects) pins unbounded RAM with no write ever landing.
/// The caps sit well above a single honest batch (ingress rejects
/// batches over 10_000 events) while bounding worst-case memory
/// to tens of MB plus per-event overhead. Copying a legitimate
/// chain longer than the per-subject budget from zero rights and
/// tiny batches restarts from the applied tip instead of growing
/// forever; that tradeoff is deliberate (a persistent spillover
/// store would be a separate feature, never the ledger).
#[derive(Debug, Clone, Copy)]
pub struct DeferredLimits {
    pub max_subjects: usize,
    pub max_events_per_subject: usize,
    pub max_bytes_per_subject: u64,
    pub max_events_global: usize,
    pub max_bytes_global: u64,
}

impl DeferredLimits {
    pub const fn production() -> Self {
        Self {
            max_subjects: 64,
            max_events_per_subject: 16_384,
            max_bytes_per_subject: 16 * 1024 * 1024,
            max_events_global: 65_536,
            max_bytes_global: 64 * 1024 * 1024,
        }
    }
}

/// One subject's held-back prefix. Events stay ascending by sn:
/// staging only appends continuations past the retained tip and
/// pruning only drops an applied prefix, so order is structural
/// and never re-sorted. `sizes` parallels `events` with the
/// borsh length measured once at insert. Both byte totals are
/// cached so every budget check is O(1): `live_bytes` covers the
/// usable suffix, `stored_bytes` covers everything still in RAM
/// including the pruned dead head.
struct DeferredEntry {
    events: Vec<Ledger>,
    sizes: Vec<u64>,
    /// First live index: everything before it was pruned as
    /// already applied. The Vec keeps a dead head until it pays
    /// off to compact it.
    live_from: usize,
    live_bytes: u64,
    stored_bytes: u64,
    /// Highest applied tip already pruned away. Applied tips only
    /// move forward per subject (a rollback drops the entry), so
    /// pruning is monotonic and never resurrects events.
    pruned_through: Option<u64>,
    last_used: u64,
}

impl DeferredEntry {
    fn live_len(&self) -> usize {
        self.events.len() - self.live_from
    }

    fn stored_len(&self) -> usize {
        self.events.len()
    }

    fn live_bytes(&self) -> u64 {
        self.live_bytes
    }

    fn stored_bytes(&self) -> u64 {
        self.stored_bytes
    }

    fn tip(&self) -> Option<u64> {
        self.events.last().map(|event| event.sn)
    }
}

/// Bounded store for batches held while their aux evidence is
/// uncheckable. Volatile worker RAM only, like the cursors: a
/// reboot starts clean. Eviction always drops whole entries, so
/// no chain is ever used with a hole in it; the copy restarts
/// from the applied tip through the normal re-request path.
pub(crate) struct DeferredStore {
    entries: HashMap<DigestIdentifier, DeferredEntry>,
    limits: DeferredLimits,
    live_events: u64,
    live_bytes: u64,
    stored_events: u64,
    stored_bytes: u64,
    seq: u64,
}

impl DeferredStore {
    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            limits: DeferredLimits::production(),
            live_events: 0,
            live_bytes: 0,
            stored_events: 0,
            stored_bytes: 0,
            seq: 0,
        }
    }

    /// Replaces the store bounds and drops whole entries the new
    /// budget no longer covers, oldest first. Test-only entry
    /// point: production always uses the compiled-in defaults.
    #[cfg(feature = "test")]
    pub(crate) fn set_limits(
        &mut self,
        limits: DeferredLimits,
    ) -> Vec<DigestIdentifier> {
        self.limits = limits;
        let mut evicted = Vec::new();
        while self.over_global_budget() {
            let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(id, _)| id.clone())
            else {
                break;
            };
            self.remove(&victim);
            evicted.push(victim);
        }
        let overfull: Vec<DigestIdentifier> = self
            .entries
            .iter()
            .filter(|(_, entry)| {
                entry.stored_len() as u64
                    > self.limits.max_events_per_subject as u64
                    || entry.stored_bytes() > self.limits.max_bytes_per_subject
            })
            .map(|(id, _)| id.clone())
            .collect();
        for subject_id in overfull {
            self.remove(&subject_id);
            evicted.push(subject_id);
        }
        evicted
    }

    #[cfg(feature = "test")]
    fn over_global_budget(&self) -> bool {
        self.entries.len() > self.limits.max_subjects
            || self.stored_events > self.limits.max_events_global as u64
            || self.stored_bytes > self.limits.max_bytes_global
    }

    /// Tip of the staged (received but unapplied) prefix, if any.
    /// Staged batches never count as applied state; they only let
    /// the receiver ask for the continuation instead of replaying
    /// what it already holds.
    pub(crate) fn tip(&self, subject_id: &DigestIdentifier) -> Option<u64> {
        self.entries.get(subject_id).and_then(DeferredEntry::tip)
    }

    /// Live counters for one subject and everything still in
    /// RAM for it, for the test-only stats snapshots.
    #[cfg(feature = "test")]
    pub(crate) fn live(&self, subject_id: &DigestIdentifier) -> (u64, u64) {
        self.entries.get(subject_id).map_or((0, 0), |entry| {
            (entry.live_len() as u64, entry.live_bytes())
        })
    }

    /// Retained counters for one subject, including the pruned
    /// dead head still in RAM, for the test-only stats snapshot.
    #[cfg(feature = "test")]
    pub(crate) fn retained(&self, subject_id: &DigestIdentifier) -> (u64, u64) {
        self.entries.get(subject_id).map_or((0, 0), |entry| {
            (entry.stored_len() as u64, entry.stored_bytes())
        })
    }

    /// Drops everything at or below the applied tip. The live
    /// range stays ascending, so this is a partition over the live
    /// suffix plus an occasional compaction, never a full re-sort.
    /// Byte totals stay O(1): only the dropped prefix is summed,
    /// which is O(dropped) overall amortized. Entries left empty
    /// are removed: the store never keeps empty shells. Returns the
    /// number of live events dropped, for test-only work counting.
    pub(crate) fn prune(
        &mut self,
        subject_id: &DigestIdentifier,
        applied_tip: Option<u64>,
    ) -> u64 {
        let Some(tip) = applied_tip else {
            return 0;
        };
        let Some(entry) = self.entries.get_mut(subject_id) else {
            return 0;
        };
        if entry.pruned_through.is_some_and(|pruned| tip <= pruned) {
            return 0;
        }
        entry.pruned_through = Some(tip);
        let live = &entry.events[entry.live_from..];
        let drop = live.partition_point(|event| event.sn <= tip);
        if drop > 0 {
            let dropped: u64 = entry.sizes
                [entry.live_from..entry.live_from + drop]
                .iter()
                .sum();
            self.live_events -= drop as u64;
            self.live_bytes -= dropped;
            entry.live_from += drop;
            entry.live_bytes -= dropped;
        }
        self.compact_if_due(subject_id);
        if self
            .entries
            .get(subject_id)
            .is_some_and(|entry| entry.live_from >= entry.events.len())
        {
            self.remove(subject_id);
        }
        drop as u64
    }

    /// Live staged events for a subject. Prune first: this is a
    /// read-only view over the retained range.
    pub(crate) fn view(&self, subject_id: &DigestIdentifier) -> &[Ledger] {
        self.entries
            .get(subject_id)
            .map_or(&[], |entry| &entry.events[entry.live_from..])
    }

    /// Stages a batch whose aux can not be checked yet. Only the
    /// tip continuation reaches here (the ingress `ensure` gate
    /// rejects anything else), so every incoming event is newer
    /// than everything staged and appending keeps the order: no
    /// linear duplicate scan and no re-sort. Returns the subjects
    /// whose entries were dropped to enforce the budget (evicted
    /// LRU victims first, then the staged subject itself when the
    /// budget still does not fit): the caller must invalidate
    /// their cursors and re-request from the applied tip.
    pub(crate) fn stage(
        &mut self,
        subject_id: &DigestIdentifier,
        batch: Vec<Ledger>,
        applied_tip: Option<u64>,
    ) -> Vec<DigestIdentifier> {
        self.prune(subject_id, applied_tip);
        // Measure once, up front: unmeasurable bytes fail closed
        // instead of bypassing the budget.
        let mut staged_bytes = 0u64;
        let mut sizes = Vec::with_capacity(batch.len());
        for event in &batch {
            let Ok(len) = object_length(event) else {
                self.remove(subject_id);
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_distribution_failure("deferred_overflow");
                }
                return vec![subject_id.clone()];
            };
            staged_bytes += len as u64;
            sizes.push(len as u64);
        }
        let staged_events = batch.len() as u64;
        let mut evicted = Vec::new();
        while self.over_budget(subject_id, staged_events, staged_bytes)
            && let Some(victim) = self.eviction_victim(subject_id)
        {
            self.remove(&victim);
            if let Some(metrics) = try_core_metrics() {
                metrics.observe_distribution_failure("deferred_evict");
            }
            evicted.push(victim);
        }
        if self.over_budget(subject_id, staged_events, staged_bytes) {
            self.remove(subject_id);
            if let Some(metrics) = try_core_metrics() {
                metrics.observe_distribution_failure("deferred_overflow");
            }
            if !evicted.contains(subject_id) {
                evicted.push(subject_id.clone());
            }
            return evicted;
        }
        let entry =
            self.entries.entry(subject_id.clone()).or_insert_with(|| {
                DeferredEntry {
                    events: Vec::new(),
                    sizes: Vec::new(),
                    live_from: 0,
                    live_bytes: 0,
                    stored_bytes: 0,
                    pruned_through: None,
                    last_used: 0,
                }
            });
        debug_assert!(
            entry.events[entry.live_from..]
                .last()
                .is_none_or(|last| batch
                    .first()
                    .is_none_or(|first| last.sn < first.sn)),
            "staged batches must continue the retained tip"
        );
        entry.events.extend(batch);
        entry.sizes.extend(sizes);
        entry.live_bytes += staged_bytes;
        entry.stored_bytes += staged_bytes;
        self.live_events += staged_events;
        self.live_bytes += staged_bytes;
        self.stored_events += staged_events;
        self.stored_bytes += staged_bytes;
        self.seq = self.seq.wrapping_add(1);
        entry.last_used = self.seq;
        #[cfg(debug_assertions)]
        debug_assert!(
            entry.events[entry.live_from..]
                .windows(2)
                .all(|w| w[0].sn < w[1].sn)
        );
        evicted
    }

    /// Moves the live staged prefix out for the apply path. The
    /// store forgets it: every exit from the apply loop either
    /// applied it, rolled the copy back (which drops leftovers),
    /// or fails the batch (whose sender re-sends anything still
    /// needed). Returns the live events plus the number of
    /// in-place moves the dead-head drain performed, so callers
    /// can keep work counters exact.
    pub(crate) fn take(
        &mut self,
        subject_id: &DigestIdentifier,
        applied_tip: Option<u64>,
    ) -> (Vec<Ledger>, u64) {
        self.prune(subject_id, applied_tip);
        let Some(entry) = self.entries.remove(subject_id) else {
            return (Vec::new(), 0);
        };
        self.live_events -= entry.live_len() as u64;
        self.live_bytes -= entry.live_bytes();
        self.stored_events -= entry.stored_len() as u64;
        self.stored_bytes -= entry.stored_bytes();
        let moved = if entry.live_from > 0 {
            entry.live_len() as u64
        } else {
            0
        };
        let mut events = entry.events;
        events.drain(..entry.live_from);
        (events, moved)
    }

    /// Drops staged state for a subject: its chain proved forged
    /// or its copy is being rolled back, so nothing staged may be
    /// applied later. The sender re-sends anything still needed.
    pub(crate) fn drop(&mut self, subject_id: &DigestIdentifier) {
        self.remove(subject_id);
    }

    fn remove(&mut self, subject_id: &DigestIdentifier) {
        if let Some(entry) = self.entries.remove(subject_id) {
            self.live_events -= entry.live_len() as u64;
            self.live_bytes -= entry.live_bytes();
            self.stored_events -= entry.stored_len() as u64;
            self.stored_bytes -= entry.stored_bytes();
        }
    }

    fn over_budget(
        &self,
        subject_id: &DigestIdentifier,
        staged_events: u64,
        staged_bytes: u64,
    ) -> bool {
        let stored = self.entries.get(subject_id).map_or((0, 0), |entry| {
            (entry.stored_len() as u64, entry.stored_bytes())
        });
        stored.0 + staged_events > self.limits.max_events_per_subject as u64
            || stored.1 + staged_bytes > self.limits.max_bytes_per_subject
            || self.entries.len()
                + usize::from(!self.entries.contains_key(subject_id))
                > self.limits.max_subjects
            || self.stored_events + staged_events
                > self.limits.max_events_global as u64
            || self.stored_bytes + staged_bytes > self.limits.max_bytes_global
    }

    fn eviction_victim(
        &self,
        exclude: &DigestIdentifier,
    ) -> Option<DigestIdentifier> {
        self.entries
            .iter()
            .filter(|(id, _)| *id != exclude)
            .min_by_key(|(_, entry)| entry.last_used)
            .map(|(id, _)| id.clone())
    }

    /// Compacts the dead pruned head once it dominates the entry:
    /// each event moves O(1) times amortized, so pruning stays
    /// linear overall instead of quadratic per delivery. Totals
    /// stay O(1): the dead head is the difference between stored
    /// and live, freed without rescanning.
    fn compact_if_due(&mut self, subject_id: &DigestIdentifier) {
        let dominated = self.entries.get(subject_id).is_some_and(|entry| {
            entry.live_from >= 1024 && entry.live_from * 2 >= entry.events.len()
        });
        if !dominated {
            return;
        }
        if let Some(entry) = self.entries.get_mut(subject_id) {
            let dead = entry.live_from;
            let dead_bytes = entry.stored_bytes - entry.live_bytes;
            entry.events.drain(..dead);
            entry.sizes.drain(..dead);
            entry.live_from = 0;
            entry.stored_bytes = entry.live_bytes;
            self.stored_events -= dead as u64;
            self.stored_bytes -= dead_bytes;
        }
    }
}

#[cfg(feature = "test")]
pub(crate) type SharedDeferredStats =
    std::sync::Arc<std::sync::Mutex<DeferredStatsRegistry>>;

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    use ave_common::identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signature, TimeStamp,
        keys::{DSAlgorithm, SignatureIdentifier},
    };

    use crate::model::event::{
        EvaluationDataOpaque, EvaluationResponseOpaque, OpaqueData, Protocols,
        ValidationData, ValidationMetadata,
    };

    fn dummy_pubkey() -> PublicKey {
        PublicKey::new(DSAlgorithm::Ed25519, vec![0u8; 32]).unwrap()
    }

    fn dummy_sig() -> Signature {
        Signature {
            signer: dummy_pubkey(),
            timestamp: TimeStamp::from_nanos(0),
            content_hash: DigestIdentifier::default(),
            value: SignatureIdentifier::new(
                DSAlgorithm::Ed25519,
                vec![0u8; 64],
            )
            .unwrap(),
        }
    }

    fn synthetic_ledger(sn: u64, extra: usize) -> Ledger {
        let viewpoints = BTreeSet::from(["x".repeat(extra)]);
        Ledger {
            gov_version: 0,
            sn,
            prev_ledger_event_hash: DigestIdentifier::default(),
            ledger_seal_signature: dummy_sig(),
            protocols: Protocols::TrackerFactOpaque {
                event_request_hash: DigestIdentifier::default(),
                evaluation: EvaluationDataOpaque {
                    eval_req_signature: dummy_sig(),
                    eval_req_hash: DigestIdentifier::default(),
                    evaluators_signatures: Vec::new(),
                    viewpoints,
                    response: EvaluationResponseOpaque::Ok {
                        result_hash: DigestIdentifier::default(),
                    },
                },
                validation: ValidationData {
                    validation_req_signature: dummy_sig(),
                    validation_req_hash: DigestIdentifier::default(),
                    validators_signatures: Vec::new(),
                    validation_metadata: ValidationMetadata::ModifiedHash {
                        modified_metadata_without_propierties_hash:
                            DigestIdentifier::default(),
                        propierties_hash: DigestIdentifier::default(),
                        event_request_hash: DigestIdentifier::default(),
                        viewpoints_hash: DigestIdentifier::default(),
                    },
                },
                data: OpaqueData {
                    subject_id: DigestIdentifier::default(),
                    event_request_timestamp: TimeStamp::from_nanos(0),
                    signer: dummy_pubkey(),
                },
            },
        }
    }

    fn subject_id(byte: u8) -> DigestIdentifier {
        DigestIdentifier::new(HashAlgorithm::Blake3, vec![byte; 32]).unwrap()
    }

    fn test_limits() -> DeferredLimits {
        DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 8,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 32,
            max_bytes_global: u64::MAX,
        }
    }

    #[test]
    fn per_subject_events_boundary_evicts_whole_chain() {
        let mut store = DeferredStore::new();
        store.set_limits(test_limits());
        let id = subject_id(1);
        let batch: Vec<Ledger> =
            (0..8).map(|sn| synthetic_ledger(sn, 0)).collect();
        assert!(store.stage(&id, batch, None).is_empty());
        assert_eq!(store.live(&id).0, 8);
        let overflow = vec![synthetic_ledger(8, 0)];
        let evicted = store.stage(&id, overflow, None);
        assert!(evicted.contains(&id));
        assert_eq!(store.live(&id), (0, 0));
        assert_eq!(store.retained(&id), (0, 0));
    }

    #[test]
    fn per_subject_bytes_boundary_is_exact() {
        let mut store = DeferredStore::new();
        let one = synthetic_ledger(0, 3);
        let one_len = object_length(&one).unwrap() as u64;
        let two = synthetic_ledger(1, 3);
        let two_len = object_length(&two).unwrap() as u64;
        store.set_limits(DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 8,
            max_bytes_per_subject: one_len + two_len,
            max_events_global: 32,
            max_bytes_global: u64::MAX,
        });
        let id = subject_id(2);
        assert!(store.stage(&id, vec![one], None).is_empty());
        assert!(store.stage(&id, vec![two], None).is_empty());
        assert_eq!(store.live(&id).0, 2);
        assert_eq!(store.retained(&id).1, one_len + two_len);
        // One byte over the per-subject budget evicts the whole chain.
        let oversized = synthetic_ledger(2, 3);
        let oversized_len = object_length(&oversized).unwrap() as u64;
        assert!(oversized_len > 0);
        let evicted = store.stage(&id, vec![oversized], None);
        assert!(evicted.contains(&id));
        assert_eq!(store.live(&id), (0, 0));
        assert_eq!(store.retained(&id), (0, 0));
        assert_eq!(store.live_events, 0);
        assert_eq!(store.stored_events, 0);
        // Exactly the budget minus one byte still fits a smaller event.
        let small = synthetic_ledger(0, 0);
        let small_len = object_length(&small).unwrap() as u64;
        store.set_limits(DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 8,
            max_bytes_per_subject: small_len,
            max_events_global: 32,
            max_bytes_global: u64::MAX,
        });
        let id2 = subject_id(3);
        assert!(store.stage(&id2, vec![small], None).is_empty());
        assert_eq!(store.live(&id2).0, 1);
    }

    #[test]
    fn global_budgets_evict_lru_first() {
        let mut store = DeferredStore::new();
        store.set_limits(DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 8,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 3,
            max_bytes_global: u64::MAX,
        });
        let a = subject_id(10);
        let b = subject_id(11);
        let c = subject_id(12);
        assert!(
            store
                .stage(&a, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        assert!(
            store
                .stage(&b, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        assert!(
            store
                .stage(&c, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        assert_eq!(store.stored_events, 3);
        let d = subject_id(13);
        let evicted = store.stage(&d, vec![synthetic_ledger(0, 0)], None);
        assert!(evicted.contains(&a));
        assert!(!evicted.contains(&d));
        assert_eq!(store.live(&a), (0, 0));
        assert_eq!(store.live(&d).0, 1);
    }

    #[test]
    fn global_bytes_budget_evicts_lru_and_rejects_oversized() {
        let one = synthetic_ledger(0, 1);
        let one_len = object_length(&one).unwrap() as u64;
        let mut store = DeferredStore::new();
        store.set_limits(DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 8,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 32,
            max_bytes_global: one_len * 2,
        });
        let a = subject_id(14);
        let b = subject_id(15);
        assert!(
            store
                .stage(&a, vec![synthetic_ledger(0, 1)], None)
                .is_empty()
        );
        assert!(
            store
                .stage(&b, vec![synthetic_ledger(0, 1)], None)
                .is_empty()
        );
        assert_eq!(store.stored_bytes, one_len * 2);
        let c = subject_id(16);
        let evicted = store.stage(&c, vec![synthetic_ledger(0, 1)], None);
        assert!(evicted.contains(&a));
        assert_eq!(store.live(&c).0, 1);
        // An incoming entry larger than the whole global budget is
        // rejected even after evicting every victim.
        let big = synthetic_ledger(0, 5000);
        let big_len = object_length(&big).unwrap() as u64;
        assert!(big_len > one_len * 2);
        let d = subject_id(17);
        let evicted = store.stage(&d, vec![big], None);
        assert!(evicted.contains(&d));
        assert_eq!(store.live(&d), (0, 0));
    }

    #[test]
    fn max_subjects_evicts_least_recently_used() {
        let mut store = DeferredStore::new();
        store.set_limits(DeferredLimits {
            max_subjects: 2,
            max_events_per_subject: 8,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 32,
            max_bytes_global: u64::MAX,
        });
        let a = subject_id(20);
        let b = subject_id(21);
        assert!(
            store
                .stage(&a, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        assert!(
            store
                .stage(&b, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        assert!(
            store
                .stage(&a, vec![synthetic_ledger(1, 0)], None)
                .is_empty()
        );
        let c = subject_id(22);
        let evicted = store.stage(&c, vec![synthetic_ledger(0, 0)], None);
        assert!(evicted.contains(&b));
        assert!(!evicted.contains(&a));
        assert_eq!(store.live(&a).0, 2);
        assert_eq!(store.live(&c).0, 1);
    }

    #[test]
    fn prune_dead_head_stays_within_retained_budget() {
        let mut store = DeferredStore::new();
        let sizes: Vec<u64> = (0..4)
            .map(|sn| object_length(&synthetic_ledger(sn, 2)).unwrap() as u64)
            .collect();
        let total: u64 = sizes.iter().sum();
        store.set_limits(DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 8,
            max_bytes_per_subject: total,
            max_events_global: 32,
            max_bytes_global: total,
        });
        let id = subject_id(30);
        let batch: Vec<Ledger> =
            (0..4).map(|sn| synthetic_ledger(sn, 2)).collect();
        assert!(store.stage(&id, batch, None).is_empty());
        store.prune(&id, Some(1));
        let (live_events, _) = store.live(&id);
        let (stored_events, stored_bytes) = store.retained(&id);
        assert_eq!(live_events, 2);
        assert_eq!(stored_events, 4);
        assert!(stored_bytes <= total);
        assert_eq!(store.stored_bytes, stored_bytes);
        assert_eq!(store.live_events, live_events);
    }

    #[test]
    fn prune_compaction_keeps_live_and_stored_coherent() {
        let mut store = DeferredStore::new();
        store.set_limits(DeferredLimits {
            max_subjects: 8,
            max_events_per_subject: 4096,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 4096,
            max_bytes_global: u64::MAX,
        });
        let id = subject_id(31);
        let batch: Vec<Ledger> =
            (0..2048).map(|sn| synthetic_ledger(sn, 0)).collect();
        assert!(store.stage(&id, batch, None).is_empty());
        assert_eq!(store.live(&id).0, 2048);
        store.prune(&id, Some(1500));
        let (live_events, live_bytes) = store.live(&id);
        let (stored_events, stored_bytes) = store.retained(&id);
        assert_eq!(live_events, 2048 - 1501);
        assert_eq!(stored_events, live_events);
        assert_eq!(stored_bytes, live_bytes);
        assert_eq!(store.live_events, live_events);
        assert_eq!(store.stored_events, stored_events);
    }

    #[test]
    fn take_drop_and_limit_reset_leave_no_shells() {
        let mut store = DeferredStore::new();
        store.set_limits(test_limits());
        let id = subject_id(40);
        assert!(
            store
                .stage(
                    &id,
                    vec![synthetic_ledger(0, 0), synthetic_ledger(1, 0)],
                    None
                )
                .is_empty()
        );
        let (taken, moved) = store.take(&id, Some(0));
        assert_eq!(taken.len(), 1);
        assert_eq!(moved, 1, "pruning one event shifts the survivor once");
        assert_eq!(taken[0].sn, 1);
        assert_eq!(store.live(&id), (0, 0));
        let evicted = store.stage(&id, vec![synthetic_ledger(2, 0)], None);
        assert!(evicted.is_empty());
        assert_eq!(store.live(&id).0, 1);
        assert_eq!(store.retained(&id).0, 1);
        store.drop(&id);
        assert_eq!(store.live(&id), (0, 0));
        assert_eq!(store.retained(&id), (0, 0));
        assert_eq!(store.live_events, 0);
        assert_eq!(store.stored_events, 0);
        assert_eq!(store.live_bytes, 0);
        assert_eq!(store.stored_bytes, 0);
        let a = subject_id(41);
        let b = subject_id(42);
        assert!(
            store
                .stage(&a, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        assert!(
            store
                .stage(&b, vec![synthetic_ledger(0, 0)], None)
                .is_empty()
        );
        let evicted = store.set_limits(DeferredLimits {
            max_subjects: 1,
            max_events_per_subject: 8,
            max_bytes_per_subject: u64::MAX,
            max_events_global: 32,
            max_bytes_global: u64::MAX,
        });
        assert_eq!(evicted.len(), 1);
        assert_eq!(store.live_events, 1);
        assert_eq!(store.stored_events, 1);
    }
}

/// Test-only retained-prefix counters, per subject: exact live
/// and stored events and bytes currently held. The worker
/// snapshots the authoritative store after every mutation, so no
/// accounting path can drift silently; tests pin the exact
/// numbers. Zero cost in production: every note is `cfg(test)`-gated.
#[cfg(feature = "test")]
#[derive(Debug, Default)]
pub(crate) struct DeferredStatsRegistry {
    live: HashMap<DigestIdentifier, (u64, u64)>,
    stored: HashMap<DigestIdentifier, (u64, u64)>,
}

#[cfg(feature = "test")]
impl DeferredStatsRegistry {
    pub(crate) fn note(
        &mut self,
        subject_id: &DigestIdentifier,
        live_events: u64,
        live_bytes: u64,
        stored_events: u64,
        stored_bytes: u64,
    ) {
        if stored_events == 0 {
            self.live.remove(subject_id);
            self.stored.remove(subject_id);
        } else {
            self.live
                .insert(subject_id.clone(), (live_events, live_bytes));
            self.stored
                .insert(subject_id.clone(), (stored_events, stored_bytes));
        }
    }

    pub(crate) fn snapshot(&self) -> (usize, u64, u64) {
        let mut subjects = 0usize;
        let mut events = 0u64;
        let mut bytes = 0u64;
        for (_, (entry_events, entry_bytes)) in self.live.iter() {
            subjects += 1;
            events += *entry_events;
            bytes += *entry_bytes;
        }
        (subjects, events, bytes)
    }

    pub(crate) fn snapshot_retained(&self) -> (usize, u64, u64) {
        let mut subjects = 0usize;
        let mut events = 0u64;
        let mut bytes = 0u64;
        for (_, (entry_events, entry_bytes)) in self.stored.iter() {
            subjects += 1;
            events += *entry_events;
            bytes += *entry_bytes;
        }
        (subjects, events, bytes)
    }
}
