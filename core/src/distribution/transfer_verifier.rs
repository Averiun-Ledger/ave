use std::collections::{HashMap, HashSet};
use std::sync::Arc;
#[cfg(feature = "test")]
use std::sync::atomic::AtomicU8;

use ave_actors::{ActorContext, ActorError};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
    request::EventRequest,
};

use crate::governance::role_register::{RoleDataRegister, SearchRole};
use crate::model::common::{
    check_quorum_signers, get_actual_roles_register, node::get_subject_data,
    subject::get_local_subject_sn,
};
use crate::model::event::{
    EvaluationData, Ledger, LedgerSeal, Protocols, ValidationMetadata,
};
use crate::node::SubjectData;
use crate::subject::Metadata;
use crate::subject::RequestSubjectData;
use crate::validation::response::ValidationRes;
use crate::validation::worker::{EventAnchor, check_evaluation};
use tracing::warn;

use super::error::DistributorError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferSimulationResult {
    /// La simulación fue afirmativa: el nodo es testigo del owner/new_owner.
    Witness,
    /// The aux chain is incomplete: the missing events may still
    /// arrive, so the batch is held unapplied without passage or
    /// proof until a later batch completes the chain.
    WitnessUnproven,
    /// The aux chain is complete but its evidence can not be
    /// judged (opaque prefix, roles gone): like the apply path,
    /// which trusts the envelope on an incomplete pre-state, the
    /// aux may open passage, but it never records a proof and can
    /// never be refuted into a rollback.
    WitnessUnverified,
    /// The aux evidence was checkable and refuted: the hint is
    /// forged and must open nothing, leaving no trace behind.
    /// Any recorded proof for it is dropped with the held batch.
    Refuted,
    /// La simulación devolvió None: no somos testigo.
    NotWitness,
}

/// Outcome of rebuilding the evaluation evidence chain for an
/// external transfer hint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuxEvidence {
    /// The aux evaluation reproduces over the sender batch
    /// continued from our own ledger: free passage with proof.
    Proven,
    /// The chain is incomplete: events between our tip and the aux
    /// are still missing, so no verdict is possible yet. A later
    /// batch may still prove or refute the aux once the missing
    /// events arrive; until then the batch is held unapplied and
    /// records nothing.
    Missing,
    /// The chain is complete and checkable, but the aux evaluation
    /// does not reproduce: the hint is forged and must open
    /// nothing, leaving no trace behind.
    Refuted,
    /// The chain reaches the aux, but its evidence can not be
    /// judged: an opaque prefix hides the properties the check
    /// would need, and the register only serves current roles. Like
    /// the apply path, which trusts the envelope when its
    /// pre-state is incomplete, the aux may open passage but never
    /// records a proof, firm or speculative.
    Unverifiable,
}

/// Trust built up while replaying a chain prefix: downgrade
/// only, never upgraded by reuse. `Proven` means every replayed
/// event reproduced fully; `EnvelopeOnly` that some event
/// advanced on its envelope (roles gone), usable as state but
/// never as proof; `Opaque` that an opaque event hides
/// properties of the pre-state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorTrust {
    Proven,
    EnvelopeOnly,
    Opaque,
}

/// Bounded evaluation-role cache keyed by (gov version,
/// schema, namespace). Roles resolve per version, so a long
/// chain replays with one lookup each; the LRU bound keeps a
/// cursor that outlives many governance versions from pinning
/// every register it ever saw. Eviction only costs a future
/// re-resolution, never correctness: a missing entry resolves
/// again, and resolution failures are never cached (the caller
/// only inserts on success; the envelope path handles the rest).
pub(crate) struct RoleCache {
    entries:
        HashMap<(u64, SchemaType, Namespace), (RoleDataRegister, u64)>,
    seq: u64,
}

impl RoleCache {
    pub(crate) const MAX_ROLES: usize = 8;

    pub(crate) fn new() -> Self {
        Self {
            entries: HashMap::new(),
            seq: 0,
        }
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn get_mut(
        &mut self,
        key: &(u64, SchemaType, Namespace),
    ) -> Option<&mut RoleDataRegister> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.entries.get_mut(key).map(|(register, last_used)| {
            *last_used = seq;
            register
        })
    }

    pub(crate) fn insert(
        &mut self,
        key: (u64, SchemaType, Namespace),
        value: RoleDataRegister,
    ) {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        if !self.entries.contains_key(&key)
            && self.entries.len() >= Self::MAX_ROLES
            && let Some(victim) = self
                .entries
                .iter()
                .min_by_key(|(_, (_, last_used))| *last_used)
                .map(|(id, _)| id.clone())
        {
            self.entries.remove(&victim);
        }
        self.entries.insert(key, (value, seq));
    }
}

/// Saved replay state for one subject chain: lets later aux
/// checks resume `verify_chain` from the tip instead of
/// rebuilding from genesis. Volatile (worker RAM only, never
/// persisted); identity-checked on every use, so a divergent
/// branch always rebuilds instead of reusing it. Verdicts are
/// keyed by the exact replay inputs (aux bytes, tip and suffix),
/// so reuse can never promote `Missing` into `Proven` nor an
/// `Unverifiable` hint into a firm proof.
pub(crate) struct VerifyCursor {
    metadata: Metadata,
    tip_hash: DigestIdentifier,
    local_tip: Option<u64>,
    trust: CursorTrust,
    roles: RoleCache,
    // (aux sn, aux bytes hash, chain tip hash, suffix fingerprint):
    // a verdict is only reusable for the exact replay inputs that
    // produced it, so a new batch can never inherit the verdict of
    // a different chain, and staleness can not hide new events.
    verdicts: HashMap<
        (u64, DigestIdentifier, DigestIdentifier, DigestIdentifier),
        AuxEvidence,
    >,
    last_used: u64,
}

/// Per-worker verification cursors, keyed by subject. Bounded
/// with LRU eviction; eviction only costs a future rebuild,
/// never correctness (a missing cursor rebuilds from scratch).
pub(crate) struct VerifyCursorStore {
    cursors: HashMap<DigestIdentifier, VerifyCursor>,
    seq: u64,
}

impl VerifyCursorStore {
    pub(crate) const MAX_CURSORS: usize = 64;

    pub(crate) fn new() -> Self {
        Self {
            cursors: HashMap::new(),
            seq: 0,
        }
    }

    pub(crate) fn get_mut(
        &mut self,
        subject_id: &DigestIdentifier,
    ) -> Option<&mut VerifyCursor> {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        self.cursors.get_mut(subject_id).map(|cursor| {
            cursor.last_used = seq;
            cursor
        })
    }

    pub(crate) fn store(
        &mut self,
        subject_id: DigestIdentifier,
        mut cursor: VerifyCursor,
    ) {
        self.seq = self.seq.wrapping_add(1);
        cursor.last_used = self.seq;
        if !self.cursors.contains_key(&subject_id)
            && self.cursors.len() >= Self::MAX_CURSORS
            && let Some(victim) = self
                .cursors
                .iter()
                .min_by_key(|(_, existing)| existing.last_used)
                .map(|(id, _)| id.clone())
        {
            self.cursors.remove(&victim);
        }
        self.cursors.insert(subject_id, cursor);
    }

    pub(crate) fn invalidate(&mut self, subject_id: &DigestIdentifier) {
        self.cursors.remove(subject_id);
    }
}

/// Test-only verification workload counters: full local reloads
/// and events fed to the aux evidence replay, per subject.
/// Proves the incremental check stays linear instead of
/// re-scanning the prefix per aux. Zero cost in production:
/// every increment is `cfg(test)`-gated, no locks or tasks.
#[cfg(feature = "test")]
#[derive(Debug, Default)]
pub(crate) struct VerifyStatsRegistry {
    processed: HashMap<DigestIdentifier, u64>,
    reloads: HashMap<DigestIdentifier, u64>,
    full_rebuilds: HashMap<DigestIdentifier, u64>,
    buffer_cloned: HashMap<DigestIdentifier, u64>,
    buffer_visited: HashMap<DigestIdentifier, u64>,
    buffer_reordered: HashMap<DigestIdentifier, u64>,
    roles_resolved: HashMap<DigestIdentifier, u64>,
}

#[cfg(feature = "test")]
pub(crate) type SharedVerifyStats =
    std::sync::Arc<std::sync::Mutex<VerifyStatsRegistry>>;

#[cfg(feature = "test")]
impl VerifyStatsRegistry {
    pub(crate) fn add_processed(
        &mut self,
        subject_id: &DigestIdentifier,
        n: u64,
    ) {
        *self.processed.entry(subject_id.clone()).or_default() += n;
    }

    pub(crate) fn add_reload(&mut self, subject_id: &DigestIdentifier) {
        *self.reloads.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn add_full_rebuild(&mut self, subject_id: &DigestIdentifier) {
        *self.full_rebuilds.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn full_rebuilds(&self, subject_id: &DigestIdentifier) -> u64 {
        self.full_rebuilds.get(subject_id).copied().unwrap_or(0)
    }

    /// Suffix assembly work: cloned events, examined source
    /// events and reordered elements per delivery. The merge emits
    /// in ascending order by construction and the partition probes
    /// skip whole verified prefixes logarithmically, so all stay
    /// linear in the new events instead of rescanning the prefix.
    /// The full-path rebuild sorts once and counts its length as
    /// reordered; the incremental merge never reorders.
    pub(crate) fn add_buffer_work(
        &mut self,
        subject_id: &DigestIdentifier,
        cloned: u64,
        visited: u64,
        reordered: u64,
    ) {
        *self.buffer_cloned.entry(subject_id.clone()).or_default() += cloned;
        *self.buffer_visited.entry(subject_id.clone()).or_default() += visited;
        if reordered > 0 {
            *self.buffer_reordered.entry(subject_id.clone()).or_default() +=
                reordered;
        }
    }

    pub(crate) fn snapshot(&self, subject_id: &DigestIdentifier) -> (u64, u64) {
        (
            self.processed.get(subject_id).copied().unwrap_or(0),
            self.reloads.get(subject_id).copied().unwrap_or(0),
        )
    }

    pub(crate) fn buffer_snapshot(
        &self,
        subject_id: &DigestIdentifier,
    ) -> (u64, u64, u64) {
        (
            self.buffer_cloned.get(subject_id).copied().unwrap_or(0),
            self.buffer_visited.get(subject_id).copied().unwrap_or(0),
            self.buffer_reordered.get(subject_id).copied().unwrap_or(0),
        )
    }

    pub(crate) fn add_roles_resolved(&mut self, subject_id: &DigestIdentifier) {
        *self.roles_resolved.entry(subject_id.clone()).or_default() += 1;
    }

    pub(crate) fn roles_resolved(&self, subject_id: &DigestIdentifier) -> u64 {
        self.roles_resolved.get(subject_id).copied().unwrap_or(0)
    }
}

pub(crate) struct TransferVerifier {
    hash: HashAlgorithm,
    our_key: Arc<PublicKey>,
    /// Test-only one-shot fault: fail the tracker resolve right
    /// after a successful `Up` in `load_local_ledger`, proving the
    /// lease is released on that path. 0 idle, 1 armed; consumed
    /// once. Production never arms it.
    #[cfg(feature = "test")]
    pub(crate) test_tracker_resolve_fault: AtomicU8,
}

impl TransferVerifier {
    pub(crate) const fn new(
        hash: HashAlgorithm,
        our_key: Arc<PublicKey>,
    ) -> Self {
        Self {
            hash,
            our_key,
            #[cfg(feature = "test")]
            test_tracker_resolve_fault: AtomicU8::new(0),
        }
    }

    /// Lightweight cryptographic check of a Transfer event.
    /// With `require_ok` the evaluation must be successful: passage
    /// proofs only open access on success. Without it, failed
    /// transfers still pass every cryptographic and structural
    /// check (a committed failure is valid history); they just
    /// grant no ownership, which the caller must enforce.
    /// `prev_event` is the ledger predecessor when known (the
    /// event with `sn - 1` inside the same batch): the transfer
    /// must link to it, otherwise a re-sealed event could open
    /// reception before the apply-time chain check.
    pub(crate) async fn verify_light(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        transfer_event: &Ledger,
        expected_subject_id: &DigestIdentifier,
        ledger: &Ledger,
        require_ok: bool,
        prev_event: Option<&Ledger>,
    ) -> Result<(DigestIdentifier, bool, Option<SubjectData>), DistributorError>
    {
        // 1. El protocolo debe ser Transfer.
        let (event_request, evaluation, validation) =
            match &transfer_event.protocols {
                Protocols::Transfer {
                    event_request,
                    evaluation,
                    validation,
                } => (event_request, evaluation, validation),
                _ => {
                    return Err(DistributorError::TransferEventInvalid {
                        details: "protocol is not Transfer".to_string(),
                    });
                }
            };

        if require_ok && !evaluation.is_ok() {
            return Err(DistributorError::TransferEventInvalid {
                details: "transfer evaluation is not ok".to_string(),
            });
        }

        // Chain link: the transfer must extend its predecessor.
        // A re-sealed event with a forged previous hash passes
        // every check below, so the link is verified up front,
        // before ownership is rebuilt from the batch.
        if let Some(prev) = prev_event {
            let prev_hash = prev.ledger_hash(self.hash).map_err(|e| {
                DistributorError::TransferEventInvalid {
                    details: format!("prev hash failed: {e}"),
                }
            })?;
            if transfer_event.prev_ledger_event_hash != prev_hash {
                return Err(DistributorError::TransferEventInvalid {
                    details: "transfer does not link to previous event"
                        .to_string(),
                });
            }
        }

        if validation.validators_signatures.is_empty() {
            return Err(DistributorError::TransferEventInvalid {
                details: "transfer validation signatures are empty".to_string(),
            });
        }

        let ValidationMetadata::ModifiedHash {
            modified_metadata_without_propierties_hash,
            propierties_hash,
            event_request_hash,
            viewpoints_hash,
        } = &validation.validation_metadata
        else {
            return Err(DistributorError::TransferEventInvalid {
                details: "invalid validation metadata type".to_string(),
            });
        };

        let validation_res = ValidationRes::Response {
            vali_req_hash: validation.validation_req_hash.clone(),
            modified_metadata_without_propierties_hash:
                modified_metadata_without_propierties_hash.clone(),
            propierties_hash: propierties_hash.clone(),
            event_request_hash: event_request_hash.clone(),
            viewpoints_hash: viewpoints_hash.clone(),
            // Transfers never carry an approval requirement.
            approval_data_hash: None,
        };

        for signature in validation.validators_signatures.iter() {
            let signed_res =
                Signed::from_parts(validation_res.clone(), signature.clone());
            if signed_res.verify().is_err() {
                return Err(DistributorError::TransferEventInvalid {
                    details: "invalid validator signature".to_string(),
                });
            }
        }

        // 2. El EventRequest interno debe ser Transfer.
        let transfer = match event_request.content() {
            EventRequest::Transfer(t) => t,
            _ => {
                return Err(DistributorError::TransferEventInvalid {
                    details: "event request is not Transfer".to_string(),
                });
            }
        };

        // 2b. Bind the quorum attestation to the presented request: the
        // validator signatures above cover the stored request hash, so
        // recompute it from the presented request. Without this, a valid
        // quorum block from another event could back a different Transfer.
        let recomputed_request_hash =
            hash_borsh(&*self.hash.hasher(), event_request).map_err(|e| {
                DistributorError::TransferEventInvalid {
                    details: format!("request hash failed: {}", e),
                }
            })?;
        if recomputed_request_hash != *event_request_hash {
            return Err(DistributorError::TransferEventInvalid {
                details: "event request hash mismatch".to_string(),
            });
        }

        // 3. Verificar firma del ledger_seal.
        let protocols_hash = transfer_event
            .protocols
            .hash_for_ledger(&self.hash)
            .map_err(|e| DistributorError::TransferEventInvalid {
                details: format!("protocol hash failed: {}", e),
            })?;

        let ledger_seal = LedgerSeal {
            gov_version: transfer_event.gov_version,
            sn: transfer_event.sn,
            prev_ledger_event_hash: transfer_event
                .prev_ledger_event_hash
                .clone(),
            protocols_hash,
        };

        if transfer_event
            .ledger_seal_signature
            .verify(&ledger_seal)
            .is_err()
        {
            return Err(DistributorError::TransferEventInvalid {
                details: "ledger seal signature invalid".to_string(),
            });
        }

        // 4. Verificar firma del event_request.
        if event_request.verify().is_err() {
            return Err(DistributorError::TransferEventInvalid {
                details: "event request signature invalid".to_string(),
            });
        }

        // 5. Coherencia interna: ambos signers deben coincidir.
        let ledger_signer = &transfer_event.ledger_seal_signature.signer;
        let request_signer = &event_request.signature().signer;
        if ledger_signer != request_signer {
            return Err(DistributorError::TransferEventInvalid {
                details: format!(
                    "signer mismatch: ledger_signer={}, request_signer={}",
                    ledger_signer, request_signer
                ),
            });
        }

        // 6. Verificar subject_id.
        if event_request.content().get_subject_id() != *expected_subject_id {
            return Err(DistributorError::TransferEventInvalid {
                details: "subject id mismatch".to_string(),
            });
        }

        // 7. Coherencia del Transfer: no puedes transferirte a ti mismo.
        if transfer.new_owner == *request_signer {
            return Err(DistributorError::TransferEventInvalid {
                details: "new_owner is the same as signer".to_string(),
            });
        }

        // 8. Verificar quorum de validación.
        let subject_data = get_subject_data(ctx, expected_subject_id)
            .await
            .map_err(|e| DistributorError::TransferEventInvalid {
                details: format!("failed to get subject data: {}", e),
            })?;

        let (governance_id, schema_id, namespace, is_register) =
            match &subject_data {
                Some(SubjectData::Tracker {
                    governance_id,
                    schema_id,
                    namespace,
                    ..
                }) => (
                    governance_id.clone(),
                    schema_id.clone(),
                    Namespace::from(namespace.clone()),
                    true,
                ),
                Some(SubjectData::Governance { .. }) => {
                    return Err(DistributorError::TransferEventInvalid {
                        details: "subject is governance".to_string(),
                    });
                }
                None => {
                    let Some(create) = ledger.get_create_event() else {
                        return Err(DistributorError::TransferEventInvalid {
                            details: "ledger has no create event".to_string(),
                        });
                    };
                    if create.schema_id.is_gov()
                        || create.governance_id.is_empty()
                    {
                        return Err(DistributorError::TransferEventInvalid {
                            details: "invalid create event for transfer hint"
                                .to_string(),
                        });
                    }

                    (
                        create.governance_id,
                        create.schema_id,
                        create.namespace,
                        false,
                    )
                }
            };

        let role_data = crate::model::common::get_validation_roles_register(
            ctx,
            &governance_id,
            SearchRole {
                schema_id,
                namespace,
            },
            transfer_event.gov_version,
        )
        .await
        .map_err(|e| DistributorError::TransferEventInvalid {
            details: format!("failed to get validation roles: {}", e),
        })?;

        if !check_quorum_signers(
            &validation
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<_>>(),
            &role_data.quorum,
            &role_data.workers,
        ) {
            return Err(DistributorError::TransferEventInvalid {
                details: "quorum check failed".to_string(),
            });
        }

        Ok((governance_id, is_register, subject_data))
    }

    /// Pre-authorization evidence for first-copy batches. Rebuilds
    /// the pre-transfer properties from the batch prefix itself
    /// (genesis plus each evidence-checked event) and runs the full
    /// evaluation check over them. Returns the SNs of inline
    /// transfers whose Ok evaluation genuinely reproduces: only
    /// those may open pending ownership during reception. Anything
    /// else (failed, unverifiable or forged evidence) grants
    /// nothing, though the batch can still be copied on independent
    /// rights. Fails closed at the first gap: transfers past an
    /// unchecked event stay unverified.
    pub(crate) async fn verified_inline_transfers(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        _subject_id: &DigestIdentifier,
        ledger: &[Ledger],
    ) -> HashSet<u64> {
        let mut ordered = ledger.to_vec();
        ordered.sort_by_key(|event| event.sn);
        #[cfg(feature = "test")]
        Self::note_buffer_work(
            ctx,
            _subject_id,
            ordered.len() as u64,
            ordered.len() as u64,
            ordered.len() as u64,
        );
        let Some(mut cursor) = Self::genesis_metadata(&ordered) else {
            return HashSet::new();
        };
        // Roles repeat per governance version, not per event: cache
        // them so a long first-copy batch costs one lookup.
        let mut roles_cache = RoleCache::new();
        let (proven, _, _, _) = self
            .verify_chain(
                ctx,
                governance_id,
                &mut cursor,
                &ordered[1..],
                &mut roles_cache,
            )
            .await;
        proven
    }

    /// Genesis pre-state of a Create-led batch, if usable.
    pub(crate) fn genesis_metadata(ordered: &[Ledger]) -> Option<Metadata> {
        let create = ordered.first().filter(|e| e.is_create_event())?;
        if create.sn != 0 {
            return None;
        }
        let Protocols::Create { validation, .. } = &create.protocols else {
            return None;
        };
        let ValidationMetadata::Metadata(genesis) =
            &validation.validation_metadata
        else {
            return None;
        };
        Some(genesis.as_ref().clone())
    }

    /// Evidence gate for an external transfer hint: the aux grants
    /// free passage only if its evaluation reproduces over a
    /// trustworthy pre-state. That is the receiver's own ledger
    /// continued with the sender batch, or batch genesis when the
    /// subject is unknown. Anything else (gap, opaque or diverged
    /// prefix, unverifiable evidence) yields Missing, so the caller
    /// defers instead of opening passage on seal and quorum alone.
    /// Checkable but wrong evidence yields Refuted instead. An
    /// already applied transfer needs no gate.
    ///
    /// Test-only verification workload counters, proving the
    /// incremental check stays linear instead of re-scanning the
    /// prefix per aux. Zero cost in production: every increment is
    /// `cfg(test)`-gated, no locks or tasks.
    #[cfg(feature = "test")]
    fn note_verify_work(
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
        processed: u64,
        reload: bool,
    ) {
        if let Some(stats) =
            ctx.system().get_helper::<SharedVerifyStats>("verify_stats")
        {
            let mut guard = stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if reload {
                guard.add_reload(subject_id);
            }
            if processed > 0 {
                guard.add_processed(subject_id, processed);
            }
        }
    }

    /// Test-only buffer workload counters: cloned events,
    /// merge/dedup visits and reordered elements per suffix
    /// assembly and full rebuild. The merge emits in ascending
    /// order by construction and the partition probes skip whole
    /// verified prefixes logarithmically, so all stay linear in
    /// the new events. Zero cost in production: every increment is
    /// `cfg(test)`-gated.
    #[cfg(feature = "test")]
    fn note_buffer_work(
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
        cloned: u64,
        visited: u64,
        reordered: u64,
    ) {
        if let Some(stats) =
            ctx.system().get_helper::<SharedVerifyStats>("verify_stats")
        {
            let mut guard = stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            if cloned > 0 || visited > 0 || reordered > 0 {
                guard.add_buffer_work(subject_id, cloned, visited, reordered);
            }
        }
    }

    /// Test-only full-rebuild counter: counts authoritative
    /// rebuilds from genesis, so a test can tell an incremental
    /// suffix replay apart from a full scan.
    #[cfg(feature = "test")]
    fn note_full_rebuild(
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) =
            ctx.system().get_helper::<SharedVerifyStats>("verify_stats")
        {
            stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .add_full_rebuild(subject_id);
        }
    }

    /// Test-only role-resolution counter: successful evaluation
    /// role lookups per subject. Proves repeated events resolve
    /// once per cached version instead of hitting the register
    /// per event. Zero cost in production: `cfg(test)`-gated.
    #[cfg(feature = "test")]
    fn note_roles_resolved(
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
    ) {
        if let Some(stats) =
            ctx.system().get_helper::<SharedVerifyStats>("verify_stats")
        {
            let mut guard = stats
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            guard.add_roles_resolved(subject_id);
        }
    }

    /// Reloads one applied-ledger window for the evidence replay.
    /// `lo_sn` is exclusive: events after it up to `hi_sn` come
    /// back. Any failure (missing tracker, failed read) is `None`:
    /// callers fail closed instead of judging on a partial chain.
    /// The reload runs inside a subject lease: every exit after a
    /// successful `Up` releases the requester, so a failed resolve
    /// can never pin `aux-evidence` until reboot.
    async fn load_local_ledger(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
        lo_sn: Option<u64>,
        hi_sn: u64,
    ) -> Option<Vec<Ledger>> {
        let path = ave_actors::ActorPath::from(format!(
            "/user/node/subject_manager/{subject_id}"
        ));
        // An idle tracker is already stopped: only live
        // requesters keep it running, so reload it for the read
        // and release the lease right away.
        let tracker = match ctx
            .system()
            .get_actor::<crate::tracker::Tracker>(&path)
            .await
        {
            Ok(tracker) => tracker,
            Err(_) => {
                // Test-only one-shot fault: fail the resolve after
                // a successful Up, proving the lease is released on
                // that path too. Consumed once, when armed.
                #[cfg(feature = "test")]
                let fail_resolve = self
                    .test_tracker_resolve_fault
                    .swap(0, std::sync::atomic::Ordering::SeqCst)
                    != 0;
                #[cfg(not(feature = "test"))]
                let fail_resolve = false;
                let lease = match crate::model::common::subject::acquire_subject(
                    ctx,
                    subject_id,
                    "aux-evidence".to_owned(),
                    None,
                    true,
                )
                .await
                {
                    Ok(lease) => lease,
                    // Up failed: nothing was registered, so there
                    // is no lease to release.
                    Err(_) => return None,
                };
                let loaded = if fail_resolve {
                    None
                } else {
                    match ctx
                        .system()
                        .get_actor::<crate::tracker::Tracker>(&path)
                        .await
                    {
                        Err(_) => None,
                        Ok(tracker) => {
                            match tracker
                                .ask(crate::tracker::TrackerMessage::GetLedger {
                                    lo_sn,
                                    hi_sn,
                                })
                                .await
                            {
                                Ok(crate::tracker::TrackerResponse::Ledger {
                                    ledger,
                                    ..
                                }) => Some(ledger),
                                _ => None,
                            }
                        }
                    }
                };
                // A release failure is logged, never confused with
                // evidence: the verdict below only depends on the
                // read itself.
                if let Err(error) = lease.finish(ctx).await {
                    warn!(
                        msg_type = "AuxEvidenceReload",
                        subject_id = %subject_id,
                        error = %error,
                        "Failed to release aux-evidence requester",
                    );
                }
                return loaded;
            }
        };
        let fetched = tracker
            .ask(crate::tracker::TrackerMessage::GetLedger { lo_sn, hi_sn })
            .await;
        match fetched {
            Ok(crate::tracker::TrackerResponse::Ledger { ledger, .. }) => {
                Some(ledger)
            }
            _ => None,
        }
    }

    /// Identity of the exact replay inputs: chain tip plus every
    /// event about to be replayed. Verdicts cached under it can
    /// only be reused by the identical aux over the identical
    /// chain, so staleness can never hide newly arrived events.
    fn chain_fingerprint(
        &self,
        tip_sn: u64,
        tip_hash: &DigestIdentifier,
        events: &[Ledger],
    ) -> Option<DigestIdentifier> {
        let mut parts: Vec<(u64, DigestIdentifier)> =
            Vec::with_capacity(events.len() + 1);
        parts.push((tip_sn, tip_hash.clone()));
        for event in events {
            parts.push((event.sn, event.ledger_hash(self.hash).ok()?));
        }
        hash_borsh(&*self.hash.hasher(), &parts).ok()
    }

    /// Merges individually ascending runs into one ascending
    /// chain, keeping the first copy on ties: precedence runs
    /// delta, held, sender, aux, i.e. authoritative order. A linear
    /// merge replaces the full re-sort: nothing already ordered is
    /// ever reordered. Runs must arrive ascending (ingress sorts
    /// the sender batch, staged batches only append past the tip,
    /// the store reads ascending); a misordered run fails closed
    /// downstream, with a debug assertion catching it in tests.
    fn merge_runs(runs: [&[Ledger]; 4]) -> Vec<Ledger> {
        #[cfg(debug_assertions)]
        for run in runs {
            debug_assert!(
                run.windows(2).all(|w| w[0].sn <= w[1].sn),
                "merge inputs must arrive ascending"
            );
        }
        let total: usize = runs.iter().map(|run| run.len()).sum();
        let mut out: Vec<Ledger> = Vec::with_capacity(total);
        let mut idx = [0usize; 4];
        loop {
            let mut best: Option<usize> = None;
            for (run, events) in runs.iter().enumerate() {
                let Some(head) = events.get(idx[run]) else {
                    continue;
                };
                let is_earlier = match best {
                    None => true,
                    Some(kept) => head.sn < runs[kept][idx[kept]].sn,
                };
                if is_earlier {
                    best = Some(run);
                }
            }
            let Some(take) = best else {
                break;
            };
            out.push(runs[take][idx[take]].clone());
            idx[take] += 1;
        }
        out
    }

    /// Incremental aux check: replays only the events past the
    /// saved tip instead of the whole prefix. Returns `None` when
    /// the saved tip can not be continued (divergent branch or an
    /// already-covered aux): the caller discards the cursor and
    /// rebuilds authoritatively.
    #[allow(clippy::too_many_arguments)]
    async fn verify_aux_suffix(
        &self,
        cursors: &mut VerifyCursorStore,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        transfer_event: &Ledger,
        buffered: &[Ledger],
        aux_hash: &DigestIdentifier,
        local_sn: Option<u64>,
    ) -> Option<AuxEvidence> {
        // Snapshot what the continuity check needs, then release
        // the borrow before any await below.
        let (tip_sn, tip_hash, covered) = {
            let cursor = cursors.get_mut(subject_id)?;
            if transfer_event.sn <= cursor.metadata.sn {
                // Aux already behind the validated tip: rebuild
                // authoritatively instead of guessing (rare).
                return None;
            }
            // A vanished or regressed local ledger invalidates the
            // coverage it provided; the full path below handles
            // the no-local case like a first copy.
            if cursor.local_tip.is_some() && local_sn.is_none() {
                return None;
            }
            if let Some(covered) = cursor.local_tip
                && let Some(current) = local_sn
                && current < covered
            {
                return None;
            }
            (
                cursor.metadata.sn,
                cursor.tip_hash.clone(),
                cursor.local_tip,
            )
        };
        // The three prefix sources join here in authoritative
        // order: applied local delta first, then held batches,
        // then the sender batch. The sender window never runs
        // past the aux it carries, like in the full path below.
        // The aux itself is always judged, even when it travels
        // outside the sender batch; a held copy of the same SN
        // wins, exactly like the full-path dedup order.
        // Assemble the suffix to replay from ascending runs: the
        // applied local delta, the held batches, the sender batch
        // and the aux itself. Every run arrives sorted (ingress
        // sorts the batch, staged events only append past the tip,
        // the store reads ascending), so a linear merge replaces
        // the full re-sort: nothing already ordered is ever
        // reordered. Precedence on ties is authoritative order
        // (delta, held, sender, aux): the first copy wins the
        // identity check below, exactly like the full path.
        let mut delta: Vec<Ledger> = Vec::new();
        if local_sn.is_some_and(|current| Some(current) > covered) {
            let Some(loaded) = self.load_local_ledger(
                ctx,
                subject_id,
                covered,
                local_sn.unwrap_or(0),
            )
            .await
            else {
                return Some(AuxEvidence::Missing);
            };
            // A first delta with no coverage at all is a full
            // reload, like the full path.
            delta = loaded;
        }
        let hold_from = buffered.partition_point(|event| event.sn < tip_sn);
        let held_window = &buffered[hold_from..];
        let sender_from =
            sender_ledger.partition_point(|event| event.sn < tip_sn);
        let sender_to =
            sender_ledger.partition_point(|event| event.sn < transfer_event.sn);
        let sender_window = sender_ledger
            .get(sender_from..sender_to)
            .unwrap_or(&[]);
        // Only the uncovered tail is cloned: the partitions above
        // skip whole verified prefixes with logarithmic probes
        // instead of scanning them.
        let mut fresh: Vec<Ledger> = Self::merge_runs([
            delta.as_slice(),
            held_window,
            sender_window,
            std::slice::from_ref(transfer_event),
        ]);
        // Merge by identity with authoritative precedence: the
        // first copy wins, so an exact re-send replays once
        // instead of stalling the chain. The same SN with
        // different bytes is a divergent branch, not a
        // duplicate: fall back to the authoritative rebuild
        // instead of borrowing the forged bytes. Unmeasurable
        // bytes never dedup and never diverge on their own: the
        // replay below decides over them.
        #[cfg(feature = "test")]
        let merged_len = fresh.len();
        let mut deduped: Vec<Ledger> = Vec::with_capacity(fresh.len());
        for event in fresh {
            let duplicate = match deduped.last() {
                Some(prev) if prev.sn == event.sn => {
                    match (
                        prev.ledger_hash(self.hash),
                        event.ledger_hash(self.hash),
                    ) {
                        (Ok(previous), Ok(current)) => {
                            Some(previous == current)
                        }
                        _ => None,
                    }
                }
                _ => None,
            };
            match duplicate {
                // Exact re-send: replay once.
                Some(true) => continue,
                // Same SN, different bytes: divergent branch.
                Some(false) => return None,
                // Unique SN, or unmeasurable bytes the replay
                // below decides over.
                None => deduped.push(event),
            }
        }
        fresh = deduped;
        // Buffer work stays linear in the new events: every merged
        // event is cloned once, and the dedup pass visits each of
        // them once. Partition probes are logarithmic and stay
        // uncounted; dropped history was never cloned. The merge
        // never reorders: inputs arrive ascending and emit ascending.
        #[cfg(feature = "test")]
        Self::note_buffer_work(
            ctx,
            subject_id,
            merged_len as u64,
            (merged_len + fresh.len()) as u64,
            0,
        );
        // Drop what the cursor already covers: history below the
        // tip never replays. The tip itself replays only if it is
        // gone, which the hash tells apart from a quiet re-send:
        // a different hash for the same SN is a divergence and
        // rebuilds instead of continuing from the saved tip.
        let mut suffix: Vec<Ledger> = Vec::with_capacity(fresh.len());
        for event in fresh {
            if event.sn < tip_sn {
                continue;
            }
            if event.sn == tip_sn {
                let same = match event.ledger_hash(self.hash) {
                    Ok(hash) => hash == tip_hash,
                    // Unmeasurable tip bytes never pass as
                    // covered: replay decides over them.
                    _ => false,
                };
                if same {
                    continue;
                }
                return None;
            }
            suffix.push(event);
        }
        fresh = suffix;
        // Exact-identity reuse: the same aux over the same tip
        // with the same new events replays identically, so the
        // cached verdict stands without re-running any check. Any
        // new byte (continuation, fork, re-sealed hint) changes
        // the fingerprint and forces a fresh replay below.
        let suffix_fp = match self.chain_fingerprint(tip_sn, &tip_hash, &fresh)
        {
            Some(fp) => fp,
            // Unmeasurable inputs are never cached: replay now,
            // store nothing.
            None => {
                return Some(
                    self.replay_suffix(
                        cursors,
                        ctx,
                        governance_id,
                        subject_id,
                        transfer_event,
                        aux_hash,
                        fresh,
                        tip_sn,
                        local_sn,
                        None,
                    )
                    .await,
                );
            }
        };
        if let Some(hit) = cursors.get_mut(subject_id).and_then(|cursor| {
            cursor
                .verdicts
                .get(&(
                    transfer_event.sn,
                    aux_hash.clone(),
                    tip_hash.clone(),
                    suffix_fp.clone(),
                ))
                .copied()
        }) {
            return Some(hit);
        }
        // A genuinely absent continuation only defers: the valid
        // prefix stays cached for the batch that brings it.
        let Some(first) = fresh.first() else {
            return Some(AuxEvidence::Missing);
        };
        if first.sn != tip_sn.saturating_add(1) {
            return Some(AuxEvidence::Missing);
        }
        // Forked ancestry can not continue the saved tip: drop it
        // and rebuild from the authoritative prefix instead.
        if first.prev_ledger_event_hash != tip_hash {
            return None;
        }
        Some(
            self.replay_suffix(
                cursors,
                ctx,
                governance_id,
                subject_id,
                transfer_event,
                aux_hash,
                fresh,
                tip_sn,
                local_sn,
                Some(suffix_fp),
            )
            .await,
        )
    }

    /// Replays one suffix through the saved cursor and adopts the
    /// extended tip. The verdict is cached under the exact replay
    /// inputs; entries from older tips are pruned since the tip
    /// only moves forward and they can never match again.
    #[allow(clippy::too_many_arguments)]
    async fn replay_suffix(
        &self,
        cursors: &mut VerifyCursorStore,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        transfer_event: &Ledger,
        aux_hash: &DigestIdentifier,
        fresh: Vec<Ledger>,
        tip_sn: u64,
        local_sn: Option<u64>,
        suffix_fp: Option<DigestIdentifier>,
    ) -> AuxEvidence {
        let Some(cursor) = cursors.get_mut(subject_id) else {
            // Evicted concurrently: nothing to resume; the caller
            // rebuilds authoritatively instead.
            return AuxEvidence::Missing;
        };
        // A first delta with no coverage at all counts as a full
        // reload, like the full path; later deltas are uncounted.
        #[cfg(feature = "test")]
        let full_load = cursor.local_tip.is_none() && local_sn.is_some();
        let (proven, refuted, skipped_opaque, used_envelope) = self
            .verify_chain(
                ctx,
                governance_id,
                &mut cursor.metadata,
                &fresh,
                &mut cursor.roles,
            )
            .await;
        let trust = if skipped_opaque || cursor.trust == CursorTrust::Opaque {
            CursorTrust::Opaque
        } else if used_envelope || cursor.trust != CursorTrust::Proven {
            CursorTrust::EnvelopeOnly
        } else {
            CursorTrust::Proven
        };
        cursor.trust = trust;
        // A transfer that does not reproduce over incomplete
        // properties stays unproven, never refuted: opaque steps
        // below the replayed suffix may hold the patch its check
        // needs. Downgrade-only trust keeps that verdict stable
        // across incremental replays and full rebuilds alike.
        let verdict = if proven.contains(&transfer_event.sn) {
            AuxEvidence::Proven
        } else if refuted.contains(&transfer_event.sn)
            && trust != CursorTrust::Opaque
        {
            AuxEvidence::Refuted
        } else if cursor.metadata.sn == transfer_event.sn {
            AuxEvidence::Unverifiable
        } else if skipped_opaque || trust == CursorTrust::Opaque {
            AuxEvidence::Unverifiable
        } else {
            AuxEvidence::Missing
        };
        // Adopt the extended tip: identity comes from the
        // replayed bytes themselves.
        if cursor.metadata.sn > tip_sn {
            let tip_hash = fresh
                .iter()
                .find(|event| event.sn == cursor.metadata.sn)
                .and_then(|event| event.ledger_hash(self.hash).ok());
            match tip_hash {
                Some(hash) => cursor.tip_hash = hash,
                // Unreachable: the cursor only advances over the
                // events just replayed. Keep the saved tip rather
                // than attesting an unknown one.
                None => return verdict,
            }
        }
        cursor.local_tip = local_sn;
        if let Some(fp) = suffix_fp {
            cursor.verdicts.retain(|key, _| key.2 == cursor.tip_hash);
            // Bounded per tip: entries for one tip are few by
            // construction (one per distinct suffix), but an
            // adversary could still vary suffixes; dropping the
            // whole set only costs future replays, never
            // correctness.
            if cursor.verdicts.len() >= 16 {
                cursor.verdicts.clear();
            }
            cursor.verdicts.insert(
                (
                    transfer_event.sn,
                    aux_hash.clone(),
                    cursor.tip_hash.clone(),
                    fp,
                ),
                verdict,
            );
        }
        #[cfg(feature = "test")]
        Self::note_verify_work(ctx, subject_id, fresh.len() as u64, full_load);
        verdict
    }

    /// Evidence gate for an external transfer hint: the aux grants
    /// free passage only if its evaluation reproduces over a
    /// trustworthy pre-state. That is the receiver's own ledger
    /// continued with the sender batch, or batch genesis when the
    /// subject is unknown. Anything else (gap, opaque or diverged
    /// prefix, unverifiable evidence) yields Missing, so the caller
    /// defers instead of opening passage on seal and quorum alone.
    /// Checkable but wrong evidence yields Refuted instead. An
    /// already applied transfer needs no gate.
    pub(crate) async fn verify_aux_evidence(
        &self,
        cursors: &mut VerifyCursorStore,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        transfer_event: &Ledger,
        buffered: &[Ledger],
    ) -> AuxEvidence {
        let local_sn =
            get_local_subject_sn(ctx, subject_id).await.ok().flatten();
        if let Some(lsn) = local_sn
            && lsn >= transfer_event.sn
        {
            return AuxEvidence::Proven;
        }
        // The verdict belongs to the exact hint bytes: a re-sealed
        // variant never shares a verdict with another by SN alone.
        let aux_hash = match transfer_event.ledger_hash(self.hash) {
            Ok(hash) => hash,
            Err(_) => return AuxEvidence::Missing,
        };
        // Fast path: resume the validated prefix instead of
        // rebuilding it from genesis. A divergent branch or an
        // already-covered aux falls back to a full rebuild below.
        if cursors.get_mut(subject_id).is_some() {
            match self
                .verify_aux_suffix(
                    cursors,
                    ctx,
                    governance_id,
                    subject_id,
                    sender_ledger,
                    transfer_event,
                    buffered,
                    &aux_hash,
                    local_sn,
                )
                .await
            {
                Some(verdict) => return verdict,
                None => cursors.invalidate(subject_id),
            }
        }
        // Own prefix first: the locally applied events are exactly
        // what a continued copy would rebuild, with no register
        // round-trip that could race a just-applied prefix. Gaps,
        // opaque spans and unverifiable evidence yield Missing (the
        // aux may still prove itself once the chain is available);
        // only checkable-but-wrong evidence yields Refuted.
        let mut combined: Vec<Ledger> = Vec::new();
        let mut tip: Option<u64> = None;
        if local_sn.is_some() {
            let Some(ledger) = self.load_local_ledger(
                ctx,
                subject_id,
                None,
                local_sn.unwrap_or(0),
            )
            .await
            else {
                return AuxEvidence::Missing;
            };
            tip = ledger.last().map(|event| event.sn);
            combined.extend(ledger);
        }
        // Deferred batches held locally count as prefix too: they are
        // exactly what this node already received but could not apply
        // yet for lack of evidence. Anything at or below the applied
        // tip is stale and ignored.
        combined.extend(
            buffered
                .iter()
                .filter(|event| {
                    local_sn.is_none_or(|applied| event.sn > applied)
                })
                .cloned(),
        );
        let buffered_tip = buffered.last().map(|event| event.sn);
        tip = tip.max(buffered_tip);
        // Sender events strictly after the own tip, up to the aux.
        let after_tip = tip;
        let mut needed: Vec<Ledger> = sender_ledger
            .iter()
            .filter(|event| {
                after_tip.is_none_or(|tip| event.sn > tip)
                    && event.sn <= transfer_event.sn
            })
            .cloned()
            .collect();
        needed.retain(|event| event.sn != transfer_event.sn);
        needed.push(transfer_event.clone());
        combined.extend(needed);
        // Own events win on overlap: they are what this node
        // already committed, never the sender's claim about them.
        // This authoritative rebuild happens at most once per
        // cursor lifetime: later batches resume incrementally.
        combined.sort_by_key(|event| event.sn);
        combined.dedup_by_key(|event| event.sn);
        #[cfg(feature = "test")]
        {
            Self::note_buffer_work(
                ctx,
                subject_id,
                combined.len() as u64,
                combined.len() as u64,
                combined.len() as u64,
            );
            Self::note_full_rebuild(ctx, subject_id);
        }
        let Some(mut cursor) = Self::genesis_metadata(&combined) else {
            return AuxEvidence::Missing;
        };
        let (_, tail) = combined.split_at(1);
        let mut roles_cache = RoleCache::new();
        let (proven, refuted, skipped_opaque, used_envelope) = self
            .verify_chain(
                ctx,
                governance_id,
                &mut cursor,
                tail,
                &mut roles_cache,
            )
            .await;
        #[cfg(feature = "test")]
        Self::note_verify_work(
            ctx,
            subject_id,
            tail.len() as u64,
            local_sn.is_some(),
        );
        let verdict = if proven.contains(&transfer_event.sn) {
            AuxEvidence::Proven
        } else if refuted.contains(&transfer_event.sn) {
            AuxEvidence::Refuted
        } else if cursor.sn == transfer_event.sn {
            // The chain reaches the aux, but its evidence can not
            // be rechecked (roles for its version are gone): trust
            // the envelope like the apply path does, yet attest
            // nothing, so this never records a proof.
            AuxEvidence::Unverifiable
        } else if skipped_opaque {
            // An opaque prefix hides the properties the recheck
            // would need: without them a failed check proves
            // nothing, so the aux stays unverified instead of
            // counting as refuted. Like the apply path, passage may
            // open, but it never records a proof.
            AuxEvidence::Unverifiable
        } else {
            // The next expected event is simply absent: the chain is
            // incomplete and a later batch with the missing events
            // may still prove or refute the aux.
            AuxEvidence::Missing
        };
        // Remember the validated prefix and this verdict: later
        // batches resume from the tip instead of replaying it.
        // Downgrade-only trust: an opaque or envelope step never
        // becomes a proof by reuse. The verdict is keyed by the
        // exact replay inputs (aux bytes, tip and suffix), so a
        // later batch with different events always replays instead
        // of inheriting it.
        if let Some(tip_event) =
            combined.iter().find(|event| event.sn == cursor.sn)
            && let Ok(tip_hash) = tip_event.ledger_hash(self.hash)
            && let Some(suffix_fp) =
                self.chain_fingerprint(cursor.sn, &tip_hash, tail)
        {
            let trust = if skipped_opaque {
                CursorTrust::Opaque
            } else if used_envelope {
                CursorTrust::EnvelopeOnly
            } else {
                CursorTrust::Proven
            };
            let mut verdicts = HashMap::new();
            verdicts.insert(
                (transfer_event.sn, aux_hash, tip_hash.clone(), suffix_fp),
                verdict,
            );
            cursors.store(
                subject_id.clone(),
                VerifyCursor {
                    metadata: cursor,
                    tip_hash,
                    local_tip: local_sn,
                    trust,
                    roles: roles_cache,
                    verdicts,
                    last_used: 0,
                },
            );
        }
        verdict
    }

    /// Chained evaluation evidence shared by inline screening and
    /// external-aux validation. Rebuilds properties event by event
    /// from `cursor` (exclusive) and returns the SNs of transfers
    /// whose Ok evaluation genuinely reproduces, plus the SNs of
    /// transfers whose checkable evidence failed. Stops (without
    /// error) at the first gap, the first refuted evidence, or a
    /// protocol that cannot be replayed here: later transfers stay
    /// unverified. Confirm and Reject carry no evaluation and
    /// change no properties, so they are skipped without breaking
    /// the chain; opaque or foreign protocols stop it instead of
    /// standing in for evidence they cannot provide.
    ///
    /// When the evaluation roles for an event version are
    /// unavailable (the register only serves the current version),
    /// the evidence can not be judged: the event is trusted on its
    /// envelope like the apply path does, its patch advances the
    /// cursor, but it never counts as proven. A later event whose
    /// evidence genuinely reproduces still proves over that cursor.
    /// Refuted evidence (roles available, check failed) stops the
    /// chain instead.
    pub(crate) async fn verify_chain(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        cursor: &mut Metadata,
        events: &[Ledger],
        roles_cache: &mut RoleCache,
    ) -> (HashSet<u64>, HashSet<u64>, bool, bool) {
        use json_patch::{Patch, patch};
        fn apply_patch(
            properties: &mut ValueWrapper,
            json_patch: ValueWrapper,
        ) -> Result<(), DistributorError> {
            let json_patch = serde_json::from_value::<Patch>(json_patch.0)
                .map_err(|e| DistributorError::TransferEventInvalid {
                    details: format!("patch decode failed: {e}"),
                })?;
            patch(&mut properties.0, &json_patch).map_err(|e| {
                DistributorError::TransferEventInvalid {
                    details: format!("patch apply failed: {e}"),
                }
            })?;
            Ok(())
        }
        // Advances the cursor over one envelope-trusted event: the
        // patch applies when the evaluation succeeded, but nothing
        // is proven. A corrupt patch stops the chain instead.
        fn advance_unproven(
            cursor: &mut Metadata,
            event: &Ledger,
            evaluation: &EvaluationData,
        ) -> Result<(), DistributorError> {
            if evaluation.is_ok()
                && let Some(result) = evaluation.evaluator_response_ok()
            {
                apply_patch(&mut cursor.properties, result.patch.clone())?;
            }
            cursor.sn = event.sn;
            Ok(())
        }
        let mut proven = HashSet::new();
        let mut refuted = HashSet::new();
        let mut skipped_opaque = false;
        let mut used_envelope = false;
        for event in events {
            if event.sn != cursor.sn.saturating_add(1) {
                break;
            }
            let (request, evaluation, validation, is_transfer) = match &event
                .protocols
            {
                Protocols::TrackerFactFull {
                    event_request,
                    evaluation,
                    validation,
                } => (event_request, evaluation, validation, false),
                Protocols::Transfer {
                    event_request,
                    evaluation,
                    validation,
                } => (event_request, evaluation, validation, true),
                Protocols::TrackerConfirm { .. } | Protocols::Reject { .. } => {
                    cursor.sn = event.sn;
                    continue;
                }
                Protocols::TrackerFactOpaque { .. } => {
                    // Opaque facts carry no properties to replay:
                    // advance past them without proving so later
                    // transfers whose evaluation does not depend
                    // on the hidden patch can still prove. A
                    // transfer that does depend on it simply will
                    // not reproduce and stays unproven, never
                    // refuted on incomplete properties.
                    cursor.sn = event.sn;
                    skipped_opaque = true;
                    continue;
                }
                _ => break,
            };
            let roles_key = (
                event.gov_version,
                cursor.schema_id.clone(),
                cursor.namespace.clone(),
            );
            let eval_data = match roles_cache.get_mut(&roles_key).cloned() {
                Some(cached) => Some(cached),
                None => {
                    match get_actual_roles_register(
                        ctx,
                        governance_id,
                        SearchRole {
                            schema_id: cursor.schema_id.clone(),
                            namespace: cursor.namespace.clone(),
                        },
                        false,
                        false,
                        event.gov_version,
                    )
                    .await
                    {
                        Ok((fetched, _, _)) => {
                            #[cfg(feature = "test")]
                            Self::note_roles_resolved(
                                ctx,
                                &cursor.subject_id,
                            );
                            roles_cache.insert(roles_key, fetched.clone());
                            Some(fetched)
                        }
                        Err(_) => None,
                    }
                }
            };
            let Some(eval_data) = eval_data else {
                // Old version or momentarily missing register: the
                // apply path trusts the envelope and skips the
                // recheck, so the screening advances the cursor the
                // same way without granting passage on it.
                if advance_unproven(cursor, event, evaluation).is_err() {
                    break;
                }
                used_envelope = true;
                continue;
            };
            let signer = validation.validation_req_signature.signer.clone();
            let Ok(req_hash) = hash_borsh(
                &*self.hash.hasher(),
                &RequestSubjectData {
                    subject_id: cursor.subject_id.clone(),
                    governance_id: cursor.governance_id.clone(),
                    namespace: cursor.namespace.clone(),
                    schema_id: cursor.schema_id.clone(),
                    sn: cursor.sn.saturating_add(1),
                    gov_version: event.gov_version,
                    signer: signer.clone(),
                },
            ) else {
                break;
            };
            if check_evaluation(
                &self.hash,
                evaluation.clone(),
                eval_data,
                cursor.properties.clone(),
                EventAnchor {
                    event_request: request,
                    metadata: cursor,
                    gov_version: event.gov_version,
                    req_subject_data_hash: req_hash,
                    signer,
                },
            )
            .is_err()
            {
                // Checkable and wrong: the evidence is refuted, not
                // merely missing, unless the cursor skipped opaque
                // facts whose hidden patch the check may need. Then
                // the failure proves nothing and the chain simply
                // stays unproven. Callers decide whether that fails
                // the batch outright or only denies passage.
                if is_transfer && !skipped_opaque {
                    refuted.insert(event.sn);
                }
                break;
            }
            if evaluation.is_ok() {
                if is_transfer {
                    proven.insert(event.sn);
                }
                if let Some(result) = evaluation.evaluator_response_ok()
                    && apply_patch(&mut cursor.properties, result.patch.clone())
                        .is_err()
                {
                    break;
                }
            }
            cursor.sn = event.sn;
        }
        (proven, refuted, skipped_opaque, used_envelope)
    }

    /// Verifica criptográficamente un transfer_event, simula si el nodo local
    /// sigue siendo testigo tras esa transferencia, y si es así lo registra en
    /// el TransferVerificationRegister.
    pub(crate) async fn verify_and_simulate(
        &self,
        cursors: &mut VerifyCursorStore,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        transfer_event: &Ledger,
        buffered: &[Ledger],
    ) -> Result<TransferSimulationResult, ActorError> {
        let first_ledger =
            sender_ledger
                .first()
                .ok_or_else(|| ActorError::Functional {
                    description:
                        "Empty sender ledger in verify_and_simulate_transfer"
                            .to_string(),
                })?;
        // A continuation past a held prefix carries its genesis in
        // the buffer: use it for light metadata when the tail alone
        // has no create event.
        let light_ledger = if first_ledger.get_create_event().is_some() {
            first_ledger
        } else if let Some(held) = buffered
            .iter()
            .find(|event| event.get_create_event().is_some())
        {
            held
        } else {
            first_ledger
        };
        let (governance_id, _, subject_data) = self
            .verify_light(
                ctx,
                transfer_event,
                subject_id,
                light_ledger,
                // A failed transfer is valid history that grants
                // no passage: let the simulation below (which only
                // opens ownership on success) decide Witness or
                // NotWitness instead of rejecting up front.
                false,
                None,
            )
            .await?;

        // The sender fetches the pending transfer separately from
        // the offered window by design (`build_distribution_batch`),
        // so an aux ahead of the batch is the normal case.
        //
        // A failed transfer is valid history that grants no
        // passage on its own: only a successful transfer can open
        // pending ownership, so only it needs its evidence
        // rechecked up front. Failed transfers fall through to the
        // simulation below, which grants Witness solely on
        // independent rights, never on the failed transfer itself.
        //
        // When the evidence can not be rebuilt yet (aux ahead of
        // the batch), the batch is held unapplied without passage
        // or proof until the missing events arrive. Checkable-
        // but-wrong evidence fails here instead, leaving no trace.
        // A recorded firm proof means its evidence was already
        // validated: do not re-validate per batch.
        let transfer_opens_passage = matches!(
            &transfer_event.protocols,
            Protocols::Transfer { evaluation, .. }
                if evaluation.is_ok()
        );
        let mut covered = false;
        if transfer_opens_passage
            && let Ok(Some((proven_sn, _, speculative))) =
                crate::model::common::get_verified_transfer_detail(
                    ctx,
                    &governance_id,
                    subject_id,
                )
                .await
            && !speculative
            && proven_sn >= transfer_event.sn
        {
            covered = true;
        }
        if transfer_opens_passage && !covered {
            let aux_evidence = self
                .verify_aux_evidence(
                    cursors,
                    ctx,
                    &governance_id,
                    subject_id,
                    sender_ledger,
                    transfer_event,
                    buffered,
                )
                .await;
            match aux_evidence {
                AuxEvidence::Proven => {}
                // Incomplete chain: the caller holds the batch
                // unapplied without passage or proof until the
                // missing events arrive.
                AuxEvidence::Missing => {
                    return Ok(TransferSimulationResult::WitnessUnproven);
                }
                // Complete chain whose evidence can not be rebuilt:
                // passage opens without any recorded proof.
                AuxEvidence::Unverifiable => {
                    return Ok(TransferSimulationResult::WitnessUnverified);
                }
                // Forged aux with a checkable chain: no passage, no
                // proof, no writes. The worker additionally drops
                // any held prefix and rolls back on a recorded proof.
                AuxEvidence::Refuted => {
                    return Ok(TransferSimulationResult::Refuted);
                }
            }
        }
        let (schema_id, namespace) = match subject_data {
            Some(SubjectData::Tracker {
                schema_id,
                namespace,
                ..
            }) => (schema_id, namespace),
            Some(SubjectData::Governance { .. }) => {
                (SchemaType::Governance, String::default())
            }
            None => {
                let create = sender_ledger
                    .iter()
                    .chain(buffered.iter())
                    .find(|l| l.is_create_event())
                    .and_then(|l| l.get_create_event())
                    .ok_or_else(|| ActorError::Functional {
                        description: "Cannot resolve metadata needed for simulation: no create event in sender ledger".to_string(),
                    })?;
                (create.schema_id, create.namespace.to_string())
            }
        };

        let simulated_limit = crate::model::common::subject::check_simulated_transfer_hi_sn_limit(
            ctx,
            &governance_id,
            subject_id,
            transfer_event.clone(),
            (*self.our_key).clone(),
            namespace,
            schema_id,
        )
        .await?;

        if !matches!(
            simulated_limit,
            crate::governance::witnesses_register::HiSnLimit::None
        ) {
            Ok(TransferSimulationResult::Witness)
        } else {
            Ok(TransferSimulationResult::NotWitness)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::governance::model::Quorum;

    fn test_roles() -> RoleDataRegister {
        RoleDataRegister {
            workers: HashSet::new(),
            quorum: Quorum::Majority,
        }
    }

    fn test_key(version: u64) -> (u64, SchemaType, Namespace) {
        (
            version,
            SchemaType::Type("Example".to_owned()),
            Namespace::from("test"),
        )
    }

    #[test]
    fn roles_cache_evicts_least_recently_used() {
        let mut cache = RoleCache::new();
        for version in 0..RoleCache::MAX_ROLES as u64 {
            cache.insert(test_key(version), test_roles());
        }
        assert_eq!(cache.len(), RoleCache::MAX_ROLES);
        // Touch version 0 so version 1 becomes the victim.
        assert!(cache.get_mut(&test_key(0)).is_some());
        cache.insert(test_key(RoleCache::MAX_ROLES as u64), test_roles());
        assert_eq!(cache.len(), RoleCache::MAX_ROLES);
        assert!(cache.get_mut(&test_key(0)).is_some());
        assert!(cache.get_mut(&test_key(1)).is_none());
        // An evicted version resolves again instead of reusing
        // another version's register.
        cache.insert(test_key(1), test_roles());
        assert!(cache.get_mut(&test_key(1)).is_some());
        assert_eq!(cache.len(), RoleCache::MAX_ROLES);
    }

    #[test]
    fn roles_cache_reinsert_does_not_evict() {
        let mut cache = RoleCache::new();
        for version in 0..RoleCache::MAX_ROLES as u64 {
            cache.insert(test_key(version), test_roles());
        }
        // Refreshing an existing entry must not evict anything.
        cache.insert(test_key(0), test_roles());
        assert_eq!(cache.len(), RoleCache::MAX_ROLES);
        for version in 0..RoleCache::MAX_ROLES as u64 {
            assert!(cache.get_mut(&test_key(version)).is_some());
        }
    }
}
