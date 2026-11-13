use std::collections::{HashMap, HashSet};
use std::sync::Arc;

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
use crate::node::subject_manager::{
    SubjectManager, SubjectManagerMessage,
};
use crate::subject::Metadata;
use crate::subject::RequestSubjectData;
use crate::validation::response::ValidationRes;
use crate::validation::worker::{EventAnchor, check_evaluation};

use super::error::DistributorError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferSimulationResult {
    /// La simulación fue afirmativa: el nodo es testigo del owner/new_owner.
    Witness,
    /// The aux evidence is not (yet) checkable, so the aux opens
    /// speculative passage with a speculative proof: a later batch
    /// rechecks the evidence once its chain is available, firming
    /// the proof or rolling the subject back on refutation.
    WitnessUnproven,
    /// The aux evidence was checkable and refuted: the hint is
    /// forged and must open nothing, leaving no trace behind.
    /// Any speculative passage it opened is rolled back.
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
    /// The chain can not be rebuilt yet (gap, opaque or diverged
    /// prefix, unavailable roles, missing genesis): no verdict yet,
    /// a later batch may still prove or refute it once the chain
    /// is available. Never a substitute for evidence.
    Missing,
    /// The chain is complete and checkable, but the aux evaluation
    /// does not reproduce: the hint is forged and must open
    /// nothing, leaving no trace behind.
    Refuted,
}

pub(crate) struct TransferVerifier {
    hash: HashAlgorithm,
    our_key: Arc<PublicKey>,
}

impl TransferVerifier {
    pub(crate) const fn new(
        hash: HashAlgorithm,
        our_key: Arc<PublicKey>,
    ) -> Self {
        Self { hash, our_key }
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
            let prev_hash =
                prev.ledger_hash(self.hash).map_err(|e| {
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
        ledger: &[Ledger],
    ) -> HashSet<u64> {
        let mut ordered = ledger.to_vec();
        ordered.sort_by_key(|event| event.sn);
        let Some(mut cursor) = Self::genesis_metadata(&ordered) else {
            return HashSet::new();
        };
        // Roles repeat per governance version, not per event: cache
        // them so a long first-copy batch costs one lookup.
        let mut roles_cache: HashMap<u64, RoleDataRegister> = HashMap::new();
        let (proven, _) = self
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
    fn genesis_metadata(ordered: &[Ledger]) -> Option<Metadata> {
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
    pub(crate) async fn verify_aux_evidence(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        transfer_event: &Ledger,
    ) -> AuxEvidence {
        let local_sn =
            get_local_subject_sn(ctx, subject_id).await.ok().flatten();
        if let Some(lsn) = local_sn
            && lsn >= transfer_event.sn
        {
            return AuxEvidence::Proven;
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
            let path = ave_actors::ActorPath::from(format!(
                "/user/node/subject_manager/{subject_id}"
            ));
            // An idle tracker is already stopped: only live
            // requesters keep it running, so reload it for the read
            // and release the lease right away.
            let mut reloaded = false;
            let tracker = match ctx
                .system()
                .get_actor::<crate::tracker::Tracker>(&path)
                .await
            {
                Ok(tracker) => tracker,
                Err(_) => {
                    let manager_path = ave_actors::ActorPath::from(
                        "/user/node/subject_manager",
                    );
                    let Ok(manager) = ctx
                        .system()
                        .get_actor::<SubjectManager>(&manager_path)
                        .await
                    else {
                        return AuxEvidence::Missing;
                    };
                    if manager
                        .ask(SubjectManagerMessage::Up {
                            subject_id: subject_id.clone(),
                            requester: "aux-evidence".to_owned(),
                            create_ledger: None,
                        })
                        .await
                        .is_err()
                    {
                        return AuxEvidence::Missing;
                    }
                    reloaded = true;
                    let Ok(tracker) = ctx
                        .system()
                        .get_actor::<crate::tracker::Tracker>(&path)
                        .await
                    else {
                        return AuxEvidence::Missing;
                    };
                    tracker
                }
            };
            let fetched = tracker
                .ask(crate::tracker::TrackerMessage::GetLedger {
                    lo_sn: None,
                    hi_sn: local_sn.unwrap_or(0),
                })
                .await;
            if reloaded
                && let Ok(manager) = ctx
                    .system()
                    .get_actor::<SubjectManager>(&ave_actors::ActorPath::from(
                        "/user/node/subject_manager",
                    ))
                    .await
            {
                let _ = manager
                    .ask(SubjectManagerMessage::Finish {
                        subject_id: subject_id.clone(),
                        requester: "aux-evidence".to_owned(),
                    })
                    .await;
            }
            let Ok(crate::tracker::TrackerResponse::Ledger {
                ledger,
                ..
            }) = fetched
            else {
                return AuxEvidence::Missing;
            };
            tip = ledger.last().map(|event| event.sn);
            combined.extend(ledger);
        }
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
        combined.sort_by_key(|event| event.sn);
        combined.dedup_by_key(|event| event.sn);
        let Some(mut cursor) = Self::genesis_metadata(&combined) else {
            return AuxEvidence::Missing;
        };
        let (_, tail) = combined.split_at(1);
        let mut roles_cache = HashMap::new();
        let (proven, refuted) = self
            .verify_chain(ctx, governance_id, &mut cursor, tail, &mut roles_cache)
            .await;
        if proven.contains(&transfer_event.sn) {
            AuxEvidence::Proven
        } else if refuted.contains(&transfer_event.sn) {
            AuxEvidence::Refuted
        } else {
            AuxEvidence::Missing
        }
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
        roles_cache: &mut HashMap<u64, RoleDataRegister>,
    ) -> (HashSet<u64>, HashSet<u64>) {
        use json_patch::{Patch, patch};
        fn apply_patch(
            properties: &mut ValueWrapper,
            json_patch: ValueWrapper,
        ) -> Result<(), DistributorError> {
            let json_patch =
                serde_json::from_value::<Patch>(json_patch.0).map_err(
                    |e| DistributorError::TransferEventInvalid {
                        details: format!("patch decode failed: {e}"),
                    },
                )?;
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
                apply_patch(
                    &mut cursor.properties,
                    result.patch.clone(),
                )?;
            }
            cursor.sn = event.sn;
            Ok(())
        }
        let mut proven = HashSet::new();
        let mut refuted = HashSet::new();
        for event in events {
            if event.sn != cursor.sn.saturating_add(1) {
                break;
            }
            let (request, evaluation, validation, is_transfer) =
                match &event.protocols {
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
                    Protocols::TrackerConfirm { .. }
                    | Protocols::Reject { .. } => {
                        cursor.sn = event.sn;
                        continue;
                    }
                    _ => break,
                };
            let eval_data = match roles_cache.get(&event.gov_version) {
                Some(cached) => Some(cached.clone()),
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
                            roles_cache.insert(
                                event.gov_version,
                                fetched.clone(),
                            );
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
                // merely missing. Callers decide whether that fails
                // the batch outright or only denies passage.
                if is_transfer {
                    refuted.insert(event.sn);
                }
                break;
            }
            if evaluation.is_ok() {
                if is_transfer {
                    proven.insert(event.sn);
                }
                if let Some(result) = evaluation.evaluator_response_ok()
                    && apply_patch(
                        &mut cursor.properties,
                        result.patch.clone(),
                    )
                    .is_err()
                {
                    break;
                }
            }
            cursor.sn = event.sn;
        }
        (proven, refuted)
    }

    /// Verifica criptográficamente un transfer_event, simula si el nodo local
    /// sigue siendo testigo tras esa transferencia, y si es así lo registra en
    /// el TransferVerificationRegister.
    pub(crate) async fn verify_and_simulate(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        transfer_event: &Ledger,
    ) -> Result<TransferSimulationResult, ActorError> {
        let first_ledger =
            sender_ledger
                .first()
                .ok_or_else(|| ActorError::Functional {
                    description:
                        "Empty sender ledger in verify_and_simulate_transfer"
                            .to_string(),
                })?;
        let (governance_id, _, subject_data) = self
            .verify_light(
                ctx,
                transfer_event,
                subject_id,
                first_ledger,
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
        // the batch), the aux still opens speculative passage with
        // a speculative proof, and a later batch rechecks it once
        // its chain is available; refuting it then rolls the
        // subject back. Checkable-but-wrong evidence fails here
        // instead, leaving no trace. A recorded firm proof means
        // its evidence was already validated: do not re-validate
        // per batch.
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
            match self
                .verify_aux_evidence(
                    ctx,
                    &governance_id,
                    subject_id,
                    sender_ledger,
                    transfer_event,
                )
                .await
            {
                AuxEvidence::Proven => {}
                // Speculative passage: the batch may advance on the
                // aux, but the proof stays speculative until a later
                // batch rechecks the evidence.
                AuxEvidence::Missing => {
                    return Ok(TransferSimulationResult::WitnessUnproven);
                }
                // Forged aux with a checkable chain: no passage, no
                // proof, no writes. The worker additionally rolls
                // back any speculative prefix it opened.
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
