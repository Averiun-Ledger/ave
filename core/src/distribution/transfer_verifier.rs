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
use crate::model::event::{Ledger, LedgerSeal, Protocols, ValidationMetadata};
use crate::node::SubjectData;
use crate::subject::Metadata;
use crate::subject::RequestSubjectData;
use crate::validation::response::ValidationRes;
use crate::validation::worker::{EventAnchor, check_evaluation};

use super::error::DistributorError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TransferSimulationResult {
    /// La simulación fue afirmativa: el nodo es testigo del owner/new_owner.
    Witness,
    /// La simulación devolvió None: no somos testigo.
    NotWitness,
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
        let mut proven = HashSet::new();
        let mut ordered = ledger.to_vec();
        ordered.sort_by_key(|event| event.sn);
        let Some(create) = ordered.first().filter(|e| e.is_create_event())
        else {
            return proven;
        };
        let Protocols::Create { validation, .. } = &create.protocols
        else {
            return proven;
        };
        let ValidationMetadata::Metadata(genesis) =
            &validation.validation_metadata
        else {
            return proven;
        };
        let mut cursor: Metadata = genesis.as_ref().clone();
        // Roles repeat per governance version, not per event: cache
        // them so a long first-copy batch costs one lookup.
        let mut roles_cache: HashMap<u64, RoleDataRegister> = HashMap::new();
        for event in ordered.iter().skip(1) {
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
                    _ => break,
                };
            let eval_data = match roles_cache.get(&event.gov_version) {
                Some(cached) => cached.clone(),
                None => {
                    let Ok((fetched, _, _)) = get_actual_roles_register(
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
                    else {
                        break;
                    };
                    roles_cache
                        .insert(event.gov_version, fetched.clone());
                    fetched
                }
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
                    metadata: &cursor,
                    gov_version: event.gov_version,
                    req_subject_data_hash: req_hash,
                    signer,
                },
            )
            .is_err()
            {
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
        proven
    }

    /// Whether the local pre-state reproduces the owner's: full
    /// visibility mode plus no opaque span in the prefix. Opaque
    /// facts carry no patch, so any `None` span means the local
    /// properties diverge and the evidence can not be rechecked.
    async fn prefix_complete(
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        governance_id: &DigestIdentifier,
        meta: &Metadata,
    ) -> bool {
        use crate::governance::witnesses_register::{
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        };
        let path = ave_actors::ActorPath::from(format!(
            "/user/node/subject_manager/{governance_id}/witnesses_register"
        ));
        let Ok(actor) =
            ctx.system().get_actor::<WitnessesRegister>(&path).await
        else {
            return false;
        };
        let Ok(response) = actor
            .ask(WitnessesRegisterMessage::GetTrackerVisibilityState {
                subject_id: meta.subject_id.clone(),
            })
            .await
        else {
            return false;
        };
        let WitnessesRegisterResponse::TrackerVisibilityState { state } =
            response
        else {
            return false;
        };
        if !state.is_full() {
            return false;
        }
        for range in &state.stored_ranges {
            if range.from_sn > meta.sn {
                break;
            }
            if matches!(
                range.visibility,
                crate::model::common::TrackerStoredVisibility::None
            ) {
                return false;
            }
        }
        true
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

        // When the pre-state is local (we are exactly one sn behind
        // the transfer), check the evaluation evidence against it:
        // request binding, evaluator quorum and result hash must
        // reproduce over the pre-event properties.
        if let Some(local_sn) =
            get_local_subject_sn(ctx, subject_id).await.ok().flatten()
            && local_sn.saturating_add(1) == transfer_event.sn
        {
            let Protocols::Transfer {
                event_request,
                evaluation,
                validation,
            } = &transfer_event.protocols
            else {
                return Err(ActorError::Functional {
                    description: "transfer hint is not a transfer".to_string(),
                });
            };
            let path = ave_actors::ActorPath::from(format!(
                "/user/node/subject_manager/{subject_id}"
            ));
            if let Ok(tracker) = ctx
                .system()
                .get_actor::<crate::tracker::Tracker>(&path)
                .await
                && let Ok(crate::tracker::TrackerResponse::Metadata(meta)) =
                    tracker
                        .ask(crate::tracker::TrackerMessage::GetMetadata)
                        .await
                && Self::prefix_complete(ctx, &governance_id, &meta).await
            {
                let pre: Metadata = (*meta).clone();
                // Missing roles (the register only serves the
                // current governance version) mean the evidence
                // can not be judged here: skip it, the seal and
                // validation quorum still apply.
                if let Ok((eval_data, _, _)) = get_actual_roles_register(
                    ctx,
                    &governance_id,
                    SearchRole {
                        schema_id: pre.schema_id.clone(),
                        namespace: pre.namespace.clone(),
                    },
                    false,
                    false,
                    transfer_event.gov_version,
                )
                .await
                {
                    let signer =
                        validation.validation_req_signature.signer.clone();
                    let req_hash = hash_borsh(
                        &*self.hash.hasher(),
                        &RequestSubjectData {
                            subject_id: pre.subject_id.clone(),
                            governance_id: pre.governance_id.clone(),
                            namespace: pre.namespace.clone(),
                            schema_id: pre.schema_id.clone(),
                            sn: pre.sn.saturating_add(1),
                            gov_version: transfer_event.gov_version,
                            signer: signer.clone(),
                        },
                    )
                    .map_err(|e| {
                        ActorError::Functional {
                            description: format!("req hash failed: {e}"),
                        }
                    })?;
                    check_evaluation(
                        &self.hash,
                        evaluation.clone(),
                        eval_data,
                        pre.properties.clone(),
                        EventAnchor {
                            event_request,
                            metadata: &pre,
                            gov_version: transfer_event.gov_version,
                            req_subject_data_hash: req_hash,
                            signer,
                        },
                    )
                    .map_err(|e| {
                        DistributorError::TransferEventInvalid {
                            details: format!("eval evidence: {e}"),
                        }
                    })?;
                }
            }
        }

        // No sn-vs-batch gate here: the sender fetches the pending
        // transfer separately from the offered window by design
        // (`build_distribution_batch`), so a transfer ahead of the
        // batch is the normal case, not an attack. The binding is the
        // cryptographic verification above (seal + quorum + subject):
        // a transfer that passes it is authentic, and the receiver
        // still applies events strictly in order downstream.
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
