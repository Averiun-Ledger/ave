use std::collections::HashSet;
use std::sync::Arc;

use ave_actors::{ActorContext, ActorError};
use ave_common::{
    Namespace, SchemaType,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey, Signed},
    request::EventRequest,
};

use crate::governance::role_register::SearchRole;
use crate::model::common::{check_quorum_signers, node::get_subject_data};
use crate::model::event::{Ledger, LedgerSeal, Protocols, ValidationMetadata};
use crate::node::SubjectData;
use crate::validation::response::ValidationRes;

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
    pub(crate) fn new(hash: HashAlgorithm, our_key: Arc<PublicKey>) -> Self {
        Self { hash, our_key }
    }

    /// Verificación criptográfica ligera de un evento Transfer.
    /// Devuelve (governance_id, is_register).
    pub(crate) async fn verify_light(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        transfer_event: &Ledger,
        expected_subject_id: &DigestIdentifier,
        ledger: &Ledger,
    ) -> Result<(DigestIdentifier, bool), DistributorError> {
        // 1. El protocolo debe ser Transfer.
        let (event_request, evaluation, validation) = match &transfer_event.protocols {
            Protocols::Transfer { event_request, evaluation, validation } => {
                (event_request, evaluation, validation)
            }
            _ => {
                return Err(DistributorError::TransferEventInvalid {
                    details: "protocol is not Transfer".to_string(),
                });
            }
        };

        if !evaluation.is_ok() {
            return Err(DistributorError::TransferEventInvalid {
                details: "transfer evaluation is not ok".to_string(),
            });
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
            prev_ledger_event_hash: transfer_event.prev_ledger_event_hash.clone(),
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
        let subject_data = get_subject_data(ctx, expected_subject_id).await
            .map_err(|e| DistributorError::TransferEventInvalid {
                details: format!("failed to get subject data: {}", e),
            })?;

        let (governance_id, schema_id, namespace, is_register) = match subject_data {
            Some(SubjectData::Tracker { governance_id, schema_id, namespace, .. }) => {
                (governance_id, schema_id, Namespace::from(namespace), true)
            }
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
                if create.schema_id.is_gov() || create.governance_id.is_empty() {
                    return Err(DistributorError::TransferEventInvalid {
                        details: "invalid create event for transfer hint".to_string(),
                    });
                }

                (create.governance_id.clone(), create.schema_id.clone(), create.namespace.clone(), false)
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

        Ok((governance_id, is_register))
    }

    /// Verifica criptográficamente un transfer_event, simula si el nodo local
    /// sigue siendo testigo tras esa transferencia, y si es así lo registra en
    /// el TransferVerificationRegister.
    pub(crate) async fn verify_and_simulate(
        &self,
        ctx: &mut ActorContext<super::worker::DistriWorker>,
        subject_id: &DigestIdentifier,
        sender_ledger: &[Ledger],
        sender: PublicKey,
        transfer_event: &Ledger,
    ) -> Result<TransferSimulationResult, ActorError> {
        let first_ledger = sender_ledger.first().ok_or_else(|| ActorError::Functional {
            description: "Empty sender ledger in verify_and_simulate_transfer".to_string(),
        })?;
        let (governance_id, _) = self
            .verify_light(ctx, transfer_event, subject_id, first_ledger)
            .await?;

        let (schema_id, namespace) =
            if let Some(data) = get_subject_data(ctx, subject_id).await? {
                match data {
                    SubjectData::Tracker {
                        schema_id,
                        namespace,
                        ..
                    } => (schema_id, namespace),
                    SubjectData::Governance { .. } => {
                        (SchemaType::Governance, String::default())
                    }
                }
            } else {
                let create = sender_ledger
                    .iter()
                    .find(|l| l.is_create_event())
                    .and_then(|l| l.get_create_event())
                    .ok_or_else(|| ActorError::Functional {
                        description: "Cannot resolve metadata needed for simulation: no create event in sender ledger".to_string(),
                    })?;
                (create.schema_id, create.namespace.to_string())
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

        if !matches!(simulated_limit, crate::governance::witnesses_register::HiSnLimit::None) {
            Ok(TransferSimulationResult::Witness)
        } else {
            Ok(TransferSimulationResult::NotWitness)
        }
    }
}
