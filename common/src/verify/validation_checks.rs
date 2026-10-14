//! Validation evidence checks shared by the node and the
//! off-chain verification tool.

use std::{
    collections::{BTreeSet, HashSet},
    time::Duration,
};

use super::{
    approval_data::ApprovalData,
    approval_request::ApprovalReq,
    approval_verify::{
        ApprovalVerification, rebuild_approval_req, verify_approval_data,
    },
    check_quorum_signers,
    compilation_data::{CompilationData, CompilationResponse},
    compilation_request::{CompilationReq, effective_pin},
    compilation_response::CompilationResult,
    compilation_sets::compilation_set,
    evaluation_data::{
        EvaluationData, EvaluationDataOpaque, EvaluationResponse,
        EvaluationResponseOpaque,
    },
    evaluation_request::{EvaluateData, EvaluationReq},
    evaluation_response::EvaluationResult,
    governance::GovernanceData,
    role_data::{RoleDataRegister, RolesAtVersion},
    subject_data::RequestSubjectData,
    subject_metadata::{Metadata, MetadataWithoutProperties},
    validation_response::{ValidationData, ValidationMetadata, ValidationRes},
    validator_error::ValidatorError,
    CLOCK_SKEW,
};
use crate::{
    Namespace, SchemaType, ValueWrapper,
    bridge::request::EventRequestType,
    governance::{ProtocolTypes, toolchain_info},
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, TimeStamp,
        hash_borsh,
    },
    request::EventRequest,
};

use anyhow::{Result, bail};

use std::sync::Arc;

use json_patch::{Patch, patch};

/// Ledger-anchored identity of the event under validation, shared by
/// the evidence checks so their signatures stay readable. Public so
/// the off-chain verification tool runs the same checks over
/// replayed state.
pub struct EventAnchor<'a> {
    pub event_request: &'a Arc<Signed<EventRequest>>,
    pub metadata: &'a Metadata,
    pub gov_version: u64,
    pub req_subject_data_hash: DigestIdentifier,
    pub signer: PublicKey,
}

pub fn event_request_hash(
    hash: &HashAlgorithm,
    event_request: &Signed<EventRequest>,
) -> Result<DigestIdentifier, ValidatorError> {
    hash_borsh(&*hash.hasher(), event_request).map_err(|e| {
        ValidatorError::InternalError {
            problem: e.to_string(),
        }
    })
}

pub fn viewpoints_hash(
    hash: &HashAlgorithm,
    event_request: &EventRequest,
) -> Result<DigestIdentifier, ValidatorError> {
    let viewpoints = match event_request {
        EventRequest::Fact(fact_request) => fact_request.viewpoints.clone(),
        _ => BTreeSet::new(),
    };

    hash_borsh(&*hash.hasher(), &viewpoints).map_err(|e| {
        ValidatorError::InternalError {
            problem: e.to_string(),
        }
    })
}

pub fn check_metadata(
    event_type: &EventRequestType,
    metadata: &Metadata,
    gov_version: u64,
) -> Result<(), ValidatorError> {
    let is_gov = metadata.schema_id.is_gov();

    if let Some(name) = &metadata.name
        && (name.is_empty() || name.len() > 100)
    {
        return Err(ValidatorError::InvalidData {
            value: "metadata name",
        });
    }

    if let Some(description) = &metadata.description
        && (description.is_empty() || description.len() > 200)
    {
        return Err(ValidatorError::InvalidData {
            value: "metadata description",
        });
    }

    if metadata.subject_id.is_empty() {
        return Err(ValidatorError::InvalidData {
            value: "metadata subject_id",
        });
    }

    if is_gov && metadata.governance_id != metadata.subject_id
        || !is_gov && metadata.governance_id == metadata.subject_id
    {
        return Err(ValidatorError::InvalidData {
            value: "metadata governance_id",
        });
    }

    if is_gov && metadata.genesis_gov_version != 0
        || !is_gov && metadata.genesis_gov_version == 0
    {
        return Err(ValidatorError::InvalidData {
            value: "metadata genesis_gov_version",
        });
    }

    if metadata.genesis_gov_version > gov_version {
        return Err(ValidatorError::InvalidData {
            value: "metadata genesis_gov_version",
        });
    }

    if metadata.sn == 0 && !metadata.prev_ledger_event_hash.is_empty()
        || metadata.sn != 0 && metadata.prev_ledger_event_hash.is_empty()
    {
        return Err(ValidatorError::InvalidData {
            value: "metadata prev_ledger_event_hash",
        });
    };

    if !metadata.schema_id.is_valid_in_request() {
        return Err(ValidatorError::InvalidData {
            value: "metadata schema_id",
        });
    };

    if is_gov && !metadata.namespace.is_empty() {
        return Err(ValidatorError::InvalidData {
            value: "metadata namespace",
        });
    }

    if metadata.creator.is_empty() {
        return Err(ValidatorError::InvalidData {
            value: "metadata creator",
        });
    }

    if metadata.owner.is_empty() {
        return Err(ValidatorError::InvalidData {
            value: "metadata owner",
        });
    }

    if let Some(new_owner) = &metadata.new_owner
        && (new_owner.is_empty() || new_owner == &metadata.owner)
    {
        return Err(ValidatorError::InvalidData {
            value: "metadata new owner",
        });
    };

    if !metadata.active {
        return Err(ValidatorError::InvalidData {
            value: "metadata active",
        });
    }

    match event_type {
        EventRequestType::Create => {
            return Err(ValidatorError::InvalidData {
                value: "Event request type",
            });
        }
        EventRequestType::Confirm | EventRequestType::Reject => {
            if metadata.new_owner.is_none() {
                return Err(ValidatorError::InvalidData {
                    value: "Event request type",
                });
            }
        }
        EventRequestType::Fact
        | EventRequestType::Transfer
        | EventRequestType::Eol => {
            if metadata.new_owner.is_some() {
                return Err(ValidatorError::InvalidData {
                    value: "Event request type",
                });
            }
        }
    };

    Ok(())
}

pub fn check_basic_data(
    request: &Signed<EventRequest>,
    metadata: &Metadata,
    vali_req_signer: &PublicKey,
    gov_version: u64,
    sn: u64,
) -> Result<(), ValidatorError> {
    // Check event request.

    if request.verify().is_err() {
        return Err(ValidatorError::InvalidSignature {
            data: "event request",
        });
    }

    check_metadata(
        &EventRequestType::from(request.content()),
        metadata,
        gov_version,
    )?;

    if !request.content().check_request_signature(
        &request.signature().signer,
        &metadata.owner,
        &metadata.new_owner,
    ) {
        return Err(ValidatorError::InvalidSigner {
            signer: request.signature().signer.to_string(),
        });
    }

    // subject
    if request.content().get_subject_id() != metadata.subject_id {
        return Err(ValidatorError::InvalidData {
            value: "Subject_id",
        });
    }

    // vali request signer
    let signer = metadata
        .new_owner
        .clone()
        .unwrap_or_else(|| metadata.owner.clone());

    if &signer != vali_req_signer {
        return Err(ValidatorError::InvalidSigner {
            signer: vali_req_signer.to_string(),
        });
    }

    // sn
    if sn != metadata.sn.saturating_add(1) {
        return Err(ValidatorError::InvalidData { value: "sn" });
    }
    Ok(())
}

/// Static verification of the signed approval request carried by an
/// approve variant: it must be signed by the requester, describe
/// exactly this event (subject, sn, governance version, evaluated
/// patch) and respect the minimum approval window. The votes are not
/// checked here: this worker verifies the closed evidence data-only
/// when it arrives inside the validation request.
pub fn check_approval_req(
    approval_req: &Signed<ApprovalReq>,
    metadata: &Metadata,
    gov_version: u64,
    patch: &ValueWrapper,
    signer: &PublicKey,
    min_window: Duration,
) -> Result<(), ValidatorError> {
    if approval_req.verify().is_err() {
        return Err(ValidatorError::InvalidSignature {
            data: "approval request",
        });
    }

    if approval_req.signature().signer != *signer {
        return Err(ValidatorError::InvalidSigner {
            signer: approval_req.signature().signer.to_string(),
        });
    }

    let req = approval_req.content();

    if req.signer != *signer {
        return Err(ValidatorError::InvalidSigner {
            signer: req.signer.to_string(),
        });
    }

    if req.subject_id != metadata.subject_id {
        return Err(ValidatorError::InvalidData {
            value: "approval subject_id",
        });
    }

    if req.sn != metadata.sn.saturating_add(1) {
        return Err(ValidatorError::InvalidData {
            value: "approval sn",
        });
    }

    if req.gov_version != gov_version {
        return Err(ValidatorError::InvalidData {
            value: "approval gov_version",
        });
    }

    if &req.patch != patch {
        return Err(ValidatorError::InvalidData {
            value: "approval patch",
        });
    }

    let min_deadline = TimeStamp::from_nanos(
        req.issued_at
            .as_nanos()
            .saturating_add(min_window.as_nanos() as u64),
    );
    if req.deadline < min_deadline {
        return Err(ValidatorError::InvalidData {
            value: "approval window",
        });
    }

    let now = TimeStamp::now();
    let skew_limit = TimeStamp::from_nanos(
        now.as_nanos().saturating_add(CLOCK_SKEW.as_nanos() as u64),
    );
    if req.issued_at > skew_limit {
        return Err(ValidatorError::InvalidData {
            value: "approval issued_at",
        });
    }

    Ok(())
}

pub fn check_evaluation(
    hash: &HashAlgorithm,
    evaluation: EvaluationData,
    eval_data: RoleDataRegister,
    mut properties: ValueWrapper,
    anchor: EventAnchor<'_>,
) -> Result<(bool, Option<ValueWrapper>, ValueWrapper), ValidatorError>
{
    let EventAnchor {
        event_request,
        metadata,
        gov_version,
        req_subject_data_hash,
        signer,
    } = anchor;
    if signer != evaluation.eval_req_signature.signer {
        return Err(ValidatorError::InvalidSigner {
            signer: signer.to_string(),
        });
    }

    // The evaluation request is fully determined by the event under
    // validation (signed event request, subject metadata and
    // governance version), so it is rebuilt here: the stored request
    // signature must verify cryptographically over it and the stored
    // request hash must reproduce exactly. The state sent to the
    // evaluators is the pre-event subject properties, the same data
    // this validator re-evaluates over.
    let eval_state = match (
        metadata.schema_id.is_gov(),
        EventRequestType::from(event_request.content()),
    ) {
        (true, EventRequestType::Fact) => EvaluateData::GovFact {
            state: GovernanceData::try_from(metadata.properties.clone())
                .map_err(|_| ValidatorError::InvalidData {
                    value: "evaluation gov state",
                })?,
        },
        (true, EventRequestType::Transfer) => EvaluateData::GovTransfer {
            state: GovernanceData::try_from(metadata.properties.clone())
                .map_err(|_| ValidatorError::InvalidData {
                    value: "evaluation gov state",
                })?,
        },
        (true, EventRequestType::Confirm) => EvaluateData::GovConfirm {
            state: GovernanceData::try_from(metadata.properties.clone())
                .map_err(|_| ValidatorError::InvalidData {
                    value: "evaluation gov state",
                })?,
        },
        (false, EventRequestType::Fact) => {
            EvaluateData::TrackerSchemasFact {
                state: metadata.properties.clone(),
            }
        }
        (false, EventRequestType::Transfer) => {
            EvaluateData::TrackerSchemasTransfer {
                state: metadata.properties.clone(),
            }
        }
        _ => {
            return Err(ValidatorError::InvalidData {
                value: "evaluation event type",
            });
        }
    };
    let signed_eval_req = Signed::from_parts(
        EvaluationReq {
            event_request: event_request.clone(),
            governance_id: metadata.governance_id.clone(),
            data: eval_state,
            sn: metadata.sn.saturating_add(1),
            gov_version,
            namespace: metadata.namespace.clone(),
            schema_id: metadata.schema_id.clone(),
            signer: signer.clone(),
            signer_is_owner: signer == event_request.signature().signer,
        },
        evaluation.eval_req_signature.clone(),
    );
    if signed_eval_req.verify().is_err() {
        return Err(ValidatorError::InvalidSignature {
            data: "evaluation request",
        });
    }
    let recomputed_req_hash =
        hash_borsh(&*hash.hasher(), &signed_eval_req).map_err(
            |e| ValidatorError::InternalError {
                problem: e.to_string(),
            },
        )?;
    if recomputed_req_hash != evaluation.eval_req_hash {
        return Err(ValidatorError::InvalidData {
            value: "eval request hash",
        });
    }

    if !check_quorum_signers(
        &evaluation
            .evaluators_signatures
            .iter()
            .map(|x| x.signer.clone())
            .collect::<HashSet<PublicKey>>(),
        &eval_data.quorum,
        &eval_data.workers,
    ) {
        return Err(ValidatorError::InvalidOperation {
            action: "verify evaluation quorum",
        });
    }

    let (eval_result, result_hash) = match evaluation.response.clone() {
        EvaluationResponse::Ok {
            result,
            result_hash,
        } => (
            EvaluationResult::Ok {
                response: result,
                eval_req_hash: evaluation.eval_req_hash.clone(),
                req_subject_data_hash,
            },
            result_hash,
        ),
        EvaluationResponse::Error {
            result,
            result_hash,
        } => (
            EvaluationResult::Error {
                error: result,
                eval_req_hash: evaluation.eval_req_hash.clone(),
                req_subject_data_hash,
            },
            result_hash,
        ),
    };

    let eval_result_hash = hash_borsh(&*hash.hasher(), &eval_result)
        .map_err(|e| ValidatorError::InternalError {
        problem: e.to_string(),
    })?;

    if eval_result_hash != result_hash {
        return Err(ValidatorError::InvalidData {
            value: "eval result hash",
        });
    }

    for signature in evaluation.evaluators_signatures.iter() {
        if signature.verify(&eval_result_hash).is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "evaluation",
            });
        }
    }

    let (appr_required, req_patch) = if let Some(evaluator_res) =
        evaluation.evaluator_response_ok()
    {
        // Keep the patch: it is part of the approval request that
        // `check_approval` rebuilds and verifies.
        let req_patch = evaluator_res.patch.clone();
        let json_patch =
            serde_json::from_value::<Patch>(evaluator_res.patch.0)
                .map_err(|_| ValidatorError::InvalidData {
                    value: "evaluation patch",
                })?;

        patch(&mut properties.0, &json_patch).map_err(|_| {
            ValidatorError::InvalidOperation {
                action: "apply patch",
            }
        })?;

        let properties_hash = hash_borsh(&*hash.hasher(), &properties)
            .map_err(|e| ValidatorError::InternalError {
                problem: e.to_string(),
            })?;

        if properties_hash != evaluator_res.properties_hash {
            return Err(ValidatorError::InvalidData {
                value: "properties_hash",
            });
        }

        (evaluator_res.appr_required, Some(req_patch))
    } else {
        (false, None)
    };

    Ok((appr_required, req_patch, properties))
}

pub fn check_compilation(
    hash: &HashAlgorithm,
    compilation: CompilationData,
    comp_data: RoleDataRegister,
    anchor: EventAnchor<'_>,
) -> Result<(), ValidatorError> {
    let EventAnchor {
        event_request,
        metadata,
        gov_version,
        req_subject_data_hash,
        signer,
    } = anchor;
    if signer != compilation.compile_req_signature.signer {
        return Err(ValidatorError::InvalidSigner {
            signer: signer.to_string(),
        });
    }

    // The compilation request is fully determined by the event under
    // validation (signed event request, governance, sn, governance
    // version and effective build pin), so it is rebuilt here: the
    // stored request signature must verify cryptographically over it
    // and the stored request hash must reproduce exactly. This
    // closes the chain from the event request to the compiler votes,
    // which sign a result hash embedding this request hash (and the
    // pin through it and through the voted result).
    let pre = GovernanceData::try_from(metadata.properties.clone())
        .map_err(|_| ValidatorError::InvalidData {
            value: "governance state",
        })?;
    let signed_compile_req = Signed::from_parts(
        CompilationReq {
            event_request: event_request.clone(),
            governance_id: metadata.governance_id.clone(),
            sn: metadata.sn.saturating_add(1),
            gov_version,
            pin: effective_pin(
                event_request.content(),
                &pre.toolchain,
            ),
        },
        compilation.compile_req_signature.clone(),
    );
    if signed_compile_req.verify().is_err() {
        return Err(ValidatorError::InvalidSignature {
            data: "compilation request",
        });
    }
    let recomputed_req_hash =
        hash_borsh(&*hash.hasher(), &signed_compile_req).map_err(
            |e| ValidatorError::InternalError {
                problem: e.to_string(),
            },
        )?;
    if recomputed_req_hash != compilation.compile_req_hash {
        return Err(ValidatorError::InvalidData {
            value: "compile request hash",
        });
    }

    if !check_quorum_signers(
        &compilation
            .compilers_signatures
            .iter()
            .map(|x| x.signer.clone())
            .collect::<HashSet<PublicKey>>(),
        &comp_data.quorum,
        &comp_data.workers,
    ) {
        return Err(ValidatorError::InvalidOperation {
            action: "verify compilation quorum",
        });
    }

    // The voted result is rebuilt with the same effective pin: the
    // hash check below proves the compilers signed exactly this pin,
    // making divergence attributable.
    let pin = effective_pin(
        event_request.content(),
        &pre.toolchain,
    );
    // The voted toolchain version rides the evidence the same way:
    // the hash binds it, and the check below compares it against
    // the registry entry for the pin.
    let toolchain_version = match &compilation.response {
        CompilationResponse::Ok {
            toolchain_version, ..
        }
        | CompilationResponse::Error {
            toolchain_version, ..
        } => toolchain_version.clone(),
    };
    let (compile_result, result_hash) = match compilation.response.clone() {
        CompilationResponse::Ok {
            result,
            result_hash,
            ..
        } => (
            CompilationResult::Ok {
                response: result,
                compile_req_hash: compilation.compile_req_hash.clone(),
                req_subject_data_hash,
                pin: pin.clone(),
                toolchain_version: toolchain_version.clone(),
            },
            result_hash,
        ),
        CompilationResponse::Error {
            result,
            result_hash,
            ..
        } => (
            CompilationResult::Error {
                error: result,
                compile_req_hash: compilation.compile_req_hash.clone(),
                req_subject_data_hash,
                pin: pin.clone(),
                toolchain_version: toolchain_version.clone(),
            },
            result_hash,
        ),
    };

    let compile_result_hash =
        hash_borsh(&*hash.hasher(), &compile_result).map_err(|e| {
            ValidatorError::InternalError {
                problem: e.to_string(),
            }
        })?;

    if compile_result_hash != result_hash {
        return Err(ValidatorError::InvalidData {
            value: "compile result hash",
        });
    }

    for signature in compilation.compilers_signatures.iter() {
        if signature.verify(&compile_result_hash).is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "compilation",
            });
        }
    }

    // The toolchain that built the bytes must be the pin's: a valid
    // ID with another toolchain's bytes is rejected here (no
    // commit), which an empty version can never smuggle past —
    // in tests exactly as in production.
    if toolchain_version.is_empty() {
        return Err(ValidatorError::InvalidData {
            value: "compilation toolchain version",
        });
    } else {
        let entry = toolchain_info(&pin).ok_or(
            ValidatorError::InvalidData {
                value: "compilation toolchain pin",
            },
        )?;
        if toolchain_version != entry.rustc_version {
            return Err(ValidatorError::InvalidData {
                value: "compilation toolchain version",
            });
        }
    }

    // The response must cover exactly the contracts this event sends
    // through the compilation phase: a missing schema would commit
    // without a ledger anchor and an extra one would overwrite the
    // anchor of a contract the event did not touch.
    if let CompilationResponse::Ok { result, .. } = &compilation.response {
        let EventRequest::Fact(fact_request) = event_request.content()
        else {
            return Err(ValidatorError::InvalidData {
                value: "event request",
            });
        };
        // Coverage against the committed state: a pin switch
        // recompiles every existing schema under the new pin.
        let pre = GovernanceData::try_from(metadata.properties.clone())
            .map_err(|_| ValidatorError::InvalidData {
                value: "governance state",
            })?;
        let expected = compilation_set(&fact_request.payload, &pre).ok_or(
            ValidatorError::InvalidData {
                value: "compilation schemas",
            },
        )?;
        let got = result.contracts.keys().collect::<BTreeSet<_>>();
        if got != expected.iter().collect::<BTreeSet<_>>() {
            return Err(ValidatorError::InvalidData {
                value: "compilation contracts",
            });
        }
    }

    Ok(())
}

/// One named check and its detail for the report.
#[derive(Debug, Clone)]
pub struct Check {
    pub name: &'static str,
    pub detail: String,
}

/// Request-subject hash anchoring requests to their position,
/// exactly like validators compute it.
pub fn req_subject_data_hash(
    hash: &HashAlgorithm,
    metadata: &Metadata,
    sn: u64,
    gov_version: u64,
    signer: &PublicKey,
) -> Result<DigestIdentifier> {
    hash_borsh(
        &*hash.hasher(),
        &RequestSubjectData {
            subject_id: metadata.subject_id.clone(),
            governance_id: metadata.governance_id.clone(),
            namespace: metadata.namespace.clone(),
            schema_id: metadata.schema_id.clone(),
            sn,
            gov_version,
            signer: signer.clone(),
        },
    )
    .map_err(|e| anyhow::anyhow!("subject hash: {e}"))
}

/// Approval tally hash of an approval evidence, when present.
pub fn approval_data_hash_of(
    hash: &HashAlgorithm,
    approval: Option<&ApprovalData>,
) -> Result<Option<DigestIdentifier>> {
    match approval {
        Some(data) => Ok(Some(
            hash_borsh(&*hash.hasher(), data)
                .map_err(|e| anyhow::anyhow!("approval hash: {e}"))?,
        )),
        None => Ok(None),
    }
}

/// The validation result the validators of an event signed, read
/// off the event's own stored components (mirrors the subject
/// verifier: post-state hashes plus the current request and
/// approval hashes). Genesis carries genesis metadata instead of
/// a hash bundle.
pub fn validation_result_from_parts(
    validation: &ValidationData,
    approval_data_hash: Option<DigestIdentifier>,
) -> Result<ValidationRes> {
    match &validation.validation_metadata {
        ValidationMetadata::Metadata(metadata) => {
            Ok(ValidationRes::Create {
                vali_req_hash: validation.validation_req_hash.clone(),
                subject_metadata: metadata.clone(),
            })
        }
        ValidationMetadata::ModifiedHash {
            modified_metadata_without_propierties_hash,
            propierties_hash,
            event_request_hash,
            viewpoints_hash,
        } => Ok(ValidationRes::Response {
            vali_req_hash: validation.validation_req_hash.clone(),
            modified_metadata_without_propierties_hash:
                modified_metadata_without_propierties_hash.clone(),
            propierties_hash: propierties_hash.clone(),
            event_request_hash: event_request_hash.clone(),
            viewpoints_hash: viewpoints_hash.clone(),
            approval_data_hash,
        }),
    }
}

/// Validator signatures over the rebuilt result plus their quorum.
pub fn check_validation_signatures(
    validation: &ValidationData,
    rebuilt: &ValidationRes,
    validators: &RoleDataRegister,
) -> Result<()> {
    for signature in validation.validators_signatures.iter() {
        let signed =
            Signed::from_parts(rebuilt.clone(), signature.clone());
        if signed.verify().is_err() {
            bail!("validator signature invalid");
        }
    }
    let signers: HashSet<PublicKey> = validation
        .validators_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    if signers.is_empty() {
        bail!("no validator signatures");
    }
    if !check_quorum_signers(&signers, &validators.quorum, &validators.workers)
    {
        bail!("validator quorum not reached");
    }
    Ok(())
}

/// Stored validation bundle against freshly recomputed
/// post-state: the node commits an event only when the voted
/// bundle equals the post-state hashes plus the current request
/// hashes. Catches evidence that is well-signed but describes
/// another state.
pub fn check_validation_bundle(
    hash: &HashAlgorithm,
    validation: &ValidationData,
    request: &Arc<Signed<EventRequest>>,
    post_metadata: &Metadata,
    post_properties: &ValueWrapper,
) -> Result<Check> {
    let ValidationMetadata::ModifiedHash {
        modified_metadata_without_propierties_hash,
        propierties_hash,
        event_request_hash: stored_req_hash,
        viewpoints_hash: stored_viewpoints_hash,
    } = &validation.validation_metadata
    else {
        bail!("non-genesis event without hash metadata");
    };
    let recomputed_meta = hash_borsh(
        &*hash.hasher(),
        &MetadataWithoutProperties::from(post_metadata.clone()),
    )
    .map_err(|e| anyhow::anyhow!("metadata hash: {e}"))?;
    if recomputed_meta != *modified_metadata_without_propierties_hash {
        bail!("validation metadata does not match the post-state");
    }
    let recomputed_props =
        hash_borsh(&*hash.hasher(), post_properties)
            .map_err(|e| anyhow::anyhow!("properties hash: {e}"))?;
    if recomputed_props != *propierties_hash {
        bail!("validation properties do not match the post-state");
    }
    let recomputed_req = event_request_hash(hash, request)
        .map_err(|e| anyhow::anyhow!("event request hash: {e}"))?;
    if recomputed_req != *stored_req_hash {
        bail!("validation event hash does not match the request");
    }
    let recomputed_viewpoints =
        viewpoints_hash(hash, request.content())
            .map_err(|e| anyhow::anyhow!("viewpoints hash: {e}"))?;
    if recomputed_viewpoints != *stored_viewpoints_hash {
        bail!("validation viewpoints do not match the request");
    }
    Ok(Check {
        name: "validation-metadata",
        detail: "stored bundle matches the post-state".to_owned(),
    })
}

/// Phase and validator sets for a governance event, read off its
/// pre-event properties: the node commits gov events against the
/// historical governance state, never against a later register.
/// Mirrors the subject verifier exactly.
pub fn gov_roles_from_pre(
    pre_properties: &ValueWrapper,
    need_approval: bool,
    need_compilation: bool,
) -> Result<RolesAtVersion> {
    let gov = GovernanceData::try_from(pre_properties.clone())
        .map_err(|e| anyhow::anyhow!("governance state: {e}"))?;
    let set = |role: ProtocolTypes| {
        gov.get_quorum_and_signers(role, &SchemaType::Governance, Namespace::new())
            .map(|(workers, quorum)| RoleDataRegister {
                workers: workers.into_iter().collect::<HashSet<_>>(),
                quorum,
            })
            .map_err(|e| anyhow::anyhow!("gov roles: {e}"))
    };
    Ok(RolesAtVersion {
        evaluation: set(ProtocolTypes::Evaluation)?,
        approval: need_approval.then(|| set(ProtocolTypes::Approval)).transpose()?,
        compilation: need_compilation
            .then(|| set(ProtocolTypes::Compilation))
            .transpose()?,
        validators: set(ProtocolTypes::Validation)?,
    })
}

/// Approval evidence through the node's own checks, with the
/// evaluated patch and roles the node itself would use.
#[allow(clippy::too_many_arguments)]
pub fn verify_approval_evidence(
    hash: &HashAlgorithm,
    approval: &ApprovalData,
    subject_id: &DigestIdentifier,
    sn: u64,
    gov_version: u64,
    patch: &ValueWrapper,
    signer: &PublicKey,
    approvers: &RoleDataRegister,
    validators: &RoleDataRegister,
    req_subject_data_hash: &DigestIdentifier,
    metadata: &Metadata,
    min_window_secs: u64,
) -> Result<Vec<Check>> {
    use std::time::Duration;
    let rebuilt = rebuild_approval_req(
        approval, subject_id, sn, gov_version, patch, signer,
    );
    let signed = Signed::from_parts(
        rebuilt,
        approval.approval_req_signature.clone(),
    );
    if signed.verify().is_err() {
        bail!("approval request signature invalid");
    }
    let mut checks = vec![Check {
        name: "approval-request",
        detail: "rebuilt request matches its signature".to_owned(),
    }];
    check_approval_req(
        &signed,
        metadata,
        gov_version,
        patch,
        signer,
        Duration::from_secs(min_window_secs),
    )
    .map_err(|e| anyhow::anyhow!("approval request gates: {e}"))?;
    checks.push(Check {
        name: "approval-gates",
        detail: "subject/sn/version/patch/window match".to_owned(),
    });
    verify_approval_data(ApprovalVerification {
        hash,
        approval,
        approvers,
        validators,
        req_subject_data_hash,
        subject_id,
        sn,
        gov_version,
        patch,
        signer,
        now: TimeStamp::now(),
    })
    .map_err(|e| anyhow::anyhow!("approval evidence: {e}"))?;
    checks.push(Check {
        name: "approval",
        detail: "approval evidence verifies".to_owned(),
    });
    Ok(checks)
}

/// Compilation evidence through the node's own check.
#[allow(clippy::too_many_arguments)]
pub fn verify_compilation_evidence(
    hash: &HashAlgorithm,
    compilation: &CompilationData,
    event_request: &Arc<Signed<EventRequest>>,
    metadata: &Metadata,
    gov_version: u64,
    req_subject_data_hash: &DigestIdentifier,
    signer: &PublicKey,
    comp_roles: &RoleDataRegister,
) -> Result<Vec<Check>> {
    check_compilation(
        hash,
        compilation.clone(),
        comp_roles.clone(),
        EventAnchor {
            event_request,
            metadata,
            gov_version,
            req_subject_data_hash: req_subject_data_hash.clone(),
            signer: signer.clone(),
        },
    )
    .map_err(|e| anyhow::anyhow!("compilation evidence: {e}"))?;
    Ok(vec![Check {
        name: "compilation",
        detail: "compilation evidence verifies".to_owned(),
    }])
}

/// Evaluator signatures over the stored result hash plus
/// their quorum, without rebuilding the evaluation request
/// (which binds pre-state a diverged witness replay can not
/// reproduce). Same shape as the opaque evaluation check: it
/// proves the evaluators stood behind the stored result, while
/// the validator quorum above vouches for the bundle itself.
pub fn check_witness_evaluation(
    evaluation: &EvaluationData,
    eval_roles: &RoleDataRegister,
) -> Result<Check> {
    let result_hash = match &evaluation.response {
        EvaluationResponse::Ok { result_hash, .. }
        | EvaluationResponse::Error { result_hash, .. } => result_hash,
    };
    for signature in evaluation.evaluators_signatures.iter() {
        if signature.verify(result_hash).is_err() {
            bail!("witness evaluator signature invalid");
        }
    }
    let signers: HashSet<PublicKey> = evaluation
        .evaluators_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    if signers.is_empty() {
        bail!("no witness evaluator signatures");
    }
    if !check_quorum_signers(
        &signers,
        &eval_roles.quorum,
        &eval_roles.workers,
    ) {
        bail!("witness evaluator quorum not reached");
    }
    Ok(Check {
        name: "witness-evaluation-quorum",
        detail: "evaluator signatures verify with quorum".to_owned(),
    })
}

/// Evaluator signatures over an opaque stored result hash plus
/// their quorum. Same shape as the witness check, under opaque
/// report names so an opaque event never passes as fully rebuilt.
pub fn check_opaque_evaluation(
    evaluation: &EvaluationDataOpaque,
    eval_roles: &RoleDataRegister,
) -> Result<Check> {
    let result_hash = match &evaluation.response {
        EvaluationResponseOpaque::Ok { result_hash }
        | EvaluationResponseOpaque::Error { result_hash } => result_hash,
    };
    for signature in evaluation.evaluators_signatures.iter() {
        if signature.verify(result_hash).is_err() {
            bail!("opaque evaluator signature invalid");
        }
    }
    let signers: HashSet<PublicKey> = evaluation
        .evaluators_signatures
        .iter()
        .map(|signature| signature.signer.clone())
        .collect();
    if signers.is_empty() {
        bail!("no opaque evaluator signatures");
    }
    if !check_quorum_signers(
        &signers,
        &eval_roles.quorum,
        &eval_roles.workers,
    ) {
        bail!("opaque evaluator quorum not reached");
    }
    Ok(Check {
        name: "opaque-evaluation-quorum",
        detail: "evaluator signatures verify with quorum".to_owned(),
    })
}

/// Patch decided by successful evaluation, for the approval path.
pub fn evaluated_patch(
    evaluation: &EvaluationData,
) -> Result<ValueWrapper> {
    match &evaluation.response {
        EvaluationResponse::Ok { result, .. } => Ok(result.patch.clone()),
        EvaluationResponse::Error { .. } => {
            bail!("evaluation failed: no patch to approve")
        }
    }
}

/// Phase combination rules of a governance fact, mirroring the
/// node constructors: a failed compilation carries neither
/// evaluation nor approval (nothing to evaluate); otherwise an
/// evaluation is mandatory, a successful one always travels with
/// its approval and a failed one never does.
pub fn check_gov_fact_combination(
    compilation: &Option<Box<CompilationData>>,
    evaluation: &Option<EvaluationData>,
    approval: &Option<ApprovalData>,
) -> Result<()> {
    if let Some(compilation) = compilation {
        if !compilation.is_ok() {
            if evaluation.is_some() || approval.is_some() {
                bail!(
                    "failed compilation carries no evaluation or approval"
                );
            }
            return Ok(());
        }
    }
    match (evaluation, approval) {
        (None, _) => bail!("governance fact without evaluation"),
        (Some(evaluation), None) => {
            if evaluation.is_ok() {
                bail!("evaluation succeeded without approval");
            }
            Ok(())
        }
        (Some(evaluation), Some(_)) => {
            match &evaluation.response {
                EvaluationResponse::Ok {
                    result,
                    ..
                } => {
                    if !result.appr_required {
                        bail!("approval without required evaluation");
                    }
                    Ok(())
                }
                _ => bail!("approval over failed evaluation"),
            }
        }
    }
}

/// Static gates over genesis metadata, mirroring what the node
/// enforces before anything else exists (empty previous hash is
/// covered by the chain link check).
pub fn check_genesis_metadata(metadata: &Metadata) -> Result<()> {
    if metadata.sn != 0 {
        bail!("genesis metadata sn is not zero");
    }
    if metadata.subject_id.is_empty()
        || metadata.governance_id.is_empty()
        || metadata.creator.is_empty()
        || metadata.owner.is_empty()
    {
        bail!("genesis metadata has empty identities");
    }
    if !metadata.active {
        bail!("genesis metadata is inactive");
    }
    if !metadata.schema_id.is_valid_in_request() {
        bail!("genesis schema is not valid");
    }
    if metadata.schema_id == SchemaType::Governance {
        if metadata.governance_id != metadata.subject_id {
            bail!("genesis governance id mismatch");
        }
        if !metadata.namespace.is_empty() {
            bail!("genesis governance namespace is not empty");
        }
    } else if metadata.governance_id == metadata.subject_id {
        bail!("genesis tracker governance id mismatch");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Namespace, SchemaType,
        identity::{
            DigestIdentifier, KeyPair, PublicKey, keys::Ed25519Signer,
        },
    };

    fn key() -> PublicKey {
        KeyPair::Ed25519(Ed25519Signer::generate().expect("keygen"))
            .public_key()
    }

    fn gov_metadata() -> Metadata {
        Metadata {
            name: Some("gov".to_owned()),
            description: None,
            subject_id: DigestIdentifier::default(),
            governance_id: DigestIdentifier::default(),
            genesis_gov_version: 0,
            prev_ledger_event_hash: DigestIdentifier::default(),
            schema_id: SchemaType::Governance,
            namespace: Namespace::new(),
            sn: 1,
            creator: key(),
            owner: key(),
            new_owner: None,
            active: true,
            properties: ValueWrapper(serde_json::json!({"one": 0})),
        }
    }

    #[test]
    fn metadata_gates() {
        // Subject ids must be non-empty: hash fixed bytes.
        let id = |b: u8| {
            hash_borsh(&*HashAlgorithm::Blake3.hasher(), &b).expect("hash")
        };
        let mut gov = gov_metadata();
        gov.subject_id = id(1);
        gov.governance_id = gov.subject_id.clone();
        gov.prev_ledger_event_hash = id(2);
        assert!(
            check_metadata(&EventRequestType::Fact, &gov, 3).is_ok(),
            "honest gov metadata passes"
        );

        let mut tracker = gov.clone();
        tracker.schema_id = SchemaType::Type("Example".to_owned());
        tracker.governance_id = id(3);
        tracker.genesis_gov_version = 1;
        assert!(
            check_metadata(&EventRequestType::Fact, &tracker, 3).is_ok(),
            "honest tracker metadata passes"
        );

        // Each gate trips alone.
        let mut bad = gov.clone();
        bad.name = Some(String::new());
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.subject_id = DigestIdentifier::default();
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.governance_id = id(4);
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.genesis_gov_version = 9;
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.sn = 0;
        bad.prev_ledger_event_hash = id(5);
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.creator = PublicKey::default();
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.active = false;
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let mut bad = gov.clone();
        bad.new_owner = Some(key());
        assert!(check_metadata(&EventRequestType::Fact, &bad, 3).is_err());

        let bad = gov.clone();
        assert!(
            check_metadata(&EventRequestType::Confirm, &bad, 3).is_err(),
            "confirm needs a pending owner"
        );
    }
}
