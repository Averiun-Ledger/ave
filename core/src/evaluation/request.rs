use crate::{
    evaluation::{
        response::EvaluatorError, runner::types::EvaluateInfo,
    },
};

use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed},
    request::EventRequest,
    schematype::ReservedWords,
};

use crate::governance::data::GovernanceData;

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

/// A struct representing an evaluation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct EvaluationReq {
    /// The signed event request.
    pub event_request: Arc<Signed<EventRequest>>,

    pub governance_id: DigestIdentifier,

    pub data: EvaluateData,

    pub sn: u64,

    pub gov_version: u64,

    pub namespace: Namespace,

    pub schema_id: SchemaType,

    pub signer: PublicKey,

    pub signer_is_owner: bool,
}

impl EvaluationReq {
    pub fn validate_fact_viewpoints(
        fact_viewpoints: &BTreeSet<String>,
        schema_id: &SchemaType,
        schema_viewpoints: Option<&BTreeSet<String>>,
    ) -> Result<(), EvaluatorError> {
        validate_fact_viewpoints(fact_viewpoints, schema_id, schema_viewpoints)
            .map_err(EvaluatorError::InvalidEventRequest)
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum EvaluateData {
    GovFact { state: GovernanceData },
    GovTransfer { state: GovernanceData },
    GovConfirm { state: GovernanceData },
    TrackerSchemasFact { state: ValueWrapper },
    TrackerSchemasTransfer { state: ValueWrapper },
}

impl EvaluateData {
    pub const fn is_gov_event(&self) -> bool {
        match self {
            Self::GovFact { .. }
            | Self::GovTransfer { .. }
            | Self::GovConfirm { .. } => true,
            Self::TrackerSchemasFact { .. }
            | Self::TrackerSchemasTransfer { .. } => false,
        }
    }
}

/// Viewpoint rules for evaluation requests: strict shared validation
/// (governance facts take none; tracker facts need schema-covered,
/// well-formed viewpoints). Intake keeps its own lenient check in
/// `crate::model::common::viewpoints`; evaluation (here and the
/// workers) requires this one — do not unify them without a protocol
/// decision.
pub fn validate_fact_viewpoints(
    fact_viewpoints: &BTreeSet<String>,
    schema_id: &SchemaType,
    schema_viewpoints: Option<&BTreeSet<String>>,
) -> Result<(), String> {
    if schema_id.is_gov() {
        if !fact_viewpoints.is_empty() {
            return Err(
                "governance fact events cannot define viewpoints".to_owned()
            );
        }

        return Ok(());
    }

    let Some(schema_viewpoints) = schema_viewpoints else {
        return Err(
            "tracker fact evaluation is missing schema viewpoints".to_owned()
        );
    };

    if schema_viewpoints.is_empty() && !fact_viewpoints.is_empty() {
        return Err(format!("schema {} does not define viewpoints", schema_id));
    }

    for viewpoint in fact_viewpoints {
        if viewpoint.trim().len() != viewpoint.len() {
            return Err(
                "viewpoints cannot have surrounding whitespace".to_owned()
            );
        }

        if viewpoint.is_empty() {
            return Err("viewpoints cannot be empty".to_owned());
        }

        if viewpoint == &ReservedWords::AllViewpoints.to_string() {
            return Err(
                "AllViewpoints is not valid in fact requests; use an empty viewpoints set to indicate an unsegmented event"
                    .to_owned(),
            );
        }

        if viewpoint.len() > 100 {
            return Err(
                "viewpoints cannot be longer than 100 characters".to_owned()
            );
        }
    }

    if fact_viewpoints.is_empty() {
        return Ok(());
    }

    for viewpoint in fact_viewpoints {
        if !schema_viewpoints.contains(viewpoint) {
            return Err(format!(
                "viewpoint '{}' is not defined in schema {}",
                viewpoint, schema_id
            ));
        }
    }

    Ok(())
}

#[derive(Debug, Clone, Default)]
pub enum EvalWorkerContext {
    #[default]
    Empty,
    Governance {
        issuers: BTreeSet<PublicKey>,
        issuer_any: bool,
        /// Committed toolchain pin, pushed by the governance actor: the
        /// intake gate validates event pins against it (never against
        /// locally installed toolchains).
        toolchain: String,
    },
    TrackerFact {
        issuers: BTreeSet<PublicKey>,
        issuer_any: bool,
        schema_viewpoints: BTreeSet<String>,
    },
    TrackerTransfer {
        members: BTreeSet<PublicKey>,
        creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
    },
}

impl EvalWorkerContext {
    pub const fn issuers(&self) -> Option<(&BTreeSet<PublicKey>, bool)> {
        match self {
            Self::Governance {
                issuers,
                issuer_any,
                ..
            }
            | Self::TrackerFact {
                issuers,
                issuer_any,
                ..
            } => Some((issuers, *issuer_any)),
            Self::Empty | Self::TrackerTransfer { .. } => None,
        }
    }

    /// Committed toolchain pin, if this worker evaluates governance
    /// facts.
    pub const fn toolchain(&self) -> Option<&String> {
        match self {
            Self::Governance { toolchain, .. } => Some(toolchain),
            _ => None,
        }
    }
}

pub fn build_evaluate_info(
    req: &EvaluationReq,
    init_state: &Option<ValueWrapper>,
    worker_context: &EvalWorkerContext,
) -> Result<EvaluateInfo, EvaluatorError> {
    match (req.event_request.content(), &req.data) {
        (
            EventRequest::Fact(fact_request),
            EvaluateData::GovFact { state },
        ) => {
            EvaluationReq::validate_fact_viewpoints(
                &fact_request.viewpoints,
                &req.schema_id,
                None,
            )?;

            Ok(EvaluateInfo::GovFact {
                payload: fact_request.payload.clone(),
                state: state.clone(),
            })
        }
        (
            EventRequest::Fact(fact_request),
            EvaluateData::TrackerSchemasFact { state },
        ) => init_state.as_ref().map_or_else(
            || {
                Err(EvaluatorError::InternalError(
                    "Init state must be some".to_owned(),
                ))
            },
            |init_state| {
                let EvalWorkerContext::TrackerFact {
                    schema_viewpoints,
                    ..
                } = worker_context
                else {
                    return Err(EvaluatorError::InternalError(
                        "Tracker fact evaluation context is missing"
                            .to_owned(),
                    ));
                };

                EvaluationReq::validate_fact_viewpoints(
                    &fact_request.viewpoints,
                    &req.schema_id,
                    Some(schema_viewpoints),
                )?;

                Ok(EvaluateInfo::TrackerSchemasFact {
                    contract: format!(
                        "{}_{}",
                        req.governance_id, req.schema_id
                    ),
                    init_state: init_state.clone(),
                    state: state.clone(),
                    payload: fact_request.payload.clone(),
                })
            },
        ),
        (
            EventRequest::Transfer(transfer_request),
            EvaluateData::GovTransfer { state },
        ) => Ok(EvaluateInfo::GovTransfer {
            new_owner: transfer_request.new_owner.clone(),
            state: state.clone(),
        }),
        (
            EventRequest::Transfer(transfer_request),
            EvaluateData::TrackerSchemasTransfer { .. },
        ) => {
            let EvalWorkerContext::TrackerTransfer { members, creators } =
                worker_context
            else {
                return Err(EvaluatorError::InternalError(
                    "Tracker transfer evaluation context is missing"
                        .to_owned(),
                ));
            };

            Ok(EvaluateInfo::TrackerSchemasTransfer {
                new_owner: transfer_request.new_owner.clone(),
                old_owner: req.event_request.signature().signer.clone(),
                namespace: req.namespace.clone(),
                schema_id: req.schema_id.clone(),
                members: members.clone(),
                creators: creators.clone(),
            })
        }
        (
            EventRequest::Confirm(confirm_request),
            EvaluateData::GovConfirm { state },
        ) => Ok(EvaluateInfo::GovConfirm {
            new_owner: req.event_request.signature().signer.clone(),
            old_owner_name: confirm_request.name_old_owner.clone(),
            state: state.clone(),
        }),
        _ => Err(EvaluatorError::InvalidEventRequest(
            "Evaluate data does not correspond to the type of request"
                .to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::identity::{
        Signed,
        keys::{Ed25519Signer, KeyPair},
    };
    use ave_common::{SchemaType, identity::DigestIdentifier};
    use crate::governance::data::GovernanceData;
    use serde_json::json;
    use std::sync::Arc;

    #[test]
    fn test_build_evaluate_info_rejects_governance_fact_viewpoints() {
        let signer = Ed25519Signer::generate().unwrap();
        let public_key = KeyPair::Ed25519(signer.clone()).public_key();
        let request = EventRequest::Fact(ave_common::request::FactRequest {
            subject_id: DigestIdentifier::default(),
            payload: ValueWrapper(json!({ "members": { "add": [] } })),
            viewpoints: BTreeSet::from(["agua".to_owned()]),
        });

        let event_request = Signed::new(request, &signer).unwrap();

        let req = EvaluationReq {
            event_request: Arc::new(event_request),
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::GovFact {
                state: GovernanceData::new(public_key.clone()),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Governance,
            signer: public_key,
            signer_is_owner: true,
        };

        let error =         build_evaluate_info(&req,  &None, &EvalWorkerContext::default())
            .unwrap_err();
        assert!(matches!(error, EvaluatorError::InvalidEventRequest(_)));
    }

    #[test]
    fn test_build_evaluate_info_rejects_unknown_tracker_fact_viewpoint() {
        let signer = Ed25519Signer::generate().unwrap();
        let public_key = KeyPair::Ed25519(signer.clone()).public_key();
        let request = EventRequest::Fact(ave_common::request::FactRequest {
            subject_id: DigestIdentifier::default(),
            payload: ValueWrapper(json!({ "ModOne": { "data": 1 } })),
            viewpoints: BTreeSet::from(["vidrio".to_owned()]),
        });

        let event_request = Signed::new(request, &signer).unwrap();

        let req = EvaluationReq {
            event_request: Arc::new(event_request),
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::TrackerSchemasFact {
                state: ValueWrapper(json!({ "one": 0, "two": 0, "three": 0 })),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Type("Example".to_owned()),
            signer: public_key,
            signer_is_owner: true,
        };

        let error =         build_evaluate_info(&req,  
                &Some(ValueWrapper(json!({}))),
                &EvalWorkerContext::TrackerFact {
                    issuers: BTreeSet::new(),
                    issuer_any: false,
                    schema_viewpoints: BTreeSet::from([
                        "agua".to_owned(),
                        "basura".to_owned(),
                    ]),
                },
            )
            .unwrap_err();
        assert!(matches!(error, EvaluatorError::InvalidEventRequest(_)));
    }

    #[test]
    fn test_build_evaluate_info_rejects_all_viewpoints_in_tracker_fact() {
        let signer = Ed25519Signer::generate().unwrap();
        let public_key = KeyPair::Ed25519(signer.clone()).public_key();
        let request = EventRequest::Fact(ave_common::request::FactRequest {
            subject_id: DigestIdentifier::default(),
            payload: ValueWrapper(json!({ "ModOne": { "data": 1 } })),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        });

        let event_request = Signed::new(request, &signer).unwrap();

        let req = EvaluationReq {
            event_request: Arc::new(event_request),
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::TrackerSchemasFact {
                state: ValueWrapper(json!({ "one": 0, "two": 0, "three": 0 })),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Type("Example".to_owned()),
            signer: public_key,
            signer_is_owner: true,
        };

        let error =         build_evaluate_info(&req,  
                &Some(ValueWrapper(json!({}))),
                &EvalWorkerContext::TrackerFact {
                    issuers: BTreeSet::new(),
                    issuer_any: false,
                    schema_viewpoints: BTreeSet::from([
                        "agua".to_owned(),
                        "basura".to_owned(),
                    ]),
                },
            )
            .unwrap_err();
        assert!(matches!(error, EvaluatorError::InvalidEventRequest(_)));
    }

    #[test]
    fn test_build_evaluate_info_rejects_unknown_no_viewpoints_viewpoint() {
        let signer = Ed25519Signer::generate().unwrap();
        let public_key = KeyPair::Ed25519(signer.clone()).public_key();
        let request = EventRequest::Fact(ave_common::request::FactRequest {
            subject_id: DigestIdentifier::default(),
            payload: ValueWrapper(json!({ "ModOne": { "data": 1 } })),
            viewpoints: BTreeSet::from(["NoViewpoints".to_owned()]),
        });

        let event_request = Signed::new(request, &signer).unwrap();

        let req = EvaluationReq {
            event_request: Arc::new(event_request),
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::TrackerSchemasFact {
                state: ValueWrapper(json!({ "one": 0, "two": 0, "three": 0 })),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Type("Example".to_owned()),
            signer: public_key,
            signer_is_owner: true,
        };

        let error =         build_evaluate_info(&req,  
                &Some(ValueWrapper(json!({}))),
                &EvalWorkerContext::TrackerFact {
                    issuers: BTreeSet::new(),
                    issuer_any: false,
                    schema_viewpoints: BTreeSet::from([
                        "agua".to_owned(),
                        "basura".to_owned(),
                    ]),
                },
            )
            .unwrap_err();
        assert!(matches!(error, EvaluatorError::InvalidEventRequest(_)));
    }
}
