use crate::{
    evaluation::{response::EvaluatorError, runner::types::EvaluateInfo},
    governance::data::GovernanceData,
    model::common::viewpoints::validate_fact_viewpoints,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed},
    request::EventRequest,
};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

/// A struct representing an evaluation request.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct EvaluationReq {
    /// The signed event request.
    pub event_request: Signed<EventRequest>,

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
    fn validate_fact_viewpoints(
        fact_viewpoints: &BTreeSet<String>,
        schema_id: &SchemaType,
        schema_viewpoints: Option<&BTreeSet<String>>,
    ) -> Result<(), EvaluatorError> {
        validate_fact_viewpoints(fact_viewpoints, schema_id, schema_viewpoints)
            .map_err(EvaluatorError::InvalidEventRequest)
    }

    pub fn build_evaluate_info(
        &self,
        init_state: &Option<ValueWrapper>,
    ) -> Result<EvaluateInfo, EvaluatorError> {
        match (self.event_request.content(), &self.data) {
            (
                EventRequest::Fact(fact_request),
                EvaluateData::GovFact { state },
            ) => {
                Self::validate_fact_viewpoints(
                    &fact_request.viewpoints,
                    &self.schema_id,
                    None,
                )?;

                Ok(EvaluateInfo::GovFact {
                    payload: fact_request.payload.clone(),
                    state: state.clone(),
                })
            }
            (
                EventRequest::Fact(fact_request),
                EvaluateData::TrackerSchemasFact {
                    contract,
                    state,
                    schema_viewpoints,
                },
            ) => init_state.as_ref().map_or_else(
                || {
                    Err(EvaluatorError::InternalError(
                        "Init state must be some".to_owned(),
                    ))
                },
                |init_state| {
                    Self::validate_fact_viewpoints(
                        &fact_request.viewpoints,
                        &self.schema_id,
                        Some(schema_viewpoints),
                    )?;

                    Ok(EvaluateInfo::TrackerSchemasFact {
                        contract: contract.clone(),
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
                EvaluateData::TrackerSchemasTransfer {
                    governance_data,
                    namespace,
                    schema_id,
                    ..
                },
            ) => Ok(EvaluateInfo::TrackerSchemasTransfer {
                governance_data: governance_data.clone(),
                new_owner: transfer_request.new_owner.clone(),
                old_owner: self.event_request.signature().signer.clone(),
                namespace: namespace.clone(),
                schema_id: schema_id.clone(),
            }),
            (
                EventRequest::Confirm(confirm_request),
                EvaluateData::GovConfirm { state },
            ) => Ok(EvaluateInfo::GovConfirm {
                new_owner: self.event_request.signature().signer.clone(),
                old_owner_name: confirm_request.name_old_owner.clone(),
                state: state.clone(),
            }),
            _ => Err(EvaluatorError::InvalidEventRequest(
                "Evaluate data does not correspond to the type of request"
                    .to_string(),
            )),
        }
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum EvaluateData {
    GovFact {
        state: GovernanceData,
    },
    GovTransfer {
        state: GovernanceData,
    },
    GovConfirm {
        state: GovernanceData,
    },
    TrackerSchemasFact {
        contract: String,
        state: ValueWrapper,
        schema_viewpoints: BTreeSet<String>,
    },
    TrackerSchemasTransfer {
        state: ValueWrapper,
        governance_data: GovernanceData,
        namespace: Namespace,
        schema_id: SchemaType,
    },
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

/// A struct representing the context in which the evaluation is being performed.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Eq,
    PartialEq,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SubjectContext {
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub schema_id: SchemaType,
    pub is_owner: bool,
    pub namespace: Namespace,
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::identity::{Signed, keys::{Ed25519Signer, KeyPair}};
    use serde_json::json;

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
            event_request,
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

        let error = req.build_evaluate_info(&None).unwrap_err();
        assert!(matches!(
            error,
            EvaluatorError::InvalidEventRequest(_)
        ));
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
            event_request,
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::TrackerSchemasFact {
                contract: "contract".to_owned(),
                state: ValueWrapper(json!({ "one": 0, "two": 0, "three": 0 })),
                schema_viewpoints: BTreeSet::from([
                    "agua".to_owned(),
                    "basura".to_owned(),
                ]),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Type("Example".to_owned()),
            signer: public_key,
            signer_is_owner: true,
        };

        let error = req
            .build_evaluate_info(&Some(ValueWrapper(json!({}))))
            .unwrap_err();
        assert!(matches!(
            error,
            EvaluatorError::InvalidEventRequest(_)
        ));
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
            event_request,
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::TrackerSchemasFact {
                contract: "contract".to_owned(),
                state: ValueWrapper(json!({ "one": 0, "two": 0, "three": 0 })),
                schema_viewpoints: BTreeSet::from([
                    "agua".to_owned(),
                    "basura".to_owned(),
                ]),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Type("Example".to_owned()),
            signer: public_key,
            signer_is_owner: true,
        };

        let error = req
            .build_evaluate_info(&Some(ValueWrapper(json!({}))))
            .unwrap_err();
        assert!(matches!(
            error,
            EvaluatorError::InvalidEventRequest(_)
        ));
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
            event_request,
            governance_id: DigestIdentifier::default(),
            data: EvaluateData::TrackerSchemasFact {
                contract: "contract".to_owned(),
                state: ValueWrapper(json!({ "one": 0, "two": 0, "three": 0 })),
                schema_viewpoints: BTreeSet::from([
                    "agua".to_owned(),
                    "basura".to_owned(),
                ]),
            },
            sn: 1,
            gov_version: 0,
            namespace: Namespace::default(),
            schema_id: SchemaType::Type("Example".to_owned()),
            signer: public_key,
            signer_is_owner: true,
        };

        let error = req
            .build_evaluate_info(&Some(ValueWrapper(json!({}))))
            .unwrap_err();
        assert!(matches!(
            error,
            EvaluatorError::InvalidEventRequest(_)
        ));
    }
}
