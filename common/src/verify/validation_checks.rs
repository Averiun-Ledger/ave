//! Validation evidence checks shared by the node and the
//! off-chain verification tool. Full evaluation and compilation
//! checks stay in core: they anchor governance state.

use std::{collections::BTreeSet, time::Duration};

use super::{
    approval_request::ApprovalReq, subject_metadata::Metadata,
    validator_error::ValidatorError, CLOCK_SKEW,
};
use crate::{
    ValueWrapper,
    bridge::request::EventRequestType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, TimeStamp,
        hash_borsh,
    },
    request::EventRequest,
};

use std::sync::Arc;

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

        let mut bad = gov.clone();
        assert!(
            check_metadata(&EventRequestType::Confirm, &bad, 3).is_err(),
            "confirm needs a pending owner"
        );
    }
}
