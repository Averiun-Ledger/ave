//! # Request data model.
//!

use std::{collections::HashSet, fmt::Display};

use crate::{
    governance::{data::GovernanceData, model::SignersType},
    subject::Metadata,
};

use ave_common::{identity::PublicKey, request::EventRequest};

pub enum EventRequestType {
    Create,
    Fact,
    Transfer,
    Confirm,
    Reject,
    EOL,
}

pub enum SignerTypes {
    One(PublicKey),
    List(HashSet<PublicKey>, bool),
}

impl From<&EventRequest> for EventRequestType {
    fn from(value: &EventRequest) -> Self {
        match value {
            EventRequest::Create(_start_request) => Self::Create,
            EventRequest::Fact(_fact_request) => Self::Fact,
            EventRequest::Transfer(_transfer_request) => Self::Transfer,
            EventRequest::Confirm(_confirm_request) => Self::Confirm,
            EventRequest::EOL(_eolrequest) => Self::EOL,
            EventRequest::Reject(_reject_request) => Self::Reject,
        }
    }
}

impl Display for EventRequestType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EventRequestType::Create => write!(f, "Create"),
            EventRequestType::Fact => write!(f, "Fact"),
            EventRequestType::Transfer => write!(f, "Transfer"),
            EventRequestType::Confirm => write!(f, "Confirm"),
            EventRequestType::Reject => write!(f, "Reject"),
            EventRequestType::EOL => write!(f, "EOL"),
        }
    }
}

pub fn check_signers(
    request: EventRequest,
    signer: &PublicKey,
    metadata: &Metadata,
    gov: &GovernanceData,
) -> bool {
    match request {
        EventRequest::Create(_)
        | EventRequest::EOL(_)
        | EventRequest::Transfer(_) => {
            return metadata.owner == *signer;
        }
        EventRequest::Fact(_) => {
            let (set, any) = gov.get_signers(
                SignersType::Issuer,
                &metadata.schema_id,
                metadata.namespace.clone(),
            );

            if any {
                return true;
            }

            return set.iter().any(|x| x == signer);
        }
        EventRequest::Confirm(_) | EventRequest::Reject(_) => {
            if let Some(new_owner) = metadata.new_owner.clone() {
                return new_owner == *signer;
            }
        }
    }
    false
}

#[cfg(test)]
pub mod tests {

    use super::*;

    use ave_common::identity::{Signature, Signed, keys::KeyPair};

    // Mocks

    // Create governance request mock.
    pub fn create_start_request_mock(
        _issuer: &str,
        keys: KeyPair,
    ) -> Signed<EventRequest> {
        let req = CreateRequest {
            name: None,
            description: None,
            governance_id: DigestIdentifier::default(),
            schema_id: SchemaType::Governance,
            namespace: Namespace::from("namespace"),
        };
        let content = EventRequest::Create(req);
        let signature = Signature::new(&content, &keys).unwrap();
        Signed { content, signature }
    }
}
