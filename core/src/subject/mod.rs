//! # Subject module.
//!

use std::{collections::HashSet, ops::Deref};

use crate::{
    EventRequestType,
    governance::{
        Governance,
        data::GovernanceData,
        model::Quorum,
        role_register::{RoleDataRegister, SearchRole},
    },
    model::{
        common::{
            check_quorum_signers, get_n_events, get_validation_roles_register,
        },
        event::{Ledger, Protocols, ValidationMetadata},
    },
    node::register::{Register, RegisterMessage},
    tracker::Tracker,
    validation::{
        request::{ActualProtocols, LastData, ValidationReq},
        response::ValidationRes,
    },
};

use error::SubjectError;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, PersistentActor,
};
use ave_common::{
    DataToSinkEvent, Namespace, SchemaType, ValueWrapper,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
    request::EventRequest,
};

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use sinkdata::{SinkData, SinkDataMessage};
use tracing::{debug, error};

pub mod error;
pub mod sinkdata;

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct SignedLedger(pub Signed<Ledger>);

impl Deref for SignedLedger {
    type Target = Signed<Ledger>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Event for SignedLedger {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RequestSubjectData {
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub namespace: Namespace,
    pub schema_id: SchemaType,
    pub sn: u64,
    pub gov_version: u64,
    pub signer: PublicKey,
}

/// Subject metadata.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct Metadata {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The identifier of the subject of the event.
    pub subject_id: DigestIdentifier,
    /// The identifier of the governance contract.
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    /// The identifier of the schema_id used to validate the event.
    pub schema_id: SchemaType,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The current sequence number of the subject.
    pub sn: u64,
    /// The identifier of the public key of the creator owner.
    pub creator: PublicKey,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

impl From<Governance> for Metadata {
    fn from(value: Governance) -> Self {
        Metadata {
            name: value.subject_metadata.name,
            description: value.subject_metadata.description,
            subject_id: value.subject_metadata.subject_id.clone(),
            governance_id: value.subject_metadata.subject_id,
            genesis_gov_version: 0,
            prev_ledger_event_hash: value
                .subject_metadata
                .prev_ledger_event_hash,
            schema_id: value.subject_metadata.schema_id,
            namespace: Namespace::new(),
            sn: value.subject_metadata.sn,
            creator: value.subject_metadata.creator,
            owner: value.subject_metadata.owner,
            new_owner: value.subject_metadata.new_owner,
            active: value.subject_metadata.active,
            properties: value.properties.to_value_wrapper(),
        }
    }
}

impl From<Tracker> for Metadata {
    fn from(value: Tracker) -> Self {
        Metadata {
            name: value.subject_metadata.name,
            description: value.subject_metadata.description,
            subject_id: value.subject_metadata.subject_id,
            governance_id: value.governance_id,
            genesis_gov_version: value.genesis_gov_version,
            prev_ledger_event_hash: value
                .subject_metadata
                .prev_ledger_event_hash,
            schema_id: value.subject_metadata.schema_id,
            namespace: value.namespace,
            sn: value.subject_metadata.sn,
            creator: value.subject_metadata.creator,
            owner: value.subject_metadata.owner,
            new_owner: value.subject_metadata.new_owner,
            active: value.subject_metadata.active,
            properties: value.properties,
        }
    }
}

pub struct DataForSink {
    pub gov_id: Option<String>,
    pub subject_id: String,
    pub sn: u64,
    pub owner: String,
    pub namespace: String,
    pub schema_id: SchemaType,
    pub issuer: String,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
}

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Clone,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SubjectMetadata {
    /// The name of the subject.
    pub name: Option<String>,
    /// The description of the subject.
    pub description: Option<String>,
    /// The identifier of the subject.
    pub subject_id: DigestIdentifier,

    pub schema_id: SchemaType,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    /// The identifier of the public key of the new subject owner.
    pub new_owner: Option<PublicKey>,

    pub prev_ledger_event_hash: DigestIdentifier,
    /// The identifier of the public key of the subject creator.
    pub creator: PublicKey,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current sequence number of the subject.
    pub sn: u64,
}

impl SubjectMetadata {
    pub fn new(data: &Metadata) -> Self {
        Self {
            name: data.name.clone(),
            description: data.description.clone(),
            subject_id: data.subject_id.clone(),
            owner: data.creator.clone(),
            schema_id: data.schema_id.clone(),
            new_owner: data.new_owner.clone(),
            prev_ledger_event_hash: data.prev_ledger_event_hash.clone(),
            creator: data.creator.clone(),
            active: data.active.clone(),
            sn: data.sn.clone(),
        }
    }
}

#[async_trait]
pub trait Subject
where
    <Self as Actor>::Event: BorshSerialize + BorshDeserialize,
    Self: PersistentActor,
{
    fn apply_patch_verify(
        subject_properties: &mut ValueWrapper,
        json_patch: ValueWrapper,
    ) -> Result<(), SubjectError> {
        let json_patch = serde_json::from_value::<Patch>(json_patch.0)
            .map_err(|e| SubjectError::PatchConversionFailed {
                details: e.to_string(),
            })?;

        patch(&mut subject_properties.0, &json_patch).map_err(|e| {
            SubjectError::PatchApplicationFailed {
                details: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn verify_new_ledger_event(
        ctx: &mut ActorContext<Self>,
        new_ledger_event: &SignedLedger,
        subject_metadata: Metadata,
        actual_ledger_event_hash: DigestIdentifier,
        last_data: LastData,
        hash: &HashAlgorithm,
    ) -> Result<bool, SubjectError> {
        if !subject_metadata.active {
            return Err(SubjectError::SubjectInactive);
        }

        if new_ledger_event.verify().is_err() {
            return Err(SubjectError::SignatureVerificationFailed {
                context: "new ledger event signature verification failed"
                    .to_string(),
            });
        }

        let signer = if let Some(new_owner) = &subject_metadata.new_owner {
            new_owner.clone()
        } else {
            subject_metadata.owner.clone()
        };

        if new_ledger_event.signature().signer != signer {
            return Err(SubjectError::IncorrectSigner {
                expected: signer.to_string(),
                actual: new_ledger_event.signature().signer.to_string(),
            });
        }

        if new_ledger_event.content().event_request.verify().is_err() {
            return Err(SubjectError::SignatureVerificationFailed {
                context: "event request signature verification failed"
                    .to_string(),
            });
        }

        if new_ledger_event.content().sn == subject_metadata.sn + 1 {
            return Err(SubjectError::InvalidSequenceNumber {
                expected: subject_metadata.sn + 1,
                actual: new_ledger_event.content().sn,
            });
        }

        if actual_ledger_event_hash
            != new_ledger_event.content().prev_ledger_event_hash
        {
            return Err(SubjectError::PreviousHashMismatch);
        }

        let mut modified_subject_metadata = subject_metadata.clone();
        modified_subject_metadata.sn += 1;

        let (validation, new_actual_protocols) = match (
            new_ledger_event.content().event_request.content(),
            &new_ledger_event.content().protocols,
            subject_metadata.schema_id.is_gov(),
        ) {
            (
                EventRequest::Fact(..),
                Protocols::TrackerFact {
                    evaluation,
                    validation,
                },
                false,
            ) => {
                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedFactEvent);
                }

                if let Some(eval) = evaluation.evaluator_res() {
                    Self::apply_patch_verify(
                        &mut modified_subject_metadata.properties,
                        eval.patch,
                    )?;
                }
                (
                    validation,
                    ActualProtocols::Eval {
                        eval_data: evaluation.clone(),
                    },
                )
            }
            (
                EventRequest::Fact(..),
                Protocols::GovFact {
                    evaluation,
                    approval,
                    validation,
                },
                true,
            ) => {
                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedFactEvent);
                }

                let actual_protocols = if let Some(eval) =
                    evaluation.evaluator_res()
                {
                    if let Some(appr) = approval {
                        if appr.approved {
                            Self::apply_patch_verify(
                                &mut modified_subject_metadata.properties,
                                eval.patch,
                            )?;
                        }

                        ActualProtocols::EvalApprove {
                            eval_data: evaluation.clone(),
                            approval_data: appr.clone(),
                        }
                    } else {
                        return Err(
                            SubjectError::MissingApprovalAfterEvaluation,
                        );
                    }
                } else {
                    if approval.is_some() {
                        return Err(SubjectError::UnexpectedApprovalAfterFailedEvaluation);
                    } else {
                        ActualProtocols::Eval {
                            eval_data: evaluation.clone(),
                        }
                    }
                };

                (validation, actual_protocols)
            }
            (
                EventRequest::Transfer(transfer),
                Protocols::Transfer {
                    evaluation,
                    validation,
                },
                ..,
            ) => {
                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedTransferEvent);
                }

                if let Some(eval) = evaluation.evaluator_res() {
                    Self::apply_patch_verify(
                        &mut modified_subject_metadata.properties,
                        eval.patch,
                    )?;
                    modified_subject_metadata.new_owner =
                        Some(transfer.new_owner.clone());
                }

                (
                    validation,
                    ActualProtocols::Eval {
                        eval_data: evaluation.clone(),
                    },
                )
            }
            (
                EventRequest::Confirm(..),
                Protocols::TrackerConfirm { validation },
                false,
            ) => {
                if let Some(new_owner) =
                    &modified_subject_metadata.new_owner.take()
                {
                    modified_subject_metadata.owner = new_owner.clone();
                } else {
                    return Err(SubjectError::ConfirmWithoutNewOwner);
                }

                (validation, ActualProtocols::None)
            }
            (
                EventRequest::Confirm(..),
                Protocols::GovConfirm {
                    evaluation,
                    validation,
                },
                true,
            ) => {
                if let Some(eval) = evaluation.evaluator_res() {
                    Self::apply_patch_verify(
                        &mut modified_subject_metadata.properties,
                        eval.patch,
                    )?;

                    if let Some(new_owner) =
                        &modified_subject_metadata.new_owner.take()
                    {
                        modified_subject_metadata.owner = new_owner.clone();
                    } else {
                        return Err(SubjectError::ConfirmWithoutNewOwner);
                    }
                }

                (
                    validation,
                    ActualProtocols::Eval {
                        eval_data: evaluation.clone(),
                    },
                )
            }
            (
                EventRequest::Reject(..),
                Protocols::Reject { validation },
                ..,
            ) => {
                if modified_subject_metadata.new_owner.take().is_none() {
                    return Err(SubjectError::RejectWithoutNewOwner);
                }

                (validation, ActualProtocols::None)
            }
            (EventRequest::EOL(..), Protocols::EOL { validation }, ..) => {
                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedEOLEvent);
                }

                modified_subject_metadata.active = false;
                (validation, ActualProtocols::None)
            }
            _ => {
                return Err(SubjectError::EventProtocolMismatch);
            }
        };

        let validation_req = ValidationReq::Event {
            actual_protocols: new_actual_protocols,
            event_request: new_ledger_event.content().event_request.clone(),
            ledger_hash: actual_ledger_event_hash,
            metadata: subject_metadata.clone(),
            last_data,
            gov_version: new_ledger_event.content().gov_version,
            sn: new_ledger_event.content().sn,
        };

        let signed_validation_req = Signed::from_parts(
            validation_req,
            validation.validation_req_signature.clone(),
        );

        if signed_validation_req.verify().is_err() {
            return Err(SubjectError::InvalidValidationRequestSignature);
        }

        let hash_signed_val_req =
            hash_borsh(&*hash.hasher(), &signed_validation_req).map_err(
                |e| SubjectError::ValidationRequestHashFailed {
                    details: e.to_string(),
                },
            )?;

        if hash_signed_val_req != validation.validation_req_hash {
            return Err(SubjectError::ValidationRequestHashMismatch);
        }

        let modified_metadata_hash =
            hash_borsh(&*hash.hasher(), &modified_subject_metadata).map_err(
                |e| SubjectError::ModifiedMetadataHashFailed {
                    details: e.to_string(),
                },
            )?;

        let validation_res = ValidationRes::Response {
            vali_req_hash: hash_signed_val_req,
            modified_metadata_hash,
        };

        let role_data = get_validation_roles_register(
            ctx,
            &subject_metadata.governance_id,
            SearchRole {
                schema_id: subject_metadata.schema_id,
                namespace: subject_metadata.namespace,
            },
            new_ledger_event.content().gov_version,
        )
        .await
        .map_err(|e| SubjectError::ValidatorsRetrievalFailed {
            details: e.to_string(),
        })?;

        if !check_quorum_signers(
            &validation
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &role_data.quorum,
            &role_data.workers,
        ) {
            return Err(SubjectError::InvalidQuorum);
        }

        for signature in validation.validators_signatures.iter() {
            let signed_res =
                Signed::from_parts(validation_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(SubjectError::InvalidValidatorSignature);
            }
        }

        Ok(new_ledger_event.content().protocols.is_success())
    }

    async fn verify_first_ledger_event(
        ctx: &mut ActorContext<Self>,
        ledger_event: &SignedLedger,
        hash: &HashAlgorithm,
        subject_metadata: Metadata,
    ) -> Result<(), SubjectError> {
        if ledger_event.verify().is_err() {
            return Err(SubjectError::SignatureVerificationFailed {
                context: "first ledger event signature verification failed"
                    .to_string(),
            });
        }

        if ledger_event.signature().signer != subject_metadata.owner {
            return Err(SubjectError::IncorrectSigner {
                expected: subject_metadata.owner.to_string(),
                actual: ledger_event.signature().signer.to_string(),
            });
        }

        if ledger_event.content().event_request.verify().is_err() {
            return Err(SubjectError::SignatureVerificationFailed {
                context: "event request signature verification failed"
                    .to_string(),
            });
        }

        if ledger_event.content().sn != 0 {
            return Err(SubjectError::InvalidCreationSequenceNumber);
        }

        if !ledger_event.content().prev_ledger_event_hash.is_empty() {
            return Err(SubjectError::NonEmptyPreviousHashInCreation);
        }

        let event_request_type = EventRequestType::from(
            ledger_event.content().event_request.content(),
        );

        let validation =
            match (event_request_type, &ledger_event.content().protocols) {
                (
                    EventRequestType::Create,
                    Protocols::Create { validation },
                ) => validation,
                _ => {
                    return Err(SubjectError::EventProtocolMismatch);
                }
            };

        let ValidationMetadata::Metadata(metadata) =
            &validation.validation_metadata
        else {
            return Err(SubjectError::InvalidValidationMetadata);
        };

        let validation_req = ValidationReq::Create {
            event_request: ledger_event.content().event_request.clone(),
            gov_version: ledger_event.content().gov_version,
        };

        let signed_validation_req = Signed::from_parts(
            validation_req,
            validation.validation_req_signature.clone(),
        );

        if signed_validation_req.verify().is_err() {
            return Err(SubjectError::InvalidValidationRequestSignature);
        }

        let hash_signed_val_req =
            hash_borsh(&*hash.hasher(), &signed_validation_req).map_err(
                |e| SubjectError::ValidationRequestHashFailed {
                    details: e.to_string(),
                },
            )?;

        if hash_signed_val_req != validation.validation_req_hash {
            return Err(SubjectError::ValidationRequestHashMismatch);
        }

        if metadata != &subject_metadata {
            return Err(SubjectError::MetadataMismatch);
        }

        if let SchemaType::Governance = metadata.schema_id {
            serde_json::from_value::<GovernanceData>(
                metadata.properties.0.clone(),
            )
            .map_err(|e| {
                SubjectError::GovernancePropertiesConversionFailed {
                    details: e.to_string(),
                }
            })?;
        }

        let validation_res = ValidationRes::Create {
            vali_req_hash: hash_signed_val_req,
            subject_metadata,
        };

        let role_data = match metadata.schema_id {
            SchemaType::Governance => RoleDataRegister {
                workers: HashSet::from([metadata.owner.clone()]),
                quorum: Quorum::Majority,
            },
            SchemaType::Type(_) => get_validation_roles_register(
                ctx,
                &metadata.governance_id,
                SearchRole {
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                },
                ledger_event.content().gov_version,
            )
            .await
            .map_err(|e| {
                SubjectError::ValidatorsRetrievalFailed {
                    details: e.to_string(),
                }
            })?,
            SchemaType::AllSchemas => {
                return Err(SubjectError::InvalidSchemaId);
            }
        };

        if !check_quorum_signers(
            &validation
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &role_data.quorum,
            &role_data.workers,
        ) {
            return Err(SubjectError::InvalidQuorum);
        }

        for signature in validation.validators_signatures.iter() {
            let signed_res =
                Signed::from_parts(validation_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(SubjectError::InvalidValidatorSignature);
            }
        }

        Ok(())
    }

    async fn register(
        ctx: &mut ActorContext<Self>,
        message: RegisterMessage,
    ) -> Result<(), ActorError> {
        let register_path = ActorPath::from("/user/node/register");
        match ctx.system().get_actor::<Register>(&register_path).await {
            Ok(register) => {
                register.tell(message).await?;

                debug!("Register message sent successfully");
            }
            Err(e) => {
                error!(
                    path = %register_path,
                    "Register actor not found"
                );
                return Err(e);
            }
        };

        Ok(())
    }

    async fn event_to_sink(
        ctx: &mut ActorContext<Self>,
        data: DataForSink,
        event: &EventRequest,
    ) -> Result<(), ActorError> {
        let event = match event {
            EventRequest::Create(..) => DataToSinkEvent::Create {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                owner: data.owner,
                schema_id: data.schema_id,
                namespace: data.namespace.to_string(),
                sn: data.sn,
            },
            EventRequest::Fact(fact_request) => DataToSinkEvent::Fact {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                issuer: data.issuer.to_string(),
                owner: data.owner,
                payload: fact_request.payload.0.clone(),
                schema_id: data.schema_id,
                sn: data.sn,
            },
            EventRequest::Transfer(transfer_request) => {
                DataToSinkEvent::Transfer {
                    governance_id: data.gov_id,
                    subject_id: data.subject_id,
                    owner: data.owner,
                    new_owner: transfer_request.new_owner.to_string(),
                    schema_id: data.schema_id,
                    sn: data.sn,
                }
            }
            EventRequest::Confirm(..) => DataToSinkEvent::Confirm {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
            },
            EventRequest::Reject(..) => DataToSinkEvent::Reject {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
            },
            EventRequest::EOL(..) => DataToSinkEvent::EOL {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
            },
        };

        let msg = SinkDataMessage::Event {
            event,
            event_request_timestamp: data.event_request_timestamp,
            event_ledger_timestamp: data.event_ledger_timestamp,
        };

        Self::publish_sink(ctx, msg).await
    }

    async fn publish_sink(
        ctx: &mut ActorContext<Self>,
        message: SinkDataMessage,
    ) -> Result<(), ActorError> {
        let sink_data = ctx.get_child::<SinkData>("sink_data").await?;

        sink_data.tell(message).await?;
        debug!("Message published to sink successfully");

        Ok(())
    }

    async fn get_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
        lo_sn: Option<u64>,
        hi_sn: u64,
    ) -> Result<(Vec<<Self as Actor>::Event>, bool), ActorError> {
        if let Some(lo_sn) = lo_sn {
            let actual_sn = lo_sn + 1;
            if (hi_sn - actual_sn) > 99 {
                Ok((get_n_events(ctx, lo_sn + 1, 99).await?, false))
            } else {
                Ok((get_n_events(ctx, actual_sn, hi_sn).await?, true))
            }
        } else {
            if hi_sn > 99 {
                Ok((get_n_events(ctx, 0, 99).await?, false))
            } else {
                Ok((get_n_events(ctx, 0, hi_sn).await?, true))
            }
        }
    }

    async fn update_sn(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError>;

    async fn reject(
        &self,
        ctx: &mut ActorContext<Self>,
        gov_version: u64,
    ) -> Result<(), ActorError>;

    async fn confirm(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), ActorError>;

    async fn transfer(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), ActorError>;

    fn apply_patch(
        &mut self,
        json_patch: ValueWrapper,
    ) -> Result<(), ActorError>;

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError>;

    async fn get_last_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Option<SignedLedger>, ActorError>;
}

#[cfg(test)]
mod tests {

    use std::{collections::HashSet, time::Instant, vec};

    use super::*;

    use crate::{
        FactRequest,
        governance::{
            GovernanceMessage, GovernanceResponse, data::GovernanceData,
        },
        model::{
            event::Event as AveEvent, request::tests::create_start_request_mock,
        },
        node::NodeResponse,
        subject::laststate::{LastState, LastStateMessage, LastStateResponse},
        system::tests::create_system,
        validation::proof::EventProof,
    };

    async fn create_subject_and_ledger_event(
        system: SystemRef,
        node_keys: KeyPair,
    ) -> (ActorRef<Governance>, Signed<Ledger>) {
        let node_actor = system
            .create_root_actor("node", Node::initial(node_keys.clone()))
            .await
            .unwrap();

        let request = create_start_request_mock("issuer", node_keys.clone());
        let event = AveEvent::from_create_request(
            &request,
            0,
            &GovernanceData::new(node_keys.public_key()).to_value_wrapper(),
        )
        .unwrap();
        let ledger = Ledger::from(event.clone());
        let signature_ledger =
            Signature::new(&ledger, &node_keys.clone()).unwrap();
        let signed_ledger = Signed::from_parts(ledger, signature);

        let signature_event = Signature::new(&event, &node_keys).unwrap();

        let signed_event = Signed::from_parts(event, signature_event);

        let response = node_actor
            .ask(NodeMessage::CreateNewSubjectLedger(SignedLedger(
                signed_ledger.clone(),
            )))
            .await
            .unwrap();

        let NodeResponse::SonWasCreated = response else {
            panic!("Invalid response");
        };

        let subject_actor = system
            .get_actor(&ActorPath::from(format!(
                "user/node/{}",
                signed_ledger.content().subject_id
            )))
            .await
            .unwrap();

        let last_state_actor: ActorRef<LastState> = system
            .get_actor(&ActorPath::from(format!(
                "user/node/{}/last_state",
                signed_ledger.content().subject_id
            )))
            .await
            .unwrap();

        let empty_proof = ValidationProof {
            subject_id: DigestIdentifier::default(),
            schema_id: SchemaType::default(),
            namespace: Namespace::new(),
            governance_id: DigestIdentifier::default(),
            genesis_governance_version: 0,
            sn: 0,
            prev_event_hash: DigestIdentifier::default(),
            event_hash: DigestIdentifier::default(),
            governance_version: 0,
            owner: node_keys.public_key(),
            new_owner: None,
            active: true,
            event: EventProof::Create,
        };
        let response = last_state_actor
            .ask(LastStateMessage::UpdateLastState {
                proof: Box::new(empty_proof),
                event: Box::new(signed_event),
                vali_res: vec![],
            })
            .await
            .unwrap();

        if let LastStateResponse::Ok = response {
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(GovernanceMessage::UpdateLedger {
                events: vec![SignedLedger(signed_ledger.clone())],
            })
            .await
            .unwrap();

        if let GovernanceResponse::UpdateResult(last_sn, _, _) = response {
            assert_eq!(last_sn, 0);
        } else {
            panic!("Invalid response");
        }

        (subject_actor, signed_ledger)
    }

    fn create_n_fact_events(
        mut hash_prev_event: DigestIdentifier,
        n: u64,
        keys: KeyPair,
        subject_id: DigestIdentifier,
        mut subject_properties: Value,
    ) -> Vec<SignedLedger> {
        let mut vec = vec![];

        for i in 0..n {
            let key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                .public_key()
                .to_string();

            let name = format!("AveNode{}", i);
            let event_req_payload = json!({
                "members": {
                    "add": [
                        {
                            "name": name,
                            "key": key
                        }
                    ]
                }
            });

            let event_req = EventRequest::Fact(FactRequest {
                subject_id: subject_id.clone(),
                payload: ValueWrapper(event_req_payload.clone()),
            });

            let signature_event_req =
                Signature::new(&event_req, &keys).unwrap();

            let signed_event_req = Signed {
                content: event_req,
                signature: signature_event_req,
            };

            let patch_event_req = json!(
                    [{"op":"add","path": format!("/members/AveNode{}", i),"value": key},
                    {
                        "op": "add",
                        "path": "/version",
                        "value": i
                    }]
            );

            let patch_json =
                serde_json::from_value::<Patch>(patch_event_req.clone())
                    .unwrap();
            patch(&mut subject_properties, &patch_json).unwrap();

            let state_hash = hash_borsh(
                &Blake3Hasher,
                &ValueWrapper(subject_properties.clone()),
            )
            .unwrap();

            let ledger = Ledger {
                subject_id: subject_id.clone(),
                event_request: signed_event_req,
                sn: i + 1,
                gov_version: i,
                value: LedgerValue::Patch(ValueWrapper(patch_event_req)),
                state_hash,
                eval_success: Some(true),
                appr_required: true,
                appr_success: Some(true),
                vali_success: true,
                hash_prev_event: hash_prev_event.clone(),
            };

            let signature_ledger = Signature::new(&ledger, &keys).unwrap();

            let signed_ledger = Signed {
                content: ledger,
                signature: signature_ledger,
            };

            hash_prev_event =
                hash_borsh(&Blake3Hasher, &signed_ledger).unwrap();
            vec.push(SignedLedger(signed_ledger));
        }

        vec
    }

    impl AveEvent {
        pub fn from_create_request(
            request: &Signed<EventRequest>,
            governance_version: u64,
            init_state: &ValueWrapper,
        ) -> Result<Self, Error> {
            let EventRequest::Create(_start_request) = &request.content else {
                panic!("Invalid Event Request")
            };

            let state_hash = hash_borsh(&Blake3Hasher, init_state).unwrap();
            let subject_id = hash_borsh(&Blake3Hasher, request).unwrap();

            Ok(AveEvent {
                subject_id,
                event_request: request.clone(),
                sn: 0,
                gov_version: governance_version,
                value: LedgerValue::Patch(init_state.clone()),
                state_hash,
                eval_success: None,
                appr_required: false,
                hash_prev_event: DigestIdentifier::default(),
                evaluators: None,
                approvers: None,
                appr_success: None,
                vali_success: true,
                validators: HashSet::new(),
            })
        }
    }

    use ave_actors::SystemRef;
    use ave_common::identity::{
        Blake3Hasher, KeyPair, KeyPairAlgorithm, Signature, keys::Ed25519Signer,
    };
    use serde_json::{Value, json};
    use test_log::test;

    #[test]
    fn test_serialize_deserialize() {
        let node_keys = KeyPair::generate(KeyPairAlgorithm::Ed25519).unwrap();

        let value =
            GovernanceData::new(node_keys.public_key()).to_value_wrapper();

        let request = create_start_request_mock("issuer", node_keys.clone());
        let event = AveEvent::from_create_request(&request, 0, &value).unwrap();

        let ledger = Ledger::from(event);

        let signature = Signature::new(&ledger, &node_keys).unwrap();
        let signed_ledger = Signed {
            content: ledger,
            signature,
        };

        let subject_a = Governance::from_create_event(&signed_ledger).unwrap();

        let bytes = borsh::to_vec(&subject_a).unwrap();
        let subject_b: Governance = borsh::from_slice(&bytes).unwrap();
        assert_eq!(
            subject_a.0.subject_id,
            subject_b.subject_metadata.subject_id
        );
    }

    #[test(tokio::test)]
    async fn test_get_events() {
        let (system, .., _dir) = create_system().await;
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

        let (subject_actor, _signed_ledger) =
            create_subject_and_ledger_event(system, node_keys.clone()).await;

        let response = subject_actor
            .ask(GovernanceMessage::GetLedger { last_sn: 0 })
            .await
            .unwrap();
        if let GovernanceResponse::Ledger { ledger, last_state } = response {
            assert!(ledger.len() == 1);
            last_state.unwrap();
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap();

        if let GovernanceResponse::Metadata(metadata) = response {
            assert_eq!(metadata.sn, 0);
        } else {
            panic!("Invalid response");
        }
    }

    #[test(tokio::test)]
    async fn test_1000_events() {
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let (system, .., _dirs) = create_system().await;

        let (subject_actor, signed_ledger) =
            create_subject_and_ledger_event(system, node_keys.clone()).await;

        let res = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap();
        let GovernanceResponse::Metadata(metadata) = res else {
            panic!("Invalid response")
        };

        let hash_pre_event = hash_borsh(&Blake3Hasher, &signed_ledger).unwrap();

        let inicio = Instant::now();
        let response = subject_actor
            .ask(GovernanceMessage::UpdateLedger {
                events: create_n_fact_events(
                    hash_pre_event,
                    1000,
                    node_keys,
                    metadata.subject_id,
                    metadata.properties.0,
                ),
            })
            .await
            .unwrap();
        let duracion = inicio.elapsed();
        println!("El método tardó: {:.2?}", duracion);

        if let GovernanceResponse::UpdateResult(last_sn, _, _) = response {
            assert_eq!(last_sn, 1000);
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap();

        if let GovernanceResponse::Metadata(metadata) = response {
            assert_eq!(metadata.sn, 1000);
        } else {
            panic!("Invalid response");
        }

        let response = subject_actor
            .ask(GovernanceMessage::GetGovernance)
            .await
            .unwrap();

        if let GovernanceResponse::Governance(gov) = response {
            assert_eq!(gov.version, 1000);
        } else {
            panic!("Invalid response");
        }
    }
}
