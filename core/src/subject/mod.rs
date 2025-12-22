//! # Subject module.
//!

use crate::{
    CreateRequest, Error, EventRequestType, Node,
    governance::Governance,
    model::{
        Namespace,
        event::{Event as AveEvent, Ledger, LedgerValue, ProtocolsSignatures},
        request::{EventRequest, SchemaType},
    },
    node::{
        NodeMessage, TransferSubject,
        register::{Register, RegisterMessage},
        transfer::{TransferRegister, TransferRegisterMessage},
    },
    tracker::Tracker,
    validation::proof::ValidationProof,
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Event,
    PersistentActor,
};
use ave_common::{
    ValueWrapper,
    identity::{DigestIdentifier, PublicKey, Signed, hash_borsh},
};

use std::ops::Deref;

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use sinkdata::{SinkData, SinkDataMessage};

pub mod laststate;
pub mod sinkdata;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LastStateData {
    pub event: Box<Signed<AveEvent>>,
    pub proof: Box<ValidationProof>,
    pub vali_res: Vec<ProtocolsSignatures>,
}

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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CreateSubjectData {
    pub create_req: CreateRequest,
    pub subject_id: DigestIdentifier,
    pub creator: PublicKey,
    pub genesis_gov_version: u64,
    pub value: ValueWrapper,
}

/// Subject metadata.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub struct Metadata {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The identifier of the subject of the event.
    pub subject_id: DigestIdentifier,
    /// The identifier of the governance contract.
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub last_event_hash: DigestIdentifier,
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
            subject_id: value.subject_metadata.subject_id,
            governance_id: DigestIdentifier::default(),
            genesis_gov_version: 0,
            last_event_hash: value.subject_metadata.last_event_hash,
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
            last_event_hash: value.subject_metadata.last_event_hash,
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
}

pub struct VerifyData {
    pub active: bool,
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    pub is_gov: bool,
    pub properties: ValueWrapper,
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

    pub last_event_hash: DigestIdentifier,
    /// The identifier of the public key of the subject creator.
    pub creator: PublicKey,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current sequence number of the subject.
    pub sn: u64,
}

impl SubjectMetadata {
    pub fn new(data: &CreateSubjectData) -> Self {
        Self {
            name: data.create_req.name.clone(),
            description: data.create_req.description.clone(),
            subject_id: data.subject_id.clone(),
            owner: data.creator.clone(),
            schema_id: data.create_req.schema_id.clone(),
            new_owner: None,
            last_event_hash: DigestIdentifier::default(),
            creator: data.creator.clone(),
            active: true,
            sn: 0,
        }
    }
    pub fn from_create_request(
        subject_id: DigestIdentifier,
        request: &CreateRequest,
        owner: PublicKey,
        last_event_hash: DigestIdentifier
    ) -> Self {
        Self {
            name: request.name.clone(),
            description: request.description.clone(),
            subject_id: subject_id,
            owner: owner.clone(),
            schema_id: request.schema_id.clone(),
            new_owner: None,
            last_event_hash,
            creator: owner.clone(),
            active: true,
            sn: 0,
        }
    }
}

#[async_trait]
pub trait Subject
where
    <Self as Actor>::Event: BorshSerialize + BorshDeserialize,
    Self: PersistentActor,
{
    fn verify_protocols_state(
        request: EventRequestType,
        eval: Option<bool>,
        approve: Option<bool>,
        approval_require: bool,
        val: bool,
        is_gov: bool,
    ) -> Result<bool, Error> {
        match request {
            EventRequestType::Create
            | EventRequestType::EOL
            | EventRequestType::Reject => {
                if approve.is_some() || eval.is_some() || approval_require {
                    return Err(Error::Protocols("In create, reject and eol request, approve and eval must be None and approval require must be false".to_owned()));
                }
                Ok(val)
            }
            EventRequestType::Transfer => {
                let Some(eval) = eval else {
                    return Err(Error::Protocols(
                        "In Transfer even eval must be Some".to_owned(),
                    ));
                };

                if approve.is_some() || approval_require {
                    return Err(Error::Protocols("In transfer request, approve must be None and approval require must be false".to_owned()));
                }

                Ok(val && eval)
            }
            EventRequestType::Fact => {
                let Some(eval) = eval else {
                    return Err(Error::Protocols(
                        "In fact request eval must be Some".to_owned(),
                    ));
                };

                if !is_gov {
                    if approve.is_some() || approval_require {
                        return Err(Error::Protocols("In fact request (not governace subject), approve must be None and approval require must be false".to_owned()));
                    }

                    Ok(val && eval)
                } else if eval {
                    if !approval_require {
                        return Err(Error::Protocols("In fact request (governace subject), if eval is success approval require must be true".to_owned()));
                    }
                    let Some(approve) = approve else {
                        return Err(Error::Protocols("In fact request if approval was required, approve must be Some".to_owned()));
                    };
                    Ok(eval && approve && val)
                } else {
                    if approval_require {
                        return Err(Error::Protocols("In fact request (governace subject), if eval is not success approval require must be false".to_owned()));
                    }

                    if approve.is_some() {
                        return Err(Error::Protocols("In fact request if approval was not required, approve must be None".to_owned()));
                    }

                    Ok(eval && val)
                }
            }
            EventRequestType::Confirm => {
                if !is_gov {
                    if approve.is_some() || eval.is_some() || approval_require {
                        return Err(Error::Protocols("In confirm request (not governance subject), approve and eval must be None and approval require must be false".to_owned()));
                    }
                    Ok(val)
                } else {
                    let Some(eval) = eval else {
                        return Err(Error::Protocols(
                        "In confirm request (governace subject) eval must be Some".to_owned(),
                    ));
                    };

                    if approve.is_some() || approval_require {
                        return Err(Error::Protocols("In confirm request (governace subject), approve must be None and approval require must be false".to_owned()));
                    }

                    Ok(val && eval)
                }
            }
        }
    }

    async fn change_node_subject(
        ctx: &mut ActorContext<Self>,
        subject_id: &str,
        new_owner: &str,
        old_owner: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .ask(NodeMessage::ChangeSubjectOwner {
                    new_owner: new_owner.to_owned(),
                    old_owner: old_owner.to_owned(),
                    subject_id: subject_id.to_owned(),
                })
                .await?;
        } else {
            return Err(ActorError::NotFound(node_path));
        }

        Ok(())
    }

    async fn new_transfer_subject(
        ctx: &mut ActorContext<Self>,
        name: Option<String>,
        subject_id: &str,
        new_owner: &str,
        actual_owner: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .tell(NodeMessage::TransferSubject(TransferSubject {
                    name: name.unwrap_or_default(),
                    subject_id: subject_id.to_owned(),
                    new_owner: new_owner.to_owned(),
                    actual_owner: actual_owner.to_owned(),
                }))
                .await?;
        } else {
            return Err(ActorError::NotFound(node_path));
        }
        Ok(())
    }

    async fn reject_transfer_subject(
        ctx: &mut ActorContext<Self>,
        subject_id: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .tell(NodeMessage::RejectTransfer(subject_id.to_owned()))
                .await?;
        } else {
            return Err(ActorError::NotFound(node_path));
        }
        Ok(())
    }

    async fn verify_new_ledger_event(
        verify_data: VerifyData,
        last_ledger: &Signed<Ledger>,
        new_ledger: &Signed<Ledger>,
    ) -> Result<bool, Error> {
        // Si no sigue activo
        if !verify_data.active {
            return Err(Error::Subject("Subject is not active".to_owned()));
        }

        if !new_ledger
            .content
            .event_request
            .content
            .check_ledger_signature(
                &new_ledger.signature.signer,
                &verify_data.owner,
                &verify_data.new_owner,
            )?
        {
            return Err(Error::Subject("Invalid ledger signer".to_owned()));
        }

        if !new_ledger
            .content
            .event_request
            .content
            .check_ledger_signature(
                &new_ledger.content.event_request.signature.signer,
                &verify_data.owner,
                &verify_data.new_owner,
            )?
        {
            return Err(Error::Subject("Invalid event signer".to_owned()));
        }

        if let Err(e) = new_ledger.verify() {
            return Err(Error::Subject(format!(
                "In new event, event signature: {}",
                e
            )));
        }

        if let Err(e) = new_ledger.content.event_request.verify() {
            return Err(Error::Subject(format!(
                "In new event request, request signature: {}",
                e
            )));
        }

        // Mirar que sea el siguiente sn
        if last_ledger.content.sn + 1 != new_ledger.content.sn {
            return Err(Error::Sn);
        }

        //Comprobar que el hash del actual event sea el mismo que el pre_event_hash,
        let last_ledger_hash = hash_borsh(
            &*new_ledger.content.hash_prev_event.algorithm().hasher(),
            last_ledger,
        )
        .map_err(|e| {
            Error::Subject(format!(
                "Can not obtain previous event hash : {}",
                e
            ))
        })?;

        if last_ledger_hash != new_ledger.content.hash_prev_event {
            return Err(Error::Subject("Last event hash is not the same that previous event hash in new event".to_owned()));
        }

        let valid_last_event = Self::verify_protocols_state(
            EventRequestType::from(&last_ledger.content.event_request.content),
            last_ledger.content.eval_success,
            last_ledger.content.appr_success,
            last_ledger.content.appr_required,
            last_ledger.content.vali_success,
            verify_data.is_gov,
        )?;

        if valid_last_event
            && let EventRequest::EOL(..) =
                last_ledger.content.event_request.content.clone()
        {
            return Err(Error::Subject(
                "The last event was EOL, no more events can be received"
                    .to_owned(),
            ));
        }

        let valid_new_event = Self::verify_protocols_state(
            EventRequestType::from(&new_ledger.content.event_request.content),
            new_ledger.content.eval_success,
            new_ledger.content.appr_success,
            new_ledger.content.appr_required,
            new_ledger.content.vali_success,
            verify_data.is_gov,
        )?;

        // Si el nuevo evento a registrar fue correcto.
        if valid_new_event {
            match &new_ledger.content.event_request.content {
                EventRequest::Create(_start_request) => {
                    return Err(Error::Subject("A creation event is being logged when the subject has already been created previously".to_owned()));
                }
                EventRequest::Fact(_fact_request) => {
                    if verify_data.new_owner.is_some() {
                        return Err(Error::Subject("After a transfer event there must be a confirmation or a reject event.".to_owned()));
                    }

                    Self::check_patch(
                        verify_data.properties.clone(),
                        &new_ledger.content.value,
                        &new_ledger.content.state_hash,
                    )?;
                }
                EventRequest::Transfer(..) => {
                    if verify_data.new_owner.is_some() {
                        return Err(Error::Subject("After a transfer event there must be a confirmation or a reject event.".to_owned()));
                    }
                    let hash_without_patch = hash_borsh(
                        &*new_ledger.content.state_hash.algorithm().hasher(),
                        &verify_data.properties,
                    )
                    .map_err(|e| {
                        Error::Subject(format!(
                            "Can not obtain state hash : {}",
                            e
                        ))
                    })?;

                    if hash_without_patch != new_ledger.content.state_hash {
                        return Err(Error::Subject("In Transfer event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                    }
                }
                EventRequest::Confirm(..) => {
                    if verify_data.new_owner.is_none() {
                        return Err(Error::Subject("Before a confirm event there must be a transfer event.".to_owned()));
                    }

                    if verify_data.is_gov {
                        Self::check_patch(
                            verify_data.properties.clone(),
                            &new_ledger.content.value,
                            &new_ledger.content.state_hash,
                        )?;
                    } else {
                        let hash_without_patch = hash_borsh(
                            &*new_ledger
                                .content
                                .state_hash
                                .algorithm()
                                .hasher(),
                            &verify_data.properties,
                        )
                        .map_err(|e| {
                            Error::Subject(format!(
                                "Can not obtain state hash : {}",
                                e
                            ))
                        })?;

                        if hash_without_patch != new_ledger.content.state_hash {
                            return Err(Error::Subject("In Confirm event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                        }
                    }
                }
                EventRequest::Reject(..) => {
                    if verify_data.new_owner.is_none() {
                        return Err(Error::Subject("Before a reject event there must be a transfer event.".to_owned()));
                    }

                    let hash_without_patch = hash_borsh(
                        &*new_ledger.content.state_hash.algorithm().hasher(),
                        &verify_data.properties,
                    )
                    .map_err(|e| {
                        Error::Subject(format!(
                            "Can not obtain state hash : {}",
                            e
                        ))
                    })?;

                    if hash_without_patch != new_ledger.content.state_hash {
                        return Err(Error::Subject("In Reject event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                    }
                }
                EventRequest::EOL(..) => {
                    if verify_data.new_owner.is_some() {
                        return Err(Error::Subject("After a transfer event there must be a confirmation or a reject event.".to_owned()));
                    }

                    let hash_without_patch = hash_borsh(
                        &*new_ledger.content.state_hash.algorithm().hasher(),
                        &verify_data.properties,
                    )
                    .map_err(|e| {
                        Error::Subject(format!(
                            "Can not obtain state hash : {}",
                            e
                        ))
                    })?;

                    if hash_without_patch != new_ledger.content.state_hash {
                        return Err(Error::Subject("In EOL event, the hash obtained without applying any patch is different from the state hash of the event".to_owned()));
                    }
                }
            };
        } else {
            let hash_without_patch = hash_borsh(
                &*new_ledger.content.state_hash.algorithm().hasher(),
                &verify_data.properties,
            )
            .map_err(|e| {
                Error::Subject(format!("Can not obtain state hash : {}", e))
            })?;

            if hash_without_patch != new_ledger.content.state_hash {
                return Err(Error::Subject("The hash obtained without applying any patch is different from the state hash of the event".to_owned()));
            }
        }
        Ok(valid_new_event)
    }

    async fn verify_first_ledger_event(
        owner: PublicKey,
        event: &SignedLedger,
    ) -> Result<(), Error> {
        let is_gov = if let EventRequest::Create(event_req) =
            event.content.event_request.content.clone()
        {
            if let Some(name) = event_req.name
                && (name.is_empty() || name.len() > 100)
            {
                return Err(Error::Subject("The subject name must be less than 100 characters or not be empty.".to_owned()));
            }

            if let Some(description) = event_req.description
                && (description.is_empty() || description.len() > 200)
            {
                return Err(Error::Subject("The subject description must be less than 200 characters or not be empty.".to_owned()));
            }

            if event_req.schema_id.is_gov()
                && (!event_req.governance_id.is_empty()
                    || !event_req.namespace.is_empty()
                        && event.content.gov_version != 0)
            {
                return Err(Error::Subject("In create event, governance_id must be empty, namespace must be empty and gov version must be 0".to_owned()));
            }

            event_req.schema_id.is_gov()
        } else {
            return Err(Error::Subject(
                "First event is not a create event".to_owned(),
            ));
        };

        if event.signature.signer != owner
            || event.content.event_request.signature.signer != owner
        {
            return Err(Error::Subject(
                "In create event, owner must sign request and event."
                    .to_owned(),
            ));
        }

        if let Err(e) = event.verify() {
            return Err(Error::Subject(format!(
                "In create event, event signature: {}",
                e
            )));
        }

        if let Err(e) = event.content.event_request.verify() {
            return Err(Error::Subject(format!(
                "In create event, request signature: {}",
                e
            )));
        }

        if event.content.sn != 0 {
            return Err(Error::Subject(
                "In create event, sn must be 0.".to_owned(),
            ));
        }

        if !event.content.hash_prev_event.is_empty() {
            return Err(Error::Subject(
                "In create event, previous hash event must be empty."
                    .to_owned(),
            ));
        }

        if Self::verify_protocols_state(
            EventRequestType::Create,
            event.content.eval_success,
            event.content.appr_success,
            event.content.appr_required,
            event.content.vali_success,
            is_gov,
        )? {
            Ok(())
        } else {
            Err(Error::Subject(
                "Create event fail in validation protocol".to_owned(),
            ))
        }
    }

    async fn register(
        ctx: &mut ActorContext<Self>,
        message: RegisterMessage,
    ) -> Result<(), ActorError> {
        let register_path = ActorPath::from("/user/node/register");
        let register: Option<ActorRef<Register>> =
            ctx.system().get_actor(&register_path).await;
        if let Some(register) = register {
            /*
                        let message = if self.governance_id.is_empty() {
                RegisterMessage::RegisterGov {
                    gov_id: self.subject_id.to_string(),
                    data: RegisterDataGov {
                        active,
                        name: self.name.clone(),
                        description: self.description.clone(),
                    },
                }
            } else {
                RegisterMessage::RegisterSubj {
                    gov_id: self.governance_id.to_string(),
                    data: RegisterDataSubj {
                        subject_id: self.subject_id.to_string(),
                        schema_id: self.schema_id.clone(),
                        active,
                        name: self.name.clone(),
                        description: self.description.clone(),
                    },
                }
            };
             */

            register.tell(message).await?;
        } else {
            return Err(ActorError::NotFound(register_path));
        }

        Ok(())
    }

    async fn event_to_sink(
        ctx: &mut ActorContext<Self>,
        data: DataForSink,
        event: &EventRequest,
    ) -> Result<(), ActorError> {
        let event_to_sink = match event {
            EventRequest::Create(..) => SinkDataMessage::Create {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                owner: data.owner,
                schema_id: data.schema_id,
                namespace: data.namespace.to_string(),
                sn: data.sn,
            },
            EventRequest::Fact(fact_request) => SinkDataMessage::Fact {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                issuer: data.issuer.to_string(),
                owner: data.owner,
                payload: fact_request.payload.0.clone(),
                schema_id: data.schema_id,
                sn: data.sn,
            },
            EventRequest::Transfer(transfer_request) => {
                SinkDataMessage::Transfer {
                    governance_id: data.gov_id,
                    subject_id: data.subject_id,
                    owner: data.owner,
                    new_owner: transfer_request.new_owner.to_string(),
                    schema_id: data.schema_id,
                    sn: data.sn,
                }
            }
            EventRequest::Confirm(..) => SinkDataMessage::Confirm {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
            },
            EventRequest::Reject(..) => SinkDataMessage::Reject {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
            },
            EventRequest::EOL(..) => SinkDataMessage::EOL {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
            },
        };

        Self::publish_sink(ctx, event_to_sink).await
    }

    async fn delet_node_subject(
        ctx: &mut ActorContext<Self>,
        subject_id: &str,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        // We obtain the validator
        let Some(node_actor) = node_actor else {
            return Err(ActorError::NotFound(node_path));
        };
        node_actor
            .tell(NodeMessage::DeleteSubject(subject_id.to_owned()))
            .await
    }

    async fn transfer_register(
        ctx: &mut ActorContext<Self>,
        subject_id: &str,
        new: PublicKey,
        old: PublicKey,
    ) -> Result<(), ActorError> {
        let tranfer_register_path =
            ActorPath::from("/user/node/transfer_register");
        let transfer_register_actor: Option<
            ave_actors::ActorRef<TransferRegister>,
        > = ctx.system().get_actor(&tranfer_register_path).await;

        let Some(transfer_register_actor) = transfer_register_actor else {
            return Err(ActorError::NotFound(tranfer_register_path));
        };

        transfer_register_actor
            .tell(TransferRegisterMessage::RegisterNewOldOwner {
                old,
                new,
                subject_id: subject_id.to_owned(),
            })
            .await?;

        Ok(())
    }


    async fn publish_sink(
        ctx: &mut ActorContext<Self>,
        message: SinkDataMessage,
    ) -> Result<(), ActorError> {
        let sink_data: Option<ActorRef<SinkData>> =
            ctx.get_child("sink_data").await;
        if let Some(sink_data) = sink_data {
            sink_data.tell(message).await
        } else {
            Err(ActorError::NotFound(ActorPath::from(format!(
                "{}/sink_data",
                ctx.path()
            ))))
        }
    }

    async fn update_subject_node(
        ctx: &mut ActorContext<Self>,
        subject_id: &str,
        sn: u64,
    ) -> Result<(), ActorError> {
        let node_path = ActorPath::from("/user/node");
        let node_actor: Option<ActorRef<Node>> =
            ctx.system().get_actor(&node_path).await;

        if let Some(node_actor) = node_actor {
            node_actor
                .tell(NodeMessage::UpdateSubject {
                    subject_id: subject_id.to_owned(),
                    sn,
                })
                .await
        } else {
            Err(ActorError::NotFound(node_path))
        }
    }

    fn check_patch(
        mut properties: ValueWrapper,
        value: &LedgerValue,
        state_hash: &DigestIdentifier,
    ) -> Result<(), Error> {
        let LedgerValue::Patch(json_patch) = value else {
            return Err(Error::Subject("The event was successful but does not have a json patch to apply".to_owned()));
        };

        let patch_json = serde_json::from_value::<Patch>(json_patch.0.clone())
            .map_err(|e| {
                Error::Subject(format!("Failed to extract event patch: {}", e))
            })?;
        let Ok(()) = patch(&mut properties.0, &patch_json) else {
            return Err(Error::Subject(
                "Failed to apply event patch".to_owned(),
            ));
        };

        let hash_state_after_patch =
            hash_borsh(&*state_hash.algorithm().hasher(), &properties)
                .map_err(|e| {
                    Error::Subject(format!(
                        "Can not obtain previous event hash : {}",
                        e
                    ))
                })?;

        if hash_state_after_patch != *state_hash {
            return Err(Error::Subject("The new patch has been applied and we have obtained a different hash than the event after applying the patch".to_owned()));
        }
        Ok(())
    }

    async fn delete_subject(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError>;

    fn apply_patch(&mut self, value: LedgerValue) -> Result<(), ActorError>;

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<SignedLedger>,
    ) -> Result<(), ActorError>;

    async fn get_ledger_data(
        &self,
        ctx: &mut ActorContext<Self>,
        last_sn: u64,
    ) -> Result<(Vec<SignedLedger>, Option<LastStateData>), ActorError>;
}

#[cfg(test)]
mod tests {

    use std::{collections::HashSet, time::Instant, vec};

    use super::*;

    use crate::{
        FactRequest, governance::{GovernanceMessage, GovernanceResponse, data::GovernanceData}, model::{
            event::Event as AveEvent, request::tests::create_start_request_mock,
        }, node::NodeResponse, subject::laststate::{LastState, LastStateMessage, LastStateResponse}, system::tests::create_system, validation::proof::EventProof
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
            &GovernanceData::new(node_keys.public_key())
                .to_value_wrapper(),
        )
        .unwrap();
        let ledger = Ledger::from(event.clone());
        let signature_ledger =
            Signature::new(&ledger, &node_keys.clone()).unwrap();
        let signed_ledger = Signed {
            content: ledger,
            signature: signature_ledger,
        };

        let signature_event = Signature::new(&event, &node_keys).unwrap();

        let signed_event = Signed {
            content: event,
            signature: signature_event,
        };

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
                signed_ledger.content.subject_id
            )))
            .await
            .unwrap();

        let last_state_actor: ActorRef<LastState> = system
            .get_actor(&ActorPath::from(format!(
                "user/node/{}/last_state",
                signed_ledger.content.subject_id
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
            let patch_event_req = json!(
                    [{"op":"add","path": format!("/members/AveNode{}", i),"value": key},
                    {
                        "op": "add",
                        "path": "/version",
                        "value": i
                    }]
            );

            let event_req = EventRequest::Fact(FactRequest {
                subject_id: subject_id.clone(),
                payload: ValueWrapper(patch_event_req.clone()),
            });

            let signature_event_req =
                Signature::new(&event_req, &keys).unwrap();

            let signed_event_req = Signed {
                content: event_req,
                signature: signature_event_req,
            };

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

        let value = GovernanceData::new(node_keys.public_key())
            .to_value_wrapper();

        let request = create_start_request_mock("issuer", node_keys.clone());
        let event = AveEvent::from_create_request(&request, 0, &value).unwrap();

        let ledger = Ledger::from(event);

        let signature = Signature::new(&ledger, &node_keys).unwrap();
        let signed_ledger = Signed {
            content: ledger,
            signature,
        };

        let subject_a = Governance::from_create_event(
            &signed_ledger,
        )
        .unwrap();

        let bytes = borsh::to_vec(&subject_a).unwrap();
        let subject_b: Governance = borsh::from_slice(&bytes).unwrap();
        assert_eq!(subject_a.subject_metadata.subject_id, subject_b.subject_metadata.subject_id);
    }

    #[test(tokio::test)]
    async fn test_get_events() {
        let (system, ..) = create_system().await;
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
        let (system, ..) = create_system().await;

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