//! # Validation module.
//!
use crate::{
    governance::model::Quorum,
    helpers::network::service::NetworkSender,
    model::{
        common::{
            abort_req, emit_fail, send_reboot_to_req, take_random_signers,
        },
        event::{ValidationData, ValidationMetadata},
    },
    request::manager::{RebootType, RequestManager, RequestManagerMessage},
    validation::{
        coordinator::{ValiCoordinator, ValiCoordinatorMessage},
        response::ResponseSummary,
        worker::{ValiWorker, ValiWorkerMessage},
    },
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::{
    ValueWrapper,
    identity::{
        CryptoError, DigestIdentifier, HashAlgorithm, PublicKey, Signature,
        Signed, hash_borsh,
    },
};

use request::ValidationReq;
use response::ValidationRes;
use tracing::{Span, debug, error, info_span, warn};

use std::{collections::HashSet, sync::Arc};

pub mod coordinator;
pub mod request;
pub mod response;
pub mod schema;
pub mod worker;

#[derive(Clone, Debug)]
pub struct Validation {
    our_key: Arc<PublicKey>,
    // Quorum
    quorum: Quorum,
    // Actual responses
    validators_signatures: Vec<Signature>,

    validators_response: Vec<ValidationMetadata>,

    validators_quantity: u32,

    request: Signed<ValidationReq>,

    hash: HashAlgorithm,

    network: Arc<NetworkSender>,

    request_id: DigestIdentifier,

    version: u64,

    validation_request_hash: DigestIdentifier,

    reboot: bool,

    current_validators: HashSet<PublicKey>,

    pending_validators: HashSet<PublicKey>,

    init_state: Option<ValueWrapper>,
}

impl Validation {
    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<ValidationReq>,
        init_state: Option<ValueWrapper>,
        quorum: Quorum,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Validation {
            our_key,
            quorum,
            init_state,
            validators_response: vec![],
            validators_signatures: vec![],
            validators_quantity: 0,
            request,
            hash,
            network,
            request_id: DigestIdentifier::default(),
            version: 0,
            validation_request_hash: DigestIdentifier::default(),
            reboot: false,
            current_validators: HashSet::new(),
            pending_validators: HashSet::new(),
        }
    }

    fn check_validator(&mut self, validator: PublicKey) -> bool {
        self.current_validators.remove(&validator)
    }

    async fn create_validators(
        &self,
        ctx: &mut ActorContext<Validation>,
        signer: PublicKey,
    ) -> Result<(), ActorError> {
        if signer != *self.our_key {
            let child = ctx
                .create_child(
                    &format!("{}", signer),
                    ValiCoordinator::new(
                        signer.clone(),
                        self.request_id.to_string(),
                        self.version,
                        self.network.clone(),
                    ),
                )
                .await?;

            child
                .tell(ValiCoordinatorMessage::NetworkValidation {
                    validation_req: Box::new(self.request.clone()),
                    node_key: signer,
                })
                .await?
        } else {
            let child = ctx
                .create_child(
                    &format!("{}", signer),
                    ValiWorker {
                        node_key: (*self.our_key).clone(),
                        our_key: self.our_key.clone(),
                        init_state: self.init_state.clone(),
                        governance_id: self
                            .request
                            .content().get_governance_id().expect("The build process verified that the event request is valid")
                            ,
                        gov_version: self.request.content().get_gov_version(),
                        sn: self.request.content().get_sn(),
                        hash: self.hash,
                        network: self.network.clone(),
                        stop:true
                    },
                )
                .await?;

            child
                .tell(ValiWorkerMessage::LocalValidation {
                    validation_req: Box::new(self.request.clone()),
                })
                .await?
        }

        Ok(())
    }

    async fn send_validation_to_req(
        &self,
        ctx: &mut ActorContext<Validation>,
        response: ValidationData,
    ) -> Result<(), ActorError> {
        let req_actor = ctx.get_parent::<RequestManager>().await?;

        req_actor
            .tell(RequestManagerMessage::ValidationRes {
                request_id: self.request_id.clone(),
                val_req: Box::new(self.request.content().clone()),
                val_res: response,
            })
            .await?;

        Ok(())
    }

    fn create_vali_req_hash(&self) -> Result<DigestIdentifier, CryptoError> {
        hash_borsh(&*self.hash.hasher(), &self.request)
    }

    fn check_responses(&self) -> ResponseSummary {
        let res_set: HashSet<ValidationMetadata> =
            HashSet::from_iter(self.validators_response.iter().cloned());

        if res_set.len() == 1 {
            ResponseSummary::Ok
        } else {
            ResponseSummary::Reboot
        }
    }

    fn build_validation_data(&self) -> ValidationData {
        ValidationData {
            validation_req_signature: self.request.signature().clone(),
            validation_req_hash: self.validation_request_hash.clone(),
            validators_signatures: self.validators_signatures.clone(),
            validation_metadata: self.validators_response[0].clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValidationMessage {
    Create {
        request_id: DigestIdentifier,
        version: u64,
        signers: HashSet<PublicKey>,
    },
    Response {
        validation_res: Box<ValidationRes>,
        sender: PublicKey,
        signature: Option<Signature>,
    },
}

impl Message for ValidationMessage {}

impl NotPersistentActor for Validation {}

#[async_trait]
impl Actor for Validation {
    type Event = ();
    type Message = ValidationMessage;
    type Response = ();

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Validation")
        } else {
            info_span!("Validation")
        }
    }
}

#[async_trait]
impl Handler<Validation> for Validation {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ValidationMessage,
        ctx: &mut ActorContext<Validation>,
    ) -> Result<(), ActorError> {
        match msg {
            ValidationMessage::Create {
                request_id,
                version,
                signers,
            } => {
                let vali_req_hash = match self.create_vali_req_hash() {
                    Ok(digest) => digest,
                    Err(e) => {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to create validation request hash"
                        );
                        return Err(emit_fail(
                            ctx,
                            ActorError::FunctionalCritical {
                                description: format!(
                                    "Cannot create validation request hash: {}",
                                    e
                                ),
                            },
                        )
                        .await);
                    }
                };

                self.validation_request_hash = vali_req_hash;
                self.validators_quantity = signers.len() as u32;
                self.request_id = request_id.clone();
                self.version = version;

                let validators_quantity = self.quorum.get_signers(
                    self.validators_quantity,
                    signers.len() as u32,
                );

                let (current_vali, pending_vali) =
                    take_random_signers(signers, validators_quantity as usize);
                self.current_validators.clone_from(&current_vali);
                self.pending_validators.clone_from(&pending_vali);

                for signer in current_vali.clone() {
                    if let Err(e) =
                        self.create_validators(ctx, signer.clone()).await
                    {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            signer = %signer,
                            "Failed to create validator"
                        );
                    }
                }

                debug!(
                    msg_type = "Create",
                    request_id = %request_id,
                    version = version,
                    validators_count = current_vali.len(),
                    "Validation created and validators initialized"
                );
            }
            ValidationMessage::Response {
                validation_res,
                sender,
                signature,
            } => {
                if !self.reboot {
                    if self.check_validator(sender.clone()) {
                        match *validation_res {
                            ValidationRes::Create {
                                vali_req_hash,
                                subject_metadata,
                            } => {
                                let Some(signature) = signature else {
                                    error!(
                                        msg_type = "Response",
                                        sender = %sender,
                                        "Validation response without signature"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Validation Response solver without signature".to_owned(),
                                    });
                                };

                                if vali_req_hash != self.validation_request_hash
                                {
                                    error!(
                                        msg_type = "Response",
                                        expected_hash = %self.validation_request_hash,
                                        received_hash = %vali_req_hash,
                                        "Invalid validation request hash"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Validation Response, Invalid validation request hash".to_owned(),
                                    });
                                }

                                self.validators_response.push(
                                    ValidationMetadata::Metadata(
                                        subject_metadata,
                                    ),
                                );
                                self.validators_signatures.push(signature);
                            }
                            ValidationRes::Response {
                                vali_req_hash,
                                modified_metadata_hash,
                            } => {
                                let Some(signature) = signature else {
                                    error!(
                                        msg_type = "Response",
                                        sender = %sender,
                                        "Validation response without signature"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Validation Response solver without signature".to_owned(),
                                    });
                                };

                                if vali_req_hash != self.validation_request_hash
                                {
                                    error!(
                                        msg_type = "Response",
                                        expected_hash = %self.validation_request_hash,
                                        received_hash = %vali_req_hash,
                                        "Invalid validation request hash"
                                    );
                                    return Err(ActorError::Functional {
                                        description: "Validation Response, Invalid validation request hash".to_owned(),
                                    });
                                }

                                self.validators_response.push(
                                    ValidationMetadata::ModifiedHash(
                                        modified_metadata_hash,
                                    ),
                                );
                                self.validators_signatures.push(signature);
                            }
                            ValidationRes::TimeOut => {
                                // Do nothing
                            }
                            ValidationRes::Abort(error) => {
                                if let Err(e) = abort_req(
                                    ctx,
                                    self.request_id.clone(),
                                    sender.clone(),
                                    error,
                                    self.request.content().get_sn(),
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        sender = %sender,
                                        "Failed to abort request"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            }
                            ValidationRes::Reboot => {
                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content().get_governance_id().expect("The build process verified that the event request is valid"),
                                    RebootType::Normal
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }

                                self.reboot = true;

                                return Ok(());
                            }
                        };

                        if self.quorum.check_quorum(
                            self.validators_quantity,
                            self.validators_response.len() as u32,
                        ) {
                            let summary = self.check_responses();
                            if let ResponseSummary::Reboot = summary
                                && let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content().get_governance_id().expect("The build process verified that the event request is valid"),
                                    RebootType::Diff
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }

                            let validation_data = self.build_validation_data();

                            if let Err(e) = self
                                .send_validation_to_req(ctx, validation_data)
                                .await
                            {
                                error!(
                                    msg_type = "Response",
                                    error = %e,
                                    "Failed to send validation to request actor"
                                );
                                return Err(emit_fail(ctx, e).await);
                            };

                            debug!(
                                msg_type = "Response",
                                request_id = %self.request_id,
                                version = self.version,
                                "Validation completed and sent to request"
                            );
                        } else if self.current_validators.is_empty()
                            && !self.pending_validators.is_empty()
                        {
                            let validators_quantity = self.quorum.get_signers(
                                self.validators_quantity,
                                self.pending_validators.len() as u32,
                            );

                            let (curren_vali, pending_vali) =
                                take_random_signers(
                                    self.pending_validators.clone(),
                                    validators_quantity as usize,
                                );
                            self.current_validators.clone_from(&curren_vali);
                            self.pending_validators.clone_from(&pending_vali);

                            for signer in curren_vali.clone() {
                                if let Err(e) = self
                                    .create_validators(ctx, signer.clone())
                                    .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        signer = %signer,
                                        "Failed to create validator from pending pool"
                                    );
                                }
                            }

                            debug!(
                                msg_type = "Response",
                                new_validators = curren_vali.len(),
                                "Created additional validators from pending pool"
                            );
                        } else if self.current_validators.is_empty()
                            && let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    self.request
                                        .content().get_governance_id().expect("The build process verified that the event request is valid"),
                                    RebootType::TimeOut
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                    } else {
                        warn!(
                            msg_type = "Response",
                            sender = %sender,
                            "Response from unexpected sender"
                        );
                    }
                }
            }
        };
        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Validation>,
    ) -> ChildAction {
        error!(
            request_id = %self.request_id,
            version = self.version,
            error = %error,
            "Child fault in validation actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[cfg(test)]
pub mod tests {
    use core::panic;
    use std::{sync::Arc, time::Duration};
    use tempfile::TempDir;
    use test_log::test;

    use ave_actors::{ActorPath, ActorRef, PersistentActor, SystemRef};
    use ave_common::{
        Namespace, SchemaType,
        identity::{
            DigestIdentifier, HashAlgorithm, KeyPair, keys::Ed25519Signer,
        },
        request::{CreateRequest, EOLRequest},
        response::RequestEventDB,
    };
    use tokio::sync::mpsc;

    use crate::{
        EventRequest, Node, NodeMessage, NodeResponse, Signed,
        governance::{
            Governance, GovernanceMessage, GovernanceResponse,
            data::GovernanceData,
        },
        helpers::{db::ExternalDB, network::service::NetworkSender},
        model::common::node::SignTypesNode,
        node::InitParamsNode,
        query::{Query, QueryMessage, QueryResponse},
        request::{
            RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
            tracking::RequestTracking,
        },
        system::tests::create_system,
    };

    pub async fn create_gov() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        ActorRef<Query>,
        ActorRef<Governance>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let (system, .., _dirs) = create_system().await;

        let (command_sender, _command_receiver) = mpsc::channel(10);
        let network = Arc::new(NetworkSender::new(command_sender));

        system.add_helper("network", network.clone()).await;

        let public_key = Arc::new(node_keys.public_key());
        let node_actor = system
            .create_root_actor(
                "node",
                Node::initial(InitParamsNode {
                    key_pair: node_keys.clone(),
                    public_key: public_key.clone(),
                    hash: HashAlgorithm::Blake3,
                    is_service: true,
                }),
            )
            .await
            .unwrap();

        let request_actor = system
            .create_root_actor(
                "request",
                RequestHandler::initial((
                    public_key.clone(),
                    (HashAlgorithm::Blake3, network),
                )),
            )
            .await
            .unwrap();

        let ext_db = system
            .get_helper::<Arc<ExternalDB>>("ext_db")
            .await
            .unwrap();

        let query_actor = system
            .create_root_actor("query", Query::new(ext_db))
            .await
            .unwrap();

        let create_req = EventRequest::Create(CreateRequest {
            name: Some("Name".to_string()),
            description: Some("Description".to_string()),
            governance_id: DigestIdentifier::default(),
            schema_id: SchemaType::Governance,
            namespace: Namespace::new(),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                create_req.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(create_req, signature);

        let RequestHandlerResponse::Ok(response) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let owned_subj = response.subject_id;

        tokio::time::sleep(Duration::from_millis(1000)).await;

        let subject_actor: ActorRef<Governance> = system
            .get_actor(&ActorPath::from(format!("/user/node/{}", owned_subj)))
            .await
            .unwrap();

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };
        let QueryResponse::Subject(subject_data) = query_actor
            .ask(QueryMessage::GetSubject {
                subject_id: owned_subj.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let QueryResponse::Event(event) = query_actor
            .ask(QueryMessage::GetEventSn {
                subject_id: owned_subj.clone(),
                sn: 0,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let RequestEventDB::Create {
            name,
            description,
            schema_id,
            namespace,
        } = event.event
        else {
            panic!()
        };

        assert_eq!(metadata.name, name);
        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, description);
        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, owned_subj);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, owned_subj);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(metadata.schema_id.to_string(), schema_id);
        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(metadata.namespace.to_string(), namespace);
        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 0);

        assert!(subject_data.active);
        assert!(metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 0);

        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());

        let tracking = system
            .get_actor::<RequestTracking>(&ActorPath::from(
                "/user/request/tracking",
            ))
            .await
            .unwrap();

        (
            system,
            node_actor,
            request_actor,
            query_actor,
            subject_actor,
            tracking,
            metadata.subject_id,
            _dirs,
        )
    }

    #[test(tokio::test)]
    async fn test_create_gov() {
        let _ = create_gov().await;
    }

    #[test(tokio::test)]
    async fn test_eol_gov() {
        let (
            _system,
            node_actor,
            request_actor,
            query_actor,
            subject_actor,
            _tracking,
            subject_id,
            _dirs,
        ) = create_gov().await;

        let eol_reques = EventRequest::EOL(EOLRequest {
            subject_id: subject_id.clone(),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(SignTypesNode::EventRequest(
                eol_reques.clone(),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(eol_reques, signature);

        let RequestHandlerResponse::Ok(_response) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        tokio::time::sleep(Duration::from_secs(2)).await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let QueryResponse::Subject(subject_data) = query_actor
            .ask(QueryMessage::GetSubject {
                subject_id: subject_id.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let QueryResponse::Event(event) = query_actor
            .ask(QueryMessage::GetEventSn {
                subject_id: subject_id.clone(),
                sn: 1,
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let RequestEventDB::EOL = event.event else {
            panic!()
        };

        assert_eq!(metadata.name, subject_data.name);
        assert_eq!(metadata.name.unwrap(), "Name");

        assert_eq!(metadata.description, subject_data.description);
        assert_eq!(metadata.description.unwrap(), "Description");

        assert_eq!(metadata.subject_id.to_string(), event.subject_id);
        assert_eq!(metadata.subject_id.to_string(), subject_data.subject_id);
        assert_eq!(metadata.subject_id, subject_id);

        assert_eq!(
            metadata.governance_id.to_string(),
            subject_data.governance_id
        );
        assert_eq!(metadata.governance_id, subject_id);

        assert_eq!(
            metadata.genesis_gov_version,
            subject_data.genesis_gov_version
        );
        assert_eq!(metadata.genesis_gov_version, 0);

        assert_eq!(
            metadata.schema_id.to_string(),
            subject_data.schema_id.to_string()
        );
        assert_eq!(metadata.schema_id, SchemaType::Governance);

        assert_eq!(
            metadata.namespace.to_string(),
            subject_data.namespace.to_string()
        );
        assert_eq!(metadata.namespace, Namespace::new());

        assert!(subject_data.new_owner.is_none());
        assert!(metadata.new_owner.is_none());

        assert_eq!(metadata.sn, event.sn);
        assert_eq!(metadata.sn, subject_data.sn);
        assert_eq!(metadata.sn, 1);

        assert!(!subject_data.active);
        assert!(!metadata.active);

        assert_eq!(metadata.properties.0, subject_data.properties);
        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);

        assert!(!gov.members.is_empty());
        assert!(gov.roles_schema.is_empty());
        assert!(gov.schemas.is_empty());
        assert!(gov.policies_schema.is_empty());

        if !request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .is_err()
        {
            panic!("Invalid response")
        }
    }
}
