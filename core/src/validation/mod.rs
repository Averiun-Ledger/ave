//! # Validation module.
//!
use crate::{
    governance::model::Quorum,
    helpers::network::service::NetworkSender,
    model::{
        common::{emit_fail, send_reboot_to_req, take_random_signers},
        event::{ValidationData, ValidationMetadata},
    },
    request::manager::{RequestManager, RequestManagerMessage},
    validation::{
        response::ResponseSummary, coordinator::{ValiCoordinator, ValiCoordinatorMessage}, worker::{ValiWorker, ValiWorkerMessage}
    },
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, ChildAction, Handler,
    Message, NotPersistentActor,
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

pub mod request;
pub mod response;
pub mod schema;
pub mod coordinator;
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

    request_id: String,

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
            request_id: String::default(),
            version: 0,
            validation_request_hash: DigestIdentifier::default(),
            reboot: false,
            current_validators: HashSet::new(),
            pending_validators: HashSet::new(),
        }
    }

    async fn end_validators(
        &self,
        ctx: &mut ActorContext<Validation>,
    ) -> Result<(), ActorError> {
        for validator in self.current_validators.clone() {
            if validator == *self.our_key {
                let child: Option<ActorRef<ValiWorker>> =
                    ctx.get_child(&validator.to_string()).await;
                if let Some(child) = child {
                    child.ask_stop().await?;
                }
            } else {
                let child: Option<ActorRef<ValiCoordinator>> =
                    ctx.get_child(&validator.to_string()).await;
                if let Some(child) = child {
                    child.ask_stop().await?;
                }
            }
        }

        Ok(())
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
                    validation_req: self.request.clone(),
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
                            .content().get_governance_id().expect("The build process verified that the event request is valid.")
                            ,
                        gov_version: self.request.content().get_gov_version(),
                        sn: self.request.content().get_sn(),
                        hash: self.hash,
                        network: self.network.clone(),
                    },
                )
                .await?;

            child
                .tell(ValiWorkerMessage::LocalValidation {
                    validation_req: self.request.clone(),
                })
                .await?
        }

        Ok(())
    }

    async fn send_validation_to_req(
        &self,
        ctx: &mut ActorContext<Validation>,
        response: ValidationData
    ) -> Result<(), ActorError> {
        let req_path =
            ActorPath::from(format!("/user/request/{}", self.request_id));
        let req_actor: Option<ActorRef<RequestManager>> =
            ctx.system().get_actor(&req_path).await;

        if let Some(req_actor) = req_actor {
            req_actor
                .tell(RequestManagerMessage::ValidationRes {
                    val_req: self.request.content().clone(),
                    val_res: response
                })
                .await?;
        } else {
            return Err(ActorError::NotFound { path: req_path});
        };

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

    fn build_validation_data(
        &self,
    ) -> ValidationData {
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
        request_id: String,
        version: u64,
        signers: HashSet<PublicKey>,
    },
    Response {
        validation_res: ValidationRes,
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

        fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "Validation", id = id)
        } else {
            info_span!("Validation", id = id)
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
                                description: format!("Cannot create validation request hash: {}", e)
                            },
                        )
                        .await);
                    }
                };

                self.validation_request_hash = vali_req_hash;
                self.validators_quantity = signers.len() as u32;
                self.request_id = request_id.to_string();
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
                        match validation_res {
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

                                self.validators_response.push(ValidationMetadata::Metadata(subject_metadata));
                                self.validators_signatures.push(signature);
                            }
                            ValidationRes::Response {
                                vali_req_hash,
                                modified_metadata_hash
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

                                self.validators_response.push(ValidationMetadata::ModifiedHash(modified_metadata_hash));
                                self.validators_signatures.push(signature);
                            }
                            ValidationRes::TimeOut => {
                                // Do nothing
                            }
                            ValidationRes::Abort(error) => {
                                todo!("ME dijeron que abortara la request")
                            }
                            ValidationRes::Reboot => {
                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    &self.request_id,
                                    self.request
                                        .content().get_governance_id().expect("The build process verified that the event request is valid.")
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

                                if let Err(e) = self.end_validators(ctx).await {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to end validators"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                };

                                debug!(
                                    msg_type = "Response",
                                    request_id = %self.request_id,
                                    "Reboot requested, validators stopped"
                                );

                                ctx.stop(None).await;
                                return Ok(());
                            }
                        };

                        if self.quorum.check_quorum(
                            self.validators_quantity,
                            self.validators_response.len() as u32,
                        ) {
                            let summary = self.check_responses();
                            if let ResponseSummary::Reboot = summary {
                                todo!(
                                    "Respuestas diferentes, hay que hacer reboot, pero no tengo por qué actualizar la gov"
                                )
                            }

                            let validation_data = self.build_validation_data();

                            if let Err(e) =
                                self.send_validation_to_req(ctx, validation_data).await
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

                            ctx.stop(None).await;
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
                        } else if self.current_validators.is_empty() {
                            todo!(
                                "Reboot, no tengo el quorum, hay que actualizar la governance y reintentarlo"
                            );
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
        error!(error = %error, "Child fault occurred");
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}

#[cfg(test)]
pub mod tests {
    use core::panic;
    use std::time::Duration;
    use tempfile::TempDir;
    use test_log::test;

    use ave_actors::{ActorPath, ActorRef, PersistentActor, SystemRef};
    use ave_common::{
        ValueWrapper,
        identity::{
            Blake3Hasher, DigestIdentifier, KeyPair, hash_borsh,
            keys::Ed25519Signer,
        },
    };

    use crate::{
        CreateRequest, EOLRequest, EventRequest, Node, NodeMessage,
        NodeResponse, Signed,
        governance::{
            Governance, GovernanceMessage, GovernanceResponse,
            data::GovernanceData,
        },
        model::{
            Namespace, SignTypesNode, event::LedgerValue, request::SchemaType,
        },
        query::Query,
        request::{
            RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
            tracking::RequestTracking,
        },
        subject::laststate::{LastState, LastStateMessage, LastStateResponse},
        system::tests::create_system,
    };

    pub async fn create_subject_gov() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        ActorRef<Query>,
        ActorRef<Governance>,
        ActorRef<LastState>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let (system, .., _dirs) = create_system().await;

        let node_actor = system
            .create_root_actor("node", Node::initial(node_keys.clone()))
            .await
            .unwrap();

        let request_actor = system
            .create_root_actor(
                "request",
                RequestHandler::initial(node_keys.public_key()),
            )
            .await
            .unwrap();

        let query_actor = system
            .create_root_actor("query", Query::new(node_keys.public_key()))
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

        let last_state_actor: ActorRef<LastState> = system
            .get_actor(&ActorPath::from(format!(
                "/user/node/{}/last_state",
                owned_subj
            )))
            .await
            .unwrap();

        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let last_event = *event;
        assert_eq!(last_event.content().subject_id.to_string(), owned_subj);
        assert_eq!(last_event.content().event_request, signed_event_req);
        assert_eq!(last_event.content().sn, 0);
        assert_eq!(last_event.content().gov_version, 0);
        assert_eq!(
            last_event.content().value,
            LedgerValue::Patch(ValueWrapper(serde_json::Value::String(
                "[]".to_owned(),
            ),))
        );

        assert_eq!(
            last_event.content().state_hash,
            hash_borsh(&Blake3Hasher, &metadata.properties).unwrap()
        );
        assert!(last_event.content().eval_success.is_none());
        assert!(!last_event.content().appr_required);
        assert!(last_event.content().appr_success.is_none());
        assert!(last_event.content().vali_success);
        assert_eq!(
            last_event.content().hash_prev_event,
            DigestIdentifier::default()
        );
        assert!(last_event.content().validators.is_none());
        assert!(last_event.content().approvers.is_none(),);
        assert!(!last_event.content().validators.is_empty());

        assert_eq!(metadata.subject_id.to_string(), owned_subj);
        assert_eq!(metadata.name.unwrap(), "Name");
        assert_eq!(metadata.description.unwrap(), "Description");
        assert_eq!(metadata.governance_id.to_string(), "");
        assert_eq!(metadata.genesis_gov_version, 0);
        assert_eq!(metadata.schema_id.to_string(), "governance");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 0);
        assert_eq!(metadata.owner, node_keys.public_key());
        assert!(metadata.active);

        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 0);
        // TODO MEJORAR
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
            last_state_actor,
            tracking,
            metadata.subject_id,
            _dirs,
        )
    }

    #[test(tokio::test)]
    async fn test_create_req() {
        let _ = create_subject_gov().await;
    }

    #[test(tokio::test)]
    async fn test_eol_req() {
        let (
            _system,
            node_actor,
            request_actor,
            _query_actor,
            subject_actor,
            last_state_actor,
            _tracking,
            subject_id,
            _dirs,
        ) = create_subject_gov().await;

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

        tokio::time::sleep(Duration::from_secs(3)).await;

        let LastStateResponse::LastState { event, .. } = last_state_actor
            .ask(LastStateMessage::GetLastState)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let last_event = *event;
        assert_eq!(last_event.content().subject_id, subject_id);
        assert_eq!(last_event.content().event_request, signed_event_req);
        assert_eq!(last_event.content().sn, 1);
        assert_eq!(last_event.content().gov_version, 0);
        assert_eq!(
            last_event.content().value,
            LedgerValue::Patch(ValueWrapper(serde_json::Value::String(
                "[]".to_owned(),
            ),))
        );
        assert!(last_event.content().eval_success.is_none());
        assert!(!last_event.content().appr_required);
        assert!(last_event.content().appr_success.is_none());
        assert!(last_event.content().vali_success);
        assert!(last_event.content().validators.is_none());
        assert!(last_event.content().approvers.is_none(),);
        assert!(!last_event.content().validators.is_empty());

        assert_eq!(metadata.subject_id, subject_id);
        assert_eq!(metadata.governance_id.to_string(), "");
        assert_eq!(metadata.name.unwrap(), "Name");
        assert_eq!(metadata.description.unwrap(), "Description");
        assert_eq!(metadata.genesis_gov_version, 0);
        assert_eq!(metadata.schema_id.to_string(), "governance");
        assert_eq!(metadata.namespace, Namespace::new());
        assert_eq!(metadata.sn, 1);
        assert!(!metadata.active);

        let gov = GovernanceData::try_from(metadata.properties).unwrap();
        assert_eq!(gov.version, 1);
        // TODO MEJORAR
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
