use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, HashAlgorithm, PublicKey},
};
use network::ComunicateInfo;
use tracing::{Span, debug, error, info_span, warn};

use crate::{
    Signed,
    governance::role_register::CurrentSchemaRoles,
    helpers::network::service::NetworkSender,
    metrics::try_core_metrics,
    model::common::{emit_fail, node::try_to_update},
    validation::worker::{CurrentWorkerRoles, ValiWorker, ValiWorkerMessage},
};

use super::request::ValidationReq;

#[derive(Clone, Debug)]
pub struct ValidationSchema {
    pub our_key: Arc<PublicKey>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub sn: u64,
    pub schema_id: SchemaType,
    pub creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
    pub init_state: ValueWrapper,
    pub current_roles: CurrentSchemaRoles,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
}

#[derive(Debug, Clone)]
pub enum ValidationSchemaMessage {
    NetworkRequest {
        validation_req: Box<Signed<ValidationReq>>,
        info: ComunicateInfo,
        sender: PublicKey,
    },
    Update {
        creators: BTreeMap<PublicKey, BTreeSet<Namespace>>,
        sn: u64,
        gov_version: u64,
        init_state: ValueWrapper,
        current_roles: CurrentSchemaRoles,
    },
}

impl Message for ValidationSchemaMessage {}

impl NotPersistentActor for ValidationSchema {}

#[async_trait]
impl Actor for ValidationSchema {
    type Event = ();
    type Message = ValidationSchemaMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ValidationSchema", id),
            |parent_span| info_span!(parent: parent_span, "ValidationSchema", id),
        )
    }
}

#[async_trait]
impl Handler<Self> for ValidationSchema {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ValidationSchemaMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ValidationSchemaMessage::NetworkRequest {
                validation_req,
                info,
                sender,
            } => {
                let observe = |result: &'static str| {
                    if let Some(metrics) = try_core_metrics() {
                        metrics
                            .observe_schema_event("validation_schema", result);
                    }
                };
                if sender != validation_req.signature().signer {
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        signer = %validation_req.signature().signer,
                        "Signer and sender are not the same"
                    );
                    return Ok(());
                }

                let governance_id =
                    match validation_req.content().get_governance_id() {
                        Ok(governance_id) => governance_id,
                        Err(e) => {
                            observe("rejected");
                            warn!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Failed to get governance_id"
                            );
                            return Ok(());
                        }
                    };

                if self.governance_id != governance_id {
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_governance_id = %self.governance_id,
                        received_governance_id = %governance_id,
                        "Invalid governance_id"
                    );
                    return Ok(());
                }

                let schema_id = match validation_req.content().get_schema_id() {
                    Ok(schema_id) => schema_id,
                    Err(e) => {
                        observe("rejected");
                        warn!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to get schema_id"
                        );
                        return Ok(());
                    }
                };

                if self.schema_id != schema_id {
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_schema_id = ?self.schema_id,
                        received_schema_id = ?schema_id,
                        "Invalid schema_id"
                    );
                    return Ok(());
                }

                if let Some(ns) = self.creators.get(&sender) {
                    let namespace =
                        match validation_req.content().get_namespace() {
                            Ok(namespace) => namespace,
                            Err(e) => {
                                observe("rejected");
                                warn!(
                                    msg_type = "NetworkRequest",
                                    error = %e,
                                    "Failed to get namespace"
                                );
                                return Ok(());
                            }
                        };
                    if !ns.contains(&namespace) {
                        observe("rejected");
                        warn!(
                            msg_type = "NetworkRequest",
                            sender = %sender,
                            namespace = ?namespace,
                            "Invalid sender namespace"
                        );
                        return Ok(());
                    }
                } else {
                    observe("rejected");
                    warn!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        "Sender is not a creator"
                    );
                    return Ok(());
                }

                if self.gov_version < validation_req.content().get_gov_version()
                    && let Err(e) =
                        try_to_update(ctx, self.governance_id.clone(), None)
                            .await
                {
                    error!(
                        msg_type = "NetworkRequest",
                        error = %e,
                        "Failed to update governance"
                    );
                    return Err(emit_fail(ctx, e).await);
                }

                let child = ctx
                    .create_child(
                        &format!("{}", validation_req.signature().signer),
                        ValiWorker {
                            init_state: Some(self.init_state.clone()),
                            node_key: sender.clone(),
                            our_key: self.our_key.clone(),
                            governance_id: self.governance_id.clone(),
                            gov_version: self.gov_version,
                            sn: self.sn,
                            current_roles: CurrentWorkerRoles {
                                evaluation: crate::governance::role_register::RoleDataRegister {
                                    workers: self
                                        .current_roles
                                        .evaluation
                                        .iter()
                                        .filter(|role| role.namespace.is_ancestor_or_equal_of(&validation_req.content().get_namespace().unwrap_or_default()))
                                        .map(|role| role.key.clone())
                                        .collect(),
                                    quorum: self.current_roles.evaluation_quorum.clone(),
                                },
                                approval: crate::governance::role_register::RoleDataRegister {
                                    workers: std::collections::HashSet::new(),
                                    quorum: crate::governance::model::Quorum::default(),
                                },
                            },
                            hash: self.hash,
                            network: self.network.clone(),
                            stop: true,
                        },
                    )
                    .await;

                let validator_actor = match child {
                    Ok(child) => child,
                    Err(e) => {
                        if let ActorError::Exists { .. } = e {
                            observe("rejected");
                            warn!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Validator actor already exists"
                            );
                            return Ok(());
                        } else {
                            error!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Failed to create validator actor"
                            );
                            return Err(emit_fail(ctx, e).await);
                        }
                    }
                };

                if let Err(e) = validator_actor
                    .tell(ValiWorkerMessage::NetworkRequest {
                        validation_req,
                        info,
                        sender: sender.clone(),
                    })
                    .await
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        error = %e,
                        "Failed to send request to validator"
                    );
                } else {
                    observe("delegated");
                    debug!(
                        msg_type = "NetworkRequest",
                        sender = %sender,
                        "Validation request delegated to worker"
                    );
                }
            }
            ValidationSchemaMessage::Update {
                creators,
                sn,
                gov_version,
                init_state,
                current_roles,
            } => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_schema_event("validation_schema", "update");
                }
                self.creators = creators;
                self.gov_version = gov_version;
                self.sn = sn;
                self.init_state = init_state;
                self.current_roles = current_roles;

                debug!(
                    msg_type = "Update",
                    sn = self.sn,
                    gov_version = self.gov_version,
                    "Schema updated successfully"
                );
            }
        };
        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_schema_event("validation_schema", "child_fault");
        }
        error!(
            governance_id = %self.governance_id,
            schema_id = ?self.schema_id,
            gov_version = self.gov_version,
            error = %error,
            "Child fault in validation schema"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
