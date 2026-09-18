use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use crate::{
    approval::{
        persist::{ApprPersist, ApprPersistMessage},
        request::ApprovalReq,
        response::ApprovalRes,
        verify::{ApprovalVerification, CLOCK_SKEW, verify_approval_data},
    },
    compilation::{
        request::CompilationReq, response::CompilationResult,
        schemas_to_compile,
    },
    config::ApprovalConfig,
    evaluation::{
        request::{EvaluateData, EvaluationReq},
        response::EvaluationResult,
    },
    governance::{
        data::GovernanceData,
        role_register::{RoleDataRegister, SearchRole},
    },
    helpers::network::{NetworkMessage, service::NetworkSender},
    metrics::try_core_metrics,
    model::{
        common::{
            GovVersionSync, check_quorum_signers, crash_system,
            get_actual_roles_register, get_validation_roles_register,
            gov_version_sync,
            node::{SignTypesNode, get_sign},
        },
        event::{
            ApprovalData, CompilationData, CompilationResponse, EvaluationData,
            EvaluationResponse, ValidationMetadata,
        },
    },
    subject::{Metadata, MetadataWithoutProperties, RequestSubjectData},
    system::ConfigHelper,
    validation::{
        request::{ActualProtocols, LastData},
        response::ValidatorError,
    },
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::{
    ValueWrapper,
    bridge::request::EventRequestType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, TimeStamp,
        hash_borsh,
    },
    request::EventRequest,
};
use borsh::{BorshDeserialize, BorshSerialize};

use ave_network::ComunicateInfo;
use json_patch::{Patch, patch};
use std::collections::BTreeSet;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Validation, ValidationMessage, request::ValidationReq,
    response::ValidationRes,
};

/// A struct representing a ValiWorker actor.
#[derive(
    Clone,
    Debug,
    serde::Serialize,
    serde::Deserialize,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct CurrentRequestRoles {
    pub evaluation: RoleDataRegister,
    pub compilation: RoleDataRegister,
    pub approval: RoleDataRegister,
}

#[derive(Clone, Debug)]
pub struct CurrentWorkerRoles {
    pub evaluation: RoleDataRegister,
    pub compilation: RoleDataRegister,
    pub approval: RoleDataRegister,
    /// Validation role set of the governance: the worker needs it to
    /// verify the validator-signed timeout attestations inside a tally
    /// proposal.
    pub validation: RoleDataRegister,
}

#[derive(Clone, Debug)]
pub struct ValiWorker {
    pub node_key: PublicKey,
    pub our_key: Arc<PublicKey>,
    pub init_state: Option<ValueWrapper>,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub sn: u64,
    pub hash: HashAlgorithm,
    pub network: Arc<NetworkSender>,
    pub current_roles: CurrentWorkerRoles,
    pub stop: bool,
    /// In-flight network validation request, if any (see `pre_stop`).
    pub pending: Option<PendingValidation>,
    /// Approval vote collections in flight, keyed by approval request
    /// hash. Volatile by design: superseded by a newer request of the
    /// same subject and expired shortly after the deadline.
    pub approvals: HashMap<DigestIdentifier, ApprovalCollection>,
}

/// A network validation request being processed. `pre_stop` uses it to
/// notify the requester that this validator is going down mid-validation
/// (`ValidationRes::Unavailable`) instead of letting it burn the
/// coordinator retries on a dead node.
#[derive(Clone, Debug)]
pub struct PendingValidation {
    /// Requester node key (response receiver).
    pub sender: PublicKey,
    /// Request identifier of the in-flight validation.
    pub request_id: String,
    /// Validation request version.
    pub version: u64,
    /// Subject the validation belongs to (response actor path).
    pub subject_id: DigestIdentifier,
}

/// How to reach the requester of the validation request that owns an
/// approval collection.
#[derive(Clone, Debug)]
pub enum OwnerRoute {
    /// The requester is this same node: the `Validation` actor is the
    /// parent of this worker.
    Local,
    /// The requester is a remote node reached through the network.
    Network,
}

/// Everything the worker needs to build the final validation response
/// once the requester proposes the approval tally.
#[derive(Clone, Debug)]
pub struct ResponseMaterial {
    pub vali_req_hash: DigestIdentifier,
    pub event_request: Signed<EventRequest>,
    /// Pre-event subject metadata.
    pub metadata: Metadata,
    /// Post-evaluation properties, when the event evaluated successfully.
    pub properties: Option<ValueWrapper>,
    pub ledger_hash: DigestIdentifier,
}

/// An approval vote collection in flight. All of it is volatile: keyed by
/// the approval request hash, superseded by a newer request of the same
/// subject and expired at `deadline + 2 * keepalive`.
#[derive(Clone, Debug)]
pub struct ApprovalCollection {
    /// Requester node key (vote pushes and final response receiver).
    pub requester: PublicKey,
    pub request_id: String,
    pub version: u64,
    pub owner_route: OwnerRoute,
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub gov_version: u64,
    pub approval_req: Signed<ApprovalReq>,
    pub approval_req_hash: DigestIdentifier,
    pub approvers: RoleDataRegister,
    pub req_subject_data_hash: DigestIdentifier,
    /// One vote per approver; conflicting signers live in `double_votes`.
    pub votes: HashMap<PublicKey, Signed<ApprovalRes>>,
    /// (accept, reject) conflicting pairs observed per approver.
    pub double_votes: Vec<(Signed<ApprovalRes>, Signed<ApprovalRes>)>,
    /// Own timeout attestations signed at the deadline for the approvers
    /// that never answered, keyed by approver. A late vote or double vote
    /// removes the entry: the answer always wins over the timeout.
    pub timeouts: HashMap<PublicKey, Signed<ApprovalRes>>,
    /// Guard so the deadline tick signs the timeouts only once.
    pub timeouts_signed: bool,
    pub material: ResponseMaterial,
}

/// Outcome of processing a validation request.
enum WorkerVerdict {
    /// The request is fully validated: this is the final response.
    Final(ValidationRes),
    /// The request needs approval: the worker answered `Working` and is
    /// now collecting the approver votes.
    Collecting(Box<ApprovalCollection>),
}

/// Approval request context extracted while checking the actual
/// protocols of a validation request.
struct ApprovalContext {
    approval_req: Signed<ApprovalReq>,
    approval_req_hash: DigestIdentifier,
    approvers: RoleDataRegister,
    req_subject_data_hash: DigestIdentifier,
}

impl ValiWorker {
    /// Best-effort `Unavailable` notification for the in-flight network
    /// validation request: the node is going down before answering, so
    /// the requester can replace this validator immediately instead of
    /// waiting for the coordinator retries and timeout. The response is
    /// signed like any other validation response. Errors are logged and
    /// swallowed — the coordinator timeout is the fallback.
    async fn notify_unavailable(&self, ctx: &mut ActorContext<Self>) {
        let Some(pending) = &self.pending else {
            return;
        };

        let signature = match get_sign(
            ctx,
            SignTypesNode::ValidationRes(ValidationRes::Unavailable),
        )
        .await
        {
            Ok(signature) => signature,
            Err(error) => {
                debug!(
                    error = %error,
                    request_id = %pending.request_id,
                    "Could not sign unavailability notification"
                );
                return;
            }
        };

        let info = ComunicateInfo {
            receiver: pending.sender.clone(),
            request_id: pending.request_id.clone(),
            version: pending.version,
            receiver_actor: format!(
                "/user/request/{}/validation/{}",
                pending.subject_id, self.our_key
            ),
        };

        let signed_response: Signed<ValidationRes> =
            Signed::from_parts(ValidationRes::Unavailable, signature);
        if let Err(error) = self
            .network
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info,
                    message: ActorMessage::ValidationRes {
                        res: signed_response,
                    },
                },
            })
            .await
        {
            debug!(
                error = %error,
                request_id = %pending.request_id,
                "Could not notify validator unavailability while stopping"
            );
        }
    }

    fn event_request_hash(
        &self,
        event_request: &Signed<EventRequest>,
    ) -> Result<DigestIdentifier, ValidatorError> {
        hash_borsh(&*self.hash.hasher(), event_request).map_err(|e| {
            ValidatorError::InternalError {
                problem: e.to_string(),
            }
        })
    }

    fn viewpoints_hash(
        &self,
        event_request: &EventRequest,
    ) -> Result<DigestIdentifier, ValidatorError> {
        let viewpoints = match event_request {
            EventRequest::Fact(fact_request) => fact_request.viewpoints.clone(),
            _ => BTreeSet::new(),
        };

        hash_borsh(&*self.hash.hasher(), &viewpoints).map_err(|e| {
            ValidatorError::InternalError {
                problem: e.to_string(),
            }
        })
    }

    fn current_evaluation_roles(&self) -> RoleDataRegister {
        self.current_roles.evaluation.clone()
    }

    fn current_compilation_roles(&self) -> RoleDataRegister {
        self.current_roles.compilation.clone()
    }

    fn current_approval_roles(&self) -> RoleDataRegister {
        self.current_roles.approval.clone()
    }

    fn check_data(
        &self,
        validation_req: &Signed<ValidationReq>,
    ) -> Result<(), ValidatorError> {
        if !validation_req.content().is_valid() {
            return Err(ValidatorError::InvalidData {
                value: "validation request",
            });
        }

        let governance_id = validation_req
            .content()
            .get_governance_id()
            .map_err(|_| ValidatorError::InvalidData {
                value: "governance_id",
            })?;

        if governance_id != self.governance_id {
            return Err(ValidatorError::InvalidData {
                value: "governance_id",
            });
        }

        if validation_req.verify().is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "validation request",
            });
        }

        if validation_req
            .content()
            .get_signed_event_request()
            .verify()
            .is_err()
        {
            return Err(ValidatorError::InvalidSignature {
                data: "event request",
            });
        }

        Ok(())
    }

    fn check_metadata(
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

    fn check_basic_data(
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

        Self::check_metadata(
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
        if sn != metadata.sn + 1 {
            return Err(ValidatorError::InvalidData { value: "sn" });
        }
        Ok(())
    }

    /// Static verification of the signed approval request carried by an
    /// approve variant: it must be signed by the requester, describe
    /// exactly this event (subject, sn, governance version, evaluated
    /// patch) and respect the minimum approval window. The votes are not
    /// checked here: they are collected by this worker and verified when
    /// the requester proposes the tally.
    fn check_approval_req(
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

        if req.sn != metadata.sn + 1 {
            return Err(ValidatorError::InvalidData { value: "approval sn" });
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

    fn approval_config(
        ctx: &ActorContext<Self>,
    ) -> Result<ApprovalConfig, ActorError> {
        ctx.system()
            .get_helper::<ConfigHelper>("config")
            .map(|config| config.approval)
            .ok_or_else(|| ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            })
    }

    fn observe_approval_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("approval", result);
        }
    }

    /// Registers a collection, discarding any older collection of the
    /// same subject (supersede), sends the first probe round, arms the
    /// deadline tick (timeout attestations) and the absolute TTL
    /// (`deadline + 2 * keepalive`). A duplicate request for a collection
    /// already in flight (requester recovery) keeps the votes gathered so
    /// far: its probes, deadline tick and TTL are already running.
    async fn start_collection(
        &mut self,
        ctx: &mut ActorContext<Self>,
        collection: ApprovalCollection,
    ) -> Result<(), ActorError> {
        let approval_req_hash = collection.approval_req_hash.clone();
        let subject_id = collection.subject_id.clone();
        let deadline = collection.approval_req.content().deadline;

        if self.approvals.contains_key(&approval_req_hash) {
            return Ok(());
        }

        self.approvals.retain(|_, old| old.subject_id != subject_id);
        self.approvals.insert(approval_req_hash.clone(), collection);

        self.probe_approvers(ctx, &approval_req_hash, 0).await?;

        let until_deadline = deadline
            .as_nanos()
            .saturating_sub(TimeStamp::now().as_nanos());
        ctx.schedule_once(
            Duration::from_nanos(until_deadline),
            ValiWorkerMessage::ApprovalDeadline {
                approval_req_hash: approval_req_hash.clone(),
            },
        )?;

        let config = Self::approval_config(ctx)?;
        let ttl_nanos = deadline
            .as_nanos()
            .saturating_sub(TimeStamp::now().as_nanos())
            .saturating_add(2 * config.keepalive_secs * 1_000_000_000);
        ctx.schedule_once(
            Duration::from_nanos(ttl_nanos),
            ValiWorkerMessage::ExpireCollection { approval_req_hash },
        )?;

        Ok(())
    }

    /// Signs a timeout attestation for every approver that never answered
    /// (no vote, no double-vote pair) and pushes them to the requester.
    /// Runs once per collection, at the deadline; a late answer still wins
    /// over the attestation when the requester merges the evidence.
    async fn sign_timeouts(
        &mut self,
        ctx: &mut ActorContext<Self>,
        approval_req_hash: &DigestIdentifier,
    ) -> Result<(), ActorError> {
        let Some(collection) = self.approvals.get_mut(approval_req_hash)
        else {
            return Ok(());
        };

        if collection.timeouts_signed {
            return Ok(());
        }
        collection.timeouts_signed = true;

        let undecided: Vec<PublicKey> = collection
            .approvers
            .workers
            .iter()
            .filter(|approver| {
                !collection.votes.contains_key(*approver)
                    && !collection.double_votes.iter().any(|(accept, _)| {
                        accept.signature().signer == **approver
                    })
            })
            .cloned()
            .collect();

        for approver in undecided {
            let response = ApprovalRes::TimeOut {
                approval_req_hash: approval_req_hash.clone(),
                who: approver.clone(),
            };
            let signature = get_sign(
                ctx,
                SignTypesNode::ApprovalRes(Box::new(response.clone())),
            )
            .await?;
            let signed = Signed::from_parts(response, signature);
            collection.timeouts.insert(approver, signed);
        }

        if collection.timeouts.is_empty() {
            return Ok(());
        }

        Self::observe_approval_event("timeout_signed");

        let collection = collection.clone();
        for timeout in collection.timeouts.values() {
            if let Err(error) = self
                .push_vote_report(ctx, &collection, timeout.clone())
                .await
            {
                warn!(
                    msg_type = "ApprovalDeadline",
                    error = %error,
                    approval_req_hash = %approval_req_hash,
                    "Failed to push timeout attestation to the requester"
                );
            }
        }

        Ok(())
    }

    /// Sends the approval request to every approver without a vote and
    /// schedules the next probe round of the configured schedule. The
    /// last round lands on the deadline itself.
    async fn probe_approvers(
        &mut self,
        ctx: &mut ActorContext<Self>,
        approval_req_hash: &DigestIdentifier,
        attempt: usize,
    ) -> Result<(), ActorError> {
        let config = Self::approval_config(ctx)?;

        let Some(collection) = self.approvals.get(approval_req_hash) else {
            return Ok(());
        };

        if attempt > config.probe_schedule_secs.len() {
            return Ok(());
        }

        let decided: HashSet<PublicKey> = collection
            .votes
            .keys()
            .cloned()
            .chain(
                collection
                    .double_votes
                    .iter()
                    .map(|(accept, _)| accept.signature().signer.clone()),
            )
            .collect();

        let asker_actor = ctx.path().to_string();
        for approver in collection
            .approvers
            .workers
            .iter()
            .filter(|approver| !decided.contains(*approver))
        {
            // A local approver gets the same message as a direct tell:
            // one code path in the approver, no network self-round-trip.
            if *approver == *self.our_key {
                let path = ActorPath::from(format!(
                    "/user/node/subject_manager/{}/approver",
                    collection.governance_id
                ));
                match ctx.system().get_actor::<ApprPersist>(&path).await {
                    Ok(actor) => {
                        if let Err(error) = actor
                            .tell(ApprPersistMessage::NetworkRequest {
                                approval_req: collection.approval_req.clone(),
                                info: ComunicateInfo {
                                    request_id: collection.request_id.clone(),
                                    version: collection.version,
                                    receiver: approver.clone(),
                                    receiver_actor: path.to_string(),
                                },
                                sender: (*self.our_key).clone(),
                                asker_actor: asker_actor.clone(),
                            })
                            .await
                        {
                            debug!(
                                msg_type = "Probe",
                                error = %error,
                                approver = %approver,
                                approval_req_hash = %approval_req_hash,
                                "Failed to tell local approver"
                            );
                        }
                    }
                    Err(error) => {
                        debug!(
                            msg_type = "Probe",
                            error = %error,
                            approver = %approver,
                            approval_req_hash = %approval_req_hash,
                            "Local approver actor not found"
                        );
                    }
                }
                continue;
            }

            let info = ComunicateInfo {
                request_id: collection.request_id.clone(),
                version: collection.version,
                receiver: approver.clone(),
                receiver_actor: format!(
                    "/user/node/subject_manager/{}/approver",
                    collection.governance_id
                ),
            };

            if let Err(error) = self
                .network
                .send_command(ave_network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info,
                        message: ActorMessage::ApprovalReq {
                            req: collection.approval_req.clone(),
                            asker_actor: asker_actor.clone(),
                        },
                    },
                })
                .await
            {
                debug!(
                    msg_type = "Probe",
                    error = %error,
                    approver = %approver,
                    approval_req_hash = %approval_req_hash,
                    "Failed to send approval request probe"
                );
            }
        }

        if attempt < config.probe_schedule_secs.len() {
            let base = config.probe_schedule_secs[attempt] as i64;
            let wait = (base + Self::probe_jitter_secs()).max(0) as u64;
            ctx.schedule_once(
                Duration::from_secs(wait),
                ValiWorkerMessage::Probe {
                    approval_req_hash: approval_req_hash.clone(),
                    attempt: attempt + 1,
                },
            )?;
        }

        Ok(())
    }

    /// Random jitter in [-10, 10] seconds applied to probe rounds so
    /// validators do not hit the approvers in lockstep. Disabled in test
    /// builds to keep round timing deterministic.
    fn probe_jitter_secs() -> i64 {
        #[cfg(not(any(test, feature = "test")))]
        {
            fastrand::i64(-10..=10)
        }
        #[cfg(any(test, feature = "test"))]
        {
            0
        }
    }

    /// Forwards an approver's abort to the requester as a validator
    /// abort: the approver is ahead of the request's governance version,
    /// so the requester built the request on a stale governance.
    async fn forward_approval_abort(
        &self,
        ctx: &mut ActorContext<Self>,
        collection: &ApprovalCollection,
        reason: String,
    ) -> Result<(), ActorError> {
        let response = ValidationRes::Abort(reason);
        let signature = get_sign(
            ctx,
            SignTypesNode::ValidationRes(response.clone()),
        )
        .await?;

        match &collection.owner_route {
            OwnerRoute::Local => {
                let parent = ctx.get_parent::<Validation>().await?;
                parent
                    .tell(ValidationMessage::Response {
                        validation_res: Box::new(response),
                        sender: (*self.our_key).clone(),
                        signature: Some(signature),
                    })
                    .await?;
            }
            OwnerRoute::Network => {
                let signed_response: Signed<ValidationRes> =
                    Signed::from_parts(response, signature);
                let info = ComunicateInfo {
                    request_id: collection.request_id.clone(),
                    version: collection.version,
                    receiver: collection.requester.clone(),
                    receiver_actor: format!(
                        "/user/request/{}/validation/{}",
                        collection.subject_id, self.our_key
                    ),
                };

                self.network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info,
                            message: ActorMessage::ValidationRes {
                                res: signed_response,
                            },
                        },
                    })
                    .await?;
            }
        }

        Ok(())
    }

    /// Pushes a newly observed vote to the requester: a tell to the parent
    /// `Validation` actor when the requester is this node, a network
    /// message otherwise.
    async fn push_vote_report(
        &self,
        ctx: &mut ActorContext<Self>,
        collection: &ApprovalCollection,
        vote: Signed<ApprovalRes>,
    ) -> Result<(), ActorError> {
        match &collection.owner_route {
            OwnerRoute::Local => {
                let parent = ctx.get_parent::<Validation>().await?;
                parent
                    .tell(ValidationMessage::VoteReport {
                        vote: Box::new(vote),
                        sender: (*self.our_key).clone(),
                    })
                    .await?;
            }
            OwnerRoute::Network => {
                let info = ComunicateInfo {
                    request_id: collection.request_id.clone(),
                    version: collection.version,
                    receiver: collection.requester.clone(),
                    receiver_actor: format!(
                        "/user/request/{}/validation",
                        collection.subject_id
                    ),
                };

                self.network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info,
                            message: ActorMessage::ApprovalVoteReport {
                                res: Box::new(vote),
                            },
                        },
                    })
                    .await?;
            }
        }

        Ok(())
    }

    /// Answers a keepalive status ask with every vote and own timeout
    /// attestation observed so far, deterministically ordered by signer.
    async fn send_status_to_owner(
        &self,
        ctx: &mut ActorContext<Self>,
        collection: &ApprovalCollection,
    ) -> Result<(), ActorError> {
        let mut votes: Vec<Signed<ApprovalRes>> =
            collection.votes.values().cloned().collect();
        for (accept, reject) in &collection.double_votes {
            votes.push(accept.clone());
            votes.push(reject.clone());
        }
        let mut timeouts: Vec<Signed<ApprovalRes>> =
            collection.timeouts.values().cloned().collect();
        timeouts.sort_by(|a, b| {
            let ApprovalRes::TimeOut { who: a_who, .. } = a.content()
            else {
                return std::cmp::Ordering::Equal;
            };
            let ApprovalRes::TimeOut { who: b_who, .. } = b.content()
            else {
                return std::cmp::Ordering::Equal;
            };
            a_who.cmp(b_who)
        });
        votes.extend(timeouts);
        votes.sort_by(|a, b| a.signature().signer.cmp(&b.signature().signer));

        match &collection.owner_route {
            OwnerRoute::Local => {
                let parent = ctx.get_parent::<Validation>().await?;
                parent
                    .tell(ValidationMessage::StatusRes {
                        approval_req_hash: collection.approval_req_hash.clone(),
                        votes,
                        sender: (*self.our_key).clone(),
                    })
                    .await?;
            }
            OwnerRoute::Network => {
                let info = ComunicateInfo {
                    request_id: collection.request_id.clone(),
                    version: collection.version,
                    receiver: collection.requester.clone(),
                    receiver_actor: format!(
                        "/user/request/{}/validation",
                        collection.subject_id
                    ),
                };

                self.network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info,
                            message: ActorMessage::ApprovalStatusRes {
                                approval_req_hash: collection
                                    .approval_req_hash
                                    .clone(),
                                votes,
                            },
                        },
                    })
                    .await?;
            }
        }

        Ok(())
    }

    /// Verifies the tally proposed by the requester (data-only: vote
    /// signatures, quorum, deadline), signs the final validation
    /// response over its hash and drops the collection: once the
    /// request enters validation the worker keeps no approval state.
    async fn finish_collection(
        &mut self,
        ctx: &mut ActorContext<Self>,
        approval_data: ApprovalData,
    ) -> Result<(), ActorError> {
        let approval_req_hash = approval_data.approval_req_hash.clone();
        let Some(collection) = self.approvals.get(&approval_req_hash).cloned()
        else {
            return Ok(());
        };

        if verify_approval_data(ApprovalVerification {
            hash: &self.hash,
            approval: &approval_data,
            approvers: &collection.approvers,
            validators: &self.current_roles.validation,
            req_subject_data_hash: &collection.req_subject_data_hash,
            subject_id: &collection.subject_id,
            sn: collection.material.metadata.sn + 1,
            gov_version: collection.gov_version,
            patch: &collection.approval_req.content().patch,
            signer: &collection.approval_req.content().signer,
            now: TimeStamp::now(),
        })
        .is_err()
        {
            Self::observe_approval_event("tally_rejected");
            warn!(
                msg_type = "TallyProposal",
                approval_req_hash = %approval_req_hash,
                "Tally proposal failed verification"
            );
            return Ok(());
        }

        let approval_data_hash = hash_borsh(&*self.hash.hasher(), &approval_data)
            .map_err(|e| ActorError::FunctionalCritical {
                description: format!("Can not hash approval data: {}", e),
            })?;

        let modified_metadata = Self::create_modified_metadata(
            approval_data.approved,
            collection.material.event_request.content(),
            collection.material.properties.clone(),
            collection.material.ledger_hash.clone(),
            collection.material.metadata.clone(),
        )
        .map_err(|e| ActorError::FunctionalCritical {
            description: format!("Can not build modified metadata: {}", e),
        })?;

        let meta_wo_props =
            MetadataWithoutProperties::from(modified_metadata.clone());
        let meta_wo_props_hash = hash_borsh(&*self.hash.hasher(), &meta_wo_props)
            .map_err(|e| ActorError::FunctionalCritical {
                description: e.to_string(),
            })?;
        let propierties_hash =
            hash_borsh(&*self.hash.hasher(), &modified_metadata.properties)
                .map_err(|e| ActorError::FunctionalCritical {
                    description: e.to_string(),
                })?;
        let event_request_hash =
            self.event_request_hash(&collection.material.event_request)
                .map_err(|e| ActorError::FunctionalCritical {
                    description: e.to_string(),
                })?;
        let viewpoints_hash = self
            .viewpoints_hash(collection.material.event_request.content())
            .map_err(|e| ActorError::FunctionalCritical {
                description: e.to_string(),
            })?;

        let response = ValidationRes::Response {
            vali_req_hash: collection.material.vali_req_hash.clone(),
            modified_metadata_without_propierties_hash: meta_wo_props_hash,
            propierties_hash,
            event_request_hash,
            viewpoints_hash,
            approval_data_hash: Some(approval_data_hash),
        };

        let signature = get_sign(
            ctx,
            SignTypesNode::ValidationRes(response.clone()),
        )
        .await?;

        match &collection.owner_route {
            OwnerRoute::Local => {
                let parent = ctx.get_parent::<Validation>().await?;
                parent
                    .tell(ValidationMessage::Response {
                        validation_res: Box::new(response),
                        sender: (*self.our_key).clone(),
                        signature: Some(signature),
                    })
                    .await?;
            }
            OwnerRoute::Network => {
                let signed_response: Signed<ValidationRes> =
                    Signed::from_parts(response, signature);
                let info = ComunicateInfo {
                    request_id: collection.request_id.clone(),
                    version: collection.version,
                    receiver: collection.requester.clone(),
                    receiver_actor: format!(
                        "/user/request/{}/validation/{}",
                        collection.subject_id, self.our_key
                    ),
                };

                self.network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info,
                            message: ActorMessage::ValidationRes {
                                res: signed_response,
                            },
                        },
                    })
                    .await?;
            }
        }

        Self::observe_approval_event("tally_accepted");
        self.approvals.remove(&approval_req_hash);
        self.pending = None;

        if self.stop {
            ctx.stop(None).await;
        }

        Ok(())
    }

    fn check_evaluation(
        &self,
        evaluation: EvaluationData,
        eval_data: RoleDataRegister,
        mut properties: ValueWrapper,
        event_request: &Signed<EventRequest>,
        metadata: &Metadata,
        gov_version: u64,
        req_subject_data_hash: DigestIdentifier,
        signer: PublicKey,
    ) -> Result<(bool, Option<ValueWrapper>, ValueWrapper), ValidatorError>
    {
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
            (true, EventRequestType::Transfer) => {
                EvaluateData::GovTransfer {
                    state: GovernanceData::try_from(
                        metadata.properties.clone(),
                    )
                    .map_err(|_| ValidatorError::InvalidData {
                        value: "evaluation gov state",
                    })?,
                }
            }
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
                sn: metadata.sn + 1,
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
            hash_borsh(&*self.hash.hasher(), &signed_eval_req).map_err(
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

        let eval_result_hash = hash_borsh(&*self.hash.hasher(), &eval_result)
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

            let properties_hash = hash_borsh(&*self.hash.hasher(), &properties)
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

    fn check_compilation(
        &self,
        compilation: CompilationData,
        comp_data: RoleDataRegister,
        event_request: &Signed<EventRequest>,
        metadata: &Metadata,
        gov_version: u64,
        req_subject_data_hash: DigestIdentifier,
        signer: PublicKey,
    ) -> Result<(), ValidatorError> {
        if signer != compilation.compile_req_signature.signer {
            return Err(ValidatorError::InvalidSigner {
                signer: signer.to_string(),
            });
        }

        // The compilation request is fully determined by the event under
        // validation (signed event request, governance, sn and governance
        // version), so it is rebuilt here: the stored request signature
        // must verify cryptographically over it and the stored request
        // hash must reproduce exactly. This closes the chain from the
        // event request to the compiler votes, which sign a result hash
        // embedding this request hash.
        let signed_compile_req = Signed::from_parts(
            CompilationReq {
                event_request: event_request.clone(),
                governance_id: metadata.governance_id.clone(),
                sn: metadata.sn + 1,
                gov_version,
            },
            compilation.compile_req_signature.clone(),
        );
        if signed_compile_req.verify().is_err() {
            return Err(ValidatorError::InvalidSignature {
                data: "compilation request",
            });
        }
        let recomputed_req_hash =
            hash_borsh(&*self.hash.hasher(), &signed_compile_req).map_err(
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

        let (compile_result, result_hash) = match compilation.response.clone() {
            CompilationResponse::Ok {
                result,
                result_hash,
            } => (
                CompilationResult::Ok {
                    response: result,
                    compile_req_hash: compilation.compile_req_hash.clone(),
                    req_subject_data_hash,
                },
                result_hash,
            ),
            CompilationResponse::Error {
                result,
                result_hash,
            } => (
                CompilationResult::Error {
                    error: result,
                    compile_req_hash: compilation.compile_req_hash.clone(),
                    req_subject_data_hash,
                },
                result_hash,
            ),
        };

        let compile_result_hash =
            hash_borsh(&*self.hash.hasher(), &compile_result).map_err(|e| {
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

        // The response must cover exactly the contracts this event sends
        // through the compilation phase: a missing schema would commit
        // without a ledger anchor and an extra one would overwrite the
        // anchor of a contract the event did not touch.
        if let CompilationResponse::Ok { result, .. } = &compilation.response
        {
            let EventRequest::Fact(fact_request) = event_request.content()
            else {
                return Err(ValidatorError::InvalidData {
                    value: "event request",
                });
            };
            let expected = schemas_to_compile(&fact_request.payload).ok_or(
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

    async fn check_actual_protocols(
        &self,
        ctx: &mut ActorContext<Self>,
        metadata: &Metadata,
        actual_protocols: &ActualProtocols,
        event_request: &Signed<EventRequest>,
        gov_version: u64,
        signer: PublicKey,
    ) -> Result<(Option<ValueWrapper>, Option<ApprovalContext>), ValidatorError>
    {
        let event_type = EventRequestType::from(event_request.content());

        if !actual_protocols
            .check_protocols(metadata.schema_id.is_gov(), &event_type)
        {
            return Err(ValidatorError::InvalidData {
                value: "actual protocols",
            });
        }

        let (compilation, evaluation, approval_req) = match &actual_protocols {
            ActualProtocols::None => (None, None, None),
            ActualProtocols::Eval { eval_data } => {
                (None, Some(eval_data.clone()), None)
            }
            ActualProtocols::EvalApprove {
                eval_data,
                approval_req,
            } => (None, Some(eval_data.clone()), Some(approval_req.clone())),
            ActualProtocols::Compile { compile_data } => {
                (Some(compile_data.clone()), None, None)
            }
            ActualProtocols::CompileEval {
                compile_data,
                eval_data,
            } => (Some(compile_data.clone()), Some(eval_data.clone()), None),
            ActualProtocols::CompileEvalApprove {
                compile_data,
                eval_data,
                approval_req,
            } => (
                Some(compile_data.clone()),
                Some(eval_data.clone()),
                Some(approval_req.clone()),
            ),
        };

        // In governance facts the compilation evidence must be present
        // exactly when the fact adds a schema or changes a contract (or
        // its initial value): the owner can not skip the phase nor add
        // it where it does not belong.
        if metadata.schema_id.is_gov()
            && matches!(event_type, EventRequestType::Fact)
        {
            let EventRequest::Fact(fact_request) = event_request.content()
            else {
                return Err(ValidatorError::InvalidData {
                    value: "event request",
                });
            };

            let needs_compilation = schemas_to_compile(&fact_request.payload)
                .is_some_and(|schemas| !schemas.is_empty());

            if needs_compilation != compilation.is_some() {
                return Err(ValidatorError::InvalidData {
                    value: "compilation evidence",
                });
            }
        }

        let (properties, approval_ctx) = if compilation.is_some()
            || evaluation.is_some()
        {
            let req_subject_data_hash = hash_borsh(
                &*self.hash.hasher(),
                &RequestSubjectData {
                    subject_id: metadata.subject_id.clone(),
                    governance_id: metadata.governance_id.clone(),
                    sn: metadata.sn + 1,
                    namespace: metadata.namespace.clone(),
                    schema_id: metadata.schema_id.clone(),
                    gov_version,
                    signer: signer.clone(),
                },
            )
            .map_err(|e| ValidatorError::InternalError {
                problem: e.to_string(),
            })?;

            let (eval_data, comp_data, appro_data) = if gov_version
                == self.gov_version
            {
                (
                    self.current_evaluation_roles(),
                    compilation
                        .as_ref()
                        .map(|_| self.current_compilation_roles()),
                    approval_req
                        .as_ref()
                        .map(|_| self.current_approval_roles()),
                )
            } else {
                let (eval_roles, appro_roles, comp_roles) =
                    get_actual_roles_register(
                        ctx,
                        &metadata.governance_id,
                        SearchRole {
                            schema_id: metadata.schema_id.clone(),
                            namespace: metadata.namespace.clone(),
                        },
                        approval_req.is_some(),
                        compilation.is_some(),
                        gov_version,
                    )
                    .await
                    .map_err(|e| {
                        if let ActorError::UnexpectedResponse { .. } = e {
                            ValidatorError::OutOfVersion
                        } else {
                            ValidatorError::InternalError {
                                problem: e.to_string(),
                            }
                        }
                    })?;

                (eval_roles, comp_roles, appro_roles)
            };

            if let Some(compilation) = compilation {
                let Some(comp_data) = comp_data else {
                    return Err(ValidatorError::InvalidData {
                        value: "compilation roles",
                    });
                };

                self.check_compilation(
                    compilation,
                    comp_data,
                    event_request,
                    metadata,
                    gov_version,
                    req_subject_data_hash.clone(),
                    signer.clone(),
                )?;
            }

            if let Some(evaluation) = evaluation {
                let (appr_required, req_patch, properties) = self
                    .check_evaluation(
                        evaluation,
                        eval_data,
                        metadata.properties.clone(),
                        event_request,
                        metadata,
                        gov_version,
                        req_subject_data_hash.clone(),
                        signer.clone(),
                    )?;

                let approval_ctx = if let Some(approval_req) = approval_req
                    && let Some(approvers) = appro_data
                {
                    if !appr_required {
                        return Err(ValidatorError::InvalidData {
                            value: "evaluation appr_required",
                        });
                    }

                    // Approval requires a successful evaluation: its
                    // request carries the evaluated patch.
                    let Some(req_patch) = req_patch else {
                        return Err(ValidatorError::InvalidData {
                            value: "approval patch",
                        });
                    };

                    let min_window = Duration::from_secs(
                        Self::approval_config(ctx)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?
                            .min_window_secs,
                    );
                    Self::check_approval_req(
                        &approval_req,
                        metadata,
                        gov_version,
                        &req_patch,
                        &signer,
                        min_window,
                    )?;

                    let approval_req_hash = hash_borsh(
                        &*self.hash.hasher(),
                        approval_req.content(),
                    )
                    .map_err(|e| ValidatorError::InternalError {
                        problem: e.to_string(),
                    })?;

                    Some(ApprovalContext {
                        approval_req,
                        approval_req_hash,
                        approvers,
                        req_subject_data_hash,
                    })
                } else if appr_required {
                    return Err(ValidatorError::InvalidData {
                        value: "evaluation appr_required",
                    });
                } else {
                    None
                };

                (Some(properties), approval_ctx)
            } else {
                (None, None)
            }
        } else {
            (None, None)
        };

        Ok((properties, approval_ctx))
    }

    async fn check_last_vali_data(
        &self,
        ctx: &mut ActorContext<Self>,
        metadata: &Metadata,
        last_validation: &LastData,
    ) -> Result<(), ValidatorError> {
        let vali_data = get_validation_roles_register(
            ctx,
            &metadata.governance_id,
            SearchRole {
                schema_id: metadata.schema_id.clone(),
                namespace: metadata.namespace.clone(),
            },
            last_validation.gov_version,
        )
        .await
        .map_err(|e| {
            if let ActorError::UnexpectedResponse { .. } = e {
                ValidatorError::InvalidData {
                    value: "gov_version",
                }
            } else {
                ValidatorError::InternalError {
                    problem: e.to_string(),
                }
            }
        })?;

        if !check_quorum_signers(
            &last_validation
                .vali_data
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &vali_data.quorum,
            &vali_data.workers,
        ) {
            return Err(ValidatorError::InvalidOperation {
                action: "verify validation quorum",
            });
        }

        let vali_req_hash =
            last_validation.vali_data.validation_req_hash.clone();
        let vali_res = if metadata.sn == 0 {
            ValidationRes::Create {
                vali_req_hash,
                subject_metadata: Box::new(metadata.clone()),
            }
        } else {
            let ValidationMetadata::ModifiedHash {
                event_request_hash,
                viewpoints_hash,
                ..
            } = &last_validation.vali_data.validation_metadata
            else {
                return Err(ValidatorError::InvalidData {
                    value: "last validation metadata",
                });
            };

            let meta_wo_props =
                MetadataWithoutProperties::from(metadata.clone());
            let meta_wo_props_hash =
                hash_borsh(&*self.hash.hasher(), &meta_wo_props).map_err(
                    |e| ValidatorError::InternalError {
                        problem: e.to_string(),
                    },
                )?;

            let propierties_hash =
                hash_borsh(&*self.hash.hasher(), &metadata.properties)
                    .map_err(|e| ValidatorError::InternalError {
                        problem: e.to_string(),
                    })?;

            ValidationRes::Response {
                vali_req_hash,
                modified_metadata_without_propierties_hash: meta_wo_props_hash,
                propierties_hash,
                event_request_hash: event_request_hash.clone(),
                viewpoints_hash: viewpoints_hash.clone(),
                approval_data_hash: last_validation.approval_data_hash.clone(),
            }
        };

        for signature in last_validation.vali_data.validators_signatures.iter()
        {
            let signed_res =
                Signed::from_parts(vali_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(ValidatorError::InvalidSignature {
                    data: "last validation",
                });
            }
        }

        Ok(())
    }

    fn create_modified_metadata(
        is_success: bool,
        event_request: &EventRequest,
        properties: Option<ValueWrapper>,
        ledger_hash: DigestIdentifier,
        mut metadata: Metadata,
    ) -> Result<Metadata, ValidatorError> {
        metadata.sn += 1;

        metadata.prev_ledger_event_hash = ledger_hash;

        if !is_success {
            return Ok(metadata);
        }

        match event_request {
            EventRequest::Create(..) => {
                return Err(ValidatorError::InvalidData {
                    value: "Event request type",
                });
            }
            EventRequest::Fact(..) => {
                if let Some(properties) = properties {
                    metadata.properties = properties;
                }
            }
            EventRequest::Transfer(transfer_request) => {
                metadata.new_owner = Some(transfer_request.new_owner.clone());
            }
            EventRequest::Confirm(..) => {
                if let Some(new_owner) = metadata.new_owner.take() {
                    metadata.owner = new_owner;
                } else {
                    return Err(ValidatorError::InvalidData {
                        value: "new owner",
                    });
                }

                if let Some(properties) = properties {
                    metadata.properties = properties;
                }
            }
            EventRequest::Reject(..) => metadata.new_owner = None,
            EventRequest::EOL(..) => metadata.active = false,
        }

        if metadata.schema_id.is_gov() {
            let mut gov_data =
                serde_json::from_value::<GovernanceData>(metadata.properties.0)
                    .map_err(|_| ValidatorError::InvalidData {
                        value: "metadata properties",
                    })?;

            gov_data.version += 1;
            metadata.properties = gov_data.to_value_wrapper();
        }

        Ok(metadata)
    }

    async fn create_res(
        &self,
        ctx: &mut ActorContext<Self>,
        validation_req: &Signed<ValidationReq>,
        owner_route: OwnerRoute,
        requester: PublicKey,
        request_id: String,
        version: u64,
    ) -> Result<WorkerVerdict, ValidatorError> {
        match validation_req.content() {
            ValidationReq::Create {
                event_request,
                gov_version,
                subject_id,
            } => {
                if let EventRequest::Create(create) = event_request.content() {
                    if let Some(name) = &create.name
                        && (name.is_empty() || name.len() > 100)
                    {
                        return Err(ValidatorError::InvalidData {
                            value: "create event name",
                        });
                    }

                    if let Some(description) = &create.description
                        && (description.is_empty() || description.len() > 200)
                    {
                        return Err(ValidatorError::InvalidData {
                            value: "create event description",
                        });
                    }

                    if !create.schema_id.is_valid_in_request() {
                        return Err(ValidatorError::InvalidData {
                            value: "create event schema_id",
                        });
                    }

                    if create.schema_id.is_gov() {
                        if !create.governance_id.is_empty() {
                            return Err(ValidatorError::InvalidData {
                                value: "create event governance_id",
                            });
                        }

                        if !create.namespace.is_empty() {
                            return Err(ValidatorError::InvalidData {
                                value: "create event namespace",
                            });
                        }
                    } else if create.governance_id.is_empty() {
                        return Err(ValidatorError::InvalidData {
                            value: "create event governance_id",
                        });
                    }

                    let subject_id_worker =
                        hash_borsh(&*self.hash.hasher(), &event_request)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                    if subject_id != &subject_id_worker {
                        return Err(ValidatorError::InvalidData {
                            value: "subject_id",
                        });
                    }

                    let init_state = self.init_state.as_ref().map_or_else(
                        || {
                            let governance_data = GovernanceData::new(
                                validation_req.signature().signer.clone(),
                            );

                            governance_data.to_value_wrapper()
                        },
                        |init_state| init_state.clone(),
                    );

                    let governance_id = if create.schema_id.is_gov() {
                        subject_id.clone()
                    } else {
                        create.governance_id.clone()
                    };

                    let subject_metadata = Metadata {
                        name: create.name.clone(),
                        description: create.description.clone(),
                        subject_id: subject_id_worker,
                        governance_id,
                        genesis_gov_version: *gov_version,
                        prev_ledger_event_hash: DigestIdentifier::default(),
                        schema_id: create.schema_id.clone(),
                        namespace: create.namespace.clone(),
                        sn: 0,
                        creator: validation_req.signature().signer.clone(),
                        owner: validation_req.signature().signer.clone(),
                        new_owner: None,
                        active: true,
                        properties: init_state,
                    };

                    let vali_req_hash =
                        hash_borsh(&*self.hash.hasher(), &validation_req)
                            .map_err(|e| ValidatorError::InternalError {
                                problem: e.to_string(),
                            })?;

                    Ok(WorkerVerdict::Final(ValidationRes::Create {
                        vali_req_hash,
                        subject_metadata: Box::new(subject_metadata),
                    }))
                } else {
                    Err(ValidatorError::InvalidData {
                        value: "event type",
                    })
                }
            }
            ValidationReq::Event {
                actual_protocols,
                event_request,
                metadata,
                last_data,
                gov_version,
                sn,
                ledger_hash,
            } => {
                let signer = validation_req.signature().signer.clone();
                Self::check_basic_data(
                    event_request,
                    metadata,
                    &signer,
                    *gov_version,
                    *sn,
                )?;

                let (properties, approval_ctx) = self
                    .check_actual_protocols(
                        ctx,
                        metadata,
                        actual_protocols,
                        event_request,
                        *gov_version,
                        signer,
                    )
                    .await?;

                self.check_last_vali_data(ctx, metadata, last_data).await?;

                let vali_req_hash =
                    hash_borsh(&*self.hash.hasher(), &validation_req).map_err(
                        |e| ValidatorError::InternalError {
                            problem: e.to_string(),
                        },
                    )?;

                if let Some(approval_ctx) = approval_ctx {
                    // The request needs approval: the verdict arrives when
                    // the collection closes. Everything needed for the
                    // final response is stored with the collection.
                    return Ok(WorkerVerdict::Collecting(Box::new(
                        ApprovalCollection {
                            requester,
                            request_id,
                            version,
                            owner_route,
                            subject_id: metadata.subject_id.clone(),
                            governance_id: metadata.governance_id.clone(),
                            gov_version: *gov_version,
                            approval_req: approval_ctx.approval_req,
                            approval_req_hash: approval_ctx.approval_req_hash,
                            approvers: approval_ctx.approvers,
                            req_subject_data_hash: approval_ctx
                                .req_subject_data_hash,
                            votes: HashMap::new(),
                            double_votes: Vec::new(),
                            timeouts: HashMap::new(),
                            timeouts_signed: false,
                            material: ResponseMaterial {
                                vali_req_hash,
                                event_request: event_request.clone(),
                                metadata: (**metadata).clone(),
                                properties,
                                ledger_hash: ledger_hash.clone(),
                            },
                        },
                    )));
                }

                // No approval: the `approved` flag only applies to the
                // approve variants, absent here.
                let is_success = actual_protocols.is_success(false);

                let modified_metadata = Self::create_modified_metadata(
                    is_success,
                    event_request.content(),
                    properties,
                    ledger_hash.clone(),
                    *metadata.clone(),
                )?;

                let meta_wo_props =
                    MetadataWithoutProperties::from(modified_metadata.clone());
                let meta_wo_props_hash =
                    hash_borsh(&*self.hash.hasher(), &meta_wo_props).map_err(
                        |e| ValidatorError::InternalError {
                            problem: e.to_string(),
                        },
                    )?;

                let propierties_hash = hash_borsh(
                    &*self.hash.hasher(),
                    &modified_metadata.properties,
                )
                .map_err(|e| {
                    ValidatorError::InternalError {
                        problem: e.to_string(),
                    }
                })?;

                let event_request_hash =
                    self.event_request_hash(event_request)?;
                let viewpoints_hash =
                    self.viewpoints_hash(event_request.content())?;

                Ok(WorkerVerdict::Final(ValidationRes::Response {
                    vali_req_hash,
                    modified_metadata_without_propierties_hash:
                        meta_wo_props_hash,
                    propierties_hash,
                    event_request_hash,
                    viewpoints_hash,
                    approval_data_hash: None,
                }))
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum ValiWorkerMessage {
    UpdateCurrentRoles {
        gov_version: u64,
        current_roles: CurrentWorkerRoles,
    },
    LocalValidation {
        validation_req: Box<Signed<ValidationReq>>,
        request_id: String,
        version: u64,
    },
    NetworkRequest {
        validation_req: Box<Signed<ValidationReq>>,
        sender: PublicKey,
        info: ComunicateInfo,
    },
    /// An approver answered a vote probe.
    ApprovalResponse {
        approval_res: Box<Signed<ApprovalRes>>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
    /// The requester asks for the votes collected so far (keepalive).
    ApprovalStatusReq {
        approval_req_hash: DigestIdentifier,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
    /// The requester proposes the canonical tally for signature.
    TallyProposal {
        approval_data: Box<ApprovalData>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
    /// Self-scheduled vote probe round.
    Probe {
        approval_req_hash: DigestIdentifier,
        attempt: usize,
    },
    /// Self-scheduled deadline of a collection: sign and push the timeout
    /// attestations for the approvers that never answered.
    ApprovalDeadline { approval_req_hash: DigestIdentifier },
    /// Self-scheduled absolute TTL of a collection.
    ExpireCollection { approval_req_hash: DigestIdentifier },
}

impl Message for ValiWorkerMessage {}

#[async_trait]
impl Actor for ValiWorker {
    type Event = ();
    type Message = ValiWorkerMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ValiWorker", id),
            |parent_span| info_span!(parent: parent_span, "ValiWorker", id),
        )
    }

    /// On any stop (graceful shutdown, controlled crash or fault) with a
    /// network validation still in flight, tell the requester this
    /// validator is unavailable so it can replace it without waiting for
    /// the coordinator retries.
    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        self.notify_unavailable(ctx).await;
        Ok(())
    }
}

impl NotPersistentActor for ValiWorker {}

#[async_trait]
impl Handler<Self> for ValiWorker {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: ValiWorkerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ValiWorkerMessage::UpdateCurrentRoles {
                gov_version,
                current_roles,
            } => {
                self.gov_version = gov_version;
                self.current_roles = current_roles;
            }
            ValiWorkerMessage::LocalValidation {
                validation_req,
                request_id,
                version,
            } => {
                let verdict = match self
                    .create_res(
                        ctx,
                        &validation_req,
                        OwnerRoute::Local,
                        (*self.our_key).clone(),
                        request_id,
                        version,
                    )
                    .await
                {
                    Ok(verdict) => verdict,
                    Err(e) => {
                        if matches!(e, ValidatorError::OutOfVersion) {
                            WorkerVerdict::Final(ValidationRes::Reboot)
                        } else {
                            return Err(crash_system(
                                ctx,
                                ActorError::FunctionalCritical {
                                    description: e.to_string(),
                                },
                            )
                            .await);
                        }
                    }
                };

                let validation = match verdict {
                    WorkerVerdict::Final(validation) => validation,
                    WorkerVerdict::Collecting(collection) => {
                        // ACK the parent: the final response arrives when
                        // the approval collection closes.
                        match ctx.get_parent::<Validation>().await {
                            Ok(validation_actor) => {
                                validation_actor
                                    .tell(ValidationMessage::Working {
                                        sender: (*self.our_key).clone(),
                                    })
                                    .await?;
                            }
                            Err(e) => {
                                error!(
                                    msg_type = "LocalValidation",
                                    "Failed to obtain Validation actor"
                                );
                                return Err(e);
                            }
                        }

                        if let Err(e) =
                            self.start_collection(ctx, *collection).await
                        {
                            error!(
                                msg_type = "LocalValidation",
                                error = %e,
                                "Failed to start approval collection"
                            );
                            return Err(crash_system(ctx, e).await);
                        }

                        return Ok(());
                    }
                };

                let signature = match get_sign(
                    ctx,
                    SignTypesNode::ValidationRes(validation.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            msg_type = "LocalValidation",
                            error = %e,
                            "Failed to sign validator response"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                };

                match ctx.get_parent::<Validation>().await {
                    Ok(validation_actor) => {
                        validation_actor
                            .tell(ValidationMessage::Response {
                                validation_res: Box::new(validation),
                                sender: (*self.our_key).clone(),
                                signature: Some(signature),
                            })
                            .await?;

                        debug!(
                            msg_type = "LocalValidation",
                            "Validation completed and sent to parent"
                        );
                    }
                    Err(e) => {
                        error!(
                            msg_type = "LocalValidation",
                            "Failed to obtain Validation actor"
                        );
                        return Err(e);
                    }
                };

                ctx.stop(None).await;
            }
            ValiWorkerMessage::NetworkRequest {
                validation_req,
                info,
                sender,
            } => {
                if sender != validation_req.signature().signer
                    || sender != self.node_key
                {
                    warn!(
                        msg_type = "NetworkRequest",
                        expected_sender = %self.node_key,
                        received_sender = %sender,
                        signer = %validation_req.signature().signer,
                        "Unexpected sender"
                    );
                    if self.stop {
                        ctx.stop(None).await;
                    }

                    return Ok(());
                }

                self.pending = Some(PendingValidation {
                    sender: sender.clone(),
                    request_id: info.request_id.clone(),
                    version: info.version,
                    subject_id: validation_req.content().get_subject_id(),
                });

                let verdict = if let Err(error) =
                    self.check_data(&validation_req)
                {
                    WorkerVerdict::Final(ValidationRes::Abort(
                        error.to_string(),
                    ))
                } else {
                    match gov_version_sync(
                        self.gov_version,
                        validation_req.content().get_gov_version(),
                    ) {
                        // This node is behind the request's governance
                        // version and can not validate it: say so instead
                        // of staying silent — the requester replaces this
                        // validator from its pending pool.
                        GovVersionSync::NodeBehind => {
                            warn!(
                                msg_type = "NetworkRequest",
                                local_gov_version = self.gov_version,
                                request_gov_version = validation_req.content().get_gov_version(),
                                governance_id = %self.governance_id,
                                sender = %self.node_key,
                                "Request governance version is higher than local; answering unavailable"
                            );
                            WorkerVerdict::Final(ValidationRes::Unavailable)
                        }
                        // The requester is behind: it must sync its
                        // governance and retry the request.
                        GovVersionSync::RequesterBehind => {
                            WorkerVerdict::Final(ValidationRes::Reboot)
                        }
                        GovVersionSync::Current => {
                            match self
                                .create_res(
                                    ctx,
                                    &validation_req,
                                    OwnerRoute::Network,
                                    sender.clone(),
                                    info.request_id.clone(),
                                    info.version,
                                )
                                .await
                            {
                                Ok(verdict) => verdict,
                                Err(e) => {
                                    if let ValidatorError::InternalError {
                                        ..
                                    } = e
                                    {
                                        error!(
                                            msg_type = "NetworkRequest",
                                            error = %e,
                                            "Internal error during validation"
                                        );

                                        return Err(crash_system(
                                            ctx,
                                            ActorError::FunctionalCritical {
                                                description: e.to_string(),
                                            },
                                        )
                                        .await);
                                    } else if matches!(
                                        e,
                                        ValidatorError::OutOfVersion
                                    ) {
                                        WorkerVerdict::Final(
                                            ValidationRes::Reboot,
                                        )
                                    } else {
                                        WorkerVerdict::Final(
                                            ValidationRes::Abort(
                                                e.to_string(),
                                            ),
                                        )
                                    }
                                }
                            }
                        }
                    }
                };

                let (validation, collection) = match verdict {
                    WorkerVerdict::Final(validation) => (validation, None),
                    WorkerVerdict::Collecting(collection) => {
                        // ACK the requester: the final response arrives
                        // when the approval collection closes.
                        (ValidationRes::Working, Some(collection))
                    }
                };

                let signature = match get_sign(
                    ctx,
                    SignTypesNode::ValidationRes(validation.clone()),
                )
                .await
                {
                    Ok(signature) => signature,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to sign validation response"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                };

                let new_info = ComunicateInfo {
                    receiver: sender,
                    request_id: info.request_id,
                    version: info.version,
                    receiver_actor: format!(
                        "/user/request/{}/validation/{}",
                        validation_req.content().get_subject_id(),
                        self.our_key.clone()
                    ),
                };

                let signed_response: Signed<ValidationRes> =
                    Signed::from_parts(validation, signature);
                if let Err(e) = self
                    .network
                    .send_command(ave_network::CommandHelper::SendMessage {
                        message: NetworkMessage {
                            info: new_info.clone(),
                            message: ActorMessage::ValidationRes {
                                res: signed_response,
                            },
                        },
                    })
                    .await
                {
                    error!(
                        msg_type = "NetworkRequest",
                        error = %e,
                        "Failed to send response to network"
                    );
                    return Err(crash_system(ctx, e).await);
                }
                debug!(
                    msg_type = "NetworkRequest",
                    receiver = %new_info.receiver,
                    request_id = %new_info.request_id,
                    "Validation response sent to network"
                );

                if let Some(collection) = collection {
                    // The collection is in flight: the pending slot stays
                    // armed until the final response, and this worker
                    // keeps running.
                    if let Err(e) =
                        self.start_collection(ctx, *collection).await
                    {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Failed to start approval collection"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                } else {
                    self.pending = None;

                    if self.stop {
                        ctx.stop(None).await;
                    }
                }
            }
            ValiWorkerMessage::ApprovalResponse {
                approval_res,
                request_id,
                version,
                sender,
            } => {
                if approval_res.verify().is_err() {
                    warn!(
                        msg_type = "ApprovalResponse",
                        sender = %sender,
                        "Approval response with invalid signature"
                    );
                    return Ok(());
                }

                // An approver ahead of the request's governance version
                // aborts it: the requester built on a stale governance.
                // Forwarded as a validator abort; Pending/Unavailable
                // carry no request hash and the probe schedule keeps
                // asking until the deadline.
                if let ApprovalRes::Abort(reason) = approval_res.content() {
                    let Some(approval_req_hash) = self
                        .approvals
                        .iter()
                        .find(|(_, collection)| {
                            collection.request_id == request_id
                                && collection.version == version
                        })
                        .map(|(hash, _)| hash.clone())
                    else {
                        debug!(
                            msg_type = "ApprovalResponse",
                            sender = %sender,
                            "Approval abort for an unknown or closed collection"
                        );
                        return Ok(());
                    };

                    let abort = {
                        let Some(collection) =
                            self.approvals.get(&approval_req_hash)
                        else {
                            return Ok(());
                        };

                        if sender != approval_res.signature().signer
                            || !collection.approvers.workers.contains(&sender)
                        {
                            warn!(
                                msg_type = "ApprovalResponse",
                                sender = %sender,
                                "Approval abort from an unexpected approver"
                            );
                            return Ok(());
                        }

                        self.forward_approval_abort(
                            ctx,
                            collection,
                            reason.clone(),
                        )
                        .await
                    };

                    if let Err(e) = abort {
                        error!(
                            msg_type = "ApprovalResponse",
                            error = %e,
                            "Failed to forward approval abort"
                        );
                        return Err(crash_system(ctx, e).await);
                    }

                    self.approvals.remove(&approval_req_hash);
                    return Ok(());
                }

                let ApprovalRes::Response {
                    approval_req_hash,
                    agrees,
                    req_subject_data_hash,
                } = approval_res.content().clone()
                else {
                    if matches!(
                        approval_res.content(),
                        ApprovalRes::Pending
                    ) {
                        Self::observe_approval_event("pending");
                    }
                    debug!(
                        msg_type = "ApprovalResponse",
                        sender = %sender,
                        response = ?approval_res.content(),
                        "Approver has no vote yet"
                    );
                    return Ok(());
                };

                enum VoteMerge {
                    New,
                    Duplicate,
                    Double,
                }

                let merge = {
                    let Some(collection) =
                        self.approvals.get_mut(&approval_req_hash)
                    else {
                        debug!(
                            msg_type = "ApprovalResponse",
                            approval_req_hash = %approval_req_hash,
                            sender = %sender,
                            "Vote for an unknown or closed collection"
                        );
                        return Ok(());
                    };

                    if request_id != collection.request_id
                        || version != collection.version
                    {
                        return Ok(());
                    }

                    if sender != approval_res.signature().signer
                        || !collection.approvers.workers.contains(&sender)
                    {
                        warn!(
                            msg_type = "ApprovalResponse",
                            sender = %sender,
                            "Vote from an unexpected approver"
                        );
                        return Ok(());
                    }

                    if req_subject_data_hash
                        != collection.req_subject_data_hash
                    {
                        warn!(
                            msg_type = "ApprovalResponse",
                            sender = %sender,
                            "Vote subject data hash mismatch"
                        );
                        return Ok(());
                    }

                    if let Some(previous) = collection.votes.get(&sender) {
                        let previous_agrees = matches!(
                            previous.content(),
                            ApprovalRes::Response { agrees: true, .. }
                        );
                        if previous_agrees == agrees {
                            VoteMerge::Duplicate
                        } else if let Some(previous) =
                            collection.votes.remove(&sender)
                        {
                            // Conflicting votes: the approver is excluded
                            // from both tallies and counted as absent; the
                            // pair is the evidence.
                            let (accept, reject) = if agrees {
                                (*approval_res.clone(), previous)
                            } else {
                                (previous, *approval_res.clone())
                            };
                            collection.double_votes.push((accept, reject));
                            // The answer wins over any timeout attestation
                            // this validator signed for the approver.
                            collection.timeouts.remove(&sender);
                            VoteMerge::Double
                        } else {
                            VoteMerge::Duplicate
                        }
                    } else {
                        collection
                            .votes
                            .insert(sender.clone(), *approval_res.clone());
                        // The answer wins over any timeout attestation this
                        // validator signed for the approver.
                        collection.timeouts.remove(&sender);
                        VoteMerge::New
                    }
                };

                match merge {
                    VoteMerge::Duplicate => {}
                    VoteMerge::New | VoteMerge::Double => {
                        if matches!(merge, VoteMerge::Double) {
                            Self::observe_approval_event(
                                "double_vote_excluded",
                            );
                        } else {
                            Self::observe_approval_event("vote_received");
                        }

                        if let Some(collection) =
                            self.approvals.get(&approval_req_hash).cloned()
                            && let Err(error) = self
                                .push_vote_report(
                                    ctx,
                                    &collection,
                                    *approval_res,
                                )
                                .await
                        {
                            warn!(
                                msg_type = "ApprovalResponse",
                                error = %error,
                                "Failed to push vote report to the requester"
                            );
                        }
                    }
                }
            }
            ValiWorkerMessage::ApprovalStatusReq {
                approval_req_hash,
                request_id,
                version,
                sender,
            } => {
                let Some(collection) = self.approvals.get(&approval_req_hash)
                else {
                    return Ok(());
                };

                if sender != collection.requester
                    || request_id != collection.request_id
                    || version != collection.version
                {
                    warn!(
                        msg_type = "ApprovalStatusReq",
                        sender = %sender,
                        "Status request from an unexpected requester"
                    );
                    return Ok(());
                }

                let collection = collection.clone();
                if let Err(error) =
                    self.send_status_to_owner(ctx, &collection).await
                {
                    warn!(
                        msg_type = "ApprovalStatusReq",
                        error = %error,
                        "Failed to send collection status to the requester"
                    );
                }
            }
            ValiWorkerMessage::TallyProposal {
                approval_data,
                request_id,
                version,
                sender,
            } => {
                let matches_request = self
                    .approvals
                    .get(&approval_data.approval_req_hash)
                    .is_some_and(|collection| {
                        sender == collection.requester
                            && request_id == collection.request_id
                            && version == collection.version
                    });

                if !matches_request {
                    warn!(
                        msg_type = "TallyProposal",
                        sender = %sender,
                        "Tally proposal from an unexpected requester"
                    );
                    return Ok(());
                }

                if let Err(e) =
                    self.finish_collection(ctx, *approval_data).await
                {
                    error!(
                        msg_type = "TallyProposal",
                        error = %e,
                        "Failed to finish approval collection"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValiWorkerMessage::Probe {
                approval_req_hash,
                attempt,
            } => {
                if let Err(e) =
                    self.probe_approvers(ctx, &approval_req_hash, attempt).await
                {
                    error!(
                        msg_type = "Probe",
                        error = %e,
                        "Failed to probe approvers"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValiWorkerMessage::ApprovalDeadline { approval_req_hash } => {
                if let Err(e) =
                    self.sign_timeouts(ctx, &approval_req_hash).await
                {
                    error!(
                        msg_type = "ApprovalDeadline",
                        error = %e,
                        "Failed to sign timeout attestations"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValiWorkerMessage::ExpireCollection { approval_req_hash } => {
                if let Some(collection) =
                    self.approvals.remove(&approval_req_hash)
                {
                    debug!(
                        msg_type = "ExpireCollection",
                        approval_req_hash = %approval_req_hash,
                        "Approval collection expired"
                    );

                    if self
                        .pending
                        .as_ref()
                        .is_some_and(|pending| {
                            pending.request_id == collection.request_id
                        })
                    {
                        self.pending = None;
                    }

                    if self.stop {
                        ctx.stop(None).await;
                    }
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        compilation::response::CompilerResponse,
        evaluation::response::EvaluatorResponse,
        governance::model::Quorum,
    };
    use ave_common::{
        Namespace, SchemaType,
        governance::{GovernanceEvent, SchemaAdd, SchemasEvent},
        identity::{KeyPair, Signature, keys::Ed25519Signer},
        request::FactRequest,
    };
    use std::collections::BTreeMap;
    use tokio::sync::mpsc;

    fn public_key(signer: &Ed25519Signer) -> PublicKey {
        KeyPair::Ed25519(signer.clone()).public_key()
    }

    fn test_worker() -> ValiWorker {
        let node_key = public_key(&Ed25519Signer::generate().unwrap());
        let (sender, _receiver) = mpsc::channel(1);
        #[cfg(feature = "test")]
        let network = Arc::new(NetworkSender::new(
            sender.clone(),
            Arc::new(std::sync::Mutex::new(
                crate::helpers::network::test_faults::TestFaultRegistry::new(
                    sender,
                ),
            )),
        ));
        #[cfg(not(feature = "test"))]
        let network = Arc::new(NetworkSender::new(sender));

        let empty_roles = || RoleDataRegister {
            workers: HashSet::new(),
            quorum: Quorum::Majority,
        };
        ValiWorker {
            node_key: node_key.clone(),
            our_key: Arc::new(node_key),
            init_state: None,
            governance_id: DigestIdentifier::default(),
            gov_version: 0,
            sn: 0,
            hash: HashAlgorithm::Blake3,
            network,
            current_roles: CurrentWorkerRoles {
                evaluation: empty_roles(),
                compilation: empty_roles(),
                approval: empty_roles(),
                validation: empty_roles(),
            },
            stop: false,
            pending: None,
            approvals: HashMap::new(),
        }
    }

    /// A governance fact event adding one schema, plus every piece of
    /// ledger-anchored data the validator rebuilds the phase requests
    /// from.
    struct PhaseFixture {
        worker: ValiWorker,
        owner: Ed25519Signer,
        compilers: Vec<Ed25519Signer>,
        evaluators: Vec<Ed25519Signer>,
        approvers: Vec<Ed25519Signer>,
        event_request: Signed<EventRequest>,
        metadata: Metadata,
        gov_version: u64,
        signer: PublicKey,
        req_subject_data_hash: DigestIdentifier,
    }

    impl PhaseFixture {
        fn new() -> Self {
            let worker = test_worker();
            let hasher = worker.hash.hasher();
            let owner = Ed25519Signer::generate().unwrap();
            let owner_pub = public_key(&owner);
            let gen_keys = || {
                vec![
                    Ed25519Signer::generate().unwrap(),
                    Ed25519Signer::generate().unwrap(),
                ]
            };

            let subject_id =
                hash_borsh(&*hasher, &b"governance subject".to_vec()).unwrap();
            let event_request = Signed::new(
                EventRequest::Fact(FactRequest {
                    subject_id: subject_id.clone(),
                    payload: ValueWrapper(
                        serde_json::to_value(GovernanceEvent {
                            members: None,
                            roles: None,
                            schemas: Some(SchemasEvent {
                                add: Some(HashSet::from([SchemaAdd {
                                    id: SchemaType::Type("Example".to_owned()),
                                    contract: "contract source".to_owned(),
                                    initial_value: serde_json::json!({
                                        "one": 0
                                    }),
                                    viewpoints: vec![],
                                }])),
                                remove: None,
                                change: None,
                            }),
                            policies: None,
                        })
                        .unwrap(),
                    ),
                    viewpoints: BTreeSet::new(),
                }),
                &owner,
            )
            .unwrap();

            let metadata = Metadata {
                name: Some("Gov".to_owned()),
                description: None,
                subject_id: subject_id.clone(),
                governance_id: subject_id.clone(),
                genesis_gov_version: 0,
                prev_ledger_event_hash: DigestIdentifier::default(),
                schema_id: SchemaType::Governance,
                namespace: Namespace::new(),
                sn: 0,
                creator: owner_pub.clone(),
                owner: owner_pub.clone(),
                new_owner: None,
                active: true,
                properties: GovernanceData::new(owner_pub.clone())
                    .to_value_wrapper(),
            };

            let req_subject_data_hash = hash_borsh(
                &*hasher,
                &RequestSubjectData {
                    subject_id: subject_id.clone(),
                    governance_id: subject_id,
                    sn: metadata.sn + 1,
                    namespace: metadata.namespace.clone(),
                    schema_id: metadata.schema_id.clone(),
                    gov_version: 0,
                    signer: owner_pub.clone(),
                },
            )
            .unwrap();

            Self {
                worker,
                owner,
                compilers: gen_keys(),
                evaluators: gen_keys(),
                approvers: gen_keys(),
                event_request,
                metadata,
                gov_version: 0,
                signer: owner_pub,
                req_subject_data_hash,
            }
        }

        fn roles(&self, signers: &[Ed25519Signer]) -> RoleDataRegister {
            RoleDataRegister {
                workers: signers.iter().map(public_key).collect(),
                quorum: Quorum::Majority,
            }
        }

        fn tampered_hash(&self) -> DigestIdentifier {
            hash_borsh(&*self.worker.hash.hasher(), &b"tampered".to_vec())
                .unwrap()
        }

        /// Compilation evidence signed by the owner and the compilers
        /// over the request the validator rebuilds, with the given
        /// response contracts.
        fn compilation_with_contracts(
            &self,
            contracts: BTreeMap<SchemaType, DigestIdentifier>,
        ) -> CompilationData {
            let hasher = self.worker.hash.hasher();
            let signed_req = Signed::new(
                CompilationReq {
                    event_request: self.event_request.clone(),
                    governance_id: self.metadata.governance_id.clone(),
                    sn: self.metadata.sn + 1,
                    gov_version: self.gov_version,
                },
                &self.owner,
            )
            .unwrap();
            let compile_req_hash = hash_borsh(&*hasher, &signed_req).unwrap();

            let response = CompilerResponse { contracts };
            let result = CompilationResult::Ok {
                response: response.clone(),
                compile_req_hash: compile_req_hash.clone(),
                req_subject_data_hash: self.req_subject_data_hash.clone(),
            };
            let result_hash = hash_borsh(&*hasher, &result).unwrap();
            let compilers_signatures = self
                .compilers
                .iter()
                .map(|s| Signature::new(&result_hash, s).unwrap())
                .collect();

            CompilationData {
                compile_req_signature: signed_req.signature().clone(),
                compile_req_hash,
                compilers_signatures,
                response: CompilationResponse::Ok { result: response, result_hash },
            }
        }

        fn honest_compilation(&self) -> CompilationData {
            let wasm_hash =
                hash_borsh(&*self.worker.hash.hasher(), &b"wasm".to_vec())
                    .unwrap();
            self.compilation_with_contracts(BTreeMap::from([(
                SchemaType::Type("Example".to_owned()),
                wasm_hash,
            )]))
        }

        fn check_compilation(
            &self,
            compilation: CompilationData,
        ) -> Result<(), ValidatorError> {
            self.worker.check_compilation(
                compilation,
                self.roles(&self.compilers),
                &self.event_request,
                &self.metadata,
                self.gov_version,
                self.req_subject_data_hash.clone(),
                self.signer.clone(),
            )
        }

        /// Evaluation evidence signed by the owner and the evaluators
        /// over the request the validator rebuilds. Returns the evidence
        /// and the evaluated patch, which feeds the approval request.
        fn honest_evaluation(&self) -> (EvaluationData, ValueWrapper) {
            let hasher = self.worker.hash.hasher();
            let signed_req = Signed::new(
                EvaluationReq {
                    event_request: self.event_request.clone(),
                    governance_id: self.metadata.governance_id.clone(),
                    data: EvaluateData::GovFact {
                        state: GovernanceData::try_from(
                            self.metadata.properties.clone(),
                        )
                        .unwrap(),
                    },
                    sn: self.metadata.sn + 1,
                    gov_version: self.gov_version,
                    namespace: self.metadata.namespace.clone(),
                    schema_id: self.metadata.schema_id.clone(),
                    signer: self.signer.clone(),
                    signer_is_owner: self.signer
                        == self.event_request.signature().signer,
                },
                &self.owner,
            )
            .unwrap();
            let eval_req_hash = hash_borsh(&*hasher, &signed_req).unwrap();

            let req_patch = ValueWrapper(serde_json::json!([
                { "op": "replace", "path": "/version", "value": 1 }
            ]));
            let mut patched = self.metadata.properties.0.clone();
            let patch_ops =
                serde_json::from_value::<Patch>(req_patch.0.clone()).unwrap();
            patch(&mut patched, &patch_ops).unwrap();
            let properties_hash =
                hash_borsh(&*hasher, &ValueWrapper(patched)).unwrap();

            let evaluator_response = EvaluatorResponse {
                patch: req_patch.clone(),
                properties_hash,
                appr_required: true,
            };
            let result = EvaluationResult::Ok {
                response: evaluator_response.clone(),
                eval_req_hash: eval_req_hash.clone(),
                req_subject_data_hash: self.req_subject_data_hash.clone(),
            };
            let result_hash = hash_borsh(&*hasher, &result).unwrap();
            let evaluators_signatures = self
                .evaluators
                .iter()
                .map(|s| Signature::new(&result_hash, s).unwrap())
                .collect();

            (
                EvaluationData {
                    eval_req_signature: signed_req.signature().clone(),
                    eval_req_hash,
                    evaluators_signatures,
                    response: EvaluationResponse::Ok {
                        result: evaluator_response,
                        result_hash,
                    },
                },
                req_patch,
            )
        }

        fn check_evaluation(
            &self,
            evaluation: EvaluationData,
        ) -> Result<(bool, Option<ValueWrapper>, ValueWrapper), ValidatorError>
        {
            self.worker.check_evaluation(
                evaluation,
                self.roles(&self.evaluators),
                self.metadata.properties.clone(),
                &self.event_request,
                &self.metadata,
                self.gov_version,
                self.req_subject_data_hash.clone(),
                self.signer.clone(),
            )
        }

        /// Approval evidence signed by the owner and the approvers over
        /// the request the validator rebuilds for the given patch.
        fn honest_approval(&self, patch: ValueWrapper) -> ApprovalData {
            let hasher = self.worker.hash.hasher();
            let issued_at = TimeStamp::now();
            let deadline =
                TimeStamp::from_nanos(issued_at.as_nanos() + 7_000_000_000);
            let approval_req = ApprovalReq {
                subject_id: self.metadata.subject_id.clone(),
                sn: self.metadata.sn + 1,
                gov_version: self.gov_version,
                patch,
                signer: self.signer.clone(),
                issued_at,
                deadline,
            };
            let signed_req = Signed::new(approval_req.clone(), &self.owner)
                .unwrap();
            // The approval phase hashes the request content, not the
            // signed envelope (unlike compilation and evaluation).
            let approval_req_hash =
                hash_borsh(&*hasher, &approval_req).unwrap();
            let mut approvers_agrees_signatures: Vec<Signature> = self
                .approvers
                .iter()
                .map(|s| {
                    Signed::new(
                        ApprovalRes::Response {
                            approval_req_hash: approval_req_hash.clone(),
                            agrees: true,
                            req_subject_data_hash: self
                                .req_subject_data_hash
                                .clone(),
                        },
                        s,
                    )
                    .unwrap()
                    .signature()
                    .clone()
                })
                .collect();
            // The tally is canonical: every list is ordered by signer
            // public key.
            approvers_agrees_signatures
                .sort_by(|a, b| a.signer.cmp(&b.signer));

            ApprovalData {
                approval_req_signature: signed_req.signature().clone(),
                approval_req_hash,
                issued_at,
                deadline,
                approvers_agrees_signatures,
                approvers_disagrees_signatures: vec![],
                double_votes: vec![],
                approvers_timeouts: vec![],
                approved: true,
            }
        }

        /// The tally evidence is verified with the same shared routine
        /// the worker uses before signing a tally proposal.
        fn check_approval(
            &self,
            approval: ApprovalData,
            patch: ValueWrapper,
        ) -> Result<(), ValidatorError> {
            verify_approval_data(ApprovalVerification {
                hash: &self.worker.hash,
                approval: &approval,
                approvers: &self.roles(&self.approvers),
                validators: &self.roles(&[]),
                req_subject_data_hash: &self.req_subject_data_hash,
                subject_id: &self.metadata.subject_id,
                sn: self.metadata.sn + 1,
                gov_version: self.gov_version,
                patch: &patch,
                signer: &self.signer,
                now: TimeStamp::now(),
            })
        }
    }

    /// Validators rebuild the compilation request from ledger-anchored
    /// data, verify the stored request signature over the rebuild and
    /// recompute the stored request hash; an Ok response must cover
    /// exactly the schemas the event sends through the phase.
    #[test]
    fn compilation_request_evidence_is_rebuilt_and_verified() {
        let fixture = PhaseFixture::new();

        // Honest evidence, reconstructed byte-for-byte, is accepted.
        assert!(
            fixture.check_compilation(fixture.honest_compilation()).is_ok()
        );

        // The stored request signature does not verify over the rebuilt
        // request (it signs a request with a different governance
        // version, from the same signer).
        let mut tampered = fixture.honest_compilation();
        tampered.compile_req_signature = Signed::new(
            CompilationReq {
                event_request: fixture.event_request.clone(),
                governance_id: fixture.metadata.governance_id.clone(),
                sn: fixture.metadata.sn + 1,
                gov_version: fixture.gov_version + 1,
            },
            &fixture.owner,
        )
        .unwrap()
        .signature()
        .clone();
        assert!(matches!(
            fixture.check_compilation(tampered),
            Err(ValidatorError::InvalidSignature {
                data: "compilation request"
            })
        ));

        // The stored request hash does not reproduce the rebuild.
        let mut tampered = fixture.honest_compilation();
        tampered.compile_req_hash = fixture.tampered_hash();
        assert!(matches!(
            fixture.check_compilation(tampered),
            Err(ValidatorError::InvalidData {
                value: "compile request hash"
            })
        ));

        // An Ok response covering one schema fewer than the payload
        // sends through the phase is rejected.
        let fewer = fixture.compilation_with_contracts(BTreeMap::new());
        assert!(matches!(
            fixture.check_compilation(fewer),
            Err(ValidatorError::InvalidData {
                value: "compilation contracts"
            })
        ));

        // And so is one covering one schema more.
        let extra_wasm =
            hash_borsh(&*fixture.worker.hash.hasher(), &b"wasm2".to_vec())
                .unwrap();
        let wasm_hash =
            hash_borsh(&*fixture.worker.hash.hasher(), &b"wasm".to_vec())
                .unwrap();
        let more = fixture.compilation_with_contracts(BTreeMap::from([
            (SchemaType::Type("Example".to_owned()), wasm_hash),
            (SchemaType::Type("Other".to_owned()), extra_wasm),
        ]));
        assert!(matches!(
            fixture.check_compilation(more),
            Err(ValidatorError::InvalidData {
                value: "compilation contracts"
            })
        ));
    }

    /// The evaluation and approval requests get the same treatment: the
    /// validator rebuilds them from ledger-anchored data (the approval
    /// patch comes from the verified evaluation evidence), verifies the
    /// stored signatures over the rebuilds and recomputes the stored
    /// hashes.
    #[test]
    fn evaluation_and_approval_request_evidence_is_rebuilt_and_verified() {
        let fixture = PhaseFixture::new();

        // Honest evaluation evidence, reconstructed byte-for-byte, is
        // accepted and yields the patch the approval request carries.
        let (evaluation, patch) = fixture.honest_evaluation();
        let (appr_required, req_patch, _) =
            fixture.check_evaluation(evaluation.clone()).unwrap();
        assert!(appr_required);
        assert_eq!(req_patch, Some(patch.clone()));

        // The stored evaluation request signature does not verify over
        // the rebuilt request.
        let mut tampered = evaluation.clone();
        tampered.eval_req_signature = Signed::new(
            EvaluationReq {
                event_request: fixture.event_request.clone(),
                governance_id: fixture.metadata.governance_id.clone(),
                data: EvaluateData::GovFact {
                    state: GovernanceData::try_from(
                        fixture.metadata.properties.clone(),
                    )
                    .unwrap(),
                },
                sn: fixture.metadata.sn + 1,
                gov_version: fixture.gov_version + 1,
                namespace: fixture.metadata.namespace.clone(),
                schema_id: fixture.metadata.schema_id.clone(),
                signer: fixture.signer.clone(),
                signer_is_owner: true,
            },
            &fixture.owner,
        )
        .unwrap()
        .signature()
        .clone();
        assert!(matches!(
            fixture.check_evaluation(tampered),
            Err(ValidatorError::InvalidSignature {
                data: "evaluation request"
            })
        ));

        // The stored evaluation request hash does not reproduce the
        // rebuild.
        let mut tampered = evaluation;
        tampered.eval_req_hash = fixture.tampered_hash();
        assert!(matches!(
            fixture.check_evaluation(tampered),
            Err(ValidatorError::InvalidData {
                value: "eval request hash"
            })
        ));

        // Honest approval evidence over the evaluated patch is accepted.
        let approval = fixture.honest_approval(patch.clone());
        assert!(
            fixture.check_approval(approval.clone(), patch.clone()).is_ok()
        );

        // The stored approval request signature does not verify over the
        // rebuilt request.
        let mut tampered = approval.clone();
        tampered.approval_req_signature = Signed::new(
            ApprovalReq {
                subject_id: fixture.metadata.subject_id.clone(),
                sn: fixture.metadata.sn + 1,
                gov_version: fixture.gov_version + 1,
                patch: patch.clone(),
                signer: fixture.signer.clone(),
                issued_at: approval.issued_at,
                deadline: approval.deadline,
            },
            &fixture.owner,
        )
        .unwrap()
        .signature()
        .clone();
        assert!(matches!(
            fixture.check_approval(tampered, patch.clone()),
            Err(ValidatorError::InvalidSignature {
                data: "approval request"
            })
        ));

        // The stored approval request hash does not reproduce the
        // rebuild.
        let mut tampered = approval.clone();
        tampered.approval_req_hash = fixture.tampered_hash();
        assert!(matches!(
            fixture.check_approval(tampered, patch.clone()),
            Err(ValidatorError::InvalidData {
                value: "approval request hash"
            })
        ));

        // An approval patch that does not match the verified evaluation
        // evidence rebuilds a different request, so the stored signature
        // no longer verifies.
        let wrong_patch = ValueWrapper(serde_json::json!([
            { "op": "replace", "path": "/version", "value": 2 }
        ]));
        assert!(matches!(
            fixture.check_approval(approval, wrong_patch),
            Err(ValidatorError::InvalidSignature {
                data: "approval request"
            })
        ));
    }

    /// The approval window is anchored to the signed `issued_at`, not to
    /// the moment the worker receives the request: a deadline shorter
    /// than the minimum window is rejected, and an `issued_at` further
    /// in the future than the clock skew allowance is rejected.
    #[test]
    fn approval_window_is_checked_against_signed_issued_at() {
        let fixture = PhaseFixture::new();
        let patch = ValueWrapper(serde_json::json!([
            { "op": "replace", "path": "/version", "value": 1 }
        ]));
        let min_window = Duration::from_secs(300);
        let issued_at = TimeStamp::now();

        let signed_req = |issued_at: TimeStamp, deadline: TimeStamp| {
            Signed::new(
                ApprovalReq {
                    subject_id: fixture.metadata.subject_id.clone(),
                    sn: fixture.metadata.sn + 1,
                    gov_version: fixture.gov_version,
                    patch: patch.clone(),
                    signer: fixture.signer.clone(),
                    issued_at,
                    deadline,
                },
                &fixture.owner,
            )
            .unwrap()
        };

        let check = |req: &Signed<ApprovalReq>| {
            ValiWorker::check_approval_req(
                req,
                &fixture.metadata,
                fixture.gov_version,
                &patch,
                &fixture.signer,
                min_window,
            )
        };

        // A deadline exactly at issued_at + min_window is accepted.
        let ok = signed_req(
            issued_at,
            TimeStamp::from_nanos(
                issued_at.as_nanos() + min_window.as_nanos() as u64,
            ),
        );
        assert!(check(&ok).is_ok());

        // A deadline one nanosecond below the minimum window is
        // rejected.
        let short = signed_req(
            issued_at,
            TimeStamp::from_nanos(
                issued_at.as_nanos() + min_window.as_nanos() as u64 - 1,
            ),
        );
        assert!(matches!(
            check(&short),
            Err(ValidatorError::InvalidData {
                value: "approval window"
            })
        ));

        // An issued_at further in the future than the clock skew
        // allowance is rejected, even with a valid window.
        let future = TimeStamp::from_nanos(
            TimeStamp::now().as_nanos()
                + 2 * CLOCK_SKEW.as_nanos() as u64,
        );
        let skewed = signed_req(
            future,
            TimeStamp::from_nanos(
                future.as_nanos() + min_window.as_nanos() as u64,
            ),
        );
        assert!(matches!(
            check(&skewed),
            Err(ValidatorError::InvalidData {
                value: "approval issued_at"
            })
        ));
    }
}
