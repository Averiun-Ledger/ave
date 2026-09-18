//! # Validation module.
//!
use crate::{
    approval::{
        request::ApprovalReq,
        response::ApprovalRes,
        verify::{CLOCK_SKEW, build_canonical_tally, terminal_outcome},
    },
    governance::{model::Quorum, role_register::RoleDataRegister},
    helpers::network::{
        ActorMessage, NetworkMessage, service::NetworkSender,
    },
    metrics::try_core_metrics,
    model::{
        common::{
            abort_req, crash_system, send_reboot_to_req, take_random_signers,
        },
        event::{ApprovalData, ValidationData, ValidationMetadata},
    },
    request::manager::{RebootType, RequestManager, RequestManagerMessage},
    subject::RequestSubjectData,
    system::ConfigHelper,
    validation::{
        coordinator::{ValiCoordinator, ValiCoordinatorMessage},
        response::ResponseSummary,
        worker::{
            CurrentRequestRoles, CurrentWorkerRoles, ValiWorker,
            ValiWorkerMessage,
        },
    },
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::{
    ValueWrapper,
    identity::{
        CryptoError, DigestIdentifier, HashAlgorithm, PublicKey, Signature,
        Signed, TimeStamp, hash_borsh,
    },
};
use ave_network::ComunicateInfo;

use request::{ActualProtocols, ValidationReq};
use response::ValidationRes;
use tracing::{Span, debug, error, info_span, warn};

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

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

    /// The round is closed (result, reboot or abort already sent): late
    /// responses are ignored. Responses only matter until the quorum
    /// closes or the validator list runs out.
    closed: bool,

    current_validators: HashSet<PublicKey>,

    pending_validators: HashSet<PublicKey>,

    init_state: Option<ValueWrapper>,

    current_request_roles: CurrentRequestRoles,

    /// Full validation role set of the governance, captured in `Create`:
    /// the local validator worker needs it to verify the validator-signed
    /// timeout attestations inside an approval tally proposal.
    validation_roles: RoleDataRegister,

    /// Approval collection state, present when the request carries an
    /// approval requirement (governance facts). The selected validators
    /// collect the approver votes; this node merges their reports,
    /// closes the collection at the terminal condition and proposes the
    /// canonical tally for signature.
    approval: Option<OwnerApproval>,
}

/// Requester-side state of an approval collection.
#[derive(Clone, Debug)]
struct OwnerApproval {
    approval_req: Signed<ApprovalReq>,
    approval_req_hash: DigestIdentifier,
    approvers: RoleDataRegister,
    req_subject_data_hash: DigestIdentifier,
    /// Merged votes reported by the validators, one per approver.
    votes: HashMap<PublicKey, Signed<ApprovalRes>>,
    /// (accept, reject) conflicting pairs reported per approver.
    double_votes: Vec<(Signed<ApprovalRes>, Signed<ApprovalRes>)>,
    /// Timeout attestations reported by the validators, grouped by
    /// approver and keyed by attesting validator. An approver present in
    /// `votes` or `double_votes` never appears here: the answer wins.
    timeouts: HashMap<PublicKey, HashMap<PublicKey, Signed<ApprovalRes>>>,
    /// Canonical tally proposed to the validators, once the terminal
    /// condition is reached.
    tally: Option<ApprovalData>,
    tally_hash: Option<DigestIdentifier>,
    /// Validators that acknowledged the request and are collecting.
    working: HashSet<PublicKey>,
    /// Validators asked at the last keepalive round that have not
    /// answered yet.
    status_pending: HashSet<PublicKey>,
}

impl OwnerApproval {
    /// Merges a reported vote into the collection. Returns true when the
    /// union changed (new vote or new double vote).
    fn merge_vote(&mut self, vote: Signed<ApprovalRes>) -> bool {
        let ApprovalRes::Response {
            approval_req_hash,
            agrees,
            req_subject_data_hash,
        } = vote.content()
        else {
            return false;
        };

        if approval_req_hash != &self.approval_req_hash
            || req_subject_data_hash != &self.req_subject_data_hash
        {
            return false;
        }

        let signer = vote.signature().signer.clone();
        if !self.approvers.workers.contains(&signer) {
            return false;
        }

        if self
            .double_votes
            .iter()
            .any(|(accept, _)| accept.signature().signer == signer)
        {
            return false;
        }

        if let Some(previous) = self.votes.get(&signer) {
            let previous_agrees = matches!(
                previous.content(),
                ApprovalRes::Response { agrees: true, .. }
            );
            if previous_agrees == *agrees {
                return false;
            }
            let Some(previous) = self.votes.remove(&signer) else {
                return false;
            };
            let (accept, reject) =
                if *agrees { (vote, previous) } else { (previous, vote) };
            self.double_votes.push((accept, reject));
            self.timeouts.remove(&signer);
            true
        } else {
            self.votes.insert(signer.clone(), vote);
            self.timeouts.remove(&signer);
            true
        }
    }

    /// Merges a validator-signed timeout attestation into the collection.
    /// Returns true when the union changed. The attester must be the
    /// reporting validator itself (validators only attest their own
    /// observations; the caller gates the sender against the working
    /// set), the attested approver must belong to the approver set and
    /// must not have answered: the answer always wins over the timeout.
    fn merge_timeout(
        &mut self,
        timeout: Signed<ApprovalRes>,
        sender: &PublicKey,
    ) -> bool {
        let ApprovalRes::TimeOut {
            approval_req_hash,
            who,
        } = timeout.content()
        else {
            return false;
        };

        if approval_req_hash != &self.approval_req_hash {
            return false;
        }

        let signer = timeout.signature().signer.clone();
        if &signer != sender {
            return false;
        }

        if !self.approvers.workers.contains(who) {
            return false;
        }

        if self.votes.contains_key(who)
            || self
                .double_votes
                .iter()
                .any(|(accept, _)| accept.signature().signer == *who)
        {
            return false;
        }

        self.timeouts
            .entry(who.clone())
            .or_default()
            .insert(signer.clone(), timeout)
            .is_none()
    }

    /// Approvers whose timeout is attested by at least the validation
    /// quorum of validators: only these count as proven absent.
    fn attested_timeouts(
        &self,
        quorum: &Quorum,
        validators_total: u32,
    ) -> usize {
        self.timeouts
            .values()
            .filter(|attestations| {
                quorum.check_quorum(
                    validators_total,
                    attestations.len() as u32,
                )
            })
            .count()
    }

    /// Timeout attestations that reached the validation quorum, flattened
    /// for the canonical tally.
    fn attested_timeouts_map(
        &self,
        quorum: &Quorum,
        validators_total: u32,
    ) -> HashMap<PublicKey, Vec<Signed<ApprovalRes>>> {
        self.timeouts
            .iter()
            .filter(|(_, attestations)| {
                quorum.check_quorum(
                    validators_total,
                    attestations.len() as u32,
                )
            })
            .map(|(who, attestations)| {
                (who.clone(), attestations.values().cloned().collect())
            })
            .collect()
    }

    fn agrees_disagrees(&self) -> (usize, usize) {
        let mut agrees = 0;
        let mut disagrees = 0;
        for vote in self.votes.values() {
            if matches!(
                vote.content(),
                ApprovalRes::Response { agrees: true, .. }
            ) {
                agrees += 1;
            } else {
                disagrees += 1;
            }
        }
        (agrees, disagrees)
    }
}

impl Validation {
    fn observe_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("validation", result);
        }
    }

    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<ValidationReq>,
        init_state: Option<ValueWrapper>,
        current_request_roles: CurrentRequestRoles,
        quorum: Quorum,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
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
            closed: false,
            current_validators: HashSet::new(),
            pending_validators: HashSet::new(),
            current_request_roles,
            validation_roles: RoleDataRegister {
                workers: HashSet::new(),
                quorum: Quorum::default(),
            },
            approval: None,
        }
    }

    fn check_validator(&mut self, validator: PublicKey) -> bool {
        if self.current_validators.remove(&validator) {
            return true;
        }
        if let Some(approval) = &mut self.approval {
            return approval.working.remove(&validator);
        }
        false
    }

    /// Validators still expected to answer: the ones that have not
    /// acknowledged yet plus the ones collecting votes.
    fn awaiting_count(&self) -> usize {
        self.current_validators.len()
            + self.approval.as_ref().map_or(0, |approval| {
                approval.working.len()
            })
    }

    fn observe_approval_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("approval", result);
        }
    }

    async fn create_validators(
        &self,
        ctx: &mut ActorContext<Self>,
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
                        current_roles: CurrentWorkerRoles {
                            evaluation: self
                                .current_request_roles
                                .evaluation
                                .clone(),
                            compilation: self
                                .current_request_roles
                                .compilation
                                .clone(),
                            approval: self.current_request_roles.approval.clone(),
                            validation: self.validation_roles.clone(),
                        },
                        stop:true,
                        pending: None,
                        approvals: HashMap::new(),
                    },
                )
                .await?;

            child
                .tell(ValiWorkerMessage::LocalValidation {
                    validation_req: Box::new(self.request.clone()),
                    request_id: self.request_id.to_string(),
                    version: self.version,
                })
                .await?
        }

        Ok(())
    }

    async fn send_validation_to_req(
        &self,
        ctx: &ActorContext<Self>,
        response: ValidationData,
    ) -> Result<(), ActorError> {
        let req_actor = ctx.get_parent::<RequestManager>().await?;

        req_actor
            .tell(RequestManagerMessage::ValidationRes {
                request_id: self.request_id.clone(),
                val_req: Box::new(self.request.content().clone()),
                val_res: response,
                approval_data: self
                    .approval
                    .as_ref()
                    .and_then(|approval| approval.tally.clone()),
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

    fn keepalive_secs(ctx: &ActorContext<Self>) -> Result<u64, ActorError> {
        ctx.system()
            .get_helper::<ConfigHelper>("config")
            .map(|config| config.approval.keepalive_secs)
            .ok_or_else(|| ActorError::Helper {
                name: "config".to_owned(),
                reason: "Not found".to_owned(),
            })
    }

    /// Sends the proposed tally to one working validator: a tell to the
    /// local child worker when this node is the validator, a network
    /// message to its governance validator worker otherwise.
    async fn send_tally_proposal(
        &self,
        ctx: &mut ActorContext<Self>,
        validator: PublicKey,
    ) -> Result<(), ActorError> {
        let Some(approval) = &self.approval else {
            return Ok(());
        };
        let Some(tally) = approval.tally.clone() else {
            return Ok(());
        };

        if validator == *self.our_key {
            let child = ctx
                .get_child::<ValiWorker>(&format!("{}", validator))
                .await?;
            child
                .tell(ValiWorkerMessage::TallyProposal {
                    approval_data: Box::new(tally),
                    request_id: self.request_id.to_string(),
                    version: self.version,
                    sender: (*self.our_key).clone(),
                })
                .await?;
        } else {
            let governance_id = self
                .request
                .content()
                .get_governance_id()
                .map_err(|e| ActorError::Functional {
                    description: format!("Can not get governance id: {}", e),
                })?;

            self.network
                .send_command(ave_network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info: ComunicateInfo {
                            request_id: self.request_id.to_string(),
                            version: self.version,
                            receiver: validator,
                            receiver_actor: format!(
                                "/user/node/subject_manager/{}/validator",
                                governance_id
                            ),
                        },
                        message: ActorMessage::TallyProposal {
                            approval_data: tally,
                        },
                    },
                })
                .await?;
        }

        Ok(())
    }

    /// Sends a keepalive status ask to one working validator.
    async fn send_status_req(
        &self,
        ctx: &mut ActorContext<Self>,
        validator: PublicKey,
    ) -> Result<(), ActorError> {
        let Some(approval) = &self.approval else {
            return Ok(());
        };
        let approval_req_hash = approval.approval_req_hash.clone();

        if validator == *self.our_key {
            let child = ctx
                .get_child::<ValiWorker>(&format!("{}", validator))
                .await?;
            child
                .tell(ValiWorkerMessage::ApprovalStatusReq {
                    approval_req_hash,
                    request_id: self.request_id.to_string(),
                    version: self.version,
                    sender: (*self.our_key).clone(),
                })
                .await?;
        } else {
            let governance_id = self
                .request
                .content()
                .get_governance_id()
                .map_err(|e| ActorError::Functional {
                    description: format!("Can not get governance id: {}", e),
                })?;

            self.network
                .send_command(ave_network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info: ComunicateInfo {
                            request_id: self.request_id.to_string(),
                            version: self.version,
                            receiver: validator,
                            receiver_actor: format!(
                                "/user/node/subject_manager/{}/validator",
                                governance_id
                            ),
                        },
                        message: ActorMessage::ApprovalStatusReq {
                            approval_req_hash,
                        },
                    },
                })
                .await?;
        }

        Ok(())
    }

    /// Evaluates the terminal condition over the merged votes; once
    /// reached, builds the canonical tally and proposes it to the working
    /// validators. The first proposal stands: votes reported afterwards
    /// never rebuild the tally, so every validator signs the same package.
    async fn maybe_close_collection(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.closed {
            return Ok(());
        }

        let Some(approval) = &self.approval else {
            return Ok(());
        };

        let deadline = approval.approval_req.content().deadline;
        let (agrees, disagrees) = approval.agrees_disagrees();
        let attested = approval
            .attested_timeouts(&self.quorum, self.validators_quantity);

        // A deadline closure requires full accounting: every approver
        // explained by a vote, a double-vote pair or an attested timeout.
        // The validators sign and push their attestations at the deadline,
        // so right at the deadline the collection keeps waiting until
        // they arrive (replacements sign immediately when the deadline
        // already lapsed).
        if TimeStamp::now() >= deadline {
            let accounted =
                agrees + disagrees + approval.double_votes.len() + attested;
            if accounted < approval.approvers.workers.len() {
                return Ok(());
            }
        }

        let Some(outcome) = terminal_outcome(
            &approval.approvers,
            agrees,
            disagrees,
            approval.double_votes.len(),
            attested,
            deadline,
            TimeStamp::now(),
        ) else {
            return Ok(());
        };

        let proven_absent = approval.double_votes.len() + attested;
        let deadline_reached = TimeStamp::from_nanos(
            TimeStamp::now()
                .as_nanos()
                .saturating_add(CLOCK_SKEW.as_nanos() as u64),
        ) >= deadline;

        let timeouts =
            approval.attested_timeouts_map(&self.quorum, self.validators_quantity);
        let tally = build_canonical_tally(
            &self.hash,
            &approval.approval_req,
            &approval.votes,
            &approval.double_votes,
            &timeouts,
            outcome,
        )
        .map_err(|e| ActorError::FunctionalCritical {
            description: e.to_string(),
        })?;
        let tally_hash = hash_borsh(&*self.hash.hasher(), &tally).map_err(
            |e| ActorError::FunctionalCritical {
                description: format!("Can not hash approval tally: {}", e),
            },
        )?;

        // The first proposal stands: votes reported afterwards never
        // rebuild the tally, so every validator signs the same package.
        if approval.tally_hash.is_some() {
            return Ok(());
        }

        // The approval collection closes here: the request leaves the
        // approval state and enters validation, where the validators sign
        // the final response over the proposed tally.
        if let Some(approval) = &mut self.approval {
            approval.tally = Some(tally);
            approval.tally_hash = Some(tally_hash);
        }

        let req_actor = ctx.get_parent::<RequestManager>().await?;
        req_actor
            .tell(RequestManagerMessage::ApprovalClosed {
                request_id: self.request_id.clone(),
            })
            .await?;

        if deadline_reached && proven_absent > 0 {
            Self::observe_approval_event("absent_attested");
        }

        let working = self
            .approval
            .as_ref()
            .map(|approval| approval.working.iter().cloned().collect::<Vec<_>>())
            .unwrap_or_default();

        for validator in working {
            if let Err(e) = self.send_tally_proposal(ctx, validator).await {
                error!(
                    msg_type = "TallyProposal",
                    error = %e,
                    "Failed to send tally proposal"
                );
                return Err(crash_system(ctx, e).await);
            }
        }

        Ok(())
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
    /// A validator acknowledged the request and is collecting the
    /// approval votes.
    Working { sender: PublicKey },
    /// A validator pushes a newly observed approver vote.
    VoteReport {
        vote: Box<Signed<ApprovalRes>>,
        sender: PublicKey,
    },
    /// A validator answers the keepalive status ask with its votes.
    StatusRes {
        approval_req_hash: DigestIdentifier,
        votes: Vec<Signed<ApprovalRes>>,
        sender: PublicKey,
    },
    /// Self-scheduled keepalive round.
    KeepaliveTick,
    /// Self-scheduled at the approval deadline: the collection closes
    /// immediately once the window lapses.
    DeadlineTick,
}

impl Message for ValidationMessage {}

impl NotPersistentActor for Validation {}

#[async_trait]
impl Actor for Validation {
    type Event = ();
    type Message = ValidationMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Validation"),
            |parent_span| info_span!(parent: parent_span, "Validation"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Validation {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: ValidationMessage,
        ctx: &mut ActorContext<Self>,
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
                        return Err(crash_system(
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
                self.validation_roles = RoleDataRegister {
                    workers: signers.iter().cloned().collect(),
                    quorum: self.quorum.clone(),
                };
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
                        // Drop the failed signer so the round can
                        // exhaust itself instead of hanging forever
                        // waiting for a response that will never come.
                        self.current_validators.remove(&signer);
                    }
                }

                if self.current_validators.is_empty() {
                    let governance_id =
                        match self.request.content().get_governance_id() {
                            Ok(governance_id) => governance_id,
                            Err(e) => {
                                error!(
                                    msg_type = "Create",
                                    error = %e,
                                    "Failed to get governance id"
                                );
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Cannot get governance id: {}",
                                            e
                                        ),
                                    },
                                )
                                .await);
                            }
                        };

                    if let Err(e) = send_reboot_to_req(
                        ctx,
                        request_id.clone(),
                        governance_id,
                        RebootType::TimeOut,
                    )
                    .await
                    {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to send reboot to request actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                    Self::observe_event("reboot");
                    self.closed = true;
                    return Ok(());
                }

                // Requests with an approval requirement open the
                // requester-side collection: the validators gather the
                // votes and this node merges their reports.
                if let ValidationReq::Event {
                    actual_protocols,
                    metadata,
                    gov_version,
                    ..
                } = self.request.content()
                {
                    let approval_req = match actual_protocols.as_ref() {
                        ActualProtocols::EvalApprove {
                            approval_req, ..
                        }
                        | ActualProtocols::CompileEvalApprove {
                            approval_req,
                            ..
                        } => Some(approval_req.clone()),
                        _ => None,
                    };
                    if let Some(approval_req) = approval_req {
                        let approval_req_hash = hash_borsh(
                            &*self.hash.hasher(),
                            approval_req.content(),
                        );
                        let approval_req_hash = match approval_req_hash {
                            Ok(hash) => hash,
                            Err(e) => {
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Cannot hash approval request: {}",
                                            e
                                        ),
                                    },
                                )
                                .await);
                            }
                        };

                        let req_subject_data_hash = hash_borsh(
                            &*self.hash.hasher(),
                            &RequestSubjectData {
                                subject_id: metadata.subject_id.clone(),
                                governance_id: metadata.governance_id.clone(),
                                sn: metadata.sn + 1,
                                namespace: metadata.namespace.clone(),
                                schema_id: metadata.schema_id.clone(),
                                gov_version: *gov_version,
                                signer: self.request.signature().signer.clone(),
                            },
                        );
                        let req_subject_data_hash = match req_subject_data_hash
                        {
                            Ok(hash) => hash,
                            Err(e) => {
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Cannot hash subject data: {}",
                                            e
                                        ),
                                    },
                                )
                                .await);
                            }
                        };

                        self.approval = Some(OwnerApproval {
                            approval_req,
                            approval_req_hash,
                            approvers: self
                                .current_request_roles
                                .approval
                                .clone(),
                            req_subject_data_hash,
                            votes: HashMap::new(),
                            double_votes: Vec::new(),
                            timeouts: HashMap::new(),
                            tally: None,
                            tally_hash: None,
                            working: HashSet::new(),
                            status_pending: HashSet::new(),
                        });

                        match Self::keepalive_secs(ctx) {
                            Ok(keepalive) => {
                                if let Err(e) = ctx.schedule_once(
                                    Duration::from_secs(keepalive),
                                    ValidationMessage::KeepaliveTick,
                                ) {
                                    error!(
                                        msg_type = "Create",
                                        error = %e,
                                        "Failed to schedule approval keepalive"
                                    );
                                    return Err(crash_system(ctx, e).await);
                                }
                            }
                            Err(e) => {
                                return Err(crash_system(ctx, e).await);
                            }
                        }

                        // The collection closes the instant the deadline
                        // lapses, without waiting for a keepalive round.
                        let until_deadline = Duration::from_nanos(
                            self.approval
                                .as_ref()
                                .map(|approval| {
                                    approval
                                        .approval_req
                                        .content()
                                        .deadline
                                        .as_nanos()
                                })
                                .unwrap_or_default()
                                .saturating_sub(TimeStamp::now().as_nanos()),
                        );
                        if let Err(e) = ctx.schedule_once(
                            until_deadline,
                            ValidationMessage::DeadlineTick,
                        ) {
                            error!(
                                msg_type = "Create",
                                error = %e,
                                "Failed to schedule approval deadline"
                            );
                            return Err(crash_system(ctx, e).await);
                        }
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
                if !self.closed {
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
                                modified_metadata_without_propierties_hash,
                                propierties_hash,
                                event_request_hash,
                                viewpoints_hash,
                                approval_data_hash,
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

                                // With approval the final response must
                                // attest the tally this node proposed;
                                // without approval it must carry none.
                                let expected_hash = self
                                    .approval
                                    .as_ref()
                                    .and_then(|approval| {
                                        approval.tally_hash.clone()
                                    });
                                if approval_data_hash != expected_hash {
                                    warn!(
                                        msg_type = "Response",
                                        sender = %sender,
                                        "Validation response with unexpected approval data hash"
                                    );
                                    Self::observe_approval_event(
                                        "tally_rejected",
                                    );
                                    return Ok(());
                                }

                                self.validators_response.push(
                                    ValidationMetadata::ModifiedHash {
                                        modified_metadata_without_propierties_hash,
                                        propierties_hash,
                                        event_request_hash,
                                        viewpoints_hash,
                                    },
                                );
                                self.validators_signatures.push(signature);
                            }
                            // The acknowledgement travels through the
                            // dedicated Working message; one inside a
                            // response just drops the validator like a
                            // timeout would.
                            ValidationRes::Working => {
                                warn!(
                                    msg_type = "Response",
                                    sender = %sender,
                                    "Working acknowledgement inside a response"
                                );
                            }
                            ValidationRes::TimeOut => {
                                Self::observe_event("timeout");
                            }
                            // Same handling as a timeout — the validator
                            // is dropped from the current set and replaced
                            // from the pending pool — but explicit and
                            // immediate: no coordinator timeout wait.
                            ValidationRes::Unavailable => {
                                Self::observe_event("unavailable");
                            }
                            ValidationRes::Abort(error) => {
                                Self::observe_event("abort");
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
                                    return Err(crash_system(ctx, e).await);
                                }

                                self.closed = true;

                                return Ok(());
                            }
                            ValidationRes::Reboot => {
                                Self::observe_event("reboot");
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
                                    return Err(crash_system(ctx, e).await);
                                }

                                self.closed = true;

                                return Ok(());
                            }
                        };

                        if self.quorum.check_quorum(
                            self.validators_quantity,
                            self.validators_response.len() as u32,
                        ) {
                            let summary = self.check_responses();
                            if matches!(summary, ResponseSummary::Reboot)
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
                                    return Err(crash_system(ctx, e).await);
                                }
                            if matches!(summary, ResponseSummary::Reboot) {
                                Self::observe_event("reboot");
                                self.closed = true;
                                return Ok(());
                            }

                            // A rejected tally commits like any other:
                            // the event lands in the ledger with
                            // `approved=false` and the fact is not
                            // applied.
                            if let Some(approval) = &self.approval
                                && let Some(tally) = &approval.tally
                                && !tally.approved
                            {
                                Self::observe_approval_event("rejected");
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
                                return Err(crash_system(ctx, e).await);
                            };

                            self.closed = true;

                            if !matches!(summary, ResponseSummary::Reboot) {
                                Self::observe_event("success");
                            }

                            debug!(
                                msg_type = "Response",
                                request_id = %self.request_id,
                                version = self.version,
                                "Validation completed and sent to request"
                            );
                        } else if self.awaiting_count() == 0
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
                                    // Drop the failed signer so the
                                    // round can exhaust itself instead
                                    // of hanging forever.
                                    self.current_validators.remove(&signer);
                                }
                            }

                            if self.current_validators.is_empty() {
                                let governance_id = match self
                                    .request
                                    .content()
                                    .get_governance_id()
                                {
                                    Ok(governance_id) => governance_id,
                                    Err(e) => {
                                        error!(
                                            msg_type = "Response",
                                            error = %e,
                                            "Failed to get governance id"
                                        );
                                        return Err(crash_system(
                                            ctx,
                                            ActorError::FunctionalCritical {
                                                description: format!(
                                                    "Cannot get governance id: {}",
                                                    e
                                                ),
                                            },
                                        )
                                        .await);
                                    }
                                };

                                if let Err(e) = send_reboot_to_req(
                                    ctx,
                                    self.request_id.clone(),
                                    governance_id,
                                    RebootType::TimeOut,
                                )
                                .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        "Failed to send reboot to request actor"
                                    );
                                    return Err(crash_system(ctx, e).await);
                                }
                                Self::observe_event("reboot");
                                self.closed = true;
                            }

                            debug!(
                                msg_type = "Response",
                                new_validators = curren_vali.len(),
                                "Created additional validators from pending pool"
                            );
                        } else if self.awaiting_count() == 0
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
                                    return Err(crash_system(ctx, e).await);
                                } else if self.awaiting_count() == 0 {
                                    Self::observe_event("reboot");
                                    self.closed = true;
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
            ValidationMessage::Working { sender } => {
                if self.closed || self.approval.is_none() {
                    return Ok(());
                }
                if !self.current_validators.remove(&sender) {
                    warn!(
                        msg_type = "Working",
                        sender = %sender,
                        "Working acknowledgement from unexpected validator"
                    );
                    return Ok(());
                }

                let has_tally = self
                    .approval
                    .as_ref()
                    .is_some_and(|approval| approval.tally.is_some());
                if let Some(approval) = &mut self.approval {
                    approval.working.insert(sender.clone());
                }

                // A validator that acknowledges after the tally was
                // proposed receives the proposal right away; otherwise it
                // is surveyed immediately so a recovered requester does
                // not wait a whole keepalive round for its votes.
                if has_tally {
                    if let Err(e) =
                        self.send_tally_proposal(ctx, sender.clone()).await
                    {
                        error!(
                            msg_type = "Working",
                            error = %e,
                            "Failed to send tally proposal"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                } else if let Err(e) =
                    self.send_status_req(ctx, sender.clone()).await
                {
                    error!(
                        msg_type = "Working",
                        error = %e,
                        "Failed to send approval status ask"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValidationMessage::VoteReport { vote, sender } => {
                if self.closed {
                    return Ok(());
                }

                let mut changed = false;
                if let Some(approval) = &mut self.approval
                    && approval.working.contains(&sender)
                {
                    // A pushed vote is proof of liveness too: it answers
                    // any open keepalive round for this validator.
                    approval.status_pending.remove(&sender);
                    match vote.verify() {
                        Ok(()) => {
                            changed = if matches!(
                                vote.content(),
                                ApprovalRes::TimeOut { .. }
                            ) {
                                approval.merge_timeout(*vote, &sender)
                            } else {
                                approval.merge_vote(*vote)
                            };
                        }
                        Err(e) => {
                            warn!(
                                msg_type = "VoteReport",
                                sender = %sender,
                                error = %e,
                                "Approval vote with invalid signature"
                            );
                        }
                    }
                }

                if changed
                    && let Err(e) = self.maybe_close_collection(ctx).await
                {
                    error!(
                        msg_type = "VoteReport",
                        error = %e,
                        "Failed to close approval collection"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValidationMessage::StatusRes {
                approval_req_hash,
                votes,
                sender,
            } => {
                if self.closed {
                    return Ok(());
                }

                let mut changed = false;
                if let Some(approval) = &mut self.approval {
                    approval.status_pending.remove(&sender);
                    if approval_req_hash == approval.approval_req_hash
                        && approval.working.contains(&sender)
                    {
                        for vote in votes {
                            match vote.verify() {
                                Ok(()) => {
                                    changed |= if matches!(
                                        vote.content(),
                                        ApprovalRes::TimeOut { .. }
                                    ) {
                                        approval.merge_timeout(vote, &sender)
                                    } else {
                                        approval.merge_vote(vote)
                                    };
                                }
                                Err(e) => {
                                    warn!(
                                        msg_type = "StatusRes",
                                        sender = %sender,
                                        error = %e,
                                        "Approval vote with invalid signature"
                                    );
                                }
                            }
                        }
                    }
                }

                if changed
                    && let Err(e) = self.maybe_close_collection(ctx).await
                {
                    error!(
                        msg_type = "StatusRes",
                        error = %e,
                        "Failed to close approval collection"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValidationMessage::KeepaliveTick => {
                if self.closed || self.approval.is_none() {
                    return Ok(());
                }

                let keepalive = match Self::keepalive_secs(ctx) {
                    Ok(keepalive) => keepalive,
                    Err(e) => return Err(crash_system(ctx, e).await),
                };

                // Validators silent for a whole keepalive round are
                // dropped and replaced from the pending pool.
                let dead: Vec<PublicKey> = self
                    .approval
                    .as_mut()
                    .map(|approval| {
                        let dead: Vec<PublicKey> =
                            approval.status_pending.drain().collect();
                        for validator in &dead {
                            approval.working.remove(validator);
                        }
                        dead
                    })
                    .unwrap_or_default();

                for validator in dead {
                    Self::observe_approval_event("validator_replaced");
                    debug!(
                        msg_type = "KeepaliveTick",
                        validator = %validator,
                        "Unresponsive validator dropped"
                    );

                    let replacement =
                        self.pending_validators.iter().next().cloned();
                    if let Some(replacement) = replacement {
                        self.pending_validators.remove(&replacement);
                        self.current_validators.insert(replacement.clone());
                        if let Err(e) = self
                            .create_validators(ctx, replacement.clone())
                            .await
                        {
                            error!(
                                msg_type = "KeepaliveTick",
                                error = %e,
                                signer = %replacement,
                                "Failed to create replacement validator"
                            );
                            self.current_validators.remove(&replacement);
                        }
                    }
                }

                // Nobody left to answer and nothing in reserve.
                if self.awaiting_count() == 0
                    && self.pending_validators.is_empty()
                {
                    let governance_id =
                        match self.request.content().get_governance_id() {
                            Ok(governance_id) => governance_id,
                            Err(e) => {
                                error!(
                                    msg_type = "KeepaliveTick",
                                    error = %e,
                                    "Failed to get governance id"
                                );
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Cannot get governance id: {}",
                                            e
                                        ),
                                    },
                                )
                                .await);
                            }
                        };

                    if let Err(e) = send_reboot_to_req(
                        ctx,
                        self.request_id.clone(),
                        governance_id,
                        RebootType::TimeOut,
                    )
                    .await
                    {
                        error!(
                            msg_type = "KeepaliveTick",
                            error = %e,
                            "Failed to send reboot to request actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                    Self::observe_event("reboot");
                    self.closed = true;
                    return Ok(());
                }

                // New keepalive round: ask every working validator for
                // the votes it has observed so far.
                let working: Vec<PublicKey> = self
                    .approval
                    .as_ref()
                    .map(|approval| {
                        approval.working.iter().cloned().collect()
                    })
                    .unwrap_or_default();
                if let Some(approval) = &mut self.approval {
                    approval.status_pending = approval.working.clone();
                }

                for validator in working {
                    if let Err(e) =
                        self.send_status_req(ctx, validator).await
                    {
                        error!(
                            msg_type = "KeepaliveTick",
                            error = %e,
                            "Failed to send approval status ask"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                }

                if let Err(e) = self.maybe_close_collection(ctx).await {
                    error!(
                        msg_type = "KeepaliveTick",
                        error = %e,
                        "Failed to close approval collection"
                    );
                    return Err(crash_system(ctx, e).await);
                }

                if let Err(e) = ctx.schedule_once(
                    Duration::from_secs(keepalive),
                    ValidationMessage::KeepaliveTick,
                ) {
                    error!(
                        msg_type = "KeepaliveTick",
                        error = %e,
                        "Failed to schedule approval keepalive"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ValidationMessage::DeadlineTick => {
                if self.closed {
                    return Ok(());
                }

                if let Err(e) = self.maybe_close_collection(ctx).await {
                    error!(
                        msg_type = "DeadlineTick",
                        error = %e,
                        "Failed to close approval collection at deadline"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
        };
        Ok(())
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
        EventRequest, NetworkMessage, Node, NodeMessage, NodeResponse, Signed,
        evaluation::tests::wait_request,
        governance::{
            Governance, GovernanceMessage, GovernanceResponse,
            data::GovernanceData,
        },
        helpers::{
            db::{ExternalDB, ReadStore},
            network::service::NetworkSender,
        },
        model::common::node::SignTypesNode,
        node::InitParamsNode,
        request::{
            RequestHandler, RequestHandlerMessage, RequestHandlerResponse,
            tracking::RequestTracking,
        },
        system::tests::create_system,
    };
    use ave_network::CommandHelper as NetworkCommandHelper;

    async fn get_subject_state(
        db: &Arc<ExternalDB>,
        subject_id: &DigestIdentifier,
        expected_sn: u64,
    ) -> ave_common::response::SubjectDB {
        let started = tokio::time::Instant::now();
        loop {
            match db.get_subject_state(&subject_id.to_string()).await {
                Ok(state) if state.sn >= expected_sn => return state,
                Ok(_) | Err(_)
                    if started.elapsed() < Duration::from_secs(5) =>
                {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Ok(state) => {
                    panic!(
                        "subject state not updated in time for {}: expected sn >= {}, got {}",
                        subject_id, expected_sn, state.sn
                    );
                }
                Err(error) => {
                    panic!(
                        "subject state not available in time for {}: {}",
                        subject_id, error
                    );
                }
            }
        }
    }

    async fn get_event_sn(
        db: &Arc<ExternalDB>,
        subject_id: &DigestIdentifier,
        sn: u64,
    ) -> ave_common::response::LedgerDB {
        let started = tokio::time::Instant::now();
        loop {
            match db.get_event_sn(&subject_id.to_string(), sn).await {
                Ok(event) => return event,
                Err(_) if started.elapsed() < Duration::from_secs(5) => {
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
                Err(error) => {
                    panic!(
                        "event {} for {} not available in time: {}",
                        sn, subject_id, error
                    );
                }
            }
        }
    }

    fn spawn_dummy_network(
        mut receiver: mpsc::Receiver<NetworkCommandHelper<NetworkMessage>>,
    ) {
        tokio::spawn(async move { while receiver.recv().await.is_some() {} });
    }

    pub async fn create_gov() -> (
        SystemRef,
        ActorRef<Node>,
        ActorRef<RequestHandler>,
        Arc<ExternalDB>,
        ActorRef<Governance>,
        ActorRef<RequestTracking>,
        DigestIdentifier,
        Vec<TempDir>,
    ) {
        let node_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let (system, .., _dirs) = create_system().await;

        let (command_sender, command_receiver) = mpsc::channel(10);
        spawn_dummy_network(command_receiver);
        #[cfg(feature = "test")]
        let network = Arc::new(NetworkSender::new(
            command_sender.clone(),
            Arc::new(std::sync::Mutex::new(
                crate::helpers::network::test_faults::TestFaultRegistry::new(
                    command_sender,
                ),
            )),
        ));
        #[cfg(not(feature = "test"))]
        let network = Arc::new(NetworkSender::new(command_sender));

        system.add_helper("network", network.clone());

        let public_key = Arc::new(node_keys.public_key());
        let node_actor = system
            .create_root_actor(
                "node",
                Node::initial(InitParamsNode {
                    key_pair: node_keys.clone(),
                    public_key: public_key.clone(),
                    hash: HashAlgorithm::Blake3,
                    is_service: true,
                    only_clear_events: false,
                    ledger_batch_size: 100,
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

        let ext_db = system.get_helper::<Arc<ExternalDB>>("ext_db").unwrap();

        let create_req = EventRequest::Create(CreateRequest {
            name: Some("Name".to_string()),
            description: Some("Description".to_string()),
            governance_id: DigestIdentifier::default(),
            schema_id: SchemaType::Governance,
            namespace: Namespace::new(),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::EventRequest(create_req.clone()),
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

        let tracking = system
            .get_actor::<RequestTracking>(&ActorPath::from(
                "/user/request/tracking",
            ))
            .await
            .unwrap();

        wait_request(&tracking, response.request_id).await;

        let subject_actor: ActorRef<Governance> = system
            .get_actor(&ActorPath::from(format!(
                "/user/node/subject_manager/{}",
                owned_subj
            )))
            .await
            .unwrap();

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };
        let subject_data = get_subject_state(&ext_db, &owned_subj, 0).await;
        let event = get_event_sn(&ext_db, &owned_subj, 0).await;

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

        (
            system,
            node_actor,
            request_actor,
            ext_db,
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
            db,
            subject_actor,
            tracking,
            subject_id,
            _dirs,
        ) = create_gov().await;

        let eol_reques = EventRequest::EOL(EOLRequest {
            subject_id: subject_id.clone(),
        });

        let response = node_actor
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::EventRequest(eol_reques.clone()),
            )))
            .await
            .unwrap();
        let NodeResponse::SignRequest(signature) = response else {
            panic!("Invalid Response")
        };

        let signed_event_req = Signed::from_parts(eol_reques, signature);

        let RequestHandlerResponse::Ok(response) = request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        wait_request(&tracking, response.request_id).await;

        let GovernanceResponse::Metadata(metadata) = subject_actor
            .ask(GovernanceMessage::GetMetadata)
            .await
            .unwrap()
        else {
            panic!("Invalid response")
        };

        let subject_data = get_subject_state(&db, &subject_id, 1).await;
        let event = get_event_sn(&db, &subject_id, 1).await;

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

        if request_actor
            .ask(RequestHandlerMessage::NewRequest {
                request: signed_event_req.clone(),
            })
            .await
            .is_ok()
        {
            panic!("Invalid response")
        }
    }
}
