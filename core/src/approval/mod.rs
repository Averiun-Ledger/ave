//! # Approval module.
//!
//! The approval is a protocol of its own, closed BEFORE the validation
//! phase starts: the requester picks a random set of validators (sized
//! as the validation quorum), delivers them the signed approval request
//! and they collect the approver votes, attesting with their own
//! signature the timeouts of the approvers that never answer. The
//! requester merges the reports, closes the collection at the terminal
//! condition and hands the resulting `ApprovalData` to the request
//! manager, which then starts the validation phase with that evidence
//! already closed inside the validation request.

use crate::{
    approval::{
        coordinator::{ApprCoordinator, ApprCoordinatorMessage},
        request::ApprovalReq,
        response::ApprovalRes,
        verify::{CLOCK_SKEW, build_canonical_tally, terminal_outcome},
    },
    governance::{model::Quorum, role_register::RoleDataRegister},
    helpers::network::{
        ActorMessage, NetworkMessage, delivery_of, service::NetworkSender,
    },
    metrics::try_core_metrics,
    model::common::{
        abort_req, crash_system, send_reboot_to_req, take_random_signers,
    },
    request::manager::{RebootType, RequestManager, RequestManagerMessage},
    subject::RequestSubjectData,
    system::ConfigHelper,
    validation::worker::{CurrentWorkerRoles, ValiWorker, ValiWorkerMessage},
};
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::{
    Namespace, SchemaType,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, TimeStamp,
        hash_borsh,
    },
};
use ave_network::ComunicateInfo;

use tracing::{Span, debug, error, info_span, warn};

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

pub mod coordinator;
pub mod persist;
pub mod request;
pub mod response;
pub mod types;
pub mod verify;

/// Keepalive rounds between full status snapshots. Filtered rounds only
/// ask about the approvers still missing evidence; every N-th round
/// asks for everything as a backstop against lost vote pushes (e.g. a
/// late conflicting vote the owner would otherwise never relearn).
const FULL_STATUS_SWEEP_ROUNDS: u64 = 8;

/// Requester-side actor of the approval phase: one per request, child of
/// the request manager. All its state is volatile — on a restart the
/// phase is recreated from the persisted request manager state and the
/// votes are recovered from the validators (their collections hold them
/// and the approvers persist their own votes).
#[derive(Clone, Debug)]
pub struct Approval {
    our_key: Arc<PublicKey>,

    request: Signed<ApprovalReq>,

    approval_req_hash: DigestIdentifier,

    approvers: RoleDataRegister,

    req_subject_data_hash: DigestIdentifier,

    /// Validation quorum of the governance: sizes the validator set and
    /// the timeout attestation threshold.
    quorum: Quorum,

    validators_quantity: u32,

    hash: HashAlgorithm,

    network: Arc<NetworkSender>,

    request_id: DigestIdentifier,

    version: u64,

    /// The collection is closed (result, reboot or abort already sent):
    /// late reports are ignored.
    closed: bool,

    current_validators: HashSet<PublicKey>,

    pending_validators: HashSet<PublicKey>,

    /// Full validation role set, captured in `Create`.
    validation_roles: RoleDataRegister,

    /// Merged votes reported by the validators, one per approver.
    votes: HashMap<PublicKey, Signed<ApprovalRes>>,

    /// (accept, reject) conflicting pairs reported per approver.
    double_votes: Vec<(Signed<ApprovalRes>, Signed<ApprovalRes>)>,

    /// Timeout attestations reported by the validators, grouped by
    /// approver and keyed by attesting validator. An approver present in
    /// `votes` or `double_votes` never appears here: the answer wins.
    timeouts: HashMap<PublicKey, HashMap<PublicKey, Signed<ApprovalRes>>>,

    /// Validators that acknowledged the request and are collecting.
    working: HashSet<PublicKey>,

    /// Validators asked at the last keepalive round that have not
    /// answered yet.
    status_pending: HashSet<PublicKey>,

    /// Keepalive rounds elapsed. Every `FULL_STATUS_SWEEP_ROUNDS`-th
    /// round asks for the full snapshot as a backstop against lost
    /// vote pushes; the rounds in between only ask about the approvers
    /// still missing evidence.
    keepalive_rounds: u64,

    /// Hashes of the exact signed votes already verified. Validators
    /// push every vote they observe and resend full snapshots per
    /// keepalive round, so most verifies are repeats. Keyed by the
    /// signed bytes (content and signature), so only byte-identical
    /// evidence skips the check. Volatile per request, dropped at close.
    verified: HashSet<DigestIdentifier>,
}

impl Approval {
    fn observe_event(result: &'static str) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_protocol_event("approval", result);
        }
    }

    pub fn new(
        our_key: Arc<PublicKey>,
        request: Signed<ApprovalReq>,
        approvers: RoleDataRegister,
        quorum: Quorum,
        hash: HashAlgorithm,
        network: Arc<NetworkSender>,
    ) -> Self {
        Self {
            our_key,
            request,
            approval_req_hash: DigestIdentifier::default(),
            approvers,
            req_subject_data_hash: DigestIdentifier::default(),
            quorum,
            validators_quantity: 0,
            hash,
            network,
            request_id: DigestIdentifier::default(),
            version: 0,
            closed: false,
            current_validators: HashSet::new(),
            pending_validators: HashSet::new(),
            validation_roles: RoleDataRegister {
                workers: HashSet::new(),
                quorum: Quorum::default(),
            },
            votes: HashMap::new(),
            double_votes: Vec::new(),
            timeouts: HashMap::new(),
            working: HashSet::new(),
            status_pending: HashSet::new(),
            keepalive_rounds: 0,
            verified: HashSet::new(),
        }
    }

    fn check_validator(&mut self, validator: PublicKey) -> bool {
        if self.current_validators.remove(&validator) {
            return true;
        }
        // Any answer is proof of liveness: leaving the validator in
        // status_pending would drain it as dead at the next keepalive
        // tick and trigger a spurious replacement.
        self.status_pending.remove(&validator);
        self.working.remove(&validator)
    }

    /// Drops a validator that can no longer serve the request (silent
    /// for a whole keepalive round, unable to collect, or its local
    /// worker is gone) and pulls a replacement from the pending pool.
    /// If the remaining validators cannot reach the validation quorum
    /// even if all of them attest, the request reboots instead of
    /// waiting forever.
    async fn drop_and_replace_validator(
        &mut self,
        ctx: &mut ActorContext<Self>,
        validator: PublicKey,
    ) -> Result<(), ActorError> {
        if self.closed {
            return Ok(());
        }

        self.check_validator(validator.clone());
        Self::observe_event("validator_replaced");

        let replacement = self.pending_validators.iter().next().cloned();
        if let Some(replacement) = replacement {
            self.pending_validators.remove(&replacement);
            self.current_validators.insert(replacement.clone());
            if let Err(e) =
                self.create_validators(ctx, replacement.clone()).await
            {
                error!(
                    error = %e,
                    signer = %replacement,
                    "Failed to create replacement approval validator"
                );
                self.current_validators.remove(&replacement);
            }
        }

        let threshold = self.quorum.get_signers(
            self.validators_quantity,
            self.validators_quantity,
        );
        let reachable = self.working.len()
            + self.current_validators.len()
            + self.pending_validators.len();
        if (reachable as u32) < threshold {
            Self::observe_event("reboot");
            send_reboot_to_req(
                ctx,
                self.request_id.clone(),
                self.request.content().subject_id.clone(),
                RebootType::TimeOut,
            )
            .await?;
            self.closed = true;
        }

        Ok(())
    }

    /// Validators still expected to answer: the ones that have not
    /// acknowledged yet plus the ones collecting votes.
    fn awaiting_count(&self) -> usize {
        self.current_validators.len() + self.working.len()
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
                    ApprCoordinator::new(
                        signer.clone(),
                        self.request.content().subject_id.clone(),
                        self.request_id.to_string(),
                        self.version,
                        self.approval_req_hash.clone(),
                        self.network.clone(),
                    ),
                )
                .await?;

            child
                .tell(ApprCoordinatorMessage::NetworkApproval {
                    approval_req: Box::new(self.request.clone()),
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
                        init_state: None,
                        governance_id: self.request.content().subject_id.clone(),
                        gov_version: self.request.content().gov_version,
                        sn: self.request.content().sn,
                        hash: self.hash,
                        network: self.network.clone(),
                        current_roles: CurrentWorkerRoles {
                            evaluation: RoleDataRegister {
                                workers: HashSet::new(),
                                quorum: Quorum::default(),
                            },
                            compilation: RoleDataRegister {
                                workers: HashSet::new(),
                                quorum: Quorum::default(),
                            },
                            approval: self.approvers.clone(),
                            validation: self.validation_roles.clone(),
                        },
                        stop: true,
                        pending: None,
                        approvals: HashMap::new(),
                    },
                )
                .await?;

            child
                .tell(ValiWorkerMessage::LocalApprovalCollect {
                    approval_req: Box::new(self.request.clone()),
                    request_id: self.request_id.to_string(),
                    version: self.version,
                })
                .await?
        }

        Ok(())
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

    /// Sends a keepalive status ask to one working validator. A local
    /// child that is gone is dropped and replaced like an unresponsive
    /// validator — a recoverable condition that must never crash.
    /// `wanted` holds the approvers the collection still needs evidence
    /// about; `None` asks for the full snapshot.
    async fn send_status_req(
        &mut self,
        ctx: &mut ActorContext<Self>,
        validator: PublicKey,
        wanted: Option<HashSet<PublicKey>>,
    ) -> Result<(), ActorError> {
        let approval_req_hash = self.approval_req_hash.clone();

        if validator == *self.our_key {
            let send = match ctx
                .get_child::<ValiWorker>(&format!("{}", validator))
                .await
            {
                Ok(child) => {
                    child
                        .tell(ValiWorkerMessage::ApprovalStatusReq {
                            approval_req_hash,
                            request_id: self.request_id.to_string(),
                            version: self.version,
                            sender: (*self.our_key).clone(),
                            wanted,
                        })
                        .await
                }
                Err(e) => Err(e),
            };
            if let Err(e) = send {
                warn!(
                    error = %e,
                    validator = %validator,
                    "Local approval validator worker gone, replacing it"
                );
                self.drop_and_replace_validator(ctx, validator).await?;
            }
        } else {
            let message = ActorMessage::ApprovalStatusReq {
                approval_req_hash,
                wanted,
            };
            self.network
                .send_command(ave_network::CommandHelper::SendMessage {
                    delivery: delivery_of(&message),
                    message: NetworkMessage {
                        info: ComunicateInfo {
                            request_id: self.request_id.to_string(),
                            version: self.version,
                            receiver: validator.clone(),
                            receiver_actor: format!(
                                "/user/node/subject_manager/{}/validator",
                                self.request.content().subject_id
                            ),
                        },
                        message,
                    },
                })
                .await?;
        }

        Ok(())
    }

    /// Merges a reported vote into the collection. Returns true when the
    /// union changed (new vote or new double vote).
    /// True when these exact signed bytes were already verified. A
    /// hashing failure simply misses: the cache is a pure optimization,
    /// never a gate.
    fn is_verified(&self, vote: &Signed<ApprovalRes>) -> bool {
        hash_borsh(&*self.hash.hasher(), vote)
            .is_ok_and(|hash| self.verified.contains(&hash))
    }

    /// Records exact signed bytes as verified.
    fn mark_verified(&mut self, vote: &Signed<ApprovalRes>) {
        if let Ok(hash) = hash_borsh(&*self.hash.hasher(), vote) {
            self.verified.insert(hash);
        }
    }

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
    fn attested_timeouts(&self) -> usize {
        self.timeouts
            .values()
            .filter(|attestations| {
                self.quorum.check_quorum(
                    self.validators_quantity,
                    attestations.len() as u32,
                )
            })
            .count()
    }

    /// True when no more evidence is needed about this approver: a vote
    /// or a conflicting pair is recorded (a verified vote cannot be
    /// forged, so one report suffices), or the absence is attested by a
    /// validator quorum.
    fn approver_settled(&self, who: &PublicKey) -> bool {
        if self.votes.contains_key(who) {
            return true;
        }
        if self
            .double_votes
            .iter()
            .any(|(accept, _)| accept.signature().signer == *who)
        {
            return true;
        }
        self.timeouts.get(who).is_some_and(|attestations| {
            self.quorum.check_quorum(
                self.validators_quantity,
                attestations.len() as u32,
            )
        })
    }

    /// Approvers the collection still needs evidence about.
    fn pending_approvers(&self) -> HashSet<PublicKey> {
        self.approvers
            .workers
            .iter()
            .filter(|who| !self.approver_settled(who))
            .cloned()
            .collect()
    }

    /// Timeout attestations that reached the validation quorum, flattened
    /// for the canonical evidence.
    fn attested_timeouts_map(
        &self,
    ) -> HashMap<PublicKey, Vec<Signed<ApprovalRes>>> {
        self.timeouts
            .iter()
            .filter(|(_, attestations)| {
                self.quorum.check_quorum(
                    self.validators_quantity,
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

    /// Evaluates the terminal condition over the merged votes; once
    /// reached, builds the canonical approval evidence and hands it to
    /// the request manager, which starts the validation phase with it.
    /// The working validators learn of the close data-driven: the
    /// validation request carrying the evidence purges their volatile
    /// collections.
    async fn maybe_close_collection(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if self.closed {
            return Ok(());
        }

        let deadline = self.request.content().deadline;
        let (agrees, disagrees) = self.agrees_disagrees();
        let attested = self.attested_timeouts();

        // A deadline closure requires full accounting: every approver
        // explained by a vote, a double-vote pair or an attested timeout.
        // The validators sign and push their attestations at the
        // deadline, so right at the deadline the collection keeps
        // waiting until they arrive (replacements sign immediately when
        // the deadline already lapsed).
        if TimeStamp::now() >= deadline {
            let accounted =
                agrees + disagrees + self.double_votes.len() + attested;
            if accounted < self.approvers.workers.len() {
                return Ok(());
            }
        }

        let Some(outcome) = terminal_outcome(
            &self.approvers,
            agrees,
            disagrees,
            self.double_votes.len(),
            attested,
            deadline,
            TimeStamp::now(),
        ) else {
            return Ok(());
        };

        let proven_absent = self.double_votes.len() + attested;
        let deadline_reached = TimeStamp::from_nanos(
            TimeStamp::now()
                .as_nanos()
                .saturating_add(CLOCK_SKEW.as_nanos() as u64),
        ) >= deadline;

        let timeouts = self.attested_timeouts_map();
        let approval_data = build_canonical_tally(
            &self.hash,
            &self.request,
            &self.votes,
            &self.double_votes,
            &timeouts,
            outcome,
        )
        .map_err(|e| ActorError::FunctionalCritical {
            description: e.to_string(),
        })?;

        // The approval protocol ends here: the evidence is closed and
        // the request enters the validation phase with it.
        self.closed = true;

        let req_actor = ctx.get_parent::<RequestManager>().await?;
        req_actor
            .tell(RequestManagerMessage::ApprovalClosed {
                request_id: self.request_id.clone(),
                approval_data: Box::new(approval_data),
            })
            .await?;

        if !outcome {
            Self::observe_event("rejected");
        }
        if deadline_reached && proven_absent > 0 {
            Self::observe_event("absent_attested");
        }

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum ApprovalMessage {
    Create {
        request_id: DigestIdentifier,
        version: u64,
        signers: HashSet<PublicKey>,
    },
    /// A validator acknowledged the request and is collecting the
    /// approver votes.
    Working {
        sender: PublicKey,
    },
    /// A validator can not collect for this request (never acknowledged
    /// or explicitly unavailable): it is dropped and replaced.
    Unavailable {
        sender: PublicKey,
    },
    /// A validator reports the requester is behind its governance
    /// version: the request reboots so the requester syncs first.
    Reboot {
        sender: PublicKey,
    },
    /// A validator pushes a newly observed approver vote, a signed
    /// timeout attestation or an approver abort.
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
    /// once the window lapses and the accounting is complete (every
    /// approver explained by a vote, a double vote or an attested
    /// timeout); otherwise the close waits for the attestation pushes
    /// or the next keepalive round.
    DeadlineTick,
}

impl Message for ApprovalMessage {}

impl NotPersistentActor for Approval {}

#[async_trait]
impl Actor for Approval {
    type Event = ();
    type Message = ApprovalMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Approval"),
            |parent_span| info_span!(parent: parent_span, "Approval"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Approval {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: ApprovalMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            ApprovalMessage::Create {
                request_id,
                version,
                signers,
            } => {
                let approval_req_hash = hash_borsh(
                    &*self.hash.hasher(),
                    self.request.content(),
                );
                let approval_req_hash = match approval_req_hash {
                    Ok(hash) => hash,
                    Err(e) => {
                        error!(
                            msg_type = "Create",
                            error = %e,
                            "Failed to hash approval request"
                        );
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
                self.approval_req_hash = approval_req_hash;

                // The voted subject data is derived from the approval
                // request itself: approvals only exist for governance
                // facts, whose subject is the governance (empty
                // namespace, governance schema, governance id equal to
                // the subject id).
                let req_subject_data_hash = hash_borsh(
                    &*self.hash.hasher(),
                    &RequestSubjectData {
                        subject_id: self.request.content().subject_id.clone(),
                        governance_id: self
                            .request
                            .content()
                            .subject_id
                            .clone(),
                        sn: self.request.content().sn,
                        namespace: Namespace::new(),
                        schema_id: SchemaType::Governance,
                        gov_version: self.request.content().gov_version,
                        signer: self.request.signature().signer.clone(),
                    },
                );
                let req_subject_data_hash = match req_subject_data_hash {
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
                self.req_subject_data_hash = req_subject_data_hash;

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
                            "Failed to create approval validator"
                        );
                        // Drop the failed signer so the round can
                        // exhaust itself instead of hanging forever
                        // waiting for an acknowledgement that will never
                        // come.
                        self.current_validators.remove(&signer);
                    }
                }

                if self.current_validators.is_empty() {
                    if let Err(e) = send_reboot_to_req(
                        ctx,
                        request_id.clone(),
                        self.request.content().subject_id.clone(),
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

                match Self::keepalive_secs(ctx) {
                    Ok(keepalive) => {
                        if let Err(e) = ctx.schedule_once(
                            Duration::from_secs(keepalive),
                            ApprovalMessage::KeepaliveTick,
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

                // The deadline tick re-evaluates the close without
                // waiting for a keepalive round: the collection closes
                // once the window lapses and the accounting is
                // complete.
                let until_deadline = Duration::from_nanos(
                    self.request
                        .content()
                        .deadline
                        .as_nanos()
                        .saturating_sub(TimeStamp::now().as_nanos()),
                );
                if let Err(e) = ctx.schedule_once(
                    until_deadline,
                    ApprovalMessage::DeadlineTick,
                ) {
                    error!(
                        msg_type = "Create",
                        error = %e,
                        "Failed to schedule approval deadline"
                    );
                    return Err(crash_system(ctx, e).await);
                }

                debug!(
                    msg_type = "Create",
                    request_id = %request_id,
                    version = version,
                    validators_count = current_vali.len(),
                    "Approval created and validators initialized"
                );
            }
            ApprovalMessage::Working { sender } => {
                if self.closed {
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

                self.working.insert(sender.clone());

                // A freshly acknowledged validator is surveyed
                // immediately so a recovered requester does not wait a
                // whole keepalive round for its votes. Full snapshot: a
                // new validator may hold votes the owner never saw.
                if let Err(e) =
                    self.send_status_req(ctx, sender.clone(), None).await
                {
                    error!(
                        msg_type = "Working",
                        error = %e,
                        "Failed to send approval status ask"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ApprovalMessage::Unavailable { sender } => {
                if self.closed {
                    return Ok(());
                }

                if let Err(e) =
                    self.drop_and_replace_validator(ctx, sender.clone()).await
                {
                    error!(
                        msg_type = "Unavailable",
                        error = %e,
                        sender = %sender,
                        "Failed to replace unavailable approval validator"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ApprovalMessage::Reboot { .. } => {
                if self.closed {
                    return Ok(());
                }

                Self::observe_event("reboot");
                if let Err(e) = send_reboot_to_req(
                    ctx,
                    self.request_id.clone(),
                    self.request.content().subject_id.clone(),
                    RebootType::Normal,
                )
                .await
                {
                    error!(
                        msg_type = "Reboot",
                        error = %e,
                        "Failed to send reboot to request actor"
                    );
                    return Err(crash_system(ctx, e).await);
                }

                self.closed = true;
            }
            ApprovalMessage::VoteReport { vote, sender } => {
                if self.closed {
                    return Ok(());
                }

                // Reports are accepted from any validator still in
                // play (asked, collecting, or in reserve): a pushed
                // vote can overtake the working acknowledgement.
                // Authenticity comes from the vote signatures, not
                // from this gate.
                let reporter_in_play =
                    self.current_validators.contains(&sender)
                        || self.pending_validators.contains(&sender)
                        || self.working.contains(&sender);
                if !reporter_in_play {
                    return Ok(());
                }

                // A pushed vote is proof of liveness too: it answers
                // any open keepalive round for this validator.
                self.status_pending.remove(&sender);

                // Same evidence arrives many times (every observing
                // validator pushes it, snapshots resend it): verify
                // byte-identical bytes only once.
                if !self.is_verified(&vote) {
                    if let Err(e) = vote.verify() {
                        warn!(
                            msg_type = "VoteReport",
                            sender = %sender,
                            error = %e,
                            "Approval vote with invalid signature"
                        );
                        return Ok(());
                    }
                    self.mark_verified(&vote);
                }

                // An approver ahead of the request's governance version
                // aborts it: the requester built on a stale governance.
                if let ApprovalRes::Abort(reason) = vote.content() {
                    if !self
                        .approvers
                        .workers
                        .contains(&vote.signature().signer)
                    {
                        warn!(
                            msg_type = "VoteReport",
                            sender = %sender,
                            signer = %vote.signature().signer,
                            "Approval abort from an unexpected approver"
                        );
                        return Ok(());
                    }

                    if let Err(e) = abort_req(
                        ctx,
                        self.request_id.clone(),
                        sender.clone(),
                        reason.clone(),
                        self.request.content().sn,
                    )
                    .await
                    {
                        error!(
                            msg_type = "VoteReport",
                            error = %e,
                            sender = %sender,
                            "Failed to abort request"
                        );
                        return Err(crash_system(ctx, e).await);
                    }

                    self.closed = true;
                    return Ok(());
                }

                let changed = if matches!(
                    vote.content(),
                    ApprovalRes::TimeOut { .. }
                ) {
                    self.merge_timeout(*vote, &sender)
                } else {
                    self.merge_vote(*vote)
                };

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
            ApprovalMessage::StatusRes {
                approval_req_hash,
                votes,
                sender,
            } => {
                if self.closed {
                    return Ok(());
                }

                // Same gate as VoteReport: any validator still in play.
                let reporter_in_play =
                    self.current_validators.contains(&sender)
                        || self.pending_validators.contains(&sender)
                        || self.working.contains(&sender);

                self.status_pending.remove(&sender);
                let mut changed = false;
                if approval_req_hash == self.approval_req_hash
                    && reporter_in_play
                {
                    for vote in votes {
                        if !self.is_verified(&vote) {
                            if let Err(e) = vote.verify() {
                                warn!(
                                    msg_type = "StatusRes",
                                    sender = %sender,
                                    error = %e,
                                    "Approval vote with invalid signature"
                                );
                                continue;
                            }
                            self.mark_verified(&vote);
                        }
                        changed |= if matches!(
                            vote.content(),
                            ApprovalRes::TimeOut { .. }
                        ) {
                            self.merge_timeout(vote, &sender)
                        } else {
                            self.merge_vote(vote)
                        };
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
            ApprovalMessage::KeepaliveTick => {
                if self.closed {
                    return Ok(());
                }

                let keepalive = match Self::keepalive_secs(ctx) {
                    Ok(keepalive) => keepalive,
                    Err(e) => return Err(crash_system(ctx, e).await),
                };

                // Validators silent for a whole keepalive round are
                // dropped and replaced from the pending pool.
                let dead: Vec<PublicKey> =
                    self.status_pending.drain().collect();
                for validator in &dead {
                    self.working.remove(validator);
                }

                for validator in dead {
                    debug!(
                        msg_type = "KeepaliveTick",
                        validator = %validator,
                        "Unresponsive approval validator dropped"
                    );
                    if let Err(e) =
                        self.drop_and_replace_validator(ctx, validator).await
                    {
                        error!(
                            msg_type = "KeepaliveTick",
                            error = %e,
                            "Failed to replace unresponsive validator"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                }

                // A drop may have rebooted the request: nothing left to
                // do in this phase.
                if self.closed {
                    return Ok(());
                }

                // Nobody left to answer and nothing in reserve.
                if self.awaiting_count() == 0
                    && self.pending_validators.is_empty()
                {
                    if let Err(e) = send_reboot_to_req(
                        ctx,
                        self.request_id.clone(),
                        self.request.content().subject_id.clone(),
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
                // the votes it has observed so far. Filtered rounds only
                // carry the approvers still missing evidence; every
                // N-th round sweeps everything. The ask itself is the
                // liveness heartbeat either way.
                self.keepalive_rounds = self.keepalive_rounds.saturating_add(1);
                let wanted =
                    if self.keepalive_rounds % FULL_STATUS_SWEEP_ROUNDS == 0 {
                        None
                    } else {
                        Some(self.pending_approvers())
                    };
                let working: Vec<PublicKey> =
                    self.working.iter().cloned().collect();
                self.status_pending.clone_from(&self.working);

                for validator in working {
                    if let Err(e) = self
                        .send_status_req(ctx, validator, wanted.clone())
                        .await
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
                    ApprovalMessage::KeepaliveTick,
                ) {
                    error!(
                        msg_type = "KeepaliveTick",
                        error = %e,
                        "Failed to schedule approval keepalive"
                    );
                    return Err(crash_system(ctx, e).await);
                }
            }
            ApprovalMessage::DeadlineTick => {
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

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;
    use ave_common::{
        ValueWrapper,
        identity::{KeyPair, keys::Ed25519Signer},
    };
    use std::sync::Arc;
    use tokio::sync::mpsc;

    use crate::helpers::network::{
        service::NetworkSender, test_faults::TestFaultRegistry,
    };

    fn key(signer: &Ed25519Signer) -> PublicKey {
        KeyPair::Ed25519(signer.clone()).public_key()
    }

    struct Fixture {
        approval: Approval,
        approvers: Vec<Ed25519Signer>,
        validators: Vec<Ed25519Signer>,
        req_hash: DigestIdentifier,
        subject_hash: DigestIdentifier,
    }

    fn fixture() -> Fixture {
        let owner = Ed25519Signer::generate().unwrap();
        let owner_key = key(&owner);
        let approvers: Vec<Ed25519Signer> = (0..3)
            .map(|_| Ed25519Signer::generate().unwrap())
            .collect();
        let validators: Vec<Ed25519Signer> = (0..3)
            .map(|_| Ed25519Signer::generate().unwrap())
            .collect();
        let request = Signed::new(
            ApprovalReq {
                subject_id: DigestIdentifier::default(),
                sn: 1,
                gov_version: 0,
                patch: ValueWrapper(serde_json::json!({})),
                signer: owner_key.clone(),
                issued_at: TimeStamp::from_nanos(10),
                deadline: TimeStamp::from_nanos(20),
            },
            &owner,
        )
        .unwrap();
        let hash = HashAlgorithm::Blake3;
        let req_hash =
            hash_borsh(&*hash.hasher(), request.content()).unwrap();
        let subject_hash =
            hash_borsh(&*hash.hasher(), &b"subject data".to_vec()).unwrap();
        let (tx, _) = mpsc::channel(8);
        let faults = Arc::new(std::sync::Mutex::new(
            TestFaultRegistry::new(tx.clone()),
        ));
        let mut approval = Approval::new(
            Arc::new(owner_key),
            request,
            RoleDataRegister {
                workers: approvers.iter().map(key).collect(),
                quorum: Quorum::Fixed(2),
            },
            Quorum::Fixed(2),
            hash,
            Arc::new(NetworkSender::new(tx, faults)),
        );
        approval.validators_quantity = 3;
        approval.approval_req_hash = req_hash.clone();
        approval.req_subject_data_hash = subject_hash.clone();
        Fixture {
            approval,
            approvers,
            validators,
            req_hash,
            subject_hash,
        }
    }

    fn vote(
        req_hash: &DigestIdentifier,
        subject_hash: &DigestIdentifier,
        approver: &Ed25519Signer,
        agrees: bool,
    ) -> Signed<ApprovalRes> {
        Signed::new(
            ApprovalRes::Response {
                approval_req_hash: req_hash.clone(),
                agrees,
                req_subject_data_hash: subject_hash.clone(),
            },
            approver,
        )
        .unwrap()
    }

    fn timeout(
        req_hash: &DigestIdentifier,
        validator: &Ed25519Signer,
        approver: &Ed25519Signer,
    ) -> Signed<ApprovalRes> {
        Signed::new(
            ApprovalRes::TimeOut {
                approval_req_hash: req_hash.clone(),
                who: key(approver),
            },
            validator,
        )
        .unwrap()
    }

    fn pending_set(fx: &Fixture) -> HashSet<PublicKey> {
        fx.approval.pending_approvers()
    }

    #[test]
    fn pending_approvers_tracks_votes_and_timeouts() {
        let mut fx = fixture();
        let (req_hash, subject_hash) =
            (fx.req_hash.clone(), fx.subject_hash.clone());
        let a: Vec<PublicKey> = fx.approvers.iter().map(key).collect();
        let all: HashSet<PublicKey> = a.iter().cloned().collect();
        assert_eq!(pending_set(&fx), all);

        // A verified vote settles its approver.
        assert!(
            fx.approval
                .merge_vote(vote(&req_hash, &subject_hash, &fx.approvers[0], true))
        );
        let mut rest: HashSet<PublicKey> = a[1..].iter().cloned().collect();
        assert_eq!(pending_set(&fx), rest);

        // A single timeout attestation is not a quorum of 2.
        assert!(
            fx.approval.merge_timeout(
                timeout(&req_hash, &fx.validators[0], &fx.approvers[1]),
                &key(&fx.validators[0]),
            )
        );
        assert_eq!(pending_set(&fx), rest);

        // The second attestation reaches the quorum and settles it.
        assert!(
            fx.approval.merge_timeout(
                timeout(&req_hash, &fx.validators[1], &fx.approvers[1]),
                &key(&fx.validators[1]),
            )
        );
        rest.remove(&a[1]);
        assert_eq!(pending_set(&fx), rest);

        // A conflicting pair settles the approver as excluded.
        assert!(
            fx.approval
                .merge_vote(vote(&req_hash, &subject_hash, &fx.approvers[2], true))
        );
        assert!(
            fx.approval
                .merge_vote(vote(&req_hash, &subject_hash, &fx.approvers[2], false))
        );
        assert!(pending_set(&fx).is_empty());
    }

    #[test]
    fn verified_cache_keys_on_exact_bytes() {
        let mut fx = fixture();
        let (req_hash, subject_hash) =
            (fx.req_hash.clone(), fx.subject_hash.clone());
        let a0 = fx.approvers[0].clone();
        let v = vote(&req_hash, &subject_hash, &a0, true);
        assert!(!fx.approval.is_verified(&v));
        fx.approval.mark_verified(&v);
        assert!(fx.approval.is_verified(&v));
        assert!(fx.approval.is_verified(&v.clone()));

        // The same content with another signature is different bytes:
        // it misses the cache and fails verification.
        let ApprovalRes::Response {
            approval_req_hash,
            agrees,
            req_subject_data_hash,
        } = v.content().clone()
        else {
            panic!("expected a response vote");
        };
        let other_sig =
            vote(&req_hash, &subject_hash, &a0, false).signature().clone();
        let corrupt = Signed::from_parts(
            ApprovalRes::Response {
                approval_req_hash,
                agrees,
                req_subject_data_hash,
            },
            other_sig,
        );
        assert!(!fx.approval.is_verified(&corrupt));
        assert!(corrupt.verify().is_err());
    }
}
