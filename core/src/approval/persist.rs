use std::{collections::HashSet, sync::Arc};

use crate::{
    ActorMessage, NetworkMessage,
    approval::types::VotationType,
    db::Storable,
    governance::data::GovernanceData,
    helpers::network::{delivery_of, service::NetworkSender},
    model::common::{
        crash_system,
        node::{SignTypesNode, UpdateData, get_sign, update_ledger_network},
        purge_storage,
        subject::get_metadata,
    },
    subject::{Metadata, RequestSubjectData},
    validation::worker::{ValiWorker, ValiWorkerMessage},
};
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::{
    Namespace, SchemaType,
    bridge::request::{ApprovalState, ApprovalStateRes},
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
};
use ave_network::ComunicateInfo;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use super::{request::ApprovalReq, response::ApprovalRes};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprPersist {
    #[serde(skip)]
    helpers: Option<(HashAlgorithm, Arc<NetworkSender>)>,
    #[serde(skip)]
    our_key: Arc<PublicKey>,
    #[serde(skip)]
    subject_id: DigestIdentifier,
    #[serde(skip)]
    pass_votation: VotationType,
    #[serde(skip)]
    node_key: PublicKey,
    request_id: String,
    version: u64,
    state: Option<ApprovalState>,
    request: Option<Signed<ApprovalReq>>,
    /// Validators that asked for this vote and the actor path each one
    /// listens on: every registered asker receives the vote once cast.
    askers: Vec<(PublicKey, String)>,
    /// Current validator set of the governance: pushed by the parent
    /// governance actor on creation and on every governance change.
    /// Not persisted; the version negotiation in `check_governance`
    /// guarantees it is not stale when a request is gated.
    #[serde(skip)]
    validators: HashSet<PublicKey>,
    /// Validator appointed to (re)send a full request missed by
    /// hash-only probes, with the count of pings seen without the
    /// request arriving. Volatile: a restart simply appoints the next
    /// pinger.
    #[serde(skip)]
    needfull_supplier: Option<(PublicKey, u8)>,
}

/// Unanswered supplier pings before rotating to the next validator.
const NEEDFULL_ROTATE_AFTER: u8 = 2;

impl BorshSerialize for ApprPersist {
    fn serialize<W: std::io::Write>(
        &self,
        writer: &mut W,
    ) -> std::io::Result<()> {
        // Serialize only the persisted fields (request id, version,
        // state, request and askers); live-only maps stay in memory.
        BorshSerialize::serialize(&self.request_id, writer)?;
        BorshSerialize::serialize(&self.version, writer)?;
        BorshSerialize::serialize(&self.state, writer)?;
        BorshSerialize::serialize(&self.request, writer)?;
        BorshSerialize::serialize(&self.askers, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for ApprPersist {
    fn deserialize_reader<R: std::io::Read>(
        reader: &mut R,
    ) -> std::io::Result<Self> {
        // Deserialize the persisted fields
        let request_id = String::deserialize_reader(reader)?;
        let version = u64::deserialize_reader(reader)?;
        let state = Option::<ApprovalState>::deserialize_reader(reader)?;
        let request =
            Option::<Signed<ApprovalReq>>::deserialize_reader(reader)?;
        let askers = Vec::<(PublicKey, String)>::deserialize_reader(reader)?;

        let node_key = PublicKey::default();
        let our_key = Arc::new(PublicKey::default());
        let pass_votation = VotationType::AlwaysAccept;
        let subject_id = DigestIdentifier::default();

        Ok(Self {
            helpers: None,
            our_key,
            request_id,
            version,
            subject_id,
            pass_votation,
            state,
            request,
            askers,
            node_key,
            validators: HashSet::new(),
            needfull_supplier: None,
        })
    }
}

pub struct InitApprPersist {
    pub our_key: Arc<PublicKey>,
    pub node_key: PublicKey,
    pub subject_id: DigestIdentifier,
    pub pass_votation: VotationType,
    pub helpers: (HashAlgorithm, Arc<NetworkSender>),
    pub validators: HashSet<PublicKey>,
}

/// Outcome of the governance version check against an approval request.
enum GovernanceCheck {
    /// Versions match: the approver can vote.
    CanVote,
    /// The approver is behind the request's governance version: it can
    /// not vote until it updates (the update is requested by the check).
    Behind,
    /// The approver is ahead: the requester built the request on a stale
    /// governance and the request must abort. Carries the reason.
    Ahead(String),
}

impl ApprPersist {
    /// Checks the local governance version against the request one.
    async fn check_governance(
        &self,
        metadata: &Metadata,
        gov_version: u64,
    ) -> Result<GovernanceCheck, ActorError> {
        let Some((.., network)) = &self.helpers else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers are None".to_owned(),
            });
        };

        let governance =
            match GovernanceData::try_from(metadata.properties.clone()) {
                Ok(gov) => gov,
                Err(e) => {
                    error!(
                        subject_id = %metadata.subject_id,
                        error = %e,
                        "Failed to convert governance from properties"
                    );
                    return Err(ActorError::FunctionalCritical {
                        description: format!(
                            "can not convert governance from properties: {}",
                            e
                        ),
                    });
                }
            };

        match gov_version.cmp(&governance.version) {
            std::cmp::Ordering::Equal => {
                // If it is the same it means that we have the latest version of governance, we are up to date.
            }
            std::cmp::Ordering::Greater => {
                // Me llega una versión mayor a la mía.
                let data = UpdateData {
                    sn: metadata.sn,
                    gov_version: governance.version,
                    subject_id: metadata.subject_id.clone(),
                    other_node: self.node_key.clone(),
                };
                update_ledger_network(data, network.clone()).await?;
                return Ok(GovernanceCheck::Behind);
            }
            std::cmp::Ordering::Less => {
                return Ok(GovernanceCheck::Ahead(format!(
                    "Abort approval, governance update is required by signer: local={}, request={}",
                    governance.version, gov_version
                )));
            }
        }

        Ok(GovernanceCheck::CanVote)
    }

    /// Signs the response and routes it to the asking validator: a tell
    /// to its local worker actor when the asker is this node, a network
    /// message otherwise.
    async fn send_signed_response(
        &self,
        ctx: &mut ActorContext<Self>,
        response: ApprovalRes,
        asker: &(PublicKey, String),
        request_id: &str,
        version: u64,
    ) -> Result<(), ActorError> {
        let Some((.., network)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers are None".to_owned(),
            });
        };

        let sign_type = SignTypesNode::ApprovalRes(Box::new(response.clone()));
        let signature = get_sign(ctx, sign_type).await?;
        let signed_response: Signed<ApprovalRes> =
            Signed::from_parts(response, signature);

        if asker.0 == *self.our_key {
            match ctx
                .system()
                .get_actor::<ValiWorker>(&ActorPath::from(&asker.1))
                .await
            {
                Ok(worker) => {
                    worker
                        .tell(ValiWorkerMessage::ApprovalResponse {
                            approval_res: Box::new(signed_response),
                            request_id: request_id.to_owned(),
                            version,
                            sender: (*self.our_key).clone(),
                        })
                        .await?;
                }
                Err(e) => {
                    // The collecting validator is gone: the vote is moot.
                    debug!(
                        error = %e,
                        asker_actor = %asker.1,
                        "Validator worker not found, dropping approval response"
                    );
                }
            }
        } else {
            let new_info = ComunicateInfo {
                receiver: asker.0.clone(),
                request_id: request_id.to_owned(),
                version,
                receiver_actor: asker.1.clone(),
            };

            let message = ActorMessage::ApprovalRes {
                res: Box::new(signed_response),
            };
            if let Err(e) = network
                .send_command(ave_network::CommandHelper::SendMessage {
                    delivery: delivery_of(&message),
                    message: NetworkMessage {
                        info: new_info,
                        message,
                    },
                })
                .await
            {
                return Err(crash_system(ctx, e).await);
            };
        }

        Ok(())
    }

    async fn send_response(
        &self,
        ctx: &mut ActorContext<Self>,
        request: &Signed<ApprovalReq>,
        response: bool,
        asker: &(PublicKey, String),
        request_id: &str,
        version: u64,
    ) -> Result<(), ActorError> {
        let Some((hash, ..)) = self.helpers.clone() else {
            return Err(ActorError::FunctionalCritical {
                description: "Helpers are None".to_owned(),
            });
        };
        let approval_req_hash = hash_borsh(&*hash.hasher(), request.content())
            .map_err(|e| ActorError::FunctionalCritical {
                description: format!(
                    "Can not obtain approval request hash {}",
                    e
                ),
            })?;

        let req_subject_data_hash = hash_borsh(
            &*hash.hasher(),
            &RequestSubjectData {
                subject_id: request.content().subject_id.clone(),
                governance_id: request.content().subject_id.clone(),
                sn: request.content().sn,
                namespace: Namespace::new(),
                schema_id: SchemaType::Governance,
                gov_version: request.content().gov_version,
                signer: request.content().signer.clone(),
            },
        )
        .map_err(|e| ActorError::FunctionalCritical {
            description: format!("Can not obtain approval request hash {}", e),
        })?;

        let res = ApprovalRes::Response {
            approval_req_hash,
            agrees: response,
            req_subject_data_hash,
        };
        self.send_signed_response(ctx, res, asker, request_id, version)
            .await
    }
}

#[derive(Debug, Clone)]
pub enum ApprPersistMessage {
    MakeObsolete,
    PurgeStorage,
    // Message to request approval from the helper and return there
    NetworkRequest {
        approval_req: Signed<ApprovalReq>,
        info: ComunicateInfo,
        sender: PublicKey,
        /// Actor path the asking validator listens on for the vote.
        asker_actor: String,
    },
    /// A validator re-probes without the full request: answer from the
    /// stored request, or appoint it as the supplier of the missing
    /// full request (see `NeedFull`).
    HashPing {
        approval_req_hash: DigestIdentifier,
        info: ComunicateInfo,
        sender: PublicKey,
        /// Actor path the asking validator listens on for the vote.
        asker_actor: String,
    },
    GetApproval {
        state: Option<ApprovalState>,
    },
    ChangeResponse {
        response: ApprovalStateRes,
    }, // Emit an approval event, not just the automatic one
    /// The parent governance pushes the current validator set on every
    /// governance change.
    Update {
        validators: HashSet<PublicKey>,
        node_key: PublicKey,
    },
}

impl Message for ApprPersistMessage {
    fn is_critical(&self) -> bool {
        matches!(self, Self::MakeObsolete | Self::PurgeStorage)
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum ApprPersistEvent {
    ChangeState {
        state: ApprovalState,
    },
    SafeState {
        subject_id: DigestIdentifier,
        request_id: String,
        version: u64,
        request: Box<Signed<ApprovalReq>>,
        state: ApprovalState,
        /// First validator that asked for this vote; a new collection
        /// resets the asker list to it.
        asker: (PublicKey, String),
    },
    /// Another validator asked for the same vote.
    AddAsker {
        key: PublicKey,
        actor: String,
    },
}

impl Event for ApprPersistEvent {}

pub enum ApprPersistResponse {
    Ok,
    Approval {
        request: ApprovalReq,
        state: ApprovalState,
    },
}

impl Response for ApprPersistResponse {}

#[async_trait]
impl Actor for ApprPersist {
    type Event = ApprPersistEvent;
    type Message = ApprPersistMessage;
    type Response = ApprPersistResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ApprPersist"),
            |parent_span| info_span!(parent: parent_span, "ApprPersist"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self
            .init_store(
                "approver",
                Some(ctx.path().parent().key().to_owned()),
                false,
                ctx,
            )
            .await
        {
            error!(
                error = %e,
                "Failed to initialize approver store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for ApprPersist {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: ApprPersistMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<ApprPersistResponse, ActorError> {
        match msg {
            ApprPersistMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    subject_id = %self.subject_id,
                    "Approval storage purged"
                );

                return Ok(ApprPersistResponse::Ok);
            }
            ApprPersistMessage::Update {
                validators,
                node_key,
            } => {
                self.validators = validators;
                self.node_key = node_key;

                // A governance change obsoletes a still-pending vote:
                // it was cast against the previous role set.
                if self.state == Some(ApprovalState::Pending) {
                    self.on_event(
                        ApprPersistEvent::ChangeState {
                            state: ApprovalState::Obsolete,
                        },
                        ctx,
                    )
                    .await;
                }

                debug!(
                    msg_type = "Update",
                    subject_id = %self.subject_id,
                    validators = self.validators.len(),
                    "Approver validator set updated"
                );

                return Ok(ApprPersistResponse::Ok);
            }
            ApprPersistMessage::GetApproval { state } => {
                let res = if let Some(req) = &self.request
                    && let Some(req_state) = &self.state
                {
                    state.map_or_else(
                        || ApprPersistResponse::Approval {
                            request: req.content().clone(),
                            state: req_state.clone(),
                        },
                        |query| {
                            if &query == req_state {
                                ApprPersistResponse::Approval {
                                    request: req.content().clone(),
                                    state: query,
                                }
                            } else {
                                ApprPersistResponse::Ok
                            }
                        },
                    )
                } else {
                    ApprPersistResponse::Ok
                };

                return Ok(res);
            }
            ApprPersistMessage::MakeObsolete => {
                let state = if let Some(state) = self.state.clone() {
                    state
                } else {
                    return Ok(ApprPersistResponse::Ok);
                };

                if state == ApprovalState::Pending {
                    self.on_event(
                        ApprPersistEvent::ChangeState {
                            state: ApprovalState::Obsolete,
                        },
                        ctx,
                    )
                    .await;

                    debug!(
                        msg_type = "MakeObsolete",
                        "State changed to obsolete"
                    );
                }
            }
            ApprPersistMessage::ChangeResponse { response } => {
                let Some(state) = self.state.clone() else {
                    warn!(
                        msg_type = "ChangeResponse",
                        "Approval state not found"
                    );
                    return Err(ActorError::Functional {
                        description: "Can not get approval state".to_owned(),
                    });
                };

                if response == ApprovalStateRes::Obsolete {
                    warn!(
                        msg_type = "ChangeResponse",
                        "Invalid state transition to Obsolete"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "New state is Obsolete, is an invalid state"
                                .to_owned(),
                    });
                }

                if state == ApprovalState::Pending {
                    let (response, state) =
                        if ApprovalStateRes::Accepted == response {
                            (true, ApprovalState::Accepted)
                        } else {
                            (false, ApprovalState::Rejected)
                        };

                    let Some(approval_req) = self.request.clone() else {
                        error!(
                            msg_type = "ChangeResponse",
                            "Approval request not found"
                        );
                        return Err(ActorError::Functional {
                            description: "Can not get approval request"
                                .to_owned(),
                        });
                    };

                    // Every validator that asked for this vote receives
                    // it once cast.
                    for asker in self.askers.clone() {
                        if let Err(e) = self
                            .send_response(
                                ctx,
                                &approval_req,
                                response,
                                &asker,
                                &self.request_id.clone(),
                                self.version,
                            )
                            .await
                        {
                            error!(
                                msg_type = "ChangeResponse",
                                error = %e,
                                asker = %asker.0,
                                "Failed to send approval response"
                            );
                            return Err(crash_system(ctx, e).await);
                        };
                    }

                    debug!(
                        msg_type = "ChangeResponse",
                        new_state = ?state,
                        "State changed successfully"
                    );

                    self.on_event(ApprPersistEvent::ChangeState { state }, ctx)
                        .await;
                }
            }
            ApprPersistMessage::NetworkRequest {
                approval_req,
                info,
                sender,
                asker_actor,
            } => {
                if info.request_id != self.request_id
                    || info.version != self.version
                {
                    // Free gates first: a mismatched subject is dropped
                    // before burning a signature verification. Everything
                    // below stays after the verify on purpose: denials
                    // are signed responses, so they must only answer an
                    // owner-signed request.
                    if approval_req.content().subject_id != self.subject_id {
                        warn!(
                            msg_type = "NetworkRequest",
                            subject_id = %approval_req.content().subject_id,
                            "Approval request for another subject"
                        );
                        return Ok(ApprPersistResponse::Ok);
                    }

                    if let Err(e) = approval_req.verify() {
                        error!(
                            msg_type = "NetworkRequest",
                            error = %e,
                            "Invalid approval signature"
                        );
                        return Err(ActorError::Functional {
                            description: format!(
                                "Can not verify signature of request: {}",
                                e
                            ),
                        });
                    }

                    let metadata =
                        match get_metadata(ctx, &self.subject_id).await {
                            Ok(metadata) => metadata,
                            Err(e) => {
                                warn!(
                                    msg_type = "NetworkRequest",
                                    error = %e,
                                    "Failed to get subject metadata"
                                );
                                return Err(crash_system(ctx, e).await);
                            }
                        };

                    if approval_req.signature().signer != metadata.owner {
                        warn!(
                            msg_type = "NetworkRequest",
                            signer = %approval_req.signature().signer,
                            owner = %metadata.owner,
                            "Approval request signer is not the subject owner"
                        );
                        return Ok(ApprPersistResponse::Ok);
                    }

                    let check = match self
                        .check_governance(
                            &metadata,
                            approval_req.content().gov_version,
                        )
                        .await
                    {
                        Ok(check) => check,
                        Err(e) => {
                            warn!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Failed to check governance"
                            );
                            return Err(crash_system(ctx, e).await);
                        }
                    };

                    let asker = (sender.clone(), asker_actor);

                    let deny_response = match check {
                        GovernanceCheck::CanVote => None,
                        GovernanceCheck::Behind => {
                            Some(ApprovalRes::Unavailable)
                        }
                        GovernanceCheck::Ahead(reason) => {
                            Some(ApprovalRes::Abort(reason))
                        }
                    };

                    // Denials are answered before the validator gate on
                    // purpose: they signal a version mismatch, and a
                    // stale or newer asker may legitimately be absent
                    // from the current validator set.
                    if let Some(response) = deny_response {
                        if let Err(e) = self
                            .send_signed_response(
                                ctx,
                                response,
                                &asker,
                                &info.request_id,
                                info.version,
                            )
                            .await
                        {
                            error!(
                                msg_type = "NetworkRequest",
                                error = %e,
                                "Failed to send approval deny response"
                            );
                            return Err(crash_system(ctx, e).await);
                        }

                        return Ok(ApprPersistResponse::Ok);
                    }

                    // Only a current validator of the governance may ask
                    // for votes. The set is pushed by the parent
                    // governance on every change; the version negotiation
                    // above guarantees it is not stale here.
                    if !self.validators.contains(&sender) {
                        warn!(
                            msg_type = "NetworkRequest",
                            sender = %sender,
                            "Approval request from a non-validator"
                        );
                        return Ok(ApprPersistResponse::Ok);
                    }

                    // Replay guard: with the governance version matched,
                    // a live approval request always targets the next
                    // event of the subject; an older sequence is a
                    // replay of a committed or superseded request and
                    // must not overwrite the persisted state.
                    if approval_req.content().sn <= metadata.sn {
                        warn!(
                            msg_type = "NetworkRequest",
                            sn = approval_req.content().sn,
                            subject_sn = metadata.sn,
                            "Approval request for an already committed sequence"
                        );
                        return Ok(ApprPersistResponse::Ok);
                    }

                    // Freshness guard: a delayed request older than the
                    // persisted one (earlier issued_at, then older
                    // version, then request id as the tie-breaker) must
                    // never overwrite the newer state.
                    if !self.request_id.is_empty() {
                        let incoming = (
                            approval_req.content().issued_at.as_nanos(),
                            info.version,
                            info.request_id.as_str(),
                        );
                        let stored = (
                            self.request.as_ref().map_or(0, |request| {
                                request.content().issued_at.as_nanos()
                            }),
                            self.version,
                            self.request_id.as_str(),
                        );
                        if incoming <= stored {
                            warn!(
                                msg_type = "NetworkRequest",
                                stored_request_id = %self.request_id,
                                stored_version = self.version,
                                incoming_request_id = %info.request_id,
                                incoming_version = info.version,
                                "Stale approval request ignored"
                            );
                            return Ok(ApprPersistResponse::Ok);
                        }
                    }

                    let state =
                        if self.pass_votation == VotationType::AlwaysAccept {
                            ApprovalState::Accepted
                        } else {
                            ApprovalState::Pending
                        };

                    self.on_event(
                        ApprPersistEvent::SafeState {
                            subject_id: self.subject_id.clone(),
                            request_id: info.request_id.clone(),
                            version: info.version,
                            request: Box::new(approval_req.clone()),
                            state: state.clone(),
                            asker: asker.clone(),
                        },
                        ctx,
                    )
                    .await;

                    match state {
                        ApprovalState::Accepted => {
                            if let Err(e) = self
                                .send_response(
                                    ctx,
                                    &approval_req,
                                    true,
                                    &asker,
                                    &info.request_id,
                                    info.version,
                                )
                                .await
                            {
                                error!(
                                    msg_type = "NetworkRequest",
                                    error = %e,
                                    "Failed to send approval response"
                                );
                                return Err(crash_system(ctx, e).await);
                            };
                        }
                        _ => {
                            // Manual voting: the asker is told the vote
                            // is pending instead of being kept waiting.
                            if let Err(e) = self
                                .send_signed_response(
                                    ctx,
                                    ApprovalRes::Pending,
                                    &asker,
                                    &info.request_id,
                                    info.version,
                                )
                                .await
                            {
                                error!(
                                    msg_type = "NetworkRequest",
                                    error = %e,
                                    "Failed to send approval pending response"
                                );
                                return Err(crash_system(ctx, e).await);
                            };
                        }
                    }

                    debug!(
                        msg_type = "NetworkRequest",
                        request_id = %info.request_id,
                        version = info.version,
                        new_state = ?state,
                        "Network approval request processed"
                    );
                } else if !self.request_id.is_empty() {
                    // A validator re-asking for the same collection (a
                    // probe retry or a replacement validator): the same
                    // gate as the first delivery applies, against the
                    // current validator set pushed by the governance.
                    if !self.validators.contains(&sender) {
                        warn!(
                            msg_type = "NetworkRequest",
                            sender = %sender,
                            "Approval re-ask from a non-validator"
                        );
                        return Ok(ApprPersistResponse::Ok);
                    }

                    self.resend_stored_answer(
                        ctx,
                        (sender, asker_actor),
                        "NetworkRequest",
                    )
                    .await?;
                }
            }
            ApprPersistMessage::HashPing {
                approval_req_hash,
                info,
                sender,
                asker_actor,
            } => {
                // Only a current validator may ping. The set is pushed
                // by the parent governance on every change.
                if !self.validators.contains(&sender) {
                    warn!(
                        msg_type = "HashPing",
                        sender = %sender,
                        "Hash ping from a non-validator"
                    );
                    return Ok(ApprPersistResponse::Ok);
                }

                // Stored request for this collection: answer from it
                // like a re-ask (vote, pending, or nothing when
                // obsolete).
                let stored_matches = info.request_id == self.request_id
                    && info.version == self.version
                    && !self.request_id.is_empty()
                    && self.request.as_ref().is_some_and(|request| {
                        let Some((hash, ..)) = self.helpers.clone() else {
                            return false;
                        };
                        hash_borsh(&*hash.hasher(), request.content())
                            .is_ok_and(|hash| hash == approval_req_hash)
                    });
                if stored_matches {
                    self.resend_stored_answer(
                        ctx,
                        (sender, asker_actor),
                        "HashPing",
                    )
                    .await?;
                    return Ok(ApprPersistResponse::Ok);
                }

                // Missing request: appoint one supplier at a time and
                // rotate to the most recent pinger when it does not
                // deliver. No timers: every ping either appoints,
                // counts, or rotates, so a dead supplier can never wedge
                // the wait while other validators keep probing.
                let asker = (sender.clone(), asker_actor);
                let rotate = match &self.needfull_supplier {
                    None => true,
                    Some((current, attempts)) => {
                        *current != sender
                            || *attempts + 1 >= NEEDFULL_ROTATE_AFTER
                    }
                };
                if rotate {
                    self.needfull_supplier = Some((sender.clone(), 0));
                    self.send_need_full(
                        ctx,
                        &approval_req_hash,
                        &asker,
                        &info.request_id,
                        info.version,
                    )
                    .await?;
                } else if let Some((current, attempts)) =
                    self.needfull_supplier.clone()
                {
                    self.needfull_supplier = Some((current, attempts + 1));
                }
            }
        }
        Ok(ApprPersistResponse::Ok)
    }
}

impl ApprPersist {
    /// Answers a validator from the stored request: registers it as an
    /// asker and resends the vote (or the pending notice).
    async fn resend_stored_answer(
        &mut self,
        ctx: &mut ActorContext<Self>,
        asker: (PublicKey, String),
        msg_type: &'static str,
    ) -> Result<(), ActorError> {
        if !self.askers.contains(&asker) {
            self.on_event(
                ApprPersistEvent::AddAsker {
                    key: asker.0.clone(),
                    actor: asker.1.clone(),
                },
                ctx,
            )
            .await;
        }

        let state = if let Some(state) = self.state.clone() {
            state
        } else {
            warn!(msg_type = msg_type, "Approval state not found");
            let e = ActorError::FunctionalCritical {
                description: "Can not get state".to_owned(),
            };
            return Err(crash_system(ctx, e).await);
        };

        match state {
            ApprovalState::Accepted | ApprovalState::Rejected => {
                let approval_req = if let Some(approval_req) =
                    self.request.clone()
                {
                    approval_req
                } else {
                    error!(msg_type = msg_type, "Approval request not found");
                    let e = ActorError::FunctionalCritical {
                        description: "Can not get approve request".to_owned(),
                    };
                    return Err(crash_system(ctx, e).await);
                };

                if let Err(e) = self
                    .send_response(
                        ctx,
                        &approval_req,
                        state == ApprovalState::Accepted,
                        &asker,
                        &self.request_id.clone(),
                        self.version,
                    )
                    .await
                {
                    error!(
                        msg_type = msg_type,
                        error = %e,
                        "Failed to resend approval response"
                    );
                    return Err(crash_system(ctx, e).await);
                };

                debug!(
                    msg_type = msg_type,
                    request_id = %self.request_id,
                    version = self.version,
                    "Response resent successfully"
                );
            }
            ApprovalState::Pending => {
                if let Err(e) = self
                    .send_signed_response(
                        ctx,
                        ApprovalRes::Pending,
                        &asker,
                        &self.request_id.clone(),
                        self.version,
                    )
                    .await
                {
                    error!(
                        msg_type = msg_type,
                        error = %e,
                        "Failed to send approval pending response"
                    );
                    return Err(crash_system(ctx, e).await);
                };
            }
            ApprovalState::Obsolete => {}
        }
        Ok(())
    }

    /// Asks one validator for the missing full request.
    async fn send_need_full(
        &self,
        ctx: &mut ActorContext<Self>,
        approval_req_hash: &DigestIdentifier,
        asker: &(PublicKey, String),
        request_id: &str,
        version: u64,
    ) -> Result<(), ActorError> {
        if let Err(e) = self
            .send_signed_response(
                ctx,
                ApprovalRes::NeedFull {
                    approval_req_hash: approval_req_hash.clone(),
                },
                asker,
                request_id,
                version,
            )
            .await
        {
            error!(
                msg_type = "HashPing",
                error = %e,
                asker = %asker.0,
                "Failed to send NeedFull"
            );
            return Err(crash_system(ctx, e).await);
        }
        Ok(())
    }

    async fn on_event(
        &mut self,
        event: ApprPersistEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(event, ctx).await {
            error!(error = %e, "Failed to persist event");
            crash_system(ctx, e).await;
        };
    }
}

// The request state is persisted until it is approved
#[async_trait]
impl PersistentActor for ApprPersist {
    type Persistence = LightPersistence;
    type InitParams = InitApprPersist;
    type State = Self;

    fn create_initial(params: Self::InitParams) -> Self {
        let Self::InitParams {
            our_key,
            node_key,
            subject_id,
            pass_votation,
            helpers,
            validators,
        } = params;

        Self {
            helpers: Some(helpers),
            node_key,
            our_key,
            request_id: String::default(),
            version: 0,
            subject_id,
            pass_votation,
            state: None,
            request: None,
            askers: Vec::new(),
            validators,
            needfull_supplier: None,
        }
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            ApprPersistEvent::ChangeState { state, .. } => {
                debug!(
                    event_type = "ChangeState",
                    new_state = ?state,
                    "Approval state changed"
                );
                inner.state = Some(state.clone());
                // Any transition settles the wait for a missing full
                // request (voted, or the request is dead).
                inner.needfull_supplier = None;
            }
            ApprPersistEvent::SafeState {
                request,
                state,
                request_id,
                version,
                asker,
                ..
            } => {
                debug!(
                    event_type = "SafeState",
                    request_id = %request_id,
                    version = version,
                    new_state = ?state,
                    "Approval state saved"
                );
                inner.version = *version;
                inner.request_id.clone_from(request_id);
                inner.request = Some(*request.clone());
                inner.state = Some(state.clone());
                inner.askers = vec![asker.clone()];
                // The full request arrived: no supplier needed.
                inner.needfull_supplier = None;
            }
            ApprPersistEvent::AddAsker { key, actor } => {
                debug!(
                    event_type = "AddAsker",
                    key = %key,
                    "Approval asker registered"
                );
                let asker = (key.clone(), actor.clone());
                if !inner.askers.contains(&asker) {
                    inner.askers.push(asker);
                }
            }
        };

        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        Arc::new(self.clone())
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        let state = &*state;
        self.request_id.clone_from(&state.request_id);
        self.version = state.version;
        self.state.clone_from(&state.state);
        self.request.clone_from(&state.request);
        self.askers.clone_from(&state.askers);
    }
}

impl Storable for ApprPersist {}
