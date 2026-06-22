use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
};
use std::future::Future;

use ave_common::{
    Namespace, SchemaType, ValueWrapper,
    identity::{DigestIdentifier, PublicKey},
    request::EventRequest,
};

use std::collections::{BTreeMap, BTreeSet, HashSet};

use crate::model::common::{OwnerContext, TrackerParams, TrackerPeers};

use crate::{
    approval::persist::{ApprPersist, ApprPersistMessage},
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData,
        data::MemberName,
        model::{
            HashThisRole, ProtocolTypes, Quorum, RoleTypes, RolesSchema,
            RolesTrackerSchemas, WitnessesData,
        },
        witnesses_register::{
            HiSnLimit, TrackerDeliveryRange, TransferData, WitnessStatus,
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        },
    },
    model::{
        common::{
            TrackerVisibilityState, check_subject_creation,
            node::get_subject_data,
        },
        event::Ledger,
    },
    node::{
        SubjectData,
        subject_manager::{
            SubjectManager, SubjectManagerMessage, SubjectManagerResponse,
        },
    },
    subject::Metadata,
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};

pub async fn get_gov<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<GovernanceData, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetGovernance)
        .await?;

    match response {
        GovernanceResponse::Governance(gov_data) => Ok(*gov_data),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::Governance".to_owned(),
            path,
        }),
    }
}

pub async fn has_role<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    role_query: HashThisRole,
) -> Result<bool, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::HasRole {
            governance_id: governance_id.clone(),
            role_query,
        })
        .await?;

    match response {
        GovernanceResponse::Bool(result) => Ok(result),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::Bool".to_owned(),
            path,
        }),
    }
}

pub async fn get_witnesses<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    data: WitnessesData,
) -> Result<HashSet<PublicKey>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetWitnesses {
            governance_id: governance_id.clone(),
            data,
        })
        .await?;

    match response {
        GovernanceResponse::Witnesses(witnesses) => Ok(witnesses),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::Witnesses".to_owned(),
            path,
        }),
    }
}

pub async fn get_schema_viewpoints<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    schema_id: SchemaType,
) -> Result<Option<BTreeSet<String>>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetSchemaViewpoints {
            governance_id: governance_id.clone(),
            schema_id,
        })
        .await?;

    match response {
        GovernanceResponse::SchemaViewpoints(viewpoints) => Ok(viewpoints),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::SchemaViewpoints".to_owned(),
            path,
        }),
    }
}

pub async fn get_quorum_and_signers<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    protocol: ProtocolTypes,
    schema_id: SchemaType,
    namespace: Namespace,
) -> Result<(HashSet<PublicKey>, Quorum), ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetQuorumAndSigners {
            governance_id: governance_id.clone(),
            protocol,
            schema_id,
            namespace,
        })
        .await?;

    match response {
        GovernanceResponse::QuorumAndSigners(signers, quorum) => {
            Ok((signers, quorum))
        }
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::QuorumAndSigners".to_owned(),
            path,
        }),
    }
}

pub async fn get_init_state<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    schema_id: SchemaType,
) -> Result<Option<ValueWrapper>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetInitState {
            governance_id: governance_id.clone(),
            schema_id,
        })
        .await?;

    match response {
        GovernanceResponse::InitState(init_state) => Ok(init_state),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::InitState".to_owned(),
            path,
        }),
    }
}

pub async fn get_signers<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    role: RoleTypes,
    schema_id: SchemaType,
    namespace: Namespace,
) -> Result<(HashSet<PublicKey>, bool), ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetSigners {
            governance_id: governance_id.clone(),
            role,
            schema_id,
            namespace,
        })
        .await?;

    match response {
        GovernanceResponse::Signers(signers, any) => Ok((signers, any)),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::Signers".to_owned(),
            path,
        }),
    }
}

pub async fn get_members<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<BTreeMap<MemberName, PublicKey>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetMembers {
            governance_id: governance_id.clone(),
        })
        .await?;

    match response {
        GovernanceResponse::Members(members) => Ok(members),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::Members".to_owned(),
            path,
        }),
    }
}

pub async fn get_schema_roles<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    schema_id: SchemaType,
) -> Result<Option<RolesSchema>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetSchemaRoles {
            governance_id: governance_id.clone(),
            schema_id,
        })
        .await?;

    match response {
        GovernanceResponse::SchemaRoles(roles) => Ok(roles),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::SchemaRoles".to_owned(),
            path,
        }),
    }
}

pub async fn get_tracker_roles<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<RolesTrackerSchemas, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let governance_actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = governance_actor
        .ask(GovernanceMessage::GetTrackerRoles {
            governance_id: governance_id.clone(),
        })
        .await?;

    match response {
        GovernanceResponse::TrackerRoles(roles) => Ok(roles),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::TrackerRoles".to_owned(),
            path,
        }),
    }
}

pub async fn up_subject<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
    requester: String,
    create_ledger: Option<Ledger>,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from("/user/node/subject_manager");
    let actor = ctx.system().get_actor::<SubjectManager>(&path).await?;
    let response = actor
        .ask(SubjectManagerMessage::Up {
            subject_id: subject_id.clone(),
            requester,
            create_ledger: create_ledger.map(Box::new),
        })
        .await?;

    match response {
        SubjectManagerResponse::Up => Ok(()),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "SubjectManagerResponse::Up".to_owned(),
            path,
        }),
    }
}

pub async fn finish_subject<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
    requester: String,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from("/user/node/subject_manager");
    let actor = ctx.system().get_actor::<SubjectManager>(&path).await?;
    let response = actor
        .ask(SubjectManagerMessage::Finish {
            subject_id: subject_id.clone(),
            requester,
        })
        .await?;

    match response {
        SubjectManagerResponse::Finish => Ok(()),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "SubjectManagerResponse::Finish".to_owned(),
            path,
        }),
    }
}

#[derive(Clone, Debug)]
pub struct SubjectLease {
    subject_id: DigestIdentifier,
    requester: String,
    active: bool,
}

impl SubjectLease {
    pub const fn is_active(&self) -> bool {
        self.active
    }

    pub async fn finish<A>(
        self,
        ctx: &mut ActorContext<A>,
    ) -> Result<(), ActorError>
    where
        A: Actor + Handler<A>,
    {
        if self.active {
            finish_subject(ctx, &self.subject_id, self.requester).await?;
        }

        Ok(())
    }

    pub async fn finish_if<A>(
        self,
        ctx: &mut ActorContext<A>,
        should_finish: bool,
    ) -> Result<(), ActorError>
    where
        A: Actor + Handler<A>,
    {
        if should_finish {
            self.finish(ctx).await?;
        }

        Ok(())
    }
}

pub async fn acquire_subject<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
    requester: String,
    create_ledger: Option<Ledger>,
    active: bool,
) -> Result<SubjectLease, ActorError>
where
    A: Actor + Handler<A>,
{
    if active {
        up_subject(ctx, subject_id, requester.clone(), create_ledger).await?;
    }

    Ok(SubjectLease {
        subject_id: subject_id.clone(),
        requester,
        active,
    })
}

pub async fn with_subject_up<A, F, Fut, T>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
    requester: String,
    create_ledger: Option<Ledger>,
    active: bool,
    operation: F,
) -> Result<T, ActorError>
where
    A: Actor + Handler<A>,
    F: FnOnce(&mut ActorContext<A>) -> Fut,
    Fut: Future<Output = Result<T, ActorError>>,
{
    let lease =
        acquire_subject(ctx, subject_id, requester, create_ledger, active)
            .await?;
    let result = operation(ctx).await;
    lease.finish(ctx).await?;
    result
}

async fn get_subject_path_and_data<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<(ActorPath, SubjectData), ActorError>
where
    A: Actor + Handler<A>,
{
    let path =
        ActorPath::from(format!("/user/node/subject_manager/{}", subject_id));
    let Some(subject_data) = get_subject_data(ctx, subject_id).await? else {
        return Err(ActorError::NotFound { path });
    };

    Ok((path, subject_data))
}

pub async fn get_metadata<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<Metadata, ActorError>
where
    A: Actor + Handler<A>,
{
    let (path, subject_data) =
        get_subject_path_and_data(ctx, subject_id).await?;

    match subject_data {
        SubjectData::Tracker { .. } => {
            let tracker_actor =
                ctx.system().get_actor::<Tracker>(&path).await?;
            let response =
                tracker_actor.ask(TrackerMessage::GetMetadata).await?;
            match response {
                TrackerResponse::Metadata(metadata) => Ok(*metadata),
                _ => Err(ActorError::UnexpectedResponse {
                    expected: "TrackerResponse::Metadata".to_owned(),
                    path,
                }),
            }
        }
        SubjectData::Governance { .. } => {
            let governance_actor =
                ctx.system().get_actor::<Governance>(&path).await?;
            let response =
                governance_actor.ask(GovernanceMessage::GetMetadata).await?;
            match response {
                GovernanceResponse::Metadata(metadata) => Ok(*metadata),
                _ => Err(ActorError::UnexpectedResponse {
                    expected: "GovernanceResponse::Metadata".to_owned(),
                    path,
                }),
            }
        }
    }
}

pub async fn get_version<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<u64, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!(
        "/user/node/subject_manager/{}",
        governance_id
    ));
    let actor = ctx.system().get_actor::<Governance>(&path).await?;
    let response = actor.ask(GovernanceMessage::GetVersion).await?;

    match response {
        GovernanceResponse::Version(version) => Ok(version),
        _ => Err(ActorError::UnexpectedResponse {
            expected: "GovernanceResponse::Version".to_owned(),
            path,
        }),
    }
}

pub async fn get_last_ledger_event<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<Option<Ledger>, ActorError>
where
    A: Actor + Handler<A>,
{
    let (path, subject_data) =
        get_subject_path_and_data(ctx, subject_id).await?;

    match subject_data {
        SubjectData::Tracker { .. } => {
            let tracker_actor =
                ctx.system().get_actor::<Tracker>(&path).await?;
            let response =
                tracker_actor.ask(TrackerMessage::GetLastLedger).await?;
            match response {
                TrackerResponse::LastLedger { ledger_event } => {
                    Ok(*ledger_event)
                }
                _ => Err(ActorError::UnexpectedResponse {
                    path,
                    expected: "TrackerResponse::LastLedger".to_owned(),
                }),
            }
        }
        SubjectData::Governance { .. } => {
            let governance_actor =
                ctx.system().get_actor::<Governance>(&path).await?;
            let response = governance_actor
                .ask(GovernanceMessage::GetLastLedger)
                .await?;
            match response {
                GovernanceResponse::LastLedger { ledger_event } => {
                    Ok(*ledger_event)
                }
                _ => Err(ActorError::UnexpectedResponse {
                    path,
                    expected: "GovernanceResponse::LastLedger".to_owned(),
                }),
            }
        }
    }
}

pub async fn update_ledger<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
    events: Vec<Ledger>,
) -> Result<(u64, PublicKey, Option<PublicKey>), ActorError>
where
    A: Actor + Handler<A>,
{
    let (path, subject_data) =
        get_subject_path_and_data(ctx, subject_id).await?;

    match subject_data {
        SubjectData::Tracker { .. } => {
            let tracker_actor =
                ctx.system().get_actor::<Tracker>(&path).await?;
            let response = tracker_actor
                .ask(TrackerMessage::UpdateLedger { events })
                .await?;
            match response {
                TrackerResponse::UpdateResult(last_sn, owner, new_owner) => {
                    Ok((last_sn, owner, new_owner))
                }
                _ => Err(ActorError::UnexpectedResponse {
                    path,
                    expected: "TrackerResponse::UpdateResult".to_owned(),
                }),
            }
        }
        SubjectData::Governance { .. } => {
            let governance_actor =
                ctx.system().get_actor::<Governance>(&path).await?;
            let response = governance_actor
                .ask(GovernanceMessage::UpdateLedger { events })
                .await?;
            match response {
                GovernanceResponse::UpdateResult(last_sn, owner, new_owner) => {
                    Ok((last_sn, owner, new_owner))
                }
                _ => Err(ActorError::UnexpectedResponse {
                    path,
                    expected: "GovernanceResponse::UpdateResult".to_owned(),
                }),
            }
        }
    }
}

pub async fn create_subject<A>(
    ctx: &mut ActorContext<A>,
    ledger: Ledger,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let mut should_finish = true;
    if ledger.get_event_request_type().is_create_event()
        && let EventRequest::Create(request) = ledger
            .get_event_request()
            .ok_or_else(|| ActorError::Functional {
                description: "Can not obtain create event request".to_string(),
            })?
    {
        if request.schema_id.is_gov() {
            should_finish = false;
        } else {
            check_subject_creation(
                ctx,
                &request.governance_id,
                ledger.ledger_seal_signature.signer.clone(),
                ledger.gov_version,
                request.namespace.to_string(),
                request.schema_id,
            )
            .await?;
        }
    }

    let subject_id = ledger.get_subject_id();
    let requester = ctx.path().to_string();
    let lease =
        acquire_subject(ctx, &subject_id, requester, Some(ledger), true)
            .await?;
    lease.finish_if(ctx, should_finish).await?;

    Ok(())
}

pub async fn get_gov_sn<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<u64, ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor.ask(WitnessesRegisterMessage::GetSnGov).await?;

    match response {
        WitnessesRegisterResponse::GovSn { sn } => Ok(sn),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::GovSn".to_string(),
        }),
    }
}

pub async fn get_tracker_sn_owner<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
) -> Result<Option<(PublicKey, u64)>, ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::GetTrackerSnOwner {
            subject_id: subject_id.clone(),
        })
        .await?;

    match response {
        WitnessesRegisterResponse::TrackerOwnerSn { data } => Ok(data),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::TrackerSn".to_string(),
        }),
    }
}

pub async fn get_tracker_visibility_state<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
) -> Result<TrackerVisibilityState, ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::GetTrackerVisibilityState {
            subject_id: subject_id.clone(),
        })
        .await?;

    match response {
        WitnessesRegisterResponse::TrackerVisibilityState { state } => {
            Ok(state)
        }
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::TrackerVisibilityState"
                .to_string(),
        }),
    }
}

pub async fn get_local_subject_sn<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<Option<u64>, ActorError>
where
    A: Actor + Handler<A>,
{
    let Some(subject_data) = get_subject_data(ctx, subject_id).await? else {
        return Ok(None);
    };

    match subject_data {
        SubjectData::Tracker { governance_id, .. } => {
            Ok(get_tracker_sn_owner(ctx, &governance_id, subject_id)
                .await?
                .map(|(_, sn)| sn))
        }
        SubjectData::Governance { .. } => {
            Ok(Some(get_gov_sn(ctx, subject_id).await?))
        }
    }
}

pub async fn get_tracker_window<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
    node: PublicKey,
    sender: PublicKey,
    params: TrackerParams,
) -> Result<
    (
        Option<u64>,
        Option<u64>,
        Option<u64>,
        bool,
        Vec<TrackerDeliveryRange>,
    ),
    ActorError,
>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::GetTrackerWindow {
            subject_id: subject_id.clone(),
            node,
            sender,
            namespace: params.namespace,
            schema_id: params.schema_id,
            actual_sn: params.actual_sn,
        })
        .await?;

    match response {
        WitnessesRegisterResponse::TrackerWindow {
            sn,
            transfer_sn,
            clear_sn,
            is_all,
            ranges,
        } => Ok((sn, transfer_sn, clear_sn, is_all, ranges)),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::TrackerWindow".to_string(),
        }),
    }
}

pub async fn get_tracker_window_from_ledger<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
    ledger: Vec<Ledger>,
    node: PublicKey,
    sender: PublicKey,
    params: TrackerParams,
) -> Result<
    (
        Option<u64>,
        Option<u64>,
        Option<u64>,
        bool,
        Vec<TrackerDeliveryRange>,
    ),
    ActorError,
>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::GetTrackerWindowFromLedger {
            subject_id: subject_id.clone(),
            ledger,
            node,
            sender,
            namespace: params.namespace,
            schema_id: params.schema_id,
            actual_sn: params.actual_sn,
        })
        .await?;

    match response {
        WitnessesRegisterResponse::TrackerWindow {
            sn,
            transfer_sn,
            clear_sn,
            is_all,
            ranges,
        } => Ok((sn, transfer_sn, clear_sn, is_all, ranges)),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::TrackerWindow".to_string(),
        }),
    }
}

pub async fn check_witness_status_and_window<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
    transfer_data: Option<TransferData>,
    peers: TrackerPeers,
    params: TrackerParams,
    owner_ctx: OwnerContext,
) -> Result<
    (
        WitnessStatus,
        Option<u64>,
        Option<u64>,
        Option<u64>,
        bool,
        Vec<TrackerDeliveryRange>,
    ),
    ActorError,
>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::QueryWitnessStatusAndWindow {
            subject_id: subject_id.clone(),
            transfer_data,
            node: peers.node,
            sender: peers.sender,
            namespace: params.namespace,
            schema_id: params.schema_id,
            actual_sn: params.actual_sn,
            owner: owner_ctx.owner,
            owner_gov_version: owner_ctx.gov_version,
        })
        .await?;

    match response {
        WitnessesRegisterResponse::WitnessStatusAndWindow {
            status,
            sn,
            transfer_sn,
            clear_sn,
            is_all,
            ranges,
        } => Ok((status, sn, transfer_sn, clear_sn, is_all, ranges)),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::WitnessStatusAndWindow"
                .to_string(),
        }),
    }
}

pub async fn check_simulated_transfer_hi_sn_limit<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
    transfer_event: Ledger,
    node: PublicKey,
    namespace: String,
    schema_id: ave_common::SchemaType,
) -> Result<HiSnLimit, ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::SimulateTransferHiSnLimit {
            subject_id: subject_id.clone(),
            transfer_event: Box::new(transfer_event),
            node,
            namespace,
            schema_id,
        })
        .await?;

    match response {
        WitnessesRegisterResponse::WitnessStatus(status) => {
            Ok(status.hi_sn_limit)
        }
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::WitnessStatus".to_string(),
        }),
    }
}

pub async fn make_obsolete<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/subject_manager/{}/approver",
        governance_id
    ));

    let actor: ActorRef<ApprPersist> =
        ctx.system().get_actor(&actor_path).await?;

    actor.tell(ApprPersistMessage::MakeObsolete).await
}
