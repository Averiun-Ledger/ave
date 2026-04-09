use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
};
use std::future::Future;

use ave_common::{
    identity::{DigestIdentifier, PublicKey},
    request::EventRequest,
};

use crate::{
    approval::persist::{ApprPersist, ApprPersistMessage},
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData,
        witnesses_register::{
            TrackerDeliveryRange, WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        },
    },
    model::{
        common::{check_subject_creation, node::get_subject_data},
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
        && let EventRequest::Create(request) =
            ledger.get_event_request().ok_or_else(|| ActorError::Functional {
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
        SubjectData::Tracker { governance_id, .. } => Ok(
            get_tracker_sn_owner(ctx, &governance_id, subject_id)
                .await?
                .map(|(_, sn)| sn),
        ),
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
    namespace: String,
    schema_id: ave_common::SchemaType,
    actual_sn: Option<u64>,
) -> Result<(Option<u64>, Option<u64>, bool, Vec<TrackerDeliveryRange>), ActorError>
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
            namespace,
            schema_id,
            actual_sn,
        })
        .await?;

    match response {
        WitnessesRegisterResponse::TrackerWindow {
            sn,
            clear_sn,
            is_all,
            ranges,
        } => Ok((sn, clear_sn, is_all, ranges)),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::TrackerWindow".to_string(),
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
