use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
};

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
            WitnessesRegister, WitnessesRegisterMessage,
            WitnessesRegisterResponse,
        },
    },
    model::common::check_subject_creation,
    node::{Node, NodeMessage},
    subject::{Metadata, SignedLedger},
    tracker::{Tracker, TrackerMessage, TrackerResponse},
};

pub async fn get_gov<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<GovernanceData, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if let Ok(tracker_actor) = ctx.system().get_actor::<Tracker>(&path).await {
        let response = tracker_actor.ask(TrackerMessage::GetGovernance).await?;
        match response {
            TrackerResponse::Governance(gov_data) => Ok(*gov_data),
            _ => Err(ActorError::UnexpectedResponse {
                expected: "TrackerResponse::Governance".to_owned(),
                path,
            }),
        }
    } else if let Ok(governance_actor) =
        ctx.system().get_actor::<Governance>(&path).await
    {
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
    } else {
        Err(ActorError::NotFound { path })
    }
}

pub async fn get_metadata<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<Metadata, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if let Ok(tracker_actor) = ctx.system().get_actor::<Tracker>(&path).await {
        let response = tracker_actor.ask(TrackerMessage::GetMetadata).await?;
        match response {
            TrackerResponse::Metadata(metadata) => Ok(*metadata),
            _ => Err(ActorError::UnexpectedResponse {
                expected: "TrackerResponse::Metadata".to_owned(),
                path,
            }),
        }
    } else if let Ok(governance_actor) =
        ctx.system().get_actor::<Governance>(&path).await
    {
        let response =
            governance_actor.ask(GovernanceMessage::GetMetadata).await?;
        match response {
            GovernanceResponse::Metadata(metadata) => Ok(*metadata),
            _ => Err(ActorError::UnexpectedResponse {
                expected: "GovernanceResponse::Metadata".to_owned(),
                path,
            }),
        }
    } else {
        Err(ActorError::NotFound { path })
    }
}

pub async fn get_version<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
) -> Result<u64, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", governance_id));
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
) -> Result<Option<SignedLedger>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if let Ok(tracker_actor) = ctx.system().get_actor::<Tracker>(&path).await {
        let response = tracker_actor.ask(TrackerMessage::GetLastLedger).await?;
        match response {
            TrackerResponse::LastLedger { ledger_event } => Ok(*ledger_event),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "TrackerResponse::LastLedger".to_owned(),
            }),
        }
    } else if let Ok(governance_actor) =
        ctx.system().get_actor::<Governance>(&path).await
    {
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
    } else {
        Err(ActorError::NotFound { path })
    }
}

pub async fn update_ledger<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
    events: Vec<SignedLedger>,
) -> Result<(u64, PublicKey, Option<PublicKey>), ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if let Ok(tracker_actor) = ctx.system().get_actor::<Tracker>(&path).await {
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
    } else if let Ok(governance_actor) =
        ctx.system().get_actor::<Governance>(&path).await
    {
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
    } else {
        Err(ActorError::NotFound { path })
    }
}

pub async fn create_subject<A>(
    ctx: &mut ActorContext<A>,
    ledger: SignedLedger,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    if let EventRequest::Create(request) =
        ledger.content().event_request.content().clone()
        && !request.schema_id.is_gov()
    {
        check_subject_creation(
            ctx,
            &request.governance_id,
            ledger.signature().signer.clone(),
            ledger.content().gov_version,
            request.namespace.to_string(),
            request.schema_id,
        )
        .await?;
    }

    let node_path = ActorPath::from("/user/node");
    let node_actor = ctx.system().get_actor::<Node>(&node_path).await?;

    node_actor
        .ask(NodeMessage::CreateNewSubject(ledger))
        .await?;

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
        "/user/node/{}/witnesses_register",
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

pub async fn get_tracker_sn_creator<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
) -> Result<Option<(PublicKey, u64)>, ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::GetTrackerSnCreator {
            subject_id: subject_id.clone(),
        })
        .await?;

    match response {
        WitnessesRegisterResponse::TrackerCreatorSn { data } => Ok(data),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::TrackerSn".to_string(),
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
    let actor_path =
        ActorPath::from(format!("/user/node/{}/approver", governance_id));

    let actor: ActorRef<ApprPersist> =
        ctx.system().get_actor(&actor_path).await?;

    actor.tell(ApprPersistMessage::MakeObsolete).await
}
