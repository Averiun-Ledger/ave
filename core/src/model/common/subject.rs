use std::collections::HashSet;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
};

use ave_common::{
    Namespace,
    identity::{PublicKey, Signed},
};

use crate::{
    Event as AveEvent,
    governance::{
        Governance, GovernanceMessage, GovernanceResponse,
        data::GovernanceData,
        model::{ProtocolTypes, Quorum}, relationship::{OwnerSchema, RelationShip, RelationShipMessage, RelationShipResponse},
    },
    model::{event::ProtocolsSignatures, request::SchemaType},
    subject::{
        Metadata, SignedLedger,
        laststate::{LastState, LastStateMessage, LastStateResponse},
    },
    tracker::{Tracker, TrackerMessage, TrackerResponse},
    validation::proof::ValidationProof,
};

pub async fn get_gov<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
) -> Result<GovernanceData, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if let Some(tracker_actor) = ctx.system().get_actor::<Tracker>(&path).await
    {
        let response = tracker_actor.ask(TrackerMessage::GetGovernance).await?;
        match response {
            TrackerResponse::Governance(gov_data) => Ok(*gov_data),
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "TrackerResponse::Governance".to_owned(),
            )),
        }
    } else if let Some(governance_actor) =
        ctx.system().get_actor::<Governance>(&path).await
    {
        let response = governance_actor
            .ask(GovernanceMessage::GetGovernance)
            .await?;
        match response {
            GovernanceResponse::Governance(gov_data) => Ok(*gov_data),
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "GovernanceResponse::Governance".to_owned(),
            )),
        }
    } else {
        Err(ActorError::NotFound(path))
    }
}

pub async fn get_metadata<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
) -> Result<Metadata, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if let Some(tracker_actor) = ctx.system().get_actor::<Tracker>(&path).await
    {
        let response = tracker_actor.ask(TrackerMessage::GetMetadata).await?;
        match response {
            TrackerResponse::Metadata(metadata) => Ok(*metadata),
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "TrackerResponse::Metadata".to_owned(),
            )),
        }
    } else if let Some(governance_actor) =
        ctx.system().get_actor::<Governance>(&path).await
    {
        let response =
            governance_actor.ask(GovernanceMessage::GetMetadata).await?;
        match response {
            GovernanceResponse::Metadata(metadata) => Ok(*metadata),
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "GovernanceResponse::Metadata".to_owned(),
            )),
        }
    } else {
        Err(ActorError::NotFound(path))
    }
}

pub async fn update_last_state<A>(
    ctx: &mut ActorContext<A>,
    event: Signed<AveEvent>,
    proof: ValidationProof,
    vali_res: Vec<ProtocolsSignatures>,
) -> Result<bool, ActorError>
where
    A: Actor + Handler<A>,
{
    let last_state_path = ActorPath::from(format!(
        "/user/node/{}/last_state",
        event.content.subject_id
    ));
    let last_state_actor: Option<ActorRef<LastState>> =
        ctx.system().get_actor(&last_state_path).await;

    let response = if let Some(last_state_actor) = last_state_actor {
        last_state_actor
            .ask(LastStateMessage::UpdateLastState {
                proof: Box::new(proof),
                event: Box::new(event),
                vali_res,
            })
            .await?
    } else {
        return Err(ActorError::NotFound(last_state_path));
    };

    match response {
        LastStateResponse::Ok => Ok(true),
        LastStateResponse::LessThanOurSn => Ok(false),
        _ => Err(ActorError::UnexpectedResponse(
            last_state_path,
            "LastStateResponse::Ok |  LastStateResponse::LessThanOurSn"
                .to_owned(),
        )),
    }
}

pub async fn get_signers_quorum_gov_version<A>(
    ctx: &mut ActorContext<A>,
    governance: &str,
    schema_id: &SchemaType,
    namespace: Namespace,
    role: ProtocolTypes,
) -> Result<(HashSet<PublicKey>, Quorum, u64), ActorError>
where
    A: Actor + Handler<A>,
{
    let gov = get_gov(ctx, governance).await?;
    let (signers, quorum) =
        gov.get_quorum_and_signers(role, schema_id, namespace)?;
    Ok((signers, quorum, gov.version))
}

pub async fn get_last_state<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
) -> Result<
    (
        Box<Signed<AveEvent>>,
        Box<ValidationProof>,
        Vec<ProtocolsSignatures>,
    ),
    ActorError,
>
where
    A: Actor + Handler<A>,
{
    let last_state_path =
        ActorPath::from(format!("/user/node/{}/last_state", subject_id));
    let last_state_actor: Option<ActorRef<LastState>> =
        ctx.system().get_actor(&last_state_path).await;

    let response = if let Some(last_state_actor) = last_state_actor {
        last_state_actor.ask(LastStateMessage::GetLastState).await?
    } else {
        return Err(ActorError::NotFound(last_state_path));
    };

    match response {
        LastStateResponse::LastState {
            proof,
            event,
            vali_res,
        } => Ok((event, proof, vali_res)),
        _ => Err(ActorError::UnexpectedResponse(
            last_state_path,
            "LedgerEventResponse::LastEvent".to_owned(),
        )),
    }
}

pub async fn update_ledger<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
    events: Vec<SignedLedger>,
    is_gov: bool,
) -> Result<(u64, PublicKey, Option<PublicKey>), ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from(format!("/user/node/{}", subject_id));

    if is_gov {
        let response = if let Some(governance_actor) =
            ctx.system().get_actor::<Governance>(&path).await
        {
            governance_actor
                .ask(GovernanceMessage::UpdateLedger { events })
                .await?
        } else {
            return Err(ActorError::NotFound(path));
        };

        match response {
            GovernanceResponse::UpdateResult(last_sn, owner, new_owner) => {
                Ok((last_sn, owner, new_owner))
            }
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "GovernanceResponse::UpdateResult".to_owned(),
            )),
        }
    } else {
        let response = if let Some(tracker_actor) =
            ctx.system().get_actor::<Tracker>(&path).await
        {
            tracker_actor
                .ask(TrackerMessage::UpdateLedger { events })
                .await?
        } else {
            return Err(ActorError::NotFound(path));
        };

        match response {
            TrackerResponse::UpdateResult(last_sn, owner, new_owner) => {
                Ok((last_sn, owner, new_owner))
            }
            _ => Err(ActorError::UnexpectedResponse(
                path,
                "TrackerResponse::UpdateResult".to_owned(),
            )),
        }
    }
}

pub async fn get_quantity<A>(
    ctx: &mut ActorContext<A>,
    gov: String,
    schema_id: SchemaType,
    owner: String,
    namespace: String,
) -> Result<usize, ActorError>
where
    A: Actor + Handler<A>,
{
    let relation_path =
        ActorPath::from(&format!("/user/node/{}/relation_ship", gov));
    let relation_actor: Option<ActorRef<RelationShip>> =
        ctx.system().get_actor(&relation_path).await;

    let response = if let Some(relation_actor) = relation_actor {
        relation_actor
            .ask(RelationShipMessage::GetSubjectsCount(OwnerSchema {
                owner,
                schema_id,
                namespace,
            }))
            .await?
    } else {
        return Err(ActorError::NotFound(relation_path));
    };

    if let RelationShipResponse::Count(quantity) = response {
        Ok(quantity)
    } else {
        Err(ActorError::UnexpectedResponse(
            relation_path,
            "RelationShipResponse::Count".to_owned(),
        ))
    }
}
