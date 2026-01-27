use std::sync::Arc;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
};

use ave_common::identity::{DigestIdentifier, PublicKey, Signature};
use network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage, Node, NodeMessage, NodeResponse,
    auth::{Auth, AuthMessage, WitnessesAuth},
    helpers::network::service::NetworkSender,
    model::event::Ledger,
    node::{
        SubjectData,
        transfer::{
            TransferRegister, TransferRegisterMessage, TransferRegisterResponse,
        },
    },
};

use ave_common::request::EventRequest;

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    evaluation::{request::EvaluationReq, response::EvaluationRes},
    validation::{request::ValidationReq, response::ValidationRes},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignTypesNode {
    ApprovalReq(ApprovalReq),
    ApprovalRes(Box<ApprovalRes>),

    EvaluationReq(EvaluationReq),
    EvaluationRes(EvaluationRes),

    ValidationReq(Box<ValidationReq>),
    ValidationRes(ValidationRes),

    EventRequest(EventRequest),
    Ledger(Ledger),
}

pub async fn subject_owner<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
) -> Result<(bool, bool), ActorError>
where
    A: Actor + Handler<A>,
{
    let node_path = ActorPath::from("/user/node");
    let node_actor: Option<ave_actors::ActorRef<Node>> =
        ctx.system().get_actor(&node_path).await;

    let response = if let Some(node_actor) = node_actor {
        node_actor
            .ask(NodeMessage::OwnerPendingSubject(subject_id.to_owned()))
            .await?
    } else {
        return Err(ActorError::NotFound(node_path));
    };

    match response {
        NodeResponse::IOwnerPending(res) => Ok(res),
        _ => Err(ActorError::UnexpectedResponse(
            node_path,
            "NodeResponse::OwnerPending".to_owned(),
        )),
    }
}

pub async fn subject_old<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
) -> Result<bool, ActorError>
where
    A: Actor + Handler<A>,
{
    let node_path = ActorPath::from("/user/node");
    let node_actor: Option<ave_actors::ActorRef<Node>> =
        ctx.system().get_actor(&node_path).await;

    let response = if let Some(node_actor) = node_actor {
        node_actor
            .ask(NodeMessage::OldSubject(subject_id.to_owned()))
            .await?
    } else {
        return Err(ActorError::NotFound(node_path));
    };

    match response {
        NodeResponse::IOld(res) => Ok(res),
        _ => Err(ActorError::UnexpectedResponse(
            node_path,
            "NodeResponse::OwnerPending".to_owned(),
        )),
    }
}

pub async fn get_sign<A>(
    ctx: &mut ActorContext<A>,
    sign_type: SignTypesNode,
) -> Result<Signature, ActorError>
where
    A: Actor + Handler<A>,
{
    let node_path = ActorPath::from("/user/node");
    let node_actor: Option<ActorRef<Node>> =
        ctx.system().get_actor(&node_path).await;

    // We obtain the validator
    let node_response = if let Some(node_actor) = node_actor {
        node_actor.ask(NodeMessage::SignRequest(sign_type)).await?
    } else {
        return Err(ActorError::NotFound(node_path));
    };

    match node_response {
        NodeResponse::SignRequest(signature) => Ok(signature),
        _ => Err(ActorError::UnexpectedResponse(
            node_path,
            "NodeResponse::SignRequest".to_owned(),
        )),
    }
}

pub async fn get_node_subject_data<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<Option<SubjectData>, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from("/user/node");
    let node_actor = ctx.system().get_actor::<Node>(&path).await?;

    let response = node_actor
        .ask(NodeMessage::GetSubjectData(subject_id.to_owned()))
        .await?;

    match response {
        NodeResponse::SubjectData(data) => Ok(data),
        _ => Err(ActorError::UnexpectedResponse {
            path,
            expected: "NodeResponse::SubjectData".to_owned(),
        }),
    }
}

pub async fn try_to_update<A>(
    ctx: &mut ActorContext<A>,
    subject_id: DigestIdentifier,
    more_info: WitnessesAuth,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let auth_path = ActorPath::from("/user/node/auth");
    let auth_actor: Option<ActorRef<Auth>> =
        ctx.system().get_actor(&auth_path).await;

    if let Some(auth_actor) = auth_actor {
        auth_actor
            .tell(AuthMessage::Update {
                subject_id,
                more_info,
            })
            .await?;
    } else {
        return Err(ActorError::NotFound(auth_path));
    }

    Ok(())
}

pub struct UpdateData {
    pub sn: u64,
    pub gov_version: u64,
    pub subject_id: DigestIdentifier,
    pub other_node: PublicKey,
}

pub async fn update_ledger_network<A>(
    ctx: &mut ActorContext<A>,
    data: UpdateData,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let subject_string = data.subject_id.to_string();
    let request = ActorMessage::DistributionLedgerReq {
        gov_version: Some(data.gov_version),
        actual_sn: Some(data.sn),
        subject_id: data.subject_id,
    };

    let info = ComunicateInfo {
        receiver: data.other_node,
        request_id: String::default(),
        version: 0,
        receiver_actor: format!("/user/node/distributor_{}", subject_string),
    };

    let helper: Option<Arc<NetworkSender>> =
        ctx.system().get_helper("network").await;

    let Some(helper) = helper else {
        let e = ActorError::NotHelper("network".to_owned());
        return Err(e);
    };

    helper
        .send_command(network::CommandHelper::SendMessage {
            message: NetworkMessage {
                info,
                message: request,
            },
        })
        .await
}

pub async fn subject_old_owner<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &str,
    old: PublicKey,
) -> Result<bool, ActorError>
where
    A: Actor + Handler<A>,
{
    let tranfer_register_path = ActorPath::from("/user/node/transfer_register");
    let transfer_register_actor: Option<
        ave_actors::ActorRef<TransferRegister>,
    > = ctx.system().get_actor(&tranfer_register_path).await;

    let response =
        if let Some(transfer_register_actor) = transfer_register_actor {
            transfer_register_actor
                .ask(TransferRegisterMessage::IsOldOwner {
                    subject_id: subject_id.to_owned(),
                    old,
                })
                .await?
        } else {
            return Err(ActorError::NotFound(tranfer_register_path));
        };

    match response {
        TransferRegisterResponse::IsOwner(res) => Ok(res),
        _ => Err(ActorError::UnexpectedResponse(
            tranfer_register_path,
            "TransferRegisterResponse::IsOwner".to_owned(),
        )),
    }
}
