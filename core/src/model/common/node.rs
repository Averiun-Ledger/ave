use std::sync::Arc;

use ave_actors::{Actor, ActorContext, ActorError, ActorPath, Handler};

use ave_common::identity::{DigestIdentifier, PublicKey, Signature};
use ave_network::ComunicateInfo;

use crate::{
    ActorMessage, NetworkMessage, Node, NodeMessage, NodeResponse,
    auth::{SubjectAccess, SubjectAccessMessage},
    helpers::network::service::NetworkSender,
    model::event::LedgerSeal,
    node::SubjectData,
};

use ave_common::request::EventRequest;

use crate::{
    approval::{request::ApprovalReq, response::ApprovalRes},
    compilation::request::CompilationReq,
    evaluation::request::EvaluationReq,
    validation::{request::ValidationReq, response::ValidationRes},
};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SignTypesNode {
    ApprovalReq(ApprovalReq),
    ApprovalRes(Box<ApprovalRes>),

    CompilationReq(Box<CompilationReq>),
    CompilationSignature(DigestIdentifier),

    EvaluationReq(Box<EvaluationReq>),
    EvaluationSignature(DigestIdentifier),

    ValidationReq(Box<ValidationReq>),
    ValidationRes(ValidationRes),

    EventRequest(EventRequest),
    LedgerSeal(LedgerSeal),

    SinkDelivery(Vec<u8>),
}

pub async fn i_owner_new_owner<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<(bool, Option<bool>), ActorError>
where
    A: Actor + Handler<A>,
{
    let node_path = ActorPath::from("/user/node");
    let node_actor = ctx.system().get_actor::<Node>(&node_path).await?;

    let response = node_actor
        .ask(NodeMessage::IOwnerNewOwnerSubject(subject_id.to_owned()))
        .await?;

    match response {
        NodeResponse::IOwnerNewOwner {
            i_owner,
            i_new_owner,
        } => Ok((i_owner, i_new_owner)),
        _ => Err(ActorError::UnexpectedResponse {
            path: node_path,
            expected: "NodeResponse::IOwnerNewOwner".to_owned(),
        }),
    }
}

pub async fn i_can_send_last_ledger<A>(
    ctx: &mut ActorContext<A>,
    subject_id: &DigestIdentifier,
) -> Result<Option<SubjectData>, ActorError>
where
    A: Actor + Handler<A>,
{
    let node_path = ActorPath::from("/user/node");
    let node_actor = ctx.system().get_actor::<Node>(&node_path).await?;

    let response = node_actor
        .ask(NodeMessage::ICanSendLastLedger(subject_id.to_owned()))
        .await?;

    match response {
        NodeResponse::SubjectData(data) => Ok(data),
        _ => Err(ActorError::UnexpectedResponse {
            path: node_path,
            expected: "NodeResponse::SubjectData".to_owned(),
        }),
    }
}

pub async fn get_sign<A>(
    ctx: &mut ActorContext<A>,
    sign_type: SignTypesNode,
) -> Result<Signature, ActorError>
where
    A: Actor + Handler<A>,
{
    let path = ActorPath::from("/user/node");
    let node_actor = ctx.system().get_actor::<Node>(&path).await?;

    // We obtain the validator
    let node_response = node_actor
        .ask(NodeMessage::SignRequest(Box::new(sign_type)))
        .await?;

    match node_response {
        NodeResponse::SignRequest(signature) => Ok(signature),
        _ => Err(ActorError::UnexpectedResponse {
            path,
            expected: "NodeResponse::SignRequest".to_owned(),
        }),
    }
}

pub async fn get_subject_data<A>(
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
    objective: Option<PublicKey>,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let access_path = ActorPath::from("/user/node/auth");
    let access_actor = ctx
        .system()
        .get_actor::<SubjectAccess>(&access_path)
        .await?;

    access_actor
        .tell(SubjectAccessMessage::Update {
            subject_id,
            objective,
            strict: false,
        })
        .await
}

pub struct UpdateData {
    pub sn: u64,
    pub gov_version: u64,
    pub subject_id: DigestIdentifier,
    pub other_node: PublicKey,
}

pub async fn update_ledger_network(
    data: UpdateData,
    network: Arc<NetworkSender>,
) -> Result<(), ActorError> {
    let subject_string = data.subject_id.to_string();
    let request = ActorMessage::DistributionLedgerReq {
        actual_sn: Some(data.sn),
        target_sn: None,
        subject_id: data.subject_id,
        already_verified_transfer_sn: None,
    };

    let info = ComunicateInfo {
        receiver: data.other_node,
        request_id: String::default(),
        version: 0,
        receiver_actor: format!("/user/node/distributor_{}", subject_string),
    };

    network
        .send_command(ave_network::CommandHelper::SendMessage {
            message: NetworkMessage {
                info,
                message: request,
            },
        })
        .await
}
