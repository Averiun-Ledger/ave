use async_trait::async_trait;
use identity::PublicKey;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message, Response,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeKey {
    key: PublicKey,
}

impl NodeKey {
    pub fn new(key: PublicKey) -> Self {
        Self { key }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeKeyMessage {
    GetPublicKey,
}

impl Message for NodeKeyMessage {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum NodeKeyResponse {
    PublicKey(PublicKey),
}

impl Response for NodeKeyResponse {}

#[async_trait]
impl Actor for NodeKey {
    type Message = NodeKeyMessage;
    type Event = ();
    type Response = NodeKeyResponse;

    async fn pre_start(
        &mut self,
        _ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<(), ActorError> {
        Ok(())
    }

    async fn pre_stop(
        &mut self,
        _ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        Ok(())
    }
}

#[async_trait]
impl Handler<NodeKey> for NodeKey {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: NodeKeyMessage,
        _ctx: &mut ave_actors::ActorContext<NodeKey>,
    ) -> Result<NodeKeyResponse, ActorError> {
        match msg {
            NodeKeyMessage::GetPublicKey => {
                Ok(NodeKeyResponse::PublicKey(self.key.clone()))
            }
        }
    }
}
