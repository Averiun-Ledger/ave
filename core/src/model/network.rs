use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, NotPersistentActor,
};
use ave_common::identity::{PublicKey, TimeStamp};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span};

use crate::{NetworkMessage, helpers::network::service::NetworkSender};

use super::common::emit_fail;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    PartialEq,
    Eq,
    Hash,
    BorshSerialize,
    BorshDeserialize,
    Ord,
    PartialOrd,
)]
pub struct TimeOut {
    pub who: PublicKey,
    pub re_trys: u32,
    pub timestamp: TimeStamp,
}

#[derive(Clone, Debug)]
pub struct RetryNetwork {
    network: Arc<NetworkSender>,
}

impl RetryNetwork {
    pub fn new(network: Arc<NetworkSender>) -> Self {
        Self { network }
    }
}

#[async_trait]
impl Actor for RetryNetwork {
    type Event = ();
    type Message = NetworkMessage;
    type Response = ();

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "RetryNetwork")
        } else {
            info_span!("RetryNetwork")
        }
    }
}

impl NotPersistentActor for RetryNetwork {}

#[async_trait]
impl Handler<RetryNetwork> for RetryNetwork {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: NetworkMessage,
        ctx: &mut ActorContext<RetryNetwork>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self
            .network
            .send_command(network::CommandHelper::SendMessage { message: msg })
            .await
        {
            error!(
                error = %e,
                "Failed to send message to network helper"
            );
            return Err(emit_fail(ctx, e).await);
        };
        Ok(())
    }
}
