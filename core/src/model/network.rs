use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use identity::{PublicKey, TimeStamp};
use ave_actors::{Actor, ActorContext, ActorError, ActorPath, Handler};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::{NetworkMessage, intermediary::Intermediary};

use super::{ common::emit_fail};

const TARGET_NETWORK: &str = "Ave-Model-Network";

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
    PartialOrd
)]
pub struct TimeOutResponse {
    pub who: PublicKey,
    pub re_trys: u32,
    pub timestamp: TimeStamp,
}

#[derive(Default, Clone, Debug, Serialize, Deserialize)]
pub struct RetryNetwork {}

#[async_trait]
impl Actor for RetryNetwork {
    type Event = ();
    type Message = NetworkMessage;
    type Response = ();
}

#[async_trait]
impl Handler<RetryNetwork> for RetryNetwork {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: NetworkMessage,
        ctx: &mut ActorContext<RetryNetwork>,
    ) -> Result<(), ActorError> {
        let helper: Option<Intermediary> =
            ctx.system().get_helper("network").await;

        let Some(mut helper) = helper else {
            let e = ActorError::NotHelper("network".to_owned());
            error!(TARGET_NETWORK, "Can not obtain network helper");
            return Err(emit_fail(ctx, e).await);
        };

        if let Err(e) = helper
            .send_command(network::CommandHelper::SendMessage { message: msg })
            .await
        {
            error!(TARGET_NETWORK, "Can not send message to network helper");
            return Err(emit_fail(ctx, e).await);
        };
        Ok(())
    }
}
