
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message, NotPersistentActor
};
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::
    error::Error
;

const TARGET_EXTERNAL: &str = "Ave-ExternalDB";


#[derive(
    Clone, Debug, Serialize, Deserialize
)]
pub struct DBManager;

impl NotPersistentActor for DBManager {}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum DBManagerMessage {
    Error(Error),
}

impl Message for DBManagerMessage {}

#[async_trait]
impl Actor for DBManager {
    type Message = DBManagerMessage;
    type Event = ();
    type Response = ();

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
impl Handler<DBManager> for DBManager {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: DBManagerMessage,
        ctx: &mut ave_actors::ActorContext<DBManager>,
    ) -> Result<(), ActorError> {
        match msg {
            DBManagerMessage::Error(error) => {
                error!(
                    TARGET_EXTERNAL,
                    "Error, Problem in Subscriber: {}", error
                );
                ctx.system().stop_system();
                Ok(())
            }
        }
    }
}