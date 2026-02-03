use async_trait::async_trait;
use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message, NotPersistentActor,
};
use serde::{Deserialize, Serialize};
use tracing::{Span, error, info_span};

use crate::{helpers::db::DatabaseError};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DBManager;

impl NotPersistentActor for DBManager {}

#[derive(Clone, Debug)]
pub enum DBManagerMessage {
    Error(DatabaseError),
}

impl Message for DBManagerMessage {}

#[async_trait]
impl Actor for DBManager {
    type Message = DBManagerMessage;
    type Event = ();
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "DBManager", id = id)
        } else {
            info_span!("DBManager", id = id)
        }
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
                    msg_type = "Error",
                    error = %error,
                    "Critical database error in subscriber"
                );
                ctx.system().stop_system();
                Ok(())
            }
        }
    }
}
