use ave_actors::{
    Actor, ActorError, ActorPath, Handler, Message, NotPersistentActor,
    Response,
};
use ave_common::response::MonitorNetworkState;
use tracing::{Span, info_span};

use crate::{Event as NetworkEvent, NetworkState};

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
/// Actor in charge of monitoring the network, allows communication between the actor system and the network.
pub struct Monitor {
    state: MonitorNetworkState,
    busy: bool,
    busy_causes: Vec<String>,
}

/// Snapshot of network busy status.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NetworkBusyStatus {
    /// True when network worker still has pending activity.
    pub busy: bool,
    /// Reasons why network worker is considered busy.
    pub causes: Vec<String>,
}

impl Monitor {
    /// Monitor new
    pub fn new() -> Self {
        Self {
            state: MonitorNetworkState::default(),
            busy: false,
            busy_causes: Vec::new(),
        }
    }
}

impl Default for Monitor {
    fn default() -> Self {
        Self::new()
    }
}

/// Monitor actor messages
#[derive(Debug, Clone)]
pub enum MonitorMessage {
    /// Network event
    Network(NetworkEvent),
    /// Network state
    State,
    /// Combined network busy status snapshot
    BusyStatus,
}

impl Message for MonitorMessage {}

impl NotPersistentActor for Monitor {}

/// Monitor actor responses
#[derive(Debug, Clone)]
pub enum MonitorResponse {
    /// Network state
    State(MonitorNetworkState),
    /// Combined network busy status
    BusyStatus(NetworkBusyStatus),
    /// Defaulto message
    Ok,
}

impl Response for MonitorResponse {}

#[async_trait]
impl Actor for Monitor {
    type Message = MonitorMessage;
    type Event = ();
    type Response = MonitorResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Monitor"),
            |parent_span| info_span!(parent: parent_span, "Monitor"),
        )
    }
}

#[async_trait]
impl Handler<Self> for Monitor {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: MonitorMessage,
        _ctx: &mut ave_actors::ActorContext<Self>,
    ) -> Result<MonitorResponse, ActorError> {
        match msg {
            MonitorMessage::Network(event) => {
                match event {
                    NetworkEvent::StateChanged(state) => {
                        self.state = match state {
                            NetworkState::Running => {
                                MonitorNetworkState::Running
                            }
                            NetworkState::Disconnected => {
                                MonitorNetworkState::Down
                            }
                            NetworkState::Start
                            | NetworkState::Dial
                            | NetworkState::Dialing => {
                                MonitorNetworkState::Connecting
                            }
                        };
                    }
                    NetworkEvent::BusyChanged(busy) => {
                        self.busy = busy;
                    }
                    NetworkEvent::BusyCausesChanged(causes) => {
                        self.busy_causes = causes;
                    }
                    NetworkEvent::Error(..) => {
                        self.state = MonitorNetworkState::Down;
                    }
                }
                Ok(MonitorResponse::Ok)
            }
            MonitorMessage::State => {
                Ok(MonitorResponse::State(self.state.clone()))
            }
            MonitorMessage::BusyStatus => {
                Ok(MonitorResponse::BusyStatus(NetworkBusyStatus {
                    busy: self.busy,
                    causes: self.busy_causes.clone(),
                }))
            }
        }
    }
}
