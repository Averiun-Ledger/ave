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
}

impl Monitor {
    /// Monitor new
    pub fn new() -> Self {
        Self {
            state: MonitorNetworkState::default(),
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
}

impl Message for MonitorMessage {}

impl NotPersistentActor for Monitor {}

/// Monitor actor responses
#[derive(Debug, Clone)]
pub enum MonitorResponse {
    /// Network state
    State(MonitorNetworkState),
    /// Defaulto message
    Ok,
}

impl Response for MonitorResponse {}

#[async_trait]
impl Actor for Monitor {
    type Message = MonitorMessage;
    type Event = ();
    type Response = MonitorResponse;
    type SinkEvent = ();

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
                if matches!(
                    event,
                    NetworkEvent::StateChanged(NetworkState::Running)
                ) {
                    self.state = MonitorNetworkState::Running
                }
                Ok(MonitorResponse::Ok)
            }
            MonitorMessage::State => {
                Ok(MonitorResponse::State(self.state.clone()))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_actors::ActorSystem;
    use tokio_util::sync::CancellationToken;

    async fn setup_monitor() -> ave_actors::ActorRef<Monitor> {
        let (system, mut runner) =
            ActorSystem::create(CancellationToken::new(), CancellationToken::new());
        tokio::spawn(async move {
            runner.run().await;
        });
        let monitor = Monitor::new();
        system.create_root_actor("monitor", monitor).await.unwrap()
    }

    #[tokio::test]
    async fn monitor_new_and_default() {
        let m = Monitor::new();
        assert_eq!(m.state, MonitorNetworkState::default());
        let m2: Monitor = Default::default();
        assert_eq!(m2.state, MonitorNetworkState::default());
    }

    #[tokio::test]
    async fn monitor_get_span() {
        let span = Monitor::get_span("test-id", None);
        assert_eq!(span.metadata().unwrap().name(), "Monitor");
    }

    #[tokio::test]
    async fn monitor_handles_network_state_changed() {
        let actor_ref = setup_monitor().await;

        // Initially should be default
        let response = actor_ref.ask(MonitorMessage::State).await.unwrap();
        if let MonitorResponse::State(state) = response {
            assert_eq!(state, MonitorNetworkState::default());
        } else {
            panic!("expected State response, got {:?}", response);
        }

        // Send StateChanged(Running)
        actor_ref
            .tell(MonitorMessage::Network(NetworkEvent::StateChanged(
                NetworkState::Running,
            )))
            .await
            .unwrap();

        let response = actor_ref.ask(MonitorMessage::State).await.unwrap();
        if let MonitorResponse::State(state) = response {
            assert_eq!(state, MonitorNetworkState::Running);
        } else {
            panic!("expected State response, got {:?}", response);
        }
    }

    #[tokio::test]
    async fn monitor_handles_other_network_events() {
        let actor_ref = setup_monitor().await;

        // Send a non-Running state change — should keep default
        actor_ref
            .tell(MonitorMessage::Network(NetworkEvent::StateChanged(
                NetworkState::Dial,
            )))
            .await
            .unwrap();

        let response = actor_ref.ask(MonitorMessage::State).await.unwrap();
        if let MonitorResponse::State(state) = response {
            assert_eq!(state, MonitorNetworkState::default());
        } else {
            panic!("expected State response, got {:?}", response);
        }
    }
}
