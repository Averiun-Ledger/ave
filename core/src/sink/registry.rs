//! Persistent registry of configured and residual sinks.
//!
//! The registry stores every sink that should be observable in the node. Sinks
//! declared in the node configuration are registered at startup with
//! `from_config: true`. Sinks that are removed from configuration but still
//! have persisted cursors are kept in the registry (or re-registered on
//! startup) with `from_config: false`, so operators can still inspect and
//! delete them until they are fully cleaned up.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::{
    db::Storable,
    model::common::{crash_system, purge_storage},
};

/// Stored metadata for a single sink.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct SinkRegistration {
    /// Unique sink identifier (matches `SinkServer.server`).
    pub name: String,
    /// Schema identifier this sink is associated with.
    pub schema_id: String,
    /// Governance identifier when `schema_id` is not `"governance"`.
    pub governance_id: Option<String>,
    /// Whether the sink is currently declared in the node configuration.
    pub from_config: bool,
}

/// Messages accepted by [`SinkRegistry`].
#[derive(Debug, Clone)]
pub enum SinkRegistryMessage {
    /// Register (or update) a sink in the registry.
    RegisterSink {
        name: String,
        schema_id: String,
        governance_id: Option<String>,
        from_config: bool,
    },
    /// Remove a sink from the registry.
    UnregisterSink { name: String },
    /// Return the current list of registered sinks.
    GetSinkRegistry,
    /// Check whether a sink name is currently registered.
    GetSink { name: String },
    /// Purge all persisted registry storage.
    PurgeStorage,
}

impl Message for SinkRegistryMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::RegisterSink { .. }
                | Self::UnregisterSink { .. }
                | Self::PurgeStorage
        )
    }
}

/// Responses emitted by [`SinkRegistry`].
#[derive(Debug, Clone)]
pub enum SinkRegistryResponse {
    /// Acknowledgement after a state-changing operation.
    Ok,
    /// Full snapshot of the registry.
    Registry(Vec<SinkRegistration>),
    /// Lookup result for a single sink name.
    Sink(Option<SinkRegistration>),
}

impl Response for SinkRegistryResponse {}

/// Persistent events used to mutate the registry state.
#[derive(
    Debug, Clone, Serialize, Deserialize, BorshSerialize, BorshDeserialize,
)]
pub enum SinkRegistryEvent {
    SinkRegistered {
        name: String,
        schema_id: String,
        governance_id: Option<String>,
        from_config: bool,
    },
    SinkUnregistered {
        name: String,
    },
}

impl Event for SinkRegistryEvent {}

/// Persistent registry of sinks.
#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct SinkRegistry {
    sinks: HashMap<String, SinkRegistration>,
}

impl SinkRegistry {
    async fn on_event(
        &mut self,
        event: SinkRegistryEvent,
        ctx: &mut ActorContext<Self>,
    ) {
        if let Err(e) = self.persist(event, ctx).await {
            error!(error = %e, "Failed to persist sink registry event");
            crash_system(ctx, e).await;
        }
    }
}

#[async_trait]
impl Actor for SinkRegistry {
    type Message = SinkRegistryMessage;
    type Event = SinkRegistryEvent;
    type Response = SinkRegistryResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("SinkRegistry"),
            |parent_span| info_span!(parent: parent_span, "SinkRegistry"),
        )
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.init_store("sink_registry", None, false, ctx).await
        {
            error!(error = %e, "Failed to initialize sink registry store");
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<Self> for SinkRegistry {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: SinkRegistryMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<SinkRegistryResponse, ActorError> {
        match msg {
            SinkRegistryMessage::RegisterSink {
                name,
                schema_id,
                governance_id,
                from_config,
            } => {
                debug!(
                    sink = %name,
                    schema_id = %schema_id,
                    ?governance_id,
                    from_config,
                    "Registering sink"
                );
                let existing = self.sinks.get(&name);
                let changed = existing.is_none_or(|reg| {
                    reg.schema_id != schema_id
                        || reg.governance_id != governance_id
                        || reg.from_config != from_config
                });
                if changed {
                    self.on_event(
                        SinkRegistryEvent::SinkRegistered {
                            name: name.clone(),
                            schema_id: schema_id.clone(),
                            governance_id: governance_id.clone(),
                            from_config,
                        },
                        ctx,
                    )
                    .await;
                }
                Ok(SinkRegistryResponse::Ok)
            }
            SinkRegistryMessage::UnregisterSink { name } => {
                debug!(sink = %name, "Unregistering sink");
                if self.sinks.contains_key(&name) {
                    self.on_event(
                        SinkRegistryEvent::SinkUnregistered { name },
                        ctx,
                    )
                    .await;
                }
                Ok(SinkRegistryResponse::Ok)
            }
            SinkRegistryMessage::GetSinkRegistry => {
                let values: Vec<_> = self.sinks.values().cloned().collect();
                Ok(SinkRegistryResponse::Registry(values))
            }
            SinkRegistryMessage::GetSink { name } => {
                let sink = self.sinks.get(&name).cloned();
                Ok(SinkRegistryResponse::Sink(sink))
            }
            SinkRegistryMessage::PurgeStorage => {
                purge_storage(ctx).await?;
                debug!("Sink registry storage purged");
                Ok(SinkRegistryResponse::Ok)
            }
        }
    }
}

#[async_trait]
impl PersistentActor for SinkRegistry {
    type Persistence = LightPersistence;
    type InitParams = ();
    type State = Self;

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(
        state: Arc<Self::State>,
        event: &Self::Event,
    ) -> Result<Arc<Self::State>, ActorError> {
        let mut state = Arc::clone(&state);
        let inner = Arc::make_mut(&mut state);
        match event {
            SinkRegistryEvent::SinkRegistered {
                name,
                schema_id,
                governance_id,
                from_config,
            } => {
                inner.sinks.insert(
                    name.clone(),
                    SinkRegistration {
                        name: name.clone(),
                        schema_id: schema_id.clone(),
                        governance_id: governance_id.clone(),
                        from_config: *from_config,
                    },
                );
                debug!(
                    sink = %name,
                    schema_id = %schema_id,
                    ?governance_id,
                    from_config,
                    "Sink registered in state"
                );
            }
            SinkRegistryEvent::SinkUnregistered { name } => {
                inner.sinks.remove(name);
                debug!(sink = %name, "Sink unregistered from state");
            }
        }
        Ok(state)
    }

    fn state(&self) -> Arc<Self::State> {
        Arc::new(self.clone())
    }

    fn set_state(&mut self, state: Arc<Self::State>) {
        *self = (*state).clone();
    }
}

#[async_trait]
impl Storable for SinkRegistry {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_register_and_unregister_events() {
        let registry = SinkRegistry::default();
        let state = registry.state();

        let state = SinkRegistry::apply(
            state,
            &SinkRegistryEvent::SinkRegistered {
                name: "node-sink".to_owned(),
                schema_id: "governance".to_owned(),
                governance_id: None,
                from_config: true,
            },
        )
        .unwrap();

        assert_eq!(state.sinks.len(), 1);
        let reg = state.sinks.get("node-sink").unwrap();
        assert_eq!(reg.schema_id, "governance");
        assert!(reg.from_config);

        let gov_id = "governance-1".to_owned();
        let state = SinkRegistry::apply(
            state,
            &SinkRegistryEvent::SinkRegistered {
                name: "tracker-sink".to_owned(),
                schema_id: "schema-a".to_owned(),
                governance_id: Some(gov_id.clone()),
                from_config: false,
            },
        )
        .unwrap();

        assert_eq!(state.sinks.len(), 2);
        let reg = state.sinks.get("tracker-sink").unwrap();
        assert_eq!(reg.schema_id, "schema-a");
        assert_eq!(reg.governance_id, Some(gov_id));
        assert!(!reg.from_config);

        let state = SinkRegistry::apply(
            state,
            &SinkRegistryEvent::SinkUnregistered {
                name: "node-sink".to_owned(),
            },
        )
        .unwrap();

        assert_eq!(state.sinks.len(), 1);
        assert!(!state.sinks.contains_key("node-sink"));
    }

    #[test]
    fn registration_update_keeps_latest_values() {
        let registry = SinkRegistry::default();
        let state = registry.state();

        let state = SinkRegistry::apply(
            state,
            &SinkRegistryEvent::SinkRegistered {
                name: "sink".to_owned(),
                schema_id: "schema-a".to_owned(),
                governance_id: Some("gov-a".to_owned()),
                from_config: true,
            },
        )
        .unwrap();

        let state = SinkRegistry::apply(
            state,
            &SinkRegistryEvent::SinkRegistered {
                name: "sink".to_owned(),
                schema_id: "schema-a".to_owned(),
                governance_id: Some("gov-a".to_owned()),
                from_config: false,
            },
        )
        .unwrap();

        let reg = state.sinks.get("sink").unwrap();
        assert!(!reg.from_config);
    }
}
