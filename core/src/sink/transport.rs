//! Transport abstraction for sink delivery.

use std::sync::Arc;

use async_trait::async_trait;
use ave_actors::ActorRef;
use ave_common::identity::Signature;
use ave_common::{DataToSink, LightEvent};

use crate::config::{SinkServer, SinkTransportConfig};
use crate::model::common::node::SignTypesNode;
use crate::node::{Node, NodeMessage, NodeResponse};
use crate::sink::{
    error::SinkError, http::HttpTransport, kafka::KafkaTransport,
};
use ave_common::IncomingSinkEvent;

/// Transport contract implemented by each sink delivery mechanism.
#[async_trait]
pub trait SinkTransport: Send + Sync + std::fmt::Debug {
    /// Deliver a full event to the sink.
    async fn send(&self, data: Arc<DataToSink>) -> Result<(), SinkError>;
    /// Deliver a light event (event type not covered by the `events` filter).
    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError>;
    /// Deliver a batch of events as a single payload. Only used when the
    /// sink opts into batch delivery. The default implementation delivers
    /// the events sequentially, preserving order and aborting on the first
    /// error.
    async fn send_batch(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        for event in events {
            match event {
                IncomingSinkEvent::Full(data) => self.send(data).await?,
                IncomingSinkEvent::Light(light) => {
                    self.send_light(light).await?
                }
            }
        }
        Ok(())
    }
    /// Best-effort batch delivery: a single attempt, no retries. Used during
    /// Pause/Stop teardown where blocking on retries would delay actor
    /// shutdown; the cursor guarantees re-delivery via catch-up. The default
    /// implementation delegates to `send_batch`.
    async fn send_batch_best_effort(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        self.send_batch(events).await
    }
    /// Health check of the endpoint.
    async fn health_check(&self) -> Result<(), SinkError>;
    /// Non-persistent test delivery. Verifies that the endpoint is reachable
    /// and accepts a payload using the same authentication, signature and
    /// compression configuration as real deliveries, without advancing any
    /// cursor or altering persisted state.
    async fn test(&self) -> Result<(), SinkError> {
        // Transports that do not implement a dedicated test path fall back to
        // the health check. This is safe but may not exercise auth/signature.
        self.health_check().await
    }
    /// Transport startup logic (HTTP: eager OAuth2 token fetch).
    /// Default: no-op.
    async fn warm_up(&self) -> Result<(), SinkError> {
        Ok(())
    }
}

/// Signs sink delivery payloads with the node identity.
///
/// A cheap, cloneable handle to the node actor; only HTTP sinks with
/// `signature = true` receive one.
#[derive(Clone, Debug)]
pub struct NodeSigner {
    node: ActorRef<Node>,
}

impl NodeSigner {
    pub const fn new(node: ActorRef<Node>) -> Self {
        Self { node }
    }

    /// Ask the node to sign a delivery payload. Signing happens once per
    /// logical event and the result is reused across delivery retries.
    pub async fn sign(&self, payload: Vec<u8>) -> Result<Signature, SinkError> {
        let response = self
            .node
            .ask(NodeMessage::SignRequest(Box::new(
                SignTypesNode::SinkDelivery(payload),
            )))
            .await
            .map_err(|e| SinkError::Delivery {
                message: format!("node signing request failed: {}", e),
                retryable: true,
                retry_after_ms: None,
            })?;

        match response {
            NodeResponse::SignRequest(signature) => Ok(signature),
            _ => Err(SinkError::Delivery {
                message: "unexpected node response to signing request"
                    .to_owned(),
                retryable: true,
                retry_after_ms: None,
            }),
        }
    }
}

/// Build the transport for a sink server from its configuration.
/// `node_id` (the node's public key) is only used by the Kafka transport to
/// derive a per-node default `transactional.id`.
pub async fn build_transport(
    server: &SinkServer,
    signer: Option<NodeSigner>,
    node_id: Option<&str>,
) -> Result<Arc<dyn SinkTransport>, SinkError> {
    match &server.transport {
        SinkTransportConfig::Http(http) => Ok(Arc::new(
            HttpTransport::new(server.server.clone(), *http.clone(), signer)
                .await?,
        )),
        SinkTransportConfig::Kafka(kafka) => Ok(Arc::new(KafkaTransport::new(
            server.server.clone(),
            kafka.clone(),
            signer,
            node_id,
        )?)),
    }
}
