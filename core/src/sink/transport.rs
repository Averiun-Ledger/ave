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

/// Transport contract implemented by each sink delivery mechanism.
#[async_trait]
pub trait SinkTransport: Send + Sync + std::fmt::Debug {
    /// Deliver a full event to the sink.
    async fn send(&self, data: Arc<DataToSink>) -> Result<(), SinkError>;
    /// Deliver a light event (event type not covered by the `events` filter).
    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError>;
    /// Health check of the endpoint.
    async fn health_check(&self) -> Result<(), SinkError>;
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
    pub fn new(node: ActorRef<Node>) -> Self {
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
            })?;

        match response {
            NodeResponse::SignRequest(signature) => Ok(signature),
            _ => Err(SinkError::Delivery {
                message: "unexpected node response to signing request"
                    .to_owned(),
                retryable: true,
            }),
        }
    }
}

/// Build the transport for a sink server from its configuration.
pub fn build_transport(
    server: &SinkServer,
    signer: Option<NodeSigner>,
) -> Result<Arc<dyn SinkTransport>, SinkError> {
    match &server.transport {
        SinkTransportConfig::Http(http) => Ok(Arc::new(HttpTransport::new(
            server.server.clone(),
            http.clone(),
            signer,
        )?)),
        SinkTransportConfig::Kafka(kafka) => Ok(Arc::new(
            KafkaTransport::new(server.server.clone(), kafka.clone())?,
        )),
    }
}
