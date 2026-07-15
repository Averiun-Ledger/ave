//! Transport abstraction for sink delivery.

use std::sync::Arc;

use async_trait::async_trait;
use ave_common::{DataToSink, LightEvent};

use crate::config::{SinkServer, SinkTransportConfig};
use crate::sink::{error::SinkError, http::HttpTransport, kafka::KafkaTransport};

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

/// Build the transport for a sink server from its configuration.
pub fn build_transport(
    server: &SinkServer,
) -> Result<Arc<dyn SinkTransport>, SinkError> {
    match &server.transport {
        SinkTransportConfig::Http(http) => Ok(Arc::new(HttpTransport::new(
            server.server.clone(),
            http.clone(),
        )?)),
        SinkTransportConfig::Kafka(kafka) => Ok(Arc::new(
            KafkaTransport::new(server.server.clone(), kafka.clone())?,
        )),
    }
}
