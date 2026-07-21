//! Kafka delivery logic for a single external sink.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use tracing::debug;

use ave_common::{DataToSink, LightEvent};

use crate::config::{KafkaAcks, KafkaSecurityConfig, KafkaSinkConfig};
use crate::sink::SinkError;
use crate::sink::http::sink_password_env_var;
use crate::sink::template::CompiledTemplate;
use crate::sink::transport::SinkTransport;

/// Kafka transport for a single sink server.
pub struct KafkaTransport {
    sink_name: String,
    config: KafkaSinkConfig,
    producer: FutureProducer,
    topic_template: CompiledTemplate,
}

impl std::fmt::Debug for KafkaTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaTransport")
            .field("sink_name", &self.sink_name)
            .field("config", &self.config)
            .field("topic_template", &self.topic_template)
            .finish_non_exhaustive()
    }
}

impl KafkaTransport {
    pub fn new(
        sink_name: String,
        config: KafkaSinkConfig,
    ) -> Result<Self, SinkError> {
        let mut client_config = ClientConfig::new();
        client_config
            .set("bootstrap.servers", &config.bootstrap_servers)
            .set("client.id", &config.client_id)
            .set("acks", config.acks.as_str())
            .set("compression.type", config.compression.as_str())
            .set("message.timeout.ms", config.request_timeout_ms.to_string());

        // Idempotence requires `acks=all`; otherwise librdkafka rejects the
        // producer configuration. Keep it enabled only for the default acks.
        client_config.set(
            "enable.idempotence",
            if matches!(config.acks, KafkaAcks::All) {
                "true"
            } else {
                "false"
            },
        );

        match &config.security {
            KafkaSecurityConfig::Plaintext => {
                client_config.set("security.protocol", "plaintext");
            }
            KafkaSecurityConfig::Ssl => {
                client_config.set("security.protocol", "ssl");
            }
            KafkaSecurityConfig::SaslPlaintext {
                mechanism,
                username,
            } => {
                client_config
                    .set("security.protocol", "sasl_plaintext")
                    .set("sasl.mechanism", mechanism.as_str())
                    .set("sasl.username", username)
                    .set("sasl.password", sasl_password(&sink_name)?);
            }
            KafkaSecurityConfig::SaslSsl {
                mechanism,
                username,
            } => {
                client_config
                    .set("security.protocol", "sasl_ssl")
                    .set("sasl.mechanism", mechanism.as_str())
                    .set("sasl.username", username)
                    .set("sasl.password", sasl_password(&sink_name)?);
            }
        }

        let producer = client_config.create().map_err(|e| {
            SinkError::ClientBuild(format!(
                "failed to create kafka producer: {e}"
            ))
        })?;

        Ok(Self {
            sink_name,
            topic_template: CompiledTemplate::new(&config.topic),
            producer,
            config,
        })
    }

    async fn produce(
        &self,
        topic: &str,
        key: &str,
        payload: &[u8],
    ) -> Result<(), SinkError> {
        let record = FutureRecord::to(topic).key(key).payload(payload);
        self.producer
            .send(
                record,
                Duration::from_millis(self.config.request_timeout_ms),
            )
            .await
            .map(|delivery| {
                debug!(
                    msg_type = "SinkSend",
                    sink = %self.sink_name,
                    topic = %topic,
                    partition = delivery.partition,
                    offset = delivery.offset,
                    "Sink delivery succeeded"
                );
            })
            .map_err(|(err, _message)| map_produce_error(err))
    }

    fn fetch_metadata(&self) -> Result<(), SinkError> {
        self.producer
            .client()
            .fetch_metadata(
                None,
                Duration::from_millis(self.config.request_timeout_ms),
            )
            .map(|metadata| {
                debug!(
                    msg_type = "SinkHealthCheck",
                    sink = %self.sink_name,
                    brokers = metadata.brokers().len(),
                    "Kafka cluster reachable"
                );
            })
            .map_err(|e| match map_produce_error(e.clone()) {
                SinkError::Delivery { .. } => SinkError::Delivery {
                    message: format!("kafka metadata fetch failed: {e}"),
                    retryable: true,
                    retry_after_ms: None,
                },
                other => other,
            })
    }
}

/// Load the SASL password from the environment, failing if it is not set.
fn sasl_password(sink_name: &str) -> Result<String, SinkError> {
    let env_var = sink_password_env_var(sink_name);
    let password = std::env::var(&env_var).unwrap_or_default();
    if password.is_empty() {
        return Err(SinkError::ClientBuild(format!(
            "SASL configured for sink '{sink_name}' but password environment variable {env_var} is not set"
        )));
    }
    Ok(password)
}

/// Map a produce error to the sink error taxonomy.
fn map_produce_error(err: KafkaError) -> SinkError {
    match err {
        KafkaError::MessageProduction(code) => map_produce_code(code),
        e => SinkError::Delivery {
            message: format!("kafka produce failed: {e}"),
            retryable: true,
            retry_after_ms: None,
        },
    }
}

fn map_produce_code(code: RDKafkaErrorCode) -> SinkError {
    match code {
        // Authentication/authorization problems: the subject goes to lagging
        // and the catch-up mechanism retries it later.
        RDKafkaErrorCode::Authentication
        | RDKafkaErrorCode::SaslAuthenticationFailed
        | RDKafkaErrorCode::TopicAuthorizationFailed
        | RDKafkaErrorCode::GroupAuthorizationFailed
        | RDKafkaErrorCode::ClusterAuthorizationFailed
        | RDKafkaErrorCode::UnsupportedSASLMechanism
        | RDKafkaErrorCode::IllegalSASLState => SinkError::Auth {
            message: format!("kafka auth/authorization failed ({code})"),
            retry_after_ms: None,
        },
        // Permanent payload/topic problems: retrying will never succeed, so
        // the sink is blocked until the configuration is fixed.
        RDKafkaErrorCode::MessageSizeTooLarge
        | RDKafkaErrorCode::MessageBatchTooLarge
        | RDKafkaErrorCode::InvalidTopic => SinkError::Rejected {
            message: format!("kafka rejected the record ({code})"),
        },
        // Everything else (timeouts, brokers down, leader elections, unknown
        // topics that may be created later...): retryable.
        other => SinkError::Delivery {
            message: format!("kafka produce failed ({other})"),
            retryable: true,
            retry_after_ms: None,
        },
    }
}

#[async_trait]
impl SinkTransport for KafkaTransport {
    async fn send(&self, data: Arc<DataToSink>) -> Result<(), SinkError> {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let topic = self.topic_template.render(&subject_id, &schema_id);
        let payload = serde_json::to_vec(data.as_ref()).map_err(|e| {
            SinkError::Delivery {
                message: format!("JSON serialization failed: {e}"),
                retryable: false,
                retry_after_ms: None,
            }
        })?;

        self.produce(&topic, &subject_id, &payload).await
    }

    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError> {
        let topic = self
            .topic_template
            .render(&light.subject_id, &light.schema_id);
        let payload =
            serde_json::to_vec(&light).map_err(|e| SinkError::Delivery {
                message: format!("JSON serialization failed: {e}"),
                retryable: false,
                retry_after_ms: None,
            })?;

        self.produce(&topic, &light.subject_id, &payload).await
    }

    async fn health_check(&self) -> Result<(), SinkError> {
        self.fetch_metadata()
    }

    async fn warm_up(&self) -> Result<(), SinkError> {
        self.fetch_metadata()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn map_produce_code_auth_codes() {
        for code in [
            RDKafkaErrorCode::Authentication,
            RDKafkaErrorCode::SaslAuthenticationFailed,
            RDKafkaErrorCode::TopicAuthorizationFailed,
            RDKafkaErrorCode::GroupAuthorizationFailed,
            RDKafkaErrorCode::ClusterAuthorizationFailed,
            RDKafkaErrorCode::UnsupportedSASLMechanism,
            RDKafkaErrorCode::IllegalSASLState,
        ] {
            assert!(matches!(map_produce_code(code), SinkError::Auth { .. }));
        }
    }

    #[test]
    fn map_produce_code_rejected_codes() {
        for code in [
            RDKafkaErrorCode::MessageSizeTooLarge,
            RDKafkaErrorCode::MessageBatchTooLarge,
            RDKafkaErrorCode::InvalidTopic,
        ] {
            assert!(matches!(
                map_produce_code(code),
                SinkError::Rejected { .. }
            ));
        }
    }

    #[test]
    fn map_produce_code_retryable_codes() {
        for code in [
            RDKafkaErrorCode::UnknownTopicOrPartition,
            RDKafkaErrorCode::NotLeaderForPartition,
            RDKafkaErrorCode::RequestTimedOut,
            RDKafkaErrorCode::BrokerNotAvailable,
            RDKafkaErrorCode::NetworkException,
        ] {
            assert!(matches!(
                map_produce_code(code),
                SinkError::Delivery {
                    retryable: true,
                    ..
                }
            ));
        }
    }
}
