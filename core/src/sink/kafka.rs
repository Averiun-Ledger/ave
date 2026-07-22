//! Kafka delivery logic for a single external sink.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::{Header, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use tracing::debug;

use ave_common::{DataToSink, LightEvent};

use crate::config::{KafkaAcks, KafkaSecurityConfig, KafkaSinkConfig};
use crate::metrics::try_core_metrics;
use crate::sink::SinkError;
use crate::sink::http::sink_password_env_var;
use crate::sink::template::CompiledTemplate;
use crate::sink::transport::SinkTransport;

/// Header carrying the subject identifier of the delivered event.
const SUBJECT_ID_HEADER: &str = "x-ave-subject-id";
/// Header carrying the sequence number of the delivered event.
const SN_HEADER: &str = "x-ave-sn";
/// Header carrying the delivered event type (`create`, `fact`, ...).
const EVENT_TYPE_HEADER: &str = "x-ave-event-type";
/// Header allowing the receiver to deduplicate deliveries
/// (`<subject_id>-<sn>`, following the Stripe convention).
const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
/// Header carrying a unique identifier for this delivery attempt, useful for
/// correlating logs between the node and the receiver.
const REQUEST_ID_HEADER: &str = "x-ave-request-id";
/// Header marking a request as a non-persistent sink test delivery.
const TEST_HEADER: &str = "x-ave-test";

/// Generate a unique request id for a single delivery attempt.
/// Combines a nanosecond timestamp with a random suffix so collisions are
/// practically impossible without adding a new dependency.
fn generate_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{:016x}", nanos, fastrand::u64(..))
}

/// Idempotency metadata of a single-event delivery, sent as headers so the
/// receiver can deduplicate without parsing the body. Not sent on batch
/// deliveries, where each array element already carries this data.
struct DeliveryMeta {
    subject_id: String,
    sn: u64,
    event_type: String,
}

/// Build the key, payload and headers for a non-persistent test delivery.
/// Extracted into a helper so unit tests can verify the wire format without a
/// running Kafka cluster.
fn build_test_delivery(
    request_id: &str,
) -> Result<(String, Vec<u8>, OwnedHeaders), SinkError> {
    let key = format!("__ave-test-{}", request_id);
    let payload = serde_json::to_vec(&serde_json::json!({"test": true}))
        .map_err(|e| SinkError::Delivery {
            message: format!("JSON serialization failed: {e}"),
            retryable: false,
            retry_after_ms: None,
        })?;
    let headers = OwnedHeaders::new()
        .insert(Header {
            key: TEST_HEADER,
            value: Some("true"),
        })
        .insert(Header {
            key: REQUEST_ID_HEADER,
            value: Some(request_id),
        });
    Ok((key, payload, headers))
}

/// Build Kafka message headers for a single-event delivery.
fn build_headers(meta: &DeliveryMeta, request_id: &str) -> OwnedHeaders {
    OwnedHeaders::new()
        .insert(Header {
            key: SUBJECT_ID_HEADER,
            value: Some(&meta.subject_id),
        })
        .insert(Header {
            key: SN_HEADER,
            value: Some(&meta.sn.to_string()),
        })
        .insert(Header {
            key: EVENT_TYPE_HEADER,
            value: Some(&meta.event_type),
        })
        .insert(Header {
            key: IDEMPOTENCY_KEY_HEADER,
            value: Some(&format!("{}-{}", meta.subject_id, meta.sn)),
        })
        .insert(Header {
            key: REQUEST_ID_HEADER,
            value: Some(request_id),
        })
}

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
            .set("message.timeout.ms", config.request_timeout_ms.to_string())
            // Idempotence requires retries >= 1; we set 1 so librdkafka retries
            // once internally (required for idempotence) and `produce` manages
            // the rest of the backoff logic.
            .set("retries", "1")
            .set("socket.timeout.ms", config.socket_timeout_ms.to_string())
            .set("socket.keepalive.enable", config.socket_keepalive.to_string())
            .set("connections.max.idle.ms", config.connections_max_idle_ms.to_string())
            .set("metadata.max.age.ms", config.metadata_max_age_ms.to_string());

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

        let uses_tls = matches!(
            config.security,
            KafkaSecurityConfig::Ssl | KafkaSecurityConfig::SaslSsl { .. }
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

        if uses_tls && let Some(tls) = &config.tls {
            if !tls.ca_certificate.is_empty() {
                client_config.set("ssl.ca.location", &tls.ca_certificate);
            }
            if !tls.client_certificate.is_empty() {
                client_config
                    .set("ssl.certificate.location", &tls.client_certificate)
                    .set("ssl.key.location", &tls.client_key);
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

    async fn produce_once(
        &self,
        topic: &str,
        key: &str,
        payload: &[u8],
        headers: Option<OwnedHeaders>,
        request_id: &str,
    ) -> Result<(), SinkError> {
        let mut record = FutureRecord::to(topic).key(key).payload(payload);
        if let Some(headers) = headers {
            record = record.headers(headers);
        }
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
                    request_id = %request_id,
                    "Sink delivery succeeded"
                );
            })
            .map_err(|(err, _message)| map_produce_error(err))
    }

    fn retry_delay(&self, attempt: usize) -> u64 {
        // Saturate the exponent so a large `max_retries` cannot overflow the
        // shift (debug panic / masked shift in release).
        let exp = (attempt - 1).min(63);
        let base_delay = self
            .config
            .retry_base_delay_ms
            .saturating_mul(1_u64 << exp);
        let delay = crate::sink::add_jitter(base_delay);
        delay.min(self.config.retry_max_delay_ms)
    }

    async fn produce(
        &self,
        topic: &str,
        key: &str,
        payload: &[u8],
        headers: Option<OwnedHeaders>,
        request_id: &str,
    ) -> Result<(), SinkError> {
        let mut last_err = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_sink_retry(&self.sink_name);
                }
                let delay = self.retry_delay(attempt);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self
                .produce_once(topic, key, payload, headers.clone(), request_id)
                .await
            {
                Ok(()) => return Ok(()),
                Err(
                    e @ (SinkError::Delivery {
                        retryable: false, ..
                    }
                    | SinkError::ClientBuild(_)
                    | SinkError::Rejected { .. }
                    | SinkError::Shutdown),
                ) => {
                    // Permanent error: no retries.
                    return Err(e);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| SinkError::Delivery {
            message: "Max retries exceeded".to_owned(),
            retryable: false,
            retry_after_ms: None,
        }))
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

        let request_id = generate_request_id();
        let meta = DeliveryMeta {
            subject_id: subject_id.clone(),
            sn: crate::sink::extract_sn(&data),
            event_type: ave_common::sink::SinkTypes::from(data.as_ref())
                .as_str()
                .to_owned(),
        };
        let headers = build_headers(&meta, &request_id);

        self.produce(&topic, &subject_id, &payload, Some(headers), &request_id)
            .await
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

        let request_id = generate_request_id();
        let meta = DeliveryMeta {
            subject_id: light.subject_id.clone(),
            sn: light.sn,
            event_type: light.event_type.as_str().to_owned(),
        };
        let headers = build_headers(&meta, &request_id);

        self.produce(&topic, &light.subject_id, &payload, Some(headers), &request_id)
            .await
    }

    async fn health_check(&self) -> Result<(), SinkError> {
        self.fetch_metadata()
    }

    /// Run a non-persistent end-to-end test of the sink. Performs a health
    /// check followed by a single test message delivery, using the same
    /// authentication and TLS paths as real deliveries. No cursor is advanced
    /// and nothing is persisted.
    async fn test(&self) -> Result<(), SinkError> {
        self.health_check().await?;

        let topic = self.topic_template.render("-", "-");
        let request_id = generate_request_id();
        let (key, payload, headers) = build_test_delivery(&request_id)?;
        self.produce(&topic, &key, &payload, Some(headers), &request_id)
            .await
    }

    async fn warm_up(&self) -> Result<(), SinkError> {
        self.fetch_metadata()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_headers_contains_delivery_metadata() {
        use rdkafka::message::Headers as _;

        let meta = DeliveryMeta {
            subject_id: "subject-1".to_owned(),
            sn: 42,
            event_type: "fact".to_owned(),
        };
        let headers = build_headers(&meta, "req-123");
        let borrowed = headers.as_borrowed();

        assert_eq!(borrowed.count(), 5);

        let get = |idx: usize| {
            let h = borrowed.get(idx);
            (
                h.key,
                h.value.map(|v| String::from_utf8_lossy(v).into_owned()),
            )
        };

        assert_eq!(get(0), (SUBJECT_ID_HEADER, Some("subject-1".to_owned())));
        assert_eq!(get(1), (SN_HEADER, Some("42".to_owned())));
        assert_eq!(get(2), (EVENT_TYPE_HEADER, Some("fact".to_owned())));
        assert_eq!(
            get(3),
            (IDEMPOTENCY_KEY_HEADER, Some("subject-1-42".to_owned()))
        );
        assert_eq!(get(4), (REQUEST_ID_HEADER, Some("req-123".to_owned())));
    }

    #[test]
    fn generate_request_id_is_unique() {
        let a = generate_request_id();
        let b = generate_request_id();
        assert_ne!(a, b, "request ids must be unique per attempt");
    }

    #[test]
    fn build_test_delivery_has_test_header_and_payload() {
        use rdkafka::message::Headers as _;

        let (key, payload, headers) = build_test_delivery("req-456").unwrap();
        assert_eq!(key, "__ave-test-req-456");
        assert_eq!(payload, br#"{"test":true}"#.to_vec());

        let borrowed = headers.as_borrowed();
        assert_eq!(borrowed.count(), 2);
        let get = |idx: usize| {
            let h = borrowed.get(idx);
            (
                h.key,
                h.value.map(|v| String::from_utf8_lossy(v).into_owned()),
            )
        };
        assert_eq!(get(0), (TEST_HEADER, Some("true".to_owned())));
        assert_eq!(get(1), (REQUEST_ID_HEADER, Some("req-456".to_owned())));
    }

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
