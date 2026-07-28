//! Kafka delivery logic for a single external sink.

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::{Header, Headers, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use tracing::debug;

use ave_common::{DataToSink, IncomingSinkEvent, LightEvent};

use crate::config::{KafkaAcks, KafkaKeyStrategy, KafkaSecurityConfig, KafkaSinkConfig};
use crate::metrics::try_core_metrics;
use crate::sink::SinkError;
use crate::sink::delivery::{
    DeliveryMeta, EVENT_TYPE_HEADER, IDEMPOTENCY_KEY_HEADER, REQUEST_ID_HEADER,
    SIGNATURE_HEADER, SIGNATURE_PUBLIC_KEY_HEADER, SIGNATURE_TIMESTAMP_HEADER,
    SN_HEADER, SUBJECT_ID_HEADER, TEST_HEADER, generate_request_id, sign_delivery,
    sink_password_env_var,
};
use crate::sink::template::CompiledTemplate;
use crate::sink::transport::{NodeSigner, SinkTransport};

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
    /// Compiled template for the `Template` key strategy. `None` for every
    /// other strategy.
    key_template: Option<CompiledTemplate>,
    /// Node identity signer; required when `config.signature` is enabled.
    signer: Option<NodeSigner>,
}

impl std::fmt::Debug for KafkaTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KafkaTransport")
            .field("sink_name", &self.sink_name)
            .field("config", &self.config)
            .field("topic_template", &self.topic_template)
            .field("has_signer", &self.signer.is_some())
            .finish_non_exhaustive()
    }
}

impl KafkaTransport {
    pub fn new(
        sink_name: String,
        config: KafkaSinkConfig,
        signer: Option<NodeSigner>,
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
            .set("metadata.max.age.ms", config.metadata_max_age_ms.to_string())
            // Producer batch tuning (point 12).
            .set("linger.ms", config.linger_ms.to_string())
            .set("batch.size", config.batch_size_bytes.to_string())
            .set("queue.buffering.max.messages",
                config.queue_buffering_max_messages.to_string());

        let key_template = match &config.key_strategy {
            KafkaKeyStrategy::Template(template) => {
                Some(CompiledTemplate::new(template))
            }
            _ => None,
        };

        // Point 11: transactional producer requires a non-empty
        // `transactional.id` so Kafka can fence zombie producers.
        if config.transactional {
            let transactional_id = config
                .transactional_id
                .clone()
                .unwrap_or_else(|| format!("ave-sink-{sink_name}"));
            client_config.set("transactional.id", &transactional_id);
        }

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

        if config.signature && signer.is_none() {
            return Err(SinkError::ClientBuild(format!(
                "signature enabled for sink '{}' but no node signer is available",
                sink_name
            )));
        }

        let producer: FutureProducer = client_config.create().map_err(|e| {
            SinkError::ClientBuild(format!(
                "failed to create kafka producer: {e}"
            ))
        })?;

        // For transactional producers, ask the broker to fence zombies and
        // establish the producer epoch before the first delivery. This is a
        // one-time setup; the operation is synchronous from the caller's
        // point of view because `init_transactions` does not return until the
        // coordinator responds, which is exactly what we want — a misconfigured
        // `transactional.id` must surface at construction, not at the first
        // delivery.
        if config.transactional {
            producer
                .init_transactions(Duration::from_millis(config.request_timeout_ms))
                .map_err(|e| {
                    SinkError::ClientBuild(format!(
                        "failed to init kafka transactions for sink '{sink_name}': {e}"
                    ))
                })?;
        }

        Ok(Self {
            sink_name,
            topic_template: CompiledTemplate::new(&config.topic),
            key_template,
            producer,
            config,
            signer,
        })
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

    /// Sign the delivery body with the node identity. Uses the shared
    /// canonical payload contract so every transport produces signatures
    /// verifiable against the same byte sequence.
    async fn sign_payload(
        &self,
        payload: &[u8],
        meta: Option<&DeliveryMeta>,
    ) -> Result<Option<crate::sink::delivery::SignatureHeaders>, SinkError> {
        sign_delivery(
            self.signer.as_ref(),
            payload,
            self.config.signature_version,
            &[],
            meta,
        )
        .await
    }

    /// Derive the Kafka message key from the configured strategy for a
    /// delivery to `subject_id` under `schema_id`. `None` means the message
    /// is sent without a key (round-robin partition).
    fn compute_key(
        &self,
        subject_id: &str,
        schema_id: &str,
    ) -> Option<String> {
        match &self.config.key_strategy {
            KafkaKeyStrategy::SubjectId => Some(subject_id.to_owned()),
            KafkaKeyStrategy::None => None,
            KafkaKeyStrategy::Static(value) => Some(value.clone()),
            KafkaKeyStrategy::Template(_) => Some(
                self.key_template
                    .as_ref()
                    .expect("key template compiled for Template strategy")
                    .render(subject_id, schema_id),
            ),
        }
    }

    async fn produce(
        &self,
        topic: &str,
        key: Option<&str>,
        payload: &[u8],
        meta: Option<&DeliveryMeta>,
        additional_headers: Option<OwnedHeaders>,
        request_id: &str,
    ) -> Result<(), SinkError> {
        let mut last_err = None;
        let signature_headers = self.sign_payload(payload, meta).await?;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_sink_retry(&self.sink_name);
                }
                let delay = self.retry_delay(attempt);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            // Each attempt is a fresh transaction: a retryable failure
            // aborts the previous one and starts over. Aborting ignores the
            // result intentionally: the producer may already be in a fatal
            // state, and the next begin_transaction would surface that.
            let transactional = self.config.transactional;
            if transactional {
                if let Err(e) = self.producer.begin_transaction() {
                    last_err = Some(SinkError::Delivery {
                        message: format!("begin transaction: {e}"),
                        retryable: true,
                        retry_after_ms: None,
                    });
                    continue;
                }
            }

            // `FutureRecord::headers` replaces the whole header set, so all
            // headers (meta, additional and signature) are composed into a
            // single `OwnedHeaders` before attaching them.
            let mut headers = match meta {
                Some(meta) => build_headers(meta, request_id),
                None => OwnedHeaders::new(),
            };
            if let Some(extra) = &additional_headers {
                for header in extra.as_borrowed().iter() {
                    headers = headers.insert(Header {
                        key: header.key,
                        value: header.value,
                    });
                }
            }
            if let Some(sig) = &signature_headers {
                headers = headers
                    .insert(Header {
                        key: SIGNATURE_HEADER,
                        value: Some(&sig.signature),
                    })
                    .insert(Header {
                        key: SIGNATURE_TIMESTAMP_HEADER,
                        value: Some(&sig.timestamp),
                    })
                    .insert(Header {
                        key: SIGNATURE_PUBLIC_KEY_HEADER,
                        value: Some(&sig.public_key),
                    });
            }

            let mut record = FutureRecord::to(topic)
                .payload(payload)
                .headers(headers);
            if let Some(key) = key {
                record = record.key(key);
            }

            let send_result = self
                .producer
                .send(
                    record,
                    Duration::from_millis(self.config.request_timeout_ms),
                )
                .await;

            match send_result {
                Ok(delivery) => {
                    if transactional {
                        if let Err(e) = self.producer.commit_transaction(
                            Duration::from_millis(self.config.request_timeout_ms),
                        ) {
                            // The message reached the broker but the commit
                            // failed: abort so the receiver does not see a
                            // dangling transaction, and retry as a unit.
                            let _ = self.producer.abort_transaction(
                                Duration::from_millis(
                                    self.config.request_timeout_ms,
                                ),
                            );
                            last_err = Some(SinkError::Delivery {
                                message: format!("commit transaction: {e}"),
                                retryable: true,
                                retry_after_ms: None,
                            });
                            continue;
                        }
                    }
                    debug!(
                        msg_type = "SinkSend",
                        sink = %self.sink_name,
                        topic = %topic,
                        partition = delivery.partition,
                        offset = delivery.offset,
                        request_id = %request_id,
                        "Sink delivery succeeded"
                    );
                    return Ok(());
                }
                Err((err, _message)) => {
                    if transactional {
                        let _ = self.producer.abort_transaction(
                            Duration::from_millis(self.config.request_timeout_ms),
                        );
                    }
                    let e = map_produce_error(err);
                    match e {
                        SinkError::Delivery {
                            retryable: false, ..
                        }
                        | SinkError::ClientBuild(_)
                        | SinkError::Rejected { .. }
                        | SinkError::Shutdown => {
                            // Permanent error: no retries.
                            return Err(e);
                        }
                        _ => {
                            last_err = Some(e);
                        }
                    }
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
        let event_type = ave_common::sink::SinkTypes::from(data.as_ref());
        let topic = self.topic_template.render_with_event_type(
            &subject_id,
            &schema_id,
            event_type.as_str(),
        );
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
            event_type: event_type.as_str().to_owned(),
        };

        let key = self.compute_key(&subject_id, &schema_id);
        self.produce(
            &topic,
            key.as_deref(),
            &payload,
            Some(&meta),
            None,
            &request_id,
        )
        .await
    }

    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError> {
        let topic = self.topic_template.render_with_event_type(
            &light.subject_id,
            &light.schema_id,
            light.event_type.as_str(),
        );
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

        let key = self.compute_key(&light.subject_id, &light.schema_id);
        self.produce(
            &topic,
            key.as_deref(),
            &payload,
            Some(&meta),
            None,
            &request_id,
        )
        .await
    }

    /// Deliver a batch of events as JSON array messages. When the topic
    /// template routes by event type (`{{event-type}}`), events are grouped
    /// by type (preserving the relative order inside each group) and one
    /// array message is produced per group, so every type lands in its own
    /// topic; otherwise the whole batch is delivered as a single array
    /// message, like the HTTP sink does. Per-event idempotency headers are
    /// not sent: every array element already carries `subject_id`, `sn` and
    /// the event type.
    ///
    /// A failure mid-batch fails the whole call: the worker retries the full
    /// batch later, so already-produced groups may be delivered twice
    /// (at-least-once semantics, as with any other delivery).
    async fn send_batch(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        let Some(first_event) = events.first() else {
            return Ok(());
        };

        // Group by event type only when the template routes by type;
        // otherwise one message carries the whole batch. Group order follows
        // first appearance so a homogeneous batch produces one message.
        let mut groups: Vec<(String, Vec<IncomingSinkEvent>)> = Vec::new();
        if self.topic_template.has_event_type() {
            for event in events {
                let event_type = event.event_type().as_str().to_owned();
                match groups.iter_mut().find(|(t, _)| *t == event_type) {
                    Some((_, group)) => group.push(event),
                    None => groups.push((event_type, vec![event])),
                }
            }
        } else {
            let event_type = first_event.event_type().as_str().to_owned();
            groups.push((event_type, events));
        }

        for (event_type, group) in groups {
            // `group` is never empty: it is created with its first element.
            let Some(first) = group.first() else {
                continue;
            };
            let schema_id = match first {
                IncomingSinkEvent::Full(data) => {
                    data.payload.get_subject_schema().1
                }
                IncomingSinkEvent::Light(light) => light.schema_id.clone(),
            };
            let topic = self.topic_template.render_with_event_type(
                first.subject_id(),
                &schema_id,
                &event_type,
            );
            let payload = serde_json::to_vec(&group).map_err(|e| {
                SinkError::Delivery {
                    message: format!("JSON serialization failed: {e}"),
                    retryable: false,
                    retry_after_ms: None,
                }
            })?;

            let request_id = generate_request_id();
            let key = self.compute_key(first.subject_id(), &schema_id);
            self.produce(
                &topic,
                key.as_deref(),
                &payload,
                None,
                None,
                &request_id,
            )
            .await?;
        }

        Ok(())
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

        let topic = self.topic_template.render_with_event_type("-", "-", "test");
        let request_id = generate_request_id();
        let (key, payload, headers) = build_test_delivery(&request_id)?;
        self.produce(&topic, Some(&key), &payload, None, Some(headers), &request_id)
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
