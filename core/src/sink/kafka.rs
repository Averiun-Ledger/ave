//! Kafka delivery logic for a single external sink.

use std::sync::{Arc, atomic::AtomicU64};
use std::time::Duration;

use async_trait::async_trait;
use rdkafka::ClientConfig;
use rdkafka::error::{KafkaError, RDKafkaErrorCode};
use rdkafka::message::{Header, Headers, OwnedHeaders};
use rdkafka::producer::{FutureProducer, FutureRecord, Producer};
use tracing::{debug, error};

use ave_common::{DataToSink, IncomingSinkEvent, LightEvent};

use crate::config::{
    KafkaAcks, KafkaKeyStrategy, KafkaSaslMechanism, KafkaSecurityConfig,
    KafkaSinkConfig,
};
use crate::metrics::try_core_metrics;
use crate::sink::SinkError;
use crate::sink::delivery::{
    DeliveryMeta, EVENT_TYPE_HEADER, IDEMPOTENCY_KEY_HEADER, REQUEST_ID_HEADER,
    SIGNATURE_HEADER, SIGNATURE_PUBLIC_KEY_HEADER, SIGNATURE_TIMESTAMP_HEADER,
    SN_HEADER, SUBJECT_ID_HEADER, TEST_HEADER, batch_group_schema_id,
    generate_request_id, group_events_by_type, is_sink_reserved_header,
    load_required_secret, serialize_json_payload, sign_delivery,
    sink_password_env_var, test_delivery_payload, timed_sink_request,
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
    let payload = serialize_json_payload(&test_delivery_payload())?;
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
            value: Some(&meta.idempotency_key()),
        })
        .insert(Header {
            key: REQUEST_ID_HEADER,
            value: Some(request_id),
        })
}

/// Everything needed to mint an OAUTHBEARER token on librdkafka's refresh
/// callback: the OIDC client-credentials flow runs on the node's runtime
/// from the producer's poll thread via `Handle::block_on`.
struct KafkaOAuthContext {
    handle: tokio::runtime::Handle,
    client: reqwest::Client,
    auth: ave_common::sink::SinkAuthConfig,
    password: String,
    principal: String,
    retry_base_delay_ms: u64,
}

/// Producer context that forwards librdkafka statistics to the core metrics.
/// `last_tx_errors` holds the absolute error total of the previous report,
/// because librdkafka reports cumulative values (point 13).
struct KafkaStatsContext {
    sink_name: String,
    last_tx_errors: AtomicU64,
    /// Present only with the OAUTHBEARER SASL mechanism.
    oauth: Option<KafkaOAuthContext>,
}

impl rdkafka::ClientContext for KafkaStatsContext {
    const ENABLE_REFRESH_OAUTH_TOKEN: bool = true;

    fn stats(&self, statistics: rdkafka::Statistics) {
        if let Some(metrics) = try_core_metrics() {
            metrics.observe_kafka_producer_stats(
                &self.sink_name,
                &statistics,
                &self.last_tx_errors,
            );
        }
    }

    fn generate_oauth_token(
        &self,
        _oauthbearer_config: Option<&str>,
    ) -> Result<rdkafka::client::OAuthToken, Box<dyn std::error::Error>> {
        let oauth = self.oauth.as_ref().ok_or(
            "OAUTHBEARER token refresh requested without OAuth configuration",
        )?;
        let response =
            oauth.handle.block_on(crate::sink::obtain_token_with_retry(
                &oauth.client,
                &oauth.auth,
                &oauth.password,
                oauth.retry_base_delay_ms,
            ))?;
        let lifetime_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_millis() as i64
            + response.expires_in.saturating_mul(1_000);
        Ok(rdkafka::client::OAuthToken {
            token: response.access_token,
            principal_name: oauth.principal.clone(),
            lifetime_ms,
        })
    }

    fn error(&self, error: KafkaError, reason: &str) {
        // `Fatal` is librdkafka's own dead-producer signal. `Fenced` is
        // counted as fatal too: a fenced transactional producer can no
        // longer deliver and this transport never re-initializes it, so for
        // alerting purposes the producer is dead.
        let is_fatal = matches!(
            error,
            KafkaError::Global(RDKafkaErrorCode::Fatal)
                | KafkaError::Global(RDKafkaErrorCode::Fenced)
        );
        if is_fatal && let Some(metrics) = try_core_metrics() {
            metrics.observe_kafka_producer_fatal_error(&self.sink_name);
        }
        error!(
            msg_type = "KafkaClientError",
            sink = %self.sink_name,
            fatal = is_fatal,
            error = %error,
            reason = %reason,
            "librdkafka client error"
        );
    }
}

/// Key strategy resolved once at construction: the `Template` variant holds
/// the already-compiled template, so `compute_key` cannot hit an
/// uncompiled-template invariant.
enum ResolvedKeyStrategy {
    SubjectId,
    None,
    Static(String),
    Template(CompiledTemplate),
}

impl ResolvedKeyStrategy {
    fn from_config(strategy: &KafkaKeyStrategy) -> Self {
        match strategy {
            KafkaKeyStrategy::SubjectId => Self::SubjectId,
            KafkaKeyStrategy::None => Self::None,
            KafkaKeyStrategy::Static(value) => Self::Static(value.clone()),
            KafkaKeyStrategy::Template(template) => {
                Self::Template(CompiledTemplate::new(template))
            }
        }
    }

    /// Derive the Kafka message key for a delivery to `subject_id` under
    /// `schema_id`. `None` means the message is sent without a key
    /// (round-robin partition).
    fn compute_key(&self, subject_id: &str, schema_id: &str) -> Option<String> {
        match self {
            Self::SubjectId => Some(subject_id.to_owned()),
            Self::None => None,
            Self::Static(value) => Some(value.clone()),
            Self::Template(template) => {
                Some(template.render(subject_id, schema_id))
            }
        }
    }
}

/// Default transactional id: stable per node (derived from the node public
/// key) so restarts keep fencing the node's own zombies, and unique per
/// node so several nodes running the same sink never fence each other.
fn default_transactional_id(sink_name: &str, node_id: Option<&str>) -> String {
    node_id.map_or_else(|| format!("ave-sink-{sink_name}"), |node_id| {
        let short: String = node_id.chars().take(12).collect();
        format!("ave-sink-{sink_name}-{short}")
    })
}

/// Topic, optional message key, JSON payload and request id of a batch
/// group ready to be produced.
type PreparedGroup = (String, Option<String>, Vec<u8>, String);

/// Build the reqwest client that fetches OAUTHBEARER tokens from the OIDC
/// endpoint. Honors the sink's `tls.ca_certificate` as an additional root
/// CA so IdPs on corporate CAs work; proxying follows reqwest's standard
/// system-proxy detection (`HTTP_PROXY`/`HTTPS_PROXY`/`NO_PROXY`).
async fn build_oauth_token_client(
    sink_name: &str,
    config: &KafkaSinkConfig,
) -> Result<reqwest::Client, SinkError> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(config.request_timeout_ms));
    if let Some(tls) = &config.tls
        && !tls.ca_certificate.is_empty()
    {
        builder = crate::sink::add_root_certificates(
            builder,
            sink_name,
            &tls.ca_certificate,
        )
        .await?;
    }
    builder.build().map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{sink_name}': failed to build OAuth token client: {e}"
        ))
    })
}

/// Kafka transport for a single sink server.
pub struct KafkaTransport {
    sink_name: String,
    config: KafkaSinkConfig,
    producer: FutureProducer<KafkaStatsContext>,
    topic_template: CompiledTemplate,
    key_strategy: ResolvedKeyStrategy,
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
    pub async fn new(
        sink_name: String,
        config: KafkaSinkConfig,
        signer: Option<NodeSigner>,
        node_id: Option<&str>,
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
            .set(
                "socket.keepalive.enable",
                config.socket_keepalive.to_string(),
            )
            .set(
                "connections.max.idle.ms",
                config.connections_max_idle_ms.to_string(),
            )
            .set(
                "metadata.max.age.ms",
                config.metadata_max_age_ms.to_string(),
            )
            // Producer batch tuning (point 12).
            .set("linger.ms", config.linger_ms.to_string())
            .set("batch.size", config.batch_size_bytes.to_string())
            .set(
                "queue.buffering.max.messages",
                config.queue_buffering_max_messages.to_string(),
            )
            // Producer metrics (point 13); `0` disables the stats callback.
            .set(
                "statistics.interval.ms",
                config.statistics_interval_ms.to_string(),
            );

        if let Some(partitioner) = &config.partitioner {
            client_config.set("partitioner", partitioner);
        }

        let key_strategy = ResolvedKeyStrategy::from_config(&config.key_strategy);

        // Point 11: transactional producer requires a non-empty
        // `transactional.id` so Kafka can fence zombie producers. The default
        // id is derived from the node identity so two nodes running the same
        // sink never fence each other.
        if config.transactional {
            let transactional_id = config
                .transactional_id
                .clone()
                .unwrap_or_else(|| {
                    default_transactional_id(&sink_name, node_id)
                });
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

        let mut oauth_context: Option<KafkaOAuthContext> = None;
        match &config.security {
            KafkaSecurityConfig::Plaintext => {
                client_config.set("security.protocol", "plaintext");
            }
            KafkaSecurityConfig::Ssl => {
                client_config.set("security.protocol", "ssl");
            }
            KafkaSecurityConfig::SaslPlaintext { .. } => {
                client_config.set("security.protocol", "sasl_plaintext");
            }
            KafkaSecurityConfig::SaslSsl { .. } => {
                client_config.set("security.protocol", "sasl_ssl");
            }
        }
        let sasl = match &config.security {
            KafkaSecurityConfig::SaslPlaintext {
                mechanism,
                username,
            }
            | KafkaSecurityConfig::SaslSsl {
                mechanism,
                username,
            } => Some((mechanism, username)),
            _ => None,
        };
        if let Some((mechanism, username)) = sasl {
            client_config.set("sasl.mechanism", mechanism.as_str());
            match mechanism {
                KafkaSaslMechanism::Plain
                | KafkaSaslMechanism::ScramSha256
                | KafkaSaslMechanism::ScramSha512 => {
                    client_config
                        .set("sasl.username", username)
                        .set("sasl.password", sasl_password(&sink_name)?);
                }
                KafkaSaslMechanism::OAuthBearer => {
                    // The token is fetched and refreshed by the
                    // `generate_oauth_token` context callback, so the OIDC
                    // properties (`sasl.oauthbearer.client.id`, ...) are
                    // intentionally not set: they select librdkafka's own
                    // OIDC client, which requires a libcurl build.
                    let secret = sasl_password(&sink_name)?;
                    let token_url = config.oauth_token_url.clone().ok_or_else(|| {
                        SinkError::ClientBuild(format!(
                            "OAUTHBEARER configured for sink '{sink_name}' but oauth_token_url is not set"
                        ))
                    })?;
                    let token_client =
                        build_oauth_token_client(&sink_name, &config).await?;
                    oauth_context = Some(KafkaOAuthContext {
                        handle: tokio::runtime::Handle::current(),
                        client: token_client,
                        auth: ave_common::sink::SinkAuthConfig {
                            auth_url: token_url,
                            username: String::new(),
                            api_key: String::new(),
                            grant_type:
                                ave_common::sink::OAuth2GrantType::ClientCredentials,
                            client_id: username.clone(),
                            scope: config
                                .oauth_scope
                                .clone()
                                .unwrap_or_default(),
                        },
                        password: secret,
                        principal: username.clone(),
                        retry_base_delay_ms: config.retry_base_delay_ms,
                    });
                }
                KafkaSaslMechanism::Gssapi => {
                    let kerberos = config.kerberos.as_ref().ok_or_else(|| {
                        SinkError::ClientBuild(format!(
                            "GSSAPI configured for sink '{sink_name}' but the kerberos section is missing"
                        ))
                    })?;
                    client_config
                        .set("sasl.kerberos.service.name", &kerberos.service_name)
                        .set("sasl.kerberos.principal", &kerberos.principal)
                        .set("sasl.kerberos.keytab", &kerberos.keytab);
                }
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

        let producer: FutureProducer<KafkaStatsContext> = client_config
            .create_with_context(KafkaStatsContext {
                sink_name: sink_name.clone(),
                last_tx_errors: AtomicU64::new(0),
                oauth: oauth_context,
            })
            .map_err(|e| {
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
            key_strategy,
            producer,
            config,
            signer,
        })
    }

    /// Sign the delivery body with the node identity. Uses the shared
    /// canonical payload contract so every transport produces signatures
    /// verifiable against the same byte sequence.
    async fn sign_payload(
        &self,
        payload: &[u8],
        meta: Option<&DeliveryMeta>,
    ) -> Result<Option<crate::sink::delivery::SignatureHeaders>, SinkError>
    {
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
    fn compute_key(&self, subject_id: &str, schema_id: &str) -> Option<String> {
        self.key_strategy.compute_key(subject_id, schema_id)
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
                let delay = crate::sink::retry_delay_ms(
                    self.config.retry_base_delay_ms,
                    self.config.retry_max_delay_ms,
                    attempt,
                    None,
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self
                .produce_once(
                    topic,
                    key,
                    payload,
                    meta,
                    additional_headers.clone(),
                    &signature_headers,
                    request_id,
                )
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) if crate::sink::is_permanent_error(&e) => {
                    // Permanent error: no retries.
                    return Err(e);
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(crate::sink::max_retries_exceeded_error))
    }

    /// One produce attempt with request-duration metrics, so every transport
    /// reports `core_sink_request_duration_seconds` with the same labels.
    /// Used by `produce` (retry loop) and by best-effort batch delivery.
    #[allow(clippy::too_many_arguments)]
    async fn produce_once(
        &self,
        topic: &str,
        key: Option<&str>,
        payload: &[u8],
        meta: Option<&DeliveryMeta>,
        additional_headers: Option<OwnedHeaders>,
        signature_headers: &Option<crate::sink::delivery::SignatureHeaders>,
        request_id: &str,
    ) -> Result<(), SinkError> {
        timed_sink_request(&self.sink_name, || {
            self.produce_attempt(
                topic,
                key,
                payload,
                meta,
                additional_headers,
                signature_headers,
                request_id,
            )
        })
        .await
    }

    /// A single produce attempt: optional transaction, one send, optional
    /// commit. Each retry of `produce` is a fresh transaction: a retryable
    /// failure aborts the previous one and starts over. Aborting ignores the
    /// result intentionally: the producer may already be in a fatal state,
    /// and the next begin_transaction would surface that.
    #[allow(clippy::too_many_arguments)]
    async fn produce_attempt(
        &self,
        topic: &str,
        key: Option<&str>,
        payload: &[u8],
        meta: Option<&DeliveryMeta>,
        additional_headers: Option<OwnedHeaders>,
        signature_headers: &Option<crate::sink::delivery::SignatureHeaders>,
        request_id: &str,
    ) -> Result<(), SinkError> {
        let transactional = self.config.transactional;
        if transactional {
            self.producer.begin_transaction().map_err(|e| {
                SinkError::Delivery {
                    message: format!("begin transaction: {e}"),
                    retryable: true,
                    retry_after_ms: None,
                }
            })?;
        }

        // `FutureRecord::headers` replaces the whole header set, so all
        // headers (custom, meta, additional and signature) are composed into
        // a single `OwnedHeaders` before attaching them. Custom static
        // headers go first and reserved ones are filtered out, so the
        // internal contract headers always win.
        let mut headers = OwnedHeaders::new();
        for (name, value) in &self.config.headers {
            if is_sink_reserved_header(name) {
                continue;
            }
            headers = headers.insert(Header {
                key: name.as_str(),
                value: Some(value.as_str()),
            });
        }
        if let Some(meta) = meta {
            for header in build_headers(meta, request_id).as_borrowed().iter()
            {
                headers = headers.insert(header);
            }
        }
        if let Some(extra) = &additional_headers {
            for header in extra.as_borrowed().iter() {
                headers = headers.insert(header);
            }
        }
        if let Some(sig) = signature_headers {
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

        let mut record =
            FutureRecord::to(topic).payload(payload).headers(headers);
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
                if transactional
                    && let Err(e) = self.producer.commit_transaction(
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
                        return Err(SinkError::Delivery {
                            message: format!("commit transaction: {e}"),
                            retryable: true,
                            retry_after_ms: None,
                        });
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
                Ok(())
            }
            Err((err, _message)) => {
                if transactional {
                    let _ = self.producer.abort_transaction(
                        Duration::from_millis(self.config.request_timeout_ms),
                    );
                }
                Err(map_produce_error(err))
            }
        }
    }

    /// Prepare one batch group for production: topic, message key, JSON
    /// array payload and request id. Returns `None` for an empty group
    /// (groups are never empty by construction, but the caller continues
    /// instead of failing the whole batch).
    fn prepare_group(
        &self,
        event_type: &str,
        group: &[IncomingSinkEvent],
    ) -> Result<Option<PreparedGroup>, SinkError> {
        let Some(first) = group.first() else {
            return Ok(None);
        };
        let schema_id = batch_group_schema_id(first);
        let topic = self.topic_template.render_with_event_type(
            first.subject_id(),
            &schema_id,
            event_type,
        );
        let payload = serialize_json_payload(group)?;
        let request_id = generate_request_id();
        let key = self.compute_key(first.subject_id(), &schema_id);
        Ok(Some((topic, key, payload, request_id)))
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
    load_required_secret(sink_name, &sink_password_env_var(sink_name), "SASL")
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
        let payload = serialize_json_payload(data.as_ref())?;

        let request_id = generate_request_id();
        let meta = DeliveryMeta::from_data(&data);

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
        let payload = serialize_json_payload(&light)?;

        let request_id = generate_request_id();
        let meta = DeliveryMeta::from_light(&light);

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
        for (event_type, group) in
            group_events_by_type(events, self.topic_template.has_event_type())
        {
            let Some((topic, key, payload, request_id)) =
                self.prepare_group(&event_type, &group)?
            else {
                continue;
            };
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

    /// Best-effort batch delivery: a single produce attempt per group, no
    /// retries. Used during Pause/Stop teardown where blocking on retries
    /// would delay actor shutdown; the cursor guarantees re-delivery via
    /// catch-up.
    async fn send_batch_best_effort(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        for (event_type, group) in
            group_events_by_type(events, self.topic_template.has_event_type())
        {
            let Some((topic, key, payload, request_id)) =
                self.prepare_group(&event_type, &group)?
            else {
                continue;
            };
            let signature_headers = self.sign_payload(&payload, None).await?;
            self.produce_once(
                &topic,
                key.as_deref(),
                &payload,
                None,
                None,
                &signature_headers,
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

        let topic =
            self.topic_template.render_with_event_type("-", "-", "test");
        let request_id = generate_request_id();
        let (key, payload, headers) = build_test_delivery(&request_id)?;
        self.produce(
            &topic,
            Some(&key),
            &payload,
            None,
            Some(headers),
            &request_id,
        )
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

    #[tokio::test]
    async fn generate_oauth_token_fetches_from_oidc_endpoint() {
        use rdkafka::ClientContext as _;

        // Mock OIDC token endpoint speaking the client_credentials contract.
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "access_token": "oidc-token-123",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }))
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });

        let ctx = KafkaStatsContext {
            sink_name: "unit-oauth".to_owned(),
            last_tx_errors: AtomicU64::new(0),
            oauth: Some(KafkaOAuthContext {
                handle: tokio::runtime::Handle::current(),
                client: reqwest::Client::new(),
                auth: ave_common::sink::SinkAuthConfig {
                    auth_url: format!("http://{addr}/token"),
                    username: String::new(),
                    api_key: String::new(),
                    grant_type:
                        ave_common::sink::OAuth2GrantType::ClientCredentials,
                    client_id: "client-1".to_owned(),
                    scope: "read".to_owned(),
                },
                password: "secret".to_owned(),
                principal: "client-1".to_owned(),
                retry_base_delay_ms: 10,
            }),
        };

        // The callback contract is synchronous and runs off-runtime:
        // exercise it from a blocking thread, exactly like librdkafka's poll
        // thread would (`Handle::block_on` panics on a runtime thread), and
        // await it so the runtime keeps polling the token fetch.
        let (token, principal_name, lifetime_ms) =
            tokio::task::spawn_blocking(move || {
                ctx.generate_oauth_token(None)
                    .map(|t| (t.token, t.principal_name, t.lifetime_ms))
                    .map_err(|e| e.to_string())
            })
            .await
            .expect("callback thread should not panic")
            .expect("token should be generated");

        assert_eq!(token, "oidc-token-123");
        assert_eq!(principal_name, "client-1");
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_millis() as i64;
        assert!(
            lifetime_ms > now_ms,
            "the token must expire in the future"
        );
    }

    #[test]
    fn kafka_stats_context_counts_only_fatal_errors() {        use rdkafka::ClientContext as _;

        // Initialize the core metrics global (idempotent via `OnceLock`).
        let mut registry = prometheus_client::registry::Registry::default();
        crate::metrics::register(&mut registry);

        let ctx = KafkaStatsContext {
            sink_name: "unit-fatal".to_owned(),
            last_tx_errors: AtomicU64::new(0),
            oauth: None,
        };
        ctx.error(KafkaError::Global(RDKafkaErrorCode::Fatal), "test fatal");
        ctx.error(
            KafkaError::Global(RDKafkaErrorCode::BrokerNotAvailable),
            "test non-fatal",
        );

        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, &registry)
            .unwrap();
        assert!(
            text.contains(
                "core_kafka_producer_fatal_errors_total{sink=\"unit-fatal\"} 1"
            ),
            "fatal counter must be 1 after one fatal and one non-fatal error:\n{text}"
        );
    }

    #[test]
    fn default_transactional_id_is_per_node_stable_and_truncated() {        let id = default_transactional_id("sink", Some("node-public-key-abcdef"));
        // First 12 chars of the node id: unique per node, stable per restart.
        assert_eq!(id, "ave-sink-sink-node-public-");
        assert_eq!(
            id,
            default_transactional_id("sink", Some("node-public-key-abcdef")),
            "the default id must be stable across constructions"
        );
        assert_ne!(
            default_transactional_id("sink", Some("node-a")),
            default_transactional_id("sink", Some("node-b")),
            "different nodes must get different ids"
        );
        // Without node identity, the historical sink-only default remains.
        assert_eq!(default_transactional_id("sink", None), "ave-sink-sink");
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

    fn oauth_config_with_ca(ca_path: &str) -> KafkaSinkConfig {
        KafkaSinkConfig {
            tls: Some(crate::config::KafkaTlsConfig {
                ca_certificate: ca_path.to_owned(),
                ..crate::config::KafkaTlsConfig::default()
            }),
            ..KafkaSinkConfig::default()
        }
    }

    #[tokio::test]
    async fn build_oauth_token_client_rejects_missing_ca_file() {
        let config = oauth_config_with_ca("/nonexistent/ave-test-ca.pem");
        let err = build_oauth_token_client("unit-oidc-missing-ca", &config)
            .await
            .unwrap_err();
        let SinkError::ClientBuild(message) = err else {
            panic!("expected ClientBuild error, got {err:?}");
        };
        assert!(
            message.contains("cannot read TLS ca_certificate file"),
            "unexpected error: {message}"
        );
    }

    #[tokio::test]
    async fn build_oauth_token_client_rejects_invalid_ca_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, "not a pem").unwrap();
        let config = oauth_config_with_ca(&ca_path.to_string_lossy());
        let err = build_oauth_token_client("unit-oidc-bad-ca", &config)
            .await
            .unwrap_err();
        let SinkError::ClientBuild(message) = err else {
            panic!("expected ClientBuild error, got {err:?}");
        };
        assert!(
            message.contains("invalid CA certificate"),
            "unexpected error: {message}"
        );
    }

    /// The OIDC token fetch must honor the sink's `tls.ca_certificate`: an
    /// IdP serving HTTPS with a corporate (here: throwaway) CA is reachable
    /// only when that CA is added to the token client.
    #[tokio::test]
    async fn build_oauth_token_client_fetches_token_over_custom_ca() {
        use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair,
            SanType,
        };
        use rustls::ServerConfig as RustlsServerConfig;
        use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
        use std::net::{IpAddr, Ipv4Addr};

        // Throwaway CA and server certificate for 127.0.0.1, same generation
        // as the integration TLS helpers.
        let ca_key = KeyPair::generate().expect("CA key should generate");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "ave-test-oidc-ca");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("CA cert should generate");
        let issuer = Issuer::from_params(&ca_params, &ca_key);
        let server_key =
            KeyPair::generate().expect("server key should generate");
        let mut server_params = CertificateParams::default();
        server_params.subject_alt_names =
            vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert should generate");

        // HTTPS token endpoint speaking the client_credentials contract.
        let app = axum::Router::new().route(
            "/token",
            axum::routing::post(|| async {
                axum::Json(serde_json::json!({
                    "access_token": "tls-oidc-token",
                    "token_type": "Bearer",
                    "expires_in": 3600
                }))
            }),
        );
        let listener =
            std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("non-blocking");
        let addr = listener.local_addr().expect("local address");
        // Explicit crypto provider: the process-level default may be unset
        // when several rustls backends are linked.
        let provider = rustls::crypto::aws_lc_rs::default_provider();
        let server_config =
            RustlsServerConfig::builder_with_provider(Arc::new(provider))
                .with_safe_default_protocol_versions()
                .expect("default TLS versions should be valid")
                .with_no_client_auth()
                .with_single_cert(
                    vec![server_cert.der().clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        server_key.serialize_der(),
                    )),
                )
                .expect("server cert/key should be valid");
        let rustls_config = RustlsConfig::from_config(Arc::new(server_config));
        tokio::spawn(async move {
            let _ = axum_server::from_tcp(listener)
                .expect("listener should convert to tokio")
                .acceptor(RustlsAcceptor::new(rustls_config))
                .serve(app.into_make_service())
                .await;
        });

        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, ca_cert.pem()).unwrap();
        let config = oauth_config_with_ca(&ca_path.to_string_lossy());
        let client = build_oauth_token_client("unit-oidc-tls", &config)
            .await
            .expect("client with custom CA should build");

        let auth = ave_common::sink::SinkAuthConfig {
            auth_url: format!("https://{addr}/token"),
            username: String::new(),
            api_key: String::new(),
            grant_type: ave_common::sink::OAuth2GrantType::ClientCredentials,
            client_id: "client-1".to_owned(),
            scope: String::new(),
        };
        let response = crate::sink::obtain_token(&client, &auth, "secret")
            .await
            .expect("the token fetch must trust the configured CA");
        assert_eq!(response.access_token, "tls-oidc-token");
    }
}
