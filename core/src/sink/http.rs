//! HTTP delivery logic for a single external sink.

use std::io::Write;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use flate2::Compression;
use flate2::write::GzEncoder;
use futures::StreamExt;
use reqwest::{Certificate, Client, Identity, tls::Version};
use tokio::sync::RwLock;
use tracing::debug;

use crate::config::{
    HttpCompression, HttpSinkConfig, HttpTlsVersion, TokenResponse,
};
use crate::metrics::try_core_metrics;
use crate::sink::SinkError;
use crate::sink::extract_sn;
use crate::sink::template::CompiledTemplate;
use crate::sink::transport::{NodeSigner, SinkTransport};
use ave_common::{DataToSink, IncomingSinkEvent, LightEvent, SinkTypes};

/// Build the environment variable name for a sink's password.
/// Format: `AVE_SINK_PASSWORD_{{SERVER_UPPER}}` where non-alphanumeric
/// chars are replaced by `_`.
pub fn sink_password_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_PASSWORD_", sink_name)
}

/// Build the environment variable name for a sink's API key.
/// Format: `AVE_SINK_APIKEY_{{SERVER_UPPER}}` where non-alphanumeric
/// chars are replaced by `_`.
pub fn sink_apikey_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_APIKEY_", sink_name)
}

/// Build the environment variable name for a sink's proxy password.
/// Format: `AVE_SINK_PROXY_PASSWORD_{{SERVER_UPPER}}` where non-alphanumeric
/// chars are replaced by `_`.
pub fn sink_proxy_password_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_PROXY_PASSWORD_", sink_name)
}

/// Build the environment variable name for a sink secret with the given
/// prefix, normalizing the sink name to upper-case with non-alphanumeric
/// chars replaced by `_`.
fn sink_secret_env_var(prefix: &str, sink_name: &str) -> String {
    let normalized: String = sink_name
        .chars()
        .map(|c| {
            if c.is_alphanumeric() {
                c.to_ascii_uppercase()
            } else {
                '_'
            }
        })
        .collect();
    format!("{}{}", prefix, normalized)
}

/// Build the reqwest client for a sink, applying the optional TLS
/// customization: additional root CA, mTLS identity and minimum TLS version.
fn build_http_client(
    sink_name: &str,
    config: &HttpSinkConfig,
) -> Result<Client, SinkError> {
    let mut builder = Client::builder()
        .timeout(Duration::from_millis(config.request_timeout_ms))
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
        .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs))
        .pool_max_idle_per_host(config.pool_max_idle_per_host);

    if let Some(secs) = config.tcp_keepalive_secs {
        builder = builder.tcp_keepalive(Duration::from_secs(secs));
    }

    if let Some(tls) = &config.tls {
        if !tls.ca_certificate.is_empty() {
            let pem = read_tls_file(
                sink_name,
                "ca_certificate",
                &tls.ca_certificate,
            )?;
            // With the rustls backend `Certificate::from_pem` defers parsing
            // and silently accepts a buffer without PEM sections, so parse
            // the bundle here and require at least one certificate.
            let certs = Certificate::from_pem_bundle(&pem).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': invalid CA certificate '{}': {}",
                    sink_name, tls.ca_certificate, e
                ))
            })?;
            if certs.is_empty() {
                return Err(SinkError::ClientBuild(format!(
                    "sink '{}': invalid CA certificate '{}': no PEM certificates found",
                    sink_name, tls.ca_certificate
                )));
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }

        if !tls.client_certificate.is_empty() {
            let mut pem = read_tls_file(
                sink_name,
                "client_certificate",
                &tls.client_certificate,
            )?;
            let key = read_tls_file(sink_name, "client_key", &tls.client_key)?;
            // rustls expects a single PEM buffer with the certificate chain
            // followed by the private key.
            pem.extend_from_slice(&key);
            let identity = Identity::from_pem(&pem).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': invalid mTLS identity ('{}' / '{}'): {}",
                    sink_name, tls.client_certificate, tls.client_key, e
                ))
            })?;
            builder = builder.identity(identity);
        }

        if let Some(min_version) = &tls.min_tls_version {
            let version = match min_version {
                HttpTlsVersion::Tls12 => Version::TLS_1_2,
                HttpTlsVersion::Tls13 => Version::TLS_1_3,
            };
            builder = builder.tls_version_min(version);
        }
    }

    if let Some(proxy_config) = &config.proxy {
        let mut proxy =
            reqwest::Proxy::all(&proxy_config.url).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': invalid proxy URL '{}': {}",
                    sink_name, proxy_config.url, e
                ))
            })?;

        if !proxy_config.username.is_empty() {
            let env_var = sink_proxy_password_env_var(sink_name);
            let password = std::env::var(&env_var).unwrap_or_default();
            if password.is_empty() {
                return Err(SinkError::ClientBuild(format!(
                    "proxy authentication configured for sink '{}' but password environment variable {} is not set",
                    sink_name, env_var
                )));
            }
            proxy = proxy.basic_auth(&proxy_config.username, &password);
        }

        if !proxy_config.no_proxy.is_empty() {
            proxy = proxy.no_proxy(reqwest::NoProxy::from_string(
                &proxy_config.no_proxy.join(","),
            ));
        }

        // Setting an explicit proxy also disables reqwest's automatic
        // system proxy detection for this client.
        builder = builder.proxy(proxy);
    }

    builder.build().map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': failed to build HTTP client: {}",
            sink_name, e
        ))
    })
}

/// Read a PEM file referenced by the TLS configuration.
fn read_tls_file(
    sink_name: &str,
    field: &str,
    path: &str,
) -> Result<Vec<u8>, SinkError> {
    std::fs::read(path).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': cannot read TLS {} file '{}': {}",
            sink_name, field, path, e
        ))
    })
}

/// Header carrying the Ed25519 signature of the delivery body.
const SIGNATURE_HEADER: &str = "X-Ave-Signature";
/// Header carrying the signature timestamp (nanoseconds since Unix epoch).
const SIGNATURE_TIMESTAMP_HEADER: &str = "X-Ave-Signature-Timestamp";
/// Header carrying the signer's public key.
const SIGNATURE_PUBLIC_KEY_HEADER: &str = "X-Ave-Public-Key";

/// Header carrying the subject identifier of the delivered event.
const SUBJECT_ID_HEADER: &str = "X-Ave-Subject-Id";
/// Header carrying the sequence number of the delivered event.
const SN_HEADER: &str = "X-Ave-SN";
/// Header carrying the delivered event type (`create`, `fact`, ...).
const EVENT_TYPE_HEADER: &str = "X-Ave-Event-Type";
/// Header allowing the receiver to deduplicate deliveries
/// (`<subject_id>-<sn>`, following the Stripe convention).
const IDEMPOTENCY_KEY_HEADER: &str = "Idempotency-Key";

/// Signature headers for one delivery, computed once per logical event and
/// reused across retries of the same body.
struct SignatureHeaders {
    signature: String,
    timestamp: String,
    public_key: String,
}

/// Idempotency metadata of a single-event delivery, sent as headers so the
/// receiver can deduplicate without parsing the body. Not sent on batch
/// deliveries, where each array element already carries this data.
struct DeliveryMeta {
    subject_id: String,
    sn: u64,
    event_type: SinkTypes,
}

/// HTTP transport for a single sink server.
#[derive(Debug)]
pub struct HttpTransport {
    client: Client,
    sink_name: String,
    config: HttpSinkConfig,
    url_template: CompiledTemplate,
    /// Password loaded from the environment variable `AVE_SINK_PASSWORD_{{SERVER}}`.
    password: String,
    /// API key: the `AVE_SINK_APIKEY_{{SERVER}}` environment variable takes
    /// precedence over the config value.
    api_key: String,
    cached_token: RwLock<Option<TokenResponse>>,
    /// Node identity signer; required when `config.signature` is enabled.
    signer: Option<NodeSigner>,
}

impl HttpTransport {
    pub fn new(
        sink_name: String,
        config: HttpSinkConfig,
        signer: Option<NodeSigner>,
    ) -> Result<Self, SinkError> {
        let client = build_http_client(&sink_name, &config)?;

        let password = std::env::var(sink_password_env_var(&sink_name))
            .unwrap_or_default();
        let api_key = std::env::var(sink_apikey_env_var(&sink_name))
            .ok()
            .filter(|k| !k.is_empty())
            .or_else(|| {
                config.auth.as_ref().and_then(|a| {
                    if a.api_key.is_empty() {
                        None
                    } else {
                        Some(a.api_key.clone())
                    }
                })
            })
            .unwrap_or_default();

        if let Some(auth) = &config.auth {
            let oauth2_configured =
                !auth.auth_url.is_empty() && !auth.username.is_empty();
            if oauth2_configured {
                // If OAuth2 is configured, the password environment variable must exist.
                if password.is_empty() {
                    return Err(SinkError::ClientBuild(format!(
                        "OAuth2 configured for sink '{}' but password environment variable {} is not set",
                        sink_name,
                        sink_password_env_var(&sink_name)
                    )));
                }
            } else if api_key.is_empty() {
                return Err(SinkError::ClientBuild(format!(
                    "API key authentication configured for sink '{}' but neither 'api_key' nor environment variable {} is set",
                    sink_name,
                    sink_apikey_env_var(&sink_name)
                )));
            }
        }

        if config.signature && signer.is_none() {
            return Err(SinkError::ClientBuild(format!(
                "signature enabled for sink '{}' but no node signer is available",
                sink_name
            )));
        }

        Ok(Self {
            client,
            url_template: CompiledTemplate::new(&config.url),
            password,
            api_key,
            cached_token: RwLock::new(None),
            signer,
            sink_name,
            config,
        })
    }

    /// Sign the delivery body with the node identity when signature is
    /// enabled. Returns `None` headers when no signer is configured.
    async fn sign_payload(
        &self,
        payload: &[u8],
    ) -> Result<Option<SignatureHeaders>, SinkError> {
        let Some(signer) = &self.signer else {
            return Ok(None);
        };
        let signature = signer.sign(payload.to_vec()).await?;
        Ok(Some(SignatureHeaders {
            signature: signature.value.to_string(),
            timestamp: signature.timestamp.to_string(),
            public_key: signature.signer.to_string(),
        }))
    }

    async fn invalidate_cached_token(&self) {
        let mut guard = self.cached_token.write().await;
        *guard = None;
    }

    async fn send_with_retry(
        &self,
        url: &str,
        payload: Vec<u8>,
        meta: Option<&DeliveryMeta>,
    ) -> Result<(), SinkError> {
        let mut last_err = None;
        let sink_name = &self.sink_name;
        let signature_headers = self.sign_payload(&payload).await?;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_sink_retry(sink_name);
                }
                // Saturate the exponent so a large `max_retries` cannot
                // overflow the shift (debug panic / masked shift in release).
                let exp = (attempt - 1).min(63);
                let base_delay = self
                    .config
                    .retry_base_delay_ms
                    .saturating_mul(1_u64 << exp);
                let mut delay = crate::sink::add_jitter(base_delay);
                // Honor the server-provided Retry-After hint when it exceeds
                // the computed backoff.
                if let Some(retry_after_ms) =
                    last_err.as_ref().and_then(retry_after_of)
                {
                    delay = delay.max(retry_after_ms);
                }
                delay = delay.min(self.config.retry_max_delay_ms);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self
                .timed_send_once(url, &payload, &signature_headers, meta)
                .await
            {
                Ok(()) => {
                    return Ok(());
                }
                Err(
                    e @ (SinkError::Delivery {
                        retryable: false, ..
                    }
                    | SinkError::ClientBuild(_)
                    | SinkError::Rejected { .. }
                    | SinkError::Shutdown),
                ) => {
                    // Permanent error: 422, bad config, etc. No retries.
                    return Err(e);
                }
                Err(e @ SinkError::Auth { .. }) if attempt == 0 => {
                    // Auth error on first attempt: invalidate cache, refresh
                    // token, retry once immediately.
                    self.invalidate_cached_token().await;
                    if self.build_auth_header().await.is_err() {
                        // Can't refresh auth; report the original auth error.
                        return Err(e);
                    }
                    // Retry once with fresh auth.
                    return self
                        .timed_send_once(
                            url,
                            &payload,
                            &signature_headers,
                            meta,
                        )
                        .await;
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

    async fn timed_send_once(
        &self,
        url: &str,
        payload: &[u8],
        signature_headers: &Option<SignatureHeaders>,
        meta: Option<&DeliveryMeta>,
    ) -> Result<(), SinkError> {
        let start = Instant::now();
        let result =
            self.send_once(url, payload, signature_headers, meta).await;
        let duration = start.elapsed();

        if let Some(metrics) = try_core_metrics() {
            let result_label = match &result {
                Ok(()) => "success",
                Err(SinkError::Auth { .. }) => "auth",
                Err(SinkError::Delivery {
                    retryable: true, ..
                }) => "transient",
                Err(SinkError::Shutdown) => "shutdown",
                Err(_) => "permanent",
            };
            metrics.observe_sink_request_duration(
                &self.sink_name,
                result_label,
                duration,
            );
        }

        result
    }

    async fn send_once(
        &self,
        url: &str,
        payload: &[u8],
        signature_headers: &Option<SignatureHeaders>,
        meta: Option<&DeliveryMeta>,
    ) -> Result<(), SinkError> {
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_vec());

        if let Some(headers) = signature_headers {
            request = request
                .header(SIGNATURE_HEADER, &headers.signature)
                .header(SIGNATURE_TIMESTAMP_HEADER, &headers.timestamp)
                .header(SIGNATURE_PUBLIC_KEY_HEADER, &headers.public_key);
        }

        if let Some(meta) = meta {
            request = request
                .header(SUBJECT_ID_HEADER, &meta.subject_id)
                .header(SN_HEADER, meta.sn.to_string())
                .header(EVENT_TYPE_HEADER, meta.event_type.as_str())
                .header(
                    IDEMPOTENCY_KEY_HEADER,
                    format!("{}-{}", meta.subject_id, meta.sn),
                );
        }

        if let Some(encoding) = self.config.compression.content_encoding() {
            request = request.header("Content-Encoding", encoding);
        }

        if self.config.auth.is_some()
            && let Some(header) = self.build_auth_header().await?
        {
            request = request.header("Authorization", header);
        }

        let response =
            request.send().await.map_err(|e| SinkError::Delivery {
                message: format!("HTTP request failed: {}", e),
                retryable: true,
                retry_after_ms: None,
            })?;

        let status = response.status();
        if status.is_success() {
            debug!(
                msg_type = "SinkSend",
                sink = %self.sink_name,
                url = %url,
                status = %status,
                "Sink delivery succeeded"
            );
            Ok(())
        } else if status == 401 || status == 403 {
            let body = read_limited_body(
                response.bytes_stream(),
                self.config.max_error_body_bytes,
            )
            .await;
            Err(SinkError::Auth {
                message: format!("HTTP {}: {}", status, body),
            })
        } else {
            // Read the Retry-After hint before consuming the body.
            let retry_after_ms = if status == 429 || status.is_server_error() {
                parse_retry_after(response.headers())
            } else {
                None
            };
            let body = read_limited_body(
                response.bytes_stream(),
                self.config.max_error_body_bytes,
            )
            .await;
            Err(SinkError::Delivery {
                message: format!("HTTP {}: {}", status, body),
                retryable: status.is_server_error() || status == 429,
                retry_after_ms,
            })
        }
    }

    async fn build_auth_header(&self) -> Result<Option<String>, SinkError> {
        let auth = match &self.config.auth {
            Some(a) => a,
            None => return Ok(None),
        };

        if !self.api_key.is_empty() {
            return Ok(Some(format!("Api-Key {}", self.api_key)));
        }

        let margin = self.config.token_refresh_margin_secs;

        // Check cached token
        {
            let guard = self.cached_token.read().await;
            if let Some(token) = guard.as_ref()
                && !token.is_expired_or_expiring_soon(margin)
            {
                return Ok(Some(format!("Bearer {}", token.access_token)));
            }
            // Token is missing, expired or expiring soon; fall through to obtain new token
        }

        if !auth.auth_url.is_empty()
            && !auth.username.is_empty()
            && !self.password.is_empty()
        {
            // Refresh the token outside the write lock so other deliveries are
            // not blocked while the auth endpoint is failing or slow.
            let token = crate::sink::obtain_token_with_retry(
                &self.client,
                auth,
                &self.password,
                self.config.retry_base_delay_ms,
            )
            .await?;

            let header = format!("Bearer {}", token.access_token);
            let mut guard = self.cached_token.write().await;
            *guard = Some(token);
            return Ok(Some(header));
        }

        Err(SinkError::Auth {
            message: "auth configured but no API key and incomplete OAuth2 credentials"
                .to_owned(),
        })
    }

    /// Serialize and, when configured, compress the delivery body.
    /// Signing happens on the encoded bytes (the exact wire payload).
    /// Compression runs in `spawn_blocking` because `GzEncoder` is CPU-bound
    /// and batches can be large.
    async fn encode_body<T: serde::Serialize + Sync>(
        &self,
        body: &T,
    ) -> Result<Vec<u8>, SinkError> {
        let raw =
            serde_json::to_vec(body).map_err(|e| SinkError::Delivery {
                message: format!("JSON serialization failed: {}", e),
                retryable: false,
                retry_after_ms: None,
            })?;

        if matches!(self.config.compression, HttpCompression::None) {
            return Ok(raw);
        }

        tokio::task::spawn_blocking(move || {
            let mut encoder =
                GzEncoder::new(Vec::new(), Compression::default());
            encoder
                .write_all(&raw)
                .and_then(|()| encoder.finish())
                .map_err(|e| SinkError::Delivery {
                    message: format!("gzip compression failed: {}", e),
                    retryable: false,
                    retry_after_ms: None,
                })
        })
        .await
        .map_err(|e| SinkError::Delivery {
            message: format!("compression task failed: {}", e),
            retryable: true,
            retry_after_ms: None,
        })?
    }
}

#[async_trait]
impl SinkTransport for HttpTransport {
    async fn send(&self, data: Arc<DataToSink>) -> Result<(), SinkError> {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let url = self
            .url_template
            .render_url_encoded(&subject_id, &schema_id);
        let payload = self.encode_body(data.as_ref()).await?;
        let meta = DeliveryMeta {
            subject_id,
            sn: extract_sn(&data),
            event_type: SinkTypes::from(data.as_ref()),
        };

        self.send_with_retry(&url, payload, Some(&meta)).await
    }

    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError> {
        let url = self
            .url_template
            .render_url_encoded(&light.subject_id, &light.schema_id);
        let payload = self.encode_body(&light).await?;
        let meta = DeliveryMeta {
            subject_id: light.subject_id.clone(),
            sn: light.sn,
            event_type: light.event_type.clone(),
        };

        self.send_with_retry(&url, payload, Some(&meta)).await
    }

    /// Send a lightweight GET request to verify the sink is reachable.
    async fn health_check(&self) -> Result<(), SinkError> {
        // Use dedicated health-check URL if configured, otherwise render the
        // delivery URL with empty placeholders.
        // MIN-3: Use "-" as placeholder instead of "" to avoid "//" in rendered URL.
        let url = self
            .config
            .health_check_url
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.url_template.render_url_encoded("-", "-"));

        let mut request = self.client.get(&url);

        // Add auth header if available
        if self.config.auth.is_some() {
            match self.build_auth_header().await {
                Ok(Some(header)) => {
                    request = request.header("Authorization", header);
                }
                Ok(None) => {}
                Err(_e) => {
                    // If auth is required but we can't build a header, still try without auth
                    // Some sinks have public health endpoints even when delivery requires auth
                }
            }
        }

        let response =
            request.send().await.map_err(|e| SinkError::Delivery {
                message: format!("Health check request failed: {}", e),
                retryable: true,
                retry_after_ms: None,
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if status == 401 || status == 403 {
            self.invalidate_cached_token().await;
            let body = read_limited_body(
                response.bytes_stream(),
                self.config.max_error_body_bytes,
            )
            .await;
            Err(SinkError::Auth {
                message: format!("Health check returned {}: {}", status, body),
            })
        } else {
            let body = read_limited_body(
                response.bytes_stream(),
                self.config.max_error_body_bytes,
            )
            .await;
            Err(SinkError::Delivery {
                message: format!("Health check returned {}: {}", status, body),
                retryable: status.is_server_error() || status == 429,
                retry_after_ms: None,
            })
        }
    }

    /// Deliver a batch of events as a single POST with a JSON array body.
    /// Per-event idempotency headers are not sent: every array element
    /// already carries `subject_id`, `sn` and the event type.
    async fn send_batch(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        let Some(first) = events.first() else {
            return Ok(());
        };
        let schema_id = match first {
            IncomingSinkEvent::Full(data) => {
                data.payload.get_subject_schema().1
            }
            IncomingSinkEvent::Light(light) => light.schema_id.clone(),
        };
        let url = self
            .url_template
            .render_url_encoded(first.subject_id(), &schema_id);
        let payload = self.encode_body(&events).await?;

        self.send_with_retry(&url, payload, None).await
    }

    /// Best-effort batch delivery: a single attempt, no retries and no auth
    /// refresh. Used during Pause/Stop teardown where blocking on retries
    /// would delay actor shutdown; the cursor guarantees re-delivery via
    /// catch-up.
    async fn send_batch_best_effort(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        let Some(first) = events.first() else {
            return Ok(());
        };
        let schema_id = match first {
            IncomingSinkEvent::Full(data) => {
                data.payload.get_subject_schema().1
            }
            IncomingSinkEvent::Light(light) => light.schema_id.clone(),
        };
        let url = self
            .url_template
            .render_url_encoded(first.subject_id(), &schema_id);
        let payload = self.encode_body(&events).await?;
        let signature_headers = self.sign_payload(&payload).await?;
        self.timed_send_once(&url, &payload, &signature_headers, None)
            .await
    }

    /// If the sink has OAuth2 auth config, obtain a token eagerly on startup.
    async fn warm_up(&self) -> Result<(), SinkError> {
        if let Some(ref auth) = self.config.auth
            && !auth.auth_url.is_empty()
            && !auth.username.is_empty()
            && !self.password.is_empty()
        {
            let token = crate::sink::obtain_token_with_retry(
                &self.client,
                auth,
                &self.password,
                self.config.retry_base_delay_ms,
            )
            .await?;
            let mut guard = self.cached_token.write().await;
            *guard = Some(token);
        }
        Ok(())
    }
}

/// Extract the `Retry-After` hint carried by a delivery error, if any.
const fn retry_after_of(err: &SinkError) -> Option<u64> {
    match err {
        SinkError::Delivery { retry_after_ms, .. } => *retry_after_ms,
        _ => None,
    }
}

/// Parse the `Retry-After` header of a 429 / 5xx response. The value may be
/// a number of seconds or an HTTP-date; the result is milliseconds from now.
fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    let value = headers
        .get(reqwest::header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim();

    if let Ok(seconds) = value.parse::<u64>() {
        return Some(seconds.saturating_mul(1_000));
    }

    let date = httpdate::parse_http_date(value).ok()?;
    let delay = date.duration_since(std::time::SystemTime::now()).ok()?;
    Some(delay.as_millis() as u64)
}

/// Read at most `limit` bytes from a byte stream, truncating the rest.
/// Returns a lossy UTF-8 string with a `…(truncated)` marker when the body
/// exceeds the limit. This prevents a misbehaving endpoint from causing an
/// out-of-memory error by returning a multi-gigabyte error payload.
async fn read_limited_body<S, E>(stream: S, limit: usize) -> String
where
    S: futures::Stream<Item = Result<bytes::Bytes, E>>,
{
    let mut collected = Vec::with_capacity(limit.min(1024));
    let mut stream = Box::pin(stream);

    while let Some(chunk) = stream.next().await {
        match chunk {
            Ok(bytes) => {
                let remaining = limit.saturating_sub(collected.len());
                if remaining == 0 {
                    return format!(
                        "{}…(truncated)",
                        String::from_utf8_lossy(&collected)
                    );
                }
                let take = bytes.len().min(remaining);
                collected.extend_from_slice(&bytes[..take]);
                if collected.len() >= limit {
                    return format!(
                        "{}…(truncated)",
                        String::from_utf8_lossy(&collected)
                    );
                }
            }
            Err(_) => break,
        }
    }

    String::from_utf8_lossy(&collected).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_common::sink::{HttpTlsConfig, SinkAuthConfig};

    // Throwaway self-signed certificate and key generated ad hoc for these
    // tests; they do not protect anything real.
    const TEST_CERT_PEM: &str = r"-----BEGIN CERTIFICATE-----
MIIDBzCCAe+gAwIBAgIUFy3R8W8wanseVP54+nyeNFsApL8wDQYJKoZIhvcNAQEL
BQAwEzERMA8GA1UEAwwIYXZlLXRlc3QwHhcNMjYwNzE1MTAwODA4WhcNMzYwNzEy
MTAwODA4WjATMREwDwYDVQQDDAhhdmUtdGVzdDCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBAOyWBpK+/6LydEydWc6YEWgRlsCddTpgkSnN/B4IxzlZFBnU
BS5A/AyaniqiojpSpVSbUiF/PkMz4jrBb0gI/jazMUThsGt0RwuRcL29SQjMdLjT
yB5P8jjUQYwrhr+yyBy0IQ97jgcWyRt5+627i7WB7d8OpKNKWQA6+DX6cg53eEQs
awR5EMFLhV/RhqRt+dflATuINMwtFcIfZhcqrgvbAKy8l9NqVowWXy2+EI2SkT8j
M9fhsFjlPn5XtOudRh210ynBMOmR3CTlc2+wbLzC03L2vLYH6xmQ5w8KdcXEWI9o
Q3mAWPGVAK+6L4fkL3Xw58cqNS5Eqik5iYD4Kg0CAwEAAaNTMFEwHQYDVR0OBBYE
FI5L8iCL+D0cYMdkMbl2nfAOtv1KMB8GA1UdIwQYMBaAFI5L8iCL+D0cYMdkMbl2
nfAOtv1KMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBAJu4Jwkl
xmI7DjMgFysHqRwVXFQxDwCENKBnvBWE8rCPys1eKcRUhqp5VE5IzIm9g5F/4LKP
RVH1nRAFDMxfgsqda//Rpex3upjSsY311ofUZfoEcLEp5wG+DjztD6a4/yE9Vs9S
5dp+1epZsXAqpApYK3XM8AbZYu/qDv6AvqXnft2K1tGi3KS+I/00cbhwSEqRrwcs
tWPJo0F4usp8a5Fm/5zwKOyU8D8gLXC/cXomwFaDla8wwXOC8zLeeB3Qh2H+ht7W
LhuBoQ4jvcEN3xrRT1BiBsantFgw1FOR42zrvnUgHNrWrJ0I1gfND+k07ZckTZYG
0ir8wZZgJbjAhIQ=
-----END CERTIFICATE-----
";

    const TEST_KEY_PEM: &str = r"-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDslgaSvv+i8nRM
nVnOmBFoEZbAnXU6YJEpzfweCMc5WRQZ1AUuQPwMmp4qoqI6UqVUm1Ihfz5DM+I6
wW9ICP42szFE4bBrdEcLkXC9vUkIzHS408geT/I41EGMK4a/ssgctCEPe44HFskb
efutu4u1ge3fDqSjSlkAOvg1+nIOd3hELGsEeRDBS4Vf0YakbfnX5QE7iDTMLRXC
H2YXKq4L2wCsvJfTalaMFl8tvhCNkpE/IzPX4bBY5T5+V7TrnUYdtdMpwTDpkdwk
5XNvsGy8wtNy9ry2B+sZkOcPCnXFxFiPaEN5gFjxlQCvui+H5C918OfHKjUuRKop
OYmA+CoNAgMBAAECggEAXoHJq2ofzTRED+zVWKk3XtaT3WqozwKPSl9N5KOGDdsP
JAglb6Ym6VQEdayU2G52O9d11gqx0P+TUfw+W0y4XBp1xnnPUwVWcgENw8WuvJSL
1d9HtBAkht4HNxqWD9K3jHvKLxigkiVgfZjbWDmwY/e8kVuUmeQTrHth9pIOaMc8
6/8yBJnMnrjkAbpUZwqHVcOuK70LECFRXAqzLakHaCRj77nmdj55LAVseIxhnjft
Mxo3Vyo7vTgptGGwc0fFOEsD1k2gRN/Kcz6sgRZnj0RnmLhsmzCrTlhkSxS6wxPm
jq9ndDIvWhgMbhHcB/Tl4CEX1+eK6W1UkcTeXJypswKBgQD+FINdhO8gvPBZQtyn
gNoBbrlmqP3hZ5G28aQtyfA+YSqRAPLz1VfcpHNerHYWPiBhenT8/9A0TC8kw/7V
bAL3n5AmtcsW9ixGCWbEwgSAy7SvOsnIPbQcuNmil971h9VUPuCVmf6kJGX4rY3w
KRcDkaR5XoEiwKPfTA1PQ08IlwKBgQDuX6wfge+2JtSlMO0WKOc1Ft5D4DIBydxt
g1eH1m9uT4yhhXx+usLygoFLiWxfTF2GbmUESiKtJhA8Y0x4cQ4L8E4+dG0aE/CH
Jo7klKOePmUW8ZaYaGoxxI3MvG6MvGx4e+iPS1Wb5wAUMkfrjLF9YICXQRZeo22F
5ity5gTy+wKBgCJ/In7WB6mIPZHA9DiB1BeRsvZvR1kNOMl/8WyOGGI/ywm4+UOF
2dIJOejGvZmzga36dFvNV7ViCpyRR84uRhDcxzOaRyKs9cHkkOFx/i6Gede4waDA
T+3+Yv4iZJEtihdQGin1qI8cqgOjfLv4uDkx0wTvgdT4FsfAiaYTW22tAoGBALLu
Kdu0w2UtnK0rHqxlo7gcJFc68Q6aodWqo4eZlSdumxebhanzMuaqw7cZvrmCLyn7
r+QaahEi40kRGJPH+U1I4tLKviK3GPO6I8S9NlxQZb1lNy/MIPqemfo275zAy4Nd
L2JwoCBYs5x1absMbya3y46+EraTYmECN1cWBl0FAoGANZ0szjSsdvT/9gFmoXr4
fpgT8yKu4qpb14wNbJq1tnNpekZj8rk0672ByTorvq3LVG2Zmg4O+JDEyNlDTay6
nu6mmURC6HSG1u6cKUJqEpc56NpqMBViQ6pm7xFBHvRfMrAE+e5ELFQZQdyj97UJ
ov1w4iaMiBWHRcL/ZZMytPQ=
-----END PRIVATE KEY-----
";

    fn base_config() -> HttpSinkConfig {
        HttpSinkConfig {
            url: "http://127.0.0.1/events".to_owned(),
            ..HttpSinkConfig::default()
        }
    }

    fn client_build_error(result: Result<HttpTransport, SinkError>) -> String {
        match result {
            Err(SinkError::ClientBuild(message)) => message,
            other => panic!("expected ClientBuild error, got {:?}", other),
        }
    }

    #[test]
    fn build_client_rejects_missing_ca_file() {
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            ca_certificate: "/nonexistent/ave-test-ca.pem".to_owned(),
            ..HttpTlsConfig::default()
        });
        let err = client_build_error(HttpTransport::new(
            "unit-missing-ca".to_owned(),
            config,
            None,
        ));
        assert!(
            err.contains("cannot read TLS ca_certificate file"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn build_client_rejects_invalid_ca_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, "not a pem").unwrap();
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..HttpTlsConfig::default()
        });
        let err = client_build_error(HttpTransport::new(
            "unit-bad-ca".to_owned(),
            config,
            None,
        ));
        assert!(
            err.contains("invalid CA certificate"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn build_client_accepts_valid_ca_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, TEST_CERT_PEM).unwrap();
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..HttpTlsConfig::default()
        });
        assert!(
            HttpTransport::new("unit-valid-ca".to_owned(), config, None)
                .is_ok()
        );
    }

    #[test]
    fn build_client_accepts_mtls_identity() {
        let dir = tempfile::tempdir().unwrap();
        let cert_path = dir.path().join("client.pem");
        let key_path = dir.path().join("client.key");
        std::fs::write(&cert_path, TEST_CERT_PEM).unwrap();
        std::fs::write(&key_path, TEST_KEY_PEM).unwrap();
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            client_certificate: cert_path.to_string_lossy().into_owned(),
            client_key: key_path.to_string_lossy().into_owned(),
            min_tls_version: Some(HttpTlsVersion::Tls12),
            ..HttpTlsConfig::default()
        });
        assert!(
            HttpTransport::new("unit-mtls".to_owned(), config, None).is_ok()
        );
    }

    #[tokio::test]
    async fn api_key_env_var_takes_precedence_over_config() {
        let env_var = "AVE_SINK_APIKEY_UNIT_ENV_PRECEDENCE";
        unsafe {
            std::env::set_var(env_var, "env-key");
        }
        let mut config = base_config();
        config.auth = Some(SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: "config-key".to_owned(),
        });
        let transport =
            HttpTransport::new("unit-env-precedence".to_owned(), config, None)
                .unwrap();
        let header = transport.build_auth_header().await.unwrap();
        unsafe {
            std::env::remove_var(env_var);
        }
        assert_eq!(header.as_deref(), Some("Api-Key env-key"));
    }

    #[tokio::test]
    async fn api_key_from_config_when_env_not_set() {
        let mut config = base_config();
        config.auth = Some(SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: "config-key".to_owned(),
        });
        let transport =
            HttpTransport::new("unit-config-key".to_owned(), config, None)
                .unwrap();
        let header = transport.build_auth_header().await.unwrap();
        assert_eq!(header.as_deref(), Some("Api-Key config-key"));
    }

    #[test]
    fn auth_without_any_credential_fails() {
        let mut config = base_config();
        config.auth = Some(SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: String::new(),
        });
        let err = client_build_error(HttpTransport::new(
            "unit-missing-key".to_owned(),
            config,
            None,
        ));
        assert!(
            err.contains("AVE_SINK_APIKEY_UNIT_MISSING_KEY"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn signature_without_signer_fails() {
        let mut config = base_config();
        config.signature = true;
        let err = client_build_error(HttpTransport::new(
            "unit-signer".to_owned(),
            config,
            None,
        ));
        assert!(err.contains("no node signer"), "unexpected error: {}", err);
    }

    #[test]
    fn proxy_without_password_env_fails() {
        let mut config = base_config();
        config.proxy = Some(ave_common::sink::HttpProxyConfig {
            url: "http://proxy.local:3128".to_owned(),
            username: "ave".to_owned(),
            no_proxy: vec![],
        });
        let err = client_build_error(HttpTransport::new(
            "unit-proxy-nopass".to_owned(),
            config,
            None,
        ));
        assert!(
            err.contains("AVE_SINK_PROXY_PASSWORD_UNIT_PROXY_NOPASS"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn proxy_with_invalid_url_fails() {
        let mut config = base_config();
        config.proxy = Some(ave_common::sink::HttpProxyConfig {
            url: "not a url".to_owned(),
            username: String::new(),
            no_proxy: vec![],
        });
        let err = client_build_error(HttpTransport::new(
            "unit-proxy-badurl".to_owned(),
            config,
            None,
        ));
        assert!(
            err.contains("invalid proxy URL"),
            "unexpected error: {}",
            err
        );
    }

    #[test]
    fn proxy_with_password_env_builds() {
        let env_var = "AVE_SINK_PROXY_PASSWORD_UNIT_PROXY_OK";
        unsafe {
            std::env::set_var(env_var, "proxy-secret");
        }
        let mut config = base_config();
        config.proxy = Some(ave_common::sink::HttpProxyConfig {
            url: "http://proxy.local:3128".to_owned(),
            username: "ave".to_owned(),
            no_proxy: vec!["localhost".to_owned()],
        });
        let result =
            HttpTransport::new("unit-proxy-ok".to_owned(), config, None);
        unsafe {
            std::env::remove_var(env_var);
        }
        assert!(result.is_ok());
    }

    #[test]
    fn parse_retry_after_seconds() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "2".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), Some(2_000));
    }

    #[test]
    fn parse_retry_after_http_date() {
        let mut headers = reqwest::header::HeaderMap::new();
        let date = httpdate::fmt_http_date(
            std::time::SystemTime::now() + Duration::from_secs(3),
        );
        headers.insert(reqwest::header::RETRY_AFTER, date.parse().unwrap());
        let parsed = parse_retry_after(&headers).unwrap();
        assert!(
            parsed > 0 && parsed <= 3_000,
            "unexpected value: {}",
            parsed
        );
    }

    #[test]
    fn parse_retry_after_past_date_is_none() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::RETRY_AFTER,
            "Sun, 06 Nov 1994 08:49:37 GMT".parse().unwrap(),
        );
        assert_eq!(parse_retry_after(&headers), None);
    }

    #[test]
    fn parse_retry_after_garbage_is_none() {
        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(reqwest::header::RETRY_AFTER, "soon".parse().unwrap());
        assert_eq!(parse_retry_after(&headers), None);
        assert_eq!(parse_retry_after(&reqwest::header::HeaderMap::new()), None);
    }

    #[tokio::test]
    async fn encode_body_plain_when_no_compression() {
        let transport =
            HttpTransport::new("unit-plain".to_owned(), base_config(), None)
                .unwrap();
        let body = transport
            .encode_body(&serde_json::json!({"a": 1}))
            .await
            .unwrap();
        assert_eq!(body, br#"{"a":1}"#.to_vec());
    }

    #[tokio::test]
    async fn encode_body_gzip_roundtrip() {
        let mut config = base_config();
        config.compression = HttpCompression::Gzip;
        let transport =
            HttpTransport::new("unit-gzip".to_owned(), config, None).unwrap();
        let raw = serde_json::to_vec(&serde_json::json!({"a": 1})).unwrap();
        let body = transport
            .encode_body(&serde_json::json!({"a": 1}))
            .await
            .unwrap();
        assert_ne!(body, raw);
        let mut decoder = flate2::read::GzDecoder::new(body.as_slice());
        let mut decoded = Vec::new();
        std::io::Read::read_to_end(&mut decoder, &mut decoded).unwrap();
        assert_eq!(decoded, raw);
    }

    fn test_stream(
        chunks: Vec<Result<bytes::Bytes, ()>>,
    ) -> impl futures::Stream<Item = Result<bytes::Bytes, ()>> {
        futures::stream::iter(chunks)
    }

    #[tokio::test]
    async fn read_limited_body_returns_small_body_intact() {
        let stream =
            test_stream(vec![Ok(bytes::Bytes::from_static(b"small error"))]);
        let body = read_limited_body(stream, 100).await;
        assert_eq!(body, "small error");
    }

    #[tokio::test]
    async fn read_limited_body_truncates_large_body() {
        let stream =
            test_stream(vec![Ok(bytes::Bytes::from_static(b"0123456789"))]);
        let body = read_limited_body(stream, 5).await;
        assert_eq!(body, "01234…(truncated)");
    }

    #[tokio::test]
    async fn read_limited_body_empty_body() {
        let stream = test_stream(vec![]);
        let body = read_limited_body(stream, 100).await;
        assert!(body.is_empty());
    }

    #[tokio::test]
    async fn read_limited_body_ignores_chunk_errors() {
        let stream = test_stream(vec![
            Ok(bytes::Bytes::from_static(b"partial")),
            Err(()),
        ]);
        let body = read_limited_body(stream, 100).await;
        assert_eq!(body, "partial");
    }

    /// Starts a minimal HTTP OAuth2 token endpoint that returns a single JSON
    /// token response and then closes the connection.
    async fn start_oauth2_server(access_token: &str) -> String {
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");

        let body = format!(
            r#"{{"access_token":"{}","token_type":"Bearer","expires_in":3600}}"#,
            access_token
        );
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );

        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test listener should accept");
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        format!("http://{}/token", addr)
    }

    #[tokio::test]
    async fn build_auth_header_refreshes_expired_token() {
        let env_var = "AVE_SINK_PASSWORD_UNIT_REFRESH_EXPIRED";
        unsafe {
            std::env::set_var(env_var, "unit-secret");
        }

        let auth_url = start_oauth2_server("fresh-token").await;

        let mut config = base_config();
        config.auth = Some(SinkAuthConfig {
            auth_url,
            username: "unit-user".to_owned(),
            api_key: String::new(),
        });

        let transport =
            HttpTransport::new("unit-refresh-expired".to_owned(), config, None)
                .expect("transport should build");

        // Seed an expired token; the next call must obtain a fresh one.
        let expired_token = TokenResponse {
            access_token: "expired-token".to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in: 1,
            refresh_token: None,
            scope: None,
            obtained_at: Some(
                std::time::Instant::now() - std::time::Duration::from_secs(2),
            ),
        };
        {
            let mut guard = transport.cached_token.write().await;
            *guard = Some(expired_token);
        }

        let header = transport
            .build_auth_header()
            .await
            .expect("should build auth header")
            .expect("should return a header");

        assert_eq!(header, "Bearer fresh-token");

        unsafe {
            std::env::remove_var(env_var);
        }
    }
}
