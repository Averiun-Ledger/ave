//! HTTP delivery logic for a single external sink.

use std::io::Write;
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use flate2::Compression;
use flate2::write::GzEncoder;
use futures::StreamExt;
use reqwest::{Client, Identity, tls::Version};
use tokio::sync::RwLock;
use tracing::debug;

use rustls::client::danger::{
    HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier,
};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, Error as RustlsError, SignatureScheme};

use crate::config::{
    HttpCompression, HttpSinkConfig, HttpTlsVersion, TokenResponse,
};
use crate::metrics::try_core_metrics;
use crate::sink::SinkError;
use crate::sink::read_tls_file;
use crate::sink::delivery::{
    DeliveryMeta, EVENT_TYPE_HEADER, IDEMPOTENCY_KEY_HEADER, REQUEST_ID_HEADER,
    SIGNATURE_HEADER, SIGNATURE_PUBLIC_KEY_HEADER, SIGNATURE_TIMESTAMP_HEADER,
    SN_HEADER, SUBJECT_ID_HEADER, TEST_HEADER, batch_group_schema_id,
    generate_request_id, group_events_by_type, is_sink_reserved_header,
    load_required_secret, serialize_json_payload, sign_delivery,
    sink_apikey_env_var, sink_password_env_var, sink_proxy_password_env_var,
    test_delivery_payload, timed_sink_request,
};
use crate::sink::template::CompiledTemplate;
use crate::sink::transport::{NodeSigner, SinkTransport};
use ave_common::{
    DataToSink, IncomingSinkEvent, LightEvent, SinkTypes, sink::SinkAuthConfig,
};

/// TLS certificate pinning verifier. Pinning **replaces** normal CA / WebPKI
/// verification: the operator explicitly trusts this exact certificate, so
/// chain building, hostname verification and expiry are intentionally ignored.
/// The inner verifier is only used to verify handshake signature schemes.
struct PinnedCertificateVerifier {
    pinned: CertificateDer<'static>,
    inner: std::sync::Arc<dyn ServerCertVerifier>,
}

impl std::fmt::Debug for PinnedCertificateVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PinnedCertificateVerifier")
            .field("pinned_len", &self.pinned.len())
            .finish()
    }
}

impl ServerCertVerifier for PinnedCertificateVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        // Pinning replaces CA validation: the operator explicitly trusts this
        // exact certificate, so any chain or expiry is intentionally ignored.
        if end_entity.as_ref() != self.pinned.as_ref() {
            return Err(RustlsError::General(
                "server certificate does not match pinned certificate"
                    .to_owned(),
            ));
        }

        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// Build a rustls `ClientConfig` that wraps the default WebPKI verification
/// with certificate pinning. The config includes native roots, the optional
/// custom CA and mTLS identity from the sink config.
async fn build_pinned_tls_config(
    sink_name: &str,
    config: &HttpSinkConfig,
) -> Result<rustls::ClientConfig, SinkError> {
    let tls = config.tls.as_ref().ok_or_else(|| {
        SinkError::ClientBuild(format!(
            "sink '{}': pinned_certificate requires a tls section",
            sink_name
        ))
    })?;

    let pinned_pem =
        read_tls_file(sink_name, "pinned_certificate", &tls.pinned_certificate)
            .await?;
    let pinned = CertificateDer::from_pem_slice(&pinned_pem).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': invalid pinned certificate '{}': {}",
            sink_name, tls.pinned_certificate, e
        ))
    })?;

    let mut root_store = rustls::RootCertStore::empty();
    let native_certs = rustls_native_certs::load_native_certs();
    for cert in native_certs.certs {
        root_store.add(cert).map_err(|e| {
            SinkError::ClientBuild(format!(
                "sink '{}': failed to add native root certificate: {}",
                sink_name, e
            ))
        })?;
    }

    if !tls.ca_certificate.is_empty() {
        let pem =
            read_tls_file(sink_name, "ca_certificate", &tls.ca_certificate)
                .await?;
        let mut found = false;
        for item in CertificateDer::pem_slice_iter(&pem) {
            let cert = item.map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': invalid CA certificate '{}': {}",
                    sink_name, tls.ca_certificate, e
                ))
            })?;
            root_store.add(cert).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': failed to add CA certificate '{}': {}",
                    sink_name, tls.ca_certificate, e
                ))
            })?;
            found = true;
        }
        if !found {
            return Err(SinkError::ClientBuild(format!(
                "sink '{}': invalid CA certificate '{}': no PEM certificates found",
                sink_name, tls.ca_certificate
            )));
        }
    }

    let provider = rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| {
            Arc::new(rustls::crypto::aws_lc_rs::default_provider())
        });

    let verifier = rustls::client::WebPkiServerVerifier::builder_with_provider(
        Arc::new(root_store),
        provider.clone(),
    )
    .build()
    .map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': failed to build TLS verifier: {}",
            sink_name, e
        ))
    })?;

    let pinned_verifier = PinnedCertificateVerifier {
        pinned: pinned.into_owned(),
        inner: verifier,
    };

    let versions: &[&'static rustls::SupportedProtocolVersion] =
        match &tls.min_tls_version {
            Some(HttpTlsVersion::Tls12) => &[&rustls::version::TLS12],
            Some(HttpTlsVersion::Tls13) => &[&rustls::version::TLS13],
            None => &[&rustls::version::TLS12, &rustls::version::TLS13],
        };

    let config_builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)
        .map_err(|e| {
            SinkError::ClientBuild(format!(
                "sink '{}': invalid TLS protocol versions: {}",
                sink_name, e
            ))
        })?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(pinned_verifier));

    let mut client_config = if !tls.client_certificate.is_empty() {
        let cert_pem = read_tls_file(
            sink_name,
            "client_certificate",
            &tls.client_certificate,
        )
        .await?;
        let key_pem =
            read_tls_file(sink_name, "client_key", &tls.client_key).await?;

        let cert_chain: Vec<CertificateDer<'static>> =
            CertificateDer::pem_slice_iter(&cert_pem)
                .map(|item| item.map(|c| c.into_owned()))
                .collect::<Result<_, _>>()
                .map_err(|e| {
                    SinkError::ClientBuild(format!(
                        "sink '{}': invalid mTLS client certificate '{}': {}",
                        sink_name, tls.client_certificate, e
                    ))
                })?;
        if cert_chain.is_empty() {
            return Err(SinkError::ClientBuild(format!(
                "sink '{}': invalid mTLS client certificate '{}': no PEM certificates found",
                sink_name, tls.client_certificate
            )));
        }

        let private_key =
            rustls::pki_types::PrivateKeyDer::from_pem_slice(&key_pem)
                .map_err(|e| {
                    SinkError::ClientBuild(format!(
                        "sink '{}': invalid mTLS client key '{}': {}",
                        sink_name, tls.client_key, e
                    ))
                })?;

        config_builder
            .with_client_auth_cert(cert_chain, private_key)
            .map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': failed to configure mTLS identity: {}",
                    sink_name, e
                ))
            })?
    } else {
        config_builder.with_no_client_auth()
    };

    client_config.enable_sni = true;
    client_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

    Ok(client_config)
}

/// Build the reqwest client for a sink, applying the optional TLS
/// customization: additional root CA, mTLS identity, minimum TLS version and
/// certificate pinning.
async fn build_http_client(
    sink_name: &str,
    config: &HttpSinkConfig,
) -> Result<Client, SinkError> {
    let mut builder = Client::builder()
        .timeout(Duration::from_millis(config.request_timeout_ms))
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
        .pool_idle_timeout(Duration::from_secs(config.pool_idle_timeout_secs))
        .pool_max_idle_per_host(config.pool_max_idle_per_host)
        .redirect(if config.max_redirects == 0 {
            reqwest::redirect::Policy::none()
        } else {
            reqwest::redirect::Policy::limited(config.max_redirects)
        });

    if let Some(secs) = config.tcp_keepalive_secs {
        builder = builder.tcp_keepalive(Duration::from_secs(secs));
    }

    let pinned = config
        .tls
        .as_ref()
        .is_some_and(|t| !t.pinned_certificate.is_empty());

    if pinned {
        // When certificate pinning is enabled, the whole TLS stack must be
        // built with a custom verifier; reqwest does not allow swapping the
        // verifier on a partially configured builder.
        let tls_config = build_pinned_tls_config(sink_name, config).await?;
        builder = builder.use_preconfigured_tls(tls_config);
    } else if let Some(tls) = &config.tls {
        if !tls.ca_certificate.is_empty() {
            builder = crate::sink::add_root_certificates(
                builder,
                sink_name,
                &tls.ca_certificate,
            )
            .await?;
        }

        if !tls.client_certificate.is_empty() {
            let mut pem = read_tls_file(
                sink_name,
                "client_certificate",
                &tls.client_certificate,
            )
            .await?;
            let key =
                read_tls_file(sink_name, "client_key", &tls.client_key).await?;
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
            let password = load_required_secret(
                sink_name,
                &sink_proxy_password_env_var(sink_name),
                "proxy authentication",
            )?;
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

/// Headers managed by the HTTP sink itself, on top of the shared contract
/// list (`SINK_RESERVED_HEADERS` in `delivery.rs`): body encoding and auth
/// are set per request, so custom values for them are rejected too.
const HTTP_RESERVED_HEADERS: &[&str] =
    &["content-type", "content-encoding", "authorization"];

/// Whether `name` collides with a header reserved for internal sink use:
/// the shared contract headers plus the HTTP-specific ones above. Custom
/// values for these names are ignored because they would break the delivery
/// contract or create duplicate headers on the wire. Used for deliveries and
/// health checks alike: a GET has no body and no event context, so the same
/// contract applies. The comparison is case-insensitive.
fn is_reserved_header(name: &str) -> bool {
    is_sink_reserved_header(name)
        || HTTP_RESERVED_HEADERS
            .iter()
            .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// Whether the authentication configuration has all required OAuth2 fields
/// for the configured grant type. The config is assumed to have passed
/// `SinkAuthConfig::validate`, so only the active grant's pair is checked.
fn oauth2_credentials_ready(auth: &SinkAuthConfig) -> bool {
    use ave_common::sink::OAuth2GrantType;
    !auth.auth_url.is_empty()
        && match auth.grant_type {
            OAuth2GrantType::Password => !auth.username.is_empty(),
            OAuth2GrantType::ClientCredentials => !auth.client_id.is_empty(),
        }
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
    pub async fn new(
        sink_name: String,
        config: HttpSinkConfig,
        signer: Option<NodeSigner>,
    ) -> Result<Self, SinkError> {
        let client = build_http_client(&sink_name, &config).await?;

        let mut password = std::env::var(sink_password_env_var(&sink_name))
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
            if oauth2_credentials_ready(auth) {
                // If OAuth2 is configured, the password environment variable must exist.
                password = load_required_secret(
                    &sink_name,
                    &sink_password_env_var(&sink_name),
                    "OAuth2",
                )?;
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
        meta: Option<&DeliveryMeta>,
    ) -> Result<Option<crate::sink::delivery::SignatureHeaders>, SinkError>
    {
        let extra: &[(&str, &str)] =
            match self.config.compression.content_encoding() {
                Some(encoding) => &[("content-encoding", encoding)],
                None => &[],
            };
        sign_delivery(
            self.signer.as_ref(),
            payload,
            self.config.signature_version,
            extra,
            meta,
        )
        .await
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
        let signature_headers = self.sign_payload(&payload, meta).await?;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_sink_retry(sink_name);
                }
                // The server-provided Retry-After hint is honored when it
                // exceeds the computed backoff.
                let delay = crate::sink::retry_delay_ms(
                    self.config.retry_base_delay_ms,
                    self.config.retry_max_delay_ms,
                    attempt,
                    last_err.as_ref().and_then(retry_after_of),
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self
                .timed_send_once(url, &payload, &signature_headers, meta)
                .await
            {
                Ok(()) => {
                    return Ok(());
                }
                Err(e) if crate::sink::is_permanent_error(&e) => {
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

        Err(last_err.unwrap_or_else(crate::sink::max_retries_exceeded_error))
    }

    async fn timed_send_once(
        &self,
        url: &str,
        payload: &[u8],
        signature_headers: &Option<crate::sink::delivery::SignatureHeaders>,
        meta: Option<&DeliveryMeta>,
    ) -> Result<(), SinkError> {
        timed_sink_request(&self.sink_name, || {
            self.send_once(url, payload, signature_headers, meta)
        })
        .await
    }

    fn apply_custom_headers(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        for (name, value) in &self.config.headers {
            // Skip headers that the sink sets itself. reqwest appends values
            // when `.header()` is called repeatedly, so letting a custom value
            // through would produce duplicates and could cause the receiver to
            // see the wrong value (e.g. a custom "Content-Type" shadowing the
            // required "application/json").
            if is_reserved_header(name) {
                continue;
            }
            request = request.header(name, value);
        }
        request
    }

    fn apply_healthcheck_headers(
        &self,
        mut request: reqwest::RequestBuilder,
    ) -> reqwest::RequestBuilder {
        for (name, value) in &self.config.headers {
            // A GET health check has no body and no event context; do not let
            // custom headers pretend otherwise.
            if is_reserved_header(name) {
                continue;
            }
            request = request.header(name, value);
        }
        request
    }

    async fn send_once(
        &self,
        url: &str,
        payload: &[u8],
        signature_headers: &Option<crate::sink::delivery::SignatureHeaders>,
        meta: Option<&DeliveryMeta>,
    ) -> Result<(), SinkError> {
        let request_id = generate_request_id();
        let mut request = self.client.post(url).body(payload.to_vec());

        request = self.apply_custom_headers(request);

        // Internal headers are set after custom ones so they always take
        // precedence (e.g. a custom "Content-Type" cannot break the JSON
        // contract).
        request = request
            .header("Content-Type", "application/json")
            .header(REQUEST_ID_HEADER, &request_id);

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
                .header(IDEMPOTENCY_KEY_HEADER, meta.idempotency_key());
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
                message: format!("HTTP request failed ({}): {}", request_id, e),
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
                request_id = %request_id,
                "Sink delivery succeeded"
            );
            Ok(())
        } else {
            Err(map_error_response(
                response,
                &request_id,
                self.config.max_error_body_bytes,
                "HTTP",
            )
            .await)
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

        if oauth2_credentials_ready(auth) && !self.password.is_empty() {
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
            retry_after_ms: None,
        })
    }

    /// Prepare one batch group for delivery: rendered URL and encoded JSON
    /// array payload. Returns `None` for an empty group (groups are never
    /// empty by construction, but the caller continues instead of failing
    /// the whole batch).
    async fn prepare_group(
        &self,
        event_type: &str,
        group: &[IncomingSinkEvent],
    ) -> Result<Option<(String, Vec<u8>)>, SinkError> {
        let Some(first) = group.first() else {
            return Ok(None);
        };
        let schema_id = batch_group_schema_id(first);
        let url = self.url_template.render_url_encoded_with_event_type(
            first.subject_id(),
            &schema_id,
            event_type,
        );
        let payload = self.encode_body(group).await?;
        Ok(Some((url, payload)))
    }

    /// Serialize and, when configured, compress the delivery body.
    /// Signing happens on the encoded bytes (the exact wire payload).
    /// Compression runs in `spawn_blocking` because `GzEncoder` is CPU-bound
    /// and batches can be large.
    async fn encode_body<T: serde::Serialize + Sync + ?Sized>(
        &self,
        body: &T,
    ) -> Result<Vec<u8>, SinkError> {
        let raw = serialize_json_payload(body)?;

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
        let event_type = SinkTypes::from(data.as_ref());
        let url = self.url_template.render_url_encoded_with_event_type(
            &subject_id,
            &schema_id,
            event_type.as_str(),
        );
        let payload = self.encode_body(data.as_ref()).await?;
        let meta = DeliveryMeta::from_data(&data);

        self.send_with_retry(&url, payload, Some(&meta)).await
    }

    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError> {
        let url = self.url_template.render_url_encoded_with_event_type(
            &light.subject_id,
            &light.schema_id,
            light.event_type.as_str(),
        );
        let payload = self.encode_body(&light).await?;
        let meta = DeliveryMeta::from_light(&light);

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
            .unwrap_or_else(|| {
                self.url_template.render_url_encoded_with_event_type(
                    "-", "-", "-",
                )
            });

        let request_id = generate_request_id();
        let mut request = self.client.get(&url);
        request = self.apply_healthcheck_headers(request);
        request = request.header(REQUEST_ID_HEADER, &request_id);

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
                message: format!(
                    "Health check request failed ({}): {}",
                    request_id, e
                ),
                retryable: true,
                retry_after_ms: None,
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            // Unlike deliveries (whose retry loop invalidates and retries
            // once), a health check has no retry path: invalidate inline so
            // the next one re-authenticates.
            if status == 401 || status == 403 {
                self.invalidate_cached_token().await;
            }
            Err(map_error_response(
                response,
                &request_id,
                self.config.max_error_body_bytes,
                "Health check returned",
            )
            .await)
        }
    }

    /// Run a non-persistent end-to-end test of the sink. Performs a health
    /// check followed by a single POST of a test payload, using the same
    /// authentication, signature and compression paths as real deliveries. No
    /// cursor is advanced and nothing is persisted.
    async fn test(&self) -> Result<(), SinkError> {
        self.health_check().await?;

        let url = self
            .url_template
            .render_url_encoded_with_event_type("-", "-", "test");
        let payload = self.encode_body(&test_delivery_payload()).await?;
        let request_id = generate_request_id();

        let mut request = self.client.post(&url).body(payload.clone());
        request = self.apply_custom_headers(request);
        request = request
            .header("Content-Type", "application/json")
            .header(REQUEST_ID_HEADER, &request_id)
            .header(TEST_HEADER, "true");

        if let Some(headers) = self.sign_payload(&payload, None).await? {
            request = request
                .header(SIGNATURE_HEADER, &headers.signature)
                .header(SIGNATURE_TIMESTAMP_HEADER, &headers.timestamp)
                .header(SIGNATURE_PUBLIC_KEY_HEADER, &headers.public_key);
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
                message: format!(
                    "Sink test request failed ({}): {}",
                    request_id, e
                ),
                retryable: true,
                retry_after_ms: None,
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else {
            // No retry loop here (deliveries invalidate in their retry
            // loop): invalidate inline so the next test re-authenticates.
            if status == 401 || status == 403 {
                self.invalidate_cached_token().await;
            }
            Err(map_error_response(
                response,
                &request_id,
                self.config.max_error_body_bytes,
                "Sink test returned",
            )
            .await)
        }
    }

    /// Deliver a batch of events as JSON array payloads. When the URL
    /// template routes by event type (`{{event-type}}`), events are grouped
    /// by type (preserving the relative order inside each group) and one
    /// POST is sent per group, so every type lands in its own route;
    /// otherwise the whole batch is sent as a single JSON array. Per-event
    /// idempotency headers are not sent: every array element already carries
    /// `subject_id`, `sn` and the event type.
    async fn send_batch(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        for (event_type, group) in
            group_events_by_type(events, self.url_template.has_event_type())
        {
            let Some((url, payload)) =
                self.prepare_group(&event_type, &group).await?
            else {
                continue;
            };

            self.send_with_retry(&url, payload, None).await?;
        }

        Ok(())
    }

    /// Best-effort batch delivery: a single attempt per group, no retries
    /// and no auth refresh. Used during Pause/Stop teardown where blocking
    /// on retries would delay actor shutdown; the cursor guarantees
    /// re-delivery via catch-up.
    async fn send_batch_best_effort(
        &self,
        events: Vec<IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        for (event_type, group) in
            group_events_by_type(events, self.url_template.has_event_type())
        {
            let Some((url, payload)) =
                self.prepare_group(&event_type, &group).await?
            else {
                continue;
            };
            let signature_headers = self.sign_payload(&payload, None).await?;
            self.timed_send_once(&url, &payload, &signature_headers, None)
                .await?;
        }

        Ok(())
    }

    /// If the sink has OAuth2 auth config, obtain a token eagerly on startup.
    async fn warm_up(&self) -> Result<(), SinkError> {
        if let Some(ref auth) = self.config.auth
            && oauth2_credentials_ready(auth)
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

/// Map a non-success HTTP response to the shared error taxonomy: 401/403 →
/// `Auth`; 429 and 5xx → retryable `Delivery` honoring the `Retry-After`
/// hint; any other status → non-retryable `Delivery`. The body is truncated
/// to `max_error_body_bytes` and `label` prefixes the message (`"HTTP"` for
/// deliveries, `"Health check returned"`, ...). Single place so every call
/// site classifies statuses identically.
async fn map_error_response(
    response: reqwest::Response,
    request_id: &str,
    max_error_body_bytes: usize,
    label: &str,
) -> SinkError {
    let status = response.status();
    // Read the Retry-After hint before consuming the body.
    let retry_after_ms = if status == 429 || status.is_server_error() {
        crate::sink::parse_retry_after(response.headers())
    } else {
        None
    };
    let body =
        read_limited_body(response.bytes_stream(), max_error_body_bytes)
            .await;
    let message = format!("{label} {status} ({request_id}): {body}");
    if status == 401 || status == 403 {
        SinkError::Auth {
            message,
            retry_after_ms: None,
        }
    } else {
        SinkError::Delivery {
            message,
            retryable: status.is_server_error() || status == 429,
            retry_after_ms,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    use crate::sink::parse_retry_after;

    use super::*;
    use ave_common::sink::{HttpTlsConfig, SinkAuthConfig};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::sync::Mutex;

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

    #[tokio::test]
    async fn build_client_rejects_missing_ca_file() {
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            ca_certificate: "/nonexistent/ave-test-ca.pem".to_owned(),
            ..HttpTlsConfig::default()
        });
        let err = client_build_error(
            HttpTransport::new("unit-missing-ca".to_owned(), config, None)
                .await,
        );
        assert!(
            err.contains("cannot read TLS ca_certificate file"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn build_client_rejects_invalid_ca_pem() {
        let dir = tempfile::tempdir().unwrap();
        let ca_path = dir.path().join("ca.pem");
        std::fs::write(&ca_path, "not a pem").unwrap();
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..HttpTlsConfig::default()
        });
        let err = client_build_error(
            HttpTransport::new("unit-bad-ca".to_owned(), config, None).await,
        );
        assert!(
            err.contains("invalid CA certificate"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn build_client_accepts_valid_ca_pem() {
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
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn build_client_accepts_mtls_identity() {
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
            HttpTransport::new("unit-mtls".to_owned(), config, None)
                .await
                .is_ok()
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
            api_key: "config-key".to_owned(),
            ..SinkAuthConfig::default()
        });
        let transport =
            HttpTransport::new("unit-env-precedence".to_owned(), config, None)
                .await
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
            api_key: "config-key".to_owned(),
            ..SinkAuthConfig::default()
        });
        let transport =
            HttpTransport::new("unit-config-key".to_owned(), config, None)
                .await
                .unwrap();
        let header = transport.build_auth_header().await.unwrap();
        assert_eq!(header.as_deref(), Some("Api-Key config-key"));
    }

    #[tokio::test]
    async fn auth_without_any_credential_fails() {
        let mut config = base_config();
        config.auth = Some(SinkAuthConfig {
            ..SinkAuthConfig::default()
        });
        let err = client_build_error(
            HttpTransport::new("unit-missing-key".to_owned(), config, None)
                .await,
        );
        assert!(
            err.contains("AVE_SINK_APIKEY_UNIT_MISSING_KEY"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn signature_without_signer_fails() {
        let mut config = base_config();
        config.signature = true;
        let err = client_build_error(
            HttpTransport::new("unit-signer".to_owned(), config, None).await,
        );
        assert!(err.contains("no node signer"), "unexpected error: {}", err);
    }

    #[tokio::test]
    async fn proxy_without_password_env_fails() {
        let mut config = base_config();
        config.proxy = Some(ave_common::sink::HttpProxyConfig {
            url: "http://proxy.local:3128".to_owned(),
            username: "ave".to_owned(),
            no_proxy: vec![],
        });
        let err = client_build_error(
            HttpTransport::new("unit-proxy-nopass".to_owned(), config, None)
                .await,
        );
        assert!(
            err.contains("AVE_SINK_PROXY_PASSWORD_UNIT_PROXY_NOPASS"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn proxy_with_invalid_url_fails() {
        let mut config = base_config();
        config.proxy = Some(ave_common::sink::HttpProxyConfig {
            url: "not a url".to_owned(),
            username: String::new(),
            no_proxy: vec![],
        });
        let err = client_build_error(
            HttpTransport::new("unit-proxy-badurl".to_owned(), config, None)
                .await,
        );
        assert!(
            err.contains("invalid proxy URL"),
            "unexpected error: {}",
            err
        );
    }

    #[tokio::test]
    async fn proxy_with_password_env_builds() {
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
            HttpTransport::new("unit-proxy-ok".to_owned(), config, None).await;
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
                .await
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
            HttpTransport::new("unit-gzip".to_owned(), config, None)
                .await
                .unwrap();
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
            ..SinkAuthConfig::default()
        });

        let transport =
            HttpTransport::new("unit-refresh-expired".to_owned(), config, None)
                .await
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

    #[tokio::test]
    async fn build_auth_header_obtains_token_for_client_credentials() {
        let env_var = "AVE_SINK_PASSWORD_UNIT_CLIENT_CREDENTIALS";
        unsafe {
            std::env::set_var(env_var, "client-secret");
        }

        let auth_url = start_oauth2_server("cc-token").await;

        let mut config = base_config();
        config.auth = Some(SinkAuthConfig {
            auth_url,
            grant_type: ave_common::sink::OAuth2GrantType::ClientCredentials,
            client_id: "unit-client".to_owned(),
            ..SinkAuthConfig::default()
        });

        let transport = HttpTransport::new(
            "unit-client-credentials".to_owned(),
            config,
            None,
        )
        .await
        .expect("transport should build");

        let header = transport
            .build_auth_header()
            .await
            .expect("should build auth header")
            .expect("should return a header");

        assert_eq!(header, "Bearer cc-token");

        unsafe {
            std::env::remove_var(env_var);
        }
    }

    #[tokio::test]
    async fn custom_headers_are_applied_to_requests() {
        let mut config = base_config();
        config
            .headers
            .insert("X-Custom-Header".to_owned(), "custom-value".to_owned());
        let transport =
            HttpTransport::new("unit-custom-headers".to_owned(), config, None)
                .await
                .expect("transport should build");

        let request = transport
            .apply_custom_headers(
                transport.client.get("http://127.0.0.1/health"),
            )
            .build()
            .expect("request should build");

        assert_eq!(
            request
                .headers()
                .get("X-Custom-Header")
                .and_then(|v| v.to_str().ok()),
            Some("custom-value")
        );
    }

    #[test]
    fn reserved_headers_compose_contract_and_http_specific() {
        // Shared contract headers (from delivery.rs).
        for name in ["x-ave-sn", "X-Ave-Signature", "Idempotency-Key"] {
            assert!(is_reserved_header(name), "{name} must be reserved");
        }
        // HTTP-specific extras.
        for name in ["content-type", "Content-Encoding", "Authorization"] {
            assert!(is_reserved_header(name), "{name} must be reserved");
        }
        // Regular custom headers pass through.
        for name in ["x-custom-tenant", "x-ave", "traceparent"] {
            assert!(
                !is_reserved_header(name),
                "{name} must not be reserved"
            );
        }
    }

    /// Parse a raw HTTP request buffer into a map of lowercase header names to
    /// values. Only the headers are extracted; the body is ignored.
    fn parse_request_headers(
        buf: &[u8],
    ) -> std::collections::HashMap<String, String> {
        let mut map = std::collections::HashMap::new();
        let text = String::from_utf8_lossy(buf);
        for line in text.lines().skip(1) {
            if line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(": ") {
                map.insert(name.to_ascii_lowercase(), value.to_owned());
            }
        }
        map
    }

    /// Start a minimal HTTP server that records the headers of every request it
    /// receives and returns HTTP 200. Returns the base URL and a shared vector
    /// of captured header maps.
    async fn start_header_capture_server() -> (
        String,
        Arc<Mutex<Vec<std::collections::HashMap<String, String>>>>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");
        let captured = Arc::new(Mutex::new(Vec::new()));
        let captured_server = Arc::clone(&captured);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = stream.read(&mut tmp).await.unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                captured_server
                    .lock()
                    .await
                    .push(parse_request_headers(&buf));

                let response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        (format!("http://{}/events", addr), captured)
    }

    #[tokio::test]
    async fn health_check_sends_request_id_header() {
        let (url, captured) = start_header_capture_server().await;

        let mut config = base_config();
        config.url = url;
        let transport =
            HttpTransport::new("unit-request-id".to_owned(), config, None)
                .await
                .expect("transport should build");

        transport
            .health_check()
            .await
            .expect("health check should succeed");

        let headers = captured.lock().await;
        assert_eq!(headers.len(), 1);
        let request_id = headers[0]
            .get("x-ave-request-id")
            .expect("X-Ave-Request-Id header should be present");
        assert!(!request_id.is_empty(), "request id should not be empty");
    }

    #[tokio::test]
    async fn request_id_changes_between_attempts() {
        let (url, captured) = start_header_capture_server().await;

        let mut config = base_config();
        config.url = url;
        let transport = HttpTransport::new(
            "unit-request-id-unique".to_owned(),
            config,
            None,
        )
        .await
        .expect("transport should build");

        transport
            .health_check()
            .await
            .expect("first health check should succeed");
        transport
            .health_check()
            .await
            .expect("second health check should succeed");

        let headers = captured.lock().await;
        assert_eq!(headers.len(), 2);
        let first = headers[0].get("x-ave-request-id").unwrap();
        let second = headers[1].get("x-ave-request-id").unwrap();
        assert_ne!(
            first, second,
            "each delivery attempt must carry a unique request id"
        );
    }

    #[tokio::test]
    async fn health_check_omits_content_type_and_event_headers() {
        let (url, captured) = start_header_capture_server().await;

        let mut config = base_config();
        config.url = url;
        config
            .headers
            .insert("Content-Type".to_owned(), "text/plain".to_owned());
        config
            .headers
            .insert("Content-Encoding".to_owned(), "gzip".to_owned());
        config
            .headers
            .insert("X-Ave-Event-Type".to_owned(), "create".to_owned());
        config.headers.insert(
            "X-Custom-Health-Header".to_owned(),
            "custom-value".to_owned(),
        );

        let transport = HttpTransport::new(
            "unit-healthcheck-headers".to_owned(),
            config,
            None,
        )
        .await
        .expect("transport should build");

        transport
            .health_check()
            .await
            .expect("health check should succeed");

        let headers = &captured.lock().await[0];
        assert!(
            headers.get("content-type").is_none(),
            "GET health check must not send Content-Type"
        );
        assert!(
            headers.get("content-encoding").is_none(),
            "GET health check must not send Content-Encoding"
        );
        assert!(
            headers.get("x-ave-event-type").is_none(),
            "GET health check must not send event headers"
        );
        assert_eq!(
            headers.get("x-custom-health-header"),
            Some(&"custom-value".to_owned()),
            "non-body custom headers should still reach the health endpoint"
        );
    }

    #[tokio::test]
    async fn sink_test_sends_health_check_and_test_payload() {
        let (url, captured) = start_header_capture_server().await;

        let mut config = base_config();
        config.url = url;
        let transport =
            HttpTransport::new("unit-test-delivery".to_owned(), config, None)
                .await
                .expect("transport should build");

        transport.test().await.expect("sink test should succeed");

        let requests = captured.lock().await;
        assert_eq!(
            requests.len(),
            2,
            "sink test must perform a health check and a test POST"
        );

        // First request is the health check GET.
        assert!(
            requests[0].get("x-ave-test").is_none(),
            "health check should not carry X-Ave-Test"
        );

        // Second request is the test POST.
        assert_eq!(
            requests[1].get("x-ave-test"),
            Some(&"true".to_owned()),
            "test POST must carry X-Ave-Test: true"
        );
        assert_eq!(
            requests[1].get("content-type"),
            Some(&"application/json".to_owned()),
            "test POST must set Content-Type to application/json"
        );
    }

    /// Start a minimal HTTP server that returns a redirect on the first request
    /// and HTTP 200 on subsequent requests. Returns the base URL and an atomic
    /// request counter.
    async fn start_redirect_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");
        let count = Arc::new(AtomicUsize::new(0));
        let count_server = Arc::clone(&count);

        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    break;
                };
                let n = count_server.fetch_add(1, Ordering::SeqCst);
                let response = if n == 0 {
                    "HTTP/1.1 302 Found\r\nLocation: /ok\r\nContent-Length: 0\r\n\r\n"
                } else {
                    "HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"
                };
                // Drain enough of the request to avoid RST on some platforms.
                let mut tmp = [0u8; 1024];
                let _ = stream.read(&mut tmp).await;
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        (format!("http://{}/events", addr), count)
    }

    #[tokio::test]
    async fn max_redirects_zero_rejects_redirect() {
        let (url, count) = start_redirect_server().await;

        let mut config = base_config();
        config.url = url;
        config.max_redirects = 0;
        let transport = HttpTransport::new(
            "unit-redirect-disabled".to_owned(),
            config,
            None,
        )
        .await
        .expect("transport should build");

        let result = transport.health_check().await;
        assert!(
            result.is_err(),
            "health check should fail when redirects are disabled"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "only the initial request should have been sent"
        );
    }

    #[tokio::test]
    async fn max_redirects_one_follows_single_redirect() {
        let (url, count) = start_redirect_server().await;

        let mut config = base_config();
        config.url = url;
        config.max_redirects = 1;
        let transport =
            HttpTransport::new("unit-redirect-one".to_owned(), config, None)
                .await
                .expect("transport should build");

        transport
            .health_check()
            .await
            .expect("health check should follow the redirect and succeed");
        assert_eq!(
            count.load(Ordering::SeqCst),
            2,
            "initial request plus the followed redirect"
        );
    }

    /// Generate a self-signed test certificate and return its DER.
    fn test_cert_der(common_name: &str) -> CertificateDer<'static> {
        let cert =
            rcgen::generate_simple_self_signed(vec![common_name.to_owned()])
                .expect("test cert should generate");
        CertificateDer::from(cert.cert.der().to_vec())
    }

    #[derive(Debug)]
    struct NoopVerifier;

    impl ServerCertVerifier for NoopVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, RustlsError> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, RustlsError> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![]
        }
    }

    #[test]
    fn pinned_certificate_verifier_accepts_matching_cert() {
        let pinned = test_cert_der("sink.example.com");
        let verifier = PinnedCertificateVerifier {
            pinned: pinned.clone(),
            inner: Arc::new(NoopVerifier),
        };

        let result = verifier.verify_server_cert(
            &pinned,
            &[],
            &ServerName::try_from("sink.example.com").expect("server name"),
            &[],
            UnixTime::now(),
        );
        assert!(
            result.is_ok(),
            "matching pinned certificate must be accepted"
        );
    }

    #[test]
    fn pinned_certificate_verifier_rejects_different_cert() {
        let pinned = test_cert_der("sink.example.com");
        let other = test_cert_der("other.example.com");
        let verifier = PinnedCertificateVerifier {
            pinned,
            inner: Arc::new(NoopVerifier),
        };

        let result = verifier.verify_server_cert(
            &other,
            &[],
            &ServerName::try_from("other.example.com").expect("server name"),
            &[],
            UnixTime::now(),
        );
        assert!(result.is_err(), "different certificate must be rejected");
    }
}
