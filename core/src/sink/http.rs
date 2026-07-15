//! HTTP delivery logic for a single external sink.

use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use reqwest::{Certificate, Client, Identity, tls::Version};
use tokio::sync::RwLock;
use tracing::debug;

use crate::config::{HttpSinkConfig, TokenResponse};
use crate::metrics::try_core_metrics;
use crate::sink::SinkError;
use crate::sink::template::CompiledTemplate;
use crate::sink::transport::{NodeSigner, SinkTransport};
use ave_common::{DataToSink, LightEvent};

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
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms));

    if let Some(tls) = &config.tls {
        if !tls.ca_certificate.is_empty() {
            let pem = read_tls_file(
                sink_name,
                "ca_certificate",
                &tls.ca_certificate,
            )?;
            let cert = Certificate::from_pem(&pem).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': invalid CA certificate '{}': {}",
                    sink_name, tls.ca_certificate, e
                ))
            })?;
            builder = builder.add_root_certificate(cert);
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

        match tls.min_tls_version.as_str() {
            "" => {}
            "1.2" => builder = builder.tls_version_min(Version::TLS_1_2),
            "1.3" => builder = builder.tls_version_min(Version::TLS_1_3),
            other => {
                return Err(SinkError::ClientBuild(format!(
                    "sink '{}': min_tls_version must be \"1.2\" or \"1.3\", got {}",
                    sink_name, other
                )));
            }
        }
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

/// Signature headers for one delivery, computed once per logical event and
/// reused across retries of the same body.
struct SignatureHeaders {
    signature: String,
    timestamp: String,
    public_key: String,
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

        let password =
            std::env::var(sink_password_env_var(&sink_name)).unwrap_or_default();
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
    ) -> Result<(), SinkError> {
        let mut last_err = None;
        let sink_name = &self.sink_name;
        let signature_headers = self.sign_payload(&payload).await?;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_sink_retry(sink_name);
                }
                let base_delay =
                    self.config.retry_base_delay_ms * (1_u64 << (attempt - 1));
                let delay = crate::sink::add_jitter(base_delay);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self
                .timed_send_once(url, &payload, &signature_headers)
                .await
            {
                Ok(()) => {
                    return Ok(());
                }
                Err(
                    e @ (SinkError::Delivery { retryable: false, .. }
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
                        .timed_send_once(url, &payload, &signature_headers)
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
        }))
    }

    async fn timed_send_once(
        &self,
        url: &str,
        payload: &[u8],
        signature_headers: &Option<SignatureHeaders>,
    ) -> Result<(), SinkError> {
        let start = Instant::now();
        let result = self.send_once(url, payload, signature_headers).await;
        let duration = start.elapsed();

        if let Some(metrics) = try_core_metrics() {
            let result_label = match &result {
                Ok(()) => "success",
                Err(SinkError::Auth { .. }) => "auth",
                Err(SinkError::Delivery { retryable: true, .. }) => "transient",
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

        if self.config.auth.is_some()
            && let Some(header) = self.build_auth_header().await?
        {
            request = request.header("Authorization", header);
        }

        let response =
            request.send().await.map_err(|e| SinkError::Delivery {
                message: format!("HTTP request failed: {}", e),
                retryable: true,
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
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            Err(SinkError::Auth {
                message: format!("HTTP {}: {}", status, body),
            })
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            Err(SinkError::Delivery {
                message: format!("HTTP {}: {}", status, body),
                retryable: status.is_server_error() || status == 429,
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
            // Double-check inside write lock to prevent parallel token refresh.
            let mut guard = self.cached_token.write().await;
            if let Some(token) = guard.as_ref()
                && !token.is_expired_or_expiring_soon(margin)
            {
                return Ok(Some(format!("Bearer {}", token.access_token)));
            }
            // Retry obtain_token with backoff to survive transient auth endpoint failures.
            let mut last_token_err = None;
            for attempt in 0..=2 {
                if attempt > 0 {
                    let base_delay = self.config.retry_base_delay_ms
                        * (1_u64 << (attempt - 1));
                    let delay = crate::sink::add_jitter(base_delay);
                    tokio::time::sleep(std::time::Duration::from_millis(delay))
                        .await;
                }
                match crate::sink::obtain_token(
                    &auth.auth_url,
                    &auth.username,
                    &self.password,
                )
                .await
                {
                    Ok(token) => {
                        let header = format!("Bearer {}", token.access_token);
                        *guard = Some(token);
                        return Ok(Some(header));
                    }
                    Err(e) if attempt < 2 => {
                        last_token_err = Some(e);
                    }
                    Err(e) => {
                        return Err(e);
                    }
                }
            }
            return Err(last_token_err.unwrap_or_else(|| SinkError::Auth {
                message: "token refresh failed".to_owned(),
            }));
        }

        Err(SinkError::Auth {
            message: "auth configured but no API key and incomplete OAuth2 credentials"
                .to_owned(),
        })
    }
}

#[async_trait]
impl SinkTransport for HttpTransport {
    async fn send(&self, data: Arc<DataToSink>) -> Result<(), SinkError> {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let url = self
            .url_template
            .render_url_encoded(&subject_id, &schema_id);
        let payload = serde_json::to_vec(data.as_ref()).map_err(|e| {
            SinkError::Delivery {
                message: format!("JSON serialization failed: {}", e),
                retryable: false,
            }
        })?;

        self.send_with_retry(&url, payload).await
    }

    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError> {
        let url = self
            .url_template
            .render_url_encoded(&light.subject_id, &light.schema_id);
        let payload =
            serde_json::to_vec(&light).map_err(|e| SinkError::Delivery {
                message: format!("JSON serialization failed: {}", e),
                retryable: false,
            })?;

        self.send_with_retry(&url, payload).await
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
            })?;

        let status = response.status();
        if status.is_success() {
            Ok(())
        } else if status == 401 || status == 403 {
            self.invalidate_cached_token().await;
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            Err(SinkError::Auth {
                message: format!("Health check returned {}: {}", status, body),
            })
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            Err(SinkError::Delivery {
                message: format!("Health check returned {}: {}", status, body),
                retryable: status.is_server_error() || status == 429,
            })
        }
    }

    /// If the sink has OAuth2 auth config, obtain a token eagerly on startup.
    async fn warm_up(&self) -> Result<(), SinkError> {
        if let Some(ref auth) = self.config.auth
            && !auth.auth_url.is_empty()
            && !auth.username.is_empty()
            && !self.password.is_empty()
        {
            let token = crate::sink::obtain_token(
                &auth.auth_url,
                &auth.username,
                &self.password,
            )
            .await?;
            let mut guard = self.cached_token.write().await;
            *guard = Some(token);
        }
        Ok(())
    }
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
            min_tls_version: "1.2".to_owned(),
            ..HttpTlsConfig::default()
        });
        assert!(
            HttpTransport::new("unit-mtls".to_owned(), config, None).is_ok()
        );
    }

    #[test]
    fn build_client_rejects_invalid_min_tls_version() {
        let mut config = base_config();
        config.tls = Some(HttpTlsConfig {
            min_tls_version: "1.1".to_owned(),
            ..HttpTlsConfig::default()
        });
        let err = client_build_error(HttpTransport::new(
            "unit-tls-version".to_owned(),
            config,
            None,
        ));
        assert!(err.contains("min_tls_version"), "unexpected error: {}", err);
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
}
