//! HTTP delivery logic for a single external sink.

use std::sync::Arc;
use std::time::Duration;

use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};
use reqwest::Client;
use tokio::sync::RwLock;
use tracing::debug;

use crate::config::{SinkServer, TokenResponse};
use crate::sink::SinkError;
use ave_common::{DataToSink, LightEvent};

/// Compiled URL template that replaces `{{subject-id}}` and `{{schema-id}}`.
#[derive(Debug, Clone)]
pub struct CompiledUrlTemplate {
    template: String,
}

/// RFC 3986 path segment encode set: unreserved + sub-delimiters allowed,
/// everything else percent-encoded.
const PATH_SEGMENT_ENCODE_SET: &AsciiSet = &CONTROLS
    .add(b' ')
    .add(b'"')
    .add(b'#')
    .add(b'<')
    .add(b'>')
    .add(b'`')
    .add(b'?')
    .add(b'[')
    .add(b']')
    .add(b'{')
    .add(b'}')
    .add(b'/')
    .add(b'%');

impl CompiledUrlTemplate {
    pub fn new(template: &str) -> Self {
        Self {
            template: template.to_owned(),
        }
    }

    pub fn render(&self, subject_id: &str, schema_id: &str) -> String {
        let encoded_subject =
            utf8_percent_encode(subject_id, PATH_SEGMENT_ENCODE_SET);
        let encoded_schema =
            utf8_percent_encode(schema_id, PATH_SEGMENT_ENCODE_SET);
        self.template
            .replace("{{subject-id}}", &encoded_subject.to_string())
            .replace("{{schema-id}}", &encoded_schema.to_string())
    }
}

/// Build the environment variable name for a sink's password.
/// Format: `AVE_SINK_PASSWORD_{{SERVER_UPPER}}` where non-alphanumeric
/// chars are replaced by `_`.
pub fn sink_password_env_var(sink_name: &str) -> String {
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
    format!("AVE_SINK_PASSWORD_{}", normalized)
}

/// HTTP client wrapper for a single sink server.
#[derive(Debug)]
pub struct SinkHttpClient {
    client: Client,
    server: SinkServer,
    url_template: CompiledUrlTemplate,
    /// Password loaded from the environment variable `AVE_SINK_PASSWORD_{{SERVER}}`.
    password: String,
    pub cached_token: RwLock<Option<TokenResponse>>,
}

impl SinkHttpClient {
    pub fn new(server: SinkServer) -> Result<Self, SinkError> {
        let client = Client::builder()
            .timeout(Duration::from_millis(server.request_timeout_ms))
            .connect_timeout(Duration::from_millis(server.connect_timeout_ms))
            .build()
            .map_err(|e| SinkError::ClientBuild(e.to_string()))?;

        let password = std::env::var(sink_password_env_var(&server.server))
            .unwrap_or_default();

        // If OAuth2 is configured, the password environment variable must exist.
        if let Some(auth) = &server.auth
            && auth.api_key.is_empty()
            && !auth.auth_url.is_empty()
            && !auth.username.is_empty()
            && password.is_empty()
        {
            return Err(SinkError::Unauthorized);
        }

        Ok(Self {
            client,
            url_template: CompiledUrlTemplate::new(&server.url),
            password,
            cached_token: RwLock::new(None),
            server,
        })
    }

    /// Send a lightweight GET request to verify the sink is reachable.
    pub async fn health_check(&self) -> Result<(), SinkError> {
        // Use dedicated health-check URL if configured, otherwise render the
        // delivery URL with empty placeholders.
        // MIN-3: Use "-" as placeholder instead of "" to avoid "//" in rendered URL.
        let url = self
            .server
            .health_check_url
            .clone()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| self.url_template.render("-", "-"));

        let mut request = self.client.get(&url);

        // Add auth header if available
        if self.server.auth.is_some() {
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
            request.send().await.map_err(|e| SinkError::SendRequest {
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
            Err(SinkError::AuthExpired {
                status: status.as_u16(),
                message: format!("Health check returned {}: {}", status, body),
            })
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            Err(SinkError::HttpStatus {
                status: status.as_u16(),
                message: format!("Health check returned {}: {}", status, body),
                retryable: status.is_server_error() || status == 429,
            })
        }
    }

    pub async fn send_data_to_sink(
        &self,
        data: Arc<DataToSink>,
    ) -> Result<(), SinkError> {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let url = self.url_template.render(&subject_id, &schema_id);
        let payload = serde_json::to_vec(data.as_ref()).map_err(|e| {
            SinkError::SendRequest {
                message: format!("JSON serialization failed: {}", e),
                retryable: false,
            }
        })?;

        self.send_with_retry(&url, payload).await
    }

    pub async fn send_light_event(
        &self,
        light: LightEvent,
    ) -> Result<(), SinkError> {
        let url = self
            .url_template
            .render(&light.subject_id, &light.schema_id);
        let payload =
            serde_json::to_vec(&light).map_err(|e| SinkError::SendRequest {
                message: format!("JSON serialization failed: {}", e),
                retryable: false,
            })?;

        self.send_with_retry(&url, payload).await
    }

    pub async fn invalidate_cached_token(&self) {
        let mut guard = self.cached_token.write().await;
        *guard = None;
    }

    async fn send_with_retry(
        &self,
        url: &str,
        payload: Vec<u8>,
    ) -> Result<(), SinkError> {
        let mut last_err = None;

        for attempt in 0..=self.server.max_retries {
            if attempt > 0 {
                let base_delay =
                    self.server.retry_base_delay_ms * (1_u64 << (attempt - 1));
                let delay = crate::sink::add_jitter(base_delay);
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self.send_once(url, &payload).await {
                Ok(()) => {
                    return Ok(());
                }
                Err(e) if !e.is_transient() && !e.is_auth_recoverable() => {
                    // Permanent error: 422, bad config, etc. No retries.
                    return Err(e);
                }
                Err(e) if e.is_auth_recoverable() && attempt == 0 => {
                    // Auth error on first attempt: invalidate cache, refresh token, retry once immediately.
                    self.invalidate_cached_token().await;
                    if let Err(_refresh_err) = self.build_auth_header().await {
                        // Can't refresh auth; report the original auth error.
                        return Err(e);
                    }
                    // Retry once with fresh auth.
                    match self.send_once(url, &payload).await {
                        Ok(()) => {
                            return Ok(());
                        }
                        Err(e2) => {
                            return Err(e2);
                        }
                    }
                }
                Err(e) => {
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| SinkError::SendRequest {
            message: "Max retries exceeded".to_owned(),
            retryable: false,
        }))
    }

    async fn send_once(
        &self,
        url: &str,
        payload: &[u8],
    ) -> Result<(), SinkError> {
        let mut request = self
            .client
            .post(url)
            .header("Content-Type", "application/json")
            .body(payload.to_vec());

        if self.server.auth.is_some()
            && let Some(header) = self.build_auth_header().await?
        {
            request = request.header("Authorization", header);
        }

        let response =
            request.send().await.map_err(|e| SinkError::SendRequest {
                message: format!("HTTP request failed: {}", e),
                retryable: true,
            })?;

        let status = response.status();
        if status.is_success() {
            debug!(
                msg_type = "SinkSend",
                sink = %self.server.server,
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
            Err(SinkError::AuthExpired {
                status: status.as_u16(),
                message: format!("HTTP {}: {}", status, body),
            })
        } else {
            let body = response
                .text()
                .await
                .unwrap_or_else(|_| "<unreadable>".to_owned());
            Err(SinkError::HttpStatus {
                status: status.as_u16(),
                message: format!("HTTP {}: {}", status, body),
                retryable: status.is_server_error() || status == 429,
            })
        }
    }

    async fn build_auth_header(&self) -> Result<Option<String>, SinkError> {
        let auth = match &self.server.auth {
            Some(a) => a,
            None => return Ok(None),
        };

        if !auth.api_key.is_empty() {
            return Ok(Some(format!("Api-Key {}", auth.api_key)));
        }

        let margin = self.server.token_refresh_margin_secs;

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
                    let base_delay = self.server.retry_base_delay_ms
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
            return Err(last_token_err.unwrap_or(SinkError::Unauthorized));
        }

        Err(SinkError::Unauthorized)
    }
}
