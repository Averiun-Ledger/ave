//! Reliable sink managers and workers.

pub mod delivery;
pub mod error;
pub mod grpc;
pub mod http;
pub mod kafka;
pub mod manager;
pub mod registry;
pub mod subject_worker;
pub mod template;
pub mod transport;
pub mod worker;

pub use error::SinkError;
pub use manager::{
    SendResult, SinkManager, SinkManagerDetailedStatus, SinkManagerEvent,
    SinkManagerInitParams, SinkManagerMessage, SinkManagerResponse, SinkStatus,
};
pub use registry::{
    SinkRegistration, SinkRegistry, SinkRegistryEvent, SinkRegistryMessage,
    SinkRegistryResponse,
};
pub use subject_worker::{
    SinkSubjectWorker, SinkSubjectWorkerMessage, SinkSubjectWorkerResponse,
};
pub use transport::{NodeSigner, SinkTransport, build_transport};
pub use worker::{SinkWorker, SinkWorkerMessage, SinkWorkerResponse};

use std::time::Duration;

use crate::config::TokenResponse;
use ave_common::{
    DataToSink,
    sink::{OAuth2GrantType, SinkAuthConfig},
};

/// Parse the `Retry-After` header of a 429 / 5xx response. The value may be
/// a number of seconds or an HTTP-date; the result is milliseconds from now.
pub fn parse_retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
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

/// Add random symmetric jitter to a base delay value.
/// Returns a value between `base * 0.75` and `base * 1.25` (±25% jitter),
/// clamped to zero to avoid negative delays.
pub fn add_jitter(base: u64) -> u64 {
    let jitter = base.saturating_div(4);
    let sign = if fastrand::bool() { 1i128 } else { -1i128 };
    let delta = (jitter as i128).saturating_mul(sign);
    if delta < 0 {
        base.saturating_sub((-delta) as u64)
    } else {
        base.saturating_add(delta as u64)
    }
}

/// Delay before the next healthcheck attempt: the configured interval at
/// `idx` (clamped to the last entry so the backoff stops growing), or 60s
/// when the configured list is empty.
///
/// Single source for worker and manager healthcheck scheduling — keep the
/// fallback in sync here only.
pub fn healthcheck_delay_secs(intervals: &[u64], idx: usize) -> u64 {
    intervals
        .get(idx.min(intervals.len().saturating_sub(1)))
        .copied()
        .unwrap_or(60)
}

/// Compute the backoff delay for a delivery retry `attempt` (1-based: it is
/// only called after the first failure).
///
/// Saturates the exponent so a large `max_retries` cannot overflow the
/// shift, applies ±25% jitter, honors the optional server-provided
/// `retry_after_hint` when it exceeds the computed backoff and caps the
/// result at `max_ms`. Shared by every transport so the retry policy cannot
/// diverge.
pub fn retry_delay_ms(
    base_ms: u64,
    max_ms: u64,
    attempt: usize,
    retry_after_hint: Option<u64>,
) -> u64 {
    let exp = attempt.saturating_sub(1).min(63);
    let base_delay = base_ms.saturating_mul(1_u64 << exp);
    let mut delay = add_jitter(base_delay);
    if let Some(hint) = retry_after_hint {
        delay = delay.max(hint);
    }
    delay.min(max_ms)
}

/// Whether a delivery error is permanent and must not be retried.
pub const fn is_permanent_error(err: &SinkError) -> bool {
    matches!(
        err,
        SinkError::Delivery {
            retryable: false,
            ..
        } | SinkError::ClientBuild(_)
            | SinkError::Rejected { .. }
            | SinkError::Shutdown
    )
}

/// The terminal error returned when every retry attempt failed.
pub fn max_retries_exceeded_error() -> SinkError {
    SinkError::Delivery {
        message: "Max retries exceeded".to_owned(),
        retryable: false,
        retry_after_ms: None,
    }
}

/// Extract the server-provided retry hint carried by an error, if any.
/// Shared by every transport so the retry policy cannot diverge.
pub const fn retry_after_of(err: &SinkError) -> Option<u64> {
    match err {
        SinkError::Delivery { retry_after_ms, .. }
        | SinkError::Auth { retry_after_ms, .. } => *retry_after_ms,
        _ => None,
    }
}

/// What to do when the first delivery attempt fails with an auth error.
pub enum AuthRetryDecision {
    /// Retry once immediately: the credentials were refreshed.
    Retry,
    /// Abort with the original auth error: the credentials cannot be
    /// refreshed.
    Abort,
    /// Treat the auth error as transient: back off and keep retrying.
    Backoff,
}

/// Run a sink delivery with the shared retry policy.
///
/// Exponential backoff with jitter between attempts (honoring the
/// server-provided hint), permanent errors abort immediately, and a
/// first-attempt auth error is delegated to `on_auth_error` (credential
/// refresh plus a single immediate retry). Shared by every transport so
/// the retry policy cannot diverge.
pub async fn deliver_with_retries<A, AFut, R, RFut>(
    sink_name: &str,
    max_retries: usize,
    retry_base_delay_ms: u64,
    retry_max_delay_ms: u64,
    mut attempt: A,
    mut on_auth_error: R,
) -> Result<(), SinkError>
where
    A: FnMut() -> AFut,
    AFut: std::future::Future<Output = Result<(), SinkError>>,
    R: FnMut() -> RFut,
    RFut: std::future::Future<Output = AuthRetryDecision>,
{
    let mut last_err = None;
    for attempt_n in 0..=max_retries {
        if attempt_n > 0 {
            if let Some(metrics) = crate::metrics::try_core_metrics() {
                metrics.observe_sink_retry(sink_name);
            }
            let delay = retry_delay_ms(
                retry_base_delay_ms,
                retry_max_delay_ms,
                attempt_n,
                last_err.as_ref().and_then(retry_after_of),
            );
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match attempt().await {
            Ok(()) => return Ok(()),
            Err(e) if is_permanent_error(&e) => return Err(e),
            Err(e @ SinkError::Auth { .. }) if attempt_n == 0 => {
                match on_auth_error().await {
                    AuthRetryDecision::Retry => return attempt().await,
                    AuthRetryDecision::Abort => return Err(e),
                    AuthRetryDecision::Backoff => last_err = Some(e),
                }
            }
            Err(e) => last_err = Some(e),
        }
    }
    // Surface the last real error (the worker needs the original
    // Auth/Delivery kind to drive its state machine).
    Err(last_err.unwrap_or_else(max_retries_exceeded_error))
}

/// Extract the sequence number from a `DataToSink` event.
pub const fn extract_sn(data: &DataToSink) -> u64 {
    match &data.payload {
        ave_common::DataToSinkEvent::Create { sn, .. } => *sn,
        ave_common::DataToSinkEvent::FactFull { sn, .. } => *sn,
        ave_common::DataToSinkEvent::FactOpaque { sn, .. } => *sn,
        ave_common::DataToSinkEvent::Transfer { sn, .. } => *sn,
        ave_common::DataToSinkEvent::Confirm { sn, .. } => *sn,
        ave_common::DataToSinkEvent::Reject { sn, .. } => *sn,
        ave_common::DataToSinkEvent::Eol { sn, .. } => *sn,
    }
}

/// Maximum number of retries when obtaining an OAuth2 token.
const TOKEN_OBTAIN_MAX_RETRIES: u32 = 2;

/// Obtain an OAuth2 token from the authentication endpoint, reusing the
/// caller's `reqwest::Client` so the token request travels through the same
/// TLS, proxy and pool configuration as deliveries.
///
/// `password_or_secret` is the value read from the environment variable
/// `AVE_SINK_PASSWORD_{{SERVER}}`. For the `password` grant it is the user's
/// password; for `client_credentials` it is the client secret.
pub async fn obtain_token(
    client: &reqwest::Client,
    auth: &SinkAuthConfig,
    password_or_secret: &str,
) -> Result<TokenResponse, SinkError> {
    let mut body = match auth.grant_type {
        OAuth2GrantType::Password => serde_json::json!({
            "grant_type": auth.grant_type.as_str(),
            "username": auth.username,
            "password": password_or_secret,
        }),
        OAuth2GrantType::ClientCredentials => serde_json::json!({
            "grant_type": auth.grant_type.as_str(),
            "client_id": auth.client_id,
            "client_secret": password_or_secret,
        }),
    };
    if !auth.scope.is_empty() {
        body["scope"] = serde_json::Value::String(auth.scope.clone());
    }

    let res = client
        .post(&auth.auth_url)
        .json(&body)
        .send()
        .await
        .map_err(|e| SinkError::Auth {
            message: format!("failed to send auth request: {e}"),
            retry_after_ms: None,
        })?;

    let status = res.status();
    if status.is_client_error() || status.is_server_error() {
        let retry_after_ms = if status == 429 || status.is_server_error() {
            crate::sink::parse_retry_after(res.headers())
        } else {
            None
        };
        let body = res
            .text()
            .await
            .unwrap_or_else(|_| "could not read auth error body".to_owned());
        return Err(SinkError::Auth {
            message: format!("auth endpoint returned {}: {}", status, body),
            retry_after_ms,
        });
    }

    let mut token: TokenResponse =
        res.json::<TokenResponse>()
            .await
            .map_err(|e| SinkError::Auth {
                message: format!("failed to parse token response: {e}"),
                retry_after_ms: None,
            })?;

    token.obtained_at = Some(std::time::Instant::now());

    Ok(token)
}

/// Obtain an OAuth2 token with retry/backoff, running entirely outside any
/// cache lock so other deliveries are not blocked while the auth endpoint is
/// down.
pub async fn obtain_token_with_retry(
    client: &reqwest::Client,
    auth: &SinkAuthConfig,
    password_or_secret: &str,
    retry_base_delay_ms: u64,
) -> Result<TokenResponse, SinkError> {
    let mut last_err = None;
    for attempt in 0..=TOKEN_OBTAIN_MAX_RETRIES {
        if attempt > 0 {
            // Same saturation as the delivery backoff: avoid shift overflow
            // with a large configured base delay.
            let exp = (attempt - 1).min(63);
            let base_delay = retry_base_delay_ms.saturating_mul(1_u64 << exp);
            let mut delay = add_jitter(base_delay);
            // Honor a server-provided Retry-After hint when it exceeds the
            // computed backoff.
            if let Some(SinkError::Auth { retry_after_ms, .. }) = &last_err
                && let Some(hint) = retry_after_ms {
                    delay = delay.max(*hint);
                }
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match obtain_token(client, auth, password_or_secret).await {
            Ok(token) => return Ok(token),
            Err(e) if attempt < TOKEN_OBTAIN_MAX_RETRIES => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(last_err.unwrap_or_else(|| SinkError::Auth {
        message: "token refresh failed".to_owned(),
        retry_after_ms: None,
    }))
}

/// OAuth2 access-token cache shared by the sink transports (HTTP and gRPC).
///
/// `token()` returns the cached token while it is fresh (with the
/// configured refresh margin) and otherwise fetches a new one, running the
/// fetch outside any lock so concurrent deliveries are never blocked while
/// the auth endpoint is slow or down. `invalidate()` forces the next call
/// to re-authenticate (used after a 401 / UNAUTHENTICATED).
#[derive(Debug)]
pub struct OAuth2TokenCache {
    client: reqwest::Client,
    auth: SinkAuthConfig,
    secret: String,
    margin_secs: u64,
    retry_base_delay_ms: u64,
    /// `pub(crate)` so transport tests can seed an expired token.
    pub(crate) cached: tokio::sync::RwLock<Option<TokenResponse>>,
}

impl OAuth2TokenCache {
    pub fn new(
        client: reqwest::Client,
        auth: SinkAuthConfig,
        secret: String,
        margin_secs: u64,
        retry_base_delay_ms: u64,
    ) -> Self {
        Self {
            client,
            auth,
            secret,
            margin_secs,
            retry_base_delay_ms,
            cached: tokio::sync::RwLock::new(None),
        }
    }

    /// A valid access token: cached while fresh, otherwise freshly fetched.
    pub async fn token(&self) -> Result<String, SinkError> {
        {
            let guard = self.cached.read().await;
            if let Some(token) = guard.as_ref()
                && !token.is_expired_or_expiring_soon(self.margin_secs)
            {
                return Ok(token.access_token.clone());
            }
            // Missing, expired or expiring soon; fall through to fetch.
        }

        let token = obtain_token_with_retry(
            &self.client,
            &self.auth,
            &self.secret,
            self.retry_base_delay_ms,
        )
        .await?;
        let access_token = token.access_token.clone();
        *self.cached.write().await = Some(token);
        Ok(access_token)
    }

    /// Drop the cached token so the next `token()` re-authenticates.
    pub async fn invalidate(&self) {
        *self.cached.write().await = None;
    }
}

/// Read a PEM file referenced by the TLS configuration asynchronously.
/// TLS files can be large and live on network filesystems, so this avoids
/// blocking the async executor during client construction.
pub(crate) async fn read_tls_file(
    sink_name: &str,
    field: &str,
    path: &str,
) -> Result<Vec<u8>, SinkError> {
    tokio::fs::read(path).await.map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': cannot read TLS {} file '{}': {}",
            sink_name, field, path, e
        ))
    })
}

/// Add every PEM certificate in `path` as a root CA to the client builder.
/// Shared by the HTTP sink and the OIDC token client of the Kafka sink so
/// both honor the same custom-CA configuration.
pub(crate) async fn add_root_certificates(
    mut builder: reqwest::ClientBuilder,
    sink_name: &str,
    path: &str,
) -> Result<reqwest::ClientBuilder, SinkError> {
    let pem = read_tls_file(sink_name, "ca_certificate", path).await?;
    // With the rustls backend `Certificate::from_pem` defers parsing and
    // silently accepts a buffer without PEM sections, so parse the bundle
    // here and require at least one certificate.
    let certs = reqwest::Certificate::from_pem_bundle(&pem).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': invalid CA certificate '{}': {}",
            sink_name, path, e
        ))
    })?;
    if certs.is_empty() {
        return Err(SinkError::ClientBuild(format!(
            "sink '{}': invalid CA certificate '{}': no PEM certificates found",
            sink_name, path
        )));
    }
    for cert in certs {
        builder = builder.add_root_certificate(cert);
    }
    Ok(builder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn add_jitter_stays_within_symmetric_25_percent_range() {
        let base = 1_000_u64;
        for _ in 0..1_000 {
            let jittered = add_jitter(base);
            assert!(
                (750..=1_250).contains(&jittered),
                "jittered value {jittered} outside [750, 1250]"
            );
        }
    }

    #[test]
    fn retry_delay_ms_caps_at_max_and_honors_hint() {
        // Backoff grows with the attempt but never exceeds max_ms.
        for attempt in 1..10 {
            let delay = retry_delay_ms(500, 1_000, attempt, None);
            assert!(delay <= 1_000, "delay {delay} must be capped at max_ms");
        }
        // A hint above the backoff wins, but is still capped at max_ms.
        assert_eq!(retry_delay_ms(100, 30_000, 1, Some(5_000)), 5_000);
        assert_eq!(retry_delay_ms(100, 10_000, 1, Some(60_000)), 10_000);
    }

    #[test]
    fn retry_delay_ms_saturates_the_exponent() {
        // A huge attempt count must not overflow the shift nor panic; the
        // result is always capped at max_ms.
        let delay = retry_delay_ms(u64::MAX / 2, 30_000, usize::MAX, None);
        assert_eq!(delay, 30_000);
    }

    #[test]
    fn is_permanent_error_covers_the_taxonomy() {
        assert!(is_permanent_error(&SinkError::Delivery {
            message: String::new(),
            retryable: false,
            retry_after_ms: None,
        }));
        assert!(is_permanent_error(&SinkError::ClientBuild(String::new())));
        assert!(is_permanent_error(&SinkError::Rejected {
            message: String::new(),
        }));
        assert!(is_permanent_error(&SinkError::Shutdown));
        assert!(!is_permanent_error(&SinkError::Delivery {
            message: String::new(),
            retryable: true,
            retry_after_ms: None,
        }));
        assert!(!is_permanent_error(&SinkError::Auth {
            message: String::new(),
            retry_after_ms: None,
        }));
    }

    #[test]
    fn max_retries_exceeded_error_is_permanent() {
        assert!(is_permanent_error(&max_retries_exceeded_error()));
    }

    #[test]
    fn add_jitter_saturates_at_zero_and_does_not_panic() {
        assert_eq!(add_jitter(0), 0);
        // Extreme values must not panic and must stay within the contract.
        let max = add_jitter(u64::MAX);
        assert!(max >= u64::MAX - u64::MAX / 4);
    }

    #[tokio::test]
    async fn obtain_token_with_retry_retries_then_succeeds() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_server = Arc::clone(&request_count);

        tokio::spawn(async move {
            let ok_body = r#"{"access_token":"ok-token","token_type":"Bearer","expires_in":3600}"#;
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("test listener should accept");
                let count = request_count_server.fetch_add(1, Ordering::SeqCst);
                let response = if count < 2 {
                    "HTTP/1.1 500 Internal Server Error\r\nContent-Length: 0\r\n\r\n".to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        ok_body.len(),
                        ok_body
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let auth = SinkAuthConfig {
            auth_url: format!("http://{}/token", addr),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        };

        let token = obtain_token_with_retry(&client, &auth, "test-secret", 10)
            .await
            .expect("token should be obtained after retries");

        assert_eq!(token.access_token, "ok-token");
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            3,
            "should retry twice before succeeding on the third attempt"
        );
    }

    #[tokio::test]
    async fn obtain_token_with_retry_honors_retry_after_hint() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::time::Instant;
        use tokio::io::AsyncWriteExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");

        let request_count = Arc::new(AtomicUsize::new(0));
        let request_count_server = Arc::clone(&request_count);

        tokio::spawn(async move {
            let ok_body = r#"{"access_token":"ok-token","token_type":"Bearer","expires_in":3600}"#;
            loop {
                let (mut stream, _) = listener
                    .accept()
                    .await
                    .expect("test listener should accept");
                let count = request_count_server.fetch_add(1, Ordering::SeqCst);
                let response = if count == 0 {
                    "HTTP/1.1 429 Too Many Requests\r\nRetry-After: 1\r\nContent-Length: 0\r\n\r\n".to_owned()
                } else {
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        ok_body.len(),
                        ok_body
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            }
        });

        let client = reqwest::Client::new();
        let auth = SinkAuthConfig {
            auth_url: format!("http://{}/token", addr),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        };

        let start = Instant::now();
        let token = obtain_token_with_retry(&client, &auth, "test-secret", 10)
            .await
            .expect("token should be obtained after retry");
        let elapsed = start.elapsed();

        assert_eq!(token.access_token, "ok-token");
        assert!(
            elapsed >= std::time::Duration::from_millis(900),
            "Retry-After hint of 1s must be honored; elapsed: {:?}",
            elapsed
        );
        assert_eq!(
            request_count.load(Ordering::SeqCst),
            2,
            "should retry once before succeeding"
        );
    }

    /// Starts a minimal HTTP OAuth2 token endpoint that captures the JSON body
    /// of the token request and returns it through the oneshot sender.
    async fn start_oauth2_server_that_captures_body(
        access_token: &str,
    ) -> (String, tokio::sync::oneshot::Receiver<serde_json::Value>) {
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener should bind");
        let addr = listener.local_addr().expect("listener has local address");

        let ok_body = serde_json::json!({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
        })
        .to_string();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            ok_body.len(),
            ok_body
        );

        let (tx, rx) = tokio::sync::oneshot::channel();

        tokio::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .expect("test listener should accept");

            let body = {
                let mut reader = tokio::io::BufReader::new(&mut stream);
                let mut headers = String::new();
                loop {
                    let mut line = String::new();
                    reader
                        .read_line(&mut line)
                        .await
                        .expect("should read request line");
                    if line == "\r\n" || line.is_empty() {
                        break;
                    }
                    headers.push_str(&line);
                }

                let content_length = headers
                    .lines()
                    .find_map(|l| {
                        let mut parts = l.splitn(2, ':');
                        let name = parts.next()?;
                        let value = parts.next()?.trim();
                        if name.eq_ignore_ascii_case("Content-Length") {
                            value.parse::<usize>().ok()
                        } else {
                            None
                        }
                    })
                    .unwrap_or(0);

                let mut body_bytes = vec![0u8; content_length];
                if content_length > 0 {
                    reader
                        .read_exact(&mut body_bytes)
                        .await
                        .expect("should read request body");
                }

                serde_json::from_slice(&body_bytes)
                    .expect("request body should be valid JSON")
            };
            let _ = tx.send(body);

            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });

        (format!("http://{}/token", addr), rx)
    }

    #[tokio::test]
    async fn obtain_token_uses_client_credentials_body() {
        let (auth_url, body_rx) =
            start_oauth2_server_that_captures_body("cc-token").await;

        let client = reqwest::Client::new();
        let auth = SinkAuthConfig {
            auth_url,
            grant_type: OAuth2GrantType::ClientCredentials,
            client_id: "test-client".to_owned(),
            scope: "read write".to_owned(),
            ..SinkAuthConfig::default()
        };

        let token = obtain_token(&client, &auth, "test-secret")
            .await
            .expect("token should be obtained");

        assert_eq!(token.access_token, "cc-token");

        let body = body_rx.await.expect("server should send captured body");
        assert_eq!(body["grant_type"], "client_credentials");
        assert_eq!(body["client_id"], "test-client");
        assert_eq!(body["client_secret"], "test-secret");
        assert_eq!(body["scope"], "read write");
    }

    #[tokio::test]
    async fn obtain_token_uses_password_body_with_scope() {
        let (auth_url, body_rx) =
            start_oauth2_server_that_captures_body("pwd-token").await;

        let client = reqwest::Client::new();
        let auth = SinkAuthConfig {
            auth_url,
            username: "test-user".to_owned(),
            scope: "admin".to_owned(),
            ..SinkAuthConfig::default()
        };

        let token = obtain_token(&client, &auth, "test-password")
            .await
            .expect("token should be obtained");

        assert_eq!(token.access_token, "pwd-token");

        let body = body_rx.await.expect("server should send captured body");
        assert_eq!(body["grant_type"], "password");
        assert_eq!(body["username"], "test-user");
        assert_eq!(body["password"], "test-password");
        assert_eq!(body["scope"], "admin");
    }

    #[tokio::test]
    async fn obtain_token_omits_scope_when_empty() {
        let (auth_url, body_rx) =
            start_oauth2_server_that_captures_body("no-scope-token").await;

        let client = reqwest::Client::new();
        let auth = SinkAuthConfig {
            auth_url,
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        };

        let token = obtain_token(&client, &auth, "test-password")
            .await
            .expect("token should be obtained");

        assert_eq!(token.access_token, "no-scope-token");

        let body = body_rx.await.expect("server should send captured body");
        assert_eq!(body["grant_type"], "password");
        assert!(
            !body
                .as_object()
                .expect("body is object")
                .contains_key("scope")
        );
    }
}
