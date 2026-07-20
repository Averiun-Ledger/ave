//! Reliable sink managers and workers.

pub mod error;
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
use ave_common::{DataToSink, sink::{OAuth2GrantType, SinkAuthConfig}};

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
        })?;

    let res = res.error_for_status().map_err(|e| SinkError::Auth {
        message: format!("auth endpoint error: {e}"),
    })?;

    let mut token: TokenResponse =
        res.json::<TokenResponse>()
            .await
            .map_err(|e| SinkError::Auth {
                message: format!("failed to parse token response: {e}"),
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
            let delay = add_jitter(base_delay);
            tokio::time::sleep(Duration::from_millis(delay)).await;
        }
        match obtain_token(client, auth, password_or_secret).await {
            Ok(token) => return Ok(token),
            Err(e) if attempt < TOKEN_OBTAIN_MAX_RETRIES => last_err = Some(e),
            Err(e) => return Err(e),
        }
    }
    Err(match last_err {
        Some(e) => e,
        None => SinkError::Auth {
            message: "token refresh failed".to_owned(),
        },
    })
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
                jittered >= 750 && jittered <= 1_250,
                "jittered value {jittered} outside [750, 1250]"
            );
        }
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
        use tokio::io::AsyncWriteExt;
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

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
                let count =
                    request_count_server.fetch_add(1, Ordering::SeqCst);
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
        assert!(!body.as_object().expect("body is object").contains_key("scope"));
    }
}
