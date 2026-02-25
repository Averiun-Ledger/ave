mod error;

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use ave_actors::Subscriber;
use ave_common::DataToSink;
use reqwest::Client;
use serde::Deserialize;
use tokio::sync::RwLock;
use tracing::{debug, error, warn};

const TARGET: &str = "ave::core::sink";

pub use error::SinkError;

use crate::{
    config::SinkServer,
    subject::sinkdata::{SinkDataEvent, SinkTypes},
};

#[derive(Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

pub async fn obtain_token(
    auth: &str,
    username: &str,
    password: &str,
) -> Result<TokenResponse, SinkError> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .map_err(|e| SinkError::ClientBuild(e.to_string()))?;

    let res = client
        .post(auth)
        .json(
            &serde_json::json!({ "username": username, "password": password }),
        )
        .send()
        .await
        .map_err(|e| SinkError::AuthRequest(e.to_string()))?;

    let res = res
        .error_for_status()
        .map_err(|e| SinkError::AuthEndpoint(e.to_string()))?;

    res.json::<TokenResponse>()
        .await
        .map_err(|e| SinkError::TokenParse(e.to_string()))
}

// All fields behind a single Arc so that AveSink::clone is a cheap atomic
// increment instead of deep-cloning the sinks map and all strings.
struct AveSinkInner {
    sinks: BTreeMap<String, Vec<SinkServer>>,
    // Arc removed: the outer Arc<AveSinkInner> already provides shared ownership.
    token: Option<RwLock<TokenResponse>>,
    auth: String,
    username: String,
    password: String,
    api_key: Option<String>,
    // Reused across every notify() call; reqwest::Client is a connection pool.
    client: Client,
}

#[derive(Clone)]
pub struct AveSink(Arc<AveSinkInner>);

impl AveSink {
    pub fn new(
        sinks: BTreeMap<String, Vec<SinkServer>>,
        token: Option<TokenResponse>,
        auth: &str,
        username: &str,
        password: &str,
        api_key: Option<String>,
    ) -> Self {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self(Arc::new(AveSinkInner {
            sinks,
            token: token.map(RwLock::new),
            auth: auth.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            api_key,
            client,
        }))
    }

    fn server_wants_event(server: &SinkServer, data: &DataToSink) -> bool {
        server.events.contains(&SinkTypes::All)
            || server.events.contains(&SinkTypes::from(data))
    }

    fn build_url(template: &str, subject_id: &str, schema_id: &str) -> String {
        template
            .replace("{{subject-id}}", subject_id)
            .replace("{{schema-id}}", schema_id)
    }

    async fn current_auth_header(&self) -> Option<String> {
        let lock = self.0.token.as_ref()?;
        let token = lock.read().await;
        Some(format!("{} {}", token.token_type, token.access_token))
    }

    async fn refresh_token(&self) -> Option<TokenResponse> {
        match obtain_token(&self.0.auth, &self.0.username, &self.0.password)
            .await
        {
            Ok(t) => Some(t),
            Err(e) => {
                error!(
                    target: TARGET,
                    error = %e,
                    "Failed to obtain new auth token"
                );
                None
            }
        }
    }

    async fn send_once(
        client: &Client,
        url: &str,
        data: &DataToSink,
        auth_header: Option<(&str, &str)>,
    ) -> Result<(), SinkError> {
        let req = if let Some((header_name, header_value)) = auth_header {
            client
                .post(url)
                .header(header_name, header_value)
                .json(data)
        } else {
            client.post(url).json(data)
        };

        let res = req
            .send()
            .await
            .map_err(|e| SinkError::SendRequest(e.to_string()))?;

        if let Err(e) = res.error_for_status_ref() {
            if let Some(status) = e.status() {
                return Err(match status.as_u16() {
                    401 => SinkError::Unauthorized,
                    422 => SinkError::UnprocessableEntity,
                    code => SinkError::HttpStatus {
                        status: code,
                        message: e.to_string(),
                    },
                });
            }
            return Err(SinkError::SendRequest(e.to_string()));
        }

        Ok(())
    }

    async fn send_with_retry_on_401(
        &self,
        client: &Client,
        url: &str,
        event: &DataToSink,
        server_requires_auth: bool,
    ) {
        // Build the auth header: either X-API-Key or Authorization (bearer token)
        let header: Option<(String, String)> = if server_requires_auth {
            if let Some(ref key) = self.0.api_key {
                Some(("X-API-Key".to_owned(), key.clone()))
            } else {
                self.current_auth_header()
                    .await
                    .map(|bearer| ("Authorization".to_owned(), bearer))
            }
        } else {
            None
        };

        let header_ref = header.as_ref().map(|(n, v)| (n.as_str(), v.as_str()));

        match Self::send_once(client, url, event, header_ref).await {
            Ok(_) => {
                debug!(
                    target: TARGET,
                    url = %url,
                    "Data sent to sink successfully"
                );
            }
            Err(SinkError::UnprocessableEntity) => {
                warn!(
                    target: TARGET,
                    url = %url,
                    "Sink rejected data format (422)"
                );
            }
            // Token refresh only applies to bearer token mode, not api_key
            Err(SinkError::Unauthorized)
                if server_requires_auth
                    && self.0.api_key.is_none()
                    && self.0.token.is_some() =>
            {
                warn!(
                    target: TARGET,
                    url = %url,
                    "Authentication failed, refreshing token"
                );

                if let Some(new_token) = self.refresh_token().await {
                    if let Some(lock) = &self.0.token {
                        *lock.write().await = new_token.clone();
                    }
                    debug!(target: TARGET, "Token refreshed, retrying request");
                    let new_header = format!(
                        "{} {}",
                        new_token.token_type, new_token.access_token
                    );

                    match Self::send_once(
                        client,
                        url,
                        event,
                        Some(("Authorization", &new_header)),
                    )
                    .await
                    {
                        Ok(_) => {
                            debug!(
                                target: TARGET,
                                url = %url,
                                "Data sent to sink successfully after token refresh"
                            );
                        }
                        Err(SinkError::UnprocessableEntity) => {
                            warn!(
                                target: TARGET,
                                url = %url,
                                "Sink rejected data format (422)"
                            );
                        }
                        Err(e) => {
                            error!(
                                target: TARGET,
                                url = %url,
                                error = %e,
                                "Failed to send data to sink after token refresh"
                            );
                        }
                    }
                }
            }
            Err(e) => {
                error!(
                    target: TARGET,
                    url = %url,
                    error = %e,
                    "Failed to send data to sink"
                );
            }
        }
    }
}

#[async_trait]
impl Subscriber<SinkDataEvent> for AveSink {
    async fn notify(&self, event: SinkDataEvent) {
        let data = match event {
            SinkDataEvent::Event(data_to_sink) => data_to_sink,
            SinkDataEvent::State(..) => return,
        };

        let (subject_id, schema_id) = data.event.get_subject_schema();
        let Some(servers) = self.0.sinks.get(&schema_id) else {
            debug!(
                target: TARGET,
                schema_id = %schema_id,
                "No sink servers configured for schema"
            );
            return;
        };
        if servers.is_empty() {
            return;
        }

        debug!(
            target: TARGET,
            subject_id = %subject_id,
            schema_id = %schema_id,
            servers_count = servers.len(),
            "Processing sink event"
        );

        let client = &self.0.client;

        for server in servers {
            if !Self::server_wants_event(server, &data) {
                continue;
            }

            let url = Self::build_url(&server.url, &subject_id, &schema_id);
            let requires_auth = server.auth;

            self.send_with_retry_on_401(client, &url, &data, requires_auth)
                .await;
        }
    }
}
