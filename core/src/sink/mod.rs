//! Reliable sink managers and workers.

pub mod error;
pub mod http;
pub mod manager;
pub mod subject_worker;
pub mod worker;

pub use error::SinkError;
pub use manager::{SinkManager, SinkManagerInitParams, SinkManagerMessage, SinkManagerResponse, SinkManagerEvent, SendResult};
pub use subject_worker::{SinkSubjectWorker, SinkSubjectWorkerMessage, SinkSubjectWorkerResponse};
pub use worker::{SinkWorker, SinkWorkerMessage, SinkWorkerResponse};

use std::time::Duration;

use crate::config::TokenResponse;
use ave_common::DataToSink;

/// Add random jitter to a base delay value.
/// Returns a value between `base` and `base * 1.25` (25% jitter).
pub fn add_jitter(base: u64) -> u64 {
    const JITTER_PCT: f64 = 0.25;
    let jitter = (base as f64 * JITTER_PCT * fastrand::f64()) as u64;
    base + jitter
}

/// Extract the sequence number from a `DataToSink` event.
pub fn extract_sn(data: &DataToSink) -> u64 {
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

/// Obtain an OAuth2 token from the authentication endpoint.
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
        .json(&serde_json::json!({ "username": username, "password": password }))
        .send()
        .await
        .map_err(|e| SinkError::AuthRequest(e.to_string()))?;

    let res = res
        .error_for_status()
        .map_err(|e| SinkError::AuthEndpoint(e.to_string()))?;

    let mut token: TokenResponse = res
        .json::<TokenResponse>()
        .await
        .map_err(|e| SinkError::TokenParse(e.to_string()))?;

    token.obtained_at = Some(std::time::Instant::now());

    Ok(token)
}
