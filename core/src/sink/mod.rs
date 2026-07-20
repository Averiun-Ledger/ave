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
use ave_common::DataToSink;

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
        .json(
            &serde_json::json!({ "username": username, "password": password }),
        )
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
}
