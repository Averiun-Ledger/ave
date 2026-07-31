//! gRPC transport for sink delivery (tonic, protobuf over HTTP/2).

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use ave_common::sink::pb;
use ave_common::sink::{
    GrpcAuthConfig, GrpcSinkConfig, GrpcTlsConfig, HttpCompression,
};
use ave_common::{DataToSink, LightEvent};
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Status};

use crate::metrics::try_core_metrics;
use crate::sink::delivery::{
    DeliveryMeta, SignatureHeaders, generate_request_id, is_sink_reserved_header,
    serialize_json_payload, sign_delivery, sink_apikey_env_var,
    sink_token_env_var, test_delivery_payload, timed_sink_request,
};
use crate::sink::error::SinkError;
use crate::sink::transport::{NodeSigner, SinkTransport};
use crate::sink::{read_tls_file, retry_delay_ms};

use pb::event_sink_client::EventSinkClient;

/// Service name reported to `grpc.health.v1` health checks.
const HEALTH_SERVICE_NAME: &str = "ave.sink.v1.EventSink";

/// gRPC delivery transport: protobuf over a single multiplexed HTTP/2
/// channel per sink.
///
/// Deliveries are unary `Deliver` RPCs (see
/// `temporal/plan-sink-grpc-mvp.md`); payloads are the same canonical JSON
/// documents as the HTTP sink, so receivers share parser and signature
/// verification across transports.
pub struct GrpcTransport {
    sink_name: String,
    config: GrpcSinkConfig,
    signer: Option<NodeSigner>,
    channel: Channel,
    client: EventSinkClient<Channel>,
    /// Per-RPC authentication metadata (secret loaded from the environment).
    auth: Option<(MetadataKey<Ascii>, MetadataValue<Ascii>)>,
    /// User-provided static metadata (reserved keys already filtered out).
    custom_metadata: Vec<(MetadataKey<Ascii>, MetadataValue<Ascii>)>,
}

impl std::fmt::Debug for GrpcTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GrpcTransport")
            .field("sink_name", &self.sink_name)
            .field("config", &self.config)
            .field("has_signer", &self.signer.is_some())
            .field("has_auth", &self.auth.is_some())
            .finish_non_exhaustive()
    }
}

impl GrpcTransport {
    pub async fn new(
        sink_name: String,
        config: GrpcSinkConfig,
        signer: Option<NodeSigner>,
    ) -> Result<Self, SinkError> {
        let mut endpoint =
            Endpoint::from_shared(config.endpoint.clone()).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': invalid endpoint '{}': {}",
                    sink_name, config.endpoint, e
                ))
            })?;
        endpoint = endpoint
            .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
            .timeout(Duration::from_millis(config.request_timeout_ms));

        if config.tls.is_some() || config.endpoint.starts_with("https://") {
            let tls_config =
                build_tls_config(&sink_name, config.tls.as_ref()).await?;
            endpoint = endpoint.tls_config(tls_config).map_err(|e| {
                SinkError::ClientBuild(format!(
                    "sink '{}': failed to configure TLS: {}",
                    sink_name, e
                ))
            })?;
        }

        let auth = build_auth_metadata(&sink_name, config.auth.as_ref())?;
        let custom_metadata = build_custom_metadata(&config.headers);

        let channel = endpoint.connect_lazy();
        let mut client = EventSinkClient::new(channel.clone())
            .max_decoding_message_size(config.max_decoding_message_bytes)
            .max_encoding_message_size(config.max_encoding_message_bytes);
        if matches!(config.compression, HttpCompression::Gzip) {
            client = client
                .send_compressed(tonic::codec::CompressionEncoding::Gzip);
        }

        Ok(Self {
            sink_name,
            config,
            signer,
            channel,
            client,
            auth,
            custom_metadata,
        })
    }

    /// Sign the delivery body with the node identity when configured.
    /// gRPC signs the canonical v2 payload only (there is no legacy v1; see
    /// the MVP plan), mirroring the HTTP sink byte for byte.
    async fn sign_payload(
        &self,
        payload: &[u8],
        meta: Option<&DeliveryMeta>,
    ) -> Result<Option<SignatureHeaders>, SinkError> {
        let extra: &[(&str, &str)] =
            match self.config.compression.content_encoding() {
                Some(encoding) => &[("content-encoding", encoding)],
                None => &[],
            };
        sign_delivery(self.signer.as_ref(), payload, 2, extra, meta).await
    }

    /// Attach authentication and user metadata to an outgoing RPC.
    fn apply_metadata<T>(&self, request: &mut Request<T>) {
        let metadata = request.metadata_mut();
        for (key, value) in &self.custom_metadata {
            metadata.insert(key.clone(), value.clone());
        }
        if let Some((key, value)) = &self.auth {
            metadata.insert(key.clone(), value.clone());
        }
    }

    /// Build the `SignedPayload` message: canonical JSON bytes plus the
    /// optional Ed25519 signature block.
    async fn build_signed_payload(
        &self,
        payload: Vec<u8>,
        meta: Option<&DeliveryMeta>,
    ) -> Result<pb::SignedPayload, SinkError> {
        let signature_headers = self.sign_payload(&payload, meta).await?;
        let (signature, timestamp, public_key) = match signature_headers {
            Some(headers) => (
                headers.signature,
                headers.timestamp.parse().unwrap_or(0),
                headers.public_key,
            ),
            None => (String::new(), 0, String::new()),
        };
        Ok(pb::SignedPayload {
            payload,
            signature,
            signature_timestamp: timestamp,
            public_key,
        })
    }

    /// Deliver one request with the shared retry policy: exponential backoff
    /// with jitter between attempts, permanent errors abort immediately.
    async fn deliver_with_retry(
        &self,
        payload: Vec<u8>,
        meta: Option<pb::EventMeta>,
        sign_meta: Option<&DeliveryMeta>,
    ) -> Result<(), SinkError> {
        let body = self.build_signed_payload(payload, sign_meta).await?;
        let sink_name = &self.sink_name;
        let mut last_err: Option<SinkError> = None;

        for attempt in 0..=self.config.max_retries {
            if attempt > 0 {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_sink_retry(sink_name);
                }
                let delay = retry_delay_ms(
                    self.config.retry_base_delay_ms,
                    self.config.retry_max_delay_ms,
                    attempt,
                    last_err.as_ref().and_then(retry_after_of),
                );
                tokio::time::sleep(Duration::from_millis(delay)).await;
            }

            match self.deliver_once(body.clone(), meta.clone()).await {
                Ok(()) => return Ok(()),
                Err(e) if crate::sink::is_permanent_error(&e) => return Err(e),
                Err(e) => last_err = Some(e),
            }
        }

        // Mirror the HTTP sink: surface the last real error (the worker
        // needs the original Auth/Delivery kind to drive its state machine).
        Err(last_err.unwrap_or_else(crate::sink::max_retries_exceeded_error))
    }

    /// One `Deliver` RPC attempt, timed for the shared duration metric.
    async fn deliver_once(
        &self,
        body: pb::SignedPayload,
        meta: Option<pb::EventMeta>,
    ) -> Result<(), SinkError> {
        let request_id = generate_request_id();
        let mut client = self.client.clone();
        timed_sink_request(&self.sink_name, || async {
            let mut request = Request::new(pb::DeliverRequest {
                request_id,
                meta,
                body: Some(body),
            });
            self.apply_metadata(&mut request);
            client
                .deliver(request)
                .await
                .map(|_| ())
                .map_err(|e| map_status(&e))
        })
        .await
    }

    /// `grpc.health.v1.Health/Check` against the sink service. The boolean
    /// flags the `UNIMPLEMENTED` case (server without a health service) so
    /// callers can fall back without conflating it with real rejections.
    async fn health_service_check(&self) -> Result<bool, SinkError> {
        let mut client =
            tonic_health::pb::health_client::HealthClient::new(
                self.channel.clone(),
            );
        let mut request = Request::new(
            tonic_health::pb::HealthCheckRequest {
                service: HEALTH_SERVICE_NAME.to_owned(),
            },
        );
        self.apply_metadata(&mut request);
        match client.check(request).await {
            Ok(response) => {
                match response.into_inner().status() {
                    tonic_health::pb::health_check_response::ServingStatus::Serving => {
                        Ok(false)
                    }
                    other => Err(SinkError::Delivery {
                        message: format!(
                            "health check reports {:?} for {}",
                            other, HEALTH_SERVICE_NAME
                        ),
                        retryable: true,
                        retry_after_ms: None,
                    }),
                }
            }
            Err(status) if status.code() == Code::Unimplemented => Ok(true),
            Err(status) => Err(map_status(&status)),
        }
    }

    /// The `Test` RPC: a signed, authenticated, non-persistent delivery.
    async fn test_rpc(&self) -> Result<(), SinkError> {
        let payload = serialize_json_payload(&test_delivery_payload())?;
        let body = self.build_signed_payload(payload, None).await?;
        let mut client = self.client.clone();
        let request_id = generate_request_id();
        timed_sink_request(&self.sink_name, || async {
            let mut request = Request::new(pb::TestRequest {
                request_id,
                body: Some(body),
            });
            self.apply_metadata(&mut request);
            client.test(request).await.map(|_| ()).map_err(|e| map_status(&e))
        })
        .await
    }
}

#[async_trait]
impl SinkTransport for GrpcTransport {
    async fn send(&self, data: Arc<DataToSink>) -> Result<(), SinkError> {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let governance_id =
            data.payload.get_governance_id().unwrap_or_default();
        let meta = DeliveryMeta::from_data(&data);
        let payload = serialize_json_payload(data.as_ref())?;
        let pb_meta = pb::EventMeta {
            subject_id,
            sn: meta.sn,
            event_type: meta.event_type.clone(),
            schema_id,
            governance_id,
            idempotency_key: meta.idempotency_key(),
            light: false,
        };
        self.deliver_with_retry(payload, Some(pb_meta), Some(&meta))
            .await
    }

    async fn send_light(&self, light: LightEvent) -> Result<(), SinkError> {
        let meta = DeliveryMeta::from_light(&light);
        let payload = serialize_json_payload(&light)?;
        let pb_meta = pb::EventMeta {
            subject_id: light.subject_id.clone(),
            sn: meta.sn,
            event_type: meta.event_type.clone(),
            schema_id: light.schema_id.clone(),
            governance_id: light.governance_id.clone().unwrap_or_default(),
            idempotency_key: meta.idempotency_key(),
            light: true,
        };
        self.deliver_with_retry(payload, Some(pb_meta), Some(&meta))
            .await
    }

    async fn send_batch(
        &self,
        events: Vec<ave_common::IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        // Mirror the HTTP sink: one request with a JSON array payload and no
        // per-event metadata (the array elements carry subject/sn/type).
        let payload = serialize_json_payload(&events)?;
        self.deliver_with_retry(payload, None, None).await
    }

    async fn health_check(&self) -> Result<(), SinkError> {
        match self.health_service_check().await {
            Ok(false) => Ok(()),
            Ok(true) => {
                // Minimal servers may not implement grpc.health.v1: fall
                // back to the Test RPC, which exercises the same channel,
                // auth and signature paths.
                self.test_rpc().await
            }
            Err(e) => Err(e),
        }
    }

    async fn test(&self) -> Result<(), SinkError> {
        // A missing health service must not fail the test delivery: only
        // real health errors (unreachable, NOT_SERVING) abort it.
        self.health_service_check().await?;
        self.test_rpc().await
    }
}

/// Map a gRPC status to the shared sink error taxonomy (see the MVP plan):
/// transient statuses retry with backoff, auth statuses drive the token
/// path, everything else is a permanent rejection.
fn map_status(status: &Status) -> SinkError {
    let message = format!("gRPC {}: {}", status.code(), status.message());
    match status.code() {
        Code::Unavailable
        | Code::DeadlineExceeded
        | Code::Cancelled
        | Code::Unknown
        | Code::Internal
        | Code::Aborted
        | Code::DataLoss
        | Code::ResourceExhausted => SinkError::Delivery {
            message,
            retryable: true,
            retry_after_ms: None,
        },
        Code::Unauthenticated => SinkError::Auth {
            message,
            retry_after_ms: None,
        },
        // `Code::Ok` never reaches this point (success returns before the
        // mapping); it is covered for exhaustiveness and treated as
        // transient so nothing is lost.
        Code::Ok => SinkError::Delivery {
            message,
            retryable: true,
            retry_after_ms: None,
        },
        Code::PermissionDenied
        | Code::InvalidArgument
        | Code::OutOfRange
        | Code::FailedPrecondition
        | Code::Unimplemented
        | Code::AlreadyExists
        | Code::NotFound => SinkError::Rejected { message },
    }
}

/// `retry_after_ms` extractor for the shared backoff, mirroring the HTTP
/// helper (`retry_after_of` in `http.rs`).
const fn retry_after_of(err: &SinkError) -> Option<u64> {
    match err {
        SinkError::Delivery { retry_after_ms, .. }
        | SinkError::Auth { retry_after_ms, .. } => *retry_after_ms,
        _ => None,
    }
}

/// Metadata key/value pair attached to outgoing RPCs (auth or custom).
type MetadataPair = (MetadataKey<Ascii>, MetadataValue<Ascii>);

/// Resolve the authentication metadata for the transport. The secret is read
/// from the environment; a configured auth mode with a missing secret is a
/// configuration error (same behavior as the HTTP sink).
fn build_auth_metadata(
    sink_name: &str,
    auth: Option<&GrpcAuthConfig>,
) -> Result<Option<MetadataPair>, SinkError> {
    let Some(auth) = auth else {
        return Ok(None);
    };
    let (key, secret) = match auth {
        GrpcAuthConfig::BearerToken => {
            let env_var = sink_token_env_var(sink_name);
            let secret = read_secret(sink_name, &env_var)?;
            ("authorization", format!("Bearer {secret}"))
        }
        GrpcAuthConfig::ApiKey => {
            let env_var = sink_apikey_env_var(sink_name);
            let secret = read_secret(sink_name, &env_var)?;
            ("x-api-key", secret)
        }
    };
    let key = MetadataKey::from_bytes(key.as_bytes()).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': invalid metadata key '{}': {}",
            sink_name, key, e
        ))
    })?;
    let mut value = MetadataValue::try_from(secret).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': invalid metadata value: {}",
            sink_name, e
        ))
    })?;
    value.set_sensitive(true);
    Ok(Some((key, value)))
}

/// Read a required secret from the environment.
fn read_secret(sink_name: &str, env_var: &str) -> Result<String, SinkError> {
    match std::env::var(env_var) {
        Ok(value) if !value.is_empty() => Ok(value),
        _ => Err(SinkError::ClientBuild(format!(
            "sink '{}': authentication configured but environment variable {} is not set",
            sink_name, env_var
        ))),
    }
}

/// Parse the user-provided static metadata, dropping keys reserved by the
/// sink contract or by gRPC itself so the delivery contract cannot be
/// broken (same policy as the HTTP sink's custom headers).
fn build_custom_metadata(
    headers: &std::collections::HashMap<String, String>,
) -> Vec<(MetadataKey<Ascii>, MetadataValue<Ascii>)> {
    headers
        .iter()
        .filter(|(name, _)| {
            let name = name.to_lowercase();
            !is_sink_reserved_header(&name)
                && !name.starts_with("grpc-")
                && name != "authorization"
                && name != "x-api-key"
        })
        .filter_map(|(name, value)| {
            let key = MetadataKey::from_bytes(name.as_bytes()).ok()?;
            let value = MetadataValue::try_from(value.as_str()).ok()?;
            Some((key, value))
        })
        .collect()
}

/// Build the TLS configuration for the transport: native roots plus the
/// optional custom CA and mTLS identity from the sink config. The TLS stack
/// is rustls with aws-lc-rs (like the rest of the node); the minimum
/// protocol version is the rustls default (TLS 1.2+).
async fn build_tls_config(
    sink_name: &str,
    tls: Option<&GrpcTlsConfig>,
) -> Result<ClientTlsConfig, SinkError> {
    let mut tls_config = ClientTlsConfig::new().with_native_roots();

    if let Some(tls) = tls {
        if !tls.ca_certificate.is_empty() {
            let pem =
                read_tls_file(sink_name, "ca_certificate", &tls.ca_certificate)
                    .await?;
            tls_config = tls_config.ca_certificate(
                tonic::transport::Certificate::from_pem(pem),
            );
        }

        if !tls.client_certificate.is_empty() {
            let cert_pem = read_tls_file(
                sink_name,
                "client_certificate",
                &tls.client_certificate,
            )
            .await?;
            let key_pem =
                read_tls_file(sink_name, "client_key", &tls.client_key)
                    .await?;
            tls_config = tls_config.identity(
                tonic::transport::Identity::from_pem(cert_pem, key_pem),
            );
        }
    }

    Ok(tls_config)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status(code: Code, message: &str) -> Status {
        Status::new(code, message)
    }

    #[test]
    fn map_status_transient_codes_are_retryable_delivery() {
        for code in [
            Code::Unavailable,
            Code::DeadlineExceeded,
            Code::Cancelled,
            Code::Unknown,
            Code::Internal,
            Code::Aborted,
            Code::ResourceExhausted,
        ] {
            match map_status(&status(code, "boom")) {
                SinkError::Delivery { retryable, .. } => {
                    assert!(retryable, "{code} must be retryable");
                }
                other => panic!("{code} must map to Delivery, got {other:?}"),
            }
        }
    }

    #[test]
    fn map_status_unauthenticated_is_auth_error() {
        match map_status(&status(Code::Unauthenticated, "bad token")) {
            SinkError::Auth { .. } => {}
            other => panic!("expected Auth, got {other:?}"),
        }
    }

    #[test]
    fn map_status_permanent_codes_are_rejected() {
        for code in [
            Code::PermissionDenied,
            Code::InvalidArgument,
            Code::OutOfRange,
            Code::FailedPrecondition,
            Code::Unimplemented,
        ] {
            match map_status(&status(code, "nope")) {
                SinkError::Rejected { .. } => {}
                other => panic!("{code} must map to Rejected, got {other:?}"),
            }
        }
    }

    #[test]
    fn custom_metadata_drops_reserved_keys() {
        let headers = std::collections::HashMap::from([
            ("x-team".to_owned(), "ledger".to_owned()),
            ("authorization".to_owned(), "Bearer evil".to_owned()),
            ("x-api-key".to_owned(), "evil".to_owned()),
            ("grpc-timeout".to_owned(), "1S".to_owned()),
            ("x-ave-sn".to_owned(), "7".to_owned()),
        ]);
        let metadata = build_custom_metadata(&headers);
        assert_eq!(metadata.len(), 1);
        assert_eq!(metadata[0].0.as_str(), "x-team");
    }

    #[test]
    fn auth_metadata_requires_the_secret_env_var() {
        let result =
            build_auth_metadata("no-such-sink", Some(&GrpcAuthConfig::ApiKey));
        assert!(
            matches!(result, Err(SinkError::ClientBuild(_))),
            "missing env secret must be a build error"
        );
    }
}
