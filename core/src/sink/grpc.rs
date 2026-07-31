//! gRPC transport for sink delivery (tonic, protobuf over HTTP/2).

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use async_trait::async_trait;
use ave_common::sink::pb;
use ave_common::sink::{
    GrpcAuthConfig, GrpcSinkConfig, GrpcTlsConfig, HttpCompression,
    SinkAuthConfig,
};
use ave_common::{DataToSink, LightEvent};
use base64::{Engine as Base64Engine, prelude::BASE64_STANDARD};
use futures::StreamExt as _;
use tokio::sync::{Mutex, RwLock, Semaphore, mpsc, oneshot};
use tokio_stream::wrappers::ReceiverStream;
use tonic::metadata::{Ascii, MetadataKey, MetadataValue};
use tonic::transport::{Channel, ClientTlsConfig, Endpoint};
use tonic::{Code, Request, Status};

use crate::config::TokenResponse;
use crate::metrics::try_core_metrics;
use crate::sink::delivery::{
    DeliveryMeta, SignatureHeaders, generate_request_id, is_sink_reserved_header,
    serialize_json_payload, sign_delivery, sink_apikey_env_var,
    sink_password_env_var, sink_token_env_var, test_delivery_payload,
    timed_sink_request,
};
use crate::sink::error::SinkError;
use crate::sink::transport::{NodeSigner, SinkTransport};
use crate::sink::{read_tls_file, retry_delay_ms};

use pb::event_sink_client::EventSinkClient;

/// Service name reported to `grpc.health.v1` health checks.
const HEALTH_SERVICE_NAME: &str = "ave.sink.v1.EventSink";

/// Pending per-message acks of a live delivery stream, keyed by
/// `request_id`. Resolved by the stream reader task; cleared (failing every
/// waiter as retryable) when the stream dies.
type PendingAcks =
    Arc<Mutex<HashMap<String, oneshot::Sender<Result<(), SinkError>>>>>;

/// A live delivery stream: deliveries are forwarded into the RPC request
/// stream and the reader task resolves their acks by `request_id`.
#[derive(Clone)]
struct StreamHandle {
    tx: mpsc::Sender<pb::DeliverRequest>,
    pending: PendingAcks,
}

/// Failure of a stream delivery attempt.
enum StreamFailure {
    /// The server does not implement `DeliverStream`: use the unary RPC.
    Unimplemented,
    /// A regular sink error (retryable or permanent).
    Delivery(SinkError),
}

/// Metadata key/value pair attached to outgoing RPCs (auth or custom).
type MetadataPair = (MetadataKey<Ascii>, MetadataValue<Ascii>);

/// OAuth2 client state: the token is fetched from the auth endpoint, cached
/// with a refresh margin and refreshed on UNAUTHENTICATED (mirrors the HTTP
/// sink's token flow).
struct GrpcOAuthState {
    config: SinkAuthConfig,
    /// HTTP client used only for token requests (honors the sink CA).
    token_client: reqwest::Client,
    /// Password or client secret read from the environment.
    secret: String,
    cached_token: RwLock<Option<TokenResponse>>,
}

/// Authentication state of the transport, resolved at construction.
enum GrpcAuth {
    /// Static per-RPC metadata (bearer token, API key, basic credentials).
    Static(MetadataPair),
    /// OAuth2 client (boxed: much larger than the static variant).
    OAuth2(Box<GrpcOAuthState>),
}

/// gRPC delivery transport: protobuf over a single multiplexed HTTP/2
/// channel per sink.
///
/// Deliveries are pipelined over a persistent bidirectional stream
/// (`DeliverStream`): a bounded in-flight window gives real backpressure
/// and every message is acked individually. Servers implementing only the
/// unary RPCs of the MVP are fully supported (automatic unary fallback).
/// Payloads are the same canonical JSON documents as the HTTP sink, so
/// receivers share parser and signature verification across transports.
pub struct GrpcTransport {
    sink_name: String,
    config: GrpcSinkConfig,
    signer: Option<NodeSigner>,
    channel: Channel,
    client: EventSinkClient<Channel>,
    /// Per-RPC authentication state (secrets loaded from the environment).
    auth: Option<GrpcAuth>,
    /// User-provided static metadata (reserved keys already filtered out).
    custom_metadata: Vec<(MetadataKey<Ascii>, MetadataValue<Ascii>)>,
    /// Lazily opened delivery stream; cleared on stream death so the next
    /// delivery reopens it.
    stream: Arc<Mutex<Option<StreamHandle>>>,
    /// Set once the server answers `DeliverStream` with UNIMPLEMENTED:
    /// every delivery uses the unary RPC from then on.
    unary_only: AtomicBool,
    /// In-flight window: maximum unacked deliveries on the stream.
    in_flight: Arc<Semaphore>,
    /// Configured window size (for the in-flight gauge).
    in_flight_limit: usize,
    /// Set after the first stream open; later opens are reconnections.
    stream_opened_once: AtomicBool,
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
            .http2_keep_alive_interval(Duration::from_secs(
                config.http2_keepalive_interval_secs,
            ))
            .keep_alive_timeout(Duration::from_secs(
                config.http2_keepalive_timeout_secs,
            ))
            // Streams can stay idle between events: keep them alive too.
            .keep_alive_while_idle(true);
        if let Some(secs) = config.tcp_keepalive_secs {
            endpoint =
                endpoint.tcp_keepalive(Some(Duration::from_secs(secs)));
        }

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

        let auth = build_auth(
            &sink_name,
            config.auth.as_ref(),
            config.tls.as_ref(),
            config.request_timeout_ms,
        )
        .await?;
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
            in_flight: Arc::new(Semaphore::new(
                config.max_in_flight_batches.max(1),
            )),
            in_flight_limit: config.max_in_flight_batches.max(1),
            config,
            signer,
            channel,
            client,
            auth,
            custom_metadata,
            stream: Arc::new(Mutex::new(None)),
            unary_only: AtomicBool::new(false),
            stream_opened_once: AtomicBool::new(false),
        })
    }

    /// Update the in-flight gauge from the semaphore state (no extra
    /// counter: the semaphore is the source of truth).
    fn observe_in_flight(&self) {
        if let Some(metrics) = try_core_metrics() {
            let in_flight = self
                .in_flight_limit
                .saturating_sub(self.in_flight.available_permits());
            metrics.set_grpc_in_flight_batches(
                &self.sink_name,
                in_flight as i64,
            );
        }
    }

    /// Per-request timeout for unary RPCs and per-message ack waits.
    const fn request_timeout(&self) -> Duration {
        Duration::from_millis(self.config.request_timeout_ms)
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

    /// Attach authentication and user metadata to an outgoing RPC. With
    /// OAuth2 the cached token is used (refreshing it when expired).
    async fn apply_metadata<T>(
        &self,
        request: &mut Request<T>,
    ) -> Result<(), SinkError> {
        let metadata = request.metadata_mut();
        for (key, value) in &self.custom_metadata {
            metadata.insert(key.clone(), value.clone());
        }
        if let Some(auth) = &self.auth {
            let (key, value) = match auth {
                GrpcAuth::Static(pair) => pair.clone(),
                GrpcAuth::OAuth2(_) => {
                    let token = self.bearer_token().await?;
                    auth_metadata_pair(
                        &self.sink_name,
                        "authorization",
                        format!("Bearer {token}"),
                    )?
                }
            };
            metadata.insert(key, value);
        }
        Ok(())
    }

    /// Resolve a valid OAuth2 access token: cached while fresh (with the
    /// configured margin), otherwise fetched from the auth endpoint outside
    /// any lock (mirrors the HTTP sink's `build_auth_header`).
    async fn bearer_token(&self) -> Result<String, SinkError> {
        let Some(GrpcAuth::OAuth2(state)) = &self.auth else {
            return Err(SinkError::Auth {
                message: format!(
                    "sink '{}': bearer token requested without OAuth2 auth",
                    self.sink_name
                ),
                retry_after_ms: None,
            });
        };
        let GrpcOAuthState {
            config,
            token_client,
            secret,
            cached_token,
        } = state.as_ref();

        {
            let guard = cached_token.read().await;
            if let Some(token) = guard.as_ref()
                && !token.is_expired_or_expiring_soon(
                    self.config.token_refresh_margin_secs,
                )
            {
                return Ok(token.access_token.clone());
            }
        }

        let token = crate::sink::obtain_token_with_retry(
            token_client,
            config,
            secret,
            self.config.retry_base_delay_ms,
        )
        .await?;
        let access_token = token.access_token.clone();
        *cached_token.write().await = Some(token);
        Ok(access_token)
    }

    /// Drop the cached OAuth2 token and the delivery stream (its metadata
    /// carries the stale token), so the next attempt re-authenticates from
    /// scratch.
    async fn reset_auth(&self) {
        if let Some(GrpcAuth::OAuth2(state)) = &self.auth {
            *state.cached_token.write().await = None;
        }
        *self.stream.lock().await = None;
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
                Err(SinkError::Auth { .. })
                    if attempt == 0
                        && matches!(
                            self.auth,
                            Some(GrpcAuth::OAuth2(_))
                        ) =>
                {
                    // Auth error on the first attempt with OAuth2: drop the
                    // stale token (and the stream, which carries it) and
                    // retry once immediately with a fresh one (mirrors the
                    // HTTP sink).
                    self.reset_auth().await;
                    return self.deliver_once(body, meta).await;
                }
                Err(e) => last_err = Some(e),
            }
        }

        // Mirror the HTTP sink: surface the last real error (the worker
        // needs the original Auth/Delivery kind to drive its state machine).
        Err(last_err.unwrap_or_else(crate::sink::max_retries_exceeded_error))
    }

    /// One delivery attempt over the stream (with unary fallback), timed
    /// for the shared duration metric.
    async fn deliver_once(
        &self,
        body: pb::SignedPayload,
        meta: Option<pb::EventMeta>,
    ) -> Result<(), SinkError> {
        let request_id = generate_request_id();
        if !self.unary_only.load(Ordering::Acquire) {
            match self
                .deliver_via_stream(&request_id, &body, &meta)
                .await
            {
                Ok(()) => return Ok(()),
                Err(StreamFailure::Unimplemented) => {
                    // v1-unary-only server: remember it and deliver every
                    // message with the unary RPC from now on.
                    self.unary_only.store(true, Ordering::Release);
                }
                Err(StreamFailure::Delivery(e)) => return Err(e),
            }
        }
        self.deliver_unary(request_id, body, meta).await
    }

    /// One unary `Deliver` RPC attempt (MVP contract and fallback for
    /// servers without `DeliverStream`).
    async fn deliver_unary(
        &self,
        request_id: String,
        body: pb::SignedPayload,
        meta: Option<pb::EventMeta>,
    ) -> Result<(), SinkError> {
        let mut client = self.client.clone();
        timed_sink_request(&self.sink_name, || async {
            let mut request = Request::new(pb::DeliverRequest {
                request_id,
                meta,
                body: Some(body),
            });
            request.set_timeout(self.request_timeout());
            self.apply_metadata(&mut request).await?;
            client
                .deliver(request)
                .await
                .map(|_| ())
                .map_err(|e| map_status(&e))
        })
        .await
    }

    /// One delivery attempt over the persistent stream: waits for an
    /// in-flight slot (backpressure), enqueues the request and waits for
    /// its per-message ack.
    async fn deliver_via_stream(
        &self,
        request_id: &str,
        body: &pb::SignedPayload,
        meta: &Option<pb::EventMeta>,
    ) -> Result<(), StreamFailure> {
        // The semaphore is never closed; an acquisition error is impossible.
        let permit = match self.in_flight.clone().acquire_owned().await {
            Ok(permit) => permit,
            Err(_) => {
                return Err(StreamFailure::Delivery(SinkError::Delivery {
                    message: format!(
                        "sink '{}': in-flight window closed",
                        self.sink_name
                    ),
                    retryable: true,
                    retry_after_ms: None,
                }));
            }
        };
        let handle = self.stream_handle().await?;
        self.observe_in_flight();

        let (ack_tx, ack_rx) = oneshot::channel();
        handle
            .pending
            .lock()
            .await
            .insert(request_id.to_owned(), ack_tx);
        let send_result = handle
            .tx
            .send(pb::DeliverRequest {
                request_id: request_id.to_owned(),
                meta: meta.clone(),
                body: Some(body.clone()),
            })
            .await;
        if send_result.is_err() {
            // The reader task is gone: forget the pending ack and force a
            // lazy reopen on the next attempt.
            handle.pending.lock().await.remove(request_id);
            *self.stream.lock().await = None;
            drop(permit);
            self.observe_in_flight();
            return Err(StreamFailure::Delivery(SinkError::Delivery {
                message: format!(
                    "sink '{}': delivery stream closed",
                    self.sink_name
                ),
                retryable: true,
                retry_after_ms: None,
            }));
        }

        let result = timed_sink_request(&self.sink_name, || async {
            let ack_start = std::time::Instant::now();
            match tokio::time::timeout(self.request_timeout(), ack_rx).await {
                Ok(Ok(ack_result)) => {
                    if let Some(metrics) = try_core_metrics() {
                        metrics.observe_grpc_ack_roundtrip(
                            &self.sink_name,
                            ack_start.elapsed(),
                        );
                    }
                    ack_result
                }
                Ok(Err(_closed)) => Err(SinkError::Delivery {
                    message: format!(
                        "sink '{}': delivery stream closed before ack",
                        self.sink_name
                    ),
                    retryable: true,
                    retry_after_ms: None,
                }),
                Err(_elapsed) => {
                    // The ack may still arrive: drop the pending entry so a
                    // late ack is ignored instead of leaking.
                    handle.pending.lock().await.remove(request_id);
                    Err(SinkError::Delivery {
                        message: format!(
                            "sink '{}': stream ack timeout after {} ms",
                            self.sink_name, self.config.request_timeout_ms
                        ),
                        retryable: true,
                        retry_after_ms: None,
                    })
                }
            }
        })
        .await;
        drop(permit);
        self.observe_in_flight();
        result.map_err(StreamFailure::Delivery)
    }

    /// The live stream, opening it lazily on first use. Concurrent callers
    /// are serialized so exactly one stream exists per transport.
    async fn stream_handle(&self) -> Result<StreamHandle, StreamFailure> {
        let mut slot = self.stream.lock().await;
        if let Some(handle) = slot.as_ref() {
            return Ok(handle.clone());
        }

        let (tx, rx) = mpsc::channel(self.config.max_in_flight_batches.max(1));
        let mut request = Request::new(ReceiverStream::new(rx));
        self.apply_metadata(&mut request)
            .await
            .map_err(StreamFailure::Delivery)?;
        let response = self
            .client
            .clone()
            .deliver_stream(request)
            .await
            .map_err(|e| {
                if e.code() == Code::Unimplemented {
                    StreamFailure::Unimplemented
                } else {
                    StreamFailure::Delivery(map_status(&e))
                }
            })?;

        let pending: PendingAcks = Arc::new(Mutex::new(HashMap::new()));
        let handle = StreamHandle {
            tx,
            pending: Arc::clone(&pending),
        };
        *slot = Some(handle.clone());
        // The guard is no longer needed: release it before spawning the
        // reader task so other deliveries are not blocked behind it.
        drop(slot);

        // Any open after the first one is a reconnection (the slot is only
        // cleared when the stream dies).
        if self.stream_opened_once.swap(true, Ordering::AcqRel) {
            if let Some(metrics) = try_core_metrics() {
                metrics.observe_grpc_stream_reconnect(&self.sink_name);
            }
            tracing::debug!(
                msg_type = "GrpcStreamReconnect",
                sink = %self.sink_name,
                "gRPC delivery stream reopened after a failure"
            );
        }

        tokio::spawn(
            tracing::Instrument::instrument(
                stream_reader(
                    response.into_inner(),
                    pending,
                    Arc::clone(&self.stream),
                    self.sink_name.clone(),
                ),
                tracing::info_span!(
                    "grpc_delivery_stream",
                    sink = %self.sink_name
                ),
            ),
        );
        Ok(handle)
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
        request.set_timeout(self.request_timeout());
        self.apply_metadata(&mut request).await?;
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
            request.set_timeout(self.request_timeout());
            self.apply_metadata(&mut request).await?;
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

    async fn warm_up(&self) -> Result<(), SinkError> {
        // Eager OAuth2 token fetch (mirrors the HTTP sink) so the first
        // delivery does not pay the token round-trip.
        if matches!(self.auth, Some(GrpcAuth::OAuth2(_))) {
            self.bearer_token().await?;
        }
        // Open the delivery stream eagerly so the first delivery does not
        // pay the handshake either; a unary-only server just latches the
        // fallback.
        if !self.unary_only.load(Ordering::Acquire) {
            match self.stream_handle().await {
                Ok(_) => {}
                Err(StreamFailure::Unimplemented) => {
                    self.unary_only.store(true, Ordering::Release);
                }
                Err(StreamFailure::Delivery(e)) => return Err(e),
            }
        }
        Ok(())
    }

    async fn send_batch_best_effort(
        &self,
        events: Vec<ave_common::IncomingSinkEvent>,
    ) -> Result<(), SinkError> {
        // A single attempt, no retries (mirrors the Kafka transport):
        // blocking on backoff would delay actor shutdown, and the cursor
        // guarantees re-delivery via catch-up. When the worker stops, the
        // transport is dropped and the stream half-closes naturally, letting
        // the server drain the in-flight messages.
        let payload = serialize_json_payload(&events)?;
        let body = self.build_signed_payload(payload, None).await?;
        self.deliver_once(body, None).await
    }
}

/// Read the acks of a delivery stream, resolving each pending delivery by
/// `request_id`. When the stream ends (server close or terminal status)
/// every pending delivery is failed as retryable (its cursor never
/// advanced, so catch-up re-delivers in order) and the transport slot is
/// cleared so the next delivery reopens the stream lazily.
async fn stream_reader(
    mut streaming: tonic::codec::Streaming<pb::DeliverAck>,
    pending: PendingAcks,
    slot: Arc<Mutex<Option<StreamHandle>>>,
    sink_name: String,
) {
    loop {
        match streaming.next().await {
            Some(Ok(ack)) => {
                let sender = pending.lock().await.remove(&ack.request_id);
                if let Some(sender) = sender {
                    // The waiter may have timed out already; a late ack is
                    // then simply dropped.
                    let _ = sender.send(map_ack(&ack));
                }
            }
            Some(Err(status)) => {
                tracing::debug!(
                    sink = %sink_name,
                    error = %status,
                    "gRPC delivery stream closed by the server"
                );
                break;
            }
            None => break,
        }
    }

    // Dropping the oneshot senders makes every waiter see the stream as
    // broken (retryable); clearing the slot forces a lazy reopen.
    pending.lock().await.clear();
    *slot.lock().await = None;
}

/// Map a per-message stream ack to a delivery result, using the same status
/// table as unary responses plus the optional `retry_after_ms` hint.
fn map_ack(ack: &pb::DeliverAck) -> Result<(), SinkError> {
    if ack.error_code == 0 {
        return Ok(());
    }
    let retry_after_ms =
        (ack.retry_after_ms > 0).then_some(ack.retry_after_ms);
    Err(map_code(
        Code::from(ack.error_code),
        format!("gRPC stream ack {}: {}", ack.error_code, ack.error_message),
        retry_after_ms,
    ))
}

/// Map a gRPC status to the shared sink error taxonomy (see the MVP plan):
/// transient statuses retry with backoff, auth statuses drive the token
/// path, everything else is a permanent rejection. A `ResourceExhausted`
/// carrying `google.rpc.RetryInfo` surfaces the server's exact backoff
/// hint (parity with HTTP's `Retry-After`).
fn map_status(status: &Status) -> SinkError {
    let retry_after_ms = (status.code() == Code::ResourceExhausted)
        .then(|| {
            tonic_types::StatusExt::get_details_retry_info(status)
                .and_then(|info| {
                    info.retry_delay.map(|delay| {
                        u64::try_from(delay.as_millis()).unwrap_or(u64::MAX)
                    })
                })
        })
        .flatten();
    map_code(
        status.code(),
        format!("gRPC {}: {}", status.code(), status.message()),
        retry_after_ms,
    )
}

/// Shared status-code mapping for unary responses and stream acks.
const fn map_code(
    code: Code,
    message: String,
    retry_after_ms: Option<u64>,
) -> SinkError {
    match code {
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
            retry_after_ms,
        },
        Code::Unauthenticated => SinkError::Auth {
            message,
            retry_after_ms,
        },
        // `Code::Ok` never reaches this point (success returns before the
        // mapping); it is covered for exhaustiveness and treated as
        // transient so nothing is lost.
        Code::Ok => SinkError::Delivery {
            message,
            retryable: true,
            retry_after_ms,
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

/// Resolve the authentication state for the transport. Secrets are read
/// from the environment; a configured auth mode with a missing secret is a
/// configuration error (same behavior as the HTTP sink).
async fn build_auth(
    sink_name: &str,
    auth: Option<&GrpcAuthConfig>,
    tls: Option<&GrpcTlsConfig>,
    request_timeout_ms: u64,
) -> Result<Option<GrpcAuth>, SinkError> {
    let Some(auth) = auth else {
        return Ok(None);
    };
    match auth {
        GrpcAuthConfig::BearerToken => {
            let env_var = sink_token_env_var(sink_name);
            let secret = read_secret(sink_name, &env_var)?;
            Ok(Some(GrpcAuth::Static(auth_metadata_pair(
                sink_name,
                "authorization",
                format!("Bearer {secret}"),
            )?)))
        }
        GrpcAuthConfig::ApiKey => {
            let env_var = sink_apikey_env_var(sink_name);
            let secret = read_secret(sink_name, &env_var)?;
            Ok(Some(GrpcAuth::Static(auth_metadata_pair(
                sink_name, "x-api-key", secret,
            )?)))
        }
        GrpcAuthConfig::Basic { username } => {
            let env_var = sink_password_env_var(sink_name);
            let password = read_secret(sink_name, &env_var)?;
            let encoded =
                BASE64_STANDARD.encode(format!("{username}:{password}"));
            Ok(Some(GrpcAuth::Static(auth_metadata_pair(
                sink_name,
                "authorization",
                format!("Basic {encoded}"),
            )?)))
        }
        GrpcAuthConfig::OAuth2(config) => {
            let env_var = sink_password_env_var(sink_name);
            let secret = read_secret(sink_name, &env_var)?;
            let token_client =
                build_token_client(sink_name, tls, request_timeout_ms).await?;
            Ok(Some(GrpcAuth::OAuth2(Box::new(GrpcOAuthState {
                config: config.clone(),
                token_client,
                secret,
                cached_token: RwLock::new(None),
            }))))
        }
    }
}

/// Build an auth metadata pair, marking the value as sensitive.
fn auth_metadata_pair(
    sink_name: &str,
    key: &str,
    value: String,
) -> Result<MetadataPair, SinkError> {
    let key = MetadataKey::from_bytes(key.as_bytes()).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': invalid metadata key '{}': {}",
            sink_name, key, e
        ))
    })?;
    let mut value = MetadataValue::try_from(value).map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{}': invalid metadata value: {}",
            sink_name, e
        ))
    })?;
    value.set_sensitive(true);
    Ok((key, value))
}

/// Build the reqwest client that fetches OAuth2 tokens, honoring the
/// sink's `tls.ca_certificate` as an additional root CA (same policy as
/// the Kafka OIDC token client).
async fn build_token_client(
    sink_name: &str,
    tls: Option<&GrpcTlsConfig>,
    request_timeout_ms: u64,
) -> Result<reqwest::Client, SinkError> {
    let mut builder = reqwest::Client::builder()
        .timeout(Duration::from_millis(request_timeout_ms));
    if let Some(tls) = tls
        && !tls.ca_certificate.is_empty()
    {
        builder = crate::sink::add_root_certificates(
            builder,
            sink_name,
            &tls.ca_certificate,
        )
        .await?;
    }
    builder.build().map_err(|e| {
        SinkError::ClientBuild(format!(
            "sink '{sink_name}': failed to build OAuth token client: {e}"
        ))
    })
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

    #[tokio::test]
    async fn auth_metadata_requires_the_secret_env_var() {
        let oauth = GrpcAuthConfig::OAuth2(SinkAuthConfig {
            auth_url: "http://127.0.0.1:1/token".to_owned(),
            username: "user".to_owned(),
            ..SinkAuthConfig::default()
        });
        for auth in [
            GrpcAuthConfig::BearerToken,
            GrpcAuthConfig::ApiKey,
            GrpcAuthConfig::Basic {
                username: "user".to_owned(),
            },
            oauth,
        ] {
            let result = build_auth("no-such-sink", Some(&auth), None, 1000)
                .await;
            assert!(
                matches!(result, Err(SinkError::ClientBuild(_))),
                "missing env secret must be a build error for {auth:?}"
            );
        }
    }
}
