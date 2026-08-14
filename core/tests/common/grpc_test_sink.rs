//! In-process gRPC sink receiver for integration tests.
//!
//! Stands up a real tonic server (no docker) implementing the
//! `ave.sink.v1.EventSink` contract and, optionally, `grpc.health.v1`.
//! Every RPC is recorded so tests can assert on payloads, metadata and
//! attempt counts; response behavior is driven by [`GrpcResponseMode`].

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ave_common::sink::pb;
use ave_common::sink::pb::event_sink_server::{
    EventSink, EventSinkServer,
};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rustls::{
    RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::pem::PemObject as _,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::{ReceiverStream, TcpListenerStream};
use tonic::service::Routes;
use tonic::{Code, Request, Response, Status};

use super::test_sink::TestTlsMaterial;

use pb::{DeliverRequest, DeliverResponse, TestRequest, TestResponse};

/// How the test server answers `Deliver` RPCs.
#[derive(Debug, Clone)]
pub enum GrpcResponseMode {
    /// Always succeeds.
    Accept,
    /// Fails every request with the given status code.
    AlwaysStatus(Code),
    /// Fails every request with the given status code plus a backoff hint
    /// (`google.rpc.RetryInfo` details on unary, `DeliverAck.retry_after_ms`
    /// on the stream).
    AlwaysStatusRetryInfo { code: Code, retry_after_ms: u64 },
    /// Fails the first `remaining` requests with the given code, then
    /// accepts (drives the transport's retry path).
    FailTimes {
        code: Code,
        remaining: Arc<AtomicUsize>,
    },
}

/// Build a rejection status carrying `google.rpc.RetryInfo` details.
fn retry_info_status(code: Code, retry_after_ms: u64) -> Status {
    use tonic_types::StatusExt as _;

    Status::with_error_details(
        code,
        "test server rejecting",
        tonic_types::ErrorDetails::with_retry_info(Some(
            std::time::Duration::from_millis(retry_after_ms),
        )),
    )
}

/// Collect the ASCII metadata entries of an RPC into a plain map
/// (keys are already lowercased by tonic).
fn metadata_map(metadata: &tonic::metadata::MetadataMap) -> HashMap<String, String> {
    metadata
        .iter()
        .filter_map(|kv| match kv {
            tonic::metadata::KeyAndValueRef::Ascii(key, value) => value
                .to_str()
                .ok()
                .map(|v| (key.as_str().to_owned(), v.to_owned())),
            tonic::metadata::KeyAndValueRef::Binary(..) => None,
        })
        .collect()
}

/// One recorded `Deliver` RPC.
#[derive(Debug, Clone)]
pub struct RecordedDelivery {
    pub request_id: String,
    pub meta: Option<pb::EventMeta>,
    pub body: Option<pb::SignedPayload>,
    /// Value of the `authorization` metadata, when present.
    pub authorization: Option<String>,
    /// Value of the `x-api-key` metadata, when present.
    pub api_key: Option<String>,
    /// All ASCII metadata entries received with the RPC (lowercased keys),
    /// so tests can assert on custom headers and reserved-header filtering.
    pub metadata: HashMap<String, String>,
    /// `true` when the server answered the RPC with success; rejected
    /// attempts (retryable or not) are recorded with `false`.
    pub accepted: bool,
}

/// One recorded `Test` RPC.
#[derive(Debug, Clone)]
pub struct RecordedTest {
    pub request_id: String,
    pub body: Option<pb::SignedPayload>,
}

#[derive(Default)]
struct GrpcSinkState {
    mode: Option<GrpcResponseMode>,
    deliveries: Vec<RecordedDelivery>,
    tests: Vec<RecordedTest>,
    /// When false, `DeliverStream` answers UNIMPLEMENTED (drives the
    /// client's unary fallback).
    stream_enabled: bool,
    /// Artificial delay before acking each stream message.
    stream_ack_delay_ms: u64,
    /// One-shot: the next read of an open stream tears it down with
    /// UNAVAILABLE (simulates a connection cut mid-stream).
    stream_cut: bool,
    /// While set, open streams stop reading (simulates a stalled consumer).
    stream_paused: bool,
    /// Number of `DeliverStream` invocations (streams opened by clients).
    stream_opens: usize,
}

/// In-process gRPC receiver. The server task ends when the instance is
/// dropped (the channel-close aborts serving).
pub struct GrpcTestSink {
    endpoint: String,
    state: Arc<Mutex<GrpcSinkState>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    health_reporter: Option<tonic_health::server::HealthReporter>,
    /// Wakes stream handlers parked waiting for messages so stream control
    /// changes (cut, pause) apply immediately, not on the next message.
    control_notify: Arc<tokio::sync::Notify>,
}

impl GrpcTestSink {
    /// Start a server with the standard `grpc.health.v1` service reporting
    /// SERVING for `ave.sink.v1.EventSink`.
    pub async fn start() -> Self {
        Self::start_inner(true, None).await
    }

    /// Start a server WITHOUT the health service (drives the client's
    /// UNIMPLEMENTED fallback).
    pub async fn start_without_health_service() -> Self {
        Self::start_inner(false, None).await
    }

    /// Start a server that does not implement `DeliverStream` (drives the
    /// client's unary-only fallback).
    pub async fn start_unary_only() -> Self {
        let sink = Self::start_inner(true, None).await;
        sink.state
            .lock()
            .expect("state lock")
            .stream_enabled = false;
        sink
    }

    /// Start a TLS server with a throwaway CA (see [`TestTlsMaterial`]) and
    /// the standard health service. When `require_client_cert` is true the
    /// server verifies a client certificate signed by that same CA (mTLS).
    /// Returns the sink and the TLS material so tests can configure the
    /// node's `tls` paths.
    pub async fn start_tls(
        require_client_cert: bool,
    ) -> (Self, TestTlsMaterial) {
        let material = TestTlsMaterial::generate();
        let sink =
            Self::start_inner(true, Some((&material, require_client_cert)))
                .await;
        (sink, material)
    }

    async fn start_inner(
        with_health: bool,
        tls: Option<(&TestTlsMaterial, bool)>,
    ) -> Self {
        let state = Arc::new(Mutex::new(GrpcSinkState {
            mode: Some(GrpcResponseMode::Accept),
            stream_enabled: true,
            ..Default::default()
        }));
        let std_listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("grpc test sink should bind an ephemeral port");
        std_listener
            .set_nonblocking(true)
            .expect("listener should be non-blocking");
        let addr: SocketAddr =
            std_listener.local_addr().expect("listener has local address");

        let control_notify = Arc::new(tokio::sync::Notify::new());
        let service = TestEventSink {
            state: Arc::clone(&state),
            control_notify: Arc::clone(&control_notify),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let scheme = if tls.is_some() { "https" } else { "http" };
        let routes = Routes::new(
            EventSinkServer::new(service)
                .accept_compressed(tonic::codec::CompressionEncoding::Gzip)
                .accept_compressed(tonic::codec::CompressionEncoding::Zstd),
        );
        let (routes, health_reporter) = if with_health {
            let (reporter, health_service) =
                tonic_health::server::health_reporter();
            reporter
                .set_serving::<EventSinkServer<TestEventSink>>()
                .await;
            (routes.add_service(health_service), Some(reporter))
        } else {
            (routes, None)
        };

        match tls {
            None => {
                let listener = TcpListener::from_std(std_listener)
                    .expect("listener should convert to tokio");
                let server =
                    tonic::transport::Server::builder().add_routes(routes);
                tokio::spawn(async move {
                    let _ = server
                        .serve_with_incoming_shutdown(
                            TcpListenerStream::new(listener),
                            async move {
                                let mut rx = shutdown_rx;
                                let _ = rx.wait_for(|v| *v).await;
                            },
                        )
                        .await;
                });
            }
            Some((material, require_client_cert)) => {
                // Serve the tonic routes over axum-server with an explicit
                // crypto provider: tonic's `ServerTlsConfig` resolves the
                // process-level default, which is unset when several rustls
                // backends are linked into the test binary.
                let cert_der = CertificateDer::from_pem_slice(
                    material.server_cert_pem.as_bytes(),
                )
                .expect("test server certificate PEM should parse");
                let key_der = PrivatePkcs8KeyDer::from_pem_slice(
                    material.server_key_pem.as_bytes(),
                )
                .expect("test server key PEM should parse");
                let provider =
                    Arc::new(rustls::crypto::aws_lc_rs::default_provider());
                let builder = RustlsServerConfig::builder_with_provider(
                    provider.clone(),
                )
                .with_safe_default_protocol_versions()
                .expect("default TLS versions should be valid");
                let builder = if require_client_cert {
                    let mut roots = RootCertStore::empty();
                    let ca_der = CertificateDer::from_pem_slice(
                        material.ca_pem.as_bytes(),
                    )
                    .expect("test CA PEM should parse");
                    roots.add(ca_der).expect("CA cert should be valid");
                    let verifier =
                        WebPkiClientVerifier::builder_with_provider(
                            Arc::new(roots),
                            provider,
                        )
                        .build()
                        .expect("client verifier should build");
                    builder.with_client_cert_verifier(verifier)
                } else {
                    builder.with_no_client_auth()
                };
                let mut server_config = builder
                    .with_single_cert(
                        vec![cert_der],
                        PrivateKeyDer::Pkcs8(key_der),
                    )
                    .expect("server cert/key should be valid");
                server_config.alpn_protocols = vec![b"h2".to_vec()];

                let app = routes.prepare().into_axum_router();
                let rustls_config =
                    RustlsConfig::from_config(Arc::new(server_config));
                tokio::spawn(async move {
                    let server = axum_server::from_tcp(std_listener)
                        .expect("listener should convert to axum-server")
                        .acceptor(RustlsAcceptor::new(rustls_config))
                        .serve(app.into_make_service());
                    tokio::select! {
                        _ = server => {}
                        _ = async move {
                            let mut rx = shutdown_rx;
                            let _ = rx.wait_for(|v| *v).await;
                        } => {}
                    }
                });
            }
        }

        Self {
            endpoint: format!("{}://{}", scheme, addr),
            state,
            shutdown: shutdown_tx,
            health_reporter,
            control_notify,
        }
    }

    /// Flip the health service to NOT_SERVING (drives the client's
    /// health-check failure path).
    pub async fn set_health_not_serving(&self) {
        let reporter = self
            .health_reporter
            .as_ref()
            .expect("sink was started with a health service");
        reporter
            .set_not_serving::<EventSinkServer<TestEventSink>>()
            .await;
    }

    /// Base endpoint URL to configure in `GrpcSinkConfig.endpoint`.
    pub fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    /// Set how the server answers `Deliver` RPCs.
    pub fn set_mode(&self, mode: GrpcResponseMode) {
        self.state.lock().expect("state lock").mode = Some(mode);
    }

    /// Delay every stream ack by `ms` (drives client-side pipelining).
    pub fn set_stream_ack_delay(&self, ms: u64) {
        self.state.lock().expect("state lock").stream_ack_delay_ms = ms;
    }

    /// Tear down the currently open delivery stream(s) with UNAVAILABLE,
    /// like a connection cut; new streams work again afterwards.
    pub fn cut_streams(&self) {
        self.state.lock().expect("state lock").stream_cut = true;
        self.control_notify.notify_waiters();
    }

    /// Stop reading from open delivery streams (stalled consumer).
    pub fn pause_streams(&self) {
        self.state.lock().expect("state lock").stream_paused = true;
        self.control_notify.notify_waiters();
    }

    /// Resume reading from open delivery streams.
    pub fn resume_streams(&self) {
        self.state.lock().expect("state lock").stream_paused = false;
        self.control_notify.notify_waiters();
    }

    /// How many delivery streams clients have opened.
    pub fn stream_opens(&self) -> usize {
        self.state.lock().expect("state lock").stream_opens
    }

    /// Recorded `Deliver` RPCs, in arrival order.
    pub fn deliveries(&self) -> Vec<RecordedDelivery> {
        self.state.lock().expect("state lock").deliveries.clone()
    }

    /// Recorded `Deliver` RPCs the server answered with success, in
    /// arrival order (rejected attempts are excluded).
    pub fn accepted_deliveries(&self) -> Vec<RecordedDelivery> {
        self.state
            .lock()
            .expect("state lock")
            .deliveries
            .iter()
            .filter(|d| d.accepted)
            .cloned()
            .collect()
    }

    /// Recorded `Test` RPCs, in arrival order.
    pub fn tests(&self) -> Vec<RecordedTest> {
        self.state.lock().expect("state lock").tests.clone()
    }

    /// Wait until the server has recorded `expected` `Test` RPCs, polling
    /// like the rest of the test helpers (no fixed sleeps).
    pub async fn wait_for_tests(&self, expected: usize) {
        for _ in 0..100 {
            if self.tests().len() >= expected {
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        }
        panic!(
            "grpc test sink did not receive {} test RPCs; received {}",
            expected,
            self.tests().len()
        );
    }

    /// Wait until the server has recorded `expected` deliveries, polling
    /// like the rest of the test helpers (no fixed sleeps).
    pub async fn wait_for_deliveries(&self, expected: usize) {
        for _ in 0..100 {
            if self.deliveries().len() >= expected {
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        }
        panic!(
            "grpc test sink did not receive {} deliveries; received {}",
            expected,
            self.deliveries().len()
        );
    }

    /// Wait until the server has accepted `expected` deliveries, polling
    /// like the rest of the test helpers (no fixed sleeps).
    pub async fn wait_for_accepted(&self, expected: usize) {
        for _ in 0..100 {
            if self.accepted_deliveries().len() >= expected {
                return;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
        }
        panic!(
            "grpc test sink did not accept {} deliveries; accepted {}",
            expected,
            self.accepted_deliveries().len()
        );
    }
}

impl Drop for GrpcTestSink {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

struct TestEventSink {
    state: Arc<Mutex<GrpcSinkState>>,
    control_notify: Arc<tokio::sync::Notify>,
}

#[tonic::async_trait]
impl EventSink for TestEventSink {
    async fn deliver(
        &self,
        request: Request<DeliverRequest>,
    ) -> Result<Response<DeliverResponse>, Status> {
        let (metadata, _, message) = request.into_parts();
        let metadata = metadata_map(&metadata);
        let authorization = metadata.get("authorization").cloned();
        let api_key = metadata.get("x-api-key").cloned();

        let mut state = self.state.lock().expect("state lock");
        let response = match state.mode.clone().unwrap_or(GrpcResponseMode::Accept)
        {
            GrpcResponseMode::Accept => Ok(Response::new(DeliverResponse {})),
            GrpcResponseMode::AlwaysStatus(code) => {
                Err(Status::new(code, "test server rejecting"))
            }
            GrpcResponseMode::AlwaysStatusRetryInfo {
                code,
                retry_after_ms,
            } => Err(retry_info_status(code, retry_after_ms)),
            GrpcResponseMode::FailTimes { code, remaining } => {
                if remaining.fetch_sub(1, Ordering::SeqCst) > 0 {
                    Err(Status::new(code, "test server rejecting"))
                } else {
                    Ok(Response::new(DeliverResponse {}))
                }
            }
        };

        state.deliveries.push(RecordedDelivery {
            request_id: message.request_id.clone(),
            meta: message.meta.clone(),
            body: message.body.clone(),
            authorization,
            api_key,
            metadata,
            accepted: response.is_ok(),
        });

        response
    }

    async fn test(
        &self,
        request: Request<TestRequest>,
    ) -> Result<Response<TestResponse>, Status> {
        let message = request.into_inner();
        let mut state = self.state.lock().expect("state lock");
        state.tests.push(RecordedTest {
            request_id: message.request_id,
            body: message.body,
        });
        Ok(Response::new(TestResponse {}))
    }

    type DeliverStreamStream =
        ReceiverStream<Result<pb::DeliverAck, Status>>;

    async fn deliver_stream(
        &self,
        request: Request<tonic::Streaming<DeliverRequest>>,
    ) -> Result<Response<Self::DeliverStreamStream>, Status> {
        let (metadata, _, mut streaming) = request.into_parts();
        let metadata = metadata_map(&metadata);
        let authorization = metadata.get("authorization").cloned();
        let api_key = metadata.get("x-api-key").cloned();

        {
            let mut state = self.state.lock().expect("state lock");
            if !state.stream_enabled {
                return Err(Status::unimplemented(
                    "test server without DeliverStream",
                ));
            }
            state.stream_opens += 1;
        }

        let state = Arc::clone(&self.state);
        let control_notify = Arc::clone(&self.control_notify);
        let (tx, rx) = tokio::sync::mpsc::channel(64);
        tokio::spawn(async move {
            loop {
                // Control flags are re-evaluated on every wakeup: the
                // notify fires when a test cuts or pauses the stream while
                // this task is parked waiting for messages.
                let (cut, paused) = {
                    let mut state = state.lock().expect("state lock");
                    let cut = state.stream_cut;
                    if cut {
                        state.stream_cut = false;
                    }
                    (cut, state.stream_paused)
                };
                if cut {
                    let _ = tx
                        .send(Err(Status::unavailable(
                            "test server cut the stream",
                        )))
                        .await;
                    return;
                }
                if paused {
                    // Stalled consumer: do not read until resumed.
                    tokio::time::sleep(tokio::time::Duration::from_millis(50))
                        .await;
                    continue;
                }

                let message = tokio::select! {
                    message = streaming.message() => match message {
                        Ok(Some(message)) => message,
                        Ok(None) | Err(_) => return,
                    },
                    () = control_notify.notified() => continue,
                };

                // The response mode is read fresh per message: a mode set
                // while parked waiting for messages must apply to them.
                let (delay, mode) = {
                    let state = state.lock().expect("state lock");
                    (
                        state.stream_ack_delay_ms,
                        state
                            .mode
                            .clone()
                            .unwrap_or(GrpcResponseMode::Accept),
                    )
                };
                let (error_code, error_message, ack_retry_after_ms) = match &mode
                {
                    GrpcResponseMode::Accept => (0, String::new(), 0),
                    GrpcResponseMode::AlwaysStatus(code) => {
                        (*code as i32, "test server rejecting".to_owned(), 0)
                    }
                    GrpcResponseMode::AlwaysStatusRetryInfo {
                        code,
                        retry_after_ms,
                    } => (
                        *code as i32,
                        "test server rejecting".to_owned(),
                        *retry_after_ms,
                    ),
                    GrpcResponseMode::FailTimes { code, remaining } => {
                        if remaining.fetch_sub(1, Ordering::SeqCst) > 0 {
                            (*code as i32, "test server rejecting".to_owned(), 0)
                        } else {
                            (0, String::new(), 0)
                        }
                    }
                };

                state.lock().expect("state lock").deliveries.push(
                    RecordedDelivery {
                        request_id: message.request_id.clone(),
                        meta: message.meta.clone(),
                        body: message.body.clone(),
                        authorization: authorization.clone(),
                        api_key: api_key.clone(),
                        metadata: metadata.clone(),
                        accepted: error_code == 0,
                    },
                );

                if delay > 0 {
                    tokio::time::sleep(tokio::time::Duration::from_millis(
                        delay,
                    ))
                    .await;
                }
                let ack = pb::DeliverAck {
                    request_id: message.request_id,
                    error_code,
                    error_message,
                    retry_after_ms: ack_retry_after_ms,
                };
                if tx.send(Ok(ack)).await.is_err() {
                    return;
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }
}
