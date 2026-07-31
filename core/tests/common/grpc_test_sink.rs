//! In-process gRPC sink receiver for integration tests.
//!
//! Stands up a real tonic server (no docker) implementing the
//! `ave.sink.v1.EventSink` contract and, optionally, `grpc.health.v1`.
//! Every RPC is recorded so tests can assert on payloads, metadata and
//! attempt counts; response behavior is driven by [`GrpcResponseMode`].

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use ave_common::sink::pb;
use ave_common::sink::pb::event_sink_server::{
    EventSink, EventSinkServer,
};
use tokio::net::TcpListener;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::{Certificate, Identity, ServerTlsConfig};
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
    /// Fails the first `remaining` requests with the given code, then
    /// accepts (drives the transport's retry path).
    FailTimes {
        code: Code,
        remaining: Arc<AtomicUsize>,
    },
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
}

/// In-process gRPC receiver. The server task ends when the instance is
/// dropped (the channel-close aborts serving).
pub struct GrpcTestSink {
    endpoint: String,
    state: Arc<Mutex<GrpcSinkState>>,
    shutdown: tokio::sync::watch::Sender<bool>,
    health_reporter: Option<tonic_health::server::HealthReporter>,
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

    /// Start a TLS server with a throwaway CA (see [`TestTlsMaterial`]) and
    /// the standard health service. When `require_client_cert` is true the
    /// server verifies a client certificate signed by that same CA (mTLS).
    /// Returns the sink and the TLS material so tests can configure the
    /// node's `tls` paths.
    pub async fn start_tls(
        require_client_cert: bool,
    ) -> (Self, TestTlsMaterial) {
        let material = TestTlsMaterial::generate();
        let identity = Identity::from_pem(
            material.server_cert_pem.clone(),
            material.server_key_pem.clone(),
        );
        let mut tls = ServerTlsConfig::new().identity(identity);
        if require_client_cert {
            tls = tls
                .client_ca_root(Certificate::from_pem(material.ca_pem.clone()));
        }
        let sink = Self::start_inner(true, Some(tls)).await;
        (sink, material)
    }

    async fn start_inner(
        with_health: bool,
        tls: Option<ServerTlsConfig>,
    ) -> Self {
        let state = Arc::new(Mutex::new(GrpcSinkState {
            mode: Some(GrpcResponseMode::Accept),
            ..Default::default()
        }));
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("grpc test sink should bind an ephemeral port");
        let addr: SocketAddr =
            listener.local_addr().expect("listener has local address");

        let service = TestEventSink {
            state: Arc::clone(&state),
        };
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let scheme = if tls.is_some() { "https" } else { "http" };
        let mut server = tonic::transport::Server::builder();
        if let Some(tls) = tls {
            server = server.tls_config(tls).expect("test TLS config is valid");
        }
        let router = server.add_service(EventSinkServer::new(service));
        let (router, health_reporter) = if with_health {
            let (reporter, health_service) =
                tonic_health::server::health_reporter();
            reporter
                .set_serving::<EventSinkServer<TestEventSink>>()
                .await;
            (router.add_service(health_service), Some(reporter))
        } else {
            (router, None)
        };

        tokio::spawn(async move {
            let _ = router
                .serve_with_incoming_shutdown(
                    TcpListenerStream::new(listener),
                    async move {
                        let mut rx = shutdown_rx;
                        let _ = rx.wait_for(|v| *v).await;
                    },
                )
                .await;
        });

        Self {
            endpoint: format!("{}://{}", scheme, addr),
            state,
            shutdown: shutdown_tx,
            health_reporter,
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
}

#[tonic::async_trait]
impl EventSink for TestEventSink {
    async fn deliver(
        &self,
        request: Request<DeliverRequest>,
    ) -> Result<Response<DeliverResponse>, Status> {
        let (metadata, _, message) = request.into_parts();
        let authorization = metadata
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let api_key = metadata
            .get("x-api-key")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);

        let mut state = self.state.lock().expect("state lock");
        let response = match state.mode.clone().unwrap_or(GrpcResponseMode::Accept)
        {
            GrpcResponseMode::Accept => Ok(Response::new(DeliverResponse {})),
            GrpcResponseMode::AlwaysStatus(code) => {
                Err(Status::new(code, "test server rejecting"))
            }
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
}
