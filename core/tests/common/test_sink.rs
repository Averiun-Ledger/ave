use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use ave_common::IncomingSinkEvent;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use axum_server::tls_rustls::{RustlsAcceptor, RustlsConfig};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, IsCa, Issuer, KeyPair, SanType,
};
use serde::Deserialize;
use tokio::{sync::Mutex, task::JoinHandle};
use tokio_rustls::rustls::{
    RootCertStore, ServerConfig as RustlsServerConfig,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer},
    server::WebPkiClientVerifier,
};
use tokio_util::sync::CancellationToken;

/// Response mode of the test sink.
#[derive(Debug, Clone, Copy)]
pub enum ResponseMode {
    /// Accept the event, store it and return HTTP 200.
    Accept,
    /// Return HTTP 500 without storing the event (transient failure).
    ServerError,
    /// Return HTTP 422 without storing the event (non-transient failure).
    ClientError,
    /// Wait `ms` milliseconds before returning HTTP 200, simulating a slow or
    /// unresponsive sink. When `ms` is larger than the sink's configured
    /// `request_timeout_ms`, the worker will see a timeout.
    Timeout(u64),
    /// Never respond, simulating a crashed or unreachable sink. The HTTP
    /// connection will hang until the node's request timeout fires.
    Drop,
    /// Healthcheck succeeds (`GET /events` returns 200) but event delivery
    /// fails (`POST /events` returns 500). Used to test flapping detection.
    HealthOkDeliveryFail,
    /// Return HTTP 401 on the first delivery request, then accept subsequent
    /// ones. Used to test OAuth2 token refresh.
    UnauthorizedOnce,
    /// Always return HTTP 401. Used to test persistent auth failures.
    UnauthorizedAlways,
    /// Return HTTP 429 with a `Retry-After: <secs>` header on the first
    /// delivery request, then accept subsequent ones. Used to test that the
    /// worker honors the server-provided retry delay.
    RateLimitOnce(u64),
}

/// Response mode of the test sink's OAuth2 token endpoint.
#[derive(Debug, Clone, Copy)]
pub enum AuthResponseMode {
    /// Return a valid OAuth2 token.
    TokenSuccess,
    /// Return HTTP 401 to simulate invalid credentials.
    TokenFailure,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AuthRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, serde::Serialize)]
struct TokenResponse {
    access_token: String,
    token_type: String,
    expires_in: i64,
}

struct TestSinkState {
    events: Vec<IncomingSinkEvent>,
    mode: ResponseMode,
    auth_mode: AuthResponseMode,
    auth_requests: Vec<AuthRequest>,
    authorization_headers: Vec<Option<String>>,
    signature_headers: Vec<SignatureHeaders>,
    idempotency_headers: Vec<IdempotencyHeaders>,
    content_encodings: Vec<Option<String>>,
    /// All headers received on each `/events` request, in request order.
    headers: Vec<HeaderMap>,
    /// Path of each `/events` request, in request order (the wildcard route
    /// `/events/{*rest}` lets tests exercise `{{event-type}}` URL templates).
    paths: Vec<String>,
    raw_bodies: Vec<Vec<u8>>,
    received_at: Vec<std::time::Instant>,
    /// Number of events accepted per request (1 for individual deliveries,
    /// N for batch deliveries).
    batch_lens: Vec<usize>,
    unauthorized_once_consumed: bool,
    ratelimit_once_consumed: bool,
}

/// Signature headers captured on a `/events` delivery.
#[derive(Debug, Clone, Default)]
pub struct SignatureHeaders {
    /// `X-Ave-Signature` value; `None` when the header was absent.
    pub signature: Option<String>,
    /// `X-Ave-Signature-Timestamp` value; `None` when the header was absent.
    pub timestamp: Option<String>,
    /// `X-Ave-Public-Key` value; `None` when the header was absent.
    pub public_key: Option<String>,
}

/// Idempotency headers captured on a `/events` delivery. All fields are
/// `None` on batch deliveries, which do not carry them.
#[derive(Debug, Clone, Default)]
pub struct IdempotencyHeaders {
    /// `X-Ave-Subject-Id` value; `None` when the header was absent.
    pub subject_id: Option<String>,
    /// `X-Ave-SN` value; `None` when the header was absent.
    pub sn: Option<String>,
    /// `X-Ave-Event-Type` value; `None` when the header was absent.
    pub event_type: Option<String>,
    /// `Idempotency-Key` value; `None` when the header was absent.
    pub key: Option<String>,
}

impl IdempotencyHeaders {
    fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned())
        };
        Self {
            subject_id: get("X-Ave-Subject-Id"),
            sn: get("X-Ave-SN"),
            event_type: get("X-Ave-Event-Type"),
            key: get("Idempotency-Key"),
        }
    }
}

impl SignatureHeaders {
    fn from_headers(headers: &HeaderMap) -> Self {
        let get = |name: &str| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned())
        };
        Self {
            signature: get("X-Ave-Signature"),
            timestamp: get("X-Ave-Signature-Timestamp"),
            public_key: get("X-Ave-Public-Key"),
        }
    }
}

/// TLS material of an HTTPS test sink: a throwaway CA, a server certificate
/// valid for `127.0.0.1` and a client certificate, both signed by that CA.
#[derive(Clone, Debug)]
pub struct TestTlsMaterial {
    /// CA certificate in PEM; configure it as `tls.ca_certificate` so the
    /// node trusts the sink.
    pub ca_pem: String,
    /// Client certificate chain in PEM; configure it as
    /// `tls.client_certificate` for mTLS.
    pub client_cert_pem: String,
    /// Client private key in PEM; configure it as `tls.client_key` for mTLS.
    pub client_key_pem: String,
    ca_der: CertificateDer<'static>,
    /// Server certificate in PEM; configure it as `tls.pinned_certificate`
    /// to pin the sink's certificate.
    pub server_cert_pem: String,
    /// Server private key in PEM; configure it as the TLS key of a test
    /// server (e.g. Redpanda with TLS).
    pub server_key_pem: String,
    server_cert_der: CertificateDer<'static>,
    server_key_der: Vec<u8>,
}

impl TestTlsMaterial {
    /// Generate a fresh CA, server and client certificates.
    pub fn generate() -> Self {
        let ca_key = KeyPair::generate().expect("CA key should generate");
        let mut ca_params = CertificateParams::default();
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "ave-test-ca");
        let ca_cert = ca_params
            .self_signed(&ca_key)
            .expect("CA cert should generate");
        let issuer = Issuer::from_params(&ca_params, &ca_key);

        let server_key =
            KeyPair::generate().expect("server key should generate");
        let mut server_params = CertificateParams::default();
        server_params
            .distinguished_name
            .push(DnType::CommonName, "ave-test-server");
        server_params.subject_alt_names =
            vec![SanType::IpAddress(IpAddr::V4(Ipv4Addr::LOCALHOST))];
        let server_cert = server_params
            .signed_by(&server_key, &issuer)
            .expect("server cert should generate");

        let client_key =
            KeyPair::generate().expect("client key should generate");
        let mut client_params = CertificateParams::default();
        client_params
            .distinguished_name
            .push(DnType::CommonName, "ave-test-client");
        let client_cert = client_params
            .signed_by(&client_key, &issuer)
            .expect("client cert should generate");

        Self {
            ca_pem: ca_cert.pem(),
            client_cert_pem: client_cert.pem(),
            client_key_pem: client_key.serialize_pem(),
            ca_der: ca_cert.der().clone(),
            server_cert_pem: server_cert.pem(),
            server_key_pem: server_key.serialize_pem(),
            server_cert_der: server_cert.der().clone(),
            server_key_der: server_key.serialize_der(),
        }
    }
}

/// A real HTTP sink used by integration tests.
pub struct TestSink {
    addr: SocketAddr,
    scheme: &'static str,
    state: Arc<Mutex<TestSinkState>>,
    #[allow(dead_code)]
    handle: JoinHandle<()>,
    #[allow(dead_code)]
    cancel: CancellationToken,
}

impl TestSink {
    fn new_state() -> Arc<Mutex<TestSinkState>> {
        Arc::new(Mutex::new(TestSinkState {
            events: Vec::new(),
            mode: ResponseMode::Accept,
            auth_mode: AuthResponseMode::TokenSuccess,
            auth_requests: Vec::new(),
            authorization_headers: Vec::new(),
            signature_headers: Vec::new(),
            idempotency_headers: Vec::new(),
            content_encodings: Vec::new(),
            headers: Vec::new(),
            paths: Vec::new(),
            raw_bodies: Vec::new(),
            received_at: Vec::new(),
            batch_lens: Vec::new(),
            unauthorized_once_consumed: false,
            ratelimit_once_consumed: false,
        }))
    }

    fn app(state: Arc<Mutex<TestSinkState>>) -> Router {
        Router::new()
            .route("/events", post(Self::receive).get(Self::health))
            .route("/events/{*rest}", post(Self::receive).get(Self::health))
            .route("/auth/token", post(Self::auth))
            .with_state(state)
    }

    /// Bind to `127.0.0.1:0` and start accepting requests.
    pub async fn start() -> Self {
        let state = Self::new_state();
        let app = Self::app(state.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test sink should bind");
        let addr = listener.local_addr().expect("listener has local address");

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app);
            tokio::select! {
                _ = server => {}
                _ = task_cancel.cancelled() => {}
            }
        });

        Self {
            addr,
            scheme: "http",
            state,
            handle,
            cancel,
        }
    }

    /// Bind to `127.0.0.1:0` and serve HTTPS with a freshly generated CA.
    ///
    /// When `require_client_cert` is true the sink demands a client
    /// certificate signed by the same CA (mTLS). Returns the sink and the
    /// TLS material so tests can point the node's `tls` config at the CA
    /// and client credentials.
    pub async fn start_tls(
        require_client_cert: bool,
    ) -> (Self, TestTlsMaterial) {
        let material = TestTlsMaterial::generate();
        let state = Self::new_state();
        let app = Self::app(state.clone());

        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("test sink should bind");
        listener
            .set_nonblocking(true)
            .expect("listener should be non-blocking");
        let addr = listener.local_addr().expect("listener has local address");

        let rustls_config = if require_client_cert {
            let mut roots = RootCertStore::empty();
            roots
                .add(material.ca_der.clone())
                .expect("CA cert should parse");
            let verifier = WebPkiClientVerifier::builder(Arc::new(roots))
                .build()
                .expect("client verifier should build");
            let mut server_config = RustlsServerConfig::builder()
                .with_client_cert_verifier(verifier)
                .with_single_cert(
                    vec![material.server_cert_der.clone()],
                    PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                        material.server_key_der.clone(),
                    )),
                )
                .expect("server cert/key should be valid");
            server_config.alpn_protocols =
                vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            RustlsConfig::from_config(Arc::new(server_config))
        } else {
            // Build the server config manually with an explicit crypto provider
            // so the test does not depend on the process-level default, which
            // may be unset when multiple rustls crypto backends are linked.
            let provider = rustls::crypto::aws_lc_rs::default_provider();
            let mut server_config =
                RustlsServerConfig::builder_with_provider(Arc::new(provider))
                    .with_safe_default_protocol_versions()
                    .expect("default TLS versions should be valid")
                    .with_no_client_auth()
                    .with_single_cert(
                        vec![material.server_cert_der.clone()],
                        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
                            material.server_key_der.clone(),
                        )),
                    )
                    .expect("server cert/key should be valid");
            server_config.alpn_protocols =
                vec![b"h2".to_vec(), b"http/1.1".to_vec()];
            RustlsConfig::from_config(Arc::new(server_config))
        };

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let server = axum_server::from_tcp(listener)
                .expect("listener should convert to tokio")
                .acceptor(RustlsAcceptor::new(rustls_config))
                .serve(app.into_make_service());
            tokio::select! {
                _ = server => {}
                _ = task_cancel.cancelled() => {}
            }
        });

        (
            Self {
                addr,
                scheme: "https",
                state,
                handle,
                cancel,
            },
            material,
        )
    }

    pub fn url(&self) -> String {
        format!("{}://{}/events", self.scheme, self.addr)
    }

    pub fn auth_url(&self) -> String {
        format!("{}://{}/auth/token", self.scheme, self.addr)
    }

    /// Change the response mode for subsequent `/events` requests.
    pub async fn set_mode(&self, mode: ResponseMode) {
        self.state.lock().await.mode = mode;
    }

    /// Change the response mode for subsequent `/auth/token` requests.
    pub async fn set_auth_mode(&self, mode: AuthResponseMode) {
        self.state.lock().await.auth_mode = mode;
    }

    /// Wait until `count` events have been received.
    pub async fn wait_for_count(&self, count: usize, timeout: bool) {
        let mut attempts = 0;
        loop {
            let current = self.state.lock().await.events.len();
            if current >= count {
                return;
            }
            if timeout && attempts > 100 {
                panic!(
                    "test sink did not receive {} events; received {}",
                    count, current
                );
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            attempts += 1;
        }
    }

    /// Wait until `count` full (non-lightweight) events have been received.
    pub async fn wait_for_full_count(&self, count: usize, timeout: bool) {
        let mut attempts = 0;
        loop {
            let current = self
                .state
                .lock()
                .await
                .events
                .iter()
                .filter(|e| matches!(e, IncomingSinkEvent::Full(_)))
                .count();
            if current >= count {
                return;
            }
            if timeout && attempts > 100 {
                panic!(
                    "test sink did not receive {} full events; received {}",
                    count, current
                );
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            attempts += 1;
        }
    }

    /// Wait until `count` distinct `(subject_id, sn)` pairs have been received.
    ///
    /// Unlike `wait_for_count`, this tolerates duplicate HTTP deliveries of the
    /// same event and only returns once at least `count` unique sequence
    /// numbers are present for `subject_id`.
    pub async fn wait_for_distinct_sn_count(
        &self,
        subject_id: &str,
        count: usize,
        timeout: bool,
    ) {
        use std::collections::HashSet;
        let mut attempts = 0;
        loop {
            let state = self.state.lock().await;
            let distinct: HashSet<u64> = state
                .events
                .iter()
                .filter(|e| e.subject_id() == subject_id)
                .map(|e| e.sn())
                .collect();
            let current = distinct.len();
            drop(state);
            if current >= count {
                return;
            }
            if timeout && attempts > 100 {
                panic!(
                    "test sink did not receive {} distinct SNs for {}; received {}",
                    count, subject_id, current
                );
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            attempts += 1;
        }
    }

    /// Wait until `count` raw request bodies have been received, including
    /// failed delivery attempts (they are recorded before the response mode
    /// is applied).
    pub async fn wait_for_raw_count(&self, count: usize, timeout: bool) {
        let mut attempts = 0;
        loop {
            let current = self.state.lock().await.raw_bodies.len();
            if current >= count {
                return;
            }
            if timeout && attempts > 100 {
                panic!(
                    "test sink did not receive {} raw deliveries; received {}",
                    count, current
                );
            }
            tokio::time::sleep(Duration::from_millis(300)).await;
            attempts += 1;
        }
    }

    /// Return a snapshot of the events received so far.
    pub async fn snapshot(&self) -> Vec<IncomingSinkEvent> {
        self.state.lock().await.events.clone()
    }

    /// Return a snapshot of only the full (non-lightweight) events received so
    /// far.
    pub async fn full_snapshot(&self) -> Vec<IncomingSinkEvent> {
        self.state
            .lock()
            .await
            .events
            .iter()
            .filter(|e| matches!(e, IncomingSinkEvent::Full(_)))
            .cloned()
            .collect()
    }

    /// Remove all events received so far, useful to simulate data loss at the
    /// sink before a replay.
    pub async fn clear(&self) {
        self.state.lock().await.events.clear();
    }

    /// Remove events for `subject_id` with SN >= `from_sn`.
    pub async fn remove_events_for_subject_from_sn(
        &self,
        subject_id: &str,
        from_sn: u64,
    ) {
        let mut state = self.state.lock().await;
        state
            .events
            .retain(|e| !(e.subject_id() == subject_id && e.sn() >= from_sn));
    }

    /// Return a snapshot of all `/auth/token` requests received so far.
    pub async fn auth_requests(&self) -> Vec<AuthRequest> {
        self.state.lock().await.auth_requests.clone()
    }

    /// Return a snapshot of the `Authorization` headers received on `/events`,
    /// in request order. `None` means the header was absent.
    pub async fn authorization_headers(&self) -> Vec<Option<String>> {
        self.state.lock().await.authorization_headers.clone()
    }

    /// Return a snapshot of the `X-Ave-Signature*` headers received on
    /// `/events`, in request order.
    pub async fn signature_headers(&self) -> Vec<SignatureHeaders> {
        self.state.lock().await.signature_headers.clone()
    }

    /// Return a snapshot of the raw request bodies received on `/events`,
    /// in request order. Bodies are stored exactly as received (still
    /// compressed when the sink used `Content-Encoding`).
    pub async fn raw_bodies(&self) -> Vec<Vec<u8>> {
        self.state.lock().await.raw_bodies.clone()
    }

    /// Return a snapshot of the idempotency headers received on `/events`,
    /// in request order.
    pub async fn idempotency_headers(&self) -> Vec<IdempotencyHeaders> {
        self.state.lock().await.idempotency_headers.clone()
    }

    /// Return a snapshot of the `Content-Encoding` values received on
    /// `/events`, in request order. `None` means the header was absent.
    pub async fn content_encodings(&self) -> Vec<Option<String>> {
        self.state.lock().await.content_encodings.clone()
    }

    /// Return the value of `name` from the most recent `/events` request,
    /// or `None` if the header was absent or there have been no requests.
    pub async fn last_header(&self, name: &str) -> Option<String> {
        self.state.lock().await.headers.last().and_then(|headers| {
            headers
                .get(name)
                .and_then(|v| v.to_str().ok())
                .map(|s| s.to_owned())
        })
    }

    /// Return the instants at which each `/events` request was received,
    /// in request order.
    pub async fn received_at(&self) -> Vec<std::time::Instant> {
        self.state.lock().await.received_at.clone()
    }

    /// Return the number of events accepted per request, in request order
    /// (1 for individual deliveries, N for batch deliveries).
    pub async fn batch_lens(&self) -> Vec<usize> {
        self.state.lock().await.batch_lens.clone()
    }

    /// Path of each request received, in request order.
    #[allow(dead_code)]
    pub async fn paths(&self) -> Vec<String> {
        self.state.lock().await.paths.clone()
    }

    async fn receive(
        State(state): State<Arc<Mutex<TestSinkState>>>,
        uri: axum::http::Uri,
        headers: HeaderMap,
        body: axum::body::Bytes,
    ) -> Response {
        let auth_header = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        let signature_headers = SignatureHeaders::from_headers(&headers);
        let idempotency_headers = IdempotencyHeaders::from_headers(&headers);
        let content_encoding = headers
            .get("Content-Encoding")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        // Decompress the body for JSON parsing; the raw bytes are stored
        // untouched so tests can verify the exact wire payload.
        let decoded;
        let json_bytes: &[u8] = match content_encoding.as_deref() {
            Some("gzip") => {
                let mut decoder = flate2::read::GzDecoder::new(body.as_ref());
                let mut buf = Vec::new();
                match std::io::Read::read_to_end(&mut decoder, &mut buf) {
                    Ok(_) => {
                        decoded = buf;
                        &decoded
                    }
                    Err(e) => {
                        return (
                            StatusCode::BAD_REQUEST,
                            format!("invalid gzip body: {}", e),
                        )
                            .into_response();
                    }
                }
            }
            _ => &body,
        };

        // A delivery is either a single event object or a JSON array of
        // events (batch delivery).
        let received_events: Vec<IncomingSinkEvent> =
            match serde_json::from_slice::<Vec<IncomingSinkEvent>>(json_bytes) {
                Ok(events) => events,
                Err(_) => {
                    match serde_json::from_slice::<IncomingSinkEvent>(
                        json_bytes,
                    ) {
                        Ok(event) => vec![event],
                        Err(e) => {
                            return (
                                StatusCode::BAD_REQUEST,
                                format!("invalid event JSON: {}", e),
                            )
                                .into_response();
                        }
                    }
                }
            };

        let mut guard = state.lock().await;
        guard.authorization_headers.push(auth_header);
        guard.signature_headers.push(signature_headers);
        guard.idempotency_headers.push(idempotency_headers);
        guard.content_encodings.push(content_encoding);
        guard.headers.push(headers);
        guard.paths.push(uri.path().to_owned());
        guard.raw_bodies.push(body.to_vec());
        guard.received_at.push(std::time::Instant::now());

        match guard.mode {
            ResponseMode::Accept => {
                // Store every event the sink is asked to accept, including
                // lightweight events, so tests can verify partial filters.
                guard.batch_lens.push(received_events.len());
                guard.events.extend(received_events);
                StatusCode::OK.into_response()
            }
            ResponseMode::ServerError => {
                drop(guard);
                (StatusCode::INTERNAL_SERVER_ERROR, "server error")
                    .into_response()
            }
            ResponseMode::ClientError => {
                drop(guard);
                (StatusCode::UNPROCESSABLE_ENTITY, "client error")
                    .into_response()
            }
            ResponseMode::Timeout(ms) => {
                // Store the event before sleeping so the slow response still
                // counts as a successful delivery.
                guard.batch_lens.push(received_events.len());
                guard.events.extend(received_events);
                drop(guard);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                StatusCode::OK.into_response()
            }
            ResponseMode::Drop => {
                // Never return: the connection hangs just like a crashed sink.
                drop(guard);
                std::future::pending::<()>().await;
                unreachable!()
            }
            ResponseMode::HealthOkDeliveryFail => {
                drop(guard);
                (StatusCode::INTERNAL_SERVER_ERROR, "delivery failed")
                    .into_response()
            }
            ResponseMode::UnauthorizedOnce => {
                if !guard.unauthorized_once_consumed {
                    guard.unauthorized_once_consumed = true;
                    drop(guard);
                    (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
                } else {
                    guard.batch_lens.push(received_events.len());
                    guard.events.extend(received_events);
                    StatusCode::OK.into_response()
                }
            }
            ResponseMode::UnauthorizedAlways => {
                drop(guard);
                (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
            }
            ResponseMode::RateLimitOnce(secs) => {
                if !guard.ratelimit_once_consumed {
                    guard.ratelimit_once_consumed = true;
                    drop(guard);
                    (
                        StatusCode::TOO_MANY_REQUESTS,
                        [(axum::http::header::RETRY_AFTER, secs.to_string())],
                        "rate limited",
                    )
                        .into_response()
                } else {
                    guard.batch_lens.push(received_events.len());
                    guard.events.extend(received_events);
                    StatusCode::OK.into_response()
                }
            }
        }
    }

    async fn health() -> StatusCode {
        StatusCode::OK
    }

    async fn auth(
        State(state): State<Arc<Mutex<TestSinkState>>>,
        Json(req): Json<AuthRequest>,
    ) -> Response {
        let mut guard = state.lock().await;
        guard.auth_requests.push(req);

        match guard.auth_mode {
            AuthResponseMode::TokenSuccess => {
                let token = TokenResponse {
                    access_token: "test-access-token".to_owned(),
                    token_type: "Bearer".to_owned(),
                    expires_in: 3600,
                };
                drop(guard);
                (StatusCode::OK, Json(token)).into_response()
            }
            AuthResponseMode::TokenFailure => {
                drop(guard);
                (StatusCode::UNAUTHORIZED, "invalid credentials")
                    .into_response()
            }
        }
    }
}

/// A request proxied by [`TestProxy`].
#[derive(Debug, Clone)]
pub struct ProxiedRequest {
    /// Request line as received: `"METHOD absolute-uri"`.
    pub request_line: String,
    /// `Proxy-Authorization` header value; `None` when absent.
    pub proxy_authorization: Option<String>,
}

/// Shared state of [`TestProxy`]: the recorded requests plus a single
/// forwarding client reused across requests.
struct ProxyState {
    requests: Mutex<Vec<ProxiedRequest>>,
    client: reqwest::Client,
}

/// A minimal forward proxy used to test the sink `proxy` configuration.
///
/// Requests arrive in the standard HTTP proxy absolute-URI form
/// (`POST http://real-sink/events`) and are forwarded to that URI with a
/// plain HTTP client. Every proxied request is recorded.
pub struct TestProxy {
    addr: SocketAddr,
    state: Arc<ProxyState>,
    #[allow(dead_code)]
    handle: JoinHandle<()>,
    #[allow(dead_code)]
    cancel: CancellationToken,
}

impl TestProxy {
    /// Bind to `127.0.0.1:0` and start accepting requests.
    pub async fn start() -> Self {
        // One client for all forwarding: it does not honor system proxy env
        // vars (which would break loopback forwarding) and avoids connection
        // setup per request.
        let state = Arc::new(ProxyState {
            requests: Mutex::new(Vec::new()),
            client: reqwest::Client::builder()
                .no_proxy()
                .build()
                .expect("test proxy client should build"),
        });
        let app = Router::new()
            .fallback(Self::forward)
            .with_state(Arc::clone(&state));

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test proxy should bind");
        let addr = listener.local_addr().expect("listener has local address");

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let handle = tokio::spawn(async move {
            let server = axum::serve(listener, app);
            tokio::select! {
                _ = server => {}
                _ = task_cancel.cancelled() => {}
            }
        });

        Self {
            addr,
            state,
            handle,
            cancel,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    /// Requests proxied so far, in request order.
    pub async fn proxied_requests(&self) -> Vec<ProxiedRequest> {
        self.state.requests.lock().await.clone()
    }

    async fn forward(
        State(state): State<Arc<ProxyState>>,
        request: axum::extract::Request,
    ) -> Response {
        let uri = request.uri().clone();
        let method = request.method().clone();
        let headers = request.headers().clone();

        if uri.scheme().is_none() || uri.authority().is_none() {
            return (
                StatusCode::BAD_REQUEST,
                "proxy requests must use absolute-form URIs",
            )
                .into_response();
        }
        let target = uri.to_string();

        let body =
            match axum::body::to_bytes(request.into_body(), 64 * 1024 * 1024)
                .await
            {
                Ok(body) => body,
                Err(e) => {
                    return (
                        StatusCode::BAD_REQUEST,
                        format!("cannot read request body: {}", e),
                    )
                        .into_response();
                }
            };

        let proxy_authorization = headers
            .get(axum::http::header::PROXY_AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());
        state.requests.lock().await.push(ProxiedRequest {
            request_line: format!("{} {}", method, target),
            proxy_authorization,
        });

        let mut out = state.client.request(method, &target).body(body.to_vec());
        for (name, value) in headers.iter() {
            if name == axum::http::header::HOST
                || name == axum::http::header::CONTENT_LENGTH
                || name == axum::http::header::PROXY_AUTHORIZATION
            {
                // HOST and CONTENT_LENGTH are recomputed by the forwarding
                // client; Proxy-Authorization is hop-by-hop and a real proxy
                // never leaks it upstream.
                continue;
            }
            out = out.header(name, value);
        }

        match out.send().await {
            Ok(resp) => {
                let status = StatusCode::from_u16(resp.status().as_u16())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                let body = resp.bytes().await.unwrap_or_default();
                (status, body.to_vec()).into_response()
            }
            Err(e) => (
                StatusCode::BAD_GATEWAY,
                format!("proxy upstream error: {}", e),
            )
                .into_response(),
        }
    }
}
