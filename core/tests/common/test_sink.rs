use std::{net::SocketAddr, sync::Arc, time::Duration};

use ave_common::IncomingSinkEvent;
use axum::{
    Json, Router,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
};
use serde::Deserialize;
use tokio::{sync::Mutex, task::JoinHandle};
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
    unauthorized_once_consumed: bool,
}

/// A real HTTP sink used by integration tests.
pub struct TestSink {
    addr: SocketAddr,
    state: Arc<Mutex<TestSinkState>>,
    #[allow(dead_code)]
    handle: JoinHandle<()>,
    #[allow(dead_code)]
    cancel: CancellationToken,
}

impl TestSink {
    /// Bind to `127.0.0.1:0` and start accepting requests.
    pub async fn start() -> Self {
        let state = Arc::new(Mutex::new(TestSinkState {
            events: Vec::new(),
            mode: ResponseMode::Accept,
            auth_mode: AuthResponseMode::TokenSuccess,
            auth_requests: Vec::new(),
            authorization_headers: Vec::new(),
            unauthorized_once_consumed: false,
        }));
        let app = Router::new()
            .route("/events", post(Self::receive).get(Self::health))
            .route("/auth/token", post(Self::auth))
            .with_state(state.clone());

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
            state,
            handle,
            cancel,
        }
    }

    pub fn url(&self) -> String {
        format!("http://{}/events", self.addr)
    }

    pub fn auth_url(&self) -> String {
        format!("http://{}/auth/token", self.addr)
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

    async fn receive(
        State(state): State<Arc<Mutex<TestSinkState>>>,
        headers: HeaderMap,
        Json(event): Json<IncomingSinkEvent>,
    ) -> Response {
        let auth_header = headers
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_owned());

        let mut guard = state.lock().await;
        guard.authorization_headers.push(auth_header);

        match guard.mode {
            ResponseMode::Accept => {
                // Store every event the sink is asked to accept, including
                // lightweight events, so tests can verify partial filters.
                guard.events.push(event);
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
                guard.events.push(event);
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
                    guard.events.push(event);
                    StatusCode::OK.into_response()
                }
            }
            ResponseMode::UnauthorizedAlways => {
                drop(guard);
                (StatusCode::UNAUTHORIZED, "unauthorized").into_response()
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
