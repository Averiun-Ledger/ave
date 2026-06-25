use std::{net::SocketAddr, sync::Arc, time::Duration};

use ave_common::IncomingSinkEvent;
use axum::{
    Json, Router,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
};
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
    /// Return HTTP 200 with a non-JSON body without storing the event.
    Malformed,
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
}

struct TestSinkState {
    events: Vec<IncomingSinkEvent>,
    mode: ResponseMode,
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
        }));
        let app = Router::new()
            .route("/events", post(Self::receive).get(Self::health))
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

    /// Change the response mode for subsequent requests.
    pub async fn set_mode(&self, mode: ResponseMode) {
        self.state.lock().await.mode = mode;
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

    /// Remove the last `n` events received so far.
    pub async fn remove_last(&self, n: usize) {
        let mut state = self.state.lock().await;
        let len = state.events.len();
        state.events.truncate(len.saturating_sub(n));
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

    async fn receive(
        State(state): State<Arc<Mutex<TestSinkState>>>,
        Json(event): Json<IncomingSinkEvent>,
    ) -> Response {
        let mode = state.lock().await.mode;
        match mode {
            ResponseMode::Accept => {
                // Store every event the sink is asked to accept, including
                // lightweight events, so tests can verify partial filters.
                state.lock().await.events.push(event);
                StatusCode::OK.into_response()
            }
            ResponseMode::ServerError => {
                (StatusCode::INTERNAL_SERVER_ERROR, "server error")
                    .into_response()
            }
            ResponseMode::ClientError => {
                (StatusCode::UNPROCESSABLE_ENTITY, "client error")
                    .into_response()
            }
            ResponseMode::Malformed => {
                (StatusCode::OK, "this is not json").into_response()
            }
            ResponseMode::Timeout(ms) => {
                // Store the event before sleeping so the slow response still
                // counts as a successful delivery.
                state.lock().await.events.push(event);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                StatusCode::OK.into_response()
            }
            ResponseMode::Drop => {
                // Never return: the connection hangs just like a crashed sink.
                std::future::pending::<()>().await;
                unreachable!()
            }
            ResponseMode::HealthOkDeliveryFail => {
                // Healthcheck passes but delivery fails: simulate a flapping sink.
                (StatusCode::INTERNAL_SERVER_ERROR, "delivery failed")
                    .into_response()
            }
        }
    }

    async fn health() -> StatusCode {
        StatusCode::OK
    }
}
