//! Minimal HTTP sink for HTTP-layer integration tests.
//!
//! This is a stripped-down counterpart of `core/tests/common/test_sink.rs`.
//! It only stores raw deliveries and supports the response modes needed to
//! exercise the HTTP surface of sinks: acceptance, server errors, client
//! errors and slow responses.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use ave_bridge::ave_common::IncomingSinkEvent;
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
    /// Wait `ms` milliseconds before returning HTTP 200.
    Timeout(u64),
}

struct TestSinkState {
    events: Vec<IncomingSinkEvent>,
    mode: ResponseMode,
}

/// A real HTTP sink used by HTTP integration tests.
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
            .route("/events", post(Self::receive))
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

    /// Change the response mode for subsequent `/events` requests.
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

    /// Return a snapshot of the events received so far.
    pub async fn snapshot(&self) -> Vec<IncomingSinkEvent> {
        self.state.lock().await.events.clone()
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
        let mut guard = state.lock().await;
        match guard.mode {
            ResponseMode::Accept => {
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
                guard.events.push(event);
                drop(guard);
                tokio::time::sleep(Duration::from_millis(ms)).await;
                StatusCode::OK.into_response()
            }
        }
    }
}
