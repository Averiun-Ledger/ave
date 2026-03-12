mod error;

use std::{
    collections::BTreeMap,
    collections::BTreeSet,
    collections::hash_map::DefaultHasher,
    hash::{Hash, Hasher},
    sync::Arc,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};

use async_trait::async_trait;
use ave_actors::Subscriber;
use ave_common::DataToSink;
use rand::{RngExt, rng};
use reqwest::Client;
use serde::Deserialize;
use tokio::{
    sync::{Mutex, Notify, RwLock, mpsc},
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, warn};

const TARGET: &str = "ave::core::sink";
const TRANSIENT_RETRY_BASE_DELAY_MS: u64 = 250;
const TOKEN_REFRESH_MARGIN: Duration = Duration::from_secs(30);
const MAX_ERROR_BODY_CHARS: usize = 512;
const MAX_ERROR_BODY_BYTES: usize = 2048;
const CIRCUIT_BREAKER_THRESHOLD: usize = 3;
const CIRCUIT_BREAKER_OPEN_FOR: Duration = Duration::from_secs(5);
const LOG_AGGREGATION_WINDOW: Duration = Duration::from_secs(30);

pub use error::SinkError;

use crate::{
    config::{SinkQueuePolicy, SinkRoutingStrategy, SinkServer},
    subject::sinkdata::{SinkDataEvent, SinkTypes},
};

#[derive(Deserialize, Debug, Clone)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: Option<String>,
    pub scope: Option<String>,
}

#[derive(Debug, Clone)]
struct CachedToken {
    response: TokenResponse,
    expires_at: Instant,
}

impl CachedToken {
    fn new(response: TokenResponse) -> Self {
        let expires_in = response.expires_in.max(0) as u64;
        let expires_at = Instant::now()
            .checked_add(Duration::from_secs(expires_in))
            .unwrap_or_else(Instant::now);

        Self {
            response,
            expires_at,
        }
    }

    fn auth_header(&self) -> String {
        format!(
            "{} {}",
            self.response.token_type, self.response.access_token
        )
    }

    fn expires_soon(&self) -> bool {
        let refresh_deadline = Instant::now()
            .checked_add(TOKEN_REFRESH_MARGIN)
            .unwrap_or_else(Instant::now);
        self.expires_at <= refresh_deadline
    }
}

#[derive(Debug, Clone)]
struct QueuedSinkEvent {
    data: Arc<DataToSink>,
    subject_id: String,
    schema_id: String,
}

#[derive(Clone)]
struct SinkRoute {
    destination: Arc<str>,
    events: BTreeSet<SinkTypes>,
    queues: Arc<[Arc<SinkQueue>]>,
    logs: Arc<SinkLogState>,
    routing_strategy: SinkRoutingStrategy,
    next_queue: Arc<AtomicUsize>,
}

struct SinkWorker {
    destination: Arc<str>,
    url_template: Arc<CompiledUrlTemplate>,
    requires_auth: bool,
    queue: Arc<SinkQueue>,
    breaker: Arc<SinkBreaker>,
    logs: Arc<SinkLogState>,
    shared: Arc<SinkSharedState>,
    client: Client,
    request_timeout: Duration,
    max_retries: usize,
}

struct SinkQueue {
    sender: mpsc::Sender<QueuedSinkEvent>,
    receiver: Mutex<mpsc::Receiver<QueuedSinkEvent>>,
    policy: SinkQueuePolicy,
    queued_events: AtomicUsize,
    dropped_events: AtomicUsize,
}

enum QueuePushOutcome {
    Enqueued,
    Closed { dropped_count: usize },
    DroppedNewest { dropped_count: usize },
    DroppedOldest { dropped_count: usize },
}

struct RateLimitedCounter {
    count: AtomicUsize,
    last_emit: Mutex<Instant>,
}

struct SinkLogState {
    retry_logs: RateLimitedCounter,
    breaker_logs: RateLimitedCounter,
    queue_drop_logs: RateLimitedCounter,
    shutdown_drop_logs: RateLimitedCounter,
}

#[derive(Default)]
struct CircuitBreakerState {
    mode: CircuitBreakerMode,
    consecutive_transient_failures: usize,
}

#[derive(Default)]
enum CircuitBreakerMode {
    #[default]
    Closed,
    OpenUntil(Instant),
    HalfOpen { probe_in_flight: bool },
}

struct SinkBreaker {
    state: Mutex<CircuitBreakerState>,
    notify: Notify,
}

struct SinkSharedState {
    token: RwLock<Option<CachedToken>>,
    token_refresh_lock: Mutex<()>,
    auth: String,
    username: String,
    password: String,
    api_key: Option<String>,
    shutdown: CancellationToken,
}

enum UrlTemplatePart {
    Literal(String),
    SubjectId,
    SchemaId,
}

struct CompiledUrlTemplate {
    parts: Vec<UrlTemplatePart>,
    base_len: usize,
}

impl CircuitBreakerState {
    fn register_success(&mut self) {
        self.mode = CircuitBreakerMode::Closed;
        self.consecutive_transient_failures = 0;
    }

    fn register_failure(&mut self, error: &SinkError) -> Option<Duration> {
        if matches!(self.mode, CircuitBreakerMode::HalfOpen { .. }) {
            if error.is_transient() {
                self.mode = CircuitBreakerMode::OpenUntil(
                    Instant::now() + CIRCUIT_BREAKER_OPEN_FOR,
                );
                self.consecutive_transient_failures = 0;
                return Some(CIRCUIT_BREAKER_OPEN_FOR);
            }

            self.mode = CircuitBreakerMode::Closed;
            self.consecutive_transient_failures = 0;
            return None;
        }

        if error.is_transient() {
            self.consecutive_transient_failures += 1;
            if self.consecutive_transient_failures >= CIRCUIT_BREAKER_THRESHOLD
            {
                self.mode = CircuitBreakerMode::OpenUntil(
                    Instant::now() + CIRCUIT_BREAKER_OPEN_FOR,
                );
                self.consecutive_transient_failures = 0;
                return Some(CIRCUIT_BREAKER_OPEN_FOR);
            }
        } else {
            self.consecutive_transient_failures = 0;
            self.mode = CircuitBreakerMode::Closed;
        }

        None
    }
}

impl SinkQueue {
    fn new(capacity: usize, policy: SinkQueuePolicy) -> Self {
        let (sender, receiver) = mpsc::channel(capacity.max(1));
        Self {
            sender,
            receiver: Mutex::new(receiver),
            policy,
            queued_events: AtomicUsize::new(0),
            dropped_events: AtomicUsize::new(0),
        }
    }

    async fn push(&self, event: QueuedSinkEvent) -> QueuePushOutcome {
        match self.sender.try_send(event) {
            Ok(()) => {
                self.queued_events.fetch_add(1, Ordering::Relaxed);
                QueuePushOutcome::Enqueued
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                let dropped_count =
                    self.dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
                QueuePushOutcome::Closed { dropped_count }
            }
            Err(mpsc::error::TrySendError::Full(event)) => {
                let dropped_count =
                    self.dropped_events.fetch_add(1, Ordering::Relaxed) + 1;
                match self.policy {
                    SinkQueuePolicy::DropNewest => {
                        QueuePushOutcome::DroppedNewest { dropped_count }
                    }
                    SinkQueuePolicy::DropOldest => {
                        let mut receiver = self.receiver.lock().await;
                        if receiver.try_recv().is_ok() {
                            self.queued_events.fetch_sub(1, Ordering::Relaxed);
                        }
                        drop(receiver);

                        match self.sender.try_send(event) {
                            Ok(()) => {
                                self.queued_events.fetch_add(1, Ordering::Relaxed);
                                QueuePushOutcome::DroppedOldest { dropped_count }
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => {
                                QueuePushOutcome::Closed { dropped_count }
                            }
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                QueuePushOutcome::DroppedNewest { dropped_count }
                            }
                        }
                    }
                }
            }
        }
    }

    async fn pop(
        &self,
        shutdown: &CancellationToken,
    ) -> Option<QueuedSinkEvent> {
        let mut receiver = self.receiver.lock().await;
        let event = tokio::select! {
            result = receiver.recv() => result,
            _ = shutdown.cancelled() => None,
        };
        if event.is_some() {
            self.queued_events.fetch_sub(1, Ordering::Relaxed);
        }
        event
    }

    fn pending_count(&self) -> usize {
        self.queued_events.load(Ordering::Relaxed)
    }
}

impl SinkBreaker {
    fn new() -> Self {
        Self {
            state: Mutex::new(CircuitBreakerState::default()),
            notify: Notify::new(),
        }
    }

    async fn acquire_delivery_slot(
        &self,
        server: &str,
        logs: &SinkLogState,
        shutdown: &CancellationToken,
    ) {
        loop {
            let wait_for = {
                let mut state = self.state.lock().await;
                match &mut state.mode {
                    CircuitBreakerMode::Closed => return,
                    CircuitBreakerMode::OpenUntil(until) => {
                        if let Some(wait_for) =
                            until.checked_duration_since(Instant::now())
                        {
                            Some(wait_for)
                        } else {
                            state.mode =
                                CircuitBreakerMode::HalfOpen { probe_in_flight: false };
                            None
                        }
                    }
                    CircuitBreakerMode::HalfOpen { probe_in_flight } => {
                        if *probe_in_flight {
                            None
                        } else {
                            *probe_in_flight = true;
                            return;
                        }
                    }
                }
            };

            if let Some(wait_for) = wait_for {
                logs.log_breaker_open(server, wait_for).await;
                tokio::select! {
                    _ = sleep(wait_for) => {}
                    _ = shutdown.cancelled() => return,
                }
            } else {
                tokio::select! {
                    _ = self.notify.notified() => {}
                    _ = shutdown.cancelled() => return,
                }
            }
        }
    }

    async fn register_success(&self) {
        let mut state = self.state.lock().await;
        state.register_success();
        drop(state);
        self.notify.notify_waiters();
    }

    async fn register_failure(&self, error: &SinkError) -> Option<Duration> {
        let mut state = self.state.lock().await;
        let open_for = state.register_failure(error);
        drop(state);
        self.notify.notify_waiters();
        open_for
    }
}

impl Drop for AveSinkInner {
    fn drop(&mut self) {
        self.shared.shutdown.cancel();

        for routes in self.sinks.values() {
            for route in routes {
                let dropped = route
                    .queues
                    .iter()
                    .map(|queue| queue.pending_count())
                    .sum::<usize>();
                if dropped > 0 {
                    route
                        .logs
                        .log_shutdown_drop(route.destination.as_ref(), dropped);
                }
            }
        }
    }
}

impl RateLimitedCounter {
    fn new() -> Self {
        let last_emit = Instant::now()
            .checked_sub(LOG_AGGREGATION_WINDOW)
            .unwrap_or_else(Instant::now);
        Self {
            count: AtomicUsize::new(0),
            last_emit: Mutex::new(last_emit),
        }
    }

    async fn record(&self) -> Option<usize> {
        self.count.fetch_add(1, Ordering::Relaxed);

        let now = Instant::now();
        let mut last_emit = self.last_emit.lock().await;
        if now.duration_since(*last_emit) < LOG_AGGREGATION_WINDOW {
            return None;
        }

        *last_emit = now;
        Some(self.count.swap(0, Ordering::Relaxed))
    }
}

impl SinkLogState {
    fn new() -> Self {
        Self {
            retry_logs: RateLimitedCounter::new(),
            breaker_logs: RateLimitedCounter::new(),
            queue_drop_logs: RateLimitedCounter::new(),
            shutdown_drop_logs: RateLimitedCounter::new(),
        }
    }

    async fn log_retry(
        &self,
        destination: &str,
        retry_in_ms: u64,
        error: &SinkError,
    ) {
        if let Some(retry_count) = self.retry_logs.record().await {
            warn!(
                target: TARGET,
                destination = %destination,
                retry_in_ms = retry_in_ms,
                retry_count = retry_count,
                error = %error,
                "Transient sink delivery failures, retrying with aggregation"
            );
        }
    }

    async fn log_breaker_open(&self, destination: &str, wait_for: Duration) {
        if let Some(delayed_events) = self.breaker_logs.record().await {
            warn!(
                target: TARGET,
                destination = %destination,
                wait_for_ms = wait_for.as_millis(),
                delayed_events = delayed_events,
                "Circuit breaker open, delaying sink deliveries"
            );
        }
    }

    async fn log_queue_drop(
        &self,
        destination: &str,
        policy: &str,
        dropped_count: usize,
    ) {
        if let Some(total_dropped) = self.queue_drop_logs.record().await {
            warn!(
                target: TARGET,
                destination = %destination,
                policy = %policy,
                dropped_count = dropped_count,
                total_dropped = total_dropped,
                "Sink queue overflow, dropping events with aggregation"
            );
        }
    }

    fn log_shutdown_drop(&self, destination: &str, dropped_count: usize) {
        let retry_counter = &self.shutdown_drop_logs;
        if let Ok(mut last_emit) = retry_counter.last_emit.try_lock() {
            let now = Instant::now();
            retry_counter.count.fetch_add(1, Ordering::Relaxed);
            if now.duration_since(*last_emit) >= LOG_AGGREGATION_WINDOW {
                *last_emit = now;
                let total_dropped =
                    retry_counter.count.swap(0, Ordering::Relaxed);
                warn!(
                    target: TARGET,
                    destination = %destination,
                    dropped_count = dropped_count,
                    total_dropped = total_dropped,
                    "Dropping queued sink events during shutdown"
                );
            }
        } else {
            retry_counter.count.fetch_add(1, Ordering::Relaxed);
        }
    }
}

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
        .map_err(|e| SinkError::AuthRequest(e.to_string()))?;

    let res = res
        .error_for_status()
        .map_err(|e| SinkError::AuthEndpoint(e.to_string()))?;

    res.json::<TokenResponse>()
        .await
        .map_err(|e| SinkError::TokenParse(e.to_string()))
}

// All fields behind a single Arc so that AveSink::clone is a cheap atomic
// increment instead of deep-cloning the sinks map and all strings.
struct AveSinkInner {
    sinks: BTreeMap<String, Vec<SinkRoute>>,
    shared: Arc<SinkSharedState>,
}

#[derive(Clone)]
pub struct AveSink(Arc<AveSinkInner>);

impl SinkSharedState {
    fn new(
        token: Option<TokenResponse>,
        auth: &str,
        username: &str,
        password: &str,
        api_key: Option<String>,
    ) -> Self {
        Self {
            token: RwLock::new(token.map(CachedToken::new)),
            token_refresh_lock: Mutex::new(()),
            auth: auth.to_owned(),
            username: username.to_owned(),
            password: password.to_owned(),
            api_key,
            shutdown: CancellationToken::new(),
        }
    }

    async fn current_fresh_auth_header(&self) -> Option<String> {
        let token = self.token.read().await;
        token
            .as_ref()
            .filter(|token| !token.expires_soon())
            .map(CachedToken::auth_header)
    }

    async fn set_token(&self, token: TokenResponse) {
        *self.token.write().await = Some(CachedToken::new(token));
    }

    async fn refresh_token(&self) -> Option<TokenResponse> {
        match obtain_token(&self.auth, &self.username, &self.password).await {
            Ok(t) => Some(t),
            Err(e) => {
                error!(
                    target: TARGET,
                    error = %e,
                    "Failed to obtain new auth token"
                );
                None
            }
        }
    }

    async fn refresh_bearer_auth_header(
        &self,
        stale_header: Option<&str>,
    ) -> Option<String> {
        let _refresh_guard = self.token_refresh_lock.lock().await;

        if let Some(current_header) = self.current_fresh_auth_header().await {
            if stale_header.is_none_or(|stale| stale != current_header) {
                return Some(current_header);
            }
        }

        let new_token = self.refresh_token().await?;
        let header =
            format!("{} {}", new_token.token_type, new_token.access_token);
        self.set_token(new_token).await;
        Some(header)
    }

    async fn ensure_bearer_auth_header(&self) -> Option<String> {
        match self.current_fresh_auth_header().await {
            Some(header) => Some(header),
            None => self.refresh_bearer_auth_header(None).await,
        }
    }
}

impl CompiledUrlTemplate {
    fn compile(template: &str) -> Self {
        let mut parts = Vec::new();
        let mut rest = template;
        let mut base_len = 0;

        while !rest.is_empty() {
            let subject_pos = rest.find("{{subject-id}}");
            let schema_pos = rest.find("{{schema-id}}");
            let next = match (subject_pos, schema_pos) {
                (Some(subject), Some(schema)) if subject <= schema => {
                    Some((subject, "{{subject-id}}", UrlTemplatePart::SubjectId))
                }
                (Some(_), Some(schema)) => {
                    Some((schema, "{{schema-id}}", UrlTemplatePart::SchemaId))
                }
                (Some(subject), None) => {
                    Some((subject, "{{subject-id}}", UrlTemplatePart::SubjectId))
                }
                (None, Some(schema)) => {
                    Some((schema, "{{schema-id}}", UrlTemplatePart::SchemaId))
                }
                (None, None) => None,
            };

            let Some((index, marker, token)) = next else {
                base_len += rest.len();
                parts.push(UrlTemplatePart::Literal(rest.to_owned()));
                break;
            };

            if index > 0 {
                let literal = &rest[..index];
                base_len += literal.len();
                parts.push(UrlTemplatePart::Literal(literal.to_owned()));
            }
            parts.push(token);
            rest = &rest[index + marker.len()..];
        }

        Self { parts, base_len }
    }

    fn render(&self, subject_id: &str, schema_id: &str) -> String {
        let mut rendered = String::with_capacity(
            self.base_len + subject_id.len() + schema_id.len(),
        );
        for part in &self.parts {
            match part {
                UrlTemplatePart::Literal(literal) => rendered.push_str(literal),
                UrlTemplatePart::SubjectId => rendered.push_str(subject_id),
                UrlTemplatePart::SchemaId => rendered.push_str(schema_id),
            }
        }
        rendered
    }
}

impl AveSink {
    fn build_routes(
        sinks: BTreeMap<String, Vec<SinkServer>>,
        shared: &Arc<SinkSharedState>,
    ) -> (BTreeMap<String, Vec<SinkRoute>>, Vec<SinkWorker>) {
        let mut routes_by_schema = BTreeMap::new();
        let mut workers = Vec::new();

        for (schema_id, servers) in sinks {
            let mut routes = Vec::with_capacity(servers.len());

            for server in servers {
                let destination: Arc<str> = Arc::from(format!(
                    "{}|schema={}|url={}",
                    server.server, schema_id, server.url
                ));
                let logs = Arc::new(SinkLogState::new());
                let breaker = Arc::new(SinkBreaker::new());
                let client = Client::builder()
                    .connect_timeout(Duration::from_millis(server.connect_timeout_ms))
                    .build()
                    .unwrap_or_else(|_| Client::new());
                let template = Arc::new(CompiledUrlTemplate::compile(&server.url));
                let queues: Vec<Arc<SinkQueue>> = (0..server.concurrency.max(1))
                    .map(|_| {
                        Arc::new(SinkQueue::new(
                            server.queue_capacity,
                            server.queue_policy.clone(),
                        ))
                    })
                    .collect();
                let queues: Arc<[Arc<SinkQueue>]> = queues.into();

                routes.push(SinkRoute {
                    destination: Arc::clone(&destination),
                    events: server.events.clone(),
                    queues: Arc::clone(&queues),
                    logs: Arc::clone(&logs),
                    routing_strategy: server.routing_strategy.clone(),
                    next_queue: Arc::new(AtomicUsize::new(0)),
                });

                for queue in queues.iter() {
                    workers.push(SinkWorker {
                        destination: Arc::clone(&destination),
                        url_template: Arc::clone(&template),
                        requires_auth: server.auth,
                        queue: Arc::clone(queue),
                        breaker: Arc::clone(&breaker),
                        logs: Arc::clone(&logs),
                        shared: Arc::clone(shared),
                        client: client.clone(),
                        request_timeout: Duration::from_millis(
                            server.request_timeout_ms,
                        ),
                        max_retries: server.max_retries,
                    });
                }
            }

            routes_by_schema.insert(schema_id, routes);
        }

        (routes_by_schema, workers)
    }

    pub fn new(
        sinks: BTreeMap<String, Vec<SinkServer>>,
        token: Option<TokenResponse>,
        auth: &str,
        username: &str,
        password: &str,
        api_key: Option<String>,
    ) -> Self {
        let shared = Arc::new(SinkSharedState::new(
            token,
            auth,
            username,
            password,
            api_key,
        ));
        let (routes, workers) = Self::build_routes(sinks, &shared);
        let sink = Self(Arc::new(AveSinkInner {
            sinks: routes,
            shared,
        }));

        for worker in workers {
            sink.spawn_worker(worker);
        }

        sink
    }

    fn route_wants_event(route: &SinkRoute, data: &DataToSink) -> bool {
        route.events.contains(&SinkTypes::All)
            || route.events.contains(&SinkTypes::from(data))
    }

    fn shard_index(subject_id: &str, shards: usize) -> usize {
        let mut hasher = DefaultHasher::new();
        subject_id.hash(&mut hasher);
        (hasher.finish() as usize) % shards.max(1)
    }

    fn route_queue_index(route: &SinkRoute, subject_id: &str) -> usize {
        match route.routing_strategy {
            SinkRoutingStrategy::OrderedBySubject => {
                Self::shard_index(subject_id, route.queues.len())
            }
            SinkRoutingStrategy::UnorderedRoundRobin => {
                route.next_queue.fetch_add(1, Ordering::Relaxed)
                    % route.queues.len().max(1)
            }
        }
    }

    #[cfg(test)]
    fn server_wants_event(server: &SinkServer, data: &DataToSink) -> bool {
        server.events.contains(&SinkTypes::All)
            || server.events.contains(&SinkTypes::from(data))
    }

    #[cfg(test)]
    fn build_url(template: &str, subject_id: &str, schema_id: &str) -> String {
        CompiledUrlTemplate::compile(template).render(subject_id, schema_id)
    }

    fn event_id_components(data: &DataToSink) -> (&'static str, &str, String, u64) {
        match &data.event {
            ave_common::DataToSinkEvent::Create {
                subject_id,
                schema_id,
                sn,
                ..
            } => ("create", subject_id.as_str(), schema_id.to_string(), *sn),
            ave_common::DataToSinkEvent::Fact {
                subject_id,
                schema_id,
                sn,
                ..
            } => ("fact", subject_id.as_str(), schema_id.to_string(), *sn),
            ave_common::DataToSinkEvent::Transfer {
                subject_id,
                schema_id,
                sn,
                ..
            } => ("transfer", subject_id.as_str(), schema_id.to_string(), *sn),
            ave_common::DataToSinkEvent::Confirm {
                subject_id,
                schema_id,
                sn,
                ..
            } => ("confirm", subject_id.as_str(), schema_id.to_string(), *sn),
            ave_common::DataToSinkEvent::Reject {
                subject_id,
                schema_id,
                sn,
                ..
            } => ("reject", subject_id.as_str(), schema_id.to_string(), *sn),
            ave_common::DataToSinkEvent::Eol {
                subject_id,
                schema_id,
                sn,
                ..
            } => ("eol", subject_id.as_str(), schema_id.to_string(), *sn),
        }
    }

    fn idempotency_key(data: &DataToSink) -> String {
        let (event_type, subject_id, schema_id, sn) =
            Self::event_id_components(data);
        format!("ave:{event_type}:{subject_id}:{schema_id}:{sn}")
    }

    fn truncate_error_body(body: &str) -> String {
        let sanitized = body.split_whitespace().collect::<Vec<_>>().join(" ");
        let mut chars = sanitized.chars();
        let truncated: String =
            chars.by_ref().take(MAX_ERROR_BODY_CHARS).collect();
        if chars.next().is_some() {
            format!("{truncated}...")
        } else {
            truncated
        }
    }

    fn format_http_error_message(status: u16, body: &str) -> String {
        if body.is_empty() {
            format!("HTTP {status} without response body")
        } else {
            format!("HTTP {status} body: {body}")
        }
    }

    fn is_retryable_request_error(error: &reqwest::Error) -> bool {
        let message = error.to_string().to_ascii_lowercase();
        error.is_timeout()
            || error.is_connect()
            || message.contains("connection reset")
            || message.contains("broken pipe")
    }

    async fn send_with_transient_retry(
        destination: &str,
        client: &Client,
        url: &str,
        data: &DataToSink,
        auth_header: Option<(&str, &str)>,
        logs: &SinkLogState,
        shutdown: &CancellationToken,
        request_timeout: Duration,
        max_retries: usize,
        idempotency_key: &str,
    ) -> Result<(), SinkError> {
        let mut attempt = 0;

        loop {
            if shutdown.is_cancelled() {
                return Err(SinkError::Shutdown);
            }

            match tokio::select! {
                result = Self::send_once(
                    client,
                    url,
                    data,
                    auth_header,
                    request_timeout,
                    idempotency_key,
                ) => result,
                _ = shutdown.cancelled() => Err(SinkError::Shutdown),
            } {
                Ok(()) => return Ok(()),
                Err(error)
                    if error.is_transient()
                        && attempt < max_retries =>
                {
                    let retry_in_ms = Self::jittered_retry_delay_ms(attempt);
                    attempt += 1;
                    logs.log_retry(destination, retry_in_ms, &error).await;

                    tokio::select! {
                        _ = sleep(Duration::from_millis(retry_in_ms)) => {}
                        _ = shutdown.cancelled() => return Err(SinkError::Shutdown),
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }

    fn jittered_retry_delay_ms(attempt: usize) -> u64 {
        let base_delay = TRANSIENT_RETRY_BASE_DELAY_MS
            .saturating_mul(1_u64 << attempt.min(20));
        let jitter = rng().random_range(0..=base_delay / 2);
        base_delay.saturating_add(jitter)
    }

    async fn read_limited_error_body(
        mut res: reqwest::Response,
    ) -> String {
        let mut body = Vec::new();
        let mut truncated = false;

        while body.len() < MAX_ERROR_BODY_BYTES {
            match res.chunk().await {
                Ok(Some(chunk)) => {
                    let remaining = MAX_ERROR_BODY_BYTES - body.len();
                    if chunk.len() > remaining {
                        body.extend_from_slice(&chunk[..remaining]);
                        truncated = true;
                        break;
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(error) => {
                    return format!("<failed to read error body: {error}>");
                }
            }
        }

        let mut text = String::from_utf8_lossy(&body).into_owned();
        if truncated {
            text.push_str("...");
        }
        text
    }

    async fn send_once(
        client: &Client,
        url: &str,
        data: &DataToSink,
        auth_header: Option<(&str, &str)>,
        request_timeout: Duration,
        idempotency_key: &str,
    ) -> Result<(), SinkError> {
        let req = client
            .post(url)
            .header("Idempotency-Key", idempotency_key)
            .timeout(request_timeout);
        let req = if let Some((header_name, header_value)) = auth_header {
            req.header(header_name, header_value).json(data)
        } else {
            req.json(data)
        };

        let res = req.send().await.map_err(|e| SinkError::SendRequest {
            message: e.to_string(),
            retryable: Self::is_retryable_request_error(&e),
        })?;

        let status = res.status();
        if !status.is_success() {
            let body = Self::read_limited_error_body(res).await;
            let body_excerpt = Self::truncate_error_body(&body);
            let message =
                Self::format_http_error_message(status.as_u16(), &body_excerpt);

            return Err(match status.as_u16() {
                401 => SinkError::Unauthorized,
                422 => SinkError::UnprocessableEntity { message },
                code => SinkError::HttpStatus {
                    status: code,
                    message,
                    retryable: matches!(code, 429 | 502 | 503 | 504),
                },
            });
        }

        Ok(())
    }

    async fn send_with_retry_on_401(
        shared: &SinkSharedState,
        destination: &str,
        client: &Client,
        url: &str,
        event: &DataToSink,
        server_requires_auth: bool,
        logs: &SinkLogState,
        request_timeout: Duration,
        max_retries: usize,
        idempotency_key: &str,
    ) -> Result<(), SinkError> {
        if shared.shutdown.is_cancelled() {
            return Err(SinkError::Shutdown);
        }

        // Build the auth header: either X-API-Key or Authorization (bearer token)
        let header: Option<(String, String)> = if server_requires_auth {
            if let Some(ref key) = shared.api_key {
                Some(("X-API-Key".to_owned(), key.clone()))
            } else {
                match tokio::select! {
                    result = shared.ensure_bearer_auth_header() => result,
                    _ = shared.shutdown.cancelled() => return Err(SinkError::Shutdown),
                } {
                    Some(bearer) => Some(("Authorization".to_owned(), bearer)),
                    None => {
                        error!(
                            target: TARGET,
                            url = %url,
                            "Sink requires bearer auth but no token could be obtained"
                        );
                        return Err(SinkError::Unauthorized);
                    }
                }
            }
        } else {
            None
        };

        let header_ref = header.as_ref().map(|(n, v)| (n.as_str(), v.as_str()));

        match Self::send_with_transient_retry(
            destination,
            client,
            url,
            event,
            header_ref,
            logs,
            &shared.shutdown,
            request_timeout,
            max_retries,
            idempotency_key,
        )
        .await
        {
            Ok(_) => {
                debug!(
                    target: TARGET,
                    url = %url,
                    "Data sent to sink successfully"
                );
                Ok(())
            }
            Err(SinkError::Shutdown) => Ok(()),
            Err(SinkError::UnprocessableEntity { message }) => {
                warn!(
                    target: TARGET,
                    url = %url,
                    error = %message,
                    "Sink rejected data format (422)"
                );
                Err(SinkError::UnprocessableEntity { message })
            }
            // Token refresh only applies to bearer token mode, not api_key
            Err(SinkError::Unauthorized)
                if server_requires_auth && shared.api_key.is_none() =>
            {
                warn!(
                    target: TARGET,
                    url = %url,
                    "Authentication failed, refreshing token"
                );

                if let Some(new_header) = tokio::select! {
                    result = shared.refresh_bearer_auth_header(
                        header.as_ref().map(|(_, value)| value.as_str()),
                    ) => result,
                    _ = shared.shutdown.cancelled() => return Err(SinkError::Shutdown),
                }
                {
                    debug!(target: TARGET, "Token refreshed, retrying request");

                    match Self::send_with_transient_retry(
                        destination,
                        client,
                        url,
                        event,
                        Some(("Authorization", &new_header)),
                        logs,
                        &shared.shutdown,
                        request_timeout,
                        max_retries,
                        idempotency_key,
                    )
                    .await
                    {
                        Ok(_) => {
                            debug!(
                                target: TARGET,
                                url = %url,
                                "Data sent to sink successfully after token refresh"
                            );
                            Ok(())
                        }
                        Err(SinkError::Shutdown) => Ok(()),
                        Err(SinkError::UnprocessableEntity { message }) => {
                            warn!(
                                target: TARGET,
                                url = %url,
                                error = %message,
                                "Sink rejected data format (422)"
                            );
                            Err(SinkError::UnprocessableEntity { message })
                        }
                        Err(e) => {
                            error!(
                                target: TARGET,
                                url = %url,
                                error = %e,
                                "Failed to send data to sink after token refresh"
                            );
                            Err(e)
                        }
                    }
                } else {
                    Err(SinkError::Unauthorized)
                }
            }
            Err(e) => {
                error!(
                    target: TARGET,
                    url = %url,
                    error = %e,
                    "Failed to send data to sink"
                );
                Err(e)
            }
        }
    }

    fn spawn_worker(&self, worker: SinkWorker) {
        tokio::spawn(async move {
            loop {
                if worker.shared.shutdown.is_cancelled() {
                    break;
                }

                worker
                    .breaker
                    .acquire_delivery_slot(
                        worker.destination.as_ref(),
                        worker.logs.as_ref(),
                        &worker.shared.shutdown,
                    )
                    .await;
                let Some(queued_event) =
                    worker.queue.pop(&worker.shared.shutdown).await
                else {
                    break;
                };

                if worker.shared.shutdown.is_cancelled() {
                    worker
                        .logs
                        .log_shutdown_drop(worker.destination.as_ref(), 1);
                    break;
                }

                let url = worker.url_template.render(
                    &queued_event.subject_id,
                    &queued_event.schema_id,
                );
                let idempotency_key =
                    Self::idempotency_key(queued_event.data.as_ref());

                match Self::send_with_retry_on_401(
                        worker.shared.as_ref(),
                        worker.destination.as_ref(),
                        &worker.client,
                        &url,
                        queued_event.data.as_ref(),
                        worker.requires_auth,
                        worker.logs.as_ref(),
                        worker.request_timeout,
                        worker.max_retries,
                        &idempotency_key,
                    )
                    .await
                {
                    Ok(()) => worker.breaker.register_success().await,
                    Err(SinkError::Shutdown) => {
                        worker
                            .logs
                            .log_shutdown_drop(worker.destination.as_ref(), 1);
                        break;
                    }
                    Err(error) => {
                        if let Some(open_for) =
                            worker.breaker.register_failure(&error).await
                        {
                            warn!(
                                target: TARGET,
                                destination = %worker.destination,
                                subject_id = %queued_event.subject_id,
                                schema_id = %queued_event.schema_id,
                                open_for_ms = open_for.as_millis(),
                                error = %error,
                                "Opening sink circuit breaker after repeated failures"
                            );
                        }
                    }
                }
            }
        });
    }
}

#[async_trait]
impl Subscriber<SinkDataEvent> for AveSink {
    async fn notify(&self, event: SinkDataEvent) {
        let data: Arc<DataToSink> = match event {
            SinkDataEvent::Event(data_to_sink) => Arc::from(data_to_sink),
            SinkDataEvent::State(..) => return,
        };

        let (subject_id, schema_id) = data.event.get_subject_schema();
        let Some(servers) = self.0.sinks.get(&schema_id) else {
            debug!(
                target: TARGET,
                schema_id = %schema_id,
                "No sink servers configured for schema"
            );
            return;
        };
        if servers.is_empty() {
            return;
        }

        debug!(
            target: TARGET,
            subject_id = %subject_id,
            schema_id = %schema_id,
            servers_count = servers.len(),
            "Processing sink event"
        );

        for route in servers {
            if !Self::route_wants_event(route, data.as_ref()) {
                continue;
            }

            let shard_index = Self::route_queue_index(route, &subject_id);
            match route.queues[shard_index]
                .push(QueuedSinkEvent {
                    data: Arc::clone(&data),
                    subject_id: subject_id.clone(),
                    schema_id: schema_id.clone(),
                })
                .await
            {
                QueuePushOutcome::Enqueued => {}
                QueuePushOutcome::Closed { dropped_count } => {
                    route
                        .logs
                        .log_queue_drop(
                            route.destination.as_ref(),
                            "closed",
                            dropped_count,
                        )
                        .await;
                }
                QueuePushOutcome::DroppedNewest { dropped_count } => {
                    route
                        .logs
                        .log_queue_drop(
                            route.destination.as_ref(),
                            "drop_newest",
                            dropped_count,
                        )
                        .await;
                }
                QueuePushOutcome::DroppedOldest { dropped_count } => {
                    route
                        .logs
                        .log_queue_drop(
                            route.destination.as_ref(),
                            "drop_oldest",
                            dropped_count,
                        )
                        .await;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{
        collections::BTreeSet,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
    };

    use ave_common::{DataToSinkEvent, SchemaType};
    use axum::{
        Json, Router,
        extract::{Path, Request},
        http::{HeaderMap, StatusCode},
        middleware::{self, Next},
        response::Response,
        routing::post,
    };
    use serde_json::json;
    use tokio::{
        net::TcpListener,
        sync::Mutex,
        task::JoinHandle,
        time::{sleep, timeout},
    };

    struct TestServer {
        base_url: String,
        task: JoinHandle<()>,
    }

    impl TestServer {
        async fn spawn(router: Router) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind test listener");
            let addr = listener.local_addr().expect("get test listener addr");
            let task = tokio::spawn(async move {
                axum::serve(listener, router)
                    .await
                    .expect("run test server");
            });

            Self {
                base_url: format!("http://{addr}"),
                task,
            }
        }
    }

    impl Drop for TestServer {
        fn drop(&mut self) {
            self.task.abort();
        }
    }

    fn sample_token(access_token: &str, expires_in: i64) -> TokenResponse {
        TokenResponse {
            access_token: access_token.to_owned(),
            token_type: "Bearer".to_owned(),
            expires_in,
            refresh_token: None,
            scope: None,
        }
    }

    fn sample_data(schema_id: SchemaType) -> DataToSink {
        DataToSink {
            event: DataToSinkEvent::Create {
                governance_id: None,
                subject_id: "subject-1".to_owned(),
                owner: "owner-1".to_owned(),
                schema_id,
                namespace: "ns.test".to_owned(),
                sn: 1,
                gov_version: 1,
                state: json!({ "status": "ok" }),
            },
            public_key: "pubkey-1".to_owned(),
            event_request_timestamp: 1,
            event_ledger_timestamp: 2,
            sink_timestamp: 3,
        }
    }

    fn sample_server(
        url: &str,
        auth: bool,
        events: impl IntoIterator<Item = SinkTypes>,
    ) -> SinkServer {
        sample_server_with(url, auth, events, 1, 32, SinkQueuePolicy::DropNewest, SinkRoutingStrategy::OrderedBySubject, 2_000, 10_000, 3)
    }

    fn sample_server_with(
        url: &str,
        auth: bool,
        events: impl IntoIterator<Item = SinkTypes>,
        concurrency: usize,
        queue_capacity: usize,
        queue_policy: SinkQueuePolicy,
        routing_strategy: SinkRoutingStrategy,
        connect_timeout_ms: u64,
        request_timeout_ms: u64,
        max_retries: usize,
    ) -> SinkServer {
        SinkServer {
            server: "test-sink".to_owned(),
            events: events.into_iter().collect::<BTreeSet<_>>(),
            url: url.to_owned(),
            auth,
            concurrency,
            queue_capacity,
            queue_policy,
            routing_strategy,
            connect_timeout_ms,
            request_timeout_ms,
            max_retries,
        }
    }

    fn build_sink(
        sink_url: &str,
        auth_url: &str,
        token: Option<TokenResponse>,
        auth: bool,
        events: impl IntoIterator<Item = SinkTypes>,
    ) -> AveSink {
        let mut sinks = BTreeMap::new();
        sinks.insert(
            "schema-a".to_owned(),
            vec![sample_server(sink_url, auth, events)],
        );

        AveSink::new(sinks, token, auth_url, "user-1", "pass-1", None)
    }

    fn build_sink_with_servers(
        schema_id: &str,
        servers: Vec<SinkServer>,
        auth_url: &str,
        token: Option<TokenResponse>,
    ) -> AveSink {
        let mut sinks = BTreeMap::new();
        sinks.insert(schema_id.to_owned(), servers);
        AveSink::new(sinks, token, auth_url, "user-1", "pass-1", None)
    }

    const TEST_WAIT_TIMEOUT: Duration = Duration::from_secs(10);
    const TEST_POLL_INTERVAL: Duration = Duration::from_millis(20);
    const TEST_STABLE_POLLS: usize = 5;

    async fn wait_until<F>(description: &str, mut condition: F)
    where
        F: FnMut() -> bool,
    {
        timeout(TEST_WAIT_TIMEOUT, async {
            loop {
                if condition() {
                    break;
                }
                sleep(TEST_POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("{description}: {error}"));
    }

    async fn wait_for_counter_at_least(
        counter: &AtomicUsize,
        minimum: usize,
        description: &str,
    ) {
        wait_until(description, || counter.load(Ordering::SeqCst) >= minimum)
            .await;
    }

    async fn wait_for_counter_stable(
        counter: &AtomicUsize,
        minimum: usize,
        description: &str,
    ) -> usize {
        timeout(TEST_WAIT_TIMEOUT, async {
            let mut last_seen = counter.load(Ordering::SeqCst);
            let mut stable_polls = 0usize;

            loop {
                let current = counter.load(Ordering::SeqCst);
                if current >= minimum {
                    if current == last_seen {
                        stable_polls += 1;
                    } else {
                        stable_polls = 0;
                    }

                    if stable_polls >= TEST_STABLE_POLLS {
                        return current;
                    }
                } else {
                    stable_polls = 0;
                }

                last_seen = current;
                sleep(TEST_POLL_INTERVAL).await;
            }
        })
        .await
        .unwrap_or_else(|error| panic!("{description}: {error}"))
    }

    async fn count_requests(
        counter: Arc<AtomicUsize>,
        request: Request,
        next: Next,
    ) -> Response {
        counter.fetch_add(1, Ordering::SeqCst);
        next.run(request).await
    }

    #[test]
    fn build_url_and_event_filter_work() {
        let data = sample_data(SchemaType::Type("schema-a".to_owned()));
        let accepts_create = sample_server(
            "http://localhost/sink/{{subject-id}}/{{schema-id}}",
            false,
            [SinkTypes::Create],
        );
        let rejects_create =
            sample_server("http://localhost/ignored", false, [SinkTypes::Fact]);

        assert!(AveSink::server_wants_event(&accepts_create, &data));
        assert!(!AveSink::server_wants_event(&rejects_create, &data));
        assert_eq!(
            AveSink::build_url(&accepts_create.url, "subject-1", "schema-a",),
            "http://localhost/sink/subject-1/schema-a"
        );
    }

    #[test]
    fn route_queue_index_round_robin_ignores_subject() {
        let route = SinkRoute {
            destination: Arc::from("test-sink|schema=schema-a|url=http://localhost"),
            events: BTreeSet::from([SinkTypes::All]),
            queues: vec![
                Arc::new(SinkQueue::new(4, SinkQueuePolicy::DropNewest)),
                Arc::new(SinkQueue::new(4, SinkQueuePolicy::DropNewest)),
            ]
            .into(),
            logs: Arc::new(SinkLogState::new()),
            routing_strategy: SinkRoutingStrategy::UnorderedRoundRobin,
            next_queue: Arc::new(AtomicUsize::new(0)),
        };

        assert_eq!(AveSink::route_queue_index(&route, "subject-1"), 0);
        assert_eq!(AveSink::route_queue_index(&route, "subject-1"), 1);
        assert_eq!(AveSink::route_queue_index(&route, "subject-2"), 0);
        assert_eq!(AveSink::route_queue_index(&route, "subject-2"), 1);
    }

    #[tokio::test]
    async fn closing_queue_wakes_waiting_workers() {
        let queue = Arc::new(SinkQueue::new(4, SinkQueuePolicy::DropNewest));
        let shutdown = CancellationToken::new();
        let waiter = {
            let queue = Arc::clone(&queue);
            let shutdown = shutdown.clone();
            tokio::spawn(async move { queue.pop(&shutdown).await })
        };

        sleep(Duration::from_millis(20)).await;
        shutdown.cancel();

        let result = timeout(Duration::from_secs(1), waiter)
            .await
            .expect("queue waiter should wake up")
            .expect("queue waiter task should finish");
        assert!(result.is_none());
    }

    #[test]
    fn closed_queue_rejects_new_events_even_with_drop_oldest_policy() {
        let queue = SinkQueue::new(2, SinkQueuePolicy::DropOldest);
        let mut receiver =
            queue.receiver.try_lock().expect("queue receiver lock");
        receiver.close();
        drop(receiver);

        let push = futures::executor::block_on(queue.push(QueuedSinkEvent {
            data: Arc::new(sample_data(SchemaType::Type("schema-a".to_owned()))),
            subject_id: "subject-1".to_owned(),
            schema_id: "schema-a".to_owned(),
        }));

        assert!(matches!(push, QueuePushOutcome::Closed { .. }));
    }

    #[tokio::test]
    async fn shutdown_cancels_retry_backoff() {
        let shared = Arc::new(SinkSharedState::new(
            None,
            "",
            "",
            "",
            None,
        ));
        let logs = SinkLogState::new();
        let client = Client::new();
        let server = TestServer::spawn(Router::new().route(
            "/sink",
            post(|| async { StatusCode::SERVICE_UNAVAILABLE }),
        ))
        .await;
        let data = sample_data(SchemaType::Type("schema-a".to_owned()));

        let retry = tokio::spawn({
            let shared = Arc::clone(&shared);
            let url = format!("{}/sink", server.base_url);
            async move {
                AveSink::send_with_transient_retry(
                    "test-sink|schema=schema-a|url=http://localhost/sink",
                    &client,
                    &url,
                    &data,
                    None,
                    &logs,
                    &shared.shutdown,
                    Duration::from_secs(10),
                    3,
                    "idempotency-key",
                )
                .await
            }
        });

        sleep(Duration::from_millis(20)).await;
        shared.shutdown.cancel();

        let result = timeout(Duration::from_secs(1), retry)
            .await
            .expect("retry loop should stop on shutdown")
            .expect("retry task should finish");
        assert!(matches!(result, Err(SinkError::Shutdown)));
    }

    #[tokio::test]
    async fn send_once_captures_truncated_error_body() {
        let long_body = "invalid payload ".repeat(80);
        let server = TestServer::spawn(Router::new().route(
            "/unprocessable",
            post({
                let long_body = long_body.clone();
                move || {
                    let long_body = long_body.clone();
                    async move { (StatusCode::UNPROCESSABLE_ENTITY, long_body) }
                }
            }),
        ))
        .await;

        let result = AveSink::send_once(
            &Client::new(),
            &format!("{}/unprocessable", server.base_url),
            &sample_data(SchemaType::Type("schema-a".to_owned())),
            None,
            Duration::from_secs(10),
            "idempotency-key",
        )
        .await;

        match result {
            Err(SinkError::UnprocessableEntity { message }) => {
                assert!(message.contains("HTTP 422 body:"));
                assert!(message.contains("invalid payload"));
                assert!(message.len() < long_body.len());
            }
            other => panic!("unexpected result: {other:?}"),
        }
    }

    #[tokio::test]
    async fn send_once_sets_idempotency_key_header() {
        let seen_idempotency = Arc::new(Mutex::new(Vec::new()));
        let server = TestServer::spawn(Router::new().route(
            "/sink",
            post({
                let seen_idempotency = Arc::clone(&seen_idempotency);
                move |headers: HeaderMap, Json(_payload): Json<DataToSink>| {
                    let seen_idempotency = Arc::clone(&seen_idempotency);
                    async move {
                        seen_idempotency.lock().await.push(
                            headers
                                .get("idempotency-key")
                                .and_then(|value| value.to_str().ok())
                                .map(str::to_owned),
                        );
                        StatusCode::OK
                    }
                }
            }),
        ))
        .await;

        let data = sample_data(SchemaType::Type("schema-a".to_owned()));
        let key = AveSink::idempotency_key(&data);
        let result = AveSink::send_once(
            &Client::new(),
            &format!("{}/sink", server.base_url),
            &data,
            None,
            Duration::from_secs(10),
            &key,
        )
        .await;

        assert!(result.is_ok());
        assert_eq!(seen_idempotency.lock().await.as_slice(), &[Some(key)]);
    }

    #[tokio::test]
    async fn notify_honors_configured_max_retries() {
        let sink_calls = Arc::new(AtomicUsize::new(0));
        let server = TestServer::spawn(Router::new().route(
            "/sink/{subject_id}/{schema_id}",
            post({
                let sink_calls = Arc::clone(&sink_calls);
                move |_path: Path<(String, String)>,
                      Json(_payload): Json<DataToSink>| {
                    let sink_calls = Arc::clone(&sink_calls);
                    async move {
                        sink_calls.fetch_add(1, Ordering::SeqCst);
                        StatusCode::SERVICE_UNAVAILABLE
                    }
                }
            }),
        ))
        .await;

        let sink = build_sink_with_servers(
            "schema-a",
            vec![sample_server_with(
                &format!(
                    "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                    server.base_url
                ),
                false,
                [SinkTypes::Create],
                1,
                32,
                SinkQueuePolicy::DropNewest,
                SinkRoutingStrategy::OrderedBySubject,
                2_000,
                1_000,
                1,
            )],
            "",
            None,
        );

        sink.notify(SinkDataEvent::Event(Box::new(sample_data(
            SchemaType::Type("schema-a".to_owned()),
        ))))
        .await;

        let attempts = wait_for_counter_stable(
            sink_calls.as_ref(),
            2,
            "sink retries did not stabilize after max_retries",
        )
        .await;
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn notify_honors_configured_request_timeout() {
        let sink_calls = Arc::new(AtomicUsize::new(0));
        let server = TestServer::spawn(
            Router::new()
                .route(
                    "/sink/{subject_id}/{schema_id}",
                    post(
                        move |_path: Path<(String, String)>,
                              Json(_payload): Json<DataToSink>| async move {
                            sleep(Duration::from_millis(150)).await;
                            StatusCode::OK
                        },
                    ),
                )
                .layer(middleware::from_fn({
                    let sink_calls = Arc::clone(&sink_calls);
                    move |request: Request, next: Next| {
                        count_requests(Arc::clone(&sink_calls), request, next)
                    }
                })),
        )
        .await;

        let sink = build_sink_with_servers(
            "schema-a",
            vec![sample_server_with(
                &format!(
                    "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                    server.base_url
                ),
                false,
                [SinkTypes::Create],
                1,
                32,
                SinkQueuePolicy::DropNewest,
                SinkRoutingStrategy::OrderedBySubject,
                2_000,
                25,
                1,
            )],
            "",
            None,
        );

        sink.notify(SinkDataEvent::Event(Box::new(sample_data(
            SchemaType::Type("schema-a".to_owned()),
        ))))
        .await;

        let attempts = wait_for_counter_stable(
            sink_calls.as_ref(),
            2,
            "sink timeout retries did not stabilize",
        )
        .await;
        assert_eq!(attempts, 2);
    }

    #[tokio::test]
    async fn notify_round_robin_allows_parallel_delivery() {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let sink_calls = Arc::new(AtomicUsize::new(0));

        let server = TestServer::spawn(Router::new().route(
            "/sink/{subject_id}/{schema_id}",
            post({
                let active = Arc::clone(&active);
                let max_active = Arc::clone(&max_active);
                let sink_calls = Arc::clone(&sink_calls);
                move |_path: Path<(String, String)>,
                      Json(_payload): Json<DataToSink>| {
                    let active = Arc::clone(&active);
                    let max_active = Arc::clone(&max_active);
                    let sink_calls = Arc::clone(&sink_calls);
                    async move {
                        sink_calls.fetch_add(1, Ordering::SeqCst);
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        loop {
                            let observed = max_active.load(Ordering::SeqCst);
                            if current <= observed {
                                break;
                            }
                            if max_active
                                .compare_exchange(
                                    observed,
                                    current,
                                    Ordering::SeqCst,
                                    Ordering::SeqCst,
                                )
                                .is_ok()
                            {
                                break;
                            }
                        }
                        sleep(Duration::from_millis(100)).await;
                        active.fetch_sub(1, Ordering::SeqCst);
                        StatusCode::OK
                    }
                }
            }),
        ))
        .await;

        let sink = build_sink_with_servers(
            "schema-a",
            vec![sample_server_with(
                &format!(
                    "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                    server.base_url
                ),
                false,
                [SinkTypes::Create],
                2,
                32,
                SinkQueuePolicy::DropNewest,
                SinkRoutingStrategy::UnorderedRoundRobin,
                2_000,
                1_000,
                0,
            )],
            "",
            None,
        );

        let mut first = sample_data(SchemaType::Type("schema-a".to_owned()));
        if let DataToSinkEvent::Create { subject_id, .. } = &mut first.event {
            *subject_id = "subject-1".to_owned();
        }
        let mut second = sample_data(SchemaType::Type("schema-a".to_owned()));
        if let DataToSinkEvent::Create { subject_id, sn, .. } = &mut second.event {
            *subject_id = "subject-2".to_owned();
            *sn = 2;
        }

        sink.notify(SinkDataEvent::Event(Box::new(first))).await;
        sink.notify(SinkDataEvent::Event(Box::new(second))).await;

        wait_for_counter_at_least(
            sink_calls.as_ref(),
            2,
            "parallel sink deliveries were not observed",
        )
        .await;
        wait_for_counter_at_least(
            max_active.as_ref(),
            2,
            "parallel sink concurrency did not increase",
        )
        .await;
        assert!(max_active.load(Ordering::SeqCst) >= 2);
    }

    #[tokio::test]
    async fn notify_bootstraps_token_when_missing() {
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let sink_calls = Arc::new(AtomicUsize::new(0));
        let seen_auth = Arc::new(Mutex::new(Vec::new()));
        let seen_paths = Arc::new(Mutex::new(Vec::new()));

        let server = TestServer::spawn(
            Router::new()
                .route(
                    "/auth",
                    post({
                        let auth_calls = Arc::clone(&auth_calls);
                        move || {
                            let auth_calls = Arc::clone(&auth_calls);
                            async move {
                                auth_calls.fetch_add(1, Ordering::SeqCst);
                                Json(json!({
                                    "access_token": "fresh-token",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                    "refresh_token": null,
                                    "scope": null
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/sink/{subject_id}/{schema_id}",
                    post({
                        let sink_calls = Arc::clone(&sink_calls);
                        let seen_auth = Arc::clone(&seen_auth);
                        let seen_paths = Arc::clone(&seen_paths);
                        move |Path((subject_id, schema_id)): Path<(String, String)>,
                              headers: HeaderMap,
                              Json(_payload): Json<DataToSink>| {
                            let sink_calls = Arc::clone(&sink_calls);
                            let seen_auth = Arc::clone(&seen_auth);
                            let seen_paths = Arc::clone(&seen_paths);
                            async move {
                                sink_calls.fetch_add(1, Ordering::SeqCst);
                                seen_auth.lock().await.push(
                                    headers
                                        .get("authorization")
                                        .and_then(|value| value.to_str().ok())
                                        .map(str::to_owned),
                                );
                                seen_paths
                                    .lock()
                                    .await
                                    .push((subject_id, schema_id));
                                StatusCode::OK
                            }
                        }
                    }),
                ),
        )
        .await;

        let sink = build_sink(
            &format!(
                "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                server.base_url
            ),
            &format!("{}/auth", server.base_url),
            None,
            true,
            [SinkTypes::Create],
        );

        sink.notify(SinkDataEvent::Event(Box::new(sample_data(
            SchemaType::Type("schema-a".to_owned()),
        ))))
        .await;

        let auth_attempts = wait_for_counter_stable(
            auth_calls.as_ref(),
            1,
            "auth bootstrap call did not complete",
        )
        .await;
        let sink_attempts = wait_for_counter_stable(
            sink_calls.as_ref(),
            1,
            "sink bootstrap delivery did not complete",
        )
        .await;
        assert_eq!(auth_attempts, 1);
        assert_eq!(sink_attempts, 1);
        assert_eq!(
            seen_auth.lock().await.as_slice(),
            &[Some("Bearer fresh-token".to_owned())]
        );
        assert_eq!(
            seen_paths.lock().await.as_slice(),
            &[("subject-1".to_owned(), "schema-a".to_owned())]
        );
    }

    #[tokio::test]
    async fn notify_refreshes_expiring_token_before_send() {
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let seen_auth = Arc::new(Mutex::new(Vec::new()));

        let server = TestServer::spawn(
            Router::new()
                .route(
                    "/auth",
                    post({
                        let auth_calls = Arc::clone(&auth_calls);
                        move || {
                            let auth_calls = Arc::clone(&auth_calls);
                            async move {
                                auth_calls.fetch_add(1, Ordering::SeqCst);
                                Json(json!({
                                    "access_token": "refreshed-token",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                    "refresh_token": null,
                                    "scope": null
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/sink/{subject_id}/{schema_id}",
                    post({
                        let seen_auth = Arc::clone(&seen_auth);
                        move |_path: Path<(String, String)>,
                              headers: HeaderMap,
                              Json(_payload): Json<DataToSink>| {
                            let seen_auth = Arc::clone(&seen_auth);
                            async move {
                                seen_auth.lock().await.push(
                                    headers
                                        .get("authorization")
                                        .and_then(|value| value.to_str().ok())
                                        .map(str::to_owned),
                                );
                                StatusCode::OK
                            }
                        }
                    }),
                ),
        )
        .await;

        let sink = build_sink(
            &format!(
                "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                server.base_url
            ),
            &format!("{}/auth", server.base_url),
            Some(sample_token("stale-token", 1)),
            true,
            [SinkTypes::Create],
        );

        sink.notify(SinkDataEvent::Event(Box::new(sample_data(
            SchemaType::Type("schema-a".to_owned()),
        ))))
        .await;

        let auth_attempts = wait_for_counter_stable(
            auth_calls.as_ref(),
            1,
            "token refresh did not complete",
        )
        .await;
        assert_eq!(auth_attempts, 1);
        assert_eq!(
            seen_auth.lock().await.as_slice(),
            &[Some("Bearer refreshed-token".to_owned())]
        );
    }

    #[tokio::test]
    async fn notify_refreshes_after_401_and_retries() {
        let auth_calls = Arc::new(AtomicUsize::new(0));
        let sink_calls = Arc::new(AtomicUsize::new(0));
        let seen_auth = Arc::new(Mutex::new(Vec::new()));

        let server = TestServer::spawn(
            Router::new()
                .route(
                    "/auth",
                    post({
                        let auth_calls = Arc::clone(&auth_calls);
                        move || {
                            let auth_calls = Arc::clone(&auth_calls);
                            async move {
                                auth_calls.fetch_add(1, Ordering::SeqCst);
                                Json(json!({
                                    "access_token": "fresh-after-401",
                                    "token_type": "Bearer",
                                    "expires_in": 3600,
                                    "refresh_token": null,
                                    "scope": null
                                }))
                            }
                        }
                    }),
                )
                .route(
                    "/sink/{subject_id}/{schema_id}",
                    post({
                        let sink_calls = Arc::clone(&sink_calls);
                        let seen_auth = Arc::clone(&seen_auth);
                        move |_path: Path<(String, String)>,
                              headers: HeaderMap,
                              Json(_payload): Json<DataToSink>| {
                            let sink_calls = Arc::clone(&sink_calls);
                            let seen_auth = Arc::clone(&seen_auth);
                            async move {
                                let attempt =
                                    sink_calls.fetch_add(1, Ordering::SeqCst)
                                        + 1;
                                let header = headers
                                    .get("authorization")
                                    .and_then(|value| value.to_str().ok())
                                    .map(str::to_owned);
                                seen_auth.lock().await.push(header.clone());

                                match (attempt, header.as_deref()) {
                                    (1, Some("Bearer stale-token")) => {
                                        StatusCode::UNAUTHORIZED
                                    }
                                    (2, Some("Bearer fresh-after-401")) => {
                                        StatusCode::OK
                                    }
                                    _ => StatusCode::BAD_REQUEST,
                                }
                            }
                        }
                    }),
                ),
        )
        .await;

        let sink = build_sink(
            &format!(
                "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                server.base_url
            ),
            &format!("{}/auth", server.base_url),
            Some(sample_token("stale-token", 3600)),
            true,
            [SinkTypes::Create],
        );

        sink.notify(SinkDataEvent::Event(Box::new(sample_data(
            SchemaType::Type("schema-a".to_owned()),
        ))))
        .await;

        let auth_attempts = wait_for_counter_stable(
            auth_calls.as_ref(),
            1,
            "401 token refresh did not complete",
        )
        .await;
        let sink_attempts = wait_for_counter_stable(
            sink_calls.as_ref(),
            2,
            "401 retry sequence did not stabilize",
        )
        .await;
        assert_eq!(auth_attempts, 1);
        assert_eq!(sink_attempts, 2);
        assert_eq!(
            seen_auth.lock().await.as_slice(),
            &[
                Some("Bearer stale-token".to_owned()),
                Some("Bearer fresh-after-401".to_owned()),
            ]
        );
    }

    #[tokio::test]
    async fn notify_retries_transient_sink_errors() {
        let sink_calls = Arc::new(AtomicUsize::new(0));

        let server = TestServer::spawn(Router::new().route(
            "/sink/{subject_id}/{schema_id}",
            post({
                let sink_calls = Arc::clone(&sink_calls);
                move |_path: Path<(String, String)>,
                      Json(_payload): Json<DataToSink>| {
                    let sink_calls = Arc::clone(&sink_calls);
                    async move {
                        let attempt =
                            sink_calls.fetch_add(1, Ordering::SeqCst) + 1;
                        if attempt < 3 {
                            StatusCode::SERVICE_UNAVAILABLE
                        } else {
                            StatusCode::OK
                        }
                    }
                }
            }),
        ))
        .await;

        let sink = build_sink(
            &format!(
                "{}/sink/{{{{subject-id}}}}/{{{{schema-id}}}}",
                server.base_url
            ),
            "",
            None,
            false,
            [SinkTypes::Create],
        );

        sink.notify(SinkDataEvent::Event(Box::new(sample_data(
            SchemaType::Type("schema-a".to_owned()),
        ))))
        .await;

        let attempts = wait_for_counter_stable(
            sink_calls.as_ref(),
            3,
            "transient sink retries did not stabilize",
        )
        .await;
        assert_eq!(attempts, 3);
    }
}
