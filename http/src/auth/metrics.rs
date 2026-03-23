use std::sync::Arc;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        counter::Counter, family::Family, gauge::Gauge,
        histogram::Histogram,
    },
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PoolLabels {
    pool: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct OperationLabels {
    operation: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    request_kind: &'static str,
    result: &'static str,
}

#[derive(Debug)]
pub struct AuthPrometheusMetrics {
    lock_wait_seconds: Family<PoolLabels, Histogram, fn() -> Histogram>,
    transaction_duration_seconds:
        Family<OperationLabels, Histogram, fn() -> Histogram>,
    blocking_queue_wait_seconds:
        Family<OperationLabels, Histogram, fn() -> Histogram>,
    blocking_task_duration_seconds:
        Family<OperationLabels, Histogram, fn() -> Histogram>,
    blocking_task_rejections_total: Family<OperationLabels, Counter>,
    blocking_in_flight: Gauge,
    request_db_duration_seconds:
        Family<RequestLabels, Histogram, fn() -> Histogram>,
}

impl AuthPrometheusMetrics {
    pub fn new() -> Self {
        Self {
            lock_wait_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
                    1.0, 2.0, 5.0,
                ])
            }),
            transaction_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0,
                    5.0, 10.0,
                ])
            }),
            blocking_queue_wait_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.0005, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5,
                    1.0, 2.0, 5.0,
                ])
            }),
            blocking_task_duration_seconds: Family::new_with_constructor(
                || {
                    Histogram::new(vec![
                        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
                        2.0, 5.0, 10.0,
                    ])
                },
            ),
            blocking_task_rejections_total: Family::default(),
            blocking_in_flight: Gauge::default(),
            request_db_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0,
                    5.0, 10.0,
                ])
            }),
        }
    }

    pub fn register_into(&self, registry: &mut Registry) {
        registry.register(
            "auth_db_lock_wait_seconds",
            "Time spent waiting for an auth SQLite connection, labeled by pool.",
            self.lock_wait_seconds.clone(),
        );
        registry.register(
            "auth_db_transaction_seconds",
            "Duration of auth SQLite transactions, labeled by operation.",
            self.transaction_duration_seconds.clone(),
        );
        registry.register(
            "auth_db_blocking_queue_wait_seconds",
            "Time spent waiting for auth blocking execution capacity, labeled by operation.",
            self.blocking_queue_wait_seconds.clone(),
        );
        registry.register(
            "auth_db_blocking_task_seconds",
            "Duration of auth blocking tasks dispatched through spawn_blocking, labeled by operation.",
            self.blocking_task_duration_seconds.clone(),
        );
        registry.register(
            "auth_db_blocking_rejections",
            "Total auth blocking tasks rejected due to backpressure timeout, labeled by operation.",
            self.blocking_task_rejections_total.clone(),
        );
        registry.register(
            "auth_db_blocking_in_flight",
            "Current number of auth blocking tasks holding execution capacity.",
            self.blocking_in_flight.clone(),
        );
        registry.register(
            "auth_db_request_seconds",
            "End-to-end database time consumed by auth-facing requests, labeled by request kind and result.",
            self.request_db_duration_seconds.clone(),
        );
    }

    pub fn observe_lock_wait(&self, pool: &'static str, seconds: f64) {
        self.lock_wait_seconds
            .get_or_create(&PoolLabels { pool })
            .observe(seconds);
    }

    pub fn observe_transaction_duration(
        &self,
        operation: &'static str,
        seconds: f64,
    ) {
        self.transaction_duration_seconds
            .get_or_create(&OperationLabels { operation })
            .observe(seconds);
    }

    pub fn observe_blocking_queue_wait(
        &self,
        operation: &'static str,
        seconds: f64,
    ) {
        self.blocking_queue_wait_seconds
            .get_or_create(&OperationLabels { operation })
            .observe(seconds);
    }

    pub fn inc_blocking_task_rejection(&self, operation: &'static str) {
        self.blocking_task_rejections_total
            .get_or_create(&OperationLabels { operation })
            .inc();
    }

    pub fn observe_blocking_task_duration(
        &self,
        operation: &'static str,
        seconds: f64,
    ) {
        self.blocking_task_duration_seconds
            .get_or_create(&OperationLabels { operation })
            .observe(seconds);
    }

    pub fn observe_request_metrics(
        &self,
        request_kind: &'static str,
        result: &'static str,
        elapsed_seconds: f64,
    ) {
        let labels = RequestLabels {
            request_kind,
            result,
        };
        self.request_db_duration_seconds
            .get_or_create(&labels)
            .observe(elapsed_seconds);
    }

    pub fn set_blocking_in_flight(&self, value: i64) {
        self.blocking_in_flight.set(value);
    }
}

pub type SharedAuthPrometheusMetrics = Arc<AuthPrometheusMetrics>;
