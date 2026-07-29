use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
    },
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestResultLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestPhaseLabels {
    phase: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TrackerSyncRoundLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct TrackerSyncUpdateLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ProtocolEventLabels {
    protocol: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SchemaEventLabels {
    actor: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SinkNameLabels {
    sink: String,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct SinkResultLabels {
    sink: String,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DistributionFailureLabels {
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DistributionDurationLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct GovernanceVersionSyncFailureLabels {
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ContractPrepareLabels {
    kind: &'static str,
    result: &'static str,
}

#[derive(Debug)]
pub struct CoreMetrics {
    requests: Family<RequestResultLabels, Counter>,
    request_duration_seconds:
        Family<RequestResultLabels, Histogram, fn() -> Histogram>,
    request_phase_duration_seconds:
        Family<RequestPhaseLabels, Histogram, fn() -> Histogram>,
    contract_preparations: Family<ContractPrepareLabels, Counter>,
    contract_prepare_seconds:
        Family<ContractPrepareLabels, Histogram, fn() -> Histogram>,
    tracker_sync_rounds: Family<TrackerSyncRoundLabels, Counter>,
    tracker_sync_updates: Family<TrackerSyncUpdateLabels, Counter>,
    protocol_events: Family<ProtocolEventLabels, Counter>,
    schema_events: Family<SchemaEventLabels, Counter>,
    sink_events: Family<SinkResultLabels, Counter>,
    sink_delivery_retries: Family<SinkNameLabels, Counter>,
    sink_request_duration_seconds:
        Family<SinkResultLabels, Histogram, fn() -> Histogram>,
    sink_blocked: Family<SinkNameLabels, Gauge>,
    sink_lagging_subjects: Family<SinkNameLabels, Gauge>,
    sink_lagging_events: Family<SinkNameLabels, Gauge>,
    sink_lag_max_distance: Family<SinkNameLabels, Gauge>,
    kafka_producer_queue_size: Family<SinkNameLabels, Gauge>,
    kafka_producer_tx_errors: Family<SinkNameLabels, Counter>,
    kafka_producer_rtt_seconds:
        Family<SinkNameLabels, Histogram, fn() -> Histogram>,
    kafka_producer_fatal_errors: Family<SinkNameLabels, Counter>,
    distribution_failures: Family<DistributionFailureLabels, Counter>,
    distribution_duration_seconds:
        Family<DistributionDurationLabels, Histogram, fn() -> Histogram>,
    update_retries_exceeded: Counter,
    reboot_max_retries_reached: Counter,
    external_db_critical_errors: Counter,
    governance_version_sync_failures:
        Family<GovernanceVersionSyncFailureLabels, Counter>,
    http_server_errors: Counter,
}

static CORE_METRICS: OnceLock<Arc<CoreMetrics>> = OnceLock::new();

impl CoreMetrics {
    fn new() -> Self {
        Self {
            requests: Family::default(),
            request_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
                    60.0, 120.0, 300.0,
                ])
            }),
            request_phase_duration_seconds: Family::new_with_constructor(
                || {
                    Histogram::new(vec![
                        0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
                        60.0, 120.0, 300.0,
                    ])
                },
            ),
            contract_preparations: Family::default(),
            contract_prepare_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
                    60.0, 120.0,
                ])
            }),
            tracker_sync_rounds: Family::default(),
            tracker_sync_updates: Family::default(),
            protocol_events: Family::default(),
            schema_events: Family::default(),
            sink_events: Family::default(),
            sink_delivery_retries: Family::default(),
            sink_request_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5,
                    5.0, 10.0,
                ])
            }),
            sink_blocked: Family::default(),
            sink_lagging_subjects: Family::default(),
            sink_lagging_events: Family::default(),
            sink_lag_max_distance: Family::default(),
            kafka_producer_queue_size: Family::default(),
            kafka_producer_tx_errors: Family::default(),
            kafka_producer_rtt_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                    0.5, 1.0,
                ])
            }),
            kafka_producer_fatal_errors: Family::default(),
            distribution_failures: Family::default(),
            distribution_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
                    60.0, 120.0, 300.0,
                ])
            }),
            update_retries_exceeded: Counter::default(),
            reboot_max_retries_reached: Counter::default(),
            external_db_critical_errors: Counter::default(),
            governance_version_sync_failures: Family::default(),
            http_server_errors: Counter::default(),
        }
    }

    fn register_into(&self, registry: &mut Registry) {
        registry.register(
            "core_requests",
            "Core request lifecycle counters labeled by result.",
            self.requests.clone(),
        );
        registry.register(
            "core_request_duration_seconds",
            "Total handled request duration labeled by terminal result.",
            self.request_duration_seconds.clone(),
        );
        registry.register(
            "core_request_phase_duration_seconds",
            "Duration of the main request phases labeled by phase.",
            self.request_phase_duration_seconds.clone(),
        );
        registry.register(
            "core_contract_preparations",
            "Contract preparation attempts labeled by kind and result.",
            self.contract_preparations.clone(),
        );
        registry.register(
            "core_contract_prepare_seconds",
            "Contract preparation duration labeled by kind and result.",
            self.contract_prepare_seconds.clone(),
        );
        registry.register(
            "core_tracker_sync_rounds",
            "Tracker sync round counters labeled by result.",
            self.tracker_sync_rounds.clone(),
        );
        registry.register(
            "core_tracker_sync_updates",
            "Tracker sync update counters labeled by result.",
            self.tracker_sync_updates.clone(),
        );
        registry.register(
            "core_protocol_events",
            "Core protocol events labeled by protocol and result.",
            self.protocol_events.clone(),
        );
        registry.register(
            "core_schema_events",
            "Evaluation and validation schema actor events labeled by actor and result.",
            self.schema_events.clone(),
        );
        registry.register(
            "core_sink_events",
            "Sink events delivered or failed, labeled by sink and result.",
            self.sink_events.clone(),
        );
        registry.register(
            "core_sink_delivery_retries",
            "Sink delivery retry attempts, labeled by sink.",
            self.sink_delivery_retries.clone(),
        );
        registry.register(
            "core_sink_request_duration_seconds",
            "Sink HTTP request duration, labeled by sink and result.",
            self.sink_request_duration_seconds.clone(),
        );
        registry.register(
            "core_sink_blocked",
            "Whether a sink is currently blocked (1) or not (0).",
            self.sink_blocked.clone(),
        );
        registry.register(
            "core_sink_lagging_subjects",
            "Number of subjects currently lagging behind for a sink.",
            self.sink_lagging_subjects.clone(),
        );
        registry.register(
            "core_sink_lagging_events",
            "Total event lag (sum of last_seen - cursor) across all lagging subjects of a sink.",
            self.sink_lagging_events.clone(),
        );
        registry.register(
            "core_sink_lag_max_distance",
            "Maximum SN distance (last_seen - cursor) among lagging subjects of a sink.",
            self.sink_lag_max_distance.clone(),
        );
        registry.register(
            "core_kafka_producer_queue_size",
            "Current number of messages in the Kafka producer queue, labeled by sink.",
            self.kafka_producer_queue_size.clone(),
        );
        registry.register(
            "core_kafka_producer_tx_errors",
            "Total Kafka producer transmission errors and request timeouts, labeled by sink.",
            self.kafka_producer_tx_errors.clone(),
        );
        registry.register(
            "core_kafka_producer_rtt_seconds",
            "Kafka broker round-trip time reported by producer statistics, labeled by sink.",
            self.kafka_producer_rtt_seconds.clone(),
        );
        registry.register(
            "core_kafka_producer_fatal_errors",
            "Total fatal Kafka producer errors (producer fenced, unsupported feature, ...), labeled by sink.",
            self.kafka_producer_fatal_errors.clone(),
        );
        registry.register(
            "core_distribution_failures_total",
            "Total distribution failures by reason.",
            self.distribution_failures.clone(),
        );
        registry.register(
            "core_distribution_duration_seconds",
            "Distribution duration in seconds.",
            self.distribution_duration_seconds.clone(),
        );
        registry.register(
            "core_update_retries_exceeded_total",
            "Total update processes that exceeded the retry threshold.",
            self.update_retries_exceeded.clone(),
        );
        registry.register(
            "core_reboot_max_retries_reached_total",
            "Total reboot processes that reached the maximum stability checks.",
            self.reboot_max_retries_reached.clone(),
        );
        registry.register(
            "core_external_db_critical_errors_total",
            "Total critical external database errors reported to DBManager.",
            self.external_db_critical_errors.clone(),
        );
        registry.register(
            "core_governance_version_sync_failures_total",
            "Total governance version sync failures by reason.",
            self.governance_version_sync_failures.clone(),
        );
        registry.register(
            "core_http_server_errors_total",
            "Total HTTP 5xx server errors.",
            self.http_server_errors.clone(),
        );
    }

    const fn seconds(duration: Duration) -> f64 {
        duration.as_secs_f64()
    }

    pub fn observe_request_started(&self) {
        self.requests
            .get_or_create(&RequestResultLabels { result: "started" })
            .inc();
    }

    pub fn observe_request_invalid(&self) {
        self.requests
            .get_or_create(&RequestResultLabels { result: "invalid" })
            .inc();
    }

    pub fn observe_request_terminal(
        &self,
        result: &'static str,
        duration: Duration,
    ) {
        self.requests
            .get_or_create(&RequestResultLabels { result })
            .inc();
        self.request_duration_seconds
            .get_or_create(&RequestResultLabels { result })
            .observe(Self::seconds(duration));
    }

    pub fn observe_request_phase(
        &self,
        phase: &'static str,
        duration: Duration,
    ) {
        self.request_phase_duration_seconds
            .get_or_create(&RequestPhaseLabels { phase })
            .observe(Self::seconds(duration));
    }

    pub fn observe_contract_prepare(
        &self,
        kind: &'static str,
        result: &'static str,
        duration: Duration,
    ) {
        let labels = ContractPrepareLabels { kind, result };
        self.contract_preparations.get_or_create(&labels).inc();
        self.contract_prepare_seconds
            .get_or_create(&labels)
            .observe(Self::seconds(duration));
    }

    pub fn observe_tracker_sync_round(&self, result: &'static str) {
        self.tracker_sync_rounds
            .get_or_create(&TrackerSyncRoundLabels { result })
            .inc();
    }

    pub fn observe_tracker_sync_update(&self, result: &'static str) {
        self.tracker_sync_updates
            .get_or_create(&TrackerSyncUpdateLabels { result })
            .inc();
    }

    pub fn observe_protocol_event(
        &self,
        protocol: &'static str,
        result: &'static str,
    ) {
        self.protocol_events
            .get_or_create(&ProtocolEventLabels { protocol, result })
            .inc();
    }

    pub fn observe_schema_event(
        &self,
        actor: &'static str,
        result: &'static str,
    ) {
        self.schema_events
            .get_or_create(&SchemaEventLabels { actor, result })
            .inc();
    }

    pub fn observe_sink_event(&self, sink: &str, result: &'static str) {
        self.observe_sink_event_n(sink, result, 1);
    }

    pub fn observe_sink_event_n(
        &self,
        sink: &str,
        result: &'static str,
        n: u64,
    ) {
        self.sink_events
            .get_or_create(&SinkResultLabels {
                sink: sink.to_owned(),
                result,
            })
            .inc_by(n);
    }

    pub fn observe_sink_retry(&self, sink: &str) {
        self.sink_delivery_retries
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .inc();
    }

    pub fn observe_sink_request_duration(
        &self,
        sink: &str,
        result: &'static str,
        duration: Duration,
    ) {
        self.sink_request_duration_seconds
            .get_or_create(&SinkResultLabels {
                sink: sink.to_owned(),
                result,
            })
            .observe(Self::seconds(duration));
    }

    pub fn set_sink_blocked(&self, sink: &str, blocked: bool) {
        self.sink_blocked
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .set(if blocked { 1 } else { 0 });
    }

    pub fn set_sink_lagging_subjects(&self, sink: &str, count: i64) {
        self.sink_lagging_subjects
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .set(count);
    }

    pub fn set_sink_lagging_events(&self, sink: &str, count: i64) {
        self.sink_lagging_events
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .set(count);
    }

    pub fn set_sink_lag_max_distance(&self, sink: &str, distance: i64) {
        self.sink_lag_max_distance
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .set(distance);
    }

    /// Forwards a librdkafka producer statistics report to the Kafka
    /// producer metrics. `last_tx_errors` holds the absolute error total of
    /// the previous report (librdkafka reports cumulative values) so the
    /// counter only advances by the delta.
    pub fn observe_kafka_producer_stats(
        &self,
        sink: &str,
        stats: &rdkafka::Statistics,
        last_tx_errors: &AtomicU64,
    ) {
        self.kafka_producer_queue_size
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .set(stats.msg_cnt as i64);

        let tx_errors: u64 = stats
            .brokers
            .values()
            .map(|broker| broker.txerrs + broker.req_timeouts)
            .sum();
        let previous = last_tx_errors.swap(tx_errors, Ordering::Relaxed);
        if tx_errors > previous {
            self.kafka_producer_tx_errors
                .get_or_create(&SinkNameLabels {
                    sink: sink.to_owned(),
                })
                .inc_by(tx_errors - previous);
        }

        for broker in stats.brokers.values() {
            if let Some(rtt) = &broker.rtt
                && rtt.avg > 0
            {
                self.kafka_producer_rtt_seconds
                    .get_or_create(&SinkNameLabels {
                        sink: sink.to_owned(),
                    })
                    .observe(rtt.avg as f64 / 1_000_000.0);
            }
        }
    }

    /// Record a fatal error reported by the librdkafka client error callback
    /// (producer fenced, unsupported feature, ...). Unlike the stats-derived
    /// counters, a fatal error means the producer instance is dead.
    pub fn observe_kafka_producer_fatal_error(&self, sink: &str) {
        self.kafka_producer_fatal_errors
            .get_or_create(&SinkNameLabels {
                sink: sink.to_owned(),
            })
            .inc();
    }

    pub fn observe_distribution_failure(&self, reason: &'static str) {
        self.distribution_failures
            .get_or_create(&DistributionFailureLabels { reason })
            .inc();
    }

    pub fn observe_distribution_duration(
        &self,
        kind: &'static str,
        duration: Duration,
    ) {
        self.distribution_duration_seconds
            .get_or_create(&DistributionDurationLabels { kind })
            .observe(Self::seconds(duration));
    }

    pub fn observe_update_retries_exceeded(&self) {
        self.update_retries_exceeded.inc();
    }

    pub fn observe_reboot_max_retries_reached(&self) {
        self.reboot_max_retries_reached.inc();
    }

    pub fn observe_external_db_critical_error(&self) {
        self.external_db_critical_errors.inc();
    }

    pub fn observe_governance_version_sync_failure(
        &self,
        reason: &'static str,
    ) {
        self.governance_version_sync_failures
            .get_or_create(&GovernanceVersionSyncFailureLabels { reason })
            .inc();
    }

    pub fn observe_http_server_error(&self) {
        self.http_server_errors.inc();
    }
}

pub fn register(registry: &mut Registry) -> Arc<CoreMetrics> {
    let metrics = CORE_METRICS
        .get_or_init(|| Arc::new(CoreMetrics::new()))
        .clone();
    metrics.register_into(registry);
    metrics
}

pub fn try_core_metrics() -> Option<&'static Arc<CoreMetrics>> {
    CORE_METRICS.get()
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prometheus_client::{encoding::text::encode, registry::Registry};

    use super::*;

    fn metric_value(metrics: &str, name: &str) -> f64 {
        metrics
            .lines()
            .find_map(|line| {
                if line.starts_with(name) {
                    line.split_whitespace().last()?.parse::<f64>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0.0)
    }

    #[test]
    fn core_metrics_expose_expected_counter_labels() {
        let metrics = CoreMetrics::new();
        let mut registry = Registry::default();
        metrics.register_into(&mut registry);

        metrics.observe_request_started();
        metrics.observe_request_invalid();
        metrics.observe_request_terminal("finished", Duration::from_millis(20));
        metrics.observe_request_phase("evaluation", Duration::from_millis(10));
        metrics.observe_tracker_sync_round("completed");
        metrics.observe_tracker_sync_update("launched");
        metrics.observe_protocol_event("approval", "approved");
        metrics.observe_schema_event("validation_schema", "delegated");

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(&text, "core_requests_total{result=\"started\"}"),
            1.0
        );
        assert_eq!(
            metric_value(&text, "core_requests_total{result=\"invalid\"}"),
            1.0
        );
        assert_eq!(
            metric_value(&text, "core_requests_total{result=\"finished\"}"),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_tracker_sync_rounds_total{result=\"completed\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_tracker_sync_updates_total{result=\"launched\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_protocol_events_total{protocol=\"approval\",result=\"approved\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_schema_events_total{actor=\"validation_schema\",result=\"delegated\"}"
            ),
            1.0
        );
    }

    #[test]
    fn core_metrics_expose_expected_histogram_series() {
        let metrics = CoreMetrics::new();
        let mut registry = Registry::default();
        metrics.register_into(&mut registry);

        metrics.observe_request_terminal("aborted", Duration::from_millis(30));
        metrics
            .observe_request_phase("distribution", Duration::from_millis(12));

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(
                &text,
                "core_request_duration_seconds_count{result=\"aborted\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_request_phase_duration_seconds_count{phase=\"distribution\"}"
            ),
            1.0
        );
    }

    #[test]
    fn core_metrics_expose_sink_series() {
        let metrics = CoreMetrics::new();
        let mut registry = Registry::default();
        metrics.register_into(&mut registry);

        metrics.observe_sink_event("gov-sink", "success");
        metrics.observe_sink_event("gov-sink", "success");
        metrics.observe_sink_event("schema-sink", "delivery_failed");
        metrics.observe_sink_event("schema-sink", "auth_failed");
        metrics.observe_sink_event("schema-sink", "blocked");
        metrics.observe_sink_event("schema-sink", "subject_not_found");

        metrics.observe_sink_retry("schema-sink");
        metrics.observe_sink_retry("schema-sink");

        metrics.observe_sink_request_duration(
            "gov-sink",
            "success",
            Duration::from_millis(12),
        );
        metrics.observe_sink_request_duration(
            "schema-sink",
            "transient",
            Duration::from_millis(250),
        );

        metrics.set_sink_blocked("schema-sink", true);
        metrics.set_sink_lagging_subjects("schema-sink", 3);
        metrics.set_sink_lagging_events("schema-sink", 42);
        metrics.set_sink_lag_max_distance("schema-sink", 17);

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(
                &text,
                "core_sink_events_total{sink=\"gov-sink\",result=\"success\"}"
            ),
            2.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_events_total{sink=\"schema-sink\",result=\"delivery_failed\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_events_total{sink=\"schema-sink\",result=\"auth_failed\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_events_total{sink=\"schema-sink\",result=\"blocked\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_events_total{sink=\"schema-sink\",result=\"subject_not_found\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_delivery_retries_total{sink=\"schema-sink\"}"
            ),
            2.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_request_duration_seconds_count{sink=\"gov-sink\",result=\"success\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_request_duration_seconds_count{sink=\"schema-sink\",result=\"transient\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(&text, "core_sink_blocked{sink=\"schema-sink\"}"),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_lagging_subjects{sink=\"schema-sink\"}"
            ),
            3.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_lagging_events{sink=\"schema-sink\"}"
            ),
            42.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_sink_lag_max_distance{sink=\"schema-sink\"}"
            ),
            17.0
        );
    }

    #[test]
    fn kafka_producer_stats_expose_queue_errors_and_rtt() {
        let metrics = CoreMetrics::new();
        let mut registry = Registry::default();
        metrics.register_into(&mut registry);

        let last_tx_errors = AtomicU64::new(0);
        let mut stats = rdkafka::Statistics::default();
        stats.msg_cnt = 7;
        let mut broker = rdkafka::statistics::Broker::default();
        broker.txerrs = 3;
        broker.req_timeouts = 1;
        broker.rtt = Some(rdkafka::statistics::Window {
            avg: 1_500,
            ..Default::default()
        });
        stats.brokers.insert("broker:9092/1".to_owned(), broker);

        metrics.observe_kafka_producer_stats(
            "unit-kafka-sink",
            &stats,
            &last_tx_errors,
        );

        // librdkafka reports cumulative values: the second report must only
        // advance the error counter by the delta (6 - 4 = 2).
        let mut stats = stats;
        stats.msg_cnt = 0;
        let mut broker = stats
            .brokers
            .remove("broker:9092/1")
            .expect("broker present in stats");
        broker.txerrs = 5;
        stats.brokers.insert("broker:9092/1".to_owned(), broker);
        metrics.observe_kafka_producer_stats(
            "unit-kafka-sink",
            &stats,
            &last_tx_errors,
        );

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(
                &text,
                "core_kafka_producer_queue_size{sink=\"unit-kafka-sink\"}"
            ),
            0.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_kafka_producer_tx_errors_total{sink=\"unit-kafka-sink\"}"
            ),
            6.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_kafka_producer_rtt_seconds_count{sink=\"unit-kafka-sink\"}"
            ),
            2.0
        );
    }
}
