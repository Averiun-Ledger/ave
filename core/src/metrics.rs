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
struct ContractPrepareLabels {
    kind: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ContractExecutionLabels {
    result: &'static str,
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
    contract_executions: Family<ContractExecutionLabels, Counter>,
    contract_execution_seconds:
        Family<ContractExecutionLabels, Histogram, fn() -> Histogram>,
    contract_fuel_consumed:
        Family<ContractExecutionLabels, Histogram, fn() -> Histogram>,
    contract_fuel_exhausted_total: Family<ContractExecutionLabels, Counter>,
    contract_memory_peak_bytes:
        Family<ContractExecutionLabels, Histogram, fn() -> Histogram>,
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
            contract_executions: Family::default(),
            contract_execution_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                    0.5, 1.0, 2.0, 5.0,
                ])
            }),
            contract_fuel_consumed: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    1_000.0,
                    10_000.0,
                    100_000.0,
                    500_000.0,
                    1_000_000.0,
                    2_500_000.0,
                    5_000_000.0,
                    7_500_000.0,
                    10_000_000.0,
                ])
            }),
            contract_fuel_exhausted_total: Family::default(),
            contract_memory_peak_bytes: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    4_096.0,
                    16_384.0,
                    65_536.0,
                    262_144.0,
                    1_048_576.0,
                    4_194_304.0,
                    16_777_216.0,
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
            "core_contract_executions",
            "Contract execution attempts labeled by result.",
            self.contract_executions.clone(),
        );
        registry.register(
            "core_contract_execution_seconds",
            "Contract execution duration labeled by result.",
            self.contract_execution_seconds.clone(),
        );
        registry.register(
            "core_contract_fuel_consumed",
            "Contract fuel consumed per execution labeled by result.",
            self.contract_fuel_consumed.clone(),
        );
        registry.register(
            "core_contract_fuel_exhausted",
            "Total number of contract executions that ran out of fuel.",
            self.contract_fuel_exhausted_total.clone(),
        );
        registry.register(
            "core_contract_memory_peak_bytes",
            "Peak WASM linear memory used per contract execution labeled by result.",
            self.contract_memory_peak_bytes.clone(),
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

    pub fn observe_contract_execution(
        &self,
        result: &'static str,
        duration: Duration,
    ) {
        let labels = ContractExecutionLabels { result };
        self.contract_executions.get_or_create(&labels).inc();
        self.contract_execution_seconds
            .get_or_create(&labels)
            .observe(Self::seconds(duration));
    }

    pub fn observe_contract_fuel_consumed(
        &self,
        result: &'static str,
        fuel: u64,
    ) {
        let labels = ContractExecutionLabels { result };
        self.contract_fuel_consumed
            .get_or_create(&labels)
            .observe(fuel as f64);
    }

    pub fn observe_contract_fuel_exhausted(&self) {
        self.contract_fuel_exhausted_total
            .get_or_create(&ContractExecutionLabels { result: "error" })
            .inc();
    }

    pub fn observe_contract_memory_peak(
        &self,
        result: &'static str,
        bytes: u64,
    ) {
        let labels = ContractExecutionLabels { result };
        self.contract_memory_peak_bytes
            .get_or_create(&labels)
            .observe(bytes as f64);
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
        self.sink_events
            .get_or_create(&SinkResultLabels {
                sink: sink.to_owned(),
                result,
            })
            .inc();
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
        metrics.observe_contract_prepare(
            "registered",
            "cwasm_hit",
            Duration::from_millis(5),
        );
        metrics.observe_contract_prepare(
            "registered",
            "skipped",
            Duration::default(),
        );
        metrics.observe_contract_execution("success", Duration::from_millis(1));
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
                "core_contract_preparations_total{kind=\"registered\",result=\"cwasm_hit\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_preparations_total{kind=\"registered\",result=\"skipped\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_executions_total{result=\"success\"}"
            ),
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
        metrics.observe_contract_prepare(
            "temporary",
            "recompiled",
            Duration::from_millis(8),
        );
        metrics.observe_contract_execution("error", Duration::from_millis(2));

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
        assert_eq!(
            metric_value(
                &text,
                "core_contract_prepare_seconds_count{kind=\"temporary\",result=\"recompiled\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_execution_seconds_count{result=\"error\"}"
            ),
            1.0
        );
    }

    #[test]
    fn core_metrics_expose_contract_fuel_and_memory_series() {
        let metrics = CoreMetrics::new();
        let mut registry = Registry::default();
        metrics.register_into(&mut registry);

        metrics.observe_contract_fuel_consumed("success", 1_000_000);
        metrics.observe_contract_fuel_consumed("success", 2_500_000);
        metrics.observe_contract_fuel_consumed("error", 5_000_000);
        metrics.observe_contract_fuel_exhausted();
        metrics.observe_contract_fuel_exhausted();
        metrics.observe_contract_memory_peak("success", 64 * 1024);
        metrics.observe_contract_memory_peak("error", 128 * 1024);

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(
                &text,
                "core_contract_fuel_consumed_count{result=\"success\"}"
            ),
            2.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_fuel_consumed_count{result=\"error\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_fuel_exhausted_total{result=\"error\"}"
            ),
            2.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_memory_peak_bytes_count{result=\"success\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "core_contract_memory_peak_bytes_count{result=\"error\"}"
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
    }
}
