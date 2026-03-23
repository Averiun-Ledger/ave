use std::sync::{Arc, OnceLock};
use std::time::Duration;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        counter::Counter,
        family::Family,
        histogram::Histogram,
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
    tracker_sync_rounds: Family<TrackerSyncRoundLabels, Counter>,
    tracker_sync_updates: Family<TrackerSyncUpdateLabels, Counter>,
    protocol_events: Family<ProtocolEventLabels, Counter>,
    schema_events: Family<SchemaEventLabels, Counter>,
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
                        0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0,
                        30.0, 60.0, 120.0, 300.0,
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
                    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1,
                    0.25, 0.5, 1.0, 2.0, 5.0,
                ])
            }),
            tracker_sync_rounds: Family::default(),
            tracker_sync_updates: Family::default(),
            protocol_events: Family::default(),
            schema_events: Family::default(),
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
                    line.split_whitespace().nth(1)?.parse::<f64>().ok()
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
        metrics.observe_request_phase("distribution", Duration::from_millis(12));
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
}
