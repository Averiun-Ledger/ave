//! Prometheus metrics for the network worker.

use std::sync::Arc;

use crate::utils::NetworkState;

use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
    },
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DialAttemptLabels {
    phase: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct DialFailureLabels {
    phase: &'static str,
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct MessageDropLabels {
    direction: &'static str,
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReqResMessageLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReqResFailureLabels {
    direction: &'static str,
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ErrorKindLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ControlListUpdateLabels {
    list: &'static str,
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ControlListLabels {
    list: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ControlListDeniedLabels {
    reason: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct BootstrapDurationLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct NetworkStateLabels {
    state: &'static str,
}

/// Metrics handle used by the network worker.
#[derive(Debug)]
pub struct NetworkMetrics {
    dial_attempts_total: Family<DialAttemptLabels, Counter>,
    dial_failures_total: Family<DialFailureLabels, Counter>,
    messages_dropped_total: Family<MessageDropLabels, Counter>,
    reqres_messages_received_total: Family<ReqResMessageLabels, Counter>,
    reqres_failures_total: Family<ReqResFailureLabels, Counter>,
    identify_errors_total: Family<ErrorKindLabels, Counter>,
    control_list_updates_total: Family<ControlListUpdateLabels, Counter>,
    control_list_apply_total: Family<ControlListLabels, Counter>,
    control_list_denied_total: Family<ControlListDeniedLabels, Counter>,
    retry_queue_len: Gauge,
    pending_outbound_peers: Gauge,
    pending_outbound_messages: Gauge,
    pending_outbound_bytes: Gauge,
    pending_inbound_peers: Gauge,
    pending_inbound_messages: Gauge,
    pending_inbound_bytes: Gauge,
    identified_peers: Gauge,
    response_channels_pending: Gauge,
    control_list_allow_last_success_age_seconds: Gauge,
    control_list_block_last_success_age_seconds: Gauge,
    control_list_allow_peers: Gauge,
    control_list_block_peers: Gauge,
    state: Family<NetworkStateLabels, Gauge>,
    bootstrap_duration_seconds:
        Family<BootstrapDurationLabels, Histogram, fn() -> Histogram>,
    pending_message_age_seconds: Histogram,
    control_list_updater_duration_seconds: Histogram,
}

impl NetworkMetrics {
    fn new() -> Self {
        Self {
            dial_attempts_total: Family::default(),
            dial_failures_total: Family::default(),
            messages_dropped_total: Family::default(),
            reqres_messages_received_total: Family::default(),
            reqres_failures_total: Family::default(),
            identify_errors_total: Family::default(),
            control_list_updates_total: Family::default(),
            control_list_apply_total: Family::default(),
            control_list_denied_total: Family::default(),
            retry_queue_len: Gauge::default(),
            pending_outbound_peers: Gauge::default(),
            pending_outbound_messages: Gauge::default(),
            pending_outbound_bytes: Gauge::default(),
            pending_inbound_peers: Gauge::default(),
            pending_inbound_messages: Gauge::default(),
            pending_inbound_bytes: Gauge::default(),
            identified_peers: Gauge::default(),
            response_channels_pending: Gauge::default(),
            control_list_allow_last_success_age_seconds: Gauge::default(),
            control_list_block_last_success_age_seconds: Gauge::default(),
            control_list_allow_peers: Gauge::default(),
            control_list_block_peers: Gauge::default(),
            state: Family::default(),
            bootstrap_duration_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0,
                ])
            }),
            pending_message_age_seconds: Histogram::new(vec![
                0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0,
            ]),
            control_list_updater_duration_seconds: Histogram::new(vec![
                0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
            ]),
        }
    }

    fn register_into(&self, registry: &mut Registry) {
        registry.register(
            "network_dial_attempts",
            "Total dial attempts, labeled by phase.",
            self.dial_attempts_total.clone(),
        );
        registry.register(
            "network_dial_failures",
            "Total dial failures, labeled by phase and kind.",
            self.dial_failures_total.clone(),
        );
        registry.register(
            "network_messages_dropped",
            "Total dropped or rejected messages, labeled by direction and reason.",
            self.messages_dropped_total.clone(),
        );
        registry.register(
            "network_reqres_messages_received",
            "Total request-response messages received, labeled by kind.",
            self.reqres_messages_received_total.clone(),
        );
        registry.register(
            "network_reqres_failures",
            "Total request-response failures, labeled by direction and kind.",
            self.reqres_failures_total.clone(),
        );
        registry.register(
            "network_identify_errors",
            "Total identify protocol errors, labeled by kind.",
            self.identify_errors_total.clone(),
        );
        registry.register(
            "network_control_list_updates",
            "Total control-list update attempts, labeled by list and result.",
            self.control_list_updates_total.clone(),
        );
        registry.register(
            "network_control_list_apply",
            "Total applied control-list updates, labeled by list.",
            self.control_list_apply_total.clone(),
        );
        registry.register(
            "network_control_list_denied",
            "Total denied connections by control list, labeled by reason.",
            self.control_list_denied_total.clone(),
        );
        registry.register(
            "network_retry_queue_len",
            "Current retry queue length.",
            self.retry_queue_len.clone(),
        );
        registry.register(
            "network_pending_outbound_peers",
            "Peers with pending outbound messages.",
            self.pending_outbound_peers.clone(),
        );
        registry.register(
            "network_pending_outbound_messages",
            "Total pending outbound messages.",
            self.pending_outbound_messages.clone(),
        );
        registry.register(
            "network_pending_outbound_bytes",
            "Total pending outbound payload bytes.",
            self.pending_outbound_bytes.clone(),
        );
        registry.register(
            "network_pending_inbound_peers",
            "Peers with pending inbound messages.",
            self.pending_inbound_peers.clone(),
        );
        registry.register(
            "network_pending_inbound_messages",
            "Total pending inbound messages.",
            self.pending_inbound_messages.clone(),
        );
        registry.register(
            "network_pending_inbound_bytes",
            "Total pending inbound payload bytes.",
            self.pending_inbound_bytes.clone(),
        );
        registry.register(
            "network_identified_peers",
            "Current number of identified peers.",
            self.identified_peers.clone(),
        );
        registry.register(
            "network_response_channels_pending",
            "Current number of pending request-response channels.",
            self.response_channels_pending.clone(),
        );
        registry.register(
            "network_control_list_allow_last_success_age_seconds",
            "Seconds since last successful allow-list update (-1 if never).",
            self.control_list_allow_last_success_age_seconds.clone(),
        );
        registry.register(
            "network_control_list_block_last_success_age_seconds",
            "Seconds since last successful block-list update (-1 if never).",
            self.control_list_block_last_success_age_seconds.clone(),
        );
        registry.register(
            "network_control_list_allow_peers",
            "Current number of peers in allow list.",
            self.control_list_allow_peers.clone(),
        );
        registry.register(
            "network_control_list_block_peers",
            "Current number of peers in block list.",
            self.control_list_block_peers.clone(),
        );
        registry.register(
            "network_state",
            "Current network state as one-hot gauges labeled by state.",
            self.state.clone(),
        );
        registry.register(
            "network_bootstrap_duration_seconds",
            "Bootstrap connection duration in seconds, labeled by result.",
            self.bootstrap_duration_seconds.clone(),
        );
        registry.register(
            "network_pending_message_age_seconds",
            "Age of pending messages when they leave queue or are dropped.",
            self.pending_message_age_seconds.clone(),
        );
        registry.register(
            "network_control_list_updater_duration_seconds",
            "Control-list updater duration in seconds.",
            self.control_list_updater_duration_seconds.clone(),
        );
    }

    pub(crate) fn inc_dial_attempt_bootstrap(&self) {
        self.dial_attempts_total
            .get_or_create(&DialAttemptLabels { phase: "bootstrap" })
            .inc();
    }

    pub(crate) fn inc_dial_attempt_runtime(&self) {
        self.dial_attempts_total
            .get_or_create(&DialAttemptLabels { phase: "runtime" })
            .inc();
    }

    pub(crate) fn observe_dial_failure(
        &self,
        phase: &'static str,
        kind: &'static str,
    ) {
        self.dial_failures_total
            .get_or_create(&DialFailureLabels { phase, kind })
            .inc();
    }

    pub(crate) fn inc_outbound_queue_drop_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "outbound",
                    reason: "queue_limit",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_inbound_queue_drop_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "inbound",
                    reason: "queue_limit",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_outbound_queue_bytes_drop_per_peer_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "outbound",
                    reason: "queue_bytes_limit_per_peer",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_outbound_queue_bytes_drop_global_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "outbound",
                    reason: "queue_bytes_limit_global",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_inbound_queue_bytes_drop_per_peer_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "inbound",
                    reason: "queue_bytes_limit_per_peer",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_inbound_queue_bytes_drop_global_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "inbound",
                    reason: "queue_bytes_limit_global",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_max_retries_drop_by(&self, count: u64) {
        if count > 0 {
            self.messages_dropped_total
                .get_or_create(&MessageDropLabels {
                    direction: "outbound",
                    reason: "max_retries",
                })
                .inc_by(count);
        }
    }

    pub(crate) fn inc_oversized_inbound_drop(&self) {
        self.messages_dropped_total
            .get_or_create(&MessageDropLabels {
                direction: "inbound",
                reason: "oversized",
            })
            .inc();
    }

    pub(crate) fn inc_oversized_outbound_drop(&self) {
        self.messages_dropped_total
            .get_or_create(&MessageDropLabels {
                direction: "outbound",
                reason: "oversized",
            })
            .inc();
    }

    pub(crate) fn inc_reqres_request_received(&self) {
        self.reqres_messages_received_total
            .get_or_create(&ReqResMessageLabels { kind: "request" })
            .inc();
    }

    pub(crate) fn inc_reqres_response_received(&self) {
        self.reqres_messages_received_total
            .get_or_create(&ReqResMessageLabels { kind: "response" })
            .inc();
    }

    pub(crate) fn observe_reqres_failure(
        &self,
        direction: &'static str,
        kind: &'static str,
    ) {
        self.reqres_failures_total
            .get_or_create(&ReqResFailureLabels { direction, kind })
            .inc();
    }

    pub(crate) fn observe_identify_error(&self, kind: &'static str) {
        self.identify_errors_total
            .get_or_create(&ErrorKindLabels { kind })
            .inc();
    }

    pub(crate) fn observe_control_list_denied(&self, reason: &'static str) {
        self.control_list_denied_total
            .get_or_create(&ControlListDeniedLabels { reason })
            .inc();
    }

    pub(crate) fn observe_control_list_allow_update(&self, success: bool) {
        let result = if success { "success" } else { "failure" };
        self.control_list_updates_total
            .get_or_create(&ControlListUpdateLabels {
                list: "allow",
                result,
            })
            .inc();
    }

    pub(crate) fn observe_control_list_block_update(&self, success: bool) {
        let result = if success { "success" } else { "failure" };
        self.control_list_updates_total
            .get_or_create(&ControlListUpdateLabels {
                list: "block",
                result,
            })
            .inc();
    }

    pub(crate) fn inc_control_list_allow_apply(&self) {
        self.control_list_apply_total
            .get_or_create(&ControlListLabels { list: "allow" })
            .inc();
    }

    pub(crate) fn inc_control_list_block_apply(&self) {
        self.control_list_apply_total
            .get_or_create(&ControlListLabels { list: "block" })
            .inc();
    }

    pub(crate) fn set_control_list_allow_last_success_age_seconds(
        &self,
        value: i64,
    ) {
        self.control_list_allow_last_success_age_seconds.set(value);
    }

    pub(crate) fn set_control_list_block_last_success_age_seconds(
        &self,
        value: i64,
    ) {
        self.control_list_block_last_success_age_seconds.set(value);
    }

    pub(crate) fn set_control_list_allow_peers(&self, value: i64) {
        self.control_list_allow_peers.set(value);
    }

    pub(crate) fn set_control_list_block_peers(&self, value: i64) {
        self.control_list_block_peers.set(value);
    }

    pub(crate) fn observe_control_list_updater_duration_seconds(
        &self,
        seconds: f64,
    ) {
        self.control_list_updater_duration_seconds.observe(seconds);
    }

    pub(crate) fn set_state_current(&self, state: &NetworkState) {
        let current = Self::state_label(state);
        for known in Self::state_labels() {
            self.state
                .get_or_create(&NetworkStateLabels { state: known })
                .set((known == current) as i64);
        }
    }

    pub(crate) fn observe_state_transition(&self, state: &NetworkState) {
        self.set_state_current(state);
    }

    pub(crate) fn observe_pending_message_age_seconds(&self, age_seconds: f64) {
        self.pending_message_age_seconds.observe(age_seconds);
    }

    pub(crate) fn set_retry_queue_len(&self, value: i64) {
        self.retry_queue_len.set(value);
    }

    pub(crate) fn set_pending_outbound_peers(&self, value: i64) {
        self.pending_outbound_peers.set(value);
    }

    pub(crate) fn set_pending_outbound_messages(&self, value: i64) {
        self.pending_outbound_messages.set(value);
    }

    pub(crate) fn set_pending_outbound_bytes(&self, value: i64) {
        self.pending_outbound_bytes.set(value);
    }

    pub(crate) fn set_pending_inbound_peers(&self, value: i64) {
        self.pending_inbound_peers.set(value);
    }

    pub(crate) fn set_pending_inbound_messages(&self, value: i64) {
        self.pending_inbound_messages.set(value);
    }

    pub(crate) fn set_pending_inbound_bytes(&self, value: i64) {
        self.pending_inbound_bytes.set(value);
    }

    pub(crate) fn set_identified_peers(&self, value: i64) {
        self.identified_peers.set(value);
    }

    pub(crate) fn set_response_channels_pending(&self, value: i64) {
        self.response_channels_pending.set(value);
    }

    pub(crate) fn observe_bootstrap_duration_seconds(
        &self,
        result: &'static str,
        seconds: f64,
    ) {
        self.bootstrap_duration_seconds
            .get_or_create(&BootstrapDurationLabels { result })
            .observe(seconds);
    }

    const fn state_labels() -> [&'static str; 5] {
        ["start", "dial", "dialing", "running", "disconnected"]
    }

    const fn state_label(state: &NetworkState) -> &'static str {
        match state {
            NetworkState::Start => "start",
            NetworkState::Dial => "dial",
            NetworkState::Dialing => "dialing",
            NetworkState::Running => "running",
            NetworkState::Disconnected => "disconnected",
        }
    }
}

/// Register network metrics in the provided Prometheus registry.
///
/// Returns a shared handle that can be passed to the network worker.
pub fn register(registry: &mut Registry) -> Arc<NetworkMetrics> {
    let metrics = Arc::new(NetworkMetrics::new());
    metrics.register_into(registry);
    metrics
}
