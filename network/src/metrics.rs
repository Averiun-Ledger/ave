//! Prometheus metrics for the network worker.

use std::sync::Arc;

use crate::utils::NetworkState;

use prometheus_client::{
    metrics::{counter::Counter, gauge::Gauge, histogram::Histogram},
    registry::Registry,
};

/// Metrics handle used by the network worker.
#[derive(Debug)]
pub struct NetworkMetrics {
    dial_attempts_bootstrap: Counter,
    dial_attempts_runtime: Counter,
    dial_failures: Counter,
    dial_failures_local_peer_id: Counter,
    dial_failures_no_addresses: Counter,
    dial_failures_peer_condition: Counter,
    dial_failures_denied: Counter,
    dial_failures_aborted: Counter,
    dial_failures_wrong_peer_id: Counter,
    dial_failures_transport: Counter,
    dropped_outbound_queue_limit: Counter,
    dropped_inbound_queue_limit: Counter,
    dropped_outbound_queue_bytes_limit: Counter,
    dropped_inbound_queue_bytes_limit: Counter,
    dropped_max_retries: Counter,
    dropped_oversized_inbound: Counter,
    dropped_oversized_outbound: Counter,
    reqres_requests_received: Counter,
    reqres_responses_received: Counter,
    reqres_failures: Counter,
    reqres_failures_inbound: Counter,
    reqres_failures_outbound: Counter,
    reqres_failures_timeout: Counter,
    reqres_failures_io: Counter,
    reqres_failures_negotiation: Counter,
    reqres_failures_connection_closed: Counter,
    reqres_failures_response_omission: Counter,
    reqres_failures_dial: Counter,
    reqres_failures_other: Counter,
    identify_errors: Counter,
    identify_errors_timeout: Counter,
    identify_errors_io: Counter,
    identify_errors_negotiation: Counter,
    identify_errors_other: Counter,
    control_list_denied: Counter,
    control_list_denied_not_allowed: Counter,
    control_list_denied_blocked: Counter,
    control_list_updater_runs: Counter,
    control_list_allow_update_success: Counter,
    control_list_allow_update_failure: Counter,
    control_list_block_update_success: Counter,
    control_list_block_update_failure: Counter,
    control_list_allow_apply: Counter,
    control_list_block_apply: Counter,
    state_transitions: Counter,
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
    state_current: Gauge,
    bootstrap_duration_seconds: Histogram,
    pending_message_age_seconds: Histogram,
    control_list_updater_duration_seconds: Histogram,
}

impl NetworkMetrics {
    fn new() -> Self {
        Self {
            dial_attempts_bootstrap: Counter::default(),
            dial_attempts_runtime: Counter::default(),
            dial_failures: Counter::default(),
            dial_failures_local_peer_id: Counter::default(),
            dial_failures_no_addresses: Counter::default(),
            dial_failures_peer_condition: Counter::default(),
            dial_failures_denied: Counter::default(),
            dial_failures_aborted: Counter::default(),
            dial_failures_wrong_peer_id: Counter::default(),
            dial_failures_transport: Counter::default(),
            dropped_outbound_queue_limit: Counter::default(),
            dropped_inbound_queue_limit: Counter::default(),
            dropped_outbound_queue_bytes_limit: Counter::default(),
            dropped_inbound_queue_bytes_limit: Counter::default(),
            dropped_max_retries: Counter::default(),
            dropped_oversized_inbound: Counter::default(),
            dropped_oversized_outbound: Counter::default(),
            reqres_requests_received: Counter::default(),
            reqres_responses_received: Counter::default(),
            reqres_failures: Counter::default(),
            reqres_failures_inbound: Counter::default(),
            reqres_failures_outbound: Counter::default(),
            reqres_failures_timeout: Counter::default(),
            reqres_failures_io: Counter::default(),
            reqres_failures_negotiation: Counter::default(),
            reqres_failures_connection_closed: Counter::default(),
            reqres_failures_response_omission: Counter::default(),
            reqres_failures_dial: Counter::default(),
            reqres_failures_other: Counter::default(),
            identify_errors: Counter::default(),
            identify_errors_timeout: Counter::default(),
            identify_errors_io: Counter::default(),
            identify_errors_negotiation: Counter::default(),
            identify_errors_other: Counter::default(),
            control_list_denied: Counter::default(),
            control_list_denied_not_allowed: Counter::default(),
            control_list_denied_blocked: Counter::default(),
            control_list_updater_runs: Counter::default(),
            control_list_allow_update_success: Counter::default(),
            control_list_allow_update_failure: Counter::default(),
            control_list_block_update_success: Counter::default(),
            control_list_block_update_failure: Counter::default(),
            control_list_allow_apply: Counter::default(),
            control_list_block_apply: Counter::default(),
            state_transitions: Counter::default(),
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
            state_current: Gauge::default(),
            bootstrap_duration_seconds: Histogram::new(vec![
                0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0,
            ]),
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
            "network_dial_attempts_bootstrap",
            "Total bootstrap dial attempts.",
            self.dial_attempts_bootstrap.clone(),
        );
        registry.register(
            "network_dial_attempts_runtime",
            "Total runtime dial attempts.",
            self.dial_attempts_runtime.clone(),
        );
        registry.register(
            "network_dial_failures",
            "Total dial failures.",
            self.dial_failures.clone(),
        );
        registry.register(
            "network_dial_failures_local_peer_id",
            "Dial failures because the target peer id matches local peer id.",
            self.dial_failures_local_peer_id.clone(),
        );
        registry.register(
            "network_dial_failures_no_addresses",
            "Dial failures because there are no addresses to dial.",
            self.dial_failures_no_addresses.clone(),
        );
        registry.register(
            "network_dial_failures_peer_condition",
            "Dial failures because dial peer conditions were not met.",
            self.dial_failures_peer_condition.clone(),
        );
        registry.register(
            "network_dial_failures_denied",
            "Dial failures denied by behaviour.",
            self.dial_failures_denied.clone(),
        );
        registry.register(
            "network_dial_failures_aborted",
            "Dial failures due to aborted dial attempts.",
            self.dial_failures_aborted.clone(),
        );
        registry.register(
            "network_dial_failures_wrong_peer_id",
            "Dial failures due to remote peer id mismatch.",
            self.dial_failures_wrong_peer_id.clone(),
        );
        registry.register(
            "network_dial_failures_transport",
            "Dial failures produced by transport errors.",
            self.dial_failures_transport.clone(),
        );
        registry.register(
            "network_messages_dropped_outbound_queue_limit",
            "Outbound messages evicted due to queue limits.",
            self.dropped_outbound_queue_limit.clone(),
        );
        registry.register(
            "network_messages_dropped_inbound_queue_limit",
            "Inbound messages evicted due to queue limits.",
            self.dropped_inbound_queue_limit.clone(),
        );
        registry.register(
            "network_messages_dropped_outbound_queue_bytes_limit",
            "Outbound messages evicted or dropped due to queue bytes limit.",
            self.dropped_outbound_queue_bytes_limit.clone(),
        );
        registry.register(
            "network_messages_dropped_inbound_queue_bytes_limit",
            "Inbound messages evicted or dropped due to queue bytes limit.",
            self.dropped_inbound_queue_bytes_limit.clone(),
        );
        registry.register(
            "network_messages_dropped_max_retries",
            "Messages dropped after exhausting retries.",
            self.dropped_max_retries.clone(),
        );
        registry.register(
            "network_messages_dropped_oversized_inbound",
            "Inbound messages dropped for exceeding payload size limit.",
            self.dropped_oversized_inbound.clone(),
        );
        registry.register(
            "network_messages_dropped_oversized_outbound",
            "Outbound messages rejected for exceeding payload size limit.",
            self.dropped_oversized_outbound.clone(),
        );
        registry.register(
            "network_reqres_requests_received",
            "Total request-response request messages received.",
            self.reqres_requests_received.clone(),
        );
        registry.register(
            "network_reqres_responses_received",
            "Total request-response response messages received.",
            self.reqres_responses_received.clone(),
        );
        registry.register(
            "network_reqres_failures",
            "Total request-response failures.",
            self.reqres_failures.clone(),
        );
        registry.register(
            "network_reqres_failures_inbound",
            "Total inbound request-response failures.",
            self.reqres_failures_inbound.clone(),
        );
        registry.register(
            "network_reqres_failures_outbound",
            "Total outbound request-response failures.",
            self.reqres_failures_outbound.clone(),
        );
        registry.register(
            "network_reqres_failures_timeout",
            "Request-response failures caused by timeout.",
            self.reqres_failures_timeout.clone(),
        );
        registry.register(
            "network_reqres_failures_io",
            "Request-response failures caused by IO errors.",
            self.reqres_failures_io.clone(),
        );
        registry.register(
            "network_reqres_failures_negotiation",
            "Request-response failures caused by protocol negotiation mismatch.",
            self.reqres_failures_negotiation.clone(),
        );
        registry.register(
            "network_reqres_failures_connection_closed",
            "Request-response failures caused by connection closure.",
            self.reqres_failures_connection_closed.clone(),
        );
        registry.register(
            "network_reqres_failures_response_omission",
            "Request-response failures caused by missing responses.",
            self.reqres_failures_response_omission.clone(),
        );
        registry.register(
            "network_reqres_failures_dial",
            "Request-response failures caused by dial failures.",
            self.reqres_failures_dial.clone(),
        );
        registry.register(
            "network_reqres_failures_other",
            "Request-response failures caused by unknown errors.",
            self.reqres_failures_other.clone(),
        );
        registry.register(
            "network_identify_errors",
            "Total identify protocol errors.",
            self.identify_errors.clone(),
        );
        registry.register(
            "network_identify_errors_timeout",
            "Identify errors caused by timeout.",
            self.identify_errors_timeout.clone(),
        );
        registry.register(
            "network_identify_errors_io",
            "Identify errors caused by IO failures.",
            self.identify_errors_io.clone(),
        );
        registry.register(
            "network_identify_errors_negotiation",
            "Identify errors caused by protocol negotiation mismatch.",
            self.identify_errors_negotiation.clone(),
        );
        registry.register(
            "network_identify_errors_other",
            "Identify errors caused by unknown failures.",
            self.identify_errors_other.clone(),
        );
        registry.register(
            "network_control_list_denied",
            "Total denied connections by control list.",
            self.control_list_denied.clone(),
        );
        registry.register(
            "network_control_list_denied_not_allowed",
            "Denied connections because peer is not in allow list.",
            self.control_list_denied_not_allowed.clone(),
        );
        registry.register(
            "network_control_list_denied_blocked",
            "Denied connections because peer is blocked.",
            self.control_list_denied_blocked.clone(),
        );
        registry.register(
            "network_control_list_updater_runs",
            "Total control-list updater runs.",
            self.control_list_updater_runs.clone(),
        );
        registry.register(
            "network_control_list_allow_update_success",
            "Successful allow-list updater runs.",
            self.control_list_allow_update_success.clone(),
        );
        registry.register(
            "network_control_list_allow_update_failure",
            "Failed allow-list updater runs.",
            self.control_list_allow_update_failure.clone(),
        );
        registry.register(
            "network_control_list_block_update_success",
            "Successful block-list updater runs.",
            self.control_list_block_update_success.clone(),
        );
        registry.register(
            "network_control_list_block_update_failure",
            "Failed block-list updater runs.",
            self.control_list_block_update_failure.clone(),
        );
        registry.register(
            "network_control_list_allow_apply",
            "Applied allow-list updates in behaviour.",
            self.control_list_allow_apply.clone(),
        );
        registry.register(
            "network_control_list_block_apply",
            "Applied block-list updates in behaviour.",
            self.control_list_block_apply.clone(),
        );
        registry.register(
            "network_state_transitions",
            "Total network state transitions.",
            self.state_transitions.clone(),
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
            "network_state_current",
            "Current network state as numeric value (start=0,dial=1,dialing=2,running=3,disconnected=4).",
            self.state_current.clone(),
        );
        registry.register(
            "network_bootstrap_duration_seconds",
            "Bootstrap connection duration in seconds.",
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
        self.dial_attempts_bootstrap.inc();
    }

    pub(crate) fn inc_dial_attempt_runtime(&self) {
        self.dial_attempts_runtime.inc();
    }

    pub(crate) fn observe_dial_failure(&self, kind: &'static str) {
        self.dial_failures.inc();
        match kind {
            "local_peer_id" => {
                self.dial_failures_local_peer_id.inc();
            }
            "no_addresses" => {
                self.dial_failures_no_addresses.inc();
            }
            "peer_condition" => {
                self.dial_failures_peer_condition.inc();
            }
            "denied" => {
                self.dial_failures_denied.inc();
            }
            "aborted" => {
                self.dial_failures_aborted.inc();
            }
            "wrong_peer_id" => {
                self.dial_failures_wrong_peer_id.inc();
            }
            "transport" => {
                self.dial_failures_transport.inc();
            }
            _ => {}
        }
    }

    pub(crate) fn inc_outbound_queue_drop_by(&self, count: u64) {
        if count > 0 {
            self.dropped_outbound_queue_limit.inc_by(count);
        }
    }

    pub(crate) fn inc_inbound_queue_drop_by(&self, count: u64) {
        if count > 0 {
            self.dropped_inbound_queue_limit.inc_by(count);
        }
    }

    pub(crate) fn inc_outbound_queue_bytes_drop_by(&self, count: u64) {
        if count > 0 {
            self.dropped_outbound_queue_bytes_limit.inc_by(count);
        }
    }

    pub(crate) fn inc_inbound_queue_bytes_drop_by(&self, count: u64) {
        if count > 0 {
            self.dropped_inbound_queue_bytes_limit.inc_by(count);
        }
    }

    pub(crate) fn inc_max_retries_drop_by(&self, count: u64) {
        if count > 0 {
            self.dropped_max_retries.inc_by(count);
        }
    }

    pub(crate) fn inc_oversized_inbound_drop(&self) {
        self.dropped_oversized_inbound.inc();
    }

    pub(crate) fn inc_oversized_outbound_drop(&self) {
        self.dropped_oversized_outbound.inc();
    }

    pub(crate) fn inc_reqres_request_received(&self) {
        self.reqres_requests_received.inc();
    }

    pub(crate) fn inc_reqres_response_received(&self) {
        self.reqres_responses_received.inc();
    }

    pub(crate) fn observe_reqres_failure(
        &self,
        direction: &'static str,
        kind: &'static str,
    ) {
        self.reqres_failures.inc();
        match direction {
            "inbound" => {
                self.reqres_failures_inbound.inc();
            }
            "outbound" => {
                self.reqres_failures_outbound.inc();
            }
            _ => {}
        };
        match kind {
            "timeout" => {
                self.reqres_failures_timeout.inc();
            }
            "io" => {
                self.reqres_failures_io.inc();
            }
            "negotiation" => {
                self.reqres_failures_negotiation.inc();
            }
            "connection_closed" => {
                self.reqres_failures_connection_closed.inc();
            }
            "response_omission" => {
                self.reqres_failures_response_omission.inc();
            }
            "dial" => {
                self.reqres_failures_dial.inc();
            }
            _ => {
                self.reqres_failures_other.inc();
            }
        };
    }

    pub(crate) fn observe_identify_error(&self, kind: &'static str) {
        self.identify_errors.inc();
        match kind {
            "timeout" => {
                self.identify_errors_timeout.inc();
            }
            "io" => {
                self.identify_errors_io.inc();
            }
            "negotiation" => {
                self.identify_errors_negotiation.inc();
            }
            _ => {
                self.identify_errors_other.inc();
            }
        };
    }

    pub(crate) fn observe_control_list_denied(&self, reason: &'static str) {
        self.control_list_denied.inc();
        match reason {
            "not_allowed" => {
                self.control_list_denied_not_allowed.inc();
            }
            "blocked" => {
                self.control_list_denied_blocked.inc();
            }
            _ => {}
        };
    }

    pub(crate) fn inc_control_list_updater_run(&self) {
        self.control_list_updater_runs.inc();
    }

    pub(crate) fn observe_control_list_allow_update(&self, success: bool) {
        if success {
            self.control_list_allow_update_success.inc();
        } else {
            self.control_list_allow_update_failure.inc();
        }
    }

    pub(crate) fn observe_control_list_block_update(&self, success: bool) {
        if success {
            self.control_list_block_update_success.inc();
        } else {
            self.control_list_block_update_failure.inc();
        }
    }

    pub(crate) fn inc_control_list_allow_apply(&self) {
        self.control_list_allow_apply.inc();
    }

    pub(crate) fn inc_control_list_block_apply(&self) {
        self.control_list_block_apply.inc();
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
        let value = match state {
            NetworkState::Start => 0,
            NetworkState::Dial => 1,
            NetworkState::Dialing => 2,
            NetworkState::Running => 3,
            NetworkState::Disconnected => 4,
        };
        self.state_current.set(value);
    }

    pub(crate) fn observe_state_transition(&self, state: &NetworkState) {
        self.state_transitions.inc();
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

    pub(crate) fn observe_bootstrap_duration_seconds(&self, seconds: f64) {
        self.bootstrap_duration_seconds.observe(seconds);
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
