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
    dial_attempts_bootstrap_total: Counter,
    dial_attempts_runtime_total: Counter,
    dial_failures_total: Counter,
    dial_failures_local_peer_id_total: Counter,
    dial_failures_no_addresses_total: Counter,
    dial_failures_peer_condition_total: Counter,
    dial_failures_denied_total: Counter,
    dial_failures_aborted_total: Counter,
    dial_failures_wrong_peer_id_total: Counter,
    dial_failures_transport_total: Counter,
    dropped_outbound_queue_limit_total: Counter,
    dropped_inbound_queue_limit_total: Counter,
    dropped_max_retries_total: Counter,
    reqres_requests_received_total: Counter,
    reqres_responses_received_total: Counter,
    reqres_failures_total: Counter,
    reqres_failures_inbound_total: Counter,
    reqres_failures_outbound_total: Counter,
    reqres_failures_timeout_total: Counter,
    reqres_failures_io_total: Counter,
    reqres_failures_negotiation_total: Counter,
    reqres_failures_connection_closed_total: Counter,
    reqres_failures_response_omission_total: Counter,
    reqres_failures_dial_total: Counter,
    reqres_failures_other_total: Counter,
    identify_errors_total: Counter,
    identify_errors_timeout_total: Counter,
    identify_errors_io_total: Counter,
    identify_errors_negotiation_total: Counter,
    identify_errors_other_total: Counter,
    control_list_denied_total: Counter,
    control_list_denied_not_allowed_total: Counter,
    control_list_denied_blocked_total: Counter,
    state_transitions_total: Counter,
    retry_queue_len: Gauge,
    pending_outbound_peers: Gauge,
    pending_outbound_messages: Gauge,
    pending_inbound_peers: Gauge,
    pending_inbound_messages: Gauge,
    identified_peers: Gauge,
    response_channels_pending: Gauge,
    state_current: Gauge,
    bootstrap_duration_seconds: Histogram,
    pending_message_age_seconds: Histogram,
}

impl NetworkMetrics {
    fn new() -> Self {
        Self {
            dial_attempts_bootstrap_total: Counter::default(),
            dial_attempts_runtime_total: Counter::default(),
            dial_failures_total: Counter::default(),
            dial_failures_local_peer_id_total: Counter::default(),
            dial_failures_no_addresses_total: Counter::default(),
            dial_failures_peer_condition_total: Counter::default(),
            dial_failures_denied_total: Counter::default(),
            dial_failures_aborted_total: Counter::default(),
            dial_failures_wrong_peer_id_total: Counter::default(),
            dial_failures_transport_total: Counter::default(),
            dropped_outbound_queue_limit_total: Counter::default(),
            dropped_inbound_queue_limit_total: Counter::default(),
            dropped_max_retries_total: Counter::default(),
            reqres_requests_received_total: Counter::default(),
            reqres_responses_received_total: Counter::default(),
            reqres_failures_total: Counter::default(),
            reqres_failures_inbound_total: Counter::default(),
            reqres_failures_outbound_total: Counter::default(),
            reqres_failures_timeout_total: Counter::default(),
            reqres_failures_io_total: Counter::default(),
            reqres_failures_negotiation_total: Counter::default(),
            reqres_failures_connection_closed_total: Counter::default(),
            reqres_failures_response_omission_total: Counter::default(),
            reqres_failures_dial_total: Counter::default(),
            reqres_failures_other_total: Counter::default(),
            identify_errors_total: Counter::default(),
            identify_errors_timeout_total: Counter::default(),
            identify_errors_io_total: Counter::default(),
            identify_errors_negotiation_total: Counter::default(),
            identify_errors_other_total: Counter::default(),
            control_list_denied_total: Counter::default(),
            control_list_denied_not_allowed_total: Counter::default(),
            control_list_denied_blocked_total: Counter::default(),
            state_transitions_total: Counter::default(),
            retry_queue_len: Gauge::default(),
            pending_outbound_peers: Gauge::default(),
            pending_outbound_messages: Gauge::default(),
            pending_inbound_peers: Gauge::default(),
            pending_inbound_messages: Gauge::default(),
            identified_peers: Gauge::default(),
            response_channels_pending: Gauge::default(),
            state_current: Gauge::default(),
            bootstrap_duration_seconds: Histogram::new(vec![
                0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 20.0, 40.0, 80.0,
            ]),
            pending_message_age_seconds: Histogram::new(vec![
                0.01, 0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0,
            ]),
        }
    }

    fn register_into(&self, registry: &mut Registry) {
        registry.register(
            "network_dial_attempts_bootstrap",
            "Total bootstrap dial attempts.",
            self.dial_attempts_bootstrap_total.clone(),
        );
        registry.register(
            "network_dial_attempts_runtime",
            "Total runtime dial attempts.",
            self.dial_attempts_runtime_total.clone(),
        );
        registry.register(
            "network_dial_failures",
            "Total dial failures.",
            self.dial_failures_total.clone(),
        );
        registry.register(
            "network_dial_failures_local_peer_id",
            "Dial failures because the target peer id matches local peer id.",
            self.dial_failures_local_peer_id_total.clone(),
        );
        registry.register(
            "network_dial_failures_no_addresses",
            "Dial failures because there are no addresses to dial.",
            self.dial_failures_no_addresses_total.clone(),
        );
        registry.register(
            "network_dial_failures_peer_condition",
            "Dial failures because dial peer conditions were not met.",
            self.dial_failures_peer_condition_total.clone(),
        );
        registry.register(
            "network_dial_failures_denied",
            "Dial failures denied by behaviour.",
            self.dial_failures_denied_total.clone(),
        );
        registry.register(
            "network_dial_failures_aborted",
            "Dial failures due to aborted dial attempts.",
            self.dial_failures_aborted_total.clone(),
        );
        registry.register(
            "network_dial_failures_wrong_peer_id",
            "Dial failures due to remote peer id mismatch.",
            self.dial_failures_wrong_peer_id_total.clone(),
        );
        registry.register(
            "network_dial_failures_transport",
            "Dial failures produced by transport errors.",
            self.dial_failures_transport_total.clone(),
        );
        registry.register(
            "network_messages_dropped_outbound_queue_limit",
            "Outbound messages evicted due to queue limits.",
            self.dropped_outbound_queue_limit_total.clone(),
        );
        registry.register(
            "network_messages_dropped_inbound_queue_limit",
            "Inbound messages evicted due to queue limits.",
            self.dropped_inbound_queue_limit_total.clone(),
        );
        registry.register(
            "network_messages_dropped_max_retries",
            "Messages dropped after exhausting retries.",
            self.dropped_max_retries_total.clone(),
        );
        registry.register(
            "network_reqres_requests_received",
            "Total request-response request messages received.",
            self.reqres_requests_received_total.clone(),
        );
        registry.register(
            "network_reqres_responses_received",
            "Total request-response response messages received.",
            self.reqres_responses_received_total.clone(),
        );
        registry.register(
            "network_reqres_failures",
            "Total request-response failures.",
            self.reqres_failures_total.clone(),
        );
        registry.register(
            "network_reqres_failures_inbound",
            "Total inbound request-response failures.",
            self.reqres_failures_inbound_total.clone(),
        );
        registry.register(
            "network_reqres_failures_outbound",
            "Total outbound request-response failures.",
            self.reqres_failures_outbound_total.clone(),
        );
        registry.register(
            "network_reqres_failures_timeout",
            "Request-response failures caused by timeout.",
            self.reqres_failures_timeout_total.clone(),
        );
        registry.register(
            "network_reqres_failures_io",
            "Request-response failures caused by IO errors.",
            self.reqres_failures_io_total.clone(),
        );
        registry.register(
            "network_reqres_failures_negotiation",
            "Request-response failures caused by protocol negotiation mismatch.",
            self.reqres_failures_negotiation_total.clone(),
        );
        registry.register(
            "network_reqres_failures_connection_closed",
            "Request-response failures caused by connection closure.",
            self.reqres_failures_connection_closed_total.clone(),
        );
        registry.register(
            "network_reqres_failures_response_omission",
            "Request-response failures caused by missing responses.",
            self.reqres_failures_response_omission_total.clone(),
        );
        registry.register(
            "network_reqres_failures_dial",
            "Request-response failures caused by dial failures.",
            self.reqres_failures_dial_total.clone(),
        );
        registry.register(
            "network_reqres_failures_other",
            "Request-response failures caused by unknown errors.",
            self.reqres_failures_other_total.clone(),
        );
        registry.register(
            "network_identify_errors",
            "Total identify protocol errors.",
            self.identify_errors_total.clone(),
        );
        registry.register(
            "network_identify_errors_timeout",
            "Identify errors caused by timeout.",
            self.identify_errors_timeout_total.clone(),
        );
        registry.register(
            "network_identify_errors_io",
            "Identify errors caused by IO failures.",
            self.identify_errors_io_total.clone(),
        );
        registry.register(
            "network_identify_errors_negotiation",
            "Identify errors caused by protocol negotiation mismatch.",
            self.identify_errors_negotiation_total.clone(),
        );
        registry.register(
            "network_identify_errors_other",
            "Identify errors caused by unknown failures.",
            self.identify_errors_other_total.clone(),
        );
        registry.register(
            "network_control_list_denied",
            "Total denied connections by control list.",
            self.control_list_denied_total.clone(),
        );
        registry.register(
            "network_control_list_denied_not_allowed",
            "Denied connections because peer is not in allow list.",
            self.control_list_denied_not_allowed_total.clone(),
        );
        registry.register(
            "network_control_list_denied_blocked",
            "Denied connections because peer is blocked.",
            self.control_list_denied_blocked_total.clone(),
        );
        registry.register(
            "network_state_transitions",
            "Total network state transitions.",
            self.state_transitions_total.clone(),
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
    }

    pub(crate) fn inc_dial_attempt_bootstrap(&self) {
        self.dial_attempts_bootstrap_total.inc();
    }

    pub(crate) fn inc_dial_attempt_runtime(&self) {
        self.dial_attempts_runtime_total.inc();
    }

    pub(crate) fn observe_dial_failure(&self, kind: &'static str) {
        self.dial_failures_total.inc();
        match kind {
            "local_peer_id" => {
                self.dial_failures_local_peer_id_total.inc();
            }
            "no_addresses" => {
                self.dial_failures_no_addresses_total.inc();
            }
            "peer_condition" => {
                self.dial_failures_peer_condition_total.inc();
            }
            "denied" => {
                self.dial_failures_denied_total.inc();
            }
            "aborted" => {
                self.dial_failures_aborted_total.inc();
            }
            "wrong_peer_id" => {
                self.dial_failures_wrong_peer_id_total.inc();
            }
            "transport" => {
                self.dial_failures_transport_total.inc();
            }
            _ => {}
        }
    }

    pub(crate) fn inc_outbound_queue_drop(&self) {
        self.dropped_outbound_queue_limit_total.inc();
    }

    pub(crate) fn inc_inbound_queue_drop(&self) {
        self.dropped_inbound_queue_limit_total.inc();
    }

    pub(crate) fn inc_max_retries_drop_by(&self, count: u64) {
        if count > 0 {
            self.dropped_max_retries_total.inc_by(count);
        }
    }

    pub(crate) fn inc_reqres_request_received(&self) {
        self.reqres_requests_received_total.inc();
    }

    pub(crate) fn inc_reqres_response_received(&self) {
        self.reqres_responses_received_total.inc();
    }

    pub(crate) fn observe_reqres_failure(
        &self,
        direction: &'static str,
        kind: &'static str,
    ) {
        self.reqres_failures_total.inc();
        match direction {
            "inbound" => {
                self.reqres_failures_inbound_total.inc();
            }
            "outbound" => {
                self.reqres_failures_outbound_total.inc();
            }
            _ => {}
        };
        match kind {
            "timeout" => {
                self.reqres_failures_timeout_total.inc();
            }
            "io" => {
                self.reqres_failures_io_total.inc();
            }
            "negotiation" => {
                self.reqres_failures_negotiation_total.inc();
            }
            "connection_closed" => {
                self.reqres_failures_connection_closed_total.inc();
            }
            "response_omission" => {
                self.reqres_failures_response_omission_total.inc();
            }
            "dial" => {
                self.reqres_failures_dial_total.inc();
            }
            _ => {
                self.reqres_failures_other_total.inc();
            }
        };
    }

    pub(crate) fn observe_identify_error(&self, kind: &'static str) {
        self.identify_errors_total.inc();
        match kind {
            "timeout" => {
                self.identify_errors_timeout_total.inc();
            }
            "io" => {
                self.identify_errors_io_total.inc();
            }
            "negotiation" => {
                self.identify_errors_negotiation_total.inc();
            }
            _ => {
                self.identify_errors_other_total.inc();
            }
        };
    }

    pub(crate) fn observe_control_list_denied(&self, reason: &'static str) {
        self.control_list_denied_total.inc();
        match reason {
            "not_allowed" => {
                self.control_list_denied_not_allowed_total.inc();
            }
            "blocked" => {
                self.control_list_denied_blocked_total.inc();
            }
            _ => {}
        };
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
        self.state_transitions_total.inc();
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

    pub(crate) fn set_pending_inbound_peers(&self, value: i64) {
        self.pending_inbound_peers.set(value);
    }

    pub(crate) fn set_pending_inbound_messages(&self, value: i64) {
        self.pending_inbound_messages.set(value);
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
