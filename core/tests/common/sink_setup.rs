use std::{collections::BTreeSet, time::Duration};

use ave_common::{IncomingSinkEvent, SinkTypes, sink::DataToSinkEvent};
use ave_core::{
    Api,
    config::{SinkConfigEntry, SinkServer, SinkTarget},
};
use ave_network::NodeType;
use serde_json::{Value, json};

use crate::common::CreateNodeConfig;

pub const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

pub fn example_schema_governance_fact() -> serde_json::Value {
    json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "tracker_schemas": {
                "add": {
                    "issuer": [
                        { "name": "Owner", "namespace": [] }
                    ]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "witness": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity"
                            }
                        ]
                    }
                }
            ]
        }
    })
}

pub fn make_sink_entry(
    server_name: &str,
    url: String,
    governance_id: Option<String>,
    events: BTreeSet<SinkTypes>,
) -> SinkConfigEntry {
    make_sink_entry_with_concurrency(server_name, url, governance_id, events, 2)
}

pub fn make_sink_entry_with_concurrency(
    server_name: &str,
    url: String,
    governance_id: Option<String>,
    events: BTreeSet<SinkTypes>,
    max_catch_up_concurrency: usize,
) -> SinkConfigEntry {
    SinkConfigEntry {
        target: SinkTarget::Schema {
            schema_id: "Example".to_owned(),
            governance_id,
        },
        servers: vec![SinkServer {
            server: server_name.to_owned(),
            events,
            url,
            max_retries: 0,
            healthcheck_intervals_secs: vec![1],
            startup_healthcheck_delay_secs: 0,
            request_timeout_ms: 2000,
            connect_timeout_ms: 1000,
            max_catch_up_concurrency,
            ..Default::default()
        }],
    }
}

pub fn example_sink_config(
    url: String,
    governance_id: Option<String>,
) -> Vec<SinkConfigEntry> {
    vec![make_sink_entry(
        "example-sink",
        url,
        governance_id,
        BTreeSet::from([SinkTypes::All]),
    )]
}

/// Returns a sink configuration designed to trigger flapping detection after
/// one failed recovery.
pub fn flapping_sink_config(
    url: String,
    governance_id: Option<String>,
) -> Vec<SinkConfigEntry> {
    vec![SinkConfigEntry {
        target: SinkTarget::Schema {
            schema_id: "Example".to_owned(),
            governance_id,
        },
        servers: vec![SinkServer {
            server: "example-sink".to_owned(),
            events: BTreeSet::from([SinkTypes::All]),
            url,
            max_retries: 0,
            request_timeout_ms: 500,
            healthcheck_intervals_secs: vec![1],
            startup_healthcheck_delay_secs: 0,
            max_recoveries_after_failure: 1,
            ..Default::default()
        }],
    }]
}

/// Returns a sink configuration with a very short worker idle timeout so the
/// worker is stopped quickly when inactive. Used to test worker shutdown and
/// recreation.
pub fn short_idle_sink_config(
    url: String,
    governance_id: Option<String>,
) -> Vec<SinkConfigEntry> {
    vec![SinkConfigEntry {
        target: SinkTarget::Schema {
            schema_id: "Example".to_owned(),
            governance_id,
        },
        servers: vec![SinkServer {
            server: "example-sink".to_owned(),
            events: BTreeSet::from([SinkTypes::All]),
            url,
            max_retries: 0,
            request_timeout_ms: 500,
            healthcheck_intervals_secs: vec![1],
            startup_healthcheck_delay_secs: 0,
            sink_worker_idle_timeout_ms: 200,
            sink_subject_worker_idle_timeout_ms: 200,
            ..Default::default()
        }],
    }]
}

/// Poll `get_sinks_status` until `sink_name` is reported as blocked.
/// Returns the block reason. Panics on timeout.
pub async fn wait_for_sink_blocked(api: &Api, sink_name: &str) -> String {
    let mut attempts = 0;
    loop {
        let statuses = api.get_sinks_status().await.unwrap();
        if let Some(status) = statuses.iter().find(|s| s.name == sink_name) {
            if let Some(reason) = &status.blocked {
                return reason.clone();
            }
        }
        if attempts > 100 {
            panic!("timeout waiting for sink {} to be blocked", sink_name);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Poll `get_sinks_status` until `sink_name` is no longer blocked.
/// Panics on timeout.
pub async fn wait_for_sink_unblocked(api: &Api, sink_name: &str) {
    let mut attempts = 0;
    loop {
        let statuses = api.get_sinks_status().await.unwrap();
        if let Some(status) = statuses.iter().find(|s| s.name == sink_name) {
            if status.blocked.is_none() {
                return;
            }
        }
        if attempts > 100 {
            panic!("timeout waiting for sink {} to be unblocked", sink_name);
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Poll `get_sinks_status` until `sink_name` reports at least `min`
/// lagging subjects. Panics on timeout.
pub async fn wait_for_sink_lagging_subjects(
    api: &Api,
    sink_name: &str,
    min: usize,
) {
    let mut attempts = 0;
    loop {
        let statuses = api.get_sinks_status().await.unwrap();
        if let Some(status) = statuses.iter().find(|s| s.name == sink_name) {
            if status.lagging_subjects >= min {
                return;
            }
        }
        if attempts > 100 {
            panic!(
                "timeout waiting for sink {} to have {} lagging subjects",
                sink_name, min
            );
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        attempts += 1;
    }
}

/// Assert through `get_sinks_status` that `sink_name` is currently blocked.
/// Returns the block reason. Panics if the sink is missing or not blocked.
pub async fn assert_sink_blocked(api: &Api, sink_name: &str) -> String {
    let statuses = api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == sink_name)
        .unwrap_or_else(|| {
            panic!("sink {} not found in status response", sink_name)
        });
    assert!(
        status.blocked.is_some(),
        "sink {} should be blocked, but it is not",
        sink_name
    );
    status.blocked.clone().unwrap()
}

/// Assert through `get_sinks_status` that `sink_name` is currently not blocked.
/// Panics if the sink is missing or still blocked.
pub async fn assert_sink_unblocked(api: &Api, sink_name: &str) {
    let statuses = api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == sink_name)
        .unwrap_or_else(|| {
            panic!("sink {} not found in status response", sink_name)
        });
    assert!(
        status.blocked.is_none(),
        "sink {} should not be blocked, but it is: {:?}",
        sink_name,
        status.blocked
    );
}

/// Assert through `get_sinks_status` that `sink_name` has at least `min`
/// lagging subjects. Panics if the sink is missing or has fewer.
pub async fn assert_sink_lagging(api: &Api, sink_name: &str, min: usize) {
    let statuses = api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == sink_name)
        .unwrap_or_else(|| {
            panic!("sink {} not found in status response", sink_name)
        });
    assert!(
        status.lagging_subjects >= min,
        "sink {} should have at least {} lagging subjects, has {}",
        sink_name,
        min,
        status.lagging_subjects
    );
}

/// Assert through `get_sinks_status` that `sink_name` has no lagging subjects.
/// Panics if the sink is missing or still lagging.
pub async fn assert_sink_not_lagging(api: &Api, sink_name: &str) {
    let statuses = api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == sink_name)
        .unwrap_or_else(|| {
            panic!("sink {} not found in status response", sink_name)
        });
    assert_eq!(
        status.lagging_subjects, 0,
        "sink {} should have no lagging subjects, has {}",
        sink_name, status.lagging_subjects
    );
}

/// Assert through `get_sinks_status` that `sink_name` is running.
/// Panics if the sink is missing or not running.
pub async fn assert_sink_running(api: &Api, sink_name: &str) {
    let statuses = api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == sink_name)
        .unwrap_or_else(|| {
            panic!("sink {} not found in status response", sink_name)
        });
    assert!(
        status.running,
        "sink {} should be running, but it is not",
        sink_name
    );
}

pub fn governance_with_transfer_roles_fact(
    new_owner_key: &str,
) -> serde_json::Value {
    json!({
        "members": {
            "add": [
                {
                    "name": "NewOwner",
                    "key": new_owner_key
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
        "roles": {
            "tracker_schemas": {
                "add": {
                    "issuer": [
                        { "name": "Owner", "namespace": [] }
                    ]
                }
            },
            "governance": {
                "add": {
                    "witness": ["NewOwner"]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "witness": [
                            { "name": "Owner", "namespace": [] },
                            { "name": "NewOwner", "namespace": [] }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity"
                            },
                            {
                                "name": "NewOwner",
                                "namespace": [],
                                "quantity": "infinity"
                            }
                        ]
                    }
                }
            ]
        }
    })
}

pub fn governance_with_viewpoints_fact(witness_key: &str) -> serde_json::Value {
    json!({
        "members": {
            "add": [
                {
                    "name": "Witness",
                    "key": witness_key
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    },
                    "viewpoints": ["agua", "basura"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Witness"]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "validator": [
                            { "name": "Owner", "namespace": [] }
                        ],
                        "witness": [
                            { "name": "Owner", "namespace": [] },
                            { "name": "Witness", "namespace": [] }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    { "name": "Witness", "viewpoints": [] }
                                ]
                            }
                        ],
                        "issuer": [
                            { "name": "Owner", "namespace": [] }
                        ]
                    }
                }
            ]
        }
    })
}

pub fn governance_sink_config(url: String) -> Vec<SinkConfigEntry> {
    vec![SinkConfigEntry {
        target: SinkTarget::Schema {
            schema_id: "governance".to_owned(),
            governance_id: None,
        },
        servers: vec![SinkServer {
            server: "gov-sink".to_owned(),
            events: BTreeSet::from([SinkTypes::All]),
            url,
            max_retries: 0,
            healthcheck_intervals_secs: vec![1],
            startup_healthcheck_delay_secs: 0,
            request_timeout_ms: 2000,
            connect_timeout_ms: 1000,
            ..Default::default()
        }],
    }]
}

pub fn restart_config(
    keys: ave_common::identity::keys::KeyPair,
    local_db: std::path::PathBuf,
    ext_db: std::path::PathBuf,
    listen_address: String,
    sinks: Vec<SinkConfigEntry>,
) -> CreateNodeConfig {
    restart_config_with_peers(
        keys,
        local_db,
        ext_db,
        listen_address,
        vec![],
        sinks,
    )
}

pub fn restart_config_with_peers(
    keys: ave_common::identity::keys::KeyPair,
    local_db: std::path::PathBuf,
    ext_db: std::path::PathBuf,
    listen_address: String,
    peers: Vec<ave_network::RoutingNode>,
    sinks: Vec<SinkConfigEntry>,
) -> CreateNodeConfig {
    CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        is_service: false,
        only_clear_events: false,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        ledger_batch_size: None,
        safe_mode: false,
        sinks,
    }
}

pub fn assert_event_is_create(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => {
            assert!(matches!(data.payload, DataToSinkEvent::Create { .. }));
        }
        _ => panic!("expected full create event"),
    }
}

pub fn assert_event_is_fact_full(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
    success: bool,
    expected_payload: Option<Value>,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactFull {
                success: s,
                payload,
                ..
            } => {
                assert_eq!(*s, success, "unexpected success flag at sn {}", sn);
                if let Some(expected) = expected_payload {
                    assert_eq!(
                        payload, &expected,
                        "unexpected payload at sn {}",
                        sn
                    );
                }
            }
            other => panic!("expected FactFull event, got {:?}", other),
        },
        _ => panic!("expected full fact event"),
    }
}

pub fn assert_event_is_fact_opaque(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
    success: bool,
    expected_viewpoints: &[&str],
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => match &data.payload {
            DataToSinkEvent::FactOpaque {
                success: s,
                viewpoints,
                ..
            } => {
                assert_eq!(*s, success, "unexpected success flag at sn {}", sn);
                let expected: Vec<String> = expected_viewpoints
                    .iter()
                    .map(|v| (*v).to_owned())
                    .collect();
                assert_eq!(
                    viewpoints, &expected,
                    "unexpected viewpoints at sn {}",
                    sn
                );
            }
            other => panic!("expected FactOpaque event, got {:?}", other),
        },
        _ => panic!("expected full opaque fact event"),
    }
}

/// Asserts that `event` is a lightweight fact event for `subject_id` at `sn`
/// with the expected success flag and governance identifier.
pub fn assert_event_is_light_fact(
    event: &IncomingSinkEvent,
    subject_id: &str,
    governance_id: &str,
    sn: u64,
    success: bool,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Light(l) => {
            assert_eq!(l.subject_id, subject_id, "unexpected subject_id");
            assert_eq!(l.schema_id, "Example", "unexpected schema_id");
            assert_eq!(
                l.governance_id.as_ref().unwrap(),
                governance_id,
                "unexpected governance_id"
            );
            assert_eq!(l.sn, sn, "unexpected sn");
            assert_eq!(l.event_type, SinkTypes::Fact, "unexpected event type");
            assert_eq!(
                l.success, success,
                "unexpected success flag at sn {}",
                sn
            );
        }
        other => panic!("expected light fact event, got {:?}", other),
    }
}

pub fn sample_sinks() -> Vec<SinkConfigEntry> {
    vec![
        SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "governance".to_owned(),
                governance_id: None,
            },
            servers: vec![SinkServer {
                server: "gov-sink".to_owned(),
                url: "http://localhost:9000".to_owned(),
                ..Default::default()
            }],
        },
        SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "Example1".to_owned(),
                governance_id: Some("some-governance".to_owned()),
            },
            servers: vec![SinkServer {
                server: "schema-sink".to_owned(),
                url: "http://localhost:9001".to_owned(),
                ..Default::default()
            }],
        },
    ]
}

/// Returns the first event in `events` matching `subject_id` and `sn`, or panics.
fn find_event<'a>(
    events: &'a [IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
) -> &'a IncomingSinkEvent {
    events
        .iter()
        .find(|e| e.subject_id() == subject_id && e.sn() == sn)
        .unwrap_or_else(|| {
            panic!(
                "event not found for subject {} sn {} in {:?}",
                subject_id, sn, events
            )
        })
}

/// Asserts that `events` contains a Create event for `subject_id` at `sn`.
pub fn assert_sink_contains_create(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_create(event, subject_id, sn);
}

/// Asserts that `events` contains a FactFull event for `subject_id` at `sn`.
pub fn assert_sink_contains_fact_full(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
    success: bool,
    expected_payload: Option<Value>,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_fact_full(event, subject_id, sn, success, expected_payload);
}

/// Asserts that `events` contains a FactOpaque event for `subject_id` at `sn`.
pub fn assert_sink_contains_fact_opaque(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
    success: bool,
    expected_viewpoints: &[&str],
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_fact_opaque(
        event,
        subject_id,
        sn,
        success,
        expected_viewpoints,
    );
}

/// Asserts that `events` contains a lightweight fact event for `subject_id`
/// at `sn` with the expected success flag and governance identifier.
pub fn assert_sink_contains_light_fact(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    governance_id: &str,
    sn: u64,
    success: bool,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_light_fact(event, subject_id, governance_id, sn, success);
}

/// Counts how many events belong to `subject_id`.
pub fn count_events_for_subject(
    events: &[IncomingSinkEvent],
    subject_id: &str,
) -> usize {
    events
        .iter()
        .filter(|e| e.subject_id() == subject_id)
        .count()
}

pub fn assert_event_is_transfer(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => {
            assert!(matches!(data.payload, DataToSinkEvent::Transfer { .. }));
        }
        _ => panic!("expected full transfer event"),
    }
}

pub fn assert_event_is_confirm(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => {
            assert!(matches!(data.payload, DataToSinkEvent::Confirm { .. }));
        }
        _ => panic!("expected full confirm event"),
    }
}

pub fn assert_event_is_reject(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => {
            assert!(matches!(data.payload, DataToSinkEvent::Reject { .. }));
        }
        _ => panic!("expected full reject event"),
    }
}

pub fn assert_event_is_eol(
    event: &IncomingSinkEvent,
    subject_id: &str,
    sn: u64,
) {
    assert_eq!(event.subject_id(), subject_id);
    assert_eq!(event.sn(), sn);
    match event {
        IncomingSinkEvent::Full(data) => {
            assert!(matches!(data.payload, DataToSinkEvent::Eol { .. }));
        }
        _ => panic!("expected full eol event"),
    }
}

pub fn assert_sink_contains_transfer(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_transfer(event, subject_id, sn);
}

pub fn assert_sink_contains_confirm(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_confirm(event, subject_id, sn);
}

pub fn assert_sink_contains_reject(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_reject(event, subject_id, sn);
}

pub fn assert_sink_contains_eol(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    sn: u64,
) {
    let event = find_event(events, subject_id, sn);
    assert_event_is_eol(event, subject_id, sn);
}

/// Asserts that `events` contains no duplicate `(subject_id, sn)` pairs.
pub fn assert_no_duplicate_events(events: &[IncomingSinkEvent]) {
    use std::collections::HashSet;
    let mut seen = HashSet::new();
    for event in events {
        let key = (event.subject_id().to_owned(), event.sn());
        assert!(
            seen.insert(key.clone()),
            "duplicate event for subject {} sn {}",
            key.0,
            key.1
        );
    }
}

/// Asserts that, for each subject, the sequence of SNs in `events` is exactly
/// `expected_from..=expected_to` in order.
pub fn assert_subject_sn_sequence(
    events: &[IncomingSinkEvent],
    subject_id: &str,
    expected_from: u64,
    expected_to: u64,
) {
    let sns: Vec<u64> = events
        .iter()
        .filter(|e| e.subject_id() == subject_id)
        .map(|e| e.sn())
        .collect();
    let expected: Vec<u64> = (expected_from..=expected_to).collect();
    assert_eq!(
        sns, expected,
        "subject {} should have consecutive SNs from {} to {}",
        subject_id, expected_from, expected_to
    );
}

/// Asserts that none of the events in `events` is a `FactFull` payload.
pub fn assert_no_fact_full_events(events: &[IncomingSinkEvent]) {
    assert!(
        !events.iter().any(|e| matches!(
            e,
            IncomingSinkEvent::Full(data)
                if matches!(data.payload, DataToSinkEvent::FactFull { .. })
        )),
        "create-only sink must not contain FactFull events, only Create and LightEvent"
    );
}
