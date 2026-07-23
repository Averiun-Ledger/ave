mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ave_common::{
    LightEvent, SchemaType, SinkTarget, SinkTypes,
    identity::{
        BLAKE3_HASHER, Hash as _, PublicKey, SignatureIdentifier, TimeStamp,
        keys::KeyPair,
    },
    sink::{DataToSink, DataToSinkEvent, IncomingSinkEvent},
};
use ave_core::config::{
    KafkaAcks, KafkaCompression, KafkaSaslMechanism, KafkaSecurityConfig,
    KafkaSinkConfig, KafkaTlsConfig, SinkConfigEntry, SinkServer,
    SinkTransportConfig,
};
use ave_core::sink::SinkError;
use ave_core::sink::SinkTransport;
use ave_core::sink::kafka::KafkaTransport;
use ave_network::NodeType;
use futures::future::join_all;
use serde_json::json;
use std::str::FromStr;
use tracing_test::traced_test;

use common::TempEnvVar;
use common::kafka_setup::{RedpandaEnv, RedpandaSaslEnv, RedpandaTlsEnv};
use common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
    create_and_authorize_governance, create_node, create_nodes_and_connections,
    create_subject, emit_confirm, emit_eol, emit_fact, emit_reject,
    emit_transfer, get_subject, node_running,
    sink_setup::{
        assert_sink_contains_confirm, assert_sink_contains_create,
        assert_sink_contains_eol, assert_sink_contains_fact_full,
        assert_sink_contains_reject, assert_sink_contains_transfer,
        example_schema_governance_fact, governance_with_transfer_roles_fact,
        restart_config, restart_config_with_peers, wait_for_sink_caught_up,
        wait_for_sink_lagging_subjects,
    },
};

const SUBJECT_ID: &str = "KAFKA-SUBJECT-ID";
const SCHEMA_ID: &str = "Example";
const TIMEOUT: Duration = Duration::from_secs(20);

fn kafka_sink_config(bootstrap_servers: &str, topic: &str) -> KafkaSinkConfig {
    KafkaSinkConfig {
        bootstrap_servers: bootstrap_servers.to_string(),
        topic: topic.to_string(),
        ..KafkaSinkConfig::default()
    }
}

fn kafka_sink_config_with(
    bootstrap_servers: &str,
    topic: &str,
    f: impl FnOnce(&mut KafkaSinkConfig),
) -> KafkaSinkConfig {
    let mut cfg = kafka_sink_config(bootstrap_servers, topic);
    f(&mut cfg);
    cfg
}

fn kafka_sink_config_sasl(
    bootstrap_servers: &str,
    topic: &str,
    username: &str,
) -> KafkaSinkConfig {
    KafkaSinkConfig {
        bootstrap_servers: bootstrap_servers.to_string(),
        topic: topic.to_string(),
        security: KafkaSecurityConfig::SaslPlaintext {
            mechanism: KafkaSaslMechanism::ScramSha256,
            username: username.to_string(),
        },
        ..KafkaSinkConfig::default()
    }
}

fn example_data_to_sink(subject_id: &str, schema_id: &str) -> DataToSink {
    DataToSink {
        payload: DataToSinkEvent::Create {
            governance_id: None,
            subject_id: subject_id.to_string(),
            owner: "owner".to_string(),
            schema_id: SchemaType::Type(schema_id.to_string()),
            namespace: "".to_string(),
            sn: 0,
            gov_version: 1,
            state: serde_json::json!({ "one": 1 }),
        },
        public_key: "pk".to_string(),
        event_request_timestamp: 1,
        event_ledger_timestamp: 2,
        sink_timestamp: 3,
    }
}

fn example_light_event(subject_id: &str, schema_id: &str) -> LightEvent {
    LightEvent {
        subject_id: subject_id.to_string(),
        schema_id: schema_id.to_string(),
        governance_id: None,
        sn: 1,
        event_type: SinkTypes::Fact,
        success: true,
    }
}

/// Happy path: full events, light events and `{{subject-id}}` topic templates
/// are all delivered with the subject id as the message key.
#[tokio::test]
async fn kafka_transport_happy_path() {
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test".to_string(),
        kafka_sink_config(&env.bootstrap_servers, "ave-{{schema-id}}"),
        None,
    )
    .unwrap();

    // Full event.
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    // Light event.
    transport
        .send_light(example_light_event(SUBJECT_ID, SCHEMA_ID))
        .await
        .unwrap();

    let messages = env.consume_string("ave-Example", 2, TIMEOUT).await;
    assert_eq!(messages.len(), 2, "expected full + light events");
    assert_eq!(messages[0].0, SUBJECT_ID);
    assert_eq!(messages[1].0, SUBJECT_ID);

    let full: serde_json::Value = serde_json::from_str(&messages[0].1).unwrap();
    assert_eq!(full["public_key"], "pk");
    assert_eq!(full["event_request_timestamp"], 1);

    let light: serde_json::Value =
        serde_json::from_str(&messages[1].1).unwrap();
    assert_eq!(light["subject_id"], SUBJECT_ID);
    assert_eq!(light["event_type"], "fact");

    // Topic template that resolves to the subject id.
    let template_subject = "TEMPLATE-SUBJECT-ID";
    let transport = KafkaTransport::new(
        "test".to_string(),
        kafka_sink_config(&env.bootstrap_servers, "{{subject-id}}"),
        None,
    )
    .unwrap();
    transport
        .send(Arc::new(example_data_to_sink(template_subject, SCHEMA_ID)))
        .await
        .unwrap();

    let messages = env.consume_string(template_subject, 1, TIMEOUT).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, template_subject);
}

/// Delivery headers: every event carries subject_id, sn, event_type,
/// idempotency-key and a unique request-id.
#[tokio::test]
async fn kafka_transport_sends_delivery_headers() {
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test-headers".to_string(),
        kafka_sink_config(&env.bootstrap_servers, "headers-{{schema-id}}"),
        None,
    )
    .unwrap();

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let messages = env
        .consume_with_headers("headers-Example", 2, TIMEOUT)
        .await;
    assert_eq!(messages.len(), 2);

    fn get<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    // First delivery.
    let (_, _, headers) = &messages[0];
    assert_eq!(get(headers, "x-ave-subject-id"), Some(SUBJECT_ID));
    assert_eq!(get(headers, "x-ave-sn"), Some("0"));
    assert_eq!(get(headers, "x-ave-event-type"), Some("create"));
    assert_eq!(
        get(headers, "idempotency-key"),
        Some(format!("{}-0", SUBJECT_ID).as_str())
    );
    let first_request_id =
        get(headers, "x-ave-request-id").expect("request id header");
    assert!(!first_request_id.is_empty());

    // Second delivery: same idempotency key (retry-deduplication) but a
    // different request id.
    let (_, _, headers) = &messages[1];
    let second_request_id =
        get(headers, "x-ave-request-id").expect("request id header");
    assert_ne!(
        first_request_id, second_request_id,
        "each delivery attempt must carry a unique request id"
    );
    assert_eq!(
        get(headers, "idempotency-key"),
        Some(format!("{}-0", SUBJECT_ID).as_str())
    );
}

/// Test endpoint: `test()` performs a health check and sends a test message
/// marked with `x-ave-test: true` and a test-specific key.
#[tokio::test]
async fn kafka_transport_test_sends_test_message() {
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test-endpoint".to_string(),
        kafka_sink_config(&env.bootstrap_servers, "test-topic"),
        None,
    )
    .unwrap();

    transport.test().await.unwrap();

    let messages = env
        .consume_with_headers("test-topic", 1, TIMEOUT)
        .await;
    assert_eq!(messages.len(), 1);
    let (key, payload, headers) = &messages[0];

    assert!(
        key.starts_with("__ave-test-"),
        "test message key must start with __ave-test-, got {}",
        key
    );

    let payload: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(payload["test"], true);

    let get = |name: &str| {
        headers
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    };
    assert_eq!(get("x-ave-test"), Some("true"));
    let request_id = get("x-ave-request-id").expect("request id header");
    assert!(!request_id.is_empty());
}

/// Test endpoint with an `{{event-type}}` topic template: the test delivery
/// must render every placeholder and land in a valid, fully-rendered topic
/// (a literal `{{event-type}}` would be an invalid topic name).
#[tokio::test]
async fn kafka_transport_test_renders_event_type_template() {
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test-endpoint-event-type".to_string(),
        kafka_sink_config(
            &env.bootstrap_servers,
            "test-{{schema-id}}-{{event-type}}",
        ),
        None,
    )
    .unwrap();

    transport.test().await.unwrap();

    // subject="-", schema="-", event-type="test" -> "test---test".
    let messages = env.consume_with_headers("test---test", 1, TIMEOUT).await;
    assert_eq!(messages.len(), 1);
    let (_, payload, headers) = &messages[0];

    let payload: serde_json::Value = serde_json::from_str(payload).unwrap();
    assert_eq!(payload["test"], true);

    let is_test = headers
        .iter()
        .find(|(k, _)| k == "x-ave-test")
        .map(|(_, v)| v.as_str());
    assert_eq!(is_test, Some("true"));
}

/// Request ID in logs and headers: the same `request_id` appears in the
/// delivery log and in the message headers, so node and receiver logs can be
/// correlated.
#[tokio::test]
#[traced_test]
async fn kafka_transport_logs_request_id() {
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test-logs".to_string(),
        kafka_sink_config(&env.bootstrap_servers, "logs-{{schema-id}}"),
        None,
    )
    .unwrap();

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let messages = env
        .consume_with_headers("logs-Example", 1, TIMEOUT)
        .await;
    let (_, _, headers) = &messages[0];
    let header_request_id = headers
        .iter()
        .find(|(k, _)| k == "x-ave-request-id")
        .map(|(_, v)| v.as_str())
        .expect("request id header");

    logs_assert(|lines: &[&str]| {
        let sink_send = lines
            .iter()
            .find(|line| line.contains("Sink delivery succeeded"))
            .expect("SinkSend log not found");
        assert!(
            sink_send.contains(header_request_id),
            "log must contain the same request_id as the header: {}",
            sink_send
        );
        Ok(())
    });
}

/// Retry with a real broker: when the topic does not exist yet, the first
/// attempt fails with `UnknownTopicOrPartition` (retryable) and the retry
/// succeeds once Redpanda auto-creates the topic.
#[tokio::test]
async fn kafka_transport_retries_on_unknown_topic() {
    let env = RedpandaEnv::start().await;
    let topic = "retry-unknown-topic";

    // The topic does not exist yet; the first attempt will fail with
    // UnknownTopicOrPartition (retryable) and the retry will succeed once
    // Redpanda auto-creates it.
    let config = kafka_sink_config_with(
        &env.bootstrap_servers,
        topic,
        |cfg| {
            cfg.max_retries = 2;
            cfg.retry_base_delay_ms = 100;
            cfg.retry_max_delay_ms = 500;
        },
    );
    let transport = KafkaTransport::new("test-retry".to_string(), config, None).unwrap();

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let messages = env.consume_string(topic, 1, TIMEOUT).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, SUBJECT_ID);
}

/// Retry exhaustion with a real unreachable broker: after `max_retries` the
/// transport returns a retryable error, not a permanent one.
#[tokio::test]
async fn kafka_transport_retry_exhaustion_returns_retryable_error() {
    // Point to a non-existent broker to force a transient error on every
    // attempt; the producer will retry until max_retries and then fail.
    let config = kafka_sink_config_with(
        "127.0.0.1:1", // unreachable
        "retry-exhaustion-test",
        |cfg| {
            cfg.max_retries = 1;
            cfg.retry_base_delay_ms = 50;
            cfg.retry_max_delay_ms = 100;
        },
    );
    let transport = KafkaTransport::new("test-retry-fail".to_string(), config, None).unwrap();

    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;
    assert!(
        result.is_err(),
        "unreachable broker must fail after max_retries"
    );

    // The error must be retryable (transient), not permanent.
    match result.unwrap_err() {
        SinkError::Delivery { retryable, .. } => {
            assert!(retryable, "broker unavailable must be retryable");
        }
        other => panic!("expected Delivery error, got {:?}", other),
    }
}

/// TLS with a custom CA: the node must deliver to a TLS-enabled Redpanda
/// whose server certificate chains to a CA configured via `tls.ca_certificate`.
///
/// **Flow:**
/// 1. Start a TLS Redpanda with a throwaway CA.
/// 2. Build a transport with `security: Ssl` and `tls.ca_certificate` pointing
///    to the generated CA.
/// 3. Send a full event; verify it arrives over TLS.
#[tokio::test]
async fn kafka_transport_tls_custom_ca() {
    let env = RedpandaTlsEnv::start().await;

    let ca_path = std::env::temp_dir().join("ave-kafka-test-ca.pem");
    std::fs::write(&ca_path, &env.ca_pem).unwrap();

    let config = KafkaSinkConfig {
        bootstrap_servers: env.bootstrap_servers.clone(),
        topic: "tls-{{schema-id}}".to_owned(),
        security: KafkaSecurityConfig::Ssl,
        tls: Some(KafkaTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..KafkaTlsConfig::default()
        }),
        ..KafkaSinkConfig::default()
    };
    let transport = KafkaTransport::new("test-tls".to_string(), config, None).unwrap();

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let messages = env.consume_string("tls-Example", 1, TIMEOUT).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, SUBJECT_ID);
}

/// TLS without the CA: delivery to a TLS-enabled Redpanda must fail when the
/// node does not trust the sink's CA (no `tls.ca_certificate` configured).
#[tokio::test]
async fn kafka_transport_tls_missing_ca_fails() {
    let env = RedpandaTlsEnv::start().await;

    let config = KafkaSinkConfig {
        bootstrap_servers: env.bootstrap_servers.clone(),
        topic: "tls-missing-ca".to_owned(),
        security: KafkaSecurityConfig::Ssl,
        tls: None,
        ..KafkaSinkConfig::default()
    };
    let transport =
        KafkaTransport::new("test-tls-fail".to_string(), config, None).unwrap();

    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;
    assert!(
        result.is_err(),
        "delivery must fail when the CA is not trusted"
    );
}

/// Configuration variants: all supported compression codecs and acks levels
/// deliver successfully.
#[tokio::test]
async fn kafka_transport_config_variants() {
    let env = RedpandaEnv::start().await;

    for compression in [
        KafkaCompression::None,
        KafkaCompression::Gzip,
        KafkaCompression::Snappy,
        KafkaCompression::Lz4,
        KafkaCompression::Zstd,
    ] {
        let name = compression.as_str();
        let config = kafka_sink_config_with(
            &env.bootstrap_servers,
            &format!("comp-{name}"),
            |cfg| cfg.compression = compression,
        );
        let transport =
            KafkaTransport::new("test".to_string(), config, None).unwrap();
        transport
            .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
            .await
            .unwrap();

        let messages = env
            .consume_string(&format!("comp-{name}"), 1, TIMEOUT)
            .await;
        assert_eq!(messages.len(), 1, "compression={name}");
        assert_eq!(messages[0].0, SUBJECT_ID);
    }

    for acks in [KafkaAcks::Zero, KafkaAcks::One, KafkaAcks::All] {
        let name = acks.as_str();
        let config = kafka_sink_config_with(
            &env.bootstrap_servers,
            &format!("acks-{name}"),
            |cfg| cfg.acks = acks,
        );
        let transport =
            KafkaTransport::new("test".to_string(), config, None).unwrap();
        transport
            .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
            .await
            .unwrap();

        let messages = env
            .consume_string(&format!("acks-{name}"), 1, TIMEOUT)
            .await;
        assert_eq!(messages.len(), 1, "acks={name}");
        assert_eq!(messages[0].0, SUBJECT_ID);
    }
}

/// Error taxonomy: invalid configuration is rejected at build time, unreachable
/// brokers are retryable and oversized messages are rejected.
#[tokio::test]
async fn kafka_transport_error_handling() {
    // SASL without a password environment variable.
    let config = KafkaSinkConfig {
        bootstrap_servers: "broker:9092".to_string(),
        topic: "t".to_string(),
        security: KafkaSecurityConfig::SaslPlaintext {
            mechanism: KafkaSaslMechanism::Plain,
            username: "u".to_string(),
        },
        ..KafkaSinkConfig::default()
    };
    let err = KafkaTransport::new("test".to_string(), config, None).unwrap_err();
    assert!(matches!(err, SinkError::ClientBuild(_)));

    // Invalid acks values are rejected at deserialization time.
    assert!(
        serde_json::from_str::<KafkaSinkConfig>(
            r#"{"bootstrap_servers": "broker:9092", "topic": "t", "acks": "2"}"#
        )
        .is_err()
    );

    // Unreachable broker is reported as a retryable delivery error.
    let config = KafkaSinkConfig {
        bootstrap_servers: "127.0.0.1:1".to_string(),
        topic: "t".to_string(),
        request_timeout_ms: 500,
        ..KafkaSinkConfig::default()
    };
    let transport = KafkaTransport::new("test".to_string(), config, None).unwrap();
    let err = transport.health_check().await.unwrap_err();
    assert!(
        matches!(
            err,
            SinkError::Delivery {
                retryable: true,
                ..
            }
        ),
        "expected retryable delivery error, got {err:?}"
    );

    // Message larger than librdkafka's default local limit is rejected.
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test".to_string(),
        kafka_sink_config(&env.bootstrap_servers, "ave-{{schema-id}}"),
        None,
    )
    .unwrap();

    let mut data = example_data_to_sink("BIG-SUBJECT", SCHEMA_ID);
    data.payload = DataToSinkEvent::Create {
        governance_id: None,
        subject_id: "BIG-SUBJECT".to_string(),
        owner: "owner".to_string(),
        schema_id: SchemaType::Type(SCHEMA_ID.to_string()),
        namespace: "".to_string(),
        sn: 0,
        gov_version: 1,
        state: serde_json::json!({ "big": "a".repeat(2_000_000) }),
    };

    let err = transport.send(Arc::new(data)).await.unwrap_err();
    assert!(
        matches!(err, SinkError::Rejected { .. }),
        "expected rejected error, got {err:?}"
    );
}

/// SASL/SCRAM authentication: a valid password delivers the event and an
/// invalid password prevents the connection from being established.
#[tokio::test]
async fn kafka_transport_sasl() {
    let username = "ave";
    let password = "test-password";
    let env = RedpandaSaslEnv::start(username, password).await;

    let _ok_env = TempEnvVar::set("AVE_SINK_PASSWORD_SASL_OK", password);
    let transport = KafkaTransport::new(
        "sasl-ok".to_string(),
        kafka_sink_config_sasl(&env.bootstrap_servers, "ave-sasl-ok", username),
        None,
    )
    .unwrap();
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let messages = env.consume_string("ave-sasl-ok", 1, TIMEOUT).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, SUBJECT_ID);

    let _bad_env =
        TempEnvVar::set("AVE_SINK_PASSWORD_SASL_BAD", "wrong-password");
    let bad_config = KafkaSinkConfig {
        bootstrap_servers: env.bootstrap_servers.clone(),
        topic: "ave-sasl-bad".to_string(),
        security: KafkaSecurityConfig::SaslPlaintext {
            mechanism: KafkaSaslMechanism::ScramSha256,
            username: username.to_string(),
        },
        request_timeout_ms: 30_000,
        ..KafkaSinkConfig::default()
    };
    let transport =
        KafkaTransport::new("sasl-bad".to_string(), bad_config, None).unwrap();
    // Force an immediate connection attempt; librdkafka may report the bad
    // credentials as an auth error or, with some broker timings, as a
    // retryable connection timeout.
    let err = transport.health_check().await.unwrap_err();

    assert!(
        matches!(
            err,
            SinkError::Auth { .. }
                | SinkError::Delivery {
                    retryable: true,
                    ..
                }
        ),
        "expected auth or retryable connection error, got {err:?}"
    );
}

/// Builds a sink configuration entry that delivers governance `Example` tracker
/// events to a Kafka topic.
fn make_kafka_sink_entry(
    server_name: &str,
    bootstrap_servers: String,
    topic: &str,
    governance_id: Option<String>,
    events: BTreeSet<SinkTypes>,
) -> SinkConfigEntry {
    SinkConfigEntry {
        target: SinkTarget::Schema {
            schema_id: "Example".to_owned(),
            governance_id,
        },
        servers: vec![SinkServer {
            server: server_name.to_owned(),
            events,
            transport: SinkTransportConfig::Kafka(KafkaSinkConfig {
                bootstrap_servers,
                topic: topic.to_owned(),
                ..KafkaSinkConfig::default()
            }),
            healthcheck_intervals_secs: vec![1],
            startup_healthcheck_delay_secs: 0,
            max_catch_up_concurrency: 2,
            ..Default::default()
        }],
    }
}

/// End-to-end test: every ledger event type produced by the node (Create, Fact,
/// Transfer, Confirm, Reject and EOL) is delivered to Kafka with the subject id
/// as the message key.
#[traced_test]
#[tokio::test]
async fn kafka_node_emits_all_event_types() {
    let env = RedpandaEnv::start().await;
    let topic = "ave-node-events";

    let (mut nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ephemeral: vec![],
            always_accept: true,
            ..Default::default()
        })
        .await;

    let mut owner = nodes.remove(0);
    let mut new_owner = nodes.remove(0);

    let mut owner_dirs: Vec<_> = dirs.drain(0..2).collect();
    let mut new_owner_dirs: Vec<_> = dirs.drain(0..2).collect();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![&new_owner.api]).await;

    emit_fact(
        &owner.api,
        governance_id.clone(),
        governance_with_transfer_roles_fact(new_owner.api.public_key()),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    // Restart owner with a Kafka sink configured for all event types.
    let owner_keys: KeyPair = owner.keys.clone();
    let owner_local_db = owner_dirs[0].path().to_path_buf();
    let owner_ext_db = owner_dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (owner, mut owner_dirs2) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{}", owner_port),
        always_accept: true,
        keys: Some(owner_keys),
        local_db: Some(owner_local_db),
        ext_db: Some(owner_ext_db),
        sinks: vec![make_kafka_sink_entry(
            "kafka-node-sink",
            env.bootstrap_servers.clone(),
            topic,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
        ..Default::default()
    })
    .await;
    owner_dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    // Restart new_owner connected to owner so it can witness the events.
    let owner_peer_id = owner.api.peer_id().to_string();
    let owner_address = owner.listen_address.clone();

    let new_owner_keys: KeyPair = new_owner.keys.clone();
    let new_owner_local_db = new_owner_dirs[0].path().to_path_buf();
    let new_owner_ext_db = new_owner_dirs[1].path().to_path_buf();
    new_owner.token.cancel();
    join_all(new_owner.handler.iter_mut()).await;

    let new_owner_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (new_owner, mut new_owner_dirs2) =
        create_node(restart_config_with_peers(
            new_owner_keys,
            new_owner_local_db,
            new_owner_ext_db,
            format!("/memory/{}", new_owner_port),
            vec![ave_network::RoutingNode {
                peer_id: owner_peer_id,
                address: vec![owner_address],
            }],
            vec![],
        ))
        .await;
    new_owner_dirs.append(&mut new_owner_dirs2);
    node_running(&new_owner.api).await.unwrap();

    get_subject(&new_owner.api, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    // Emit a representative set of ledger events.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    emit_fact(
        &owner.api,
        subject_id.clone(),
        json!({"ModThree": {"data": 50}}),
        true,
    )
    .await
    .unwrap();

    let new_owner_pk = PublicKey::from_str(new_owner.api.public_key()).unwrap();
    emit_transfer(&owner.api, subject_id.clone(), new_owner_pk, true)
        .await
        .unwrap();

    get_subject(&new_owner.api, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_confirm(&new_owner.api, subject_id.clone(), None, true)
        .await
        .unwrap();

    let owner_pk = PublicKey::from_str(owner.api.public_key()).unwrap();
    emit_transfer(&new_owner.api, subject_id.clone(), owner_pk, true)
        .await
        .unwrap();

    get_subject(&owner.api, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    emit_reject(&owner.api, subject_id.clone(), true)
        .await
        .unwrap();

    emit_eol(&new_owner.api, subject_id.clone(), true)
        .await
        .unwrap();

    // Consume all events from Kafka and verify each event type and SN.
    let messages = env.consume_string(topic, 8, Duration::from_secs(30)).await;
    assert_eq!(messages.len(), 8, "expected 8 ledger events in Kafka");

    let events: Vec<IncomingSinkEvent> = messages
        .iter()
        .map(|(_, payload)| serde_json::from_str(payload).unwrap())
        .collect();

    let subject_id_str = subject_id.to_string();
    assert!(
        messages.iter().all(|(key, _)| key == &subject_id_str),
        "all Kafka message keys must be the subject id"
    );
    assert_sink_contains_create(&events, &subject_id_str, 0);
    assert_sink_contains_fact_full(
        &events,
        &subject_id_str,
        1,
        true,
        Some(json!({"ModOne": {"data": 1}})),
    );
    assert_sink_contains_fact_full(
        &events,
        &subject_id_str,
        2,
        false,
        Some(json!({"ModThree": {"data": 50}})),
    );
    assert_sink_contains_transfer(&events, &subject_id_str, 3);
    assert_sink_contains_confirm(&events, &subject_id_str, 4);
    assert_sink_contains_transfer(&events, &subject_id_str, 5);
    assert_sink_contains_reject(&events, &subject_id_str, 6);
    assert_sink_contains_eol(&events, &subject_id_str, 7);
}

/// Batch delivery: without `{{event-type}}` in the topic template the whole
/// batch is delivered as a single Kafka message with a JSON array body, even
/// when it mixes event types, using the topic template and the subject id as
/// the message key.
#[tokio::test]
async fn kafka_transport_batch_delivery() {
    let env = RedpandaEnv::start().await;
    let config = kafka_sink_config_with(
        &env.bootstrap_servers,
        "batch-{{schema-id}}",
        |cfg| cfg.batch_delivery = true,
    );
    let transport = KafkaTransport::new("test-batch".to_string(), config, None).unwrap();

    let events: Vec<IncomingSinkEvent> = vec![
        IncomingSinkEvent::Full(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID))),
        IncomingSinkEvent::Light(example_light_event(SUBJECT_ID, SCHEMA_ID)),
    ];

    transport.send_batch(events).await.unwrap();

    let messages = env.consume_string("batch-Example", 1, TIMEOUT).await;
    assert_eq!(messages.len(), 1);
    assert_eq!(messages[0].0, SUBJECT_ID);

    let batch: Vec<IncomingSinkEvent> =
        serde_json::from_str(&messages[0].1).unwrap();
    assert_eq!(batch.len(), 2);

    assert!(
        matches!(batch[0], IncomingSinkEvent::Full(_)),
        "first batch element must be the full create event"
    );
    assert_eq!(batch[0].event_type(), SinkTypes::Create);
    assert_eq!(batch[0].subject_id(), SUBJECT_ID);

    assert!(
        matches!(batch[1], IncomingSinkEvent::Light(_)),
        "second batch element must be the light fact event"
    );
    assert_eq!(batch[1].event_type(), SinkTypes::Fact);
    assert_eq!(batch[1].subject_id(), SUBJECT_ID);
}

/// Batch with mixed event types and an `{{event-type}}` topic template: the
/// batch is grouped by event type and each group is delivered as its own
/// array message to the matching topic, preserving order inside the group.
#[tokio::test]
async fn kafka_transport_batch_groups_by_event_type() {
    let env = RedpandaEnv::start().await;
    let config = kafka_sink_config_with(
        &env.bootstrap_servers,
        "batch-{{schema-id}}-{{event-type}}",
        |cfg| cfg.batch_delivery = true,
    );
    let transport =
        KafkaTransport::new("test-batch-event-type".to_string(), config, None)
            .unwrap();

    let light = |sn: u64| LightEvent {
        subject_id: SUBJECT_ID.to_string(),
        schema_id: SCHEMA_ID.to_string(),
        governance_id: None,
        sn,
        event_type: SinkTypes::Fact,
        success: true,
    };

    let events: Vec<IncomingSinkEvent> = vec![
        IncomingSinkEvent::Full(Arc::new(example_data_to_sink(
            SUBJECT_ID, SCHEMA_ID,
        ))),
        IncomingSinkEvent::Light(light(1)),
        IncomingSinkEvent::Light(light(2)),
    ];

    transport.send_batch(events).await.unwrap();

    // The create event goes to its own topic as a one-element array.
    let create_messages =
        env.consume_string("batch-Example-create", 1, TIMEOUT).await;
    assert_eq!(create_messages.len(), 1);
    assert_eq!(create_messages[0].0, SUBJECT_ID);
    let creates: Vec<IncomingSinkEvent> =
        serde_json::from_str(&create_messages[0].1).unwrap();
    assert_eq!(creates.len(), 1);
    assert_eq!(creates[0].event_type(), SinkTypes::Create);

    // Both facts go to the fact topic as a single ordered array.
    let fact_messages =
        env.consume_string("batch-Example-fact", 1, TIMEOUT).await;
    assert_eq!(fact_messages.len(), 1);
    assert_eq!(fact_messages[0].0, SUBJECT_ID);
    let facts: Vec<IncomingSinkEvent> =
        serde_json::from_str(&fact_messages[0].1).unwrap();
    assert_eq!(facts.len(), 2);
    assert!(facts.iter().all(|e| e.event_type() == SinkTypes::Fact));
    assert_eq!(facts[0].sn(), 1);
    assert_eq!(facts[1].sn(), 2);
}

/// Topic template with `{{event-type}}`: the topic is rendered with the
/// event type so different event types can go to different topics.
#[tokio::test]
async fn kafka_transport_topic_template_with_event_type() {
    let env = RedpandaEnv::start().await;
    let transport = KafkaTransport::new(
        "test-event-type".to_string(),
        kafka_sink_config(
            &env.bootstrap_servers,
            "ave-{{schema-id}}-{{event-type}}",
        ),
        None,
    )
    .unwrap();

    // Full event (create).
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    // Light event (fact).
    transport
        .send_light(example_light_event(SUBJECT_ID, SCHEMA_ID))
        .await
        .unwrap();

    let create_messages = env.consume_string("ave-Example-create", 1, TIMEOUT).await;
    assert_eq!(create_messages.len(), 1);
    assert_eq!(create_messages[0].0, SUBJECT_ID);

    let fact_messages = env.consume_string("ave-Example-fact", 1, TIMEOUT).await;
    assert_eq!(fact_messages.len(), 1);
    assert_eq!(fact_messages[0].0, SUBJECT_ID);
}

/// Signature requires a signer: enabling `signature: true` without a node
/// signer fails at build time with a clear error.
#[tokio::test]
async fn kafka_transport_signature_requires_signer() {
    let env = RedpandaEnv::start().await;
    let topic = "signature-{{schema-id}}";

    let mut config = kafka_sink_config(&env.bootstrap_servers, topic);
    config.signature = true;

    let err = KafkaTransport::new("test-signature".to_string(), config, None)
        .unwrap_err();
    assert!(
        matches!(err, SinkError::ClientBuild(_)),
        "expected ClientBuild error, got {:?}",
        err
    );
}

/// Signature headers with node signer: every delivery carries
/// `x-ave-signature`, `x-ave-signature-timestamp` and `x-ave-public-key`
/// headers, and the signature verifies against the payload.
#[traced_test]
#[tokio::test]
async fn kafka_node_signature_headers() {
    let env = RedpandaEnv::start().await;
    let topic = "signature-node-{{schema-id}}";

    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let node_public_key = keys.public_key().to_string();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (node, mut new_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(keys),
        local_db: Some(local_db),
        ext_db: Some(ext_db),
        sinks: vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "Example".to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: "signature-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Kafka(KafkaSinkConfig {
                    bootstrap_servers: env.bootstrap_servers.clone(),
                    topic: topic.to_owned(),
                    signature: true,
                    ..KafkaSinkConfig::default()
                }),
                ..Default::default()
            }],
        }],
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    let messages = env
        .consume_with_headers("signature-node-Example", 2, TIMEOUT)
        .await;
    assert_eq!(messages.len(), 2);

    let public_key = PublicKey::from_str(&node_public_key)
        .expect("node public key must parse");

    for (_, payload, headers) in &messages {
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };

        let signature = get("x-ave-signature").expect("signature header");
        let timestamp = get("x-ave-signature-timestamp")
            .expect("timestamp header");
        let signer_key = get("x-ave-public-key").expect("public key header");

        // The signer must be the node identity.
        assert_eq!(signer_key, node_public_key);

        // Rebuild the signing payload exactly as `Signature::new` does:
        // borsh(content, timestamp), then Blake3.
        let timestamp = TimeStamp::from_nanos(
            timestamp.parse().expect("timestamp must be nanos u64"),
        );
        let signing_payload = (payload.clone().into_bytes(), timestamp);
        let payload_bytes =
            borsh::to_vec(&signing_payload).expect("borsh serialization");
        let content_hash = BLAKE3_HASHER.hash(&payload_bytes);

        let signature_id = SignatureIdentifier::from_str(signature)
            .expect("signature header must parse");

        // The signature must verify against the delivered payload.
        public_key
            .verify(content_hash.hash_bytes(), &signature_id)
            .expect("delivery signature must verify");

        // A tampered payload must not verify.
        let tampered_payload = (b"tampered".to_vec(), timestamp);
        let tampered_bytes =
            borsh::to_vec(&tampered_payload).expect("borsh serialization");
        let tampered_hash = BLAKE3_HASHER.hash(&tampered_bytes);
        assert!(
            public_key
                .verify(tampered_hash.hash_bytes(), &signature_id)
                .is_err(),
            "signature must not verify for a tampered payload"
        );
    }
}

/// Batch delivery end-to-end: with `batch_delivery` enabled on a Kafka sink,
/// the worker buffers live events and flushes them as a single Kafka message
/// with a JSON array body once `batch_delivery_size` is reached; the startup
/// catch-up also delivers the backlog as array messages.
#[traced_test]
#[tokio::test]
async fn kafka_node_batch_delivery() {
    let env = RedpandaEnv::start().await;
    let topic = "ave-node-batch";

    // Boot without sinks: governance, Example schema and one subject.
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    // Restart with a batch Kafka sink: flush every 3 events, with a delay
    // high enough that only the size-based flush fires during the test.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst)),
        vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "Example".to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: "kafka-batch-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Kafka(KafkaSinkConfig {
                    bootstrap_servers: env.bootstrap_servers.clone(),
                    topic: topic.to_owned(),
                    batch_delivery: true,
                    batch_max_delay_ms: 30_000,
                    ..KafkaSinkConfig::default()
                }),
                batch_delivery_size: 3,
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 2,
                ..Default::default()
            }],
        }],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Synchronize with the startup catch-up before emitting live events:
    // consume the Create array (proves the backlog was delivered) and wait
    // until the sink reports the subject as caught up. Without this, facts
    // emitted during catch-up can be picked up by the catch-up queries and
    // delivered as separate one-element arrays, racing the live batch.
    let first = env.consume_string(topic, 1, TIMEOUT).await;
    assert_eq!(first.len(), 1, "catch-up must deliver the Create array");
    let catch_up: Vec<IncomingSinkEvent> =
        serde_json::from_str(&first[0].1).unwrap();
    assert_eq!(catch_up.len(), 1, "catch-up batch must hold Create only");
    assert_sink_contains_create(&catch_up, &subject_id_str, 0);
    wait_for_sink_caught_up(&node.api, "kafka-batch-sink").await;

    // Three facts fill the buffer and trigger the size-based flush.
    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // The three facts arrive as a single array message. The consumer reads
    // from the beginning, so it sees the catch-up array again first.
    let messages = env.consume_string(topic, 2, TIMEOUT).await;
    assert_eq!(
        messages.len(),
        2,
        "expected catch-up array + live batch array"
    );

    for (key, _) in &messages {
        assert_eq!(key, &subject_id_str);
    }

    let batch: Vec<IncomingSinkEvent> =
        serde_json::from_str(&messages[1].1).unwrap();
    assert_eq!(batch.len(), 3, "live batch must hold the three facts");
    for (i, event) in batch.iter().enumerate() {
        let sn = (i + 1) as u64;
        assert_sink_contains_fact_full(
            std::slice::from_ref(event),
            &subject_id_str,
            sn,
            true,
            Some(json!({"ModOne": {"data": sn}})),
        );
    }

    // Batch deliveries advance the cursor: the sink must not be lagging.
    wait_for_sink_caught_up(&node.api, "kafka-batch-sink").await;
}

/// Batch delivery timer flush: when the buffer never reaches
/// `batch_delivery_size`, the `batch_max_delay_ms` timer flushes the pending
/// events as a single JSON array message.
///
/// The test follows the established restart pattern (sink configured with
/// the real `governance_id` of a subject created pre-restart). To make the
/// live timer flush deterministic, we synchronize with the startup catch-up
/// — consume the Create array it delivers and then wait for the sink to
/// report caught up — before emitting facts. Without this, catch-up queries
/// could pick up freshly emitted facts as separate one-element arrays,
/// racing the live flush.
#[traced_test]
#[tokio::test]
async fn kafka_node_batch_delivery_timer_flush() {
    let env = RedpandaEnv::start().await;
    let topic = "ave-node-batch-timer";

    // Boot without sinks: governance, Example schema and one subject.
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    // Restart with a batch Kafka sink whose size threshold is unreachable
    // (100), so only the flush timer can deliver the live events. The delay
    // must comfortably exceed the time between the two `emit_fact` calls
    // because the window starts when the first event is buffered.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst)),
        vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "Example".to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: "kafka-batch-timer-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Kafka(KafkaSinkConfig {
                    bootstrap_servers: env.bootstrap_servers.clone(),
                    topic: topic.to_owned(),
                    batch_delivery: true,
                    batch_max_delay_ms: 10_000,
                    ..KafkaSinkConfig::default()
                }),
                batch_delivery_size: 100,
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 2,
                ..Default::default()
            }],
        }],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Synchronize with the startup catch-up before emitting live events:
    // consume the Create array (proves the backlog was delivered and creates
    // the topic on the broker) and wait for the sink to report caught up so
    // the follow-up catch-up queries have completed.
    let first = env.consume_string(topic, 1, TIMEOUT).await;
    assert_eq!(first.len(), 1, "catch-up must deliver the Create array");
    let catch_up: Vec<IncomingSinkEvent> =
        serde_json::from_str(&first[0].1).unwrap();
    assert_eq!(catch_up.len(), 1, "catch-up batch must hold Create only");
    assert_sink_contains_create(&catch_up, &subject_id_str, 0);
    wait_for_sink_caught_up(&node.api, "kafka-batch-timer-sink").await;

    // Two facts stay below the size threshold: the flush timer delivers them
    // as a single array message once the 10s window elapses.
    for i in 1..=2 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // The consumer reads from the beginning, so it sees the catch-up array
    // first and then the timer-flushed batch array.
    let messages = env.consume_string(topic, 2, Duration::from_secs(30)).await;
    assert_eq!(
        messages.len(),
        2,
        "expected catch-up array + timer-flushed batch array"
    );

    for (key, _) in &messages {
        assert_eq!(key, &subject_id_str);
    }

    let batch: Vec<IncomingSinkEvent> =
        serde_json::from_str(&messages[1].1).unwrap();
    assert_eq!(batch.len(), 2, "timer batch must hold both facts");
    for (i, event) in batch.iter().enumerate() {
        let sn = (i + 1) as u64;
        assert_sink_contains_fact_full(
            std::slice::from_ref(event),
            &subject_id_str,
            sn,
            true,
            Some(json!({"ModOne": {"data": sn}})),
        );
    }

    wait_for_sink_caught_up(&node.api, "kafka-batch-timer-sink").await;
}

/// Signature version 2: the signed content binds the critical delivery
/// headers (content-type, idempotency-key, event-type, sn, subject-id) so
/// tampering with any of them invalidates the signature.
#[traced_test]
#[tokio::test]
async fn kafka_node_signature_v2_binds_headers() {
    let env = RedpandaEnv::start().await;
    let topic = "ave-signature-v2";

    // Boot without sinks: governance, Example schema and one subject.
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let keys = node.keys.clone();
    let node_public_key = keys.public_key().to_string();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst)),
        vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "Example".to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: "kafka-signature-v2-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Kafka(KafkaSinkConfig {
                    bootstrap_servers: env.bootstrap_servers.clone(),
                    topic: topic.to_owned(),
                    signature: true,
                    signature_version: 2,
                    ..KafkaSinkConfig::default()
                }),
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 2,
                ..Default::default()
            }],
        }],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    emit_fact(
        &node.api,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // Create (catch-up) + one live fact, both signed with version 2.
    let messages = env.consume_with_headers(topic, 2, TIMEOUT).await;
    assert_eq!(messages.len(), 2);

    let public_key = PublicKey::from_str(&node_public_key)
        .expect("node public key must parse");

    // Rebuild the canonical signed content from the delivery headers and the
    // body: `name:value\n` lines in lexicographic order, then the body.
    let canonical = |payload: &str,
                     headers: &[(String, String)],
                     sn_override: Option<&str>|
     -> Vec<u8> {
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .unwrap_or_else(|| panic!("{name} header missing"))
                .1
                .clone()
        };
        let sn = sn_override.map(str::to_owned).unwrap_or_else(|| get("x-ave-sn"));
        let mut lines = vec![
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", get("idempotency-key")),
            ("x-ave-event-type", get("x-ave-event-type")),
            ("x-ave-sn", sn),
            ("x-ave-subject-id", get("x-ave-subject-id")),
        ];
        lines.sort_by(|a, b| a.0.cmp(b.0));

        let mut out = Vec::with_capacity(payload.len() + 256);
        for (name, value) in lines {
            out.extend_from_slice(name.as_bytes());
            out.push(b':');
            out.extend_from_slice(value.as_bytes());
            out.push(b'\n');
        }
        out.extend_from_slice(payload.as_bytes());
        out
    };

    for (_, payload, headers) in &messages {
        let get = |name: &str| {
            headers
                .iter()
                .find(|(k, _)| k == name)
                .map(|(_, v)| v.as_str())
        };

        let signature = get("x-ave-signature").expect("signature header");
        let timestamp = get("x-ave-signature-timestamp")
            .expect("timestamp header");
        let signer_key = get("x-ave-public-key").expect("public key header");
        assert_eq!(signer_key, node_public_key);

        let timestamp = TimeStamp::from_nanos(
            timestamp.parse().expect("timestamp must be nanos u64"),
        );
        let signature_id = SignatureIdentifier::from_str(signature)
            .expect("signature header must parse");

        // The signature must verify against the canonical content.
        let signed_content = (canonical(payload, headers, None), timestamp);
        let signed_bytes =
            borsh::to_vec(&signed_content).expect("borsh serialization");
        let content_hash = BLAKE3_HASHER.hash(&signed_bytes);
        public_key
            .verify(content_hash.hash_bytes(), &signature_id)
            .expect("v2 signature must verify against headers + body");

        // Tampering with a bound header (the sn) must invalidate it.
        let tampered_content =
            (canonical(payload, headers, Some("999")), timestamp);
        let tampered_bytes =
            borsh::to_vec(&tampered_content).expect("borsh serialization");
        let tampered_hash = BLAKE3_HASHER.hash(&tampered_bytes);
        assert!(
            public_key
                .verify(tampered_hash.hash_bytes(), &signature_id)
                .is_err(),
            "v2 signature must not verify with a tampered sn header"
        );
    }
}

/// Broker-down recovery: with the broker unreachable the startup catch-up
/// cannot deliver and the subject stays in `lagging`; after a restart with
/// the broker available, automatic catch-up delivers the backlog.
#[traced_test]
#[tokio::test]
async fn kafka_broker_down_and_catch_up() {
    let env = RedpandaEnv::start().await;
    let topic = "ave-broker-down";

    // Boot without sinks: create the governance, the Example schema, a
    // subject and three facts.
    let (mut node, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&node.api, vec![]).await;
    emit_fact(
        &node.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&node.api, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    let subject_id_str = subject_id.to_string();

    for i in 1..=3 {
        emit_fact(
            &node.api,
            subject_id.clone(),
            json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Restart with the sink pointing to a broker that does not exist: the
    // startup catch-up cannot deliver and the subject stays lagging.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (mut node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst)),
        vec![make_kafka_sink_entry(
            "kafka-down-sink",
            "127.0.0.1:1".to_string(),
            topic,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    wait_for_sink_lagging_subjects(&node.api, "kafka-down-sink", 1).await;

    // Restart with the sink pointing to the real Redpanda broker.
    let keys = node.keys.clone();
    let local_db = dirs[0].path().to_path_buf();
    let ext_db = dirs[1].path().to_path_buf();
    node.token.cancel();
    join_all(node.handler.iter_mut()).await;

    let (node, mut new_dirs) = create_node(restart_config(
        keys,
        local_db,
        ext_db,
        format!("/memory/{}", PORT_COUNTER.fetch_add(1, Ordering::SeqCst)),
        vec![make_kafka_sink_entry(
            "kafka-down-sink",
            env.bootstrap_servers.clone(),
            topic,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
        )],
    ))
    .await;
    dirs.append(&mut new_dirs);
    node_running(&node.api).await.unwrap();

    // Startup catch-up must deliver Create + 3 facts to Kafka.
    let messages = env.consume_string(topic, 4, Duration::from_secs(30)).await;
    assert_eq!(messages.len(), 4, "expected Create + 3 facts in Kafka");

    let events: Vec<IncomingSinkEvent> = messages
        .iter()
        .map(|(_, payload)| serde_json::from_str(payload).unwrap())
        .collect();

    assert_sink_contains_create(&events, &subject_id_str, 0);
    for i in 1..=3 {
        assert_sink_contains_fact_full(
            &events,
            &subject_id_str,
            i,
            true,
            Some(json!({"ModOne": {"data": i}})),
        );
    }

    // After catch-up the sink is healthy and no longer lagging.
    wait_for_sink_caught_up(&node.api, "kafka-down-sink").await;

    // The status view reports the transport kind.
    let statuses = node.api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == "kafka-down-sink")
        .expect("kafka-down-sink in status response");
    assert_eq!(status.transport.as_deref(), Some("kafka"));
}
