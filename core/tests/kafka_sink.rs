mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use ave_common::{
    LightEvent, SchemaType, SinkTarget, SinkTypes,
    identity::{PublicKey, keys::KeyPair},
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
        assert_sink_not_lagging, example_schema_governance_fact,
        governance_with_transfer_roles_fact, restart_config,
        restart_config_with_peers, wait_for_sink_lagging_subjects,
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
    let transport = KafkaTransport::new("test-retry".to_string(), config).unwrap();

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
    let transport = KafkaTransport::new("test-retry-fail".to_string(), config).unwrap();

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
    let transport = KafkaTransport::new("test-tls".to_string(), config).unwrap();

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
        KafkaTransport::new("test-tls-fail".to_string(), config).unwrap();

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
            KafkaTransport::new("test".to_string(), config).unwrap();
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
            KafkaTransport::new("test".to_string(), config).unwrap();
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
    let err = KafkaTransport::new("test".to_string(), config).unwrap_err();
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
    let transport = KafkaTransport::new("test".to_string(), config).unwrap();
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
        KafkaTransport::new("sasl-bad".to_string(), bad_config).unwrap();
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
    assert_sink_not_lagging(&node.api, "kafka-down-sink").await;

    // The status view reports the transport kind.
    let statuses = node.api.get_sinks_status().await.unwrap();
    let status = statuses
        .iter()
        .find(|s| s.name == "kafka-down-sink")
        .expect("kafka-down-sink in status response");
    assert_eq!(status.transport.as_deref(), Some("kafka"));
}
