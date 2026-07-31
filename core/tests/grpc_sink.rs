//! Integration tests for the gRPC sink transport.
//!
//! Transport-level tests use a real in-process tonic server
//! ([`GrpcTestSink`]); the end-to-end test drives a full node emitting
//! ledger events into a configured gRPC sink.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ave_common::{
    LightEvent, SchemaType, SinkTarget, SinkTypes,
    identity::{
        BLAKE3_HASHER, DigestIdentifier, Hash as _, PublicKey,
        SignatureIdentifier, TimeStamp, keys::KeyPair,
    },
    sink::{DataToSink, DataToSinkEvent, IncomingSinkEvent},
};
use ave_core::config::{
    GrpcAuthConfig, GrpcSinkConfig, GrpcTlsConfig, SinkConfigEntry,
    SinkServer, SinkTransportConfig,
};
use ave_core::sink::SinkError;
use ave_core::sink::SinkTransport;
use ave_core::sink::delivery::{DeliveryMeta, canonical_payload};
use ave_core::sink::grpc::GrpcTransport;
use ave_network::NodeType;
use futures::future::join_all;
use std::str::FromStr;
use tonic::Code;
use test_log::test;
use common::grpc_test_sink::{GrpcResponseMode, GrpcTestSink};
use common::{
    CreateNodeConfig, NodeData, PORT_COUNTER, TempEnvVar,
    create_and_authorize_governance, create_node, create_subject, emit_fact,
    node_running,
    sink_setup::{
        example_schema_governance_fact, wait_for_sink_blocked,
        wait_for_sink_caught_up, wait_for_sink_lagging_subjects,
    },
};

const SUBJECT_ID: &str = "GRPC-SUBJECT-ID";
const SCHEMA_ID: &str = "Example";

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

fn grpc_config(endpoint: &str) -> GrpcSinkConfig {
    GrpcSinkConfig {
        endpoint: endpoint.to_owned(),
        ..GrpcSinkConfig::default()
    }
}

async fn build_transport(
    endpoint: &str,
    config: GrpcSinkConfig,
) -> GrpcTransport {
    GrpcTransport::new("test".to_owned(), config, None)
        .await
        .unwrap_or_else(|e| {
            panic!("transport should build for {endpoint}: {e}")
        })
}

/// Happy path: full events, light events and batches are delivered with the
/// routing metadata and the canonical JSON payload.
#[test(tokio::test)]
async fn grpc_transport_happy_path() {
    let sink = GrpcTestSink::start().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    transport
        .send_light(example_light_event(SUBJECT_ID, SCHEMA_ID))
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 2);

    let full = &deliveries[0];
    let meta = full.meta.as_ref().expect("full event carries meta");
    assert_eq!(meta.subject_id, SUBJECT_ID);
    assert_eq!(meta.sn, 0);
    assert_eq!(meta.event_type, "create");
    assert_eq!(meta.schema_id, SCHEMA_ID);
    assert_eq!(meta.idempotency_key, format!("{SUBJECT_ID}-0"));
    assert!(!meta.light);
    assert!(!full.request_id.is_empty());
    let body = full.body.as_ref().expect("delivery carries a body");
    let payload: serde_json::Value =
        serde_json::from_slice(&body.payload).expect("payload is JSON");
    assert_eq!(payload["payload"]["event"], "create");
    assert!(body.signature.is_empty(), "unsigned without a signer");

    let light = &deliveries[1];
    let meta = light.meta.as_ref().expect("light event carries meta");
    assert_eq!(meta.sn, 1);
    assert_eq!(meta.event_type, "fact");
    assert!(meta.light);
}

/// Batch delivery sends one request with a JSON array and no per-event meta
/// (mirrors the HTTP sink contract).
#[test(tokio::test)]
async fn grpc_transport_batch_delivery() {
    let sink = GrpcTestSink::start().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;

    let events = vec![
        IncomingSinkEvent::Full(Arc::new(example_data_to_sink(
            SUBJECT_ID, SCHEMA_ID,
        ))),
        IncomingSinkEvent::Light(example_light_event(SUBJECT_ID, SCHEMA_ID)),
    ];
    transport.send_batch(events).await.unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 1);
    assert!(
        deliveries[0].meta.is_none(),
        "batch deliveries carry no per-event meta"
    );
    let body = deliveries[0].body.as_ref().expect("batch carries a body");
    let payload: serde_json::Value =
        serde_json::from_slice(&body.payload).expect("payload is JSON");
    assert!(payload.is_array(), "batch payload must be a JSON array");
    assert_eq!(payload.as_array().unwrap().len(), 2);
}

/// A transient status (UNAVAILABLE) is retried until the server accepts.
#[test(tokio::test)]
async fn grpc_transport_retries_transient_status() {
    let sink = GrpcTestSink::start().await;
    sink.set_mode(GrpcResponseMode::FailTimes {
        code: Code::Unavailable,
        remaining: Arc::new(AtomicUsize::new(2)),
    });
    let config = GrpcSinkConfig {
        retry_base_delay_ms: 1,
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    assert_eq!(
        sink.deliveries().len(),
        3,
        "two failed attempts plus the accepted one"
    );
}

/// A permanent status (INVALID_ARGUMENT) is a rejection: no retries and a
/// non-retryable error kind.
#[test(tokio::test)]
async fn grpc_transport_permanent_status_is_rejected_without_retry() {
    let sink = GrpcTestSink::start().await;
    sink.set_mode(GrpcResponseMode::AlwaysStatus(Code::InvalidArgument));
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;

    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;

    assert!(
        matches!(result, Err(SinkError::Rejected { .. })),
        "expected a permanent rejection, got {result:?}"
    );
    assert_eq!(
        sink.deliveries().len(),
        1,
        "permanent errors must not be retried"
    );
}

/// UNAUTHENTICATED maps to the auth error kind (the worker drives catch-up).
#[test(tokio::test)]
async fn grpc_transport_unauthenticated_is_auth_error() {
    let sink = GrpcTestSink::start().await;
    sink.set_mode(GrpcResponseMode::AlwaysStatus(Code::Unauthenticated));
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;

    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;

    assert!(
        matches!(result, Err(SinkError::Auth { .. })),
        "expected an auth error, got {result:?}"
    );
}

/// API key auth: the secret is read from the environment and sent as
/// `x-api-key` metadata on every RPC.
#[test(tokio::test)]
async fn grpc_transport_sends_api_key_metadata() {
    let sink = GrpcTestSink::start().await;
    let _guard = TempEnvVar::set("AVE_SINK_TOKEN_TEST", "token-secret");
    let _guard2 = TempEnvVar::set("AVE_SINK_APIKEY_TEST", "key-secret");

    let config = GrpcSinkConfig {
        auth: Some(GrpcAuthConfig::ApiKey),
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 1);
    assert_eq!(deliveries[0].api_key.as_deref(), Some("key-secret"));

    // Bearer token auth: `authorization: Bearer <token>` metadata.
    let config = GrpcSinkConfig {
        auth: Some(GrpcAuthConfig::BearerToken),
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 2);
    assert_eq!(
        deliveries[1].authorization.as_deref(),
        Some("Bearer token-secret")
    );
}

/// Configured auth with a missing environment secret is a build error.
#[test(tokio::test)]
async fn grpc_transport_auth_missing_secret_is_build_error() {
    let sink = GrpcTestSink::start().await;
    let config = GrpcSinkConfig {
        auth: Some(GrpcAuthConfig::BearerToken),
        ..grpc_config(&sink.endpoint())
    };
    let result =
        GrpcTransport::new("no-env-secret-sink".to_owned(), config, None).await;
    assert!(
        matches!(result, Err(SinkError::ClientBuild(_))),
        "expected a build error, got {result:?}"
    );
}

/// Health check: SERVING passes; a server without grpc.health.v1 falls back
/// to the Test RPC.
#[test(tokio::test)]
async fn grpc_health_check_serving_and_unimplemented_fallback() {
    let sink = GrpcTestSink::start().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;
    transport.health_check().await.unwrap();

    let sink_no_health = GrpcTestSink::start_without_health_service().await;
    let transport = build_transport(
        &sink_no_health.endpoint(),
        grpc_config(&sink_no_health.endpoint()),
    )
    .await;
    transport.health_check().await.unwrap();
    assert_eq!(
        sink_no_health.tests().len(),
        1,
        "the fallback must exercise the Test RPC"
    );
}

/// The test delivery performs a health check plus a non-persistent Test RPC.
#[test(tokio::test)]
async fn grpc_test_delivery_is_non_persistent() {
    let sink = GrpcTestSink::start().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;
    transport.test().await.unwrap();

    assert_eq!(sink.tests().len(), 1);
    let tests = sink.tests();
    let body = tests[0].body.as_ref().expect("test carries a body");
    let payload: serde_json::Value =
        serde_json::from_slice(&body.payload).expect("test payload is JSON");
    assert_eq!(payload["test"], true);
    assert!(
        sink.deliveries().is_empty(),
        "test deliveries must not appear as real deliveries"
    );
}

/// Health check on a NOT_SERVING server fails as a retryable delivery error.
#[test(tokio::test)]
async fn grpc_health_check_not_serving_is_retryable_error() {
    let sink = GrpcTestSink::start().await;
    sink.set_health_not_serving().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;

    let result = transport.health_check().await;
    match result {
        Err(SinkError::Delivery { retryable, .. }) => {
            assert!(retryable, "NOT_SERVING must be retryable");
        }
        other => panic!("expected a retryable delivery error, got {other:?}"),
    }
}

/// TLS with a custom CA: delivery succeeds once `tls.ca_certificate` trusts
/// the sink's CA, and the handshake fails (before any RPC) without it.
#[test(tokio::test)]
async fn grpc_transport_tls_with_custom_ca() {
    let (sink, material) = GrpcTestSink::start_tls(false).await;
    let tls_dir = tempfile::tempdir().expect("tls dir");
    let ca_path = tls_dir.path().join("ca.pem");
    std::fs::write(&ca_path, &material.ca_pem).expect("write CA pem");

    // Without the CA the server certificate is rejected: the error surfaces
    // on the first RPC and nothing reaches the server.
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint())).await;
    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;
    assert!(result.is_err(), "an untrusted CA must fail the handshake");
    assert!(
        sink.deliveries().is_empty(),
        "no RPC must survive a failed handshake"
    );

    // Trusting the CA makes the delivery succeed.
    let config = GrpcSinkConfig {
        tls: Some(GrpcTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..GrpcTlsConfig::default()
        }),
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(sink.accepted_deliveries().len(), 1);
}

/// mTLS: a server that requires a client certificate rejects clients without
/// an identity and accepts one presenting `tls.client_certificate`/`client_key`.
#[test(tokio::test)]
async fn grpc_transport_mtls_client_identity() {
    let (sink, material) = GrpcTestSink::start_tls(true).await;
    let tls_dir = tempfile::tempdir().expect("tls dir");
    let ca_path = tls_dir.path().join("ca.pem");
    let client_cert_path = tls_dir.path().join("client.pem");
    let client_key_path = tls_dir.path().join("client.key");
    std::fs::write(&ca_path, &material.ca_pem).expect("write CA pem");
    std::fs::write(&client_cert_path, &material.client_cert_pem)
        .expect("write client cert pem");
    std::fs::write(&client_key_path, &material.client_key_pem)
        .expect("write client key pem");

    // Without a client identity the server aborts the handshake.
    let config = GrpcSinkConfig {
        tls: Some(GrpcTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..GrpcTlsConfig::default()
        }),
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;
    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;
    assert!(
        result.is_err(),
        "a missing client certificate must fail the handshake"
    );
    assert!(
        sink.deliveries().is_empty(),
        "no RPC must survive a failed handshake"
    );

    // With the client identity the delivery succeeds.
    let config = GrpcSinkConfig {
        tls: Some(GrpcTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            client_certificate: client_cert_path.to_string_lossy().into_owned(),
            client_key: client_key_path.to_string_lossy().into_owned(),
        }),
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(sink.accepted_deliveries().len(), 1);
}

/// Pipelining: concurrent deliveries share one persistent stream and are
/// correlated by `request_id`, even with a slow acker.
#[test(tokio::test)]
async fn grpc_transport_pipelines_over_single_stream() {
    let sink = GrpcTestSink::start().await;
    sink.set_stream_ack_delay(50);
    let transport = Arc::new(
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint()))
            .await,
    );

    let mut handles = Vec::new();
    for _ in 0..6 {
        let transport = Arc::clone(&transport);
        handles.push(tokio::spawn(async move {
            transport
                .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
                .await
                .unwrap();
        }));
    }
    for handle in handles {
        handle.await.unwrap();
    }

    assert_eq!(sink.accepted_deliveries().len(), 6);
    assert_eq!(
        sink.stream_opens(),
        1,
        "every delivery must share a single persistent stream"
    );
}

/// Stream cut mid-delivery: the in-flight message fails retryable, the
/// transport reopens the stream lazily and the retry delivers it.
#[test(tokio::test)]
async fn grpc_transport_recovers_from_stream_cut() {
    let sink = GrpcTestSink::start().await;
    let config = GrpcSinkConfig {
        retry_base_delay_ms: 1,
        ..grpc_config(&sink.endpoint())
    };
    let transport =
        build_transport(&sink.endpoint(), config).await;

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(sink.stream_opens(), 1);

    // The open stream dies; the next delivery reconnects transparently.
    sink.cut_streams();
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    assert_eq!(sink.accepted_deliveries().len(), 2);
    assert_eq!(
        sink.stream_opens(),
        2,
        "the transport must reopen the stream after a cut"
    );
}

/// Backpressure: with a stalled consumer the in-flight window bounds the
/// deliveries in progress (RAM bounded by construction); once the consumer
/// resumes, every pending delivery completes.
#[test(tokio::test)]
async fn grpc_transport_stream_backpressure_on_stalled_consumer() {
    let sink = GrpcTestSink::start().await;
    let config = GrpcSinkConfig {
        max_in_flight_batches: 2,
        // The ack wait must outlast the stall so no retry fires.
        request_timeout_ms: 30_000,
        ..grpc_config(&sink.endpoint())
    };
    let transport = Arc::new(build_transport(&sink.endpoint(), config).await);

    sink.pause_streams();
    let mut handles = Vec::new();
    for _ in 0..3 {
        let transport = Arc::clone(&transport);
        handles.push(tokio::spawn(async move {
            transport
                .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
                .await
        }));
    }

    // While stalled nothing is delivered and the third send cannot
    // complete (window = 2): poll briefly to observe the stable state.
    let stalled = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        async {
            while sink.deliveries().is_empty()
                && handles.iter().all(|h| !h.is_finished())
            {
                tokio::time::sleep(std::time::Duration::from_millis(50))
                    .await;
            }
        },
    )
    .await;
    assert!(
        stalled.is_err(),
        "the stall must hold for the whole observation window"
    );
    assert!(sink.deliveries().is_empty());
    assert!(
        handles.iter().all(|h| !h.is_finished()),
        "no send may complete while the consumer is stalled"
    );

    sink.resume_streams();
    for handle in handles {
        handle.await.unwrap().unwrap();
    }
    assert_eq!(sink.accepted_deliveries().len(), 3);
}

/// Unary fallback: a server without `DeliverStream` (v1-unary contract) is
/// delivered through the unary RPC, and the transport remembers it.
#[test(tokio::test)]
async fn grpc_transport_unary_fallback_for_legacy_server() {
    let sink = GrpcTestSink::start_unary_only().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint()))
            .await;

    for _ in 0..2 {
        transport
            .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
            .await
            .unwrap();
    }

    assert_eq!(sink.accepted_deliveries().len(), 2);
    assert_eq!(
        sink.stream_opens(),
        0,
        "no stream may be established against a unary-only server"
    );
}

/// Builds a sink configuration entry that delivers `Example` tracker events
/// of one governance to a gRPC endpoint.
fn make_grpc_sink_entry(
    server_name: &str,
    endpoint: &str,
    governance_id: Option<String>,
    events: BTreeSet<SinkTypes>,
    signature: bool,
) -> SinkConfigEntry {
    SinkConfigEntry {
        target: SinkTarget::Schema {
            schema_id: SCHEMA_ID.to_owned(),
            governance_id,
        },
        servers: vec![SinkServer {
            server: server_name.to_owned(),
            events,
            transport: SinkTransportConfig::Grpc(Box::new(GrpcSinkConfig {
                endpoint: endpoint.to_owned(),
                signature,
                ..GrpcSinkConfig::default()
            })),
            healthcheck_intervals_secs: vec![1],
            startup_healthcheck_delay_secs: 0,
            max_catch_up_concurrency: 2,
            ..Default::default()
        }],
    }
}

/// End-to-end: a node with a gRPC sink delivers the subject's events, in
/// order, to a real gRPC server (catch-up after restart included).
#[test(tokio::test)]
async fn grpc_node_emits_events_end_to_end() {
    let sink = GrpcTestSink::start().await;

    let (owner, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![]).await;
    emit_fact(
        &owner.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();
    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), SCHEMA_ID, "", true)
            .await
            .unwrap();
    for i in 0..3 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Restart with the gRPC sink configured: catch-up must deliver the whole
    // history in order.
    let sink_endpoint = sink.endpoint();
    let mut owner = owner;
    let owner_keys: KeyPair = owner.keys.clone();
    let owner_local_db = dirs[0].path().to_path_buf();
    let owner_ext_db = dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let (owner, mut owner_dirs2) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(owner_keys),
        local_db: Some(owner_local_db),
        ext_db: Some(owner_ext_db),
        sinks: vec![make_grpc_sink_entry(
            "grpc-node-sink",
            &sink_endpoint,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            false,
        )],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_deliveries(4).await;

    let deliveries = sink.deliveries();
    let sns: Vec<u64> = deliveries
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2, 3],
        "catch-up must deliver the subject history in order; got {sns:?}"
    );
    for delivery in &deliveries {
        let meta = delivery.meta.as_ref().expect("live events carry meta");
        assert_eq!(meta.subject_id, subject_id.to_string());
        assert_eq!(meta.schema_id, SCHEMA_ID);
    }

    // Live delivery: events confirmed after the sink is up flow through the
    // notification path (not catch-up), preserving order.
    for i in 3..5 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }
    sink.wait_for_deliveries(6).await;
    let sns: Vec<u64> = sink
        .deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2, 3, 4, 5],
        "live events must follow the catch-up in order; got {sns:?}"
    );
}

/// End-to-end with `signature = true`: every delivery carries the node's
/// Ed25519 signature over the canonical v2 payload, verifiable with the
/// node's public key (and rejected when the payload is tampered).
#[test(tokio::test)]
async fn grpc_node_delivers_signed_events() {
    let sink = GrpcTestSink::start().await;

    let (owner, mut dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![]).await;
    emit_fact(
        &owner.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();
    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), SCHEMA_ID, "", true)
            .await
            .unwrap();
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    let sink_endpoint = sink.endpoint();
    let mut owner = owner;
    let owner_keys: KeyPair = owner.keys.clone();
    let owner_local_db = dirs[0].path().to_path_buf();
    let owner_ext_db = dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let (owner, mut owner_dirs2) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(owner_keys),
        local_db: Some(owner_local_db),
        ext_db: Some(owner_ext_db),
        sinks: vec![make_grpc_sink_entry(
            "grpc-signed-sink",
            &sink_endpoint,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            true,
        )],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    wait_for_sink_caught_up(&owner.api, "grpc-signed-sink").await;
    sink.wait_for_deliveries(2).await;

    let node_key =
        PublicKey::from_str(owner.api.public_key()).expect("node public key");
    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 2, "create + one fact");

    for delivery in &deliveries {
        let meta = delivery.meta.as_ref().expect("live events carry meta");
        let body = delivery.body.as_ref().expect("deliveries carry a body");

        assert!(!body.signature.is_empty(), "signed delivery");
        assert!(!body.public_key.is_empty());
        assert_eq!(body.public_key, owner.api.public_key());
        assert!(body.signature_timestamp > 0);

        // Rebuild the signing payload exactly as `Signature::new` does:
        // borsh(canonical_payload, timestamp), then Blake3.
        let delivery_meta = DeliveryMeta {
            subject_id: meta.subject_id.clone(),
            sn: meta.sn,
            event_type: meta.event_type.clone(),
        };
        let canonical =
            canonical_payload(&body.payload, 2, &[], Some(&delivery_meta));
        let timestamp = TimeStamp::from_nanos(body.signature_timestamp);
        let payload_bytes = borsh::to_vec(&(canonical, timestamp))
            .expect("borsh serialization");
        let content_hash = BLAKE3_HASHER.hash(&payload_bytes);
        let signature_id = SignatureIdentifier::from_str(&body.signature)
            .expect("signature must parse");

        node_key
            .verify(content_hash.hash_bytes(), &signature_id)
            .expect("delivery signature must verify");

        // A tampered payload must not verify.
        let tampered = (b"tampered".to_vec(), timestamp);
        let tampered_hash = BLAKE3_HASHER
            .hash(&borsh::to_vec(&tampered).expect("borsh serialization"));
        assert!(
            node_key
                .verify(tampered_hash.hash_bytes(), &signature_id)
                .is_err(),
            "signature must not verify for a tampered payload"
        );
    }
}

/// Shared setup for the node-level tests: one node with a governance, an
/// `Example` subject and `facts` confirmed facts on it (sns 0..=facts).
async fn start_node_with_history(
    facts: u64,
) -> (
    NodeData,
    Vec<tempfile::TempDir>,
    DigestIdentifier,
    DigestIdentifier,
) {
    let (owner, dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![]).await;
    emit_fact(
        &owner.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    let (subject_id, _) =
        create_subject(&owner.api, governance_id.clone(), SCHEMA_ID, "", true)
            .await
            .unwrap();
        
    for i in 0..facts {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }
    (owner, dirs, governance_id, subject_id)
}

/// Restart the node with a gRPC sink for the subject's governance, using the
/// same identity and databases (so catch-up sees the whole history).
async fn restart_with_grpc_sink(
    mut owner: NodeData,
    mut dirs: Vec<tempfile::TempDir>,
    sink_name: &str,
    transport: GrpcSinkConfig,
    governance_id: &DigestIdentifier,
) -> (NodeData, Vec<tempfile::TempDir>) {
    let owner_keys: KeyPair = owner.keys.clone();
    let owner_local_db = dirs[0].path().to_path_buf();
    let owner_ext_db = dirs[1].path().to_path_buf();
    owner.token.cancel();
    join_all(owner.handler.iter_mut()).await;

    let (owner, mut owner_dirs2) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        keys: Some(owner_keys),
        local_db: Some(owner_local_db),
        ext_db: Some(owner_ext_db),
        sinks: vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: SCHEMA_ID.to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: sink_name.to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Grpc(Box::new(transport)),
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 2,
                ..Default::default()
            }],
        }],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();
    (owner, dirs)
}

/// Transient server failure at the node level: a live event whose delivery
/// fails with UNAVAILABLE exhausts its retries and the subject goes lagging;
/// once the server recovers, the healthcheck resumes the worker and catch-up
/// redelivers the event in order, with no loss and no duplicates.
#[test(tokio::test)]
async fn grpc_node_recovers_after_transient_failure() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(2).await;

    // Server goes down: the live event fails every attempt and the subject
    // enters lagging.
    sink.set_mode(GrpcResponseMode::AlwaysStatus(Code::Unavailable));
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    wait_for_sink_lagging_subjects(&owner.api, "grpc-node-sink", 1).await;

    // Server recovers: catch-up redelivers the failed event.
    sink.set_mode(GrpcResponseMode::Accept);
    sink.wait_for_accepted(3).await;
    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;

    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "the failed event must be redelivered in order, accepted exactly once; got {sns:?}"
    );
}

/// Batch delivery at the node level: with `batch_delivery` enabled, catch-up
/// and live events travel as single requests carrying a JSON array with no
/// per-event meta, preserving order across batches.
#[test(tokio::test)]
async fn grpc_node_batch_delivery() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let transport_config = GrpcSinkConfig {
        batch_delivery: true,
        batch_max_delay_ms: 100,
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        transport_config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    for i in 1..3 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Wait until 4 events (create + 3 facts) have arrived, however they are
    // grouped into batches.
    let mut sns = Vec::new();
    for _ in 0..100 {
        sns = sink
            .deliveries()
            .iter()
            .flat_map(|d| {
                let body = d.body.as_ref().expect("batch carries a body");
                let payload: serde_json::Value =
                    serde_json::from_slice(&body.payload)
                        .expect("batch payload is JSON");
                let events = payload
                    .as_array()
                    .expect("batch payload must be a JSON array");
                events
                    .iter()
                    .map(|e| {
                        e["payload"]["data"]["sn"]
                            .as_u64()
                            .expect("event carries sn")
                    })
                    .collect::<Vec<u64>>()
            })
            .collect();
        if sns.len() >= 4 {
            break;
        }
        tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
    }

    assert_eq!(
        sns,
        vec![0, 1, 2, 3],
        "events must arrive in order across batches; got {sns:?}"
    );
    for delivery in sink.deliveries() {
        assert!(
            delivery.meta.is_none(),
            "batch deliveries carry no per-event meta"
        );
    }
}

/// Permanent rejection at the node level: an INVALID_ARGUMENT response
/// blocks the sink; after fixing the server and unblocking manually, the
/// event is redelivered via catch-up.
#[test(tokio::test)]
async fn grpc_node_permanent_rejection_blocks_and_unblock_recovers() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(0).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_deliveries(1).await;

    // The server rejects permanently: the sink ends up blocked.
    sink.set_mode(GrpcResponseMode::AlwaysStatus(Code::InvalidArgument));
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let reason = wait_for_sink_blocked(&owner.api, "grpc-node-sink").await;
    assert!(!reason.is_empty(), "block must carry a reason");

    // The operator fixes the endpoint and unblocks: catch-up redelivers.
    sink.set_mode(GrpcResponseMode::Accept);
    owner
        .api
        .unblock_sink("grpc-node-sink".to_owned())
        .await
        .unwrap();
    sink.wait_for_accepted(2).await;

    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1],
        "the rejected event must be redelivered after unblocking; got {sns:?}"
    );
}

/// Bearer auth at the node level: the worker reads the secret from the
/// sink's environment variable and sends it as `authorization` metadata on
/// every delivery.
#[test(tokio::test)]
async fn grpc_node_delivers_with_bearer_auth() {
    let sink = GrpcTestSink::start().await;
    let _guard =
        TempEnvVar::set("AVE_SINK_TOKEN_GRPC_AUTH_SINK", "node-secret");

    let (owner, dirs, governance_id, _subject_id) =
        start_node_with_history(1).await;
    let config = GrpcSinkConfig {
        auth: Some(GrpcAuthConfig::BearerToken),
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-auth-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-auth-sink").await;
    sink.wait_for_accepted(2).await;

    let deliveries = sink.accepted_deliveries();
    assert_eq!(deliveries.len(), 2, "create + one fact");
    for delivery in &deliveries {
        assert_eq!(
            delivery.authorization.as_deref(),
            Some("Bearer node-secret"),
            "every delivery must carry the bearer token"
        );
    }
}

/// `Api::test_sink` drives a real `Test` RPC through the node's wiring
/// (config -> manager -> transport -> server) without touching delivery
/// state; unknown sinks are rejected.
#[test(tokio::test)]
async fn grpc_node_test_sink_api() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, _subject_id) =
        start_node_with_history(0).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;
    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;

    owner
        .api
        .test_sink("grpc-node-sink".to_owned())
        .await
        .unwrap();
    sink.wait_for_tests(1).await;
    let tests = sink.tests();
    assert!(!tests[0].request_id.is_empty());
    assert!(tests[0].body.is_some(), "the test RPC carries a payload");

    assert!(
        owner
            .api
            .test_sink("unknown-sink".to_owned())
            .await
            .is_err(),
        "testing an unknown sink must fail"
    );
}

/// Catch-up with several subjects delivers each subject's full history, in
/// order per subject, even with concurrent catch-up workers.
#[test(tokio::test)]
async fn grpc_node_catch_up_multiple_subjects() {
    let sink = GrpcTestSink::start().await;

    let (owner, dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        ..Default::default()
    })
    .await;
    node_running(&owner.api).await.unwrap();

    let governance_id =
        create_and_authorize_governance(&owner.api, vec![]).await;
    emit_fact(
        &owner.api,
        governance_id.clone(),
        example_schema_governance_fact(),
        true,
    )
    .await
    .unwrap();

    // Three subjects with 0, 1 and 2 facts (histories of 1, 2 and 3 events).
    let mut subject_ids = Vec::new();
    for facts in 0..3u64 {
        let (subject_id, _) = create_subject(
            &owner.api,
            governance_id.clone(),
            SCHEMA_ID,
            "",
            true,
        )
        .await
        .unwrap();
        for i in 0..facts {
            emit_fact(
                &owner.api,
                subject_id.clone(),
                serde_json::json!({"ModOne": {"data": i}}),
                true,
            )
            .await
            .unwrap();
        }
        subject_ids.push(subject_id);
    }

    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(6).await;
    assert_eq!(
        sink.stream_opens(),
        1,
        "every subject must share the sink worker's single stream"
    );

    // Subjects may interleave, but each one must arrive complete and in
    // order.
    let mut per_subject: std::collections::BTreeMap<String, Vec<u64>> =
        std::collections::BTreeMap::new();
    for delivery in sink.accepted_deliveries() {
        let meta = delivery.meta.as_ref().expect("live events carry meta");
        per_subject.entry(meta.subject_id.clone()).or_default().push(meta.sn);
    }
    assert_eq!(
        per_subject.len(),
        3,
        "every subject must be delivered; got {per_subject:?}"
    );
    for (i, subject_id) in subject_ids.iter().enumerate() {
        let expected: Vec<u64> = (0..=i as u64).collect();
        let sns = per_subject
            .get(&subject_id.to_string())
            .expect("subject must have deliveries");
        assert_eq!(sns, &expected, "subject {i} must arrive in order");
    }
}

/// Stream cut mid-live-delivery at the node level: the connection dies with
/// the worker delivering, the transport reconnects transparently and the
/// event arrives exactly once, in order, without the sink going lagging.
#[test(tokio::test)]
async fn grpc_node_recovers_from_stream_cut() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(2).await;
    assert_eq!(sink.stream_opens(), 1);

    // One live event over the open stream.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    sink.wait_for_accepted(3).await;

    // The connection dies; the next live event reconnects transparently.
    sink.cut_streams();
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();

    sink.wait_for_accepted(4).await;
    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2, 3],
        "the cut must not lose nor duplicate events; got {sns:?}"
    );
    assert_eq!(
        sink.stream_opens(),
        2,
        "the transport must reopen the stream after the cut"
    );
}

/// Unary fallback at the node level: a v1 backend (unary RPCs only, as
/// deployed with the MVP) keeps receiving catch-up and live events after
/// the node upgrade, with no stream ever established.
#[test(tokio::test)]
async fn grpc_node_unary_fallback_legacy_server() {
    let sink = GrpcTestSink::start_unary_only().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(2).await;

    for i in 2..4 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    sink.wait_for_accepted(4).await;
    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2, 3],
        "a legacy unary backend must receive every event; got {sns:?}"
    );
    assert_eq!(
        sink.stream_opens(),
        0,
        "no stream may be established against a unary-only server"
    );
}

/// Stalled consumer at the node level: the backend stops reading and the
/// delivery simply waits (backpressure, no loss, no duplicates); once it
/// resumes, the pending event arrives exactly once, in order.
#[test(tokio::test)]
async fn grpc_node_stalled_consumer_recovers() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    // The ack wait must outlast the stall so no retry fires mid-test.
    let config = GrpcSinkConfig {
        request_timeout_ms: 30_000,
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(2).await;

    sink.pause_streams();
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    // While stalled, nothing new is accepted (the delivery waits inside
    // the in-flight window): observe the stable state with the poll
    // pattern instead of a fixed sleep.
    let stalled = tokio::time::timeout(
        std::time::Duration::from_secs(1),
        async {
            while sink.accepted_deliveries().len() == 2 {
                tokio::time::sleep(std::time::Duration::from_millis(50))
                    .await;
            }
        },
    )
    .await;
    assert!(
        stalled.is_err(),
        "no delivery may complete while the consumer is stalled"
    );

    sink.resume_streams();
    sink.wait_for_accepted(3).await;
    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "the stalled event must arrive exactly once after resuming; got {sns:?}"
    );
}
