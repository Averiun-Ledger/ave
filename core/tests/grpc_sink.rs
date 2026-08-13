//! Integration tests for the gRPC sink transport.
//!
//! Transport-level tests use a real in-process tonic server
//! ([`GrpcTestSink`]); the end-to-end test drives a full node emitting
//! ledger events into a configured gRPC sink.

mod common;

use std::collections::{BTreeSet, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use ave_common::{
    LightEvent, SchemaType, SinkTarget, SinkTypes,
    bridge::request::{SinkReplayItem, SinkReplayRequest},
    bridge::response::{SinkServerView, SinkTransportView},
    identity::{
        BLAKE3_HASHER, DigestIdentifier, Hash as _, PublicKey,
        SignatureIdentifier, TimeStamp, keys::KeyPair,
    },
    sink::{
        DataToSink, DataToSinkEvent, IncomingSinkEvent, SinkAuthConfig,
    },
};
use ave_core::config::{
    SinkAuthMethod, GrpcSinkConfig, GrpcTlsConfig, SinkCompression,
    SinkConfigEntry, SinkServer, SinkTransportConfig,
};
use ave_core::sink::SinkError;
use ave_core::sink::SinkTransport;
use ave_core::sink::delivery::{DeliveryMeta, canonical_payload};
use ave_core::sink::grpc::GrpcTransport;
use ave_network::NodeType;
use base64::{Engine as _, prelude::BASE64_STANDARD};
use futures::future::join_all;
use std::str::FromStr;
use tonic::Code;
use test_log::test;
use common::grpc_test_sink::{GrpcResponseMode, GrpcTestSink};
use common::test_sink::TestSink;
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
    build_transport_named("test", endpoint, config).await
}

/// Like [`build_transport`] with an explicit sink name, so tests that read
/// credentials from the environment use a per-test variable and never race
/// with each other in the shared process environment.
async fn build_transport_named(
    name: &str,
    endpoint: &str,
    config: GrpcSinkConfig,
) -> GrpcTransport {
    GrpcTransport::new(name.to_owned(), config, None)
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

/// Gzip compression: the client sends compressed payloads and the server
/// decompresses them transparently; payload bytes arrive intact.
#[test(tokio::test)]
async fn grpc_transport_gzip_compression() {
    let sink = GrpcTestSink::start().await;
    let config = GrpcSinkConfig {
        endpoint: sink.endpoint(),
        compression: SinkCompression::Gzip,
        ..GrpcSinkConfig::default()
    };
    let transport = build_transport(&sink.endpoint(), config).await;

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    transport
        .send_batch(vec![
            IncomingSinkEvent::Full(Arc::new(example_data_to_sink(
                SUBJECT_ID, SCHEMA_ID,
            ))),
            IncomingSinkEvent::Light(example_light_event(SUBJECT_ID, SCHEMA_ID)),
        ])
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 2);
    assert!(deliveries.iter().all(|d| d.accepted));

    let single = &deliveries[0];
    let meta = single.meta.as_ref().expect("full event carries meta");
    assert_eq!(meta.subject_id, SUBJECT_ID);
    let body = single.body.as_ref().expect("delivery carries a body");
    let payload: serde_json::Value = serde_json::from_slice(&body.payload)
        .expect("gzip payload decompresses to JSON");
    assert_eq!(payload["payload"]["event"], "create");

    let batch_body =
        deliveries[1].body.as_ref().expect("batch carries a body");
    let batch: serde_json::Value = serde_json::from_slice(&batch_body.payload)
        .expect("gzip batch payload decompresses to JSON");
    assert!(batch.is_array(), "batch payload must be a JSON array");
    assert_eq!(batch.as_array().unwrap().len(), 2);

    // The wire must actually be compressed (`grpc-encoding: gzip`), not
    // just decompressible: tonic would accept plaintext transparently.
    assert!(
        deliveries
            .iter()
            .all(|d| d.metadata.get("grpc-encoding").map(String::as_str)
                == Some("gzip")),
        "compressed transports must send grpc-encoding: gzip on every RPC"
    );

    // Contrast: an uncompressed transport sends no grpc-encoding metadata.
    let plain = build_transport(
        &sink.endpoint(),
        grpc_config(&sink.endpoint()),
    )
    .await;
    plain
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 3);
    assert!(
        !deliveries[2].metadata.contains_key("grpc-encoding"),
        "uncompressed transports must not send grpc-encoding"
    );
}

/// Zstd compression: the client sends compressed payloads and the server
/// decompresses them transparently; payload bytes arrive intact.
#[test(tokio::test)]
async fn grpc_transport_zstd_compression() {
    let sink = GrpcTestSink::start().await;
    let config = GrpcSinkConfig {
        endpoint: sink.endpoint(),
        compression: SinkCompression::Zstd,
        ..GrpcSinkConfig::default()
    };
    let transport = build_transport(&sink.endpoint(), config).await;

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    transport
        .send_batch(vec![
            IncomingSinkEvent::Full(Arc::new(example_data_to_sink(
                SUBJECT_ID, SCHEMA_ID,
            ))),
            IncomingSinkEvent::Light(example_light_event(SUBJECT_ID, SCHEMA_ID)),
        ])
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 2);
    assert!(deliveries.iter().all(|d| d.accepted));

    let single = &deliveries[0];
    let body = single.body.as_ref().expect("delivery carries a body");
    let payload: serde_json::Value = serde_json::from_slice(&body.payload)
        .expect("zstd payload decompresses to JSON");
    assert_eq!(payload["payload"]["event"], "create");

    let batch_body =
        deliveries[1].body.as_ref().expect("batch carries a body");
    let batch: serde_json::Value = serde_json::from_slice(&batch_body.payload)
        .expect("zstd batch payload decompresses to JSON");
    assert_eq!(batch.as_array().expect("batch is an array").len(), 2);

    // The wire must actually be compressed (`grpc-encoding: zstd`), not
    // just decompressible: tonic would accept plaintext transparently.
    assert!(
        deliveries
            .iter()
            .all(|d| d.metadata.get("grpc-encoding").map(String::as_str)
                == Some("zstd")),
        "compressed transports must send grpc-encoding: zstd on every RPC"
    );
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
        auth: Some(SinkAuthMethod::ApiKey),
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
        auth: Some(SinkAuthMethod::BearerToken),
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

/// Basic auth: the password is read from the environment and sent as
/// `authorization: Basic base64(username:password)` metadata on every RPC.
#[test(tokio::test)]
async fn grpc_transport_sends_basic_auth_metadata() {
    let sink = GrpcTestSink::start().await;
    let _guard =
        TempEnvVar::set("AVE_SINK_PASSWORD_TEST_BASIC_AUTH", "pass-secret");

    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::Basic {
            username: "alice".to_owned(),
        }),
        ..grpc_config(&sink.endpoint())
    };
    let transport =
        build_transport_named("test-basic-auth", &sink.endpoint(), config)
            .await;
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 1);
    let expected = format!(
        "Basic {}",
        BASE64_STANDARD.encode("alice:pass-secret")
    );
    assert_eq!(deliveries[0].authorization.as_deref(), Some(expected.as_str()));
}

/// Custom static metadata: user headers reach the server on every RPC,
/// while keys reserved by the sink contract are silently filtered so the
/// delivery contract cannot be broken by configuration.
#[test(tokio::test)]
async fn grpc_transport_custom_headers_and_reserved_filtering() {
    let sink = GrpcTestSink::start().await;

    let config = GrpcSinkConfig {
        headers: HashMap::from([
            ("x-team".to_owned(), "ledger".to_owned()),
            ("x-ave-sn".to_owned(), "999".to_owned()),
            ("authorization".to_owned(), "evil".to_owned()),
            ("x-api-key".to_owned(), "evil".to_owned()),
        ]),
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();

    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 1);
    let metadata = &deliveries[0].metadata;
    assert_eq!(metadata.get("x-team").map(String::as_str), Some("ledger"));
    assert!(
        !metadata.contains_key("x-ave-sn"),
        "reserved x-ave-* headers must be filtered"
    );
    assert_eq!(
        deliveries[0].authorization, None,
        "reserved authorization header must be filtered"
    );
    assert_eq!(
        deliveries[0].api_key, None,
        "reserved x-api-key header must be filtered"
    );
}

/// OAuth2 (parity with the HTTP sink): the first delivery fetches and
/// caches the token from a real IdP, later deliveries reuse the cache, and
/// an UNAUTHENTICATED ack forces a refresh and an immediate retry.
#[test(tokio::test)]
async fn grpc_transport_oauth2_fetches_caches_and_refreshes_token() {
    let idp = TestSink::start().await;
    let sink = GrpcTestSink::start().await;
    let _guard = TempEnvVar::set(
        "AVE_SINK_PASSWORD_TEST_OAUTH2_FETCH",
        "oauth-secret",
    );

    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::OAuth2(SinkAuthConfig {
            auth_url: idp.auth_url(),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        })),
        retry_base_delay_ms: 1,
        ..grpc_config(&sink.endpoint())
    };
    let transport =
        build_transport_named("test-oauth2-fetch", &sink.endpoint(), config)
            .await;

    // First delivery: fetches the token and caches it.
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(idp.auth_requests().await.len(), 1);

    // Second delivery: the cached token is reused, no new fetch.
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(
        idp.auth_requests().await.len(),
        1,
        "a valid cached token must not be refetched"
    );
    for delivery in sink.deliveries() {
        assert_eq!(
            delivery.authorization.as_deref(),
            Some("Bearer test-access-token")
        );
    }

    // The server rejects the token once: the transport refreshes it and
    // retries immediately, delivering without error.
    sink.set_mode(GrpcResponseMode::FailTimes {
        code: Code::Unauthenticated,
        remaining: Arc::new(AtomicUsize::new(1)),
    });
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(
        idp.auth_requests().await.len(),
        2,
        "an UNAUTHENTICATED ack must force a token refresh"
    );
    assert_eq!(sink.accepted_deliveries().len(), 3);
}

/// OAuth2 proactive refresh: a cached token inside the refresh margin
/// (expiring soon) is renewed on the next RPC instead of being used until
/// it fails. With a margin larger than the IdP's `expires_in`, every RPC
/// refreshes (deterministic with the fixed 3600s test token).
///
/// Runs against a unary-only server on purpose: the delivery stream
/// carries the token in its open-time metadata, so per-RPC freshness is
/// only observable over unary deliveries (mid-stream freshness is the
/// reactive UNAUTHENTICATED path, covered by the refresh test).
#[test(tokio::test)]
async fn grpc_transport_oauth2_proactive_refresh_near_expiry() {
    let idp = TestSink::start().await;
    let sink = GrpcTestSink::start_unary_only().await;
    let _guard = TempEnvVar::set(
        "AVE_SINK_PASSWORD_TEST_OAUTH2_PROACTIVE",
        "oauth-secret",
    );

    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::OAuth2(SinkAuthConfig {
            auth_url: idp.auth_url(),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        })),
        token_refresh_margin_secs: 4_000,
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport_named(
        "test-oauth2-proactive",
        &sink.endpoint(),
        config,
    )
    .await;

    // First delivery: establishes the unary fallback and primes the cache.
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    let baseline = idp.auth_requests().await.len();

    // Every later RPC must proactively refresh the near-expiry token.
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(
        idp.auth_requests().await.len(),
        baseline + 1,
        "a token inside the refresh margin must be renewed proactively"
    );
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(
        idp.auth_requests().await.len(),
        baseline + 2,
        "every RPC must refresh a token inside the refresh margin"
    );
    assert_eq!(sink.accepted_deliveries().len(), 3);
}

/// OAuth2 with a failing IdP (invalid credentials): the token cannot be
/// obtained, the delivery fails with an `Auth` error and nothing reaches
/// the server.
#[test(tokio::test)]
async fn grpc_transport_oauth2_idp_failure_is_auth_error() {
    let idp = TestSink::start().await;
    idp.set_auth_mode(common::test_sink::AuthResponseMode::TokenFailure)
        .await;
    let sink = GrpcTestSink::start().await;
    let _guard = TempEnvVar::set(
        "AVE_SINK_PASSWORD_TEST_OAUTH2_IDP_FAIL",
        "wrong-secret",
    );

    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::OAuth2(SinkAuthConfig {
            auth_url: idp.auth_url(),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        })),
        retry_base_delay_ms: 1,
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport_named(
        "test-oauth2-idp-fail",
        &sink.endpoint(),
        config,
    )
    .await;

    let result = transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await;
    assert!(
        matches!(result, Err(SinkError::Auth { .. })),
        "expected an auth error, got {result:?}"
    );
    assert!(
        sink.deliveries().is_empty(),
        "no delivery may reach the server without a token"
    );
}

/// `ResourceExhausted` surfaces the server's backoff hint on both paths:
/// `google.rpc.RetryInfo` details (unary, parity with HTTP `Retry-After`)
/// and `DeliverAck.retry_after_ms` (stream).
#[test(tokio::test)]
async fn grpc_transport_retry_info_drives_backoff_hint() {
    for unary_only in [true, false] {
        let sink = if unary_only {
            GrpcTestSink::start_unary_only().await
        } else {
            GrpcTestSink::start().await
        };
        sink.set_mode(GrpcResponseMode::AlwaysStatusRetryInfo {
            code: Code::ResourceExhausted,
            retry_after_ms: 60_000,
        });
        let config = GrpcSinkConfig {
            max_retries: 0,
            ..grpc_config(&sink.endpoint())
        };
        let transport = build_transport(&sink.endpoint(), config).await;

        let result = transport
            .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
            .await;
        match result {
            Err(SinkError::Delivery {
                retryable: true,
                retry_after_ms: Some(60_000),
                ..
            }) => {}
            other => panic!(
                "the backoff hint must surface (unary_only={unary_only}), got {other:?}"
            ),
        }
    }
}

/// `warm_up` opens the delivery stream eagerly so the first delivery does
/// not pay the handshake.
#[test(tokio::test)]
async fn grpc_transport_warm_up_opens_stream_eagerly() {
    let sink = GrpcTestSink::start().await;
    let transport =
        build_transport(&sink.endpoint(), grpc_config(&sink.endpoint()))
            .await;

    assert_eq!(sink.stream_opens(), 0);
    transport.warm_up().await.unwrap();
    assert_eq!(
        sink.stream_opens(),
        1,
        "warm_up must open the stream eagerly"
    );

    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    assert_eq!(
        sink.stream_opens(),
        1,
        "the first delivery must reuse the warm stream"
    );
}

/// Best-effort batch delivery (Pause/Stop teardown): a single attempt, no
/// retries — the cursor guarantees re-delivery via catch-up.
#[test(tokio::test)]
async fn grpc_transport_best_effort_is_single_attempt() {
    let sink = GrpcTestSink::start().await;
    sink.set_mode(GrpcResponseMode::AlwaysStatus(Code::Unavailable));
    let config = GrpcSinkConfig {
        retry_base_delay_ms: 1,
        ..grpc_config(&sink.endpoint())
    };
    let transport = build_transport(&sink.endpoint(), config).await;

    let events = vec![IncomingSinkEvent::Full(Arc::new(
        example_data_to_sink(SUBJECT_ID, SCHEMA_ID),
    ))];
    let result = transport.send_batch_best_effort(events).await;
    assert!(
        matches!(result, Err(SinkError::Delivery { retryable: true, .. })),
        "expected a retryable delivery error, got {result:?}"
    );
    assert_eq!(
        sink.deliveries().len(),
        1,
        "best-effort delivery must not retry"
    );
}

/// The stream lifecycle surfaces in the shared metrics: the in-flight
/// gauge follows the window, acks feed the round-trip histogram and a
/// stream cut increments the reconnect counter.
#[test(tokio::test)]
async fn grpc_transport_exposes_stream_metrics() {
    // Initialize the core metrics global (idempotent OnceLock) with a
    // registry that shares the metric storage, like the Kafka stats test.
    let mut registry = prometheus_client::registry::Registry::default();
    ave_core::metrics::register(&mut registry);
    let encode = |registry: &prometheus_client::registry::Registry| {
        let mut text = String::new();
        prometheus_client::encoding::text::encode(&mut text, registry)
            .unwrap();
        text
    };

    let sink = GrpcTestSink::start().await;
    let sink_name = "test-stream-metrics";
    let config = GrpcSinkConfig {
        request_timeout_ms: 30_000,
        retry_base_delay_ms: 1,
        ..grpc_config(&sink.endpoint())
    };
    let transport = Arc::new(
        GrpcTransport::new(sink_name.to_owned(), config, None)
            .await
            .unwrap(),
    );

    // With a stalled consumer one delivery stays in flight: the gauge must
    // reflect it (poll pattern, no fixed sleeps).
    sink.pause_streams();
    let pending = tokio::spawn({
        let transport = Arc::clone(&transport);
        async move {
            transport
                .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
                .await
        }
    });
    let gauge_one =
        format!("core_sink_grpc_in_flight_batches{{sink=\"{sink_name}\"}} 1");
    let mut attempts = 0;
    loop {
        if encode(&registry).contains(&gauge_one) {
            break;
        }
        if attempts > 100 {
            panic!("timeout waiting for the in-flight gauge to reach 1");
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        attempts += 1;
    }

    sink.resume_streams();
    pending.await.unwrap().unwrap();

    let text = encode(&registry);
    assert!(
        text.contains(&format!(
            "core_sink_grpc_in_flight_batches{{sink=\"{sink_name}\"}} 0"
        )),
        "the gauge must return to 0 after the ack:\n{text}"
    );
    assert!(
        text.contains(&format!(
            "core_sink_grpc_ack_roundtrip_seconds_count{{sink=\"{sink_name}\"}} 1"
        )),
        "the ack must feed the round-trip histogram:\n{text}"
    );

    // A stream cut followed by a lazy reopen is a reconnection.
    sink.cut_streams();
    transport
        .send(Arc::new(example_data_to_sink(SUBJECT_ID, SCHEMA_ID)))
        .await
        .unwrap();
    let text = encode(&registry);
    assert!(
        text.contains(&format!(
            "core_sink_grpc_stream_reconnects_total{{sink=\"{sink_name}\"}} 1"
        )),
        "the cut must increment the reconnect counter:\n{text}"
    );
}

/// Configured auth with a missing environment secret is a build error.
#[test(tokio::test)]
async fn grpc_transport_auth_missing_secret_is_build_error() {
    let sink = GrpcTestSink::start().await;
    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::BearerToken),
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

/// End-to-end with `events: {Create}`: the create event travels as a full
/// event while facts travel as lightweight events (light flag, `fact`
/// event type and the LightEvent JSON body), both in catch-up and live.
#[test(tokio::test)]
async fn grpc_node_light_events_for_non_subscribed_types() {
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

    // Restart with a sink subscribed to Create only: catch-up must deliver
    // the create full and the fact as a lightweight event.
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
            "grpc-light-sink",
            &sink_endpoint,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::Create]),
            false,
        )],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    wait_for_sink_caught_up(&owner.api, "grpc-light-sink").await;
    sink.wait_for_deliveries(2).await;

    let deliveries = sink.deliveries();
    let create = &deliveries[0];
    let create_meta = create.meta.as_ref().expect("create carries meta");
    assert_eq!(create_meta.sn, 0);
    assert_eq!(create_meta.event_type, "create");
    assert!(!create_meta.light, "the create event must be delivered full");
    let create_body = create.body.as_ref().expect("full event carries a body");
    let payload: serde_json::Value =
        serde_json::from_slice(&create_body.payload).expect("payload is JSON");
    assert_eq!(payload["payload"]["event"], "create");

    let fact = &deliveries[1];
    let fact_meta = fact.meta.as_ref().expect("fact carries meta");
    assert_eq!(fact_meta.sn, 1);
    assert_eq!(fact_meta.event_type, "fact");
    assert!(fact_meta.light, "facts must travel as light events");
    assert_eq!(fact_meta.subject_id, subject_id.to_string());
    let fact_body = fact.body.as_ref().expect("light event carries a body");
    let light: serde_json::Value = serde_json::from_slice(&fact_body.payload)
        .expect("light payload is JSON");
    assert_eq!(light["subject_id"], subject_id.to_string());
    assert_eq!(light["sn"], 1);

    // A live fact also travels as a lightweight event.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    sink.wait_for_deliveries(3).await;
    let deliveries = sink.deliveries();
    let live_meta = deliveries[2].meta.as_ref().expect("live fact carries meta");
    assert_eq!(live_meta.sn, 2);
    assert_eq!(live_meta.event_type, "fact");
    assert!(live_meta.light, "live facts must travel as light events");
}

/// End-to-end with a governance sink (`schema_id: "governance"`): the
/// governance's own events (create + facts) are delivered with the
/// governance id as subject.
#[test(tokio::test)]
async fn grpc_node_governance_sink_receives_governance_events() {
    let sink = GrpcTestSink::start().await;

    let (owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!(
            "/memory/{}",
            PORT_COUNTER.fetch_add(1, Ordering::SeqCst)
        ),
        always_accept: true,
        sinks: vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: "governance".to_owned(),
                governance_id: None,
            },
            servers: vec![SinkServer {
                server: "grpc-gov-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Grpc(Box::new(
                    grpc_config(&sink.endpoint()),
                )),
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 2,
                ..Default::default()
            }],
        }],
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

    wait_for_sink_caught_up(&owner.api, "grpc-gov-sink").await;
    sink.wait_for_deliveries(2).await;

    let deliveries = sink.deliveries();
    let gov_id = governance_id.to_string();
    let sns: Vec<u64> = deliveries
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(sns, vec![0, 1], "governance events must arrive in order");

    let create_meta = deliveries[0].meta.as_ref().expect("create carries meta");
    assert_eq!(create_meta.subject_id, gov_id);
    assert_eq!(create_meta.schema_id, "governance");
    assert_eq!(create_meta.event_type, "create");
    assert!(!create_meta.light);

    let fact_meta = deliveries[1].meta.as_ref().expect("fact carries meta");
    assert_eq!(fact_meta.subject_id, gov_id);
    assert_eq!(fact_meta.event_type, "fact");
    assert!(!fact_meta.light);
}

/// End-to-end with `compression: gzip` and custom headers in the node's
/// sink config: both options reach the wire on real ledger deliveries
/// (catch-up and live), and reserved keys stay filtered.
#[test(tokio::test)]
async fn grpc_node_gzip_and_custom_headers_end_to_end() {
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

    // Restart with the gzip + headers sink: catch-up delivers the history.
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
        sinks: vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: SCHEMA_ID.to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: "grpc-gzip-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Grpc(Box::new(
                    GrpcSinkConfig {
                        endpoint: sink_endpoint,
                        compression: SinkCompression::Gzip,
                        headers: HashMap::from([
                            ("x-team".to_owned(), "ledger".to_owned()),
                            ("x-ave-sn".to_owned(), "999".to_owned()),
                        ]),
                        ..GrpcSinkConfig::default()
                    },
                )),
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

    wait_for_sink_caught_up(&owner.api, "grpc-gzip-sink").await;
    // Live event after the sink is up.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    sink.wait_for_deliveries(2).await;

    let deliveries = sink.deliveries();
    for delivery in &deliveries {
        assert_eq!(
            delivery.metadata.get("grpc-encoding").map(String::as_str),
            Some("gzip"),
            "every RPC must be gzip-compressed on the wire"
        );
        assert_eq!(
            delivery.metadata.get("x-team").map(String::as_str),
            Some("ledger"),
            "custom headers must reach the server"
        );
        assert!(
            !delivery.metadata.contains_key("x-ave-sn"),
            "reserved headers must stay filtered"
        );
        let body = delivery.body.as_ref().expect("delivery carries a body");
        serde_json::from_slice::<serde_json::Value>(&body.payload)
            .expect("gzip payload decompresses to JSON");
    }
}

/// End-to-end with `compression: zstd` in the node's sink config: real
/// ledger deliveries (catch-up and live) reach the wire zstd-compressed.
#[test(tokio::test)]
async fn grpc_node_zstd_end_to_end() {
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

    // Restart with the zstd sink: catch-up delivers the history.
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
        sinks: vec![SinkConfigEntry {
            target: SinkTarget::Schema {
                schema_id: SCHEMA_ID.to_owned(),
                governance_id: Some(governance_id.to_string()),
            },
            servers: vec![SinkServer {
                server: "grpc-zstd-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Grpc(Box::new(
                    GrpcSinkConfig {
                        endpoint: sink_endpoint,
                        compression: SinkCompression::Zstd,
                        ..GrpcSinkConfig::default()
                    },
                )),
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

    wait_for_sink_caught_up(&owner.api, "grpc-zstd-sink").await;
    // Live event after the sink is up.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    sink.wait_for_deliveries(2).await;

    let deliveries = sink.deliveries();
    for delivery in &deliveries {
        assert_eq!(
            delivery.metadata.get("grpc-encoding").map(String::as_str),
            Some("zstd"),
            "every RPC must be zstd-compressed on the wire"
        );
        let body = delivery.body.as_ref().expect("delivery carries a body");
        serde_json::from_slice::<serde_json::Value>(&body.payload)
            .expect("zstd payload decompresses to JSON");
    }
}

/// End-to-end replay: after the initial catch-up, `replay_sink_events`
/// re-delivers the subject history through the gRPC sink, in order,
/// without touching the cursor (mirrors the HTTP replay coverage).
#[test(tokio::test)]
async fn grpc_node_replay_redelivers_history() {
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
    for i in 0..2 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    // Restart with the gRPC sink: catch-up delivers the 3-event history.
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
            "grpc-replay-sink",
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

    wait_for_sink_caught_up(&owner.api, "grpc-replay-sink").await;
    sink.wait_for_deliveries(3).await;

    // Replay the whole history: the sink must receive sns 0..=2 again.
    let response = owner
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![SinkReplayItem {
                sink: "grpc-replay-sink".to_owned(),
                subject_id: subject_id.to_string(),
                from_sn: 0,
            }],
        })
        .await
        .unwrap();

    assert_eq!(response.processed.len(), 1);
    assert!(response.errors.is_empty());
    let processed = &response.processed[0];
    assert_eq!(processed.sink, "grpc-replay-sink");
    assert_eq!(processed.subject_id, subject_id.to_string());
    assert_eq!(processed.from_sn, 0);

    wait_for_sink_caught_up(&owner.api, "grpc-replay-sink").await;
    sink.wait_for_deliveries(6).await;
    let sns: Vec<u64> = sink
        .deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2, 0, 1, 2],
        "replay must re-deliver the history in order; got {sns:?}"
    );
}

/// Regression test: a replay that rewinds a subject whose catch-up is still
/// QUEUED in the sink worker (catch-up concurrency saturated by another
/// subject) must restart that queued catch-up from the lower SN. The worker
/// used to deduplicate pending catch-ups by subject, keeping the first
/// `from_sn`: the manager's restart with the lower `from_sn` was swallowed
/// and the events between the replay floor and the queued `from_sn` were
/// never re-delivered, while the manager's cursor advanced past them.
///
/// Scenario: two subjects with cursor at sn 1 and `max_catch_up_concurrency:
/// 1`. A replay from sn 1 leaves one catch-up active and the other pending
/// (from_sn 1); a second replay from sn 0 while the active one is still
/// running must rewind BOTH. The pending one used to keep from_sn 1, so its
/// sn 0 never arrived again. Whichever subject ends up active vs pending is
/// nondeterministic, so both are replayed and both are asserted.
#[test(tokio::test)]
async fn grpc_node_replay_rewinds_pending_catch_up() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_a) =
        start_node_with_history(1).await;
    let (subject_b, _) =
        create_subject(&owner.api, governance_id.clone(), SCHEMA_ID, "", true)
            .await
            .unwrap();
    emit_fact(
        &owner.api,
        subject_b.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // Restart with the sink and a single catch-up slot.
    let sink_endpoint = sink.endpoint();
    let mut owner = owner;
    let mut dirs = dirs;
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
                server: "grpc-pending-replay-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Grpc(Box::new(
                    grpc_config(&sink_endpoint),
                )),
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 1,
                ..Default::default()
            }],
        }],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    // Initial catch-up: sns 0 and 1 of both subjects (cursors at 1).
    wait_for_sink_caught_up(&owner.api, "grpc-pending-replay-sink").await;
    sink.wait_for_deliveries(4).await;
    let base = sink.deliveries().len();

    // Slow the acks so the active catch-up stays in flight while the second
    // replay arrives; the other subject waits in the pending queue.
    sink.set_stream_ack_delay(2_000);

    // First replay from sn 1: one catch-up goes active, the other pends
    // with from_sn 1.
    let response = owner
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                SinkReplayItem {
                    sink: "grpc-pending-replay-sink".to_owned(),
                    subject_id: subject_a.to_string(),
                    from_sn: 1,
                },
                SinkReplayItem {
                    sink: "grpc-pending-replay-sink".to_owned(),
                    subject_id: subject_b.to_string(),
                    from_sn: 1,
                },
            ],
        })
        .await
        .unwrap();
    assert_eq!(response.processed.len(), 2);
    assert!(response.errors.is_empty());

    // The active catch-up is delivering: the pending queue now holds the
    // other subject. Rewind BOTH to sn 0 before it completes.
    sink.wait_for_deliveries(base + 1).await;
    let response = owner
        .api
        .replay_sink_events(SinkReplayRequest {
            requests: vec![
                SinkReplayItem {
                    sink: "grpc-pending-replay-sink".to_owned(),
                    subject_id: subject_a.to_string(),
                    from_sn: 0,
                },
                SinkReplayItem {
                    sink: "grpc-pending-replay-sink".to_owned(),
                    subject_id: subject_b.to_string(),
                    from_sn: 0,
                },
            ],
        })
        .await
        .unwrap();
    assert_eq!(response.processed.len(), 2);
    assert!(response.errors.is_empty());

    wait_for_sink_caught_up(&owner.api, "grpc-pending-replay-sink").await;

    // The replay from sn 0 must re-deliver sn 0 of BOTH subjects: the
    // original delivery plus the replayed one.
    let accepted = sink.accepted_deliveries();
    for subject_id in [subject_a, subject_b] {
        let sn0_count = accepted
            .iter()
            .filter(|d| {
                d.meta.as_ref().is_some_and(|m| {
                    m.subject_id == subject_id.to_string() && m.sn == 0
                })
            })
            .count();
        assert_eq!(
            sn0_count, 2,
            "subject {subject_id} must receive sn 0 twice (original + \
             replay); the rewind of a pending catch-up must not be swallowed"
        );
    }
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

/// End-to-end with `events: {Create}` and `signature = true`: light events
/// are signed as well — the signature covers the light payload and the
/// routing metadata, and verifies against the node's public key (mirrors
/// the HTTP sink's signed light events).
#[test(tokio::test)]
async fn grpc_node_signs_light_events() {
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
    for i in 1..=2 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

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
            "grpc-signed-light-sink",
            &sink_endpoint,
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::Create]),
            true,
        )],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    // Catch-up: create full (sn 0) plus the two facts as light events.
    wait_for_sink_caught_up(&owner.api, "grpc-signed-light-sink").await;
    sink.wait_for_deliveries(3).await;

    let node_key =
        PublicKey::from_str(owner.api.public_key()).expect("node public key");
    let deliveries = sink.deliveries();
    assert_eq!(deliveries.len(), 3, "create + two facts");
    assert!(
        !deliveries[0].meta.as_ref().expect("create carries meta").light,
        "the create event must be delivered full"
    );
    assert!(
        deliveries[1..]
            .iter()
            .all(|d| d.meta.as_ref().expect("fact carries meta").light),
        "facts must be delivered as light events"
    );

    for delivery in &deliveries {
        let meta = delivery.meta.as_ref().expect("deliveries carry meta");
        let body = delivery.body.as_ref().expect("deliveries carry a body");

        assert!(!body.signature.is_empty(), "signed delivery");
        assert_eq!(body.public_key, owner.api.public_key());
        assert!(body.signature_timestamp > 0);

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
            .expect("light event signature must verify");

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

/// Regression test: after a manual unblock the worker's healthcheck chain
/// must resume. `ClearBlocked` used to cancel the pending healthcheck
/// without scheduling the next one, and since the chain is self-sustaining
/// (every `HealthCheck` message schedules the following one) the worker was
/// left with no healthchecks at all after an unblock. The idle check only
/// runs inside the `HealthCheck` handler, so the worker never reported idle
/// again — the manager could never idle-kill it — and the sink lost health
/// monitoring until the next delivery failure. The test sink runs without
/// the `grpc.health.v1` service, so every healthcheck falls back to the
/// `Test` RPC and is observable through `wait_for_tests`.
#[test(tokio::test)]
async fn grpc_node_unblock_resumes_healthchecks() {
    let sink = GrpcTestSink::start_without_health_service().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(0).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-unblock-hc-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-unblock-hc-sink").await;
    sink.wait_for_deliveries(1).await;
    // The periodic chain is alive: healthchecks arrive via the fallback.
    sink.wait_for_tests(1).await;

    // Block the sink with a permanent rejection, then fix the server and
    // unblock manually: catch-up redelivers the rejected event.
    sink.set_mode(GrpcResponseMode::AlwaysStatus(Code::InvalidArgument));
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    wait_for_sink_blocked(&owner.api, "grpc-unblock-hc-sink").await;
    sink.set_mode(GrpcResponseMode::Accept);
    owner
        .api
        .unblock_sink("grpc-unblock-hc-sink".to_owned())
        .await
        .unwrap();
    sink.wait_for_accepted(2).await;

    // The healthcheck chain must resume after the unblock: more Test RPCs
    // must arrive. Before the fix none ever did.
    let baseline = sink.tests().len();
    sink.wait_for_tests(baseline + 2).await;
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
        auth: Some(SinkAuthMethod::BearerToken),
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

/// `Api::get_sink` exposes the sanitized view of a gRPC sink: flat transport
/// kind, endpoint and delivery contract, without internal tuning or
/// credentials.
#[test(tokio::test)]
async fn grpc_node_sink_info_view() {
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

    let info = owner
        .api
        .get_sink("grpc-node-sink".to_owned())
        .await
        .unwrap();
    assert_eq!(info.transport.as_deref(), Some("grpc"));
    assert!(info.in_config);
    assert!(info.running);
    let Some(SinkServerView {
        transport: SinkTransportView::Grpc(view),
        ..
    }) = &info.server
    else {
        panic!("expected the gRPC transport view, got {:?}", info.server);
    };
    assert_eq!(view.endpoint, sink.endpoint());
    assert!(view.auth.is_none());
    assert!(!view.tls);
    assert!(!view.signature);
    assert!(!view.batch_delivery);
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

/// Regression test for the child-shutdown reap: server acks slower than
/// the subject worker's idle reap timeout (2s by default) must not abort
/// an in-flight catch-up — the child is working, not idle. Before the fix
/// the child was reaped mid-catch-up, the abort went unnoticed by the
/// manager and recovery came ~20s later through a second worker (breaking
/// exactly-once-per-worker assumptions like `stream_opens == 1`).
#[test(tokio::test)]
async fn grpc_node_catch_up_with_slow_acks_completes_without_restart() {
    let sink = GrpcTestSink::start().await;
    // 3s per ack: longer than the 2s child reap, shorter than the 5s
    // request timeout (so no retry fires either).
    sink.set_stream_ack_delay(3_000);
    let (owner, dirs, governance_id, _) = start_node_with_history(2).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-slow-ack-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-slow-ack-sink").await;
    sink.wait_for_deliveries(3).await;

    let sns: Vec<u64> = sink
        .deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "catch-up must deliver the whole history in order; got {sns:?}"
    );
    assert_eq!(
        sink.stream_opens(),
        1,
        "a slow ack must not cost a worker restart"
    );
}

/// A live delivery whose ack takes longer than the subject worker's reap
/// timeout must still arrive exactly once and in order: the child is
/// working, not idle, so the reap must leave it alone, and the cursor
/// only advances after the ack, so no event is ever duplicated nor lost.
#[test(tokio::test)]
async fn grpc_node_live_delivery_slow_ack_arrives_once() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(0).await;
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-live-slow-ack-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-live-slow-ack-sink").await;
    sink.wait_for_deliveries(1).await;

    // Slow the acks down after the catch-up: each live fact takes 3s.
    sink.set_stream_ack_delay(3_000);
    for i in 1..=2 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    sink.wait_for_deliveries(3).await;
    let sns: Vec<u64> = sink
        .deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "live events with slow acks must arrive exactly once, in order; got {sns:?}"
    );
}

/// Regression test for the live-delivery reap: with acks slower than the
/// subject worker's idle reap timeout (2s by default), a burst of live
/// events must be delivered by the SAME worker. The reap timer is re-armed
/// on every dispatch and every progress report, but progress only arrives
/// after the ack — so with `ack_delay > reap_timeout + burst spacing` the
/// timer fires while the child is blocked mid-delivery with the next event
/// still queued in its mailbox. The stop discards that queued event (it is
/// not critical), the cursor stalls and the event only comes back ~20s
/// later through the death-watch recovery — with a second worker and a
/// second stream.
#[test(tokio::test)]
async fn grpc_node_live_burst_slow_ack_no_worker_restart() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(0).await;
    // 10s request timeout: the 4s ack can never die of timeout, so the
    // delivery succeeds and only the child reap can interfere.
    let config = GrpcSinkConfig {
        request_timeout_ms: 10_000,
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-burst-slow-ack-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-burst-slow-ack-sink").await;
    sink.wait_for_deliveries(1).await;

    // 4s per ack: the reap timer (2s after the last dispatch) fires while
    // the first delivery is still blocked and the second fact is queued in
    // the child's mailbox.
    sink.set_stream_ack_delay(4_000);
    for i in 1..=2 {
        emit_fact(
            &owner.api,
            subject_id.clone(),
            serde_json::json!({"ModOne": {"data": i}}),
            true,
        )
        .await
        .unwrap();
    }

    sink.wait_for_deliveries(3).await;
    let sns: Vec<u64> = sink
        .deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "the burst must arrive exactly once, in order; got {sns:?}"
    );
    assert_eq!(
        sink.stream_opens(),
        1,
        "a slow ack must not discard queued events nor cost a worker restart"
    );
}

/// Regression test for the sink-worker idle kill: with an ack slower than
/// `sink_worker_idle_timeout_ms`, the worker used to report itself idle in
/// the middle of a live delivery (in-flight live events were not tracked as
/// activity), so the manager shut it down ~one idle timeout later. The
/// shutdown drained the in-flight delivery, the cursor never advanced and
/// the death-watch recovery spawned a second worker with a second stream,
/// re-delivering the event. The fix accounts live deliveries in flight, so
/// the worker is never idle while one is pending and the event arrives
/// exactly once through the original stream.
#[test(tokio::test)]
async fn grpc_node_slow_live_delivery_no_idle_kill() {
    let sink = GrpcTestSink::start().await;
    let (mut owner, mut dirs, governance_id, subject_id) =
        start_node_with_history(0).await;

    // Inline restart: the sink worker idle timeout is set to 5s so the buggy
    // idle report fires at ~5s and the kill lands at ~10s, while the 12s ack
    // keeps the live delivery in flight across both (the 15s request timeout
    // can never abort it).
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
                server: "grpc-idle-kill-sink".to_owned(),
                events: BTreeSet::from([SinkTypes::All]),
                transport: SinkTransportConfig::Grpc(Box::new(
                    GrpcSinkConfig {
                        endpoint: sink.endpoint(),
                        request_timeout_ms: 15_000,
                        ..GrpcSinkConfig::default()
                    },
                )),
                healthcheck_intervals_secs: vec![1],
                startup_healthcheck_delay_secs: 0,
                max_catch_up_concurrency: 2,
                sink_worker_idle_timeout_ms: 5_000,
                ..Default::default()
            }],
        }],
        ..Default::default()
    })
    .await;
    dirs.append(&mut owner_dirs2);
    node_running(&owner.api).await.unwrap();

    wait_for_sink_caught_up(&owner.api, "grpc-idle-kill-sink").await;
    sink.wait_for_deliveries(1).await;

    // 12s per ack: the delivery outlives the idle report (~5s) and the
    // scheduled worker shutdown (~10s).
    sink.set_stream_ack_delay(12_000);
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    sink.wait_for_deliveries(2).await;
    let sns: Vec<u64> = sink
        .deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1],
        "the slow live event must arrive exactly once; got {sns:?}"
    );
    assert_eq!(
        sink.stream_opens(),
        1,
        "a worker busy with a live delivery must never be killed as idle"
    );
}

/// OAuth2 at the node level (parity with `sink_auth_token_refresh` of the
/// HTTP sink): the worker prefetches the token eagerly on startup
/// (`warm_up`), deliveries carry it as Bearer metadata and the cache is
/// reused — no extra fetches per event.
#[test(tokio::test)]
async fn grpc_node_oauth2_eager_fetch_and_delivery() {
    let idp = TestSink::start().await;
    let sink = GrpcTestSink::start().await;
    let _guard = TempEnvVar::set(
        "AVE_SINK_PASSWORD_GRPC_OAUTH_EAGER_SINK",
        "oauth-secret",
    );

    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::OAuth2(SinkAuthConfig {
            auth_url: idp.auth_url(),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        })),
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-oauth-eager-sink",
        config,
        &governance_id,
    )
    .await;

    // The worker prefetches the token eagerly on startup (same poll
    // pattern as the HTTP eager-fetch assertions, no fixed sleeps).
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while idp.auth_requests().await.is_empty() {
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("worker should fetch a token eagerly on startup");

    wait_for_sink_caught_up(&owner.api, "grpc-oauth-eager-sink").await;
    sink.wait_for_accepted(2).await;

    // Live event: delivered with the cached token, no extra fetch.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    sink.wait_for_accepted(3).await;

    assert_eq!(
        idp.auth_requests().await.len(),
        1,
        "the cached token must be reused for every delivery"
    );
    for delivery in sink.accepted_deliveries() {
        assert_eq!(
            delivery.authorization.as_deref(),
            Some("Bearer test-access-token"),
            "every delivery must carry the OAuth2 bearer token"
        );
    }
}

/// OAuth2 refresh at the node level (full parity with
/// `sink_auth_token_refresh` of the HTTP sink): the server rejects the
/// token once, the transport refreshes it and retries immediately — the
/// event arrives exactly once, the sink never goes lagging, and the stream
/// is torn down and reopened with the fresh token.
#[test(tokio::test)]
async fn grpc_node_oauth2_refresh_after_unauthenticated() {
    let idp = TestSink::start().await;
    let sink = GrpcTestSink::start().await;
    let _guard = TempEnvVar::set(
        "AVE_SINK_PASSWORD_GRPC_OAUTH_REFRESH_SINK",
        "oauth-secret",
    );

    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let config = GrpcSinkConfig {
        auth: Some(SinkAuthMethod::OAuth2(SinkAuthConfig {
            auth_url: idp.auth_url(),
            username: "test-user".to_owned(),
            ..SinkAuthConfig::default()
        })),
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-oauth-refresh-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-oauth-refresh-sink").await;
    sink.wait_for_accepted(2).await;
    assert_eq!(idp.auth_requests().await.len(), 1);

    // The server rejects the token once: refresh + immediate retry.
    sink.set_mode(GrpcResponseMode::FailTimes {
        code: Code::Unauthenticated,
        remaining: Arc::new(AtomicUsize::new(1)),
    });
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    sink.wait_for_accepted(3).await;
    wait_for_sink_caught_up(&owner.api, "grpc-oauth-refresh-sink").await;

    assert_eq!(
        idp.auth_requests().await.len(),
        2,
        "the UNAUTHENTICATED ack must force exactly one token refresh"
    );
    assert_eq!(
        sink.stream_opens(),
        2,
        "the stale-token stream must be torn down and reopened"
    );
    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "the event must arrive exactly once after the refresh; got {sns:?}"
    );
}

/// `warm_up` at the node level: the sink worker opens the delivery stream
/// eagerly on startup, before any subject produces events (no delivery is
/// needed for the stream to exist).
#[test(tokio::test)]
async fn grpc_node_warm_up_opens_stream_before_events() {
    let sink = GrpcTestSink::start().await;

    // Node with a governance and the schema, but NO subject: nothing will
    // ever be delivered to the sink.
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

    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    // The worker must open the stream eagerly on startup (poll pattern, no
    // fixed sleeps).
    let mut attempts = 0;
    loop {
        if sink.stream_opens() >= 1 {
            break;
        }
        if attempts > 100 {
            panic!("the sink worker did not open the stream on startup");
        }
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        attempts += 1;
    }
    assert!(
        sink.deliveries().is_empty(),
        "no delivery is needed for the stream to exist"
    );
    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
}

/// Graceful shutdown with an in-flight delivery: stopping the node while a
/// delivery waits for an ack that never comes completes in bounded time —
/// the pending attempt drains with its own request timeout and nothing
/// hangs (the §6.8 scenario of the production plan).
#[test(tokio::test)]
async fn grpc_node_shutdown_with_in_flight_delivery() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let config = GrpcSinkConfig {
        request_timeout_ms: 1_000,
        retry_base_delay_ms: 100,
        ..grpc_config(&sink.endpoint())
    };
    let (mut owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(2).await;

    // A live delivery goes in flight with the consumer stalled: its ack
    // will not arrive until long after the shutdown starts.
    sink.pause_streams();
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    // The shutdown must complete in bounded time (3 attempts x 1s ack
    // timeout + backoff + teardown is a few seconds; 20s is the outer
    // bound that catches a real deadlock even on loaded machines).
    owner.token.cancel();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        join_all(owner.handler.iter_mut()),
    )
    .await
    .expect("node shutdown must complete with an in-flight delivery");
}

/// Graceful shutdown drains in-flight deliveries (does not drop them):
/// stopping the node while a delivery waits for its (slow) ack lets the
/// handler drain to completion, so the cursor advances and a restart
/// re-delivers nothing.
#[test(tokio::test)]
async fn grpc_node_shutdown_drains_in_flight_delivery() {
    let sink = GrpcTestSink::start().await;
    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let (mut owner, mut dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-node-sink",
        grpc_config(&sink.endpoint()),
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;
    sink.wait_for_accepted(2).await;

    // Live event: the server reads it (recorded) but the ack is delayed.
    sink.set_stream_ack_delay(1_000);
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();
    sink.wait_for_deliveries(3).await;

    // Shutdown while the ack is pending: bounded completion that drains
    // the in-flight delivery instead of dropping it.
    let owner_keys: KeyPair = owner.keys.clone();
    let owner_local_db = dirs[0].path().to_path_buf();
    let owner_ext_db = dirs[1].path().to_path_buf();
    owner.token.cancel();
    tokio::time::timeout(
        std::time::Duration::from_secs(20),
        join_all(owner.handler.iter_mut()),
    )
    .await
    .expect("node shutdown must complete while draining a delivery");

    // If the delivery drained, its cursor advanced: a restart on the same
    // databases re-delivers nothing and sn 2 stays delivered exactly once.
    sink.set_stream_ack_delay(0);
    let (owner, mut new_dirs) = create_node(CreateNodeConfig {
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
            &sink.endpoint(),
            Some(governance_id.to_string()),
            BTreeSet::from([SinkTypes::All]),
            false,
        )],
        ..Default::default()
    })
    .await;
    dirs.append(&mut new_dirs);
    node_running(&owner.api).await.unwrap();
    wait_for_sink_caught_up(&owner.api, "grpc-node-sink").await;

    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "the drained delivery must advance the cursor (no re-delivery); got {sns:?}"
    );
}

/// mTLS at the node level (§6.4 of the production plan): a real worker
/// delivers catch-up and live events to a server that REQUIRES a client
/// certificate, with the node's `tls` paths (CA + client identity).
#[test(tokio::test)]
async fn grpc_node_mtls_end_to_end() {
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

    let (owner, dirs, governance_id, subject_id) =
        start_node_with_history(1).await;
    let config = GrpcSinkConfig {
        tls: Some(GrpcTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            client_certificate: client_cert_path.to_string_lossy().into_owned(),
            client_key: client_key_path.to_string_lossy().into_owned(),
        }),
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-mtls-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-mtls-sink").await;
    sink.wait_for_accepted(2).await;

    // Live event over the same mTLS channel.
    emit_fact(
        &owner.api,
        subject_id.clone(),
        serde_json::json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    sink.wait_for_accepted(3).await;
    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1, 2],
        "every event must arrive over the mTLS channel; got {sns:?}"
    );
}

/// mTLS misconfiguration at the node level (parity with
/// `sink_tls_missing_ca_fails` of the HTTP sink): the server requires a
/// client certificate and the node has none, so the handshake fails, no
/// request reaches the server and the subject goes lagging; configuring
/// the client identity and restarting recovers delivery.
#[test(tokio::test)]
async fn grpc_node_mtls_missing_client_cert_lags() {
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

    let (owner, dirs, governance_id, _subject_id) =
        start_node_with_history(1).await;
    // Only the CA: no client identity, so the server aborts the handshake.
    let config = GrpcSinkConfig {
        tls: Some(GrpcTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            ..GrpcTlsConfig::default()
        }),
        ..grpc_config(&sink.endpoint())
    };
    let (owner, dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-mtls-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_lagging_subjects(&owner.api, "grpc-mtls-sink", 1).await;
    assert!(
        sink.deliveries().is_empty(),
        "no request may survive a failed handshake"
    );

    // Fix the configuration (client identity) and restart: catch-up
    // delivers the pending events.
    let config = GrpcSinkConfig {
        tls: Some(GrpcTlsConfig {
            ca_certificate: ca_path.to_string_lossy().into_owned(),
            client_certificate: client_cert_path.to_string_lossy().into_owned(),
            client_key: client_key_path.to_string_lossy().into_owned(),
        }),
        ..grpc_config(&sink.endpoint())
    };
    let (owner, _dirs) = restart_with_grpc_sink(
        owner,
        dirs,
        "grpc-mtls-sink",
        config,
        &governance_id,
    )
    .await;

    wait_for_sink_caught_up(&owner.api, "grpc-mtls-sink").await;
    sink.wait_for_accepted(2).await;
    let sns: Vec<u64> = sink
        .accepted_deliveries()
        .iter()
        .filter_map(|d| d.meta.as_ref().map(|m| m.sn))
        .collect();
    assert_eq!(
        sns,
        vec![0, 1],
        "the pending events must arrive after fixing the client identity; got {sns:?}"
    );
}
