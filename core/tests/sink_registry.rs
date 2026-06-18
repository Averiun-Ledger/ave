mod common;

use std::sync::atomic::Ordering;

use ave_common::bridge::request::SinksQuery;
use ave_core::{
    config::{SinkConfigEntry, SinkServer, SinkTarget},
    error::Error,
};
use ave_network::NodeType;
use test_log::test;

use crate::common::{
    create_node, node_running, CreateNodeConfig, PORT_COUNTER,
};

/// Build a sink configuration with one governance sink and one schema sink.
fn sample_sinks() -> Vec<SinkConfigEntry> {
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

#[test(tokio::test)]
async fn sink_registry_populated_from_config() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let sinks = node.api.get_sinks(SinksQuery::default()).await.unwrap();

    assert_eq!(sinks.len(), 2);
    let names: Vec<_> = sinks.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"gov-sink"));
    assert!(names.contains(&"schema-sink"));

    let gov = sinks.iter().find(|s| s.name == "gov-sink").unwrap();
    assert!(gov.in_config);
    assert_eq!(gov.manager, ave_common::bridge::response::SinkManagerTarget::Node);

    let schema = sinks.iter().find(|s| s.name == "schema-sink").unwrap();
    assert!(schema.in_config);
    assert!(
        matches!(
            schema.manager,
            ave_common::bridge::response::SinkManagerTarget::Governance { .. }
        ),
        "schema sink should be managed by its governance"
    );
}

#[test(tokio::test)]
async fn get_sinks_status_returns_configured_sinks() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let statuses = node.api.get_sinks_status().await.unwrap();
    let names: Vec<_> = statuses.iter().map(|s| s.name.as_str()).collect();
    assert!(names.contains(&"gov-sink"));
    assert!(names.contains(&"schema-sink"));
}

#[test(tokio::test)]
async fn delete_sink_cursors_fails_outside_safe_mode() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let err = node
        .api
        .delete_sink_cursors("gov-sink".to_owned())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SafeMode(_)), "expected safe mode error, got {:?}", err);
}

#[test(tokio::test)]
async fn unknown_sink_returns_not_found() {
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", port),
        sinks: sample_sinks(),
        ..Default::default()
    })
    .await;
    node_running(&node.api).await.unwrap();

    let err = node
        .api
        .unblock_sink("missing-sink".to_owned())
        .await
        .unwrap_err();
    assert!(matches!(err, Error::SinkNotFound(_)), "expected sink not found, got {:?}", err);
}
