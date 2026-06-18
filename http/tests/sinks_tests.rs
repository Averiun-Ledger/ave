use reqwest::Client;
use serde_json::Value;
use test_log::test;

use crate::common::{TestServer, make_request};

pub mod common;

#[test(tokio::test)]
async fn test_get_sinks_returns_list() {
    let Some((server, _dirs)) = TestServer::build(false, false, None).await else {
        return;
    };

    let client = Client::new();
    let (status, body) = make_request(&client, &server.url("/sinks"), "GET", None, None).await;

    assert_eq!(status, 200);
    let sinks: Value = serde_json::from_value(body).expect("response should be JSON");
    assert!(sinks.is_array());
}

#[test(tokio::test)]
async fn test_get_sinks_status_returns_list() {
    let Some((server, _dirs)) = TestServer::build(false, false, None).await else {
        return;
    };

    let client = Client::new();
    let (status, body) =
        make_request(&client, &server.url("/sinks/status"), "GET", None, None).await;

    assert_eq!(status, 200);
    let sinks: Value = serde_json::from_value(body).expect("response should be JSON");
    assert!(sinks.is_array());
}

#[test(tokio::test)]
async fn test_get_sinks_filters_by_name() {
    let Some((server, _dirs)) = TestServer::build(false, false, None).await else {
        return;
    };

    let client = Client::new();
    let (status, body) = make_request(
        &client,
        &server.url("/sinks?name=nonexistent"),
        "GET",
        None,
        None,
    )
    .await;

    assert_eq!(status, 200);
    let sinks: Vec<Value> = serde_json::from_value(body).expect("response should be JSON array");
    assert!(sinks.is_empty());
}
