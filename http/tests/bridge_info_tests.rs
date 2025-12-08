use std::{collections::BTreeSet, time::Duration};

use ave_common::{
    ApproveInfo, BridgeCreateRequest, BridgeEventRequest, BridgeFactRequest,
    BridgeSignedEventRequest, RequestData, RequestInfo,
    identity::{KeyPair, keys::Ed25519Signer},
};
use ave_http::config_types::ConfigHttp;
// Ave HTTP - Bridge Info Tests
//
// Tests that initialize a Bridge and retrieve peer-id and controller-id
// Also tests for business logic endpoint deserialization
use reqwest::Client;
use serde_json::{Value, json};

use crate::common::{TestServer, make_request};

mod common;

// =============================================================================
// Business Logic Endpoints Deserialization Tests
// =============================================================================
// These tests verify that HTTP request/response serialization works correctly
// for all business logic endpoints. They don't test the business logic itself
// (that's tested in core), but rather the HTTP layer deserialization.

async fn create_req(client: &Client, server: &TestServer) -> Value {
    let request = BridgeSignedEventRequest {
        request: BridgeEventRequest::Create(BridgeCreateRequest {
            name: Some("Governance".to_string()),
            description: Some("A governance".to_string()),
            governance_id: None,
            schema_id: "governance".to_string(),
            namespace: None,
        }),
        signature: None,
    };

    let (status, body) = make_request(
        &client,
        &server.url("/event-request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    body
}

async fn fact_req(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) -> (Value, String) {
    let node1_controller = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let request = BridgeSignedEventRequest {
        request: BridgeEventRequest::Fact(BridgeFactRequest {
            subject_id: subject_id.to_string(),
            payload: json!({
            "members": {
                "add": [
                    {
                        "name": "Node1",
                        "key": node1_controller
                    }
                ]
            }}),
        }),
        signature: None,
    };

    let (status, body) = make_request(
        &client,
        &server.url("/event-request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    (body, node1_controller)
}

// --- Request Endpoints ---
#[tokio::test]
async fn test_event_request_deserialization() {
    // POST /event-request - BridgeSignedEventRequest -> RequestData

    let (server, _dirs) = TestServer::build(false, false).await;
    let client = Client::new();

    let body = create_req(&client, &server).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    assert!(!request_data.request_id.is_empty());
    assert!(!request_data.subject_id.is_empty());
    assert_eq!(request_data.request_id, request_data.subject_id);
}

#[tokio::test]
async fn test_request_state_deserialization() {
    // GET /event-request/{request-id} -> RequestInfo
    let (server, _dirs) = TestServer::build(false, false).await;
    let client = Client::new();

    let body = create_req(&client, &server).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let res: Value;
    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/event-request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["status"] == "Finish" {
            res = body;
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let request_info: RequestInfo = serde_json::from_value(res).unwrap();
    assert_eq!(request_info.status, "Finish");
    assert_eq!(request_info.version, 0);
    assert_eq!(request_info.error, None);
}

// --- Approval Endpoints ---
#[tokio::test]
async fn test_approval_request_deserialization() {
    // GET /approval-request/{subject_id} -> ApproveInfo
    // PATCH /approval-request/{subject_id} + Json<String> -> String

    let (server, _dirs) = TestServer::build(false, false).await;
    let client = Client::new();

    let body = create_req(&client, &server).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let (body, controller_id) =
        fact_req(&client, &server, &request_data.subject_id).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let res: Value;
    loop {
        let (status, body) = make_request(
            &client,
            &server
                .url(&format!("/approval-request/{}", request_data.subject_id)),
            "GET",
            None,
            None,
        )
        .await;

        if status.is_success() {
            res = body;
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let approval: ApproveInfo = serde_json::from_value(res).unwrap();

    assert_eq!(approval.state, "Pending");
    assert_eq!(approval.request.sn, 1);
    assert_eq!(approval.request.gov_version, 0);
    assert_eq!(approval.request.subject_id, request_data.subject_id);
    assert_eq!(
        approval.request.event_request.content.subject_id,
        request_data.subject_id
    );
    assert_eq!(
        approval.request.event_request.content.payload,
        json!({
        "members": {
            "add": [
                {
                    "name": "Node1",
                    "key": controller_id
                }
            ]
        }})
    );
    assert!(
        !approval
            .request
            .event_request
            .signature
            .content_hash
            .is_empty()
    );
    assert!(!approval.request.event_request.signature.value.is_empty());
    assert!(!approval.request.state_hash.is_empty());
    assert!(!approval.request.hash_prev_event.is_empty());

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/approval-request/{}", request_data.subject_id)),
        "PATCH",
        None,
        Some(json!("Accepted")),
    )
    .await;

    assert!(status.is_success());

    let res: String = serde_json::from_value(body).unwrap();
    assert_eq!(
        res,
        format!(
            "The approval request for subject {} has changed to RespondedAccepted",
            request_data.subject_id
        )
    );
}

// --- Authorization Endpoints ---
#[tokio::test]
async fn test_auth_endpoints_deserialization() {
    // PUT /auth/{subject_id} + Json<Vec<String>> -> String
    // GET /auth -> Vec<String>
    // GET /auth/{subject_id} -> Vec<String>
    // DELETE /auth/{subject_id} -> String
    let (server, _dirs) = TestServer::build(false, false).await;
    let client = Client::new();

    let (status, _body) = make_request(
        &client,
        &server.url("/auth/BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGY"),
        "PUT",
        None,
        Some(json!(["EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk"])),
    )
    .await;
    assert!(status.is_success());

    let (status, _body) = make_request(
        &client,
        &server.url("/auth/BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA"),
        "PUT",
        None,
        Some(json!(["EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk"])),
    )
    .await;
    assert!(status.is_success());

    let (status, body) = make_request(
        &client,
        &server.url("/auth"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let subjects: Vec<String> = serde_json::from_value(body).unwrap();
    assert_eq!(BTreeSet::from_iter(subjects.iter()), BTreeSet::from([&"BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA".to_string(), &"BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGY".to_string()]));

    let (status, body) = make_request(
        &client,
        &server.url("/auth/BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let controller_id: Vec<String> = serde_json::from_value(body).unwrap();
    assert_eq!(controller_id, vec!["EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk"]);

    let (status, _body) = make_request(
        &client,
        &server.url("/auth/BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA"),
        "DELETE",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let (status, body) = make_request(
        &client,
        &server.url("/auth"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let subjects: Vec<String> = serde_json::from_value(body).unwrap();
    assert_eq!(subjects, vec!["BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGY"]);
}

// --- Subject Update & Transfer Endpoints ---
#[tokio::test]
#[ignore]
async fn test_update_and_transfer_deserialization() {
    // POST /update/{subject_id} -> String
    // POST /check-transfer/{subject_id} -> String
    // POST /manual-distribution/{subject_id} -> String
    // GET /pending-transfers -> Vec<TransferSubject>
    todo!("Test update and transfer endpoints deserialization")
}

// --- Governance Endpoints ---
#[tokio::test]
#[ignore]
async fn test_governances_deserialization() {
    // GET /register-governances?active={bool} -> Vec<GovsData>
    todo!("Test governance listing endpoint deserialization")
}

// --- Subject Endpoints ---
#[tokio::test]
#[ignore]
async fn test_subjects_deserialization() {
    // GET /register-subjects/{governance_id}?active={bool}&schema={string} -> Vec<RegisterDataSubj>
    // GET /state/{subject_id} -> SubjectInfo
    todo!("Test subject endpoints deserialization")
}

// --- Event Endpoints ---
#[tokio::test]
#[ignore]
async fn test_events_deserialization() {
    // GET /events/{subject_id}?quantity={u64}&page={u64}&reverse={bool} -> PaginatorEvents
    // GET /event/{subject_id}?sn={u64} -> EventInfo
    // GET /events-first-last/{subject_id}?quantity={u64}&success={bool}&reverse={bool} -> Vec<EventInfo>
    todo!("Test event endpoints deserialization")
}

// --- Signature Endpoints ---
#[tokio::test]
#[ignore]
async fn test_signatures_deserialization() {
    // GET /signatures/{subject_id} -> SignaturesInfo

    todo!("Test signatures endpoint deserialization")
}

// --- System Info Endpoints ---
#[tokio::test]
async fn test_system_info_deserialization() {
    // GET /controller-id -> String
    // GET /peer-id -> String
    // GET /config -> ConfigHttp
    // GET /keys -> Binary (application/pkcs8)

    let (server, dirs) = TestServer::build(false, false).await;
    let client = Client::new();

    // CONTROLLER-ID
    let (status, body) =
        make_request(&client, &server.url("/controller-id"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let controller_id: String = serde_json::to_string(&body).unwrap();

    // PEER-ID
    let (status, body) =
        make_request(&client, &server.url("/peer-id"), "GET", None, None).await;
    assert!(status.is_success());
    let peer_id: String = serde_json::to_string(&body).unwrap();

    assert!(!peer_id.is_empty(), "Peer ID should not be empty");
    assert!(
        !controller_id.is_empty(),
        "Controller ID should not be empty"
    );

    // Verify they are different (peer-id and controller-id should be different)
    assert_ne!(
        peer_id.to_string(),
        controller_id.to_string(),
        "Peer ID and Controller ID should be different"
    );

    // CONFIG
    let (status, body) =
        make_request(&client, &server.url("/config"), "GET", None, None).await;
    assert!(status.is_success());
    let config: ConfigHttp = serde_json::from_value(body).unwrap();

    let expected_contracts_path = dirs[2].path().to_string_lossy().to_string();
    let expected_keys_path = dirs[3].path().to_string_lossy().to_string();
    let expected_auth_db_path = dirs[4].path().to_string_lossy().to_string();
    let expected_listen_address = format!("/memory/{}", server.memory_port());

    assert_eq!(config.node.keypair_algorithm, "Ed25519");
    assert_eq!(config.node.hash_algorithm, "Blake3");
    assert_eq!(config.node.ave_db, "Sqlite");
    assert_eq!(config.node.external_db, "Sqlite");
    assert_eq!(config.node.contracts_path, expected_contracts_path);
    assert!(config.node.always_accept);
    assert_eq!(config.node.garbage_collector, 120);

    assert_eq!(config.node.network.node_type, "Bootstrap");
    assert_eq!(
        config.node.network.listen_addresses,
        vec![expected_listen_address]
    );
    assert!(config.node.network.external_addresses.is_empty());
    assert!(config.node.network.boot_nodes.is_empty());
    assert_eq!(config.node.network.tell.message_timeout_secs, 10);
    assert_eq!(config.node.network.tell.max_concurrent_streams, 100);
    assert_eq!(config.node.network.req_res.message_timeout_secs, 10);
    assert_eq!(config.node.network.req_res.max_concurrent_streams, 100);
    assert!(config.node.network.routing.dht_random_walk);
    assert_eq!(
        config.node.network.routing.discovery_only_if_under_num,
        u64::MAX
    );
    assert!(!config.node.network.routing.allow_private_address_in_dht);
    assert!(!config.node.network.routing.allow_dns_address_in_dht);
    assert!(!config.node.network.routing.allow_loop_back_address_in_dht);
    assert!(config.node.network.routing.kademlia_disjoint_query_paths);
    assert!(!config.node.network.control_list.enable);
    assert!(config.node.network.control_list.allow_list.is_empty());
    assert!(config.node.network.control_list.block_list.is_empty());
    assert!(
        config
            .node
            .network
            .control_list
            .service_allow_list
            .is_empty()
    );
    assert!(
        config
            .node
            .network
            .control_list
            .service_block_list
            .is_empty()
    );
    assert_eq!(config.node.network.control_list.interval_request_secs, 60);

    assert_eq!(config.keys_path, expected_keys_path);
    assert_eq!(config.prometheus, "127.0.0.1:0");

    assert!(config.logging.output.stdout);
    assert!(!config.logging.output.file);
    assert!(!config.logging.output.api);
    assert!(config.logging.api_url.is_none());
    assert_eq!(config.logging.file_path, "logs");
    assert_eq!(config.logging.rotation, "Size");
    assert_eq!(config.logging.max_size, 104_857_600);
    assert_eq!(config.logging.max_files, 3);

    assert!(config.sink.sinks.is_empty());
    assert_eq!(config.sink.auth, "");
    assert_eq!(config.sink.username, "");

    assert!(!config.auth.enable);
    assert_eq!(config.auth.database_path, expected_auth_db_path);
    assert_eq!(config.auth.superadmin, "admin");
    assert_eq!(config.auth.api_key.default_ttl_seconds, 3600);
    assert_eq!(config.auth.api_key.max_keys_per_user, 20);
    assert_eq!(config.auth.lockout.max_attempts, 3);
    assert_eq!(config.auth.lockout.duration_seconds, 60);
    assert!(config.auth.rate_limit.enable);
    assert_eq!(config.auth.rate_limit.window_seconds, 60);
    assert_eq!(config.auth.rate_limit.max_requests, 20);
    assert!(config.auth.rate_limit.limit_by_key);
    assert!(config.auth.rate_limit.limit_by_ip);
    assert_eq!(config.auth.rate_limit.cleanup_interval_seconds, 1800);
    assert!(config.auth.session.audit_enable);
    assert_eq!(config.auth.session.audit_retention_days, 30);
    assert!(config.auth.session.log_all_requests);

    assert_eq!(config.http.http_address, "0.0.0.0:3000");
    assert!(config.http.https_address.is_none());
    assert!(config.http.https_cert_path.is_none());
    assert!(config.http.https_private_key_path.is_none());
    assert!(!config.http.enable_doc);

    // KEYS - Verify PKCS#8 with PKCS#5 encryption
    // First check if the key file actually exists in the keys_path directory
    let key_file_path =
        std::path::Path::new(&expected_keys_path).join("node_private.der");
    println!("Checking if key file exists at: {:?}", key_file_path);
    println!("Key file exists: {}", key_file_path.exists());

    if key_file_path.exists() {
        println!(
            "Key file size: {} bytes",
            std::fs::metadata(&key_file_path).unwrap().len()
        );
    } else {
        println!("ERROR: Key file does not exist!");
        println!("Keys directory contents:");
        if let Ok(entries) = std::fs::read_dir(&expected_keys_path) {
            for entry in entries {
                if let Ok(entry) = entry {
                    println!("  - {:?}", entry.file_name());
                }
            }
        }
    }

    // Get the encrypted private key from /keys endpoint
    let response = client
        .get(&server.url("/keys"))
        .send()
        .await
        .expect("Failed to fetch keys");

    assert!(
        response.status().is_success(),
        "Keys endpoint should return success"
    );

    // Get the encrypted key bytes
    let key_bytes = response.bytes().await.expect("Failed to read key bytes");

    // Parse as PKCS#8 EncryptedPrivateKeyInfo
    use pkcs8::EncryptedPrivateKeyInfo;
    let encrypted_key = EncryptedPrivateKeyInfo::try_from(key_bytes.as_ref())
        .expect("Should be valid PKCS#8 EncryptedPrivateKeyInfo");

    // Decrypt with password "test"
    let decrypted_pk = encrypted_key
        .decrypt("test")
        .expect("Failed to decrypt private key with password 'test'");

    // Convert to KeyPair (Ed25519)
    use ave_common::identity::KeyPair;
    let _key_pair = KeyPair::from_secret_der(decrypted_pk.as_bytes())
        .expect("Failed to create KeyPair from decrypted DER");
}
