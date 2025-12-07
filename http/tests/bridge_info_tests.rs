// Ave HTTP - Bridge Info Tests
//
// Tests that initialize a Bridge and retrieve peer-id and controller-id
// Also tests for business logic endpoint deserialization

mod common;

use crate::common::create_bridge;

#[tokio::test]
async fn test_bridge_peer_id_and_controller_id() {
  let (bridge, _runners,_dirs) = create_bridge().await;

    // Get peer-id
    let peer_id = bridge.peer_id();
    println!("Peer ID: {}", peer_id);

    // Get controller-id
    let controller_id = bridge.controller_id();
    println!("Controller ID: {}", controller_id);

    // Verify both IDs are not empty
    assert!(!peer_id.to_string().is_empty(), "Peer ID should not be empty");
    assert!(!controller_id.to_string().is_empty(), "Controller ID should not be empty");

    // Verify they are different (peer-id and controller-id should be different)
    assert_ne!(peer_id.to_string(), controller_id.to_string(),
        "Peer ID and Controller ID should be different");
}

// =============================================================================
// Business Logic Endpoints Deserialization Tests
// =============================================================================
// These tests verify that HTTP request/response serialization works correctly
// for all business logic endpoints. They don't test the business logic itself
// (that's tested in core), but rather the HTTP layer deserialization.

// --- Request Endpoints ---
#[tokio::test]
#[ignore]
async fn test_event_request_deserialization() {
    // POST /event-request - BridgeSignedEventRequest -> RequestData
    todo!("Test send_event_request endpoint deserialization")
}

#[tokio::test]
#[ignore]
async fn test_request_state_deserialization() {
    // GET /event-request/{request-id} -> RequestInfo
    todo!("Test get_request_state endpoint deserialization")
}

// --- Approval Endpoints ---
#[tokio::test]
#[ignore]
async fn test_approval_request_deserialization() {
    // GET /approval-request/{subject_id} -> ApproveInfo
    // PATCH /approval-request/{subject_id} + Json<String> -> String
    todo!("Test approval endpoints deserialization")
}

// --- Authorization Endpoints ---
#[tokio::test]
#[ignore]
async fn test_auth_endpoints_deserialization() {
    // PUT /auth/{subject_id} + Json<Vec<String>> -> String
    // GET /auth -> Vec<String>
    // GET /auth/{subject_id} -> Vec<String>
    // DELETE /auth/{subject_id} -> String
    todo!("Test authorization endpoints deserialization")
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
#[ignore]
async fn test_system_info_deserialization() {
    // GET /controller-id -> String
    // GET /peer-id -> String
    // GET /config -> ConfigHttp
    // GET /keys -> Binary (application/pkcs8)
    todo!("Test system info endpoints deserialization")
}
