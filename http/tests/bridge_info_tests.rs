use ave_http::config_types::ConfigHttp;
use std::{
    collections::{BTreeSet, HashSet},
    time::Duration,
};
use test_log::test;

use ave_bridge::ave_common::{
    DataToSinkEvent,
    SchemaType,
    bridge::request::ApprovalState,
    identity::{KeyPair, keys::Ed25519Signer},
    response::{
        ApprovalEntry, GovsData, LedgerDB, PaginatorEvents, RequestData,
        RequestInfo, RequestInfoExtend, RequestState, SinkEventsPage,
        SubjectDB, SubjsData, TransferSubject,
    },
};
use reqwest::Client;
use serde_json::{Value, json};

use crate::common::{
    TestServer, add_example_schema_to_governance,
    add_governance_member_as_witness, create_governance, create_subject,
    make_request, materialize_role_test_path, role_test_request_body,
    server_main_route_catalog, wait_request_finish,
};

pub mod common;

// =============================================================================
// Business Logic Endpoints Deserialization Tests
// =============================================================================
// These tests verify that HTTP request/response serialization works correctly
// for all business logic endpoints. They don't test the business logic itself
// (that's tested in core), but rather the HTTP layer deserialization.

async fn fact_req_schema(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
    public_key: &str,
) -> Value {
    let request = json!({
        "request": {
            "event": "fact",
            "data": {
                "subject_id": subject_id.to_string(),
                "payload": {
                "members": {
                    "add": [
                        {
                            "name": "node1",
                            "key": public_key
                        }
                    ]
                },
                "schemas": {
                    "add": [
                        {
                            "id": "Example1",
                            "contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==",
                            "initial_value": {
                                "one": 0,
                                "two": 0,
                                "three": 0
                            }
                        },
                                                {
                            "id": "Example2",
                            "contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==",
                            "initial_value": {
                                "one": 0,
                                "two": 0,
                                "three": 0
                            }
                        }
                    ]
                },
                "roles": {
                    "schema":
                        [
                        {
                            "schema_id": "Example1",
                                "add": {
                                    "evaluator": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        },
                                    ],
                                    "validator": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        }
                                    ],
                                    "witness": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        }
                                    ],
                                    "creator": [
                                        {
                                            "name": "Owner",
                                            "namespace": [],
                                            "quantity": "infinity"
                                        },
                                        {
                                            "name": "node1",
                                            "namespace": [],
                                            "quantity": "infinity"
                                        }
                                    ],
                                    "issuer": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        }
                                    ]

                            }
                        },
                            {
                            "schema_id": "Example2",
                                "add": {
                                    "evaluator": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        },
                                    ],
                                    "validator": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        }
                                    ],
                                    "witness": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        }
                                    ],
                                    "creator": [
                                        {
                                            "name": "Owner",
                                            "namespace": [],
                                            "quantity": "infinity"
                                        },
                                        {
                                            "name": "node1",
                                            "namespace": [],
                                            "quantity": "infinity"
                                        }
                                    ],
                                    "issuer": [
                                        {
                                            "name": "Owner",
                                            "namespace": []
                                        }
                                    ]
                                }

                        }
                    ]
                },
                "policies": {
                    "schema": [
                        {
                            "schema_id": "Example1",

                                "change": {
                                   "evaluate": {
                                        "fixed": 1
                                   },
                                   "validate": {
                                        "fixed": 1
                                   }
                                }

                        },
                        {
                            "schema_id": "Example2",
                                "change": {
                                   "evaluate": {
                                        "fixed": 1
                                   },
                                   "validate": {
                                        "fixed": 1
                                   }
                                }

                        }
                    ]
                }
            }
            }
        }
    });

    let (status, body) = make_request(
        &client,
        &server.url("/request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    body
}

async fn transfer_req(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
    public_key: &str,
) -> Value {
    let request = json!({
        "request": {
            "event": "transfer",
            "data": {
                "subject_id": subject_id.to_string(),
                "new_owner": public_key.to_string()
            }
        }
    });

    let (status, body) = make_request(
        &client,
        &server.url("/request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    body
}

async fn reject_req(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) -> Value {
    let request = json!({
        "request": {
            "event": "reject",
            "data": {
                "subject_id": subject_id.to_string()
            }
        }
    });

    let (status, body) = make_request(
        &client,
        &server.url("/request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    body
}

async fn confirm_req(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) -> Value {
    let request = json!({
        "request": {
            "event": "confirm",
            "data": {
                "subject_id": subject_id.to_string(),
                "name_old_owner": "Old_Owner"
            }
        }
    });

    let (status, body) = make_request(
        &client,
        &server.url("/request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    body
}

async fn eol_req(
    client: &Client,
    server: &TestServer,
    subject_id: &str,
) -> Value {
    let request = json!({
        "request": {
            "event": "eol",
            "data": {
                "subject_id": subject_id.to_string(),
            }
        }
    });

    let (status, body) = make_request(
        &client,
        &server.url("/request"),
        "POST",
        None,
        Some(serde_json::to_value(request).unwrap()),
    )
    .await;
    assert!(status.is_success());

    body
}

#[test(tokio::test)]
async fn test_request_deserialization() {
    // GET /request/{request-id} -> RequestInfo
    // GET /request -> Vec<RequestInfo>
    // POST /request -> RequestData
    let Some((server, _dirs)) = TestServer::build(false, false, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let res: Value;
    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            res = body;
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let request_info: RequestInfo = serde_json::from_value(res).unwrap();
    assert_eq!(request_info.state, RequestState::Finish);
    assert_eq!(request_info.version, 0);

    let (.., body) =
        make_request(&client, &server.url("/request"), "GET", None, None).await;

    let request_info: Vec<RequestInfoExtend> =
        serde_json::from_value(body).unwrap();
    assert_eq!(request_info.len(), 1);
    assert_eq!(request_info[0].state, RequestState::Finish);
    assert_eq!(request_info[0].version, 0);
    assert_eq!(request_info[0].request_id, request_data.request_id);
}

// --- Approval Endpoints ---
#[test(tokio::test)]
async fn test_approval_deserialization() {
    // GET /approval/{subject_id}?state={ApprovalState} -> Option<ApprovalEntry>
    // GET /approval?state={ApprovalState} -> Vec<ApprovalEntry>
    // PATCH /approval/{subject_id} + Json<String> -> String

    let Some((server, _dirs)) = TestServer::build(false, false, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let public_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let body = add_governance_member_as_witness(
        &client,
        &server,
        None,
        &request_data.subject_id,
        &public_key,
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let res: Value;
    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/approval/{}", request_data.subject_id)),
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

    let approval: Option<ApprovalEntry> = serde_json::from_value(res).unwrap();
    let approval = approval.unwrap();

    assert_eq!(approval.state, ApprovalState::Pending);
    assert_eq!(approval.request.sn, 1);
    assert_eq!(approval.request.gov_version, 0);
    assert_eq!(approval.request.subject_id, request_data.subject_id);

    let (.., body) = make_request(
        &client,
        &server.url(&format!(
            "/approval/{}?state=accepted",
            request_data.subject_id
        )),
        "GET",
        None,
        None,
    )
    .await;
    let approval_empty: Option<ApprovalEntry> =
        serde_json::from_value(body).unwrap();
    assert!(approval_empty.is_none());

    let (.., body) = make_request(
        &client,
        &server.url(&format!("/approval")),
        "GET",
        None,
        None,
    )
    .await;

    let approvals: Vec<ApprovalEntry> = serde_json::from_value(body).unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].state, ApprovalState::Pending);
    assert_eq!(approvals[0].request.sn, 1);
    assert_eq!(approvals[0].request.gov_version, 0);
    assert_eq!(approvals[0].request.subject_id, request_data.subject_id);

    let (.., body) = make_request(
        &client,
        &server.url(&format!("/approval?state=accepted")),
        "GET",
        None,
        None,
    )
    .await;

    let approvals_empty: Vec<ApprovalEntry> =
        serde_json::from_value(body).unwrap();
    assert!(approvals_empty.is_empty());

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/approval/{}", request_data.subject_id)),
        "PATCH",
        None,
        Some(json!("accepted")),
    )
    .await;

    assert!(status.is_success());

    let res: String = serde_json::from_value(body).unwrap();
    assert_eq!(
        res,
        format!(
            "The approval request for subject {} has changed to accepted",
            request_data.subject_id
        )
    );

    let (.., body) = make_request(
        &client,
        &server.url(&format!(
            "/approval/{}?state=accepted",
            request_data.subject_id
        )),
        "GET",
        None,
        None,
    )
    .await;

    let approval: Option<ApprovalEntry> = serde_json::from_value(body).unwrap();
    let approval = approval.unwrap();
    assert_eq!(approval.state, ApprovalState::Accepted);
    assert_eq!(approval.request.sn, 1);
    assert_eq!(approval.request.gov_version, 0);
    assert_eq!(approval.request.subject_id, request_data.subject_id);

    let (.., body) = make_request(
        &client,
        &server.url(&format!("/approval?state=accepted")),
        "GET",
        None,
        None,
    )
    .await;

    let approvals: Vec<ApprovalEntry> = serde_json::from_value(body).unwrap();
    assert_eq!(approvals.len(), 1);
    assert_eq!(approvals[0].state, ApprovalState::Accepted);
    assert_eq!(approvals[0].request.sn, 1);
    assert_eq!(approvals[0].request.gov_version, 0);
    assert_eq!(approvals[0].request.subject_id, request_data.subject_id);
}

// --- Authorization Endpoints ---
#[test(tokio::test)]
async fn test_auth_endpoints_deserialization() {
    // GET /auth -> Vec<String>
    // PUT /auth/{subject_id} + Json<Vec<String>> -> String
    // GET /auth/{subject_id} -> HashSet<String>
    // DELETE /auth/{subject_id} -> String

    let Some((server, _dirs)) = TestServer::build(false, false, None).await
    else {
        return;
    };
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

    let (status, body) =
        make_request(&client, &server.url("/auth"), "GET", None, None).await;
    assert!(status.is_success());

    let subjects: Vec<String> = serde_json::from_value(body).unwrap();
    assert_eq!(
        BTreeSet::from_iter(subjects.iter()),
        BTreeSet::from([
            &"BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA".to_string(),
            &"BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGY".to_string()
        ])
    );

    let (status, body) = make_request(
        &client,
        &server.url("/auth/BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let public_key: HashSet<String> = serde_json::from_value(body).unwrap();
    assert_eq!(
        public_key,
        HashSet::from_iter([
            "EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk".to_string()
        ])
    );

    let (status, _body) = make_request(
        &client,
        &server.url("/auth/BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGA"),
        "DELETE",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let (status, body) =
        make_request(&client, &server.url("/auth"), "GET", None, None).await;
    assert!(status.is_success());

    let subjects: Vec<String> = serde_json::from_value(body).unwrap();
    assert_eq!(
        subjects,
        vec!["BvqeI4ZCxMZQWOSTVau3-PFjplI6__3EJN5qyi0XpEGY"]
    );
}

// --- Subject Update & Transfer Endpoints ---
#[test(tokio::test)]
async fn test_update_and_transfer_deserialization() {
    // POST /update/{subject_id} -> String
    // POST /manual-distribution/{subject_id} -> String
    // GET /pending-transfers -> Vec<TransferSubject>

    let Some((server, _dirs)) = TestServer::build(false, true, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    let (status, _body) = make_request(
        &client,
        &server.url(&format!("/auth/{}", request_data.subject_id)),
        "PUT",
        None,
        Some(json!(["EMSGajRDD_4QkngbQi3nJmCo1LKKrT9MHZncZK790ekk"])),
    )
    .await;
    assert!(status.is_success());

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/update/{}", request_data.subject_id)),
        "POST",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: String = serde_json::from_value(body).unwrap();
    assert!(!res.is_empty());

    let public_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let body = add_governance_member_as_witness(
        &client,
        &server,
        None,
        &request_data.subject_id,
        &public_key,
    )
    .await;

    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let body =
        transfer_req(&client, &server, &request_data.subject_id, &public_key)
            .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let subject_id = request_data.subject_id.clone();
    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server
            .url(&format!("/manual-distribution/{}", request_data.subject_id)),
        "POST",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: String = serde_json::from_value(body).unwrap();
    assert!(!res.is_empty());

    let (status, body) =
        make_request(&client, &server.url("/public-key"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let owner: String = serde_json::from_value(body).unwrap();

    let (status, body) = make_request(
        &client,
        &server.url("/pending-transfers"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<TransferSubject> = serde_json::from_value(body).unwrap();
    assert!(!res.is_empty());
    assert_eq!(res[0].name, Some("Governance".to_string()));
    assert_eq!(res[0].actual_owner, owner);
    assert_eq!(res[0].new_owner, public_key);
    assert_eq!(res[0].subject_id, subject_id);
}

// --- Gov Sub Endpoints ---
#[test(tokio::test)]
async fn test_gov_sub_deserialization() {
    // GET /subjects/{governance_id}?active={bool}&schema={string} -> Vec<SubjsData>
    // GET /subjects?active={bool} -> Vec<GovsData>

    let Some((server, _dirs)) = TestServer::build(false, true, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let governance_id = request_data.subject_id;
    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let node1_controller = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let body =
        fact_req_schema(&client, &server, &governance_id, &node1_controller)
            .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example1",
        "Subject1_1",
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let subject_id_1_1 = request_data.subject_id;

    let body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example1",
        "Subject2_1",
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let subject_id_2_1 = request_data.subject_id;

    let body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example2",
        "Subject1_2",
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let subject_id_1_2 = request_data.subject_id;

    let body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example2",
        "Subject2_2",
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let subject_id_2_2 = request_data.subject_id;

    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let body = eol_req(&client, &server, &subject_id_2_1).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let body = eol_req(&client, &server, &subject_id_2_2).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/subjects/{governance_id}")),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<SubjsData> = serde_json::from_value(body).unwrap();
    assert_eq!(
        BTreeSet::from_iter(res.iter()),
        BTreeSet::from([
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_1_1.clone(),
                schema_id: SchemaType::Type("Example1".to_string()),
                active: true,
                name: Some("Subject1_1".to_string()),
                description: Some("A subject".to_string())
            },
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_2_1.clone(),
                schema_id: SchemaType::Type("Example1".to_string()),
                active: false,
                name: Some("Subject2_1".to_string()),
                description: Some("A subject".to_string())
            },
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_1_2.clone(),
                schema_id: SchemaType::Type("Example2".to_string()),
                active: true,
                name: Some("Subject1_2".to_string()),
                description: Some("A subject".to_string())
            },
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_2_2.clone(),
                schema_id: SchemaType::Type("Example2".to_string()),
                active: false,
                name: Some("Subject2_2".to_string()),
                description: Some("A subject".to_string())
            },
        ])
    );

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/subjects/{governance_id}?active=false")),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<SubjsData> = serde_json::from_value(body).unwrap();
    assert_eq!(
        BTreeSet::from_iter(res.iter()),
        BTreeSet::from([
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_2_1.clone(),
                schema_id: SchemaType::Type("Example1".to_string()),
                active: false,
                name: Some("Subject2_1".to_string()),
                description: Some("A subject".to_string())
            },
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_2_2.clone(),
                schema_id: SchemaType::Type("Example2".to_string()),
                active: false,
                name: Some("Subject2_2".to_string()),
                description: Some("A subject".to_string())
            },
        ])
    );

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/subjects/{governance_id}?schema_id=Example1")),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<SubjsData> = serde_json::from_value(body).unwrap();
    assert_eq!(
        BTreeSet::from_iter(res.iter()),
        BTreeSet::from([
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_2_1.clone(),
                schema_id: SchemaType::Type("Example1".to_string()),
                active: false,
                name: Some("Subject2_1".to_string()),
                description: Some("A subject".to_string())
            },
            &SubjsData {
                namespace: String::default(),
                subject_id: subject_id_1_1.clone(),
                schema_id: SchemaType::Type("Example1".to_string()),
                active: true,
                name: Some("Subject1_1".to_string()),
                description: Some("A subject".to_string())
            }
        ])
    );

    let (status, body) = make_request(
        &client,
        &server.url(&format!(
            "/subjects/{governance_id}?active=false&schema_id=Example2"
        )),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<SubjsData> = serde_json::from_value(body).unwrap();
    assert_eq!(
        BTreeSet::from_iter(res.iter()),
        BTreeSet::from([&SubjsData {
            namespace: String::default(),
            subject_id: subject_id_2_2.clone(),
            schema_id: SchemaType::Type("Example2".to_string()),
            active: false,
            name: Some("Subject2_2".to_string()),
            description: Some("A subject".to_string())
        },])
    );

    let (status, body) =
        make_request(&client, &server.url("/subjects"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let res: Vec<GovsData> = serde_json::from_value(body).unwrap();
    assert!(!res.is_empty());
    assert_eq!(res[0].active, true);
    assert_eq!(res[0].description, Some("A governance".to_string()));
    assert_eq!(res[0].name, Some("Governance".to_string()));
    assert_eq!(res[0].governance_id, governance_id.clone());

    let (status, body) = make_request(
        &client,
        &server.url("/subjects?active=false"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<GovsData> = serde_json::from_value(body).unwrap();
    assert!(res.is_empty());

    let body = eol_req(&client, &server, &governance_id).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server.url("/subjects?active=true"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<GovsData> = serde_json::from_value(body).unwrap();
    assert!(res.is_empty());

    let (status, body) = make_request(
        &client,
        &server.url("/subjects?active=false"),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: Vec<GovsData> = serde_json::from_value(body).unwrap();
    assert!(!res.is_empty());
    assert_eq!(res[0].active, false);
    assert_eq!(res[0].description, Some("A governance".to_string()));
    assert_eq!(res[0].name, Some("Governance".to_string()));
    assert_eq!(res[0].governance_id, governance_id);
}

// --- Event Endpoints ---
#[test(tokio::test)]
async fn test_subject_deserialization() {
    // GET /events/{subject_id}? -> PaginatorEvents
    // GET /events/{subject_id}/{sn} -> EventInfo
    // GET /aborts/{subject_id}
    // GET /events-first-last/{subject_id}?quantity={u64}&success={bool}&reverse={bool} -> Vec<EventInfo>
    // GET /state/{subject_id} -> SubjectDB

    let Some((server1, _dirs)) = TestServer::build(false, true, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server1, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let governance_id = request_data.subject_id;

    loop {
        let (status, body) = make_request(
            &client,
            &server1.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) =
        make_request(&client, &server1.url("/peer-id"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let peer_id_2: String = serde_json::from_value(body).unwrap();

    let Some((server2, _dirs)) = TestServer::build(
        false,
        true,
        Some((peer_id_2, server1.memory_port())),
    )
    .await
    else {
        return;
    };

    let (status, body) =
        make_request(&client, &server2.url("/public-key"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let public_key_2: String = serde_json::from_value(body).unwrap();

    let (status, body) =
        make_request(&client, &server1.url("/public-key"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let public_key_1: String = serde_json::from_value(body).unwrap();

    let (status, _body) = make_request(
        &client,
        &server2.url(&format!("/auth/{}", governance_id)),
        "PUT",
        None,
        Some(json!([public_key_1])),
    )
    .await;
    assert!(status.is_success());

    let (status, _body) = make_request(
        &client,
        &server1.url(&format!("/auth/{}", governance_id)),
        "PUT",
        None,
        Some(json!([public_key_2])),
    )
    .await;
    assert!(status.is_success());

    let body = add_governance_member_as_witness(
        &client,
        &server1,
        None,
        &governance_id,
        &public_key_2,
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server1.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server1.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert!(subject.active);
    assert_eq!(subject.subject_id, governance_id);
    assert_eq!(subject.governance_id, governance_id);
    assert_eq!(subject.sn, 1);
    assert_eq!(subject.schema_id, "governance");
    assert_eq!(subject.name, Some("Governance".to_string()));
    assert_eq!(subject.description, Some("A governance".to_string()));
    assert_eq!(subject.namespace, "");
    assert_eq!(subject.genesis_gov_version, 0);
    assert_eq!(subject.owner, public_key_1);
    assert_eq!(subject.creator, public_key_1);
    assert!(subject.new_owner.is_none());
    assert!(subject.properties.is_object());
    assert!(subject.properties["members"].is_object());
    assert_eq!(subject.properties["members"]["Owner"], public_key_1);
    assert_eq!(subject.properties["members"]["Node1"], public_key_2);

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert!(subject.active);
    assert_eq!(subject.subject_id, governance_id);
    assert_eq!(subject.governance_id, governance_id);
    assert_eq!(subject.sn, 1);
    assert_eq!(subject.schema_id, "governance");
    assert_eq!(subject.name, Some("Governance".to_string()));
    assert_eq!(subject.description, Some("A governance".to_string()));
    assert_eq!(subject.namespace, "");
    assert_eq!(subject.genesis_gov_version, 0);
    assert_eq!(subject.owner, public_key_1);
    assert_eq!(subject.creator, public_key_1);
    assert!(subject.new_owner.is_none());
    assert!(subject.properties.is_object());
    assert!(subject.properties["members"].is_object());
    assert_eq!(subject.properties["members"]["Owner"], public_key_1);
    assert_eq!(subject.properties["members"]["Node1"], public_key_2);

    let body =
        transfer_req(&client, &server1, &governance_id, &public_key_2).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server1.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert_eq!(subject.sn, 2);

    let body = reject_req(&client, &server2, &governance_id).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server2.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server1.url(&format!("/update/{}", governance_id)),
        "POST",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let res: String = serde_json::from_value(body).unwrap();
    assert!(!res.is_empty());

    let (status, body) = make_request(
        &client,
        &server1.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert_eq!(subject.sn, 3);

    let body =
        transfer_req(&client, &server1, &governance_id, &public_key_2).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server1.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert_eq!(subject.sn, 4);

    let body = confirm_req(&client, &server2, &governance_id).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server2.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert_eq!(subject.sn, 5);

    let body = eol_req(&client, &server2, &governance_id).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();

    loop {
        let (status, body) = make_request(
            &client,
            &server2.url(&format!("/request/{}", request_data.request_id)),
            "GET",
            None,
            None,
        )
        .await;

        assert!(status.is_success());
        if body["state"] == format!("{}", RequestState::Finish) {
            break;
        } else {
            tokio::time::sleep(Duration::from_secs(1)).await
        }
    }

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/state/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let subject: SubjectDB = serde_json::from_value(body).unwrap();
    assert_eq!(subject.sn, 6);
    assert_eq!(subject.active, false);

    // events/{subject_id}?quantity={u64}&page={u64}&reverse={bool} -> PaginatorEvents
    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/events/{}?quantity=1&page=3", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let paginator: PaginatorEvents = serde_json::from_value(body).unwrap();
    assert_eq!(paginator.paginator.next, Some(4));
    assert_eq!(paginator.paginator.prev, Some(2));
    assert_eq!(paginator.paginator.pages, 7);

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/events/{}", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let paginator: PaginatorEvents = serde_json::from_value(body).unwrap();
    assert_eq!(paginator.paginator.next, None);
    assert_eq!(paginator.paginator.prev, None);
    assert_eq!(paginator.paginator.pages, 1);

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/events/{}?reverse=true", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());

    let paginator_reverse: PaginatorEvents =
        serde_json::from_value(body).unwrap();
    assert_eq!(paginator_reverse.paginator.next, None);
    assert_eq!(paginator_reverse.paginator.prev, None);
    assert_eq!(paginator_reverse.paginator.pages, 1);

    assert_eq!(paginator_reverse.events.len(), 7);
    assert_eq!(paginator_reverse.events[0].subject_id, governance_id);
    assert_eq!(paginator_reverse.events[0].sn, 6);
    assert_eq!(paginator_reverse.events[0].event_type.to_string(), "eol");

    assert_eq!(paginator_reverse.events[1].subject_id, governance_id);
    assert_eq!(paginator_reverse.events[1].sn, 5);
    assert_eq!(
        paginator_reverse.events[1].event_type.to_string(),
        "confirm"
    );

    assert_eq!(paginator_reverse.events[2].subject_id, governance_id);
    assert_eq!(paginator_reverse.events[2].sn, 4);
    assert_eq!(
        paginator_reverse.events[2].event_type.to_string(),
        "transfer"
    );
    assert_eq!(paginator_reverse.events[3].event_type.to_string(), "reject");
    assert_eq!(paginator_reverse.events[4].subject_id, governance_id);
    assert_eq!(paginator_reverse.events[4].sn, 2);
    assert_eq!(
        paginator_reverse.events[4].event_type.to_string(),
        "transfer"
    );

    assert_eq!(paginator_reverse.events[5].subject_id, governance_id);
    assert_eq!(paginator_reverse.events[5].sn, 1);
    assert_eq!(paginator_reverse.events[5].event_type.to_string(), "fact");

    assert_eq!(paginator_reverse.events[6].subject_id, governance_id);
    assert_eq!(paginator_reverse.events[6].sn, 0);
    assert_eq!(paginator_reverse.events[6].event_type.to_string(), "create");

    // GET /event/{subject_id}?sn={u64} -> EventInfo
    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/events/{}/2", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let event: LedgerDB = serde_json::from_value(body).unwrap();

    assert_eq!(event.subject_id, governance_id);
    assert_eq!(event.sn, 2);
    assert_eq!(event.event_type.to_string(), "transfer");

    // GET /events-first-last/{subject_id}?quantity={u64}&success={bool}&reverse={bool} -> Vec<EventInfo>
    let (status, body) = make_request(
        &client,
        &server2.url(&format!(
            "/events-first-last/{}?quantity=2&reverse=true",
            governance_id
        )),
        "GET",
        None,
        None,
    )
    .await;

    assert!(status.is_success());
    let events: Vec<LedgerDB> = serde_json::from_value(body).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].subject_id, governance_id);
    assert_eq!(events[0].sn, 6);
    assert_eq!(events[0].event_type.to_string(), "eol");

    assert_eq!(events[1].subject_id, governance_id);
    assert_eq!(events[1].sn, 5);
    assert_eq!(events[1].event_type.to_string(), "confirm");

    let (status, body) = make_request(
        &client,
        &server2
            .url(&format!("/events-first-last/{}?quantity=2", governance_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success());
    let events: Vec<LedgerDB> = serde_json::from_value(body).unwrap();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].subject_id, governance_id);
    assert_eq!(events[0].sn, 0);
    assert_eq!(events[0].event_type.to_string(), "create");

    assert_eq!(events[1].subject_id, governance_id);
    assert_eq!(events[1].sn, 1);
    assert_eq!(events[1].event_type.to_string(), "fact");

    // Test date filters deserialization with a future date that returns no events
    let future_date = "2099-01-01T00:00:00Z";

    // event_request_ts[from] with future date -> no events
    let (status, ..) = make_request(
        &client,
        &server2.url(&format!(
            "/events/{}?event_request_ts[from]={}",
            governance_id, future_date
        )),
        "GET",
        None,
        None,
    )
    .await;
    assert!(!status.is_success());

    // event_ledger_ts[from] with future date -> no events
    let (status, ..) = make_request(
        &client,
        &server2.url(&format!(
            "/events/{}?event_ledger_ts[from]={}",
            governance_id, future_date
        )),
        "GET",
        None,
        None,
    )
    .await;

    assert!(!status.is_success());

    // sink_ts[from] with future date -> no events
    let (status, ..) = make_request(
        &client,
        &server2.url(&format!(
            "/events/{}?sink_ts[from]={}",
            governance_id, future_date
        )),
        "GET",
        None,
        None,
    )
    .await;
    assert!(!status.is_success());
}

#[test(tokio::test)]
async fn test_sink_events_deserialization_includes_failed_governance_events() {
    let Some((server1, _dirs1)) = TestServer::build(false, true, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server1, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let governance_id = request_data.subject_id.clone();
    wait_request_finish(&client, &server1, None, &request_data.request_id)
        .await;

    let (status, body) =
        make_request(&client, &server1.url("/peer-id"), "GET", None, None)
            .await;
    assert!(status.is_success(), "{body}");
    let bootstrap_peer_id: String = serde_json::from_value(body).unwrap();

    let Some((server2, _dirs2)) = TestServer::build(
        false,
        true,
        Some((bootstrap_peer_id, server1.memory_port())),
    )
    .await
    else {
        return;
    };

    let (status, body) =
        make_request(&client, &server2.url("/public-key"), "GET", None, None)
            .await;
    assert!(status.is_success(), "{body}");
    let public_key_2: String = serde_json::from_value(body).unwrap();

    let (status, body) =
        make_request(&client, &server1.url("/public-key"), "GET", None, None)
            .await;
    assert!(status.is_success(), "{body}");
    let public_key_1: String = serde_json::from_value(body).unwrap();

    let (status, body) = make_request(
        &client,
        &server2.url(&format!("/auth/{}", governance_id)),
        "PUT",
        None,
        Some(json!([public_key_1])),
    )
    .await;
    assert!(status.is_success(), "{body}");

    let (status, body) = make_request(
        &client,
        &server1.url(&format!("/auth/{}", governance_id)),
        "PUT",
        None,
        Some(json!([public_key_2.clone()])),
    )
    .await;
    assert!(status.is_success(), "{body}");

    let body = add_governance_member_as_witness(
        &client,
        &server1,
        None,
        &governance_id,
        &public_key_2,
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server1, None, &request_data.request_id)
        .await;

    let body = add_governance_member_as_witness(
        &client,
        &server1,
        None,
        &governance_id,
        &public_key_2,
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server1, None, &request_data.request_id)
        .await;

    let body =
        transfer_req(&client, &server1, &governance_id, &public_key_1).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server1, None, &request_data.request_id)
        .await;

    let body =
        transfer_req(&client, &server1, &governance_id, &public_key_2).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server1, None, &request_data.request_id)
        .await;

    let mut transfer_visible_in_server2 = false;
    for _ in 0..60 {
        let (status, body) = make_request(
            &client,
            &server2.url(&format!("/state/{}", governance_id)),
            "GET",
            None,
            None,
        )
        .await;
        assert!(status.is_success(), "{body}");
        if body["new_owner"] == json!(public_key_2) {
            transfer_visible_in_server2 = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(transfer_visible_in_server2);

    let (status, body) = make_request(
        &client,
        &server2.url("/request"),
        "POST",
        None,
        Some(json!({
            "request": {
                "event": "confirm",
                "data": {
                    "subject_id": governance_id,
                    "name_old_owner": "Owner"
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "{body}");
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server2, None, &request_data.request_id)
        .await;

    let mut sink_page = None;
    for _ in 0..60 {
        let (status, body) = make_request(
            &client,
            &server2.url(&format!("/sink-events/{}", governance_id)),
            "GET",
            None,
            None,
        )
        .await;
        assert!(status.is_success(), "{body}");
        let page: SinkEventsPage = serde_json::from_value(body).unwrap();

        let has_failed_fact = page.events.iter().any(|event| {
            matches!(
                &event.payload,
                DataToSinkEvent::FactFull {
                    success: false,
                    payload: None,
                    patch: None,
                    error: Some(_),
                    ..
                }
            )
        });
        let has_failed_transfer = page.events.iter().any(|event| {
            matches!(
                &event.payload,
                DataToSinkEvent::Transfer {
                    success: false,
                    error: Some(_),
                    ..
                }
            )
        });
        let has_failed_confirm = page.events.iter().any(|event| {
            matches!(
                &event.payload,
                DataToSinkEvent::Confirm {
                    success: false,
                    patch: None,
                    error: Some(_),
                    ..
                }
            )
        });

        if has_failed_fact && has_failed_transfer && has_failed_confirm {
            sink_page = Some(page);
            break;
        }

        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let sink_page = sink_page.expect("sink page did not include failed governance events");

    assert!(sink_page.events.len() >= 5);
}

#[test(tokio::test)]
async fn test_sink_events_deserialization_includes_failed_tracker_fact() {
    let Some((server, _dirs)) = TestServer::build(false, true, None).await
    else {
        return;
    };
    let client = Client::new();

    let body = create_governance(&client, &server, None).await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let governance_id = request_data.subject_id.clone();
    wait_request_finish(&client, &server, None, &request_data.request_id)
        .await;

    let tracker_member_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    let body = add_example_schema_to_governance(
        &client,
        &server,
        None,
        &governance_id,
        &tracker_member_key,
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server, None, &request_data.request_id)
        .await;

    let body = create_subject(
        &client,
        &server,
        None,
        &governance_id,
        "Example1",
        "Tracker Subject",
    )
    .await;
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    let tracker_id = request_data.subject_id.clone();
    wait_request_finish(&client, &server, None, &request_data.request_id)
        .await;

    let (status, body) = make_request(
        &client,
        &server.url("/request"),
        "POST",
        None,
        Some(json!({
            "request": {
                "event": "fact",
                "data": {
                    "subject_id": tracker_id,
                    "viewpoints": [],
                    "payload": {
                        "InvalidPayload": {
                            "data": 1
                        }
                    }
                }
            }
        })),
    )
    .await;
    assert!(status.is_success(), "{body}");
    let request_data: RequestData = serde_json::from_value(body).unwrap();
    wait_request_finish(&client, &server, None, &request_data.request_id)
        .await;

    let (status, body) = make_request(
        &client,
        &server.url(&format!("/sink-events/{}", tracker_id)),
        "GET",
        None,
        None,
    )
    .await;
    assert!(status.is_success(), "{body}");
    let sink_page: SinkEventsPage = serde_json::from_value(body).unwrap();

    assert!(sink_page.events.iter().any(|event| {
        matches!(
            &event.payload,
            DataToSinkEvent::FactFull {
                success: false,
                payload: None,
                patch: None,
                error: Some(_),
                ..
            }
        )
    }));
}

// --- System Info Endpoints ---
#[test(tokio::test)]
async fn test_system_info_deserialization() {
    // GET /public-key -> String
    // GET /peer-id -> String
    // GET /config -> ConfigHttp
    // GET /keys -> Binary (application/pkcs8)

    let Some((server, dirs)) = TestServer::build(false, false, None).await
    else {
        return;
    };
    let client = Client::new();

    let (status, body) =
        make_request(&client, &server.url("/public-key"), "GET", None, None)
            .await;
    assert!(status.is_success());
    let public_key: String = serde_json::from_value(body).unwrap();

    // PEER-ID
    let (status, body) =
        make_request(&client, &server.url("/peer-id"), "GET", None, None).await;
    assert!(status.is_success());
    let peer_id: String = serde_json::from_value(body).unwrap();

    assert!(!peer_id.is_empty(), "Peer ID should not be empty");
    assert!(!public_key.is_empty(), "Controller ID should not be empty");

    // Verify they are different (peer-id and controller-id should be different)
    assert_ne!(
        peer_id.to_string(),
        public_key.to_string(),
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
    #[cfg(feature = "sqlite")]
    {
        assert_eq!(config.node.internal_db.db, "Sqlite");
    }
    #[cfg(feature = "rocksdb")]
    {
        assert_eq!(config.node.internal_db.db, "Rocksdb");
    }
    assert_eq!(config.node.external_db.db, "Sqlite");
    assert_eq!(config.node.hash_algorithm, "Blake3");

    assert_eq!(config.node.tracking_size, 200);
    assert!(config.node.is_service);
    assert_eq!(config.node.sync.ledger_batch_size, 100);
    assert_eq!(config.node.sync.governance.interval_secs, 60);
    assert_eq!(config.node.sync.governance.sample_size, 3);
    assert_eq!(config.node.sync.governance.response_timeout_secs, 10);
    assert_eq!(config.node.sync.tracker.interval_secs, 30);
    assert_eq!(config.node.sync.tracker.page_size, 50);
    assert_eq!(config.node.sync.tracker.response_timeout_secs, 10);
    assert_eq!(config.node.sync.tracker.update_batch_size, 2);
    assert_eq!(config.node.sync.tracker.update_timeout_secs, 10);
    assert_eq!(config.node.sync.update.round_retry_interval_secs, 8);
    assert_eq!(config.node.sync.update.max_round_retries, 3);
    assert_eq!(config.node.sync.update.witness_retry_count, 1);
    assert_eq!(config.node.sync.update.witness_retry_interval_secs, 5);
    assert_eq!(config.node.sync.reboot.stability_check_interval_secs, 5);
    assert_eq!(config.node.sync.reboot.stability_check_max_retries, 3);
    assert_eq!(
        config.node.sync.reboot.diff_retry_schedule_secs,
        vec![10, 20, 30, 60]
    );
    assert_eq!(
        config.node.sync.reboot.timeout_retry_schedule_secs,
        vec![5, 5, 5, 5]
    );

    assert_eq!(config.node.contracts_path, expected_contracts_path);
    assert!(!config.node.always_accept);

    assert_eq!(config.node.network.node_type, "Bootstrap");
    assert_eq!(
        config.node.network.listen_addresses,
        vec![expected_listen_address]
    );
    assert!(config.node.network.external_addresses.is_empty());
    assert!(config.node.network.boot_nodes.is_empty());
    assert!(config.node.network.routing.dht_random_walk);
    assert_eq!(config.node.network.routing.discovery_only_if_under_num, 25);
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
    assert_eq!(config.auth.rate_limit.max_requests, 10000);
    assert!(config.auth.rate_limit.limit_by_key);
    assert!(config.auth.rate_limit.limit_by_ip);
    assert_eq!(config.auth.rate_limit.cleanup_interval_seconds, 1800);
    assert!(config.auth.session.audit_enable);
    assert_eq!(config.auth.session.audit_retention_days, 30);

    assert_eq!(config.http.http_address, "0.0.0.0:3000");
    assert!(config.http.https_address.is_none());
    assert!(config.http.https_cert_path.is_none());
    assert!(config.http.https_private_key_path.is_none());
    assert!(!config.http.enable_doc);

    // Self-signed cert defaults
    assert!(!config.http.self_signed_cert.enabled);
    assert_eq!(config.http.self_signed_cert.common_name, "localhost");
    assert_eq!(
        config.http.self_signed_cert.san,
        vec!["127.0.0.1".to_string(), "::1".to_string()]
    );
    assert_eq!(config.http.self_signed_cert.validity_days, 365);
    assert_eq!(config.http.self_signed_cert.renew_before_days, 30);
    assert_eq!(config.http.self_signed_cert.check_interval_secs, 3600);

    // CORS defaults (not set in test config → defaults)
    assert!(config.http.cors.enabled);
    assert!(config.http.cors.allow_any_origin);
    assert!(config.http.cors.allowed_origins.is_empty());
    assert!(!config.http.cors.allow_credentials);

    // Proxy defaults (not set in test config → defaults)
    assert!(config.http.proxy.trusted_proxies.is_empty());
    assert!(config.http.proxy.trust_x_forwarded_for);
    assert!(config.http.proxy.trust_x_real_ip);

    // DB durability defaults
    assert!(!config.node.internal_db.durability);
    assert!(!config.node.external_db.durability);

    // Node spec: not set → None
    assert!(config.node.spec.is_none());

    // Network buffer/message limits defaults
    assert_eq!(config.node.network.memory_limits, "disabled");
    assert_eq!(config.node.network.max_app_message_bytes, 1_048_576);
    assert_eq!(
        config.node.network.max_pending_inbound_bytes_per_peer,
        8_388_608
    );
    assert_eq!(
        config.node.network.max_pending_outbound_bytes_per_peer,
        8_388_608
    );
    assert_eq!(config.node.network.max_pending_inbound_bytes_total, 0);
    assert_eq!(config.node.network.max_pending_outbound_bytes_total, 0);

    // Control list timeout/concurrency defaults
    assert_eq!(config.node.network.control_list.request_timeout_secs, 5);
    assert_eq!(config.node.network.control_list.max_concurrent_requests, 8);

    // Auth durability default
    assert!(!config.auth.durability);

    // API key prefix default (not set in test config → default "ave_node_")
    assert_eq!(config.auth.api_key.prefix, "ave_node_");

    // Rate limit sensitive endpoints: explicitly set to empty in test config
    assert!(config.auth.rate_limit.sensitive_endpoints.is_empty());

    // Session audit max entries: explicitly set in test config
    assert_eq!(config.auth.session.audit_max_entries, 1_000_000);
}

#[test]
fn test_sink_server_http_fields() {
    use ave_http::config_types::SinkServerHttp;

    // Verify SinkServerHttp has all expected fields by deserializing from JSON
    let json = serde_json::json!({
        "server": "TestSink",
        "events": ["Create", "Transfer"],
        "url": "https://test.sink",
        "auth": true,
        "concurrency": 4,
        "queue_capacity": 2048,
        "queue_policy": "drop_oldest",
        "routing_strategy": "unordered_round_robin",
        "connect_timeout_ms": 5000,
        "request_timeout_ms": 30000,
        "max_retries": 5
    });

    let http: SinkServerHttp = serde_json::from_value(json).unwrap();

    assert_eq!(http.server, "TestSink");
    assert_eq!(http.url, "https://test.sink");
    assert!(http.auth);
    assert_eq!(http.concurrency, 4);
    assert_eq!(http.queue_capacity, 2048);
    assert_eq!(http.queue_policy, "drop_oldest");
    assert_eq!(http.routing_strategy, "unordered_round_robin");
    assert_eq!(http.connect_timeout_ms, 5000);
    assert_eq!(http.request_timeout_ms, 30000);
    assert_eq!(http.max_retries, 5);

    // Verify alternate enum values
    let json2 = serde_json::json!({
        "server": "S2",
        "events": [],
        "url": "https://s2",
        "auth": false,
        "concurrency": 1,
        "queue_capacity": 1024,
        "queue_policy": "drop_newest",
        "routing_strategy": "ordered_by_subject",
        "connect_timeout_ms": 2000,
        "request_timeout_ms": 10000,
        "max_retries": 3
    });

    let http2: SinkServerHttp = serde_json::from_value(json2).unwrap();
    assert_eq!(http2.queue_policy, "drop_newest");
    assert_eq!(http2.routing_strategy, "ordered_by_subject");
}

#[test]
fn bridge_info_tests_cover_declared_main_http_routes() {
    let rt = tokio::runtime::Runtime::new().expect("runtime");
    rt.block_on(async {
        let Some((server, _dirs)) =
            TestServer::build(false, false, None).await
        else {
            panic!("test server build failed");
        };
        let client = Client::new();

        for (method, path) in server_main_route_catalog() {
            let materialized = materialize_role_test_path(&method, &path);
            assert!(
                !materialized.contains('{'),
                "bridge_info route still has unresolved placeholders: {method} {path} -> {materialized}"
            );
            let http_method = method.to_ascii_uppercase();

            let (status, body) = make_request(
                &client,
                &server.url(&materialized),
                &http_method,
                None,
                role_test_request_body(&method, &path),
            )
            .await;

            assert_ne!(
                status,
                reqwest::StatusCode::METHOD_NOT_ALLOWED,
                "main route not mounted for {method} {path}: {body}"
            );
            assert!(
                status != reqwest::StatusCode::INTERNAL_SERVER_ERROR
                    && status != reqwest::StatusCode::BAD_GATEWAY,
                "main route crashed for {method} {path}: {body}"
            );
        }
    });
}
