use std::{str::FromStr, sync::atomic::Ordering};

mod common;

use ave_common::{
    bridge::request::ApprovalStateRes,
    identity::{
        PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
    response::RequestState,
};
use ave_core::auth::AuthWitness;

use common::{
    create_and_authorize_governance, create_nodes_and_connections,
    create_subject, emit_approve, emit_confirm, emit_fact, emit_transfer,
    get_subject,
};
use futures::future::join_all;
use network::{NodeType, RoutingNode};
use serde_json::json;
use test_log::test;

use crate::common::{
    PORT_COUNTER, create_node, get_abort_request, node_running,
    wait_request_state,
};

#[test(tokio::test)]
//  Verificar que update protocol actualiza pasivamente la gobernanza.
async fn test_update_protocol() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        true,
        true,
    )
    .await;
    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        }
    });

    let _request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    node2
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node2.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(1))
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "Fake",
                "key": fake_node
            }
        ]
    }});

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(2))
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "Fake2",
                "key": fake_node
            }
        ]
    }});

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(3))
        .await
        .unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(3))
        .await
        .unwrap();
}

#[test(tokio::test)]
//  El owner perdió el ledger, se lo pidió a un testigo que no tenía la última versión
// la siguiente request se aborta.
async fn test_approve_invalid_gov_version() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        false,
        false,
    )
    .await;
    let node1 = nodes[0].api.clone();
    let node2 = nodes[1].api.clone();
    let node3 = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&node2, vec![&node1, &node3]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": node1.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": node3.public_key()
                }
            ]
        },
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["AveNode3"]
                }
            }
        }
    });

    let request_id = emit_fact(&node2, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    node1
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&node2.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node1.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(1))
        .await
        .unwrap();

    node3
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&node2.public_key()).unwrap()),
        )
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(1))
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode4",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&node2, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        &node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node3,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    let _state = get_subject(&node2, governance_id.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&node1, governance_id.clone(), Some(1))
        .await
        .unwrap();

    node3.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&node3, governance_id.clone(), Some(2))
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: node1.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_node2, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
        Some(nodes[1].keys.clone()),
    )
    .await;
    let new_node2 = node_new_node2.api.clone();
    node_running(&new_node2).await.unwrap();

    assert!(
        new_node2
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_node2
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&node1.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_node2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(1))
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode5",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&new_node2, governance_id.clone(), json, false)
        .await
        .unwrap();

    wait_request_state(
        &new_node2,
        request_id.clone(),
        Some(RequestState::Abort {
            subject_id: String::default(),
            who: String::default(),
            sn: None,
            error: String::default(),
        }),
    )
    .await
    .unwrap();

    let aborts =
        get_abort_request(&new_node2, governance_id.clone(), request_id)
            .await
            .unwrap();

    assert_eq!(aborts.events.len(), 1);
    assert_eq!(
        aborts.events[0].error,
        "Abort approval, governance update is required by signer: local=2, request=1"
    );


        new_node2
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&node3.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_node2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_node2, governance_id.clone(), Some(2))
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode5",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&new_node2, governance_id.clone(), json, false)
        .await
        .unwrap();

    emit_approve(
        &new_node2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        &node3,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        false,
    )
    .await
    .unwrap();

    
    let _state = get_subject(&new_node2, governance_id.clone(), Some(3))
        .await
        .unwrap();
}

#[test(tokio::test)]
// El el init state es invalido, se aborata la request
async fn test_invalid_init_state() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;
    let node = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==",
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                    }
                }
            ]
        },
    });

    emit_fact(node, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node, governance_id.clone(), None)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner":node.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"schemas":{},"version":0})
    );
}

#[test(tokio::test)]
// El contrato es invalido, se aborata la request
async fn test_invalid_contract() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;
    let node = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node, vec![]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXp",
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
    });

    emit_fact(node, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node, governance_id.clone(), None)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 0);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner":node.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"schemas":{},"version":0})
    );
}

#[test(tokio::test)]
//  Verificar que se puede crear una gobernanza, sujeto y emitir un evento además de recibir la copia
async fn test_governance_and_subject_copy_with_approve() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        false,
        false,
    )
    .await;
    let node1 = &nodes[0].api;
    let node2 = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(node1, vec![node2]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": node2.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
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
            "governance": {
                "add": {
                    "witness": [
                        "AveNode2"
                    ]
                }
            },
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
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
                                    "name": "AveNode2",
                                    "namespace": [],
                                    "quantity": 2
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "AveNode2",
                                    "namespace": []
                                }
                            ]
                        }

                }
            ]
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let (subject_id, ..) =
        create_subject(node2, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node2, subject_id.clone(), json, true)
        .await
        .unwrap();

    for i in 0..9 {
        let json = json!({
            "ModTwo": {
                "data": i + 1,
            }
        });

        emit_fact(node2, subject_id.clone(), json, false)
            .await
            .unwrap();
    }

    let json = json!({
        "ModTwo": {
            "data": 9 + 1,
        }
    });

    emit_fact(node2, subject_id.clone(), json, true)
        .await
        .unwrap();

    let events = node2
        .get_first_or_end_events(
            subject_id.clone(),
            Some(11),
            Some(false),
            None,
        )
        .await
        .unwrap();

    assert_eq!(events.len(), 11);

    let state = get_subject(node1, subject_id.clone(), None).await.unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node2.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node2.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 11);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 10
        })
    );

    let state = get_subject(node2, subject_id.clone(), None).await.unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node2.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node2.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 11);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 10
        })
    );
}

#[test(tokio::test)]
// Caso de uso básico 1 bootstrap (intermediario), 1 ephemeral(issuer de subject),
// 1 addressable(owner de la gobernanza)
async fn test_basic_use_case_1b_1e_1a() {
    //  Ephemeral -> Bootstrap ≤- Addressable
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![vec![0]],
        true,
        false,
    )
    .await;
    let bootstrap = &nodes[0].api;
    let addressable = &nodes[1].api;
    let ephimeral = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        addressable,
        vec![bootstrap, ephimeral],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": bootstrap.public_key()
                },
                {
                    "name": "AveNode3",
                    "key": ephimeral.public_key()
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode2", "AveNode3"],
                }
            }
        }
    });

    emit_fact(addressable, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(addressable, governance_id.clone(), None)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode2":bootstrap.public_key(),"AveNode3":ephimeral.public_key(),"Owner":addressable.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode2", "AveNode3"]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":1})
    );

    let state = get_subject(bootstrap, governance_id.clone(), Some(1))
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode2":bootstrap.public_key(),"AveNode3":ephimeral.public_key(),"Owner":addressable.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode2", "AveNode3"]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":1})
    );

    ephimeral
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let state = get_subject(ephimeral, governance_id.clone(), Some(1))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, addressable.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, addressable.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode2":bootstrap.public_key(),"AveNode3":ephimeral.public_key(),"Owner":addressable.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode2", "AveNode3"]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":1})
    );
}

#[test(tokio::test)]
async fn test_many_schema_in_one_governance() {
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;
    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let json = json!({
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
                },
                {
                    "id": "Example3",
                    "contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==",
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                }
            ]
        },
    });
    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner_governance, governance_id.clone(), None)
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner": owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{"Example1":{"evaluate":"majority","validate":"majority"},"Example2":{"evaluate":"majority","validate":"majority"},"Example3":{"evaluate":"majority","validate":"majority"}},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{"Example1":{"creator":[],"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"Example2":{"creator":[],"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"Example3":{"creator":[],"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]}},"schemas":{"Example1":{"contract":"dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==","initial_value":{"one":0,"three":0,"two":0}},"Example2":{"contract":"dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==","initial_value":{"one":0,"three":0,"two":0}},"Example3":{"contract":"dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==","initial_value":{"one":0,"three":0,"two":0}}},"version":1})
    );
}

#[test(tokio::test)]
// Testear la transferencia de gobernanza
async fn test_transfer_event_governance_1() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let future_owner = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![future_owner])
            .await;
    // add member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                    }
                }
            }
    });
    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        owner_governance,
        governance_id.clone(),
        PublicKey::from_str(&future_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    // Confirm transfer event
    emit_confirm(future_owner, governance_id.clone(), None, true)
        .await
        .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode2",
                "key": fake_node
            }
        ]
    }});

    emit_fact(future_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(future_owner, governance_id.clone(), None)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 4);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode2":fake_node, "Owner":future_owner.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":4})
    );

    let state = get_subject(owner_governance, governance_id.clone(), None)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, Some(future_owner.public_key().to_string()));
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":future_owner.public_key(),"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode1"]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":2})
    );
}

#[test(tokio::test)]
// Testear la transferencia de gobernanza, pero el owner se queda como miembro
async fn test_transfer_event_governance_2() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let future_owner = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![future_owner])
            .await;

    // Auth governance in old owner, in future he will be a normal member and need auth governance for receive a ledger copy.
    owner_governance
        .auth_subject(governance_id.clone(), AuthWitness::None)
        .await
        .unwrap();
    // add member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": future_owner.public_key()
                }
            ]
        },
            "roles": {
                "governance": {
                    "add": {
                        "witness": ["AveNode1"],
                    }
                }
            }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        owner_governance,
        governance_id.clone(),
        PublicKey::from_str(&future_owner.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let transfer_data = owner_governance.get_pending_transfers().await.unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    let transfer_data = future_owner.get_pending_transfers().await.unwrap();
    assert_eq!(
        transfer_data[0].actual_owner.to_string(),
        owner_governance.public_key()
    );
    assert_eq!(
        transfer_data[0].new_owner.to_string(),
        future_owner.public_key()
    );
    assert_eq!(transfer_data[0].subject_id, governance_id);

    // Confirm transfer event
    emit_confirm(
        future_owner,
        governance_id.clone(),
        Some("AveNode_Old".to_owned()),
        true,
    )
    .await
    .unwrap();

    let transfer_data = owner_governance.get_pending_transfers().await.unwrap();
    assert!(transfer_data.is_empty());

    let transfer_data = future_owner.get_pending_transfers().await.unwrap();
    assert!(transfer_data.is_empty());

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    // add new fake member to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode2",
                    "key": fake_node
                }
            ]
        }
    });

    emit_fact(future_owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(future_owner, governance_id.clone(), None)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 4);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode2":fake_node,"AveNode_Old":owner_governance.public_key(),"Owner":future_owner.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode_Old"]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":4})
    );

    let state = get_subject(owner_governance, governance_id.clone(), None)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, future_owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 4);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode2":fake_node,"AveNode_Old":owner_governance.public_key(),"Owner":future_owner.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode_Old"]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":4})
    );
}

#[test(tokio::test)]
async fn test_governance_fail_approve() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![],
        vec![],
        false,
        false,
    )
    .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["AveNode1"],
                }
            }
        }
    });

    let request_id = emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        node1,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id,
        true,
    )
    .await
    .unwrap();

    let state = get_subject(node1, governance_id.clone(), None)
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner":node1.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_schema":{},"schemas":{},"version":0})
    );
}

#[test(tokio::test)]
// Varios approvers y todos dicen que sí, se cumple el quorum.
async fn test_governance_manual_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        false,
        false,
    )
    .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"AveNode1":fake_node,"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1", "Approver2"]},"roles_schema":{},"schemas":{},"version":2})
    );
    let state = get_subject(approver_1, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"AveNode1":fake_node,"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1", "Approver2"]},"roles_schema":{},"schemas":{},"version":2})
    );
    let state = get_subject(approver_2, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"AveNode1":fake_node,"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1", "Approver2"]},"roles_schema":{},"schemas":{},"version":2})
    );
}

#[test(tokio::test)]
// Varios approvers y todos dicen que sí, se cumple el quorum. de forma automática.
async fn test_governance_auto_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["Approver1", "Approver2"],
                    "approver": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"AveNode1":fake_node,"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1","Approver2"]},"roles_schema":{},"schemas":{},"version":2})
    );
    let state = get_subject(approver_1, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"AveNode1":fake_node,"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1","Approver2"]},"roles_schema":{},"schemas":{},"version":2})
    );
    let state = get_subject(approver_2, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"AveNode1":fake_node,"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1","Approver2"]},"roles_schema":{},"schemas":{},"version":2})
    );
}

#[test(tokio::test)]
// Varios approvers pero uno dice que no y el quorum no se cumple.
async fn test_governance_not_quorum_many_approvers() {
    // Bootstrap ≤- Addressable
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        false,
        false,
    )
    .await;
    let owner = &nodes[0].api;
    let approver_1 = &nodes[1].api;
    let approver_2 = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![approver_1, approver_2])
            .await;

    let json = json!({
        "policies": {
            "governance": {
                "change": {
                    "approve": {
                        "fixed": 100
                    }
                }
            }
        },
        "roles": {
            "governance": {
                "add": {
                    "approver": ["Approver1", "Approver2"],
                    "witness": ["Approver1", "Approver2"]
                }
            }
        },
        "members": {
            "add": [
                {
                    "name": "Approver1",
                    "key": approver_1.public_key()
                },
                {
                    "name": "Approver2",
                    "key": approver_2.public_key()
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id,
        true,
    )
    .await
    .unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode1",
                    "key": fake_node
                }
            ]
        }
    });

    let request_id = emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    emit_approve(
        owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    emit_approve(
        approver_1,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    emit_approve(
        approver_2,
        governance_id.clone(),
        ApprovalStateRes::Rejected,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let state = get_subject(owner, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1","Approver2"]},"roles_schema":{},"schemas":{},"version":1})
    );
    let state = get_subject(approver_1, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1","Approver2"]},"roles_schema":{},"schemas":{},"version":1})
    );
    let state = get_subject(approver_2, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Approver1":approver_1.public_key(),"Approver2":approver_2.public_key(),"Owner":owner.public_key()},"policies_gov":{"approve":{"fixed":100},"evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Approver1","Approver2","Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["Approver1","Approver2"]},"roles_schema":{},"schemas":{},"version":1})
    );
}

#[test(tokio::test)]
// Se añade un evaluador, se evalua, se le elimina y se vuelve a evaluar.
async fn test_change_roles_gov() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let eval_node = &nodes[0].api;
    let owner_governance = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![eval_node])
            .await;
    // add member to governance
    let json: serde_json::Value = json!({
    "roles": {
        "governance": {
            "add": {
                "witness": ["AveNode1"],
                "evaluator": ["AveNode1"],
                "validator": ["AveNode1"]
            }
        }
    },
    "members": {
        "add": [
            {
                "name": "AveNode1",
                "key": eval_node.public_key()
            }
        ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let fake_node_1 = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode2",
                "key": fake_node_1
            }
        ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner_governance, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":eval_node.public_key(),"AveNode2":fake_node_1,"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["AveNode1","Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["AveNode1","Owner"],"witness":["AveNode1"]},"roles_schema":{},"schemas":{},"version":2})
    );
    let state = get_subject(eval_node, governance_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":eval_node.public_key(),"AveNode2":fake_node_1,"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["AveNode1","Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["AveNode1","Owner"],"witness":["AveNode1"]},"roles_schema":{},"schemas":{},"version":2})
    );

    let json = json!({
    "roles": {
        "governance": {
            "remove": {
                "evaluator": ["AveNode1"],
                "validator": ["AveNode1"]
            }
        }
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner_governance, governance_id.clone(), Some(3))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 3);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":eval_node.public_key(),"AveNode2":fake_node_1,"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode1"]},"roles_schema":{},"schemas":{},"version":3})
    );
    let state = get_subject(eval_node, governance_id.clone(), Some(3))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 3);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":eval_node.public_key(),"AveNode2":fake_node_1,"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode1"]},"roles_schema":{},"schemas":{},"version":3})
    );

    let fake_node_2 = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "AveNode3",
                    "key": fake_node_2
                }
            ]
    }});

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner_governance, governance_id.clone(), Some(4))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 4);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":eval_node.public_key(),"AveNode2":fake_node_1,"AveNode3":fake_node_2,"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode1"]},"roles_schema":{},"schemas":{},"version":4})
    );
    let state = get_subject(eval_node, governance_id.clone(), Some(4))
        .await
        .unwrap();
    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 4);
    assert_eq!(
        state.properties,
        json!({"members":{"AveNode1":eval_node.public_key(),"AveNode2":fake_node_1,"AveNode3":fake_node_2,"Owner":owner_governance.public_key()},"policies_gov":{"approve":"majority","evaluate":"majority","validate":"majority"},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":["AveNode1"]},"roles_schema":{},"schemas":{},"version":4})
    );
}

#[test(tokio::test)]
async fn test_delete_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
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
                    "schema_id": "Example",

                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
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
                                    "quantity": 2
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, subject_id.clone(), None).await.unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );

    let json = json!({
        "schemas": {
            "remove": ["Example"]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    create_subject(node1, governance_id.clone(), "Example", "", true)
        .await
        .unwrap_err();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap_err();
    let state = get_subject(node1, subject_id.clone(), None).await.unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );
}

#[test(tokio::test)]
async fn test_change_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;
    let node1 = &nodes[0].api;

    let governance_id = create_and_authorize_governance(node1, vec![]).await;

    let json = json!({
        "schemas": {
            "add": [
                {
                    "id": "Example",
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
                    "schema_id": "Example",

                        "add": {
                            "evaluator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
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
                                    "quantity": 2
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
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(node1, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(node1, subject_id.clone(), Some(1))
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 1);
    assert_eq!(
        state.properties,
        json!({
            "one": 100, "three": 0, "two": 0
        })
    );

    let json = json!({
        "schemas": {
            "change": [{
                "actual_id": "Example",
                "new_contract": "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgZGF0YTogU3RyaW5nCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0KZW51bSBTdGF0ZUV2ZW50IHsKICBDaGFuZ2VEYXRhIHsgZGF0YTogU3RyaW5nIH0sCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gbWFpbl9mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMiwgaW5pdF9zdGF0ZV9wdHI6IGkzMiwgZXZlbnRfcHRyOiBpMzIsIGlzX293bmVyOiBpMzIpIC0+IHUzMiB7CiAgc2RrOjpleGVjdXRlX2NvbnRyYWN0KHN0YXRlX3B0ciwgaW5pdF9zdGF0ZV9wdHIsIGV2ZW50X3B0ciwgaXNfb3duZXIsIGNvbnRyYWN0X2xvZ2ljKQp9CgojW3Vuc2FmZShub19tYW5nbGUpXQpwdWIgdW5zYWZlIGZuIGluaXRfY2hlY2tfZnVuY3Rpb24oc3RhdGVfcHRyOiBpMzIpIC0+IHUzMiB7CiAgc2RrOjpjaGVja19pbml0X2RhdGEoc3RhdGVfcHRyLCBpbml0X2xvZ2ljKQp9CgpmbiBpbml0X2xvZ2ljKAogIF9zdGF0ZTogJlN0YXRlLAogIGNvbnRyYWN0X3Jlc3VsdDogJm11dCBzZGs6OkNvbnRyYWN0SW5pdENoZWNrLAopIHsKICBjb250cmFjdF9yZXN1bHQuc3VjY2VzcyA9IHRydWU7Cn0KCmZuIGNvbnRyYWN0X2xvZ2ljKAogIGNvbnRleHQ6ICZzZGs6OkNvbnRleHQ8U3RhdGVFdmVudD4sCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RSZXN1bHQ8U3RhdGU+LAopIHsKICBsZXQgc3RhdGUgPSAmbXV0IGNvbnRyYWN0X3Jlc3VsdC5zdGF0ZTsKICBtYXRjaCBjb250ZXh0LmV2ZW50LmNsb25lKCkgewogICAgICBTdGF0ZUV2ZW50OjpDaGFuZ2VEYXRhIHsgZGF0YSB9ID0+IHsKICAgICAgICBzdGF0ZS5kYXRhID0gZGF0YS5jbG9uZSgpOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQo=",
                "new_initial_value": {
                    "data": ""
                }
            }]
        }
    });

    emit_fact(node1, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ChangeData": {
            "data": "AveLedger",
        }
    });

    emit_fact(node1, subject_id.clone(), json, true)
        .await
        .unwrap();
    let state = get_subject(node1, subject_id.clone(), Some(2))
        .await
        .unwrap();
    assert_eq!(state.subject_id, subject_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 1);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "Example");
    assert_eq!(state.owner, node1.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, node1.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({
            "data": "AveLedger"
        })
    );
}

#[test(tokio::test)]
// Definimos 2 validadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no
async fn test_gov_no_all_validators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "validator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
            "members": {
                "add": [
                    {
                        "name": "user",
                        "key": user
                    }
                ]
            },
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner_governance, governance_id.clone(), Some(2))
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner":owner_governance.public_key(),"offline":offline_controller,"user":user},"policies_gov":{"approve":"majority","evaluate":{"fixed":1},"validate":{"fixed":1}},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner","offline"],"witness":[]},"roles_schema":{},"schemas":{},"version":2})
    );
}

#[test(tokio::test)]
// Definimos 2 evaluadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no.
async fn test_gov_no_all_evaluators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
            "members": {
                "add": [
                    {
                        "name": "user",
                        "key": user
                    }
                ]
            },
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let state = get_subject(owner_governance, governance_id.clone(), Some(2))
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 2);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner":owner_governance.public_key(),"offline":offline_controller,"user":user},"policies_gov":{"approve":"majority","evaluate":{"fixed":1},"validate":{"fixed":1}},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner", "offline"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_schema":{},"schemas":{},"version":2})
    );
}

#[test(tokio::test)]
// Definimos 2 validadores con Quorum 1, pero solo funciona uno.
// Hay que tener en cuenta que seleccionar uno es rng, puede seleccionar
// uno que esté o que no
// Algunos eventos fallan, por lo que la versión de la governanza no aumenta
async fn test_gov_fail_no_all_evaluators() {
    let (nodes, _dirs) =
        create_nodes_and_connections(vec![vec![]], vec![], vec![], true, false)
            .await;

    let owner_governance = &nodes[0].api;

    let governance_id =
        create_and_authorize_governance(owner_governance, vec![]).await;

    let offline_controller =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
            .public_key()
            .to_string();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "offline",
                    "key": offline_controller
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "evaluator": [
                        "offline"
                    ]
                }
            }
        },
        "policies": {
            "governance": {
               "change": {
                    "evaluate": {
                        "fixed": 1
                    },
                    "validate": {
                        "fixed": 1
                    }
               }
            }
        }
    });

    emit_fact(owner_governance, governance_id.clone(), json, true)
        .await
        .unwrap();

    let mut keys = vec![];
    for i in 0..2 {
        let user = if i % 2 != 0 {
            let user = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
                .public_key()
                .to_string();

            keys.push(user.clone());

            user
        } else {
            String::default()
        };

        // add node bootstrap and ephemeral to governance
        let json = json!({
                "members": {
                    "add": [
                        {
                            "name": format!("user{}", i),
                            "key": user
                        }
                    ]
                },
        });

        emit_fact(owner_governance, governance_id.clone(), json, true)
            .await
            .unwrap();
    }

    let state = get_subject(owner_governance, governance_id.clone(), Some(3))
        .await
        .unwrap();

    assert_eq!(state.subject_id, governance_id.to_string());
    assert_eq!(state.governance_id, governance_id.to_string());
    assert_eq!(state.genesis_gov_version, 0);
    assert_eq!(state.namespace, "");
    assert_eq!(state.schema_id, "governance");
    assert_eq!(state.owner, owner_governance.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, owner_governance.public_key());
    assert_eq!(state.active, true);
    assert_eq!(state.sn, 3);
    assert_eq!(
        state.properties,
        json!({"members":{"Owner":owner_governance.public_key(),"offline":offline_controller,"user1":keys[0]},"policies_gov":{"approve":"majority","evaluate":{"fixed":1},"validate":{"fixed":1}},"policies_schema":{},"roles_tracker_schemas":{"evaluator":[],"issuer":{"any":false,"signers":[]},"validator":[],"witness":[]},"roles_gov":{"approver":["Owner"],"evaluator":["Owner", "offline"],"issuer":{"any":false,"signers":["Owner"]},"validator":["Owner"],"witness":[]},"roles_schema":{},"schemas":{},"version":2})
    );
}
