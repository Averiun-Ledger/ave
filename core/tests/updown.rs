mod common;

use ave_common::bridge::request::ApprovalStateRes;
use ave_common::identity::keys::Ed25519Signer;
use ave_common::identity::{KeyPair, PublicKey};
use ave_common::response::RequestState;
use ave_core::auth::AuthWitness;
use common::{
    create_and_authorize_governance, create_nodes_and_connections,
    create_subject, emit_confirm, emit_fact, emit_reject, emit_transfer,
    get_subject,
};

use futures::future::join_all;
use ave_network::{NodeType, RoutingNode};
use serde_json::json;
use std::{str::FromStr, sync::atomic::Ordering};
use test_log::test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
    create_node, emit_approve, emit_eol, node_running, wait_request_state,
};

#[test(tokio::test)]
// todos los eventos de una gobernanza
async fn gov_life() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            ..Default::default()
        })
        .await;
    let bootstrap = nodes[0].api.clone();
    let owner = &nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&bootstrap]).await;

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        keys: Some(nodes[1].keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "boot",
                    "key": bootstrap.public_key()
                },
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": ["boot"],
                    "approver": ["boot"]
                }
            }
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
    });

    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(1), true)
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
                "name": "AveNode1",
                "key": fake_node
            }
        ]
    }});

    let request_id = emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    emit_approve(
        &bootstrap,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        false,
    )
    .await
    .unwrap();

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    emit_approve(
        &owner,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    emit_transfer(
        &owner,
        governance_id.clone(),
        PublicKey::from_str(&bootstrap.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    owner
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(&bootstrap.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 1);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 1);

    emit_reject(&bootstrap, governance_id.clone(), true)
        .await
        .unwrap();

    owner.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![node_bootstrap.listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 0);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 0);

    emit_transfer(
        &owner,
        governance_id.clone(),
        PublicKey::from_str(&bootstrap.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, governance_id.clone(), Some(5), true)
        .await
        .unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 1);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 1);

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![node_bootstrap.listen_address.clone()],
    }];

    let (node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    emit_confirm(
        &bootstrap,
        governance_id.clone(),
        Some("old_owner".to_owned()),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&bootstrap, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 0);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 0);

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

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

    let request_id = emit_fact(&bootstrap, governance_id.clone(), json, true)
        .await
        .unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    emit_approve(
        &bootstrap,
        governance_id.clone(),
        ApprovalStateRes::Accepted,
        request_id.clone(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&bootstrap, governance_id.clone(), Some(7), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(7), true)
        .await
        .unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    emit_eol(&bootstrap, governance_id.clone(), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, governance_id.clone(), Some(8), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, governance_id.clone(), Some(8), true)
        .await
        .unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    let fake_node = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    // add new fake member to governance
    let json = json!({
    "members": {
        "add": [
            {
                "name": "AveNode1",
                "key": fake_node
            }
        ]
    }});

    assert!(
        emit_fact(&bootstrap, governance_id.clone(), json, true)
            .await
            .is_err()
    );
}

#[test(tokio::test)]
// todos los eventos de un tracker
async fn tracker_life() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let bootstrap = nodes[0].api.clone();
    let owner = &nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&bootstrap]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "boot",
                    "key": bootstrap.public_key()
                },
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
                        "boot"
                    ]
                }
            },
            "tracker_schemas": {
                "add": {
                    "issuer": [
                        {
                            "name": "boot",
                            "namespace": []
                        },
                        {
                            "name": "Owner",
                            "namespace": []
                        }
                    ]
                }
            },
            "schema": [
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
                                },
                                {
                                    "name": "boot",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "boot",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[1].keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(&owner, subject_id.clone(), json.clone(), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&bootstrap.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    nodes[0].token.cancel();
    join_all(nodes[0].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[0].keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 1);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 1);

    emit_reject(&bootstrap, subject_id.clone(), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(3), true)
        .await
        .unwrap();

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![node_bootstrap.listen_address.clone()],
    }];

    let (mut node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 0);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 0);

    emit_transfer(
        &owner,
        subject_id.clone(),
        PublicKey::from_str(&bootstrap.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 1);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 1);

    node_new_owner.token.cancel();
    join_all(node_new_owner.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![node_bootstrap.listen_address.clone()],
    }];

    let (node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_new_owner.keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    emit_confirm(&bootstrap, subject_id.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(5), true)
        .await
        .unwrap();

    assert_eq!(owner.get_pending_transfers().await.unwrap().len(), 0);
    assert_eq!(bootstrap.get_pending_transfers().await.unwrap().len(), 0);

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    let _request_id = emit_fact(&bootstrap, subject_id.clone(), json, true)
        .await
        .unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (mut node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    emit_eol(&bootstrap, subject_id.clone(), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(7), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(7), true)
        .await
        .unwrap();

    node_bootstrap.token.cancel();
    join_all(node_bootstrap.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![node_new_owner.listen_address.clone()],
    }];

    let (node_bootstrap, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(node_bootstrap.keys.clone()),
        local_db: Some(dirs[0].path().to_path_buf()),
        ext_db: Some(dirs[1].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let bootstrap = node_bootstrap.api.clone();
    node_running(&bootstrap).await.unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    assert!(
        emit_fact(&bootstrap, subject_id.clone(), json, true)
            .await
            .is_err()
    );
}

#[test(tokio::test)]
async fn not_node_role() {
    let (mut nodes, dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let bootstrap = nodes[0].api.clone();
    let owner = &nodes[1].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&bootstrap]).await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "boot",
                    "key": bootstrap.public_key()
                },
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
                        "boot"
                    ]
                }
            },
            "tracker_schemas": {
                "add": {
                    "issuer": [
                        {
                            "name": "boot",
                            "namespace": []
                        },
                        {
                            "name": "Owner",
                            "namespace": []
                        }
                    ]
                }
            },
            "schema": [
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
                                },
                                {
                                    "name": "boot",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "boot",
                                    "namespace": [],
                                    "quantity": "infinity"
                                },
                                {
                                    "name": "Owner",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(&bootstrap, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    let request_id =
        emit_fact(&bootstrap, subject_id.clone(), json.clone(), false)
            .await
            .unwrap();

    let _ = wait_request_state(
        &bootstrap,
        request_id.clone(),
        Some(RequestState::RebootTimeOut {
            seconds: 0,
            count: 0,
        }),
    )
    .await
    .unwrap();

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: bootstrap.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_owner, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        keys: Some(nodes[1].keys.clone()),
        local_db: Some(dirs[2].path().to_path_buf()),
        ext_db: Some(dirs[3].path().to_path_buf()),
        ..Default::default()
    })
    .await;
    let owner = node_new_owner.api.clone();
    node_running(&owner).await.unwrap();

    let _state = get_subject(&owner, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    let _state = get_subject(&bootstrap, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
}
