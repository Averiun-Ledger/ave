mod common;

use ave_common::identity::PublicKey;
use ave_core::auth::AuthWitness;
use common::{
    create_and_authorize_governance, create_nodes_and_connections,
    create_subject, emit_confirm, emit_fact, emit_reject, emit_transfer,
    get_subject,
};

use futures::future::join_all;
use network::{NodeType, RoutingNode};
use serde_json::json;
use std::time::Duration;
use std::{str::FromStr, sync::atomic::Ordering};
use test_log::test;

use crate::common::{PORT_COUNTER, create_node, node_running};

#[test(tokio::test)]
async fn test_not_access() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
    )
    .await;
    let owner = &nodes[0].api;
    let witness_alice = &nodes[1].api;
    let witness_bob = &nodes[2].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![witness_alice, witness_bob],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": witness_alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": witness_bob.public_key()
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
                        "Alice", "Bob"
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
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Owner"],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity"
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
                                    "namespace": []
                                },
                                {
                                    "name": "Bob",
                                    "namespace": []
                                }
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Witnesses"]
                                }
                            ]
                        },

                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    ////////////////////////////////////////////////////////////////////////////////
    // Subject de Alice existe pero Bob no tiene ninguna relación con él
    ////////////////////////////////////////////////////////////////////////////////
    let (subject_id_1, ..) = create_subject(
        witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    let state = get_subject(witness_alice, subject_id_1.clone(), Some(0))
        .await
        .unwrap();

    assert_eq!(state.genesis_gov_version, 2);

    witness_bob
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_alice.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        witness_bob
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );

    ////////////////////////////////////////////////////////////////////////////////
    // witness fue testigo explícito de A, pero su intervalo cerrado expiró ANTES de que
    // A creara el sujeto (range.hi < owner_gov_version) → sin acceso
    ////////////////////////////////////////////////////////////////////////////////

    owner
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(
                PublicKey::from_str(&witness_alice.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();

    owner.update_subject(subject_id_1.clone()).await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(owner.get_subject_state(subject_id_1.clone()).await.is_err());
}

#[test(tokio::test)]
async fn test_basic_access() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = &nodes[1].api;
    let witness_bob = nodes[2].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![witness_alice, &witness_bob],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": witness_alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": witness_bob.public_key()
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
                        "Alice", "Bob"
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
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Owner"],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
                                    "namespace": []
                                },
                                {
                                    "name": "Bob",
                                    "namespace": []
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

    let (subject_id_1, ..) = create_subject(
        witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    let (subject_id_2, ..) = create_subject(
        witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 105,
        }
    });
    emit_fact(witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        witness_alice,
        subject_id_1.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_alice, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        Some(nodes[1].keys.clone()),
    )
    .await;
    let new_alice = node_new_alice.api;
    node_running(&new_alice).await.unwrap();

    assert!(
        new_alice
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_alice
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(1))
        .await
        .unwrap();

    // T04: N == actual_owner → acceso hasta data.sn
    //
    // Setup: owner_node crea un subject y emite facts (sn avanza)
    // Verificación: owner_node.get_subject_state(subject_id).sn == data.sn
    assert!(
        new_alice
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_alice
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    // T05: Transfer pendiente, N == new_owner → acceso hasta data.sn
    //
    // Secuencia:
    //   owner emite transfer a new_owner_node (sin confirmar todavía)
    // Verificación:
    //   new_owner_node.auth_subject → recibe hasta data.sn actual
    assert!(
        witness_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    witness_bob
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    // T06: Transfer pendiente, N == actual_owner → sigue con acceso hasta data.sn
    //
    // Secuencia:
    //   owner emite transfer (pendiente), owner sigue siendo actual_owner
    // Verificación:
    //   owner.get_subject_state(subject_id).sn == data.sn
    assert!(
        new_alice
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_alice
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_1.clone(), Some(2))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 3 — Old owner sin testigos
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_basic_transfers() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0]],
        vec![],
        true,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = &nodes[1].api;
    let witness_bob = nodes[2].api.clone();
    let witness_charlie = nodes[3].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![witness_alice, &witness_bob, &witness_charlie],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": witness_alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": witness_bob.public_key()
                },
                {
                    "name": "Charlie",
                    "key": witness_charlie.public_key()
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
                        "Alice", "Bob", "Charlie"
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
                            "witness": [
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
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "Charlie",
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
                                    "namespace": []
                                },
                                {
                                    "name": "Bob",
                                    "namespace": []
                                },
                                {
                                    "name": "Charlie",
                                    "namespace": []
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

    let (subject_id_1, ..) = create_subject(
        witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    let (subject_id_2, ..) = create_subject(
        witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    let (subject_id_3, ..) = create_subject(
        witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 105,
        }
    });
    emit_fact(witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 110,
        }
    });
    emit_fact(witness_alice, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        witness_alice,
        subject_id_3.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(2))
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_3.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(3))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(3))
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 305,
        }
    });
    emit_fact(&witness_bob, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_3.clone(), Some(2))
        .await
        .unwrap();

    witness_alice
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_3.clone(), Some(3))
        .await
        .unwrap();

    emit_transfer(
        &witness_bob,
        subject_id_3.clone(),
        PublicKey::from_str(&witness_charlie.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_charlie
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_3.clone(), Some(5))
        .await
        .unwrap();

    emit_confirm(&witness_charlie, subject_id_3.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_3.clone(), Some(6))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(6))
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 405,
        }
    });
    emit_fact(&witness_charlie, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_3.clone(), Some(7))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(7))
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(5))
        .await
        .unwrap();

    witness_bob
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(6))
        .await
        .unwrap();

    // T07: A→B confirm. N=A (old owner) sin testigos → acceso hasta old_data.sn
    //
    // Secuencia:
    //   gov_v1: A crea subject (sn=0)
    //   sn avanza hasta sn=5 con facts
    //   A transfiere a B; B confirma (sn=6 en el momento del confirm → old_data.sn=6)
    //   B emite más facts (sn=7, 8, 9)
    //   A no es testigo de nadie
    //
    // Verificación:
    //   A.auth_subject → recibe hasta sn=6, no recibe sn=7,8,9
    emit_transfer(
        witness_alice,
        subject_id_1.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_1.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(3))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_1.clone(), Some(3))
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 205,
        }
    });
    emit_fact(&witness_bob, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_1.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    witness_alice
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(3))
        .await
        .unwrap();

    // T08: A→B reject. N=B (propuesto rechazado) sin testigos → acceso hasta old_data.sn
    //
    // Secuencia:
    //   A crea subject, emite facts (sn avanza)
    //   A transfiere a B; B rechaza (sn=X en ese momento → old_data.sn=X)
    //   A emite más facts
    //   B sin testigos
    //
    // Verificación:
    //   B.auth_subject → recibe hasta sn=X, no más
    emit_transfer(
        witness_alice,
        subject_id_2.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(2))
        .await
        .unwrap();

    emit_reject(&witness_bob, subject_id_2.clone(), true)
        .await
        .unwrap();

    witness_alice
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(3))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(3))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_2.clone(), Some(3))
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 205,
        }
    });
    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_bob, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        Some(nodes[2].keys.clone()),
    )
    .await;
    let new_bob = node_new_bob.api;
    node_running(&new_bob).await.unwrap();

    assert!(
        new_bob
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_bob
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(1))
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_bob
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_2.clone(), Some(3))
        .await
        .unwrap();

    // T09: A→B→C (dos confirms). N=A sin testigos → acceso hasta old_data_A.sn
    //
    // Secuencia:
    //   A crea subject → emite facts → transfiere a B (sn=5 al confirm)
    //   B emite facts → transfiere a C (sn=9 al confirm)
    //   C emite facts (sn=12 actual)
    //   A sin testigos
    //
    // Verificación:
    //   A.auth_subject → recibe hasta sn=5
    //   B.auth_subject → recibe hasta sn=9
    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_alice, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        Some(nodes[1].keys.clone()),
    )
    .await;
    let new_alice = node_new_alice.api;
    node_running(&new_alice).await.unwrap();

    nodes[3].token.cancel();
    join_all(nodes[3].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_charlie, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        Some(nodes[3].keys.clone()),
    )
    .await;
    let new_charlie = node_new_charlie.api;
    node_running(&new_charlie).await.unwrap();

    assert!(
        new_alice
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );
    new_alice
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(1))
        .await
        .unwrap();
    assert!(
        new_alice
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_alice
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&new_alice, subject_id_3.clone(), Some(3))
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_bob
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_3.clone()).await.unwrap();
    let _state = get_subject(&new_bob, subject_id_3.clone(), Some(6))
        .await
        .unwrap();

    assert!(
        new_charlie
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );
    new_charlie
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, governance_id.clone(), Some(1))
        .await
        .unwrap();
    assert!(
        new_charlie
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_charlie
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(7))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 4 — Testigo explícito del owner actual (pure witness)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_basic_explicit_witness() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_alice, &witness_bob],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": witness_alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": witness_bob.public_key()
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
                        "Alice", "Bob"
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
                            "witness": [
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
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": ["Test1"],
                                    "quantity": "infinity",
                                    "witnesses": ["Bob"],
                                },
                                {
                                    "name": "Alice",
                                    "namespace": ["Test2"],
                                    "quantity": "infinity",
                                    "witnesses": ["Bob"],
                                },
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
                                    "namespace": []
                                },
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id_1, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Test1",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    // T10: N testigo explícito de A, actualmente activo (actual_lo.is_some())
    //      → acceso hasta data.sn
    //
    // Secuencia:
    //   gov_v1: governance añade witness_node como testigo explícito de owner_node
    //   owner crea subject, emite facts (sn=5)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=5

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    // T11: N testigo explícito de A, intervalo cerrado [gov_v3, gov_v7] cubre owner_gov_version=gov_v5
    //      → acceso hasta sn_at_gov_v7 (NO hasta data.sn)
    //
    // Secuencia:
    //   gov_v3: witness_node se añade como testigo de owner_node (actual_lo=gov_v3)
    //   gov_v5: owner_node crea el subject (owner_gov_version=gov_v5)
    //   gov_v6: se emiten facts (sn avanza)
    //   gov_v7: witness_node se elimina como testigo (intervalo cierra: [gov_v3, gov_v6])
    //           → sn_at_gov_v7 es el sn que había en ese momento
    //   gov_v8: se emiten más facts (owner sigue siendo A)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn_at_gov_v7, no más allá

    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": ["Test1"],
                                    "new_witnesses": ["Witnesses"]
                                },
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": ["Witnesses"]
                                }
                            ]
                        },

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });
    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_bob, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        Some(nodes[2].keys.clone()),
    )
    .await;
    let new_bob = node_new_bob.api;
    node_running(&new_bob).await.unwrap();

    assert!(
        new_bob
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_bob
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(2))
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_bob
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_1.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    // T12: N testigo explícito de A, intervalo cerrado NO cubre owner_gov_version → sin acceso
    //
    // Secuencia:
    //   gov_v1: witness_node testigo de owner_node (actual_lo=gov_v1)
    //   gov_v2: witness_node eliminado (intervalo [gov_v1, gov_v1])
    //   gov_v5: owner_node crea el subject (owner_gov_version=gov_v5)
    //           → intervalo [gov_v1, gov_v1] no contiene gov_v5
    //
    // Verificación:
    //   witness_node.auth_subject → sin acceso

    let (subject_id_2, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Test2",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    new_bob
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_1.clone()).await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        new_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 5 — Testigo general (Witnesses) del owner actual (pure witness)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_basic_implicit_witness() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_alice, &witness_bob],
    )
    .await;

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": witness_alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": witness_bob.public_key()
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
                        "Alice", "Bob"
                    ]
                }
            },
            "tracker_schemas": {
                "add": {
                    "witness": [
                        {
                            "name": "Bob",
                            "namespace": ["Test2"]
                        },
                    ],
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
                            "witness": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                },
                                {
                                    "name": "Bob",
                                    "namespace": ["Test1"]
                                }
                            ],
                            "validator": [
                                {
                                    "name": "Owner",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": ["Test1"],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "Alice",
                                    "namespace": ["Test2"],
                                    "quantity": "infinity",
                                },
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
                                    "namespace": []
                                },
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // T13: A tiene Witnesses, N testigo general activo por schema específico → data.sn
    //
    // Secuencia:
    //   gov_v1: governance añade witness_node como testigo en roles.schema["Example"]
    //           (esto pone al owner_node con WitnessesType::Witnesses y añade witness_node
    //            a self.witnesses[(witness_pk, SchemaType::Type("Example"))])
    //   owner crea subject Example, emite facts (sn=5)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=5

    let (subject_id_1, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Test1",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    // T14: A tiene Witnesses, N testigo activo vía TrackerSchemas → data.sn
    //
    // Secuencia:
    //   gov_v1: witness_node tiene rol witness con schema_id=TrackerSchemas (todos los schemas)
    //   owner crea subject con cualquier schema, emite facts (sn=5)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=5

    let (subject_id_2, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Test2",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    // T15: A tiene Witnesses, N testigo general cerrado [gov_v3, gov_v7] cubre owner_gov_version=gov_v5
    //      → sn_at_gov_v7
    //
    // Igual que T11 pero usando testigo general (rol de schema) en lugar de explícito
    let json = json!({
        "roles": {
            "tracker_schemas": {
                "remove": {
                    "witness": [
                        {
                            "name": "Bob",
                            "namespace": ["Test2"]
                        },
                    ],
                }
            }
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });
    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_bob, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        Some(nodes[2].keys.clone()),
    )
    .await;
    let new_bob = node_new_bob.api;
    node_running(&new_bob).await.unwrap();

    assert!(
        new_bob
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_bob
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(2))
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_bob
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    // T16: A tiene Witnesses, N testigo general cerrado NO cubre owner_gov_version → sin acceso
    let (subject_id_3, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Test2",
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    new_bob
        .auth_subject(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_3.clone()).await.unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        new_bob
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
}
