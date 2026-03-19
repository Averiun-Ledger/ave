mod common;

use ave_common::identity::keys::Ed25519Signer;
use ave_common::identity::{KeyPair, PublicKey};
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
// Recibe la copia de un sujeto sin tener la gobernanza
async fn test_witeness_not_gov() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = &nodes[1].api;
    let witness_bob = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![witness_alice]).await;

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
                        "Alice"
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
                                    "witnesses": ["Bob", "Witnesses"],
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
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

    assert!(!witness_bob.public_key().is_empty());
}

#[test(tokio::test)]
async fn test_not_access() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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
        false,
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

    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake1",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
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
        false,
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

    let _state = get_subject(&new_bob, governance_id.clone(), Some(3))
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

    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake2",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

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

    new_bob.update_subject(subject_id_2.clone()).await.unwrap();

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
        false,
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
    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake1",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

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
        false,
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

    let _state = get_subject(&new_bob, governance_id.clone(), Some(3))
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

    // T16: A tiene Witnesses, N testigo general cerrado NO cubre owner_gov_version → sin acceso
    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake2",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

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

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 6 — Old owner + testigo explícito del owner actual
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_explicit_witness() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
        false,
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
                                    "namespace": [],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Alice", "Witnesses"],
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
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    // T17: N fue owner (→ old_owner) y SIGUE siendo testigo explícito activo de A
    //      → acceso hasta data.sn (el máximo)
    //
    // Secuencia:
    //   A crea subject → transfiere a B (sn=5)
    //   gov añade A como testigo explícito de B (activo, actual_lo.is_some())
    //   B emite facts (sn=8)
    //
    // Verificación:
    //   A.auth_subject → recibe hasta sn=8 (data.sn)
    let (subject_id_1, ..) = create_subject(
        &witness_alice,
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
    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
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

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(4))
        .await
        .unwrap();

    // T18: N fue owner, fue testigo explícito de B(nuevo), intervalo [gov_v3,gov_v7]
    //      cubre new_owner_gov_version=gov_v5 → max(sn_at_gov_v7, old_data.sn)
    //
    // Secuencia:
    //   gov_v3: A añadido como testigo de B (actual_lo=gov_v3)
    //   gov_v5: A crea subject, transfiere a B, B confirma (old_data.sn=5, new B gov_version=gov_v5)
    //   gov_v6: facts (sn=6)
    //   gov_v7: A eliminado como testigo de B (intervalo cierra [gov_v3, gov_v6])
    //   gov_v8: B emite más facts (sn=8)
    //
    // Verificación:
    //   A.auth_subject → recibe hasta max(sn_at_gov_v7, 5) = sn_at_gov_v7
    //   (que es >= 5 porque hay facts entre gov_v3 y gov_v7)

    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake1",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id_3, ..) = create_subject(
        &witness_alice,
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
    emit_fact(&witness_alice, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
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

    let _state = get_subject(&witness_alice, subject_id_3.clone(), Some(4))
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
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
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
            "data": 300,
        }
    });

    emit_fact(&witness_bob, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(5))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_3.clone(), Some(5))
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_3.clone(), Some(4))
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

    let (mut node_new_alice, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
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

    let _state = get_subject(&new_alice, governance_id.clone(), Some(3))
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

    let _state = get_subject(&new_alice, subject_id_3.clone(), Some(4))
        .await
        .unwrap();

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

    let _state = get_subject(&new_alice, subject_id_1.clone(), Some(4))
        .await
        .unwrap();

    // T19: N fue owner, fue testigo de B pero intervalo NO cubre new_owner_gov_version
    //      → solo old_data.sn
    //
    // Secuencia:
    //   gov_v1: A como testigo de B (actual_lo=gov_v1)
    //   gov_v2: A eliminado como testigo de B (intervalo [gov_v1, gov_v1])
    //   gov_v5: A crea subject, transfiere a B, B confirma (old_data.sn=5, B gov_version=gov_v5)
    //           → intervalo [gov_v1, gov_v1] no contiene gov_v5
    //   gov_v6: B emite facts (sn=7)
    //
    // Verificación:
    //   A.auth_subject → recibe solo hasta sn=5 (old_data.sn)
    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake2",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id_2, ..) =
        create_subject(&new_alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });
    emit_fact(&new_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &new_alice,
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

    emit_confirm(&witness_bob, subject_id_2.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(&witness_bob, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(2))
        .await
        .unwrap();

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

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_2.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(3))
        .await
        .unwrap();

    node_new_alice.token.cancel();
    join_all(node_new_alice.handler.iter_mut()).await;

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
        false,
        Some(node_new_alice.keys.clone()),
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

    let _state = get_subject(&new_alice, governance_id.clone(), Some(4))
        .await
        .unwrap();

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

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(3))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 7 — Acceso via testigos de owners históricos
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_explicit_witness_2() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();
    let witness_charlie = nodes[3].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_alice, &witness_bob, &witness_charlie],
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
                                    "name": "Bob",
                                    "namespace": ["Test1"],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "Bob",
                                    "namespace": ["Test2"],
                                    "quantity": "infinity",
                                },
                                {
                                    "name": "Alice",
                                    "namespace": ["Test1"],
                                    "quantity": "infinity",
                                    "witnesses": ["Charlie", "Witnesses"],
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
                                {
                                    "name": "Bob",
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

    // T20: A→B confirm. N testigo explícito activo de B, actual_lo <= B.interval.hi
    //      → acceso hasta old_data_B.sn
    //
    // Secuencia:
    //   gov_v1: witness_node añadido como testigo de B (actual_lo=gov_v1)
    //   gov_v2: B crea subject (B es owner, gov_version=gov_v2)
    //   sn avanza hasta sn=5
    //   gov_v4: B transfiere a C, C confirma (old_data_B.sn=5, B.interval=[gov_v2, gov_v4])
    //           actual_lo=gov_v1 <= gov_v4=range.hi → condición cumplida
    //   C emite facts (sn=8)
    //   witness_node sigue siendo testigo activo de B
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=5 (old_data_B.sn)

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

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
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

    let _state = get_subject(&witness_charlie, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    witness_charlie
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_1.clone(), Some(3))
        .await
        .unwrap();

    // T21: N testigo activo de B, pero actual_lo > B.interval.hi
    //      (N se convirtió en testigo DESPUÉS de que B dejara de ser owner) → sin acceso
    //
    // Secuencia:
    //   gov_v2: B crea subject (B es owner, gov_version=gov_v2)
    //   gov_v4: B transfiere a C, C confirma (B.interval=[gov_v2, gov_v4])
    //   gov_v5: witness_node añadido como testigo de B (actual_lo=gov_v5)
    //           → gov_v5 > gov_v4=B.interval.hi → sin acceso
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

    emit_transfer(
        &witness_alice,
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

    emit_confirm(&witness_bob, subject_id_2.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(&witness_bob, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(2))
        .await
        .unwrap();

    assert!(
        witness_charlie
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );

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
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": ["Witnesses", "Charlie"]
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

    witness_charlie
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        witness_charlie
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );

    // T22: N testigo explícito de B (cerrado), intervalo SOLAPA con rango de B
    //      → acceso hasta sn_at_max_covered
    //
    // Secuencia:
    //   gov_v2: witness_node testigo de B (actual_lo=gov_v2)
    //   gov_v3: B crea subject (gov_version=gov_v3)
    //   gov_v5: witness_node eliminado como testigo de B (intervalo [gov_v2, gov_v4])
    //           → max_covered_in(gov_v3, gov_v6) sobre {[gov_v2,gov_v4]} = gov_v4
    //   gov_v6: B transfiere a C, C confirma (B.interval=[gov_v3, gov_v6])
    //   sn_at_gov_v4 es el sn en el momento gov_v4
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn_at_gov_v4
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

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
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

    let _state = get_subject(&witness_charlie, subject_id_3.clone(), Some(1))
        .await
        .unwrap();

    nodes[3].token.cancel();
    join_all(nodes[3].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_charlie, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
        Some(nodes[3].keys.clone()),
    )
    .await;
    let new_charlie = node_new_charlie.api.clone();
    node_running(&new_charlie).await.unwrap();

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

    let _state = get_subject(&new_charlie, governance_id.clone(), Some(3))
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

    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(1))
        .await
        .unwrap();

    // T23: N testigo explícito de B (cerrado), intervalo NO solapa → sin acceso
    //
    // Secuencia:
    //   gov_v1: witness_node testigo de B (actual_lo=gov_v1)
    //   gov_v2: witness_node eliminado (intervalo [gov_v1, gov_v1])
    //   gov_v5: B crea subject (gov_version=gov_v5)
    //   gov_v7: B transfiere a C, C confirma (B.interval=[gov_v5, gov_v7])
    //           → [gov_v1, gov_v1] no solapa [gov_v5, gov_v7] → sin acceso
    //
    // Verificación:
    //   witness_node.auth_subject → sin acceso

    let (subject_id_4, ..) = create_subject(
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
    emit_fact(&witness_alice, subject_id_4.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
        subject_id_4.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .auth_subject(
            subject_id_4.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_4.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_4.clone(), Some(2))
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_4.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(&witness_bob, subject_id_4.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_4.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_4.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_4.clone(), Some(2))
        .await
        .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_4.clone())
            .await
            .is_err()
    );

    new_charlie
        .auth_subject(
            subject_id_4.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_4.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        new_charlie
            .get_subject_state(subject_id_4.clone())
            .await
            .is_err()
    );

    // T26: Alice crea subject en Test2 (gov_v=3, B=Alice)
    //      Bob confirma (Alice.interval=[3,3])
    //      gov_v=4: Charlie añadido como testigo general del schema "Example"
    //               actual_lo=4 > Alice.interval.hi=3 → sin acceso
    //
    // Verificación:
    //   new_charlie.auth_subject → sin acceso

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
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": ["Owner"]
                                },
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": ["Owner"]
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

    let (subject_id_5, ..) = create_subject(
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
    emit_fact(&witness_alice, subject_id_5.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
        subject_id_5.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .auth_subject(
            subject_id_5.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_5.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_5.clone(), Some(2))
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_5.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });
    emit_fact(&witness_bob, subject_id_5.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_5.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_5.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_5.clone(), Some(2))
        .await
        .unwrap();

    // gov_v sube a 4: añadir Charlie como testigo general del schema
    // actual_lo = 4 > Alice.interval.hi = 3 → sin acceso
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "witness": [
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

    assert!(
        new_charlie
            .get_subject_state(subject_id_5.clone())
            .await
            .is_err()
    );

    new_charlie
        .auth_subject(
            subject_id_5.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_5.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        new_charlie
            .get_subject_state(subject_id_5.clone())
            .await
            .is_err()
    );

    // T24: Alice crea subject en Test2 (gov_v=4, B=Alice)
    //      Charlie ya es testigo general del schema desde gov_v=4 (actual_lo=4)
    //      Bob confirma (Alice.interval=[4,4])
    //      actual_lo=4 <= Alice.interval.hi=4 → acceso hasta old_data_Alice.sn
    //
    // Igual que T20 pero usando testigo general (rol de schema) en lugar de explícito de B

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
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": ["Witnesses"]
                                },
                            ]
                        },

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id_6, ..) = create_subject(
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
    emit_fact(&witness_alice, subject_id_6.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
        subject_id_6.clone(),
        PublicKey::from_str(&witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .auth_subject(
            subject_id_6.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_6.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_6.clone(), Some(2))
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_6.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });
    emit_fact(&witness_bob, subject_id_6.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_6.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_6.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_6.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_6.clone(), Some(2))
        .await
        .unwrap();

    node_new_charlie.token.cancel();
    join_all(node_new_charlie.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_charlie_2, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
        Some(node_new_charlie.keys.clone()),
    )
    .await;
    let new_charlie_2 = node_new_charlie_2.api;
    node_running(&new_charlie_2).await.unwrap();

    assert!(
        new_charlie_2
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_charlie_2
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie_2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie_2, governance_id.clone(), Some(6))
        .await
        .unwrap();

    assert!(
        new_charlie_2
            .get_subject_state(subject_id_6.clone())
            .await
            .is_err()
    );
    new_charlie_2
        .auth_subject(
            subject_id_6.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie_2
        .update_subject(subject_id_6.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie_2, subject_id_6.clone(), Some(3))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 9 — Caso clave del fix: range.hi en lugar de owner_gov_version
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_range() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
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
                        "Alice", "Bob",
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
                                    "witnesses": ["Witnesses", "Bob"],
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
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

    // T29: N testigo cerrado de A con intervalo [gov_v3, gov_v7]. A owner desde gov_v5.
    //      Eventos emitidos en gov_v6 y gov_v7. sn_at_gov_v7 > sn_at_gov_v5
    //      → acceso hasta sn_at_gov_v7 (NO sn_at_gov_v5)
    //
    // Secuencia:
    //   gov_v3: witness_node testigo de owner_node (actual_lo=gov_v3)
    //   gov_v5: owner_node crea subject (owner_gov_version=gov_v5, sn=0)
    //   gov_v5→gov_v6: owner emite 3 facts (sn=3)
    //   gov_v7: witness_node eliminado como testigo (intervalo [gov_v3, gov_v6])
    //           sn en este punto = 3 → sn_at_gov_v7 = 3
    //   gov_v8: owner emite más facts (sn=6)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=3, no sn=6

    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake2",
                    "key": keys.public_key()
                },
            ]
        },
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

    let keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Fake1",
                    "key": keys.public_key()
                },
            ]
        },
    });

    emit_fact(&owner, governance_id.clone(), json, true)
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
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    // T30: N testigo cerrado de A, intervalo [gov_v5, gov_v5] (punto exacto = owner_gov_version)
    //      → range.hi == owner_gov_version → mismo resultado que antes del fix
    //      → acceso hasta sn_at_gov_v5
    //
    // Secuencia:
    //   gov_v5: witness_node añadido Y ELIMINADO en la misma gov (intervalo [gov_v5, gov_v5])
    //           owner_node crea subject en gov_v5 (owner_gov_version=gov_v5, sn=0)
    //   gov_v6: owner emite facts (sn=3)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=0 (sn_at_gov_v5)

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": ["Test2"],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses", "Bob"],
                                }
                            ],
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

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
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "change": {
                            "creator": [
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
            "data": 100,
        }
    });
    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    // Check Test29 and Test30
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
        false,
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

    let _state = get_subject(&new_bob, governance_id.clone(), Some(6))
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

    let _state = get_subject(&owner, subject_id_1.clone(), Some(2))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(2))
        .await
        .unwrap();
    let _state = get_subject(&new_bob, subject_id_1.clone(), Some(1))
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

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(1))
        .await
        .unwrap();
    let _state = get_subject(&new_bob, subject_id_2.clone(), Some(0))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 10 — Namespace y Schema matching
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_ns_schema() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();
    let witness_charlie = nodes[3].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_alice, &witness_bob, &witness_charlie],
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
                },
                {
                    "id": "Example1",
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
                                    "name": "Alice",
                                    "namespace": ["Org", "Team"],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
                                },
                                {
                                    "name": "Alice",
                                    "namespace": ["Org"],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
                                }
                            ],
                            "issuer": [
                                {
                                    "name": "Alice",
                                    "namespace": []
                                }
                            ]
                        }

                },
                {
                    "schema_id": "Example1",
                        "add": {
                            "witness": [
                                {
                                    "name": "Charlie",
                                    "namespace": []
                                }
                            ],
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // T31: N testigo con namespace "org", sujeto en namespace "org/team" → acceso (ancestro)
    // T32: N testigo con namespace "" (vacío = cualquiera), sujeto en cualquier namespace → acceso
    let (subject_id_1, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Org.Team",
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

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "witness": [
                                {
                                    "name": "Bob",
                                    "namespace": ["Org"]
                                }
                            ]
                        }

                },
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
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

    let _state = get_subject(&owner, subject_id_1.clone(), Some(1))
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(1))
        .await
        .unwrap();

    // T33: N testigo con namespace "org/team", sujeto en namespace "org" → sin acceso
    //      (descendiente no es ancestro)
    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "witness": [
                                {
                                    "name": "Bob",
                                    "namespace": ["Org", "Team"]
                                }
                            ]
                        },
                        "remove": {
                            "witness": [
                                {
                                    "name": "Bob",
                                    "namespace": ["Org"]
                                }
                            ]
                        }

                },
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id_2, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "Org",
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

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1))
        .await
        .unwrap();
    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        witness_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );

    // T34: N testigo para TrackerSchemas (todos los schemas), sujeto con schema específico → acceso
    let json = json!({

        "roles": {
            "tracker_schemas": {
                "add": {
                    "witness": [
                        {
                            "name": "Bob",
                            "namespace": []
                        }
                    ],
                }
            },
            "schema":
                [
                {
                    "schema_id": "Example",
                        "remove": {
                            "witness": [
                                {
                                    "name": "Bob",
                                    "namespace": ["Org", "Team"]
                                }
                            ]
                        }

                },
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
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

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(1))
        .await
        .unwrap();

    // T35: N testigo para schema "SchemaA", sujeto con schema "SchemaB" → sin acceso
    witness_charlie
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        witness_charlie
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 11 — Combinaciones multi-fuente (max de varios sn)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_multi_source() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();
    let witness_charlie = nodes[3].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_alice, &witness_bob, &witness_charlie],
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
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
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

    // T36: N es old_owner de B (old_data.sn=5) Y testigo de A(actual) con sn_at_gov_v=8
    //      → acceso hasta max(8, 5) = 8
    //
    // Secuencia:
    //   gov_v1: N crea subject (N es owner), emite facts hasta sn=5
    //   gov_v3: N transfiere a A, A confirma (old_data_N.sn=5)
    //   gov_v3: witness_node (=N) testigo de A (actual_lo=gov_v3)
    //   A emite facts hasta sn=8
    //
    // Verificación:
    //   N.auth_subject → recibe hasta sn=8 (max entre 5 y sn_at_gov_activo=8)
    let (subject_id_1, ..) = create_subject(
        &witness_alice,
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

    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
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
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Witnesses", "Alice"]
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

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
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

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(4))
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
        false,
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

    let _state = get_subject(&new_alice, governance_id.clone(), Some(2))
        .await
        .unwrap();

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

    let _state = get_subject(&new_alice, subject_id_1.clone(), Some(4))
        .await
        .unwrap();

    // T37: N pure witness de B(old, sn=8) Y testigo de A(actual, sn=12) → max=12
    //
    // Secuencia:
    //   gov_v1: B crea subject, emite facts hasta sn=8, transfiere a A, A confirma
    //   gov_v1: witness_node testigo de B (intervalo que solapa rango de B → sn_at_max=8)
    //   gov_v1: witness_node testigo de A (activo → sn=12)
    //   A emite facts hasta sn=12
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=12
    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "add": {
                            "witness": [
                                {
                                    "name": "Charlie",
                                    "namespace": []
                                }
                            ],
                        },
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Owner", "Charlie"]
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

    let (subject_id_2, ..) =
        create_subject(&new_alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(&new_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &new_alice,
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

    emit_confirm(&witness_bob, subject_id_2.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });

    emit_fact(&witness_bob, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(2))
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    nodes[3].token.cancel();
    join_all(nodes[3].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_charlie, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
        Some(nodes[3].keys.clone()),
    )
    .await;
    let new_charlie = node_new_charlie.api;
    node_running(&new_charlie).await.unwrap();

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

    let _state = get_subject(&new_charlie, governance_id.clone(), Some(3))
        .await
        .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_charlie
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    // T39: better_gov_version produce SnLimit::LastSn en SnRegister → resultado = data.sn
    //
    // Esto ocurre cuando gov_version > último gov_version registrado en SnRegister.
    // En la práctica ocurre si el sn_register aún no ha procesado esa gov_version.
    //
    // Verificación: el resultado final es data.sn (el sn más reciente del sujeto)

    let (subject_id_3, ..) = create_subject(
        &witness_bob,
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

    emit_fact(&witness_bob, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(1))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_3.clone(), Some(1))
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(1))
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
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Owner"]
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

    node_new_charlie.token.cancel();
    join_all(node_new_charlie.handler.iter_mut()).await;

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
        false,
        Some(node_new_charlie.keys.clone()),
    )
    .await;
    let new_charlie = node_new_charlie.api;
    node_running(&new_charlie).await.unwrap();

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

    let _state = get_subject(&new_charlie, governance_id.clone(), Some(4))
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

    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(1))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 13 — Más casos
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_more_cases() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();
    let witness_charlie = nodes[3].api.clone();
    let witness_dali = nodes[4].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![
            &witness_alice,
            &witness_bob,
            &witness_charlie,
            &witness_dali,
        ],
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
                },
                {
                    "name": "Dali",
                    "key": witness_dali.public_key()
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
                        "Alice", "Bob", "Charlie", "Dali"
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
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses", "Dali"],
                                },
                                {
                                    "name": "Charlie",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
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

    // T44: Cadena A→B→C. N testigo solo de B (actual_lo <= B.interval.hi). C es actual owner.
    //      → acceso hasta old_data_B.sn (no hasta data.sn de C)
    //
    // Secuencia:
    //   A crea subject, emite facts (sn=3), transfiere a B (old_data_A.sn=3)
    //   B emite facts (sn=6), transfiere a C (old_data_B.sn=6)
    //   C emite facts (sn=9, data.sn=9)
    //   witness_node: testigo activo de B (actual_lo <= B.interval.hi)
    //   witness_node: NO testigo de A ni de C
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=6 (old_data_B.sn)
    let (subject_id_1, ..) = create_subject(
        &witness_alice,
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
    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });
    emit_fact(&witness_bob, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_bob,
        subject_id_1.clone(),
        PublicKey::from_str(&witness_charlie.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_charlie
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_1.clone(), Some(5))
        .await
        .unwrap();

    emit_confirm(&witness_charlie, subject_id_1.clone(), None, true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 300,
        }
    });
    emit_fact(&witness_charlie, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(2))
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(5))
        .await
        .unwrap();
    let _state = get_subject(&witness_dali, subject_id_1.clone(), Some(5))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_1.clone(), Some(7))
        .await
        .unwrap();

    nodes[4].token.cancel();
    join_all(nodes[4].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (mut node_new_dali, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
        Some(nodes[4].keys.clone()),
    )
    .await;
    let new_dali = node_new_dali.api;
    node_running(&new_dali).await.unwrap();

    assert!(
        new_dali
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_dali
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_dali, governance_id.clone(), Some(1))
        .await
        .unwrap();

    assert!(
        new_dali
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_dali
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali.update_subject(subject_id_1.clone()).await.unwrap();

    let _state = get_subject(&new_dali, subject_id_1.clone(), Some(6))
        .await
        .unwrap();

    // T47: A→B reject. B en old_owners. N testigo activo de B con actual_lo <= B.interval.hi
    //      → acceso hasta old_data_B.sn
    //
    // Secuencia:
    //   gov_v1: witness_node testigo de B (actual_lo=gov_v1)
    //   gov_v3: A crea subject (data.gov_version=gov_v3)
    //   emite facts (sn=5)
    //   gov_v5: A transfiere a B (new_owner_gov_version=gov_v5)
    //   gov_v6: B rechaza (old_data_B.sn=5, B.interval=[gov_v5, gov_v6])
    //           actual_lo=gov_v1 <= range.hi=gov_v6 → TRUE → acceso
    //   A continúa como owner, emite facts (sn=8)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=5 (old_data_B.sn tras reject)

    let (subject_id_2, ..) = create_subject(
        &witness_alice,
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
    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
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

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(3))
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

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(4))
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(3))
        .await
        .unwrap();
    let _state = get_subject(&new_dali, subject_id_2.clone(), Some(3))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    node_new_dali.token.cancel();
    join_all(node_new_dali.handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: owner.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_dali, _dirs) = create_node(
        NodeType::Addressable,
        &listen_address,
        peers,
        true,
        false,
        Some(node_new_dali.keys.clone()),
    )
    .await;
    let new_dali = node_new_dali.api;
    node_running(&new_dali).await.unwrap();

    assert!(
        new_dali
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );

    new_dali
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_dali, governance_id.clone(), Some(1))
        .await
        .unwrap();

    assert!(
        new_dali
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_dali
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&new_dali, subject_id_2.clone(), Some(3))
        .await
        .unwrap();

    // T49: N es old_owner + testigo activo de A(actual) + testigo de B(old owner)
    //      → data.sn (testigo activo de A cortocircuita, es el máximo posible)
    //
    // Secuencia:
    //   gov_v1: witness_node (N) añadido como testigo activo de A y de B
    //   N crea subject (N es owner, gov_version=gov_v1)
    //   N emite fact
    //   N transfiere a B, B confirma (old_data_N.sn guardado)
    //   B emite fact
    //   B transfiere a A, A confirma (old_data_B.sn guardado)
    //   A emite fact (data.sn = sn actual)
    //
    // Verificación:
    //   N.auth_subject → recibe hasta data.sn
    //   (check_current_owner para A devuelve ActualSearch::End inmediatamente,
    //    sin evaluar el rol de old_owner ni el testigo de B)

    let json = json!({
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Charlie",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Witnesses", "Alice"]
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

    let (subject_id_3, ..) = create_subject(
        &witness_alice,
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
    emit_fact(&witness_alice, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
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

    let json = json!({
        "ModOne": {
            "data": 200,
        }
    });
    emit_fact(&witness_bob, subject_id_3.clone(), json, true)
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

    let json = json!({
        "ModOne": {
            "data": 300,
        }
    });
    emit_fact(&witness_charlie, subject_id_3.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_3.clone(), Some(7))
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(5))
        .await
        .unwrap();
    let _state = get_subject(&new_dali, subject_id_3.clone(), Some(5))
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(7))
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
        false,
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

    let _state = get_subject(&new_alice, governance_id.clone(), Some(2))
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

    let _state = get_subject(&new_alice, subject_id_3.clone(), Some(7))
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 14 — Tests para bugs nuevos (A, B, C)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_more_cases_2() {
    let (mut nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0], vec![0]],
        vec![],
        true,
        false,
    )
    .await;
    let owner = nodes[0].api.clone();
    let witness_alice = nodes[1].api.clone();
    let witness_bob = nodes[2].api.clone();
    let witness_charlie = nodes[3].api.clone();

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![&witness_alice, &witness_bob, &witness_charlie],
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
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": ["Witnesses"],
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
                            ]
                        }

                }
            ]
        }
    });

    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // T51: Bug A — N testigo explícito de A con intervalo cerrado [gov_v5, gov_v7],
    //      A owner desde gov_v3 (owner_gov_version < range.lo).
    //      Condición: owner_gov_version(v3) <= range.hi(v7) → TRUE → acceso hasta sn@gov_v7
    //
    // Este caso NO estaba cubierto antes del fix: range.contains(gov_v3) sobre [v5,v7]
    // daba false porque v3 < v5=range.lo, haciendo creer que no había acceso.
    //
    // Secuencia:
    //   gov_v3: owner_node crea el subject (owner_gov_version=gov_v3, sn=0)
    //   gov_v3→gov_v4: owner emite 3 facts (sn=3)
    //   gov_v5: witness_node añadido como testigo explícito de owner_node (actual_lo=gov_v5)
    //   gov_v5→gov_v6: owner emite 2 facts más (sn=5)
    //   gov_v7: witness_node eliminado → intervalo [gov_v5, gov_v6]; sn en ese momento = 5
    //   gov_v8: owner emite más facts (sn=8)
    //
    // Verificación:
    //   witness_node.auth_subject → recibe hasta sn=5 (sn@gov_v7), no sn=8
    //
    // Con el bug (range.contains): gov_v3 no está en [gov_v5,gov_v6] → sin acceso (INCORRECTO)
    // Con el fix (<=range.hi): gov_v3 <= gov_v6 → acceso hasta sn=5 (CORRECTO)

    let (subject_id_1, ..) = create_subject(
        &witness_alice,
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

    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
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
                                    "new_witnesses": ["Witnesses", "Charlie"]
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

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(3))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(3))
        .await
        .unwrap();

    let _state = get_subject(&witness_charlie, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

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
        false,
        Some(nodes[3].keys.clone()),
    )
    .await;
    let new_charlie = node_new_charlie.api.clone();
    node_running(&new_charlie).await.unwrap();

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

    let _state = get_subject(&new_charlie, governance_id.clone(), Some(3))
        .await
        .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_charlie
        .auth_subject(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_1.clone(), Some(2))
        .await
        .unwrap();

    // T52: Bug B — A→B reject. Witness de B activo SOLO antes de que se propusiese la transfer.
    //      Con el fix, B.interval=[new_owner_gov_version, reject_gov_version].
    //      El testigo no solapa ese intervalo → sin acceso (CORRECTO).
    //      Sin el fix, B.interval=[data.gov_version, reject_gov_version] → solapa → acceso (INCORRECTO).
    //
    // Secuencia:
    //   gov_v2: A crea el subject (data.gov_version=gov_v2)
    //   gov_v2→gov_v4: A emite facts (sn=4)
    //   gov_v4: witness_node añadido como testigo de B (actual_lo=gov_v4)
    //   gov_v5: witness_node eliminado como testigo de B → intervalo [gov_v4, gov_v4]
    //   gov_v5→gov_v6: A emite más facts (sn=6)
    //   gov_v7: A propone transfer a B (new_owner_gov_version=gov_v7)
    //   gov_v7→gov_v8: A emite más facts (sn=8, este es el sn en el reject)
    //   gov_v9: B rechaza → B.interval=[gov_v7, gov_v9] (con fix); sn@reject=8 → old_data_B.sn=8
    //           witness intervalo [gov_v4,gov_v4] NO solapa [gov_v7,gov_v9] → sin acceso
    //   A continúa, emite facts (sn=10)
    //
    // Verificación:
    //   witness_node.auth_subject → sin acceso (no debe recibir el sujeto)
    //
    // Sin el fix: B.interval=[gov_v2,gov_v9] → [gov_v4,gov_v4] SÍ solapa → acceso hasta sn=8 (INCORRECTO)
    let (subject_id_2, ..) = create_subject(
        &witness_alice,
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

    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
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
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Witnesses", "Charlie"]
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
        "roles": {
            "schema":
                [
                {
                    "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
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

    emit_fact(&witness_alice, subject_id_2.clone(), json, true)
        .await
        .unwrap();

    emit_transfer(
        &witness_alice,
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

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(3))
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

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(4))
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

    let _state = get_subject(&witness_alice, subject_id_2.clone(), Some(5))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(5))
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4))
        .await
        .unwrap();

    new_charlie
        .auth_subject(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        new_charlie
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 14 — Tests para bugs nuevos (A, B, C)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_more_cases_3() {
    let (nodes, _dirs) = create_nodes_and_connections(
        vec![vec![]],
        vec![vec![0], vec![0]],
        vec![],
        true,
        false,
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
                        "Alice"
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
                                    "witnesses": [],
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

    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
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

    let json = json!({
        "ModOne": {
            "data": 100,
        }
    });

    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    // add node bootstrap and ephemeral to governance
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Bob",
                    "key": witness_bob.public_key()
                },
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "Bob"
                    ]
                }
            },
            "schema":
                [
                {
                    "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": ["Witnesses", "Bob"]
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

    // add node bootstrap and ephemeral to governance
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
                                    "new_witnesses": ["Witnesses", "Bob", "Owner"]
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
            "data": 100,
        }
    });

    emit_fact(&witness_alice, subject_id_1.clone(), json, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_alice, subject_id_1.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4))
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(4))
        .await
        .unwrap();
}
