mod common;

use ave_common::identity::keys::Ed25519Signer;
use ave_common::identity::{DigestIdentifier, KeyPair, PublicKey};
use ave_core::auth::AuthWitness;
use common::{
    EXAMPLE_CONTRACT, create_and_authorize_governance,
    create_nodes_and_connections, create_subject, emit_confirm, emit_fact,
    emit_reject, emit_transfer, get_events, get_subject,
};

use ave_core::{
    Api,
    helpers::network::{
        ActorMessage, NetworkMessage,
        test_faults::{FaultAction, FaultDirection, FaultMessage, FaultRule},
    },
};
use ave_network::{ComunicateInfo, NodeType, RoutingNode};
use futures::future::join_all;
use serde_json::json;
use std::time::Duration;
use std::{str::FromStr, sync::atomic::Ordering};
use test_log::test;

use crate::common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig, PORT_COUNTER,
    create_node, node_running,
};

#[test(tokio::test)]
// Recibe la copia de un sujeto sin tener la gobernanza
async fn test_witeness_not_gov() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Bob", "viewpoints": ["AllViewpoints"]}, {"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(
                PublicKey::from_str(witness_alice.public_key()).unwrap(),
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
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Owner", "viewpoints": ["AllViewpoints"]}],
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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

    let state = get_subject(witness_alice, subject_id_1.clone(), Some(0), true)
        .await
        .unwrap();

    assert_eq!(state.genesis_gov_version, 2);

    witness_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(
                PublicKey::from_str(witness_alice.public_key()).unwrap(),
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
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(
                PublicKey::from_str(witness_alice.public_key()).unwrap(),
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
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Owner", "viewpoints": ["AllViewpoints"]}],
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1), true)
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

    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(1), true)
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
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(1), true)
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
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2), true)
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
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_1.clone(), Some(2), true)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 3 — Old owner sin testigos
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_basic_transfers() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(2), true)
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_3.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(3), true)
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

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();
    let _state =
        get_subject(witness_alice, subject_id_3.clone(), Some(3), true)
            .await
            .unwrap();

    witness_alice
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state =
        get_subject(witness_alice, subject_id_3.clone(), Some(3), true)
            .await
            .unwrap();

    emit_transfer(
        &witness_bob,
        subject_id_3.clone(),
        PublicKey::from_str(witness_charlie.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_charlie
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_3.clone(), Some(5), true)
            .await
            .unwrap();

    emit_confirm(&witness_charlie, subject_id_3.clone(), None, true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_3.clone(), Some(6), true)
            .await
            .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(6), true)
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

    let _state =
        get_subject(&witness_charlie, subject_id_3.clone(), Some(7), true)
            .await
            .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(7), true)
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(6), true)
        .await
        .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(6), true)
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2), true)
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id_1.clone(), None, true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_1.clone(), Some(3), true)
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

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();
    let _state =
        get_subject(witness_alice, subject_id_1.clone(), Some(3), true)
            .await
            .unwrap();

    witness_alice
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();
    let _state =
        get_subject(witness_alice, subject_id_1.clone(), Some(3), true)
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(2), true)
        .await
        .unwrap();

    emit_reject(&witness_bob, subject_id_2.clone(), true)
        .await
        .unwrap();

    witness_alice
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();
    let _state =
        get_subject(witness_alice, subject_id_2.clone(), Some(3), true)
            .await
            .unwrap();
    let _state = get_subject(&owner, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();

    let json = json!({
        "ModOne": {
            "data": 205,
        }
    });
    emit_fact(witness_alice, subject_id_2.clone(), json, true)
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

    let (node_new_bob, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_2.clone(), Some(3), true)
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

    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
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

    let (node_new_charlie, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[3].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert!(
        new_alice
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_alice
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&new_alice, subject_id_3.clone(), Some(3), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_3.clone()).await.unwrap();
    let _state = get_subject(&new_bob, subject_id_3.clone(), Some(6), true)
        .await
        .unwrap();

    assert!(
        new_charlie
            .get_subject_state(governance_id.clone())
            .await
            .is_err()
    );
    new_charlie
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    assert!(
        new_charlie
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_charlie
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();
    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(7), true)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 4 — Testigo explícito del owner actual (pure witness)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_basic_explicit_witness() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Bob", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Alice",
                                    "namespace": ["Test2"],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Bob", "viewpoints": ["AllViewpoints"]}],
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

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1), true)
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
                                },
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(2), true)
            .await
            .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1), true)
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

    let (node_new_bob, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_1.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_1.clone(), Some(1), true)
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
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
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
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(1), true)
            .await
            .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(1), true)
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

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(1), true)
            .await
            .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(1), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1), true)
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

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(2), true)
            .await
            .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(2), true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(1), true)
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

    let (node_new_bob, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_2.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_1.clone()).await.unwrap();

    let _state = get_subject(&new_bob, subject_id_1.clone(), Some(1), true)
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
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
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
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Alice", "viewpoints": ["AllViewpoints"]}, {"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(4), true)
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_3.clone(), Some(4), true)
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(5), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_3.clone(), Some(5), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_3.clone(), Some(4), true)
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

    let (mut node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    assert!(
        new_alice
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_alice
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();

    assert!(
        new_alice
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_alice
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_1.clone(), Some(4), true)
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(2), true)
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

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();

    new_alice
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();
    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(3), true)
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

    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(node_new_alice.keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    assert!(
        new_alice
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_alice
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 7 — Acceso via testigos de owners históricos
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_explicit_witness_2() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Charlie", "viewpoints": ["AllViewpoints"]}, {"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(3), true)
            .await
            .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_1.clone(), Some(2), true)
            .await
            .unwrap();

    witness_charlie
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_1.clone(), Some(3), true)
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(3), true)
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Charlie", "viewpoints": ["AllViewpoints"]}]
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
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_3.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_3.clone(), Some(3), true)
            .await
            .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_3.clone(), Some(1), true)
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

    let (node_new_charlie, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[3].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie, governance_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_charlie
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(1), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
async fn test_explicit_witness_2_1() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Charlie", "viewpoints": ["AllViewpoints"]}, {"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_4.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_4.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_4.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_4.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_4.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_4.clone(), Some(3), true)
            .await
            .unwrap();

    assert!(
        witness_charlie
            .get_subject_state(subject_id_4.clone())
            .await
            .is_err()
    );

    witness_charlie
        .authorize_governance(
            subject_id_4.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_4.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        witness_charlie
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
                                    "new_witnesses": [{"name": "Owner", "viewpoints": ["AllViewpoints"]}]
                                },
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": ["Test2"],
                                    "new_witnesses": [{"name": "Owner", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_5.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_5.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_5.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_5.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_5.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_5.clone(), Some(3), true)
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
        witness_charlie
            .get_subject_state(subject_id_5.clone())
            .await
            .is_err()
    );

    witness_charlie
        .authorize_governance(
            subject_id_5.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_5.clone())
        .await
        .unwrap();

    tokio::time::sleep(Duration::from_secs(3)).await;

    assert!(
        witness_charlie
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_6.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_6.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_6.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_6.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_6.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_6.clone(), Some(3), true)
            .await
            .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_6.clone(), Some(2), true)
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

    let (node_new_charlie_2, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[3].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie_2
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie_2, governance_id.clone(), Some(4), true)
            .await
            .unwrap();

    assert!(
        new_charlie_2
            .get_subject_state(subject_id_6.clone())
            .await
            .is_err()
    );
    new_charlie_2
        .authorize_governance(
            subject_id_6.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie_2
        .update_subject(subject_id_6.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie_2, subject_id_6.clone(), Some(3), true)
            .await
            .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 9 — Caso clave del fix: range.hi en lugar de owner_gov_version
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_range() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Bob", "viewpoints": ["AllViewpoints"]}],
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Bob", "viewpoints": ["AllViewpoints"]}],
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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

    let (node_new_bob, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(governance_id.clone()).await.unwrap();

    let _state = get_subject(&new_bob, governance_id.clone(), Some(6), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_1.clone()).await.unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(2), true)
        .await
        .unwrap();
    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(2), true)
            .await
            .unwrap();
    let _state = get_subject(&new_bob, subject_id_1.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        new_bob
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_bob.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1), true)
        .await
        .unwrap();
    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(1), true)
            .await
            .unwrap();
    let _state = get_subject(&new_bob, subject_id_2.clone(), Some(0), true)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 10 — Namespace y Schema matching
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_ns_schema() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {
                        "one": 0,
                        "two": 0,
                        "three": 0
                    }
                },
                {
                    "id": "Example1",
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Alice",
                                    "namespace": ["Org"],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(1), true)
        .await
        .unwrap();
    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(1), true)
        .await
        .unwrap();
    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(1), true)
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
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(1), true)
        .await
        .unwrap();
    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(1), true)
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
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(1), true)
        .await
        .unwrap();

    // T35: N testigo para schema "SchemaA", sujeto con schema "SchemaB" → sin acceso
    witness_charlie
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
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
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Alice", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(4), true)
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

    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    assert!(
        new_alice
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_alice
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_1.clone(), Some(4), true)
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
                                    "new_witnesses": [{"name": "Owner", "viewpoints": ["AllViewpoints"]}, {"name": "Charlie", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(2), true)
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

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_2.clone(), Some(4), true)
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

    let (mut node_new_charlie, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[3].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie, governance_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_charlie
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_2.clone(), Some(4), true)
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

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(1), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_3.clone(), Some(1), true)
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(1), true)
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
                                    "new_witnesses": [{"name": "Owner", "viewpoints": ["AllViewpoints"]}]
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

    let (node_new_charlie, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(node_new_charlie.keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie, governance_id.clone(), Some(4), true)
            .await
            .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_charlie
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_3.clone(), Some(1), true)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 13 — Más casos
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_more_cases() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Dali", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Charlie",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(2), true)
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
        PublicKey::from_str(witness_charlie.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_charlie
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_charlie
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_1.clone(), Some(5), true)
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

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(3), true)
            .await
            .unwrap();
    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(6), true)
        .await
        .unwrap();
    let _state =
        get_subject(&witness_dali, subject_id_1.clone(), Some(5), true)
            .await
            .unwrap();
    let _state = get_subject(&owner, subject_id_1.clone(), Some(7), true)
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

    let (mut node_new_dali, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[4].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_dali, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        new_dali
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_dali
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali.update_subject(subject_id_1.clone()).await.unwrap();

    let _state = get_subject(&new_dali, subject_id_1.clone(), Some(6), true)
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(2), true)
        .await
        .unwrap();

    emit_reject(&witness_bob, subject_id_2.clone(), true)
        .await
        .unwrap();

    witness_alice
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(3), true)
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

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(4), true)
            .await
            .unwrap();
    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(&new_dali, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();
    let _state = get_subject(&owner, subject_id_2.clone(), Some(4), true)
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

    let (node_new_dali, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(node_new_dali.keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_dali, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        new_dali
            .get_subject_state(subject_id_2.clone())
            .await
            .is_err()
    );
    new_dali
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_dali.update_subject(subject_id_2.clone()).await.unwrap();

    let _state = get_subject(&new_dali, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
async fn test_more_cases_1_1() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Dali", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Charlie",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Alice", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(2), true)
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

    witness_charlie
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    emit_transfer(
        &witness_bob,
        subject_id_3.clone(),
        PublicKey::from_str(witness_charlie.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_3.clone(), Some(5), true)
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

    let _state =
        get_subject(&witness_alice, subject_id_3.clone(), Some(7), true)
            .await
            .unwrap();
    let _state = get_subject(&witness_bob, subject_id_3.clone(), Some(6), true)
        .await
        .unwrap();
    let _state =
        get_subject(&witness_dali, subject_id_3.clone(), Some(5), true)
            .await
            .unwrap();
    let _state = get_subject(&owner, subject_id_3.clone(), Some(7), true)
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

    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    assert!(
        new_alice
            .get_subject_state(subject_id_3.clone())
            .await
            .is_err()
    );
    new_alice
        .authorize_governance(
            subject_id_3.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_alice
        .update_subject(subject_id_3.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_alice, subject_id_3.clone(), Some(7), true)
        .await
        .unwrap();
}

// ─────────────────────────────────────────────────────────────────────────────
// BLOQUE 14 — Tests para bugs nuevos (A, B, C)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_more_cases_2() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Charlie", "viewpoints": ["AllViewpoints"]}]
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(3), true)
            .await
            .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(3), true)
        .await
        .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id_1.clone(), Some(2), true)
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

    let (node_new_charlie, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[3].keys.clone()),
        ..Default::default()
    })
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
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(governance_id.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&new_charlie, governance_id.clone(), Some(3), true)
            .await
            .unwrap();

    assert!(
        new_charlie
            .get_subject_state(subject_id_1.clone())
            .await
            .is_err()
    );
    new_charlie
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    new_charlie
        .update_subject(subject_id_1.clone())
        .await
        .unwrap();

    let _state = get_subject(&new_charlie, subject_id_1.clone(), Some(2), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
async fn test_more_cases_2_1() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}],
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Charlie", "viewpoints": ["AllViewpoints"]}]
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}]
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
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    witness_bob
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_bob
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(3), true)
        .await
        .unwrap();

    emit_reject(&witness_bob, subject_id_2.clone(), true)
        .await
        .unwrap();

    witness_alice
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    witness_alice
        .update_subject(subject_id_2.clone())
        .await
        .unwrap();

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(4), true)
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

    let _state =
        get_subject(&witness_alice, subject_id_2.clone(), Some(5), true)
            .await
            .unwrap();

    let _state = get_subject(&owner, subject_id_2.clone(), Some(5), true)
        .await
        .unwrap();

    let _state = get_subject(&witness_bob, subject_id_2.clone(), Some(4), true)
        .await
        .unwrap();

    witness_charlie
        .authorize_governance(
            subject_id_2.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
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
// BLOQUE 14 — Tests para bugs nuevos (A, B, C)
// ─────────────────────────────────────────────────────────────────────────────
#[test(tokio::test)]
async fn test_more_cases_3() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                    "contract": EXAMPLE_CONTRACT,
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Bob", "viewpoints": ["AllViewpoints"]}]
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
                                    "new_witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Bob", "viewpoints": ["AllViewpoints"]}, {"name": "Owner", "viewpoints": ["AllViewpoints"]}]
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

    let _state =
        get_subject(&witness_alice, subject_id_1.clone(), Some(4), true)
            .await
            .unwrap();

    let _state = get_subject(&witness_bob, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();

    let _state = get_subject(&owner, subject_id_1.clone(), Some(4), true)
        .await
        .unwrap();
}

#[test(tokio::test)]
// Ownership encadenado con varios old_owners y cambios de Witnesses entre medias.
//
// Secuencia:
//   - Alice crea el subject y emite un fact.
//   - Alice transfiere a Bob y Bob confirma.
//   - Bob emite un fact.
//   - Se quita `Witnesses` de Bob y se añade tarde a Alice, cuando Alice ya
//     es old_owner.
//   - Bob transfiere a Charlie y Charlie confirma.
//   - Charlie emite un fact.
//
// Verificación:
//   - Dali, como schema witness, solo debe recuperar el tramo real en el que
//     Bob estuvo autorizado con `Witnesses`.
//   - El grant tardío sobre Alice no debe reabrir su histórico de old_owner.
//   - El corte exacto debe quedar en sn=4.
async fn test_chained_old_owners_witness_range_cut() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
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
                        "Alice",
                        "Bob",
                        "Charlie",
                        "Dali"
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
                                "name": "Dali",
                                "namespace": []
                            },
                        ],
                        "creator": [
                            {
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            },
                            {
                                "name": "Bob",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ]
                            },
                            {
                                "name": "Charlie",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Owner",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ]
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

    let _state =
        get_subject(&witness_alice, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&witness_bob, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&witness_charlie, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let _state =
        get_subject(&witness_dali, governance_id.clone(), Some(1), true)
            .await
            .unwrap();

    let (subject_id, ..) = create_subject(
        &witness_alice,
        governance_id.clone(),
        "Example",
        "",
        true,
    )
    .await
    .unwrap();

    emit_fact(
        &witness_alice,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 100
            }
        }),
        true,
    )
    .await
    .unwrap();

    emit_transfer(
        &witness_alice,
        subject_id.clone(),
        PublicKey::from_str(witness_bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state = get_subject(&witness_bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();

    emit_confirm(&witness_bob, subject_id.clone(), None, true)
        .await
        .unwrap();

    emit_fact(
        &witness_bob,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 200
            }
        }),
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Alice",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ]
                            },
                            {
                                "actual_name": "Bob",
                                "actual_namespace": [],
                                "new_witnesses": []
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

    emit_transfer(
        &witness_bob,
        subject_id.clone(),
        PublicKey::from_str(witness_charlie.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id.clone(), Some(5), true)
            .await
            .unwrap();

    emit_confirm(&witness_charlie, subject_id.clone(), None, true)
        .await
        .unwrap();

    emit_fact(
        &witness_charlie,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 300
            }
        }),
        true,
    )
    .await
    .unwrap();

    let _state =
        get_subject(&witness_charlie, subject_id.clone(), Some(7), true)
            .await
            .unwrap();

    let _state = get_subject(&witness_dali, subject_id.clone(), Some(4), true)
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

    let (node_new_dali, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[4].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_dali = node_new_dali.api;
    node_running(&new_dali).await.unwrap();

    new_dali
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_dali
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _state = get_subject(&new_dali, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    new_dali
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_dali.update_subject(subject_id.clone()).await.unwrap();

    let state = get_subject(&new_dali, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    assert_eq!(state.sn, 4);
    assert_eq!(state.owner, witness_bob.public_key());
    assert_eq!(state.new_owner, None);
    assert_eq!(state.creator, witness_alice.public_key());
    assert_eq!(
        state.properties,
        json!({
            "one": 200,
            "two": 0,
            "three": 0
        })
    );
}

#[test(tokio::test)]
// Old-owner historical cuts, case 1 of 3: on/off/on witnesses over
// the same creator must not merge windows before passing to old_owner.
async fn test_old_owner_cut_ranges_disjoint_windows() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let (mut nodes, _dirs) =
            create_nodes_and_connections(CreateNodesAndConnectionsConfig {
                bootstrap: vec![vec![]],
                addressable: vec![vec![0], vec![0], vec![0]],
                always_accept: true,
                ledger_batch_size: Some(1),
                ..Default::default()
            })
            .await;
        let owner = nodes[0].api.clone();
        let witness_alice = nodes[1].api.clone();
        let witness_bob = nodes[2].api.clone();
        let witness_dali = nodes[3].api.clone();

        let governance_id = create_and_authorize_governance(
            &owner,
            vec![&witness_alice, &witness_bob, &witness_dali],
        )
        .await;

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
                        "name": "Dali",
                        "key": witness_dali.public_key()
                    }
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
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
                            "Alice",
                            "Bob",
                            "Dali"
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
                                    "name": "Dali",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Owner",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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

        emit_fact(&owner, governance_id.clone(), json, true)
            .await
            .unwrap();

        let _state =
            get_subject(&witness_alice, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_bob, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_dali, governance_id.clone(), Some(1), true)
                .await
                .unwrap();

        let (subject_id, ..) = create_subject(
            &witness_alice,
            governance_id.clone(),
            "Example",
            "",
            true,
        )
        .await
        .unwrap();

        emit_fact(
            &witness_alice,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 100
                }
            }),
            true,
        )
        .await
        .unwrap();

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": []
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

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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

        emit_fact(
            &witness_alice,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 200
                }
            }),
            true,
        )
        .await
        .unwrap();

        emit_transfer(
            &witness_alice,
            subject_id.clone(),
            PublicKey::from_str(witness_bob.public_key()).unwrap(),
            true,
        )
        .await
        .unwrap();

        let _state =
            get_subject(&witness_bob, subject_id.clone(), Some(3), true)
                .await
                .unwrap();

        emit_confirm(&witness_bob, subject_id.clone(), None, true)
            .await
            .unwrap();

        emit_fact(
            &witness_bob,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 300
                }
            }),
            true,
        )
        .await
        .unwrap();

        let _state =
            get_subject(&witness_bob, subject_id.clone(), Some(5), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_dali, subject_id.clone(), Some(3), true)
                .await
                .unwrap();
        let _state = get_subject(&owner, subject_id.clone(), Some(5), true)
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

        let (node_new_dali, _dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address,
            peers,
            always_accept: true,
            keys: Some(nodes[3].keys.clone()),
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
            .authorize_governance(
                governance_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        new_dali
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        let _state =
            get_subject(&new_dali, governance_id.clone(), Some(3), true)
                .await
                .unwrap();

        assert!(
            new_dali
                .get_subject_state(subject_id.clone())
                .await
                .is_err()
        );

        new_dali
            .authorize_governance(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        new_dali.update_subject(subject_id.clone()).await.unwrap();

        let state = get_subject(&new_dali, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 4);
        assert_eq!(state.owner, witness_bob.public_key());
        assert_eq!(state.new_owner, None);
        assert_eq!(state.creator, witness_alice.public_key());
        assert_eq!(
            state.properties,
            json!({
                "one": 200,
                "two": 0,
                "three": 0
            })
        );
    })
    .await
    .expect("old_owner cut ranges hung (disjoint_windows)");
}

#[test(tokio::test)]
// Old-owner historical cuts, case 2 of 3: explicit witness and schema witness overlap over the same creator unions correctly.
async fn test_old_owner_cut_ranges_explicit_union() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let (mut nodes, _dirs) =
            create_nodes_and_connections(CreateNodesAndConnectionsConfig {
                bootstrap: vec![vec![]],
                addressable: vec![vec![0], vec![0], vec![0]],
                always_accept: true,
                ledger_batch_size: Some(1),
                ..Default::default()
            })
            .await;
        let owner = nodes[0].api.clone();
        let witness_alice = nodes[1].api.clone();
        let witness_bob = nodes[2].api.clone();
        let witness_dali = nodes[3].api.clone();

        let governance_id = create_and_authorize_governance(
            &owner,
            vec![&witness_alice, &witness_bob, &witness_dali],
        )
        .await;

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
                        "name": "Dali",
                        "key": witness_dali.public_key()
                    }
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
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
                            "Alice",
                            "Bob",
                            "Dali"
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
                                    "name": "Dali",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Owner",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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

        emit_fact(&owner, governance_id.clone(), json, true)
            .await
            .unwrap();

        let _state =
            get_subject(&witness_alice, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_bob, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_dali, governance_id.clone(), Some(1), true)
                .await
                .unwrap();

        let (subject_id, ..) = create_subject(
            &witness_alice,
            governance_id.clone(),
            "Example",
            "",
            true,
        )
        .await
        .unwrap();

        emit_fact(
            &witness_alice,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 100
                }
            }),
            true,
        )
        .await
        .unwrap();

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": []
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

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Alice",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Dali",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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

        emit_fact(
            &witness_alice,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 200
                }
            }),
            true,
        )
        .await
        .unwrap();

        emit_transfer(
            &witness_alice,
            subject_id.clone(),
            PublicKey::from_str(witness_bob.public_key()).unwrap(),
            true,
        )
        .await
        .unwrap();

        witness_bob
            .authorize_governance(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        witness_bob
            .update_subject(subject_id.clone())
            .await
            .unwrap();

        let _state =
            get_subject(&witness_bob, subject_id.clone(), Some(3), true)
                .await
                .unwrap();

        emit_confirm(&witness_bob, subject_id.clone(), None, true)
            .await
            .unwrap();

        emit_fact(
            &witness_bob,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 300
                }
            }),
            true,
        )
        .await
        .unwrap();

        let _state =
            get_subject(&witness_bob, subject_id.clone(), Some(5), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_dali, subject_id.clone(), Some(3), true)
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

        let (node_new_dali, _dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address,
            peers,
            always_accept: true,
            keys: Some(nodes[3].keys.clone()),
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
            .authorize_governance(
                governance_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        new_dali
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        let _state =
            get_subject(&new_dali, governance_id.clone(), Some(3), true)
                .await
                .unwrap();

        assert!(
            new_dali
                .get_subject_state(subject_id.clone())
                .await
                .is_err()
        );
        new_dali
            .authorize_governance(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        new_dali.update_subject(subject_id.clone()).await.unwrap();

        let state = get_subject(&new_dali, subject_id.clone(), Some(4), true)
            .await
            .unwrap();
        assert_eq!(state.sn, 4);
        assert_eq!(state.owner, witness_bob.public_key());
        assert_eq!(state.new_owner, None);
        assert_eq!(state.creator, witness_alice.public_key());
        assert_eq!(
            state.properties,
            json!({
                "one": 200,
                "two": 0,
                "three": 0
            })
        );
    })
    .await
    .expect("old_owner cut ranges hung (explicit_union)");
}

#[test(tokio::test)]
// Old-owner historical cuts, case 3 of 3: an ownership chain with reject instead of confirm opens no window on unconsolidated pending ownership.
async fn test_old_owner_cut_ranges_reject_no_window() {
    tokio::time::timeout(Duration::from_secs(180), async {
        let (mut nodes, _dirs) =
            create_nodes_and_connections(CreateNodesAndConnectionsConfig {
                bootstrap: vec![vec![]],
                addressable: vec![vec![0], vec![0], vec![0]],
                always_accept: true,
                ledger_batch_size: Some(1),
                ..Default::default()
            })
            .await;
        let owner = nodes[0].api.clone();
        let witness_alice = nodes[1].api.clone();
        let witness_bob = nodes[2].api.clone();
        let witness_dali = nodes[3].api.clone();

        let governance_id = create_and_authorize_governance(
            &owner,
            vec![&witness_alice, &witness_bob, &witness_dali],
        )
        .await;

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
                        "name": "Dali",
                        "key": witness_dali.public_key()
                    }
                ]
            },
            "schemas": {
                "add": [
                    {
                        "id": "Example",
                        "contract": EXAMPLE_CONTRACT,
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
                            "Alice",
                            "Bob",
                            "Dali"
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
                                    "name": "Dali",
                                    "namespace": []
                                }
                            ],
                            "creator": [
                                {
                                    "name": "Alice",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [
                                        {
                                            "name": "Owner",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": []
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

        emit_fact(&owner, governance_id.clone(), json, true)
            .await
            .unwrap();

        let _state =
            get_subject(&witness_alice, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_bob, governance_id.clone(), Some(1), true)
                .await
                .unwrap();
        let _state =
            get_subject(&witness_dali, governance_id.clone(), Some(1), true)
                .await
                .unwrap();

        let (subject_id, ..) = create_subject(
            &witness_alice,
            governance_id.clone(),
            "Example",
            "",
            true,
        )
        .await
        .unwrap();

        emit_fact(
            &witness_alice,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 100
                }
            }),
            true,
        )
        .await
        .unwrap();

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": []
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

        emit_transfer(
            &witness_alice,
            subject_id.clone(),
            PublicKey::from_str(witness_bob.public_key()).unwrap(),
            true,
        )
        .await
        .unwrap();

        let _state =
            get_subject(&witness_bob, subject_id.clone(), Some(2), true)
                .await
                .unwrap();

        emit_reject(&witness_bob, subject_id.clone(), true)
            .await
            .unwrap();

        let _state =
            get_subject(&witness_alice, subject_id.clone(), Some(3), true)
                .await
                .unwrap();

        let json = json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Bob",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["AllViewpoints"]
                                        }
                                    ]
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

        emit_fact(
            &witness_alice,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": 200
                }
            }),
            true,
        )
        .await
        .unwrap();

        let _state =
            get_subject(&witness_alice, subject_id.clone(), Some(4), true)
                .await
                .unwrap();
        let _state = get_subject(&owner, subject_id.clone(), Some(4), true)
            .await
            .unwrap();

        witness_dali
            .authorize_governance(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        witness_dali
            .update_subject(subject_id.clone())
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            witness_dali
                .get_subject_state(subject_id.clone())
                .await
                .is_err()
        );

        nodes[3].token.cancel();
        join_all(nodes[3].handler.iter_mut()).await;

        let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
        let listen_address = format!("/memory/{}", port);
        let peers = vec![RoutingNode {
            peer_id: owner.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }];

        let (node_new_dali, _dirs) = create_node(CreateNodeConfig {
            node_type: NodeType::Bootstrap,
            listen_address,
            peers,
            always_accept: true,
            keys: Some(nodes[3].keys.clone()),
            ledger_batch_size: Some(1),
            ..Default::default()
        })
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
            .authorize_governance(
                governance_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        new_dali
            .update_subject(governance_id.clone())
            .await
            .unwrap();
        let _state =
            get_subject(&new_dali, governance_id.clone(), Some(4), true)
                .await
                .unwrap();

        assert!(
            new_dali
                .get_subject_state(subject_id.clone())
                .await
                .is_err()
        );
        new_dali
            .authorize_governance(
                subject_id.clone(),
                AuthWitness::One(
                    PublicKey::from_str(owner.public_key()).unwrap(),
                ),
            )
            .await
            .unwrap();
        new_dali.update_subject(subject_id.clone()).await.unwrap();
        tokio::time::sleep(Duration::from_secs(3)).await;
        assert!(
            new_dali
                .get_subject_state(subject_id.clone())
                .await
                .is_err()
        );
    })
    .await
    .expect("old_owner cut ranges hung (reject_no_window)");
}

async fn wait_held(api: &Api, want: usize) {
    for _ in 0..120 {
        if api.test_held_count().await.unwrap_or(0) >= want {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("held messages did not arrive");
}

// DS-LOW-01 probe: a pushed Create for an untracked subject replayed
// to an outsider without governance state. Uses a genuine push held
// from the owner toward a real witness. Currently rejected (missing
// gov actor); the member-non-witness vector stays open.
#[test(tokio::test)]
async fn test_distribution_pushed_create_without_request() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let witness_c = nodes[1].api.clone();
    let outsider = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&witness_c, &outsider])
            .await;

    let json = json!({
        "members": {
            "add": [
                {"name": "C", "key": nodes[1].api.public_key()},
                {"name": "Out", "key": nodes[2].api.public_key()},
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0}
                }
            ]
        },
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "C", "namespace": []}],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity"
                            }
                        ],
                        "issuer": [{"name": "Owner", "namespace": []}]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Hold the owner's auto-push so the genuine Create can be replayed.
    owner
        .test_install_fault(FaultRule {
            direction: FaultDirection::Outbound,
            message: FaultMessage::DistributionLastEventReq,
            peer: None,
            remaining: None,
            action: FaultAction::Hold,
        })
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(&owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    wait_held(&owner, 1).await;

    let create = owner
        .test_held_outbound()
        .await
        .unwrap()
        .into_iter()
        .find_map(|m| match m.message {
            ActorMessage::DistributionLastEventReq { ledger } => Some(ledger),
            _ => None,
        })
        .expect("a create push must have been held");

    let outsider_key = PublicKey::from_str(outsider.public_key()).unwrap();
    let owner_key = PublicKey::from_str(owner.public_key()).unwrap();
    outsider
        .test_inject_inbound(
            NetworkMessage::new(
                ComunicateInfo {
                    request_id: String::new(),
                    version: 0,
                    receiver: outsider_key,
                    receiver_actor: format!(
                        "/user/node/distributor_{subject_id}"
                    ),
                },
                ActorMessage::DistributionLastEventReq { ledger: create },
            ),
            &owner_key,
        )
        .await
        .unwrap();

    // Negative window: without a "did I ask" check the push applies.
    tokio::time::sleep(Duration::from_secs(5)).await;
    assert!(
        outsider
            .get_subject_state(subject_id.clone())
            .await
            .is_err(),
        "unprompted push must not create a tracker"
    );
}

// Auxiliary-transfer provenance plus the direct-right floor.
//
// s1 (A->B, single transfer): N is B's explicit witness through a
// grant closed right after the transfer era. N's first copy runs
// with batch size 1, so the Create batch must carry the installing
// transfer as auxiliary, attributed to B. Without that provenance
// the copy stalls at Create.
//
// s4 (kept by Alice): Alice's creator-Witnesses grant is closed
// early, leaving a finite witness candidate below her direct right
// as actual owner. A fresh node with her keys (new device) must
// still copy up to the tip via the ownership floor.
#[test(tokio::test)]
async fn test_witness_copy_transfer_aux_second_owner() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = &nodes[1].api;
    let bob = nodes[2].api.clone();
    let nadia = &nodes[3].api;

    let governance_id =
        create_and_authorize_governance(&owner, vec![alice, &bob, nadia]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": bob.public_key()
                },
                {
                    "name": "Nadia",
                    "key": nadia.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
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
                        "Alice", "Bob", "Nadia"
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
                                    "name": "Alice",
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
                                    "witnesses": [{"name": "Witnesses", "viewpoints": ["AllViewpoints"]}, {"name": "Nadia", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Bob",
                                    "namespace": [],
                                    "quantity": "infinity",
                                    "witnesses": [{"name": "Nadia", "viewpoints": ["AllViewpoints"]}],
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

    // s1: Alice creates, transfers to Bob, Bob confirms and emits.
    let (subject_id_1, ..) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_transfer(
        alice,
        subject_id_1.clone(),
        PublicKey::from_str(bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    bob.authorize_governance(
        subject_id_1.clone(),
        AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id_1.clone()).await.unwrap();
    let _state = get_subject(&bob, subject_id_1.clone(), Some(1), true)
        .await
        .unwrap();

    emit_confirm(&bob, subject_id_1.clone(), None, true)
        .await
        .unwrap();

    emit_fact(
        &bob,
        subject_id_1.clone(),
        json!({
            "ModOne": {
                "data": 300
            }
        }),
        true,
    )
    .await
    .unwrap();

    // s4: Alice creates and keeps; used later for the new-device copy.
    let (subject_id_4, ..) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact(
        alice,
        subject_id_4.clone(),
        json!({
            "ModOne": {
                "data": 301
            }
        }),
        true,
    )
    .await
    .unwrap();
    emit_fact(
        alice,
        subject_id_4.clone(),
        json!({
            "ModOne": {
                "data": 302
            }
        }),
        true,
    )
    .await
    .unwrap();

    // Close Nadia's grant under Bob (finite second-owner witness).
    // Nadia keeps her grant under Alice: she is the designated
    // server for s4 later, so her access there must stay open.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Bob",
                                "actual_namespace": [],
                                "new_witnesses": []
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

    // Close Alice's creator-Witnesses grant (finite candidate for
    // the actual owner). Nadia's explicit grant stays.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Alice",
                                "actual_namespace": [],
                                "new_witnesses": [{"name": "Nadia", "viewpoints": ["AllViewpoints"]}]
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

    let _state = get_subject(nadia, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    emit_fact(
        alice,
        subject_id_4.clone(),
        json!({
            "ModOne": {
                "data": 303
            }
        }),
        true,
    )
    .await
    .unwrap();

    // The serving Bob must be current before a one-shot copy: he
    // emitted the whole subject, so his register is current by
    // construction. (One-shot updates complete short on a lagging
    // server with no retry, so a synced-but-lagging server must not
    // be the only source.)
    nadia
        .authorize_governance(
            subject_id_1.clone(),
            AuthWitness::One(PublicKey::from_str(bob.public_key()).unwrap()),
        )
        .await
        .unwrap();
    nadia.update_subject(subject_id_1.clone()).await.unwrap();

    let nadia_state = get_subject(nadia, subject_id_1.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(
        nadia_state.properties,
        json!({
            "one": 300,
            "two": 0,
            "three": 0
        })
    );
    let _events = get_events(nadia, subject_id_1.clone(), 4, true)
        .await
        .unwrap();

    // New device with Alice's keys copies s4 up to the tip even
    // though her witness candidate ended at SN 2. Nadia synced the
    // whole subject straight from Alice, so her register is current
    // by construction and she can serve it after Alice is gone.
    nadia
        .authorize_governance(
            subject_id_4.clone(),
            AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
        )
        .await
        .unwrap();
    nadia.update_subject(subject_id_4.clone()).await.unwrap();
    let _state = get_subject(nadia, subject_id_4.clone(), Some(3), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = nadia
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id_4.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 3) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 3),
        "nadia register never mapped s4 tip, got {window:?}"
    );
    let nadia_pk = nadia.public_key().to_owned();

    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;

    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let listen_address = format!("/memory/{}", port);
    let peers = vec![RoutingNode {
        peer_id: nodes[0].api.peer_id().to_string(),
        address: vec![nodes[0].listen_address.clone()],
    }];

    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address,
        peers,
        always_accept: true,
        ledger_batch_size: Some(1),
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_alice = node_new_alice.api;
    node_running(&new_alice).await.unwrap();

    new_alice
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _state = get_subject(&new_alice, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    new_alice
        .authorize_governance(
            subject_id_4.clone(),
            AuthWitness::One(PublicKey::from_str(&nadia_pk).unwrap()),
        )
        .await
        .unwrap();
    new_alice
        .update_subject(subject_id_4.clone())
        .await
        .unwrap();

    let new_state =
        get_subject(&new_alice, subject_id_4.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        new_state.properties,
        json!({
            "one": 303,
            "two": 0,
            "three": 0
        })
    );
}

// Stint-chained auxiliary transfer.
//
// A->B->A->C with Nb as B's witness through a grant closed early:
// the copy caps at SN 3 while Bob's aggregated exit moved on to
// SN 5. Sorting exits would pick transfer SN 4 (above the cap) and
// drop the auxiliary; the stint log attributes SN 1, the transfer
// that opens the first incomplete stint, and the copy proceeds.
#[test(tokio::test)]
async fn test_witness_copy_transfer_aux_stint_chain() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = &nodes[1].api;
    let bob = nodes[2].api.clone();
    let carol = nodes[3].api.clone();
    let nadia_b = &nodes[4].api;

    let governance_id = create_and_authorize_governance(
        &owner,
        vec![alice, &bob, &carol, nadia_b],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice.public_key()
                },
                {
                    "name": "Bob",
                    "key": bob.public_key()
                },
                {
                    "name": "Carol",
                    "key": carol.public_key()
                },
                {
                    "name": "Nb",
                    "key": nadia_b.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
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
                        "Alice", "Bob", "Carol", "Nb"
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
                                    "witnesses": [{"name": "Nb", "viewpoints": ["AllViewpoints"]}],
                                },
                                {
                                    "name": "Carol",
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
                                    "name": "Carol",
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

    let (subject_id, ..) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_transfer(
        alice,
        subject_id.clone(),
        PublicKey::from_str(bob.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    bob.authorize_governance(
        subject_id.clone(),
        AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    let _state = get_subject(&bob, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    emit_confirm(&bob, subject_id.clone(), None, true)
        .await
        .unwrap();

    emit_fact(
        &bob,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 300
            }
        }),
        true,
    )
    .await
    .unwrap();

    // Close Nb's grant while Bob's era is still open; later exits
    // must not move the auxiliary above this cap.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Bob",
                                "actual_namespace": [],
                                "new_witnesses": []
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

    let _state = get_subject(nadia_b, governance_id.clone(), Some(2), true)
        .await
        .unwrap();

    emit_transfer(
        &bob,
        subject_id.clone(),
        PublicKey::from_str(alice.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    alice
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    alice.update_subject(subject_id.clone()).await.unwrap();
    let _state = get_subject(alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();

    emit_confirm(alice, subject_id.clone(), None, true)
        .await
        .unwrap();

    emit_transfer(
        alice,
        subject_id.clone(),
        PublicKey::from_str(carol.public_key()).unwrap(),
        true,
    )
    .await
    .unwrap();

    carol
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    carol.update_subject(subject_id.clone()).await.unwrap();
    let _state = get_subject(&carol, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    emit_confirm(&carol, subject_id.clone(), None, true)
        .await
        .unwrap();

    emit_fact(
        &carol,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 700
            }
        }),
        true,
    )
    .await
    .unwrap();

    // The serving owner must be current before a one-shot copy.
    let _state = get_subject(&owner, subject_id.clone(), Some(8), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = owner
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 8) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 8),
        "owner register never mapped s2 tip, got {window:?}"
    );

    nadia_b
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    nadia_b.update_subject(subject_id.clone()).await.unwrap();

    let nb_state = get_subject(nadia_b, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(
        nb_state.properties,
        json!({
            "one": 300,
            "two": 0,
            "three": 0
        })
    );
    let _events = get_events(nadia_b, subject_id.clone(), 4, true)
        .await
        .unwrap();
}

// Stale-register window.
//
// Advancing governance without tracker events must not invent
// mappings: the version window ends at the last mapped SN instead
// of extending to the requested tip. The witness copy is unaffected
// and grows again once real tracker evidence lands.
#[test(tokio::test)]
async fn test_witness_copy_stale_register_window() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness]).await;

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "W",
                    "key": witness.public_key()
                }
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
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
                        "W"
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
                            }
                        ],
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "W",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ]
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

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    for data in 1..=3 {
        emit_fact(
            owner,
            subject_id.clone(),
            json!({
                "ModOne": {
                    "data": data
                }
            }),
            true,
        )
        .await
        .unwrap();
    }

    // Governance moves on with no tracker events behind it.
    let dummy_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Dummy",
                    "key": dummy_keys.public_key()
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // The window must end at the last mapped SN (3), never extend an
    // unmapped suffix to the requested tip (100).
    let mut window = Vec::new();
    for _ in 0..100 {
        window = owner
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 3) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 == 3),
        "unmapped suffix must not be invented, got {window:?}"
    );
    assert!(window.iter().all(|range| range.1 <= 3));

    // The copy itself is unaffected by the empty gov version.
    witness
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    witness.update_subject(subject_id.clone()).await.unwrap();

    let state = get_subject(witness, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(
        state.properties,
        json!({
            "one": 3,
            "two": 0,
            "three": 0
        })
    );

    // Real tracker evidence under the next version extends the copy.
    emit_fact(
        owner,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 4
            }
        }),
        true,
    )
    .await
    .unwrap();

    witness.update_subject(subject_id.clone()).await.unwrap();

    let state = get_subject(witness, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    assert_eq!(
        state.properties,
        json!({
            "one": 4,
            "two": 0,
            "three": 0
        })
    );

    let mut window = Vec::new();
    for _ in 0..100 {
        window = owner
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 4) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(window.last().is_some_and(|range| range.1 == 4));
}

// Single-witness first copy supervises loss. The first sweep
// request is dropped once; the updater retry plus the round retry
// must still drive the copy to the tip (no Direct fire-and-forget).
#[test(tokio::test)]
async fn test_single_witness_first_copy_survives_request_loss() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let alice = &nodes[1].api;
    let bob = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![alice]).await;

    let json = json!({
        "members": {
            "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Bob", "key": bob.public_key()},
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0}
                }
            ]
        },
        "roles": {
            "governance": {"add": {"witness": ["Alice"]}},
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Bob",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ],
                            }
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    for data in [1, 2, 3] {
        emit_fact(
            alice,
            subject_id.clone(),
            json!({"ModOne": {"data": data}}),
            true,
        )
        .await
        .unwrap();
    }

    bob.authorize_governance(
        governance_id.clone(),
        AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
    )
    .await
    .unwrap();
    bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(bob, governance_id.clone(), None, true)
        .await
        .unwrap();

    // Single witness: Bob copies Alice's subject through Alice only.
    // Drop the first distribution request; the sweep retries it.
    bob.test_install_fault(FaultRule {
        direction: FaultDirection::Outbound,
        message: FaultMessage::DistributionLedgerReq,
        peer: None,
        remaining: Some(1),
        action: FaultAction::Drop,
    })
    .await
    .unwrap();
    bob.authorize_governance(
        subject_id.clone(),
        AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();

    let state = get_subject(bob, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.properties, json!({"one": 3, "two": 0, "three": 0}));
}

// No overlap between creator Witnesses and schema role, no
// access. Witnesses closes at gov 2; Nora gets the schema role at
// gov 3 (phase 1: still open) and loses it at gov 4 (phase 2:
// fully closed afterwards). Neither phase shares a version with
// the closure, so Nora must never register the subject. Marta, a
// schema witness since gov 1, keeps the mapped prefix (control).
#[test(tokio::test)]
async fn test_schema_role_after_witnesses_closure_grants_nothing() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let marta = nodes[2].api.clone();
    let nora = nodes[3].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice, &marta, &nora])
            .await;

    let json = json!({
        "members": {
            "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Marta", "key": marta.public_key()},
                {"name": "Nora", "key": nora.public_key()},
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0}
                }
            ]
        },
        "roles": {
            "governance": {"add": {"witness": ["Alice", "Marta", "Nora"]}},
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [
                            {"name": "Owner", "namespace": []},
                            {"name": "Marta", "namespace": []}
                        ],
                        "creator": [
                            {
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Witnesses",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ],
                            }
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // gov 2: the creator Witnesses membership closes.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Alice",
                                "actual_namespace": [],
                                "new_witnesses": []
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
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 2}}),
        true,
    )
    .await
    .unwrap();

    // Serving-side settle: the owner must hold the event and have
    // mapped it before anyone copies, otherwise a stale offer
    // decides the test instead of the access rules.
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = alice
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 2),
        "alice register never mapped sn 2, got {window:?}"
    );

    // Marta (witness since gov 1) keeps the mapped prefix: control
    // that serving works while Nora gets nothing. Her overlap with
    // the closed Witnesses ([1,1]) ends at gov 1, so she must stop
    // exactly at sn 1.
    for node in [&marta, &nora] {
        node.authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
        node.update_subject(governance_id.clone()).await.unwrap();
    }
    get_subject(&marta, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    get_subject(&nora, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    marta
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
        )
        .await
        .unwrap();
    marta.update_subject(subject_id.clone()).await.unwrap();
    get_subject(&marta, subject_id.clone(), Some(1), true)
        .await
        .unwrap();

    // gov 3: Nora gets the schema role after the closure (phase 1:
    // open schema without overlap).
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "witness": [
                            {"name": "Nora", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 3}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = alice
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 3) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 3),
        "alice register never mapped sn 3, got {window:?}"
    );
    get_subject(&marta, governance_id.clone(), Some(3), true)
        .await
        .unwrap();
    get_subject(&nora, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    // The closure caps Marta at the gov 1 tip even though new
    // events keep arriving: re-requesting must not advance her.
    marta.update_subject(subject_id.clone()).await.unwrap();
    for _ in 0..30 {
        let state = marta.get_subject_state(subject_id.clone()).await.unwrap();
        assert_eq!(state.sn, 1, "closed Witnesses must cap at sn 1");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    nora.authorize_governance(
        subject_id.clone(),
        AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
    )
    .await
    .unwrap();
    nora.update_subject(subject_id.clone()).await.unwrap();
    for _ in 0..30 {
        assert!(
            nora.get_subject_state(subject_id.clone()).await.is_err(),
            "schema role after Witnesses closure must grant nothing"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // gov 4: Nora loses the schema role too (phase 2: closed after
    // the closure). Still no shared version, still nothing.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "witness": [
                            {"name": "Nora", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 4}}),
        true,
    )
    .await
    .unwrap();
    get_subject(&alice, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = alice
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 4) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 4),
        "alice register never mapped sn 4, got {window:?}"
    );
    get_subject(&nora, governance_id.clone(), Some(4), true)
        .await
        .unwrap();

    nora.update_subject(subject_id.clone()).await.unwrap();
    for _ in 0..30 {
        assert!(
            nora.get_subject_state(subject_id.clone()).await.is_err(),
            "fully closed schema role must grant nothing"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node_running(&nora).await.unwrap();

    // Phase 3: Marta gets a second, later schema grant after her
    // first one closes, then loses that too. Only the first
    // interval overlaps the Witnesses closure, so a fresh Marta
    // must still copy exactly the mapped prefix (sn 1) and stop:
    // the newer interval without overlap must not hide it.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "witness": [
                            {"name": "Marta", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&marta, governance_id.clone(), Some(5), true)
        .await
        .unwrap();
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "witness": [
                            {"name": "Marta", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&marta, governance_id.clone(), Some(6), true)
        .await
        .unwrap();
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "remove": {
                        "witness": [
                            {"name": "Marta", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();
    get_subject(&marta, governance_id.clone(), Some(7), true)
        .await
        .unwrap();

    // A fresh Marta (same keys, empty state) must recover exactly
    // the mapped prefix: sn 1, and never advance to the sn 4 tip.
    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node_new_marta, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![RoutingNode {
            peer_id: owner.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_marta = node_new_marta.api;
    node_running(&new_marta).await.unwrap();
    new_marta
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_marta
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&new_marta, governance_id.clone(), Some(7), true)
        .await
        .unwrap();
    new_marta
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_marta.update_subject(subject_id.clone()).await.unwrap();
    let state = get_subject(&new_marta, subject_id.clone(), Some(1), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 1, "second grant must not hide the first prefix");
    for _ in 0..30 {
        let state = new_marta
            .get_subject_state(subject_id.clone())
            .await
            .unwrap();
        assert_eq!(state.sn, 1, "capped prefix must not advance");
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    node_running(&new_marta).await.unwrap();
}

// The aux must be the confirmed installing transfer, never
// the rejected proposal, and it must follow the winning owner
// across stints. Chain: A->B (rejected) then A->C (confirmed).
// Dave (pending via C->Dave) must be offered exactly that
// transfer; then, once Dave confirms and transfers to Erin, Erin
// must be offered exactly Dave's transfer.
#[test(tokio::test)]
async fn test_aux_follows_confirmed_transfer_across_stints() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0], vec![0], vec![0], vec![0]],
            always_accept: true,
            ledger_batch_size: Some(1),
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let alice = &nodes[1].api;
    let bob = &nodes[2].api;
    let carol = &nodes[3].api;
    let dave = &nodes[4].api;
    let erin = &nodes[5].api;

    let governance_id = create_and_authorize_governance(
        owner,
        vec![alice, bob, carol, dave, erin],
    )
    .await;

    let json = json!({
        "members": {
            "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Bob", "key": bob.public_key()},
                {"name": "Carol", "key": carol.public_key()},
                {"name": "Dave", "key": dave.public_key()},
                {"name": "Erin", "key": erin.public_key()},
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0}
                }
            ]
        },
        "roles": {
            "governance": {"add": {"witness": ["Alice", "Bob", "Carol", "Dave", "Erin"]}},
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            },
                            {
                                "name": "Bob",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            },
                            {
                                "name": "Carol",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            },
                            {
                                "name": "Dave",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            },
                            {
                                "name": "Erin",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            }
                        ],
                        "issuer": [{"name": "Alice", "namespace": []}, {"name": "Carol", "namespace": []}]
                    }
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // Everyone syncs the governance once; no roles change after
    // this, so no re-sync is needed later.
    for node in [bob, carol, dave, erin] {
        node.authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
        node.update_subject(governance_id.clone()).await.unwrap();
        get_subject(node, governance_id.clone(), None, true)
            .await
            .unwrap();
    }

    let (subject_id, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();
    let bob_key = PublicKey::from_str(bob.public_key()).unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key, true)
        .await
        .unwrap();

    // Bob copies through his pending transfer, then rejects it.
    bob.authorize_governance(
        subject_id.clone(),
        AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
    )
    .await
    .unwrap();
    bob.update_subject(subject_id.clone()).await.unwrap();
    get_subject(bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    emit_reject(&bob, subject_id.clone(), true).await.unwrap();
    let carol_key = PublicKey::from_str(carol.public_key()).unwrap();
    emit_transfer(&alice, subject_id.clone(), carol_key, true)
        .await
        .unwrap();
    // Carol copies through her pending transfer, then confirms it.
    carol
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
        )
        .await
        .unwrap();
    carol.update_subject(subject_id.clone()).await.unwrap();
    get_subject(carol, subject_id.clone(), Some(4), true)
        .await
        .unwrap();
    emit_confirm(&carol, subject_id.clone(), None, true)
        .await
        .unwrap();
    let dave_key = PublicKey::from_str(dave.public_key()).unwrap();
    emit_transfer(&carol, subject_id.clone(), dave_key, true)
        .await
        .unwrap();
    // sn6 is Dave's installing transfer; sn2 is the rejected one.
    get_subject(&carol, subject_id.clone(), Some(6), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = carol
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 6) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 6),
        "carol register never mapped sn 6, got {window:?}"
    );

    // Phase 1: Dave (pending via Carol) copies with batch size 1.
    // A wrong aux (the rejected sn2 instead of the confirmed sn6,
    // or none) stalls the install, so reaching sn6 proves the
    // first batch carried sn6. Re-request on empty rounds: the
    // server answers only once its witness state lands.
    dave.authorize_governance(
        subject_id.clone(),
        AuthWitness::One(PublicKey::from_str(carol.public_key()).unwrap()),
    )
    .await
    .unwrap();
    for _ in 0..6 {
        if let Err(e) = dave.update_subject(subject_id.clone()).await {
            assert!(
                e.to_string().contains("already in progress"),
                "dave update failed: {e}"
            );
        }
        if dave
            .get_subject_state(subject_id.clone())
            .await
            .is_ok_and(|state| state.sn >= 6)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    get_subject(dave, subject_id.clone(), Some(6), true)
        .await
        .unwrap();

    // Phase 2: Dave confirms and transfers to Erin; reaching
    // sn8 proves the aux followed the winning owner to Dave's
    // transfer instead of stalling on the old one.
    emit_confirm(&dave, subject_id.clone(), None, true)
        .await
        .unwrap();
    let erin_key = PublicKey::from_str(erin.public_key()).unwrap();
    emit_transfer(&dave, subject_id.clone(), erin_key, true)
        .await
        .unwrap();
    get_subject(&dave, subject_id.clone(), Some(8), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = dave
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 8) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 8),
        "dave register never mapped sn 8, got {window:?}"
    );

    erin.authorize_governance(
        subject_id.clone(),
        AuthWitness::One(PublicKey::from_str(dave.public_key()).unwrap()),
    )
    .await
    .unwrap();
    for _ in 0..6 {
        if let Err(e) = erin.update_subject(subject_id.clone()).await {
            assert!(
                e.to_string().contains("already in progress"),
                "erin update failed: {e}"
            );
        }
        if erin
            .get_subject_state(subject_id.clone())
            .await
            .is_ok_and(|state| state.sn >= 8)
        {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    get_subject(erin, subject_id.clone(), Some(8), true)
        .await
        .unwrap();
}

// The direct floor beats a finite witness candidate, for the
// pending new owner and for the old owner. Both creators start
// with a User witness each, closed at gov 2: the surviving
// candidate caps at sn 1. Bob (pending, floor sn 2) and later
// Alice (old owner, floor sn 3) must still copy through it on a
// fresh device holding only their keys.
#[test(tokio::test)]
async fn test_direct_floor_beats_finite_witness_candidate() {
    let (mut nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = nodes[0].api.clone();
    let alice = nodes[1].api.clone();
    let bob = nodes[2].api.clone();

    let governance_id =
        create_and_authorize_governance(&owner, vec![&alice, &bob]).await;

    let json = json!({
        "members": {
            "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Bob", "key": bob.public_key()},
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0}
                }
            ]
        },
        "roles": {
            "governance": {"add": {"witness": ["Alice", "Bob"]}},
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Bob",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ],
                            },
                            {
                                "name": "Bob",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["AllViewpoints"]
                                    }
                                ],
                            }
                        ],
                        "issuer": [
                            {"name": "Alice", "namespace": []},
                            {"name": "Bob", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(&owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let (subject_id, _) =
        create_subject(&alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    emit_fact(
        &alice,
        subject_id.clone(),
        json!({"ModOne": {"data": 1}}),
        true,
    )
    .await
    .unwrap();

    // gov 2: close both User grants. Every witness candidate ends
    // at gov 1 (sn 1); direct rights must carry further.
    let json = json!({
        "roles": {
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Alice",
                                "actual_namespace": [],
                                "new_witnesses": []
                            },
                            {
                                "actual_name": "Bob",
                                "actual_namespace": [],
                                "new_witnesses": []
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

    // sn2: Alice transfers to Bob (pending). Bob's floor is sn 2.
    let bob_key = PublicKey::from_str(bob.public_key()).unwrap();
    emit_transfer(&alice, subject_id.clone(), bob_key, true)
        .await
        .unwrap();
    get_subject(&alice, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = alice
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 2) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 2),
        "alice register never mapped sn 2, got {window:?}"
    );

    // Fresh Bob (pending new owner) copies through the sn 1 cap.
    nodes[2].token.cancel();
    join_all(nodes[2].handler.iter_mut()).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node_new_bob, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![RoutingNode {
            peer_id: owner.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(nodes[2].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_bob = node_new_bob.api;
    node_running(&new_bob).await.unwrap();
    new_bob
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_bob.update_subject(governance_id.clone()).await.unwrap();
    get_subject(&new_bob, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    new_bob
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(alice.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_bob.update_subject(subject_id.clone()).await.unwrap();
    let state = get_subject(&new_bob, subject_id.clone(), Some(2), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 2, "pending floor must beat the sn 1 cap");

    // sn3: Bob confirms. Alice becomes old owner with floor sn 3.
    emit_confirm(&new_bob, subject_id.clone(), None, true)
        .await
        .unwrap();
    get_subject(&new_bob, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    let mut window = Vec::new();
    for _ in 0..100 {
        window = new_bob
            .test_get_gov_version_window(
                governance_id.clone(),
                subject_id.clone(),
                0,
                100,
            )
            .await
            .unwrap();
        if window.last().is_some_and(|range| range.1 >= 3) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(
        window.last().is_some_and(|range| range.1 >= 3),
        "bob register never mapped sn 3, got {window:?}"
    );

    // Fresh Alice (old owner) copies through the sn 1 cap.
    nodes[1].token.cancel();
    join_all(nodes[1].handler.iter_mut()).await;
    let port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (node_new_alice, _dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Bootstrap,
        listen_address: format!("/memory/{port}"),
        peers: vec![RoutingNode {
            peer_id: owner.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(nodes[1].keys.clone()),
        ..Default::default()
    })
    .await;
    let new_alice = node_new_alice.api;
    node_running(&new_alice).await.unwrap();
    new_alice
        .authorize_governance(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    new_alice
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    get_subject(&new_alice, governance_id.clone(), Some(2), true)
        .await
        .unwrap();
    new_alice
        .authorize_governance(
            subject_id.clone(),
            AuthWitness::One(
                PublicKey::from_str(new_bob.public_key()).unwrap(),
            ),
        )
        .await
        .unwrap();
    new_alice.update_subject(subject_id.clone()).await.unwrap();
    let state = get_subject(&new_alice, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(state.sn, 3, "old-owner floor must beat the sn 1 cap");
    node_running(&new_alice).await.unwrap();
}

// Boot-recovery re-sends are idempotent: replaying an applied
// Transfer+Confirm (or Transfer+Reject) pair must not reopen the
// pending transfer, list the owner as their own old owner, or
// duplicate the stint. A legitimate new transfer still applies.
// Boot-recovery re-sends are idempotent: replaying an applied
// Transfer+Confirm (or Transfer+Reject) pair must not reopen the
// pending transfer, list the owner as their own old owner, or
// duplicate the stint. A legitimate new transfer still applies.
#[test(tokio::test)]
async fn test_ownership_replay_is_idempotent() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0], vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let alice = &nodes[1].api;
    let bob = &nodes[2].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![alice, bob]).await;

    let json = json!({
        "members": {
            "add": [
                {"name": "Alice", "key": alice.public_key()},
                {"name": "Bob", "key": bob.public_key()},
            ]
        },
        "schemas": {
            "add": [
                {
                    "id": "Example",
                    "contract": EXAMPLE_CONTRACT,
                    "initial_value": {"one": 0, "two": 0, "three": 0}
                }
            ]
        },
        "roles": {
            "governance": {"add": {"witness": ["Alice", "Bob"]}},
            "schema": [
                {
                    "schema_id": "Example",
                    "add": {
                        "evaluator": [{"name": "Owner", "namespace": []}],
                        "validator": [{"name": "Owner", "namespace": []}],
                        "witness": [{"name": "Owner", "namespace": []}],
                        "creator": [
                            {
                                "name": "Alice",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            },
                            {
                                "name": "Bob",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": []
                            }
                        ],
                        "issuer": [
                            {"name": "Alice", "namespace": []}
                        ]
                    }
                }
            ]
        }
    });
    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    // sn0 creates the register entry (actual owner Alice).
    let (subject_id, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(alice, subject_id.clone(), Some(0), true)
        .await
        .unwrap();

    let bob_key = PublicKey::from_str(bob.public_key()).unwrap();
    let carol_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    let dave_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();

    async fn ownership(
        api: &Api,
        governance_id: &DigestIdentifier,
        subject_id: &DigestIdentifier,
    ) -> (
        Option<PublicKey>,
        Option<PublicKey>,
        Vec<(PublicKey, u64)>,
        usize,
    ) {
        let (owner, pending, mut old, stints) = api
            .test_witnesses_ownership(governance_id, subject_id.clone())
            .await
            .unwrap();
        old.sort_by(|a, b| a.0.to_string().cmp(&b.0.to_string()));
        (owner, pending, old, stints)
    }

    // Legit pair through raw tells, like reconcile sends them.
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id.clone(),
            1,
            bob_key.clone(),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id).await,
        (
            Some(PublicKey::from_str(alice.public_key()).unwrap()),
            Some(bob_key.clone()),
            vec![],
            0
        )
    );
    alice
        .test_witnesses_confirm(&governance_id, subject_id.clone(), 2, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id).await,
        (
            Some(bob_key.clone()),
            None,
            vec![(PublicKey::from_str(alice.public_key()).unwrap(), 2)],
            1,
        )
    );

    // Dirty-boot replay of the same pair: the transfer targets the
    // current owner and the confirm finds no pending transfer, so
    // both are ignored and the state is bit-identical.
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id.clone(),
            1,
            bob_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id.clone(), 2, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id).await,
        (
            Some(bob_key.clone()),
            None,
            vec![(PublicKey::from_str(alice.public_key()).unwrap(), 2)],
            1,
        )
    );

    // A legitimate new transfer still applies afterwards.
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id.clone(),
            3,
            carol_key.clone(),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id).await.1,
        Some(carol_key.clone())
    );
    alice
        .test_witnesses_confirm(&governance_id, subject_id.clone(), 4, 1)
        .await
        .unwrap();
    let (owner, pending, old, stints) =
        ownership(alice, &governance_id, &subject_id).await;
    assert_eq!(owner, Some(carol_key));
    assert_eq!(pending, None);
    assert_eq!(old.len(), 2);
    assert_eq!(stints, 2);

    // Same idempotency for the reject path on a fresh subject.
    let (subject_id2, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(alice, subject_id2.clone(), Some(0), true)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id2.clone(),
            1,
            dave_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_reject(&governance_id, subject_id2.clone(), 2, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id2).await,
        (
            Some(PublicKey::from_str(alice.public_key()).unwrap()),
            None,
            vec![(dave_key.clone(), 2)],
            1,
        )
    );
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id2.clone(),
            1,
            dave_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_reject(&governance_id, subject_id2.clone(), 2, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id2).await,
        (
            Some(PublicKey::from_str(alice.public_key()).unwrap()),
            None,
            vec![(dave_key.clone(), 2)],
            1,
        )
    );

    // An old Confirm replayed while a newer transfer is pending
    // must not consume it: A->B confirmed, B->C pending, then the
    // stale B install is re-sent.
    let (subject_id3, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(alice, subject_id3.clone(), Some(0), true)
        .await
        .unwrap();
    let carol_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id3.clone(),
            1,
            bob_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id3.clone(), 2, 1)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id3.clone(),
            3,
            carol_key.clone(),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id3).await,
        (
            Some(bob_key.clone()),
            Some(carol_key.clone()),
            vec![(PublicKey::from_str(alice.public_key()).unwrap(), 2)],
            1,
        )
    );
    alice
        .test_witnesses_confirm(&governance_id, subject_id3.clone(), 2, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id3).await,
        (
            Some(bob_key.clone()),
            Some(carol_key),
            vec![(PublicKey::from_str(alice.public_key()).unwrap(), 2)],
            1,
        )
    );

    // Same for Reject with a newer pending transfer in flight.
    let (subject_id4, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(alice, subject_id4.clone(), Some(0), true)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id4.clone(),
            1,
            bob_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_reject(&governance_id, subject_id4.clone(), 2, 1)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id4.clone(),
            3,
            dave_key.clone(),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id4).await,
        (
            Some(PublicKey::from_str(alice.public_key()).unwrap()),
            Some(dave_key.clone()),
            vec![(bob_key.clone(), 2)],
            1,
        )
    );
    alice
        .test_witnesses_reject(&governance_id, subject_id4.clone(), 2, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id4).await,
        (
            Some(PublicKey::from_str(alice.public_key()).unwrap()),
            Some(dave_key),
            vec![(bob_key, 2)],
            1,
        )
    );

    // Two completed confirms plus a full replay in order: the
    // historic transfers must not reopen any pending transfer.
    let (subject_id5, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(alice, subject_id5.clone(), Some(0), true)
        .await
        .unwrap();
    let eve_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    let frank_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id5.clone(),
            1,
            eve_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id5.clone(), 2, 1)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id5.clone(),
            3,
            frank_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id5.clone(), 4, 1)
        .await
        .unwrap();
    let before = ownership(alice, &governance_id, &subject_id5).await;
    assert_eq!(before.0, Some(frank_key.clone()));
    assert_eq!(before.1, None);
    assert_eq!(before.3, 2);
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id5.clone(),
            1,
            eve_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id5.clone(), 2, 1)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id5.clone(),
            3,
            frank_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id5.clone(), 4, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id5).await,
        before
    );

    // A new transfer to an already-seen key still opens pending
    // when its sn is new.
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id5.clone(),
            5,
            eve_key.clone(),
            1,
        )
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id5).await.1,
        Some(eve_key)
    );

    // Reject followed by confirm plus a full replay in order:
    // neither the rejected nor the confirmed stint may duplicate.
    let (subject_id6, _) =
        create_subject(alice, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();
    get_subject(alice, subject_id6.clone(), Some(0), true)
        .await
        .unwrap();
    let grace_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    let heidi_key =
        KeyPair::Ed25519(Ed25519Signer::generate().unwrap()).public_key();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id6.clone(),
            1,
            grace_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_reject(&governance_id, subject_id6.clone(), 2, 1)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id6.clone(),
            3,
            heidi_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id6.clone(), 4, 1)
        .await
        .unwrap();
    let before_reject = ownership(alice, &governance_id, &subject_id6).await;
    assert_eq!(before_reject.0, Some(heidi_key.clone()));
    assert_eq!(before_reject.1, None);
    assert_eq!(before_reject.3, 2);
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id6.clone(),
            1,
            grace_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_reject(&governance_id, subject_id6.clone(), 2, 1)
        .await
        .unwrap();
    alice
        .test_witnesses_transfer(
            &governance_id,
            subject_id6.clone(),
            3,
            heidi_key.clone(),
            1,
        )
        .await
        .unwrap();
    alice
        .test_witnesses_confirm(&governance_id, subject_id6.clone(), 4, 1)
        .await
        .unwrap();
    assert_eq!(
        ownership(alice, &governance_id, &subject_id6).await,
        before_reject
    );
}
