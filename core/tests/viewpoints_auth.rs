mod common;

use std::{collections::BTreeSet, str::FromStr, sync::atomic::Ordering};

use ave_common::{
    Namespace, SchemaType,
    bridge::response::{
        TrackerEventVisibilityDB, TrackerEventVisibilityRangeDB,
        TrackerStoredVisibilityDB, TrackerStoredVisibilityRangeDB,
        TrackerVisibilityModeDB,
    },
    identity::{
        PublicKey,
        keys::{Ed25519Signer, KeyPair},
    },
};
use ave_core::auth::AuthWitness;
use ave_core::governance::{
    data::GovernanceData,
    model::{CreatorWitness, RoleCreator},
};
use ave_network::{NodeType, RoutingNode};
use common::{
    CreateNodeConfig, CreateNodesAndConnectionsConfig,
    assert_tracker_fact_full, assert_tracker_fact_opaque,
    assert_tracker_visibility, create_and_authorize_governance, create_node,
    create_nodes_and_connections, create_subject, emit_fact,
    emit_fact_viewpoints, get_events, get_subject, node_running,
};
use serde_json::{from_value, json};
use test_log::test;

use crate::common::PORT_COUNTER;

const EXAMPLE_CONTRACT: &str = "dXNlIHNlcmRlOjp7U2VyaWFsaXplLCBEZXNlcmlhbGl6ZX07CnVzZSBhdmVfY29udHJhY3Rfc2RrIGFzIHNkazsKCi8vLyBEZWZpbmUgdGhlIHN0YXRlIG9mIHRoZSBjb250cmFjdC4gCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUsIENsb25lKV0Kc3RydWN0IFN0YXRlIHsKICBwdWIgb25lOiB1MzIsCiAgcHViIHR3bzogdTMyLAogIHB1YiB0aHJlZTogdTMyCn0KCiNbZGVyaXZlKFNlcmlhbGl6ZSwgRGVzZXJpYWxpemUpXQplbnVtIFN0YXRlRXZlbnQgewogIE1vZE9uZSB7IGRhdGE6IHUzMiB9LAogIE1vZFR3byB7IGRhdGE6IHUzMiB9LAogIE1vZFRocmVlIHsgZGF0YTogdTMyIH0sCiAgTW9kQWxsIHsgb25lOiB1MzIsIHR3bzogdTMyLCB0aHJlZTogdTMyIH0KfQoKI1t1bnNhZmUobm9fbWFuZ2xlKV0KcHViIHVuc2FmZSBmbiBtYWluX2Z1bmN0aW9uKHN0YXRlX3B0cjogaTMyLCBpbml0X3N0YXRlX3B0cjogaTMyLCBldmVudF9wdHI6IGkzMiwgaXNfb3duZXI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmV4ZWN1dGVfY29udHJhY3Qoc3RhdGVfcHRyLCBpbml0X3N0YXRlX3B0ciwgZXZlbnRfcHRyLCBpc19vd25lciwgY29udHJhY3RfbG9naWMpCn0KCiNbdW5zYWZlKG5vX21hbmdsZSldCnB1YiB1bnNhZmUgZm4gaW5pdF9jaGVja19mdW5jdGlvbihzdGF0ZV9wdHI6IGkzMikgLT4gdTMyIHsKICBzZGs6OmNoZWNrX2luaXRfZGF0YShzdGF0ZV9wdHIsIGluaXRfbG9naWMpCn0KCmZuIGluaXRfbG9naWMoCiAgX3N0YXRlOiAmU3RhdGUsCiAgY29udHJhY3RfcmVzdWx0OiAmbXV0IHNkazo6Q29udHJhY3RJbml0Q2hlY2ssCikgewogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQoKZm4gY29udHJhY3RfbG9naWMoCiAgY29udGV4dDogJnNkazo6Q29udGV4dDxTdGF0ZUV2ZW50PiwKICBjb250cmFjdF9yZXN1bHQ6ICZtdXQgc2RrOjpDb250cmFjdFJlc3VsdDxTdGF0ZT4sCikgewogIGxldCBzdGF0ZSA9ICZtdXQgY29udHJhY3RfcmVzdWx0LnN0YXRlOwogIG1hdGNoIGNvbnRleHQuZXZlbnQgewogICAgICBTdGF0ZUV2ZW50OjpNb2RPbmUgeyBkYXRhIH0gPT4gewogICAgICAgIHN0YXRlLm9uZSA9IGRhdGE7CiAgICAgIH0sCiAgICAgIFN0YXRlRXZlbnQ6Ok1vZFR3byB7IGRhdGEgfSA9PiB7CiAgICAgICAgc3RhdGUudHdvID0gZGF0YTsKICAgICAgfSwKICAgICAgU3RhdGVFdmVudDo6TW9kVGhyZWUgeyBkYXRhIH0gPT4gewogICAgICAgIGlmIGRhdGEgPT0gNTAgewogICAgICAgICAgY29udHJhY3RfcmVzdWx0LmVycm9yID0gIkNhbiBub3QgY2hhbmdlIHRocmVlIHZhbHVlLCA1MCBpcyBhIGludmFsaWQgdmFsdWUiLnRvX293bmVkKCk7CiAgICAgICAgICByZXR1cm4KICAgICAgICB9CiAgICAgICAgCiAgICAgICAgc3RhdGUudGhyZWUgPSBkYXRhOwogICAgICB9LAogICAgICBTdGF0ZUV2ZW50OjpNb2RBbGwgeyBvbmUsIHR3bywgdGhyZWUgfSA9PiB7CiAgICAgICAgc3RhdGUub25lID0gb25lOwogICAgICAgIHN0YXRlLnR3byA9IHR3bzsKICAgICAgICBzdGF0ZS50aHJlZSA9IHRocmVlOwogICAgICB9CiAgfQogIGNvbnRyYWN0X3Jlc3VsdC5zdWNjZXNzID0gdHJ1ZTsKfQ==";

#[test(tokio::test)]
// B19: validación de inputs de viewpoints y grants
//
// Setup:
//   crear una governance válida con schema `Example`, viewpoints `agua` y
//   `basura`, y un creator witness con `AllViewpoints` usado correctamente.
//
// Acción:
//   intentar facts de tracker con viewpoints reservados, desconocidos, vacíos y
//   mal formados; intentar un fact de governance con viewpoints; intentar
//   cambios de creator witness con grants inválidos.
//
// Comprobar:
//   `AllViewpoints` solo se acepta como grant aislado de creator witness;
//   los facts inválidos quedan en `Invalid` y no avanzan el tracker;
//   los cambios inválidos de governance no mutan schema ni creator witnesses.
async fn test_viewpoints_input_validation_battery() {
    let (nodes, _dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness]).await;
    let alice_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "Alice",
                    "key": alice_key
                },
                {
                    "name": "WitnessNode",
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
                    },
                    "viewpoints": ["agua", "basura"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "WitnessNode"
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
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Witnesses",
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

    let _ = get_subject(witness, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let governance_state =
        get_subject(owner, governance_id.clone(), Some(1), true)
            .await
            .unwrap();
    let governance: GovernanceData =
        from_value(governance_state.properties.clone()).unwrap();
    let schema_id = SchemaType::Type("Example".to_owned());
    let expected_creator_witnesses = BTreeSet::from([
        CreatorWitness {
            name: "Alice".to_owned(),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        },
        CreatorWitness {
            name: "Witnesses".to_owned(),
            viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
        },
    ]);
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(creator.witnesses, expected_creator_witnesses);

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let invalid_tracker_viewpoints = [
        BTreeSet::from(["AllViewpoints".to_owned()]),
        BTreeSet::from(["vidrio".to_owned()]),
        BTreeSet::from(["".to_owned()]),
        BTreeSet::from([" agua".to_owned()]),
        BTreeSet::from(["a".repeat(101)]),
    ];

    for viewpoints in invalid_tracker_viewpoints {
        let error = emit_fact_viewpoints(
            owner,
            subject_id.clone(),
            json!({
                "ModTwo": {
                    "data": 2
                }
            }),
            viewpoints,
            false,
        )
        .await
        .unwrap_err();

        assert!(error.to_string().contains("viewpoint"));
    }

    let bob_key = KeyPair::Ed25519(Ed25519Signer::generate().unwrap())
        .public_key()
        .to_string();
    let error = emit_fact_viewpoints(
        owner,
        governance_id.clone(),
        json!({
            "members": {
                "add": [
                    {
                        "name": "Bob",
                        "key": bob_key
                    }
                ]
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        false,
    )
    .await
    .unwrap_err();
    assert!(
        error
            .to_string()
            .contains("governance fact events cannot define viewpoints")
    );

    let invalid_governance_facts = [
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Owner",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Alice",
                                            "viewpoints": ["AllViewpoints", "agua"]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Owner",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Alice",
                                            "viewpoints": ["vidrio"]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Owner",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Alice",
                                            "viewpoints": [""]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        json!({
            "roles": {
                "schema": [
                    {
                        "schema_id": "Example",
                        "change": {
                            "creator": [
                                {
                                    "actual_name": "Owner",
                                    "actual_namespace": [],
                                    "new_witnesses": [
                                        {
                                            "name": "Witnesses",
                                            "viewpoints": ["agua"]
                                        }
                                    ]
                                }
                            ]
                        }
                    }
                ]
            }
        }),
        json!({
            "schemas": {
                "add": [
                    {
                        "id": "InvalidDuplicate",
                        "contract": EXAMPLE_CONTRACT,
                        "initial_value": {
                            "one": 0,
                            "two": 0,
                            "three": 0
                        },
                        "viewpoints": ["agua", "agua"]
                    }
                ]
            }
        }),
    ];

    for fact in invalid_governance_facts {
        emit_fact(owner, governance_id.clone(), fact, true)
            .await
            .unwrap();
    }

    let subject_state = get_subject(owner, subject_id.clone(), None, true)
        .await
        .unwrap();
    assert_eq!(subject_state.sn, 1);
    assert_eq!(
        subject_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );

    let events = get_events(owner, subject_id.clone(), 2, true)
        .await
        .unwrap();
    assert_tracker_fact_full(
        &events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );

    let governance_state =
        get_subject(owner, governance_id.clone(), None, true)
            .await
            .unwrap();
    let governance: GovernanceData =
        from_value(governance_state.properties).unwrap();
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(governance.version, 1);
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from(["agua".to_owned(), "basura".to_owned()])
    );
    assert!(
        !governance
            .schemas
            .contains_key(&SchemaType::Type("InvalidDuplicate".to_owned()))
    );
    assert_eq!(creator.witnesses, expected_creator_witnesses);
}

#[test(tokio::test)]
// B20: cambios de viewpoints del schema y copias de viewpoints obsoletos
//
// Setup:
//   crear un schema con `agua` y `basura`, emitir facts con ambos viewpoints,
//   cambiar el schema para quitar `agua` y añadir `vidrio`, y añadir un
//   requester como creator witness solo de `vidrio`.
//
// Acción:
//   intentar emitir un nuevo fact con `agua`, emitir un fact con `vidrio`,
//   y pedir copia desde el requester añadido tras el cambio del schema.
//
// Comprobar:
//   el viewpoint eliminado ya no se acepta para nuevos facts;
//   el viewpoint nuevo sí se acepta;
//   la copia conserva los viewpoints históricos pero entrega opaco lo que el
//   requester ya no puede ver y claro el nuevo viewpoint autorizado.
async fn test_viewpoints_schema_viewpoints_evolution_battery() {
    let (nodes, mut dirs) =
        create_nodes_and_connections(CreateNodesAndConnectionsConfig {
            bootstrap: vec![vec![]],
            addressable: vec![vec![0]],
            always_accept: true,
            ..Default::default()
        })
        .await;
    let owner = &nodes[0].api;
    let witness = &nodes[1].api;

    let governance_id =
        create_and_authorize_governance(owner, vec![witness]).await;
    let alice_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let alice_key = alice_keys.public_key().to_string();
    let requester_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
    let requester_key = requester_keys.public_key().to_string();

    let json = json!({
        "members": {
            "add": [
                {
                    "name": "WitnessNode",
                    "key": witness.public_key()
                },
                {
                    "name": "Requester",
                    "key": requester_key
                },
                {
                    "name": "Alice",
                    "key": alice_key
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
                    },
                    "viewpoints": ["agua", "basura"]
                }
            ]
        },
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "WitnessNode"
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
                        "creator": [
                            {
                                "name": "Owner",
                                "namespace": [],
                                "quantity": "infinity",
                                "witnesses": [
                                    {
                                        "name": "WitnessNode",
                                        "viewpoints": ["AllViewpoints"]
                                    },
                                    {
                                        "name": "Alice",
                                        "viewpoints": ["agua"]
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

    let _ = get_subject(witness, governance_id.clone(), Some(1), true)
        .await
        .unwrap();

    let (subject_id, ..) =
        create_subject(owner, governance_id.clone(), "Example", "", true)
            .await
            .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        true,
    )
    .await
    .unwrap();

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModTwo": {
                "data": 2
            }
        }),
        BTreeSet::from(["basura".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let json = json!({
        "schemas": {
            "change": [
                {
                    "actual_id": "Example",
                    "new_viewpoints": ["basura", "vidrio"]
                }
            ]
        }
    });

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let governance_state =
        get_subject(owner, governance_id.clone(), Some(2), true)
            .await
            .unwrap();
    let governance: GovernanceData =
        from_value(governance_state.properties).unwrap();
    let schema_id = SchemaType::Type("Example".to_owned());
    assert_eq!(
        governance.schemas.get(&schema_id).unwrap().viewpoints,
        BTreeSet::from(["basura".to_owned(), "vidrio".to_owned()])
    );
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(
        creator.witnesses,
        BTreeSet::from([
            CreatorWitness {
                name: "Alice".to_owned(),
                viewpoints: BTreeSet::new(),
            },
            CreatorWitness {
                name: "WitnessNode".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            },
        ])
    );

    let error = emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModOne": {
                "data": 10
            }
        }),
        BTreeSet::from(["agua".to_owned()]),
        false,
    )
    .await
    .unwrap_err();
    assert!(error.to_string().contains("viewpoint"));

    let json = json!({
        "roles": {
            "governance": {
                "add": {
                    "witness": [
                        "Requester"
                    ]
                }
            },
            "schema": [
                {
                    "schema_id": "Example",
                    "change": {
                        "creator": [
                            {
                                "actual_name": "Owner",
                                "actual_namespace": [],
                                "new_witnesses": [
                                    {
                                        "name": "Alice",
                                        "viewpoints": []
                                    },
                                    {
                                        "name": "Requester",
                                        "viewpoints": ["vidrio"]
                                    },
                                    {
                                        "name": "WitnessNode",
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

    emit_fact(owner, governance_id.clone(), json, true)
        .await
        .unwrap();

    let governance_state =
        get_subject(owner, governance_id.clone(), Some(3), true)
            .await
            .unwrap();
    let governance: GovernanceData =
        from_value(governance_state.properties).unwrap();
    let creator = governance
        .roles_schema
        .get(&schema_id)
        .unwrap()
        .creator
        .get(&RoleCreator::create("Owner", Namespace::new()))
        .unwrap();

    assert_eq!(
        creator.witnesses,
        BTreeSet::from([
            CreatorWitness {
                name: "Alice".to_owned(),
                viewpoints: BTreeSet::new(),
            },
            CreatorWitness {
                name: "Requester".to_owned(),
                viewpoints: BTreeSet::from(["vidrio".to_owned()]),
            },
            CreatorWitness {
                name: "WitnessNode".to_owned(),
                viewpoints: BTreeSet::from(["AllViewpoints".to_owned()]),
            },
        ])
    );

    emit_fact_viewpoints(
        owner,
        subject_id.clone(),
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        BTreeSet::from(["vidrio".to_owned()]),
        true,
    )
    .await
    .unwrap();

    let alice_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (alice_node, mut alice_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", alice_port),
        peers: vec![RoutingNode {
            peer_id: owner.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(alice_keys),
        ..Default::default()
    })
    .await;
    dirs.append(&mut alice_dirs);
    node_running(&alice_node.api).await.unwrap();

    alice_node
        .api
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    alice_node
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _ = get_subject(&alice_node.api, governance_id.clone(), Some(3), true)
        .await
        .unwrap();

    alice_node
        .api
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    alice_node
        .api
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let requester_port = PORT_COUNTER.fetch_add(1, Ordering::SeqCst);
    let (requester_node, mut requester_dirs) = create_node(CreateNodeConfig {
        node_type: NodeType::Addressable,
        listen_address: format!("/memory/{}", requester_port),
        peers: vec![RoutingNode {
            peer_id: owner.peer_id().to_string(),
            address: vec![nodes[0].listen_address.clone()],
        }],
        always_accept: true,
        keys: Some(requester_keys),
        ..Default::default()
    })
    .await;
    dirs.append(&mut requester_dirs);
    node_running(&requester_node.api).await.unwrap();

    requester_node
        .api
        .auth_subject(
            governance_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();
    requester_node
        .api
        .update_subject(governance_id.clone())
        .await
        .unwrap();
    let _ =
        get_subject(&requester_node.api, governance_id.clone(), Some(3), true)
            .await
            .unwrap();

    requester_node
        .api
        .auth_subject(
            subject_id.clone(),
            AuthWitness::One(PublicKey::from_str(&owner.public_key()).unwrap()),
        )
        .await
        .unwrap();

    assert!(
        requester_node
            .api
            .get_subject_state(subject_id.clone())
            .await
            .is_err(),
        "requester already has subject before update"
    );
    
    requester_node
        .api
        .update_subject(subject_id.clone())
        .await
        .unwrap();

    let owner_state = get_subject(owner, subject_id.clone(), Some(3), true)
        .await
        .unwrap();
    assert_eq!(
        owner_state.properties,
        json!({
            "one": 1,
            "two": 2,
            "three": 3
        })
    );
    assert_tracker_visibility(
        &owner_state,
        TrackerVisibilityModeDB::Full,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 1,
                to_sn: Some(1),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
        ],
        vec![
            TrackerEventVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerEventVisibilityDB::NonFact,
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 1,
                to_sn: Some(1),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let requester_state =
        get_subject(&requester_node.api, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        requester_state.properties,
        json!({
            "one": 0,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &requester_state,
        TrackerVisibilityModeDB::Opaque,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 1,
                to_sn: Some(2),
                visibility: TrackerStoredVisibilityDB::None,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
        ],
        vec![
            TrackerEventVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerEventVisibilityDB::NonFact,
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 1,
                to_sn: Some(1),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let requester_events =
        get_events(&requester_node.api, subject_id.clone(), 4, true)
            .await
            .unwrap();
    assert_tracker_fact_opaque(&requester_events[1].event, &["agua"]).unwrap();
    assert_tracker_fact_opaque(&requester_events[2].event, &["basura"])
        .unwrap();
    assert_tracker_fact_full(
        &requester_events[3].event,
        json!({
            "ModThree": {
                "data": 3
            }
        }),
        &["vidrio"],
    );

    let alice_state =
        get_subject(&alice_node.api, subject_id.clone(), Some(3), true)
            .await
            .unwrap();
    assert_eq!(
        alice_state.properties,
        json!({
            "one": 1,
            "two": 0,
            "three": 0
        })
    );
    assert_tracker_visibility(
        &alice_state,
        TrackerVisibilityModeDB::Opaque,
        vec![
            TrackerStoredVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerStoredVisibilityDB::Full,
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 1,
                to_sn: Some(1),
                visibility: TrackerStoredVisibilityDB::Only {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerStoredVisibilityRangeDB {
                from_sn: 2,
                to_sn: None,
                visibility: TrackerStoredVisibilityDB::None,
            },
        ],
        vec![
            TrackerEventVisibilityRangeDB {
                from_sn: 0,
                to_sn: Some(0),
                visibility: TrackerEventVisibilityDB::NonFact,
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 1,
                to_sn: Some(1),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["agua".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 2,
                to_sn: Some(2),
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["basura".to_owned()],
                },
            },
            TrackerEventVisibilityRangeDB {
                from_sn: 3,
                to_sn: None,
                visibility: TrackerEventVisibilityDB::Fact {
                    viewpoints: vec!["vidrio".to_owned()],
                },
            },
        ],
    )
    .unwrap();

    let alice_events = get_events(&alice_node.api, subject_id.clone(), 4, true)
        .await
        .unwrap();
    assert_tracker_fact_full(
        &alice_events[1].event,
        json!({
            "ModOne": {
                "data": 1
            }
        }),
        &["agua"],
    );
    assert_tracker_fact_opaque(&alice_events[2].event, &["basura"]).unwrap();
    assert_tracker_fact_opaque(&alice_events[3].event, &["vidrio"]).unwrap();
}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B21: visibilidad almacenada vs visibilidad del evento
//
// Setup:
//   crear eventos con:
//   fact full;
//   fact opaque;
//   fact con viewpoints;
//   non-fact;
//   y un tracker que cambie de `Full` a `Opaque`.
//
// Acción:
//   pedir histórico y actualizar el mismo tracker varias veces.
//
// Comprobar:
//   `stored_visibility = None` fuerza respuesta opaca para facts;
//   `event_visibility = NonFact` sigue saliendo en claro;
//   un evento opaque con evaluación ok deja el tracker en modo `Opaque`;
//   si la evaluación falla, no degrada el modo por error.
//   `actual_owner`, `new_owner` y `old_owner` siguen viendo claro aunque el event
//   tenga viewpoints, respetando sus atajos de ownership.
async fn test_viewpoints_stored_vs_event_visibility_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B22: namespace y schema combinados con viewpoints
//
// Setup:
//   usar witnesses correctos por viewpoint pero incorrectos por namespace/schema;
//   y otros correctos por namespace/schema pero sin viewpoint útil.
//
// Acción:
//   pedir acceso y copia sobre los mismos facts.
//
// Comprobar:
//   hay acceso solo si coinciden namespace/schema y grant de viewpoint;
//   acertar una sola dimensión no basta;
//   `TrackerSchemas` abre por schema global solo cuando el namespace también cuadra.
async fn test_viewpoints_namespace_schema_intersection_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B23: cambio de creator con mismo schema y mismo witness
//
// Setup:
//   usar el mismo schema y namespace;
//   hacer que el subject cambie de creator efectivo o de owner relevante;
//   mantener el mismo witness con grants distintos según creator.
//
// Acción:
//   pedir histórico antes y después del cambio.
//
// Comprobar:
//   el grant del creator anterior no se arrastra al siguiente;
//   el witness solo ve en claro los tramos donde el creator correcto lo autoriza;
//   el cambio no reabre en claro histórico ajeno.
async fn test_viewpoints_creator_change_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B24: `clear_sn`, prefijo contiguo y corte del primer batch
//
// Setup:
//   preparar un witness con rango `Clear` al principio y `Opaque` después;
//   por ejemplo `0..5 Clear` y `6..20 Opaque`.
//
// Acción:
//   lanzar update desde `our_sn = None` y desde `our_sn = 3`.
//
// Comprobar:
//   el primer request corta en el último `clear_sn` contiguo;
//   no mezcla en el mismo batch el tramo claro con el opaco si hay corte natural;
//   el segundo tramo se pide después por la ruta normal.
async fn test_viewpoints_clear_prefix_cut_battery() {}

#[test(tokio::test)]
#[ignore = "test plan placeholder"]
// B25: bordes de `sn`, `gov_version` y límites sin oferta útil
//
// Setup:
//   usar subjects donde:
//   el primer evento sea `sn=0`;
//   falte alguna entrada de ventana de governance;
//   `actual_sn` ya sea mayor o igual que el `sn` ofrecido por el witness.
//
// Acción:
//   pedir ventana, oferta y batch de distribución/update.
//
// Comprobar:
//   para `sn=0` se usa `data.gov_version` como fallback;
//   si no hay oferta útil, el nodo no fuerza update;
//   si `actual_sn >= witness_sn`, se corta limpio y no intenta pedir de más.
async fn test_viewpoints_sn_gov_version_edges_battery() {}
